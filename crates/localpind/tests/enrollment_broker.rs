//! Opt-in M6 enrollment socket integration with real storage and credential workers.
//!
//! The companion runner supplies disposable multiple-UID namespaces. Password,
//! account and session authorities are synthetic; no host PAM policy or TPM is used.

use localpin_auth::{Conversation, PasswordPrompt, PromptStyle as PasswordStyle};
use localpin_core::{
    eligibility::{EligibilityAuthority, EligibilityError, EligibilitySnapshot, SessionReference},
    enrollment::{LifecycleAuthority, LifecycleError, PasswordWorkerError, PasswordWorkerRequest},
    limits::ResourceBudget,
    records::CredentialRecord,
    secret::{CredentialKind, CredentialProfile, Pin, SecretBytes},
    throttle::ThrottleRecord,
    types::{AccountId, Clock, Generation, Incarnation, TimePoint, Uid},
};
use localpin_protocol::{
    Availability, Backend, Completion, EnrollmentAction, ErrorCode, Id, PromptStyle, Reason,
    Request, RequestEnvelope, Response, Status, VerificationOutcome,
    transport::{BootInstant as Instant, Client, Deadline, SocketConnection, TransportError},
};
use localpin_storage::Storage;
use localpind::{
    BootClock,
    broker::{
        Authorities, Engine, ProtectedEngine, VerificationContext, VerificationDeadlines,
        serve_connection,
    },
    enrollment::PasswordAuthority,
    platform::Peer,
    worker::WorkerSupervisor,
};
use std::{
    fs::{self, DirBuilder, File},
    os::unix::{
        fs::{DirBuilderExt, PermissionsExt},
        net::{UnixListener, UnixStream},
        process::CommandExt,
    },
    path::Path,
    process::{Command, Stdio},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
        mpsc,
    },
    thread,
    time::Duration,
};

const BASE: &str = "/run/localpin-m6";
const SOCKET: &str = "/run/localpin-m6/broker.sock";
const STATE: &str = "/run/localpin-m6/state";
const CANCEL_WINDOW: &str = "/run/localpin-m6/cancel-window";
const PASSWORD: &[u8] = b"synthetic full password";

fn account() -> AccountId {
    AccountId {
        uid: Uid::new(1000).unwrap(),
        incarnation: Incarnation::new([7; 16]).unwrap(),
    }
}

fn require_disposable_namespace() {
    assert_eq!(
        std::env::var("LOCALPIN_M6_ENROLLMENT_NAMESPACE").as_deref(),
        Ok("1"),
        "use run_enrollment_broker.py"
    );
    assert_eq!(
        rustix::process::getuid().as_raw(),
        0,
        "orchestrator must be namespace root"
    );
    let mapping = fs::read_to_string("/proc/self/uid_map").unwrap();
    let ranges: Vec<Vec<u64>> = mapping
        .lines()
        .map(|line| {
            line.split_ascii_whitespace()
                .map(|value| value.parse().unwrap())
                .collect()
        })
        .collect();
    assert!(ranges.len() >= 2, "requires separate mapped ordinary UIDs");
    assert!(
        ranges.iter().all(|range| range.len() == 3 && range[1] != 0),
        "host root must never be mapped"
    );
    assert!(ranges.iter().any(|range| range[0] == 0 && range[2] == 1));
    assert!(
        ranges
            .iter()
            .any(|range| range[0] <= 1001 && range[0] + range[2] > 1001)
    );
}

#[derive(Default)]
struct Controls {
    password_calls: AtomicUsize,
    password_mode: AtomicUsize,
    changed_incarnation: AtomicUsize,
    cancel_before_pointer: AtomicBool,
    cancel_window_opened: AtomicBool,
    transaction: Mutex<Option<[u8; 16]>>,
    stale_snapshot: AtomicUsize,
}

struct SyntheticLifecycle(Arc<Controls>);
impl LifecycleAuthority for SyntheticLifecycle {
    fn current_incarnation(&mut self, uid: Uid) -> Result<Incarnation, LifecycleError> {
        if uid != account().uid {
            return Err(LifecycleError::AccountMissing);
        }
        // The staged credential has already passed its real reopened-record
        // trial. Pause the commit after its new throttle was synchronized, but
        // before the authoritative active pointer can be replaced.
        if self.0.cancel_before_pointer.load(Ordering::SeqCst)
            && Path::new(STATE)
                .join("users/1000/generation-2/throttle")
                .is_file()
            && !self.0.cancel_window_opened.swap(true, Ordering::SeqCst)
        {
            fs::write(CANCEL_WINDOW, b"pre-pointer").unwrap();
            thread::sleep(Duration::from_millis(300));
        }
        Ok(if self.0.changed_incarnation.load(Ordering::SeqCst) == 1 {
            Incarnation::new([8; 16]).unwrap()
        } else {
            account().incarnation
        })
    }
}

struct SyntheticEligibility(Arc<Peer>);
impl EligibilityAuthority for SyntheticEligibility {
    fn check(&mut self, checked: AccountId) -> Result<EligibilitySnapshot, EligibilityError> {
        if checked != account() || self.0.uid() != checked.uid.get() {
            return Err(EligibilityError::WrongAccount);
        }
        self.0
            .ensure_live()
            .map_err(|_| EligibilityError::Unavailable)?;
        Ok(EligibilitySnapshot::from_trusted_check(
            checked,
            SessionReference::new([9; 16]).unwrap(),
        ))
    }
}

struct SyntheticAuthorities(Arc<Controls>);
impl Authorities for SyntheticAuthorities {
    fn lifecycle(&self) -> Box<dyn LifecycleAuthority> {
        Box::new(SyntheticLifecycle(self.0.clone()))
    }
    fn eligibility(&self, peer: Arc<Peer>, _: Instant) -> Box<dyn EligibilityAuthority> {
        Box::new(SyntheticEligibility(peer))
    }
}

struct SyntheticPassword(Arc<Controls>);
impl PasswordAuthority for SyntheticPassword {
    fn verify(
        &self,
        request: PasswordWorkerRequest,
        conversation: &mut dyn Conversation,
    ) -> Result<TimePoint, PasswordWorkerError> {
        self.0.password_calls.fetch_add(1, Ordering::SeqCst);
        *self.0.transaction.lock().unwrap() = Some(request.binding().transaction().get());
        assert_eq!(request.binding().account(), account());
        let answer = conversation.password(PasswordPrompt {
            style: PasswordStyle::EchoOff,
            text: "Account password:",
            deadline: Instant::now() + Duration::from_secs(4),
        })?;
        if conversation.cancelled() {
            return Err(PasswordWorkerError::Cancelled);
        }
        if answer.expose() != PASSWORD {
            return Err(PasswordWorkerError::Rejected);
        }
        drop(answer);
        match self.0.password_mode.load(Ordering::SeqCst) {
            1 => return Err(PasswordWorkerError::Unavailable),
            2 => {
                let mut stale = request.started_at();
                stale.millis -= 1;
                return Ok(stale);
            }
            3 => {
                self.0.changed_incarnation.store(1, Ordering::SeqCst);
            }
            _ => {}
        }
        BootClock::new()
            .map_err(|_| PasswordWorkerError::Unavailable)?
            .now()
            .map_err(|_| PasswordWorkerError::Unavailable)
    }
}

// Synthetic authority injection represents a challenge snapshot which no longer
// agrees with the protected record at submission. The real ProtectedEngine must
// reject it under its user lock before any durable reservation or worker call.
struct SnapshotEngine {
    actual: ProtectedEngine,
    controls: Arc<Controls>,
}
impl Engine for SnapshotEngine {
    fn check(&self, peer: Arc<Peer>, deadline: Instant) -> Result<EligibilitySnapshot, Reason> {
        self.actual.check(peer, deadline)
    }
    fn status(&self, peer: Arc<Peer>, deadline: Instant) -> Status {
        self.actual.status(peer, deadline)
    }
    fn challenge(
        &self,
        peer: Arc<Peer>,
        expected: EligibilitySnapshot,
        deadline: Instant,
    ) -> Result<VerificationContext, Reason> {
        let mut context = self.actual.challenge(peer, expected, deadline)?;
        match self.controls.stale_snapshot.load(Ordering::SeqCst) {
            1 => context.generation += 1,
            2 => context.profile.kind = CredentialKind::Passcode,
            _ => {}
        }
        Ok(context)
    }
    fn enroll(
        &self,
        peer: Arc<Peer>,
        expected: EligibilitySnapshot,
        request: RequestEnvelope,
        channel: &mut localpind::enrollment::EnrollmentIo<'_>,
    ) -> Result<(), TransportError> {
        self.actual.enroll(peer, expected, request, channel)
    }
    fn verify(
        &self,
        peer: Arc<Peer>,
        expected: EligibilitySnapshot,
        context: VerificationContext,
        pin: Pin,
        deadlines: VerificationDeadlines,
        cancelled: &mut dyn FnMut() -> bool,
        deliver: &mut dyn FnMut(VerificationOutcome, Instant),
    ) {
        self.actual
            .verify(peer, expected, context, pin, deadlines, cancelled, deliver);
    }
    fn recover(
        &self,
        peer: &Peer,
        target: Uid,
        connection: Id,
        deadline: Instant,
        deliver: &mut dyn FnMut(Result<(), Reason>),
    ) {
        self.actual
            .recover(peer, target, connection, deadline, deliver);
    }
}

fn credential_path(generation: u64) -> std::path::PathBuf {
    Path::new(STATE).join(format!("users/1000/generation-{generation}/credential"))
}
fn throttle_bytes(generation: u64) -> Vec<u8> {
    fs::read(Path::new(STATE).join(format!("users/1000/generation-{generation}/throttle"))).unwrap()
}

fn committed(generation: u64, enrolled: bool) {
    // Read only after the connection handler has returned and released its lock.
    let pointer = fs::read(Path::new(STATE).join("users/1000/active")).unwrap();
    assert_eq!(pointer.len(), 35);
    assert_eq!(&pointer[..6], b"LPA3\0\x01");
    assert_eq!(&pointer[6..10], &account().uid.get().to_be_bytes());
    assert_eq!(&pointer[10..26], &account().incarnation.get());
    assert_eq!(&pointer[26..34], &generation.to_be_bytes());
    assert_eq!(pointer[34], if enrolled { 2 } else { 0 });
    let directory = Path::new(STATE).join(format!("users/1000/generation-{generation}"));
    let throttle = ThrottleRecord::decode(&fs::read(directory.join("throttle")).unwrap()).unwrap();
    assert_eq!(throttle.generation.get(), generation);
    assert_eq!(throttle.account, account());
    assert_eq!(directory.join("credential").is_file(), enrolled);
    if enrolled {
        let record =
            CredentialRecord::decode(&fs::read(directory.join("credential")).unwrap()).unwrap();
        assert_eq!(record.account(), account());
        assert_eq!(record.generation().get(), generation);
        assert_eq!(record.backend(), localpin_core::types::Backend::Software);
    }
}

fn exchange(
    listener: &UnixListener,
    engine: &Arc<dyn Engine>,
    controls: &Arc<Controls>,
    scenario: &str,
    uid: u32,
) {
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args([
            "--exact",
            "enrollment_client_fixture",
            "--ignored",
            "--nocapture",
        ])
        .env("LOCALPIN_M6_CLIENT_SCENARIO", scenario)
        .uid(uid)
        .gid(uid)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(transaction) = *controls.transaction.lock().unwrap() {
        let hex: String = transaction
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        command.env("LOCALPIN_M6_OLD_TRANSACTION", hex);
    }
    let mut child = command.spawn().unwrap();
    let deadline = Instant::now() + Duration::from_secs(12);
    let stream = loop {
        match listener.accept() {
            Ok((stream, _)) => break stream,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                assert!(
                    child.try_wait().unwrap().is_none(),
                    "client exited before connecting"
                );
                assert!(Instant::now() < deadline, "client did not connect");
                thread::sleep(Duration::from_millis(2));
            }
            Err(error) => panic!("accept: {error}"),
        }
    };
    let engine = engine.clone();
    let (finished_tx, finished_rx) = mpsc::channel();
    thread::spawn(move || {
        let _ = finished_tx.send(serve_connection(stream, engine.as_ref()));
    });
    loop {
        if child.try_wait().unwrap().is_some() {
            break;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            panic!("client {scenario} exceeded deadline");
        }
        thread::sleep(Duration::from_millis(2));
    }
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "client {scenario}: {}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let served = finished_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("broker did not finish");
    assert!(
        served.is_ok()
            || matches!(
                served,
                Err(TransportError::Closed
                    | TransportError::Protocol(localpin_protocol::ProtocolError::Truncated))
            ),
        "server {scenario}: {served:?}"
    );
}

#[test]
#[ignore = "requires run_enrollment_broker.py disposable mapped-UID namespace"]
fn enrollment_engine_complete_lifecycle_and_authorization_fences() {
    require_disposable_namespace();
    DirBuilder::new().mode(0o755).create(BASE).unwrap();
    DirBuilder::new().mode(0o700).create(STATE).unwrap();
    let storage = Storage::open(File::open(STATE).unwrap()).unwrap();
    let controls = Arc::new(Controls::default());
    let mut lifecycle = SyntheticLifecycle(controls.clone());
    storage
        .initialize(
            account(),
            BootClock::new().unwrap().now().unwrap(),
            &mut lifecycle,
        )
        .unwrap();
    let engine: Arc<dyn Engine> = Arc::new(SnapshotEngine {
        actual: ProtectedEngine::new(
            storage,
            Arc::new(SyntheticAuthorities(controls.clone())),
            WorkerSupervisor::new("/app/localpin-worker").unwrap(),
            ResourceBudget::default(),
        )
        .with_password_authority(Arc::new(SyntheticPassword(controls.clone()))),
        controls: controls.clone(),
    });
    let listener = UnixListener::bind(SOCKET).unwrap();
    fs::set_permissions(SOCKET, fs::Permissions::from_mode(0o666)).unwrap();
    listener.set_nonblocking(true).unwrap();
    committed(1, false);
    exchange(&listener, &engine, &controls, "status-disabled", 1000);
    controls.cancel_before_pointer.store(true, Ordering::SeqCst);
    exchange(&listener, &engine, &controls, "cancel-before-pointer", 1000);
    controls
        .cancel_before_pointer
        .store(false, Ordering::SeqCst);
    assert!(controls.cancel_window_opened.load(Ordering::SeqCst));
    fs::remove_file(CANCEL_WINDOW).unwrap();
    committed(1, false);
    for scenario in [
        "wrong-password",
        "cancel-prompt",
        "replay-prompt",
        "disconnect-ready",
        "reconnect-commit",
    ] {
        exchange(&listener, &engine, &controls, scenario, 1000);
        committed(1, false);
    }
    for mode in 1..=3 {
        controls.password_mode.store(mode, Ordering::SeqCst);
        exchange(
            &listener,
            &engine,
            &controls,
            "password-authority-failure",
            1000,
        );
        controls.changed_incarnation.store(0, Ordering::SeqCst);
        committed(1, false);
    }
    controls.password_mode.store(0, Ordering::SeqCst);
    exchange(&listener, &engine, &controls, "enroll", 1000);
    committed(2, true);
    exchange(&listener, &engine, &controls, "verify-first", 1000);
    let original = fs::read(credential_path(2)).unwrap();
    let throttle_before = throttle_bytes(2);
    fs::write(credential_path(2), b"synthetic corrupt selected credential").unwrap();
    exchange(&listener, &engine, &controls, "status-corrupt", 1000);
    assert_eq!(throttle_bytes(2), throttle_before);
    fs::write(credential_path(2), original).unwrap();
    for (mode, scenario) in [(1, "verify-stale-generation"), (2, "verify-stale-profile")] {
        let before = throttle_bytes(2);
        controls.stale_snapshot.store(mode, Ordering::SeqCst);
        exchange(&listener, &engine, &controls, scenario, 1000);
        controls.stale_snapshot.store(0, Ordering::SeqCst);
        assert_eq!(
            throttle_bytes(2),
            before,
            "stale metadata must consume no attempt"
        );
    }
    for scenario in ["verify-wrong-length", "verify-wrong-kind"] {
        let before = throttle_bytes(2);
        exchange(&listener, &engine, &controls, scenario, 1000);
        assert_eq!(
            throttle_bytes(2),
            before,
            "profile mismatch must consume no attempt"
        );
    }
    // Install an explicitly synthetic historical record only inside the disposable
    // namespace, retaining its active generation and throttle bytes. No host
    // credential or account state is available to this fixture.
    let legacy = localpin_credentials::enroll(
        account(),
        Generation::new(2).unwrap(),
        &Pin::parse(b"012345").unwrap(),
        &ResourceBudget::default(),
    )
    .unwrap();
    fs::write(credential_path(2), legacy.encode().unwrap().expose()).unwrap();
    exchange(&listener, &engine, &controls, "verify-legacy", 1000);
    for scenario in [
        "change-invalid-short",
        "change-invalid-long",
        "change-invalid-kind",
    ] {
        let before = fs::read(credential_path(2)).unwrap();
        let throttle = throttle_bytes(2);
        exchange(&listener, &engine, &controls, scenario, 1000);
        assert_eq!(fs::read(credential_path(2)).unwrap(), before);
        assert_eq!(throttle_bytes(2), throttle);
    }
    let calls = controls.password_calls.load(Ordering::SeqCst);
    for scenario in ["rotate-backend-mismatch", "migrate-same-backend"] {
        exchange(&listener, &engine, &controls, scenario, 1000);
        committed(2, true);
    }
    assert_eq!(
        controls.password_calls.load(Ordering::SeqCst),
        calls,
        "invalid backend changes must not invoke password worker"
    );
    for scenario in ["old-pin-is-not-password", "cancel-ready"] {
        exchange(&listener, &engine, &controls, scenario, 1000);
        committed(2, true);
    }
    exchange(&listener, &engine, &controls, "change", 1000);
    committed(3, true);
    exchange(&listener, &engine, &controls, "verify-old", 1000);
    exchange(&listener, &engine, &controls, "verify-new", 1000);
    for (generation, change, verify) in [
        (4, "change-passcode-min", "verify-passcode-min"),
        (5, "change-passcode-max", "verify-passcode-max"),
        (6, "change-numeric-passcode", "verify-numeric-passcode"),
        (7, "change-pin-max", "verify-pin-max"),
    ] {
        exchange(&listener, &engine, &controls, change, 1000);
        committed(generation, true);
        exchange(&listener, &engine, &controls, verify, 1000);
    }
    exchange(
        &listener,
        &engine,
        &controls,
        "disable-wrong-password",
        1000,
    );
    committed(7, true);
    exchange(&listener, &engine, &controls, "disable", 1000);
    committed(8, false);
    exchange(&listener, &engine, &controls, "enroll", 1000);
    committed(9, true);
    exchange(&listener, &engine, &controls, "ordinary-recover", 1000);
    committed(9, true);
    exchange(&listener, &engine, &controls, "root-recover", 0);
    committed(10, false);
    exchange(&listener, &engine, &controls, "status-disabled", 1000);
}

fn connect() -> Client {
    Client::connect(
        Path::new(SOCKET),
        Deadline::after(Duration::from_millis(250)),
    )
    .unwrap()
}
fn deadline() -> Deadline {
    Deadline::after(Duration::from_secs(8))
}
fn terminal_denial(result: Result<localpin_protocol::ResponseEnvelope, TransportError>) {
    assert!(
        matches!(
            result,
            Ok(localpin_protocol::ResponseEnvelope {
                response: Response::Error(_),
                ..
            }) | Err(TransportError::Closed
                | TransportError::Protocol(localpin_protocol::ProtocolError::Truncated))
        ),
        "expected terminal denial: {result:?}"
    );
}
fn begin(
    client: &mut Client,
    action: EnrollmentAction,
    backend: Option<Backend>,
    kind: CredentialKind,
) -> (Id, Id) {
    let response = client
        .request(
            Request::BeginEnroll {
                action,
                backend,
                kind: backend.map(|_| kind),
            },
            deadline(),
        )
        .unwrap();
    let Response::EnrollmentStarted {
        transaction,
        generation,
        valid_for_ms,
    } = response.response
    else {
        panic!("begin was rejected")
    };
    assert!(generation > 1 && valid_for_ms <= 60_000);
    let response = client.receive(deadline()).unwrap();
    let Response::ConversationPrompt {
        transaction: checked,
        prompt,
        style,
        ..
    } = response.response
    else {
        panic!("missing password prompt")
    };
    assert_eq!(checked, transaction);
    assert_eq!(style, PromptStyle::EchoOff);
    (transaction, prompt)
}
fn password(
    client: &mut Client,
    transaction: Id,
    prompt: Id,
    answer: &[u8],
) -> Result<localpin_protocol::ResponseEnvelope, TransportError> {
    client.request(
        Request::EnrollConversation {
            transaction,
            prompt,
            response: SecretBytes::from_slice(answer, 512).unwrap(),
        },
        deadline(),
    )
}
fn ready(client: &mut Client, transaction: Id, prompt: Id) {
    let response = password(client, transaction, prompt, PASSWORD).unwrap();
    assert!(
        matches!(response.response, Response::EnrollmentReady { transaction: checked, valid_for_ms } if checked == transaction && valid_for_ms <= 60_000)
    );
}

fn cancel_before_pointer() {
    let stream = UnixStream::connect(SOCKET).unwrap();
    let mut socket = SocketConnection::new(stream).unwrap();
    let greeting = socket.read_response(deadline()).unwrap();
    assert!(matches!(greeting.response, Response::Hello));
    let connection = greeting.connection;
    let request = |socket: &mut SocketConnection, request| {
        socket
            .write_request(
                &RequestEnvelope {
                    connection,
                    request,
                },
                deadline(),
            )
            .unwrap();
        socket.read_response(deadline()).unwrap()
    };
    let response = request(
        &mut socket,
        Request::BeginEnroll {
            action: EnrollmentAction::Enroll,
            backend: Some(Backend::Software),
            kind: Some(CredentialKind::NumericPin),
        },
    );
    let Response::EnrollmentStarted { transaction, .. } = response.response else {
        panic!("missing transaction")
    };
    let response = socket.read_response(deadline()).unwrap();
    let Response::ConversationPrompt { prompt, .. } = response.response else {
        panic!("missing password prompt")
    };
    let response = request(
        &mut socket,
        Request::EnrollConversation {
            transaction,
            prompt,
            response: SecretBytes::from_slice(PASSWORD, 512).unwrap(),
        },
    );
    assert!(matches!(
        response.response,
        Response::EnrollmentReady { .. }
    ));
    socket
        .write_request(
            &RequestEnvelope {
                connection,
                request: Request::CommitEnrollment {
                    transaction,
                    pin: Pin::parse(b"01234567").unwrap(),
                },
            },
            deadline(),
        )
        .unwrap();
    let until = Instant::now() + Duration::from_secs(8);
    while !Path::new(CANCEL_WINDOW).is_file() {
        assert!(
            Instant::now() < until,
            "commit never reached its pre-pointer window"
        );
        thread::sleep(Duration::from_millis(2));
    }
    socket
        .write_request(
            &RequestEnvelope {
                connection,
                request: Request::Cancel,
            },
            deadline(),
        )
        .unwrap();
    // Cancellation before the durable pointer boundary must leave generation 1
    // authoritative. A terminal error or closed result channel is sufficient;
    // the parent verifies the exact protected state after the handler returns.
    terminal_denial(socket.read_response(deadline()));
}

#[test]
#[ignore = "subprocess entry only; launched by namespace integration test"]
fn enrollment_client_fixture() {
    let Ok(scenario) = std::env::var("LOCALPIN_M6_CLIENT_SCENARIO") else {
        return;
    };
    if scenario == "cancel-before-pointer" {
        cancel_before_pointer();
        return;
    }
    let mut client = connect();
    if scenario == "status-corrupt" {
        let status = client.status().unwrap();
        assert_eq!(status.enrolled, Some(Backend::Software));
        assert_eq!(status.profile, None);
        assert_eq!(status.availability, Availability::Unavailable);
        assert_eq!(status.reason, Reason::Storage);
        return;
    }
    if scenario == "status-disabled" {
        assert!(client.status().unwrap().enrolled.is_none());
        return;
    }
    if scenario == "root-recover" || scenario == "ordinary-recover" {
        let response = client
            .request(Request::RecoverDisable { target_uid: 1000 }, deadline())
            .unwrap();
        if scenario == "root-recover" {
            assert!(matches!(
                response.response,
                Response::Completed(Completion::RecoveryDisabled)
            ));
        } else {
            assert!(matches!(
                response.response,
                Response::Error(ErrorCode::Forbidden)
            ));
        }
        return;
    }
    if scenario.starts_with("verify-") {
        let candidate: &[u8] = match scenario.as_str() {
            "verify-new" => b"76543210",
            "verify-legacy" => b"012345",
            "verify-passcode-min" => b" spaced ",
            "verify-passcode-max" => &[b'X'; 64],
            "verify-numeric-passcode" => b"00112233",
            "verify-pin-max" => b"0012345678901234",
            "verify-wrong-length" => b"012345678",
            "verify-wrong-kind" => b"ABCDEFGH",
            _ => b"01234567",
        };
        if scenario == "verify-legacy" {
            assert_eq!(
                client.status().unwrap().profile,
                Some(CredentialProfile::legacy())
            );
        }
        if scenario == "verify-wrong-length" || scenario == "verify-wrong-kind" {
            let Response::VerifyChallenge { challenge, .. } = client
                .request(Request::BeginVerify, deadline())
                .unwrap()
                .response
            else {
                panic!("expected profile challenge");
            };
            terminal_denial(client.request(
                Request::Verify {
                    challenge,
                    pin: Pin::parse(candidate).unwrap(),
                },
                deadline(),
            ));
        } else {
            let result = client
                .verify(Pin::parse(candidate).unwrap(), Backend::Software)
                .unwrap();
            assert_eq!(
                result,
                if scenario.starts_with("verify-stale-") {
                    VerificationOutcome::Unavailable(Reason::Policy)
                } else if scenario == "verify-old" {
                    VerificationOutcome::Mismatch
                } else {
                    VerificationOutcome::Granted
                }
            );
        }
        return;
    }
    if scenario == "reconnect-commit" {
        let hex = std::env::var("LOCALPIN_M6_OLD_TRANSACTION").unwrap();
        let mut transaction = [0; 16];
        for (index, byte) in transaction.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16).unwrap();
        }
        terminal_denial(client.request(
            Request::CommitEnrollment {
                transaction: Id::from_bytes(transaction).unwrap(),
                pin: Pin::parse(b"01234567").unwrap(),
            },
            deadline(),
        ));
        return;
    }
    if scenario == "rotate-backend-mismatch" || scenario == "migrate-same-backend" {
        let (action, backend) = if scenario == "rotate-backend-mismatch" {
            (EnrollmentAction::Rotate, Backend::Tpm)
        } else {
            (EnrollmentAction::Migrate, Backend::Software)
        };
        terminal_denial(client.request(
            Request::BeginEnroll {
                action,
                backend: Some(backend),
                kind: Some(CredentialKind::NumericPin),
            },
            deadline(),
        ));
        return;
    }
    let action = if scenario == "disable" || scenario == "disable-wrong-password" {
        EnrollmentAction::Disable
    } else if scenario.starts_with("change")
        || ["old-pin-is-not-password", "cancel-ready"].contains(&scenario.as_str())
    {
        EnrollmentAction::Rotate
    } else {
        EnrollmentAction::Enroll
    };
    let backend = if action == EnrollmentAction::Disable {
        None
    } else {
        Some(Backend::Software)
    };
    let kind = if scenario.contains("passcode") {
        CredentialKind::Passcode
    } else {
        CredentialKind::NumericPin
    };
    let (transaction, prompt) = begin(&mut client, action, backend, kind);
    if scenario == "cancel-prompt" {
        assert!(matches!(
            client
                .request(Request::Cancel, deadline())
                .unwrap()
                .response,
            Response::Cancelled
        ));
        return;
    }
    if scenario == "replay-prompt" {
        terminal_denial(password(
            &mut client,
            transaction,
            Id::from_bytes([6; 16]).unwrap(),
            PASSWORD,
        ));
        return;
    }
    if [
        "wrong-password",
        "disable-wrong-password",
        "old-pin-is-not-password",
        "password-authority-failure",
    ]
    .contains(&scenario.as_str())
    {
        let answer: &[u8] = if scenario == "password-authority-failure" {
            PASSWORD
        } else if scenario == "old-pin-is-not-password" {
            b"01234567"
        } else {
            b"wrong full password"
        };
        terminal_denial(password(&mut client, transaction, prompt, answer));
        return;
    }
    ready(&mut client, transaction, prompt);
    if scenario == "disconnect-ready" {
        client.close();
        return;
    }
    if scenario == "cancel-ready" {
        assert!(matches!(
            client
                .request(Request::Cancel, deadline())
                .unwrap()
                .response,
            Response::Cancelled
        ));
        return;
    }
    let request = if action == EnrollmentAction::Disable {
        Request::Disable { transaction }
    } else {
        Request::CommitEnrollment {
            transaction,
            pin: Pin::parse(match scenario.as_str() {
                "change" => b"76543210".as_slice(),
                "change-passcode-min" => b" spaced ",
                "change-passcode-max" => &[b'X'; 64],
                "change-numeric-passcode" => b"00112233",
                "change-pin-max" => b"0012345678901234",
                "change-invalid-short" => b"012345",
                "change-invalid-long" => b"01234567890123456",
                "change-invalid-kind" => b"bad passcode",
                _ => b"01234567",
            })
            .unwrap(),
        }
    };
    if scenario.starts_with("change-invalid-") {
        terminal_denial(client.request(request, deadline()));
        return;
    }
    let response = client.request(request, deadline()).unwrap();
    assert!(
        matches!(response.response, Response::Completed(Completion::Disabled) if action == EnrollmentAction::Disable)
            || matches!(response.response, Response::Completed(Completion::Enrolled(Backend::Software)) if action != EnrollmentAction::Disable),
        "commit: {response:?}"
    );
}
