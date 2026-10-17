//! Opt-in public Storage -> broker socket -> actual worker -> durable response.
//!
//! `run_protected_broker.py` provides a disposable, multiple-UID user/mount/PID
//! namespace. Only the account/password/session authorities are synthetic. No
//! real logind, PAM transaction, account, host state, or physical TPM is used.

use localpin_core::{
    eligibility::{EligibilityAuthority, EligibilityError, EligibilitySnapshot, SessionReference},
    enrollment::{
        EnrollmentAction, EnrollmentMachine, LifecycleAuthority, LifecycleError, PasswordWorker,
        PasswordWorkerError, PasswordWorkerRequest,
    },
    limits::ResourceBudget,
    records::CredentialRecord,
    secret::Pin,
    throttle::ThrottleRecord,
    types::{AccountId, Backend, Clock, ConnectionId, Incarnation, TimePoint, TransactionId, Uid},
};
use localpin_protocol::{
    Completion, ErrorCode, Request, Response, VerificationOutcome,
    transport::{BootInstant as Instant, Client, Deadline, TransportError},
};
use localpin_storage::Storage;
use localpind::{
    BootClock,
    broker::{Authorities, Engine, ProtectedEngine, serve_connection},
    platform::Peer,
    worker::WorkerSupervisor,
};
use std::{
    fs::{self, DirBuilder, File},
    os::unix::{
        fs::{DirBuilderExt, PermissionsExt, symlink},
        net::UnixListener,
        process::CommandExt,
    },
    path::Path,
    process::{Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
        mpsc,
    },
    thread,
    time::Duration,
};

const BASE: &str = "/run/localpin-m5";
const SOCKET: &str = "/run/localpin-m5/broker.sock";
const STATE: &str = "/run/localpin-m5/state";
const THROTTLE: &str = "/run/localpin-m5/state/users/1000/generation-2/throttle";
const TEMPORARY: &str = "/run/localpin-m5/state/users/1000/generation-2/.pending";
// Public M4 independently checked fixture: software PIN 123456.
const PHC: &[u8] = b"$argon2id$v=19$m=65536,t=3,p=1$BwcHBwcHBwcHBwcHBwcHBw$CUNrJW+K3R42xrH7g4MDA7wv0ihz8Hcf0glJGhH5HZ4";

fn account() -> AccountId {
    AccountId {
        uid: Uid::new(1000).unwrap(),
        incarnation: Incarnation::new([7; 16]).unwrap(),
    }
}

fn require_disposable_namespace() {
    assert_eq!(
        std::env::var("LOCALPIN_M5_PROTECTED_NAMESPACE").as_deref(),
        Ok("1"),
        "use run_protected_broker.py"
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
    eligibility_calls: AtomicUsize,
    refuse_final_session: AtomicBool,
    refuse_completion_write: AtomicBool,
    completion_failure_installed: AtomicBool,
}

struct SyntheticLifecycle(Arc<Controls>);

impl LifecycleAuthority for SyntheticLifecycle {
    fn current_incarnation(&mut self, uid: Uid) -> Result<Incarnation, LifecycleError> {
        if uid != account().uid {
            return Err(LifecycleError::AccountMissing);
        }
        if self.0.refuse_completion_write.load(Ordering::SeqCst)
            && !self.0.completion_failure_installed.load(Ordering::SeqCst)
            && fs::read(THROTTLE)
                .ok()
                .and_then(|bytes| ThrottleRecord::decode(&bytes).ok())
                .is_some_and(|record| record.pending.is_some())
        {
            // The post-reservation lifecycle fence runs after the pending guess
            // was durably written. Force the following completion replacement
            // to fail its real descriptor-relative unsafe-path check.
            symlink("/dev/null", TEMPORARY).unwrap();
            self.0
                .completion_failure_installed
                .store(true, Ordering::SeqCst);
        }
        Ok(account().incarnation)
    }
}

struct SyntheticEligibility {
    peer: Arc<Peer>,
    controls: Arc<Controls>,
}

impl EligibilityAuthority for SyntheticEligibility {
    fn check(&mut self, checked: AccountId) -> Result<EligibilitySnapshot, EligibilityError> {
        if checked != account() || self.peer.uid() != checked.uid.get() {
            return Err(EligibilityError::WrongAccount);
        }
        self.peer
            .ensure_live()
            .map_err(|_| EligibilityError::Unavailable)?;
        let call = self
            .controls
            .eligibility_calls
            .fetch_add(1, Ordering::SeqCst)
            + 1;
        // BeginVerify and Verify submission each check once; the protected
        // engine checks twice before work. Refuse only its final live fence.
        if self.controls.refuse_final_session.load(Ordering::SeqCst) && call >= 5 {
            return Err(EligibilityError::NoSession);
        }
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
        Box::new(SyntheticEligibility {
            peer,
            controls: self.0.clone(),
        })
    }
}

struct SyntheticPassword;
impl PasswordWorker for SyntheticPassword {
    fn verify_existing_password(
        &mut self,
        request: PasswordWorkerRequest,
    ) -> Result<TimePoint, PasswordWorkerError> {
        Ok(request.started_at())
    }
}

fn provision(storage: &Storage, controls: &Arc<Controls>) {
    let mut clock = BootClock::new().unwrap();
    let now = clock.now().unwrap();
    let mut lifecycle = SyntheticLifecycle(controls.clone());
    storage.initialize(account(), now, &mut lifecycle).unwrap();
    let mut store = storage.user(account().uid, &mut lifecycle).unwrap();
    let mut machine = EnrollmentMachine::new(store.committed_state().unwrap());
    let connection = ConnectionId::new([3; 16]).unwrap();
    let binding = machine
        .begin_own_user(
            connection,
            account().uid,
            TransactionId::new([4; 16]).unwrap(),
            EnrollmentAction::Enroll(Backend::Software),
            now,
            &mut store.lifecycle(),
        )
        .unwrap();
    machine
        .authorize_with_password_worker(
            binding,
            connection,
            now,
            &mut SyntheticPassword,
            &mut store.lifecycle(),
        )
        .unwrap();
    machine
        .staged_created(binding, connection, now, &mut store.lifecycle())
        .unwrap();
    let credential = CredentialRecord::new(
        account(),
        binding.proposed_generation(),
        Backend::Software,
        PHC,
    )
    .unwrap();
    let stage = store
        .stage_credential(
            credential,
            |persisted| match localpin_credentials::validate_enrollment(
                persisted,
                &Pin::parse(b"123456").unwrap(),
                &ResourceBudget::default(),
            ) {
                Ok(true) => Ok(()),
                _ => Err(localpin_storage::Error::Corrupt),
            },
        )
        .unwrap();
    machine
        .staged_verified(binding, connection, now, &mut store.lifecycle())
        .unwrap();
    let intent = machine
        .prepare_commit(binding, connection, now, &mut store.lifecycle())
        .unwrap();
    let committed = store
        .commit_generation(intent, Some(stage), &mut clock)
        .unwrap();
    assert_eq!(
        machine
            .acknowledge_durable_commit(
                intent,
                connection,
                clock.now().unwrap(),
                &mut store.lifecycle()
            )
            .unwrap(),
        committed
    );
    assert_eq!(committed.generation().get(), 2);
}

fn record() -> ThrottleRecord {
    ThrottleRecord::decode(&fs::read(THROTTLE).unwrap()).unwrap()
}

fn exchange(listener: &UnixListener, engine: &Arc<dyn Engine>, scenario: &str, uid: u32) {
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "protected_client_fixture",
            "--ignored",
            "--nocapture",
        ])
        .env("LOCALPIN_M5_CLIENT_SCENARIO", scenario)
        .uid(uid)
        .gid(uid)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(8);
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
    let (finished_tx, finished_rx) = mpsc::channel();
    let engine = engine.clone();
    thread::spawn(move || {
        finished_tx
            .send(serve_connection(stream, engine.as_ref()))
            .unwrap();
    });
    loop {
        if child.try_wait().unwrap().is_some() {
            break;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            panic!("protected client exceeded deadline");
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
        .expect("server did not finish");
    // Status is repeatable and leaves the connection idle; this client closes
    // immediately after its response, so the next server read observes EOF.
    assert!(
        served.is_ok()
            || scenario == "disabled"
                && matches!(
                    served,
                    Err(TransportError::Closed
                        | TransportError::Protocol(localpin_protocol::ProtocolError::Truncated))
                ),
        "server {scenario}: {served:?}"
    );
}

#[test]
#[ignore = "requires run_protected_broker.py disposable mapped-UID namespace"]
fn protected_engine_socket_storage_worker_and_revocation() {
    require_disposable_namespace();
    DirBuilder::new().mode(0o755).create(BASE).unwrap();
    DirBuilder::new().mode(0o700).create(STATE).unwrap();
    let storage = Storage::open(File::open(STATE).unwrap()).unwrap();
    let controls = Arc::new(Controls::default());
    provision(&storage, &controls);
    let budget = ResourceBudget::default();
    let engine: Arc<dyn Engine> = Arc::new(ProtectedEngine::new(
        storage,
        Arc::new(SyntheticAuthorities(controls.clone())),
        WorkerSupervisor::new("/app/localpin-worker").unwrap(),
        budget,
    ));
    let listener = UnixListener::bind(SOCKET).unwrap();
    fs::set_permissions(SOCKET, fs::Permissions::from_mode(0o666)).unwrap();
    listener.set_nonblocking(true).unwrap();

    exchange(&listener, &engine, "foreign", 1001);
    exchange(&listener, &engine, "root-verify", 0);
    assert_eq!(record().last_attempt, 0);
    exchange(&listener, &engine, "mismatch", 1000);
    let mismatch = record();
    assert_eq!((mismatch.last_attempt, mismatch.recent_len), (1, 1));
    assert!(mismatch.pending.is_none());
    exchange(&listener, &engine, "match", 1000);
    let success = record();
    assert_eq!((success.last_attempt, success.recent_len), (2, 0));
    assert!(success.pending.is_none());

    controls.eligibility_calls.store(0, Ordering::SeqCst);
    controls.refuse_final_session.store(true, Ordering::SeqCst);
    exchange(&listener, &engine, "session-gone", 1000);
    assert!(controls.eligibility_calls.load(Ordering::SeqCst) >= 5);
    assert_eq!(
        record().last_attempt,
        3,
        "final session refusal must follow an actual consumed guess"
    );
    controls.refuse_final_session.store(false, Ordering::SeqCst);

    controls
        .refuse_completion_write
        .store(true, Ordering::SeqCst);
    exchange(&listener, &engine, "storage-failure", 1000);
    assert!(controls.completion_failure_installed.load(Ordering::SeqCst));
    let incomplete = record();
    assert_eq!((incomplete.last_attempt, incomplete.recent_len), (4, 1));
    assert!(
        incomplete.pending.is_some(),
        "failed success completion cannot release the consumed reservation"
    );
    controls
        .refuse_completion_write
        .store(false, Ordering::SeqCst);
    fs::remove_file(TEMPORARY).unwrap();

    exchange(&listener, &engine, "recovery", 0);
    exchange(&listener, &engine, "disabled", 1000);
    assert!(Path::new("/run/localpin-m5/state/users/1000/generation-3/throttle").is_file());
    assert!(!Path::new("/run/localpin-m5/state/users/1000/generation-3/credential").exists());
    fs::remove_file(SOCKET).unwrap();
}

#[test]
#[ignore = "subprocess entry only; launched by namespace integration test"]
fn protected_client_fixture() {
    let Ok(scenario) = std::env::var("LOCALPIN_M5_CLIENT_SCENARIO") else {
        return;
    };
    let mut client = Client::connect(
        Path::new(SOCKET),
        Deadline::after(Duration::from_millis(250)),
    )
    .unwrap();
    if scenario == "recovery" {
        let response = client
            .request(
                Request::RecoverDisable { target_uid: 1000 },
                Deadline::after(Duration::from_secs(2)),
            )
            .unwrap();
        assert!(matches!(
            response.response,
            Response::Completed(Completion::RecoveryDisabled)
        ));
        return;
    }
    if scenario == "disabled" {
        assert!(client.status().unwrap().enrolled.is_none());
        return;
    }
    let candidate = if scenario == "mismatch" {
        b"000001"
    } else {
        b"123456"
    };
    let result = client.verify(
        Pin::parse(candidate).unwrap(),
        localpin_protocol::Backend::Software,
    );
    match scenario.as_str() {
        "foreign" | "root-verify" => {
            assert_eq!(result, Err(TransportError::Rejected(ErrorCode::Forbidden)))
        }
        "mismatch" => assert_eq!(result, Ok(VerificationOutcome::Mismatch)),
        "match" => assert_eq!(result, Ok(VerificationOutcome::Granted)),
        "session-gone" | "storage-failure" => {
            assert!(matches!(result, Ok(VerificationOutcome::Unavailable(_))))
        }
        _ => panic!("unknown synthetic client scenario"),
    }
}
