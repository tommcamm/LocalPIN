//! Opt-in synthetic TPM2-TSS tests. Every endpoint is an owned disposable swtpm.
//! No environment TCTI, /dev/tpm*, persistent handle or host hierarchy is used.
use super::*;
use localpin_core::{
    throttle::{AttemptResponse, DurableThrottleStore, RestoredThrottle, Throttle, ThrottleRecord},
    types::{BootId, Incarnation, TimePoint, Uid, Unavailable},
};
use localpin_credentials::OsRandom;
use std::{
    fs,
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    path::PathBuf,
    process::{Child, Command, Stdio},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};
use tss_esapi::{
    Context,
    constants::{SessionType, response_code::Tss2ResponseCodeKind},
    interface_types::{
        algorithm::HashingAlgorithm, resource_handles::Hierarchy, session_handles::AuthSession,
    },
    structures::{Auth, SymmetricDefinition},
};

fn account() -> AccountId {
    AccountId {
        uid: Uid::new(1000).unwrap(),
        incarnation: Incarnation::new([1; 16]).unwrap(),
    }
}
fn generation() -> Generation {
    Generation::new(1).unwrap()
}
fn now(millis: u64) -> TimePoint {
    TimePoint {
        boot: BootId::new([1; 16]).unwrap(),
        millis,
    }
}
fn permit(budget: &localpin_core::limits::ResourceBudget) -> WorkPermit {
    budget
        .try_work(
            account().uid,
            KdfParameters::ENROLLMENT,
            WorkKind::TpmPinDerivation,
        )
        .unwrap()
}

struct FixedRandom(u8);
impl Randomness for FixedRandom {
    fn fill(&mut self, destination: &mut [u8]) -> Result<(), Unavailable> {
        destination.fill(self.0);
        self.0 += 0x11;
        Ok(())
    }
}

fn unused_ports() -> u16 {
    for _ in 0..100 {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        if port < u16::MAX && TcpListener::bind(("127.0.0.1", port + 1)).is_ok() {
            return port;
        }
    }
    panic!("no disposable localhost port pair");
}

struct Simulator {
    root: PathBuf,
    port: u16,
    child: Option<Child>,
}
impl Simulator {
    fn new() -> Self {
        use std::os::unix::fs::PermissionsExt;
        let mut nonce = [0; 16];
        OsRandom.fill(&mut nonce).unwrap();
        let suffix: String = nonce.iter().map(|byte| format!("{byte:02x}")).collect();
        let root = std::env::temp_dir().join(format!("localpin-m4-tpm-{suffix}"));
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let mut sim = Self {
            root,
            port: unused_ports(),
            child: None,
        };
        sim.start();
        sim
    }
    fn start(&mut self) {
        let child = Command::new("swtpm")
            .args([
                "socket",
                "--tpm2",
                "--tpmstate",
                &format!("dir={},mode=0600", self.root.display()),
                "--ctrl",
                &format!("type=tcp,port={},bindaddr=127.0.0.1", self.port + 1),
                "--server",
                &format!("type=tcp,port={},bindaddr=127.0.0.1", self.port),
                "--flags",
                "not-need-init,startup-clear",
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("install swtpm for opt-in simulator tests");
        self.child = Some(child);
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            assert!(
                self.child.as_mut().unwrap().try_wait().unwrap().is_none(),
                "owned swtpm exited"
            );
            if TcpStream::connect(("127.0.0.1", self.port)).is_ok() {
                break;
            }
            assert!(Instant::now() < deadline, "owned swtpm startup timed out");
            thread::sleep(Duration::from_millis(10));
        }
    }
    fn stop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = Command::new("kill")
                .args(["-TERM", &child.id().to_string()])
                .status();
            let until = Instant::now() + Duration::from_secs(2);
            while child.try_wait().unwrap().is_none() && Instant::now() < until {
                thread::sleep(Duration::from_millis(10));
            }
            if child.try_wait().unwrap().is_none() {
                let _ = child.kill();
            }
            child.wait().unwrap();
        }
    }
    fn operation(&self) -> NativeOperation {
        NativeOperation::simulator(self.port).unwrap()
    }
    fn command(&self, command: &str, args: &[&str]) {
        let mut child = Command::new(command)
            .args(["-T", &format!("swtpm:host=127.0.0.1,port={}", self.port)])
            .args(args)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let until = Instant::now() + Duration::from_secs(5);
        loop {
            if let Some(status) = child.try_wait().unwrap() {
                assert!(status.success(), "owned simulator command failed");
                break;
            }
            if Instant::now() >= until {
                let _ = child.kill();
                let _ = child.wait();
                panic!("owned simulator tool timed out");
            }
            thread::sleep(Duration::from_millis(10));
        }
    }
    fn budget(&self) -> TpmDaBudget {
        let mut ctx = Context::new(self.operation().endpoint).unwrap();
        native::budget(&mut ctx).unwrap()
    }
}
impl Drop for Simulator {
    fn drop(&mut self) {
        self.stop();
        let _ = fs::remove_dir_all(&self.root);
    }
}

#[derive(Clone)]
struct Frame {
    command: bool,
    data: Vec<u8>,
}
/// In-memory command recorder with a separately forwarded simulator control port.
struct Proxy {
    port: u16,
    stop: Arc<AtomicBool>,
    threads: Vec<JoinHandle<()>>,
    frames: Arc<Mutex<Vec<Frame>>>,
}
impl Proxy {
    fn new(target: u16) -> Self {
        let port = unused_ports();
        let stop = Arc::new(AtomicBool::new(false));
        let frames = Arc::new(Mutex::new(Vec::new()));
        let mut threads = Vec::new();
        for offset in 0..2 {
            let listener = TcpListener::bind(("127.0.0.1", port + offset)).unwrap();
            listener.set_nonblocking(true).unwrap();
            let stop = stop.clone();
            let frames = frames.clone();
            threads.push(thread::spawn(move || {
                let mut clients = Vec::new();
                while !stop.load(Ordering::SeqCst) {
                    match listener.accept() {
                        Ok((client, _)) => {
                            let target =
                                TcpStream::connect(("127.0.0.1", target + offset)).unwrap();
                            let done = Arc::new(AtomicBool::new(false));
                            for (mut input, mut output, command) in [
                                (
                                    client.try_clone().unwrap(),
                                    target.try_clone().unwrap(),
                                    true,
                                ),
                                (target, client, false),
                            ] {
                                let stop = stop.clone();
                                let done = done.clone();
                                let frames = frames.clone();
                                clients.push(thread::spawn(move || {
                                    input
                                        .set_read_timeout(Some(Duration::from_millis(100)))
                                        .unwrap();
                                    let mut bytes = [0; 8192];
                                    while !stop.load(Ordering::SeqCst)
                                        && !done.load(Ordering::SeqCst)
                                    {
                                        match input.read(&mut bytes) {
                                            Ok(0) => break,
                                            Ok(length) => {
                                                if offset == 0 {
                                                    frames.lock().unwrap().push(Frame {
                                                        command,
                                                        data: bytes[..length].to_vec(),
                                                    });
                                                }
                                                if output.write_all(&bytes[..length]).is_err() {
                                                    break;
                                                }
                                            }
                                            Err(error)
                                                if matches!(
                                                    error.kind(),
                                                    std::io::ErrorKind::WouldBlock
                                                        | std::io::ErrorKind::TimedOut
                                                ) =>
                                            {
                                                continue;
                                            }
                                            Err(_) => break,
                                        }
                                    }
                                    done.store(true, Ordering::SeqCst);
                                }));
                            }
                        }
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(5))
                        }
                        Err(_) => break,
                    }
                }
                for client in clients {
                    client.join().unwrap();
                }
            }));
        }
        Self {
            port,
            stop,
            threads,
            frames,
        }
    }
    fn operation(&self) -> NativeOperation {
        NativeOperation::simulator(self.port).unwrap()
    }
    fn clear(&self) {
        self.frames.lock().unwrap().clear();
    }
    fn bytes(&self, commands: bool) -> Vec<u8> {
        self.frames
            .lock()
            .unwrap()
            .iter()
            .filter(|f| f.command == commands)
            .flat_map(|f| f.data.iter().copied())
            .collect()
    }
    fn packets(&self, commands: bool) -> Vec<Vec<u8>> {
        let bytes = self.bytes(commands);
        let mut commands = Vec::new();
        let mut offset = 0;
        while offset < bytes.len() {
            assert!(bytes.len() - offset >= 10);
            let length =
                u32::from_be_bytes(bytes[offset + 2..offset + 6].try_into().unwrap()) as usize;
            assert!(length >= 10 && offset + length <= bytes.len());
            commands.push(bytes[offset..offset + length].to_vec());
            offset += length;
        }
        commands
    }
}
impl Drop for Proxy {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        for thread in self.threads.drain(..) {
            thread.join().unwrap();
        }
    }
}

struct Store {
    record: ThrottleRecord,
    writes: usize,
}
impl DurableThrottleStore for Store {
    type Error = ();
    fn commit(
        &mut self,
        expected: &ThrottleRecord,
        replacement: &ThrottleRecord,
    ) -> Result<(), ()> {
        if self.record != *expected {
            return Err(());
        }
        self.record = *replacement;
        self.writes += 1;
        Ok(())
    }
}
fn invoke(
    verifier: &mut impl CredentialVerifier,
    pin: &[u8],
    parameters: KdfParameters,
) -> (AttemptResponse, Store) {
    let initial = ThrottleRecord::initial(account(), generation(), now(0));
    let RestoredThrottle::Ready(mut throttle) =
        Throttle::restore(initial, account(), generation(), now(0)).unwrap()
    else {
        panic!("new fixture")
    };
    let mut store = Store {
        record: initial,
        writes: 0,
    };
    let budget = localpin_core::limits::ResourceBudget::default();
    let reserved = throttle
        .reserve(now(1))
        .unwrap()
        .commit(&mut store)
        .unwrap();
    assert_eq!(store.writes, 1);
    assert!(store.record.pending.is_some());
    let job = VerificationJob::new(
        reserved,
        Backend::Tpm2,
        Pin::parse(pin).unwrap(),
        budget
            .try_work(account().uid, parameters, WorkKind::TpmPinDerivation)
            .unwrap(),
        parameters,
    )
    .unwrap();
    let completion = verifier.verify(job);
    assert!(
        budget
            .try_work(account().uid, parameters, WorkKind::TpmPinDerivation)
            .is_err(),
        "completion retains charged lease"
    );
    let response = completion
        .complete(now(2))
        .unwrap()
        .commit(&mut store, account(), Some(generation()))
        .unwrap();
    assert_eq!(store.writes, 2);
    assert!(store.record.pending.is_none());
    assert!(
        budget
            .try_work(account().uid, parameters, WorkKind::TpmPinDerivation)
            .is_ok()
    );
    (response, store)
}

fn raw_unseal(
    operation: NativeOperation,
    record: &TpmRecord,
    auth: &[u8],
    policy: bool,
) -> tss_esapi::Result<tss_esapi::structures::SensitiveData> {
    let mut ctx = Context::new(operation.endpoint)?;
    let parent = ctx
        .execute_with_nullauth_session(|ctx| {
            ctx.create_primary(
                Hierarchy::Owner,
                native::parent_template().unwrap(),
                None,
                None,
                None,
                None,
            )
        })?
        .key_handle;
    let child = ctx.execute_with_nullauth_session(|ctx| {
        ctx.load(parent, record.private.clone(), record.object.clone())
    })?;
    ctx.tr_set_auth(child.into(), Auth::try_from(auth)?)?;
    let session = if policy {
        ctx.start_auth_session(
            Some(parent),
            None,
            None,
            SessionType::Policy,
            SymmetricDefinition::AES_128_CFB,
            HashingAlgorithm::Sha256,
        )?
        .unwrap()
    } else {
        AuthSession::Password
    };
    ctx.execute_with_session(Some(session), |ctx| ctx.unseal(child.into()))
}
fn kind(error: tss_esapi::Error) -> Option<Tss2ResponseCodeKind> {
    if let tss_esapi::Error::Tss2Error(code) = error {
        code.kind()
    } else {
        None
    }
}

#[test]
#[ignore = "opt-in: starts an owned disposable localhost swtpm; never opens host TPM"]
fn dynamic_da_properties_bypass_context_cache() {
    let sim = Simulator::new();
    sim.command(
        "tpm2_dictionarylockout",
        &[
            "--setup-parameters",
            "--max-tries",
            "8",
            "--recovery-time",
            "86400",
            "--lockout-recovery-time",
            "86400",
        ],
    );
    let budget = localpin_core::limits::ResourceBudget::default();
    let pin = Pin::parse(b"000001").unwrap();
    let credential = sim
        .operation()
        .enroll(
            account(),
            generation(),
            &pin,
            &mut permit(&budget),
            &mut FixedRandom(0x11),
        )
        .unwrap();
    let record = TpmRecord::from_credential(&credential).unwrap();
    let mut context = Context::new(sim.operation().endpoint).unwrap();
    // Prime the wrapper's cache, just as parent bootstrap used to cache Permanent.
    assert_eq!(
        context
            .get_tpm_property(tss_esapi::constants::PropertyTag::LockoutCounter)
            .unwrap(),
        Some(0)
    );
    assert_eq!(
        context
            .get_tpm_property(tss_esapi::constants::PropertyTag::MaxAuthFail)
            .unwrap(),
        Some(8)
    );
    assert_eq!(
        context
            .get_tpm_property(tss_esapi::constants::PropertyTag::Permanent)
            .unwrap()
            .unwrap()
            & (1 << 9),
        0
    );
    sim.command(
        "tpm2_dictionarylockout",
        &[
            "--setup-parameters",
            "--max-tries",
            "9",
            "--recovery-time",
            "86400",
            "--lockout-recovery-time",
            "86400",
        ],
    );
    assert_eq!(native::budget(&mut context).unwrap().maximum(), 9);
    assert_eq!(
        kind(raw_unseal(sim.operation(), &record, &[0x66; 32], false).unwrap_err()),
        Some(Tss2ResponseCodeKind::AuthFail)
    );
    assert_eq!(native::budget(&mut context).unwrap().counter(), 1);
    for _ in 1..9 {
        assert_eq!(
            kind(raw_unseal(sim.operation(), &record, &[0x66; 32], false).unwrap_err()),
            Some(Tss2ResponseCodeKind::AuthFail)
        );
    }
    let locked = native::budget(&mut context).unwrap();
    assert_eq!(locked.counter(), 9);
    assert!(locked.in_lockout);
    assert!(!locked.permits(2));

    // A context that observed lockout must also see an authorized recovery by
    // another client. Only this disposable simulator's global state is changed.
    let mut locked_context = Context::new(sim.operation().endpoint).unwrap();
    assert_ne!(
        locked_context
            .get_tpm_property(tss_esapi::constants::PropertyTag::Permanent)
            .unwrap()
            .unwrap()
            & (1 << 9),
        0
    );
    sim.command("tpm2_dictionarylockout", &["--clear-lockout"]);
    let recovered = native::budget(&mut locked_context).unwrap();
    assert_eq!(recovered.counter(), 0);
    assert!(!recovered.in_lockout);
    assert!(recovered.permits(2));
}

#[test]
#[ignore = "opt-in: starts owned disposable localhost swtpm instances; never opens host TPM"]
fn flexible_credentials_authorize_exact_bytes_with_version_two_metadata() {
    use localpin_core::secret::{CredentialKind, CredentialProfile};

    let sim = Simulator::new();
    sim.command(
        "tpm2_dictionarylockout",
        &[
            "--setup-parameters",
            "--max-tries",
            "8",
            "--recovery-time",
            "86400",
            "--lockout-recovery-time",
            "86400",
        ],
    );
    let budget = localpin_core::limits::ResourceBudget::default();
    let long = [b'Z'; 64];
    for (kind, bytes) in [
        (CredentialKind::NumericPin, b"0001".as_slice()),
        (CredentialKind::NumericPin, b"0000000000000001"),
        (CredentialKind::Passcode, b"  Mixed passcode  "),
        (CredentialKind::Passcode, long.as_slice()),
    ] {
        let secret = Pin::parse(bytes).unwrap();
        let profile = CredentialProfile::for_enrollment(Backend::Tpm2, kind, &secret).unwrap();
        let credential = sim
            .operation()
            .enroll(
                account(),
                generation(),
                &secret,
                &mut permit(&budget),
                &mut FixedRandom(0x11),
            )
            .unwrap()
            .with_profile(profile)
            .unwrap();
        let encoded = credential.encode().unwrap();
        let reopened = CredentialRecord::decode(encoded.expose()).unwrap();
        assert_eq!(reopened.profile(), profile);
        assert_eq!(
            invoke(
                &mut sim.operation().verifier(&reopened, 2),
                bytes,
                KdfParameters::ENROLLMENT
            )
            .0,
            AttemptResponse::Success,
        );
        if kind == CredentialKind::Passcode {
            let mut changed = bytes.to_vec();
            *changed.last_mut().unwrap() = b'0';
            assert_eq!(
                invoke(
                    &mut sim.operation().verifier(&reopened, 2),
                    &changed,
                    KdfParameters::ENROLLMENT
                )
                .0,
                AttemptResponse::Mismatch,
            );
        }
    }
    assert_eq!(sim.budget().counter(), 2);
}

#[test]
#[ignore = "opt-in: starts owned disposable localhost swtpm instances; never opens host TPM"]
fn native_simulator_authorization_identity_budget_and_lifetime() {
    let mut sim = Simulator::new();
    let mut foreign = Simulator::new();
    let proxy = Proxy::new(sim.port);
    sim.command(
        "tpm2_dictionarylockout",
        &[
            "--setup-parameters",
            "--max-tries",
            "8",
            "--recovery-time",
            "86400",
            "--lockout-recovery-time",
            "86400",
        ],
    );
    let budget = localpin_core::limits::ResourceBudget::default();
    let pin = Pin::parse(b"000001").unwrap();
    let credential = proxy
        .operation()
        .enroll(
            account(),
            generation(),
            &pin,
            &mut permit(&budget),
            &mut FixedRandom(0x11),
        )
        .unwrap();
    let record = TpmRecord::from_credential(&credential).unwrap();
    let auth =
        localpin_credentials::derive(&pin, record.salt(), record.parameters(), &permit(&budget))
            .unwrap();
    assert_eq!(sim.budget().counter(), 0);
    assert_eq!(sim.budget().maximum(), 8);
    // Successful protected native authorization is consumed by the same M2
    // reservation/completion API as software, including its held work lease.
    let (response, store) = invoke(
        &mut proxy.operation().verifier(&credential, 2),
        b"000001",
        KdfParameters::ENROLLMENT,
    );
    assert_eq!(response, AttemptResponse::Success);
    assert_eq!(store.record.recent_len, 0);
    // Session wire fields: nonempty salt, unbound HMAC, AES128CFB/SHA256.
    let commands = proxy.packets(true);
    let responses = proxy.packets(false);
    assert_eq!(commands.len(), responses.len());
    let mut live_salted_sessions = std::collections::HashSet::<[u8; 4]>::new();
    let mut create_seen = false;
    let mut unseal_seen = false;
    let mut salted_seen = 0;
    for (command, response) in commands.iter().zip(&responses) {
        let code = u32::from_be_bytes(command[6..10].try_into().unwrap());
        if code == 0x165 {
            live_salted_sessions.remove(&<[u8; 4]>::try_from(&command[10..14]).unwrap());
        }
        if code == 0x176 {
            assert_eq!(&command[14..18], &0x40000007u32.to_be_bytes());
            let nonce = usize::from(u16::from_be_bytes(command[18..20].try_into().unwrap()));
            let salt_length_at = 20 + nonce;
            let salt_length = usize::from(u16::from_be_bytes(
                command[salt_length_at..salt_length_at + 2]
                    .try_into()
                    .unwrap(),
            ));
            // The wrapper's empty-auth primary/load helper uses an unsalted
            // session before the reviewed salting key is available. Candidate
            // create/unseal sessions must instead carry a nonempty salt.
            if command[10..14] == 0x40000007u32.to_be_bytes() {
                assert_eq!(salt_length, 0);
                continue;
            }
            assert!(salt_length > 0);
            let tail = salt_length_at + 2 + salt_length;
            assert_eq!(&command[tail..], &[0, 0, 6, 0, 128, 0, 67, 0, 11]);
            salted_seen += 1;
            assert_eq!(&response[6..10], &[0; 4]);
            live_salted_sessions.insert(response[10..14].try_into().unwrap());
        }
        if code == 0x153 || code == 0x15e {
            let authorizing_session: [u8; 4] = command[18..22].try_into().unwrap();
            assert!(live_salted_sessions.contains(&authorizing_session));
            let nonce = usize::from(u16::from_be_bytes(command[22..24].try_into().unwrap()));
            let flags = command[24 + nonce];
            if code == 0x153 {
                assert_eq!(flags & 0x60, 0x60);
                create_seen = true;
            } else {
                assert_eq!(flags & 0x60, 0x40);
                unseal_seen = true;
            }
        }
    }
    assert!(create_seen && unseal_seen && salted_seen >= 2);
    for bytes in [proxy.bytes(true), proxy.bytes(false)] {
        assert!(
            !bytes
                .windows(32)
                .any(|window| window == auth.expose().as_slice())
        );
        assert!(!bytes.windows(32).any(|window| window == [0x22; 32]));
    }
    // Recording control: synthetic intentionally unprotected raw Unseal exposes
    // its output, establishing that the recorder sees sensitive response bytes.
    proxy.clear();
    let unprotected =
        raw_unseal(proxy.operation(), &record, auth.expose().as_slice(), false).unwrap();
    assert_eq!(unprotected.value(), &[0x22; 32]);
    drop(unprotected);
    assert!(
        proxy
            .bytes(false)
            .windows(32)
            .any(|window| window == [0x22; 32])
    );
    proxy.clear();

    let (refused, consumed) = invoke(
        &mut sim.operation().verifier(&credential, 2),
        b"000001",
        KdfParameters::new(128 * 1024, 3, 1).unwrap(),
    );
    assert!(matches!(refused, AttemptResponse::Unavailable(_)));
    assert_eq!(consumed.record.recent_len, 1);
    assert_eq!(sim.budget().counter(), 0);
    let (response, store) = invoke(
        &mut sim.operation().verifier(&credential, 2),
        b"000002",
        KdfParameters::ENROLLMENT,
    );
    assert_eq!(response, AttemptResponse::Mismatch);
    assert_eq!(store.record.recent_len, 1);
    assert_eq!(sim.budget().counter(), 1);
    assert_eq!(
        native::verify(sim.operation().endpoint, &record, &[], 2),
        Err(Error::Mismatch)
    );
    assert_eq!(sim.budget().counter(), 2);
    assert_eq!(
        kind(raw_unseal(sim.operation(), &record, &[], true).unwrap_err()),
        Some(Tss2ResponseCodeKind::PolicyFail)
    );
    assert_eq!(sim.budget().counter(), 2);

    // No context/session or successful authorization is retained across calls.
    let mut once = sim.operation().verifier(&credential, 2);
    assert_eq!(
        invoke(&mut once, b"000001", KdfParameters::ENROLLMENT).0,
        AttemptResponse::Success
    );
    assert!(matches!(
        invoke(&mut once, b"000001", KdfParameters::ENROLLMENT).0,
        AttemptResponse::Unavailable(_)
    ));
    assert_eq!(sim.budget().counter(), 2);
    sim.stop();
    sim.start(); // same saved seed, fresh resource-manager context
    assert_eq!(
        native::verify(
            sim.operation().endpoint,
            &record,
            auth.expose().as_slice(),
            2
        ),
        Ok(())
    );
    assert_eq!(
        native::verify(
            foreign.operation().endpoint,
            &record,
            auth.expose().as_slice(),
            2
        ),
        Err(Error::Record)
    );
    // Real copied blobs fail native Load on a different TPM even if the caller
    // deliberately skips LocalPIN's earlier parent identity fence.
    {
        let mut ctx = Context::new(foreign.operation().endpoint).unwrap();
        let parent = ctx
            .execute_with_nullauth_session(|ctx| {
                ctx.create_primary(
                    Hierarchy::Owner,
                    native::parent_template().unwrap(),
                    None,
                    None,
                    None,
                    None,
                )
            })
            .unwrap()
            .key_handle;
        let result = ctx.execute_with_nullauth_session(|ctx| {
            ctx.load(parent, record.private.clone(), record.object.clone())
        });
        assert_eq!(
            kind(result.unwrap_err()),
            Some(Tss2ResponseCodeKind::Integrity)
        );
    }
    metadata_rejections(&credential);
    let replacement = native::enroll(
        sim.operation().endpoint,
        account(),
        generation(),
        *record.salt(),
        auth.expose(),
        &[0x44; 32],
    )
    .unwrap();
    assert_ne!(replacement.object_name, record.object_name);
    assert_eq!(
        native::verify(
            sim.operation().endpoint,
            &replacement,
            auth.expose().as_slice(),
            2
        ),
        Ok(())
    );
    // An actual same-template/same-auth substitute's private blob cannot be
    // accepted against the enrolled public/Name, nor a self-consistent name
    // mutation against its public area.
    let mut substituted = TpmRecord::from_credential(&credential).unwrap();
    substituted.private = replacement.private;
    assert_eq!(
        native::verify(
            sim.operation().endpoint,
            &substituted,
            auth.expose().as_slice(),
            2
        ),
        Err(Error::Unavailable)
    );

    while sim.budget().counter() < 6 {
        assert_eq!(
            native::verify(sim.operation().endpoint, &record, &[0x66; 32], 2),
            Err(Error::Mismatch)
        );
    }
    assert_eq!(
        native::verify(
            sim.operation().endpoint,
            &record,
            auth.expose().as_slice(),
            2
        ),
        Err(Error::Budget)
    );
    assert_eq!(sim.budget().counter(), 6);
    while sim.budget().counter() < 8 {
        assert_eq!(
            kind(raw_unseal(sim.operation(), &record, &[0x66; 32], false).unwrap_err()),
            Some(Tss2ResponseCodeKind::AuthFail)
        );
    }
    assert!(!sim.budget().permits(2));
    assert_eq!(
        kind(raw_unseal(sim.operation(), &record, auth.expose().as_slice(), false).unwrap_err()),
        Some(Tss2ResponseCodeKind::Lockout)
    );

    // Provisioned nonempty owner auth is refused based on Permanent, with no
    // empty-auth guess. The separate simulator isolates this from DA lockout.
    foreign.command("tpm2_changeauth", &["-c", "owner", "synthetic-owner"]);
    let before = foreign.budget().counter();
    assert_eq!(
        native::verify(
            foreign.operation().endpoint,
            &record,
            auth.expose().as_slice(),
            2
        ),
        Err(Error::Unavailable)
    );
    assert_eq!(foreign.budget().counter(), before);
    foreign.stop();
    assert_eq!(
        native::verify(
            foreign.operation().endpoint,
            &record,
            auth.expose().as_slice(),
            2
        ),
        Err(Error::Unavailable)
    );
}

fn metadata_rejections(credential: &CredentialRecord) {
    let payload = credential.payload();
    for length in 0..payload.len() {
        if let Ok(short) =
            CredentialRecord::new(account(), generation(), Backend::Tpm2, &payload[..length])
        {
            assert!(TpmRecord::from_credential(&short).is_err());
        }
    }
    for index in [0, 4, 6, 8, 9, 13, 29, 37, 41, 45] {
        let mut changed = payload.to_vec();
        changed[index] ^= 0xff;
        let changed =
            CredentialRecord::new(account(), generation(), Backend::Tpm2, &changed).unwrap();
        assert!(TpmRecord::from_credential(&changed).is_err());
    }
    let mut trailing = payload.to_vec();
    trailing.push(0);
    assert!(
        TpmRecord::from_credential(
            &CredentialRecord::new(account(), generation(), Backend::Tpm2, &trailing).unwrap()
        )
        .is_err()
    );
    let record = TpmRecord::from_credential(credential).unwrap();
    let mut wrong = TpmRecord::from_credential(credential).unwrap();
    wrong.object_name[5] ^= 1;
    assert!(wrong.validate().is_err());
    let mut wrong = TpmRecord::from_credential(credential).unwrap();
    wrong.parent_name[5] ^= 1;
    assert!(wrong.validate().is_err());
    let wrong_outer = CredentialRecord::new(
        account(),
        generation().next().unwrap(),
        Backend::Tpm2,
        payload,
    )
    .unwrap();
    assert!(TpmRecord::from_credential(&wrong_outer).is_err());
    assert_eq!(record.parameters(), KdfParameters::ENROLLMENT);
    // Protecting the entire record is essential: an attacker allowed to replace
    // every public/Name/blob field could replace the authoritative credential.
}
