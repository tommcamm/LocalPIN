//! Opt-in real TPM/storage integration against an owned disposable simulator.
//! The parent owns the simulator and bounds all native work in a child process.

use super::*;
use localpin_credentials::OsRandom;
use localpin_tpm::{NativeOperation, TpmRecord};
use std::net::{Ipv4Addr, TcpListener, TcpStream};

const CHILD_PORT: &str = "LOCALPIN_STORAGE_TPM_TEST_PORT";

struct Simulator(Child);

impl Drop for Simulator {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let deadline = Instant::now() + Duration::from_secs(2);
        while self.0.try_wait().unwrap().is_none() && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(10));
        }
        assert!(
            self.0.try_wait().unwrap().is_some(),
            "simulator did not exit"
        );
    }
}

fn wait_bounded(child: &mut Child, timeout: Duration) -> std::process::ExitStatus {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            return status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let reap_deadline = Instant::now() + Duration::from_secs(2);
            while child.try_wait().unwrap().is_none() && Instant::now() < reap_deadline {
                thread::sleep(Duration::from_millis(10));
            }
            panic!("disposable TPM test child exceeded its deadline");
        }
        thread::sleep(Duration::from_millis(10));
    }
}

fn available_port_pair() -> u16 {
    for _ in 0..64 {
        let server = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = server.local_addr().unwrap().port();
        if port < u16::MAX
            && let Ok(control) = TcpListener::bind((Ipv4Addr::LOCALHOST, port + 1))
        {
            drop(control);
            drop(server);
            return port;
        }
    }
    panic!("no disposable simulator TCP port pair available");
}

fn operation(port: u16) -> NativeOperation {
    NativeOperation::simulator(port).unwrap()
}

fn tpm_attempt(
    store: &mut UserStore<'_>,
    pin: &[u8],
    now: TimePoint,
    budget: &ResourceBudget,
    calls: &AtomicUsize,
    port: u16,
) -> Result<AttemptResponse> {
    let state = store.committed_state()?;
    let credential = store.credential()?;
    let parameters = TpmRecord::from_credential(&credential)
        .map_err(|_| Error::Corrupt)?
        .parameters();
    store.with_throttle(now, |machine, store| {
        let reserved = machine
            .reserve(now)
            .map_err(|_| Error::Time)?
            .commit(store)
            .map_err(|_| Error::Uncertain)?;
        let persisted = store.read_throttle(state)?;
        assert_eq!(persisted.pending.unwrap().attempt, reserved.id().get());
        let work = budget
            .try_work(state.account().uid, parameters, WorkKind::TpmPinDerivation)
            .unwrap();
        let job = VerificationJob::new(
            reserved,
            Backend::Tpm2,
            Pin::parse(pin).unwrap(),
            work,
            parameters,
        )
        .unwrap();
        calls.fetch_add(1, Ordering::SeqCst);
        let completion = operation(port)
            .verifier(&credential, 2)
            .verify(job)
            .complete(now)
            .map_err(|_| Error::Time)?;
        assert!(store.read_throttle(state)?.pending.is_some());
        completion
            .commit(store, state.account(), Some(state.generation()))
            .map_err(|_| Error::Uncertain)
    })
}

fn run_storage_scenario(port: u16) {
    let fixture = Fixture::new();
    let account = account(1000);
    fixture.initialized(account);
    let budget = ResourceBudget::default();
    let mut authority = Authority(account.incarnation);
    let mut store = fixture.storage.user(account.uid, &mut authority).unwrap();
    let mut model = EnrollmentMachine::new(store.committed_state().unwrap());
    let connection = ConnectionId::new([3; 16]).unwrap();
    let binding = model
        .begin_own_user(
            connection,
            account.uid,
            TransactionId::new([4; 16]).unwrap(),
            EnrollmentAction::Enroll(Backend::Tpm2),
            time(10),
            &mut store.lifecycle(),
        )
        .unwrap();
    model
        .authorize_with_password_worker(
            binding,
            connection,
            time(10),
            &mut Password,
            &mut store.lifecycle(),
        )
        .unwrap();
    model
        .staged_created(binding, connection, time(10), &mut store.lifecycle())
        .unwrap();
    let pin = Pin::parse(b"000001").unwrap();
    let mut work = budget
        .try_work(
            account.uid,
            KdfParameters::ENROLLMENT,
            WorkKind::TpmPinDerivation,
        )
        .unwrap();
    let credential = operation(port)
        .enroll(
            account,
            binding.proposed_generation(),
            &pin,
            &mut work,
            &mut OsRandom,
        )
        .unwrap();
    let expected = credential.encode().unwrap();
    let stage = store
        .stage_credential(credential, |persisted| {
            assert_eq!(persisted.encode().unwrap().expose(), expected.expose());
            operation(port)
                .trial_verify(persisted, &pin, &mut work, 2)
                .map_err(|_| Error::Corrupt)
        })
        .unwrap();
    drop(work);
    model
        .staged_verified(binding, connection, time(10), &mut store.lifecycle())
        .unwrap();
    let intent = model
        .prepare_commit(binding, connection, time(10), &mut store.lifecycle())
        .unwrap();
    let state = store
        .commit_generation(intent, Some(stage), &mut FixedClock(time(10)))
        .unwrap();
    model
        .acknowledge_durable_commit(intent, connection, time(10), &mut store.lifecycle())
        .unwrap();
    let calls = AtomicUsize::new(0);
    assert_eq!(
        tpm_attempt(&mut store, b"000001", time(100), &budget, &calls, port).unwrap(),
        AttemptResponse::Success
    );
    let matched = store.read_throttle(state).unwrap();
    assert!(matched.pending.is_none());
    assert_eq!(matched.recent_len, 0);
    assert_eq!(
        tpm_attempt(&mut store, b"000002", time(101), &budget, &calls, port).unwrap(),
        AttemptResponse::Mismatch
    );
    assert_eq!(store.read_throttle(state).unwrap().recent_len, 1);

    store.set_fault_injector(FailAt::boxed(Boundary::DirectorySynced, 1));
    assert!(tpm_attempt(&mut store, b"000001", time(102), &budget, &calls, port).is_err());
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    assert_eq!(store.committed_state(), Err(Error::Uncertain));
    drop(store);
    let mut store = fixture.storage.user(account.uid, &mut authority).unwrap();
    store.with_throttle(time(103), |_, _| Ok(())).unwrap();
    assert_eq!(store.read_throttle(state).unwrap().recent_len, 2);

    store.set_fault_injector(FailAt::boxed(Boundary::DirectorySynced, 2));
    assert!(tpm_attempt(&mut store, b"000001", time(104), &budget, &calls, port).is_err());
    assert_eq!(calls.load(Ordering::SeqCst), 3);
    assert_eq!(store.committed_state(), Err(Error::Uncertain));
    drop(store);
    let mut store = fixture.storage.user(account.uid, &mut authority).unwrap();
    let committed_reset = store.read_throttle(state).unwrap();
    assert!(committed_reset.pending.is_none());
    assert_eq!(committed_reset.last_attempt, 4);
    assert_eq!(committed_reset.recent_len, 0);

    let credential = store.credential().unwrap();
    let disable = authorized_intent(
        state,
        EnrollmentAction::Disable,
        time(106),
        account.incarnation,
    );
    store
        .with_throttle(time(105), |machine, store| {
            let reserved = machine.reserve(time(105)).unwrap().commit(store).unwrap();
            let work = budget
                .try_work(
                    account.uid,
                    KdfParameters::ENROLLMENT,
                    WorkKind::TpmPinDerivation,
                )
                .unwrap();
            let job = VerificationJob::new(
                reserved,
                Backend::Tpm2,
                Pin::parse(b"000001").unwrap(),
                work,
                KdfParameters::ENROLLMENT,
            )
            .unwrap();
            let completion = operation(port)
                .verifier(&credential, 2)
                .verify(job)
                .complete(time(105))
                .unwrap();
            assert_eq!(completion.record().recent_len, 0);
            store
                .commit_generation(disable, None, &mut FixedClock(time(106)))
                .unwrap();
            assert!(
                completion
                    .commit(store, account, Some(state.generation()))
                    .is_err()
            );
            Ok(())
        })
        .unwrap();
    assert_eq!(store.committed_state().unwrap(), disable.next());
    assert!(matches!(store.credential(), Err(Error::Disabled)));
    assert!(tpm_attempt(&mut store, b"000001", time(107), &budget, &calls, port).is_err());
    assert_eq!(calls.load(Ordering::SeqCst), 3);
}

#[test]
#[ignore = "opt-in: starts only an owned localhost swtpm and never a hardware TPM"]
fn tpm_backend_obeys_durable_storage_and_revocation() {
    if let Ok(port) = std::env::var(CHILD_PORT) {
        run_storage_scenario(port.parse().unwrap());
        return;
    }
    let fixture = Fixture::new();
    let simulator_dir = fixture.path.join("simulator");
    DirBuilder::new()
        .mode(0o700)
        .create(&simulator_dir)
        .unwrap();
    let port = available_port_pair();
    let mut simulator = Simulator(
        Command::new("swtpm")
            .args(["socket", "--tpm2", "--tpmstate"])
            .arg(format!("dir={}", simulator_dir.display()))
            .arg("--ctrl")
            .arg(format!("type=tcp,port={},bindaddr=127.0.0.1", port + 1))
            .arg("--server")
            .arg(format!("type=tcp,port={port},bindaddr=127.0.0.1"))
            .args(["--flags", "not-need-init,startup-clear"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let ready_deadline = Instant::now() + Duration::from_secs(5);
    loop {
        assert!(
            simulator.0.try_wait().unwrap().is_none(),
            "simulator exited"
        );
        if TcpStream::connect((Ipv4Addr::LOCALHOST, port)).is_ok() {
            break;
        }
        assert!(Instant::now() < ready_deadline, "simulator did not start");
        thread::sleep(Duration::from_millis(10));
    }
    // Change policy only on this exclusively owned synthetic TPM, allowing a
    // real mismatch without exhausting the reserve needed by later assertions.
    let mut setup = Command::new("tpm2_dictionarylockout")
        .arg("-T")
        .arg(format!("swtpm:host=127.0.0.1,port={port}"))
        .args([
            "--setup-parameters",
            "--max-tries=8",
            "--recovery-time=1000",
            "--lockout-recovery-time=1000",
        ])
        .spawn()
        .unwrap();
    assert!(wait_bounded(&mut setup, Duration::from_secs(5)).success());
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "tests::tpm_backend::tpm_backend_obeys_durable_storage_and_revocation",
            "--ignored",
            "--nocapture",
        ])
        .env(CHILD_PORT, port.to_string())
        .spawn()
        .unwrap();
    assert!(wait_bounded(&mut child, Duration::from_secs(90)).success());
}
