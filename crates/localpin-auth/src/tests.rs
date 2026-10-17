//! Synthetic private-process and pure-core tests. No host authentication occurs.
use super::*;
use localpin_core::{
    enrollment::{
        CommittedState, EnrollmentAction, EnrollmentMachine, LifecycleAuthority, LifecycleError,
        PasswordWorker, PasswordWorkerRequest,
    },
    types::{
        AccountId, Backend, BootId, Clock, ConnectionId, Generation, Incarnation, TimePoint,
        TransactionId, Uid, Unavailable,
    },
};
use std::{
    path::PathBuf,
    sync::{Arc, Barrier},
    thread,
};

fn time(millis: u64) -> TimePoint {
    TimePoint {
        boot: BootId::new([1; 16]).unwrap(),
        millis,
    }
}
struct TrustedClock {
    before: TimePoint,
    after: TimePoint,
    calls: usize,
}
impl Clock for TrustedClock {
    fn now(&mut self) -> Result<TimePoint, Unavailable> {
        self.calls += 1;
        Ok(if self.calls == 1 {
            self.before
        } else {
            self.after
        })
    }
}
fn clock() -> TrustedClock {
    TrustedClock {
        before: time(100),
        after: time(101),
        calls: 0,
    }
}
struct Lifecycle;
impl LifecycleAuthority for Lifecycle {
    fn current_incarnation(&mut self, _: Uid) -> Result<Incarnation, LifecycleError> {
        Ok(Incarnation::new([1; 16]).unwrap())
    }
}
struct Capture(Option<PasswordWorkerRequest>);
impl PasswordWorker for Capture {
    fn verify_existing_password(
        &mut self,
        request: PasswordWorkerRequest,
    ) -> Result<TimePoint, PasswordWorkerError> {
        self.0 = Some(request);
        Err(PasswordWorkerError::Cancelled)
    }
}
fn request(uid: u32) -> PasswordWorkerRequest {
    let account = AccountId {
        uid: Uid::new(uid).unwrap(),
        incarnation: Incarnation::new([1; 16]).unwrap(),
    };
    let mut machine = EnrollmentMachine::new(CommittedState::new(
        account,
        Generation::new(1).unwrap(),
        None,
    ));
    let connection = ConnectionId::new([2; 16]).unwrap();
    let binding = machine
        .begin_own_user(
            connection,
            account.uid,
            TransactionId::new([3; 16]).unwrap(),
            EnrollmentAction::Enroll(Backend::Software),
            time(100),
            &mut Lifecycle,
        )
        .unwrap();
    let mut capture = Capture(None);
    let _ = machine.authorize_with_password_worker(
        binding,
        connection,
        time(100),
        &mut capture,
        &mut Lifecycle,
    );
    capture.0.unwrap()
}

struct Answer {
    cancelled: bool,
    calls: usize,
    barrier: Option<Arc<Barrier>>,
    password: Vec<u8>,
}
impl Default for Answer {
    fn default() -> Self {
        Self {
            cancelled: false,
            calls: 0,
            barrier: None,
            password: b"synthetic password".to_vec(),
        }
    }
}
impl Conversation for Answer {
    fn password(&mut self, prompt: PasswordPrompt) -> Result<SecretBytes, PasswordWorkerError> {
        assert_eq!(prompt.style, PromptStyle::EchoOff);
        assert_eq!(prompt.text, "Existing account password: ");
        self.calls += 1;
        if let Some(barrier) = &self.barrier {
            barrier.wait();
            thread::sleep(Duration::from_millis(100));
        }
        SecretBytes::from_slice(&self.password, MAX_PASSWORD_BYTES)
            .map_err(|_| PasswordWorkerError::Rejected)
    }
    fn cancelled(&mut self) -> bool {
        self.cancelled
    }
}

const CHILD: &str = r#"
import os, struct, sys, time
mode = sys.argv[1]
def exact(n):
    b = b''
    while len(b) < n:
        p = os.read(0, n-len(b))
        if not p: sys.exit(1)
        b += p
    return b
r = exact(105)
token = r[4:20]
def frame(kind, sequence, data=b'', nonce=token):
    os.write(1, bytes([kind])+nonce+struct.pack('!IH', sequence, len(data))+data)
if mode == 'crash': sys.exit(7)
if mode == 'stall': time.sleep(10); sys.exit(0)
if mode == 'unprompted': frame(3, 2, b'\0'); sys.exit(0)
frame(1, 1)
h = exact(23)
data = exact(struct.unpack('!H', h[21:23])[0])
if mode == 'replay': frame(3, 2, b'\0', bytes([9])*16); sys.exit(0)
if mode == 'duplicate_prompt': frame(1, 1); sys.exit(0)
if mode == 'late': time.sleep(1)
code = b'\1' if mode == 'wrong' or data != b'synthetic password' else b'\0'
frame(3, 2, code)
if mode == 'duplicate_result': frame(3, 2, code)
"#;

fn supervisor(mode: &str, timeout: Duration) -> PasswordSupervisor {
    // Fixture arguments contain only synthetic script/mode; production has no
    // argument injection, environment injection or alternate policy selector.
    supervisor::fixture(
        PathBuf::from("/usr/bin/python3"),
        vec!["-c".into(), CHILD.into(), mode.into()],
        timeout,
    )
}

fn verify(mode: &str) -> Result<TimePoint, PasswordWorkerError> {
    supervisor(mode, Duration::from_secs(2))
        .bind(&mut Answer::default(), &mut clock())
        .verify_existing_password(request(1000))
}

#[test]
fn native_process_completion_is_bound_private_and_stamped_by_trusted_clock() {
    assert_eq!(verify("success"), Ok(time(101)));
    assert_eq!(verify("wrong"), Err(PasswordWorkerError::Rejected));
}

#[test]
fn crash_replay_unprompted_and_duplicate_messages_cannot_authenticate() {
    for mode in [
        "crash",
        "replay",
        "unprompted",
        "duplicate_prompt",
        "duplicate_result",
    ] {
        assert_eq!(
            verify(mode),
            Err(PasswordWorkerError::Unavailable),
            "{mode}"
        );
    }
}

#[test]
fn stale_password_and_boot_or_time_anomalies_cannot_authenticate() {
    let supervisor = supervisor("success", Duration::from_secs(2));
    for (before, after, expected) in [
        (time(60_100), time(60_101), PasswordWorkerError::TimedOut),
        (time(99), time(101), PasswordWorkerError::Unavailable),
        (time(100), time(99), PasswordWorkerError::Unavailable),
        (time(100), time(60_100), PasswordWorkerError::TimedOut),
        (
            time(100),
            TimePoint {
                boot: BootId::new([2; 16]).unwrap(),
                millis: 101,
            },
            PasswordWorkerError::Unavailable,
        ),
    ] {
        let mut clock = TrustedClock {
            before,
            after,
            calls: 0,
        };
        assert_eq!(
            supervisor
                .bind(&mut Answer::default(), &mut clock)
                .verify_existing_password(request(1000)),
            Err(expected)
        );
    }
}

#[test]
fn cancellation_and_hard_native_deadline_retire_and_reap_the_worker() {
    let supervisor = supervisor("stall", Duration::from_millis(80));
    let started = BootInstant::now();
    assert_eq!(
        supervisor
            .bind(&mut Answer::default(), &mut clock())
            .verify_existing_password(request(1000)),
        Err(PasswordWorkerError::TimedOut)
    );
    assert!(started.elapsed() < Duration::from_secs(1));
    let until = BootInstant::now() + Duration::from_secs(2);
    while supervisor.occupied() > 0 && BootInstant::now() < until {
        thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(supervisor.occupied(), 0);
    let mut cancelled = Answer {
        cancelled: true,
        ..Answer::default()
    };
    assert_eq!(
        supervisor
            .bind(&mut cancelled, &mut clock())
            .verify_existing_password(request(1000)),
        Err(PasswordWorkerError::Cancelled)
    );
    assert_eq!(cancelled.calls, 0);
}

#[test]
fn cancellation_during_a_native_stall_kills_the_running_worker() {
    struct CancelAt(BootInstant);
    impl Conversation for CancelAt {
        fn password(&mut self, _: PasswordPrompt) -> Result<SecretBytes, PasswordWorkerError> {
            Err(PasswordWorkerError::Cancelled)
        }
        fn cancelled(&mut self) -> bool {
            BootInstant::now() >= self.0
        }
    }
    let supervisor = supervisor("stall", Duration::from_secs(2));
    let started = BootInstant::now();
    let mut conversation = CancelAt(started + Duration::from_millis(40));
    assert_eq!(
        supervisor
            .bind(&mut conversation, &mut clock())
            .verify_existing_password(request(1000)),
        Err(PasswordWorkerError::Cancelled)
    );
    assert!(started.elapsed() < Duration::from_millis(500));
    let until = BootInstant::now() + Duration::from_secs(2);
    while supervisor.occupied() > 0 && BootInstant::now() < until {
        thread::sleep(Duration::from_millis(2));
    }
    assert_eq!(supervisor.occupied(), 0);
}

#[test]
fn late_native_success_and_nul_or_empty_password_are_rejected() {
    let delayed = supervisor("late", Duration::from_millis(80));
    assert_eq!(
        delayed
            .bind(&mut Answer::default(), &mut clock())
            .verify_existing_password(request(1000)),
        Err(PasswordWorkerError::TimedOut)
    );
    for password in [vec![], b"synthetic\0password".to_vec()] {
        let supervisor = supervisor("success", Duration::from_secs(1));
        let mut answer = Answer {
            password,
            ..Answer::default()
        };
        assert_eq!(
            supervisor
                .bind(&mut answer, &mut clock())
                .verify_existing_password(request(1000)),
            Err(PasswordWorkerError::Rejected)
        );
    }
}

#[test]
fn old_request_receives_only_its_remaining_native_budget() {
    let supervisor = supervisor("stall", Duration::from_secs(2));
    let mut clock = TrustedClock {
        before: time(60_050),
        after: time(60_051),
        calls: 0,
    };
    let started = BootInstant::now();
    assert_eq!(
        supervisor
            .bind(&mut Answer::default(), &mut clock)
            .verify_existing_password(request(1000)),
        Err(PasswordWorkerError::TimedOut)
    );
    assert!(started.elapsed() < Duration::from_millis(500));
}

#[test]
fn shared_capacity_blocks_second_same_uid_without_blocking_unrelated_uid() {
    let supervisor = supervisor("success", Duration::from_secs(2));
    let barrier = Arc::new(Barrier::new(2));
    let task = {
        let supervisor = supervisor.clone();
        let barrier = barrier.clone();
        thread::spawn(move || {
            supervisor
                .bind(
                    &mut Answer {
                        barrier: Some(barrier),
                        ..Answer::default()
                    },
                    &mut clock(),
                )
                .verify_existing_password(request(1000))
        })
    };
    barrier.wait();
    assert_eq!(supervisor.occupied(), 1);
    assert_eq!(
        supervisor
            .bind(&mut Answer::default(), &mut clock())
            .verify_existing_password(request(1000)),
        Err(PasswordWorkerError::Unavailable)
    );
    assert_eq!(
        supervisor
            .bind(&mut Answer::default(), &mut clock())
            .verify_existing_password(request(1001)),
        Ok(time(101))
    );
    assert_eq!(task.join().unwrap(), Ok(time(101)));
}

#[test]
fn global_capacity_bounds_native_stalls_across_unrelated_uids() {
    let supervisor = supervisor("stall", Duration::from_millis(400));
    let tasks: Vec<_> = (0..MAX_PASSWORD_WORKERS)
        .map(|index| {
            let supervisor = supervisor.clone();
            thread::spawn(move || {
                supervisor
                    .bind(&mut Answer::default(), &mut clock())
                    .verify_existing_password(request(2000 + index as u32))
            })
        })
        .collect();
    let until = BootInstant::now() + Duration::from_millis(250);
    while supervisor.occupied() < MAX_PASSWORD_WORKERS && BootInstant::now() < until {
        thread::sleep(Duration::from_millis(2));
    }
    assert_eq!(supervisor.occupied(), MAX_PASSWORD_WORKERS);
    assert_eq!(
        supervisor
            .bind(&mut Answer::default(), &mut clock())
            .verify_existing_password(request(3000)),
        Err(PasswordWorkerError::Unavailable)
    );
    for task in tasks {
        assert_eq!(task.join().unwrap(), Err(PasswordWorkerError::TimedOut));
    }
    let until = BootInstant::now() + Duration::from_secs(2);
    while supervisor.occupied() > 0 && BootInstant::now() < until {
        thread::sleep(Duration::from_millis(2));
    }
    assert_eq!(supervisor.occupied(), 0);
}

#[test]
fn private_worker_requires_password_and_exact_answer_binding() {
    let request = request(1000);
    for (token, sequence, password, expected) in [
        ([8; 16], 1, b"synthetic password".as_slice(), 0),
        ([9; 16], 1, b"synthetic password".as_slice(), 2),
        ([8; 16], 2, b"synthetic password".as_slice(), 2),
        ([8; 16], 1, b"wrong".as_slice(), 1),
    ] {
        let mut input = ipc::Request::encode(request, [8; 16]).to_vec();
        ipc::write_frame(&mut input, ipc::ANSWER, &token, sequence, password).unwrap();
        let mut output = Vec::new();
        serve(&mut input.as_slice(), &mut output, |uid, prompt| {
            assert_eq!(uid, 1000);
            let password = prompt().map_err(|_| PasswordWorkerError::Unavailable)?;
            if password.expose() == b"synthetic password" {
                Ok(())
            } else {
                Err(PasswordWorkerError::Rejected)
            }
        })
        .unwrap();
        let mut reader = output.as_slice();
        let prompt = ipc::read_frame(&mut reader).unwrap();
        assert_eq!(prompt.kind, ipc::PROMPT);
        let result = ipc::read_frame(&mut reader).unwrap();
        assert_eq!(result.payload.expose(), &[expected]);
    }
    let mut output = Vec::new();
    serve(
        &mut ipc::Request::encode(request, [8; 16]).as_slice(),
        &mut output,
        |_, _| Ok(()),
    )
    .unwrap();
    assert_eq!(
        ipc::read_frame(&mut output.as_slice())
            .unwrap()
            .payload
            .expose(),
        &[2]
    );
}

#[test]
fn private_frames_refuse_oversize_unknown_types_and_invalid_account_binding() {
    let mut encoded = Vec::new();
    ipc::write_frame(&mut encoded, ipc::ANSWER, &[1; 16], 1, b"synthetic").unwrap();
    assert!(ipc::decode(&encoded[..10]).unwrap().is_none());
    encoded[21..23].copy_from_slice(&513u16.to_be_bytes());
    assert!(ipc::decode(&encoded).is_err());
    encoded[0] = 99;
    assert!(ipc::decode(&encoded).is_err());
    let mut encoded = ipc::Request::encode(request(1000), [8; 16]);
    encoded[20..24].copy_from_slice(&0u32.to_be_bytes());
    assert!(ipc::Request::read(&mut encoded.as_slice()).is_err());
}

#[test]
fn production_helper_configuration_requires_trusted_absolute_installation() {
    assert!(PasswordSupervisor::new("relative/helper").is_err());
    assert!(PasswordSupervisor::new("/tmp/localpin-auth-worker").is_err());
}
