use super::*;
use localpin_core::eligibility::SessionReference;
use localpin_core::limits::MAX_CONNECTIONS;
use localpin_protocol::RequestEnvelope;
use std::sync::{
    Mutex,
    atomic::{AtomicU64, AtomicUsize, Ordering},
    mpsc,
};

#[derive(Clone, Copy)]
enum Mode {
    Grant,
    CheckDelay,
    ExpiredDelivery,
    WaitForCancel,
    TpmWaitForCancel,
    WrongAccount,
}

struct TestEngine {
    checks: AtomicUsize,
    check_deadlines: Mutex<Vec<Instant>>,
    verifies: AtomicUsize,
    verify_deadlines: Mutex<Option<VerificationDeadlines>>,
    statuses: Mutex<Vec<u32>>,
    recoveries: AtomicUsize,
    session: AtomicUsize,
    mode: Mode,
    started: Mutex<Option<mpsc::Sender<()>>>,
}

impl TestEngine {
    fn new(mode: Mode) -> Arc<Self> {
        Arc::new(Self {
            checks: AtomicUsize::new(0),
            check_deadlines: Mutex::new(Vec::new()),
            verifies: AtomicUsize::new(0),
            verify_deadlines: Mutex::new(None),
            statuses: Mutex::new(Vec::new()),
            recoveries: AtomicUsize::new(0),
            session: AtomicUsize::new(1),
            mode,
            started: Mutex::new(None),
        })
    }
}

impl Engine for TestEngine {
    fn check(&self, peer: Arc<Peer>, deadline: Instant) -> Result<EligibilitySnapshot, Reason> {
        peer.ensure_live().map_err(|_| Reason::Session)?;
        self.checks.fetch_add(1, Ordering::SeqCst);
        self.check_deadlines.lock().unwrap().push(deadline);
        if matches!(self.mode, Mode::CheckDelay) {
            thread::sleep(Duration::from_millis(20));
        }
        let uid = Uid::new(peer.uid()).map_err(|_| Reason::Account)?;
        let uid = if matches!(self.mode, Mode::WrongAccount) {
            Uid::new(uid.get() + 1).unwrap()
        } else {
            uid
        };
        Ok(EligibilitySnapshot::from_trusted_check(
            AccountId {
                uid,
                incarnation: Incarnation::new([1; 16]).unwrap(),
            },
            SessionReference::new([self.session.load(Ordering::SeqCst) as u8; 16]).unwrap(),
        ))
    }

    fn status(&self, peer: Arc<Peer>, _: Instant) -> Status {
        self.statuses.lock().unwrap().push(peer.uid());
        unavailable_status(Reason::None)
    }

    fn challenge(
        &self,
        _: Arc<Peer>,
        _: EligibilitySnapshot,
        _: Instant,
    ) -> Result<VerificationContext, Reason> {
        Ok(VerificationContext {
            generation: 1,
            backend: if matches!(self.mode, Mode::TpmWaitForCancel) {
                localpin_protocol::Backend::Tpm
            } else {
                localpin_protocol::Backend::Software
            },
            profile: localpin_core::secret::CredentialProfile::legacy(),
        })
    }

    fn verify(
        &self,
        peer: Arc<Peer>,
        expected: EligibilitySnapshot,
        context: VerificationContext,
        _: Pin,
        deadlines: VerificationDeadlines,
        cancelled: &mut dyn FnMut() -> bool,
        deliver: &mut dyn FnMut(VerificationOutcome, Instant),
    ) {
        assert_eq!(expected.account().uid.get(), peer.uid());
        assert_eq!(context.generation, 1);
        assert_eq!(
            context.profile,
            localpin_core::secret::CredentialProfile::legacy()
        );
        self.verifies.fetch_add(1, Ordering::SeqCst);
        *self.verify_deadlines.lock().unwrap() = Some(deadlines);
        let deadline = if matches!(self.mode, Mode::TpmWaitForCancel) {
            deadlines.tpm
        } else {
            deadlines.unavailable
        };
        if let Some(started) = self.started.lock().unwrap().take() {
            started.send(()).unwrap();
        }
        if matches!(self.mode, Mode::WaitForCancel | Mode::TpmWaitForCancel) {
            while !cancelled() && Instant::now() < deadline {
                thread::sleep(Duration::from_millis(1));
            }
        }
        // Even a late positive callback must not override queued cancellation.
        let delivery_deadline = if matches!(self.mode, Mode::ExpiredDelivery) {
            Instant::now()
        } else {
            deadline
        };
        deliver(VerificationOutcome::Granted, delivery_deadline);
    }

    fn recover(
        &self,
        peer: &Peer,
        _: Uid,
        _: Id,
        _: Instant,
        deliver: &mut dyn FnMut(Result<(), Reason>),
    ) {
        assert_eq!(peer.uid(), 0);
        self.recoveries.fetch_add(1, Ordering::SeqCst);
        deliver(Ok(()));
    }
}

struct Harness {
    socket: SocketConnection,
    id: Id,
    server: Option<thread::JoinHandle<Result<(), TransportError>>>,
}

impl Harness {
    fn new(engine: Arc<TestEngine>) -> Self {
        Self::with_clock(engine, None)
    }

    fn with_clock(engine: Arc<TestEngine>, millis: Option<Arc<AtomicU64>>) -> Self {
        let (client, server) = UnixStream::pair().unwrap();
        let server = thread::spawn(move || match millis {
            None => serve_connection(server, engine.as_ref()),
            Some(millis) => {
                serve_connection_with_clock(server, engine.as_ref(), &mut TestClock(millis))
            }
        });
        let mut socket = SocketConnection::new(client).unwrap();
        let hello = socket.read_response(deadline()).unwrap();
        assert!(matches!(hello.response, Response::Hello));
        Self {
            socket,
            id: hello.connection,
            server: Some(server),
        }
    }

    fn send(&mut self, request: Request) {
        self.socket
            .write_request(
                &RequestEnvelope {
                    connection: self.id,
                    request,
                },
                deadline(),
            )
            .unwrap();
    }

    fn exchange(&mut self, request: Request) -> Response {
        self.send(request);
        let response = self.socket.read_response(deadline()).unwrap();
        assert_eq!(response.connection, self.id);
        response.response
    }

    fn challenge(&mut self) -> Id {
        match self.exchange(Request::BeginVerify) {
            Response::VerifyChallenge {
                challenge,
                valid_for_ms,
                ..
            } => {
                assert_eq!(valid_for_ms, 5000);
                challenge
            }
            _ => panic!("expected verification challenge"),
        }
    }

    fn finish(mut self) {
        self.socket.close();
        let result = self.server.take().unwrap().join().unwrap();
        assert!(result.is_ok() || matches!(result, Err(TransportError::Protocol(_))));
    }
}

struct TestClock(Arc<AtomicU64>);
impl Clock for TestClock {
    fn now(
        &mut self,
    ) -> Result<localpin_core::types::TimePoint, localpin_core::types::Unavailable> {
        Ok(localpin_core::types::TimePoint {
            boot: localpin_core::types::BootId::new([1; 16]).unwrap(),
            millis: self.0.load(Ordering::SeqCst),
        })
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        self.socket.close();
        if let Some(server) = self.server.take() {
            let _ = server.join();
        }
    }
}

fn deadline() -> Deadline {
    Deadline::after(Duration::from_secs(1))
}
fn pin() -> Pin {
    Pin::parse(b"123456").unwrap()
}
fn ordinary_peer() -> bool {
    rustix::process::getuid().as_raw() != 0
}

#[test]
fn status_uses_only_actual_kernel_uid_and_has_finite_request_count() {
    let engine = TestEngine::new(Mode::Grant);
    let mut client = Harness::new(engine.clone());
    if !ordinary_peer() {
        assert!(matches!(
            client.exchange(Request::Status),
            Response::Error(ErrorCode::Forbidden)
        ));
        assert!(engine.statuses.lock().unwrap().is_empty());
        client.finish();
        return;
    }
    for _ in 0..MAX_REQUESTS {
        assert!(matches!(
            client.exchange(Request::Status),
            Response::Status(_)
        ));
    }
    assert_eq!(
        *engine.statuses.lock().unwrap(),
        vec![rustix::process::getuid().as_raw(); MAX_REQUESTS]
    );
    assert!(client.socket.read_response(deadline()).is_err());
    client.finish();
}

#[test]
fn forged_connection_and_out_of_order_verify_never_reach_engine() {
    let engine = TestEngine::new(Mode::Grant);
    let mut client = Harness::new(engine.clone());
    let mut other = *client.id.as_bytes();
    other[0] ^= 1;
    client
        .socket
        .write_request(
            &RequestEnvelope {
                connection: Id::from_bytes(other).unwrap(),
                request: Request::Status,
            },
            deadline(),
        )
        .unwrap();
    assert!(matches!(
        client.socket.read_response(deadline()).unwrap().response,
        Response::Error(ErrorCode::Protocol)
    ));
    assert!(engine.statuses.lock().unwrap().is_empty());
    client.finish();

    let mut client = Harness::new(engine.clone());
    assert!(matches!(
        client.exchange(Request::Verify {
            challenge: Id::from_bytes([9; 16]).unwrap(),
            pin: pin()
        }),
        Response::Error(_)
    ));
    assert_eq!(engine.verifies.load(Ordering::SeqCst), 0);
    client.finish();
}

#[test]
fn nonroot_cannot_select_another_account_through_recovery() {
    if !ordinary_peer() {
        return;
    }
    let engine = TestEngine::new(Mode::Grant);
    let mut client = Harness::new(engine.clone());
    assert!(matches!(
        client.exchange(Request::RecoverDisable {
            target_uid: rustix::process::getuid().as_raw() + 1
        }),
        Response::Error(ErrorCode::Forbidden)
    ));
    assert_eq!(engine.recoveries.load(Ordering::SeqCst), 0);
    client.finish();
}

#[test]
fn root_kernel_peer_has_only_separate_administrative_recovery_route() {
    if ordinary_peer() {
        return;
    }
    let engine = TestEngine::new(Mode::Grant);
    let mut client = Harness::new(engine.clone());
    assert!(matches!(
        client.exchange(Request::BeginVerify),
        Response::Error(ErrorCode::Forbidden)
    ));
    assert_eq!(engine.verifies.load(Ordering::SeqCst), 0);
    client.finish();
    let mut client = Harness::new(engine.clone());
    assert!(matches!(
        client.exchange(Request::RecoverDisable { target_uid: 1 }),
        Response::Completed(Completion::RecoveryDisabled)
    ));
    assert_eq!(engine.recoveries.load(Ordering::SeqCst), 1);
    client.finish();
}

#[test]
fn status_cannot_carry_a_target_uid_in_trailing_wire_fields() {
    use std::io::Write;
    let engine = TestEngine::new(Mode::Grant);
    let mut client = Harness::new(engine.clone());
    let encoded = localpin_protocol::encode_request(&RequestEnvelope {
        connection: client.id,
        request: Request::Status,
    })
    .unwrap();
    let mut bytes = encoded.as_bytes().to_vec();
    bytes.extend_from_slice(&(rustix::process::getuid().as_raw() + 1).to_be_bytes());
    let body_len = (bytes.len() - 4) as u32;
    bytes[..4].copy_from_slice(&body_len.to_be_bytes());
    let mut stream = client.socket.raw_stream();
    stream.write_all(&bytes).unwrap();
    assert!(client.socket.read_response(deadline()).is_err());
    assert!(engine.statuses.lock().unwrap().is_empty());
    client.finish();
}

#[test]
fn verification_requires_two_live_checks_and_closes_after_one_result() {
    if !ordinary_peer() {
        return;
    }
    let engine = TestEngine::new(Mode::Grant);
    let mut client = Harness::new(engine.clone());
    let challenge = client.challenge();
    assert!(matches!(
        client.exchange(Request::Verify {
            challenge,
            pin: pin()
        }),
        Response::Verification(VerificationOutcome::Granted)
    ));
    assert_eq!(engine.checks.load(Ordering::SeqCst), 2);
    assert_eq!(engine.verifies.load(Ordering::SeqCst), 1);
    assert!(client.socket.read_response(deadline()).is_err());
    client.finish();
}

#[test]
fn verification_keeps_the_deadline_used_for_its_live_check() {
    if !ordinary_peer() {
        return;
    }
    let engine = TestEngine::new(Mode::CheckDelay);
    let mut client = Harness::new(engine.clone());
    let challenge = client.challenge();
    assert!(matches!(
        client.exchange(Request::Verify {
            challenge,
            pin: pin()
        }),
        Response::Verification(VerificationOutcome::Granted)
    ));
    let deadlines = engine.check_deadlines.lock().unwrap();
    assert_eq!(deadlines.len(), 2);
    let verification = engine.verify_deadlines.lock().unwrap().unwrap();
    assert_eq!(verification.unavailable, deadlines[1]);
    assert_eq!(
        verification.tpm,
        deadlines[1] + (TPM_TIMEOUT - UNAVAILABLE_TIMEOUT)
    );
    drop(deadlines);
    client.finish();
}

#[test]
fn tpm_extension_cannot_outlive_the_connection() {
    let unavailable = Instant::now() + UNAVAILABLE_TIMEOUT;
    let lifetime = unavailable + Duration::from_millis(500);
    let deadlines = VerificationDeadlines::for_request(unavailable, lifetime);
    assert_eq!(deadlines.unavailable, unavailable);
    assert_eq!(deadlines.tpm, lifetime);
}

#[test]
fn verification_result_cannot_extend_the_engine_delivery_deadline() {
    if !ordinary_peer() {
        return;
    }
    let engine = TestEngine::new(Mode::ExpiredDelivery);
    let mut client = Harness::new(engine);
    let challenge = client.challenge();
    client.send(Request::Verify {
        challenge,
        pin: pin(),
    });
    assert!(client.socket.read_response(deadline()).is_err());
    client.socket.close();
    assert!(matches!(
        client.server.take().unwrap().join().unwrap(),
        Err(TransportError::Timeout)
    ));
}

#[test]
fn challenge_replay_on_another_connection_and_changed_session_are_denied() {
    if !ordinary_peer() {
        return;
    }
    let engine = TestEngine::new(Mode::Grant);
    let mut first = Harness::new(engine.clone());
    let challenge = first.challenge();
    let mut second = Harness::new(engine.clone());
    assert_ne!(first.id, second.id);
    let own_challenge = second.challenge();
    assert_ne!(challenge, own_challenge);
    assert!(matches!(
        second.exchange(Request::Verify {
            challenge,
            pin: pin()
        }),
        Response::Error(ErrorCode::Protocol)
    ));
    assert_eq!(engine.verifies.load(Ordering::SeqCst), 0);
    second.finish();
    engine.session.store(2, Ordering::SeqCst);
    assert!(matches!(
        first.exchange(Request::Verify {
            challenge,
            pin: pin()
        }),
        Response::Error(ErrorCode::Forbidden)
    ));
    assert_eq!(engine.verifies.load(Ordering::SeqCst), 0);
    first.finish();
}

#[test]
fn cancellation_before_and_during_verify_cannot_deliver_late_grant() {
    if !ordinary_peer() {
        return;
    }
    let engine = TestEngine::new(Mode::Grant);
    let mut client = Harness::new(engine.clone());
    client.challenge();
    assert!(matches!(
        client.exchange(Request::Cancel),
        Response::Cancelled
    ));
    assert_eq!(engine.verifies.load(Ordering::SeqCst), 0);
    client.finish();

    let engine = TestEngine::new(Mode::WaitForCancel);
    let (started, receiver) = mpsc::channel();
    *engine.started.lock().unwrap() = Some(started);
    let mut client = Harness::new(engine.clone());
    let challenge = client.challenge();
    client.send(Request::Verify {
        challenge,
        pin: pin(),
    });
    receiver.recv_timeout(Duration::from_secs(1)).unwrap();
    assert!(matches!(
        client.exchange(Request::Cancel),
        Response::Cancelled
    ));
    assert_eq!(engine.verifies.load(Ordering::SeqCst), 1);
    client.finish();
}

#[test]
fn cancellation_after_ordinary_timeout_acknowledges_the_tpm_exchange() {
    if !ordinary_peer() {
        return;
    }
    let engine = TestEngine::new(Mode::TpmWaitForCancel);
    let (started, receiver) = mpsc::channel();
    *engine.started.lock().unwrap() = Some(started);
    let mut client = Harness::new(engine.clone());
    let challenge = client.challenge();
    client.send(Request::Verify {
        challenge,
        pin: pin(),
    });
    receiver.recv_timeout(Duration::from_secs(1)).unwrap();
    thread::sleep(UNAVAILABLE_TIMEOUT + Duration::from_millis(50));
    assert!(matches!(
        client.exchange(Request::Cancel),
        Response::Cancelled
    ));
    client.finish();
}

#[test]
fn snapshot_of_another_uid_never_issues_challenge() {
    if !ordinary_peer() {
        return;
    }
    let engine = TestEngine::new(Mode::WrongAccount);
    let mut client = Harness::new(engine.clone());
    assert!(matches!(
        client.exchange(Request::BeginVerify),
        Response::Error(ErrorCode::Forbidden)
    ));
    assert_eq!(engine.verifies.load(Ordering::SeqCst), 0);
    client.finish();
}

#[test]
fn expired_challenge_cannot_start_backend_without_waiting_for_real_time() {
    if !ordinary_peer() {
        return;
    }
    let engine = TestEngine::new(Mode::Grant);
    let millis = Arc::new(AtomicU64::new(0));
    let mut client = Harness::with_clock(engine.clone(), Some(millis.clone()));
    let challenge = client.challenge();
    millis.store(5000, Ordering::SeqCst);
    assert!(matches!(
        client.exchange(Request::Verify {
            challenge,
            pin: pin()
        }),
        Response::Error(ErrorCode::Expired)
    ));
    assert_eq!(engine.verifies.load(Ordering::SeqCst), 0);
    client.finish();
}

#[test]
fn connection_admission_is_exact_and_releases_after_disconnect() {
    let engine = TestEngine::new(Mode::Grant);
    let budget = ResourceBudget::default();
    let broker = Broker::new(engine, budget.clone());
    let permits: Vec<_> = (0..MAX_CONNECTIONS)
        .map(|_| budget.try_connection().unwrap())
        .collect();
    let (client, server) = UnixStream::pair().unwrap();
    assert_eq!(
        broker.accept(server).unwrap_err().kind(),
        io::ErrorKind::WouldBlock
    );
    drop(client);
    drop(permits);
    let (client, server) = UnixStream::pair().unwrap();
    broker.accept(server).unwrap();
    let mut client = SocketConnection::new(client).unwrap();
    assert!(matches!(
        client.read_response(deadline()).unwrap().response,
        Response::Hello
    ));
    let permits: Vec<_> = (0..MAX_CONNECTIONS - 1)
        .map(|_| budget.try_connection().unwrap())
        .collect();
    assert!(budget.try_connection().is_err());
    client.close();
    let until = Instant::now() + Duration::from_secs(1);
    while budget.try_connection().is_err() {
        assert!(Instant::now() < until);
        thread::sleep(Duration::from_millis(1));
    }
    drop(permits);
}
