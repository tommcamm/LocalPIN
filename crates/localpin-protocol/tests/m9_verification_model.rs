//! Exhaustive bounded traces against a separate verification-connection model.
//! This tests protocol sequencing, not credential, durability, or PAM correctness.

use localpin_core::secret::Pin;
use localpin_protocol::*;

use Event::*;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Event {
    StatusRequest,
    Begin,
    Submit,
    WrongChallenge,
    Grant,
    Mismatch,
    Cancel,
    DeniedBegin,
    DeniedSubmit,
    DeniedGrant,
    Close,
    RollbackStatus,
    ExpiredStatus,
    WrongConnectionStatus,
}

#[derive(Clone, Copy)]
enum State {
    Idle,
    Challenge(u64),
    Verifying(u64),
    Finished,
}

#[derive(Debug, Eq, PartialEq)]
enum Outcome {
    Status,
    Challenge,
    Verify,
    Cancel,
    Verification(VerificationOutcome),
    Closed,
    Error(ProtocolError),
}

struct Model {
    state: State,
    last_now: u64,
}

impl Model {
    fn step(&mut self, event: Event, now: u64) -> Outcome {
        if event == Close {
            self.state = State::Finished;
            return Outcome::Closed;
        }
        let result = self.evaluate(event, now);
        if matches!(result, Outcome::Error(_)) || matches!(event, Grant | Mismatch | DeniedGrant) {
            self.state = State::Finished;
        }
        result
    }

    fn evaluate(&mut self, event: Event, now: u64) -> Outcome {
        if now < self.last_now {
            return Outcome::Error(ProtocolError::Clock);
        }
        self.last_now = now;
        if matches!(self.state, State::Challenge(expires) | State::Verifying(expires) if now >= expires)
        {
            return Outcome::Error(ProtocolError::Expired);
        }
        // Trusted completion callbacks enforce their own state and eligibility.
        if matches!(event, Grant | Mismatch | DeniedGrant) {
            return if matches!(self.state, State::Verifying(_)) {
                match event {
                    Grant => Outcome::Verification(VerificationOutcome::Granted),
                    Mismatch => Outcome::Verification(VerificationOutcome::Mismatch),
                    _ => Outcome::Error(ProtocolError::Forbidden),
                }
            } else {
                Outcome::Error(ProtocolError::OutOfOrder)
            };
        }
        if event == WrongConnectionStatus {
            return Outcome::Error(ProtocolError::Binding);
        }
        if matches!(self.state, State::Finished) {
            return Outcome::Error(ProtocolError::OutOfOrder);
        }
        match (self.state, event) {
            (State::Idle, StatusRequest | RollbackStatus | ExpiredStatus) => Outcome::Status,
            (State::Idle, Begin) => {
                self.state = State::Challenge(now + VERIFY_LIFETIME_MS);
                Outcome::Challenge
            }
            (State::Idle, DeniedBegin) => Outcome::Error(ProtocolError::Forbidden),
            (State::Challenge(_), Submit) => {
                self.state = State::Verifying(now + VERIFY_LIFETIME_MS);
                Outcome::Verify
            }
            (State::Challenge(_), WrongChallenge) => Outcome::Error(ProtocolError::Binding),
            (State::Challenge(_), DeniedSubmit) => Outcome::Error(ProtocolError::Forbidden),
            (State::Challenge(_) | State::Verifying(_), Cancel) => {
                self.state = State::Finished;
                Outcome::Cancel
            }
            _ => Outcome::Error(ProtocolError::OutOfOrder),
        }
    }
}

fn id(value: u8) -> Id {
    Id::from_bytes([value; 16]).unwrap()
}

fn actual(connection: &mut Connection, event: Event, now: u64) -> Outcome {
    if event == Close {
        connection.close();
        return Outcome::Closed;
    }
    if matches!(event, Grant | Mismatch | DeniedGrant) {
        return match connection.finish_verification(
            if event == Mismatch {
                VerificationOutcome::Mismatch
            } else {
                VerificationOutcome::Granted
            },
            if event == DeniedGrant {
                Eligibility::Denied
            } else {
                Eligibility::Eligible
            },
            now,
        ) {
            Ok(ResponseEnvelope {
                response: Response::Verification(outcome),
                ..
            }) => Outcome::Verification(outcome),
            Ok(_) => panic!("unexpected completion response"),
            Err(error) => Outcome::Error(error),
        };
    }
    let request = match event {
        StatusRequest | RollbackStatus | ExpiredStatus | WrongConnectionStatus => Request::Status,
        Begin | DeniedBegin => Request::BeginVerify,
        Submit | WrongChallenge | DeniedSubmit => Request::Verify {
            challenge: id(if event == WrongChallenge { 3 } else { 2 }),
            pin: Pin::parse(b"000001").unwrap(),
        },
        Cancel => Request::Cancel,
        _ => unreachable!(),
    };
    let result = connection.accept(
        RequestEnvelope {
            connection: id(if event == WrongConnectionStatus { 9 } else { 1 }),
            request,
        },
        now,
        if matches!(event, DeniedBegin | DeniedSubmit) {
            Eligibility::Denied
        } else {
            Eligibility::Eligible
        },
        matches!(event, Begin | DeniedBegin).then_some(Issued::Verify(id(2))),
    );
    match result {
        Ok(ConnectionAction::ReadStatus { uid: 1000 }) => Outcome::Status,
        Ok(ConnectionAction::Reply(ResponseEnvelope {
            response: Response::VerifyChallenge { challenge, .. },
            ..
        })) if challenge == id(2) => Outcome::Challenge,
        Ok(ConnectionAction::Verify {
            uid: 1000,
            challenge,
            ..
        }) if challenge == id(2) => Outcome::Verify,
        Ok(ConnectionAction::Cancel) => Outcome::Cancel,
        Ok(_) => panic!("unexpected broker work"),
        Err(error) => Outcome::Error(error),
    }
}

#[test]
fn every_four_event_trace_matches_the_verification_reference_model() {
    const EVENTS: [Event; 14] = [
        StatusRequest,
        Begin,
        Submit,
        WrongChallenge,
        Grant,
        Mismatch,
        Cancel,
        DeniedBegin,
        DeniedSubmit,
        DeniedGrant,
        Close,
        RollbackStatus,
        ExpiredStatus,
        WrongConnectionStatus,
    ];
    const DEPTH: u32 = 4;
    // Covers every trace, including events after terminal errors and callbacks.
    // A successful grant needs Begin -> Submit -> Grant, leaving another event
    // to demonstrate that authorization cannot be replayed on this connection.
    for trace in 0..EVENTS.len().pow(DEPTH) {
        let mut connection = Connection::new(id(1), 1000, 1);
        let mut model = Model {
            state: State::Idle,
            last_now: 1,
        };
        let mut remaining = trace;
        let mut now = 1;
        for depth in 0..DEPTH {
            let event = EVENTS[remaining % EVENTS.len()];
            remaining /= EVENTS.len();
            now += if event == ExpiredStatus {
                VERIFY_LIFETIME_MS
            } else {
                1
            };
            let observed = if event == RollbackStatus {
                now - 2
            } else {
                now
            };
            assert_eq!(
                actual(&mut connection, event, observed),
                model.step(event, observed),
                "trace {trace}, step {depth}, event {event:?}"
            );
            assert_eq!(
                connection.is_finished(),
                matches!(model.state, State::Finished),
                "trace {trace}, step {depth}"
            );
        }
    }
}
