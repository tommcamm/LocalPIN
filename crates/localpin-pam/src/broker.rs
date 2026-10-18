//! A single live authenticated connection, with no renewed software budget.

use std::path::Path;

use localpin_core::secret::Pin;
use localpin_protocol::transport::{
    BootInstant, Client, Deadline, TPM_TIMEOUT, TransportError, UNAVAILABLE_TIMEOUT,
};
use localpin_protocol::{
    Availability, Backend, Id, Reason, Request, Response, ResponseEnvelope, VERIFY_LIFETIME_MS,
    VerificationOutcome,
};

const SOCKET: &str = "/run/localpin/broker.sock";

trait Broker {
    fn id(&self) -> Id;
    fn request(
        &mut self,
        request: Request,
        deadline: Deadline,
    ) -> Result<ResponseEnvelope, TransportError>;
    fn close(&mut self);
}

impl Broker for Client {
    fn id(&self) -> Id {
        Client::id(self)
    }

    fn request(
        &mut self,
        request: Request,
        deadline: Deadline,
    ) -> Result<ResponseEnvelope, TransportError> {
        Client::request(self, request, deadline)
    }

    fn close(&mut self) {
        Client::close(self);
    }
}

fn response(client: &mut impl Broker, request: Request, deadline: Deadline) -> Option<Response> {
    let response = client.request(request, deadline).ok()?;
    response.check_connection(client.id()).ok()?;
    (!deadline.expired()).then_some(response.response)
}

fn exchange(client: &mut impl Broker, pin: Pin, unavailable: Deadline, tpm: Deadline) -> bool {
    let result = (|| {
        let Response::Status(status) = response(client, Request::Status, unavailable)? else {
            return None;
        };
        if status.availability != Availability::Available
            || status.cooldown_ms != 0
            || status.reason != Reason::None
        {
            return None;
        }
        status.enrolled?;
        let Response::VerifyChallenge {
            challenge,
            valid_for_ms,
            generation,
            backend,
            profile,
        } = response(client, Request::BeginVerify, unavailable)?
        else {
            return None;
        };
        if !profile.matches(&pin)
            || generation == 0
            || challenge == client.id()
            || valid_for_ms == 0
            || u64::from(valid_for_ms) > VERIFY_LIFETIME_MS
        {
            return None;
        }
        // Only a submitted TPM verification may use the original five-second
        // deadline. Connect/status/challenge and the complete software path share
        // the original two-second deadline. Never use Client::status/verify here:
        // those general-purpose helpers start separate per-operation budgets.
        let deadline = match backend {
            Backend::Software => unavailable,
            Backend::Tpm => tpm,
        };
        match response(client, Request::Verify { challenge, pin }, deadline)? {
            Response::Verification(VerificationOutcome::Granted) => Some(()),
            _ => None,
        }
    })()
    .is_some();
    client.close();
    result
}

pub(crate) fn verify(pin: Pin) -> bool {
    let started = BootInstant::now();
    let unavailable = Deadline::at(started.checked_add(UNAVAILABLE_TIMEOUT).unwrap_or(started));
    let tpm = Deadline::at(started.checked_add(TPM_TIMEOUT).unwrap_or(started));
    let Ok(mut client) = Client::connect(Path::new(SOCKET), unavailable) else {
        return false;
    };
    exchange(&mut client, pin, unavailable, tpm)
}

#[cfg(test)]
mod tests {
    use super::*;
    use localpin_protocol::{BackendPreference, Integration, Status};
    use std::collections::VecDeque;
    use std::time::Duration;

    struct FakeBroker {
        responses: VecDeque<ResponseEnvelope>,
        calls: Vec<&'static str>,
        closed: bool,
        delay: Duration,
        expected: Vec<u8>,
    }

    fn id(byte: u8) -> Id {
        Id::from_bytes([byte; 16]).unwrap()
    }

    fn available(backend: Backend) -> Response {
        Response::Status(Status {
            configured: BackendPreference::Auto,
            enrolled: Some(backend),
            profile: Some(localpin_core::secret::CredentialProfile::legacy()),
            availability: Availability::Available,
            cooldown_ms: 0,
            integration: Integration::Inactive,
            tpm_detected: false,
            tpm_usable: false,
            reason: Reason::None,
        })
    }

    fn challenge_for(backend: Backend) -> Response {
        Response::VerifyChallenge {
            challenge: id(2),
            valid_for_ms: 4999,
            generation: 1,
            backend,
            profile: localpin_core::secret::CredentialProfile::legacy(),
        }
    }

    fn broker(responses: impl IntoIterator<Item = Response>) -> FakeBroker {
        FakeBroker {
            responses: responses
                .into_iter()
                .map(|response| ResponseEnvelope {
                    connection: id(1),
                    response,
                })
                .collect(),
            calls: Vec::new(),
            closed: false,
            delay: Duration::ZERO,
            expected: b"000001".to_vec(),
        }
    }

    impl Broker for FakeBroker {
        fn id(&self) -> Id {
            id(1)
        }

        fn request(
            &mut self,
            request: Request,
            deadline: Deadline,
        ) -> Result<ResponseEnvelope, TransportError> {
            assert!(!self.closed);
            match request {
                Request::Status => self.calls.push("status"),
                Request::BeginVerify => self.calls.push("begin"),
                Request::Verify { challenge, pin } => {
                    assert_eq!(challenge, id(2));
                    assert_eq!(pin.expose(), self.expected);
                    self.calls.push("verify");
                }
                _ => panic!("unexpected authorizing operation"),
            }
            std::thread::sleep(self.delay);
            if deadline.expired() {
                return Err(TransportError::Timeout);
            }
            self.responses.pop_front().ok_or(TransportError::Closed)
        }

        fn close(&mut self) {
            self.closed = true;
        }
    }

    fn run(client: &mut FakeBroker) -> bool {
        exchange(
            client,
            Pin::parse(b"000001").unwrap(),
            Deadline::after(UNAVAILABLE_TIMEOUT),
            Deadline::after(TPM_TIMEOUT),
        )
    }

    #[test]
    fn only_final_fresh_grant_succeeds_and_connection_is_always_closed() {
        for outcome in [
            VerificationOutcome::Granted,
            VerificationOutcome::Mismatch,
            VerificationOutcome::Cooldown(60000),
            VerificationOutcome::Unavailable(Reason::Backend),
            VerificationOutcome::Unavailable(Reason::Storage),
            VerificationOutcome::Unavailable(Reason::Account),
        ] {
            let mut client = broker([
                available(Backend::Software),
                challenge_for(Backend::Software),
                Response::Verification(outcome),
            ]);
            assert_eq!(run(&mut client), outcome == VerificationOutcome::Granted);
            assert_eq!(client.calls, ["status", "begin", "verify"]);
            assert!(client.closed);
        }
    }

    #[test]
    fn authoritative_profile_filters_candidates_without_submitting_an_attempt() {
        for candidate in [
            b"12345".as_slice(),
            b"1234567",
            b"ABCDEFGH",
            b"ordinary password",
        ] {
            let mut client = broker([
                available(Backend::Software),
                challenge_for(Backend::Software),
            ]);
            assert!(!exchange(
                &mut client,
                Pin::parse(candidate).unwrap(),
                Deadline::after(UNAVAILABLE_TIMEOUT),
                Deadline::after(TPM_TIMEOUT)
            ));
            assert_eq!(client.calls, ["status", "begin"]);
            assert!(client.closed);
        }
    }

    #[test]
    fn passcodes_preserve_spaces_case_and_numeric_looking_content() {
        for candidate in [b" A passcode ".as_slice(), b"0011223344", &[b'Z'; 64]] {
            let profile = localpin_core::secret::CredentialProfile::for_enrollment(
                localpin_core::types::Backend::Software,
                localpin_core::secret::CredentialKind::Passcode,
                &Pin::parse(candidate).unwrap(),
            )
            .unwrap();
            let mut client = broker([
                available(Backend::Software),
                Response::VerifyChallenge {
                    challenge: id(2),
                    generation: 9,
                    backend: Backend::Software,
                    profile,
                    valid_for_ms: 4999,
                },
                Response::Verification(VerificationOutcome::Granted),
            ]);
            client.expected = candidate.to_vec();
            assert!(exchange(
                &mut client,
                Pin::parse(candidate).unwrap(),
                Deadline::after(UNAVAILABLE_TIMEOUT),
                Deadline::after(TPM_TIMEOUT)
            ));
            assert_eq!(client.calls, ["status", "begin", "verify"]);
        }
    }

    #[test]
    fn unavailable_status_skips_verification_even_with_later_grant() {
        for availability in [
            Availability::NotEnrolled,
            Availability::Disabled,
            Availability::Cooldown,
            Availability::Ineligible,
            Availability::Unavailable,
        ] {
            let Response::Status(mut status) = available(Backend::Tpm) else {
                unreachable!()
            };
            status.availability = availability;
            let mut client = broker([
                Response::Status(status),
                challenge_for(Backend::Software),
                Response::Verification(VerificationOutcome::Granted),
            ]);
            assert!(!run(&mut client));
            assert_eq!(client.calls, ["status"]);
            assert!(client.closed);
        }
    }

    #[test]
    fn wrong_order_binding_and_challenge_fail_closed() {
        for invalid in [
            Response::Hello,
            Response::Verification(VerificationOutcome::Granted),
            Response::VerifyChallenge {
                challenge: id(1),
                valid_for_ms: 4999,
                generation: 1,
                backend: Backend::Tpm,
                profile: localpin_core::secret::CredentialProfile::legacy(),
            },
            Response::VerifyChallenge {
                challenge: id(2),
                valid_for_ms: 0,
                generation: 1,
                backend: Backend::Tpm,
                profile: localpin_core::secret::CredentialProfile::legacy(),
            },
            Response::VerifyChallenge {
                challenge: id(2),
                valid_for_ms: 5001,
                generation: 1,
                backend: Backend::Tpm,
                profile: localpin_core::secret::CredentialProfile::legacy(),
            },
        ] {
            let mut client = broker([available(Backend::Software), invalid]);
            assert!(!run(&mut client));
            assert_eq!(client.calls, ["status", "begin"]);
            assert!(client.closed);
        }
        let mut client = broker([
            available(Backend::Software),
            challenge_for(Backend::Software),
            Response::Verification(VerificationOutcome::Granted),
        ]);
        client.responses.back_mut().unwrap().connection = id(3);
        assert!(!run(&mut client));
        assert!(client.closed);
    }

    #[test]
    fn software_reuses_one_deadline_across_status_challenge_and_attempt() {
        let mut client = broker([
            available(Backend::Tpm), // stale status cannot grant the longer TPM budget
            challenge_for(Backend::Software),
            Response::Verification(VerificationOutcome::Granted),
        ]);
        client.delay = Duration::from_millis(45);
        let deadline = Deadline::after(Duration::from_millis(110));
        assert!(!exchange(
            &mut client,
            Pin::parse(b"000001").unwrap(),
            deadline,
            Deadline::after(TPM_TIMEOUT)
        ));
        assert_eq!(client.calls, ["status", "begin", "verify"]);
        assert!(client.closed);
    }

    #[test]
    fn tpm_uses_original_extended_deadline_without_renewing_it() {
        let mut client = broker([
            available(Backend::Tpm),
            challenge_for(Backend::Tpm),
            Response::Verification(VerificationOutcome::Granted),
        ]);
        client.delay = Duration::from_millis(45);
        let deadline = Deadline::after(Duration::from_millis(110));
        assert!(!exchange(
            &mut client,
            Pin::parse(b"000001").unwrap(),
            Deadline::after(UNAVAILABLE_TIMEOUT),
            deadline
        ));
        assert_eq!(client.calls, ["status", "begin", "verify"]);
        assert!(client.closed);
    }
}
