use super::*;
use localpin_protocol::{Availability, Integration, PromptText, Reason};
use std::collections::VecDeque;

fn id(value: u8) -> Id {
    Id::from_bytes([value; 16]).unwrap()
}

struct ScriptClient {
    responses: VecDeque<Response>,
    requests: Vec<Request>,
    closed: bool,
}
impl ScriptClient {
    fn new(responses: Vec<Response>) -> Self {
        Self {
            responses: responses.into(),
            requests: Vec::new(),
            closed: false,
        }
    }
}
impl BrokerClient for ScriptClient {
    fn connection_id(&self) -> Id {
        id(1)
    }
    fn exchange(&mut self, request: Request, _: Deadline) -> Result<Response, CliError> {
        let cancelled = matches!(request, Request::Cancel);
        self.requests.push(request);
        if cancelled {
            Ok(Response::Cancelled)
        } else {
            self.responses.pop_front().ok_or(CliError::Protocol)
        }
    }
    fn receive(&mut self, _: Deadline) -> Result<Response, CliError> {
        self.responses.pop_front().ok_or(CliError::Protocol)
    }
    fn close(&mut self) {
        self.closed = true;
    }
}

struct ScriptTerminal {
    inputs: VecDeque<Vec<u8>>,
    reads: usize,
}
impl ScriptTerminal {
    fn new(inputs: &[&[u8]]) -> Self {
        Self {
            inputs: inputs.iter().map(|v| v.to_vec()).collect(),
            reads: 0,
        }
    }
}
impl Conversation for ScriptTerminal {
    fn secret(&mut self, _: &str, max: usize, _: Deadline) -> Result<SecretBytes, CliError> {
        self.reads += 1;
        self.inputs
            .pop_front()
            .ok_or(CliError::Cancelled)
            .and_then(|bytes| {
                SecretBytes::from_slice(&bytes, max).map_err(|_| CliError::InputTooLong)
            })
    }
    fn message(&mut self, _: &str) -> Result<(), CliError> {
        Ok(())
    }
}

fn begin() -> Response {
    Response::EnrollmentStarted {
        transaction: id(2),
        generation: 1,
        valid_for_ms: 60_000,
    }
}
fn prompt() -> Response {
    Response::ConversationPrompt {
        transaction: id(2),
        prompt: id(3),
        style: PromptStyle::EchoOff,
        text: PromptText::new("Account password: ").unwrap(),
    }
}
fn ready() -> Response {
    Response::EnrollmentReady {
        transaction: id(2),
        valid_for_ms: 60_000,
    }
}

#[test]
fn enrollment_change_and_migration_require_password_then_confirmed_new_pin() {
    for action in [
        EnrollmentAction::Enroll,
        EnrollmentAction::Rotate,
        EnrollmentAction::Migrate,
    ] {
        let mut client = ScriptClient::new(vec![
            begin(),
            prompt(),
            ready(),
            Response::Completed(Completion::Enrolled(Backend::Software)),
        ]);
        let mut terminal =
            ScriptTerminal::new(&[b"yes", b"synthetic\xffpassword", b"000001", b"000001"]);
        assert_eq!(
            mutate(&mut client, &mut terminal, action, Some(Backend::Software)),
            Ok(Completion::Enrolled(Backend::Software))
        );
        assert_eq!(client.requests.len(), 3);
        assert!(
            matches!(&client.requests[0], Request::BeginEnroll { action: actual, backend: Some(Backend::Software) } if *actual == action)
        );
        assert!(
            matches!(&client.requests[1], Request::EnrollConversation { transaction, prompt, response } if *transaction == id(2) && *prompt == id(3) && response.expose() == b"synthetic\xffpassword")
        );
        assert!(
            matches!(&client.requests[2], Request::CommitEnrollment { transaction, pin } if *transaction == id(2) && pin.expose() == b"000001")
        );
        assert!(client.closed);
    }
}

#[test]
fn own_user_disable_uses_fresh_password_and_never_requests_a_pin() {
    let mut client = ScriptClient::new(vec![
        begin(),
        prompt(),
        ready(),
        Response::Completed(Completion::Disabled),
    ]);
    let mut terminal = ScriptTerminal::new(&[b"yes", b"synthetic-password"]);
    assert_eq!(
        mutate(&mut client, &mut terminal, EnrollmentAction::Disable, None),
        Ok(Completion::Disabled)
    );
    assert_eq!(terminal.reads, 2);
    assert!(
        matches!(&client.requests[2], Request::Disable { transaction } if *transaction == id(2))
    );
    assert!(client.closed);
}

#[test]
fn rejected_password_never_requests_or_sends_a_pin() {
    let mut client = ScriptClient::new(vec![
        begin(),
        prompt(),
        Response::Error(ErrorCode::PasswordRejected),
    ]);
    let mut terminal = ScriptTerminal::new(&[b"yes", b"wrong-password"]);
    assert_eq!(
        mutate(
            &mut client,
            &mut terminal,
            EnrollmentAction::Rotate,
            Some(Backend::Tpm)
        ),
        Err(CliError::PasswordRejected)
    );
    assert_eq!(terminal.reads, 2);
    assert!(client.requests.iter().all(|r| !matches!(
        r,
        Request::CommitEnrollment { .. } | Request::Disable { .. }
    )));
    assert!(matches!(client.requests.last(), Some(Request::Cancel)));
    assert!(client.closed);
}

#[test]
fn bad_pin_confirmation_cancels_without_commit() {
    let mut client = ScriptClient::new(vec![begin(), prompt(), ready()]);
    let mut terminal = ScriptTerminal::new(&[b"yes", b"synthetic-password", b"000001", b"000002"]);
    assert_eq!(
        mutate(
            &mut client,
            &mut terminal,
            EnrollmentAction::Enroll,
            Some(Backend::Tpm)
        ),
        Err(CliError::Confirmation)
    );
    assert!(
        client
            .requests
            .iter()
            .all(|r| !matches!(r, Request::CommitEnrollment { .. }))
    );
    assert!(matches!(client.requests.last(), Some(Request::Cancel)));
    assert!(client.closed);
}

#[test]
fn transaction_mismatch_replayed_prompt_and_expired_authorization_fail_closed() {
    for invalid in [
        Response::ConversationPrompt {
            transaction: id(9),
            prompt: id(4),
            style: PromptStyle::EchoOff,
            text: PromptText::new("Password: ").unwrap(),
        },
        prompt(),
        Response::EnrollmentReady {
            transaction: id(2),
            valid_for_ms: 0,
        },
        Response::EnrollmentReady {
            transaction: id(2),
            valid_for_ms: 60_001,
        },
        Response::EnrollmentReady {
            transaction: id(9),
            valid_for_ms: 1,
        },
        Response::Error(ErrorCode::Expired),
    ] {
        let mut client = ScriptClient::new(vec![begin(), prompt(), invalid]);
        let mut terminal = ScriptTerminal::new(&[b"yes", b"synthetic-password"]);
        assert!(
            mutate(
                &mut client,
                &mut terminal,
                EnrollmentAction::Rotate,
                Some(Backend::Tpm)
            )
            .is_err()
        );
        assert_eq!(terminal.reads, 2);
        assert!(
            client
                .requests
                .iter()
                .all(|r| !matches!(r, Request::CommitEnrollment { .. }))
        );
        assert!(client.closed);
    }
}

#[test]
fn cancellation_before_password_starts_no_enrollment() {
    let mut client = ScriptClient::new(vec![]);
    let mut terminal = ScriptTerminal::new(&[b"no"]);
    assert_eq!(
        mutate(
            &mut client,
            &mut terminal,
            EnrollmentAction::Enroll,
            Some(Backend::Tpm)
        ),
        Err(CliError::Cancelled)
    );
    assert!(client.requests.iter().all(|r| matches!(r, Request::Cancel)));
    assert!(client.closed);
}

#[test]
fn administrator_recovery_requires_confirmation_and_exact_completion() {
    let mut client = ScriptClient::new(vec![Response::Completed(Completion::RecoveryDisabled)]);
    let mut terminal = ScriptTerminal::new(&[b"yes"]);
    assert_eq!(
        recover(&mut client, &mut terminal, 1000),
        Ok(Completion::RecoveryDisabled)
    );
    assert!(matches!(
        client.requests.as_slice(),
        [Request::RecoverDisable { target_uid: 1000 }]
    ));
    assert!(client.closed);
    let mut client = ScriptClient::new(vec![]);
    assert_eq!(
        recover(&mut client, &mut ScriptTerminal::new(&[]), 0),
        Err(CliError::Account)
    );
    assert!(client.closed);
}

#[test]
fn auto_and_required_tpm_never_silently_choose_software() {
    let mut status = Status {
        configured: BackendPreference::Auto,
        enrolled: None,
        availability: Availability::NotEnrolled,
        cooldown_ms: 0,
        integration: Integration::Inactive,
        tpm_detected: true,
        tpm_usable: false,
        reason: Reason::None,
    };
    assert_eq!(
        select_backend(BackendPreference::Auto, status),
        Ok(Backend::Tpm)
    );
    assert_eq!(
        select_backend(BackendPreference::Tpm, status),
        Ok(Backend::Tpm)
    );
    assert_eq!(
        select_backend(BackendPreference::Software, status),
        Ok(Backend::Software)
    );
    status.tpm_usable = true;
    assert_eq!(
        select_backend(BackendPreference::Auto, status),
        Ok(Backend::Tpm)
    );
}

#[test]
fn recovery_account_lookup_accepts_one_exact_non_root_local_account() {
    let records =
        "root:x:0:0:root:/root:/bin/bash\nsynthetic:x:1001:1001:Test:/home/synthetic:/bin/bash\n";
    assert_eq!(parse_local_uid(records, "synthetic"), Ok(1001));
    assert_eq!(parse_local_uid(records, "root"), Err(CliError::Account));
    assert_eq!(parse_local_uid(records, "missing"), Err(CliError::Account));
    assert_eq!(
        parse_local_uid(
            &format!("{records}synthetic:x:1002:1002::/home/a:/bin/bash\n"),
            "synthetic"
        ),
        Err(CliError::Account)
    );
}
