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
fn enrollment_change_and_migration_prepare_first_and_send_only_after_password_success() {
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
        let mut terminal = ScriptTerminal::new(&[
            b"",
            b"0019374820",
            b"0019374820",
            b"yes",
            b"synthetic\xffpassword",
        ]);
        assert_eq!(
            mutate(&mut client, &mut terminal, action, Some(Backend::Software)),
            Ok(Completion::Enrolled(Backend::Software))
        );
        assert_eq!(client.requests.len(), 3);
        assert!(
            matches!(&client.requests[0], Request::BeginEnroll { action: actual, backend: Some(Backend::Software), kind: Some(CredentialKind::NumericPin) } if *actual == action)
        );
        assert!(
            matches!(&client.requests[1], Request::EnrollConversation { transaction, prompt, response } if *transaction == id(2) && *prompt == id(3) && response.expose() == b"synthetic\xffpassword")
        );
        assert!(
            matches!(&client.requests[2], Request::CommitEnrollment { transaction, pin } if *transaction == id(2) && pin.expose() == b"0019374820")
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
fn rejected_password_erases_preparation_without_sending_credential() {
    let mut client = ScriptClient::new(vec![
        begin(),
        prompt(),
        Response::Error(ErrorCode::PasswordRejected),
    ]);
    let mut terminal = ScriptTerminal::new(&[b"", b"019374", b"019374", b"yes", b"wrong-password"]);
    assert_eq!(
        mutate(
            &mut client,
            &mut terminal,
            EnrollmentAction::Rotate,
            Some(Backend::Tpm)
        ),
        Err(CliError::PasswordRejected)
    );
    assert_eq!(terminal.reads, 5);
    assert!(client.requests.iter().all(|r| !matches!(
        r,
        Request::CommitEnrollment { .. } | Request::Disable { .. }
    )));
    assert!(matches!(client.requests.last(), Some(Request::Cancel)));
    assert!(client.closed);
}

#[test]
fn mismatch_retries_locally_and_cancellation_starts_no_enrollment() {
    let mut client = ScriptClient::new(vec![begin(), prompt(), ready()]);
    let mut terminal = ScriptTerminal::new(&[b"", b"019374", b"019375"]);
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
        let mut terminal =
            ScriptTerminal::new(&[b"", b"019374", b"019374", b"yes", b"synthetic-password"]);
        assert!(
            mutate(
                &mut client,
                &mut terminal,
                EnrollmentAction::Rotate,
                Some(Backend::Tpm)
            )
            .is_err()
        );
        assert_eq!(terminal.reads, 5);
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
    let mut terminal = ScriptTerminal::new(&[b"q"]);
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
        profile: None,
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

#[test]
fn prepared_passcode_type_is_bound_to_begin_and_exact_bytes_reach_commit() {
    let mut client = ScriptClient::new(vec![
        begin(),
        prompt(),
        ready(),
        Response::Completed(Completion::Enrolled(Backend::Tpm)),
    ]);
    let mut terminal = ScriptTerminal::new(&[
        b"2",
        b"  Example phrase!  ",
        b"  Example phrase!  ",
        b"yes",
        b"account-password",
    ]);
    assert_eq!(
        mutate(
            &mut client,
            &mut terminal,
            EnrollmentAction::Rotate,
            Some(Backend::Tpm)
        ),
        Ok(Completion::Enrolled(Backend::Tpm))
    );
    assert!(matches!(
        client.requests[0],
        Request::BeginEnroll {
            kind: Some(CredentialKind::Passcode),
            ..
        }
    ));
    assert!(
        matches!(&client.requests[2], Request::CommitEnrollment { pin, .. } if pin.expose() == b"  Example phrase!  ")
    );
}

#[test]
fn declined_prepared_credential_and_invalid_software_pin_never_begin_enrollment() {
    for inputs in [
        vec![b"".as_slice(), b"0019374820", b"0019374820", b"no"],
        vec![b"".as_slice(), b"019374"],
        vec![b"".as_slice(), b"11111111", b"11111111", b"q"],
    ] {
        let mut client = ScriptClient::new(vec![]);
        let mut terminal = ScriptTerminal::new(&inputs);
        assert_eq!(
            mutate(
                &mut client,
                &mut terminal,
                EnrollmentAction::Enroll,
                Some(Backend::Software)
            ),
            Err(CliError::Cancelled)
        );
        assert!(
            client
                .requests
                .iter()
                .all(|request| matches!(request, Request::Cancel))
        );
    }
}

#[test]
fn existing_passcode_is_the_default_for_change_and_migration() {
    for action in [EnrollmentAction::Rotate, EnrollmentAction::Migrate] {
        let mut terminal =
            ScriptTerminal::new(&[b"", b"A phrase with space", b"A phrase with space"]);
        let prepared = prepare_mutation(
            &mut terminal,
            action,
            Some(Backend::Software),
            Some(CredentialProfile {
                kind: CredentialKind::Passcode,
                policy: 1,
                length: 18,
            }),
        )
        .unwrap()
        .unwrap();
        assert_eq!(prepared.kind, CredentialKind::Passcode);
    }
}

#[test]
fn unvalidated_programmatic_preparation_is_rejected_before_begin() {
    let mut client = ScriptClient::new(vec![]);
    let prepared =
        PreparedCredential::new(CredentialKind::NumericPin, Pin::parse(b"019374").unwrap());
    assert_eq!(
        mutate_confirmed(
            &mut client,
            &mut ScriptTerminal::new(&[]),
            EnrollmentAction::Enroll,
            Some(Backend::Software),
            Some(prepared)
        ),
        Err(CliError::PinFormat)
    );
    assert!(
        client
            .requests
            .iter()
            .all(|request| matches!(request, Request::Cancel))
    );
}

#[test]
fn success_distinguishes_action_and_current_activation_state() {
    use localpin_protocol::{Integration, integration::Gate};
    let message = completion_message(
        Completion::Enrolled(Backend::Software),
        EnrollmentAction::Rotate,
        Some(Integration::Active),
        Gate::Active,
    )
    .unwrap();
    assert!(message.starts_with("Credential changed."));
    assert!(message.contains("Desktop integration is active"));
    let message = completion_message(
        Completion::Enrolled(Backend::Tpm),
        EnrollmentAction::Migrate,
        Some(Integration::Inactive),
        Gate::Disabled,
    )
    .unwrap();
    assert!(message.starts_with("Protection switched"));
    assert!(message.contains("run localpin setup"));
    let unknown = completion_message(
        Completion::Enrolled(Backend::Software),
        EnrollmentAction::Rotate,
        None,
        Gate::Active,
    )
    .unwrap();
    assert!(unknown.starts_with("Credential changed."));
    assert!(unknown.contains("activation could not be confirmed"));
    assert!(!unknown.contains("integration is active"));
}
