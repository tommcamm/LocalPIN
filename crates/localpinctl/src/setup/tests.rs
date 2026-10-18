use super::*;
use crate::admin::{AccountingOutcome, FailedOperation};
use std::collections::VecDeque;

fn report(phase: Phase, enrolled: bool, trial: bool) -> SetupReport {
    SetupReport {
        schema_version: 1,
        phase,
        blocker: Blocker::None,
        enrolled,
        trial_valid: trial,
        trial_remaining_seconds: if trial { 590 } else { 0 },
        trial_ref: trial.then(|| "a".repeat(64)),
        tests_recorded: false,
        accounting_outcome: None,
    }
}

struct Fake {
    state: SetupReport,
    actions: Vec<Operation>,
    backends: Vec<BackendPreference>,
    inspections: usize,
    change_on_inspection: Option<(usize, SetupReport)>,
    fail: Option<Operation>,
    enrollment_error: Option<CliError>,
    account_error: Option<CliError>,
}

impl Fake {
    fn new(state: SetupReport) -> Self {
        Self {
            state,
            actions: vec![],
            backends: vec![],
            inspections: 0,
            change_on_inspection: None,
            fail: None,
            enrollment_error: None,
            account_error: None,
        }
    }
}

impl Host for Fake {
    fn check_account(&mut self) -> Result<(), CliError> {
        self.account_error.map_or(Ok(()), Err)
    }
    fn inspect(&mut self) -> Result<SetupReport, CliError> {
        self.inspections += 1;
        if let Some((at, state)) = &self.change_on_inspection
            && self.inspections == *at
        {
            self.state = state.clone();
        }
        Ok(self.state.clone())
    }

    fn action(
        &mut self,
        operation: Operation,
        trial_ref: Option<&str>,
    ) -> Result<Option<String>, CliError> {
        self.actions.push(operation);
        if self.fail == Some(operation) {
            return Err(CliError::Administrator);
        }
        if matches!(operation, Operation::RecordTests | Operation::Activate) {
            assert_eq!(trial_ref, self.state.trial_ref.as_deref());
        } else {
            assert_eq!(trial_ref, None);
        }
        match operation {
            Operation::Preview => return Ok(Some("synthetic policy diff".to_owned())),
            Operation::Prepare => self.state = report(Phase::Prepared, false, false),
            Operation::PrepareAccounting => self.state.blocker = Blocker::AccountingMaintenance,
            Operation::Trial => self.state = report(Phase::Prepared, true, true),
            Operation::RecordTests => self.state.tests_recorded = true,
            Operation::Activate => {
                self.state.phase = Phase::Active;
                self.state.trial_valid = false;
                self.state.trial_remaining_seconds = 0;
                self.state.trial_ref = None;
            }
            Operation::Inspect => panic!("inspect is a separate method"),
        }
        Ok(None)
    }

    fn enroll(&mut self, backend: BackendPreference) -> Result<(), CliError> {
        self.backends.push(backend);
        if let Some(error) = self.enrollment_error {
            return Err(error);
        }
        self.state.enrolled = true;
        Ok(())
    }
}

struct Script {
    answers: VecDeque<Result<usize, CliError>>,
    messages: Vec<String>,
}

impl Script {
    fn new(answers: &[usize]) -> Self {
        Self {
            answers: answers.iter().copied().map(Ok).collect(),
            messages: vec![],
        }
    }
    fn contains(&self, text: &str) -> bool {
        self.messages.iter().any(|message| message.contains(text))
    }
}

impl Ui for Script {
    fn say(&mut self, text: &str) -> Result<(), CliError> {
        self.messages.push(text.to_owned());
        Ok(())
    }
    fn choose(&mut self, prompt: &str, _choices: &[&str]) -> Result<usize, CliError> {
        self.messages.push(prompt.to_owned());
        self.answers
            .pop_front()
            .expect("unexpected wizard question")
    }
}

#[test]
fn initial_setup_stops_for_real_console_recovery_without_attesting_it() {
    let mut host = Fake::new(report(Phase::Unprepared, false, false));
    let mut ui = Script::new(&[0, 1, 0, 0, 0, 0, 0]);
    drive(&mut host, &mut ui).unwrap();
    assert_eq!(
        host.actions,
        [Operation::Preview, Operation::Prepare, Operation::Trial]
    );
    assert_eq!(host.backends, [BackendPreference::Tpm]);
    assert!(ui.contains("TEXT CONSOLE"));
    assert!(ui.contains("Recovery revokes this PIN enrollment"));
    assert!(!ui.contains("LocalPIN is active"));
}

#[test]
fn completed_recovery_reprepares_enrolls_tests_and_activates() {
    let mut host = Fake::new(report(Phase::Disabled, false, false));
    let mut ui = Script::new(&[0, 0, 0, 1, 0, 0, 0, 0]);
    drive(&mut host, &mut ui).unwrap();
    assert_eq!(host.backends, [BackendPreference::Software]);
    assert_eq!(
        host.actions,
        [
            Operation::Preview,
            Operation::Prepare,
            Operation::Trial,
            Operation::RecordTests,
            Operation::Activate
        ]
    );
    assert_eq!(host.state.phase, Phase::Active);
    assert!(ui.contains("administrator attestation"));
    assert!(ui.contains("LocalPIN is active"));
    assert!(ui.answers.is_empty());
}

#[test]
fn resume_does_not_repeat_preparation_or_enrollment() {
    let mut host = Fake::new(report(Phase::Prepared, true, true));
    let mut ui = Script::new(&[0, 0, 0, 0, 0]);
    drive(&mut host, &mut ui).unwrap();
    assert!(host.backends.is_empty());
    assert_eq!(host.actions, [Operation::RecordTests, Operation::Activate]);
    assert!(ui.contains("enrollment is retained"));
}

#[test]
fn existing_root_recorded_tests_are_retained_only_during_the_same_live_trial() {
    let mut state = report(Phase::Prepared, true, true);
    state.tests_recorded = true;
    let mut host = Fake::new(state);
    let mut ui = Script::new(&[0, 0]);
    drive(&mut host, &mut ui).unwrap();
    assert_eq!(host.actions, [Operation::Activate]);
}

#[test]
fn active_enrolled_installation_is_a_no_op() {
    let mut host = Fake::new(report(Phase::Active, true, false));
    let mut ui = Script::new(&[0]);
    drive(&mut host, &mut ui).unwrap();
    assert!(host.actions.is_empty());
    assert!(host.backends.is_empty());
    assert_eq!(host.inspections, 1);
}

#[test]
fn active_unenrolled_installation_enrolls_without_changing_integration() {
    let mut host = Fake::new(report(Phase::Active, false, false));
    let mut ui = Script::new(&[0, 0, 1]);
    drive(&mut host, &mut ui).unwrap();
    assert!(host.actions.is_empty());
    assert_eq!(host.backends, [BackendPreference::Software]);
    assert_eq!(host.inspections, 2);
    assert_eq!(host.state, report(Phase::Active, true, false));
    assert!(ui.contains("Your new credential is ready"));
    assert!(ui.contains("Desktop integration remains active"));
    assert!(ui.answers.is_empty());
}

#[test]
fn declining_active_reenrollment_leaves_the_account_unchanged() {
    let initial = report(Phase::Active, false, false);
    let mut host = Fake::new(initial.clone());
    let mut ui = Script::new(&[0, 1]);
    drive(&mut host, &mut ui).unwrap();
    assert_eq!(host.state, initial);
    assert!(host.actions.is_empty());
    assert!(host.backends.is_empty());
    assert_eq!(host.inspections, 1);
    assert!(!ui.contains("Your new credential is ready"));
    assert!(ui.answers.is_empty());
}

#[test]
fn cancelled_active_reenrollment_does_not_start_enrollment() {
    for confirmed in [false, true] {
        let initial = report(Phase::Active, false, false);
        let mut host = Fake::new(initial.clone());
        let mut ui = Script::new(if confirmed { &[0, 0] } else { &[0] });
        ui.answers.push_back(Err(CliError::Cancelled));
        assert_eq!(drive(&mut host, &mut ui), Err(CliError::Cancelled));
        assert_eq!(host.state, initial);
        assert!(host.actions.is_empty());
        assert!(host.backends.is_empty());
        assert_eq!(host.inspections, 1);
        assert!(!ui.contains("Your new credential is ready"));
        assert!(ui.answers.is_empty());
    }
}

#[test]
fn active_reenrollment_failure_does_not_retry_or_claim_success() {
    let initial = report(Phase::Active, false, false);
    let mut host = Fake::new(initial.clone());
    host.enrollment_error = Some(CliError::Backend);
    let mut ui = Script::new(&[0, 0, 0]);
    assert_eq!(drive(&mut host, &mut ui), Err(CliError::Backend));
    assert_eq!(host.state, initial);
    assert!(host.actions.is_empty());
    assert_eq!(host.backends, [BackendPreference::Tpm]);
    assert_eq!(host.inspections, 1);
    assert!(!ui.contains("Your new credential is ready"));
    assert!(ui.answers.is_empty());
}

#[test]
fn active_reenrollment_requires_fresh_active_enrollment_and_broker_readiness() {
    for changed in [
        report(Phase::Prepared, true, false),
        report(Phase::Active, false, false),
    ] {
        let mut host = Fake::new(report(Phase::Active, false, false));
        host.change_on_inspection = Some((2, changed));
        let mut ui = Script::new(&[0, 0, 1]);
        assert_eq!(drive(&mut host, &mut ui), Err(CliError::SetupReport));
        assert!(host.actions.is_empty());
        assert_eq!(host.backends, [BackendPreference::Software]);
        assert_eq!(host.inspections, 2);
        assert!(!ui.contains("Your new credential is ready"));
        assert!(ui.answers.is_empty());
    }

    let mut host = Fake::new(report(Phase::Active, false, false));
    host.account_error = Some(CliError::Service);
    let mut ui = Script::new(&[0, 0, 1]);
    assert_eq!(drive(&mut host, &mut ui), Err(CliError::Service));
    assert!(host.actions.is_empty());
    assert_eq!(host.backends, [BackendPreference::Software]);
    assert_eq!(host.inspections, 2);
    assert!(!ui.contains("Your new credential is ready"));
    assert!(ui.answers.is_empty());
}

#[test]
fn every_blocker_stops_before_any_mutation() {
    for blocker in [
        Blocker::AccountingMaintenance,
        Blocker::Multiuser,
        Blocker::Recovery,
        Blocker::Policy,
    ] {
        let mut state = report(Phase::Unprepared, false, false);
        state.blocker = blocker;
        let mut host = Fake::new(state);
        let mut ui = Script::new(&[0]);
        assert_eq!(drive(&mut host, &mut ui), Err(CliError::SetupBlocked));
        assert!(host.actions.is_empty());
        assert!(host.backends.is_empty());
        assert!(ui.contains("Guide:"));
    }
}

#[test]
fn accounting_maintenance_requires_explicit_logout_approval_and_exits_before_enrollment() {
    let mut state = report(Phase::Unprepared, false, false);
    state.blocker = Blocker::Accounting;
    let mut host = Fake::new(state);
    let mut ui = Script::new(&[0, 0]);
    drive(&mut host, &mut ui).unwrap();
    assert_eq!(host.actions, [Operation::PrepareAccounting]);
    assert!(host.backends.is_empty());
    assert_eq!(host.inspections, 1);
    assert!(ui.contains("Save your work"));
    assert!(ui.contains("log out all users"));
    assert!(ui.contains("stop running services and background jobs"));
    assert!(ui.contains("background jobs may need restarting"));
    assert!(ui.contains("full account password"));
    assert!(ui.contains("setup will reopen automatically"));
    assert!(!ui.contains("LocalPIN is active"));
    assert!(ui.answers.is_empty());
}

fn aborted_accounting(restoration: Restoration) -> SetupReport {
    let mut state = report(Phase::Unprepared, false, false);
    state.blocker = Blocker::Accounting;
    state.accounting_outcome = Some(AccountingOutcome {
        result: AccountingResult::Aborted,
        restoration,
        failed_operation: Some(FailedOperation::StopSessions),
    });
    state
}

#[test]
fn aborted_accounting_is_explained_before_deliberate_retry_approval() {
    for retry in [false, true] {
        let mut host = Fake::new(aborted_accounting(Restoration::Restored));
        let mut ui = Script::new(&[0, if retry { 0 } else { 1 }]);
        drive(&mut host, &mut ui).unwrap();
        assert_eq!(
            host.actions,
            if retry {
                vec![Operation::PrepareAccounting]
            } else {
                vec![]
            }
        );
        assert!(host.backends.is_empty());
        assert!(ui.contains("previous password-accounting maintenance was aborted"));
        assert!(ui.contains("prior preparation remains incomplete"));
        assert!(ui.contains("Failed maintenance operation: stop user sessions"));
        let explanation = ui
            .messages
            .iter()
            .position(|message| message.contains("maintenance was aborted"))
            .unwrap();
        let failure = ui
            .messages
            .iter()
            .position(|message| message.contains("Failed maintenance operation"))
            .unwrap();
        let approval = ui
            .messages
            .iter()
            .position(|message| message.contains("Have you saved your work"))
            .unwrap();
        assert!(explanation < approval && failure < approval);
        assert!(ui.answers.is_empty());
    }
}

#[test]
fn pending_restoration_blocks_retry_even_if_readiness_blocker_is_inconsistent() {
    for blocker in [
        Blocker::None,
        Blocker::Accounting,
        Blocker::AccountingMaintenance,
    ] {
        let mut state = aborted_accounting(Restoration::Pending);
        state.blocker = blocker;
        let mut host = Fake::new(state);
        let mut ui = Script::new(&[0, 1]);
        assert_eq!(drive(&mut host, &mut ui), Err(CliError::SetupBlocked));
        assert!(host.actions.is_empty());
        assert!(host.backends.is_empty());
        assert_eq!(host.inspections, 1);
        assert!(ui.contains("maintenance was aborted"));
        assert!(ui.contains("Login service restoration has not yet been verified"));
        assert!(ui.contains("Recheck readiness or exit setup?"));
        assert!(!ui.contains("Have you saved your work"));
        assert!(ui.answers.is_empty());
    }
}

#[test]
fn pending_restoration_rechecks_only_after_a_visible_user_choice() {
    let mut host = Fake::new(aborted_accounting(Restoration::Pending));
    host.change_on_inspection = Some((3, aborted_accounting(Restoration::Restored)));
    let mut ui = Script::new(&[0, 0, 0, 1]);
    drive(&mut host, &mut ui).unwrap();
    assert_eq!(host.inspections, 3);
    assert!(host.actions.is_empty());
    assert!(host.backends.is_empty());
    assert_eq!(
        ui.messages
            .iter()
            .filter(|message| message.contains("Recheck readiness or exit setup?"))
            .count(),
        2,
    );
    assert_eq!(
        ui.messages
            .iter()
            .filter(|message| message.contains("maintenance was aborted"))
            .count(),
        3,
    );
    assert!(ui.contains("Login service restoration is recorded as complete"));
    assert!(ui.contains("Have you saved your work"));
    assert!(ui.answers.is_empty());
}

#[test]
fn cancelling_pending_restoration_recheck_does_not_reinspect_or_mutate() {
    let mut host = Fake::new(aborted_accounting(Restoration::Pending));
    let mut ui = Script::new(&[0]);
    ui.answers.push_back(Err(CliError::Cancelled));
    assert_eq!(drive(&mut host, &mut ui), Err(CliError::Cancelled));
    assert_eq!(host.inspections, 1);
    assert!(host.actions.is_empty());
    assert!(host.backends.is_empty());
}

#[test]
fn aborted_request_can_restore_masks_without_restarting_login_services() {
    let mut host = Fake::new(aborted_accounting(Restoration::NotNeeded));
    let mut ui = Script::new(&[0, 1]);
    drive(&mut host, &mut ui).unwrap();
    assert!(host.actions.is_empty());
    assert!(ui.contains("Login services did not require a restart"));
    assert!(!ui.contains("did not change login services"));
}

#[test]
fn declining_or_cancelling_accounting_maintenance_never_schedules_or_enrolls() {
    for cancel in [false, true] {
        let mut state = report(Phase::Unprepared, false, false);
        state.blocker = Blocker::Accounting;
        let mut host = Fake::new(state.clone());
        let mut ui = Script::new(if cancel { &[0] } else { &[0, 1] });
        if cancel {
            ui.answers.push_back(Err(CliError::Cancelled));
        }
        assert_eq!(
            drive(&mut host, &mut ui),
            if cancel {
                Err(CliError::Cancelled)
            } else {
                Ok(())
            }
        );
        assert!(host.actions.is_empty());
        assert!(host.backends.is_empty());
        assert_eq!(host.state, state);
        assert!(!ui.contains("maintenance is scheduled"));
    }
}

#[test]
fn failed_scheduling_is_not_retried_or_reported_as_success() {
    let mut state = report(Phase::Unprepared, false, false);
    state.blocker = Blocker::Accounting;
    let mut host = Fake::new(state);
    host.fail = Some(Operation::PrepareAccounting);
    let mut ui = Script::new(&[0, 0]);
    assert_eq!(drive(&mut host, &mut ui), Err(CliError::Administrator));
    assert_eq!(host.actions, [Operation::PrepareAccounting]);
    assert!(host.backends.is_empty());
    assert!(!ui.contains("maintenance is scheduled"));
}

#[test]
fn accounting_on_existing_or_ambiguous_state_is_an_administrator_handoff() {
    for mut state in [
        report(Phase::Disabled, false, false),
        report(Phase::Prepared, true, true),
        report(Phase::Unknown, false, false),
        report(Phase::Unprepared, true, false),
    ] {
        state.blocker = Blocker::Accounting;
        let mut host = Fake::new(state);
        let mut ui = Script::new(&[0]);
        assert_eq!(drive(&mut host, &mut ui), Err(CliError::SetupBlocked));
        assert!(host.actions.is_empty());
        assert!(host.backends.is_empty());
    }
}

#[test]
fn scheduling_response_is_exact_and_must_confirm_the_handoff() {
    assert_eq!(accounting_scheduled(br#"{"scheduled":true}"#), Ok(()));
    for bytes in [
        br#"{"scheduled":false}"#.as_slice(),
        br#"{"scheduled":"true"}"#,
        br#"{"scheduled":true,"extra":0}"#,
        br#"{"scheduled":true,"scheduled":true}"#,
        br#"{}"#,
        br#"null"#,
        br#"invalid"#,
    ] {
        assert_eq!(accounting_scheduled(bytes), Err(CliError::SetupReport));
    }
}

#[test]
fn incomplete_and_suspended_states_never_reprepare() {
    for phase in [Phase::Preparing, Phase::Suspended, Phase::Unknown] {
        let mut host = Fake::new(report(phase, false, false));
        let mut ui = Script::new(&[0]);
        assert_eq!(drive(&mut host, &mut ui), Err(CliError::SetupBlocked));
        assert!(host.actions.is_empty());
    }
}

#[test]
fn declining_readiness_does_not_invoke_sudo() {
    let mut host = Fake::new(report(Phase::Unprepared, false, false));
    let mut ui = Script::new(&[1]);
    drive(&mut host, &mut ui).unwrap();
    assert_eq!(host.inspections, 0);
    assert!(host.actions.is_empty());
}

#[test]
fn declining_preparation_only_runs_the_read_only_preview() {
    let mut host = Fake::new(report(Phase::Unprepared, false, false));
    let mut ui = Script::new(&[0, 1, 1]);
    drive(&mut host, &mut ui).unwrap();
    assert_eq!(host.actions, [Operation::Preview]);
    assert_eq!(host.state.phase, Phase::Unprepared);
}

#[test]
fn declining_trial_or_final_activation_retains_committed_state() {
    let mut host = Fake::new(report(Phase::Prepared, true, false));
    let mut ui = Script::new(&[0, 0, 1]);
    drive(&mut host, &mut ui).unwrap();
    assert!(host.actions.is_empty());
    assert!(host.state.enrolled);
    let mut host = Fake::new(report(Phase::Prepared, true, true));
    let mut ui = Script::new(&[0, 0, 0, 0, 1]);
    drive(&mut host, &mut ui).unwrap();
    assert!(host.actions.is_empty());
    assert!(host.state.trial_valid);
    assert!(ui.contains("expires automatically"));
}

#[test]
fn cancelled_choice_does_not_mutate_or_retry() {
    let mut host = Fake::new(report(Phase::Unprepared, false, false));
    let mut ui = Script::new(&[]);
    ui.answers.push_back(Err(CliError::Cancelled));
    assert_eq!(drive(&mut host, &mut ui), Err(CliError::Cancelled));
    assert_eq!(host.inspections, 0);
    assert!(host.actions.is_empty());
}

#[test]
fn tpm_failure_never_retries_with_software_or_starts_a_trial() {
    let mut host = Fake::new(report(Phase::Prepared, false, false));
    host.enrollment_error = Some(CliError::Backend);
    let mut ui = Script::new(&[0, 0, 0]);
    assert_eq!(drive(&mut host, &mut ui), Err(CliError::Backend));
    assert_eq!(host.backends, [BackendPreference::Tpm]);
    assert!(host.actions.is_empty());
}

#[test]
fn expired_or_replaced_trial_cannot_receive_the_users_previous_confirmations() {
    for state in [report(Phase::Prepared, true, false), {
        let mut state = report(Phase::Prepared, true, true);
        state.trial_ref = Some("b".repeat(64));
        state
    }] {
        let mut host = Fake::new(report(Phase::Prepared, true, true));
        host.change_on_inspection = Some((2, state));
        let mut ui = Script::new(&[0, 0, 0, 0, 0]);
        assert_eq!(drive(&mut host, &mut ui), Err(CliError::SetupBlocked));
        assert!(host.actions.is_empty());
        assert!(ui.contains("trial expired or enrollment changed"));
    }
}

#[test]
fn activation_error_does_not_claim_success_or_retry() {
    let mut host = Fake::new(report(Phase::Prepared, true, true));
    host.fail = Some(Operation::Activate);
    let mut ui = Script::new(&[0, 0, 0, 0, 0]);
    assert_eq!(drive(&mut host, &mut ui), Err(CliError::Administrator));
    assert_eq!(host.actions, [Operation::RecordTests, Operation::Activate]);
    assert!(!ui.contains("LocalPIN is active"));
}

#[test]
fn unavailable_broker_or_account_authority_stops_resumed_setup_before_trial() {
    for error in [CliError::Service, CliError::SetupBlocked] {
        let mut host = Fake::new(report(Phase::Prepared, true, false));
        host.account_error = Some(error);
        let mut ui = Script::new(&[0, 0]);
        assert_eq!(drive(&mut host, &mut ui), Err(error));
        assert!(host.actions.is_empty());
        assert!(ui.contains("broker cannot currently establish"));
    }
}
