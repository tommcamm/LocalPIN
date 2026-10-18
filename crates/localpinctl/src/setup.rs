//! Resumable onboarding. Only the privileged helper and broker own authority.

use crate::{
    CliError,
    admin::{self, AccountingResult, Blocker, Operation, Phase, Restoration, SetupReport},
    args::Command,
    menu::{self, Ui},
    terminal::Terminal,
};
use localpin_protocol::{
    Availability, BackendPreference, Reason,
    transport::{CONNECT_TIMEOUT, Client, Deadline},
};
use std::path::Path;

const GUIDE: &str =
    "https://github.com/tommcamm/LocalPIN/blob/main/docs/integration-administration.md";

trait Host {
    fn inspect(&mut self) -> Result<SetupReport, CliError>;
    fn action(
        &mut self,
        operation: Operation,
        trial_ref: Option<&str>,
    ) -> Result<Option<String>, CliError>;
    fn enroll(&mut self, backend: BackendPreference) -> Result<(), CliError>;
    fn check_account(&mut self) -> Result<(), CliError>;
}

struct System {
    uid: u32,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct AccountingScheduled {
    scheduled: bool,
}

fn accounting_scheduled(bytes: &[u8]) -> Result<(), CliError> {
    let result: AccountingScheduled =
        serde_json::from_slice(bytes).map_err(|_| CliError::SetupReport)?;
    if !result.scheduled {
        return Err(CliError::SetupReport);
    }
    Ok(())
}

impl Host for System {
    fn inspect(&mut self) -> Result<SetupReport, CliError> {
        SetupReport::parse(&admin::invoke(Operation::Inspect, self.uid, None)?)
    }

    fn action(
        &mut self,
        operation: Operation,
        trial_ref: Option<&str>,
    ) -> Result<Option<String>, CliError> {
        let bytes = admin::invoke(operation, self.uid, trial_ref)?;
        if operation == Operation::PrepareAccounting {
            accounting_scheduled(&bytes)?;
            return Ok(None);
        }
        // Mutation responses cannot confer authority: each next step rereads
        // the root report, and each mutation rechecks its UID scope under lock.
        let result: serde_json::Value =
            serde_json::from_slice(&bytes).map_err(|_| CliError::SetupReport)?;
        if !result.is_object() {
            return Err(CliError::SetupReport);
        }
        Ok(if operation == Operation::Preview {
            Some(
                result
                    .get("diff")
                    .and_then(|value| value.as_str())
                    .ok_or(CliError::SetupReport)?
                    .to_owned(),
            )
        } else {
            None
        })
    }

    fn enroll(&mut self, backend: BackendPreference) -> Result<(), CliError> {
        crate::workflow::execute(Command::Enroll(backend))
    }

    fn check_account(&mut self) -> Result<(), CliError> {
        let mut client = Client::connect(
            Path::new("/run/localpin/broker.sock"),
            Deadline::after(CONNECT_TIMEOUT),
        )?;
        let status = client.status()?;
        client.close();
        if status.enrolled.is_none()
            || status.reason != Reason::None
            || !matches!(status.availability, Availability::Available)
        {
            return Err(CliError::SetupBlocked);
        }
        Ok(())
    }
}

fn check_account(host: &mut impl Host, ui: &mut impl Ui) -> Result<(), CliError> {
    if let Err(error) = host.check_account() {
        ui.warning("The broker cannot currently establish an available PIN for this account and KDE session.")?;
        ui.say("Run localpin doctor. Resolve account, service, session, storage or cooldown issues before trial or activation.")?;
        return Err(error);
    }
    Ok(())
}

fn ready(report: &SetupReport, ui: &mut impl Ui) -> Result<(), CliError> {
    if report
        .accounting_outcome
        .as_ref()
        .is_some_and(|outcome| outcome.restoration == Restoration::Pending)
    {
        ui.say("Login service restoration remains incomplete. Setup will not retry maintenance or enroll a credential; use administrator recovery to inspect the protected maintenance state.")?;
        return Err(CliError::SetupBlocked);
    }
    let message = match report.blocker {
        Blocker::Accounting => Some(
            "Password-failure counters need persistent storage. This installation requires administrator maintenance; setup cannot safely schedule it in the reported state.",
        ),
        Blocker::AccountingMaintenance => Some(
            "Password-accounting maintenance is pending, failed or interrupted. Use administrator recovery to inspect the protected state before another migration or enrollment.",
        ),
        Blocker::Multiuser => Some(
            "This installation manages other accounts. Use the administrator runbook with the complete account list; the desktop-owner wizard cannot replace that configuration.",
        ),
        Blocker::Recovery => Some(
            "Setup, package, account or activation state needs administrator recovery. Setup cannot repeat preparation or choose a repair.",
        ),
        Blocker::Policy => Some(
            "Supported Fedora KDE policy, system prerequisites or installed binaries could not be verified. Review administrator diagnostics before changing authentication.",
        ),
        Blocker::None => None,
    };
    if let Some(message) = message {
        ui.heading("Administrator action needed")?;
        ui.warning(message)?;
        ui.detail(
            "Guide",
            &format!(
                "{GUIDE}{}",
                if matches!(
                    report.blocker,
                    Blocker::Accounting | Blocker::AccountingMaintenance
                ) {
                    "#prepare-native-accounting-once"
                } else {
                    ""
                }
            ),
        )?;
        ui.say(
            "After completing that procedure, return to your KDE terminal and run localpin setup.",
        )?;
        return Err(CliError::SetupBlocked);
    }
    if matches!(
        report.phase,
        Phase::Preparing | Phase::Suspended | Phase::Unknown
    ) {
        ui.warning("An incomplete or unsupported system transaction needs administrator recovery. Do not prepare again.")?;
        return Err(CliError::SetupBlocked);
    }
    Ok(())
}

fn inspect(host: &mut impl Host, ui: &mut impl Ui) -> Result<SetupReport, CliError> {
    let report = host.inspect()?;
    ready(&report, ui)?;
    Ok(report)
}

fn pause(ui: &mut impl Ui) -> Result<(), CliError> {
    ui.heading("Setup paused")?;
    ui.say(
        "Completed preparation and enrollment are retained. A live trial expires automatically.",
    )?;
    ui.say("Resume: localpin setup")
}

fn drive(host: &mut impl Host, ui: &mut impl Ui) -> Result<(), CliError> {
    ui.heading("Before you start")?;
    ui.warning("LocalPIN is experimental. Start in a disposable Fedora KDE VM.")?;
    ui.say("Keep your full password and an administrator console available.")?;
    ui.say("Setup uses sudo for fixed administrator steps. Creating a credential requires fresh account-password verification; sudo approval does not replace it.")?;
    ui.warning("An account password matching your credential's exact length and format can consume a LocalPIN attempt, and potentially TPM allowance, before password fallback.")?;
    if !ui.confirm("Check system readiness with administrator access?")? {
        return pause(ui);
    }
    ui.step(1, 5, "Check your system")?;
    let mut report = host.inspect()?;
    while let Some(outcome) = &report.accounting_outcome {
        match outcome.result {
            AccountingResult::Aborted => ui.say("The previous password-accounting maintenance was aborted. Native accounting was preserved; the prior preparation remains incomplete. Setup has not retried it.")?,
            AccountingResult::Complete => ui.say("The previous password-accounting migration completed. Setup will recheck current readiness before continuing.")?,
        }
        if let Some(operation) = outcome.failed_operation {
            ui.say(&format!(
                "Failed maintenance operation: {}.",
                operation.description()
            ))?;
        }
        match outcome.restoration {
            Restoration::NotNeeded => ui.say("Login services did not require a restart.")?,
            Restoration::Restored => {
                ui.say("Login service restoration is recorded as complete.")?
            }
            Restoration::Pending => {
                ui.say("Login service restoration has not yet been verified. Setup will not retry maintenance or enroll a credential while restoration is unverified. You can recheck readiness without changing the system, or exit and use administrator recovery if restoration remains incomplete.")?;
                ui.say(&format!("Guide: {GUIDE}#prepare-native-accounting-once"))?;
                match ui.choose(
                    "Recheck readiness or exit setup?",
                    &["Recheck readiness", "Exit setup"],
                )? {
                    0 => {
                        report = host.inspect()?;
                        continue;
                    }
                    1 => return Err(CliError::SetupBlocked),
                    _ => return Err(CliError::Arguments),
                }
            }
        }
        break;
    }
    if report.blocker == Blocker::Accounting
        && report.phase == Phase::Unprepared
        && !report.enrolled
        && !report.trial_valid
    {
        ui.heading("One-time password-accounting maintenance")?;
        ui.say("Before PIN setup, maintenance must preserve every account's password-failure counters in persistent storage.")?;
        ui.warning("Save your work. After approval, maintenance will log out all users.")?;
        ui.say("In this boot, it will stop running services and background jobs, and briefly stop authentication.")?;
        ui.say("Normal desktop services will restart; background jobs may need restarting.")?;
        ui.say(
            "Log back into KDE with your full account password; setup will reopen automatically.",
        )?;
        ui.detail("Enrollment", "No credential has been created yet.")?;
        if !ui.confirm(
            "Have you saved your work, and approve logging out all users and stopping services and background jobs for this maintenance?",
        )? {
            return pause(ui);
        }
        host.action(Operation::PrepareAccounting, None)?;
        ui.success("Password-accounting maintenance is scheduled.")?;
        ui.say("Wait for the login screen, then log into KDE with your full account password.")?;
        return ui
            .say("Setup will reopen and recheck readiness. If it does not, run localpin setup.");
    }
    ready(&report, ui)?;
    if report.phase == Phase::Active {
        if report.enrolled {
            ui.success("Desktop integration is already active.")?;
            ui.say("Manage your credential: localpin menu. Check availability: localpin status.")?;
            return Ok(());
        }
        ui.detail("Desktop integration", "Active")?;
        ui.say("This account has no credential. Creating one preserves the active integration.")?;
        if !ui.confirm("Create a new credential for this account?")? {
            return pause(ui);
        }
        let backend = menu::backend(ui)?;
        host.enroll(backend)?;
        report = inspect(host, ui)?;
        if report.phase != Phase::Active || !report.enrolled {
            return Err(CliError::SetupReport);
        }
        check_account(host, ui)?;
        ui.success("Your new credential is ready. Desktop integration remains active.")?;
        ui.say("Lock your KDE session, enter your credential and press Enter.")?;
        return ui.say("Your full account password remains available under normal account policy.");
    }
    // This is explicitly an operator statement about earlier real testing,
    // never inferred from a disabled gate or a user-writable checkpoint.
    let recovery_done = if report.tests_recorded {
        true
    } else {
        ui.confirm("Have you successfully rehearsed administrator-console recovery for this installed package BEFORE the final/current preparation and enrollment?")?
    };
    if matches!(report.phase, Phase::Unprepared | Phase::Disabled) {
        ui.step(2, 5, "Prepare your account")?;
        ui.say("Preparation backs up and installs the reviewed KDE policy, provisions this account, and starts the broker.")?;
        ui.warning("Any previous PIN must be enrolled again. Desktop PIN use remains disabled.")?;
        if let Some(diff) = host.action(Operation::Preview, None)? {
            ui.policy_diff(&diff)?;
        }
        if !ui.confirm("Apply these system changes for your account?")? {
            return pause(ui);
        }
        host.action(Operation::Prepare, None)?;
        report = inspect(host, ui)?;
        if report.phase != Phase::Prepared {
            return Err(CliError::SetupReport);
        }
    }
    if !report.enrolled {
        ui.step(3, 5, "Create your credential")?;
        let backend = menu::backend(ui)?;
        host.enroll(backend)?;
        report = inspect(host, ui)?;
        if !report.enrolled {
            return Err(CliError::SetupReport);
        }
    } else {
        ui.step(3, 5, "Keep your credential")?;
        ui.say("Your committed credential enrollment is retained.")?;
    }
    check_account(host, ui)?;
    ui.step(4, 5, "Test unlocking and recovery")?;
    if !report.trial_valid {
        ui.say(
            "A trial allows PIN testing for ten minutes in this boot, including time suspended.",
        )?;
        ui.warning("Starting or restarting a trial clears earlier test attestations. Repeat the real unlock tests.")?;
        if !ui.confirm("Start a new ten-minute desktop trial?")? {
            return pause(ui);
        }
        host.action(Operation::Trial, None)?;
        report = inspect(host, ui)?;
    }
    if !report.trial_valid {
        return Err(CliError::SetupReport);
    }
    let tested_trial = report.trial_ref.clone().ok_or(CliError::SetupReport)?;
    ui.detail(
        "Trial remaining",
        &format!("{} seconds", report.trial_remaining_seconds),
    )?;
    ui.say("Keep an administrator console available. Lock KDE normally, enter your credential in the existing Password field and press Enter.")?;
    if !report.tests_recorded {
        if !ui.confirm("Have you performed a real PIN unlock successfully during THIS trial?")? {
            return pause(ui);
        }
        ui.say("Lock again and unlock with your full account password.")?;
        ui.say("Complete the applicable fingerprint and failure checks in the installation guide. These are manual desktop tests.")?;
        if !ui.confirm("Have full-password unlock and the applicable desktop failure checks passed during THIS trial?")? { return pause(ui); }
        if !recovery_done {
            ui.heading("Rehearse console recovery")?;
            ui.warning("Use an administrator TEXT CONSOLE. Follow the guide's component-failure and recovery procedure; running recovery here does not count as a console test.")?;
            ui.say("From that console, run:")?;
            ui.say("  sudo localpin-integration recover --dry-run\n  sudo localpin-integration recover")?;
            ui.warning("Recovery revokes this PIN enrollment. Verify full-password recovery.")?;
            ui.say("Return to KDE and rerun localpin setup. Confirm the rehearsal, then prepare, enroll and test again before activation.")?;
            ui.detail(
                "Recovery procedure",
                &format!("{GUIDE}#console-recovery-and-removal"),
            )?;
            return pause(ui);
        }
    }
    ui.step(5, 5, "Activate PIN unlocking")?;
    ui.warning("Your confirmations record an administrator attestation, not automated desktop or hardware verification.")?;
    ui.say("Activation enables PIN integration now and on future boots.")?;
    if !ui.confirm("Record the completed tests and activate LocalPIN?")? {
        return pause(ui);
    }
    report = inspect(host, ui)?;
    if !report.trial_valid || !report.enrolled || report.trial_ref.as_deref() != Some(&tested_trial)
    {
        ui.warning("The trial expired or enrollment changed. Rerun setup, start a new trial and repeat the desktop tests.")?;
        return Err(CliError::SetupBlocked);
    }
    check_account(host, ui)?;
    if !report.tests_recorded {
        host.action(Operation::RecordTests, Some(&tested_trial))?;
    }
    host.action(Operation::Activate, Some(&tested_trial))?;
    report = inspect(host, ui)?;
    if report.phase != Phase::Active {
        return Err(CliError::SetupReport);
    }
    ui.success("LocalPIN is active.")?;
    ui.say("Lock your KDE session, enter your credential and press Enter.")?;
    ui.say("Your full account password remains available under normal account policy.")?;
    ui.say("Next time: localpin menu to manage your credential; localpin status to check availability.")
}

fn phase_label(phase: Phase) -> &'static str {
    match phase {
        Phase::Unprepared => "Not prepared",
        Phase::Disabled => "Disabled",
        Phase::Prepared => "Prepared",
        Phase::Active => "Active",
        Phase::Preparing => "Preparation incomplete",
        Phase::Suspended => "Suspended",
        Phase::Unknown => "Unknown",
    }
}

pub(crate) fn run() -> Result<(), CliError> {
    let uid = rustix::process::getuid().as_raw();
    if !(1000..=59999).contains(&uid) || uid != rustix::process::geteuid().as_raw() {
        crate::presentation::diagnostic(
            "Run localpin setup as your normal user in a foreground KDE terminal, without sudo.",
        );
        return Err(CliError::Forbidden);
    }
    let mut terminal = Terminal::open()?;
    terminal.present(|renderer| renderer.heading("Set up PIN unlocking"))?;
    terminal.detail("Account UID", &uid.to_string())?;
    let mut host = System { uid };
    let result = drive(&mut host, &mut terminal);
    if result.is_err() {
        if result == Err(CliError::Cancelled) {
            pause(&mut terminal)?;
        }
        // An interrupted/failed response may follow a durable commit. Never
        // repeat a mutation, or claim rollback, without a new authoritative read.
        if !matches!(result, Err(CliError::Cancelled | CliError::SetupBlocked))
            && let Ok(report) = host.inspect()
        {
            terminal.heading("Current saved state")?;
            terminal.detail("Integration", phase_label(report.phase))?;
            terminal.detail(
                "Credential",
                if report.enrolled {
                    "Enrolled"
                } else {
                    "Not enrolled"
                },
            )?;
            if report.trial_valid {
                terminal.say(&format!(
                    "A trial remains open for up to {} seconds and expires automatically.",
                    report.trial_remaining_seconds
                ))?;
            }
        }
        terminal.say("No automatic rollback or retry was attempted. Rerun localpin setup to inspect the current state.")?;
    }
    result
}

#[cfg(test)]
mod tests;
