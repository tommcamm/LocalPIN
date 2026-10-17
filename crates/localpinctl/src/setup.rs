//! Resumable onboarding. Only the privileged helper and broker own authority.

use crate::{
    CliError,
    admin::{self, Blocker, Operation, Phase, SetupReport},
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
        ui.say("The broker cannot currently establish an available PIN for this account and KDE session. Run localpin doctor; resolve account, service, session, storage, or cooldown issues before trial or activation.")?;
        return Err(error);
    }
    Ok(())
}

fn ready(report: &SetupReport, ui: &mut impl Ui) -> Result<(), CliError> {
    let message = match report.blocker {
        Blocker::Accounting => Some(
            "One-time maintenance needed: preserve native password-failure counters while moving them to persistent storage. This must be done offline with other PAM authentication stopped. Setup will not copy live counters or reset them.",
        ),
        Blocker::Multiuser => Some(
            "This installation manages other accounts. The desktop-owner wizard cannot replace that configuration. Use the administrator runbook with the complete account list.",
        ),
        Blocker::Recovery => Some(
            "Existing setup, package, account, or activation state needs administrator recovery. Setup will not repeat preparation or guess a repair.",
        ),
        Blocker::Policy => Some(
            "The supported Fedora KDE policy, system prerequisites, or installed binary binding could not be established. Review administrator diagnostics before changing authentication.",
        ),
        Blocker::None => None,
    };
    if let Some(message) = message {
        ui.say(message)?;
        ui.say(&format!(
            "Guide: {GUIDE}{}",
            if report.blocker == Blocker::Accounting {
                "#prepare-native-accounting-once"
            } else {
                ""
            }
        ))?;
        ui.say(
            "After completing that procedure, return to your KDE terminal and run localpin setup.",
        )?;
        return Err(CliError::SetupBlocked);
    }
    if matches!(
        report.phase,
        Phase::Preparing | Phase::Suspended | Phase::Unknown
    ) {
        ui.say("An incomplete or unsupported system transaction needs administrator recovery. Do not prepare again.")?;
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
    ui.say("Setup paused. Completed preparation and enrollment are retained. A live trial expires automatically; rerun localpin setup to inspect state and resume.")
}

fn drive(host: &mut impl Host, ui: &mut impl Ui) -> Result<(), CliError> {
    ui.say("LocalPIN is experimental. Start in a disposable Fedora KDE VM; keep your full password and an administrator console available.")?;
    ui.say("Setup uses sudo for fixed administrator steps. Creating a PIN separately requires fresh account-password verification; sudo approval does not replace it.")?;
    if !ui.confirm("Check system readiness with administrator access?")? {
        return pause(ui);
    }
    ui.say("[1/5] Check your system")?;
    let mut report = inspect(host, ui)?;
    if report.phase == Phase::Active {
        ui.say("Desktop integration is already active. Setup will preserve it; use the menu to change or disable your PIN.")?;
        return Ok(());
    }
    // This is explicitly an operator statement about earlier real testing,
    // never inferred from a disabled gate or a user-writable checkpoint.
    let recovery_done = if report.tests_recorded {
        true
    } else {
        ui.confirm("Have you successfully rehearsed administrator-console recovery for this installed package BEFORE the final/current preparation and enrollment?")?
    };
    if matches!(report.phase, Phase::Unprepared | Phase::Disabled) {
        ui.say("[2/5] Prepare your account")?;
        ui.say("Preparation backs up and installs the reviewed KDE policy, provisions this account, and starts the broker. Any previous PIN for this account must be enrolled again; desktop PIN use remains disabled.")?;
        if let Some(diff) = host.action(Operation::Preview, None)? {
            ui.say("Proposed desktop policy changes:")?;
            ui.say(&diff)?;
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
        ui.say("[3/5] Create your PIN")?;
        let backend = menu::backend(ui)?;
        host.enroll(backend)?;
        report = inspect(host, ui)?;
        if !report.enrolled {
            return Err(CliError::SetupReport);
        }
    } else {
        ui.say("[3/5] Your committed PIN enrollment is retained.")?;
    }
    check_account(host, ui)?;
    ui.say("[4/5] Test unlocking and recovery")?;
    if !report.trial_valid {
        ui.say("A trial allows PIN testing for ten minutes in this boot, including time suspended. Starting/restarting it clears earlier test attestations; repeat the real unlock tests.")?;
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
    ui.say(&format!("Trial remaining: {} seconds. Keep an administrator console available. Lock KDE normally; enter the PIN in the existing Password field and press Enter.", report.trial_remaining_seconds))?;
    if !report.tests_recorded {
        if !ui.confirm("Have you performed a real PIN unlock successfully during THIS trial?")? {
            return pause(ui);
        }
        ui.say("Lock again and unlock with your full account password. Complete the applicable fingerprint/failure checks in the installation guide; these are manual desktop tests.")?;
        if !ui.confirm("Have full-password unlock and the applicable desktop failure checks passed during THIS trial?")? { return pause(ui); }
        if !recovery_done {
            ui.say("Next: rehearse recovery from an administrator TEXT CONSOLE, following the component-failure and recovery procedure in the guide. Do not run recovery here and call that a console test.")?;
            ui.say("From that console: sudo localpin-integration recover --dry-run\nThen: sudo localpin-integration recover")?;
            ui.say("Verify full-password recovery. Recovery revokes this PIN enrollment. Return to KDE, rerun localpin setup, confirm the completed rehearsal, and prepare/enroll/test again before activation.")?;
            ui.say(&format!(
                "Recovery procedure: {GUIDE}#console-recovery-and-removal"
            ))?;
            return pause(ui);
        }
    }
    ui.say("[5/5] Activate PIN unlocking")?;
    ui.say("Your confirmations record an administrator attestation, not automated desktop or hardware verification. Activation enables PIN integration now and on future boots.")?;
    if !ui.confirm("Record the completed tests and activate LocalPIN?")? {
        return pause(ui);
    }
    report = inspect(host, ui)?;
    if !report.trial_valid || !report.enrolled || report.trial_ref.as_deref() != Some(&tested_trial)
    {
        ui.say("The trial expired or enrollment changed. Rerun setup, start a new trial and repeat the desktop tests.")?;
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
    ui.say("LocalPIN is active. Lock your KDE session, enter your PIN and press Enter. Your full account password remains available under normal account policy.\nNext time: localpin opens the menu; localpin status checks availability.")
}

pub(crate) fn run() -> Result<(), CliError> {
    let uid = rustix::process::getuid().as_raw();
    if !(1000..=59999).contains(&uid) || uid != rustix::process::geteuid().as_raw() {
        eprintln!(
            "Run localpin setup as your normal user in a foreground KDE terminal, without sudo."
        );
        return Err(CliError::Forbidden);
    }
    let mut terminal = Terminal::open()?;
    menu::heading("Set up PIN unlocking");
    terminal.say(&format!("Account UID: {uid}"))?;
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
            terminal.say(&format!(
                "Saved state: {:?}; PIN enrolled: {}.",
                report.phase, report.enrolled
            ))?;
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
