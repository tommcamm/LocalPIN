//! Closed administrator operations. No shell, caller-selected paths or secrets.

use crate::CliError;
use serde::Deserialize;
use std::io::Read;
use std::process::{Command, Stdio};

const SUDO: &str = "/usr/bin/sudo";
const HELPER: &str = "/usr/libexec/localpin/localpin-integration";
const OUTPUT_LIMIT: u64 = 65536;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Phase {
    Unprepared,
    Disabled,
    Prepared,
    Active,
    Preparing,
    Suspended,
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Blocker {
    None,
    Accounting,
    #[serde(rename = "accounting-maintenance")]
    AccountingMaintenance,
    Multiuser,
    Recovery,
    Policy,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub(crate) enum AccountingResult {
    Complete,
    Aborted,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Restoration {
    NotNeeded,
    Pending,
    Restored,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum FailedOperation {
    RpmLockPath,
    MaskAuthentication,
    StopSessions,
    IsolateMaintenance,
    PersistentFilesystem,
    LabelWork,
    LabelResume,
    LabelPersistent,
    ScheduleMaintenance,
    BeginMaintenance,
    UnmaskOwned,
    RestoreGraphical,
    RestoreListeners,
    RestorationJobs,
    RestorationStatus,
    Emergency,
    SelinuxStatus,
    DisplayManagerStatus,
    RestoreUnitStatus,
    MaskStatus,
}

impl FailedOperation {
    pub fn description(self) -> &'static str {
        match self {
            Self::RpmLockPath => "check the native RPM lock path",
            Self::MaskAuthentication => "temporarily mask authentication services",
            Self::StopSessions => "stop user sessions",
            Self::IsolateMaintenance => "isolate the maintenance target",
            Self::PersistentFilesystem => "check the persistent accounting filesystem",
            Self::LabelWork => "label the maintenance directory",
            Self::LabelResume => "label the setup resume hint",
            Self::LabelPersistent => "label persistent accounting",
            Self::ScheduleMaintenance => "schedule the maintenance service",
            Self::BeginMaintenance => "begin the maintenance service",
            Self::UnmaskOwned => "remove maintenance authentication masks",
            Self::RestoreGraphical => "restore the graphical login target",
            Self::RestoreListeners => "restore login services",
            Self::RestorationJobs => "check pending service restoration jobs",
            Self::RestorationStatus => "verify restored login services",
            Self::Emergency => "select administrator emergency recovery",
            Self::SelinuxStatus => "check SELinux enforcement",
            Self::DisplayManagerStatus => "check the display manager",
            Self::RestoreUnitStatus => "check login services before maintenance",
            Self::MaskStatus => "check authentication service masks",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub(crate) struct AccountingOutcome {
    pub result: AccountingResult,
    pub restoration: Restoration,
    #[serde(deserialize_with = "Option::deserialize")]
    pub failed_operation: Option<FailedOperation>,
}

/// Separate from the unchanged public status/doctor JSON schema.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub(crate) struct SetupReport {
    pub schema_version: u32,
    pub phase: Phase,
    pub blocker: Blocker,
    pub enrolled: bool,
    pub trial_valid: bool,
    pub trial_remaining_seconds: u32,
    #[serde(deserialize_with = "Option::deserialize")]
    pub trial_ref: Option<String>,
    pub tests_recorded: bool,
    #[serde(default)]
    pub accounting_outcome: Option<AccountingOutcome>,
}

impl SetupReport {
    pub fn parse(bytes: &[u8]) -> Result<Self, CliError> {
        if bytes.len() > OUTPUT_LIMIT as usize {
            return Err(CliError::SetupReport);
        }
        let report: Self = serde_json::from_slice(bytes).map_err(|_| CliError::SetupReport)?;
        if report.schema_version != 1
            || report.trial_remaining_seconds > 600
            || report.trial_valid != (report.trial_remaining_seconds > 0)
            || report.trial_valid != report.trial_ref.is_some()
            || report
                .trial_ref
                .as_deref()
                .is_some_and(|value| !valid_reference(value))
            || (report.trial_valid && (report.phase != Phase::Prepared || !report.enrolled))
        {
            return Err(CliError::SetupReport);
        }
        Ok(report)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Operation {
    Inspect,
    Preview,
    Prepare,
    PrepareAccounting,
    Trial,
    RecordTests,
    Activate,
}

/// Arguments come only from a closed enum and the kernel's current UID.
fn valid_reference(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn command(operation: Operation, uid: u32, trial_ref: Option<&str>) -> Result<Command, CliError> {
    if !(1000..=59999).contains(&uid) {
        return Err(CliError::Forbidden);
    }
    if matches!(operation, Operation::RecordTests | Operation::Activate) != trial_ref.is_some()
        || trial_ref.is_some_and(|value| !valid_reference(value))
    {
        return Err(CliError::SetupReport);
    }
    let mut command = Command::new(SUDO);
    command
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin")
        .env("LANG", "C")
        .env("LC_ALL", "C")
        .env("TERM", "dumb")
        .arg("--")
        .arg(HELPER)
        .arg(match operation {
            Operation::Inspect => "setup-status",
            Operation::Preview | Operation::Prepare => "prepare",
            Operation::PrepareAccounting => "prepare-accounting",
            Operation::Trial => "trial",
            Operation::RecordTests => "record-tests",
            Operation::Activate => "activate",
        });
    if matches!(
        operation,
        Operation::Inspect | Operation::Preview | Operation::Prepare
    ) {
        command.args(["--uid", &uid.to_string()]);
    }
    if operation != Operation::Inspect {
        command.args(["--setup-uid", &uid.to_string()]);
    }
    if operation == Operation::Preview {
        command.arg("--dry-run");
    }
    if operation == Operation::RecordTests {
        command.args(["--pin", "--password", "--recovery"]);
    }
    if let Some(reference) = trial_ref {
        command.args(["--setup-trial", reference]);
    }
    // sudo reads its own password from the controlling terminal. Never use -S,
    // askpass, a shell, or a pipe carrying the account password/PIN.
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit());
    Ok(command)
}

pub(crate) fn invoke(
    operation: Operation,
    uid: u32,
    trial_ref: Option<&str>,
) -> Result<Vec<u8>, CliError> {
    let mut child = command(operation, uid, trial_ref)?
        .spawn()
        .map_err(|_| CliError::Administrator)?;
    let mut bytes = Vec::new();
    let read = child
        .stdout
        .take()
        .ok_or(CliError::Administrator)?
        .take(OUTPUT_LIMIT + 1)
        .read_to_end(&mut bytes);
    if read.is_err() || bytes.len() > OUTPUT_LIMIT as usize {
        let _ = child.kill();
        let _ = child.wait();
        return Err(CliError::SetupReport);
    }
    let status = child.wait().map_err(|_| CliError::Administrator)?;
    if !status.success() {
        return Err(CliError::Administrator);
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn privilege_boundary_has_fixed_executable_environment_and_arguments() {
        for operation in [
            Operation::Inspect,
            Operation::Preview,
            Operation::Prepare,
            Operation::PrepareAccounting,
            Operation::Trial,
            Operation::RecordTests,
            Operation::Activate,
        ] {
            let reference = "a".repeat(64);
            let trial_ref = matches!(operation, Operation::RecordTests | Operation::Activate)
                .then_some(reference.as_str());
            let command = command(operation, 1001, trial_ref).unwrap();
            assert_eq!(command.get_program(), SUDO);
            let args: Vec<_> = command.get_args().map(|s| s.to_str().unwrap()).collect();
            assert_eq!(&args[..2], &["--", HELPER]);
            assert!(
                !args
                    .iter()
                    .any(|arg| ["-S", "-A", "sh", "--preserve-env"].contains(arg))
            );
            if operation != Operation::Inspect {
                assert!(args.windows(2).any(|pair| pair == ["--setup-uid", "1001"]));
            }
            if operation == Operation::PrepareAccounting {
                assert_eq!(
                    args,
                    ["--", HELPER, "prepare-accounting", "--setup-uid", "1001"]
                );
            }
            let env: Vec<_> = command.get_envs().collect();
            assert_eq!(env.len(), 4);
        }
        assert!(command(Operation::Prepare, 0, None).is_err());
        assert!(command(Operation::Prepare, 60000, None).is_err());
        assert!(command(Operation::Activate, 1001, None).is_err());
        assert!(command(Operation::Activate, 1001, Some("invalid")).is_err());
        assert!(command(Operation::Trial, 1001, Some(&"a".repeat(64))).is_err());
    }

    #[test]
    fn report_is_closed_bounded_and_checks_trial_consistency() {
        let value = format!(
            r#"{{"schema_version":1,"phase":"prepared","blocker":"none","enrolled":true,"trial_valid":true,"trial_remaining_seconds":599,"trial_ref":"{}","tests_recorded":false}}"#,
            "a".repeat(64)
        );
        let valid = value.as_bytes();
        assert!(SetupReport::parse(valid).unwrap().trial_valid);
        for (old, new) in [
            ("599", "601"),
            ("599", "0"),
            ("prepared", "active"),
            ("\"enrolled\":true", "\"enrolled\":false"),
            ("\"schema_version\":1", "\"schema_version\":2"),
        ] {
            let bad = std::str::from_utf8(valid).unwrap().replace(old, new);
            assert_eq!(
                SetupReport::parse(bad.as_bytes()),
                Err(CliError::SetupReport)
            );
        }
        assert_eq!(
            SetupReport::parse(&vec![b' '; 65537]),
            Err(CliError::SetupReport)
        );
        assert_eq!(SetupReport::parse(b"{}"), Err(CliError::SetupReport));
        let extra = std::str::from_utf8(valid)
            .unwrap()
            .replace("{", "{\"secret\":false,");
        assert_eq!(
            SetupReport::parse(extra.as_bytes()),
            Err(CliError::SetupReport)
        );
        let duplicate = std::str::from_utf8(valid)
            .unwrap()
            .replace("{", "{\"phase\":\"active\",");
        assert_eq!(
            SetupReport::parse(duplicate.as_bytes()),
            Err(CliError::SetupReport)
        );
        let inactive = value
            .replace("\"trial_valid\":true", "\"trial_valid\":false")
            .replace(
                "\"trial_remaining_seconds\":599",
                "\"trial_remaining_seconds\":0",
            )
            .replace(
                &format!("\"trial_ref\":\"{}\"", "a".repeat(64)),
                "\"trial_ref\":null",
            );
        assert!(SetupReport::parse(inactive.as_bytes()).is_ok());
        let missing = inactive.replace("\"trial_ref\":null,", "");
        assert_eq!(
            SetupReport::parse(missing.as_bytes()),
            Err(CliError::SetupReport)
        );
    }

    #[test]
    fn accounting_outcome_is_optional_and_accepts_only_closed_nonsecret_fields() {
        let base = r#"{"schema_version":1,"phase":"unprepared","blocker":"accounting","enrolled":false,"trial_valid":false,"trial_remaining_seconds":0,"trial_ref":null,"tests_recorded":false}"#;
        assert!(
            SetupReport::parse(base.as_bytes())
                .unwrap()
                .accounting_outcome
                .is_none()
        );
        let add = |outcome: &str| {
            format!(
                "{},\"accounting_outcome\":{outcome}}}",
                &base[..base.len() - 1]
            )
        };
        let outcome =
            r#"{"result":"aborted","restoration":"restored","failed_operation":"stop-sessions"}"#;
        let parsed = SetupReport::parse(add(outcome).as_bytes()).unwrap();
        assert_eq!(
            parsed.accounting_outcome.unwrap(),
            AccountingOutcome {
                result: AccountingResult::Aborted,
                restoration: Restoration::Restored,
                failed_operation: Some(FailedOperation::StopSessions),
            }
        );
        for outcome in [
            outcome.replace("aborted", "failed"),
            outcome.replace("restored", "unknown"),
            outcome.replace("stop-sessions", "untrusted terminal output"),
            outcome.replace("\"result\":", "\"extra\":true,\"result\":"),
            outcome.replace("\"result\":", "\"result\":\"complete\",\"result\":"),
            r#"{"result":"aborted","restoration":"pending"}"#.to_owned(),
        ] {
            assert_eq!(
                SetupReport::parse(add(&outcome).as_bytes()),
                Err(CliError::SetupReport)
            );
        }
        for result in ["complete", "aborted"] {
            for restoration in ["not-needed", "pending", "restored"] {
                let outcome = format!(
                    r#"{{"result":"{result}","restoration":"{restoration}","failed_operation":null}}"#
                );
                assert!(SetupReport::parse(add(&outcome).as_bytes()).is_ok());
            }
        }
    }
}
