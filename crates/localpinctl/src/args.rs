//! Closed command grammar: secrets never have a command-line representation.

use localpin_protocol::BackendPreference;
use std::ffi::{OsStr, OsString};

use crate::CliError;

/// Public, nonsecret command selection.
#[derive(Debug, Eq, PartialEq)]
pub enum Command {
    /// Open the interactive command menu, or show help without a terminal.
    Menu,
    /// Guide the current local account through preparation and activation.
    Setup,
    /// Print the supported command grammar.
    Help,
    /// Print the application version.
    Version,
    /// Inspect own-account status, optionally as versioned JSON.
    Status {
        /// Use the separately versioned nonsecret JSON schema.
        json: bool,
        /// Add actionable component and recovery diagnostics.
        doctor: bool,
    },
    /// Establish a new enrollment using an explicit backend preference.
    Enroll(BackendPreference),
    /// Replace the PIN on the committed backend.
    Change,
    /// Disable the own-account credential after fresh password verification.
    Disable,
    /// Explicitly replace the backend and PIN.
    Migrate(BackendPreference),
    /// Display system integration state.
    IntegrationStatus,
    /// Show the exact root activation command and its separate test prerequisite.
    IntegrationEnable,
    /// Show the exact root integration-disable command.
    IntegrationDisable,
    /// Root-only recovery of a named local account.
    Recover(String),
}

/// Parse arguments without copying, printing or interpolating rejected values.
pub fn parse(args: &[OsString]) -> Result<Command, CliError> {
    let equals = |index: usize, value: &str| args.get(index).is_some_and(|arg| arg == value);
    match args.len() {
        0 => Ok(Command::Menu),
        1 if equals(0, "setup") => Ok(Command::Setup),
        1 if equals(0, "--help") || equals(0, "help") => Ok(Command::Help),
        1 if equals(0, "--version") => Ok(Command::Version),
        1 | 2 if equals(0, "status") || equals(0, "doctor") => {
            if args.len() == 2 && !equals(1, "--json") {
                return Err(CliError::Arguments);
            }
            Ok(Command::Status {
                json: args.len() == 2,
                doctor: equals(0, "doctor"),
            })
        }
        1 if equals(0, "change") => Ok(Command::Change),
        1 if equals(0, "disable") => Ok(Command::Disable),
        3 if (equals(0, "enroll") || equals(0, "migrate")) && equals(1, "--backend") => {
            let backend = match args[2].to_str() {
                Some("auto") if equals(0, "enroll") => BackendPreference::Auto,
                Some("tpm2-required") => BackendPreference::Tpm,
                Some("software") => BackendPreference::Software,
                _ => return Err(CliError::Arguments),
            };
            if equals(0, "enroll") {
                Ok(Command::Enroll(backend))
            } else {
                Ok(Command::Migrate(backend))
            }
        }
        2 if equals(0, "integration") && equals(1, "status") => Ok(Command::IntegrationStatus),
        2 if equals(0, "integration") && equals(1, "enable") => Ok(Command::IntegrationEnable),
        2 if equals(0, "integration") && equals(1, "disable") => Ok(Command::IntegrationDisable),
        3 if equals(0, "recover") && equals(1, "--user") => {
            let account = args[2].to_str().ok_or(CliError::Arguments)?;
            if account.is_empty()
                || account.len() > 256
                || !account
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"_-.$".contains(&b))
            {
                return Err(CliError::Arguments);
            }
            Ok(Command::Recover(account.to_owned()))
        }
        _ => Err(CliError::Arguments),
    }
}

/// Reject secret-bearing LocalPIN environment channels; values are never read.
///
/// There is no environment configuration or test/simulator injection in this CLI.
pub fn check_environment(
    names: impl IntoIterator<Item = impl AsRef<OsStr>>,
) -> Result<(), CliError> {
    for name in names {
        let name = name.as_ref().as_encoded_bytes();
        if name.starts_with(b"LOCALPIN_") || name == b"PIN" || name == b"PASSWORD" {
            return Err(CliError::SecretEnvironment);
        }
    }
    Ok(())
}

/// Supported commands and security-relevant input behavior.
pub const HELP: &str = "LocalPIN — a PIN for your local desktop account\n\nUsage: localpin [command]\n\nGet started\n  setup                                      Set up or resume guided onboarding\n  status [--json]                             See enrollment and activation\n  doctor [--json]                             Diagnose readiness and next steps\n\nManage your PIN\n  enroll --backend auto|tpm2-required|software Create a PIN with fresh password verification\n  change                                     Choose a new PIN\n  disable                                    Disable your PIN credential\n  migrate --backend tpm2-required|software    Replace protection and choose a new PIN\n\nAdministration\n  integration status                         Inspect the desktop integration gate\n  integration enable|disable                 Show the separate administrator command\n  recover --user <account>                   Recover a local account (administrator only)\n\n  --help                                     Show this help\n  --version                                  Show the installed version\n\nRun localpin with no command to open the interactive menu. The existing\nlocalpinctl command remains compatible. For the guided install path, run\nlocalpin setup as your normal desktop user; sudo prompts authorize system changes.\n\nPINs and passwords use private foreground-terminal prompts. No secret arguments,\nenvironment variables, stdin input, or simulator overrides are supported.\nInstallation and enrollment do not activate integration: preparation, a bounded\ntrial, recovery rehearsal, and administrator-recorded tests precede activation.\nAdministrator details: sudo localpin-integration status";

#[cfg(test)]
mod tests {
    use super::*;
    fn command(parts: &[&str]) -> Result<Command, CliError> {
        parse(&parts.iter().map(OsString::from).collect::<Vec<_>>())
    }
    #[test]
    fn rejects_every_secret_argument_and_extra_value() {
        for parts in [
            vec!["enroll", "--pin", "123456"],
            vec!["enroll", "--backend", "software", "123456"],
            vec!["change", "--password-stdin"],
            vec!["disable", "--yes"],
            vec!["status", "--pin=123456"],
            vec!["enroll", "--backend", "simulator"],
            vec!["migrate", "--backend", "auto"],
            vec!["recover", "--user", "root", "--pin", "123456"],
        ] {
            assert_eq!(command(&parts), Err(CliError::Arguments));
        }
    }
    #[test]
    fn accepts_only_explicit_command_grammar() {
        assert_eq!(command(&[]), Ok(Command::Menu));
        assert_eq!(command(&["setup"]), Ok(Command::Setup));
        for parts in [vec!["setup", "--yes"], vec!["setup", "--user", "other"]] {
            assert_eq!(command(&parts), Err(CliError::Arguments));
        }
        assert_eq!(
            command(&["enroll", "--backend", "software"]),
            Ok(Command::Enroll(BackendPreference::Software))
        );
        assert_eq!(
            command(&["migrate", "--backend", "tpm2-required"]),
            Ok(Command::Migrate(BackendPreference::Tpm))
        );
        assert_eq!(
            command(&["doctor", "--json"]),
            Ok(Command::Status {
                json: true,
                doctor: true
            })
        );
        assert_eq!(
            command(&["recover", "--user", "test-user"]),
            Ok(Command::Recover("test-user".to_owned()))
        );
        assert_eq!(
            command(&["recover", "--user", "../user"]),
            Err(CliError::Arguments)
        );
        assert_eq!(
            command(&["integration", "enable"]),
            Ok(Command::IntegrationEnable)
        );
        assert_eq!(
            command(&["integration", "disable"]),
            Ok(Command::IntegrationDisable)
        );
        assert_eq!(
            command(&["integration", "status"]),
            Ok(Command::IntegrationStatus)
        );
        for parts in [
            vec!["integration", "activate"],
            vec!["integration", "enable", "--yes"],
            vec!["integration", "disable", "/tmp/helper"],
        ] {
            assert_eq!(command(&parts), Err(CliError::Arguments));
        }
    }
    #[test]
    fn environment_secret_channels_and_simulator_overrides_are_rejected() {
        for key in [
            "LOCALPIN_PIN",
            "LOCALPIN_PASSWORD",
            "LOCALPIN_TEST_PASSWORD",
            "LOCALPIN_SIMULATOR",
            "PASSWORD",
            "PIN",
        ] {
            assert_eq!(check_environment([key]), Err(CliError::SecretEnvironment));
        }
        assert!(check_environment(["PATH", "TERM", "XDG_SESSION_ID"]).is_ok());
    }
}
