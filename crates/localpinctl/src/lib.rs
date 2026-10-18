//! Non-setuid LocalPIN CLI: private terminal enrollment and nonsecret status.

mod admin;
pub mod args;
mod menu;
mod setup;
pub mod status;
pub mod terminal;
pub mod workflow;

use std::fmt;

/// Fixed diagnostics never include rejected argv, environment values or secrets.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CliError {
    /// Unknown command, option or extra argument.
    Arguments,
    /// A forbidden secret or simulator environment channel was supplied.
    SecretEnvironment,
    /// A foreground real terminal is required or terminal I/O failed.
    Terminal,
    /// The process could not disable dumps before accepting interactive input.
    Process,
    /// User declined confirmation, interrupted input, or closed the terminal.
    Cancelled,
    /// Entered credential did not satisfy its selected policy.
    PinFormat,
    /// PIN confirmation mismatched.
    Confirmation,
    /// Input exceeded a fixed secret buffer bound.
    InputTooLong,
    /// The transaction's absolute deadline passed.
    Expired,
    /// Trusted broker resources are unavailable.
    Service,
    /// Server sent an unexpected or incorrectly bound message.
    Protocol,
    /// Fresh password authentication was rejected.
    PasswordRejected,
    /// A caller lacks required account/session or administrative authority.
    Forbidden,
    /// Required TPM is unavailable; software requires explicit selection.
    Backend,
    /// Own-user action requires an existing enrollment.
    NotEnrolled,
    /// Account selection did not resolve to one non-root local account.
    Account,
    /// Desktop activation requires the separate root tool and recorded tests.
    Integration,
    /// System integration disable requires the separate root administration tool.
    IntegrationDisable,
    /// Administrator helper was unavailable or refused the fixed operation.
    Administrator,
    /// The administrator helper returned an invalid or incompatible report.
    SetupReport,
    /// Setup needs an explicitly described maintenance or recovery action.
    SetupBlocked,
}

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Arguments => "unsupported arguments; run localpin --help; secret arguments are not accepted",
            Self::SecretEnvironment => "secret or simulator environment variables are not accepted; remove them and use the terminal prompts",
            Self::Terminal => "a real foreground terminal is required; secrets cannot be read from stdin or a pipe",
            Self::Process => "process secret-protection setup failed; no interactive input was accepted",
            Self::Cancelled => "operation cancelled; no success was confirmed",
            Self::PinFormat => "the credential does not meet the selected type and protection policy",
            Self::Confirmation => "credential confirmation did not match; retry the operation",
            Self::InputTooLong => "interactive input exceeded the supported length",
            Self::Expired => "operation expired; start again for fresh password authorization",
            Self::Service => "the protected LocalPIN service is unavailable; ask the administrator to inspect it",
            Self::Protocol => "the broker exchange was invalid; check client and service versions",
            Self::PasswordRejected => "password authentication was rejected; the credential was not changed",
            Self::Forbidden => "the account or session is not permitted to perform this operation",
            Self::Backend => "TPM protection is unavailable; inspect localpin doctor, or explicitly choose --backend software",
            Self::NotEnrolled => "no existing enrollment is available for this action",
            Self::Account => "select one existing, non-root local account by its account name",
            Self::Integration => "root activation tooling requires prepare, a bounded trial, and administrator-recorded desktop/password tests first; use localpin setup, or then run sudo localpin-integration activate; enrollment does not activate desktop integration",
            Self::IntegrationDisable => "run sudo localpin-integration disable to disable system desktop integration; this is separate from disabling an account's PIN credential",
            Self::Administrator => "the administrator operation was not confirmed; rerun localpin setup to inspect saved state before retrying",
            Self::SetupReport => "setup could not establish authoritative system state; use localpin doctor and the administrator recovery guide",
            Self::SetupBlocked => "setup is paused; complete the maintenance or recovery action shown above, then rerun localpin setup",
        })
    }
}

impl std::error::Error for CliError {}

/// Prevent fatal signals or crashes from persisting password/PIN memory.
///
/// Apply this before inspecting input at either the executable or public
/// terminal boundary. Zeroizing destructors do not run on fatal signals.
pub(crate) fn harden_process() -> Result<(), CliError> {
    use rustix::process::{DumpableBehavior, Resource, Rlimit};
    rustix::process::set_dumpable_behavior(DumpableBehavior::NotDumpable)
        .map_err(|_| CliError::Process)?;
    rustix::process::setrlimit(
        Resource::Core,
        Rlimit {
            current: Some(0),
            maximum: Some(0),
        },
    )
    .map_err(|_| CliError::Process)
}

impl From<localpin_protocol::transport::TransportError> for CliError {
    fn from(value: localpin_protocol::transport::TransportError) -> Self {
        use localpin_protocol::ErrorCode;
        use localpin_protocol::transport::TransportError;
        match value {
            TransportError::Timeout => Self::Expired,
            TransportError::Protocol(_) => Self::Protocol,
            TransportError::Rejected(ErrorCode::PasswordRejected) => Self::PasswordRejected,
            TransportError::Rejected(ErrorCode::Forbidden) => Self::Forbidden,
            TransportError::Rejected(ErrorCode::Expired) => Self::Expired,
            _ => Self::Service,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustix::process::{DumpableBehavior, Resource, Rlimit};
    use std::process::{Command, Stdio};

    #[test]
    fn process_protection_precedes_both_input_boundaries() {
        const CHILD: &str = "LOCALPIN_CLI_HARDENING_BOUNDARY";
        if let Some(boundary) = std::env::var_os(CHILD) {
            // Each child starts from an explicitly dumpable process. Never
            // lower irreversible process limits in the parallel test parent.
            rustix::process::set_dumpable_behavior(DumpableBehavior::Dumpable).unwrap();
            match boundary.to_str().unwrap() {
                "run" => assert_eq!(workflow::run(), Err(CliError::Arguments)),
                "terminal" => assert!(terminal::Terminal::open().is_err()),
                _ => panic!("unknown test boundary"),
            }
            assert_eq!(
                rustix::process::dumpable_behavior().unwrap(),
                DumpableBehavior::NotDumpable
            );
            assert_eq!(
                rustix::process::getrlimit(Resource::Core),
                Rlimit {
                    current: Some(0),
                    maximum: Some(0),
                }
            );
            return;
        }
        let original_dumpable = rustix::process::dumpable_behavior().unwrap();
        let original_core_limit = rustix::process::getrlimit(Resource::Core);
        for boundary in ["run", "terminal"] {
            let output = Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "tests::process_protection_precedes_both_input_boundaries",
                    "--nocapture",
                ])
                .env(CHILD, boundary)
                .stdin(Stdio::null())
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{boundary}: {}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
        assert_eq!(
            rustix::process::dumpable_behavior().unwrap(),
            original_dumpable
        );
        assert_eq!(
            rustix::process::getrlimit(Resource::Core),
            original_core_limit
        );
    }
}
