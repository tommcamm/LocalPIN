//! Closed command grammar: secrets never have a command-line representation.

use localpin_protocol::BackendPreference;
use std::ffi::{OsStr, OsString};

use crate::CliError;

#[path = "help.rs"]
mod help_text;
pub use help_text::{HELP, OVERVIEW};

/// Terminal color policy for human-readable output.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum ColorChoice {
    /// Use color only on a capable terminal, respecting `NO_COLOR`.
    #[default]
    Auto,
    /// Color human-readable output even when its destination is redirected.
    Always,
    /// Never emit terminal color escapes.
    Never,
}

/// A supported shell completion format.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CompletionShell {
    /// Bash completion.
    Bash,
    /// Zsh completion.
    Zsh,
    /// Fish completion.
    Fish,
}

/// A command with dedicated help, requiring no system inspection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HelpTopic {
    /// Explicit interactive menu.
    Menu,
    /// Guided onboarding.
    Setup,
    /// Own-account status.
    Status,
    /// Readiness diagnostics.
    Doctor,
    /// Credential creation.
    Enroll,
    /// Credential replacement.
    Change,
    /// Own-account credential removal.
    Disable,
    /// Protection migration.
    Migrate,
    /// Integration command group.
    Integration,
    /// Integration inspection.
    IntegrationStatus,
    /// Integration activation instructions.
    IntegrationEnable,
    /// Integration disable instructions.
    IntegrationDisable,
    /// Administrator account recovery.
    Recover,
    /// Shell completion generation.
    Completions,
}

/// Render command help without inspecting the system or opening a terminal.
pub fn help(topic: HelpTopic) -> &'static str {
    help_text::command(topic)
}

/// Public, nonsecret command selection.
#[derive(Debug, Eq, PartialEq)]
pub enum Command {
    /// Print a concise command overview without opening a menu.
    Overview,
    /// Open the explicitly requested interactive command menu.
    Menu,
    /// Guide the current local account through preparation and activation.
    Setup,
    /// Print the supported command grammar.
    Help,
    /// Print help for a command without performing that command.
    CommandHelp(HelpTopic),
    /// Print the application version.
    Version,
    /// Print shell completion source without inspecting system state.
    Completions(CompletionShell),
    /// Inspect own-account status, optionally as versioned JSON.
    Status {
        /// Use the separately versioned nonsecret JSON schema.
        json: bool,
        /// Add actionable component and recovery diagnostics.
        doctor: bool,
    },
    /// Establish a new enrollment using an explicit backend preference.
    Enroll(BackendPreference),
    /// Replace the credential on the committed backend.
    Change,
    /// Disable the own-account credential after fresh password verification.
    Disable,
    /// Explicitly replace the backend and credential.
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

/// A command and its nonsecret presentation and input preferences.
#[derive(Debug, Eq, PartialEq)]
pub struct Invocation {
    /// The requested command, or the overview when no command was supplied.
    pub command: Command,
    /// Color policy for human-readable output; JSON remains unstyled.
    pub color: ColorChoice,
    /// Refuse interactive actions before opening a terminal or running a helper.
    pub no_input: bool,
}

/// Parse arguments without printing or interpolating rejected values.
///
/// Global options may appear before or after the command. A token following a
/// value-taking option remains its value, even if it resembles a global flag.
pub fn parse_invocation(args: &[OsString]) -> Result<Invocation, CliError> {
    let (command_args, color, no_input) = global_options(args)?;
    Ok(Invocation {
        command: parse_command(&command_args)?,
        color,
        no_input,
    })
}

/// Preserve valid color preferences when command syntax is rejected.
///
/// This uses the same closed global grammar without formatting rejected values.
/// Invalid color options use automatic detection; option values stay opaque.
pub fn diagnostic_color(args: &[OsString]) -> ColorChoice {
    global_options(args)
        .map(|(_, color, _)| color)
        .unwrap_or_default()
}

fn global_options(args: &[OsString]) -> Result<(Vec<&OsStr>, ColorChoice, bool), CliError> {
    let mut color = ColorChoice::Auto;
    let mut no_input = false;
    let mut command_args = Vec::with_capacity(args.len());
    let mut index = 0;
    while let Some(arg) = args.get(index) {
        if arg == "--color" {
            index += 1;
            color = color_choice(args.get(index).ok_or(CliError::Arguments)?)?;
        } else if let Some(value) = arg.as_encoded_bytes().strip_prefix(b"--color=") {
            color = match value {
                b"auto" => ColorChoice::Auto,
                b"always" => ColorChoice::Always,
                b"never" => ColorChoice::Never,
                _ => return Err(CliError::Arguments),
            };
        } else if arg == "--no-input" {
            no_input = true;
        } else {
            command_args.push(arg.as_os_str());
            if arg == "--backend" || arg == "--user" {
                index += 1;
                if let Some(value) = args.get(index) {
                    command_args.push(value.as_os_str());
                }
            }
        }
        index += 1;
    }
    Ok((command_args, color, no_input))
}

fn color_choice(value: &OsStr) -> Result<ColorChoice, CliError> {
    match value.to_str() {
        Some("auto") => Ok(ColorChoice::Auto),
        Some("always") => Ok(ColorChoice::Always),
        Some("never") => Ok(ColorChoice::Never),
        _ => Err(CliError::Arguments),
    }
}

/// Parse only the command, discarding nonsecret invocation preferences.
pub fn parse(args: &[OsString]) -> Result<Command, CliError> {
    parse_invocation(args).map(|invocation| invocation.command)
}

fn help_topic(args: &[&OsStr]) -> Result<HelpTopic, CliError> {
    match args {
        [name] => match name.to_str() {
            Some("menu") => Ok(HelpTopic::Menu),
            Some("setup") => Ok(HelpTopic::Setup),
            Some("status") => Ok(HelpTopic::Status),
            Some("doctor") => Ok(HelpTopic::Doctor),
            Some("enroll") => Ok(HelpTopic::Enroll),
            Some("change") => Ok(HelpTopic::Change),
            Some("disable") => Ok(HelpTopic::Disable),
            Some("migrate") => Ok(HelpTopic::Migrate),
            Some("integration") => Ok(HelpTopic::Integration),
            Some("recover") => Ok(HelpTopic::Recover),
            Some("completions") => Ok(HelpTopic::Completions),
            _ => Err(CliError::Arguments),
        },
        [group, name] if *group == "integration" => match name.to_str() {
            Some("status") => Ok(HelpTopic::IntegrationStatus),
            Some("enable") => Ok(HelpTopic::IntegrationEnable),
            Some("disable") => Ok(HelpTopic::IntegrationDisable),
            _ => Err(CliError::Arguments),
        },
        _ => Err(CliError::Arguments),
    }
}

fn command_topic(command: Command) -> Result<HelpTopic, CliError> {
    match command {
        Command::Menu => Ok(HelpTopic::Menu),
        Command::Setup => Ok(HelpTopic::Setup),
        Command::Status { doctor: false, .. } => Ok(HelpTopic::Status),
        Command::Status { doctor: true, .. } => Ok(HelpTopic::Doctor),
        Command::Enroll(_) => Ok(HelpTopic::Enroll),
        Command::Change => Ok(HelpTopic::Change),
        Command::Disable => Ok(HelpTopic::Disable),
        Command::Migrate(_) => Ok(HelpTopic::Migrate),
        Command::IntegrationStatus => Ok(HelpTopic::IntegrationStatus),
        Command::IntegrationEnable => Ok(HelpTopic::IntegrationEnable),
        Command::IntegrationDisable => Ok(HelpTopic::IntegrationDisable),
        Command::Recover(_) => Ok(HelpTopic::Recover),
        Command::Completions(_) => Ok(HelpTopic::Completions),
        _ => Err(CliError::Arguments),
    }
}

fn parse_command(args: &[&OsStr]) -> Result<Command, CliError> {
    let equals = |index: usize, value: &str| args.get(index).is_some_and(|arg| *arg == value);
    if equals(0, "help") {
        return if args.len() == 1 {
            Ok(Command::Help)
        } else {
            help_topic(&args[1..]).map(Command::CommandHelp)
        };
    }
    if args.len() > 1
        && args
            .last()
            .is_some_and(|arg| *arg == "--help" || *arg == "-h")
    {
        let subject = &args[..args.len() - 1];
        let topic =
            help_topic(subject).or_else(|_| parse_command(subject).and_then(command_topic))?;
        return Ok(Command::CommandHelp(topic));
    }
    match args.len() {
        0 => Ok(Command::Overview),
        1 if equals(0, "menu") => Ok(Command::Menu),
        1 if equals(0, "setup") => Ok(Command::Setup),
        1 if equals(0, "--help") || equals(0, "-h") => Ok(Command::Help),
        1 if equals(0, "--version") || equals(0, "-V") => Ok(Command::Version),
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
        2 if equals(0, "completions") => match args[1].to_str() {
            Some("bash") => Ok(Command::Completions(CompletionShell::Bash)),
            Some("zsh") => Ok(Command::Completions(CompletionShell::Zsh)),
            Some("fish") => Ok(Command::Completions(CompletionShell::Fish)),
            _ => Err(CliError::Arguments),
        },
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
                || account.starts_with('-')
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
        if name.starts_with(b"LOCALPIN_")
            || name == b"PIN"
            || name == b"PASSWORD"
            || name == b"PASSCODE"
        {
            return Err(CliError::SecretEnvironment);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn invocation(parts: &[&str]) -> Result<Invocation, CliError> {
        parse_invocation(&parts.iter().map(OsString::from).collect::<Vec<_>>())
    }

    fn command(parts: &[&str]) -> Result<Command, CliError> {
        invocation(parts).map(|invocation| invocation.command)
    }

    #[test]
    fn rejects_secret_arguments_unknown_options_and_extra_values_even_with_help() {
        for parts in [
            vec!["enroll", "--pin", "123456"],
            vec!["enroll", "--backend", "software", "123456"],
            vec!["change", "--password-stdin"],
            vec!["disable", "--yes"],
            vec!["status", "--pin=123456"],
            vec!["enroll", "--backend", "simulator"],
            vec!["migrate", "--backend", "auto"],
            vec!["recover", "--user", "root", "--pin", "123456"],
            vec!["setup", "--yes", "--help"],
            vec!["status", "--pin=123456", "--help"],
            vec!["help", "setup", "--yes"],
            vec!["completions", "powershell"],
            vec!["integration", "activate"],
            vec!["integration", "enable", "--yes"],
            vec!["integration", "disable", "/tmp/helper"],
        ] {
            assert_eq!(command(&parts), Err(CliError::Arguments));
        }
    }

    #[test]
    fn accepts_only_explicit_command_grammar() {
        assert_eq!(command(&[]), Ok(Command::Overview));
        assert_eq!(command(&["menu"]), Ok(Command::Menu));
        assert_eq!(command(&["setup"]), Ok(Command::Setup));
        assert_eq!(command(&["-V"]), Ok(Command::Version));
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
        for (shell, parsed) in [
            ("bash", CompletionShell::Bash),
            ("zsh", CompletionShell::Zsh),
            ("fish", CompletionShell::Fish),
        ] {
            assert_eq!(
                command(&["completions", shell]),
                Ok(Command::Completions(parsed))
            );
        }
    }

    #[test]
    fn global_options_are_independent_of_command_position_and_do_not_consume_values() {
        for parts in [
            vec!["--color=never", "--no-input", "status", "--json"],
            vec!["status", "--color", "never", "--json", "--no-input"],
            vec!["status", "--json", "--no-input", "--color=never"],
        ] {
            assert_eq!(
                invocation(&parts),
                Ok(Invocation {
                    command: Command::Status {
                        json: true,
                        doctor: false
                    },
                    color: ColorChoice::Never,
                    no_input: true,
                })
            );
        }
        assert_eq!(
            invocation(&[]),
            Ok(Invocation {
                command: Command::Overview,
                color: ColorChoice::Auto,
                no_input: false,
            })
        );
        assert_eq!(
            invocation(&["--color", "always"]),
            Ok(Invocation {
                command: Command::Overview,
                color: ColorChoice::Always,
                no_input: false,
            })
        );
        for parts in [
            vec!["--color"],
            vec!["--color", "rainbow", "status"],
            vec!["--color="],
            vec!["--color", "--no-input"],
            vec!["enroll", "--backend", "--no-input"],
            vec!["enroll", "--backend", "--color", "never"],
            vec!["recover", "--user", "--no-input"],
            vec!["recover", "--user", "--color=never"],
        ] {
            assert_eq!(invocation(&parts), Err(CliError::Arguments));
        }
    }

    #[test]
    fn diagnostic_color_preserves_global_preferences_without_interpreting_values() {
        for (parts, expected) in [
            (vec!["--color=never", "unknown"], ColorChoice::Never),
            (vec!["unknown", "--color", "always"], ColorChoice::Always),
            (vec!["--color=rainbow", "unknown"], ColorChoice::Auto),
            (vec!["--color"], ColorChoice::Auto),
            (
                vec!["--color=never", "enroll", "--backend"],
                ColorChoice::Never,
            ),
            (
                vec!["recover", "--user", "--color=never"],
                ColorChoice::Auto,
            ),
            (
                vec!["enroll", "--backend", "--color=always"],
                ColorChoice::Auto,
            ),
        ] {
            let args = parts.iter().map(OsString::from).collect::<Vec<_>>();
            assert_eq!(parse_invocation(&args), Err(CliError::Arguments));
            assert_eq!(diagnostic_color(&args), expected);
        }
    }

    #[test]
    fn top_level_command_and_nested_help_are_pure_command_selections() {
        for parts in [vec!["help"], vec!["--help"], vec!["-h"]] {
            assert_eq!(command(&parts), Ok(Command::Help));
        }
        for (name, topic) in [
            ("menu", HelpTopic::Menu),
            ("setup", HelpTopic::Setup),
            ("status", HelpTopic::Status),
            ("doctor", HelpTopic::Doctor),
            ("enroll", HelpTopic::Enroll),
            ("change", HelpTopic::Change),
            ("disable", HelpTopic::Disable),
            ("migrate", HelpTopic::Migrate),
            ("integration", HelpTopic::Integration),
            ("recover", HelpTopic::Recover),
            ("completions", HelpTopic::Completions),
        ] {
            for parts in [vec!["help", name], vec![name, "--help"], vec![name, "-h"]] {
                assert_eq!(command(&parts), Ok(Command::CommandHelp(topic)));
            }
            assert!(help(topic).contains("Usage: localpin"));
        }
        for (name, topic) in [
            ("status", HelpTopic::IntegrationStatus),
            ("enable", HelpTopic::IntegrationEnable),
            ("disable", HelpTopic::IntegrationDisable),
        ] {
            assert_eq!(
                command(&["help", "integration", name]),
                Ok(Command::CommandHelp(topic))
            );
            assert_eq!(
                command(&["integration", name, "--help"]),
                Ok(Command::CommandHelp(topic))
            );
        }
        assert_eq!(
            command(&["enroll", "--backend", "software", "--help"]),
            Ok(Command::CommandHelp(HelpTopic::Enroll))
        );
        assert_eq!(
            command(&["status", "--json", "-h"]),
            Ok(Command::CommandHelp(HelpTopic::Status))
        );
    }

    #[test]
    fn non_utf8_arguments_remain_closed_and_are_never_formatted() {
        use std::os::unix::ffi::OsStringExt;
        let invalid = OsString::from_vec(b"synthetic-private-\xff-value".to_vec());
        for args in [
            vec![invalid.clone()],
            vec!["--color".into(), invalid.clone()],
            vec!["recover".into(), "--user".into(), invalid.clone()],
            vec!["help".into(), invalid],
        ] {
            assert_eq!(parse_invocation(&args), Err(CliError::Arguments));
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
        assert!(check_environment(["PATH", "TERM", "NO_COLOR", "XDG_SESSION_ID"]).is_ok());
    }
}
