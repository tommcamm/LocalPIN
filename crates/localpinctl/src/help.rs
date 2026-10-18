//! Plain, system-independent help content for the public command surface.

use super::HelpTopic;

/// Concise landing page shown when no command is supplied.
pub const OVERVIEW: &str = "LocalPIN — a PIN for your local desktop account

Usage: localpin [options] <command>

  setup             Set up or resume PIN unlocking
  status            Check enrollment and activation
  doctor            Diagnose readiness and next steps
  menu              Open the interactive command menu

Get started:  localpin setup
All commands: localpin --help
Command help: localpin help <command>";

/// Full command index; detailed contracts live in command-specific help.
pub const HELP: &str = "LocalPIN — a PIN for your local desktop account

Usage: localpin [options] <command>

Get started
  setup             Set up or resume guided onboarding
  status [--json]   Check enrollment and activation
  doctor [--json]   Diagnose readiness and next steps
  menu              Open the interactive command menu

Manage your credential
  enroll            Create a credential with an explicit protection choice
  change            Choose a new PIN or passcode
  disable           Disable your account's credential
  migrate           Switch protection and choose a new credential

Administration
  integration       Inspect integration or show administrator instructions
  recover           Recover a named local account (administrator only)

Tools
  completions       Print shell completion source for bash, zsh, or fish
  help [command]    Show full help or help for one command

Options
  -h, --help        Show help; also available after a command
  -V, --version     Show the installed version
  --color <when>    Color human output: auto (default), always, or never
  --no-input        Refuse actions that require interactive input

Examples
  localpin setup
  localpin status --json
  localpin enroll --backend tpm2-required
  localpin help setup

No command prints a brief overview. Use localpin menu to open the menu.
The localpinctl command remains compatible.

PINs, passcodes, and passwords use private foreground-terminal prompts.
Secret arguments, environment variables, and stdin input are not accepted.
Installation and enrollment do not activate desktop integration; setup guides
preparation, a bounded trial, recovery rehearsal, and recorded tests.";

pub(super) fn command(topic: HelpTopic) -> &'static str {
    match topic {
        HelpTopic::Menu => {
            "Open the interactive command menu

Usage: localpin menu

Choose an action using its number. Press q to cancel.
Run as your normal desktop user in a foreground terminal.
Use localpin setup to start onboarding directly.

Options: --color <auto|always|never>, --no-input, -h, --help"
        }
        HelpTopic::Setup => {
            "Set up or resume PIN unlocking

Usage: localpin setup

Run as your normal user in a foreground KDE terminal, without sudo.
Setup requests sudo authorization for fixed administrator steps and separate
account-password verification when creating a credential.

Setup checks readiness, prepares your account, creates a credential, guides a
bounded desktop trial and recovery rehearsal, then requests activation.
Completed preparation and enrollment are retained when setup is paused.

LocalPIN is experimental. Start in a disposable Fedora KDE VM and keep your
full account password and an administrator console available.

Options: --color <auto|always|never>, --no-input, -h, --help"
        }
        HelpTopic::Status => {
            "Check enrollment and activation

Usage: localpin status [--json]

Inspect your own account without prompting or changing authentication state.
Enrollment, recorded tests, and active desktop integration are separate states.

Options
  --json            Print the versioned, nonsecret JSON status schema
  --color <when>    Color human output: auto, always, or never
  --no-input        Permit only commands that do not need interactive input
  -h, --help        Show this help

Use localpin doctor for detailed readiness and recovery diagnostics.
JSON output never contains terminal styling."
        }
        HelpTopic::Doctor => {
            "Diagnose readiness and next steps

Usage: localpin doctor [--json]

Inspect your own account's broker, protection, integration, and recovery state.
This read-only command does not repeat desktop or physical hardware tests.
Administrator attestations are identified as attestations.

Options
  --json            Print the versioned, nonsecret JSON diagnostic schema
  --color <when>    Color human output: auto, always, or never
  --no-input        Permit only commands that do not need interactive input
  -h, --help        Show this help

JSON output never contains terminal styling."
        }
        HelpTopic::Enroll => {
            "Create your account's credential

Usage: localpin enroll --backend <auto|tpm2-required|software>

Protection
  auto              Attempt TPM protection; never fall back to software
  tpm2-required     Require TPM 2.0 protection
  software          Explicitly choose protection without TPM hardware binding

Numeric PINs use 4–16 digits with TPM or 8–16 digits with software protection.
Passcodes use 8–64 printable ASCII characters. Leading zeroes, spaces, and
case are preserved. New credentials are masked; passwords stay hidden.

A real foreground terminal, explicit confirmation, and fresh account-password
verification are required. No secret flags, environment variables, or stdin.
Enrollment does not activate desktop integration. Next: localpin setup.

Options: --color <auto|always|never>, --no-input, -h, --help"
        }
        HelpTopic::Change => {
            "Choose a new PIN or passcode

Usage: localpin change

Replace your own account's credential on its committed protection backend.
Requires an existing enrollment, a private foreground terminal, explicit
confirmation, and fresh account-password verification.

Use localpin migrate to switch protection. No secret arguments are accepted.

Options: --color <auto|always|never>, --no-input, -h, --help"
        }
        HelpTopic::Disable => {
            "Disable your account's LocalPIN credential

Usage: localpin disable

Requires a private foreground terminal, explicit confirmation, and fresh
account-password verification. Use your existing account password afterward.
This does not disable system-wide desktop integration.

Administrator integration instructions: localpin integration disable

Options: --color <auto|always|never>, --no-input, -h, --help"
        }
        HelpTopic::Migrate => {
            "Switch protection and choose a new credential

Usage: localpin migrate --backend <tpm2-required|software>

Explicitly replace your own account's protection backend and credential.
Software protection has no TPM hardware binding; TPM failure never selects it
automatically. Requires an existing enrollment, a private foreground terminal,
explicit confirmation, and fresh account-password verification.

Numeric PINs use 4–16 digits with TPM or 8–16 with software protection.
Passcodes use 8–64 printable ASCII characters. No secret arguments are accepted.

Options: --color <auto|always|never>, --no-input, -h, --help"
        }
        HelpTopic::Integration => {
            "Inspect desktop integration or show administrator instructions

Usage: localpin integration <command>

Commands
  status            Inspect the readable desktop integration gate
  enable            Show separate administrator activation instructions
  disable           Show separate administrator disable instructions

Use localpin setup for guided preparation, trial, tests, and activation.
For administrator details: sudo localpin-integration status

Options: --color <auto|always|never>, --no-input, -h, --help"
        }
        HelpTopic::IntegrationStatus => {
            "Inspect the desktop integration gate

Usage: localpin integration status

Read the local integration gate without a broker connection or a terminal.
A trial, active integration, and recorded tests are reported separately.
For administrator details: sudo localpin-integration status

Options: --color <auto|always|never>, --no-input, -h, --help"
        }
        HelpTopic::IntegrationEnable => {
            "Show separate administrator activation instructions

Usage: localpin integration enable

This command reports the administrator command and exits unsuccessfully.
It does not activate integration. Activation requires preparation, a bounded
trial, recovery rehearsal, and administrator-recorded desktop/password tests.

Guided setup: localpin setup
Administrator activation after prerequisites: sudo localpin-integration activate

Options: --color <auto|always|never>, --no-input, -h, --help"
        }
        HelpTopic::IntegrationDisable => {
            "Show separate administrator disable instructions

Usage: localpin integration disable

This command reports the administrator command and exits unsuccessfully.
It does not change integration. To disable system desktop integration:
  sudo localpin-integration disable

To disable only your account's credential: localpin disable

Options: --color <auto|always|never>, --no-input, -h, --help"
        }
        HelpTopic::Recover => {
            "Recover a named local account (administrator only)

Usage: localpin recover --user <account>

An already-root caller may disable one existing non-root local account's
credential. Requires explicit confirmation through a private foreground
terminal. Recovery never reveals or recovers a PIN or passcode.

The existing account password remains the recovery route.
Follow the administrator console recovery runbook for integration recovery.

Options: --color <auto|always|never>, --no-input, -h, --help"
        }
        HelpTopic::Completions => {
            "Print shell completion source

Usage: localpin completions <bash|zsh|fish>

Print completion source to stdout without a terminal, broker, or system change.
Installed packages provide completion files in the shell's standard location.
For a temporary Bash session:
  source <(localpin completions bash)

Completion source never contains terminal styling.

Options: --color <auto|always|never>, --no-input, -h, --help"
        }
    }
}
