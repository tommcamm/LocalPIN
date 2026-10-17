//! Inline terminal navigation; all credential actions retain their own checks.

use crate::{
    CliError,
    args::Command,
    terminal::{Conversation, Terminal},
};
use localpin_protocol::{BackendPreference, transport::Deadline};
use std::io::IsTerminal;
use std::time::Duration;

pub(crate) trait Ui {
    fn say(&mut self, text: &str) -> Result<(), CliError>;
    fn choose(&mut self, prompt: &str, choices: &[&str]) -> Result<usize, CliError>;

    fn confirm(&mut self, prompt: &str) -> Result<bool, CliError> {
        self.choose(prompt, &["Yes", "No / pause"])
            .map(|answer| answer == 0)
    }
}

impl Ui for Terminal {
    fn say(&mut self, text: &str) -> Result<(), CliError> {
        self.message(text)
    }

    fn choose(&mut self, prompt: &str, choices: &[&str]) -> Result<usize, CliError> {
        self.message(prompt)?;
        for (index, choice) in choices.iter().enumerate() {
            self.message(&format!("  {}. {choice}", index + 1))?;
        }
        loop {
            let answer = self.choice(
                "Choose a number (q to cancel): ",
                2,
                Deadline::after(Duration::from_secs(3600)),
            )?;
            if answer == "q" {
                return Err(CliError::Cancelled);
            }
            if let Ok(number) = answer.parse::<usize>()
                && number > 0
                && number <= choices.len()
            {
                return Ok(number - 1);
            }
            self.message("Choose one of the listed numbers, or q to cancel.")?;
        }
    }
}

pub(crate) fn heading(subtitle: &str) {
    let color = std::io::stdout().is_terminal()
        && std::env::var_os("NO_COLOR").is_none()
        && std::env::var_os("TERM").is_some_and(|term| term != "dumb");
    if color {
        println!("\n\x1b[1;36mLocalPIN\x1b[0m  {subtitle}\n");
    } else {
        println!("\nLocalPIN  |  {subtitle}\n");
    }
}

pub(crate) fn backend(ui: &mut impl Ui) -> Result<BackendPreference, CliError> {
    ui.say(
        "Choose protection explicitly. Device detection alone does not establish TPM usability.",
    )?;
    match ui.choose(
        "PIN protection",
        &[
            "TPM 2.0 — hardware bound; requires a separately validated TPM deployment",
            "Software — no TPM binding; copied verifier data can be guessed offline",
        ],
    )? {
        0 => Ok(BackendPreference::Tpm),
        1 => Ok(BackendPreference::Software),
        _ => Err(CliError::Arguments),
    }
}

pub(crate) fn run() -> Result<(), CliError> {
    if !std::io::stdin().is_terminal() || !std::io::stdout().is_terminal() {
        println!("{}", crate::args::HELP);
        return Ok(());
    }
    if rustix::process::getuid().as_raw() == 0 {
        println!(
            "Run localpin as your normal user in your KDE terminal.\nAdministrator console recovery: localpin-integration recover\n\n{}",
            crate::args::HELP
        );
        return Ok(());
    }
    let mut terminal = Terminal::open()?;
    loop {
        heading("PIN unlocking for your KDE session");
        let selected = terminal.choose(
            "What would you like to do?",
            &[
                "Set up or resume setup",
                "Check status",
                "Diagnose a problem",
                "Change my PIN",
                "Switch PIN protection",
                "Disable my PIN",
                "Exit",
            ],
        )?;
        let command = match selected {
            0 => Command::Setup,
            1 => Command::Status {
                json: false,
                doctor: false,
            },
            2 => Command::Status {
                json: false,
                doctor: true,
            },
            3 => Command::Change,
            4 => Command::Migrate(backend(&mut terminal)?),
            5 => Command::Disable,
            6 => return Ok(()),
            _ => return Err(CliError::Arguments),
        };
        crate::workflow::execute(command)?;
    }
}
