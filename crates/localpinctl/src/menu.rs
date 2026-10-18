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

    fn heading(&mut self, title: &str) -> Result<(), CliError> {
        self.say(title)
    }

    fn step(&mut self, current: usize, total: usize, title: &str) -> Result<(), CliError> {
        self.say(&format!("[{current}/{total}] {title}"))
    }

    fn warning(&mut self, text: &str) -> Result<(), CliError> {
        self.say(text)
    }

    fn success(&mut self, text: &str) -> Result<(), CliError> {
        self.say(text)
    }

    fn detail(&mut self, label: &str, value: &str) -> Result<(), CliError> {
        self.say(&format!("{label}: {value}"))
    }

    fn policy_diff(&mut self, text: &str) -> Result<(), CliError> {
        self.say(text)
    }

    fn confirm(&mut self, prompt: &str) -> Result<bool, CliError> {
        self.choose(prompt, &["Yes", "No / pause"])
            .map(|answer| answer == 0)
    }
}

impl Ui for Terminal {
    fn say(&mut self, text: &str) -> Result<(), CliError> {
        self.message(text)
    }

    fn heading(&mut self, title: &str) -> Result<(), CliError> {
        self.present(|renderer| renderer.section(title))
    }

    fn step(&mut self, current: usize, total: usize, title: &str) -> Result<(), CliError> {
        self.present(|renderer| renderer.step(current, total, title))
    }

    fn warning(&mut self, text: &str) -> Result<(), CliError> {
        self.present(|renderer| {
            renderer.notice("Warning", text, crate::presentation::Tone::Warning)
        })
    }

    fn success(&mut self, text: &str) -> Result<(), CliError> {
        self.present(|renderer| renderer.notice("Done", text, crate::presentation::Tone::Success))
    }

    fn detail(&mut self, label: &str, value: &str) -> Result<(), CliError> {
        self.present(|renderer| renderer.detail(label, value))
    }

    fn policy_diff(&mut self, text: &str) -> Result<(), CliError> {
        if !review_preview(self)? {
            return Ok(());
        }
        self.present(|_renderer| {
            let mut output = String::new();
            // Preserve whitespace and every line of the policy preview. It is
            // external helper output and must never supply terminal escapes.
            output.push_str(&crate::terminal::sanitize_prompt(text));
            output.push('\n');
            output
        })
    }

    fn choose(&mut self, prompt: &str, choices: &[&str]) -> Result<usize, CliError> {
        self.present(|renderer| renderer.section(prompt))?;
        for (index, choice) in choices.iter().enumerate() {
            self.present(|renderer| renderer.choice(index + 1, choice))?;
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

fn review_preview(ui: &mut impl Ui) -> Result<bool, CliError> {
    match ui.choose(
        "Review proposed policy changes",
        &[
            "View policy diff",
            "Continue to apply confirmation",
            "Pause setup",
        ],
    )? {
        0 => Ok(true),
        1 => Ok(false),
        2 => Err(CliError::Cancelled),
        _ => Err(CliError::Arguments),
    }
}

pub(crate) fn backend(ui: &mut impl Ui) -> Result<BackendPreference, CliError> {
    ui.say(
        "Choose protection explicitly. Device detection alone does not establish TPM usability.",
    )?;
    match ui.choose(
        "Credential protection",
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
        return Err(CliError::Terminal);
    }
    if rustix::process::getuid().as_raw() == 0 {
        return Err(CliError::Forbidden);
    }
    let mut terminal = Terminal::open()?;
    loop {
        Conversation::heading(&mut terminal, "PIN unlocking for your KDE session")?;
        let selected = terminal.choose(
            "What would you like to do?",
            &[
                "Set up or resume setup",
                "Check status",
                "Diagnose a problem",
                "Change my credential",
                "Switch protection",
                "Disable my credential",
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

#[cfg(test)]
mod tests {
    use super::*;

    struct PreviewChoice(usize);
    impl Ui for PreviewChoice {
        fn say(&mut self, _text: &str) -> Result<(), CliError> {
            panic!("preview choice cannot apply or report a system change")
        }
        fn choose(&mut self, prompt: &str, choices: &[&str]) -> Result<usize, CliError> {
            assert_eq!(prompt, "Review proposed policy changes");
            assert_eq!(
                choices,
                [
                    "View policy diff",
                    "Continue to apply confirmation",
                    "Pause setup"
                ]
            );
            Ok(self.0)
        }
    }

    #[test]
    fn preview_is_optional_and_pause_does_not_imply_apply_confirmation() {
        assert_eq!(review_preview(&mut PreviewChoice(0)), Ok(true));
        assert_eq!(review_preview(&mut PreviewChoice(1)), Ok(false));
        assert_eq!(
            review_preview(&mut PreviewChoice(2)),
            Err(CliError::Cancelled)
        );
        assert_eq!(
            review_preview(&mut PreviewChoice(3)),
            Err(CliError::Arguments)
        );
    }
}
