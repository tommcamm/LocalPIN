//! Trusted inline presentation; external text is sanitized before styling.

use crate::{CliError, args::ColorChoice, terminal::sanitize_prompt};
use std::cell::Cell;
use std::io::{self, IsTerminal, Write};
use std::os::fd::AsFd;

thread_local! {
    static COLOR: Cell<ColorChoice> = const { Cell::new(ColorChoice::Auto) };
    static REPORTED: Cell<bool> = const { Cell::new(false) };
}

pub(crate) fn configure(color: ColorChoice) {
    COLOR.set(color);
    REPORTED.set(false);
}

pub(crate) fn reported() {
    REPORTED.set(true);
}

pub(crate) fn diagnostic(text: &str) {
    let stderr = io::stderr();
    let renderer = Renderer::for_output(&stderr);
    if stderr
        .lock()
        .write_all(renderer.notice("Error", text, Tone::Error).as_bytes())
        .is_ok()
    {
        reported();
    }
}

/// Render one diagnostic unless its command already explained the outcome.
pub fn report_error(error: CliError) {
    if error == CliError::BrokenPipe || REPORTED.get() {
        return;
    }
    let stderr = io::stderr();
    let renderer = Renderer::for_output(&stderr);
    let label = if error == CliError::Cancelled {
        "Cancelled"
    } else {
        "Error"
    };
    let text = renderer.notice(label, &error.to_string(), Tone::Error);
    let _ = stderr.lock().write_all(text.as_bytes());
}

#[derive(Clone, Copy)]
pub(crate) enum Tone {
    Accent,
    Success,
    Warning,
    Error,
    Muted,
}

#[derive(Clone, Copy)]
pub(crate) struct Renderer {
    color: bool,
    width: usize,
    unicode: bool,
}

impl Renderer {
    pub(crate) fn for_output(output: &(impl AsFd + IsTerminal)) -> Self {
        let terminal = output.is_terminal();
        let term = std::env::var_os("TERM");
        let capable = term.as_ref().is_some_and(|value| value != "dumb");
        let color = Self::use_color(
            COLOR.get(),
            terminal,
            capable,
            std::env::var_os("NO_COLOR").is_some(),
        );
        let width = rustix::termios::tcgetwinsize(output)
            .ok()
            .map(|size| usize::from(size.ws_col))
            .filter(|width| *width > 0)
            .unwrap_or(80)
            .clamp(20, 100);
        Self {
            color,
            width,
            unicode: terminal && capable,
        }
    }

    fn use_color(choice: ColorChoice, terminal: bool, capable: bool, no_color: bool) -> bool {
        match choice {
            ColorChoice::Always => true,
            ColorChoice::Never => false,
            ColorChoice::Auto => terminal && capable && !no_color,
        }
    }

    fn styled(self, text: &str, tone: Tone) -> String {
        let text = sanitize_prompt(text);
        if !self.color {
            return text;
        }
        let code = match tone {
            Tone::Accent => "1;36",
            Tone::Success => "32",
            Tone::Warning => "33",
            Tone::Error => "1;31",
            Tone::Muted => "2",
        };
        format!("\x1b[{code}m{text}\x1b[0m")
    }

    pub(crate) fn heading(self, title: &str) -> String {
        format!(
            "\n{}  /  {}\n\n",
            self.styled("LocalPIN", Tone::Accent),
            sanitize_prompt(title)
        )
    }

    pub(crate) fn section(self, title: &str) -> String {
        format!(
            "\n{}\n",
            self.styled(self.paragraph(title).trim_end(), Tone::Accent)
        )
    }

    pub(crate) fn step(self, current: usize, total: usize, title: &str) -> String {
        let marker = if self.unicode { "◇" } else { "*" };
        let title = format!("{marker} {title}  [{current}/{total}]");
        let rail = if self.unicode { "│" } else { "|" };
        format!(
            "\n{}\n{}\n",
            self.styled(self.paragraph(&title).trim_end(), Tone::Accent),
            self.styled(rail, Tone::Muted)
        )
    }

    pub(crate) fn paragraph(self, text: &str) -> String {
        self.wrap(text, "", "")
    }

    pub(crate) fn notice(self, label: &str, text: &str, tone: Tone) -> String {
        let mut output = self.styled(label, tone);
        output.push('\n');
        output.push_str(&self.wrap(text, "  ", "  "));
        output
    }

    pub(crate) fn detail(self, label: &str, value: &str) -> String {
        let label = sanitize_prompt(label);
        let prefix = format!("  {label:<20} ");
        let mut body = if self.width < 48 {
            format!("  {}\n{}", label, self.wrap(value, "    ", "    "))
        } else {
            self.wrap(value, &prefix, &" ".repeat(prefix.chars().count()))
        };
        let tone = match (label.trim_end_matches(':'), value) {
            ("Availability", "available")
            | ("Integration", "active" | "Active")
            | ("Active", "yes") => Some(Tone::Success),
            ("Availability", "cooldown" | "unavailable")
            | ("Integration", "trial" | "needs-attention" | "unknown")
            | ("Active", "unknown")
            | ("Broker", "unavailable") => Some(Tone::Warning),
            _ => None,
        };
        if let Some(tone) = tone
            && let Some(start) = body.rfind(value)
        {
            body.replace_range(start..start + value.len(), &self.styled(value, tone));
        }
        // Only closed presentation labels are styled, never external bytes.
        body.replacen(&label, &self.styled(&label, Tone::Muted), 1)
    }

    pub(crate) fn choice(self, number: usize, text: &str) -> String {
        let prefix = format!("  {number}. ");
        self.wrap(text, &prefix, &" ".repeat(prefix.len()))
    }

    pub(crate) fn document(self, text: &str) -> String {
        let mut output = String::new();
        for line in text.lines() {
            if line.is_empty() {
                output.push('\n');
            } else if line == "LocalPIN"
                || line.starts_with("LocalPIN —")
                || line.starts_with("Usage:")
            {
                output.push_str(&self.styled(self.paragraph(line).trim_end(), Tone::Accent));
                output.push('\n');
            } else if let Some((command, description)) = line.trim_start().split_once("  ")
                && line.starts_with("  ")
                && !command.is_empty()
            {
                output.push_str(&self.detail(command, description.trim()));
            } else if let Some((label, value)) = line.split_once(": ") {
                if !line.starts_with(' ') && label.len() <= 22 {
                    if matches!(label, "Next" | "Guide" | "Recommended") {
                        output.push_str(&self.notice(label, value.trim_start(), Tone::Accent));
                    } else {
                        output.push_str(&self.detail(&format!("{label}:"), value.trim_start()));
                    }
                } else {
                    output.push_str(&self.paragraph(line));
                }
            } else if !line.starts_with(' ') && !line.contains('.') && line.len() < 40 {
                output.push_str(&self.styled(line, Tone::Accent));
                output.push('\n');
            } else {
                output.push_str(&self.paragraph(line));
            }
        }
        output
    }

    fn wrap(self, text: &str, first: &str, continuation: &str) -> String {
        let text = sanitize_prompt(text);
        let mut output = String::new();
        for line in text.split('\n') {
            if line.is_empty() {
                output.push('\n');
                continue;
            }
            if first.chars().count() + line.chars().count() <= self.width {
                output.push_str(first);
                output.push_str(line);
                output.push('\n');
                continue;
            }
            let indent = line.len() - line.trim_start_matches(' ').len();
            let source_indent = " ".repeat(indent.min(12));
            let line_prefix = format!("{first}{source_indent}");
            let next_prefix = format!("{continuation}{source_indent}");
            output.push_str(&line_prefix);
            let mut columns = line_prefix.chars().count();
            let mut words_on_line = false;
            for word in line.split_whitespace() {
                let length = word.chars().count();
                if words_on_line && columns + length + 1 > self.width {
                    output.push('\n');
                    output.push_str(&next_prefix);
                    columns = next_prefix.chars().count();
                    words_on_line = false;
                }
                if words_on_line {
                    output.push(' ');
                    columns += 1;
                }
                output.push_str(word);
                columns += length;
                words_on_line = true;
            }
            output.push('\n');
        }
        output
    }
}

pub(crate) fn stdout(text: &str) -> Result<(), CliError> {
    let mut output = io::stdout().lock();
    writeln!(output, "{text}")
        .and_then(|()| output.flush())
        .map_err(|error| {
            if error.kind() == io::ErrorKind::BrokenPipe {
                CliError::BrokenPipe
            } else {
                CliError::Output
            }
        })
}

pub(crate) fn human(text: &str) -> Result<(), CliError> {
    let renderer = Renderer::for_output(&io::stdout());
    stdout(renderer.document(text).trim_end())
}

pub(crate) fn success(text: &str) -> Result<(), CliError> {
    let renderer = Renderer::for_output(&io::stdout());
    stdout(renderer.notice("Done", text, Tone::Success).trim_end())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn forced_human_color_never_styles_synthetic_json_reports() {
        configure(ColorChoice::Always);
        let reports = [false, true].map(|doctor| crate::status::json(None, doctor));
        configure(ColorChoice::Auto);
        for (index, report) in reports.into_iter().enumerate() {
            assert!(!report.contains('\x1b'));
            let report: serde_json::Value = serde_json::from_str(&report).unwrap();
            assert_eq!(report["schema_version"], 2);
            assert_eq!(report["broker_available"], false);
            assert_eq!(
                report["command"],
                if index == 0 { "status" } else { "doctor" }
            );
        }
    }

    #[test]
    fn explicit_color_overrides_automatic_detection() {
        for terminal in [false, true] {
            for capable in [false, true] {
                for no_color in [false, true] {
                    assert!(Renderer::use_color(
                        ColorChoice::Always,
                        terminal,
                        capable,
                        no_color
                    ));
                    assert!(!Renderer::use_color(
                        ColorChoice::Never,
                        terminal,
                        capable,
                        no_color
                    ));
                    assert_eq!(
                        Renderer::use_color(ColorChoice::Auto, terminal, capable, no_color),
                        terminal && capable && !no_color
                    );
                }
            }
        }
    }

    #[test]
    fn wrapping_and_narrow_rows_preserve_content_without_control_injection() {
        for width in [40, 80, 100] {
            let renderer = Renderer {
                color: false,
                width,
                unicode: false,
            };
            let text = renderer.detail(
                "Integration",
                "A trial is open; activation still requires recorded desktop and recovery tests.",
            );
            assert!(text.lines().all(|line| line.chars().count() <= width));
            assert!(text.contains("Integration"));
            assert!(text.contains("tests."));
            assert!(!renderer.paragraph("worker\x1b[31m text").contains('\x1b'));
        }
    }

    #[test]
    fn only_trusted_style_sequences_survive_in_colored_output() {
        let renderer = Renderer {
            color: true,
            width: 80,
            unicode: true,
        };
        let output = renderer.notice("Warning", "injected \x1b[2Jmessage", Tone::Warning);
        assert!(output.starts_with("\x1b[33mWarning\x1b[0m\n"));
        assert!(!output.contains("\x1b[2J"));
        assert!(renderer.step(2, 5, "Prepare account").contains("[2/5]"));
    }

    #[test]
    fn help_layout_reflows_at_narrow_normal_and_wide_terminal_sizes() {
        for width in [40, 80, 100] {
            let renderer = Renderer {
                color: false,
                width,
                unicode: false,
            };
            for help in [
                crate::args::OVERVIEW,
                crate::args::HELP,
                crate::args::help(crate::args::HelpTopic::Status),
            ] {
                let output = renderer.document(help);
                assert!(
                    output.lines().all(|line| line.chars().count() <= width),
                    "{width}: {output}"
                );
                assert!(output.contains("Usage:"));
                assert!(!output.contains('\x1b'));
            }
        }
    }

    #[test]
    fn status_rows_have_readable_plain_and_colored_presentations() {
        let plain = Renderer {
            color: false,
            width: 80,
            unicode: false,
        };
        assert_eq!(
            plain.detail("Integration:", "trial"),
            "  Integration:         trial\n"
        );
        let narrow = Renderer { width: 40, ..plain };
        assert_eq!(
            narrow.detail("Integration:", "trial"),
            "  Integration:\n    trial\n"
        );
        let color = Renderer {
            color: true,
            ..plain
        };
        assert!(
            color
                .detail("Integration:", "trial")
                .contains("\x1b[33mtrial\x1b[0m")
        );
        assert!(
            color
                .detail("Active:", "yes")
                .contains("\x1b[32myes\x1b[0m")
        );
    }
}
