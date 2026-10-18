//! Installed-command rejection checks use no host authentication mutation.

use std::process::Command;

fn command() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_localpinctl"));
    command.env_clear();
    command
}

#[test]
fn secret_arguments_are_usage_errors_without_printing_the_value() {
    for parts in [
        vec!["enroll", "--pin", "synthetic-private-value"],
        vec!["setup", "--password", "synthetic-private-value"],
        vec!["status", "--pin=synthetic-private-value"],
        vec!["status", "--pin=synthetic-private-value", "--help"],
        vec!["--color", "synthetic-private-value", "--help"],
    ] {
        let output = command().args(parts).output().unwrap();
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("secret arguments are not accepted"));
        assert!(!stderr.contains("synthetic-private-value"));
        assert!(!output.stderr.contains(&0x1b));
    }
}

#[test]
fn invalid_non_utf8_tokens_are_not_printed_in_usage_errors() {
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;
    let rejected = OsString::from_vec(b"synthetic-private-\xff-value".to_vec());
    for (choice, expected_color) in [("never", false), ("always", true)] {
        let output = command()
            .args(["--color", choice])
            .arg(&rejected)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
        assert_eq!(output.stderr.contains(&0x1b), expected_color);
        assert!(
            !output
                .stderr
                .windows(b"synthetic-private".len())
                .any(|part| part == b"synthetic-private")
        );
        assert!(!output.stderr.contains(&0xff));
    }
}

#[test]
fn secret_environment_and_simulator_override_are_rejected_without_values() {
    for name in ["LOCALPIN_PASSWORD", "LOCALPIN_SIMULATOR"] {
        let output = command()
            .arg("status")
            .env(name, "synthetic-private-value")
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("environment variables are not accepted"));
        assert!(!stderr.contains("synthetic-private-value"));
    }
}

#[test]
fn integration_changes_do_not_claim_activation() {
    for (operation, root_action) in [("enable", "activate"), ("disable", "disable")] {
        let output = command().args(["integration", operation]).output().unwrap();
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        let diagnostic = String::from_utf8_lossy(&output.stderr);
        assert!(diagnostic.contains(&format!("sudo localpin-integration {root_action}")));
        if operation == "enable" {
            assert!(diagnostic.contains("root activation tooling"));
            assert!(diagnostic.contains("bounded trial"));
            assert!(diagnostic.contains("tests first"));
        }
    }
}

#[test]
fn integration_status_reads_the_local_gate_without_broker_or_terminal() {
    let output = command().args(["integration", "status"]).output().unwrap();
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    assert!(String::from_utf8_lossy(&output.stdout).contains("Desktop integration gate:"));
}

#[test]
fn version_and_top_level_help_need_no_broker_or_terminal() {
    for argument in ["--version", "-V", "--help", "-h", "help"] {
        let output = command().arg(argument).output().unwrap();
        assert!(output.status.success());
        assert!(output.stderr.is_empty());
        assert!(String::from_utf8_lossy(&output.stdout).contains("localpinctl"));
        assert!(!output.stdout.contains(&0x1b));
    }
}

#[test]
fn no_command_prints_a_brief_overview_without_prompting() {
    let output = command().output().unwrap();
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    let overview = String::from_utf8_lossy(&output.stdout);
    assert!(overview.contains("Usage: localpin"));
    assert!(overview.contains("localpin setup"));
    assert!(overview.contains("localpin --help"));
    assert!(overview.lines().count() <= 16, "{overview}");
    assert!(!overview.contains("Choose"));
    assert!(!output.stdout.contains(&0x1b));
}

#[test]
fn every_command_help_path_is_pure_without_broker_terminal_or_privilege() {
    for args in [
        vec!["help", "menu"],
        vec!["setup", "--help"],
        vec!["help", "setup"],
        vec!["status", "-h"],
        vec!["doctor", "--help"],
        vec!["enroll", "--help"],
        vec!["enroll", "--backend", "software", "--help"],
        vec!["change", "--help"],
        vec!["disable", "--help"],
        vec!["migrate", "--help"],
        vec!["integration", "--help"],
        vec!["integration", "status", "--help"],
        vec!["help", "integration", "enable"],
        vec!["integration", "disable", "-h"],
        vec!["recover", "--help"],
        vec!["completions", "--help"],
    ] {
        let output = command().arg("--no-input").args(&args).output().unwrap();
        assert!(output.status.success(), "{args:?}: {:?}", output.stderr);
        assert!(output.stderr.is_empty(), "{args:?}: {:?}", output.stderr);
        let help = String::from_utf8_lossy(&output.stdout);
        assert!(help.contains("Usage: localpin"), "{args:?}: {help}");
        assert!(!output.stdout.contains(&0x1b));
    }
}

#[test]
fn no_input_refuses_interactive_commands_before_terminal_or_helper_work() {
    for args in [
        vec!["menu"],
        vec!["setup"],
        vec!["enroll", "--backend", "software"],
        vec!["change"],
        vec!["disable"],
        vec!["migrate", "--backend", "software"],
        vec!["recover", "--user", "synthetic-account"],
    ] {
        let output = command().arg("--no-input").args(&args).output().unwrap();
        assert_eq!(output.status.code(), Some(1), "{args:?}");
        assert!(output.stdout.is_empty(), "{args:?}: {:?}", output.stdout);
        let diagnostic = String::from_utf8_lossy(&output.stderr);
        assert!(diagnostic.contains("--no-input"), "{args:?}: {diagnostic}");
        assert!(!diagnostic.contains("[sudo]"));
        assert!(!diagnostic.contains("Password:"));
        assert!(!diagnostic.contains("Choose a number"));
    }
}

#[test]
fn global_color_option_controls_human_output_and_respects_no_color() {
    let automatic = command()
        .arg("--help")
        .env("NO_COLOR", "1")
        .output()
        .unwrap();
    assert!(automatic.status.success());
    assert!(!automatic.stdout.contains(&0x1b));

    let never = command()
        .args(["--help", "--color=never"])
        .output()
        .unwrap();
    assert!(never.status.success());
    assert!(!never.stdout.contains(&0x1b));

    let forced = command()
        .args(["--help", "--color=always"])
        .env("NO_COLOR", "1")
        .output()
        .unwrap();
    assert!(forced.status.success());
    assert!(forced.stdout.contains(&0x1b));
}

#[test]
fn completion_output_matches_packaged_source_without_styling_or_inspection() {
    for (shell, source) in [
        (
            "bash",
            include_str!("../../../packaging/completions/localpin.bash"),
        ),
        (
            "zsh",
            include_str!("../../../packaging/completions/localpin.zsh"),
        ),
        (
            "fish",
            include_str!("../../../packaging/completions/localpin.fish"),
        ),
    ] {
        let output = command()
            .args(["--color=always", "--no-input", "completions", shell])
            .output()
            .unwrap();
        assert!(output.status.success(), "{shell}: {:?}", output.stderr);
        assert!(output.stderr.is_empty());
        assert_eq!(
            String::from_utf8(output.stdout.clone()).unwrap(),
            format!("{}\n", source.trim_end())
        );
        assert!(!output.stdout.contains(&0x1b));
    }
}

#[test]
fn closed_output_reader_exits_successfully_without_panicking_or_diagnostic() {
    use std::os::fd::OwnedFd;
    use std::os::unix::net::UnixStream;
    use std::process::Stdio;

    // Close the reader before exec, avoiding a race with a short help write.
    // A Unix stream reports the same BrokenPipe write error as a closed pipe.
    let (writer, reader) = UnixStream::pair().unwrap();
    drop(reader);
    let output = command()
        .arg("--help")
        .stdout(Stdio::from(OwnedFd::from(writer)))
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(0));
    assert!(output.stdout.is_empty());
    assert!(output.stderr.is_empty(), "{:?}", output.stderr);
}

#[test]
fn usage_errors_preserve_explicit_color_and_no_color_precedence_in_pipes() {
    for (choice, no_color, expected_color) in [
        ("always", false, true),
        ("always", true, true),
        ("never", false, false),
        ("never", true, false),
        ("auto", false, false),
        ("auto", true, false),
    ] {
        let mut command = command();
        command.args(["--color", choice, "synthetic-private-invalid-command"]);
        if no_color {
            command.env("NO_COLOR", "1");
        }
        let output = command.output().unwrap();
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
        assert_eq!(output.stderr.contains(&0x1b), expected_color);
        assert!(!String::from_utf8_lossy(&output.stderr).contains("synthetic-private"));
    }
}

#[test]
fn usage_errors_detect_stderr_terminal_and_respect_explicit_color() {
    use rustix::pty::{OpenptFlags, grantpt, ioctl_tiocgptpeer, openpt, unlockpt};
    use std::fs::File;
    use std::io::Read;
    use std::process::Stdio;

    for (choice, no_color, expected_color) in [
        ("never", false, false),
        ("always", true, true),
        ("auto", false, true),
        ("auto", true, false),
    ] {
        let master =
            openpt(OpenptFlags::RDWR | OpenptFlags::NOCTTY | OpenptFlags::CLOEXEC).unwrap();
        grantpt(&master).unwrap();
        unlockpt(&master).unwrap();
        let slave = ioctl_tiocgptpeer(
            &master,
            OpenptFlags::RDWR | OpenptFlags::NOCTTY | OpenptFlags::CLOEXEC,
        )
        .unwrap();
        let mut command = command();
        command
            .args(["--color", choice, "synthetic-private-invalid-command"])
            .env("TERM", "xterm-256color")
            .stderr(Stdio::from(File::from(slave)));
        if no_color {
            command.env("NO_COLOR", "1");
        }
        let output = command.output().unwrap();
        // Command keeps its configured stderr descriptor until dropped.
        drop(command);
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
        let mut terminal = File::from(master);
        let mut diagnostics = Vec::new();
        let mut buffer = [0; 1024];
        loop {
            match terminal.read(&mut buffer) {
                Ok(0) => break,
                Ok(count) => diagnostics.extend_from_slice(&buffer[..count]),
                Err(error)
                    if error.raw_os_error() == Some(rustix::io::Errno::IO.raw_os_error()) =>
                {
                    break;
                }
                Err(error) => panic!("could not read disposable stderr PTY: {error}"),
            }
        }
        assert_eq!(diagnostics.contains(&0x1b), expected_color);
        assert!(!String::from_utf8_lossy(&diagnostics).contains("synthetic-private"));
    }
}
