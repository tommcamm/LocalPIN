//! Installed-command rejection checks use no host authentication mutation.

use std::process::Command;

fn command() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_localpinctl"));
    command.env_clear();
    command
}

#[test]
fn secret_arguments_are_rejected_without_printing_the_value() {
    let output = command()
        .args(["enroll", "--pin", "synthetic-private-value"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stdout.is_empty());
    assert!(stderr.contains("secret arguments are not accepted"));
    assert!(!stderr.contains("synthetic-private-value"));
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
    let output = command().args(["integration", "enable"]).output().unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("root activation tooling"));
}

#[test]
fn version_and_help_need_no_broker_or_terminal() {
    for argument in ["--version", "--help"] {
        let output = command().arg(argument).output().unwrap();
        assert!(output.status.success());
        assert!(output.stderr.is_empty());
        assert!(String::from_utf8_lossy(&output.stdout).contains("localpinctl"));
    }
}
