//! Closed root-command grammar; no host lifecycle state is changed.

use std::process::Command;

#[test]
fn cache_commands_have_no_paths_programs_or_uid_arguments() {
    for arguments in [
        vec!["cache-window-begin", "--uid", "1000"],
        vec!["cache-window-finish", "--root", "/tmp"],
        vec!["cache-window-begin", "/usr/bin/true"],
        vec!["cache-window-finish", "extra"],
        vec!["check-policy", "--uid", "1000"],
        vec!["check-policy", "--root", "/tmp"],
        vec!["check-policy", "kde"],
        vec!["check-policy", "--integration-lock-fd", "3"],
        vec!["--help", "--integration-lock-fd", "3"],
        vec!["begin-mutation", "--integration-lock-fd", "0"],
        vec!["begin-mutation", "--integration-lock-fd", "-1"],
        vec!["begin-mutation", "--integration-lock-fd", "03"],
        vec!["begin-mutation", "--integration-lock-fd", "+3"],
        vec!["begin-mutation", "--integration-lock-fd", "2147483648"],
        vec![
            "begin-mutation",
            "--integration-lock-fd",
            "3",
            "--integration-lock-fd",
            "4",
        ],
        vec!["seal", "--integration-lock-fd", "3", "--uid", "1000"],
        vec!["recover", "--uid", "1000", "--integration-lock-fd"],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_localpin-account"))
            .args(arguments)
            .env_clear()
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
    }
}

#[test]
fn help_exposes_fixed_cache_commands_and_non_root_cannot_open_a_window() {
    let output = Command::new(env!("CARGO_BIN_EXE_localpin-account"))
        .arg("--help")
        .env_clear()
        .output()
        .unwrap();
    assert!(output.status.success());
    let help = String::from_utf8(output.stdout).unwrap();
    assert!(help.contains("cache-window-begin"));
    assert!(help.contains("cache-window-finish"));
    assert!(help.contains("check-policy"));
    // A root CI invocation must never execute an accepted administrative verb
    // against its host. The closed-grammar checks above remain safe there.
    if rustix::process::getuid().as_raw() != 0 {
        for operation in ["cache-window-begin", "cache-window-finish", "check-policy"] {
            let output = Command::new(env!("CARGO_BIN_EXE_localpin-account"))
                .arg(operation)
                .env_clear()
                .output()
                .unwrap();
            assert!(!output.status.success());
            assert!(String::from_utf8_lossy(&output.stderr).contains("Privilege"));
        }
        for arguments in [
            vec!["begin-mutation", "--integration-lock-fd", "3"],
            vec!["seal", "--uid", "1000", "--integration-lock-fd", "3"],
            vec!["recover", "--uid", "1000", "--integration-lock-fd", "3"],
            vec!["cache-window-begin", "--integration-lock-fd", "3"],
            vec!["cache-window-finish", "--integration-lock-fd", "3"],
        ] {
            let output = Command::new(env!("CARGO_BIN_EXE_localpin-account"))
                .args(arguments)
                .env_clear()
                .output()
                .unwrap();
            assert!(!output.status.success());
            assert!(String::from_utf8_lossy(&output.stderr).contains("Privilege"));
        }
    }
}
