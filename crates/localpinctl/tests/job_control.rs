//! Real controlling-terminal regression; no broker, PAM or account is used.

use localpin_protocol::transport::Deadline;
use localpinctl::{terminal::Terminal, workflow::confirm_recovery};
use std::process::Command;

// The installed CLI is single-threaded. A libtest main thread would receive
// process-directed signals while its terminal test thread blocks them.
fn main() {
    if let Some(kind) = std::env::var_os("LOCALPIN_CLI_JOB_CONTROL_CHILD") {
        let mut terminal = Terminal::open().unwrap();
        if kind == "choice" {
            assert!(
                terminal
                    .choice(
                        "Choose [1]: ",
                        1,
                        Deadline::after(std::time::Duration::from_secs(10))
                    )
                    .is_err()
            );
        } else {
            assert!(confirm_recovery(&mut terminal).is_err());
        }
        return;
    }
    let output = Command::new("python3")
        .args(["-c", include_str!("terminal_job_control.py")])
        .arg(std::env::current_exe().unwrap())
        .arg(env!("CARGO_BIN_EXE_localpinctl"))
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
