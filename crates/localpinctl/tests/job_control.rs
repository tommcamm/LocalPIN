//! Real controlling-terminal regression; no broker, PAM or account is used.

use localpinctl::{terminal::Terminal, workflow::confirm_recovery};
use std::process::Command;

// The installed CLI is single-threaded. A libtest main thread would receive
// process-directed signals while its terminal test thread blocks them.
fn main() {
    if std::env::var_os("LOCALPIN_CLI_JOB_CONTROL_CHILD").is_some() {
        let mut terminal = Terminal::open().unwrap();
        assert!(confirm_recovery(&mut terminal).is_err());
        return;
    }
    let output = Command::new("python3")
        .args(["-c", include_str!("terminal_job_control.py")])
        .arg(std::env::current_exe().unwrap())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
