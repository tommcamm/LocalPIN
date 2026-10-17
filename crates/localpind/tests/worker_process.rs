//! Exercise the installed helper entry point over its actual private pipes.

use localpin_core::{
    limits::MAX_RECORD_BYTES,
    records::CredentialRecord,
    types::{AccountId, Backend, Generation, Incarnation, Uid},
};
use std::{
    io::Write,
    process::{Command, Output, Stdio},
    thread,
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

const WORKER: &str = env!("CARGO_BIN_EXE_localpin-worker");
// Existing M4 independently checked synthetic enrollment vector for 123456.
const PHC: &[u8] = b"$argon2id$v=19$m=65536,t=3,p=1$BwcHBwcHBwcHBwcHBwcHBw$CUNrJW+K3R42xrH7g4MDA7wv0ihz8Hcf0glJGhH5HZ4";

fn request(pin: &[u8; 6]) -> Zeroizing<Vec<u8>> {
    let record = CredentialRecord::new(
        AccountId {
            uid: Uid::new(1000).unwrap(),
            incarnation: Incarnation::new([1; 16]).unwrap(),
        },
        Generation::new(1).unwrap(),
        Backend::Software,
        PHC,
    )
    .unwrap()
    .encode()
    .unwrap();
    let mut request = Zeroizing::new(Vec::new());
    request.extend_from_slice(b"LPW1");
    request.extend_from_slice(&17u64.to_be_bytes());
    request.extend_from_slice(&(record.expose().len() as u32).to_be_bytes());
    request.extend_from_slice(record.expose());
    request.extend_from_slice(pin);
    request
}

fn execute(input: &[u8], arguments: &[&str]) -> Output {
    let mut child = Command::new(WORKER)
        .args(arguments)
        .env_clear()
        .current_dir("/")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    // Argument refusal can close stdin before this small synthetic write.
    let _ = stdin.write_all(input);
    drop(stdin);
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        if child.try_wait().unwrap().is_some() {
            return child.wait_with_output().unwrap();
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            // No unbounded wait even if a regression blocks native cleanup.
            let reap_deadline = Instant::now() + Duration::from_secs(1);
            while Instant::now() < reap_deadline {
                if child.try_wait().unwrap().is_some() {
                    break;
                }
                thread::sleep(Duration::from_millis(5));
            }
            panic!("one-shot helper exceeded its test deadline");
        }
        thread::sleep(Duration::from_millis(5));
    }
}

#[test]
fn actual_helper_software_match_and_mismatch_are_fixed_sanitized_results() {
    for (pin, outcome) in [(b"123456", 1), (b"000001", 2)] {
        let output = execute(&request(pin), &[]);
        assert!(output.status.success());
        let mut expected = b"LPWR".to_vec();
        expected.extend_from_slice(&17u64.to_be_bytes());
        expected.push(outcome);
        assert_eq!(output.stdout, expected);
        assert!(output.stderr.is_empty());
    }
}

#[test]
fn actual_helper_rejects_oversized_partial_trailing_input_and_arguments_silently() {
    let mut oversized = b"LPW1".to_vec();
    oversized.extend_from_slice(&17u64.to_be_bytes());
    oversized.extend_from_slice(&((MAX_RECORD_BYTES + 1) as u32).to_be_bytes());
    let mut trailing = request(b"123456");
    trailing.push(0);
    for input in [
        oversized.as_slice(),
        b"LPW1".as_slice(),
        trailing.as_slice(),
    ] {
        let output = execute(input, &[]);
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        assert!(output.stderr.is_empty());
    }
    let output = execute(&request(b"123456"), &["--unexpected"]);
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert!(output.stderr.is_empty());
}
