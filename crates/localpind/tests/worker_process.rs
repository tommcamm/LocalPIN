//! Exercise the installed helper entry point over its actual private pipes.

use localpin_core::{
    limits::MAX_RECORD_BYTES,
    records::CredentialRecord,
    secret::{CredentialKind, CredentialProfile, Pin},
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

fn request(pin: &[u8]) -> Zeroizing<Vec<u8>> {
    let credential = CredentialRecord::new(
        AccountId {
            uid: Uid::new(1000).unwrap(),
            incarnation: Incarnation::new([1; 16]).unwrap(),
        },
        Generation::new(1).unwrap(),
        Backend::Software,
        PHC,
    )
    .unwrap();
    record_request(&credential, pin, false)
}

fn record_request(credential: &CredentialRecord, pin: &[u8], trial: bool) -> Zeroizing<Vec<u8>> {
    let record = credential.encode().unwrap();
    let mut request = Zeroizing::new(Vec::new());
    request.extend_from_slice(if trial { b"LPT2" } else { b"LPW2" });
    request.extend_from_slice(&17u64.to_be_bytes());
    request.extend_from_slice(&(record.expose().len() as u32).to_be_bytes());
    request.extend_from_slice(record.expose());
    request.extend_from_slice(&(pin.len() as u16).to_be_bytes());
    request.extend_from_slice(pin);
    request
}

fn enrollment_request(pin: &[u8]) -> Zeroizing<Vec<u8>> {
    enrollment_kind_request(pin, CredentialKind::NumericPin)
}

fn enrollment_kind_request(pin: &[u8], kind: CredentialKind) -> Zeroizing<Vec<u8>> {
    let mut request = Zeroizing::new(Vec::new());
    request.extend_from_slice(b"LPE2");
    request.extend_from_slice(&17u64.to_be_bytes());
    request.extend_from_slice(&32u32.to_be_bytes());
    request.extend_from_slice(&1000u32.to_be_bytes());
    request.extend_from_slice(&[1; 16]);
    request.extend_from_slice(&2u64.to_be_bytes());
    request.push(2); // Explicitly selected software; this test never opens a TPM.
    request.extend_from_slice(&[1, kind as u8, pin.len() as u8]);
    request.extend_from_slice(&(pin.len() as u16).to_be_bytes());
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
    let mut oversized = b"LPW2".to_vec();
    oversized.extend_from_slice(&17u64.to_be_bytes());
    oversized.extend_from_slice(&((MAX_RECORD_BYTES + 1) as u32).to_be_bytes());
    let mut trailing = request(b"123456");
    trailing.push(0);
    for input in [
        oversized.as_slice(),
        b"LPW2".as_slice(),
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

#[test]
fn actual_helper_provisions_bound_software_and_trials_the_returned_record() {
    let output = execute(&enrollment_request(b"01234567"), &[]);
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    assert!(output.stdout.len() <= 17 + MAX_RECORD_BYTES);
    assert_eq!(&output.stdout[..4], b"LPWE");
    assert_eq!(&output.stdout[4..12], &17u64.to_be_bytes());
    assert_eq!(output.stdout[12], 1);
    let length = u32::from_be_bytes(output.stdout[13..17].try_into().unwrap()) as usize;
    assert_eq!(output.stdout.len(), 17 + length);
    let record = CredentialRecord::decode(&output.stdout[17..]).unwrap();
    assert_eq!(record.account().uid.get(), 1000);
    assert_eq!(record.account().incarnation.get(), [1; 16]);
    assert_eq!(record.generation().get(), 2);
    assert_eq!(record.backend(), Backend::Software);
    for (pin, outcome) in [(b"01234567", 1), (b"12345678", 2)] {
        let output = execute(&record_request(&record, pin, true), &[]);
        assert!(output.status.success());
        assert_eq!(output.stdout.len(), 13);
        assert_eq!(&output.stdout[..4], b"LPWR");
        assert_eq!(&output.stdout[4..12], &17u64.to_be_bytes());
        assert_eq!(output.stdout[12], outcome);
        assert!(output.stderr.is_empty());
    }
    let output = execute(&record_request(&record, b"01234567", false), &[]);
    assert!(output.status.success());
    assert_eq!(output.stdout[12], 1);
}

#[test]
fn actual_helper_rejects_invalid_enrollment_bindings_pin_and_envelopes() {
    let request = enrollment_request(b"01234567");
    let mut malformed = Vec::new();
    for length in 0..request.len() {
        malformed.push(request[..length].to_vec());
    }
    for (start, end) in [(4, 12), (16, 20), (20, 36), (36, 44)] {
        let mut invalid = request.to_vec();
        invalid[start..end].fill(0);
        malformed.push(invalid);
    }
    for (offset, byte) in [
        (12, 1),
        (15, 28),
        (44, 3),
        (45, 0),
        (46, 0),
        (47, 6),
        (50, b'a'),
    ] {
        let mut invalid = request.to_vec();
        invalid[offset] = byte;
        malformed.push(invalid);
    }
    let mut trailing = request.to_vec();
    trailing.push(0);
    malformed.push(trailing);
    for input in malformed {
        let output = execute(&input, &[]);
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        assert!(output.stderr.is_empty());
    }
}

#[test]
fn actual_helper_handles_variable_numeric_and_exact_ascii_passcodes() {
    // Public synthetic fixtures. No installed credential or physical TPM is used.
    for (kind, value) in [
        (CredentialKind::NumericPin, b"0081463927".as_slice()),
        (CredentialKind::NumericPin, b"0081463927051836".as_slice()),
        (CredentialKind::Passcode, b" space and Symbols! ".as_slice()),
        (CredentialKind::Passcode, b"00814639".as_slice()),
        (CredentialKind::Passcode, &[b'X'; 64][..]),
    ] {
        let output = execute(&enrollment_kind_request(value, kind), &[]);
        assert!(output.status.success());
        assert_eq!(output.stdout[12], 1);
        let record = CredentialRecord::decode(&output.stdout[17..]).unwrap();
        assert_eq!(record.profile(), CredentialProfile::for_enrollment(
            Backend::Software, kind, &Pin::parse(value).unwrap(),
        ).unwrap());
        assert_eq!(&output.stdout[21..23], &2u16.to_be_bytes());
        let checked = execute(&record_request(&record, value, true), &[]);
        assert!(checked.status.success());
        assert_eq!(checked.stdout[12], 1);
        // Extra or missing spaces/characters must never turn into a valid prefix.
        let mut different_length = value.to_vec();
        different_length.pop();
        let checked = execute(&record_request(&record, &different_length, false), &[]);
        assert!(!checked.status.success());
        assert!(checked.stdout.is_empty());
    }
}

#[test]
fn actual_helper_rejects_legacy_requests_and_new_short_software_enrollment() {
    let mut old = request(b"123456");
    old[..4].copy_from_slice(b"LPW1");
    for input in [old, enrollment_request(b"123456")] {
        let output = execute(&input, &[]);
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        assert!(output.stderr.is_empty());
    }
}
