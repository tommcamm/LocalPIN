//! Generate public synthetic seeds; never read a host credential or open IPC.
use localpin_core::{
    limits::KdfParameters,
    records::{ConfigRecord, CredentialRecord},
    secret::{CredentialKind, CredentialProfile, Pin, SecretBytes},
    throttle::ThrottleRecord,
    types::{
        AccountId, Backend as CoreBackend, BackendSelection, BootId, Generation, Incarnation,
        TimePoint, Uid,
    },
};
use localpin_protocol::*;
use std::{fs, path::Path};

fn id(byte: u8) -> Id {
    Id::from_bytes([byte; 16]).unwrap()
}

fn main() {
    let destination = std::env::args_os().nth(1).expect("corpus output directory");
    let root = Path::new(&destination);
    for name in ["records", "streams", "phc"] {
        fs::create_dir_all(root.join(name)).unwrap();
    }
    let account = AccountId {
        uid: Uid::new(1000).unwrap(),
        incarnation: Incarnation::new([7; 16]).unwrap(),
    };
    let generation = Generation::new(1).unwrap();
    let phc = b"$argon2id$v=19$m=65536,t=3,p=1$BwcHBwcHBwcHBwcHBwcHBw$CUNrJW+K3R42xrH7g4MDA7wv0ihz8Hcf0glJGhH5HZ4";
    fs::write(root.join("phc/canonical"), phc).unwrap();
    fs::write(root.join("phc/oversize"), [b'x'; 99]).unwrap();
    let config = ConfigRecord {
        selection: BackendSelection::Auto,
        kdf: KdfParameters::ENROLLMENT,
        tpm_safety_reserve: 2,
    }
    .encode()
    .unwrap();
    fs::write(root.join("records/config"), config).unwrap();
    let credential = CredentialRecord::new(account, generation, CoreBackend::Software, phc)
        .unwrap()
        .encode()
        .unwrap();
    fs::write(root.join("records/credential"), credential.expose()).unwrap();
    // Envelope parser seeds deliberately reuse one opaque synthetic PHC. They
    // exercise metadata and canonical encoding, never KDF work or verification.
    for (name, kind, length) in [
        ("pin-min", CredentialKind::NumericPin, 8),
        ("pin-max", CredentialKind::NumericPin, 16),
        ("passcode-min", CredentialKind::Passcode, 8),
        ("passcode-max", CredentialKind::Passcode, 64),
    ] {
        let profile = CredentialProfile {
            policy: 1,
            kind,
            length,
        };
        let record = CredentialRecord::new_with_profile(
            account,
            generation,
            CoreBackend::Software,
            profile,
            phc,
        )
        .unwrap()
        .encode()
        .unwrap();
        fs::write(
            root.join(format!("records/credential-v2-{name}")),
            record.expose(),
        )
        .unwrap();
    }
    let throttle = ThrottleRecord::initial(
        account,
        generation,
        TimePoint {
            boot: BootId::new([8; 16]).unwrap(),
            millis: 1,
        },
    )
    .encode()
    .unwrap();
    fs::write(root.join("records/throttle"), throttle).unwrap();
    let mut requests = vec![
        Request::Status,
        Request::BeginVerify,
        Request::Verify {
            challenge: id(2),
            pin: Pin::parse(b"000001").unwrap(),
        },
        Request::Cancel,
        Request::BeginEnroll {
            action: EnrollmentAction::Enroll,
            backend: Some(Backend::Software),
            kind: Some(CredentialKind::NumericPin),
        },
        Request::EnrollConversation {
            transaction: id(3),
            prompt: id(4),
            response: SecretBytes::from_slice(b"synthetic", MAX_CONVERSATION_BYTES).unwrap(),
        },
        Request::CommitEnrollment {
            transaction: id(3),
            pin: Pin::parse(b"00000123").unwrap(),
        },
        Request::Disable { transaction: id(3) },
        Request::RecoverDisable { target_uid: 1000 },
    ];
    for (kind, bytes) in [
        (CredentialKind::NumericPin, b"0012".as_slice()),
        (CredentialKind::NumericPin, b"0012345678901234"),
        (CredentialKind::Passcode, b" spaced "),
        (CredentialKind::Passcode, b"00112233"),
        (CredentialKind::Passcode, &[b'X'; 64]),
    ] {
        requests.push(Request::BeginEnroll {
            action: EnrollmentAction::Enroll,
            backend: Some(Backend::Tpm),
            kind: Some(kind),
        });
        requests.push(Request::Verify {
            challenge: id(2),
            pin: Pin::parse(bytes).unwrap(),
        });
        requests.push(Request::CommitEnrollment {
            transaction: id(3),
            pin: Pin::parse(bytes).unwrap(),
        });
    }
    requests.push(Request::BeginEnroll {
        action: EnrollmentAction::Disable,
        backend: None,
        kind: None,
    });
    let mut coalesced = Vec::new();
    for (index, request) in requests.into_iter().enumerate() {
        let frame = encode_request(&RequestEnvelope {
            connection: id(1),
            request,
        })
        .unwrap();
        fs::write(
            root.join(format!("streams/request-{index}")),
            frame.as_bytes(),
        )
        .unwrap();
        coalesced.extend_from_slice(frame.as_bytes());
    }
    let responses = [
        Response::Hello,
        Response::Status(Status {
            configured: BackendPreference::Auto,
            enrolled: Some(Backend::Tpm),
            profile: Some(CredentialProfile::legacy()),
            availability: Availability::Cooldown,
            cooldown_ms: u32::MAX,
            integration: Integration::NeedsAttention,
            tpm_detected: true,
            tpm_usable: false,
            reason: Reason::EligibilityUnavailable,
        }),
        Response::VerifyChallenge {
            challenge: id(2),
            generation: 1,
            backend: Backend::Tpm,
            profile: CredentialProfile::legacy(),
            valid_for_ms: 1,
        },
        Response::VerifyChallenge {
            challenge: id(2),
            generation: 1,
            backend: Backend::Tpm,
            profile: CredentialProfile {
                policy: 1,
                kind: CredentialKind::NumericPin,
                length: 4,
            },
            valid_for_ms: 5000,
        },
        Response::VerifyChallenge {
            challenge: id(2),
            generation: u64::MAX,
            backend: Backend::Software,
            profile: CredentialProfile {
                policy: 1,
                kind: CredentialKind::Passcode,
                length: 64,
            },
            valid_for_ms: 5000,
        },
        Response::Status(Status {
            configured: BackendPreference::Software,
            enrolled: Some(Backend::Software),
            profile: Some(CredentialProfile {
                policy: 1,
                kind: CredentialKind::Passcode,
                length: 8,
            }),
            availability: Availability::Available,
            cooldown_ms: 0,
            integration: Integration::Active,
            tpm_detected: false,
            tpm_usable: false,
            reason: Reason::None,
        }),
        Response::EnrollmentStarted {
            transaction: id(3),
            generation: 1,
            valid_for_ms: 1,
        },
        Response::ConversationPrompt {
            transaction: id(3),
            prompt: id(4),
            style: PromptStyle::EchoOff,
            text: PromptText::new("Synthetic prompt").unwrap(),
        },
        Response::EnrollmentReady {
            transaction: id(3),
            valid_for_ms: 1,
        },
        Response::Verification(VerificationOutcome::Granted),
        Response::Completed(Completion::Enrolled(Backend::Software)),
        Response::Cancelled,
        Response::Error(ErrorCode::PasswordRejected),
    ];
    for (index, response) in responses.into_iter().enumerate() {
        let frame = encode_response(&ResponseEnvelope {
            connection: id(1),
            response,
        })
        .unwrap();
        fs::write(
            root.join(format!("streams/response-{index}")),
            frame.as_bytes(),
        )
        .unwrap();
    }
    fs::write(root.join("streams/coalesced"), coalesced).unwrap();
    let hello = encode_response(&ResponseEnvelope {
        connection: id(1),
        response: Response::Hello,
    })
    .unwrap();
    let mut old_hello = hello.as_bytes().to_vec();
    old_hello[4] = 1;
    fs::write(root.join("streams/old-version-hello"), old_hello).unwrap();
    let request = encode_request(&RequestEnvelope {
        connection: id(1),
        request: Request::Verify {
            challenge: id(2),
            pin: Pin::parse(b"00112233").unwrap(),
        },
    })
    .unwrap();
    let mut overflow = request.as_bytes().to_vec();
    overflow[38..40].copy_from_slice(&65u16.to_be_bytes());
    fs::write(root.join("streams/credential-length-overflow"), overflow).unwrap();
}
