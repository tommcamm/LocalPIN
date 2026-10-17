//! Reproducible bounded parser campaigns; these are not coverage-guided fuzzing.
//! All payloads are synthetic and no Linux transport is opened.

use localpin_core::secret::{Pin, SecretBytes};
use localpin_protocol::*;

struct Generator(u64);
impl Generator {
    fn next(&mut self) -> usize {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        (self.0 >> 32) as usize
    }
}

fn id(value: u8) -> Id {
    Id::from_bytes([value; 16]).unwrap()
}

trait CanonicalDecoder: Default {
    fn push_frame(&mut self, bytes: &[u8]) -> Result<(usize, Option<EncodedFrame>), ProtocolError>;
    fn finish_stream(&mut self) -> Result<(), ProtocolError>;
}

impl CanonicalDecoder for RequestDecoder {
    fn push_frame(&mut self, bytes: &[u8]) -> Result<(usize, Option<EncodedFrame>), ProtocolError> {
        let (consumed, request) = self.push(bytes)?;
        Ok((consumed, request.as_ref().map(encode_request).transpose()?))
    }

    fn finish_stream(&mut self) -> Result<(), ProtocolError> {
        self.finish()
    }
}

impl CanonicalDecoder for ResponseDecoder {
    fn push_frame(&mut self, bytes: &[u8]) -> Result<(usize, Option<EncodedFrame>), ProtocolError> {
        let (consumed, response) = self.push(bytes)?;
        Ok((
            consumed,
            response.as_ref().map(encode_response).transpose()?,
        ))
    }

    fn finish_stream(&mut self) -> Result<(), ProtocolError> {
        self.finish()
    }
}

fn remains_poisoned<D: CanonicalDecoder>(decoder: &mut D) {
    assert!(matches!(
        decoder.push_frame(&[]),
        Err(ProtocolError::OutOfOrder)
    ));
    assert!(matches!(
        decoder.push_frame(&[0; 22]),
        Err(ProtocolError::OutOfOrder)
    ));
    assert_eq!(decoder.finish_stream(), Err(ProtocolError::OutOfOrder));
}

fn inspect<D: CanonicalDecoder>(bytes: &[u8], generator: &mut Generator) -> (usize, bool) {
    let mut decoder = D::default();
    let mut offset = 0;
    let mut frame_start = 0;
    let mut frames = 0;
    while offset < bytes.len() {
        let end = bytes.len().min(offset + 1 + generator.next() % 37);
        match decoder.push_frame(&bytes[offset..end]) {
            Ok((consumed, frame)) => {
                // A parser may stop at one frame, but must make bounded progress.
                assert!((1..=end - offset).contains(&consumed));
                offset += consumed;
                if let Some(frame) = frame {
                    assert_eq!(frame.as_bytes(), &bytes[frame_start..offset]);
                    assert!(frame.as_bytes().len() <= MAX_FRAME_BYTES);
                    frame_start = offset;
                    frames += 1;
                }
            }
            Err(_) => {
                remains_poisoned(&mut decoder);
                return (frames, false);
            }
        }
    }
    if decoder.finish_stream().is_err() {
        remains_poisoned(&mut decoder);
        (frames, false)
    } else {
        assert_eq!(frame_start, bytes.len());
        (frames, true)
    }
}

fn responses() -> Vec<EncodedFrame> {
    let messages = [
        Response::Hello,
        Response::Status(Status {
            configured: BackendPreference::Auto,
            enrolled: Some(Backend::Tpm),
            availability: Availability::Cooldown,
            cooldown_ms: u32::MAX,
            integration: Integration::NeedsAttention,
            tpm_detected: true,
            tpm_usable: false,
            reason: Reason::EligibilityUnavailable,
        }),
        Response::VerifyChallenge {
            challenge: id(2),
            valid_for_ms: VERIFY_LIFETIME_MS as u32,
        },
        Response::EnrollmentStarted {
            transaction: id(3),
            generation: u64::MAX,
            valid_for_ms: ENROLLMENT_LIFETIME_MS as u32,
        },
        Response::ConversationPrompt {
            transaction: id(3),
            prompt: id(4),
            style: PromptStyle::EchoOff,
            text: PromptText::new(&"ø".repeat(MAX_PROMPT_BYTES / 2)).unwrap(),
        },
        Response::EnrollmentReady {
            transaction: id(3),
            valid_for_ms: 1,
        },
        Response::Verification(VerificationOutcome::Granted),
        Response::Verification(VerificationOutcome::Mismatch),
        Response::Verification(VerificationOutcome::Cooldown(u32::MAX)),
        Response::Verification(VerificationOutcome::Unavailable(Reason::Policy)),
        Response::Completed(Completion::Enrolled(Backend::Software)),
        Response::Completed(Completion::Disabled),
        Response::Completed(Completion::RecoveryDisabled),
        Response::Cancelled,
        Response::Error(ErrorCode::PasswordRejected),
    ];
    messages
        .into_iter()
        .map(|response| {
            encode_response(&ResponseEnvelope {
                connection: id(1),
                response,
            })
            .unwrap()
        })
        .collect()
}

#[test]
fn response_mutation_campaign_checks_chunking_canonicalization_and_poisoning() {
    let mut generator = Generator(0x4d39_7265_7370_6f6e);
    for original in responses() {
        assert_eq!(
            inspect::<ResponseDecoder>(original.as_bytes(), &mut generator),
            (1, true)
        );
        for _ in 0..2048 {
            let mut bytes = original.as_bytes().to_vec();
            for _ in 0..1 + generator.next() % 8 {
                let offset = generator.next() % bytes.len();
                bytes[offset] = generator.next() as u8;
            }
            let _ = inspect::<ResponseDecoder>(&bytes, &mut generator);
        }
    }
    // Plausible framing drives arbitrary payloads beyond the length-prefix check.
    for body_len in 18..=MAX_BODY_BYTES + 1 {
        let mut bytes = vec![0; body_len + 4];
        bytes[..4].copy_from_slice(&(body_len as u32).to_be_bytes());
        for byte in &mut bytes[4..] {
            *byte = generator.next() as u8;
        }
        bytes[4] = VERSION;
        bytes[5] = 0x80 + (generator.next() % 10) as u8;
        let _ = inspect::<ResponseDecoder>(&bytes, &mut generator);
    }
}

#[test]
fn coalesced_frames_and_malformed_tails_are_independent_of_stream_partition() {
    let request_frames: Vec<_> = [
        Request::Status,
        Request::BeginVerify,
        Request::Verify {
            challenge: id(2),
            pin: Pin::parse(b"000001").unwrap(),
        },
        Request::BeginEnroll {
            action: EnrollmentAction::Enroll,
            backend: Some(Backend::Software),
        },
        Request::EnrollConversation {
            transaction: id(3),
            prompt: id(4),
            response: SecretBytes::from_slice(
                &vec![0xff; MAX_CONVERSATION_BYTES],
                MAX_CONVERSATION_BYTES,
            )
            .unwrap(),
        },
        Request::CommitEnrollment {
            transaction: id(3),
            pin: Pin::parse(b"000000").unwrap(),
        },
        Request::Disable { transaction: id(3) },
        Request::RecoverDisable {
            target_uid: u32::MAX - 1,
        },
        Request::Cancel,
    ]
    .into_iter()
    .map(|request| {
        encode_request(&RequestEnvelope {
            connection: id(1),
            request,
        })
        .unwrap()
    })
    .collect();
    let response_frames = responses();
    let request_stream: Vec<_> = request_frames
        .iter()
        .flat_map(|frame| frame.as_bytes())
        .copied()
        .collect();
    let response_stream: Vec<_> = response_frames
        .iter()
        .flat_map(|frame| frame.as_bytes())
        .copied()
        .collect();
    for seed in 1..=64 {
        let mut generator = Generator(seed);
        assert_eq!(
            inspect::<RequestDecoder>(&request_stream, &mut generator),
            (request_frames.len(), true)
        );
        assert_eq!(
            inspect::<ResponseDecoder>(&response_stream, &mut generator),
            (response_frames.len(), true)
        );
        for tail in [
            &[0xff][..],
            &[0xff; 4][..],
            &request_frames[0].as_bytes()[..10],
        ] {
            let mut stream = request_stream.clone();
            stream.extend_from_slice(tail);
            assert_eq!(
                inspect::<RequestDecoder>(&stream, &mut generator),
                (request_frames.len(), false)
            );
            let mut stream = response_stream.clone();
            stream.extend_from_slice(tail);
            assert_eq!(
                inspect::<ResponseDecoder>(&stream, &mut generator),
                (response_frames.len(), false)
            );
        }
    }
}
