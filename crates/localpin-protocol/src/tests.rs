use super::*;
use localpin_core::secret::{Pin, SecretBytes};

fn id(byte: u8) -> Id {
    Id::from_bytes([byte; 16]).unwrap()
}
fn pin() -> Pin {
    Pin::parse(b"012345").unwrap()
}
fn secret(bytes: &[u8]) -> SecretBytes {
    SecretBytes::from_slice(bytes, MAX_CONVERSATION_BYTES).unwrap()
}
fn request(request: Request) -> RequestEnvelope {
    RequestEnvelope {
        connection: id(1),
        request,
    }
}

fn requests() -> Vec<RequestEnvelope> {
    vec![
        request(Request::Status),
        request(Request::BeginVerify),
        request(Request::Verify {
            challenge: id(2),
            pin: pin(),
        }),
        request(Request::Cancel),
        request(Request::BeginEnroll {
            action: EnrollmentAction::Enroll,
            backend: Some(Backend::Tpm),
        }),
        request(Request::BeginEnroll {
            action: EnrollmentAction::Rotate,
            backend: Some(Backend::Software),
        }),
        request(Request::BeginEnroll {
            action: EnrollmentAction::Migrate,
            backend: Some(Backend::Software),
        }),
        request(Request::BeginEnroll {
            action: EnrollmentAction::Disable,
            backend: None,
        }),
        request(Request::EnrollConversation {
            transaction: id(2),
            prompt: id(3),
            response: secret(b"non-utf8-\xff-password"),
        }),
        request(Request::EnrollConversation {
            transaction: id(2),
            prompt: id(3),
            response: secret(&[0xff; MAX_CONVERSATION_BYTES]),
        }),
        request(Request::CommitEnrollment {
            transaction: id(2),
            pin: pin(),
        }),
        request(Request::Disable { transaction: id(2) }),
        request(Request::RecoverDisable { target_uid: 1000 }),
    ]
}

fn responses() -> Vec<ResponseEnvelope> {
    vec![
        Response::Hello,
        Response::Status(Status {
            configured: BackendPreference::Auto,
            enrolled: Some(Backend::Tpm),
            availability: Availability::Available,
            cooldown_ms: 0,
            integration: Integration::Active,
            tpm_detected: true,
            tpm_usable: true,
            reason: Reason::None,
        }),
        Response::VerifyChallenge {
            challenge: id(2),
            valid_for_ms: 5_000,
        },
        Response::EnrollmentStarted {
            transaction: id(2),
            generation: 9,
            valid_for_ms: 60_000,
        },
        Response::ConversationPrompt {
            transaction: id(2),
            prompt: id(3),
            style: PromptStyle::EchoOff,
            text: PromptText::new("Password: ").unwrap(),
        },
        Response::EnrollmentReady {
            transaction: id(2),
            valid_for_ms: 60_000,
        },
        Response::Verification(VerificationOutcome::Granted),
        Response::Verification(VerificationOutcome::Mismatch),
        Response::Verification(VerificationOutcome::Cooldown(300_000)),
        Response::Verification(VerificationOutcome::Unavailable(Reason::Storage)),
        Response::Completed(Completion::Enrolled(Backend::Software)),
        Response::Completed(Completion::Disabled),
        Response::Completed(Completion::RecoveryDisabled),
        Response::Cancelled,
        Response::Error(ErrorCode::PasswordRejected),
    ]
    .into_iter()
    .map(|response| ResponseEnvelope {
        connection: id(1),
        response,
    })
    .collect()
}

#[test]
fn all_requests_and_responses_roundtrip_at_every_split() {
    for original in requests() {
        let frame = encode_request(&original).unwrap();
        for split in 0..=frame.as_bytes().len() {
            let mut decoder = RequestDecoder::default();
            let (consumed, first) = decoder.push(&frame.as_bytes()[..split]).unwrap();
            assert_eq!(consumed, split);
            let value = if let Some(value) = first {
                value
            } else {
                let (consumed, next) = decoder.push(&frame.as_bytes()[split..]).unwrap();
                assert_eq!(consumed, frame.as_bytes().len() - split);
                next.unwrap()
            };
            assert_eq!(encode_request(&value).unwrap().as_bytes(), frame.as_bytes());
            decoder.finish().unwrap();
        }
    }
    for original in responses() {
        let frame = encode_response(&original).unwrap();
        for split in 0..=frame.as_bytes().len() {
            let mut decoder = ResponseDecoder::default();
            let (_, first) = decoder.push(&frame.as_bytes()[..split]).unwrap();
            let value = first
                .unwrap_or_else(|| decoder.push(&frame.as_bytes()[split..]).unwrap().1.unwrap());
            assert_eq!(
                encode_response(&value).unwrap().as_bytes(),
                frame.as_bytes()
            );
            decoder.finish().unwrap();
        }
    }
}

#[test]
fn every_nonempty_truncation_fails_at_eof_and_poisoned_decoder_stays_closed() {
    for original in requests() {
        let frame = encode_request(&original).unwrap();
        for len in 1..frame.as_bytes().len() {
            let mut decoder = RequestDecoder::default();
            assert!(decoder.push(&frame.as_bytes()[..len]).unwrap().1.is_none());
            assert_eq!(decoder.finish(), Err(ProtocolError::Truncated));
            assert!(matches!(
                decoder.push(frame.as_bytes()),
                Err(ProtocolError::OutOfOrder)
            ));
        }
    }
    for original in responses() {
        let frame = encode_response(&original).unwrap();
        for len in 1..frame.as_bytes().len() {
            let mut decoder = ResponseDecoder::default();
            assert!(decoder.push(&frame.as_bytes()[..len]).unwrap().1.is_none());
            assert_eq!(decoder.finish(), Err(ProtocolError::Truncated));
        }
    }
}

#[test]
fn prefix_bounds_are_checked_before_body_and_maximum_body_is_bounded() {
    for body in [MAX_BODY_BYTES as u32 + 1, 4096, u32::MAX] {
        let mut decoder = RequestDecoder::default();
        assert!(matches!(
            decoder.push(&body.to_be_bytes()),
            Err(ProtocolError::Oversized)
        ));
    }
    for body in 0..18u32 {
        assert!(matches!(
            RequestDecoder::default().push(&body.to_be_bytes()),
            Err(ProtocolError::Truncated)
        ));
    }
    let mut frame = vec![0; MAX_FRAME_BYTES];
    frame[..4].copy_from_slice(&(MAX_BODY_BYTES as u32).to_be_bytes());
    frame[4] = VERSION;
    frame[5] = 1;
    frame[6..22].fill(1);
    let mut decoder = RequestDecoder::default();
    assert!(decoder.push(&frame[..4]).unwrap().1.is_none());
    assert!(matches!(
        decoder.push(&frame[4..]),
        Err(ProtocolError::TrailingData)
    ));
}

#[test]
fn unknown_versions_operations_enum_values_and_trailing_fields_are_rejected() {
    let frame = encode_request(&request(Request::Status)).unwrap();
    for value in 0..=u8::MAX {
        if value != VERSION {
            let mut bytes = frame.as_bytes().to_vec();
            bytes[4] = value;
            assert!(matches!(
                RequestDecoder::default().push(&bytes),
                Err(ProtocolError::Version)
            ));
        }
        if !(1..=9).contains(&value) {
            let mut bytes = frame.as_bytes().to_vec();
            bytes[5] = value;
            assert!(matches!(
                RequestDecoder::default().push(&bytes),
                Err(ProtocolError::UnknownValue)
            ));
        }
    }
    let mut bytes = frame.as_bytes().to_vec();
    bytes.push(0);
    bytes[..4].copy_from_slice(&19u32.to_be_bytes());
    assert!(matches!(
        RequestDecoder::default().push(&bytes),
        Err(ProtocolError::TrailingData)
    ));
    let mut bytes = frame.as_bytes().to_vec();
    bytes[6..22].fill(0);
    assert!(matches!(
        RequestDecoder::default().push(&bytes),
        Err(ProtocolError::InvalidField)
    ));
    let frame = encode_request(&request(Request::BeginEnroll {
        action: EnrollmentAction::Enroll,
        backend: Some(Backend::Tpm),
    }))
    .unwrap();
    for offset in [22, 23] {
        let mut bytes = frame.as_bytes().to_vec();
        bytes[offset] = 255;
        assert!(matches!(
            RequestDecoder::default().push(&bytes),
            Err(ProtocolError::UnknownValue)
        ));
    }
    // A client cannot send a server-only password-ready or verification result.
    for response in responses() {
        assert!(matches!(
            RequestDecoder::default().push(encode_response(&response).unwrap().as_bytes()),
            Err(ProtocolError::UnknownValue)
        ));
    }
}

#[test]
fn variable_fields_are_bounded_and_bytes_are_not_reinterpreted_as_strings() {
    let frame = encode_request(&request(Request::EnrollConversation {
        transaction: id(2),
        prompt: id(3),
        response: secret(b"\xff\0\x80"),
    }))
    .unwrap();
    let decoded = RequestDecoder::default()
        .push(frame.as_bytes())
        .unwrap()
        .1
        .unwrap();
    let Request::EnrollConversation { response, .. } = decoded.request else {
        panic!("wrong request");
    };
    assert_eq!(response.expose(), b"\xff\0\x80");
    let mut bytes = frame.as_bytes().to_vec();
    bytes[54..56].copy_from_slice(&2049u16.to_be_bytes());
    assert!(matches!(
        RequestDecoder::default().push(&bytes),
        Err(ProtocolError::InvalidField)
    ));
    assert!(PromptText::new(&"x".repeat(MAX_PROMPT_BYTES)).is_ok());
    assert!(PromptText::new(&"x".repeat(MAX_PROMPT_BYTES + 1)).is_err());
    assert!(PromptText::new("nul\0prompt").is_err());
    for target_uid in [0, u32::MAX] {
        assert!(encode_request(&request(Request::RecoverDisable { target_uid })).is_err());
    }
    assert!(
        encode_request(&request(Request::BeginEnroll {
            action: EnrollmentAction::Disable,
            backend: Some(Backend::Software)
        }))
        .is_err()
    );
    assert!(
        encode_request(&request(Request::BeginEnroll {
            action: EnrollmentAction::Enroll,
            backend: None
        }))
        .is_err()
    );
}

#[test]
fn concatenated_frames_are_consumed_one_at_a_time_and_single_byte_reads_work() {
    let frame = encode_request(&request(Request::Status)).unwrap();
    let both = [frame.as_bytes(), frame.as_bytes()].concat();
    let mut decoder = RequestDecoder::default();
    let (count, first) = decoder.push(&both).unwrap();
    assert_eq!(count, frame.as_bytes().len());
    assert!(first.is_some());
    assert!(decoder.push(&both[count..]).unwrap().1.is_some());
    let mut decoder = RequestDecoder::default();
    for (index, byte) in frame.as_bytes().iter().enumerate() {
        let (count, value) = decoder.push(&[*byte]).unwrap();
        assert_eq!(count, 1);
        assert_eq!(value.is_some(), index + 1 == frame.as_bytes().len());
    }
}

#[test]
fn deterministic_untrusted_byte_mutations_never_panic_or_emit_noncanonical_messages() {
    let mut seed = 0x2312_9809u32;
    for original in requests() {
        let frame = encode_request(&original).unwrap();
        for _ in 0..300 {
            let mut bytes = frame.as_bytes().to_vec();
            seed = seed.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            let offset = seed as usize % bytes.len();
            bytes[offset] ^= (seed >> 24) as u8 | 1;
            if let Ok((_, Some(value))) = RequestDecoder::default().push(&bytes) {
                assert_eq!(encode_request(&value).unwrap().as_bytes(), bytes);
            }
        }
    }
    for len in 0..MAX_FRAME_BYTES {
        let mut bytes = vec![0; len];
        for byte in &mut bytes {
            seed = seed.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            *byte = (seed >> 24) as u8;
        }
        let _ = RequestDecoder::default().push(&bytes);
        let _ = ResponseDecoder::default().push(&bytes);
    }
}

fn accept(
    connection: &mut Connection,
    request_value: Request,
    now: u64,
    issued: Option<Issued>,
) -> Result<ConnectionAction, ProtocolError> {
    connection.accept(
        RequestEnvelope {
            connection: connection.id(),
            request: request_value,
        },
        now,
        Eligibility::Eligible,
        issued,
    )
}

fn verification(now: u64) -> Connection {
    let mut connection = Connection::new(id(1), 1000, now);
    accept(
        &mut connection,
        Request::BeginVerify,
        now,
        Some(Issued::Verify(id(2))),
    )
    .unwrap();
    connection
}

fn enrollment(
    connection_id: u8,
    uid: u32,
    action: EnrollmentAction,
    now: u64,
) -> (Connection, PasswordContext) {
    let mut connection = Connection::new(id(connection_id), uid, now);
    let backend = if action == EnrollmentAction::Disable {
        None
    } else {
        Some(Backend::Tpm)
    };
    let result = accept(
        &mut connection,
        Request::BeginEnroll { action, backend },
        now,
        Some(Issued::Enrollment {
            transaction: id(20),
            generation: 9,
        }),
    )
    .unwrap();
    let ConnectionAction::StartPassword { context, .. } = result else {
        panic!("wrong action");
    };
    (connection, context)
}

#[test]
fn verification_is_bound_one_use_eligible_and_strictly_expiring() {
    let mut connection = verification(100);
    assert!(matches!(
        accept(
            &mut connection,
            Request::Verify {
                challenge: id(2),
                pin: pin()
            },
            5099,
            None
        ),
        Ok(ConnectionAction::Verify { uid: 1000, .. })
    ));
    let response = connection
        .finish_verification(VerificationOutcome::Granted, Eligibility::Eligible, 5100)
        .unwrap();
    assert!(matches!(
        response.response,
        Response::Verification(VerificationOutcome::Granted)
    ));
    assert!(connection.is_finished());
    assert!(
        connection
            .finish_verification(VerificationOutcome::Granted, Eligibility::Eligible, 5100)
            .is_err()
    );
    let mut connection = verification(100);
    assert!(matches!(
        accept(
            &mut connection,
            Request::Verify {
                challenge: id(2),
                pin: pin()
            },
            5100,
            None
        ),
        Err(ProtocolError::Expired)
    ));
    let mut connection = verification(100);
    assert!(matches!(
        accept(
            &mut connection,
            Request::Verify {
                challenge: id(3),
                pin: pin()
            },
            101,
            None
        ),
        Err(ProtocolError::Binding)
    ));
    let mut connection = verification(100);
    let request = RequestEnvelope {
        connection: id(9),
        request: Request::Verify {
            challenge: id(2),
            pin: pin(),
        },
    };
    assert!(matches!(
        connection.accept(request, 101, Eligibility::Eligible, None),
        Err(ProtocolError::Binding)
    ));
    let mut connection = verification(100);
    let request = RequestEnvelope {
        connection: id(1),
        request: Request::Verify {
            challenge: id(2),
            pin: pin(),
        },
    };
    assert!(matches!(
        connection.accept(request, 101, Eligibility::Denied, None),
        Err(ProtocolError::Forbidden)
    ));
}

#[test]
fn late_cancelled_or_ineligible_backend_results_cannot_authorize() {
    for mode in 0..3 {
        let mut connection = verification(0);
        accept(
            &mut connection,
            Request::Verify {
                challenge: id(2),
                pin: pin(),
            },
            1,
            None,
        )
        .unwrap();
        if mode == 0 {
            assert!(matches!(
                accept(&mut connection, Request::Cancel, 2, None),
                Ok(ConnectionAction::Cancel)
            ));
        }
        let now = if mode == 1 { 5001 } else { 2 };
        let eligibility = if mode == 2 {
            Eligibility::Denied
        } else {
            Eligibility::Eligible
        };
        assert!(
            connection
                .finish_verification(VerificationOutcome::Granted, eligibility, now)
                .is_err()
        );
        assert!(connection.is_finished());
    }
}

#[test]
fn fresh_password_context_enables_exactly_one_transaction_action_and_generation() {
    let (mut connection, context) = enrollment(1, 1000, EnrollmentAction::Rotate, 0);
    connection
        .password_prompt(
            context,
            id(3),
            PromptStyle::EchoOff,
            PromptText::new("Password:").unwrap(),
            1,
        )
        .unwrap();
    assert!(matches!(
        accept(
            &mut connection,
            Request::EnrollConversation {
                transaction: id(20),
                prompt: id(3),
                response: secret(b"\xff-password")
            },
            2,
            None
        ),
        Ok(ConnectionAction::AnswerPassword { .. })
    ));
    connection.password_authenticated(context, 3).unwrap();
    let action = accept(
        &mut connection,
        Request::CommitEnrollment {
            transaction: id(20),
            pin: pin(),
        },
        60_002,
        None,
    )
    .unwrap();
    let ConnectionAction::CommitEnrollment {
        context: grant,
        backend,
        ..
    } = action
    else {
        panic!("wrong action");
    };
    assert_eq!(grant, context);
    assert_eq!(grant.uid(), 1000);
    assert_eq!(grant.generation(), 9);
    assert_eq!(grant.action(), EnrollmentAction::Rotate);
    assert_eq!(backend, Backend::Tpm);
    connection
        .finish_mutation(
            Completion::Enrolled(Backend::Tpm),
            Eligibility::Eligible,
            60_002,
        )
        .unwrap();
    assert!(
        accept(
            &mut connection,
            Request::CommitEnrollment {
                transaction: id(20),
                pin: pin()
            },
            60_002,
            None
        )
        .is_err()
    );
}

#[test]
fn preauthentication_wrong_action_reconnect_and_worker_context_replay_fail() {
    let (mut connection, _) = enrollment(1, 1000, EnrollmentAction::Enroll, 0);
    assert!(matches!(
        accept(
            &mut connection,
            Request::CommitEnrollment {
                transaction: id(20),
                pin: pin()
            },
            1,
            None
        ),
        Err(ProtocolError::OutOfOrder)
    ));
    let (mut first, context) = enrollment(1, 1000, EnrollmentAction::Enroll, 0);
    let (mut second, other) = enrollment(2, 1001, EnrollmentAction::Enroll, 0);
    assert!(matches!(
        second.password_authenticated(context, 1),
        Err(ProtocolError::Binding)
    ));
    assert!(matches!(
        first.password_authenticated(other, 1),
        Err(ProtocolError::Binding)
    ));
    let mut reconnected = Connection::new(id(9), 1000, 0);
    assert!(matches!(
        accept(
            &mut reconnected,
            Request::Disable {
                transaction: id(20)
            },
            1,
            None
        ),
        Err(ProtocolError::OutOfOrder)
    ));
    let (mut connection, context) = enrollment(1, 1000, EnrollmentAction::Enroll, 0);
    connection.password_authenticated(context, 1).unwrap();
    assert!(matches!(
        accept(
            &mut connection,
            Request::Disable {
                transaction: id(20)
            },
            2,
            None
        ),
        Err(ProtocolError::OutOfOrder)
    ));
    let (mut connection, context) = enrollment(1, 1000, EnrollmentAction::Disable, 0);
    connection.password_authenticated(context, 1).unwrap();
    assert!(matches!(
        accept(
            &mut connection,
            Request::CommitEnrollment {
                transaction: id(20),
                pin: pin()
            },
            2,
            None
        ),
        Err(ProtocolError::OutOfOrder)
    ));
}

#[test]
fn password_prompt_replay_unexpected_answers_and_prompt_count_are_bounded() {
    let (mut connection, context) = enrollment(1, 1000, EnrollmentAction::Enroll, 0);
    for index in 0..MAX_PASSWORD_PROMPTS {
        let prompt = id(index as u8 + 30);
        connection
            .password_prompt(
                context,
                prompt,
                PromptStyle::EchoOff,
                PromptText::new("Password:").unwrap(),
                1,
            )
            .unwrap();
        accept(
            &mut connection,
            Request::EnrollConversation {
                transaction: id(20),
                prompt,
                response: secret(b"password"),
            },
            1,
            None,
        )
        .unwrap();
    }
    assert!(matches!(
        connection.password_prompt(
            context,
            id(99),
            PromptStyle::EchoOff,
            PromptText::new("").unwrap(),
            1
        ),
        Err(ProtocolError::OutOfOrder)
    ));
    let (mut connection, context) = enrollment(1, 1000, EnrollmentAction::Enroll, 0);
    connection
        .password_prompt(
            context,
            id(3),
            PromptStyle::Info,
            PromptText::new("Notice").unwrap(),
            1,
        )
        .unwrap();
    assert!(
        accept(
            &mut connection,
            Request::EnrollConversation {
                transaction: id(20),
                prompt: id(3),
                response: secret(b"unexpected")
            },
            1,
            None
        )
        .is_err()
    );
    let (mut connection, context) = enrollment(1, 1000, EnrollmentAction::Enroll, 0);
    connection
        .password_prompt(
            context,
            id(3),
            PromptStyle::Info,
            PromptText::new("Notice").unwrap(),
            1,
        )
        .unwrap();
    accept(
        &mut connection,
        Request::EnrollConversation {
            transaction: id(20),
            prompt: id(3),
            response: secret(b""),
        },
        1,
        None,
    )
    .unwrap();
    assert!(matches!(
        connection.password_prompt(
            context,
            id(3),
            PromptStyle::Info,
            PromptText::new("Notice").unwrap(),
            1
        ),
        Err(ProtocolError::OutOfOrder)
    ));
}

#[test]
fn enrollment_expiry_password_failure_and_clock_anomalies_fail_closed() {
    let (mut connection, context) = enrollment(1, 1000, EnrollmentAction::Enroll, 0);
    assert!(matches!(
        connection.password_authenticated(context, 60_000),
        Err(ProtocolError::Expired)
    ));
    let (mut connection, context) = enrollment(1, 1000, EnrollmentAction::Enroll, 0);
    connection.password_authenticated(context, 10).unwrap();
    assert!(matches!(
        accept(
            &mut connection,
            Request::CommitEnrollment {
                transaction: id(20),
                pin: pin()
            },
            60_010,
            None
        ),
        Err(ProtocolError::Expired)
    ));
    let (mut connection, context) = enrollment(1, 1000, EnrollmentAction::Enroll, 0);
    connection.password_failed(context, 1).unwrap();
    assert!(connection.password_authenticated(context, 2).is_err());
    let mut connection = verification(100);
    assert!(matches!(
        accept(
            &mut connection,
            Request::Verify {
                challenge: id(2),
                pin: pin()
            },
            99,
            None
        ),
        Err(ProtocolError::Clock)
    ));
    let mut connection = Connection::new(id(1), 1000, u64::MAX);
    assert!(matches!(
        accept(
            &mut connection,
            Request::BeginVerify,
            u64::MAX,
            Some(Issued::Verify(id(2)))
        ),
        Err(ProtocolError::Clock)
    ));
}

#[test]
fn disable_and_admin_recovery_are_distinct_and_root_cannot_use_normal_operations() {
    let (mut connection, context) = enrollment(1, 1000, EnrollmentAction::Disable, 0);
    connection.password_authenticated(context, 1).unwrap();
    assert!(matches!(
        accept(
            &mut connection,
            Request::Disable {
                transaction: id(20)
            },
            2,
            None
        ),
        Ok(ConnectionAction::Disable { .. })
    ));
    connection
        .finish_mutation(Completion::Disabled, Eligibility::Eligible, 3)
        .unwrap();
    let mut root = Connection::new(id(1), 0, 0);
    assert!(matches!(
        accept(
            &mut root,
            Request::RecoverDisable { target_uid: 1000 },
            1,
            None
        ),
        Ok(ConnectionAction::RecoverDisable { target_uid: 1000 })
    ));
    root.finish_mutation(Completion::RecoveryDisabled, Eligibility::Denied, 2)
        .unwrap();
    let mut user = Connection::new(id(1), 1000, 0);
    assert!(matches!(
        accept(
            &mut user,
            Request::RecoverDisable { target_uid: 1000 },
            1,
            None
        ),
        Err(ProtocolError::Forbidden)
    ));
    for uid in [0, u32::MAX] {
        let mut peer = Connection::new(id(1), uid, 0);
        assert!(matches!(
            accept(&mut peer, Request::Status, 1, None),
            Err(ProtocolError::Forbidden)
        ));
    }
}

#[test]
fn errors_and_debug_redact_secret_payloads_and_ancillary_data_is_refused() {
    let value = request(Request::EnrollConversation {
        transaction: id(2),
        prompt: id(3),
        response: secret(b"synthetic-secret"),
    });
    assert!(!format!("{value:?}").contains("synthetic-secret"));
    assert!(
        !format!(
            "{:?}",
            request(Request::Verify {
                challenge: id(2),
                pin: pin()
            })
        )
        .contains("012345")
    );
    assert!(
        !format!("{:?}", PromptText::new("private worker text").unwrap())
            .contains("private worker text")
    );
    assert_eq!(reject_ancillary(false), Ok(()));
    assert_eq!(reject_ancillary(true), Err(ProtocolError::Ancillary));
    let response = ResponseEnvelope {
        connection: id(1),
        response: Response::Verification(VerificationOutcome::Granted),
    };
    assert_eq!(
        response.check_connection(id(2)),
        Err(ProtocolError::Binding)
    );
}

#[test]
fn every_wire_action_backend_combination_resolves_to_the_exact_core_action_or_refuses() {
    use localpin_core::enrollment::EnrollmentAction as CoreAction;
    use localpin_core::types::Backend as CoreBackend;
    let backends = [None, Some(Backend::Tpm), Some(Backend::Software)];
    // Columns enumerate (requested, current): (none, none/TPM/software),
    // (TPM, none/TPM/software), (software, none/TPM/software).
    let cases = [
        (
            EnrollmentAction::Enroll,
            [
                None,
                None,
                None,
                Some(CoreAction::Enroll(CoreBackend::Tpm2)),
                None,
                None,
                Some(CoreAction::Enroll(CoreBackend::Software)),
                None,
                None,
            ],
        ),
        (
            EnrollmentAction::Rotate,
            [
                None,
                None,
                None,
                None,
                Some(CoreAction::Rotate),
                None,
                None,
                None,
                Some(CoreAction::Rotate),
            ],
        ),
        (
            EnrollmentAction::Migrate,
            [
                None,
                None,
                None,
                None,
                None,
                Some(CoreAction::MigrateBackend(CoreBackend::Tpm2)),
                None,
                Some(CoreAction::MigrateBackend(CoreBackend::Software)),
                None,
            ],
        ),
        (
            EnrollmentAction::Disable,
            [
                None,
                Some(CoreAction::Disable),
                Some(CoreAction::Disable),
                None,
                None,
                None,
                None,
                None,
                None,
            ],
        ),
    ];
    for (action, expected) in cases {
        for (requested_index, requested) in backends.into_iter().enumerate() {
            for (current_index, current) in backends.into_iter().enumerate() {
                assert_eq!(
                    resolve_enrollment_action(action, requested, current),
                    expected[requested_index * 3 + current_index]
                        .ok_or(ProtocolError::InvalidField),
                    "action={action:?}, requested={requested:?}, current={current:?}",
                );
            }
        }
    }
}
