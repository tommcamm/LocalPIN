use crate::wire::*;
use localpin_core::secret::{MAX_CREDENTIAL_BYTES, Pin, SecretBytes};
use zeroize::Zeroize;

const HEADER_BYTES: usize = 18;

/// Fixed-capacity encoded frame; its contents are erased when dropped.
///
/// Deliberately implements neither `Debug` nor `Clone`: frames can contain PINs
/// and arbitrary password bytes. Transmit through authenticated private IPC.
pub struct EncodedFrame {
    bytes: [u8; MAX_FRAME_BYTES],
    len: usize,
}

impl EncodedFrame {
    fn new(connection: Id, operation: u8) -> Self {
        let mut frame = Self {
            bytes: [0; MAX_FRAME_BYTES],
            len: 4,
        };
        // All three writes fit by construction.
        frame.bytes[4] = VERSION;
        frame.bytes[5] = operation;
        frame.bytes[6..22].copy_from_slice(connection.as_bytes());
        frame.len = 22;
        frame
    }

    /// Read bytes for transmission, including the four-byte length prefix.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }

    fn put(&mut self, bytes: &[u8]) -> Result<(), ProtocolError> {
        let end = self
            .len
            .checked_add(bytes.len())
            .ok_or(ProtocolError::Oversized)?;
        if end > MAX_FRAME_BYTES {
            return Err(ProtocolError::Oversized);
        }
        self.bytes[self.len..end].copy_from_slice(bytes);
        self.len = end;
        Ok(())
    }

    fn byte(&mut self, byte: u8) -> Result<(), ProtocolError> {
        self.put(&[byte])
    }
    fn id(&mut self, id: Id) -> Result<(), ProtocolError> {
        self.put(id.as_bytes())
    }
    fn u32(&mut self, value: u32) -> Result<(), ProtocolError> {
        self.put(&value.to_be_bytes())
    }
    fn u64(&mut self, value: u64) -> Result<(), ProtocolError> {
        self.put(&value.to_be_bytes())
    }

    fn blob(&mut self, value: &[u8], max: usize) -> Result<(), ProtocolError> {
        if value.len() > max {
            return Err(ProtocolError::InvalidField);
        }
        let len = u16::try_from(value.len()).map_err(|_| ProtocolError::InvalidField)?;
        self.put(&len.to_be_bytes())?;
        self.put(value)
    }

    fn finish(mut self) -> Result<Self, ProtocolError> {
        let body_len = u32::try_from(self.len - 4).map_err(|_| ProtocolError::Oversized)?;
        self.bytes[..4].copy_from_slice(&body_len.to_be_bytes());
        Ok(self)
    }
}

impl Drop for EncodedFrame {
    fn drop(&mut self) {
        self.bytes.zeroize();
        self.len.zeroize();
    }
}

/// Encode one request without a heap allocation for the frame buffer.
pub fn encode_request(envelope: &RequestEnvelope) -> Result<EncodedFrame, ProtocolError> {
    let operation = match envelope.request {
        Request::Status => 1,
        Request::BeginVerify => 2,
        Request::Verify { .. } => 3,
        Request::Cancel => 4,
        Request::BeginEnroll { .. } => 5,
        Request::EnrollConversation { .. } => 6,
        Request::CommitEnrollment { .. } => 7,
        Request::Disable { .. } => 8,
        Request::RecoverDisable { .. } => 9,
    };
    let mut f = EncodedFrame::new(envelope.connection, operation);
    match &envelope.request {
        Request::Status | Request::BeginVerify | Request::Cancel => {}
        Request::Verify { challenge, pin } => {
            f.id(*challenge)?;
            f.blob(pin.expose(), MAX_CREDENTIAL_BYTES)?;
        }
        Request::BeginEnroll {
            action,
            backend,
            kind,
        } => {
            validate_enrollment_kind(*action, *backend, *kind)?;
            f.byte(*action as u8)?;
            f.byte(backend.map_or(0, |backend| backend as u8))?;
            f.byte(kind.map_or(0, encode_kind))?;
        }
        Request::EnrollConversation {
            transaction,
            prompt,
            response,
        } => {
            f.id(*transaction)?;
            f.id(*prompt)?;
            f.blob(response.expose(), MAX_CONVERSATION_BYTES)?;
        }
        Request::CommitEnrollment { transaction, pin } => {
            f.id(*transaction)?;
            f.blob(pin.expose(), MAX_CREDENTIAL_BYTES)?;
        }
        Request::Disable { transaction } => f.id(*transaction)?,
        Request::RecoverDisable { target_uid } => {
            if *target_uid == 0 || *target_uid == u32::MAX {
                return Err(ProtocolError::InvalidField);
            }
            f.u32(*target_uid)?;
        }
    }
    f.finish()
}

/// Encode a bounded response using the same fixed complete-frame limit.
pub fn encode_response(envelope: &ResponseEnvelope) -> Result<EncodedFrame, ProtocolError> {
    let operation = match envelope.response {
        Response::Hello => 0x80,
        Response::Status(_) => 0x81,
        Response::VerifyChallenge { .. } => 0x82,
        Response::EnrollmentStarted { .. } => 0x83,
        Response::ConversationPrompt { .. } => 0x84,
        Response::EnrollmentReady { .. } => 0x85,
        Response::Verification(_) => 0x86,
        Response::Completed(_) => 0x87,
        Response::Cancelled => 0x88,
        Response::Error(_) => 0x89,
    };
    let mut f = EncodedFrame::new(envelope.connection, operation);
    match &envelope.response {
        Response::Hello => {}
        Response::Status(s) => {
            f.byte(s.configured as u8)?;
            validate_status_profile(s.enrolled, s.profile, s.availability)?;
            f.byte(s.enrolled.map_or(0, |backend| backend as u8))?;
            match s.profile {
                Some(profile) => {
                    f.byte(1)?;
                    put_profile(&mut f, profile)?;
                }
                None => f.byte(0)?,
            }
            f.byte(s.availability as u8)?;
            f.u32(s.cooldown_ms)?;
            f.byte(s.integration as u8)?;
            f.byte(u8::from(s.tpm_detected))?;
            f.byte(u8::from(s.tpm_usable))?;
            f.byte(s.reason as u8)?;
        }
        Response::VerifyChallenge {
            challenge,
            generation,
            backend,
            profile,
            valid_for_ms,
        } => {
            validate_interval(*valid_for_ms, VERIFY_LIFETIME_MS)?;
            if *generation == 0 {
                return Err(ProtocolError::InvalidField);
            }
            validate_profile(*profile, *backend)?;
            f.id(*challenge)?;
            f.u64(*generation)?;
            f.byte(*backend as u8)?;
            put_profile(&mut f, *profile)?;
            f.u32(*valid_for_ms)?;
        }
        Response::EnrollmentStarted {
            transaction,
            generation,
            valid_for_ms,
        } => {
            validate_interval(*valid_for_ms, ENROLLMENT_LIFETIME_MS)?;
            if *generation == 0 {
                return Err(ProtocolError::InvalidField);
            }
            f.id(*transaction)?;
            f.u64(*generation)?;
            f.u32(*valid_for_ms)?;
        }
        Response::ConversationPrompt {
            transaction,
            prompt,
            style,
            text,
        } => {
            f.id(*transaction)?;
            f.id(*prompt)?;
            f.byte(*style as u8)?;
            f.blob(text.expose().as_bytes(), MAX_PROMPT_BYTES)?;
        }
        Response::EnrollmentReady {
            transaction,
            valid_for_ms,
        } => {
            validate_interval(*valid_for_ms, ENROLLMENT_LIFETIME_MS)?;
            f.id(*transaction)?;
            f.u32(*valid_for_ms)?;
        }
        Response::Verification(result) => match result {
            VerificationOutcome::Granted => f.byte(1)?,
            VerificationOutcome::Mismatch => f.byte(2)?,
            VerificationOutcome::Cooldown(ms) => {
                f.byte(3)?;
                f.u32(*ms)?;
            }
            VerificationOutcome::Unavailable(reason) => {
                f.byte(4)?;
                f.byte(*reason as u8)?;
            }
        },
        Response::Completed(completion) => match completion {
            Completion::Enrolled(backend) => {
                f.byte(1)?;
                f.byte(*backend as u8)?;
            }
            Completion::Disabled => f.byte(2)?,
            Completion::RecoveryDisabled => f.byte(3)?,
        },
        Response::Cancelled => {}
        Response::Error(error) => f.byte(*error as u8)?,
    }
    f.finish()
}

pub(crate) fn validate_enroll(
    action: EnrollmentAction,
    backend: Option<Backend>,
) -> Result<(), ProtocolError> {
    if (action == EnrollmentAction::Disable) == backend.is_none() {
        Ok(())
    } else {
        Err(ProtocolError::InvalidField)
    }
}

pub(crate) fn validate_enrollment_kind(
    action: EnrollmentAction,
    backend: Option<Backend>,
    kind: Option<CredentialKind>,
) -> Result<(), ProtocolError> {
    validate_enroll(action, backend)?;
    if (action == EnrollmentAction::Disable) == kind.is_none() {
        Ok(())
    } else {
        Err(ProtocolError::InvalidField)
    }
}

pub(crate) fn validate_profile(
    profile: CredentialProfile,
    backend: Backend,
) -> Result<(), ProtocolError> {
    profile
        .validate(match backend {
            Backend::Tpm => localpin_core::types::Backend::Tpm2,
            Backend::Software => localpin_core::types::Backend::Software,
        })
        .map_err(|_| ProtocolError::InvalidField)
}

fn validate_status_profile(
    backend: Option<Backend>,
    profile: Option<CredentialProfile>,
    availability: Availability,
) -> Result<(), ProtocolError> {
    match (backend, profile) {
        (Some(backend), Some(profile)) => validate_profile(profile, backend),
        (None, None) => Ok(()),
        (Some(_), None) if availability == Availability::Unavailable => Ok(()),
        _ => Err(ProtocolError::InvalidField),
    }
}

fn encode_kind(kind: CredentialKind) -> u8 {
    match kind {
        CredentialKind::NumericPin => 1,
        CredentialKind::Passcode => 2,
    }
}

fn put_profile(f: &mut EncodedFrame, profile: CredentialProfile) -> Result<(), ProtocolError> {
    f.byte(profile.policy)?;
    f.byte(encode_kind(profile.kind))?;
    f.byte(profile.length)
}

fn validate_interval(value: u32, max: u64) -> Result<(), ProtocolError> {
    if value == 0 || u64::from(value) > max {
        Err(ProtocolError::InvalidField)
    } else {
        Ok(())
    }
}

struct Reader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, len: usize) -> Result<&'a [u8], ProtocolError> {
        let end = self.pos.checked_add(len).ok_or(ProtocolError::Truncated)?;
        let value = self
            .bytes
            .get(self.pos..end)
            .ok_or(ProtocolError::Truncated)?;
        self.pos = end;
        Ok(value)
    }
    fn byte(&mut self) -> Result<u8, ProtocolError> {
        Ok(self.take(1)?[0])
    }
    fn id(&mut self) -> Result<Id, ProtocolError> {
        let mut bytes = [0; 16];
        bytes.copy_from_slice(self.take(16)?);
        Id::from_bytes(bytes)
    }
    fn u16(&mut self) -> Result<u16, ProtocolError> {
        let mut bytes = [0; 2];
        bytes.copy_from_slice(self.take(2)?);
        Ok(u16::from_be_bytes(bytes))
    }
    fn u32(&mut self) -> Result<u32, ProtocolError> {
        let mut bytes = [0; 4];
        bytes.copy_from_slice(self.take(4)?);
        Ok(u32::from_be_bytes(bytes))
    }
    fn u64(&mut self) -> Result<u64, ProtocolError> {
        let mut bytes = [0; 8];
        bytes.copy_from_slice(self.take(8)?);
        Ok(u64::from_be_bytes(bytes))
    }
    fn blob(&mut self, max: usize) -> Result<&'a [u8], ProtocolError> {
        let len = usize::from(self.u16()?);
        if len > max {
            return Err(ProtocolError::InvalidField);
        }
        self.take(len)
    }
    fn boolean(&mut self) -> Result<bool, ProtocolError> {
        match self.byte()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(ProtocolError::UnknownValue),
        }
    }
    fn done(self) -> Result<(), ProtocolError> {
        if self.pos == self.bytes.len() {
            Ok(())
        } else {
            Err(ProtocolError::TrailingData)
        }
    }
}

macro_rules! read_enum {
    ($reader:expr, $($value:literal => $variant:path),+ $(,)?) => {
        match $reader.byte()? { $($value => $variant,)+ _ => return Err(ProtocolError::UnknownValue) }
    }
}

fn backend(r: &mut Reader<'_>) -> Result<Option<Backend>, ProtocolError> {
    match r.byte()? {
        0 => Ok(None),
        1 => Ok(Some(Backend::Tpm)),
        2 => Ok(Some(Backend::Software)),
        _ => Err(ProtocolError::UnknownValue),
    }
}

fn kind(r: &mut Reader<'_>) -> Result<Option<CredentialKind>, ProtocolError> {
    match r.byte()? {
        0 => Ok(None),
        1 => Ok(Some(CredentialKind::NumericPin)),
        2 => Ok(Some(CredentialKind::Passcode)),
        _ => Err(ProtocolError::UnknownValue),
    }
}

fn profile(r: &mut Reader<'_>) -> Result<CredentialProfile, ProtocolError> {
    Ok(CredentialProfile {
        policy: r.byte()?,
        kind: kind(r)?.ok_or(ProtocolError::InvalidField)?,
        length: r.byte()?,
    })
}

fn reason(r: &mut Reader<'_>) -> Result<Reason, ProtocolError> {
    Ok(
        read_enum!(r, 0 => Reason::None, 1 => Reason::Account, 2 => Reason::Session,
        3 => Reason::Storage, 4 => Reason::Backend, 5 => Reason::Policy, 6 => Reason::Busy,
        7 => Reason::Protocol, 8 => Reason::AccountUnsupported,
        9 => Reason::LifecycleUnavailable, 10 => Reason::EligibilityUnavailable),
    )
}

fn header(body: &[u8]) -> Result<(Reader<'_>, Id, u8), ProtocolError> {
    let mut r = Reader {
        bytes: body,
        pos: 0,
    };
    if r.byte()? != VERSION {
        return Err(ProtocolError::Version);
    }
    let operation = r.byte()?;
    let connection = r.id()?;
    Ok((r, connection, operation))
}

fn decode_request(body: &[u8]) -> Result<RequestEnvelope, ProtocolError> {
    let (mut r, connection, operation) = header(body)?;
    let request = match operation {
        1 => Request::Status,
        2 => Request::BeginVerify,
        3 => Request::Verify {
            challenge: r.id()?,
            pin: Pin::parse(r.blob(MAX_CREDENTIAL_BYTES)?)
                .map_err(|_| ProtocolError::InvalidField)?,
        },
        4 => Request::Cancel,
        5 => {
            let action = read_enum!(r, 1 => EnrollmentAction::Enroll, 2 => EnrollmentAction::Rotate,
                3 => EnrollmentAction::Migrate, 4 => EnrollmentAction::Disable);
            let backend = backend(&mut r)?;
            let kind = kind(&mut r)?;
            validate_enrollment_kind(action, backend, kind)?;
            Request::BeginEnroll {
                action,
                backend,
                kind,
            }
        }
        6 => Request::EnrollConversation {
            transaction: r.id()?,
            prompt: r.id()?,
            response: SecretBytes::from_slice(
                r.blob(MAX_CONVERSATION_BYTES)?,
                MAX_CONVERSATION_BYTES,
            )
            .map_err(|_| ProtocolError::InvalidField)?,
        },
        7 => Request::CommitEnrollment {
            transaction: r.id()?,
            pin: Pin::parse(r.blob(MAX_CREDENTIAL_BYTES)?)
                .map_err(|_| ProtocolError::InvalidField)?,
        },
        8 => Request::Disable {
            transaction: r.id()?,
        },
        9 => {
            let target_uid = r.u32()?;
            if target_uid == 0 || target_uid == u32::MAX {
                return Err(ProtocolError::InvalidField);
            }
            Request::RecoverDisable { target_uid }
        }
        _ => return Err(ProtocolError::UnknownValue),
    };
    r.done()?;
    Ok(RequestEnvelope {
        connection,
        request,
    })
}

fn decode_response(body: &[u8]) -> Result<ResponseEnvelope, ProtocolError> {
    let (mut r, connection, operation) = header(body)?;
    let response = match operation {
        0x80 => Response::Hello,
        0x81 => {
            let configured = read_enum!(r, 0 => BackendPreference::Auto, 1 => BackendPreference::Tpm,
                2 => BackendPreference::Software);
            let enrolled = backend(&mut r)?;
            let profile = match r.byte()? {
                0 => None,
                1 => Some(profile(&mut r)?),
                _ => return Err(ProtocolError::UnknownValue),
            };
            let availability = read_enum!(r, 0 => Availability::Available, 1 => Availability::NotEnrolled,
                2 => Availability::Disabled, 3 => Availability::Cooldown, 4 => Availability::Ineligible,
                5 => Availability::Unavailable);
            validate_status_profile(enrolled, profile, availability)?;
            Response::Status(Status {
                configured,
                enrolled,
                profile,
                availability,
                cooldown_ms: r.u32()?,
                integration: read_enum!(r, 0 => Integration::Inactive, 1 => Integration::Active,
                2 => Integration::NeedsAttention),
                tpm_detected: r.boolean()?,
                tpm_usable: r.boolean()?,
                reason: reason(&mut r)?,
            })
        }
        0x82 => {
            let challenge = r.id()?;
            let generation = r.u64()?;
            let backend = backend(&mut r)?.ok_or(ProtocolError::InvalidField)?;
            let profile = profile(&mut r)?;
            if generation == 0 {
                return Err(ProtocolError::InvalidField);
            }
            validate_profile(profile, backend)?;
            let valid_for_ms = r.u32()?;
            validate_interval(valid_for_ms, VERIFY_LIFETIME_MS)?;
            Response::VerifyChallenge {
                challenge,
                generation,
                backend,
                profile,
                valid_for_ms,
            }
        }
        0x83 => {
            let transaction = r.id()?;
            let generation = r.u64()?;
            let valid_for_ms = r.u32()?;
            if generation == 0 {
                return Err(ProtocolError::InvalidField);
            }
            validate_interval(valid_for_ms, ENROLLMENT_LIFETIME_MS)?;
            Response::EnrollmentStarted {
                transaction,
                generation,
                valid_for_ms,
            }
        }
        0x84 => {
            let transaction = r.id()?;
            let prompt = r.id()?;
            let style = read_enum!(r, 1 => PromptStyle::EchoOff, 2 => PromptStyle::EchoOn,
                3 => PromptStyle::Info, 4 => PromptStyle::Error);
            let text = core::str::from_utf8(r.blob(MAX_PROMPT_BYTES)?)
                .map_err(|_| ProtocolError::InvalidField)?;
            Response::ConversationPrompt {
                transaction,
                prompt,
                style,
                text: PromptText::new(text)?,
            }
        }
        0x85 => {
            let transaction = r.id()?;
            let valid_for_ms = r.u32()?;
            validate_interval(valid_for_ms, ENROLLMENT_LIFETIME_MS)?;
            Response::EnrollmentReady {
                transaction,
                valid_for_ms,
            }
        }
        0x86 => Response::Verification(match r.byte()? {
            1 => VerificationOutcome::Granted,
            2 => VerificationOutcome::Mismatch,
            3 => VerificationOutcome::Cooldown(r.u32()?),
            4 => VerificationOutcome::Unavailable(reason(&mut r)?),
            _ => return Err(ProtocolError::UnknownValue),
        }),
        0x87 => Response::Completed(match r.byte()? {
            1 => Completion::Enrolled(backend(&mut r)?.ok_or(ProtocolError::InvalidField)?),
            2 => Completion::Disabled,
            3 => Completion::RecoveryDisabled,
            _ => return Err(ProtocolError::UnknownValue),
        }),
        0x88 => Response::Cancelled,
        0x89 => Response::Error(
            read_enum!(r, 1 => ErrorCode::Protocol, 2 => ErrorCode::State,
            3 => ErrorCode::Expired, 4 => ErrorCode::Forbidden, 5 => ErrorCode::PasswordRejected,
            6 => ErrorCode::Unavailable),
        ),
        _ => return Err(ProtocolError::UnknownValue),
    };
    r.done()?;
    Ok(ResponseEnvelope {
        connection,
        response,
    })
}

struct FrameDecoder {
    bytes: [u8; MAX_FRAME_BYTES],
    used: usize,
    expected: Option<usize>,
    poisoned: bool,
}

impl Default for FrameDecoder {
    fn default() -> Self {
        Self {
            bytes: [0; MAX_FRAME_BYTES],
            used: 0,
            expected: None,
            poisoned: false,
        }
    }
}

impl FrameDecoder {
    fn push(&mut self, input: &[u8]) -> Result<(usize, bool), ProtocolError> {
        if self.poisoned {
            return Err(ProtocolError::OutOfOrder);
        }
        let mut consumed = 0;
        if self.used < 4 {
            let count = (4 - self.used).min(input.len());
            self.bytes[self.used..self.used + count].copy_from_slice(&input[..count]);
            self.used += count;
            consumed += count;
            if self.used != 4 {
                return Ok((consumed, false));
            }
            let mut prefix = [0; 4];
            prefix.copy_from_slice(&self.bytes[..4]);
            let body = u32::from_be_bytes(prefix) as usize;
            // Reject the untrusted claim before reading any payload.
            if body > MAX_BODY_BYTES {
                self.poison();
                return Err(ProtocolError::Oversized);
            }
            if body < HEADER_BYTES {
                self.poison();
                return Err(ProtocolError::Truncated);
            }
            self.expected = Some(body + 4);
        }
        let expected = self.expected.ok_or(ProtocolError::OutOfOrder)?;
        let count = (expected - self.used).min(input.len() - consumed);
        self.bytes[self.used..self.used + count]
            .copy_from_slice(&input[consumed..consumed + count]);
        self.used += count;
        consumed += count;
        Ok((consumed, self.used == expected))
    }

    fn clear(&mut self) {
        self.bytes.zeroize();
        self.used = 0;
        self.expected = None;
    }
    fn poison(&mut self) {
        self.clear();
        self.poisoned = true;
    }
    fn finish(&mut self) -> Result<(), ProtocolError> {
        if self.poisoned {
            return Err(ProtocolError::OutOfOrder);
        }
        if self.used != 0 {
            self.poison();
            return Err(ProtocolError::Truncated);
        }
        Ok(())
    }
}

impl Drop for FrameDecoder {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

/// Incremental request parser with a fixed 4-KiB zeroizing buffer.
#[derive(Default)]
pub struct RequestDecoder {
    frame: FrameDecoder,
}

impl RequestDecoder {
    /// Consume up to one frame, returning bytes consumed and an optional request.
    ///
    /// Any error permanently poisons this decoder: close the socket. When a
    /// complete frame is returned, feed any unconsumed bytes in a new call.
    pub fn push(
        &mut self,
        input: &[u8],
    ) -> Result<(usize, Option<RequestEnvelope>), ProtocolError> {
        let (consumed, complete) = self.frame.push(input)?;
        if !complete {
            return Ok((consumed, None));
        }
        let result = decode_request(&self.frame.bytes[4..self.frame.used]);
        self.frame.clear();
        match result {
            Ok(request) => Ok((consumed, Some(request))),
            Err(error) => {
                self.frame.poison();
                Err(error)
            }
        }
    }

    /// Mark EOF; a partially received frame fails closed and erases its bytes.
    pub fn finish(&mut self) -> Result<(), ProtocolError> {
        self.frame.finish()
    }
}

/// Incremental server-response parser; never use it on client request traffic.
#[derive(Default)]
pub struct ResponseDecoder {
    frame: FrameDecoder,
}

impl ResponseDecoder {
    /// Consume up to one response; errors poison the decoder and require close.
    pub fn push(
        &mut self,
        input: &[u8],
    ) -> Result<(usize, Option<ResponseEnvelope>), ProtocolError> {
        let (consumed, complete) = self.frame.push(input)?;
        if !complete {
            return Ok((consumed, None));
        }
        let result = decode_response(&self.frame.bytes[4..self.frame.used]);
        self.frame.clear();
        match result {
            Ok(response) => Ok((consumed, Some(response))),
            Err(error) => {
                self.frame.poison();
                Err(error)
            }
        }
    }

    /// Mark EOF, rejecting and erasing any incomplete response.
    pub fn finish(&mut self) -> Result<(), ProtocolError> {
        self.frame.finish()
    }
}
