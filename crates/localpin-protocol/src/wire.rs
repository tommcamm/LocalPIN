//! Closed, explicitly versioned wire vocabulary.

use core::fmt;
use localpin_core::secret::{Pin, SecretBytes};
use zeroize::Zeroize;

/// Protocol version carried in every message body.
pub const VERSION: u8 = 1;
pub use localpin_core::limits::MAX_FRAME_BYTES;
/// Maximum body size accepted before reading or allocating its payload.
pub const MAX_BODY_BYTES: usize = MAX_FRAME_BYTES - 4;
/// Maximum bytes in one password-worker conversation response.
pub const MAX_CONVERSATION_BYTES: usize = 2048;
/// Maximum UTF-8 bytes in one worker prompt.
pub const MAX_PROMPT_BYTES: usize = 1024;
/// Verification challenge and genuine backend-operation deadline.
pub const VERIFY_LIFETIME_MS: u64 = 5_000;
/// Maximum password conversation and post-password commit interval.
pub const ENROLLMENT_LIFETIME_MS: u64 = 60_000;

/// Sanitized protocol/connection failure with no input bytes or secret context.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProtocolError {
    /// Frame exceeds the fixed limit.
    Oversized,
    /// Frame or field is incomplete.
    Truncated,
    /// Version is unsupported.
    Version,
    /// Message type, enum value or field is unknown.
    UnknownValue,
    /// Field encoding, length, identifier or PIN is invalid.
    InvalidField,
    /// Bytes remain after the last defined field.
    TrailingData,
    /// Message belongs to a different connection or transaction.
    Binding,
    /// Operation is not valid in the current state.
    OutOfOrder,
    /// Challenge, conversation or authorization has expired.
    Expired,
    /// Caller lacks the required peer identity or eligibility.
    Forbidden,
    /// Trusted monotonic time moved backward or overflowed.
    Clock,
    /// Ancillary capabilities were supplied.
    Ancillary,
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Oversized => "message exceeds the protocol limit",
            Self::Truncated => "incomplete protocol message",
            Self::Version => "unsupported protocol version",
            Self::UnknownValue => "unknown protocol value",
            Self::InvalidField => "invalid protocol field",
            Self::TrailingData => "unexpected protocol fields",
            Self::Binding => "message binding does not match",
            Self::OutOfOrder => "operation is not valid in this state",
            Self::Expired => "operation has expired",
            Self::Forbidden => "operation is not permitted",
            Self::Clock => "monotonic time is unavailable",
            Self::Ancillary => "ancillary capabilities are not permitted",
        })
    }
}

impl std::error::Error for ProtocolError {}

/// Opaque nonzero 128-bit identifier; fresh random values come from the broker.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Id([u8; 16]);

impl Id {
    /// Validate a nonzero identifier. This does not establish randomness.
    pub fn from_bytes(bytes: [u8; 16]) -> Result<Self, ProtocolError> {
        if bytes == [0; 16] {
            Err(ProtocolError::InvalidField)
        } else {
            Ok(Self(bytes))
        }
    }

    /// Obtain the identifier's wire representation.
    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

/// Explicit enrolled backend; software is always a deliberate choice.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Backend {
    /// TPM-protected credential.
    Tpm = 1,
    /// Explicit software credential.
    Software = 2,
}

/// Backend preference in nonsecret configuration status.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum BackendPreference {
    /// Prefer usable TPM, requiring software acceptance otherwise.
    Auto = 0,
    /// Require TPM.
    Tpm = 1,
    /// Explicit software acceptance.
    Software = 2,
}

/// Requested fresh-password-authorized account mutation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum EnrollmentAction {
    /// Enroll a new credential.
    Enroll = 1,
    /// Replace a PIN on its existing backend.
    Rotate = 2,
    /// Explicitly migrate credential backend.
    Migrate = 3,
    /// Disable the current credential.
    Disable = 4,
}

/// Sanitized availability reason, never a native library error or path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Reason {
    /// No failure reason.
    None = 0,
    /// Account restrictions.
    Account = 1,
    /// Session restrictions.
    Session = 2,
    /// Protected storage failure.
    Storage = 3,
    /// Credential backend unavailable.
    Backend = 4,
    /// Configuration or policy failure.
    Policy = 5,
    /// Bounded capacity is occupied.
    Busy = 6,
    /// Invalid client protocol.
    Protocol = 7,
}

/// Current nonsecret credential availability.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Availability {
    /// Verification can be attempted.
    Available = 0,
    /// No enrolled credential.
    NotEnrolled = 1,
    /// Credential disabled.
    Disabled = 2,
    /// Durable cooldown active.
    Cooldown = 3,
    /// Caller/account/session ineligible.
    Ineligible = 4,
    /// Required component unavailable.
    Unavailable = 5,
}

/// Integration activation status.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Integration {
    /// Integration inactive.
    Inactive = 0,
    /// Supported integration active.
    Active = 1,
    /// Integration requires repair.
    NeedsAttention = 2,
}

/// Nonsecret own-user status, suitable for separately versioned CLI JSON output.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Status {
    /// Configured preference, independent of hardware detection.
    pub configured: BackendPreference,
    /// Actual backend of the committed credential.
    pub enrolled: Option<Backend>,
    /// Current availability.
    pub availability: Availability,
    /// Remaining cooldown duration in milliseconds.
    pub cooldown_ms: u32,
    /// Desktop integration state.
    pub integration: Integration,
    /// A TPM device was detected.
    pub tpm_detected: bool,
    /// TPM backend passed its usability checks.
    pub tpm_usable: bool,
    /// Sanitized reason for unavailability.
    pub reason: Reason,
}

/// Request bound to one authenticated socket connection.
#[derive(Debug)]
pub struct RequestEnvelope {
    /// Fresh broker-issued connection identifier.
    pub connection: Id,
    /// Closed client request vocabulary.
    pub request: Request,
}

/// Client operations. There is deliberately no password-authenticated field.
#[derive(Debug)]
pub enum Request {
    /// Query the peer's own nonsecret status.
    Status,
    /// Ask for a short-lived verification challenge.
    BeginVerify,
    /// Submit one six-digit PIN to the issued challenge.
    Verify {
        /// Issued challenge identifier.
        challenge: Id,
        /// Secret PIN.
        pin: Pin,
    },
    /// Abandon this connection's active operation.
    Cancel,
    /// Start a fresh password conversation for an account mutation.
    BeginEnroll {
        /// Requested mutation.
        action: EnrollmentAction,
        /// Proposed backend; absent only for disable.
        backend: Option<Backend>,
    },
    /// Answer exactly one broker/worker prompt.
    EnrollConversation {
        /// Issued enrollment transaction.
        transaction: Id,
        /// Issued prompt identifier.
        prompt: Id,
        /// Secret conversation bytes, including non-UTF-8 passwords.
        response: SecretBytes,
    },
    /// Supply a new PIN after trusted password authentication.
    CommitEnrollment {
        /// Issued enrollment transaction.
        transaction: Id,
        /// Secret new PIN.
        pin: Pin,
    },
    /// Commit a previously password-authorized own-user disable.
    Disable {
        /// Issued enrollment transaction.
        transaction: Id,
    },
    /// Separate kernel-root-only credential disable/recovery operation.
    RecoverDisable {
        /// Non-root account to recover.
        target_uid: u32,
    },
}

/// Supported password-PAM conversation message styles.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum PromptStyle {
    /// Secret input.
    EchoOff = 1,
    /// Visible input.
    EchoOn = 2,
    /// Informational message; reply must be empty.
    Info = 3,
    /// Error message; reply must be empty.
    Error = 4,
}

/// Bounded UTF-8 worker prompt, redacted in diagnostics.
pub struct PromptText(String);

impl PromptText {
    /// Copy a bounded UTF-8 prompt.
    pub fn new(text: &str) -> Result<Self, ProtocolError> {
        if text.len() > MAX_PROMPT_BYTES || text.as_bytes().contains(&0) {
            return Err(ProtocolError::InvalidField);
        }
        Ok(Self(text.to_owned()))
    }

    /// Read prompt text for private transport/display only.
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for PromptText {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PromptText([REDACTED])")
    }
}

impl Drop for PromptText {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// Final verification result for this connection; never a reusable grant.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VerificationOutcome {
    /// Broker durably committed successful verification.
    Granted,
    /// Submitted PIN mismatched.
    Mismatch,
    /// Durable cooldown; remaining milliseconds.
    Cooldown(u32),
    /// Verification could not complete authoritatively.
    Unavailable(Reason),
}

/// Sanitized terminal wire error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ErrorCode {
    /// Request malformed or unsupported.
    Protocol = 1,
    /// Wrong order or binding.
    State = 2,
    /// Expired transaction.
    Expired = 3,
    /// Ineligible peer/account.
    Forbidden = 4,
    /// Worker rejected password authentication.
    PasswordRejected = 5,
    /// Required service unavailable.
    Unavailable = 6,
}

/// Mutation completion, conveying no reusable authorization.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Completion {
    /// New generation committed.
    Enrolled(Backend),
    /// Own-user credential disabled.
    Disabled,
    /// Administrator recovery committed.
    RecoveryDisabled,
}

/// Server response bound to the requesting socket connection.
#[derive(Debug)]
pub struct ResponseEnvelope {
    /// Connection identifier.
    pub connection: Id,
    /// Closed response vocabulary.
    pub response: Response,
}

impl ResponseEnvelope {
    /// Reject a response from a different authenticated connection.
    ///
    /// Clients must apply this after the initial authenticated server hello and
    /// consume final verification responses only for the active PAM operation.
    pub fn check_connection(&self, expected: Id) -> Result<(), ProtocolError> {
        if self.connection == expected {
            Ok(())
        } else {
            Err(ProtocolError::Binding)
        }
    }
}

/// Server-to-client messages.
#[derive(Debug)]
pub enum Response {
    /// Initial server message, delivering the fresh connection identifier.
    Hello,
    /// Nonsecret own-user status.
    Status(Status),
    /// Fresh verification challenge, valid for at most five seconds.
    VerifyChallenge {
        /// Challenge identifier.
        challenge: Id,
        /// Duration remaining in milliseconds.
        valid_for_ms: u32,
    },
    /// Fresh enrollment transaction.
    EnrollmentStarted {
        /// Transaction identifier.
        transaction: Id,
        /// Broker-selected proposed credential generation.
        generation: u64,
        /// Password conversation interval.
        valid_for_ms: u32,
    },
    /// Private password-worker conversation.
    ConversationPrompt {
        /// Transaction identifier.
        transaction: Id,
        /// One-use prompt identifier.
        prompt: Id,
        /// PAM conversation style.
        style: PromptStyle,
        /// Bounded prompt text.
        text: PromptText,
    },
    /// Worker authenticated; commit remains bound to this connection and state.
    EnrollmentReady {
        /// Transaction identifier.
        transaction: Id,
        /// Remaining commit interval, at most sixty seconds.
        valid_for_ms: u32,
    },
    /// Terminal verification result for the requesting PAM operation.
    Verification(VerificationOutcome),
    /// Terminal mutation completion.
    Completed(Completion),
    /// Operation cancelled; reserved attempts remain consumed.
    Cancelled,
    /// Sanitized terminal error.
    Error(ErrorCode),
}

/// Reject received file descriptors/ancillary data before processing a message.
///
/// The socket adapter must pass whether *any* ancillary data or truncation was
/// observed, including unrecognized control messages. It must close received
/// descriptors itself; this pure function does not own OS resources.
pub fn reject_ancillary(present_or_truncated: bool) -> Result<(), ProtocolError> {
    if present_or_truncated {
        Err(ProtocolError::Ancillary)
    } else {
        Ok(())
    }
}
