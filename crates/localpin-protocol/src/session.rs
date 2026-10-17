use crate::codec::validate_enroll;
use crate::wire::*;
use localpin_core::secret::{Pin, SecretBytes};

/// Trusted session resolver outcome; never decoded from a client message.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Eligibility {
    /// Account and local graphical session currently satisfy broker policy.
    Eligible,
    /// Account or session failed policy or could not be established.
    Denied,
}

/// Resolve a wire mutation against the trusted committed backend before starting.
///
/// `current_backend` must come from protected committed core state, never client
/// data. The broker must call this before issuing enrollment IDs/starting the
/// password worker and pass the resulting action to core's `begin_own_user`.
/// Core still checks account continuity, authority, generation and state. This
/// conversion neither grants authorization nor probes/selects another backend.
pub fn resolve_enrollment_action(
    action: EnrollmentAction,
    requested_backend: Option<Backend>,
    current_backend: Option<Backend>,
) -> Result<localpin_core::enrollment::EnrollmentAction, ProtocolError> {
    use localpin_core::enrollment::EnrollmentAction as CoreAction;
    validate_enroll(action, requested_backend)?;
    let core_backend = |backend| match backend {
        Backend::Tpm => localpin_core::types::Backend::Tpm2,
        Backend::Software => localpin_core::types::Backend::Software,
    };
    match (action, requested_backend, current_backend) {
        (EnrollmentAction::Enroll, Some(requested), None) => {
            Ok(CoreAction::Enroll(core_backend(requested)))
        }
        (EnrollmentAction::Rotate, Some(requested), Some(current)) if requested == current => {
            Ok(CoreAction::Rotate)
        }
        (EnrollmentAction::Migrate, Some(requested), Some(current)) if requested != current => {
            Ok(CoreAction::MigrateBackend(core_backend(requested)))
        }
        (EnrollmentAction::Disable, None, Some(_)) => Ok(CoreAction::Disable),
        _ => Err(ProtocolError::InvalidField),
    }
}

/// Fresh identifiers supplied by the broker's OS-randomness/generation services.
///
/// Values must be fresh across connections and transactions. This pure crate
/// validates nonzero values, but cannot prove randomness or durable uniqueness.
/// Issue enrollment IDs only after core accepts the same action/backend and
/// proposed generation. In particular, rotate must match the committed backend.
/// Use [`resolve_enrollment_action`] before beginning that core transaction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Issued {
    /// Newly generated verification challenge.
    Verify(Id),
    /// New enrollment transaction and broker-selected proposed generation.
    Enrollment {
        /// Fresh random transaction identifier.
        transaction: Id,
        /// Nonzero proposed generation from protected policy.
        generation: u64,
    },
}

/// Immutable password-worker authorization context, created only by the broker.
///
/// Send this over the private worker channel and compare it on completion. No
/// client request can construct or serialize a password-success result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PasswordContext {
    connection: Id,
    transaction: Id,
    uid: u32,
    action: EnrollmentAction,
    generation: u64,
}

impl PasswordContext {
    /// Originating socket connection.
    pub fn connection(&self) -> Id {
        self.connection
    }
    /// Unique password/enrollment transaction.
    pub fn transaction(&self) -> Id {
        self.transaction
    }
    /// Kernel-authenticated non-root account UID.
    pub fn uid(&self) -> u32 {
        self.uid
    }
    /// Authorized mutation, which cannot change after password verification.
    pub fn action(&self) -> EnrollmentAction {
        self.action
    }
    /// Broker-selected proposed generation, also for disable's revocation fence.
    pub fn generation(&self) -> u64 {
        self.generation
    }
}

/// Broker work produced by a valid client transition.
#[derive(Debug)]
pub enum ConnectionAction {
    /// Read only the kernel peer's own nonsecret status.
    ReadStatus {
        /// Own non-root peer UID.
        uid: u32,
    },
    /// Transmit this bound nonsecret control response.
    Reply(ResponseEnvelope),
    /// Reserve durably, invoke a bounded backend and durably complete the result.
    Verify {
        /// Own non-root peer UID.
        uid: u32,
        /// Challenge bound to this connection.
        challenge: Id,
        /// Secret candidate, dropped/erased on cancellation.
        pin: Pin,
    },
    /// Start a private password-only worker and send the enrollment response.
    StartPassword {
        /// Broker-owned password-worker context.
        context: PasswordContext,
        /// Proposed explicit backend.
        backend: Option<Backend>,
        /// Initial enrollment response.
        reply: ResponseEnvelope,
    },
    /// Relay one response over the private password-worker channel.
    AnswerPassword {
        /// Unchanged worker context.
        context: PasswordContext,
        /// Secret arbitrary-byte response.
        response: SecretBytes,
    },
    /// Create and validate a staged credential, then commit through core policy.
    CommitEnrollment {
        /// Password-authorized context.
        context: PasswordContext,
        /// Explicit selected backend.
        backend: Backend,
        /// New secret PIN.
        pin: Pin,
    },
    /// Commit own-user disable through protected revocation policy.
    Disable {
        /// Password-authorized context.
        context: PasswordContext,
    },
    /// Commit distinct administrator recovery through protected revocation policy.
    RecoverDisable {
        /// Explicit non-root recovery target.
        target_uid: u32,
    },
    /// Cancel workers/release resources; already reserved guesses stay consumed.
    Cancel,
}

#[derive(Clone, Copy, Debug)]
struct Enrollment {
    context: PasswordContext,
    backend: Option<Backend>,
    expires: u64,
}

#[derive(Clone, Copy, Debug)]
enum State {
    Idle,
    Challenge {
        id: Id,
        expires: u64,
    },
    Verifying {
        expires: u64,
    },
    Password(Enrollment),
    Prompt {
        enrollment: Enrollment,
        id: Id,
        style: PromptStyle,
    },
    Authorized(Enrollment),
    Mutating(Enrollment),
    Recovering {
        expires: u64,
    },
    Finished,
}

/// One authenticated socket's single-use operation state machine.
///
/// Construction requires a fresh random connection ID and kernel-supplied UID.
/// Never use a UID from client data. The caller owns worker cleanup and socket
/// read/write deadlines. Any protocol error terminates this connection state.
/// Status may repeat while idle; an authorizing operation ends the connection.
/// Connections are ephemeral process/socket state and must never be persisted
/// or restored across broker restart or reboot. All supplied times must belong
/// to the clock/boot used at construction; reboot destroys the connection.
#[derive(Debug)]
pub struct Connection {
    id: Id,
    peer_uid: u32,
    last_now: u64,
    state: State,
    // Prompt identifiers are one-use even when the worker asks the same question
    // repeatedly. A bounded count also bounds per-connection conversation work.
    prompts: [Option<Id>; MAX_PASSWORD_PROMPTS],
    prompt_count: usize,
}

/// Maximum sequential password-PAM conversation messages in one transaction.
pub const MAX_PASSWORD_PROMPTS: usize = 16;

impl Connection {
    /// Bind fresh server randomness to an authenticated kernel peer UID.
    ///
    /// Root may use only administrator recovery; normal operations require a
    /// non-root peer. Time is milliseconds on one trusted monotonic clock.
    pub fn new(id: Id, kernel_peer_uid: u32, now: u64) -> Self {
        Self {
            id,
            peer_uid: kernel_peer_uid,
            last_now: now,
            state: State::Idle,
            prompts: [None; MAX_PASSWORD_PROMPTS],
            prompt_count: 0,
        }
    }

    /// This socket's broker-issued ID, sent to its authenticated peer on setup.
    pub fn id(&self) -> Id {
        self.id
    }

    /// Initial server hello, sent before accepting any request bytes.
    ///
    /// The client must authenticate the privileged server/socket before reading
    /// this identifier or transmitting any secret, and bind later responses to it.
    pub fn hello(&self) -> ResponseEnvelope {
        self.reply(Response::Hello)
    }

    /// Whether the socket must now close and discard further requests.
    pub fn is_finished(&self) -> bool {
        matches!(self.state, State::Finished)
    }

    /// Terminate on disconnect and cancel outstanding worker work.
    ///
    /// This erases no durable reservation: the caller retains consumed attempts.
    pub fn close(&mut self) {
        self.state = State::Finished;
    }

    /// Validate a request and produce bounded broker work.
    ///
    /// `eligibility` is a fresh trusted resolver outcome at each mutation or
    /// verification submission. `issued` is required only for Begin messages;
    /// never accept fresh IDs or generations supplied by the client itself.
    pub fn accept(
        &mut self,
        envelope: RequestEnvelope,
        now: u64,
        eligibility: Eligibility,
        issued: Option<Issued>,
    ) -> Result<ConnectionAction, ProtocolError> {
        let result = self.accept_inner(envelope, now, eligibility, issued);
        if result.is_err() {
            self.state = State::Finished;
        }
        result
    }

    fn accept_inner(
        &mut self,
        envelope: RequestEnvelope,
        now: u64,
        eligibility: Eligibility,
        issued: Option<Issued>,
    ) -> Result<ConnectionAction, ProtocolError> {
        self.check_time(now)?;
        if envelope.connection != self.id {
            return Err(ProtocolError::Binding);
        }
        if matches!(self.state, State::Finished) {
            return Err(ProtocolError::OutOfOrder);
        }
        if !matches!(
            envelope.request,
            Request::BeginVerify | Request::BeginEnroll { .. }
        ) && issued.is_some()
        {
            return Err(ProtocolError::InvalidField);
        }
        if matches!(envelope.request, Request::Cancel) {
            if matches!(self.state, State::Idle) {
                return Err(ProtocolError::OutOfOrder);
            }
            self.state = State::Finished;
            return Ok(ConnectionAction::Cancel);
        }
        if let Request::RecoverDisable { target_uid } = envelope.request {
            if self.peer_uid != 0 || target_uid == 0 || target_uid == u32::MAX {
                return Err(ProtocolError::Forbidden);
            }
            if !matches!(self.state, State::Idle) {
                return Err(ProtocolError::OutOfOrder);
            }
            self.state = State::Recovering {
                expires: deadline(now, VERIFY_LIFETIME_MS)?,
            };
            return Ok(ConnectionAction::RecoverDisable { target_uid });
        }
        if self.peer_uid == 0 || self.peer_uid == u32::MAX {
            return Err(ProtocolError::Forbidden);
        }
        match (self.state, envelope.request) {
            (State::Idle, Request::Status) => {
                Ok(ConnectionAction::ReadStatus { uid: self.peer_uid })
            }
            (State::Idle, Request::BeginVerify) => {
                require_eligible(eligibility)?;
                let Some(Issued::Verify(challenge)) = issued else {
                    return Err(ProtocolError::InvalidField);
                };
                if challenge == self.id {
                    return Err(ProtocolError::Binding);
                }
                self.state = State::Challenge {
                    id: challenge,
                    expires: deadline(now, VERIFY_LIFETIME_MS)?,
                };
                Ok(ConnectionAction::Reply(self.reply(
                    Response::VerifyChallenge {
                        challenge,
                        valid_for_ms: VERIFY_LIFETIME_MS as u32,
                    },
                )))
            }
            (State::Challenge { id, .. }, Request::Verify { challenge, pin }) => {
                require_eligible(eligibility)?;
                if id != challenge {
                    return Err(ProtocolError::Binding);
                }
                self.state = State::Verifying {
                    expires: deadline(now, VERIFY_LIFETIME_MS)?,
                };
                Ok(ConnectionAction::Verify {
                    uid: self.peer_uid,
                    challenge,
                    pin,
                })
            }
            (State::Idle, Request::BeginEnroll { action, backend }) => {
                require_eligible(eligibility)?;
                validate_enroll(action, backend)?;
                let Some(Issued::Enrollment {
                    transaction,
                    generation,
                }) = issued
                else {
                    return Err(ProtocolError::InvalidField);
                };
                if generation == 0 {
                    return Err(ProtocolError::InvalidField);
                }
                if transaction == self.id {
                    return Err(ProtocolError::Binding);
                }
                let context = PasswordContext {
                    connection: self.id,
                    transaction,
                    uid: self.peer_uid,
                    action,
                    generation,
                };
                self.state = State::Password(Enrollment {
                    context,
                    backend,
                    expires: deadline(now, ENROLLMENT_LIFETIME_MS)?,
                });
                Ok(ConnectionAction::StartPassword {
                    context,
                    backend,
                    reply: self.reply(Response::EnrollmentStarted {
                        transaction,
                        generation,
                        valid_for_ms: ENROLLMENT_LIFETIME_MS as u32,
                    }),
                })
            }
            (
                State::Prompt {
                    enrollment,
                    id,
                    style,
                },
                Request::EnrollConversation {
                    transaction,
                    prompt,
                    response,
                },
            ) => {
                if transaction != enrollment.context.transaction || prompt != id {
                    return Err(ProtocolError::Binding);
                }
                if response.expose().len() > MAX_CONVERSATION_BYTES {
                    return Err(ProtocolError::InvalidField);
                }
                if matches!(style, PromptStyle::Info | PromptStyle::Error)
                    && !response.expose().is_empty()
                {
                    return Err(ProtocolError::InvalidField);
                }
                self.state = State::Password(enrollment);
                Ok(ConnectionAction::AnswerPassword {
                    context: enrollment.context,
                    response,
                })
            }
            (State::Authorized(enrollment), Request::CommitEnrollment { transaction, pin }) => {
                require_eligible(eligibility)?;
                if transaction != enrollment.context.transaction {
                    return Err(ProtocolError::Binding);
                }
                if enrollment.context.action == EnrollmentAction::Disable {
                    return Err(ProtocolError::OutOfOrder);
                }
                let backend = enrollment.backend.ok_or(ProtocolError::InvalidField)?;
                self.state = State::Mutating(enrollment);
                Ok(ConnectionAction::CommitEnrollment {
                    context: enrollment.context,
                    backend,
                    pin,
                })
            }
            (State::Authorized(enrollment), Request::Disable { transaction }) => {
                require_eligible(eligibility)?;
                if transaction != enrollment.context.transaction {
                    return Err(ProtocolError::Binding);
                }
                if enrollment.context.action != EnrollmentAction::Disable {
                    return Err(ProtocolError::OutOfOrder);
                }
                self.state = State::Mutating(enrollment);
                Ok(ConnectionAction::Disable {
                    context: enrollment.context,
                })
            }
            _ => Err(ProtocolError::OutOfOrder),
        }
    }

    /// Relay one prompt issued by this transaction's trusted password worker.
    ///
    /// Prompt IDs must be fresh OS-random values. Reuse is rejected across all
    /// prompts in this connection, and there can be at most sixteen prompts.
    pub fn password_prompt(
        &mut self,
        context: PasswordContext,
        prompt: Id,
        style: PromptStyle,
        text: PromptText,
        now: u64,
    ) -> Result<ResponseEnvelope, ProtocolError> {
        let result = (|| {
            self.check_time(now)?;
            let State::Password(enrollment) = self.state else {
                return Err(ProtocolError::OutOfOrder);
            };
            if context != enrollment.context || prompt == self.id || prompt == context.transaction {
                return Err(ProtocolError::Binding);
            }
            if self.prompt_count == MAX_PASSWORD_PROMPTS || self.prompts.contains(&Some(prompt)) {
                return Err(ProtocolError::OutOfOrder);
            }
            self.prompts[self.prompt_count] = Some(prompt);
            self.prompt_count += 1;
            self.state = State::Prompt {
                enrollment,
                id: prompt,
                style,
            };
            Ok(self.reply(Response::ConversationPrompt {
                transaction: context.transaction,
                prompt,
                style,
                text,
            }))
        })();
        if result.is_err() {
            self.state = State::Finished;
        }
        result
    }

    /// Consume a trusted password worker's authenticated result.
    ///
    /// Call only after fresh password-only PAM success received over the private
    /// authenticated worker channel; never from client traffic. The exact worker
    /// context must match. It authorizes one action/generation for at most sixty
    /// seconds from this time, on this connection and UID only.
    pub fn password_authenticated(
        &mut self,
        context: PasswordContext,
        now: u64,
    ) -> Result<ResponseEnvelope, ProtocolError> {
        let result = (|| {
            self.check_time(now)?;
            let State::Password(mut enrollment) = self.state else {
                return Err(ProtocolError::OutOfOrder);
            };
            if context != enrollment.context {
                return Err(ProtocolError::Binding);
            }
            enrollment.expires = deadline(now, ENROLLMENT_LIFETIME_MS)?;
            self.state = State::Authorized(enrollment);
            Ok(self.reply(Response::EnrollmentReady {
                transaction: context.transaction,
                valid_for_ms: ENROLLMENT_LIFETIME_MS as u32,
            }))
        })();
        if result.is_err() {
            self.state = State::Finished;
        }
        result
    }

    /// Reject/crash a trusted password worker and terminate its transaction.
    pub fn password_failed(
        &mut self,
        context: PasswordContext,
        now: u64,
    ) -> Result<ResponseEnvelope, ProtocolError> {
        let result = (|| {
            self.check_time(now)?;
            let enrollment = match self.state {
                State::Password(enrollment) | State::Prompt { enrollment, .. } => enrollment,
                _ => return Err(ProtocolError::OutOfOrder),
            };
            if context != enrollment.context {
                return Err(ProtocolError::Binding);
            }
            Ok(self.reply(Response::Error(ErrorCode::PasswordRejected)))
        })();
        self.state = State::Finished;
        result
    }

    /// Finish one verification after core policy and durable storage completion.
    ///
    /// `Granted` is legal only after durable success and a fresh revocation /
    /// eligibility check. This method enforces connection/order/deadline rules;
    /// it does not implement credential verification or protected persistence.
    pub fn finish_verification(
        &mut self,
        outcome: VerificationOutcome,
        eligibility: Eligibility,
        now: u64,
    ) -> Result<ResponseEnvelope, ProtocolError> {
        let result = (|| {
            self.check_time(now)?;
            if !matches!(self.state, State::Verifying { .. }) {
                return Err(ProtocolError::OutOfOrder);
            }
            if outcome == VerificationOutcome::Granted {
                require_eligible(eligibility)?;
            }
            Ok(self.reply(Response::Verification(outcome)))
        })();
        self.state = State::Finished;
        result
    }

    /// Report a mutation only after its protected durable commit succeeds.
    ///
    /// Core/storage must enforce the generation/identity/revocation fence and
    /// the authorization expiry *before* committing. A response is never proof
    /// that a future operation is authorized.
    pub fn finish_mutation(
        &mut self,
        completion: Completion,
        eligibility: Eligibility,
        now: u64,
    ) -> Result<ResponseEnvelope, ProtocolError> {
        let result = (|| {
            self.check_time(now)?;
            match (self.state, completion) {
                (State::Recovering { .. }, Completion::RecoveryDisabled) if self.peer_uid == 0 => {}
                (State::Mutating(enrollment), Completion::Disabled)
                    if enrollment.context.action == EnrollmentAction::Disable =>
                {
                    require_eligible(eligibility)?
                }
                (State::Mutating(enrollment), Completion::Enrolled(backend))
                    if enrollment.context.action != EnrollmentAction::Disable
                        && enrollment.backend == Some(backend) =>
                {
                    require_eligible(eligibility)?;
                }
                _ => return Err(ProtocolError::OutOfOrder),
            }
            Ok(self.reply(Response::Completed(completion)))
        })();
        self.state = State::Finished;
        result
    }

    /// Terminate a pending operation on a sanitized broker/backend error.
    pub fn fail(&mut self, error: ErrorCode) -> ResponseEnvelope {
        self.state = State::Finished;
        self.reply(Response::Error(error))
    }

    fn reply(&self, response: Response) -> ResponseEnvelope {
        ResponseEnvelope {
            connection: self.id,
            response,
        }
    }

    fn check_time(&mut self, now: u64) -> Result<(), ProtocolError> {
        if now < self.last_now {
            return Err(ProtocolError::Clock);
        }
        self.last_now = now;
        let expires = match self.state {
            State::Challenge { expires, .. }
            | State::Verifying { expires }
            | State::Recovering { expires } => Some(expires),
            State::Password(enrollment)
            | State::Prompt { enrollment, .. }
            | State::Authorized(enrollment)
            | State::Mutating(enrollment) => Some(enrollment.expires),
            State::Idle | State::Finished => None,
        };
        if expires.is_some_and(|expires| now >= expires) {
            return Err(ProtocolError::Expired);
        }
        Ok(())
    }
}

fn require_eligible(eligibility: Eligibility) -> Result<(), ProtocolError> {
    if eligibility == Eligibility::Eligible {
        Ok(())
    } else {
        Err(ProtocolError::Forbidden)
    }
}

fn deadline(now: u64, interval: u64) -> Result<u64, ProtocolError> {
    now.checked_add(interval).ok_or(ProtocolError::Clock)
}
