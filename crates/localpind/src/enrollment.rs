//! Connection-owned enrollment: password PAM, staged trial and durable commit.

use crate::{
    BootClock,
    broker::{ProtectedEngine, fresh_id},
    platform::Peer,
};
use localpin_auth::{Conversation, PasswordPrompt, PasswordSupervisor};
use localpin_core::{
    eligibility::EligibilitySnapshot,
    enrollment::{
        EnrollmentError, EnrollmentMachine, PasswordWorker, PasswordWorkerError,
        PasswordWorkerRequest,
    },
    limits::{KdfParameters, WorkKind},
    secret::SecretBytes,
    throttle::BackendOutcome,
    types::{Backend, Clock, ConnectionId, TimePoint, TransactionId, Unavailable},
};
use localpin_protocol::{
    Completion, Connection, ConnectionAction, Eligibility, ErrorCode, Issued, PasswordContext,
    PromptStyle, PromptText, Request, RequestEnvelope, resolve_enrollment_action,
    transport::{BootInstant as Instant, Deadline, SocketConnection, TransportError},
};
use std::{os::unix::net::UnixStream, sync::Arc, time::Duration};

const INTERVAL: Duration = Duration::from_secs(60);

/// Trusted password authority supplied by the operator, never by a client.
/// Test brokers may supply a synthetic authority without an installed test mode.
pub trait PasswordAuthority: Send + Sync {
    /// Authenticate exactly this core-owned request through its private relay.
    fn verify(
        &self,
        request: PasswordWorkerRequest,
        conversation: &mut dyn Conversation,
    ) -> Result<TimePoint, PasswordWorkerError>;
}

impl PasswordAuthority for PasswordSupervisor {
    fn verify(
        &self,
        request: PasswordWorkerRequest,
        conversation: &mut dyn Conversation,
    ) -> Result<TimePoint, PasswordWorkerError> {
        let mut clock = BootClock::new().map_err(|_| PasswordWorkerError::Unavailable)?;
        self.bind(conversation, &mut clock)
            .verify_existing_password(request)
    }
}

/// Private socket/session ownership for a single enrollment transaction.
pub struct EnrollmentIo<'a> {
    socket: &'a mut SocketConnection,
    session: &'a mut Connection,
    monitor: &'a UnixStream,
    clock: BootClock,
    deadline: Instant,
}

impl<'a> EnrollmentIo<'a> {
    pub(crate) fn new(
        socket: &'a mut SocketConnection,
        session: &'a mut Connection,
        monitor: &'a UnixStream,
    ) -> Result<Self, TransportError> {
        Ok(Self {
            socket,
            session,
            monitor,
            clock: BootClock::new().map_err(|_| TransportError::UntrustedPeer)?,
            deadline: Instant::now() + INTERVAL,
        })
    }

    fn now(&mut self) -> Result<TimePoint, ErrorCode> {
        self.clock.now().map_err(|_| ErrorCode::Unavailable)
    }

    /// Terminate without disclosing worker, PAM or storage details.
    pub fn fail(&mut self, error: ErrorCode) -> Result<(), TransportError> {
        let response = self.session.fail(error);
        self.socket
            .write_response(&response, Deadline::at(self.deadline))
    }

    fn cancelled(&self) -> bool {
        crate::broker::pending(self.monitor) || Instant::now() >= self.deadline
    }

    fn accept(&mut self) -> Result<ConnectionAction, ErrorCode> {
        let request = self
            .socket
            .read_request(Deadline::at(self.deadline))
            .map_err(|_| ErrorCode::Unavailable)?;
        let now = self.now()?.millis;
        let action = self
            .session
            .accept(request, now, Eligibility::Eligible, None)
            .map_err(|_| ErrorCode::Protocol)?;
        if matches!(action, ConnectionAction::Cancel) {
            let response = localpin_protocol::ResponseEnvelope {
                connection: self.session.id(),
                response: localpin_protocol::Response::Cancelled,
            };
            let _ = self
                .socket
                .write_response(&response, Deadline::at(self.deadline));
            return Err(ErrorCode::State);
        }
        Ok(action)
    }
}

struct Relay<'a, 'b> {
    channel: &'a mut EnrollmentIo<'b>,
    context: PasswordContext,
}
impl Conversation for Relay<'_, '_> {
    fn password(&mut self, prompt: PasswordPrompt) -> Result<SecretBytes, PasswordWorkerError> {
        self.channel.deadline = self.channel.deadline.min(prompt.deadline);
        let prompt_id = fresh_id().map_err(|_| PasswordWorkerError::Unavailable)?;
        let now = self
            .channel
            .now()
            .map_err(|_| PasswordWorkerError::Unavailable)?
            .millis;
        let text = PromptText::new(prompt.text).map_err(|_| PasswordWorkerError::Unavailable)?;
        let response = self
            .channel
            .session
            .password_prompt(self.context, prompt_id, PromptStyle::EchoOff, text, now)
            .map_err(|_| PasswordWorkerError::Unavailable)?;
        self.channel
            .socket
            .write_response(&response, Deadline::at(self.channel.deadline))
            .map_err(|_| PasswordWorkerError::Cancelled)?;
        match self
            .channel
            .accept()
            .map_err(|_| PasswordWorkerError::Cancelled)?
        {
            ConnectionAction::AnswerPassword { context, response } if context == self.context => {
                Ok(response)
            }
            _ => Err(PasswordWorkerError::Cancelled),
        }
    }
    fn cancelled(&mut self) -> bool {
        self.channel.cancelled()
    }
}

struct Authorize<'a> {
    authority: &'a dyn PasswordAuthority,
    relay: &'a mut dyn Conversation,
}
impl PasswordWorker for Authorize<'_> {
    fn verify_existing_password(
        &mut self,
        request: PasswordWorkerRequest,
    ) -> Result<TimePoint, PasswordWorkerError> {
        self.authority.verify(request, self.relay)
    }
}

pub(crate) fn serve(
    engine: &ProtectedEngine,
    peer: Arc<Peer>,
    expected: EligibilitySnapshot,
    request: RequestEnvelope,
    channel: &mut EnrollmentIo<'_>,
) -> Result<(), TransportError> {
    match transact(engine, peer, expected, request, channel) {
        Ok(()) => Ok(()),
        // Cancellation already terminated the session, so do not append a second result.
        Err(_) if channel.session.is_finished() => Ok(()),
        Err(error) => channel.fail(error),
    }
}

fn transact(
    engine: &ProtectedEngine,
    peer: Arc<Peer>,
    expected: EligibilitySnapshot,
    request: RequestEnvelope,
    channel: &mut EnrollmentIo<'_>,
) -> Result<(), ErrorCode> {
    let passwords = engine.passwords.as_ref().ok_or(ErrorCode::Unavailable)?;
    let Request::BeginEnroll { action, backend } = request.request else {
        return Err(ErrorCode::State);
    };
    if request.connection != channel.session.id() || peer.uid() != expected.account().uid.get() {
        return Err(ErrorCode::Forbidden);
    }
    let mut lifecycle = engine.authorities.lifecycle();
    // Supported lifecycle provisioning owns the disabled baseline. Never repair
    // missing/corrupt state implicitly during a user enrollment request.
    let mut store = engine
        .storage
        .user(expected.account().uid, lifecycle.as_mut())
        .map_err(|_| ErrorCode::Unavailable)?;
    let state = store
        .committed_state()
        .map_err(|_| ErrorCode::Unavailable)?;
    if state.account() != expected.account() {
        return Err(ErrorCode::Forbidden);
    }
    let current = state.backend().map(wire_backend);
    let core_action =
        resolve_enrollment_action(action, backend, current).map_err(|_| ErrorCode::State)?;
    let connection =
        ConnectionId::new(*channel.session.id().as_bytes()).map_err(|_| ErrorCode::State)?;
    let transaction = fresh_id().map_err(|_| ErrorCode::Unavailable)?;
    let mut machine = EnrollmentMachine::new(state);
    let binding = machine
        .begin_own_user(
            connection,
            expected.account().uid,
            TransactionId::new(*transaction.as_bytes()).map_err(|_| ErrorCode::State)?,
            core_action,
            channel.now()?,
            &mut store.lifecycle(),
        )
        .map_err(|_| ErrorCode::Forbidden)?;
    let started_at = channel.now()?.millis;
    let accepted = channel
        .session
        .accept(
            RequestEnvelope {
                connection: request.connection,
                request: Request::BeginEnroll { action, backend },
            },
            started_at,
            Eligibility::Eligible,
            Some(Issued::Enrollment {
                transaction,
                generation: binding.proposed_generation().get(),
            }),
        )
        .map_err(|_| ErrorCode::Protocol)?;
    let ConnectionAction::StartPassword { context, reply, .. } = accepted else {
        return Err(ErrorCode::State);
    };
    channel
        .socket
        .write_response(&reply, Deadline::at(channel.deadline))
        .map_err(|_| ErrorCode::Unavailable)?;
    let started = channel.now()?;
    let mut relay = Relay { channel, context };
    machine
        .authorize_with_password_worker(
            binding,
            connection,
            started,
            &mut Authorize {
                authority: passwords.as_ref(),
                relay: &mut relay,
            },
            &mut store.lifecycle(),
        )
        .map_err(authorization_error)?;
    if channel.cancelled() || peer.ensure_live().is_err() {
        return Err(ErrorCode::Expired);
    }
    let now = channel.now()?.millis;
    let reply = channel
        .session
        .password_authenticated(context, now)
        .map_err(|_| ErrorCode::Expired)?;
    channel.deadline = Instant::now() + INTERVAL;
    channel
        .socket
        .write_response(&reply, Deadline::at(channel.deadline))
        .map_err(|_| ErrorCode::Unavailable)?;
    let operation = channel.accept()?;
    let mut eligible = engine
        .authorities
        .eligibility(peer.clone(), channel.deadline);
    let mut recheck = || {
        peer.ensure_live().map_err(|_| ErrorCode::Forbidden)?;
        if eligible
            .check(expected.account())
            .map_err(|_| ErrorCode::Forbidden)?
            != expected
        {
            return Err(ErrorCode::Forbidden);
        }
        Ok(())
    };
    recheck()?;
    let (stage, completion) = match operation {
        ConnectionAction::CommitEnrollment {
            context: checked,
            backend,
            pin,
        } if checked == context => {
            machine
                .staged_created(binding, connection, channel.now()?, &mut store.lifecycle())
                .map_err(|_| ErrorCode::Expired)?;
            let selected = match backend {
                localpin_protocol::Backend::Software => Backend::Software,
                localpin_protocol::Backend::Tpm => Backend::Tpm2,
            };
            let kind = if selected == Backend::Software {
                WorkKind::Enrollment
            } else {
                WorkKind::TpmPinDerivation
            };
            let permit = engine
                .budget
                .try_work(expected.account().uid, KdfParameters::ENROLLMENT, kind)
                .map_err(|_| ErrorCode::Unavailable)?;
            let trial_pin =
                localpin_core::secret::Pin::parse(pin.expose()).map_err(|_| ErrorCode::State)?;
            let work_deadline = channel
                .deadline
                .min(Instant::now() + Duration::from_secs(5));
            let credential = engine
                .workers
                .enroll(
                    expected.account(),
                    binding.proposed_generation(),
                    selected,
                    pin,
                    permit,
                    work_deadline,
                    || channel.cancelled(),
                )
                .map_err(|_| ErrorCode::Unavailable)?;
            let verified = store
                .stage_credential(credential, |persisted| {
                    let permit = engine
                        .budget
                        .try_work(expected.account().uid, KdfParameters::ENROLLMENT, kind)
                        .map_err(|_| localpin_storage::Error::Busy)?;
                    match engine.workers.trial_verify(
                        persisted,
                        trial_pin,
                        permit,
                        work_deadline,
                        || channel.cancelled(),
                    ) {
                        BackendOutcome::Match => Ok(()),
                        _ => Err(localpin_storage::Error::Corrupt),
                    }
                })
                .map_err(|_| ErrorCode::Unavailable)?;
            machine
                .staged_verified(binding, connection, channel.now()?, &mut store.lifecycle())
                .map_err(|_| ErrorCode::Expired)?;
            (Some(verified), Completion::Enrolled(backend))
        }
        ConnectionAction::Disable { context: checked } if checked == context => {
            (None, Completion::Disabled)
        }
        _ => return Err(ErrorCode::Protocol),
    };
    recheck()?;
    if channel.cancelled() {
        return Err(ErrorCode::Expired);
    }
    let intent = machine
        .prepare_commit(binding, connection, channel.now()?, &mut store.lifecycle())
        .map_err(|_| ErrorCode::Expired)?;
    {
        // Storage calls this fence again after pointer tempfile fsync, just
        // before rename. Cancellation/session loss during earlier I/O must
        // not publish a new accepted generation.
        let mut commit_clock = FencedClock {
            clock: &mut channel.clock,
            monitor: channel.monitor,
            deadline: channel.deadline,
            recheck: &mut recheck,
        };
        store
            .commit_generation(intent, stage, &mut commit_clock)
            .map_err(|_| ErrorCode::Unavailable)?;
    }
    machine
        .acknowledge_durable_commit(intent, connection, channel.now()?, &mut store.lifecycle())
        .map_err(|_| ErrorCode::Expired)?;
    recheck()?;
    if channel.cancelled() {
        return Err(ErrorCode::Expired);
    }
    let now = channel.now()?.millis;
    let response = channel
        .session
        .finish_mutation(completion, Eligibility::Eligible, now)
        .map_err(|_| ErrorCode::Expired)?;
    channel
        .socket
        .write_response(&response, Deadline::at(channel.deadline))
        .map_err(|_| ErrorCode::Unavailable)
}

struct FencedClock<'a> {
    clock: &'a mut BootClock,
    monitor: &'a UnixStream,
    deadline: Instant,
    recheck: &'a mut dyn FnMut() -> Result<(), ErrorCode>,
}

impl Clock for FencedClock<'_> {
    fn now(&mut self) -> Result<TimePoint, Unavailable> {
        if crate::broker::pending(self.monitor) || Instant::now() >= self.deadline {
            return Err(Unavailable);
        }
        (self.recheck)().map_err(|_| Unavailable)?;
        let now = self.clock.now()?;
        if crate::broker::pending(self.monitor) || Instant::now() >= self.deadline {
            return Err(Unavailable);
        }
        Ok(now)
    }
}

fn wire_backend(backend: Backend) -> localpin_protocol::Backend {
    match backend {
        Backend::Software => localpin_protocol::Backend::Software,
        Backend::Tpm2 => localpin_protocol::Backend::Tpm,
    }
}

fn authorization_error(error: EnrollmentError) -> ErrorCode {
    match error {
        EnrollmentError::PasswordWorker(PasswordWorkerError::Rejected) => {
            ErrorCode::PasswordRejected
        }
        EnrollmentError::PasswordWorker(PasswordWorkerError::TimedOut)
        | EnrollmentError::AuthorizationExpired
        | EnrollmentError::TimeAnomaly => ErrorCode::Expired,
        EnrollmentError::AccountChanged
        | EnrollmentError::Lifecycle(_)
        | EnrollmentError::WrongPeer
        | EnrollmentError::Eligibility(_) => ErrorCode::Forbidden,
        _ => ErrorCode::Unavailable,
    }
}
