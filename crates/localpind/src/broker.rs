//! Socket dispatch and protected reservation/backend/completion composition.

use crate::{
    BootClock,
    enrollment::{EnrollmentIo, PasswordAuthority},
    platform::{Peer, ResolvedSession, SessionResolver},
    worker::WorkerSupervisor,
};
use localpin_core::{
    eligibility::{EligibilityAuthority, EligibilityError, EligibilitySnapshot},
    enrollment::{
        Administrator, EnrollmentMachine, LifecycleAuthority, LifecycleError, UnmanagedUnixAccounts,
    },
    limits::{ResourceBudget, WorkKind},
    secret::Pin,
    throttle::{AttemptResponse, ReserveError},
    types::{AccountId, Backend, Clock, ConnectionId, Incarnation, Randomness, TransactionId, Uid},
};
use localpin_credentials::{OsRandom, SoftwareVerifier};
use localpin_protocol::{
    Availability, BackendPreference, Completion, Connection, ConnectionAction, Eligibility,
    ErrorCode, Id, Integration, Issued, Reason, Request, RequestEnvelope, Response,
    ResponseEnvelope, Status, VerificationOutcome,
    transport::{BootInstant as Instant, Deadline, SocketConnection, TransportError},
};
use localpin_storage::Storage;
use std::{
    io,
    os::unix::net::{UnixListener, UnixStream},
    sync::Arc,
    thread,
    time::Duration,
};

/// Maximum idle read/write duration. Partial frames do not renew it.
pub const UNAVAILABLE_TIMEOUT: Duration = Duration::from_secs(2);
/// Maximum accepted native TPM attempt, including its final response.
pub const TPM_TIMEOUT: Duration = Duration::from_secs(5);
/// Finite idle connection lifetime, even when status requests keep arriving.
pub const CONNECTION_LIFETIME: Duration = Duration::from_secs(15);
const MAX_REQUESTS: usize = 32;

/// Absolute submission budgets, including eligibility and protected-state work.
#[derive(Clone, Copy, Debug)]
pub struct VerificationDeadlines {
    /// Ordinary unavailable/software response deadline.
    pub unavailable: Instant,
    /// Extended deadline allowed only for a protected TPM credential.
    pub tpm: Instant,
}

impl VerificationDeadlines {
    fn for_request(unavailable: Instant, lifetime: Instant) -> Self {
        Self {
            unavailable,
            tpm: unavailable
                .checked_add(TPM_TIMEOUT - UNAVAILABLE_TIMEOUT)
                .unwrap_or(unavailable)
                .min(lifetime),
        }
    }
}

/// Trusted account/session adapters. No wire field selects or implements these.
pub trait Authorities: Send + Sync {
    /// Return an independent lifecycle reader for one connection operation.
    fn lifecycle(&self) -> Box<dyn LifecycleAuthority>;
    /// Return an account-policy and live-session checker bound to this peer.
    fn eligibility(&self, peer: Arc<Peer>, deadline: Instant) -> Box<dyn EligibilityAuthority>;
}

/// Production defaults keep unsupported account lifecycle/policy unavailable.
pub struct SystemAuthorities;

impl Authorities for SystemAuthorities {
    fn lifecycle(&self) -> Box<dyn LifecycleAuthority> {
        Box::new(UnmanagedUnixAccounts)
    }
    fn eligibility(&self, peer: Arc<Peer>, deadline: Instant) -> Box<dyn EligibilityAuthority> {
        Box::new(SystemEligibility {
            peer,
            deadline,
            resolver: SessionResolver::new(),
            session: None,
        })
    }
}

struct SystemEligibility {
    peer: Arc<Peer>,
    deadline: Instant,
    resolver: SessionResolver,
    session: Option<ResolvedSession>,
}

impl EligibilityAuthority for SystemEligibility {
    fn check(&mut self, account: AccountId) -> Result<EligibilitySnapshot, EligibilityError> {
        if self.peer.uid() != account.uid.get() {
            return Err(EligibilityError::WrongAccount);
        }
        if let Some(session) = &self.session {
            self.resolver
                .revalidate(&self.peer, session, self.deadline)?;
        } else {
            self.session = Some(self.resolver.resolve(&self.peer, self.deadline)?);
        }
        // Live logind metadata does not establish account lock/expiry/PAM policy.
        // An enforcing lifecycle and supported account-policy adapter is still
        // required; do not turn successful session routing into authorization.
        Err(EligibilityError::Unavailable)
    }
}

struct Lifecycle(Box<dyn LifecycleAuthority>);
impl LifecycleAuthority for Lifecycle {
    fn current_incarnation(&mut self, uid: Uid) -> Result<Incarnation, LifecycleError> {
        self.0.current_incarnation(uid)
    }
}
struct Eligible(Box<dyn EligibilityAuthority>);
impl EligibilityAuthority for Eligible {
    fn check(&mut self, account: AccountId) -> Result<EligibilitySnapshot, EligibilityError> {
        self.0.check(account)
    }
}

/// Trusted broker service boundary. Verification calls its delivery callback
/// while retaining serialization against rotation and disable.
pub trait Engine: Send + Sync {
    /// Establish own-account live eligibility before issuing/consuming a challenge.
    fn check(&self, peer: Arc<Peer>, deadline: Instant) -> Result<EligibilitySnapshot, Reason>;
    /// Read sanitized own-account status only.
    fn status(&self, peer: Arc<Peer>, deadline: Instant) -> Status;
    /// Own one connection-bound fresh-password enrollment conversation.
    fn enroll(
        &self,
        _peer: Arc<Peer>,
        _expected: EligibilitySnapshot,
        _request: RequestEnvelope,
        channel: &mut EnrollmentIo<'_>,
    ) -> Result<(), TransportError> {
        channel.fail(ErrorCode::Unavailable)
    }
    /// Reserve, supervise, persist and revalidate before delivering one result.
    fn verify(
        &self,
        peer: Arc<Peer>,
        expected: EligibilitySnapshot,
        pin: Pin,
        deadlines: VerificationDeadlines,
        cancelled: &mut dyn FnMut() -> bool,
        deliver: &mut dyn FnMut(VerificationOutcome, Instant),
    );
    /// Separate root-only recovery, with delivery under the revocation lock.
    fn recover(
        &self,
        peer: &Peer,
        target: Uid,
        connection: Id,
        deadline: Instant,
        deliver: &mut dyn FnMut(Result<(), Reason>),
    );
}

/// M3 protected storage composed with M4 subprocess backends and M2 policy.
pub struct ProtectedEngine {
    pub(super) storage: Storage,
    pub(super) authorities: Arc<dyn Authorities>,
    pub(super) workers: WorkerSupervisor,
    pub(super) budget: ResourceBudget,
    pub(super) passwords: Option<Arc<dyn PasswordAuthority>>,
}

impl ProtectedEngine {
    /// Construct only from trusted installed storage, authorities and worker path.
    pub fn new(
        storage: Storage,
        authorities: Arc<dyn Authorities>,
        workers: WorkerSupervisor,
        budget: ResourceBudget,
    ) -> Self {
        Self {
            storage,
            authorities,
            workers,
            budget,
            passwords: None,
        }
    }

    /// Supply the independently supervised trusted password-only boundary.
    /// This is an operator/library dependency, never a wire or executable flag.
    pub fn with_password_authority(mut self, passwords: Arc<dyn PasswordAuthority>) -> Self {
        self.passwords = Some(passwords);
        self
    }
}

pub(super) fn fresh_id() -> Result<Id, Reason> {
    let mut bytes = [0; 16];
    OsRandom.fill(&mut bytes).map_err(|_| Reason::Policy)?;
    Id::from_bytes(bytes).map_err(|_| Reason::Policy)
}

fn unavailable_status(reason: Reason) -> Status {
    use std::os::unix::fs::FileTypeExt;
    Status {
        configured: BackendPreference::Auto,
        enrolled: None,
        availability: Availability::Unavailable,
        cooldown_ms: 0,
        integration: Integration::Inactive,
        // Presence is a read-only device-node observation, never usability.
        tpm_detected: ["/dev/tpmrm0", "/dev/tpm0"].iter().any(|path| {
            std::fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_char_device())
        }),
        tpm_usable: false,
        reason,
    }
}

impl Engine for ProtectedEngine {
    fn enroll(
        &self,
        peer: Arc<Peer>,
        expected: EligibilitySnapshot,
        request: RequestEnvelope,
        channel: &mut EnrollmentIo<'_>,
    ) -> Result<(), TransportError> {
        crate::enrollment::serve(self, peer, expected, request, channel)
    }
    fn check(&self, peer: Arc<Peer>, deadline: Instant) -> Result<EligibilitySnapshot, Reason> {
        peer.ensure_live().map_err(|_| Reason::Session)?;
        let uid = Uid::new(peer.uid()).map_err(|_| Reason::Account)?;
        let incarnation = self
            .authorities
            .lifecycle()
            .current_incarnation(uid)
            .map_err(|_| Reason::Account)?;
        let account = AccountId { uid, incarnation };
        let snapshot = self
            .authorities
            .eligibility(peer, deadline)
            .check(account)
            .map_err(|_| Reason::Session)?;
        if snapshot.account() != account {
            return Err(Reason::Account);
        }
        if Instant::now() >= deadline {
            return Err(Reason::Busy);
        }
        Ok(snapshot)
    }

    fn status(&self, peer: Arc<Peer>, deadline: Instant) -> Status {
        let checked = match self.check(peer.clone(), deadline) {
            Ok(value) => value,
            Err(reason) => return unavailable_status(reason),
        };
        let mut lifecycle = self.authorities.lifecycle();
        let mut store = match self.storage.user(checked.account().uid, lifecycle.as_mut()) {
            Ok(store) => store,
            Err(_) => return unavailable_status(Reason::Storage),
        };
        let state = match store.committed_state() {
            Ok(state) if state.account() == checked.account() => state,
            _ => return unavailable_status(Reason::Storage),
        };
        let mut status = unavailable_status(Reason::None);
        status.enrolled = state.backend().map(|backend| match backend {
            Backend::Software => localpin_protocol::Backend::Software,
            Backend::Tpm2 => localpin_protocol::Backend::Tpm,
        });
        status.configured = match state.backend() {
            Some(Backend::Software) => BackendPreference::Software,
            Some(Backend::Tpm2) => BackendPreference::Tpm,
            None => BackendPreference::Auto,
        };
        status.availability = Availability::Disabled;
        if state.backend().is_some() {
            let result = (|| {
                let now = BootClock::new()
                    .map_err(|_| localpin_storage::Error::Time)?
                    .now()
                    .map_err(|_| localpin_storage::Error::Time)?;
                store.with_throttle(now, |throttle, _| {
                    let remaining = throttle
                        .record()
                        .cooldown_until_millis
                        .unwrap_or(now.millis)
                        .saturating_sub(now.millis);
                    status.cooldown_ms = remaining.min(u32::MAX as u64) as u32;
                    status.availability = if remaining > 0 {
                        Availability::Cooldown
                    } else {
                        Availability::Available
                    };
                    Ok(())
                })
            })();
            if result.is_err() {
                status.availability = Availability::Unavailable;
                status.reason = Reason::Storage;
            }
        }
        if Instant::now() >= deadline {
            return unavailable_status(Reason::Busy);
        }
        status
    }

    fn verify(
        &self,
        peer: Arc<Peer>,
        expected: EligibilitySnapshot,
        pin: Pin,
        deadlines: VerificationDeadlines,
        cancelled: &mut dyn FnMut() -> bool,
        deliver: &mut dyn FnMut(VerificationOutcome, Instant),
    ) {
        if expected.account().uid.get() != peer.uid() || peer.uid() == 0 {
            deliver(
                VerificationOutcome::Unavailable(Reason::Account),
                deadlines.unavailable,
            );
            return;
        }
        let mut lifecycle = Lifecycle(self.authorities.lifecycle());
        let mut store = match self.storage.user(expected.account().uid, &mut lifecycle) {
            Ok(store) => store,
            Err(_) => {
                deliver(
                    VerificationOutcome::Unavailable(Reason::Storage),
                    deadlines.unavailable,
                );
                return;
            }
        };
        let mut response_deadline = deadlines.unavailable;
        let result = (|| -> Result<VerificationOutcome, Reason> {
            let committed = store.committed_state().map_err(|_| Reason::Storage)?;
            if committed.account() != expected.account() {
                return Err(Reason::Account);
            }
            let credential = store.credential().map_err(|_| Reason::Storage)?;
            let parameters = match credential.backend() {
                Backend::Software => SoftwareVerifier::new(&credential)
                    .map_err(|_| Reason::Backend)?
                    .parameters(),
                Backend::Tpm2 => localpin_tpm::TpmRecord::from_credential(&credential)
                    .map_err(|_| Reason::Backend)?
                    .parameters(),
            };
            let kind = match credential.backend() {
                Backend::Software => WorkKind::Verification,
                Backend::Tpm2 => WorkKind::TpmPinDerivation,
            };
            let deadline = match credential.backend() {
                Backend::Software => deadlines.unavailable,
                Backend::Tpm2 => deadlines.tpm,
            };
            response_deadline = deadline;
            if Instant::now() >= deadline || cancelled() {
                return Err(Reason::Busy);
            }
            let mut eligibility = Eligible(self.authorities.eligibility(peer.clone(), deadline));
            if eligibility
                .check(expected.account())
                .map_err(|_| Reason::Session)?
                != expected
            {
                return Err(Reason::Session);
            }
            let machine = EnrollmentMachine::new(committed);
            let fence = machine
                .begin_verification(&mut eligibility, &mut store.lifecycle())
                .map_err(|_| Reason::Policy)?;
            let permit = self
                .budget
                .try_work(expected.account().uid, parameters, kind)
                .map_err(|_| Reason::Busy)?;
            let mut clock = BootClock::new().map_err(|_| Reason::Policy)?;
            let now = clock.now().map_err(|_| Reason::Policy)?;
            if Instant::now() >= deadline || cancelled() {
                return Err(Reason::Busy);
            }
            let outcome = store
                .with_throttle(now, |throttle, store| {
                    let reservation = match throttle.reserve(now) {
                        Ok(intent) => intent
                            .commit(store)
                            .map_err(|_| localpin_storage::Error::Uncertain)?,
                        Err(ReserveError::Cooldown { remaining_millis }) => {
                            return Ok(VerificationOutcome::Cooldown(
                                remaining_millis.min(u32::MAX as u64) as u32,
                            ));
                        }
                        Err(_) => return Err(localpin_storage::Error::Time),
                    };
                    let outcome =
                        self.workers
                            .verify(&credential, pin, permit, deadline, &mut *cancelled);
                    // A timeout/cancel keeps its reservation consumed even if a
                    // killed kernel call still occupies a supervisor slot.
                    if Instant::now() >= deadline || cancelled() {
                        return Ok(VerificationOutcome::Unavailable(Reason::Backend));
                    }
                    let now = clock.now().map_err(|_| localpin_storage::Error::Time)?;
                    let response = reservation
                        .complete(outcome, now)
                        .map_err(|_| localpin_storage::Error::Time)?
                        .commit(
                            store,
                            committed.account(),
                            committed.backend().map(|_| committed.generation()),
                        )
                        .map_err(|_| localpin_storage::Error::Uncertain)?;
                    Ok(match response {
                        AttemptResponse::Success => VerificationOutcome::Granted,
                        AttemptResponse::Mismatch => VerificationOutcome::Mismatch,
                        AttemptResponse::Unavailable(_) | AttemptResponse::Cancelled => {
                            VerificationOutcome::Unavailable(Reason::Backend)
                        }
                    })
                })
                .map_err(|_| Reason::Storage)?;
            if outcome == VerificationOutcome::Granted {
                peer.ensure_live().map_err(|_| Reason::Session)?;
                if store.committed_state().map_err(|_| Reason::Storage)? != committed {
                    return Err(Reason::Policy);
                }
                machine
                    .revalidate_verification(fence, &mut eligibility, &mut store.lifecycle())
                    .map_err(|_| Reason::Session)?;
                if eligibility
                    .check(expected.account())
                    .map_err(|_| Reason::Session)?
                    != expected
                {
                    return Err(Reason::Session);
                }
            }
            if Instant::now() >= deadline || cancelled() {
                return Err(Reason::Busy);
            }
            Ok(outcome)
        })();
        deliver(
            result.unwrap_or_else(VerificationOutcome::Unavailable),
            response_deadline,
        );
        // `store` (stable UID lock) outlives the actual response write.
    }

    fn recover(
        &self,
        peer: &Peer,
        target: Uid,
        connection: Id,
        deadline: Instant,
        deliver: &mut dyn FnMut(Result<(), Reason>),
    ) {
        if peer.uid() != 0 || peer.ensure_live().is_err() {
            deliver(Err(Reason::Account));
            return;
        }
        let mut lifecycle = Lifecycle(self.authorities.lifecycle());
        let mut store = match self.storage.user(target, &mut lifecycle) {
            Ok(store) => store,
            Err(_) => {
                deliver(Err(Reason::Storage));
                return;
            }
        };
        let result = (|| {
            let connection =
                ConnectionId::new(*connection.as_bytes()).map_err(|_| Reason::Protocol)?;
            let administrator = Administrator::from_kernel_peer_uid(connection, peer.uid())
                .map_err(|_| Reason::Account)?;
            let transaction =
                TransactionId::new(*fresh_id()?.as_bytes()).map_err(|_| Reason::Policy)?;
            let mut clock = BootClock::new().map_err(|_| Reason::Policy)?;
            let mut machine =
                EnrollmentMachine::new(store.committed_state().map_err(|_| Reason::Storage)?);
            let now = clock.now().map_err(|_| Reason::Policy)?;
            let binding = machine
                .begin_administrative_recovery(
                    connection,
                    administrator,
                    transaction,
                    now,
                    &mut store.lifecycle(),
                )
                .map_err(|_| Reason::Policy)?;
            let intent = machine
                .prepare_commit(binding, connection, now, &mut store.lifecycle())
                .map_err(|_| Reason::Policy)?;
            if Instant::now() >= deadline {
                return Err(Reason::Busy);
            }
            store
                .commit_generation(intent, None, &mut clock)
                .map_err(|_| Reason::Storage)?;
            machine
                .acknowledge_durable_commit(
                    intent,
                    connection,
                    clock.now().map_err(|_| Reason::Policy)?,
                    &mut store.lifecycle(),
                )
                .map_err(|_| Reason::Policy)?;
            if Instant::now() >= deadline {
                return Err(Reason::Busy);
            }
            Ok(())
        })();
        deliver(result);
    }
}

/// One broker's bounded connection admission, shared with its KDF budget.
pub struct Broker {
    engine: Arc<dyn Engine>,
    budget: ResourceBudget,
}

impl Broker {
    /// Use the same resource budget as the protected engine's backend work.
    pub fn new(engine: Arc<dyn Engine>, budget: ResourceBudget) -> Self {
        Self { engine, budget }
    }

    /// Admit immediately or close; no application-level work queue is created.
    pub fn accept(&self, stream: UnixStream) -> io::Result<()> {
        let permit = self
            .budget
            .try_connection()
            .map_err(|_| io::ErrorKind::WouldBlock)?;
        let engine = self.engine.clone();
        thread::Builder::new()
            .name("localpin-client".into())
            .spawn(move || {
                let _permit = permit;
                let _ = serve_connection(stream, engine.as_ref());
            })?;
        Ok(())
    }

    /// Serve an installed, validated Unix listener. Each accepted stream is bounded.
    pub fn run(&self, listener: UnixListener) -> io::Result<()> {
        listener.set_nonblocking(false)?;
        for stream in listener.incoming() {
            match stream {
                Ok(stream) => {
                    let _ = self.accept(stream);
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }
}

pub(super) fn pending(stream: &UnixStream) -> bool {
    let mut byte = [0];
    match rustix::net::recv(
        stream,
        &mut byte,
        rustix::net::RecvFlags::PEEK | rustix::net::RecvFlags::DONTWAIT,
    ) {
        Ok(_) => true,
        Err(rustix::io::Errno::AGAIN | rustix::io::Errno::INTR) => false,
        Err(_) => true,
    }
}

fn protocol_error(error: localpin_protocol::ProtocolError) -> ErrorCode {
    use localpin_protocol::ProtocolError as P;
    match error {
        P::Forbidden => ErrorCode::Forbidden,
        P::Expired => ErrorCode::Expired,
        _ => ErrorCode::Protocol,
    }
}

/// Serve one kernel-authenticated socket. No caller identity is accepted on wire.
pub fn serve_connection(stream: UnixStream, engine: &dyn Engine) -> Result<(), TransportError> {
    let mut clock = BootClock::new().map_err(|_| TransportError::UntrustedPeer)?;
    serve_connection_with_clock(stream, engine, &mut clock)
}

fn serve_connection_with_clock(
    stream: UnixStream,
    engine: &dyn Engine,
    clock: &mut dyn Clock,
) -> Result<(), TransportError> {
    let peer = Arc::new(Peer::from_socket(&stream).map_err(|_| TransportError::UntrustedPeer)?);
    let monitor = stream
        .try_clone()
        .map_err(|error| TransportError::Io(error.kind()))?;
    let mut socket = SocketConnection::new(stream)?;
    let mut session = Connection::new(
        fresh_id().map_err(|_| TransportError::UntrustedPeer)?,
        peer.uid(),
        clock
            .now()
            .map_err(|_| TransportError::UntrustedPeer)?
            .millis,
    );
    let lifetime = Instant::now() + CONNECTION_LIFETIME;
    socket.write_response(&session.hello(), Deadline::after(UNAVAILABLE_TIMEOUT))?;
    let mut challenged = None;
    for _ in 0..MAX_REQUESTS {
        let deadline = lifetime.min(Instant::now() + UNAVAILABLE_TIMEOUT);
        let request = socket.read_request(Deadline::at(deadline))?;
        let verifying = matches!(request.request, Request::Verify { .. });
        let mutation = matches!(
            request.request,
            Request::BeginEnroll { .. }
                | Request::EnrollConversation { .. }
                | Request::CommitEnrollment { .. }
                | Request::Disable { .. }
        );
        // A BeginEnroll transfers ownership of the connection to a single
        // bounded transaction. No grant survives returning from that handler.
        if mutation {
            if matches!(request.request, Request::BeginEnroll { .. }) {
                let expected = engine.check(peer.clone(), deadline).ok();
                if let Some(expected) =
                    expected.filter(|s| s.account().uid.get() == peer.uid() && peer.uid() != 0)
                {
                    let mut channel = EnrollmentIo::new(&mut socket, &mut session, &monitor)?;
                    return engine.enroll(peer.clone(), expected, request, &mut channel);
                }
            }
            let response = session.fail(ErrorCode::Unavailable);
            socket.write_response(&response, Deadline::at(deadline))?;
            return Ok(());
        }
        let eligible = if matches!(
            request.request,
            Request::BeginVerify | Request::Verify { .. }
        ) {
            engine
                .check(peer.clone(), deadline)
                .ok()
                .filter(|snapshot| snapshot.account().uid.get() == peer.uid() && peer.uid() != 0)
        } else {
            None
        };
        if matches!(request.request, Request::BeginVerify) {
            challenged = eligible;
        }
        let allowed = eligible.is_some() && (!verifying || eligible == challenged);
        let issued = if matches!(request.request, Request::BeginVerify) {
            Some(Issued::Verify(
                fresh_id().map_err(|_| TransportError::UntrustedPeer)?,
            ))
        } else {
            None
        };
        let action = match session.accept(
            request,
            clock
                .now()
                .map_err(|_| TransportError::UntrustedPeer)?
                .millis,
            if allowed {
                Eligibility::Eligible
            } else {
                Eligibility::Denied
            },
            issued,
        ) {
            Ok(action) => action,
            Err(error) => {
                socket.write_response(
                    &ResponseEnvelope {
                        connection: session.id(),
                        response: Response::Error(protocol_error(error)),
                    },
                    Deadline::at(deadline),
                )?;
                return Ok(());
            }
        };
        match action {
            ConnectionAction::ReadStatus { .. } => socket.write_response(
                &ResponseEnvelope {
                    connection: session.id(),
                    response: Response::Status(engine.status(peer.clone(), deadline)),
                },
                Deadline::at(deadline),
            )?,
            ConnectionAction::Reply(response) => {
                socket.write_response(&response, Deadline::at(deadline))?
            }
            ConnectionAction::Cancel => {
                socket.write_response(
                    &ResponseEnvelope {
                        connection: session.id(),
                        response: Response::Cancelled,
                    },
                    Deadline::at(deadline),
                )?;
                return Ok(());
            }
            ConnectionAction::Verify { pin, .. } => {
                let deadlines = VerificationDeadlines::for_request(deadline, lifetime);
                let mut write_result = Ok(());
                engine.verify(
                    peer.clone(),
                    eligible.ok_or(TransportError::UntrustedPeer)?,
                    pin,
                    deadlines,
                    &mut || pending(&monitor),
                    &mut |outcome, response_deadline| {
                        let now = clock.now().map(|time| time.millis).unwrap_or(u64::MAX);
                        let response = if pending(&monitor) {
                            match socket
                                .read_request(Deadline::at(response_deadline.min(deadlines.tpm)))
                            {
                                Ok(request) => {
                                    match session.accept(request, now, Eligibility::Denied, None) {
                                        Ok(ConnectionAction::Cancel) => Some(ResponseEnvelope {
                                            connection: session.id(),
                                            response: Response::Cancelled,
                                        }),
                                        _ => None,
                                    }
                                }
                                Err(_) => None,
                            }
                        } else {
                            session
                                .finish_verification(outcome, Eligibility::Eligible, now)
                                .ok()
                        };
                        if let Some(response) = response {
                            write_result = socket.write_response(
                                &response,
                                Deadline::at(response_deadline.min(deadlines.tpm)),
                            );
                        }
                    },
                );
                write_result?;
                return Ok(());
            }
            ConnectionAction::RecoverDisable { target_uid } => {
                let mut result = Ok(());
                engine.recover(
                    &peer,
                    Uid::new(target_uid).map_err(|_| TransportError::UntrustedPeer)?,
                    session.id(),
                    deadline,
                    &mut |recovery| {
                        let response = match recovery {
                            Ok(()) => session
                                .finish_mutation(
                                    Completion::RecoveryDisabled,
                                    Eligibility::Denied,
                                    clock.now().map(|time| time.millis).unwrap_or(u64::MAX),
                                )
                                .ok(),
                            Err(_) => Some(ResponseEnvelope {
                                connection: session.id(),
                                response: Response::Error(ErrorCode::Unavailable),
                            }),
                        };
                        if let Some(response) = response {
                            result = socket.write_response(&response, Deadline::at(deadline));
                        }
                    },
                );
                result?;
                return Ok(());
            }
            _ => return Err(TransportError::UntrustedPeer),
        }
    }
    session.close();
    Ok(())
}

#[cfg(test)]
mod tests;
