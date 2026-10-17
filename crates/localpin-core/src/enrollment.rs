//! Pure enrollment transactions and revocation fences, without host I/O.
//!
//! The broker must serialize these transitions with durable storage and response
//! delivery. A commit intent is not a successful disk commit. While its outcome
//! is unresolved, verification is unavailable; M3 must recover authoritative
//! state after a crash. Previously delivered authorization cannot be retracted.
//!
//! Account identity is supplied by a trusted lifecycle authority. UID, username,
//! and home-directory equality cannot establish account continuity. Production
//! use of unmanaged Unix accounts is refused until a lifecycle adapter has been
//! implemented and tested; the opaque incarnation here is a contract, not that
//! implementation.

use crate::eligibility::{EligibilityAuthority, EligibilityError, EligibilitySnapshot};
use crate::types::{
    AccountId, Backend, ConnectionId, Generation, Incarnation, TimePoint, TransactionId, Uid,
};

/// Maximum interval between trusted password authentication and durable commit.
pub const AUTHORIZATION_LIFETIME_MILLIS: u64 = 60_000;

/// Trusted lifecycle boundary; never populate it from client account fields.
pub trait LifecycleAuthority {
    /// Return a current, stable account incarnation from a tested lifecycle source.
    fn current_incarnation(&mut self, uid: Uid) -> Result<Incarnation, LifecycleError>;
}

/// Reasons the lifecycle authority cannot establish account continuity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LifecycleError {
    /// No tested lifecycle mechanism manages the account.
    Unsupported,
    /// The lifecycle mechanism is temporarily unavailable.
    Unavailable,
    /// The account no longer exists.
    AccountMissing,
}

/// Refuses current unmanaged Unix accounts instead of inventing an identity.
#[derive(Debug, Default)]
pub struct UnmanagedUnixAccounts;

impl LifecycleAuthority for UnmanagedUnixAccounts {
    fn current_incarnation(&mut self, _uid: Uid) -> Result<Incarnation, LifecycleError> {
        Err(LifecycleError::Unsupported)
    }
}

/// A committed generation and its current acceptance policy.
///
/// A disabled state still retains its generation/revision so old verification
/// results cannot be accepted after disable and subsequent enrollment.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CommittedState {
    account: AccountId,
    generation: Generation,
    revision: u64,
    backend: Option<Backend>,
}

impl CommittedState {
    /// Load trusted authoritative state, or establish a simulator's baseline.
    ///
    /// Storage must validate this state and reject rollback before construction.
    /// `None` denotes an unenrolled/disabled account. This performs no disk I/O.
    pub fn new(account: AccountId, generation: Generation, backend: Option<Backend>) -> Self {
        Self {
            account,
            generation,
            revision: generation.get(),
            backend,
        }
    }

    /// The account incarnation represented by the committed record.
    pub fn account(self) -> AccountId {
        self.account
    }

    /// The authoritative credential or revocation generation.
    pub fn generation(self) -> Generation {
        self.generation
    }

    /// The revision used to fence in-flight operations.
    pub fn revision(self) -> u64 {
        self.revision
    }

    /// The pinned backend, or `None` when PIN verification is disabled.
    pub fn backend(self) -> Option<Backend> {
        self.backend
    }
}

/// An enrollment change, distinct from administrative integration authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EnrollmentAction {
    /// Create a credential for a currently unenrolled account.
    Enroll(Backend),
    /// Replace the PIN while retaining the current backend.
    Rotate,
    /// Replace the credential with one on another explicitly selected backend.
    MigrateBackend(Backend),
    /// Disable PIN verification following fresh own-user password authorization.
    Disable,
    /// Root-authorized recovery revokes the credential without revealing a PIN.
    AdministrativeRecovery,
}

/// A transaction capability bound to one connection, account, and proposed change.
///
/// Fields are private and the sequence changes even when a caller reuses a
/// transaction ID. This value is broker state, not a serializable client grant.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransactionBinding {
    connection: ConnectionId,
    transaction: TransactionId,
    account: AccountId,
    action: EnrollmentAction,
    proposed_generation: Generation,
    sequence: u64,
}

impl TransactionBinding {
    /// The connection for which the broker created the transaction.
    pub fn connection(self) -> ConnectionId {
        self.connection
    }
    /// The broker transaction identifier.
    pub fn transaction(self) -> TransactionId {
        self.transaction
    }
    /// The account incarnation authorized by this transaction.
    pub fn account(self) -> AccountId {
        self.account
    }
    /// The specific authorized action.
    pub fn action(self) -> EnrollmentAction {
        self.action
    }
    /// The proposed credential or revocation generation.
    pub fn proposed_generation(self) -> Generation {
        self.proposed_generation
    }
}

/// A request sent only to a trusted, supervised password-only worker.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PasswordWorkerRequest {
    binding: TransactionBinding,
    started_at: TimePoint,
}

impl PasswordWorkerRequest {
    /// The complete connection/account/action/generation binding to authenticate.
    pub fn binding(self) -> TransactionBinding {
        self.binding
    }
    /// The trusted monotonic time when the worker operation started.
    pub fn started_at(self) -> TimePoint {
        self.started_at
    }
}

/// A trusted password-worker adapter, rather than a client authentication flag.
///
/// The broker invokes this boundary itself and stores the resulting grant only
/// inside the active transaction. An implementation must supervise a dedicated
/// password-only worker, bound its lifetime, validate its result against this
/// request, reject cancellation/late results, and stamp successful completion
/// with trusted boot/monotonic time. M2 provides no real PAM implementation.
pub trait PasswordWorker {
    /// Verify the existing account password, returning trusted completion time.
    fn verify_existing_password(
        &mut self,
        request: PasswordWorkerRequest,
    ) -> Result<TimePoint, PasswordWorkerError>;
}

/// Sanitized failures from the trusted password-only worker boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PasswordWorkerError {
    /// The existing account password was not accepted.
    Rejected,
    /// The worker or supported password-only policy was unavailable.
    Unavailable,
    /// The supervised worker exceeded its deadline.
    TimedOut,
    /// The operation was cancelled.
    Cancelled,
}

/// Administrative authority acquired from kernel peer credentials.
///
/// A future broker must supply the actual peer UID, never an IPC field. This is
/// root recovery authority only and does not authorize own-user enrollment or
/// installation/integration changes through this state machine.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Administrator {
    connection: ConnectionId,
}

impl Administrator {
    /// Acquire recovery authority for an explicitly root-owned connection.
    pub fn from_kernel_peer_uid(
        connection: ConnectionId,
        peer_uid: u32,
    ) -> Result<Self, EnrollmentError> {
        if peer_uid == 0 {
            Ok(Self { connection })
        } else {
            Err(EnrollmentError::AdministrativeAuthorityRequired)
        }
    }
}

/// An opaque storage instruction; only its durable acknowledgement commits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CommitIntent {
    binding: TransactionBinding,
    previous: CommittedState,
    next: CommittedState,
    expires_at: TimePoint,
    prepared_at: TimePoint,
}

impl CommitIntent {
    /// The transaction authorized to make this change.
    pub fn binding(self) -> TransactionBinding {
        self.binding
    }
    /// The committed state which storage must compare before replacement.
    pub fn previous(self) -> CommittedState {
        self.previous
    }
    /// The staged state to synchronize and atomically make authoritative.
    pub fn next(self) -> CommittedState {
        self.next
    }
    /// The strict deadline; a commit at this instant is already too late.
    pub fn expires_at(self) -> TimePoint {
        self.expires_at
    }
    /// Last checked model time; storage must reject rollback before finalization.
    pub fn prepared_at(self) -> TimePoint {
        self.prepared_at
    }
}

/// Captures credential and session identity before an in-flight verification.
///
/// It is not a successful PIN result or a durable throttle acknowledgement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerificationFence {
    state: CommittedState,
    eligibility: EligibilitySnapshot,
}

impl VerificationFence {
    /// The account incarnation checked before verification.
    pub fn account(self) -> AccountId {
        self.state.account
    }
    /// The credential generation checked before verification.
    pub fn generation(self) -> Generation {
        self.state.generation
    }
    /// The state revision checked before verification.
    pub fn revision(self) -> u64 {
        self.state.revision
    }
    /// The pinned credential backend checked before verification.
    pub fn backend(self) -> Backend {
        // A fence is constructed only when the backend is present.
        self.state
            .backend
            .expect("verification fence requires enrolled state")
    }
}

/// Sanitized transaction/fence failures; no credential material is carried.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EnrollmentError {
    /// Another transaction for this account is active.
    Busy,
    /// There is no active transaction.
    NoTransaction,
    /// The connection or transaction binding does not match.
    BindingMismatch,
    /// Own-user operations may only target the peer's own account.
    WrongPeer,
    /// Current lifecycle evidence does not match the recorded account.
    AccountChanged,
    /// Trusted account lifecycle evidence is unavailable or unsupported.
    Lifecycle(LifecycleError),
    /// This action is incompatible with the committed state or authority.
    InvalidAction,
    /// Explicit root peer authority is required for recovery.
    AdministrativeAuthorityRequired,
    /// A credential must be staged and successfully trial-verified first.
    StageNotVerified,
    /// A stage operation was requested out of order.
    InvalidStage,
    /// A trusted password-worker grant has not been acquired.
    PasswordAuthorizationRequired,
    /// The password worker refused or could not authorize the operation.
    PasswordWorker(PasswordWorkerError),
    /// The 60-second authorization interval expired.
    AuthorizationExpired,
    /// Boot changed, monotonic time regressed, or time overflowed.
    TimeAnomaly,
    /// The generation, revision, or transaction sequence cannot advance.
    GenerationExhausted,
    /// Storage may have committed; reconciliation is required before proceeding.
    CommitInProgress,
    /// PIN verification is not enabled in committed state.
    CredentialUnavailable,
    /// The credential/session has changed since verification began.
    VerificationRevoked,
    /// Current account or session eligibility failed.
    Eligibility(EligibilityError),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Stage {
    NotRequired,
    AwaitingCreation,
    Created,
    Verified,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Transaction {
    binding: TransactionBinding,
    backend: Option<Backend>,
    stage: Stage,
    authorization: Option<TimePoint>,
    last_time: TimePoint,
    time_invalid: bool,
    pending: Option<CommitIntent>,
}

/// One account's pure serialized enrollment/revocation state machine.
#[derive(Debug)]
pub struct EnrollmentMachine {
    committed: CommittedState,
    active: Option<Transaction>,
    sequence: u64,
}

impl EnrollmentMachine {
    /// Establish a simulator or load validated authoritative storage state.
    pub fn new(committed: CommittedState) -> Self {
        Self {
            committed,
            active: None,
            sequence: 0,
        }
    }

    /// Read current committed acceptance policy, without staged state.
    pub fn committed(&self) -> CommittedState {
        self.committed
    }

    /// Begin a fresh own-user change, checking current account continuity.
    pub fn begin_own_user(
        &mut self,
        connection: ConnectionId,
        peer: Uid,
        transaction: TransactionId,
        action: EnrollmentAction,
        now: TimePoint,
        lifecycle: &mut impl LifecycleAuthority,
    ) -> Result<TransactionBinding, EnrollmentError> {
        if peer != self.committed.account.uid {
            return Err(EnrollmentError::WrongPeer);
        }
        self.ensure_idle()?;
        check_lifecycle(self.committed.account, lifecycle)?;
        let backend = match (action, self.committed.backend) {
            (EnrollmentAction::Enroll(backend), None) => Some(backend),
            (EnrollmentAction::Rotate, Some(backend)) => Some(backend),
            (EnrollmentAction::MigrateBackend(target), Some(current)) if target != current => {
                Some(target)
            }
            (EnrollmentAction::Disable, Some(_)) => None,
            _ => return Err(EnrollmentError::InvalidAction),
        };
        self.begin(
            connection,
            transaction,
            self.committed.account,
            action,
            backend,
            now,
            None,
        )
    }

    /// Begin explicitly root-authorized recovery, revoking any old credential.
    ///
    /// A changed incarnation may be adopted only as a disabled new generation.
    /// Fresh own-user password authorization is still needed to enroll it later.
    pub fn begin_administrative_recovery(
        &mut self,
        connection: ConnectionId,
        administrator: Administrator,
        transaction: TransactionId,
        now: TimePoint,
        lifecycle: &mut impl LifecycleAuthority,
    ) -> Result<TransactionBinding, EnrollmentError> {
        if administrator.connection != connection {
            return Err(EnrollmentError::BindingMismatch);
        }
        self.ensure_idle()?;
        let account = AccountId {
            uid: self.committed.account.uid,
            incarnation: lifecycle
                .current_incarnation(self.committed.account.uid)
                .map_err(EnrollmentError::Lifecycle)?,
        };
        self.begin(
            connection,
            transaction,
            account,
            EnrollmentAction::AdministrativeRecovery,
            None,
            now,
            Some(now),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn begin(
        &mut self,
        connection: ConnectionId,
        transaction: TransactionId,
        account: AccountId,
        action: EnrollmentAction,
        backend: Option<Backend>,
        now: TimePoint,
        authorization: Option<TimePoint>,
    ) -> Result<TransactionBinding, EnrollmentError> {
        let proposed_generation = self
            .committed
            .generation
            .next()
            .map_err(|_| EnrollmentError::GenerationExhausted)?;
        let sequence = self
            .sequence
            .checked_add(1)
            .ok_or(EnrollmentError::GenerationExhausted)?;
        let binding = TransactionBinding {
            connection,
            transaction,
            account,
            action,
            proposed_generation,
            sequence,
        };
        self.active = Some(Transaction {
            binding,
            backend,
            stage: if backend.is_some() {
                Stage::AwaitingCreation
            } else {
                Stage::NotRequired
            },
            authorization,
            last_time: now,
            time_invalid: false,
            pending: None,
        });
        self.sequence = sequence;
        Ok(binding)
    }

    /// Invoke the trusted password worker and retain its grant internally.
    ///
    /// There is deliberately no method accepting a client `authenticated` flag.
    pub fn authorize_with_password_worker(
        &mut self,
        binding: TransactionBinding,
        connection: ConnectionId,
        started_at: TimePoint,
        worker: &mut impl PasswordWorker,
        lifecycle: &mut impl LifecycleAuthority,
    ) -> Result<(), EnrollmentError> {
        let transaction = self.active_mut(binding, connection)?;
        if transaction.binding.action == EnrollmentAction::AdministrativeRecovery {
            return Err(EnrollmentError::InvalidAction);
        }
        check_time(transaction, started_at)?;
        // A failed reauthentication cannot leave an earlier grant usable.
        transaction.authorization = None;
        check_lifecycle(binding.account, lifecycle)?;
        let authenticated_at = worker
            .verify_existing_password(PasswordWorkerRequest {
                binding,
                started_at,
            })
            .map_err(EnrollmentError::PasswordWorker)?;
        check_time(transaction, authenticated_at)?;
        authenticated_at
            .millis
            .checked_add(AUTHORIZATION_LIFETIME_MILLIS)
            .ok_or(EnrollmentError::TimeAnomaly)?;
        check_lifecycle(binding.account, lifecycle)?;
        transaction.authorization = Some(authenticated_at);
        Ok(())
    }

    /// Record creation of the proposed generation by trusted backend/storage code.
    ///
    /// Fresh password authorization and account continuity are required before
    /// staging. The broker must check this gate before invoking the backend;
    /// this internal transition must never be driven by a client claim.
    pub fn staged_created(
        &mut self,
        binding: TransactionBinding,
        connection: ConnectionId,
        now: TimePoint,
        lifecycle: &mut impl LifecycleAuthority,
    ) -> Result<(), EnrollmentError> {
        let transaction = self.active_mut(binding, connection)?;
        check_time(transaction, now)?;
        check_lifecycle(binding.account, lifecycle)?;
        check_authorization(transaction, now)?;
        if transaction.stage != Stage::AwaitingCreation {
            return Err(EnrollmentError::InvalidStage);
        }
        transaction.stage = Stage::Created;
        Ok(())
    }

    /// Record successful trial verification of that exact staged generation.
    ///
    /// The trusted backend must validate credential identity/metadata; no real
    /// credential verifier or client-provided stage-success flag exists in M2.
    /// Password authorization must still be fresh when verification completes.
    pub fn staged_verified(
        &mut self,
        binding: TransactionBinding,
        connection: ConnectionId,
        now: TimePoint,
        lifecycle: &mut impl LifecycleAuthority,
    ) -> Result<(), EnrollmentError> {
        let transaction = self.active_mut(binding, connection)?;
        check_time(transaction, now)?;
        check_lifecycle(binding.account, lifecycle)?;
        check_authorization(transaction, now)?;
        if transaction.stage != Stage::Created {
            return Err(EnrollmentError::InvalidStage);
        }
        transaction.stage = Stage::Verified;
        Ok(())
    }

    /// Prepare an authorized, verified state replacement for durable storage.
    ///
    /// Storage must compare `previous`, synchronize staged data, and atomically
    /// replace its authoritative pointer before acknowledging, within the strict
    /// deadline. Unresolved intent blocks all verification and new transactions.
    pub fn prepare_commit(
        &mut self,
        binding: TransactionBinding,
        connection: ConnectionId,
        now: TimePoint,
        lifecycle: &mut impl LifecycleAuthority,
    ) -> Result<CommitIntent, EnrollmentError> {
        let previous = self.committed;
        let transaction = self.active_mut(binding, connection)?;
        check_time(transaction, now)?;
        check_lifecycle(binding.account, lifecycle)?;
        let expires_at = check_authorization(transaction, now)?;
        if !matches!(transaction.stage, Stage::NotRequired | Stage::Verified) {
            return Err(EnrollmentError::StageNotVerified);
        }
        let next = CommittedState {
            account: binding.account,
            generation: binding.proposed_generation,
            revision: previous
                .revision
                .checked_add(1)
                .ok_or(EnrollmentError::GenerationExhausted)?,
            backend: transaction.backend,
        };
        let intent = CommitIntent {
            binding,
            previous,
            next,
            expires_at,
            prepared_at: now,
        };
        transaction.pending = Some(intent);
        Ok(intent)
    }

    /// Acknowledge actual durable storage commit and install its revocation fence.
    ///
    /// Only trusted storage integration may call this method. It performs no
    /// writes. Failure leaves the intent unresolved and PIN verification blocked;
    /// M3 must reconcile disk state before constructing another machine.
    pub fn acknowledge_durable_commit(
        &mut self,
        intent: CommitIntent,
        connection: ConnectionId,
        now: TimePoint,
        lifecycle: &mut impl LifecycleAuthority,
    ) -> Result<CommittedState, EnrollmentError> {
        let transaction = self.active.as_mut().ok_or(EnrollmentError::NoTransaction)?;
        if transaction.binding != intent.binding
            || connection != intent.binding.connection
            || transaction.pending != Some(intent)
        {
            return Err(EnrollmentError::BindingMismatch);
        }
        check_time(transaction, now)?;
        check_lifecycle(intent.binding.account, lifecycle)?;
        check_authorization(transaction, now)?;
        if self.committed != intent.previous {
            return Err(EnrollmentError::VerificationRevoked);
        }
        self.committed = intent.next;
        self.active = None;
        Ok(self.committed)
    }

    /// Cancel before storage has received a commit intent, preserving committed state.
    ///
    /// After an intent is issued, its storage outcome may be ambiguous and must
    /// be reconciled; cancellation cannot restore an old accepted credential.
    pub fn cancel(
        &mut self,
        binding: TransactionBinding,
        connection: ConnectionId,
    ) -> Result<(), EnrollmentError> {
        self.active_mut(binding, connection)?;
        self.active = None;
        Ok(())
    }

    /// Capture current credential and eligibility before backend verification.
    pub fn begin_verification(
        &self,
        eligibility: &mut impl EligibilityAuthority,
        lifecycle: &mut impl LifecycleAuthority,
    ) -> Result<VerificationFence, EnrollmentError> {
        self.ensure_no_pending_commit()?;
        if self.committed.backend.is_none() {
            return Err(EnrollmentError::CredentialUnavailable);
        }
        check_lifecycle(self.committed.account, lifecycle)?;
        let snapshot = eligibility
            .check(self.committed.account)
            .map_err(EnrollmentError::Eligibility)?;
        if snapshot.account() != self.committed.account {
            return Err(EnrollmentError::AccountChanged);
        }
        Ok(VerificationFence {
            state: self.committed,
            eligibility: snapshot,
        })
    }

    /// Recheck the generation, account, live session and account restrictions.
    ///
    /// The broker must call this immediately before delivery, under the same
    /// serialization as revocation, after durable throttle-success completion.
    /// Passing this predicate alone does not constitute successful authentication.
    pub fn revalidate_verification(
        &self,
        fence: VerificationFence,
        eligibility: &mut impl EligibilityAuthority,
        lifecycle: &mut impl LifecycleAuthority,
    ) -> Result<(), EnrollmentError> {
        self.ensure_no_pending_commit()?;
        if self.committed != fence.state {
            return Err(EnrollmentError::VerificationRevoked);
        }
        check_lifecycle(self.committed.account, lifecycle)?;
        let snapshot = eligibility
            .check(self.committed.account)
            .map_err(EnrollmentError::Eligibility)?;
        if snapshot != fence.eligibility {
            return Err(EnrollmentError::VerificationRevoked);
        }
        Ok(())
    }

    fn ensure_idle(&self) -> Result<(), EnrollmentError> {
        if self.active.is_some() {
            Err(EnrollmentError::Busy)
        } else {
            Ok(())
        }
    }

    fn ensure_no_pending_commit(&self) -> Result<(), EnrollmentError> {
        if self
            .active
            .is_some_and(|transaction| transaction.pending.is_some())
        {
            Err(EnrollmentError::CommitInProgress)
        } else {
            Ok(())
        }
    }

    fn active_mut(
        &mut self,
        binding: TransactionBinding,
        connection: ConnectionId,
    ) -> Result<&mut Transaction, EnrollmentError> {
        let transaction = self.active.as_mut().ok_or(EnrollmentError::NoTransaction)?;
        if transaction.binding != binding || binding.connection != connection {
            return Err(EnrollmentError::BindingMismatch);
        }
        if transaction.pending.is_some() {
            return Err(EnrollmentError::CommitInProgress);
        }
        Ok(transaction)
    }
}

fn check_lifecycle(
    account: AccountId,
    lifecycle: &mut impl LifecycleAuthority,
) -> Result<(), EnrollmentError> {
    let incarnation = lifecycle
        .current_incarnation(account.uid)
        .map_err(EnrollmentError::Lifecycle)?;
    if incarnation == account.incarnation {
        Ok(())
    } else {
        Err(EnrollmentError::AccountChanged)
    }
}

fn check_time(transaction: &mut Transaction, now: TimePoint) -> Result<(), EnrollmentError> {
    if transaction.time_invalid
        || now.boot != transaction.last_time.boot
        || now.millis < transaction.last_time.millis
    {
        // An incomparable clock cannot be repaired by presenting a later value.
        // Cancellation/restart requires a new transaction and fresh authority.
        transaction.authorization = None;
        transaction.time_invalid = true;
        return Err(EnrollmentError::TimeAnomaly);
    }
    transaction.last_time = now;
    Ok(())
}

fn check_authorization(
    transaction: &Transaction,
    now: TimePoint,
) -> Result<TimePoint, EnrollmentError> {
    let authorized = transaction
        .authorization
        .ok_or(EnrollmentError::PasswordAuthorizationRequired)?;
    let expires = authorized
        .millis
        .checked_add(AUTHORIZATION_LIFETIME_MILLIS)
        .ok_or(EnrollmentError::TimeAnomaly)?;
    if authorized.boot != now.boot || now.millis < authorized.millis {
        return Err(EnrollmentError::TimeAnomaly);
    }
    if now.millis >= expires {
        return Err(EnrollmentError::AuthorizationExpired);
    }
    Ok(TimePoint {
        boot: authorized.boot,
        millis: expires,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::eligibility::{SimulatedAccountPolicy, SimulatedRoute, tests as eligibility_tests};
    use crate::types::BootId;

    struct Managed(Result<Incarnation, LifecycleError>);
    impl LifecycleAuthority for Managed {
        fn current_incarnation(&mut self, _uid: Uid) -> Result<Incarnation, LifecycleError> {
            self.0
        }
    }

    struct Worker(
        Result<TimePoint, PasswordWorkerError>,
        Option<PasswordWorkerRequest>,
    );
    impl PasswordWorker for Worker {
        fn verify_existing_password(
            &mut self,
            request: PasswordWorkerRequest,
        ) -> Result<TimePoint, PasswordWorkerError> {
            self.1 = Some(request);
            self.0
        }
    }

    fn connection(id: u8) -> ConnectionId {
        ConnectionId::new([id; 16]).unwrap()
    }
    fn transaction(id: u8) -> TransactionId {
        TransactionId::new([id; 16]).unwrap()
    }
    fn now(millis: u64) -> TimePoint {
        TimePoint {
            boot: BootId::new([1; 16]).unwrap(),
            millis,
        }
    }

    fn machine(backend: Option<Backend>) -> (EnrollmentMachine, Managed) {
        let account = eligibility_tests::account(1000, 1);
        (
            EnrollmentMachine::new(CommittedState::new(
                account,
                Generation::new(1).unwrap(),
                backend,
            )),
            Managed(Ok(account.incarnation)),
        )
    }

    fn begin(
        machine: &mut EnrollmentMachine,
        lifecycle: &mut Managed,
        action: EnrollmentAction,
    ) -> TransactionBinding {
        machine
            .begin_own_user(
                connection(1),
                machine.committed.account.uid,
                transaction(1),
                action,
                now(0),
                lifecycle,
            )
            .unwrap()
    }

    fn stage(
        machine: &mut EnrollmentMachine,
        binding: TransactionBinding,
        lifecycle: &mut Managed,
    ) {
        machine
            .staged_created(binding, connection(1), now(1), lifecycle)
            .unwrap();
        machine
            .staged_verified(binding, connection(1), now(1), lifecycle)
            .unwrap();
    }

    fn authorize(
        machine: &mut EnrollmentMachine,
        binding: TransactionBinding,
        lifecycle: &mut Managed,
        millis: u64,
    ) {
        let mut worker = Worker(Ok(now(millis)), None);
        machine
            .authorize_with_password_worker(
                binding,
                connection(1),
                now(millis),
                &mut worker,
                lifecycle,
            )
            .unwrap();
        assert_eq!(worker.1.unwrap().binding(), binding);
    }

    fn commit(
        machine: &mut EnrollmentMachine,
        binding: TransactionBinding,
        lifecycle: &mut Managed,
        millis: u64,
    ) {
        let intent = machine
            .prepare_commit(binding, connection(1), now(millis), lifecycle)
            .unwrap();
        machine
            .acknowledge_durable_commit(intent, connection(1), now(millis), lifecycle)
            .unwrap();
    }

    #[test]
    fn enrollment_requires_worker_and_verified_stage_then_durable_ack() {
        let (mut machine, mut lifecycle) = machine(None);
        let old = machine.committed();
        let binding = begin(
            &mut machine,
            &mut lifecycle,
            EnrollmentAction::Enroll(Backend::Tpm2),
        );
        assert_eq!(
            machine.prepare_commit(binding, connection(1), now(0), &mut lifecycle),
            Err(EnrollmentError::PasswordAuthorizationRequired)
        );
        authorize(&mut machine, binding, &mut lifecycle, 1);
        assert_eq!(
            machine.prepare_commit(binding, connection(1), now(1), &mut lifecycle),
            Err(EnrollmentError::StageNotVerified)
        );
        assert_eq!(
            machine.staged_verified(binding, connection(1), now(1), &mut lifecycle),
            Err(EnrollmentError::InvalidStage)
        );
        stage(&mut machine, binding, &mut lifecycle);
        let intent = machine
            .prepare_commit(binding, connection(1), now(2), &mut lifecycle)
            .unwrap();
        assert_eq!(machine.committed(), old);
        assert_eq!(intent.previous(), old);
        assert_eq!(intent.next().backend(), Some(Backend::Tpm2));
        assert_eq!(intent.next().generation().get(), 2);
        machine
            .acknowledge_durable_commit(intent, connection(1), now(3), &mut lifecycle)
            .unwrap();
        assert_eq!(machine.committed(), intent.next());
        assert_eq!(
            machine.acknowledge_durable_commit(intent, connection(1), now(3), &mut lifecycle),
            Err(EnrollmentError::NoTransaction)
        );
    }

    #[test]
    fn staging_requires_fresh_password_authorization_for_every_credential_change() {
        for (backend, action) in [
            (None, EnrollmentAction::Enroll(Backend::Tpm2)),
            (Some(Backend::Tpm2), EnrollmentAction::Rotate),
            (
                Some(Backend::Tpm2),
                EnrollmentAction::MigrateBackend(Backend::Software),
            ),
        ] {
            let (mut machine, mut lifecycle) = machine(backend);
            let old = machine.committed();
            let binding = begin(&mut machine, &mut lifecycle, action);
            assert_eq!(
                machine.staged_created(binding, connection(1), now(0), &mut lifecycle),
                Err(EnrollmentError::PasswordAuthorizationRequired)
            );
            assert_eq!(
                machine.staged_verified(binding, connection(1), now(0), &mut lifecycle),
                Err(EnrollmentError::PasswordAuthorizationRequired)
            );
            assert_eq!(machine.active.unwrap().stage, Stage::AwaitingCreation);
            assert_eq!(machine.committed(), old);
            authorize(&mut machine, binding, &mut lifecycle, 1);
            stage(&mut machine, binding, &mut lifecycle);
        }
    }

    #[test]
    fn staging_and_trial_verification_each_enforce_the_strict_grant_deadline() {
        for elapsed in [0, 59_999, 60_000, 60_001] {
            let (mut machine, mut lifecycle) = machine(Some(Backend::Tpm2));
            let binding = begin(&mut machine, &mut lifecycle, EnrollmentAction::Rotate);
            authorize(&mut machine, binding, &mut lifecycle, 0);
            let created =
                machine.staged_created(binding, connection(1), now(elapsed), &mut lifecycle);
            assert_eq!(created.is_ok(), elapsed < AUTHORIZATION_LIFETIME_MILLIS);

            let (mut machine, mut lifecycle) = self::machine(Some(Backend::Tpm2));
            let binding = begin(&mut machine, &mut lifecycle, EnrollmentAction::Rotate);
            authorize(&mut machine, binding, &mut lifecycle, 0);
            machine
                .staged_created(binding, connection(1), now(0), &mut lifecycle)
                .unwrap();
            let verified =
                machine.staged_verified(binding, connection(1), now(elapsed), &mut lifecycle);
            assert_eq!(verified.is_ok(), elapsed < AUTHORIZATION_LIFETIME_MILLIS);
            if elapsed >= AUTHORIZATION_LIFETIME_MILLIS {
                assert_eq!(machine.active.unwrap().stage, Stage::Created);
            }
        }
    }

    #[test]
    fn staging_rechecks_lifecycle_before_creation_and_trial_verification() {
        for already_created in [false, true] {
            let (mut machine, mut lifecycle) = machine(Some(Backend::Tpm2));
            let binding = begin(&mut machine, &mut lifecycle, EnrollmentAction::Rotate);
            authorize(&mut machine, binding, &mut lifecycle, 0);
            if already_created {
                machine
                    .staged_created(binding, connection(1), now(0), &mut lifecycle)
                    .unwrap();
            }
            for (result, expected) in [
                (
                    Err(LifecycleError::Unavailable),
                    EnrollmentError::Lifecycle(LifecycleError::Unavailable),
                ),
                (
                    Ok(Incarnation::new([2; 16]).unwrap()),
                    EnrollmentError::AccountChanged,
                ),
            ] {
                lifecycle.0 = result;
                let result = if already_created {
                    machine.staged_verified(binding, connection(1), now(1), &mut lifecycle)
                } else {
                    machine.staged_created(binding, connection(1), now(1), &mut lifecycle)
                };
                assert_eq!(result, Err(expected));
            }
            assert_eq!(machine.committed().generation().get(), 1);
        }
    }

    #[test]
    fn grants_are_strictly_shorter_than_sixty_seconds() {
        for elapsed in [0, 1, 59_999, 60_000, 60_001, 1_000_000] {
            let (mut machine, mut lifecycle) = machine(Some(Backend::Tpm2));
            let binding = begin(&mut machine, &mut lifecycle, EnrollmentAction::Disable);
            authorize(&mut machine, binding, &mut lifecycle, 10);
            let result =
                machine.prepare_commit(binding, connection(1), now(10 + elapsed), &mut lifecycle);
            assert_eq!(result.is_ok(), elapsed < AUTHORIZATION_LIFETIME_MILLIS);
        }
    }

    #[test]
    fn commit_ack_must_remain_fresh_and_unresolved_commit_blocks_verification() {
        let (mut machine, mut lifecycle) = machine(Some(Backend::Tpm2));
        let mut eligibility = eligibility_tests::authority(machine.committed.account);
        let fence = machine
            .begin_verification(&mut eligibility, &mut lifecycle)
            .unwrap();
        let binding = begin(&mut machine, &mut lifecycle, EnrollmentAction::Disable);
        authorize(&mut machine, binding, &mut lifecycle, 0);
        let old = machine.committed();
        let intent = machine
            .prepare_commit(binding, connection(1), now(59_999), &mut lifecycle)
            .unwrap();
        assert_eq!(
            machine.begin_verification(&mut eligibility, &mut lifecycle),
            Err(EnrollmentError::CommitInProgress)
        );
        assert_eq!(
            machine.revalidate_verification(fence, &mut eligibility, &mut lifecycle),
            Err(EnrollmentError::CommitInProgress)
        );
        assert_eq!(
            machine.cancel(binding, connection(1)),
            Err(EnrollmentError::CommitInProgress)
        );
        assert_eq!(
            machine.acknowledge_durable_commit(intent, connection(1), now(60_000), &mut lifecycle),
            Err(EnrollmentError::AuthorizationExpired)
        );
        assert_eq!(machine.committed(), old);
        assert_eq!(
            machine.begin_verification(&mut eligibility, &mut lifecycle),
            Err(EnrollmentError::CommitInProgress)
        );
    }

    #[test]
    fn cancellation_at_every_precommit_stage_preserves_committed_state() {
        for progress in 0..4 {
            let (mut machine, mut lifecycle) = machine(Some(Backend::Tpm2));
            let old = machine.committed();
            let binding = begin(&mut machine, &mut lifecycle, EnrollmentAction::Rotate);
            if progress >= 1 {
                authorize(&mut machine, binding, &mut lifecycle, 1);
            }
            if progress >= 2 {
                machine
                    .staged_created(binding, connection(1), now(1), &mut lifecycle)
                    .unwrap();
            }
            if progress >= 3 {
                machine
                    .staged_verified(binding, connection(1), now(1), &mut lifecycle)
                    .unwrap();
            }
            machine.cancel(binding, connection(1)).unwrap();
            assert_eq!(machine.committed(), old);
            assert_eq!(
                machine.staged_created(binding, connection(1), now(1), &mut lifecycle),
                Err(EnrollmentError::NoTransaction)
            );
        }
    }

    #[test]
    fn stale_bindings_and_foreign_connections_never_change_state() {
        let (mut machine, mut lifecycle) = machine(Some(Backend::Tpm2));
        let binding = begin(&mut machine, &mut lifecycle, EnrollmentAction::Rotate);
        assert_eq!(
            machine.cancel(binding, connection(2)),
            Err(EnrollmentError::BindingMismatch)
        );
        assert_eq!(
            machine.staged_created(binding, connection(2), now(1), &mut lifecycle),
            Err(EnrollmentError::BindingMismatch)
        );
        machine.cancel(binding, connection(1)).unwrap();
        let replacement = begin(&mut machine, &mut lifecycle, EnrollmentAction::Rotate);
        assert_ne!(replacement, binding);
        assert_eq!(
            machine.staged_created(binding, connection(1), now(1), &mut lifecycle),
            Err(EnrollmentError::BindingMismatch)
        );
        let mut worker = Worker(Ok(now(0)), None);
        assert_eq!(
            machine.authorize_with_password_worker(
                binding,
                connection(1),
                now(0),
                &mut worker,
                &mut lifecycle
            ),
            Err(EnrollmentError::BindingMismatch)
        );
        assert!(worker.1.is_none());
    }

    #[test]
    fn failed_or_cancelled_workers_do_not_grant_authorization() {
        for failure in [
            PasswordWorkerError::Rejected,
            PasswordWorkerError::Unavailable,
            PasswordWorkerError::TimedOut,
            PasswordWorkerError::Cancelled,
        ] {
            let (mut machine, mut lifecycle) = machine(Some(Backend::Tpm2));
            let binding = begin(&mut machine, &mut lifecycle, EnrollmentAction::Disable);
            authorize(&mut machine, binding, &mut lifecycle, 0);
            let mut worker = Worker(Err(failure), None);
            assert_eq!(
                machine.authorize_with_password_worker(
                    binding,
                    connection(1),
                    now(1),
                    &mut worker,
                    &mut lifecycle
                ),
                Err(EnrollmentError::PasswordWorker(failure))
            );
            assert_eq!(
                machine.prepare_commit(binding, connection(1), now(1), &mut lifecycle),
                Err(EnrollmentError::PasswordAuthorizationRequired)
            );
        }
    }

    #[test]
    fn boot_changes_rollbacks_and_overflow_fail_closed() {
        for bad_time in [
            TimePoint {
                boot: BootId::new([2; 16]).unwrap(),
                millis: 11,
            },
            now(9),
            now(u64::MAX),
        ] {
            let (mut machine, mut lifecycle) = machine(Some(Backend::Tpm2));
            let binding = begin(&mut machine, &mut lifecycle, EnrollmentAction::Disable);
            let mut worker = Worker(Ok(bad_time), None);
            assert_eq!(
                machine.authorize_with_password_worker(
                    binding,
                    connection(1),
                    now(10),
                    &mut worker,
                    &mut lifecycle
                ),
                Err(EnrollmentError::TimeAnomaly)
            );
            assert_eq!(machine.committed().generation().get(), 1);
        }
        let (mut machine, mut lifecycle) = machine(Some(Backend::Tpm2));
        let binding = begin(&mut machine, &mut lifecycle, EnrollmentAction::Disable);
        authorize(&mut machine, binding, &mut lifecycle, 10);
        assert_eq!(
            machine.prepare_commit(binding, connection(1), now(9), &mut lifecycle),
            Err(EnrollmentError::TimeAnomaly)
        );
        assert_eq!(
            machine.prepare_commit(binding, connection(1), now(10), &mut lifecycle),
            Err(EnrollmentError::TimeAnomaly)
        );
        let mut worker = Worker(Ok(now(11)), None);
        assert_eq!(
            machine.authorize_with_password_worker(
                binding,
                connection(1),
                now(11),
                &mut worker,
                &mut lifecycle
            ),
            Err(EnrollmentError::TimeAnomaly)
        );
        assert!(worker.1.is_none());
    }

    #[test]
    fn every_binding_component_is_fenced_before_worker_or_stage_use() {
        let (mut machine, mut lifecycle) = machine(Some(Backend::Tpm2));
        let binding = begin(&mut machine, &mut lifecycle, EnrollmentAction::Rotate);
        let mut variants = [binding; 6];
        variants[0].connection = connection(2);
        variants[1].transaction = transaction(2);
        variants[2].account = eligibility_tests::account(1000, 2);
        variants[3].action = EnrollmentAction::Disable;
        variants[4].proposed_generation = Generation::new(3).unwrap();
        variants[5].sequence += 1;
        for changed in variants {
            let mut worker = Worker(Ok(now(0)), None);
            assert_eq!(
                machine.authorize_with_password_worker(
                    changed,
                    connection(1),
                    now(0),
                    &mut worker,
                    &mut lifecycle
                ),
                Err(EnrollmentError::BindingMismatch)
            );
            assert!(worker.1.is_none());
            assert_eq!(
                machine.staged_created(changed, connection(1), now(1), &mut lifecycle),
                Err(EnrollmentError::BindingMismatch)
            );
        }
    }

    #[test]
    fn unavailable_lifecycle_never_reaches_the_password_worker() {
        for error in [
            LifecycleError::Unsupported,
            LifecycleError::Unavailable,
            LifecycleError::AccountMissing,
        ] {
            let (mut machine, mut lifecycle) = machine(Some(Backend::Tpm2));
            let binding = begin(&mut machine, &mut lifecycle, EnrollmentAction::Disable);
            lifecycle.0 = Err(error);
            let mut worker = Worker(Ok(now(1)), None);
            assert_eq!(
                machine.authorize_with_password_worker(
                    binding,
                    connection(1),
                    now(1),
                    &mut worker,
                    &mut lifecycle
                ),
                Err(EnrollmentError::Lifecycle(error))
            );
            assert!(worker.1.is_none());
            assert_eq!(machine.committed().backend(), Some(Backend::Tpm2));
        }
    }

    #[test]
    fn unavailable_and_reused_accounts_are_refused_at_every_finalization() {
        let (mut machine, mut lifecycle) = machine(Some(Backend::Tpm2));
        assert_eq!(
            machine.begin_own_user(
                connection(1),
                machine.committed.account.uid,
                transaction(1),
                EnrollmentAction::Rotate,
                now(0),
                &mut UnmanagedUnixAccounts
            ),
            Err(EnrollmentError::Lifecycle(LifecycleError::Unsupported))
        );
        let binding = begin(&mut machine, &mut lifecycle, EnrollmentAction::Disable);
        authorize(&mut machine, binding, &mut lifecycle, 1);
        lifecycle.0 = Err(LifecycleError::Unavailable);
        assert_eq!(
            machine.prepare_commit(binding, connection(1), now(2), &mut lifecycle),
            Err(EnrollmentError::Lifecycle(LifecycleError::Unavailable))
        );
        lifecycle.0 = Ok(Incarnation::new([2; 16]).unwrap());
        assert_eq!(
            machine.prepare_commit(binding, connection(1), now(3), &mut lifecycle),
            Err(EnrollmentError::AccountChanged)
        );
        lifecycle.0 = Ok(machine.committed.account.incarnation);
        let intent = machine
            .prepare_commit(binding, connection(1), now(4), &mut lifecycle)
            .unwrap();
        lifecycle.0 = Ok(Incarnation::new([2; 16]).unwrap());
        assert_eq!(
            machine.acknowledge_durable_commit(intent, connection(1), now(5), &mut lifecycle),
            Err(EnrollmentError::AccountChanged)
        );
        assert_eq!(machine.committed().backend(), Some(Backend::Tpm2));
    }

    #[test]
    fn rotation_migration_disable_and_recovery_revoke_all_old_fences() {
        for action in [
            EnrollmentAction::Rotate,
            EnrollmentAction::MigrateBackend(Backend::Software),
            EnrollmentAction::Disable,
            EnrollmentAction::AdministrativeRecovery,
        ] {
            let (mut machine, mut lifecycle) = machine(Some(Backend::Tpm2));
            let mut eligibility = eligibility_tests::authority(machine.committed.account);
            let fence = machine
                .begin_verification(&mut eligibility, &mut lifecycle)
                .unwrap();
            let binding = if action == EnrollmentAction::AdministrativeRecovery {
                let administrator = Administrator::from_kernel_peer_uid(connection(1), 0).unwrap();
                machine
                    .begin_administrative_recovery(
                        connection(1),
                        administrator,
                        transaction(1),
                        now(0),
                        &mut lifecycle,
                    )
                    .unwrap()
            } else {
                let binding = begin(&mut machine, &mut lifecycle, action);
                authorize(&mut machine, binding, &mut lifecycle, 1);
                binding
            };
            if matches!(
                action,
                EnrollmentAction::Rotate | EnrollmentAction::MigrateBackend(_)
            ) {
                stage(&mut machine, binding, &mut lifecycle);
            }
            assert!(
                machine
                    .revalidate_verification(fence, &mut eligibility, &mut lifecycle)
                    .is_ok()
            );
            commit(&mut machine, binding, &mut lifecycle, 2);
            assert_eq!(
                machine.revalidate_verification(fence, &mut eligibility, &mut lifecycle),
                Err(EnrollmentError::VerificationRevoked)
            );
            assert_eq!(machine.committed().revision(), 2);
        }
    }

    #[test]
    fn eligibility_account_and_session_are_rechecked_before_delivery() {
        let (machine, mut lifecycle) = machine(Some(Backend::Tpm2));
        let account = machine.committed.account;
        let mut eligibility = eligibility_tests::authority(account);
        let fence = machine
            .begin_verification(&mut eligibility, &mut lifecycle)
            .unwrap();
        eligibility.policy = SimulatedAccountPolicy::Locked;
        assert_eq!(
            machine.revalidate_verification(fence, &mut eligibility, &mut lifecycle),
            Err(EnrollmentError::Eligibility(
                EligibilityError::AccountRestricted
            ))
        );
        eligibility.policy = SimulatedAccountPolicy::Allowed;
        eligibility.route = SimulatedRoute::Direct(eligibility_tests::session(account, 2));
        assert_eq!(
            machine.revalidate_verification(fence, &mut eligibility, &mut lifecycle),
            Err(EnrollmentError::VerificationRevoked)
        );
        eligibility.route = SimulatedRoute::Unavailable;
        assert_eq!(
            machine.revalidate_verification(fence, &mut eligibility, &mut lifecycle),
            Err(EnrollmentError::Eligibility(EligibilityError::Unavailable))
        );
        lifecycle.0 = Ok(Incarnation::new([2; 16]).unwrap());
        assert_eq!(
            machine.revalidate_verification(fence, &mut eligibility, &mut lifecycle),
            Err(EnrollmentError::AccountChanged)
        );
    }

    #[test]
    fn root_recovery_can_only_adopt_replacement_as_disabled() {
        let (mut machine, mut lifecycle) = machine(Some(Backend::Tpm2));
        assert_eq!(
            Administrator::from_kernel_peer_uid(connection(1), 1000),
            Err(EnrollmentError::AdministrativeAuthorityRequired)
        );
        let administrator = Administrator::from_kernel_peer_uid(connection(1), 0).unwrap();
        assert_eq!(
            machine.begin_administrative_recovery(
                connection(2),
                administrator,
                transaction(1),
                now(0),
                &mut lifecycle
            ),
            Err(EnrollmentError::BindingMismatch)
        );
        lifecycle.0 = Ok(Incarnation::new([2; 16]).unwrap());
        assert_eq!(
            machine.begin_own_user(
                connection(1),
                machine.committed.account.uid,
                transaction(1),
                EnrollmentAction::Rotate,
                now(0),
                &mut lifecycle
            ),
            Err(EnrollmentError::AccountChanged)
        );
        let binding = machine
            .begin_administrative_recovery(
                connection(1),
                administrator,
                transaction(1),
                now(0),
                &mut lifecycle,
            )
            .unwrap();
        assert_eq!(
            binding.account().incarnation,
            Incarnation::new([2; 16]).unwrap()
        );
        commit(&mut machine, binding, &mut lifecycle, 1);
        assert_eq!(machine.committed().backend(), None);
        let binding = begin(
            &mut machine,
            &mut lifecycle,
            EnrollmentAction::Enroll(Backend::Software),
        );
        assert_eq!(
            machine.staged_created(binding, connection(1), now(1), &mut lifecycle),
            Err(EnrollmentError::PasswordAuthorizationRequired)
        );
        assert_eq!(
            machine.prepare_commit(binding, connection(1), now(2), &mut lifecycle),
            Err(EnrollmentError::PasswordAuthorizationRequired)
        );
    }

    #[test]
    fn wrong_peer_incompatible_actions_and_generation_exhaustion_are_refused() {
        let (mut machine, mut lifecycle) = machine(Some(Backend::Tpm2));
        assert_eq!(
            machine.begin_own_user(
                connection(1),
                Uid::new(1001).unwrap(),
                transaction(1),
                EnrollmentAction::Rotate,
                now(0),
                &mut lifecycle
            ),
            Err(EnrollmentError::WrongPeer)
        );
        for action in [
            EnrollmentAction::Enroll(Backend::Software),
            EnrollmentAction::MigrateBackend(Backend::Tpm2),
            EnrollmentAction::AdministrativeRecovery,
        ] {
            assert_eq!(
                machine.begin_own_user(
                    connection(1),
                    machine.committed.account.uid,
                    transaction(1),
                    action,
                    now(0),
                    &mut lifecycle
                ),
                Err(EnrollmentError::InvalidAction)
            );
        }
        machine.committed.generation = Generation::new(u64::MAX).unwrap();
        assert_eq!(
            machine.begin_own_user(
                connection(1),
                machine.committed.account.uid,
                transaction(1),
                EnrollmentAction::Rotate,
                now(0),
                &mut lifecycle
            ),
            Err(EnrollmentError::GenerationExhausted)
        );
    }

    #[test]
    fn repeated_changes_never_reaccept_an_older_generation() {
        let (mut machine, mut lifecycle) = machine(Some(Backend::Tpm2));
        let mut eligibility = eligibility_tests::authority(machine.committed.account);
        let mut old_fences = Vec::new();
        for generation in 1..=100 {
            old_fences.push(
                machine
                    .begin_verification(&mut eligibility, &mut lifecycle)
                    .unwrap(),
            );
            let binding = begin(&mut machine, &mut lifecycle, EnrollmentAction::Rotate);
            authorize(&mut machine, binding, &mut lifecycle, 1);
            stage(&mut machine, binding, &mut lifecycle);
            commit(&mut machine, binding, &mut lifecycle, 2);
            assert_eq!(machine.committed().generation().get(), generation + 1);
            for fence in &old_fences {
                assert_eq!(
                    machine.revalidate_verification(*fence, &mut eligibility, &mut lifecycle),
                    Err(EnrollmentError::VerificationRevoked)
                );
            }
        }
    }
}
