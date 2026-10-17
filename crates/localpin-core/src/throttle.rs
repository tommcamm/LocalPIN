//! Pure, bounded attempt accounting and the durable verification lifecycle.
//!
//! The store implementation must hold the authoritative account/UID lock across
//! reservation, verification, and completion. The mutable borrow held by the
//! phase types additionally prevents concurrent use of one in-memory machine.
//! The filesystem adapter lives in `localpin-storage`; this crate supplies no
//! verifier. A store acknowledgement remains a trusted durability boundary.

use crate::types::{AccountId, BootId, Generation, Incarnation, TimePoint, Uid};

/// Version of the bounded throttle record.
pub const THROTTLE_VERSION: u16 = 1;
/// Canonical version 1 record length, including the magic and version header.
pub const THROTTLE_ENCODED_LEN: usize = 150;
/// Maximum submitted PIN-format attempts in the rolling window.
pub const ATTEMPT_LIMIT: usize = 5;
/// Length of the half-open rolling window, in milliseconds.
pub const WINDOW_MILLIS: u64 = 60_000;
/// Cooldown installed by the fifth reservation, in milliseconds.
pub const COOLDOWN_MILLIS: u64 = 300_000;

/// A reservation identifier scoped to one account and credential generation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AttemptId(u64);

impl AttemptId {
    /// Numeric value for a bounded storage codec.
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Persisted evidence that backend work may have started.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PendingReservation {
    /// Identifier of the consumed attempt.
    pub attempt: u64,
    /// Submission time on the record's boot.
    pub millis: u64,
}

/// Fixed-size version 1 data passed to a future protected storage codec.
///
/// Public fields permit decoding, not bypassing validation: use
/// [`Throttle::restore`] before making any policy decision. Unused timestamp
/// slots must be zero. No PIN or backend verifier material belongs in this record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ThrottleRecord {
    /// Record format version.
    pub version: u16,
    /// Account incarnation to which the attempt budget belongs.
    pub account: AccountId,
    /// Credential generation to which the record belongs.
    pub generation: Generation,
    /// Monotonically increasing storage revision for conditional replacement.
    pub revision: u64,
    /// Boot on which the monotonic timestamps were measured.
    pub boot: BootId,
    /// Last durably recorded monotonic observation.
    pub observed_millis: u64,
    /// Ascending submission timestamps; only the first `recent_len` are used.
    pub recent: [u64; ATTEMPT_LIMIT],
    /// Number of used recent timestamp slots.
    pub recent_len: u8,
    /// Cooldown origin on `boot`, retained even after recent attempts are pruned.
    pub cooldown_started_millis: Option<u64>,
    /// Cooldown expiry on `boot`, exactly one full interval after its origin.
    pub cooldown_until_millis: Option<u64>,
    /// Last allocated reservation identifier; never reset by success or reboot.
    pub last_attempt: u64,
    /// An unresolved reservation remains consumed after a crash.
    pub pending: Option<PendingReservation>,
}

impl ThrottleRecord {
    /// Construct initial enrollment data, which must be durably stored before use.
    ///
    /// This is deliberately a record constructor, not an authenticating machine.
    /// Missing required state must never be replaced with this value during
    /// verification recovery.
    pub const fn initial(account: AccountId, generation: Generation, now: TimePoint) -> Self {
        Self {
            version: THROTTLE_VERSION,
            account,
            generation,
            revision: 0,
            boot: now.boot,
            observed_millis: now.millis,
            recent: [0; ATTEMPT_LIMIT],
            recent_len: 0,
            cooldown_started_millis: None,
            cooldown_until_millis: None,
            last_attempt: 0,
            pending: None,
        }
    }

    /// Encode the entire validated record into a canonical fixed-size envelope.
    ///
    /// Every integer is big-endian. The layout is `LPTH`, version, UID,
    /// incarnation, generation, revision, boot ID, observation, recent length,
    /// five timestamps, cooldown-origin tag/value, cooldown-expiry tag/value,
    /// last-attempt counter, pending tag, pending counter, pending timestamp.
    /// Absent option payloads are zero; cooldown options must be present together.
    /// These development contracts still require M3 protected-storage review.
    pub fn encode(self) -> Result<[u8; THROTTLE_ENCODED_LEN], PolicyError> {
        self.validate(self.account, self.generation)?;
        let mut bytes = [0; THROTTLE_ENCODED_LEN];
        bytes[..4].copy_from_slice(b"LPTH");
        bytes[4..6].copy_from_slice(&self.version.to_be_bytes());
        bytes[6..10].copy_from_slice(&self.account.uid.get().to_be_bytes());
        bytes[10..26].copy_from_slice(&self.account.incarnation.get());
        bytes[26..34].copy_from_slice(&self.generation.get().to_be_bytes());
        bytes[34..42].copy_from_slice(&self.revision.to_be_bytes());
        bytes[42..58].copy_from_slice(&self.boot.get());
        bytes[58..66].copy_from_slice(&self.observed_millis.to_be_bytes());
        bytes[66] = self.recent_len;
        for (index, time) in self.recent.iter().enumerate() {
            let start = 67 + index * 8;
            bytes[start..start + 8].copy_from_slice(&time.to_be_bytes());
        }
        if let Some(started) = self.cooldown_started_millis {
            bytes[107] = 1;
            bytes[108..116].copy_from_slice(&started.to_be_bytes());
        }
        if let Some(until) = self.cooldown_until_millis {
            bytes[116] = 1;
            bytes[117..125].copy_from_slice(&until.to_be_bytes());
        }
        bytes[125..133].copy_from_slice(&self.last_attempt.to_be_bytes());
        if let Some(pending) = self.pending {
            bytes[133] = 1;
            bytes[134..142].copy_from_slice(&pending.attempt.to_be_bytes());
            bytes[142..150].copy_from_slice(&pending.millis.to_be_bytes());
        }
        Ok(bytes)
    }

    /// Decode one whole bounded envelope without allocation or extensions.
    ///
    /// The maximum size and exact version 1 length are checked before reading
    /// or copying any field. This checks structural invariants; `restore` must
    /// additionally compare the trusted expected account and generation.
    pub fn decode(bytes: &[u8]) -> Result<Self, ThrottleRecordError> {
        if bytes.len() > crate::limits::MAX_THROTTLE_BYTES {
            return Err(ThrottleRecordError::Oversized);
        }
        if bytes.len() != THROTTLE_ENCODED_LEN || bytes.get(..4) != Some(b"LPTH") {
            return Err(ThrottleRecordError::Encoding);
        }
        let version = u16::from_be_bytes(read_field(bytes, 4)?);
        if version != THROTTLE_VERSION {
            return Err(ThrottleRecordError::Policy(PolicyError::UnsupportedVersion));
        }
        let uid = Uid::new(u32::from_be_bytes(read_field(bytes, 6)?))
            .map_err(|_| ThrottleRecordError::Encoding)?;
        let incarnation =
            Incarnation::new(read_field(bytes, 10)?).map_err(|_| ThrottleRecordError::Encoding)?;
        let generation = Generation::new(u64::from_be_bytes(read_field(bytes, 26)?))
            .map_err(|_| ThrottleRecordError::Encoding)?;
        let boot =
            BootId::new(read_field(bytes, 42)?).map_err(|_| ThrottleRecordError::Encoding)?;
        let mut recent = [0; ATTEMPT_LIMIT];
        for (index, time) in recent.iter_mut().enumerate() {
            *time = u64::from_be_bytes(read_field(bytes, 67 + index * 8)?);
        }
        let cooldown_started_value = u64::from_be_bytes(read_field(bytes, 108)?);
        let cooldown_started_millis = match (bytes[107], cooldown_started_value) {
            (0, 0) => None,
            (1, started) => Some(started),
            _ => return Err(ThrottleRecordError::Encoding),
        };
        let cooldown_value = u64::from_be_bytes(read_field(bytes, 117)?);
        let cooldown_until_millis = match (bytes[116], cooldown_value) {
            (0, 0) => None,
            (1, until) => Some(until),
            _ => return Err(ThrottleRecordError::Encoding),
        };
        let pending_attempt = u64::from_be_bytes(read_field(bytes, 134)?);
        let pending_millis = u64::from_be_bytes(read_field(bytes, 142)?);
        let pending = match (bytes[133], pending_attempt, pending_millis) {
            (0, 0, 0) => None,
            (1, attempt, millis) => Some(PendingReservation { attempt, millis }),
            _ => return Err(ThrottleRecordError::Encoding),
        };
        let record = Self {
            version,
            account: AccountId { uid, incarnation },
            generation,
            revision: u64::from_be_bytes(read_field(bytes, 34)?),
            boot,
            observed_millis: u64::from_be_bytes(read_field(bytes, 58)?),
            recent,
            recent_len: bytes[66],
            cooldown_started_millis,
            cooldown_until_millis,
            last_attempt: u64::from_be_bytes(read_field(bytes, 125)?),
            pending,
        };
        record
            .validate(record.account, record.generation)
            .map_err(ThrottleRecordError::Policy)?;
        Ok(record)
    }

    fn validate(self, account: AccountId, generation: Generation) -> Result<(), PolicyError> {
        if self.version != THROTTLE_VERSION {
            return Err(PolicyError::UnsupportedVersion);
        }
        if self.account != account {
            return Err(PolicyError::WrongAccount);
        }
        if self.generation != generation {
            return Err(PolicyError::WrongGeneration);
        }
        let len = usize::from(self.recent_len);
        if len > ATTEMPT_LIMIT
            || self.recent[len..].iter().any(|&time| time != 0)
            || self.recent[..len].windows(2).any(|pair| pair[0] > pair[1])
            || self.recent[..len]
                .iter()
                .any(|&time| time > self.observed_millis)
            || self.last_attempt < u64::from(self.recent_len)
        {
            return Err(PolicyError::InvalidRecord);
        }
        match (self.cooldown_started_millis, self.cooldown_until_millis) {
            (None, None) => {}
            (Some(started), Some(until))
                if started <= self.observed_millis
                    && started.checked_add(COOLDOWN_MILLIS) == Some(until)
                    && (len == 0 || self.recent[len - 1] == started)
                    && self.last_attempt != 0 => {}
            _ => return Err(PolicyError::InvalidRecord),
        }
        if len == ATTEMPT_LIMIT && self.cooldown_until_millis.is_none() {
            return Err(PolicyError::InvalidRecord);
        }
        if let Some(pending) = self.pending
            && (pending.attempt == 0
                || pending.attempt != self.last_attempt
                || len == 0
                || self.recent[len - 1] != pending.millis)
        {
            return Err(PolicyError::InvalidRecord);
        }
        Ok(())
    }

    fn advance_revision(&mut self) -> Result<(), PolicyError> {
        self.revision = self
            .revision
            .checked_add(1)
            .ok_or(PolicyError::TimeOrCounterOverflow)?;
        Ok(())
    }

    fn prune(&mut self, now: u64) {
        let mut retained = [0; ATTEMPT_LIMIT];
        let mut len = 0;
        for &time in &self.recent[..usize::from(self.recent_len)] {
            // All callers checked monotonic order before entering here.
            if now - time < WINDOW_MILLIS {
                retained[len] = time;
                len += 1;
            }
        }
        self.recent = retained;
        self.recent_len = len as u8;
        if self.cooldown_until_millis.is_some_and(|until| until <= now) {
            self.cooldown_started_millis = None;
            self.cooldown_until_millis = None;
        }
    }
}

fn read_field<const N: usize>(bytes: &[u8], start: usize) -> Result<[u8; N], ThrottleRecordError> {
    let end = start.checked_add(N).ok_or(ThrottleRecordError::Encoding)?;
    bytes
        .get(start..end)
        .ok_or(ThrottleRecordError::Encoding)?
        .try_into()
        .map_err(|_| ThrottleRecordError::Encoding)
}

/// Sanitized bounded-record parsing failures, containing no record bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ThrottleRecordError {
    /// Input exceeds the 16 KiB throttle-record limit.
    Oversized,
    /// Wrong size, magic, identifier, option tag, or noncanonical option payload.
    Encoding,
    /// The recognized envelope violates throttle policy invariants.
    Policy(PolicyError),
}

/// Sanitized reasons that authoritative PIN policy cannot proceed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PolicyError {
    /// Unknown record format.
    UnsupportedVersion,
    /// Record belongs to another UID/incarnation.
    WrongAccount,
    /// Record belongs to another credential generation.
    WrongGeneration,
    /// Bounded record invariants are not satisfied.
    InvalidRecord,
    /// Monotonic time moved backwards within one boot.
    TimeRollback,
    /// A new boot must pass through durable recovery first.
    BootChanged,
    /// Timestamp, reservation counter, or revision arithmetic would overflow.
    TimeOrCounterOverflow,
    /// An abandoned in-memory reservation must be recovered from stored state.
    UnresolvedReservation,
    /// Storage failed with an unknown commit outcome; reload is required.
    StateUncertain,
    /// Rotation, disable, or account replacement fenced out a backend result.
    StaleCredential,
}

/// A denied reservation does not invoke a backend or consume a new attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReserveError {
    /// PIN cooldown is active; the password route remains available.
    Cooldown {
        /// Remaining duration, measured on the current boot.
        remaining_millis: u64,
    },
    /// The PIN route is unavailable.
    Unavailable(PolicyError),
}

/// Failure to acknowledge a durable state transition.
#[derive(Debug, Eq, PartialEq)]
pub enum CommitError<E> {
    /// A store error never constitutes authorization.
    Storage(E),
    /// A generation/account fence failed before completion.
    Policy(PolicyError),
}

/// Contract for an atomic, authoritative durable replacement.
///
/// Implementors must compare the entire expected record (including revision),
/// recheck the live account incarnation and credential generation, and reject
/// stale writes. They must retain the authoritative per-UID lock across backend
/// work and serialize credential rotation/disable against completion. `Ok(())`
/// promises completed required file/directory synchronization. An error may
/// mean a write reached disk, so the machine becomes unusable until reloaded.
/// An in-memory implementation is appropriate only for M2 policy tests.
pub trait DurableThrottleStore {
    /// Sanitized storage error; must not contain secrets.
    type Error;

    /// Conditionally replace the stored record and acknowledge durability.
    fn commit(
        &mut self,
        expected: &ThrottleRecord,
        replacement: &ThrottleRecord,
    ) -> Result<(), Self::Error>;
}

/// Result of loading authoritative state; recovery cannot be skipped.
pub enum RestoredThrottle {
    /// Valid state on the same boot with no unresolved reservation.
    Ready(Throttle),
    /// Persist this recovery transition before accepting more attempts.
    Recovery(RecoveryIntent),
}

/// A checked per-account state machine, containing no candidate or verifier.
pub struct Throttle {
    record: ThrottleRecord,
    observed_millis: u64,
    unavailable: Option<PolicyError>,
}

impl Throttle {
    /// Validate required stored state and prepare any conservative recovery.
    ///
    /// A boot change with any recorded recent attempt, active cooldown, or pending
    /// reservation installs a new full cooldown. Persisting that transition
    /// prevents repeated loads on the same new boot from extending it. On the
    /// same boot, an abandoned reservation is cleared durably while its attempt
    /// remains subject to the ordinary rolling window and cooldown.
    pub fn restore(
        record: ThrottleRecord,
        account: AccountId,
        generation: Generation,
        now: TimePoint,
    ) -> Result<RestoredThrottle, PolicyError> {
        record.validate(account, generation)?;
        if record.boot == now.boot && now.millis < record.observed_millis {
            return Err(PolicyError::TimeRollback);
        }
        let mut next = record;
        if record.boot != now.boot {
            let exposed = record.pending.is_some()
                || record
                    .cooldown_until_millis
                    .is_some_and(|until| until > record.observed_millis)
                || record.recent_len != 0;
            next.boot = now.boot;
            next.recent = [0; ATTEMPT_LIMIT];
            next.recent_len = 0;
            next.pending = None;
            next.cooldown_started_millis = exposed.then_some(now.millis);
            next.cooldown_until_millis = if exposed {
                Some(
                    now.millis
                        .checked_add(COOLDOWN_MILLIS)
                        .ok_or(PolicyError::TimeOrCounterOverflow)?,
                )
            } else {
                None
            };
        } else if record.pending.is_some() {
            next.pending = None;
            next.prune(now.millis);
        } else {
            return Ok(RestoredThrottle::Ready(Self {
                record,
                observed_millis: now.millis,
                unavailable: None,
            }));
        }
        next.observed_millis = now.millis;
        next.advance_revision()?;
        Ok(RestoredThrottle::Recovery(RecoveryIntent {
            previous: record,
            next,
        }))
    }

    /// Current authoritative record, for diagnostics/storage integration.
    pub const fn record(&self) -> &ThrottleRecord {
        &self.record
    }

    fn observe(&mut self, now: TimePoint) -> Result<(), PolicyError> {
        if let Some(reason) = self.unavailable {
            return Err(reason);
        }
        let invalid = if now.boot != self.record.boot {
            Some(PolicyError::BootChanged)
        } else if now.millis < self.observed_millis {
            Some(PolicyError::TimeRollback)
        } else {
            None
        };
        if let Some(reason) = invalid {
            self.unavailable = Some(reason);
            return Err(reason);
        }
        self.observed_millis = now.millis;
        Ok(())
    }

    /// Plan one eligible, backend-ready PIN-format submission.
    ///
    /// Eligibility and backend readiness are prerequisites supplied by the
    /// broker. This method must never be called for malformed/non-PIN input.
    /// The fifth submission is allowed and installs its full cooldown in the
    /// reservation write, before backend work. A successful completion resets
    /// that cooldown only after a second durable write.
    pub fn reserve(&mut self, now: TimePoint) -> Result<ReservationIntent<'_>, ReserveError> {
        self.observe(now).map_err(ReserveError::Unavailable)?;
        if self.record.pending.is_some() {
            return Err(ReserveError::Unavailable(
                PolicyError::UnresolvedReservation,
            ));
        }
        if let Some(until) = self.record.cooldown_until_millis
            && until > now.millis
        {
            return Err(ReserveError::Cooldown {
                remaining_millis: until - now.millis,
            });
        }
        let mut next = self.record;
        next.prune(now.millis);
        let len = usize::from(next.recent_len);
        if len >= ATTEMPT_LIMIT {
            return Err(ReserveError::Unavailable(PolicyError::InvalidRecord));
        }
        next.last_attempt = next
            .last_attempt
            .checked_add(1)
            .ok_or(ReserveError::Unavailable(
                PolicyError::TimeOrCounterOverflow,
            ))?;
        next.advance_revision().map_err(ReserveError::Unavailable)?;
        next.recent[len] = now.millis;
        next.recent_len += 1;
        if usize::from(next.recent_len) == ATTEMPT_LIMIT {
            next.cooldown_started_millis = Some(now.millis);
            next.cooldown_until_millis = Some(now.millis.checked_add(COOLDOWN_MILLIS).ok_or(
                ReserveError::Unavailable(PolicyError::TimeOrCounterOverflow),
            )?);
        }
        next.observed_millis = now.millis;
        next.pending = Some(PendingReservation {
            attempt: next.last_attempt,
            millis: now.millis,
        });
        Ok(ReservationIntent {
            throttle: self,
            next,
        })
    }
}

/// Required durable recovery, with no way to invoke a backend.
pub struct RecoveryIntent {
    previous: ThrottleRecord,
    next: ThrottleRecord,
}

impl RecoveryIntent {
    /// Proposed recovery record for a storage codec or review.
    pub const fn record(&self) -> &ThrottleRecord {
        &self.next
    }

    /// Acknowledge recovery durability before making the machine usable.
    pub fn commit<S: DurableThrottleStore>(
        self,
        store: &mut S,
    ) -> Result<Throttle, CommitError<S::Error>> {
        store
            .commit(&self.previous, &self.next)
            .map_err(CommitError::Storage)?;
        Ok(Throttle {
            record: self.next,
            observed_millis: self.next.observed_millis,
            unavailable: None,
        })
    }
}

/// A proposed reservation; dropping it consumes no attempt and permits no backend.
#[must_use = "backend work requires a durably committed reservation"]
pub struct ReservationIntent<'a> {
    throttle: &'a mut Throttle,
    next: ThrottleRecord,
}

impl<'a> ReservationIntent<'a> {
    /// Proposed reserved record for a storage codec or review.
    pub const fn record(&self) -> &ThrottleRecord {
        &self.next
    }

    /// Acknowledged durable reservation is the capability to start backend work.
    pub fn commit<S: DurableThrottleStore>(
        self,
        store: &mut S,
    ) -> Result<ReservedAttempt<'a>, CommitError<S::Error>> {
        if let Err(error) = store.commit(&self.throttle.record, &self.next) {
            self.throttle.unavailable = Some(PolicyError::StateUncertain);
            return Err(CommitError::Storage(error));
        }
        self.throttle.record = self.next;
        Ok(ReservedAttempt {
            throttle: self.throttle,
            attempt: AttemptId(self.next.last_attempt),
        })
    }
}

/// A durably consumed attempt, held across one backend invocation.
///
/// Dropping this value models cancellation/crash after reservation: the stored
/// pending attempt remains consumed and a reload/recovery is required.
#[must_use = "a reserved attempt remains consumed until durably completed or recovered"]
pub struct ReservedAttempt<'a> {
    throttle: &'a mut Throttle,
    attempt: AttemptId,
}

impl<'a> ReservedAttempt<'a> {
    /// Identifier for a worker correlation token; this is not authorization.
    pub const fn id(&self) -> AttemptId {
        self.attempt
    }

    /// Account identity bound by the durable reservation.
    pub const fn account(&self) -> AccountId {
        self.throttle.record.account
    }

    /// Credential generation bound by the durable reservation.
    pub const fn generation(&self) -> Generation {
        self.throttle.record.generation
    }

    /// Plan completion; even a matching backend result is not yet success.
    pub fn complete(
        self,
        outcome: BackendOutcome,
        now: TimePoint,
    ) -> Result<CompletionIntent<'a>, PolicyError> {
        self.throttle.observe(now)?;
        let mut next = self.throttle.record;
        next.advance_revision()?;
        next.pending = None;
        next.observed_millis = now.millis;
        let response = match outcome {
            BackendOutcome::Match => {
                next.recent = [0; ATTEMPT_LIMIT];
                next.recent_len = 0;
                next.cooldown_started_millis = None;
                next.cooldown_until_millis = None;
                AttemptResponse::Success
            }
            BackendOutcome::Mismatch => AttemptResponse::Mismatch,
            BackendOutcome::Unavailable(reason) => AttemptResponse::Unavailable(reason),
            BackendOutcome::Cancelled => AttemptResponse::Cancelled,
        };
        Ok(CompletionIntent {
            throttle: self.throttle,
            next,
            response,
        })
    }
}

/// Backend technical failures are distinct from proof of a wrong PIN.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BackendFailure {
    /// Backend is absent, busy, or unsuitable.
    Unavailable,
    /// Worker exceeded the broker's deadline; late results must be discarded.
    Deadline,
    /// Backend operation failed without determining whether the PIN matched.
    Technical,
}

/// One backend result, bound to a still-held reserved attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BackendOutcome {
    /// Backend positively verified the enrolled generation.
    Match,
    /// Backend established that the candidate did not match.
    Mismatch,
    /// No definitive candidate result was available.
    Unavailable(BackendFailure),
    /// Request was cancelled after reservation.
    Cancelled,
}

/// A response available only after durable completion.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AttemptResponse {
    /// Positive backend result and reset both durably completed.
    Success,
    /// Wrong PIN; the reservation remains counted.
    Mismatch,
    /// Technical failure; the reservation conservatively remains counted.
    Unavailable(BackendFailure),
    /// Cancelled; the reservation remains counted.
    Cancelled,
}

/// Pending completion with an explicit final revocation fence.
#[must_use = "PIN success requires a durably committed completion"]
pub struct CompletionIntent<'a> {
    throttle: &'a mut Throttle,
    next: ThrottleRecord,
    response: AttemptResponse,
}

impl CompletionIntent<'_> {
    /// Proposed completed record; this does not constitute authorization.
    pub const fn record(&self) -> &ThrottleRecord {
        &self.next
    }

    /// Recheck live identity/generation and persist before releasing a response.
    ///
    /// The broker supplies its authoritative current identity while holding
    /// the same lock used by rotation/disable. A disabled credential has no
    /// live generation and is represented by `None`. The store independently
    /// enforces the same fence as part of its durable commit contract.
    pub fn commit<S: DurableThrottleStore>(
        self,
        store: &mut S,
        live_account: AccountId,
        live_generation: Option<Generation>,
    ) -> Result<AttemptResponse, CommitError<S::Error>> {
        if live_account != self.next.account || live_generation != Some(self.next.generation) {
            self.throttle.unavailable = Some(PolicyError::StaleCredential);
            return Err(CommitError::Policy(PolicyError::StaleCredential));
        }
        if let Err(error) = store.commit(&self.throttle.record, &self.next) {
            self.throttle.unavailable = Some(PolicyError::StateUncertain);
            return Err(CommitError::Storage(error));
        }
        self.throttle.record = self.next;
        Ok(self.response)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Incarnation, Uid};

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum StoreFailure {
        Injected,
        Conflict,
    }

    #[derive(Default)]
    enum Fault {
        #[default]
        None,
        BeforeWrite,
        AfterWrite,
    }

    struct Store {
        record: ThrottleRecord,
        fault: Fault,
        commits: usize,
    }

    impl DurableThrottleStore for Store {
        type Error = StoreFailure;

        fn commit(
            &mut self,
            expected: &ThrottleRecord,
            replacement: &ThrottleRecord,
        ) -> Result<(), Self::Error> {
            if &self.record != expected {
                return Err(StoreFailure::Conflict);
            }
            let fault = core::mem::take(&mut self.fault);
            if matches!(fault, Fault::BeforeWrite) {
                return Err(StoreFailure::Injected);
            }
            self.record = *replacement;
            self.commits += 1;
            if matches!(fault, Fault::AfterWrite) {
                return Err(StoreFailure::Injected);
            }
            Ok(())
        }
    }

    fn account() -> AccountId {
        AccountId {
            uid: Uid::new(1000).unwrap(),
            incarnation: Incarnation::new([1; 16]).unwrap(),
        }
    }

    fn generation() -> Generation {
        Generation::new(1).unwrap()
    }

    fn at(millis: u64) -> TimePoint {
        TimePoint {
            boot: BootId::new([1; 16]).unwrap(),
            millis,
        }
    }

    fn load(store: &mut Store, now: TimePoint) -> Throttle {
        match Throttle::restore(store.record, account(), generation(), now).unwrap() {
            RestoredThrottle::Ready(machine) => machine,
            RestoredThrottle::Recovery(intent) => intent.commit(store).unwrap(),
        }
    }

    fn fixture(now: u64) -> (Throttle, Store) {
        let mut store = Store {
            record: ThrottleRecord::initial(account(), generation(), at(now)),
            fault: Fault::None,
            commits: 0,
        };
        (load(&mut store, at(now)), store)
    }

    fn attempt(
        machine: &mut Throttle,
        store: &mut Store,
        now: u64,
        outcome: BackendOutcome,
    ) -> AttemptResponse {
        machine
            .reserve(at(now))
            .unwrap()
            .commit(store)
            .unwrap()
            .complete(outcome, at(now))
            .unwrap()
            .commit(store, account(), Some(generation()))
            .unwrap()
    }

    #[test]
    fn fifth_submission_is_verified_but_the_sixth_is_cooled_down() {
        let (mut machine, mut store) = fixture(0);
        for now in 0..4 {
            assert_eq!(
                attempt(&mut machine, &mut store, now, BackendOutcome::Mismatch),
                AttemptResponse::Mismatch
            );
            assert_eq!(store.record.cooldown_until_millis, None);
        }
        let reserved = machine.reserve(at(4)).unwrap().commit(&mut store).unwrap();
        // The cooldown is part of the reservation, before a result exists.
        assert_eq!(store.record.cooldown_until_millis, Some(300_004));
        assert_eq!(reserved.id().get(), 5);
        assert_eq!(reserved.account(), account());
        assert_eq!(reserved.generation(), generation());
        assert_eq!(
            reserved
                .complete(BackendOutcome::Mismatch, at(4))
                .unwrap()
                .commit(&mut store, account(), Some(generation()))
                .unwrap(),
            AttemptResponse::Mismatch
        );
        assert!(matches!(
            machine.reserve(at(300_003)),
            Err(ReserveError::Cooldown {
                remaining_millis: 1
            })
        ));
        assert_eq!(
            attempt(&mut machine, &mut store, 300_004, BackendOutcome::Mismatch),
            AttemptResponse::Mismatch
        );
        assert_eq!(store.record.recent_len, 1);
        assert_eq!(store.record.cooldown_started_millis, None);
    }

    #[test]
    fn rolling_window_is_open_at_sixty_seconds_and_closed_at_now() {
        let (mut machine, mut store) = fixture(0);
        for now in [0, 1, 2, 3] {
            attempt(&mut machine, &mut store, now, BackendOutcome::Mismatch);
        }
        // The zero timestamp lies exactly on the excluded lower boundary.
        attempt(&mut machine, &mut store, 60_000, BackendOutcome::Mismatch);
        assert_eq!(store.record.recent, [1, 2, 3, 60_000, 0]);
        assert_eq!(store.record.cooldown_until_millis, None);

        let (mut machine, mut store) = fixture(0);
        for now in [0, 1, 2, 3, 59_999] {
            attempt(&mut machine, &mut store, now, BackendOutcome::Mismatch);
        }
        assert_eq!(store.record.cooldown_until_millis, Some(359_999));

        let (mut machine, mut store) = fixture(0);
        for _ in 0..5 {
            attempt(&mut machine, &mut store, 0, BackendOutcome::Mismatch);
        }
        assert_eq!(store.record.recent_len, 5);
        assert!(matches!(
            machine.reserve(at(0)),
            Err(ReserveError::Cooldown {
                remaining_millis: 300_000
            })
        ));
    }

    #[test]
    fn success_on_the_fifth_requires_two_commits_then_resets_the_budget() {
        let (mut machine, mut store) = fixture(0);
        for _ in 0..4 {
            attempt(&mut machine, &mut store, 0, BackendOutcome::Mismatch);
        }
        let before = store.commits;
        let reserved = machine.reserve(at(1)).unwrap().commit(&mut store).unwrap();
        assert_eq!(store.commits, before + 1);
        let completion = reserved.complete(BackendOutcome::Match, at(2)).unwrap();
        assert!(store.record.pending.is_some());
        assert!(store.record.cooldown_until_millis.is_some());
        assert_eq!(
            completion.commit(&mut store, account(), Some(generation())),
            Ok(AttemptResponse::Success)
        );
        assert_eq!(store.commits, before + 2);
        assert_eq!(store.record.recent_len, 0);
        assert_eq!(store.record.cooldown_started_millis, None);
        assert_eq!(store.record.cooldown_until_millis, None);
        assert_eq!(store.record.last_attempt, 5);
        assert_eq!(
            attempt(&mut machine, &mut store, 2, BackendOutcome::Mismatch),
            AttemptResponse::Mismatch
        );
    }

    #[test]
    fn technical_errors_and_cancellation_remain_consumed_without_claiming_mismatch() {
        let (mut machine, mut store) = fixture(0);
        for (index, failure) in [
            BackendFailure::Unavailable,
            BackendFailure::Deadline,
            BackendFailure::Technical,
        ]
        .into_iter()
        .enumerate()
        {
            assert_eq!(
                attempt(
                    &mut machine,
                    &mut store,
                    index as u64,
                    BackendOutcome::Unavailable(failure)
                ),
                AttemptResponse::Unavailable(failure)
            );
        }
        assert_eq!(
            attempt(&mut machine, &mut store, 3, BackendOutcome::Cancelled),
            AttemptResponse::Cancelled
        );
        assert_eq!(store.record.recent_len, 4);
        assert!(store.record.pending.is_none());
    }

    #[test]
    fn abandoned_reservation_survives_restart_and_fifth_cooldown() {
        let (mut machine, mut store) = fixture(0);
        drop(machine.reserve(at(0)).unwrap());
        assert_eq!(store.record.recent_len, 0);
        for now in 0..4 {
            attempt(&mut machine, &mut store, now, BackendOutcome::Mismatch);
        }
        drop(machine.reserve(at(4)).unwrap().commit(&mut store).unwrap());
        assert!(matches!(
            machine.reserve(at(5)),
            Err(ReserveError::Unavailable(
                PolicyError::UnresolvedReservation
            ))
        ));
        let mut recovered = load(&mut store, at(5));
        assert!(store.record.pending.is_none());
        assert_eq!(store.record.recent_len, 5);
        assert!(matches!(
            recovered.reserve(at(5)),
            Err(ReserveError::Cooldown {
                remaining_millis: 299_999
            })
        ));
        // Repeated same-boot recovery does not refresh the cooldown.
        let mut recovered = load(&mut store, at(6));
        assert!(matches!(
            recovered.reserve(at(6)),
            Err(ReserveError::Cooldown {
                remaining_millis: 299_998
            })
        ));
    }

    #[test]
    fn abandoned_nonfinal_attempt_counts_until_its_ordinary_window_expires() {
        let (mut machine, mut store) = fixture(0);
        drop(machine.reserve(at(0)).unwrap().commit(&mut store).unwrap());
        let mut recovered = load(&mut store, at(59_999));
        assert_eq!(store.record.recent_len, 1);
        attempt(&mut recovered, &mut store, 60_000, BackendOutcome::Mismatch);
        assert_eq!(store.record.recent_len, 1);
        assert_eq!(store.record.last_attempt, 2);
    }

    #[test]
    fn partial_crash_recovery_pruning_preserves_the_original_fifth_attempt_cooldown() {
        let (mut machine, mut store) = fixture(0);
        for now in [0, 10_000, 20_000, 30_000] {
            attempt(&mut machine, &mut store, now, BackendOutcome::Mismatch);
        }
        drop(
            machine
                .reserve(at(40_000))
                .unwrap()
                .commit(&mut store)
                .unwrap(),
        );
        let _ = load(&mut store, at(60_000));
        assert_eq!(store.record.recent_len, 4);
        assert_eq!(store.record.cooldown_started_millis, Some(40_000));
        assert_eq!(store.record.cooldown_until_millis, Some(340_000));
        assert_eq!(
            ThrottleRecord::decode(&store.record.encode().unwrap()),
            Ok(store.record)
        );
        let _ = load(&mut store, at(60_001));
    }

    #[test]
    fn corrupted_shorter_or_longer_cooldown_intervals_are_rejected() {
        let (mut machine, mut store) = fixture(0);
        for _ in 0..5 {
            attempt(&mut machine, &mut store, 0, BackendOutcome::Mismatch);
        }
        for until in [1, COOLDOWN_MILLIS - 1, COOLDOWN_MILLIS + 1] {
            let mut corrupt = store.record;
            corrupt.cooldown_until_millis = Some(until);
            assert_eq!(corrupt.encode(), Err(PolicyError::InvalidRecord));
            assert!(matches!(
                Throttle::restore(corrupt, account(), generation(), at(0)),
                Err(PolicyError::InvalidRecord)
            ));
        }
        let new_boot = TimePoint {
            boot: BootId::new([2; 16]).unwrap(),
            millis: 0,
        };
        let _ = load(&mut store, new_boot);
        let mut corrupt = store.record;
        corrupt.cooldown_until_millis = Some(COOLDOWN_MILLIS + 1);
        assert_eq!(corrupt.encode(), Err(PolicyError::InvalidRecord));
    }

    #[test]
    fn same_boot_crash_recovery_retains_cooldown_after_all_timestamps_expire() {
        let (mut machine, mut store) = fixture(0);
        for _ in 0..4 {
            attempt(&mut machine, &mut store, 0, BackendOutcome::Mismatch);
        }
        drop(machine.reserve(at(0)).unwrap().commit(&mut store).unwrap());
        let mut recovered = load(&mut store, at(200_000));
        assert_eq!(store.record.recent_len, 0);
        assert_eq!(store.record.cooldown_started_millis, Some(0));
        assert_eq!(store.record.cooldown_until_millis, Some(300_000));
        assert_eq!(
            ThrottleRecord::decode(&store.record.encode().unwrap()),
            Ok(store.record)
        );
        assert!(matches!(
            recovered.reserve(at(200_000)),
            Err(ReserveError::Cooldown {
                remaining_millis: 100_000
            })
        ));
        let mut recovered = load(&mut store, at(200_001));
        assert!(matches!(
            recovered.reserve(at(200_001)),
            Err(ReserveError::Cooldown {
                remaining_millis: 99_999
            })
        ));
    }

    fn assert_empty_recovery_cooldown_rejects_corruption(record: ThrottleRecord, now: TimePoint) {
        assert_eq!(record.recent_len, 0);
        let encoded = record.encode().unwrap();
        assert_eq!(ThrottleRecord::decode(&encoded), Ok(record));

        // Before retaining the origin, this single-bit deadline shortening was
        // accepted after recovery discarded every recent-attempt timestamp.
        let mut shortened = encoded;
        shortened[122] ^= 4;
        assert_eq!(
            ThrottleRecord::decode(&shortened),
            Err(ThrottleRecordError::Policy(PolicyError::InvalidRecord))
        );
        let mut corrupt = record;
        corrupt.cooldown_until_millis = Some(record.cooldown_until_millis.unwrap() ^ (1 << 18));
        assert_eq!(corrupt.encode(), Err(PolicyError::InvalidRecord));
        assert!(matches!(
            Throttle::restore(corrupt, account(), generation(), now),
            Err(PolicyError::InvalidRecord)
        ));

        // The independent origin keeps every one-bit mutation of either
        // timestamp or presence tag from shortening or extending the interval.
        for index in 107..125 {
            for bit in 0..8 {
                let mut changed = encoded;
                changed[index] ^= 1 << bit;
                assert!(ThrottleRecord::decode(&changed).is_err());
            }
        }
    }

    #[test]
    fn empty_new_boot_recovery_rejects_shortened_or_corrupted_cooldown() {
        let (mut machine, mut store) = fixture(0);
        drop(machine.reserve(at(0)).unwrap().commit(&mut store).unwrap());
        let new_boot = TimePoint {
            boot: BootId::new([2; 16]).unwrap(),
            millis: 0,
        };
        let _ = load(&mut store, new_boot);
        assert_empty_recovery_cooldown_rejects_corruption(store.record, new_boot);
    }

    #[test]
    fn empty_same_boot_recovery_rejects_shortened_or_corrupted_cooldown() {
        let (mut machine, mut store) = fixture(0);
        for _ in 0..4 {
            attempt(&mut machine, &mut store, 0, BackendOutcome::Mismatch);
        }
        drop(machine.reserve(at(0)).unwrap().commit(&mut store).unwrap());
        let _ = load(&mut store, at(200_000));
        assert_empty_recovery_cooldown_rejects_corruption(store.record, at(200_000));
    }

    #[test]
    fn reboot_with_a_recent_attempt_even_without_cooldown_installs_one_full_cooldown() {
        let (mut machine, mut store) = fixture(100);
        attempt(&mut machine, &mut store, 100, BackendOutcome::Mismatch);
        assert_eq!(store.record.cooldown_until_millis, None);
        let new_boot = TimePoint {
            boot: BootId::new([2; 16]).unwrap(),
            millis: 7,
        };
        let mut recovered = load(&mut store, new_boot);
        assert_eq!(store.record.cooldown_started_millis, Some(7));
        assert_eq!(store.record.cooldown_until_millis, Some(300_007));
        assert_eq!(store.record.recent_len, 0);
        assert!(matches!(
            recovered.reserve(new_boot),
            Err(ReserveError::Cooldown {
                remaining_millis: 300_000
            })
        ));
        let mut recovered = load(
            &mut store,
            TimePoint {
                millis: 8,
                ..new_boot
            },
        );
        assert!(matches!(
            recovered.reserve(TimePoint {
                millis: 8,
                ..new_boot
            }),
            Err(ReserveError::Cooldown {
                remaining_millis: 299_999
            })
        ));
    }

    #[test]
    fn reboot_does_not_infer_that_persisted_attempts_expired_on_the_new_boot() {
        let (mut machine, mut store) = fixture(0);
        machine
            .reserve(at(0))
            .unwrap()
            .commit(&mut store)
            .unwrap()
            .complete(BackendOutcome::Mismatch, at(90_000))
            .unwrap()
            .commit(&mut store, account(), Some(generation()))
            .unwrap();
        assert_eq!(store.record.recent_len, 1);
        let next_boot = TimePoint {
            boot: BootId::new([2; 16]).unwrap(),
            millis: 0,
        };
        let _ = load(&mut store, next_boot);
        assert_eq!(store.record.cooldown_until_millis, Some(COOLDOWN_MILLIS));
    }

    #[test]
    fn failed_recovery_commit_cannot_produce_a_usable_machine() {
        let (mut machine, mut store) = fixture(0);
        drop(machine.reserve(at(0)).unwrap().commit(&mut store).unwrap());
        let RestoredThrottle::Recovery(recovery) =
            Throttle::restore(store.record, account(), generation(), at(1)).unwrap()
        else {
            panic!("pending reservation requires recovery")
        };
        store.fault = Fault::BeforeWrite;
        assert!(matches!(
            recovery.commit(&mut store),
            Err(CommitError::Storage(StoreFailure::Injected))
        ));
        assert!(store.record.pending.is_some());
    }

    #[test]
    fn reboot_preserves_unresolved_or_active_exposure_but_clean_state_stays_clean() {
        let new_boot = TimePoint {
            boot: BootId::new([2; 16]).unwrap(),
            millis: 0,
        };
        for pending in [false, true] {
            let (mut machine, mut store) = fixture(0);
            for _ in 0..4 {
                attempt(&mut machine, &mut store, 0, BackendOutcome::Mismatch);
            }
            let reserved = machine.reserve(at(0)).unwrap().commit(&mut store).unwrap();
            if pending {
                drop(reserved);
            } else {
                reserved
                    .complete(BackendOutcome::Mismatch, at(0))
                    .unwrap()
                    .commit(&mut store, account(), Some(generation()))
                    .unwrap();
            }
            let _ = load(&mut store, new_boot);
            assert_eq!(store.record.cooldown_until_millis, Some(COOLDOWN_MILLIS));
        }
        let (mut machine, mut store) = fixture(0);
        attempt(&mut machine, &mut store, 0, BackendOutcome::Match);
        let _ = load(&mut store, new_boot);
        assert_eq!(store.record.cooldown_until_millis, None);
    }

    #[test]
    fn storage_uncertainty_never_releases_a_backend_capability_or_success() {
        for fault in [Fault::BeforeWrite, Fault::AfterWrite] {
            let (mut machine, mut store) = fixture(0);
            store.fault = fault;
            assert!(matches!(
                machine.reserve(at(0)).unwrap().commit(&mut store),
                Err(CommitError::Storage(StoreFailure::Injected))
            ));
            assert!(matches!(
                machine.reserve(at(1)),
                Err(ReserveError::Unavailable(PolicyError::StateUncertain))
            ));
        }
        for fault in [Fault::BeforeWrite, Fault::AfterWrite] {
            let (mut machine, mut store) = fixture(0);
            let completion = machine
                .reserve(at(0))
                .unwrap()
                .commit(&mut store)
                .unwrap()
                .complete(BackendOutcome::Match, at(0))
                .unwrap();
            store.fault = fault;
            assert_eq!(
                completion.commit(&mut store, account(), Some(generation())),
                Err(CommitError::Storage(StoreFailure::Injected))
            );
            assert!(matches!(
                machine.reserve(at(1)),
                Err(ReserveError::Unavailable(PolicyError::StateUncertain))
            ));
            let mut recovered = load(&mut store, at(1));
            // A committed-but-unacknowledged success may have reset the state;
            // either disk outcome is safe because no success was delivered.
            drop(recovered.reserve(at(1)).unwrap());
        }
    }

    #[test]
    fn rotation_disable_and_account_replacement_fence_late_backend_success() {
        for live in [Some(Generation::new(2).unwrap()), None] {
            let (mut machine, mut store) = fixture(0);
            let completion = machine
                .reserve(at(0))
                .unwrap()
                .commit(&mut store)
                .unwrap()
                .complete(BackendOutcome::Match, at(0))
                .unwrap();
            assert_eq!(
                completion.commit(&mut store, account(), live),
                Err(CommitError::Policy(PolicyError::StaleCredential))
            );
            assert!(store.record.pending.is_some());
            assert!(matches!(
                machine.reserve(at(1)),
                Err(ReserveError::Unavailable(PolicyError::StaleCredential))
            ));
        }
        let (mut machine, mut store) = fixture(0);
        let completion = machine
            .reserve(at(0))
            .unwrap()
            .commit(&mut store)
            .unwrap()
            .complete(BackendOutcome::Match, at(0))
            .unwrap();
        let replacement = AccountId {
            incarnation: Incarnation::new([2; 16]).unwrap(),
            ..account()
        };
        assert_eq!(
            completion.commit(&mut store, replacement, Some(generation())),
            Err(CommitError::Policy(PolicyError::StaleCredential))
        );
    }

    #[test]
    fn stale_or_conflicting_storage_cannot_complete_success() {
        let (mut machine, mut store) = fixture(0);
        let completion = machine
            .reserve(at(0))
            .unwrap()
            .commit(&mut store)
            .unwrap()
            .complete(BackendOutcome::Match, at(0))
            .unwrap();
        // Simulate an external authoritative writer. M3 must also protect the
        // generation fence even when the separate credential record changed.
        store.record.revision += 1;
        assert_eq!(
            completion.commit(&mut store, account(), Some(generation())),
            Err(CommitError::Storage(StoreFailure::Conflict))
        );
    }

    #[test]
    fn malformed_future_and_wrong_scope_records_are_rejected() {
        let base = ThrottleRecord::initial(account(), generation(), at(10));
        let mut malformed = Vec::new();
        let mut record = base;
        record.version = 2;
        malformed.push((record, PolicyError::UnsupportedVersion));
        let mut record = base;
        record.recent_len = 6;
        malformed.push((record, PolicyError::InvalidRecord));
        let mut record = base;
        record.recent[4] = 1;
        malformed.push((record, PolicyError::InvalidRecord));
        let mut record = base;
        record.recent_len = 1;
        record.recent[0] = 11;
        record.last_attempt = 1;
        malformed.push((record, PolicyError::InvalidRecord));
        let mut record = base;
        record.recent_len = 2;
        record.recent[..2].copy_from_slice(&[10, 9]);
        record.last_attempt = 2;
        malformed.push((record, PolicyError::InvalidRecord));
        let mut record = base;
        record.pending = Some(PendingReservation {
            attempt: 1,
            millis: 10,
        });
        malformed.push((record, PolicyError::InvalidRecord));
        let mut record = base;
        record.last_attempt = 1;
        record.cooldown_until_millis = Some(300_011);
        malformed.push((record, PolicyError::InvalidRecord));
        let mut record = base;
        record.last_attempt = 1;
        record.cooldown_started_millis = Some(10);
        malformed.push((record, PolicyError::InvalidRecord));
        let mut record = base;
        record.last_attempt = 1;
        record.cooldown_started_millis = Some(11);
        record.cooldown_until_millis = Some(300_011);
        malformed.push((record, PolicyError::InvalidRecord));
        let mut record = base;
        record.last_attempt = 1;
        record.observed_millis = u64::MAX;
        record.cooldown_started_millis = Some(u64::MAX);
        record.cooldown_until_millis = Some(COOLDOWN_MILLIS - 1);
        malformed.push((record, PolicyError::InvalidRecord));
        for (record, expected) in malformed {
            assert!(
                matches!(Throttle::restore(record, account(), generation(), at(10)), Err(actual) if actual == expected)
            );
        }
        let other = AccountId {
            uid: Uid::new(1001).unwrap(),
            ..account()
        };
        assert!(matches!(
            Throttle::restore(base, other, generation(), at(10)),
            Err(PolicyError::WrongAccount)
        ));
        assert!(matches!(
            Throttle::restore(base, account(), Generation::new(2).unwrap(), at(10)),
            Err(PolicyError::WrongGeneration)
        ));
        assert!(matches!(
            Throttle::restore(base, account(), generation(), at(9)),
            Err(PolicyError::TimeRollback)
        ));
    }

    #[test]
    fn fixed_record_codec_roundtrips_all_durable_phases_canonically() {
        let (mut machine, mut store) = fixture(10);
        let initial = store.record.encode().unwrap();
        assert_eq!(initial.len(), 150);
        assert_eq!(
            &initial[..10],
            &[b'L', b'P', b'T', b'H', 0, 1, 0, 0, 3, 232]
        );
        assert_eq!(ThrottleRecord::decode(&initial), Ok(store.record));
        for _ in 0..4 {
            attempt(&mut machine, &mut store, 10, BackendOutcome::Mismatch);
        }
        let reserved = machine.reserve(at(10)).unwrap().commit(&mut store).unwrap();
        assert_eq!(
            ThrottleRecord::decode(&store.record.encode().unwrap()),
            Ok(store.record)
        );
        reserved
            .complete(BackendOutcome::Mismatch, at(11))
            .unwrap()
            .commit(&mut store, account(), Some(generation()))
            .unwrap();
        assert_eq!(
            ThrottleRecord::decode(&store.record.encode().unwrap()),
            Ok(store.record)
        );
        let new_boot = TimePoint {
            boot: BootId::new([2; 16]).unwrap(),
            millis: 0,
        };
        let _ = load(&mut store, new_boot);
        assert_eq!(
            ThrottleRecord::decode(&store.record.encode().unwrap()),
            Ok(store.record)
        );
    }

    #[test]
    fn fixed_record_codec_rejects_size_version_tags_and_noncanonical_empty_fields() {
        let record = ThrottleRecord::initial(account(), generation(), at(10));
        let encoded = record.encode().unwrap();
        for length in 0..THROTTLE_ENCODED_LEN {
            assert!(ThrottleRecord::decode(&encoded[..length]).is_err());
        }
        assert_eq!(
            ThrottleRecord::decode(&[encoded.as_slice(), &[0]].concat()),
            Err(ThrottleRecordError::Encoding)
        );
        assert_eq!(
            ThrottleRecord::decode(&vec![0; crate::limits::MAX_THROTTLE_BYTES + 1]),
            Err(ThrottleRecordError::Oversized)
        );
        let mut changed = encoded;
        changed[5] = 2;
        assert_eq!(
            ThrottleRecord::decode(&changed),
            Err(ThrottleRecordError::Policy(PolicyError::UnsupportedVersion))
        );
        for index in [107, 116, 133] {
            for tag in 2..=u8::MAX {
                let mut changed = encoded;
                changed[index] = tag;
                assert_eq!(
                    ThrottleRecord::decode(&changed),
                    Err(ThrottleRecordError::Encoding)
                );
            }
        }
        for index in [108, 115, 117, 124, 134, 141, 142, 149] {
            let mut changed = encoded;
            changed[index] = 1;
            assert_eq!(
                ThrottleRecord::decode(&changed),
                Err(ThrottleRecordError::Encoding)
            );
        }
        for range in [6..10, 10..26, 26..34, 42..58] {
            let mut changed = encoded;
            changed[range].fill(0);
            assert!(ThrottleRecord::decode(&changed).is_err());
        }
        let mut changed = record;
        changed.recent_len = 6;
        assert_eq!(changed.encode(), Err(PolicyError::InvalidRecord));
        let mut changed = encoded;
        changed[66] = 6;
        assert_eq!(
            ThrottleRecord::decode(&changed),
            Err(ThrottleRecordError::Policy(PolicyError::InvalidRecord))
        );
    }

    #[test]
    fn every_accepted_single_bit_record_mutation_has_one_canonical_encoding() {
        let (mut machine, mut store) = fixture(10);
        let mut records = vec![store.record];
        for _ in 0..4 {
            attempt(&mut machine, &mut store, 10, BackendOutcome::Mismatch);
        }
        let reserved = machine.reserve(at(10)).unwrap().commit(&mut store).unwrap();
        records.push(store.record);
        drop(reserved);
        let _ = load(&mut store, at(200_000));
        records.push(store.record);
        let _ = load(
            &mut store,
            TimePoint {
                boot: BootId::new([2; 16]).unwrap(),
                millis: 7,
            },
        );
        records.push(store.record);
        for original in records {
            let encoded = original.encode().unwrap();
            for index in 0..encoded.len() {
                for bit in 0..8 {
                    let mut changed = encoded;
                    changed[index] ^= 1 << bit;
                    if let Ok(record) = ThrottleRecord::decode(&changed) {
                        assert_eq!(record.encode().unwrap(), changed);
                    }
                }
            }
        }
    }

    #[test]
    fn backwards_time_changed_boot_and_overflow_fail_safely() {
        let (mut machine, _) = fixture(10);
        assert!(matches!(
            machine.reserve(at(9)),
            Err(ReserveError::Unavailable(PolicyError::TimeRollback))
        ));
        assert!(matches!(
            machine.reserve(at(11)),
            Err(ReserveError::Unavailable(PolicyError::TimeRollback))
        ));
        let (mut machine, _) = fixture(0);
        let other_boot = TimePoint {
            boot: BootId::new([2; 16]).unwrap(),
            millis: 0,
        };
        assert!(matches!(
            machine.reserve(other_boot),
            Err(ReserveError::Unavailable(PolicyError::BootChanged))
        ));

        let (mut machine, mut store) = fixture(u64::MAX - 1);
        for _ in 0..4 {
            attempt(
                &mut machine,
                &mut store,
                u64::MAX - 1,
                BackendOutcome::Mismatch,
            );
        }
        assert!(matches!(
            machine.reserve(at(u64::MAX)),
            Err(ReserveError::Unavailable(
                PolicyError::TimeOrCounterOverflow
            ))
        ));
        assert_eq!(store.record.recent_len, 4);
        let record = store.record;
        assert!(matches!(
            Throttle::restore(
                record,
                account(),
                generation(),
                TimePoint {
                    millis: u64::MAX,
                    ..other_boot
                }
            ),
            Err(PolicyError::TimeOrCounterOverflow)
        ));
        for counter in [true, false] {
            let mut record = ThrottleRecord::initial(account(), generation(), at(0));
            if counter {
                record.last_attempt = u64::MAX;
            } else {
                record.revision = u64::MAX;
            }
            let mut store = Store {
                record,
                fault: Fault::None,
                commits: 0,
            };
            let mut machine = load(&mut store, at(0));
            assert!(matches!(
                machine.reserve(at(0)),
                Err(ReserveError::Unavailable(
                    PolicyError::TimeOrCounterOverflow
                ))
            ));
        }
    }

    #[test]
    fn backend_completion_rejects_time_rollback_without_resetting_consumed_state() {
        let (mut machine, mut store) = fixture(10);
        let reserved = machine.reserve(at(10)).unwrap().commit(&mut store).unwrap();
        assert!(matches!(
            reserved.complete(BackendOutcome::Match, at(9)),
            Err(PolicyError::TimeRollback)
        ));
        assert!(store.record.pending.is_some());
        assert_eq!(store.record.recent_len, 1);
    }

    #[test]
    fn uid_machines_are_independent_while_one_reservation_is_pending() {
        let (mut machine, mut store) = fixture(0);
        let reserved = machine.reserve(at(0)).unwrap().commit(&mut store).unwrap();
        let other = AccountId {
            uid: Uid::new(1001).unwrap(),
            ..account()
        };
        let mut other_store = Store {
            record: ThrottleRecord::initial(other, generation(), at(0)),
            fault: Fault::None,
            commits: 0,
        };
        let RestoredThrottle::Ready(mut independent) =
            Throttle::restore(other_store.record, other, generation(), at(0)).unwrap()
        else {
            panic!("fresh fixture")
        };
        assert_eq!(
            independent
                .reserve(at(0))
                .unwrap()
                .commit(&mut other_store)
                .unwrap()
                .complete(BackendOutcome::Match, at(0))
                .unwrap()
                .commit(&mut other_store, other, Some(generation())),
            Ok(AttemptResponse::Success)
        );
        drop(reserved);
        assert!(store.record.pending.is_some());
    }

    #[test]
    fn deterministic_generated_sequences_match_an_independent_rolling_window_model() {
        // Exhaustive fixed seeds exercise success resets, simultaneous submits,
        // exact boundaries, restarts and long suspend-inclusive advances without
        // adding randomness or a test-only dependency to the core contracts.
        for seed in 1_u64..=128 {
            let (mut machine, mut store) = fixture(0);
            let mut random = seed;
            let mut now = 0;
            let mut submissions = Vec::new();
            let mut cooldown = None;
            let mut accepted = 0;
            for _ in 0..256 {
                random = random
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1);
                now += [0, 1, 59_999, 60_000, 299_999, 300_000][((random >> 32) % 6) as usize];
                let outcome = match (random >> 40) % 7 {
                    0 => BackendOutcome::Match,
                    1 => BackendOutcome::Cancelled,
                    2 => BackendOutcome::Unavailable(BackendFailure::Technical),
                    _ => BackendOutcome::Mismatch,
                };
                if let Some(until) = cooldown
                    && now < until
                {
                    assert!(
                        matches!(machine.reserve(at(now)), Err(ReserveError::Cooldown { remaining_millis }) if remaining_millis == until - now)
                    );
                    continue;
                }
                submissions.retain(|&submitted| now - submitted < 60_000);
                assert!(submissions.len() < 5);
                submissions.push(now);
                accepted += 1;
                if submissions.len() == 5 {
                    cooldown = Some(now + 300_000);
                }
                if matches!(outcome, BackendOutcome::Match) {
                    submissions.clear();
                    cooldown = None;
                } else if cooldown.is_some_and(|until| until <= now) {
                    cooldown = None;
                }
                let response = attempt(&mut machine, &mut store, now, outcome);
                assert_eq!(
                    matches!(response, AttemptResponse::Success),
                    matches!(outcome, BackendOutcome::Match)
                );
                assert_eq!(store.record.recent_len as usize, submissions.len());
                assert_eq!(store.record.cooldown_until_millis, cooldown);
                assert_eq!(store.record.last_attempt, accepted);
                assert_eq!(
                    &store.record.recent[..submissions.len()],
                    submissions.as_slice()
                );
                assert!(store.record.pending.is_none());
                machine = load(&mut store, at(now));
            }
        }
    }
}
