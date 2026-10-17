//! Bounded identifiers and narrow clock, entropy, and backend contracts.

use crate::secret::Pin;
pub use crate::throttle::BackendOutcome;

/// Invalid identifier, range, or exhausted generation space.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InvalidValue;

/// An ordinary, non-root Linux UID; the all-ones sentinel is excluded.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Uid(u32);

impl Uid {
    /// Validate a numeric UID. Names are never used as state paths.
    pub fn new(value: u32) -> Result<Self, InvalidValue> {
        match value {
            0 | u32::MAX => Err(InvalidValue),
            _ => Ok(Self(value)),
        }
    }

    /// Numeric kernel UID.
    pub const fn get(self) -> u32 {
        self.0
    }
}

/// Nonzero monotonically increasing credential generation/revocation epoch.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Generation(u64);

impl Generation {
    /// Validate a generation number.
    pub fn new(value: u64) -> Result<Self, InvalidValue> {
        if value == 0 {
            Err(InvalidValue)
        } else {
            Ok(Self(value))
        }
    }

    /// Generation number.
    pub const fn get(self) -> u64 {
        self.0
    }

    /// Advance without wrapping; exhaustion makes new operations unavailable.
    pub fn next(self) -> Result<Self, InvalidValue> {
        self.0
            .checked_add(1)
            .ok_or(InvalidValue)
            .and_then(Self::new)
    }
}

macro_rules! opaque_id {
    ($name:ident, $description:literal) => {
        #[doc = $description]
        #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
        pub struct $name([u8; 16]);
        impl $name {
            /// Reject an absent/all-zero identifier. Trusted adapters generate it.
            pub fn new(value: [u8; 16]) -> Result<Self, InvalidValue> {
                if value == [0; 16] {
                    Err(InvalidValue)
                } else {
                    Ok(Self(value))
                }
            }
            /// Nonsecret identifier bytes.
            pub const fn get(self) -> [u8; 16] {
                self.0
            }
        }
    };
}

opaque_id!(
    Incarnation,
    "Opaque identity supplied by a trusted account lifecycle authority, never UID/name/home equality."
);
opaque_id!(
    BootId,
    "Kernel boot identifier used to scope suspend-inclusive monotonic time."
);
opaque_id!(
    ConnectionId,
    "Fresh broker-generated random connection binding; never a bearer authorization."
);
opaque_id!(
    TransactionId,
    "Fresh broker-generated random transaction binding."
);

/// Stable identity within a lifecycle authority's explicitly supported domain.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct AccountId {
    /// Numeric UID used for access control and trusted storage paths.
    pub uid: Uid,
    /// Authority-issued incarnation, revoked before account deletion/reuse.
    pub incarnation: Incarnation,
}

/// Suspend-inclusive elapsed milliseconds in one boot; wall time is not used.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TimePoint {
    /// Boot namespace for this timestamp.
    pub boot: BootId,
    /// Elapsed milliseconds from the boot's monotonic origin.
    pub millis: u64,
}

/// A clock adapter must use a suspend-inclusive monotonic platform clock.
pub trait Clock {
    /// Clock acquisition failure makes the operation unavailable.
    fn now(&mut self) -> Result<TimePoint, Unavailable>;
}

/// Trusted OS entropy adapter. No fallback to clocks, process IDs, or counters.
pub trait Randomness {
    /// Fill the entire destination or fail the transaction.
    fn fill(&mut self, destination: &mut [u8]) -> Result<(), Unavailable>;
}

/// A technical failure with no secret-bearing detail.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Unavailable;

/// Credential backend pinned at enrollment.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Backend {
    /// Machine-bound TPM credential; errors never select software implicitly.
    Tpm2,
    /// Explicitly accepted software convenience credential.
    Software,
}

/// Enrollment policy selection, distinct from the pinned backend.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BackendSelection {
    /// Prefer verified TPM usability; software requires separate consent.
    Auto,
    /// Refuse enrollment unless TPM is usable.
    Tpm2Required,
    /// Explicit software choice.
    Software,
}

impl BackendSelection {
    /// Resolve using a safe probe and explicit acceptance of software mode.
    pub fn resolve(
        self,
        tpm_usable: bool,
        software_accepted: bool,
    ) -> Result<Backend, Unavailable> {
        match self {
            Self::Auto | Self::Tpm2Required if tpm_usable => Ok(Backend::Tpm2),
            Self::Software if software_accepted => Ok(Backend::Software),
            Self::Auto if software_accepted => Ok(Backend::Software),
            _ => Err(Unavailable),
        }
    }
}

/// One backend invocation, owning its durable attempt, candidate and work lease.
///
/// The job cannot be cloned or resubmitted after verification consumes it:
///
/// ```compile_fail
/// use localpin_core::types::{CredentialVerifier, VerificationJob};
/// fn resubmit<'a, V: CredentialVerifier>(verifier: &mut V, job: VerificationJob<'a>) {
///     let first = verifier.verify(job);
///     let second = verifier.verify(job);
/// }
/// ```
///
/// Sharing a reference cannot create another backend invocation:
///
/// ```compile_fail
/// use localpin_core::types::{CredentialVerifier, VerificationJob};
/// fn submit_shared<'a, V: CredentialVerifier>(verifier: &mut V, job: &VerificationJob<'a>) {
///     let completion = verifier.verify(*job);
/// }
/// ```
///
/// Concurrent workers cannot each acquire the same owned invocation:
///
/// ```compile_fail
/// use localpin_core::types::{CredentialVerifier, VerificationJob};
/// fn concurrent<'a, V: CredentialVerifier + Send>(
///     first: &mut V, second: &mut V, job: VerificationJob<'a>,
/// ) {
///     std::thread::scope(|scope| {
///         scope.spawn(move || first.verify(job));
///         scope.spawn(move || second.verify(job));
///     });
/// }
/// ```
#[must_use = "verification owns one consumed attempt and its charged work lease"]
pub struct VerificationJob<'a> {
    reservation: crate::throttle::ReservedAttempt<'a>,
    backend: Backend,
    pin: Pin,
    work: crate::limits::WorkPermit,
    parameters: crate::limits::KdfParameters,
}

impl<'a> VerificationJob<'a> {
    /// Bind one candidate to its durable attempt and exact validated work lease.
    ///
    /// A rejected binding drops the capabilities: its durable attempt remains
    /// consumed and requires authoritative recovery before another submission.
    pub fn new(
        reservation: crate::throttle::ReservedAttempt<'a>,
        backend: Backend,
        pin: Pin,
        work: crate::limits::WorkPermit,
        parameters: crate::limits::KdfParameters,
    ) -> Result<Self, crate::limits::CapacityError> {
        let kind = match backend {
            Backend::Software => crate::limits::WorkKind::Verification,
            Backend::Tpm2 => crate::limits::WorkKind::TpmPinDerivation,
        };
        if !work.covers(reservation.account().uid, parameters, kind) {
            return Err(crate::limits::CapacityError);
        }
        Ok(Self {
            reservation,
            backend,
            pin,
            work,
            parameters,
        })
    }

    /// Identifier for this one invocation's worker correlation token.
    pub fn id(&self) -> crate::throttle::AttemptId {
        self.reservation.id()
    }

    /// Exact account incarnation bound by the durable reservation.
    pub fn account(&self) -> AccountId {
        self.reservation.account()
    }

    /// Exact enrolled generation to verify.
    pub fn generation(&self) -> Generation {
        self.reservation.generation()
    }

    /// Pinned backend; availability failures must not select another backend.
    pub const fn backend(&self) -> Backend {
        self.backend
    }

    /// Validated parameters whose exact memory has already been charged.
    pub const fn parameters(&self) -> crate::limits::KdfParameters {
        self.parameters
    }

    /// Borrow the candidate only while executing this invocation.
    pub const fn pin(&self) -> &Pin {
        &self.pin
    }

    /// Borrow the exact charged work lease while deriving credential material.
    /// The job retains ownership until native work and cleanup have ended.
    pub const fn work(&self) -> &crate::limits::WorkPermit {
        &self.work
    }

    /// Finish after all native work has exited and been reaped; erase the PIN.
    ///
    /// Cancellation of the response path does not permit calling this early.
    /// The worker or its supervisor must retain this job and its charged lease
    /// until actual cleanup completes. The completion retains the lease until
    /// it is consumed or dropped; it cannot invoke another verifier.
    pub fn finish(self, outcome: BackendOutcome) -> VerificationCompletion<'a> {
        let Self {
            reservation,
            work,
            pin,
            ..
        } = self;
        drop(pin);
        VerificationCompletion {
            reservation,
            work,
            outcome,
        }
    }
}

/// Opaque, one-use backend result retaining its consumed attempt and work lease.
///
/// ```compile_fail
/// use localpin_core::types::{TimePoint, VerificationCompletion};
/// fn complete_twice(completion: VerificationCompletion<'_>, now: TimePoint) {
///     let first = completion.complete(now);
///     let second = completion.complete(now);
/// }
/// ```
#[must_use = "a backend result requires durable completion before any response"]
pub struct VerificationCompletion<'a> {
    reservation: crate::throttle::ReservedAttempt<'a>,
    work: crate::limits::WorkPermit,
    outcome: BackendOutcome,
}

impl<'a> VerificationCompletion<'a> {
    /// Plan durable completion; only its acknowledged commit yields a response.
    /// The backend has already ended, so its work lease may now be released.
    pub fn complete(
        self,
        now: TimePoint,
    ) -> Result<crate::throttle::CompletionIntent<'a>, crate::throttle::PolicyError> {
        let Self {
            reservation,
            work,
            outcome,
        } = self;
        let completion = reservation.complete(outcome, now);
        drop(work);
        completion
    }
}

/// Trusted backend adapter consuming exactly one invocation and its resources.
pub trait CredentialVerifier {
    /// Verify the job's exact account, generation, backend and parameters.
    /// Retain no cache. Return only after native work has ended and been reaped;
    /// cancellation or a response deadline must not release its work lease early.
    fn verify<'a>(&mut self, job: VerificationJob<'a>) -> VerificationCompletion<'a>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounded_ids_and_generation_exhaustion() {
        assert_eq!(Uid::new(0), Err(InvalidValue));
        assert_eq!(Uid::new(u32::MAX), Err(InvalidValue));
        assert!(Uid::new(u32::MAX - 1).is_ok());
        assert_eq!(Generation::new(0), Err(InvalidValue));
        assert_eq!(Generation::new(u64::MAX).unwrap().next(), Err(InvalidValue));
        assert_eq!(Incarnation::new([0; 16]), Err(InvalidValue));
    }

    #[test]
    fn selection_never_silently_downgrades() {
        for usable in [false, true] {
            for consent in [false, true] {
                assert_eq!(
                    BackendSelection::Tpm2Required
                        .resolve(usable, consent)
                        .is_ok(),
                    usable
                );
                assert_eq!(
                    BackendSelection::Software.resolve(usable, consent).is_ok(),
                    consent
                );
            }
        }
        assert_eq!(
            BackendSelection::Auto.resolve(false, false),
            Err(Unavailable)
        );
        assert_eq!(
            BackendSelection::Auto.resolve(true, true),
            Ok(Backend::Tpm2)
        );
    }
}
