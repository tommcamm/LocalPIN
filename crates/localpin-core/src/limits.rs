//! Shared hard resource limits. Permits remain charged until actual work ends.

use crate::types::Uid;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};

/// Maximum complete protocol frame, including the length prefix.
pub const MAX_FRAME_BYTES: usize = 4096;
/// Maximum credential or configuration record.
pub const MAX_RECORD_BYTES: usize = 64 * 1024;
/// Maximum throttle record.
pub const MAX_THROTTLE_BYTES: usize = 16 * 1024;
/// Global concurrent connection cap; there is no implicit unbounded queue.
pub const MAX_CONNECTIONS: usize = 32;
/// Aggregate KDF memory, in KiB, including enrollment and TPM derivation.
pub const MAX_KDF_KIB: u32 = 256 * 1024;

/// Reviewed Argon2id v19 policy; algorithm, salt and output sizes are fixed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KdfParameters {
    memory_kib: u32,
    passes: u32,
}

impl KdfParameters {
    /// Enrollment defaults: 64 MiB, three passes, one lane, v19.
    pub const ENROLLMENT: Self = Self {
        memory_kib: 64 * 1024,
        passes: 3,
    };

    /// Reject work outside the reviewed memory/pass/lane bounds before allocation.
    pub fn new(memory_kib: u32, passes: u32, lanes: u32) -> Result<Self, CapacityError> {
        if !(64 * 1024..=MAX_KDF_KIB).contains(&memory_kib)
            || !(3..=6).contains(&passes)
            || lanes != 1
        {
            return Err(CapacityError);
        }
        Ok(Self { memory_kib, passes })
    }

    /// Required work memory in KiB.
    pub const fn memory_kib(self) -> u32 {
        self.memory_kib
    }
    /// Number of passes; lanes is always one.
    pub const fn passes(self) -> u32 {
        self.passes
    }
}

/// Sanitized capacity/parameter refusal. No allocation or backend work is allowed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CapacityError;

/// Every PIN-derived KDF operation must use the same aggregate budget.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WorkKind {
    /// Software credential verification.
    Verification,
    /// New software credential creation or validation.
    Enrollment,
    /// TPM PIN-derived object authorization, including enrollment.
    TpmPinDerivation,
}

#[derive(Default)]
struct Usage {
    connections: usize,
    memory_kib: u32,
    uids: [Option<Uid>; MAX_CONNECTIONS],
}

/// One broker's admission controller; storage guards supply cross-process locking.
#[derive(Clone, Default)]
pub struct ResourceBudget(Arc<Mutex<Usage>>);

impl ResourceBudget {
    /// Refuse immediately at capacity; callers must use a separately bounded queue.
    pub fn try_connection(&self) -> Result<ConnectionPermit, CapacityError> {
        let mut usage = self.0.lock().map_err(|_| CapacityError)?;
        if usage.connections >= MAX_CONNECTIONS {
            return Err(CapacityError);
        }
        usage.connections += 1;
        Ok(ConnectionPermit(self.clone()))
    }

    /// Reserve memory and one own-UID work slot before allocating or starting work.
    /// All work kinds share the same cap; a timeout does not release this permit.
    pub fn try_work(
        &self,
        uid: Uid,
        parameters: KdfParameters,
        kind: WorkKind,
    ) -> Result<WorkPermit, CapacityError> {
        let mut usage = self.0.lock().map_err(|_| CapacityError)?;
        let memory = usage
            .memory_kib
            .checked_add(parameters.memory_kib())
            .ok_or(CapacityError)?;
        if memory > MAX_KDF_KIB || usage.uids.contains(&Some(uid)) {
            return Err(CapacityError);
        }
        let slot = usage
            .uids
            .iter()
            .position(Option::is_none)
            .ok_or(CapacityError)?;
        usage.uids[slot] = Some(uid);
        usage.memory_kib = memory;
        Ok(WorkPermit {
            budget: self.clone(),
            slot,
            uid,
            parameters,
            kind,
            deriving: AtomicBool::new(false),
        })
    }
}

/// Non-cloneable live connection accounting.
pub struct ConnectionPermit(ResourceBudget);

impl Drop for ConnectionPermit {
    fn drop(&mut self) {
        if let Ok(mut usage) = self.0.0.lock() {
            usage.connections -= 1;
        }
    }
}

/// Non-cloneable work accounting. A supervisor must own it until worker reaping,
/// even after cancelling the response path. Leaking it fails closed at capacity.
pub struct WorkPermit {
    budget: ResourceBudget,
    slot: usize,
    uid: Uid,
    parameters: KdfParameters,
    kind: WorkKind,
    deriving: AtomicBool,
}

impl WorkPermit {
    /// Exclusively borrow this lease's KDF capacity for one derivation.
    ///
    /// A shared permit cannot charge several simultaneous allocations to one
    /// reservation. Retain this guard until work memory has been erased.
    pub fn try_derivation(&self) -> Result<DerivationPermit<'_>, CapacityError> {
        self.deriving
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .map_err(|_| CapacityError)?;
        Ok(DerivationPermit(&self.deriving))
    }

    /// Work class, for sanitized operational accounting.
    pub const fn kind(&self) -> WorkKind {
        self.kind
    }

    /// Account charged by this permit, for matching a durable reservation.
    pub const fn uid(&self) -> Uid {
        self.uid
    }

    /// Validated KDF parameters whose memory has already been reserved.
    pub const fn parameters(&self) -> KdfParameters {
        self.parameters
    }

    /// Check the exact job binding before allocating or invoking any KDF.
    pub fn covers(&self, uid: Uid, parameters: KdfParameters, kind: WorkKind) -> bool {
        self.uid == uid && self.parameters == parameters && self.kind == kind
    }
}

/// Exclusive borrowed use of one charged KDF allocation. Cannot outlive its
/// owning work lease and cannot be cloned to admit simultaneous derivations.
pub struct DerivationPermit<'a>(&'a AtomicBool);

impl Drop for DerivationPermit<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

impl Drop for WorkPermit {
    fn drop(&mut self) {
        if let Ok(mut usage) = self.budget.0.lock() {
            usage.uids[self.slot] = None;
            usage.memory_kib -= self.parameters.memory_kib();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn uid(n: u32) -> Uid {
        Uid::new(n).unwrap()
    }

    #[test]
    fn exact_connection_limit_and_release() {
        let budget = ResourceBudget::default();
        let mut live: Vec<_> = (0..MAX_CONNECTIONS)
            .map(|_| budget.try_connection().unwrap())
            .collect();
        assert!(budget.try_connection().is_err());
        live.pop();
        assert!(budget.try_connection().is_ok());
    }

    #[test]
    fn all_kdf_classes_share_memory_and_uid_limits() {
        let budget = ResourceBudget::default();
        let mut permits = Vec::new();
        for (n, kind) in [
            WorkKind::Verification,
            WorkKind::Enrollment,
            WorkKind::TpmPinDerivation,
            WorkKind::Verification,
        ]
        .into_iter()
        .enumerate()
        {
            permits.push(
                budget
                    .try_work(uid(n as u32 + 1), KdfParameters::ENROLLMENT, kind)
                    .unwrap(),
            );
        }
        assert!(
            budget
                .try_work(uid(5), KdfParameters::ENROLLMENT, WorkKind::Enrollment)
                .is_err()
        );
        permits.pop();
        assert!(
            budget
                .try_work(uid(1), KdfParameters::ENROLLMENT, WorkKind::Verification)
                .is_err()
        );
        assert!(
            budget
                .try_work(
                    uid(5),
                    KdfParameters::ENROLLMENT,
                    WorkKind::TpmPinDerivation
                )
                .is_ok()
        );
    }

    #[test]
    fn maximum_work_excludes_every_other_kdf() {
        let budget = ResourceBudget::default();
        let permit = budget
            .try_work(
                uid(1),
                KdfParameters::new(MAX_KDF_KIB, 6, 1).unwrap(),
                WorkKind::Enrollment,
            )
            .unwrap();
        assert!(
            budget
                .try_work(uid(2), KdfParameters::ENROLLMENT, WorkKind::Verification)
                .is_err()
        );
        drop(permit);
        assert!(
            budget
                .try_work(uid(2), KdfParameters::ENROLLMENT, WorkKind::Verification)
                .is_ok()
        );
        for params in [
            (65535, 3, 1),
            (262145, 3, 1),
            (65536, 2, 1),
            (65536, 7, 1),
            (65536, 3, 2),
        ] {
            assert!(KdfParameters::new(params.0, params.1, params.2).is_err());
        }
    }

    #[test]
    fn permits_bind_uid_parameters_and_operation() {
        let budget = ResourceBudget::default();
        let work = budget
            .try_work(uid(1), KdfParameters::ENROLLMENT, WorkKind::Verification)
            .unwrap();
        assert!(work.covers(uid(1), KdfParameters::ENROLLMENT, WorkKind::Verification));
        assert!(!work.covers(uid(2), KdfParameters::ENROLLMENT, WorkKind::Verification));
        assert!(!work.covers(
            uid(1),
            KdfParameters::new(MAX_KDF_KIB, 3, 1).unwrap(),
            WorkKind::Verification
        ));
        assert!(!work.covers(uid(1), KdfParameters::ENROLLMENT, WorkKind::Enrollment));
    }

    #[test]
    fn shared_lease_cannot_admit_concurrent_derivations() {
        let budget = ResourceBudget::default();
        let work = budget
            .try_work(uid(1), KdfParameters::ENROLLMENT, WorkKind::Verification)
            .unwrap();
        let deriving = work.try_derivation().unwrap();
        std::thread::scope(|scope| {
            scope.spawn(|| assert!(work.try_derivation().is_err()));
        });
        drop(deriving);
        assert!(work.try_derivation().is_ok());
    }
}
