//! Synthetic composition tests; these do not perform credential verification.

use localpin_core::{
    eligibility::{EligibilityAuthority, EligibilityError, EligibilitySnapshot, SessionReference},
    enrollment::{
        CommittedState, EnrollmentAction, EnrollmentMachine, LifecycleAuthority, LifecycleError,
        PasswordWorker, PasswordWorkerError, PasswordWorkerRequest,
    },
    limits::{KdfParameters, MAX_KDF_KIB, ResourceBudget, WorkKind},
    secret::Pin,
    throttle::{
        AttemptResponse, BackendFailure, BackendOutcome, CommitError, DurableThrottleStore,
        PolicyError, RestoredThrottle, Throttle, ThrottleRecord,
    },
    types::{
        AccountId, Backend, BootId, ConnectionId, CredentialVerifier, Generation, Incarnation,
        TimePoint, TransactionId, Uid, VerificationCompletion, VerificationJob,
    },
};

fn account() -> AccountId {
    AccountId {
        uid: Uid::new(1000).unwrap(),
        incarnation: Incarnation::new([1; 16]).unwrap(),
    }
}

fn now(millis: u64) -> TimePoint {
    TimePoint {
        boot: BootId::new([1; 16]).unwrap(),
        millis,
    }
}

struct Authority;
impl LifecycleAuthority for Authority {
    fn current_incarnation(&mut self, _: Uid) -> Result<Incarnation, LifecycleError> {
        Ok(account().incarnation)
    }
}
impl EligibilityAuthority for Authority {
    fn check(&mut self, account: AccountId) -> Result<EligibilitySnapshot, EligibilityError> {
        Ok(EligibilitySnapshot::from_trusted_check(
            account,
            SessionReference::new([1; 16]).unwrap(),
        ))
    }
}

struct Store {
    record: ThrottleRecord,
    fail: bool,
    writes: usize,
}
impl DurableThrottleStore for Store {
    type Error = ();
    fn commit(
        &mut self,
        expected: &ThrottleRecord,
        replacement: &ThrottleRecord,
    ) -> Result<(), ()> {
        if self.fail || self.record != *expected {
            return Err(());
        }
        self.record = *replacement;
        self.writes += 1;
        Ok(())
    }
}

struct SyntheticVerifier {
    calls: usize,
    outcome: BackendOutcome,
}
impl CredentialVerifier for SyntheticVerifier {
    fn verify<'a>(&mut self, job: VerificationJob<'a>) -> VerificationCompletion<'a> {
        assert_eq!(job.account(), account());
        assert_eq!(job.generation(), Generation::new(1).unwrap());
        assert_eq!(job.backend(), Backend::Software);
        assert_eq!(job.parameters(), KdfParameters::ENROLLMENT);
        assert_eq!(job.pin().expose(), b"000001");
        self.calls += 1;
        job.finish(self.outcome)
    }
}

fn fixture() -> (EnrollmentMachine, Throttle, Store) {
    let generation = Generation::new(1).unwrap();
    let record = ThrottleRecord::initial(account(), generation, now(0));
    let RestoredThrottle::Ready(throttle) =
        Throttle::restore(record, account(), generation, now(0)).unwrap()
    else {
        panic!("new synthetic fixture")
    };
    (
        EnrollmentMachine::new(CommittedState::new(
            account(),
            generation,
            Some(Backend::Software),
        )),
        throttle,
        Store {
            record,
            fail: false,
            writes: 0,
        },
    )
}

#[test]
fn authorization_composes_live_fences_held_capacity_and_two_durable_writes() {
    let (credentials, mut throttle, mut store) = fixture();
    let fence = credentials
        .begin_verification(&mut Authority, &mut Authority)
        .unwrap();
    let budget = ResourceBudget::default();
    let work = budget
        .try_work(
            account().uid,
            KdfParameters::ENROLLMENT,
            WorkKind::Verification,
        )
        .unwrap();
    let reserved = throttle
        .reserve(now(1))
        .unwrap()
        .commit(&mut store)
        .unwrap();
    assert_eq!(store.writes, 1);
    let mut verifier = SyntheticVerifier {
        calls: 0,
        outcome: BackendOutcome::Match,
    };
    let job = VerificationJob::new(
        reserved,
        fence.backend(),
        Pin::parse(b"000001").unwrap(),
        work,
        KdfParameters::ENROLLMENT,
    )
    .unwrap();
    let result = verifier.verify(job);
    assert!(
        budget
            .try_work(
                account().uid,
                KdfParameters::ENROLLMENT,
                WorkKind::Verification
            )
            .is_err()
    );
    credentials
        .revalidate_verification(fence, &mut Authority, &mut Authority)
        .unwrap();
    let response = result
        .complete(now(2))
        .unwrap()
        .commit(&mut store, fence.account(), Some(fence.generation()))
        .unwrap();
    credentials
        .revalidate_verification(fence, &mut Authority, &mut Authority)
        .unwrap();
    assert_eq!(response, AttemptResponse::Success);
    assert_eq!(store.writes, 2);
    assert_eq!(verifier.calls, 1);
    assert_eq!(store.record.last_attempt, 1);
    assert_eq!(store.record.recent_len, 0);
    assert!(store.record.pending.is_none());
    assert!(
        budget
            .try_work(
                account().uid,
                KdfParameters::ENROLLMENT,
                WorkKind::Verification
            )
            .is_ok()
    );
}

#[test]
fn failed_reservation_cannot_call_the_verifier() {
    let (_, mut throttle, mut store) = fixture();
    store.fail = true;
    let mut verifier = SyntheticVerifier {
        calls: 0,
        outcome: BackendOutcome::Match,
    };
    if let Ok(reserved) = throttle.reserve(now(1)).unwrap().commit(&mut store) {
        let budget = ResourceBudget::default();
        let work = budget
            .try_work(
                account().uid,
                KdfParameters::ENROLLMENT,
                WorkKind::Verification,
            )
            .unwrap();
        let job = VerificationJob::new(
            reserved,
            Backend::Software,
            Pin::parse(b"000001").unwrap(),
            work,
            KdfParameters::ENROLLMENT,
        )
        .unwrap();
        let _completion = verifier.verify(job);
    }
    assert_eq!(verifier.calls, 0);
    assert_eq!(store.writes, 0);
}

#[test]
fn verification_jobs_reject_wrong_uid_parameters_and_work_kind_before_backend_use() {
    let maximum = KdfParameters::new(MAX_KDF_KIB, 3, 1).unwrap();
    for (uid, permit_parameters, kind, backend, job_parameters) in [
        (
            Uid::new(1001).unwrap(),
            KdfParameters::ENROLLMENT,
            WorkKind::Verification,
            Backend::Software,
            KdfParameters::ENROLLMENT,
        ),
        (
            account().uid,
            KdfParameters::ENROLLMENT,
            WorkKind::Verification,
            Backend::Software,
            maximum,
        ),
        (
            account().uid,
            maximum,
            WorkKind::Verification,
            Backend::Software,
            KdfParameters::ENROLLMENT,
        ),
        (
            account().uid,
            KdfParameters::ENROLLMENT,
            WorkKind::Verification,
            Backend::Software,
            KdfParameters::new(64 * 1024, 6, 1).unwrap(),
        ),
        (
            account().uid,
            KdfParameters::ENROLLMENT,
            WorkKind::TpmPinDerivation,
            Backend::Software,
            KdfParameters::ENROLLMENT,
        ),
        (
            account().uid,
            KdfParameters::ENROLLMENT,
            WorkKind::Enrollment,
            Backend::Software,
            KdfParameters::ENROLLMENT,
        ),
        (
            account().uid,
            KdfParameters::ENROLLMENT,
            WorkKind::Verification,
            Backend::Tpm2,
            KdfParameters::ENROLLMENT,
        ),
    ] {
        let (_, mut throttle, mut store) = fixture();
        let budget = ResourceBudget::default();
        let work = budget.try_work(uid, permit_parameters, kind).unwrap();
        let reserved = throttle
            .reserve(now(1))
            .unwrap()
            .commit(&mut store)
            .unwrap();
        let mut verifier = SyntheticVerifier {
            calls: 0,
            outcome: BackendOutcome::Match,
        };
        if let Ok(job) = VerificationJob::new(
            reserved,
            backend,
            Pin::parse(b"000001").unwrap(),
            work,
            job_parameters,
        ) {
            let _completion = verifier.verify(job);
            panic!("invalid binding reached the backend");
        }
        assert_eq!(verifier.calls, 0);
        assert_eq!(store.writes, 1);
        assert_eq!(store.record.last_attempt, 1);
        assert!(store.record.pending.is_some());
        assert!(throttle.reserve(now(2)).is_err());
        assert!(budget.try_work(uid, permit_parameters, kind).is_ok());
    }
}

#[test]
fn completed_cancelled_and_technical_jobs_keep_their_durable_attempts_consumed() {
    for (outcome, response) in [
        (BackendOutcome::Mismatch, AttemptResponse::Mismatch),
        (BackendOutcome::Cancelled, AttemptResponse::Cancelled),
        (
            BackendOutcome::Unavailable(BackendFailure::Technical),
            AttemptResponse::Unavailable(BackendFailure::Technical),
        ),
    ] {
        let (_, mut throttle, mut store) = fixture();
        let budget = ResourceBudget::default();
        let work = budget
            .try_work(
                account().uid,
                KdfParameters::ENROLLMENT,
                WorkKind::Verification,
            )
            .unwrap();
        let reserved = throttle
            .reserve(now(1))
            .unwrap()
            .commit(&mut store)
            .unwrap();
        let job = VerificationJob::new(
            reserved,
            Backend::Software,
            Pin::parse(b"000001").unwrap(),
            work,
            KdfParameters::ENROLLMENT,
        )
        .unwrap();
        let mut verifier = SyntheticVerifier { calls: 0, outcome };
        let completion = verifier.verify(job);
        assert!(
            budget
                .try_work(
                    account().uid,
                    KdfParameters::ENROLLMENT,
                    WorkKind::Verification,
                )
                .is_err()
        );
        let observed = completion
            .complete(now(2))
            .unwrap()
            .commit(&mut store, account(), Some(Generation::new(1).unwrap()))
            .unwrap();
        assert_eq!(observed, response);
        assert_eq!(verifier.calls, 1);
        assert_eq!(store.writes, 2);
        assert_eq!(store.record.last_attempt, 1);
        assert_eq!(store.record.recent_len, 1);
        assert!(store.record.pending.is_none());
        assert!(
            budget
                .try_work(
                    account().uid,
                    KdfParameters::ENROLLMENT,
                    WorkKind::Verification,
                )
                .is_ok()
        );
    }
}

#[test]
fn tpm_jobs_accept_only_the_reserved_pin_derivation_work_and_abandonment_is_consumed() {
    let (_, mut throttle, mut store) = fixture();
    let budget = ResourceBudget::default();
    let work = budget
        .try_work(
            account().uid,
            KdfParameters::ENROLLMENT,
            WorkKind::TpmPinDerivation,
        )
        .unwrap();
    let reserved = throttle
        .reserve(now(1))
        .unwrap()
        .commit(&mut store)
        .unwrap();
    let attempt_id = reserved.id();
    let job = VerificationJob::new(
        reserved,
        Backend::Tpm2,
        Pin::parse(b"000001").unwrap(),
        work,
        KdfParameters::ENROLLMENT,
    )
    .unwrap();
    assert_eq!(job.id(), attempt_id);
    assert_eq!(job.backend(), Backend::Tpm2);
    assert!(
        budget
            .try_work(
                account().uid,
                KdfParameters::ENROLLMENT,
                WorkKind::Verification,
            )
            .is_err()
    );
    drop(job);
    assert!(store.record.pending.is_some());
    assert!(throttle.reserve(now(2)).is_err());
    assert_eq!(store.record.last_attempt, 1);
    assert!(
        budget
            .try_work(
                account().uid,
                KdfParameters::ENROLLMENT,
                WorkKind::TpmPinDerivation,
            )
            .is_ok()
    );
}

struct TrustedSyntheticWorker;
impl PasswordWorker for TrustedSyntheticWorker {
    fn verify_existing_password(
        &mut self,
        _: PasswordWorkerRequest,
    ) -> Result<TimePoint, PasswordWorkerError> {
        Ok(now(3))
    }
}

#[test]
fn durable_disable_fences_a_previously_reserved_matching_result() {
    let (mut credentials, mut throttle, mut store) = fixture();
    let fence = credentials
        .begin_verification(&mut Authority, &mut Authority)
        .unwrap();
    let reserved = throttle
        .reserve(now(1))
        .unwrap()
        .commit(&mut store)
        .unwrap();
    let connection = ConnectionId::new([2; 16]).unwrap();
    let binding = credentials
        .begin_own_user(
            connection,
            account().uid,
            TransactionId::new([3; 16]).unwrap(),
            EnrollmentAction::Disable,
            now(2),
            &mut Authority,
        )
        .unwrap();
    credentials
        .authorize_with_password_worker(
            binding,
            connection,
            now(2),
            &mut TrustedSyntheticWorker,
            &mut Authority,
        )
        .unwrap();
    let intent = credentials
        .prepare_commit(binding, connection, now(4), &mut Authority)
        .unwrap();
    // Simulate successful M3 storage commit, then acknowledge its revocation.
    let disabled = credentials
        .acknowledge_durable_commit(intent, connection, now(4), &mut Authority)
        .unwrap();
    assert!(
        credentials
            .revalidate_verification(fence, &mut Authority, &mut Authority)
            .is_err()
    );
    assert_eq!(
        reserved
            .complete(BackendOutcome::Match, now(5))
            .unwrap()
            .commit(
                &mut store,
                disabled.account(),
                disabled.backend().map(|_| disabled.generation())
            ),
        Err(CommitError::Policy(PolicyError::StaleCredential))
    );
    assert!(store.record.pending.is_some());
    assert_eq!(store.writes, 1);
}
