//! Real software KDF integration with disposable storage and synthetic accounts.

use super::*;
use localpin_core::types::Randomness;
use localpin_credentials::software::{SoftwareVerifier, enroll_with_random, validate_enrollment};

struct FixtureRandom;

impl Randomness for FixtureRandom {
    fn fill(&mut self, destination: &mut [u8]) -> std::result::Result<(), Unavailable> {
        destination.fill(7);
        Ok(())
    }
}

/// Follow the complete password/stage/commit sequence using the same lifecycle
/// source and global work budget. Only account/password authority is synthetic.
fn commit_software(
    store: &mut UserStore<'_>,
    action: EnrollmentAction,
    pin: &[u8],
    now: TimePoint,
    budget: &ResourceBudget,
) -> CommittedState {
    let previous = store.committed_state().unwrap();
    let mut model = EnrollmentMachine::new(previous);
    let connection = ConnectionId::new([3; 16]).unwrap();
    let transaction = TransactionId::new([4; 16]).unwrap();
    let binding = model
        .begin_own_user(
            connection,
            previous.account().uid,
            transaction,
            action,
            now,
            &mut store.lifecycle(),
        )
        .unwrap();
    model
        .authorize_with_password_worker(
            binding,
            connection,
            now,
            &mut Password,
            &mut store.lifecycle(),
        )
        .unwrap();
    model
        .staged_created(binding, connection, now, &mut store.lifecycle())
        .unwrap();
    let pin = Pin::parse(pin).unwrap();
    let credential = enroll_with_random(
        previous.account(),
        binding.proposed_generation(),
        &pin,
        budget,
        &mut FixtureRandom,
    )
    .unwrap();
    let expected = credential.encode().unwrap();
    let stage = store
        .stage_credential(credential, |persisted| {
            assert_eq!(persisted.encode().unwrap().expose(), expected.expose());
            assert_eq!(persisted.account(), previous.account());
            assert_eq!(persisted.generation(), binding.proposed_generation());
            match validate_enrollment(persisted, &pin, budget) {
                Ok(true) => Ok(()),
                _ => Err(Error::Corrupt),
            }
        })
        .unwrap();
    model
        .staged_verified(binding, connection, now, &mut store.lifecycle())
        .unwrap();
    let intent = model
        .prepare_commit(binding, connection, now, &mut store.lifecycle())
        .unwrap();
    let committed = store
        .commit_generation(intent, Some(stage), &mut FixedClock(now))
        .unwrap();
    assert_eq!(
        model
            .acknowledge_durable_commit(intent, connection, now, &mut store.lifecycle())
            .unwrap(),
        committed
    );
    committed
}

fn software_attempt(
    store: &mut UserStore<'_>,
    pin: &[u8],
    now: TimePoint,
    budget: &ResourceBudget,
    calls: &AtomicUsize,
) -> Result<AttemptResponse> {
    let state = store.committed_state()?;
    let credential = store.credential()?;
    let mut verifier = SoftwareVerifier::new(&credential).map_err(|_| Error::Corrupt)?;
    let parameters = verifier.parameters();
    store.with_throttle(now, |machine, store| {
        let reserved = machine
            .reserve(now)
            .map_err(|_| Error::Time)?
            .commit(store)
            .map_err(|_| Error::Uncertain)?;
        // Inspect the authoritative file after the reservation acknowledgement
        // and before any real Argon2 allocation or backend call.
        let persisted = store.read_throttle(state)?;
        assert_eq!(persisted.pending.unwrap().attempt, reserved.id().get());
        assert_eq!(persisted.account, reserved.account());
        assert_eq!(persisted.generation, reserved.generation());
        let work = budget
            .try_work(state.account().uid, parameters, WorkKind::Verification)
            .unwrap();
        let job = VerificationJob::new(
            reserved,
            Backend::Software,
            Pin::parse(pin).unwrap(),
            work,
            parameters,
        )
        .unwrap();
        calls.fetch_add(1, Ordering::SeqCst);
        let completion = verifier
            .verify(job)
            .complete(now)
            .map_err(|_| Error::Time)?;
        // The cryptographic result is deliberately still opaque here. Disk
        // continues to show a pending, consumed attempt until commit succeeds.
        assert!(store.read_throttle(state)?.pending.is_some());
        completion
            .commit(store, state.account(), Some(state.generation()))
            .map_err(|_| Error::Uncertain)
    })
}

#[test]
fn software_enrollment_trials_the_persisted_record_and_only_durable_match_succeeds() {
    let fixture = Fixture::new();
    let account = account(1000);
    fixture.initialized(account);
    let budget = ResourceBudget::default();
    let mut authority = Authority(account.incarnation);
    let mut store = fixture.storage.user(account.uid, &mut authority).unwrap();
    let state = commit_software(
        &mut store,
        EnrollmentAction::Enroll(Backend::Software),
        b"000001",
        time(10),
        &budget,
    );
    let calls = AtomicUsize::new(0);
    assert_eq!(
        software_attempt(&mut store, b"000002", time(100), &budget, &calls).unwrap(),
        AttemptResponse::Mismatch
    );
    let mismatch = store.read_throttle(state).unwrap();
    assert_eq!(mismatch.recent_len, 1);
    assert!(mismatch.pending.is_none());
    assert_eq!(
        software_attempt(&mut store, b"000001", time(101), &budget, &calls).unwrap(),
        AttemptResponse::Success
    );
    let matched = store.read_throttle(state).unwrap();
    assert_eq!(matched.last_attempt, 2);
    assert_eq!(matched.recent_len, 0);
    assert!(matched.pending.is_none());
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    drop(store);
    let store = fixture.storage.user(account.uid, &mut authority).unwrap();
    assert_eq!(store.read_throttle(state).unwrap(), matched);
}

#[test]
fn real_software_results_do_not_escape_reservation_or_completion_write_faults() {
    let fixture = Fixture::new();
    let account = account(1000);
    fixture.initialized(account);
    let budget = ResourceBudget::default();
    let mut authority = Authority(account.incarnation);
    let mut store = fixture.storage.user(account.uid, &mut authority).unwrap();
    commit_software(
        &mut store,
        EnrollmentAction::Enroll(Backend::Software),
        b"000001",
        time(10),
        &budget,
    );
    drop(store);
    let calls = AtomicUsize::new(0);
    let mut tick = 100;
    // M3 exhaustively covers every write boundary with synthetic outcomes. Here
    // test both pre-rename and final durability failures with real KDF results.
    for boundary in [Boundary::Written, Boundary::DirectorySynced] {
        for occurrence in [1, 2] {
            let mut store = fixture.storage.user(account.uid, &mut authority).unwrap();
            store.with_throttle(time(tick), |_, _| Ok(())).unwrap();
            let state = store.committed_state().unwrap();
            let before = store.read_throttle(state).unwrap();
            let called_before = calls.load(Ordering::SeqCst);
            store.set_fault_injector(FailAt::boxed(boundary, occurrence));
            assert!(software_attempt(&mut store, b"000001", time(tick), &budget, &calls).is_err());
            assert_eq!(calls.load(Ordering::SeqCst) - called_before, occurrence - 1);
            assert_eq!(store.committed_state(), Err(Error::Uncertain));
            store.set_fault_injector(Box::new(NoFaults));
            assert!(software_attempt(&mut store, b"000001", time(tick), &budget, &calls).is_err());
            assert_eq!(calls.load(Ordering::SeqCst) - called_before, occurrence - 1);
            drop(store);
            let store = fixture.storage.user(account.uid, &mut authority).unwrap();
            let after = store.read_throttle(state).unwrap();
            assert!(after.last_attempt <= before.last_attempt + 1);
            if occurrence == 2 {
                assert_eq!(after.last_attempt, before.last_attempt + 1);
            }
            tick += 1;
        }
    }
}

#[test]
fn failed_real_trial_leaves_the_old_software_pin_authoritative() {
    let fixture = Fixture::new();
    let account = account(1000);
    fixture.initialized(account);
    let budget = ResourceBudget::default();
    let mut authority = Authority(account.incarnation);
    let mut store = fixture.storage.user(account.uid, &mut authority).unwrap();
    let previous = commit_software(
        &mut store,
        EnrollmentAction::Enroll(Backend::Software),
        b"000001",
        time(10),
        &budget,
    );
    let replacement = enroll_with_random(
        account,
        previous.generation().next().unwrap(),
        &Pin::parse(b"000002").unwrap(),
        &budget,
        &mut FixtureRandom,
    )
    .unwrap();
    let trial_pin = Pin::parse(b"000003").unwrap();
    assert!(
        store
            .stage_credential(replacement, |persisted| {
                match validate_enrollment(persisted, &trial_pin, &budget) {
                    Ok(true) => Ok(()),
                    _ => Err(Error::Corrupt),
                }
            })
            .is_err()
    );
    drop(store);
    let mut store = fixture.storage.user(account.uid, &mut authority).unwrap();
    assert_eq!(store.committed_state().unwrap(), previous);
    let calls = AtomicUsize::new(0);
    assert_eq!(
        software_attempt(&mut store, b"000001", time(100), &budget, &calls).unwrap(),
        AttemptResponse::Success
    );
}

#[test]
fn real_matching_completion_is_fenced_by_rotation_and_disable() {
    let fixture = Fixture::new();
    let account = account(1000);
    fixture.initialized(account);
    let budget = ResourceBudget::default();
    let mut authority = Authority(account.incarnation);
    let mut store = fixture.storage.user(account.uid, &mut authority).unwrap();
    commit_software(
        &mut store,
        EnrollmentAction::Enroll(Backend::Software),
        b"000001",
        time(10),
        &budget,
    );

    for (index, action) in [EnrollmentAction::Rotate, EnrollmentAction::Disable]
        .into_iter()
        .enumerate()
    {
        let tick = 100 + index as u64 * 100;
        let previous = store.committed_state().unwrap();
        let candidate = if action == EnrollmentAction::Rotate {
            b"000001"
        } else {
            b"000002"
        };
        let intent = authorized_intent(previous, action, time(tick + 1), account.incarnation);
        let stage = if action == EnrollmentAction::Rotate {
            let pin = Pin::parse(b"000002").unwrap();
            let replacement = enroll_with_random(
                account,
                intent.next().generation(),
                &pin,
                &budget,
                &mut FixtureRandom,
            )
            .unwrap();
            Some(
                store
                    .stage_credential(replacement, |persisted| {
                        assert!(validate_enrollment(persisted, &pin, &budget).unwrap());
                        Ok(())
                    })
                    .unwrap(),
            )
        } else {
            None
        };
        let credential = store.credential().unwrap();
        let mut verifier = SoftwareVerifier::new(&credential).unwrap();
        let parameters = verifier.parameters();
        store
            .with_throttle(time(tick), |machine, store| {
                let reserved = machine.reserve(time(tick)).unwrap().commit(store).unwrap();
                let work = budget
                    .try_work(account.uid, parameters, WorkKind::Verification)
                    .unwrap();
                let job = VerificationJob::new(
                    reserved,
                    Backend::Software,
                    Pin::parse(candidate).unwrap(),
                    work,
                    parameters,
                )
                .unwrap();
                let completion = verifier.verify(job).complete(time(tick)).unwrap();
                // The backend did produce Match. Its reset proposal is still
                // incapable of yielding authorization after generation change.
                assert_eq!(completion.record().recent_len, 0);
                store
                    .commit_generation(intent, stage, &mut FixedClock(time(tick + 1)))
                    .unwrap();
                assert!(
                    completion
                        .commit(store, account, Some(previous.generation()))
                        .is_err()
                );
                Ok(())
            })
            .unwrap();
        assert_eq!(store.committed_state().unwrap(), intent.next());
        if action == EnrollmentAction::Rotate {
            let calls = AtomicUsize::new(0);
            assert_eq!(
                software_attempt(&mut store, b"000001", time(tick + 2), &budget, &calls).unwrap(),
                AttemptResponse::Mismatch
            );
            assert_eq!(
                software_attempt(&mut store, b"000002", time(tick + 3), &budget, &calls).unwrap(),
                AttemptResponse::Success
            );
        } else {
            let calls = AtomicUsize::new(0);
            assert!(
                software_attempt(&mut store, candidate, time(tick + 2), &budget, &calls).is_err()
            );
            assert_eq!(calls.load(Ordering::SeqCst), 0);
        }
    }
}
