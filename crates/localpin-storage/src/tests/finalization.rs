//! Finalization regression cases for exact persisted stages and trusted time.

use super::*;

struct SequenceClock(std::collections::VecDeque<TimePoint>);

impl Clock for SequenceClock {
    fn now(&mut self) -> std::result::Result<TimePoint, Unavailable> {
        self.0.pop_front().ok_or(Unavailable)
    }
}

#[test]
fn commit_rejects_prepare_time_rollback_expiry_and_changed_boot() {
    let scenarios = [
        (vec![time(99)], false),
        (vec![other_boot(100)], false),
        (vec![time(100), time(99)], false),
        (vec![time(100), time(60_100)], false),
        (vec![time(100), time(101), time(100)], false),
        (vec![time(100), time(101), time(60_100)], false),
        (vec![time(100), time(101), other_boot(102)], false),
        (vec![time(100), time(101), time(102), time(100)], true),
        (vec![time(100), time(101), time(102), time(101)], true),
        (vec![time(100), time(101), time(102), time(60_100)], true),
        (vec![time(100), time(101), time(102), other_boot(103)], true),
    ];
    for (times, pointer_committed) in scenarios {
        let fixture = Fixture::new();
        let account = account(1000);
        let previous = fixture.enrolled(account);
        let mut authority = Authority(account.incarnation);
        let mut store = fixture.storage.user(account.uid, &mut authority).unwrap();
        let intent = authorized_intent(
            previous,
            EnrollmentAction::Rotate,
            time(100),
            account.incarnation,
        );
        assert_eq!(intent.prepared_at(), time(100));
        let stage = stage_for_intent(&mut store, intent, b"synthetic new credential").unwrap();
        assert_eq!(
            store.commit_generation(intent, stage, &mut SequenceClock(times.into())),
            Err(Error::Time)
        );
        drop(store);
        let mut store = fixture.storage.user(account.uid, &mut authority).unwrap();
        let expected = if pointer_committed {
            intent.next()
        } else {
            previous
        };
        assert_eq!(store.committed_state().unwrap(), expected);
        assert_eq!(
            store.credential().unwrap().generation(),
            expected.generation()
        );
    }
}

struct SharedClock(Arc<Mutex<TimePoint>>);

impl Clock for SharedClock {
    fn now(&mut self) -> std::result::Result<TimePoint, Unavailable> {
        Ok(*self.0.lock().unwrap())
    }
}

struct AfterActiveTempfileSync<F> {
    synced: usize,
    directory: PathBuf,
    previous: CommittedState,
    proposed: CommittedState,
    fired: Arc<AtomicUsize>,
    change: F,
}

impl<F: FnMut()> FaultInjector for AfterActiveTempfileSync<F> {
    fn check(&mut self, boundary: Boundary) -> Result<()> {
        if boundary == Boundary::FileSynced {
            self.synced += 1;
            // Install this hook only after credential staging. The first
            // synchronized replacement is the new throttle, the second active.
            if self.synced == 2 {
                assert_eq!(
                    std::fs::read(self.directory.join(".pending")).unwrap(),
                    Pointer(self.proposed).encode(),
                    "the exact proposed pointer must already be staged and synchronized"
                );
                assert_eq!(
                    std::fs::read(self.directory.join("active")).unwrap(),
                    Pointer(self.previous).encode(),
                    "the previous generation must still be authoritative"
                );
                (self.change)();
                self.fired.fetch_add(1, Ordering::SeqCst);
            }
        }
        Ok(())
    }
}

#[test]
fn expiry_rollback_and_boot_change_during_active_tempfile_sync_never_publish() {
    for changed_time in [time(60_100), time(99), other_boot(101)] {
        let fixture = Fixture::new();
        let account = account(1000);
        let previous = fixture.enrolled(account);
        let mut authority = Authority(account.incarnation);
        let mut store = fixture.storage.user(account.uid, &mut authority).unwrap();
        let original_throttle = store.read_throttle(previous).unwrap();
        let intent = authorized_intent(
            previous,
            EnrollmentAction::Rotate,
            time(100),
            account.incarnation,
        );
        let stage = stage_for_intent(&mut store, intent, b"synthetic new credential").unwrap();
        let clock = Arc::new(Mutex::new(time(100)));
        let fired = Arc::new(AtomicUsize::new(0));
        let changed_clock = clock.clone();
        store.set_fault_injector(Box::new(AfterActiveTempfileSync {
            synced: 0,
            directory: fixture.path.join("users/1000"),
            previous,
            proposed: intent.next(),
            fired: fired.clone(),
            change: move || *changed_clock.lock().unwrap() = changed_time,
        }));
        assert_eq!(
            store.commit_generation(intent, stage, &mut SharedClock(clock)),
            Err(Error::Time)
        );
        assert_eq!(fired.load(Ordering::SeqCst), 1);
        assert_eq!(store.committed_state(), Err(Error::Uncertain));
        drop(store);
        let mut store = fixture.storage.user(account.uid, &mut authority).unwrap();
        assert_eq!(store.committed_state().unwrap(), previous);
        assert_eq!(
            store.credential().unwrap().payload(),
            b"synthetic credential one"
        );
        assert_eq!(store.read_throttle(previous).unwrap(), original_throttle);
        assert!(
            !fixture
                .generation(account, intent.next().generation().get())
                .exists()
        );
    }
}

#[test]
fn account_change_after_active_tempfile_sync_never_publishes_the_staged_generation() {
    struct ChangingAuthority(Arc<AtomicUsize>);
    impl LifecycleAuthority for ChangingAuthority {
        fn current_incarnation(
            &mut self,
            _: Uid,
        ) -> std::result::Result<Incarnation, LifecycleError> {
            Ok(Incarnation::new(if self.0.load(Ordering::SeqCst) == 0 {
                [7; 16]
            } else {
                [8; 16]
            })
            .unwrap())
        }
    }
    let fixture = Fixture::new();
    let account = account(1000);
    let previous = fixture.enrolled(account);
    let revoked = Arc::new(AtomicUsize::new(0));
    let mut authority = ChangingAuthority(revoked.clone());
    let mut store = fixture.storage.user(account.uid, &mut authority).unwrap();
    let original_throttle = store.read_throttle(previous).unwrap();
    let intent = authorized_intent(
        previous,
        EnrollmentAction::Rotate,
        time(100),
        account.incarnation,
    );
    let stage = stage_for_intent(&mut store, intent, b"synthetic new credential").unwrap();
    let fired = Arc::new(AtomicUsize::new(0));
    store.set_fault_injector(Box::new(AfterActiveTempfileSync {
        synced: 0,
        directory: fixture.path.join("users/1000"),
        previous,
        proposed: intent.next(),
        fired: fired.clone(),
        change: move || {
            revoked.store(1, Ordering::SeqCst);
        },
    }));
    assert_eq!(
        store.commit_generation(intent, stage, &mut FixedClock(time(100))),
        Err(Error::Lifecycle)
    );
    assert_eq!(fired.load(Ordering::SeqCst), 1);
    assert_eq!(store.committed_state(), Err(Error::Uncertain));
    drop(store);
    let mut original_authority = Authority(account.incarnation);
    let mut store = fixture
        .storage
        .user(account.uid, &mut original_authority)
        .unwrap();
    assert_eq!(store.committed_state().unwrap(), previous);
    assert_eq!(
        store.credential().unwrap().payload(),
        b"synthetic credential one"
    );
    assert_eq!(store.read_throttle(previous).unwrap(), original_throttle);
    assert!(
        !fixture
            .generation(account, intent.next().generation().get())
            .exists()
    );
}

#[test]
fn a_verified_token_cannot_commit_an_overwritten_stage() {
    let fixture = Fixture::new();
    let account = account(1000);
    let previous = fixture.enrolled(account);
    let mut authority = Authority(account.incarnation);
    let mut store = fixture.storage.user(account.uid, &mut authority).unwrap();
    let intent = authorized_intent(
        previous,
        EnrollmentAction::Rotate,
        time(100),
        account.incarnation,
    );
    let first = stage_for_intent(&mut store, intent, b"synthetic first verified").unwrap();
    let second = stage_for_intent(&mut store, intent, b"synthetic second verified").unwrap();
    drop(second);
    assert_eq!(
        store.commit_generation(intent, first, &mut FixedClock(time(100))),
        Err(Error::Conflict)
    );
    assert_eq!(store.committed_state(), Err(Error::Uncertain));
    drop(store);
    let mut store = fixture.storage.user(account.uid, &mut authority).unwrap();
    assert_eq!(store.committed_state().unwrap(), previous);
    assert_eq!(
        store.credential().unwrap().payload(),
        b"synthetic credential one"
    );
}

#[test]
fn one_lifecycle_source_supports_model_staging_and_acknowledgement_under_lock() {
    let fixture = Fixture::new();
    let account = account(1000);
    fixture.initialized(account);
    let mut authority = Authority(account.incarnation);
    let mut store = fixture.storage.user(account.uid, &mut authority).unwrap();
    let mut model = EnrollmentMachine::new(store.committed_state().unwrap());
    let connection = ConnectionId::new([3; 16]).unwrap();
    let transaction = TransactionId::new([4; 16]).unwrap();
    let binding = model
        .begin_own_user(
            connection,
            account.uid,
            transaction,
            EnrollmentAction::Enroll(Backend::Software),
            time(10),
            &mut store.lifecycle(),
        )
        .unwrap();
    model
        .authorize_with_password_worker(
            binding,
            connection,
            time(10),
            &mut Password,
            &mut store.lifecycle(),
        )
        .unwrap();
    model
        .staged_created(binding, connection, time(10), &mut store.lifecycle())
        .unwrap();
    let stage = store
        .stage_credential(
            CredentialRecord::new(
                account,
                binding.proposed_generation(),
                Backend::Software,
                b"synthetic same authority",
            )
            .unwrap(),
            |_| Ok(()),
        )
        .unwrap();
    model
        .staged_verified(binding, connection, time(11), &mut store.lifecycle())
        .unwrap();
    let intent = model
        .prepare_commit(binding, connection, time(12), &mut store.lifecycle())
        .unwrap();
    let state = store
        .commit_generation(intent, Some(stage), &mut FixedClock(time(13)))
        .unwrap();
    assert_eq!(
        model
            .acknowledge_durable_commit(intent, connection, time(14), &mut store.lifecycle())
            .unwrap(),
        state
    );
    assert_eq!(
        store.credential().unwrap().payload(),
        b"synthetic same authority"
    );
}

#[test]
fn stale_expected_throttle_and_nonadvancing_revision_cannot_replace_disk() {
    let fixture = Fixture::new();
    let account = account(1000);
    fixture.enrolled(account);
    let mut authority = Authority(account.incarnation);
    let mut store = fixture.storage.user(account.uid, &mut authority).unwrap();
    let initial = store
        .read_throttle(store.committed_state().unwrap())
        .unwrap();
    assert_eq!(
        DurableThrottleStore::commit(&mut store, &initial, &initial),
        Err(Error::Conflict)
    );
    let calls = AtomicUsize::new(0);
    attempt(&mut store, time(100), BackendOutcome::Mismatch, &calls).unwrap();
    let current = store
        .read_throttle(store.committed_state().unwrap())
        .unwrap();
    let mut stale = initial;
    stale.revision += 1;
    assert_eq!(
        DurableThrottleStore::commit(&mut store, &initial, &stale),
        Err(Error::Conflict)
    );
    assert_eq!(
        store
            .read_throttle(store.committed_state().unwrap())
            .unwrap(),
        current
    );
}

#[test]
fn in_flight_match_cannot_authorize_after_durable_disable() {
    let fixture = Fixture::new();
    let account = account(1000);
    let previous = fixture.enrolled(account);
    let mut authority = Authority(account.incarnation);
    let mut store = fixture.storage.user(account.uid, &mut authority).unwrap();
    let intent = authorized_intent(
        previous,
        EnrollmentAction::Disable,
        time(101),
        account.incarnation,
    );
    store
        .with_throttle(time(100), |machine, store| {
            let reserved = machine.reserve(time(100)).unwrap().commit(store).unwrap();
            assert_eq!(
                store
                    .commit_generation(intent, None, &mut FixedClock(time(101)))
                    .unwrap(),
                intent.next()
            );
            // Even stale live-generation inputs cannot bypass the store's own fence.
            assert!(
                reserved
                    .complete(BackendOutcome::Match, time(102))
                    .unwrap()
                    .commit(store, previous.account(), Some(previous.generation()))
                    .is_err()
            );
            assert!(matches!(store.credential(), Err(Error::Disabled)));
            Ok(())
        })
        .unwrap();
}

#[test]
fn incomplete_selected_snapshot_cannot_delete_valid_recovery_material() {
    let fixture = Fixture::new();
    let account = account(1000);
    let original = fixture.enrolled(account);
    let missing = CommittedState::new(
        account,
        Generation::new(999).unwrap(),
        Some(Backend::Software),
    );
    std::fs::write(
        fixture.path.join("users/1000/active"),
        Pointer(missing).encode(),
    )
    .unwrap();
    let mut authority = Authority(account.incarnation);
    let mut store = fixture.storage.user(account.uid, &mut authority).unwrap();
    assert!(store.credential().is_err());
    assert!(
        fixture
            .generation(account, original.generation().get())
            .join("credential")
            .exists()
    );
    assert!(fixture.generation(account, 1).join("throttle").exists());
    let calls = AtomicUsize::new(0);
    assert!(attempt(&mut store, time(100), BackendOutcome::Match, &calls).is_err());
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}
