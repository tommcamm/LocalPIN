//! Disposable filesystem/process evidence with synthetic account authorities.
//! The backend module exercises real KDFs with public, test-only PIN fixtures.

mod backends;
mod finalization;
#[cfg(feature = "tpm-simulator-tests")]
mod tpm_backend;

use super::*;
use localpin_core::{
    enrollment::{
        Administrator, EnrollmentAction, EnrollmentMachine, LifecycleError, PasswordWorker,
        PasswordWorkerError, PasswordWorkerRequest, UnmanagedUnixAccounts,
    },
    limits::{KdfParameters, ResourceBudget, WorkKind},
    secret::Pin,
    throttle::{AttemptResponse, BackendOutcome, ReserveError},
    types::{
        Backend, BootId, ConnectionId, CredentialVerifier, Incarnation, TransactionId, Unavailable,
        VerificationCompletion, VerificationJob,
    },
};
use std::{
    fs::{DirBuilder, OpenOptions},
    io::Write,
    os::unix::fs::{DirBuilderExt, OpenOptionsExt},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{
        Mutex, MutexGuard,
        atomic::{AtomicUsize, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

static NEXT_FIXTURE: AtomicUsize = AtomicUsize::new(0);
// Child creation briefly inherits descriptors until exec closes CLOEXEC files.
// Serialize fixtures so one test's fork cannot transiently retain a different
// test's lock after its parent guard has been dropped.
pub(super) static TEST_SERIAL: Mutex<()> = Mutex::new(());
const WRITE_BOUNDARIES: [Boundary; 5] = [
    Boundary::TempCreated,
    Boundary::Written,
    Boundary::FileSynced,
    Boundary::Renamed,
    Boundary::DirectorySynced,
];

struct Fixture {
    path: PathBuf,
    storage: Storage,
    _serial: MutexGuard<'static, ()>,
}

impl Fixture {
    fn new() -> Self {
        let serial = TEST_SERIAL
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let path = std::env::temp_dir().join(format!(
            "localpin-storage-{}-{}",
            std::process::id(),
            NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed)
        ));
        DirBuilder::new().mode(0o700).create(&path).unwrap();
        let storage = Storage::from_dir(Dir::test(File::open(&path).unwrap()).unwrap()).unwrap();
        Self {
            path,
            storage,
            _serial: serial,
        }
    }

    fn initialized(&self, account: AccountId) {
        self.storage
            .initialize(account, time(0), &mut Authority(account.incarnation))
            .unwrap();
    }

    fn enrolled(&self, account: AccountId) -> CommittedState {
        self.initialized(account);
        let mut authority = Authority(account.incarnation);
        let mut store = self.storage.user(account.uid, &mut authority).unwrap();
        commit_action(
            &mut store,
            EnrollmentAction::Enroll(Backend::Software),
            time(1),
            b"synthetic credential one",
        )
        .unwrap()
    }

    fn generation(&self, account: AccountId, generation: u64) -> PathBuf {
        self.path
            .join("users")
            .join(account.uid.get().to_string())
            .join(format!("generation-{generation}"))
    }

    fn child(&self, scenario: &str) -> Command {
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args([
                "--exact",
                "tests::subprocess_entry",
                "--ignored",
                "--nocapture",
            ])
            .env("LOCALPIN_STORAGE_CHILD", scenario)
            .env("LOCALPIN_STORAGE_FIXTURE", &self.path)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        command
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        // All tests retain the singleton until fixture cleanup. No real state
        // outside this exclusively created temporary directory is touched.
        std::fs::remove_dir_all(&self.path).unwrap();
    }
}

#[derive(Clone, Copy)]
struct Authority(Incarnation);

impl LifecycleAuthority for Authority {
    fn current_incarnation(&mut self, _: Uid) -> std::result::Result<Incarnation, LifecycleError> {
        Ok(self.0)
    }
}

struct FixedClock(TimePoint);

impl Clock for FixedClock {
    fn now(&mut self) -> std::result::Result<TimePoint, Unavailable> {
        Ok(self.0)
    }
}

struct Password;

impl PasswordWorker for Password {
    fn verify_existing_password(
        &mut self,
        request: PasswordWorkerRequest,
    ) -> std::result::Result<TimePoint, PasswordWorkerError> {
        Ok(request.started_at())
    }
}

fn account(uid: u32) -> AccountId {
    AccountId {
        uid: Uid::new(uid).unwrap(),
        incarnation: Incarnation::new([7; 16]).unwrap(),
    }
}

fn time(millis: u64) -> TimePoint {
    TimePoint {
        boot: BootId::new([1; 16]).unwrap(),
        millis,
    }
}

fn other_boot(millis: u64) -> TimePoint {
    TimePoint {
        boot: BootId::new([2; 16]).unwrap(),
        millis,
    }
}

fn authorized_intent(
    state: CommittedState,
    action: EnrollmentAction,
    now: TimePoint,
    live_incarnation: Incarnation,
) -> CommitIntent {
    let mut machine = EnrollmentMachine::new(state);
    let connection = ConnectionId::new([1; 16]).unwrap();
    let transaction = TransactionId::new([2; 16]).unwrap();
    let mut lifecycle = Authority(live_incarnation);
    let binding = if action == EnrollmentAction::AdministrativeRecovery {
        machine
            .begin_administrative_recovery(
                connection,
                Administrator::from_kernel_peer_uid(connection, 0).unwrap(),
                transaction,
                now,
                &mut lifecycle,
            )
            .unwrap()
    } else {
        let binding = machine
            .begin_own_user(
                connection,
                state.account().uid,
                transaction,
                action,
                now,
                &mut lifecycle,
            )
            .unwrap();
        machine
            .authorize_with_password_worker(binding, connection, now, &mut Password, &mut lifecycle)
            .unwrap();
        if !matches!(action, EnrollmentAction::Disable) {
            machine
                .staged_created(binding, connection, now, &mut lifecycle)
                .unwrap();
            machine
                .staged_verified(binding, connection, now, &mut lifecycle)
                .unwrap();
        }
        binding
    };
    machine
        .prepare_commit(binding, connection, now, &mut lifecycle)
        .unwrap()
}

fn stage_for_intent(
    store: &mut UserStore<'_>,
    intent: CommitIntent,
    payload: &[u8],
) -> Result<Option<VerifiedStage>> {
    intent
        .next()
        .backend()
        .map(|backend| {
            let record = CredentialRecord::new(
                intent.next().account(),
                intent.next().generation(),
                backend,
                payload,
            )
            .unwrap();
            store.stage_credential(record, |persisted| {
                assert_eq!(persisted.payload(), payload);
                Ok(())
            })
        })
        .transpose()
}

fn commit_action(
    store: &mut UserStore<'_>,
    action: EnrollmentAction,
    now: TimePoint,
    payload: &[u8],
) -> Result<CommittedState> {
    let state = store.committed_state()?;
    let intent = authorized_intent(state, action, now, state.account().incarnation);
    let stage = stage_for_intent(store, intent, payload)?;
    store.commit_generation(intent, stage, &mut FixedClock(now))
}

struct SyntheticVerifier<'a> {
    calls: &'a AtomicUsize,
    outcome: BackendOutcome,
}

impl CredentialVerifier for SyntheticVerifier<'_> {
    fn verify<'a>(&mut self, job: VerificationJob<'a>) -> VerificationCompletion<'a> {
        assert_eq!(job.pin().expose(), b"000001");
        self.calls.fetch_add(1, Ordering::SeqCst);
        job.finish(self.outcome)
    }
}

fn attempt(
    store: &mut UserStore<'_>,
    now: TimePoint,
    outcome: BackendOutcome,
    calls: &AtomicUsize,
) -> Result<Option<AttemptResponse>> {
    let state = store.committed_state()?;
    store.with_throttle(now, |throttle, store| {
        let intent = match throttle.reserve(now) {
            Ok(intent) => intent,
            Err(ReserveError::Cooldown { .. }) => return Ok(None),
            Err(_) => return Err(Error::Time),
        };
        let reserved = intent.commit(store).map_err(|_| Error::Uncertain)?;
        let parameters = KdfParameters::ENROLLMENT;
        let budget = ResourceBudget::default();
        let work = budget
            .try_work(state.account().uid, parameters, WorkKind::Verification)
            .unwrap();
        let job = VerificationJob::new(
            reserved,
            state.backend().unwrap(),
            Pin::parse(b"000001").unwrap(),
            work,
            parameters,
        )
        .unwrap();
        let completion = SyntheticVerifier { calls, outcome }.verify(job);
        completion
            .complete(now)
            .map_err(|_| Error::Time)?
            .commit(store, state.account(), Some(state.generation()))
            .map(Some)
            .map_err(|_| Error::Uncertain)
    })
}

struct FailAt {
    boundary: Boundary,
    occurrence: usize,
    seen: usize,
    error: Error,
}

impl FailAt {
    fn boxed(boundary: Boundary, occurrence: usize) -> Box<Self> {
        Box::new(Self {
            boundary,
            occurrence,
            seen: 0,
            error: Error::Injected,
        })
    }
}

impl FaultInjector for FailAt {
    fn check(&mut self, boundary: Boundary) -> Result<()> {
        if self.boundary == boundary {
            self.seen += 1;
            if self.seen == self.occurrence {
                return Err(self.error);
            }
        }
        Ok(())
    }
}

#[test]
fn reserve_and_completion_faults_never_release_uncommitted_results() {
    for boundary in WRITE_BOUNDARIES {
        for occurrence in [1, 2] {
            let fixture = Fixture::new();
            let account = account(1000);
            fixture.enrolled(account);
            let mut lifecycle = Authority(account.incarnation);
            let mut store = fixture.storage.user(account.uid, &mut lifecycle).unwrap();
            let calls = AtomicUsize::new(0);
            store.set_fault_injector(FailAt::boxed(boundary, occurrence));
            assert!(attempt(&mut store, time(100), BackendOutcome::Match, &calls).is_err());
            assert_eq!(calls.load(Ordering::SeqCst), occurrence - 1);
            assert_eq!(store.committed_state(), Err(Error::Uncertain));
            store.set_fault_injector(Box::new(NoFaults));
            assert!(attempt(&mut store, time(101), BackendOutcome::Match, &calls).is_err());
            assert_eq!(calls.load(Ordering::SeqCst), occurrence - 1);
            drop(store);
            let mut store = fixture.storage.user(account.uid, &mut lifecycle).unwrap();
            let record = store
                .read_throttle(store.committed_state().unwrap())
                .unwrap();
            assert!(record.last_attempt <= 1);
            if occurrence == 2 {
                assert_eq!(record.last_attempt, 1);
            }
            // Authoritative reload must retain a reservation or its consumed
            // debt, or the fully committed successful reset after rename.
            store
                .with_throttle(time(101), |machine, _| {
                    assert!(machine.record().pending.is_none());
                    assert_eq!(machine.record().last_attempt, record.last_attempt);
                    Ok(())
                })
                .unwrap();
        }
    }
}

#[test]
fn generation_commit_faults_leave_only_a_complete_old_or_new_authority() {
    for boundary in WRITE_BOUNDARIES {
        for occurrence in [1, 2] {
            let fixture = Fixture::new();
            let account = account(1000);
            let previous = fixture.enrolled(account);
            let mut lifecycle = Authority(account.incarnation);
            let mut store = fixture.storage.user(account.uid, &mut lifecycle).unwrap();
            let intent = authorized_intent(
                previous,
                EnrollmentAction::Rotate,
                time(100),
                account.incarnation,
            );
            let stage = stage_for_intent(&mut store, intent, b"synthetic credential two").unwrap();
            store.set_fault_injector(FailAt::boxed(boundary, occurrence));
            assert!(
                store
                    .commit_generation(intent, stage, &mut FixedClock(time(100)))
                    .is_err()
            );
            assert_eq!(store.committed_state(), Err(Error::Uncertain));
            drop(store);
            let mut store = fixture.storage.user(account.uid, &mut lifecycle).unwrap();
            let current = store.committed_state().unwrap();
            assert!(current == previous || current == intent.next());
            let credential = store.credential().unwrap();
            assert_eq!(credential.generation(), current.generation());
            let expected = if current == previous {
                b"synthetic credential one".as_slice()
            } else {
                b"synthetic credential two".as_slice()
            };
            assert_eq!(credential.payload(), expected);
            assert_eq!(
                store.read_throttle(current).unwrap().generation,
                current.generation()
            );
        }
    }
}

#[test]
fn staged_write_and_trial_verification_failures_preserve_old_credential() {
    for boundary in WRITE_BOUNDARIES {
        let fixture = Fixture::new();
        let account = account(1000);
        let previous = fixture.enrolled(account);
        let mut lifecycle = Authority(account.incarnation);
        let mut store = fixture.storage.user(account.uid, &mut lifecycle).unwrap();
        store.set_fault_injector(FailAt::boxed(boundary, 1));
        let verified = AtomicUsize::new(0);
        assert!(
            store
                .stage_credential(
                    CredentialRecord::new(
                        account,
                        previous.generation().next().unwrap(),
                        Backend::Software,
                        b"synthetic replacement",
                    )
                    .unwrap(),
                    |_| {
                        verified.fetch_add(1, Ordering::SeqCst);
                        Ok(())
                    },
                )
                .is_err()
        );
        assert_eq!(verified.load(Ordering::SeqCst), 0);
        drop(store);
        let mut store = fixture.storage.user(account.uid, &mut lifecycle).unwrap();
        assert_eq!(store.committed_state().unwrap(), previous);
        assert_eq!(
            store.credential().unwrap().payload(),
            b"synthetic credential one"
        );
    }

    let fixture = Fixture::new();
    let account = account(1000);
    let previous = fixture.enrolled(account);
    let mut lifecycle = Authority(account.incarnation);
    let mut store = fixture.storage.user(account.uid, &mut lifecycle).unwrap();
    assert!(
        store
            .stage_credential(
                CredentialRecord::new(
                    account,
                    previous.generation().next().unwrap(),
                    Backend::Software,
                    b"synthetic invalid trial",
                )
                .unwrap(),
                |_| Err(Error::Corrupt),
            )
            .is_err()
    );
    drop(store);
    let mut store = fixture.storage.user(account.uid, &mut lifecycle).unwrap();
    assert_eq!(store.committed_state().unwrap(), previous);
    assert_eq!(
        store.credential().unwrap().payload(),
        b"synthetic credential one"
    );
}

#[test]
fn disable_faults_cannot_restore_the_old_pin_after_the_pointer_commits() {
    for boundary in WRITE_BOUNDARIES {
        for occurrence in [1, 2] {
            let fixture = Fixture::new();
            let account = account(1000);
            let previous = fixture.enrolled(account);
            let mut lifecycle = Authority(account.incarnation);
            let mut store = fixture.storage.user(account.uid, &mut lifecycle).unwrap();
            let intent = authorized_intent(
                previous,
                EnrollmentAction::Disable,
                time(100),
                account.incarnation,
            );
            store.set_fault_injector(FailAt::boxed(boundary, occurrence));
            assert!(
                store
                    .commit_generation(intent, None, &mut FixedClock(time(100)))
                    .is_err()
            );
            drop(store);
            let mut store = fixture.storage.user(account.uid, &mut lifecycle).unwrap();
            if occurrence == 2 && matches!(boundary, Boundary::Renamed | Boundary::DirectorySynced)
            {
                assert_eq!(store.committed_state().unwrap(), intent.next());
                assert!(matches!(store.credential(), Err(Error::Disabled)));
                let calls = AtomicUsize::new(0);
                assert!(attempt(&mut store, time(101), BackendOutcome::Match, &calls).is_err());
                assert_eq!(calls.load(Ordering::SeqCst), 0);
            } else {
                assert_eq!(store.committed_state().unwrap(), previous);
            }
        }
    }
}

#[test]
fn initialization_failures_are_never_treated_as_an_empty_attempt_budget() {
    for boundary in WRITE_BOUNDARIES {
        for occurrence in [1, 2] {
            let fixture = Fixture::new();
            let account = account(1000);
            let mut lifecycle = Authority(account.incarnation);
            assert!(
                fixture
                    .storage
                    .initialize_with_faults(
                        account,
                        time(0),
                        &mut lifecycle,
                        FailAt::boxed(boundary, occurrence),
                    )
                    .is_err()
            );
            assert_eq!(
                fixture.storage.initialize(account, time(1), &mut lifecycle),
                Err(Error::Conflict)
            );
            let calls = AtomicUsize::new(0);
            if let Ok(mut store) = fixture.storage.user(account.uid, &mut lifecycle) {
                assert!(store.credential().is_err());
                assert!(attempt(&mut store, time(1), BackendOutcome::Match, &calls).is_err());
            }
            assert_eq!(calls.load(Ordering::SeqCst), 0);
        }
    }
    for boundary in [Boundary::UidCreated, Boundary::GenerationCreated] {
        let fixture = Fixture::new();
        let account = account(1000);
        let mut lifecycle = Authority(account.incarnation);
        assert!(
            fixture
                .storage
                .initialize_with_faults(
                    account,
                    time(0),
                    &mut lifecycle,
                    FailAt::boxed(boundary, 1),
                )
                .is_err()
        );
        assert_eq!(
            fixture.storage.initialize(account, time(1), &mut lifecycle),
            Err(Error::Conflict)
        );
    }
}

#[test]
fn missing_corrupt_or_oversized_required_records_do_not_fall_back() {
    for record_name in ["active", "throttle", "credential"] {
        for damage in ["missing", "corrupt", "oversized"] {
            let fixture = Fixture::new();
            let account = account(1000);
            fixture.enrolled(account);
            let mut lifecycle = Authority(account.incarnation);
            let mut store = fixture.storage.user(account.uid, &mut lifecycle).unwrap();
            commit_action(
                &mut store,
                EnrollmentAction::Rotate,
                time(100),
                b"synthetic credential two",
            )
            .unwrap();
            let path = if record_name == "active" {
                fixture.path.join("users/1000/active")
            } else {
                fixture.generation(account, 3).join(record_name)
            };
            match damage {
                "missing" => std::fs::remove_file(&path).unwrap(),
                "corrupt" => std::fs::write(&path, b"corrupt synthetic fixture").unwrap(),
                "oversized" => OpenOptions::new()
                    .write(true)
                    .open(&path)
                    .unwrap()
                    .set_len((MAX_RECORD_BYTES + 1) as u64)
                    .unwrap(),
                _ => unreachable!(),
            }
            assert!(store.credential().is_err());
            let calls = AtomicUsize::new(0);
            assert!(attempt(&mut store, time(101), BackendOutcome::Match, &calls).is_err());
            assert_eq!(calls.load(Ordering::SeqCst), 0);
        }
    }
}

#[test]
fn uid_selection_and_live_incarnation_are_independent_fences() {
    let fixture = Fixture::new();
    let first = account(1000);
    let second = account(1001);
    fixture.enrolled(first);
    fixture.enrolled(second);
    let foreign = std::fs::read(fixture.path.join("users/1001/active")).unwrap();
    std::fs::write(fixture.path.join("users/1000/active"), foreign).unwrap();
    let mut authority = Authority(first.incarnation);
    assert!(matches!(
        fixture.storage.user(first.uid, &mut authority),
        Err(Error::Conflict)
    ));
    let mut replacement = Authority(Incarnation::new([8; 16]).unwrap());
    let mut store = fixture.storage.user(second.uid, &mut replacement).unwrap();
    assert_eq!(store.credential().unwrap_err(), Error::Lifecycle);
}

#[test]
fn unmanaged_lifecycle_cannot_provision_or_verify() {
    let fixture = Fixture::new();
    let account = account(1000);
    assert_eq!(
        fixture
            .storage
            .initialize(account, time(0), &mut UnmanagedUnixAccounts),
        Err(Error::Lifecycle)
    );
    fixture.enrolled(account);
    let mut lifecycle = UnmanagedUnixAccounts;
    let mut store = fixture.storage.user(account.uid, &mut lifecycle).unwrap();
    assert_eq!(store.credential().unwrap_err(), Error::Lifecycle);
}

#[test]
fn io_failure_classes_never_become_authorizations() {
    for kind in [
        std::io::ErrorKind::StorageFull,
        std::io::ErrorKind::ReadOnlyFilesystem,
    ] {
        let fixture = Fixture::new();
        let account = account(1000);
        fixture.enrolled(account);
        let mut lifecycle = Authority(account.incarnation);
        let mut store = fixture.storage.user(account.uid, &mut lifecycle).unwrap();
        store.set_fault_injector(Box::new(FailAt {
            boundary: Boundary::Written,
            occurrence: 2,
            seen: 0,
            error: Error::Io(kind),
        }));
        let calls = AtomicUsize::new(0);
        assert!(attempt(&mut store, time(100), BackendOutcome::Match, &calls).is_err());
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(store.committed_state(), Err(Error::Uncertain));
    }
}

#[test]
fn disabled_baseline_can_enroll_after_reboot() {
    let fixture = Fixture::new();
    let account = account(1000);
    fixture.initialized(account);
    let mut lifecycle = Authority(account.incarnation);
    let mut store = fixture.storage.user(account.uid, &mut lifecycle).unwrap();
    commit_action(
        &mut store,
        EnrollmentAction::Enroll(Backend::Software),
        other_boot(10),
        b"synthetic after reboot",
    )
    .unwrap();
    assert_eq!(
        store.credential().unwrap().payload(),
        b"synthetic after reboot"
    );
    assert_eq!(
        store
            .read_throttle(store.committed_state().unwrap())
            .unwrap()
            .boot,
        other_boot(0).boot
    );
}

#[test]
fn reboot_debt_is_committed_once_and_rollback_is_unavailable() {
    let fixture = Fixture::new();
    let account = account(1000);
    fixture.enrolled(account);
    let mut lifecycle = Authority(account.incarnation);
    let mut store = fixture.storage.user(account.uid, &mut lifecycle).unwrap();
    let calls = AtomicUsize::new(0);
    assert_eq!(
        attempt(&mut store, time(100), BackendOutcome::Mismatch, &calls).unwrap(),
        Some(AttemptResponse::Mismatch)
    );
    assert_eq!(
        attempt(&mut store, other_boot(10), BackendOutcome::Match, &calls).unwrap(),
        None
    );
    let recovered = store
        .read_throttle(store.committed_state().unwrap())
        .unwrap();
    assert_eq!(recovered.cooldown_until_millis, Some(300_010));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    drop(store);
    let mut store = fixture.storage.user(account.uid, &mut lifecycle).unwrap();
    assert_eq!(
        attempt(&mut store, other_boot(11), BackendOutcome::Match, &calls).unwrap(),
        None
    );
    assert_eq!(
        store
            .read_throttle(store.committed_state().unwrap())
            .unwrap(),
        recovered
    );
    assert!(attempt(&mut store, other_boot(9), BackendOutcome::Match, &calls).is_err());
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        attempt(
            &mut store,
            other_boot(300_010),
            BackendOutcome::Match,
            &calls
        )
        .unwrap(),
        Some(AttemptResponse::Success)
    );
}

#[test]
fn administrative_recovery_revokes_a_replaced_incarnation_and_damaged_throttle() {
    for damage in [false, true] {
        let fixture = Fixture::new();
        let account = account(1000);
        let previous = fixture.enrolled(account);
        if damage {
            std::fs::remove_file(fixture.generation(account, 2).join("throttle")).unwrap();
        }
        let incarnation = Incarnation::new([8; 16]).unwrap();
        let mut lifecycle = Authority(incarnation);
        let mut store = fixture.storage.user(account.uid, &mut lifecycle).unwrap();
        let intent = authorized_intent(
            previous,
            EnrollmentAction::AdministrativeRecovery,
            other_boot(10),
            incarnation,
        );
        let state = store
            .commit_generation(intent, None, &mut FixedClock(other_boot(10)))
            .unwrap();
        assert_eq!(state.account().incarnation, incarnation);
        assert_eq!(state.backend(), None);
        assert!(matches!(store.credential(), Err(Error::Disabled)));
        assert_eq!(
            store.read_throttle(state).unwrap().account.incarnation,
            incarnation
        );
    }
}

#[test]
fn rotations_keep_one_previous_generation_and_discard_abandoned_stages() {
    let fixture = Fixture::new();
    let account = account(1000);
    fixture.enrolled(account);
    let mut lifecycle = Authority(account.incarnation);
    let mut store = fixture.storage.user(account.uid, &mut lifecycle).unwrap();
    for generation in 3..=7 {
        let state = commit_action(
            &mut store,
            EnrollmentAction::Rotate,
            time(generation * 10),
            b"synthetic rotated credential",
        )
        .unwrap();
        assert_eq!(state.generation().get(), generation);
        let mut names: Vec<_> = store
            .dir
            .names()
            .unwrap()
            .into_iter()
            .filter(|name| name.starts_with("generation-"))
            .collect();
        names.sort();
        assert_eq!(
            names,
            vec![
                format!("generation-{}", generation - 1),
                format!("generation-{generation}"),
            ]
        );
    }
    let state = store.committed_state().unwrap();
    let abandoned = store
        .stage_credential(
            CredentialRecord::new(
                account,
                state.generation().next().unwrap(),
                Backend::Software,
                b"synthetic abandoned stage",
            )
            .unwrap(),
            |_| Ok(()),
        )
        .unwrap();
    assert!(fixture.generation(account, 8).exists());
    drop(abandoned);
    drop(store);
    let mut store = fixture.storage.user(account.uid, &mut lifecycle).unwrap();
    assert!(!fixture.generation(account, 8).exists());
    assert_eq!(store.committed_state().unwrap(), state);
    assert_eq!(
        store.credential().unwrap().payload(),
        b"synthetic rotated credential"
    );
}

#[test]
fn cleanup_recovers_after_every_deletion_boundary_without_changing_authority() {
    for boundary in [
        Boundary::FileRemoved,
        Boundary::DirectoryRemoved,
        Boundary::DirectorySynced,
    ] {
        let fixture = Fixture::new();
        let account = account(1000);
        let previous = fixture.enrolled(account);
        let mut lifecycle = Authority(account.incarnation);
        let mut store = fixture.storage.user(account.uid, &mut lifecycle).unwrap();
        let orphan = fixture.generation(account, 9);
        DirBuilder::new().mode(0o700).create(&orphan).unwrap();
        signal(&orphan, "credential", b"synthetic orphan");
        signal(&orphan, "throttle", b"synthetic orphan");
        store.set_fault_injector(FailAt::boxed(boundary, 1));
        assert_eq!(store.reconcile(), Err(Error::Injected));
        assert_eq!(store.committed_state(), Err(Error::Uncertain));
        drop(store);
        let mut store = fixture.storage.user(account.uid, &mut lifecycle).unwrap();
        assert!(!orphan.exists());
        assert_eq!(store.committed_state().unwrap(), previous);
        assert_eq!(
            store.credential().unwrap().payload(),
            b"synthetic credential one"
        );
    }
}

#[test]
fn lifecycle_revocation_after_success_write_still_refuses_authorization() {
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
    struct RevokeAfterCompletion {
        revoked: Arc<AtomicUsize>,
        synced: usize,
    }
    impl FaultInjector for RevokeAfterCompletion {
        fn check(&mut self, boundary: Boundary) -> Result<()> {
            if boundary == Boundary::DirectorySynced {
                self.synced += 1;
                if self.synced == 2 {
                    self.revoked.store(1, Ordering::SeqCst);
                }
            }
            Ok(())
        }
    }
    let fixture = Fixture::new();
    let account = account(1000);
    fixture.enrolled(account);
    let revoked = Arc::new(AtomicUsize::new(0));
    let mut lifecycle = ChangingAuthority(Arc::clone(&revoked));
    let mut store = fixture.storage.user(account.uid, &mut lifecycle).unwrap();
    store.set_fault_injector(Box::new(RevokeAfterCompletion { revoked, synced: 0 }));
    let calls = AtomicUsize::new(0);
    assert!(attempt(&mut store, time(100), BackendOutcome::Match, &calls).is_err());
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(store.committed_state(), Err(Error::Uncertain));
    drop(store);
    let mut store = fixture.storage.user(account.uid, &mut lifecycle).unwrap();
    assert_eq!(store.credential().unwrap_err(), Error::Lifecycle);
}

#[test]
fn failed_reboot_recovery_never_releases_a_backend_or_resets_attempt_debt() {
    for boundary in WRITE_BOUNDARIES {
        let fixture = Fixture::new();
        let account = account(1000);
        fixture.enrolled(account);
        let mut lifecycle = Authority(account.incarnation);
        let mut store = fixture.storage.user(account.uid, &mut lifecycle).unwrap();
        let calls = AtomicUsize::new(0);
        assert_eq!(
            attempt(&mut store, time(100), BackendOutcome::Mismatch, &calls).unwrap(),
            Some(AttemptResponse::Mismatch)
        );
        store.set_fault_injector(FailAt::boxed(boundary, 1));
        assert!(attempt(&mut store, other_boot(10), BackendOutcome::Match, &calls).is_err());
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(store.committed_state(), Err(Error::Uncertain));
        drop(store);
        let mut store = fixture.storage.user(account.uid, &mut lifecycle).unwrap();
        assert_eq!(
            attempt(&mut store, other_boot(20), BackendOutcome::Match, &calls).unwrap(),
            None
        );
        let recovered = store
            .read_throttle(store.committed_state().unwrap())
            .unwrap();
        assert_eq!(recovered.last_attempt, 1);
        let expected_deadline = if matches!(boundary, Boundary::Renamed | Boundary::DirectorySynced)
        {
            300_010
        } else {
            300_020
        };
        assert_eq!(recovered.cooldown_until_millis, Some(expected_deadline));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }
}

#[test]
fn credential_rotation_preserves_abandoned_attempt_debt() {
    let fixture = Fixture::new();
    let account = account(1000);
    fixture.enrolled(account);
    let mut lifecycle = Authority(account.incarnation);
    let mut store = fixture.storage.user(account.uid, &mut lifecycle).unwrap();
    store
        .with_throttle(time(100), |machine, store| {
            let _reserved = machine.reserve(time(100)).unwrap().commit(store).unwrap();
            Ok(())
        })
        .unwrap();
    let state = commit_action(
        &mut store,
        EnrollmentAction::Rotate,
        other_boot(10),
        b"synthetic rotated with debt",
    )
    .unwrap();
    let record = store.read_throttle(state).unwrap();
    assert_eq!(record.last_attempt, 1);
    assert!(record.pending.is_none());
    assert_eq!(record.cooldown_until_millis, Some(300_010));
    let calls = AtomicUsize::new(0);
    assert_eq!(
        attempt(&mut store, other_boot(11), BackendOutcome::Match, &calls).unwrap(),
        None
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

// These helpers deliberately bypass only the broker singleton in test children
// to exercise the lower-level per-UID defense across independent processes.
fn process_storage(path: &Path) -> Storage {
    let root = Dir::test(File::open(path).unwrap()).unwrap();
    let users = root.child("users").unwrap();
    Storage {
        broker: Arc::new(Broker {
            _root: root,
            users,
            _lock: File::open(path).unwrap(),
        }),
    }
}

fn signal(path: &Path, name: &str, value: &[u8]) {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path.join(name))
        .unwrap();
    file.write_all(value).unwrap();
}

fn wait_for(path: &Path) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !path.exists() {
        assert!(Instant::now() < deadline, "process fixture timed out");
        thread::sleep(Duration::from_millis(5));
    }
}

fn successful_child(child: Child) {
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "child failed: {}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
#[ignore = "invoked only as an isolated subprocess by storage process tests"]
fn subprocess_entry() {
    let Ok(scenario) = std::env::var("LOCALPIN_STORAGE_CHILD") else {
        return;
    };
    let path = PathBuf::from(std::env::var_os("LOCALPIN_STORAGE_FIXTURE").unwrap());
    if scenario == "singleton" {
        let result = Storage::from_dir(Dir::test(File::open(&path).unwrap()).unwrap());
        assert!(matches!(result, Err(Error::Busy)));
        return;
    }
    let storage = process_storage(&path);
    let account = account(1000);
    let mut lifecycle = Authority(account.incarnation);
    if scenario == "hold" {
        let _store = storage.user(account.uid, &mut lifecycle).unwrap();
        signal(&path, "held", b"ready");
        wait_for(&path.join("release"));
        return;
    }
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut store = loop {
        match storage.user(account.uid, &mut lifecycle) {
            Ok(store) => break store,
            Err(Error::Busy) => {
                assert!(Instant::now() < deadline);
                thread::sleep(Duration::from_millis(2));
            }
            Err(error) => panic!("unexpected child acquisition error: {error:?}"),
        }
    };
    if scenario == "reserve-exit" {
        store
            .with_throttle(time(100), |machine, store| -> Result<()> {
                let _reserved = machine.reserve(time(100)).unwrap().commit(store).unwrap();
                // Exit skips all Rust destructors: the OS releases locks while
                // the acknowledged pending reservation remains on disk.
                std::process::exit(0)
            })
            .unwrap();
        unreachable!();
    }
    assert_eq!(scenario, "race");
    let calls = AtomicUsize::new(0);
    let response = attempt(&mut store, time(100), BackendOutcome::Mismatch, &calls).unwrap();
    let id = std::env::var("LOCALPIN_STORAGE_CHILD_ID").unwrap();
    let value = match response {
        Some(AttemptResponse::Mismatch) => {
            assert_eq!(calls.load(Ordering::SeqCst), 1);
            b"mismatch".as_slice()
        }
        None => {
            assert_eq!(calls.load(Ordering::SeqCst), 0);
            b"cooldown".as_slice()
        }
        other => panic!("unexpected race result: {other:?}"),
    };
    signal(&path, &format!("result-{id}"), value);
}

#[test]
fn singleton_and_per_uid_locks_survive_real_process_contention_and_exit() {
    let fixture = Fixture::new();
    let first = account(1000);
    let second = account(1001);
    fixture.enrolled(first);
    fixture.enrolled(second);
    successful_child(fixture.child("singleton").spawn().unwrap());
    let mut child = fixture.child("hold").spawn().unwrap();
    wait_for(&fixture.path.join("held"));
    let mut first_lifecycle = Authority(first.incarnation);
    assert!(matches!(
        fixture.storage.user(first.uid, &mut first_lifecycle),
        Err(Error::Busy)
    ));
    let mut second_lifecycle = Authority(second.incarnation);
    let second_guard = fixture
        .storage
        .user(second.uid, &mut second_lifecycle)
        .unwrap();
    assert_eq!(second_guard.committed_state().unwrap().account(), second);
    child.kill().unwrap();
    child.wait().unwrap();
    let _first_guard = fixture
        .storage
        .user(first.uid, &mut first_lifecycle)
        .unwrap();
}

#[test]
fn independent_processes_share_exactly_five_durable_attempts() {
    let fixture = Fixture::new();
    let account = account(1000);
    fixture.enrolled(account);
    let children: Vec<_> = (0..12)
        .map(|id| {
            fixture
                .child("race")
                .env("LOCALPIN_STORAGE_CHILD_ID", id.to_string())
                .spawn()
                .unwrap()
        })
        .collect();
    for child in children {
        successful_child(child);
    }
    let mut mismatches = 0;
    for id in 0..12 {
        let result = std::fs::read(fixture.path.join(format!("result-{id}"))).unwrap();
        match result.as_slice() {
            b"mismatch" => mismatches += 1,
            b"cooldown" => {}
            other => panic!("unexpected fixture result: {other:?}"),
        }
    }
    assert_eq!(mismatches, 5);
    let mut lifecycle = Authority(account.incarnation);
    let store = fixture.storage.user(account.uid, &mut lifecycle).unwrap();
    let record = store
        .read_throttle(store.committed_state().unwrap())
        .unwrap();
    assert_eq!(record.last_attempt, 5);
    assert_eq!(record.recent_len, 5);
    assert_eq!(record.cooldown_until_millis, Some(300_100));
    assert!(record.pending.is_none());
}

#[test]
fn abrupt_process_exit_preserves_reserved_attempt_and_reboot_debt() {
    for reboot in [false, true] {
        let fixture = Fixture::new();
        let account = account(1000);
        fixture.enrolled(account);
        successful_child(fixture.child("reserve-exit").spawn().unwrap());
        let mut lifecycle = Authority(account.incarnation);
        let mut store = fixture.storage.user(account.uid, &mut lifecycle).unwrap();
        let before = store
            .read_throttle(store.committed_state().unwrap())
            .unwrap();
        assert_eq!(before.last_attempt, 1);
        assert_eq!(before.recent_len, 1);
        assert!(before.pending.is_some());
        let now = if reboot { other_boot(10) } else { time(101) };
        store
            .with_throttle(now, |machine, _| {
                assert!(machine.record().pending.is_none());
                assert_eq!(machine.record().last_attempt, 1);
                if reboot {
                    assert_eq!(machine.record().cooldown_until_millis, Some(300_010));
                } else {
                    assert_eq!(machine.record().recent_len, 1);
                }
                Ok(())
            })
            .unwrap();
    }
}

#[test]
fn dropping_storage_keeps_singleton_until_its_last_uid_guard_drops() {
    let fixture = Fixture::new();
    let account = account(1000);
    fixture.enrolled(account);
    let path = fixture.path.clone();
    let storage = Storage::from_dir(Dir::test(File::open(&path).unwrap()).unwrap());
    assert!(matches!(storage, Err(Error::Busy)));
    // A second independent tree lets ownership move without dismantling the
    // fixture's cleanup guard.
    let separate = fixture.path.join("separate");
    DirBuilder::new().mode(0o700).create(&separate).unwrap();
    let storage = Storage::from_dir(Dir::test(File::open(&separate).unwrap()).unwrap()).unwrap();
    storage
        .initialize(account, time(0), &mut Authority(account.incarnation))
        .unwrap();
    let mut lifecycle = Authority(account.incarnation);
    let guard = storage.user(account.uid, &mut lifecycle).unwrap();
    drop(storage);
    assert!(matches!(
        Storage::from_dir(Dir::test(File::open(&separate).unwrap()).unwrap()),
        Err(Error::Busy)
    ));
    drop(guard);
    Storage::from_dir(Dir::test(File::open(&separate).unwrap()).unwrap()).unwrap();
}
