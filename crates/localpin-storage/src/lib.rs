//! Protected Linux storage and M2 policy integration.
//!
//! The caller supplies an already trusted directory descriptor and retains the
//! returned per-UID guard through backend work and response delivery. Production
//! opening requires root ownership. There is no production account lifecycle
//! authority or credential verifier here; ordinary unmanaged accounts fail closed.
//! Only `active` selects a generation; orphaned and previous generations are never
//! alternate credentials. A delivered authorization cannot be retracted.

#[cfg(not(target_os = "linux"))]
compile_error!("localpin-storage currently supports Linux only");

mod fs;
mod pointer;

use std::{fs::File, io, sync::Arc};

use localpin_core::{
    enrollment::{CommitIntent, CommittedState, LifecycleAuthority},
    limits::{MAX_RECORD_BYTES, MAX_THROTTLE_BYTES},
    records::CredentialRecord,
    secret::SecretBytes,
    throttle::{DurableThrottleStore, RestoredThrottle, Throttle, ThrottleRecord},
    types::{AccountId, Clock, Generation, Incarnation, TimePoint, Uid},
};

use fs::Dir;
use pointer::Pointer;

/// Sanitized storage failures. No paths, credential bytes or OS error strings.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// A filesystem operation failed; its outcome may be uncertain.
    Io(io::ErrorKind),
    /// Ownership, mode, links, file type or path restrictions failed.
    UnsafePath,
    /// A required record exceeded its fixed bound.
    Oversized,
    /// Another process or guard holds the stable lock.
    Busy,
    /// The authoritative expected record or generation differs.
    Conflict,
    /// Required record data is malformed or inconsistent.
    Corrupt,
    /// The trusted account lifecycle source refused continuity.
    Lifecycle,
    /// The credential is disabled.
    Disabled,
    /// Trusted monotonic policy or transaction time failed.
    Time,
    /// Persistence was uncertain; discard the guard and reload under a new lock.
    Uncertain,
    /// A deterministic test fault interrupted persistence.
    Injected,
}

impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        Self::Io(error.kind())
    }
}

impl From<rustix::io::Errno> for Error {
    fn from(error: rustix::io::Errno) -> Self {
        io::Error::from(error).into()
    }
}

/// A storage result containing only sanitized errors.
pub type Result<T> = std::result::Result<T, Error>;

/// Observable persistence boundaries for deterministic failure/crash tests.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Boundary {
    /// A new exclusive temporary file exists.
    TempCreated,
    /// All bounded record bytes were written.
    Written,
    /// The temporary file was synchronized.
    FileSynced,
    /// The authoritative directory entry was atomically replaced.
    Renamed,
    /// The containing directory was synchronized.
    DirectorySynced,
    /// A new UID directory has been created and synchronized.
    UidCreated,
    /// A generation directory has been created and synchronized.
    GenerationCreated,
    /// A superseded generation file was unlinked.
    FileRemoved,
    /// A superseded generation directory was unlinked.
    DirectoryRemoved,
}

/// A trusted testing hook; returning an error never acknowledges durability.
pub trait FaultInjector {
    /// Observe a completed boundary, optionally interrupting the operation.
    fn check(&mut self, boundary: Boundary) -> Result<()>;
}

impl<T: FaultInjector + ?Sized> FaultInjector for Box<T> {
    fn check(&mut self, boundary: Boundary) -> Result<()> {
        (**self).check(boundary)
    }
}

/// Normal operation, without injected failures.
pub struct NoFaults;

impl FaultInjector for NoFaults {
    fn check(&mut self, _: Boundary) -> Result<()> {
        Ok(())
    }
}

struct Broker {
    _root: Dir,
    users: Dir,
    _lock: File,
}

/// One broker's exclusive protected state directory lease.
pub struct Storage {
    broker: Arc<Broker>,
}

impl Storage {
    /// Open an already trusted, root-owned 0700 state directory descriptor.
    ///
    /// Installation owns pathname/ancestor and mount trust. This method rejects
    /// unsafe directory metadata and holds `broker.lock` until all guards drop.
    pub fn open(root: File) -> Result<Self> {
        Self::from_dir(Dir::open(root)?)
    }

    fn from_dir(root: Dir) -> Result<Self> {
        let lock = root.lock("broker.lock")?;
        let users = root.create_child("users")?;
        Ok(Self {
            broker: Arc::new(Broker {
                _root: root,
                users,
                _lock: lock,
            }),
        })
    }

    /// Acquire the existing UID's stable nonblocking lock, independently of peers.
    pub fn user<'a>(
        &self,
        uid: Uid,
        lifecycle: &'a mut dyn LifecycleAuthority,
    ) -> Result<UserStore<'a>> {
        let dir = self.broker.users.child(&uid.get().to_string())?;
        let mut guard = self.guard(dir, uid, lifecycle, false)?;
        guard.reconcile()?;
        Ok(guard)
    }

    fn guard<'a>(
        &self,
        dir: Dir,
        uid: Uid,
        lifecycle: &'a mut dyn LifecycleAuthority,
        create: bool,
    ) -> Result<UserStore<'a>> {
        let lock = if create {
            dir.lock("lock")?
        } else {
            dir.existing_lock("lock")?
        };
        Ok(UserStore {
            dir,
            uid,
            _lock: lock,
            _broker: Arc::clone(&self.broker),
            lifecycle,
            faults: Box::new(NoFaults),
            uncertain: false,
        })
    }

    /// Explicitly establish a new disabled baseline in an exclusively new UID directory.
    ///
    /// This is a trusted provisioning operation, never verification recovery.
    /// Existing or partially initialized UID directories are refused. It accepts
    /// only an enforcing lifecycle source; `UnmanagedUnixAccounts` is refused.
    pub fn initialize(
        &self,
        account: AccountId,
        now: TimePoint,
        lifecycle: &mut dyn LifecycleAuthority,
    ) -> Result<()> {
        self.initialize_with_faults(account, now, lifecycle, Box::new(NoFaults))
    }

    /// Privileged offline re-provisioning after durable lifecycle revocation.
    ///
    /// The caller must hold the lifecycle authority's exclusive mutation lease.
    /// Opening `Storage` also requires that the broker is stopped. Old state is
    /// quarantined under its new incarnation rather than reused or repaired.
    /// A bounded quarantine refuses further provisioning after sixteen retained
    /// incarnations for a UID; only an explicit administrator may remove them.
    /// Own-user enrollment must never call this operation.
    pub fn reprovision(
        &mut self,
        account: AccountId,
        now: TimePoint,
        lifecycle: &mut dyn LifecycleAuthority,
    ) -> Result<()> {
        self.reprovision_with_faults(account, now, lifecycle, Box::new(NoFaults))
    }

    /// Privileged re-provisioning with deterministic crash-boundary injection.
    pub fn reprovision_with_faults(
        &mut self,
        account: AccountId,
        now: TimePoint,
        lifecycle: &mut dyn LifecycleAuthority,
        mut faults: Box<dyn FaultInjector>,
    ) -> Result<()> {
        check_lifecycle(lifecycle, account)?;
        let retired = self.broker._root.create_child("retired")?;
        let uid = account.uid.get().to_string();
        let retired_uid = retired.create_child(&uid)?;
        if retired_uid.names()?.len() >= 16 {
            return Err(Error::Oversized);
        }
        if Arc::strong_count(&self.broker) != 1 {
            return Err(Error::Busy);
        }
        if self.broker.users.entry_exists(&uid)? {
            let destination: String = account
                .incarnation
                .get()
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect();
            // RENAME_NOREPLACE prevents a retried or colliding incarnation
            // from overwriting already quarantined evidence.
            fs::quarantine(
                &self.broker.users,
                &uid,
                &retired_uid,
                &destination,
                &mut faults,
            )?;
        }
        self.initialize_with_faults(account, now, lifecycle, faults)
    }

    /// Provision with a deterministic persistence test hook.
    pub fn initialize_with_faults(
        &self,
        account: AccountId,
        now: TimePoint,
        lifecycle: &mut dyn LifecycleAuthority,
        faults: Box<dyn FaultInjector>,
    ) -> Result<()> {
        check_lifecycle(lifecycle, account)?;
        let dir = self
            .broker
            .users
            .create_child_new(&account.uid.get().to_string())?;
        let mut guard = self.guard(dir, account.uid, lifecycle, true)?;
        guard.faults = faults;
        guard.faults.check(Boundary::UidCreated)?;
        let generation = Generation::new(1).map_err(|_| Error::Corrupt)?;
        let state = CommittedState::new(account, generation, None);
        let generation_dir = guard.dir.create_child(&generation_name(generation))?;
        guard.faults.check(Boundary::GenerationCreated)?;
        let throttle = ThrottleRecord::initial(account, generation, now);
        generation_dir.replace(
            "throttle",
            &throttle.encode().map_err(|_| Error::Corrupt)?,
            &mut guard.faults,
        )?;
        check_lifecycle(guard.lifecycle, account)?;
        guard
            .dir
            .replace("active", &Pointer(state).encode(), &mut guard.faults)?;
        Ok(())
    }
}

/// A per-UID filesystem lock retained across policy, backend, and final response.
///
/// Dropping it releases only this UID; it also retains the broker singleton lease.
/// No blocking acquisition holds a global mutex. A failed write poisons the guard.
pub struct UserStore<'a> {
    dir: Dir,
    uid: Uid,
    _lock: File,
    _broker: Arc<Broker>,
    lifecycle: &'a mut dyn LifecycleAuthority,
    faults: Box<dyn FaultInjector>,
    uncertain: bool,
}

/// A consumed-once proof that the exact persisted proposed credential was trial verified.
/// No serializable client flag can construct this value.
pub struct VerifiedStage {
    previous: CommittedState,
    credential: CredentialRecord,
    encoded: SecretBytes,
}

/// A temporary handle to the guard's same trusted lifecycle source.
///
/// Use it for M2 enrollment transitions while retaining the filesystem lock.
/// Drop the handle before calling another storage method on the guard.
pub struct LifecycleHandle<'a> {
    source: &'a mut dyn LifecycleAuthority,
}

impl LifecycleAuthority for LifecycleHandle<'_> {
    fn current_incarnation(
        &mut self,
        uid: Uid,
    ) -> std::result::Result<Incarnation, localpin_core::enrollment::LifecycleError> {
        self.source.current_incarnation(uid)
    }
}

impl UserStore<'_> {
    /// Borrow this guard's authority for core enrollment/finalization checks.
    pub fn lifecycle(&mut self) -> LifecycleHandle<'_> {
        LifecycleHandle {
            source: self.lifecycle,
        }
    }

    /// Install a test hook. This cannot clear an uncertain state.
    pub fn set_fault_injector(&mut self, faults: Box<dyn FaultInjector>) {
        self.faults = faults;
    }

    fn ensure_ready(&self) -> Result<()> {
        if self.uncertain {
            Err(Error::Uncertain)
        } else {
            Ok(())
        }
    }

    /// Load only the authoritative pointer, without interpreting an old generation.
    ///
    /// This structural state is also needed to prepare administrative recovery
    /// after incarnation changes. Verification separately requires live continuity.
    pub fn committed_state(&self) -> Result<CommittedState> {
        self.ensure_ready()?;
        let bytes = self.dir.read("active", pointer::ENCODED_LEN)?;
        let state = Pointer::decode(&bytes)?.0;
        if state.account().uid != self.uid {
            return Err(Error::Conflict);
        }
        Ok(state)
    }

    fn generation_dir(&self, state: CommittedState) -> Result<Dir> {
        self.dir.child(&generation_name(state.generation()))
    }

    fn read_throttle(&self, state: CommittedState) -> Result<ThrottleRecord> {
        let bytes = self
            .generation_dir(state)?
            .read("throttle", MAX_THROTTLE_BYTES)?;
        let record = ThrottleRecord::decode(&bytes).map_err(|_| Error::Corrupt)?;
        if record.account != state.account() || record.generation != state.generation() {
            return Err(Error::Conflict);
        }
        Ok(record)
    }

    /// Deterministically discard orphaned stages and obsolete history under lock.
    ///
    /// Retain only the committed generation and, if present, its immediate
    /// predecessor. Neither cleanup nor a corrupt pointer selects a fallback.
    /// Startup runs this before returning a UID guard.
    pub fn reconcile(&mut self) -> Result<()> {
        let state = self.committed_state()?;
        // A well-shaped but damaged pointer must not destroy real recovery
        // material merely because it names a nonexistent/incomplete snapshot.
        // Retain the guard so explicit administrative revocation is possible;
        // verification still requires both selected records below.
        if self.read_throttle(state).is_err()
            || (state.backend().is_some() && self.read_credential(state).is_err())
        {
            return Ok(());
        }
        let result = self.cleanup(state);
        if result.is_err() {
            self.uncertain = true;
        }
        result
    }

    fn cleanup(&mut self, state: CommittedState) -> Result<()> {
        for name in self.dir.names()? {
            if matches!(name.as_str(), "active" | "lock" | ".pending") {
                continue;
            }
            let number = name
                .strip_prefix("generation-")
                .and_then(|value| value.parse::<u64>().ok())
                .ok_or(Error::UnsafePath)?;
            if number == 0 || name != format!("generation-{number}") {
                return Err(Error::UnsafePath);
            }
            if number != state.generation().get() && number != state.generation().get() - 1 {
                self.dir.remove_child(&name, &mut self.faults)?;
            }
        }
        self.dir.sync()
    }

    /// Load the one committed backend envelope. Disabled/missing/corrupt state fails closed.
    pub fn credential(&mut self) -> Result<CredentialRecord> {
        let state = self.committed_state()?;
        check_lifecycle(self.lifecycle, state.account())?;
        state.backend().ok_or(Error::Disabled)?;
        self.read_throttle(state)?;
        self.read_credential(state)
    }

    fn read_credential(&self, state: CommittedState) -> Result<CredentialRecord> {
        let backend = state.backend().ok_or(Error::Disabled)?;
        let bytes = self
            .generation_dir(state)?
            .read("credential", MAX_RECORD_BYTES)?;
        let record = CredentialRecord::decode(&bytes).map_err(|_| Error::Corrupt)?;
        if record.account() != state.account()
            || record.generation() != state.generation()
            || record.backend() != backend
        {
            return Err(Error::Conflict);
        }
        Ok(record)
    }

    /// Run policy under this guard, durably recovering pending/reboot debt first.
    ///
    /// The closure cannot return an attempt borrowing the local policy machine.
    /// Callers retain this guard through eligibility checks and response delivery.
    pub fn with_throttle<T>(
        &mut self,
        now: TimePoint,
        operation: impl FnOnce(&mut Throttle, &mut Self) -> Result<T>,
    ) -> Result<T> {
        let state = self.committed_state()?;
        self.credential()?;
        let record = self.read_throttle(state)?;
        let mut throttle = match Throttle::restore(record, state.account(), state.generation(), now)
            .map_err(|_| Error::Time)?
        {
            RestoredThrottle::Ready(machine) => machine,
            RestoredThrottle::Recovery(intent) => {
                intent.commit(self).map_err(|_| Error::Uncertain)?
            }
        };
        operation(&mut throttle, self)
    }

    /// Persist, reopen and trial verify the exact proposed generation before commit.
    ///
    /// The callback is trusted backend code, and must perform actual verification
    /// in M4. M3 tests use clearly synthetic credentials. The broker must first
    /// obtain the M2 fresh-password/staging grant; this is not an IPC operation.
    pub fn stage_credential(
        &mut self,
        credential: CredentialRecord,
        verify: impl FnOnce(&CredentialRecord) -> Result<()>,
    ) -> Result<VerifiedStage> {
        let previous = self.committed_state()?;
        if credential.account() != previous.account()
            || previous.generation().next().ok() != Some(credential.generation())
        {
            return Err(Error::Conflict);
        }
        check_lifecycle(self.lifecycle, credential.account())?;
        let result = (|| {
            let dir = self
                .dir
                .create_child(&generation_name(credential.generation()))?;
            self.faults.check(Boundary::GenerationCreated)?;
            let encoded = credential.encode().map_err(|_| Error::Corrupt)?;
            dir.replace("credential", encoded.expose(), &mut self.faults)?;
            let bytes = dir.read("credential", MAX_RECORD_BYTES)?;
            if bytes.as_slice() != encoded.expose() {
                return Err(Error::Conflict);
            }
            let persisted = CredentialRecord::decode(&bytes).map_err(|_| Error::Corrupt)?;
            verify(&persisted)?;
            Ok(VerifiedStage {
                previous,
                credential,
                encoded,
            })
        })();
        if result.is_err() {
            self.uncertain = true;
        }
        result
    }

    /// Commit a model-authorized generation or durable revocation tombstone.
    ///
    /// The active-pointer directory sync is the revocation boundary. Complete
    /// generations are synchronized first. The previous generation remains
    /// recovery material only. Failures require reload, including expiry after
    /// a successful write; they never restore the previous accepted generation.
    pub fn commit_generation(
        &mut self,
        intent: CommitIntent,
        stage: Option<VerifiedStage>,
        clock: &mut impl Clock,
    ) -> Result<CommittedState> {
        let previous = self.committed_state()?;
        let next = intent.next();
        if previous != intent.previous()
            || previous.generation().next().ok() != Some(next.generation())
            || previous.account().uid != next.account().uid
            || next.revision() != next.generation().get()
        {
            return Err(Error::Conflict);
        }
        let started = clock.now().map_err(|_| Error::Time)?;
        valid_commit_time(started, intent.expires_at())?;
        if started.boot != intent.prepared_at().boot || started.millis < intent.prepared_at().millis
        {
            return Err(Error::Time);
        }
        check_lifecycle(self.lifecycle, next.account())?;
        let old = match self.read_throttle(previous) {
            Ok(record) => record,
            // Explicit root recovery may revoke damaged state. This installs a
            // disabled generation, never a credential or an available verifier.
            Err(_)
                if intent.binding().action()
                    == localpin_core::enrollment::EnrollmentAction::AdministrativeRecovery =>
            {
                ThrottleRecord::initial(next.account(), previous.generation(), started)
            }
            Err(error) => return Err(error),
        };
        let recovered = match Throttle::restore(old, old.account, previous.generation(), started)
            .map_err(|_| Error::Time)?
        {
            RestoredThrottle::Ready(machine) => *machine.record(),
            RestoredThrottle::Recovery(intent) => *intent.record(),
        };
        let result = (|| {
            let dir = self.dir.create_child(&generation_name(next.generation()))?;
            self.faults.check(Boundary::GenerationCreated)?;
            match (next.backend(), stage) {
                (Some(backend), Some(stage))
                    if stage.previous == previous
                        && stage.credential.account() == next.account()
                        && stage.credential.generation() == next.generation()
                        && stage.credential.backend() == backend =>
                {
                    let bytes = dir.read("credential", MAX_RECORD_BYTES)?;
                    if bytes.as_slice() != stage.encoded.expose() {
                        return Err(Error::Conflict);
                    }
                }
                (None, None) => {}
                _ => return Err(Error::Conflict),
            }
            // Preserve attempt debt across authorized credential changes.
            let mut throttle = recovered;
            throttle.account = next.account();
            throttle.generation = next.generation();
            throttle.revision = throttle.revision.checked_add(1).ok_or(Error::Corrupt)?;
            throttle.observed_millis = started.millis;
            dir.replace(
                "throttle",
                &throttle.encode().map_err(|_| Error::Corrupt)?,
                &mut self.faults,
            )?;
            check_lifecycle(self.lifecycle, next.account())?;
            let before_pointer = clock.now().map_err(|_| Error::Time)?;
            valid_commit_time(before_pointer, intent.expires_at())?;
            if before_pointer.millis < started.millis {
                return Err(Error::Time);
            }
            let mut publishing_time = before_pointer;
            self.dir.replace_guarded(
                "active",
                &Pointer(next).encode(),
                &mut self.faults,
                || {
                    // Pointer staging itself can stall. Do not publish an
                    // expired/cancelled grant after its tempfile write/fsync.
                    check_lifecycle(self.lifecycle, next.account())?;
                    let publishing = clock.now().map_err(|_| Error::Time)?;
                    valid_commit_time(publishing, intent.expires_at())?;
                    if publishing.millis < before_pointer.millis {
                        return Err(Error::Time);
                    }
                    publishing_time = publishing;
                    Ok(())
                },
            )?;
            self.cleanup(next)?;
            let finished = clock.now().map_err(|_| Error::Time)?;
            valid_commit_time(finished, intent.expires_at())?;
            if finished.millis < publishing_time.millis {
                return Err(Error::Time);
            }
            check_lifecycle(self.lifecycle, next.account())?;
            Ok(next)
        })();
        if result.is_err() {
            self.uncertain = true;
        }
        result
    }
}

impl DurableThrottleStore for UserStore<'_> {
    type Error = Error;

    fn commit(&mut self, expected: &ThrottleRecord, replacement: &ThrottleRecord) -> Result<()> {
        let state = self.committed_state()?;
        check_lifecycle(self.lifecycle, state.account())?;
        if state.backend().is_none()
            || self.read_throttle(state)? != *expected
            || replacement.account != state.account()
            || replacement.generation != state.generation()
            || expected.revision.checked_add(1) != Some(replacement.revision)
        {
            return Err(Error::Conflict);
        }
        let bytes = replacement.encode().map_err(|_| Error::Corrupt)?;
        let result = (|| {
            self.generation_dir(state)?
                .replace("throttle", &bytes, &mut self.faults)?;
            check_lifecycle(self.lifecycle, state.account())
        })();
        if result.is_err() {
            self.uncertain = true;
        }
        result
    }
}

fn check_lifecycle(lifecycle: &mut dyn LifecycleAuthority, account: AccountId) -> Result<()> {
    if lifecycle
        .current_incarnation(account.uid)
        .map_err(|_| Error::Lifecycle)?
        != account.incarnation
    {
        return Err(Error::Lifecycle);
    }
    Ok(())
}

fn generation_name(generation: Generation) -> String {
    format!("generation-{}", generation.get())
}

fn valid_commit_time(now: TimePoint, expires: TimePoint) -> Result<()> {
    if now.boot != expires.boot
        || now.millis >= expires.millis
        || now.millis
            < expires
                .millis
                .saturating_sub(localpin_core::enrollment::AUTHORIZATION_LIFETIME_MILLIS)
    {
        return Err(Error::Time);
    }
    Ok(())
}

#[cfg(test)]
mod tests;
