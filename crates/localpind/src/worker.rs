//! Disposable native workers with bounded private IPC and asynchronous reaping.
//!
//! The broker retains the durable reservation. This module accepts an already
//! charged work permit and retains it until the exact child is reaped, including
//! after the caller's deadline. A returned match is only a backend result; the
//! broker must still revalidate identity/generation and durably complete it.
//!
//! Process-group cleanup includes unexpected descendants that remain in the
//! helper's group. A separate service/cgroup sandbox must prevent `setsid` or
//! process-group escapes and bound descendant creation; this is not that sandbox.

#![forbid(unsafe_code)]

use localpin_core::{
    limits::{KdfParameters, MAX_RECORD_BYTES, ResourceBudget, WorkKind, WorkPermit},
    records::CredentialRecord,
    secret::{CredentialKind, CredentialProfile, MAX_CREDENTIAL_BYTES, Pin},
    throttle::{BackendFailure, BackendOutcome},
    types::{AccountId, Backend, Generation, Incarnation, Uid},
};
use localpin_protocol::transport::BootInstant as Instant;
use std::{
    io::{self, Read, Write},
    os::unix::{fs::MetadataExt, net::UnixStream, process::CommandExt},
    path::{Component, Path, PathBuf},
    process::{Child, Command, ExitStatus, Stdio},
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    thread,
    time::Duration,
};
use zeroize::Zeroizing;

/// At most four 64 MiB jobs fit the shared 256 MiB KDF budget.
pub const MAX_WORKERS: usize = 4;
const REQUEST_HEADER: usize = 16;
const RESPONSE_BYTES: usize = 13;
const ENROLLMENT_BINDING_BYTES: usize = 32;
const ENROLLMENT_RESPONSE_HEADER: usize = 17;
const MAX_ENROLLMENT_RESPONSE: usize = ENROLLMENT_RESPONSE_HEADER + MAX_RECORD_BYTES;
const POLL_INTERVAL: Duration = Duration::from_millis(2);
const TPM_DA_RESERVE: u32 = 2;

fn unavailable() -> BackendOutcome {
    BackendOutcome::Unavailable(BackendFailure::Unavailable)
}

struct Entry {
    child: Child,
    group: rustix::process::Pid,
    reaped: Option<ExitStatus>,
    // Remains charged even if a killed native call cannot yet be reaped.
    _permit: WorkPermit,
    retired: bool,
    #[cfg(test)]
    reap_after: Instant,
}

impl Entry {
    fn terminate(&mut self) {
        // Before reaping, the child's PID pins this process-group identifier.
        // Never signal its numeric ID again after the child has been reaped.
        if self.reaped.is_none() {
            let _ = rustix::process::kill_process_group(self.group, rustix::process::Signal::KILL);
            let _ = self.child.kill();
        }
    }

    fn poll_reaped(&mut self) -> io::Result<Option<ExitStatus>> {
        if self.reaped.is_none() {
            use rustix::process::{WaitId, WaitIdOptions, waitid};
            if waitid(
                WaitId::Pid(self.group),
                WaitIdOptions::EXITED | WaitIdOptions::NOHANG | WaitIdOptions::NOWAIT,
            )?
            .is_none()
            {
                return Ok(None);
            }
            // WNOWAIT leaves the exited leader as a zombie, pinning its PID
            // while all remaining same-group descendants receive SIGKILL.
            // This also runs on normal worker exit, before accepting a result.
            match rustix::process::kill_process_group(self.group, rustix::process::Signal::KILL) {
                Ok(()) | Err(rustix::io::Errno::SRCH) => {}
                Err(error) => return Err(error.into()),
            }
            self.reaped = self.child.try_wait()?;
        }
        let Some(status) = self.reaped else {
            return Ok(None);
        };
        // Descendants may briefly remain (or be stuck in native device I/O).
        // Keep capacity charged until the group disappears. Only query here:
        // after reaping, numeric PID reuse must never cause an unrelated kill.
        match rustix::process::test_kill_process_group(self.group) {
            Err(rustix::io::Errno::SRCH) => Ok(Some(status)),
            Ok(()) => Ok(None),
            Err(error) => Err(error.into()),
        }
    }
}

enum Slot {
    Starting,
    Child(Entry),
}

struct Shared {
    slots: Mutex<[Option<Slot>; MAX_WORKERS]>,
    next_id: AtomicU64,
    #[cfg(test)]
    reap_delay: Duration,
}

/// One bounded supervisor shared by all broker connection handlers.
///
/// Its single reaper thread polls only retired children. It never blocks in
/// `wait`, and its process/memory/UID capacity is retained until `try_wait`
/// confirms leader exit and the process group disappears. Dropping the last
/// caller does not abandon occupied slots.
#[derive(Clone)]
pub struct WorkerSupervisor {
    executable: PathBuf,
    shared: Arc<Shared>,
    #[cfg(test)]
    fixture_arguments: Vec<std::ffi::OsString>,
}

impl WorkerSupervisor {
    /// Select an operator-configured installed helper, never a client path.
    ///
    /// Every component must be root-owned and not group/world writable. Symlinks
    /// and relative paths are refused; deployment must preserve this ownership.
    /// The helper receives no inherited environment or caller-selected arguments.
    pub fn new(executable: impl AsRef<Path>) -> io::Result<Self> {
        validate_executable(executable.as_ref())?;
        Self::build(executable.as_ref().to_owned(), Duration::ZERO)
    }

    fn build(executable: PathBuf, _reap_delay: Duration) -> io::Result<Self> {
        let shared = Arc::new(Shared {
            slots: Mutex::new(std::array::from_fn(|_| None)),
            next_id: AtomicU64::new(1),
            #[cfg(test)]
            reap_delay: _reap_delay,
        });
        let reaping = shared.clone();
        thread::Builder::new()
            .name("localpin-reaper".into())
            .spawn(move || {
                loop {
                    let mut empty = false;
                    if let Ok(mut slots) = reaping.slots.lock() {
                        for slot in slots.iter_mut() {
                            let Some(Slot::Child(entry)) = slot else {
                                continue;
                            };
                            if !entry.retired {
                                continue;
                            }
                            #[cfg(test)]
                            if Instant::now() < entry.reap_after {
                                continue;
                            }
                            match entry.poll_reaped() {
                                Ok(Some(_)) => {
                                    *slot = None;
                                }
                                Ok(None) | Err(_) => {
                                    // A transient/repeated wait error fails closed:
                                    // keep the occupied capacity and retry safely.
                                    entry.terminate();
                                }
                            }
                        }
                        empty = slots.iter().all(Option::is_none);
                    }
                    if empty && Arc::strong_count(&reaping) == 1 {
                        break;
                    }
                    thread::sleep(POLL_INTERVAL);
                }
            })?;
        Ok(Self {
            executable,
            shared,
            #[cfg(test)]
            fixture_arguments: Vec::new(),
        })
    }

    /// Run one exact protected record under the broker's existing work lease.
    ///
    /// Cancellation and deadlines close private IPC, discard all results and
    /// request forced termination. The response does not wait for reaping.
    /// Same-UID and aggregate memory admission stays charged in the reaper.
    /// This method never grants authorization or changes a reservation.
    pub fn verify(
        &self,
        credential: &CredentialRecord,
        pin: Pin,
        permit: WorkPermit,
        deadline: Instant,
        mut cancelled: impl FnMut() -> bool,
    ) -> BackendOutcome {
        let kind = match credential.backend() {
            Backend::Software => WorkKind::Verification,
            Backend::Tpm2 => WorkKind::TpmPinDerivation,
        };
        self.check_record(
            credential,
            pin,
            permit,
            kind,
            false,
            deadline,
            &mut cancelled,
        )
    }

    /// Trial-check the exact protected record reopened by the storage transaction.
    ///
    /// This uses the same bounded worker table as ordinary verification and
    /// enrollment. Its result grants no authentication or enrollment authority.
    pub fn trial_verify(
        &self,
        credential: &CredentialRecord,
        pin: Pin,
        permit: WorkPermit,
        deadline: Instant,
        mut cancelled: impl FnMut() -> bool,
    ) -> BackendOutcome {
        let kind = match credential.backend() {
            Backend::Software => WorkKind::Enrollment,
            Backend::Tpm2 => WorkKind::TpmPinDerivation,
        };
        self.check_record(
            credential,
            pin,
            permit,
            kind,
            true,
            deadline,
            &mut cancelled,
        )
    }

    /// Create one candidate for an already authorized enrollment transaction.
    ///
    /// The returned record is bound to the exact account, proposed generation
    /// and selected backend. The broker must stage, reopen and trial-check it
    /// before committing. No TPM error selects software. The existing aggregate
    /// work lease remains charged until this disposable process is fully reaped.
    #[allow(clippy::too_many_arguments)]
    pub fn enroll(
        &self,
        account: AccountId,
        generation: Generation,
        backend: Backend,
        credential_kind: CredentialKind,
        pin: Pin,
        permit: WorkPermit,
        deadline: Instant,
        mut cancelled: impl FnMut() -> bool,
    ) -> Result<CredentialRecord, BackendFailure> {
        let profile = CredentialProfile::for_enrollment(backend, credential_kind, &pin)
            .map_err(|_| BackendFailure::Unavailable)?;
        let kind = match backend {
            Backend::Software => WorkKind::Enrollment,
            Backend::Tpm2 => WorkKind::TpmPinDerivation,
        };
        if !permit.covers(account.uid, KdfParameters::ENROLLMENT, kind)
            || Instant::now() >= deadline
            || cancelled()
        {
            return Err(BackendFailure::Unavailable);
        }
        let id = self.next_id().ok_or(BackendFailure::Unavailable)?;
        let request = encode_enrollment_request(account, generation, backend, profile, &pin, id);
        drop(pin);
        let response = self
            .exchange(
                request,
                permit,
                MAX_ENROLLMENT_RESPONSE,
                deadline,
                cancelled,
            )
            .ok_or(BackendFailure::Unavailable)?;
        decode_enrollment_response(&response, id, account, generation, backend, profile)
            .ok_or(BackendFailure::Unavailable)
    }

    #[allow(clippy::too_many_arguments)]
    fn check_record(
        &self,
        credential: &CredentialRecord,
        pin: Pin,
        permit: WorkPermit,
        kind: WorkKind,
        trial: bool,
        deadline: Instant,
        mut cancelled: impl FnMut() -> bool,
    ) -> BackendOutcome {
        if !credential.profile().matches(&pin) {
            return unavailable();
        }
        let parameters = match parameters(credential) {
            Ok(parameters) => parameters,
            Err(()) => return unavailable(),
        };
        if !permit.covers(credential.account().uid, parameters, kind)
            || Instant::now() >= deadline
            || cancelled()
        {
            return unavailable();
        }
        let Some(id) = self.next_id() else {
            return unavailable();
        };
        let request = match encode_record_request(credential, &pin, id, trial) {
            Ok(request) => request,
            Err(()) => return unavailable(),
        };
        drop(pin);
        self.exchange(request, permit, RESPONSE_BYTES, deadline, cancelled)
            .and_then(|response| decode_response(&response, id))
            .unwrap_or_else(unavailable)
    }

    fn next_id(&self) -> Option<u64> {
        self.shared
            .next_id
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |id| id.checked_add(1))
            .ok()
    }

    fn exchange(
        &self,
        request: Zeroizing<Vec<u8>>,
        permit: WorkPermit,
        response_limit: usize,
        deadline: Instant,
        mut cancelled: impl FnMut() -> bool,
    ) -> Option<Zeroizing<Vec<u8>>> {
        if Instant::now() >= deadline || cancelled() {
            return None;
        }
        let slot = self.reserve_slot()?;
        let mut stream = match self.spawn(slot, permit) {
            Ok(stream) => stream,
            Err(_) => {
                if let Ok(mut slots) = self.shared.slots.lock() {
                    slots[slot] = None;
                }
                return None;
            }
        };
        // The guard retires the child even if cancellation code unwinds.
        let mut guard = ActiveGuard {
            shared: self.shared.clone(),
            slot,
            completed: false,
        };
        let mut sent = 0;
        let mut response = Zeroizing::new(vec![0u8; response_limit + 1]);
        let mut received = 0;
        let mut eof = false;
        let mut status = None;
        loop {
            if Instant::now() >= deadline || cancelled() {
                return None;
            }
            if sent < request.len() {
                match stream.write(&request[sent..]) {
                    Ok(0) => return None,
                    Ok(n) => {
                        sent += n;
                        if sent == request.len()
                            && stream.shutdown(std::net::Shutdown::Write).is_err()
                        {
                            return None;
                        }
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                    Err(_) => return None,
                }
            }
            if !eof {
                match stream.read(&mut response[received..]) {
                    Ok(0) => eof = true,
                    Ok(n) => {
                        received += n;
                        if received > response_limit {
                            return None;
                        }
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                    Err(_) => return None,
                }
            }
            if status.is_none() {
                match self.try_reap_active(slot) {
                    Ok(found) => status = found,
                    Err(_) => return None,
                }
            }
            if let Some(status) = status {
                // Child has been reaped, so no lease needs to be quarantined.
                guard.completed = true;
                if eof {
                    if !status.success()
                        || sent != request.len()
                        || Instant::now() >= deadline
                        || cancelled()
                    {
                        return None;
                    }
                    response.truncate(received);
                    return Some(response);
                }
            }
            thread::sleep(POLL_INTERVAL.min(deadline.saturating_duration_since(Instant::now())));
        }
    }

    /// Currently charged live and retired worker groups, for status/tests.
    pub fn occupied(&self) -> usize {
        self.shared
            .slots
            .lock()
            .map(|slots| slots.iter().filter(|slot| slot.is_some()).count())
            .unwrap_or(MAX_WORKERS)
    }

    fn reserve_slot(&self) -> Option<usize> {
        let mut slots = self.shared.slots.lock().ok()?;
        let index = slots.iter().position(Option::is_none)?;
        slots[index] = Some(Slot::Starting);
        Some(index)
    }

    fn spawn(&self, slot: usize, permit: WorkPermit) -> io::Result<UnixStream> {
        let (parent, child_socket) = UnixStream::pair()?;
        parent.set_nonblocking(true)?;
        let mut command = Command::new(&self.executable);
        command
            .env_clear()
            .current_dir("/")
            .process_group(0)
            .stdin(Stdio::from(std::os::fd::OwnedFd::from(
                child_socket.try_clone()?,
            )))
            .stdout(Stdio::from(std::os::fd::OwnedFd::from(child_socket)))
            .stderr(Stdio::null());
        #[cfg(test)]
        command.args(&self.fixture_arguments);
        let mut child = command.spawn()?;
        let group = rustix::process::Pid::from_raw(child.id() as i32)
            .ok_or_else(|| io::Error::other("invalid child PID"))?;
        let mut slots = match self.shared.slots.lock() {
            Ok(slots) => slots,
            Err(_) => {
                // Poisoning is not recoverable, and must not release the lease
                // while a native child could still execute.
                let _ = rustix::process::kill_process_group(group, rustix::process::Signal::KILL);
                let _ = child.kill();
                std::mem::forget((child, permit));
                return Err(io::Error::other("worker accounting unavailable"));
            }
        };
        slots[slot] = Some(Slot::Child(Entry {
            child,
            group,
            reaped: None,
            _permit: permit,
            retired: false,
            #[cfg(test)]
            reap_after: Instant::now(),
        }));
        Ok(parent)
    }

    fn try_reap_active(&self, slot: usize) -> io::Result<Option<ExitStatus>> {
        let mut slots = self
            .shared
            .slots
            .lock()
            .map_err(|_| io::Error::other("worker accounting unavailable"))?;
        let Some(Slot::Child(entry)) = &mut slots[slot] else {
            return Err(io::Error::other("worker missing"));
        };
        let status = entry.poll_reaped()?;
        if status.is_some() {
            slots[slot] = None;
        }
        Ok(status)
    }
}

struct ActiveGuard {
    shared: Arc<Shared>,
    slot: usize,
    completed: bool,
}

impl Drop for ActiveGuard {
    fn drop(&mut self) {
        if self.completed {
            return;
        }
        if let Ok(mut slots) = self.shared.slots.lock()
            && let Some(Slot::Child(entry)) = &mut slots[self.slot]
        {
            entry.retired = true;
            #[cfg(test)]
            {
                entry.reap_after = Instant::now() + self.shared.reap_delay;
            }
            entry.terminate();
        }
    }
}

fn validate_executable(path: &Path) -> io::Result<()> {
    validate_executable_owner(path, 0)
}

fn validate_executable_owner(path: &Path, owner: u32) -> io::Result<()> {
    if !path.is_absolute()
        || path
            .components()
            .any(|part| matches!(part, Component::CurDir | Component::ParentDir))
    {
        return Err(io::Error::other(
            "worker path must be absolute and canonical",
        ));
    }
    for ancestor in path.ancestors() {
        let metadata = std::fs::symlink_metadata(ancestor)?;
        if metadata.file_type().is_symlink()
            || metadata.uid() != owner
            || metadata.mode() & 0o022 != 0
            || (ancestor == path && (!metadata.is_file() || metadata.mode() & 0o111 == 0))
            || (ancestor != path && !metadata.is_dir())
        {
            return Err(io::Error::other("untrusted worker installation"));
        }
    }
    Ok(())
}

fn parameters(credential: &CredentialRecord) -> Result<KdfParameters, ()> {
    match credential.backend() {
        Backend::Software => localpin_credentials::SoftwareVerifier::new(credential)
            .map(|verifier| verifier.parameters())
            .map_err(|_| ()),
        Backend::Tpm2 => localpin_tpm::TpmRecord::from_credential(credential)
            .map(|record| record.parameters())
            .map_err(|_| ()),
    }
}

fn encode_record_request(
    credential: &CredentialRecord,
    pin: &Pin,
    id: u64,
    trial: bool,
) -> Result<Zeroizing<Vec<u8>>, ()> {
    let record = credential.encode().map_err(|_| ())?;
    let mut output = Zeroizing::new(Vec::with_capacity(
        REQUEST_HEADER + record.expose().len() + 2 + pin.expose().len(),
    ));
    output.extend_from_slice(if trial { b"LPT2" } else { b"LPW2" });
    output.extend_from_slice(&id.to_be_bytes());
    output.extend_from_slice(&(record.expose().len() as u32).to_be_bytes());
    output.extend_from_slice(record.expose());
    output.extend_from_slice(&(pin.expose().len() as u16).to_be_bytes());
    output.extend_from_slice(pin.expose());
    Ok(output)
}

fn decode_response(bytes: &[u8], id: u64) -> Option<BackendOutcome> {
    if bytes.len() != RESPONSE_BYTES || &bytes[..4] != b"LPWR" || bytes[4..12] != id.to_be_bytes() {
        return None;
    }
    Some(match bytes[12] {
        1 => BackendOutcome::Match,
        2 => BackendOutcome::Mismatch,
        3 => unavailable(),
        _ => return None,
    })
}

fn encode_enrollment_request(
    account: AccountId,
    generation: Generation,
    backend: Backend,
    profile: CredentialProfile,
    pin: &Pin,
    id: u64,
) -> Zeroizing<Vec<u8>> {
    let mut output = Zeroizing::new(Vec::with_capacity(
        REQUEST_HEADER + ENROLLMENT_BINDING_BYTES + 2 + pin.expose().len(),
    ));
    output.extend_from_slice(b"LPE2");
    output.extend_from_slice(&id.to_be_bytes());
    output.extend_from_slice(&(ENROLLMENT_BINDING_BYTES as u32).to_be_bytes());
    output.extend_from_slice(&account.uid.get().to_be_bytes());
    output.extend_from_slice(&account.incarnation.get());
    output.extend_from_slice(&generation.get().to_be_bytes());
    output.push(match backend {
        Backend::Tpm2 => 1,
        Backend::Software => 2,
    });
    output.extend_from_slice(&[profile.policy, profile.kind as u8, profile.length]);
    output.extend_from_slice(&(pin.expose().len() as u16).to_be_bytes());
    output.extend_from_slice(pin.expose());
    output
}

fn decode_enrollment_response(
    bytes: &[u8],
    id: u64,
    account: AccountId,
    generation: Generation,
    backend: Backend,
    profile: CredentialProfile,
) -> Option<CredentialRecord> {
    if bytes.len() < ENROLLMENT_RESPONSE_HEADER
        || bytes.len() > MAX_ENROLLMENT_RESPONSE
        || &bytes[..4] != b"LPWE"
        || bytes[4..12] != id.to_be_bytes()
        || bytes[12] != 1
    {
        return None;
    }
    let length = u32::from_be_bytes(bytes[13..17].try_into().ok()?) as usize;
    if length == 0 || length != bytes.len() - ENROLLMENT_RESPONSE_HEADER {
        return None;
    }
    let record = CredentialRecord::decode(&bytes[ENROLLMENT_RESPONSE_HEADER..]).ok()?;
    if record.account() != account
        || record.generation() != generation
        || record.backend() != backend
        || record.profile() != profile
        || parameters(&record).ok()? != KdfParameters::ENROLLMENT
    {
        return None;
    }
    Some(record)
}

enum WorkerRequest {
    Record {
        credential: CredentialRecord,
        pin: Pin,
    },
    Enroll {
        account: AccountId,
        generation: Generation,
        backend: Backend,
        profile: CredentialProfile,
        pin: Pin,
    },
}

fn read_request(input: &mut impl Read) -> Result<(u64, WorkerRequest), ()> {
    let mut header = [0; REQUEST_HEADER];
    input.read_exact(&mut header).map_err(|_| ())?;
    let enrollment = match &header[..4] {
        b"LPW2" | b"LPT2" => false,
        b"LPE2" => true,
        _ => return Err(()),
    };
    let id = u64::from_be_bytes(header[4..12].try_into().map_err(|_| ())?);
    let length = u32::from_be_bytes(header[12..16].try_into().map_err(|_| ())?) as usize;
    if id == 0
        || length == 0
        || length > MAX_RECORD_BYTES
        || (enrollment && length != ENROLLMENT_BINDING_BYTES)
    {
        return Err(());
    }
    let mut bytes = Zeroizing::new(vec![0; length]);
    input.read_exact(&mut bytes).map_err(|_| ())?;
    let mut secret_length = [0; 2];
    input.read_exact(&mut secret_length).map_err(|_| ())?;
    let secret_length = usize::from(u16::from_be_bytes(secret_length));
    if secret_length == 0 || secret_length > MAX_CREDENTIAL_BYTES {
        return Err(());
    }
    let mut secret = Zeroizing::new(vec![0; secret_length]);
    input.read_exact(&mut secret).map_err(|_| ())?;
    let mut trailing = [0];
    if input.read(&mut trailing).map_err(|_| ())? != 0 {
        return Err(());
    }
    let pin = Pin::parse(&secret).map_err(|_| ())?;
    let request = if enrollment {
        let account = AccountId {
            uid: Uid::new(u32::from_be_bytes(bytes[..4].try_into().map_err(|_| ())?))
                .map_err(|_| ())?,
            incarnation: Incarnation::new(bytes[4..20].try_into().map_err(|_| ())?)
                .map_err(|_| ())?,
        };
        let generation = Generation::new(u64::from_be_bytes(
            bytes[20..28].try_into().map_err(|_| ())?,
        ))
        .map_err(|_| ())?;
        let backend = match bytes[28] {
            1 => Backend::Tpm2,
            2 => Backend::Software,
            _ => return Err(()),
        };
        let credential_kind = match bytes[30] {
            1 => CredentialKind::NumericPin,
            2 => CredentialKind::Passcode,
            _ => return Err(()),
        };
        let profile =
            CredentialProfile::for_enrollment(backend, credential_kind, &pin).map_err(|_| ())?;
        if [bytes[29], bytes[30], bytes[31]] != [profile.policy, profile.kind as u8, profile.length]
        {
            return Err(());
        }
        WorkerRequest::Enroll {
            account,
            generation,
            backend,
            profile,
            pin,
        }
    } else {
        let credential = CredentialRecord::decode(&bytes[..length]).map_err(|_| ())?;
        if !credential.profile().matches(&pin) {
            return Err(());
        }
        parameters(&credential)?;
        WorkerRequest::Record { credential, pin }
    };
    Ok((id, request))
}

fn dispatch(credential: &CredentialRecord, pin: &Pin) -> BackendOutcome {
    let budget = ResourceBudget::default();
    match credential.backend() {
        Backend::Software => {
            match localpin_credentials::validate_enrollment(credential, pin, &budget) {
                Ok(true) => BackendOutcome::Match,
                Ok(false) => BackendOutcome::Mismatch,
                Err(_) => unavailable(),
            }
        }
        Backend::Tpm2 => {
            let result = (|| {
                let parameters = localpin_tpm::TpmRecord::from_credential(credential)?.parameters();
                let mut permit = budget
                    .try_work(
                        credential.account().uid,
                        parameters,
                        WorkKind::TpmPinDerivation,
                    )
                    .map_err(|_| localpin_tpm::Error::Unavailable)?;
                localpin_tpm::NativeOperation::resource_manager()?.trial_verify(
                    credential,
                    pin,
                    &mut permit,
                    TPM_DA_RESERVE,
                )
            })();
            match result {
                Ok(()) => BackendOutcome::Match,
                Err(localpin_tpm::Error::Mismatch) => BackendOutcome::Mismatch,
                Err(_) => unavailable(),
            }
        }
    }
}

fn dispatch_enrollment(
    account: AccountId,
    generation: Generation,
    backend: Backend,
    profile: CredentialProfile,
    pin: &Pin,
) -> Result<CredentialRecord, ()> {
    let budget = ResourceBudget::default();
    let record = match backend {
        Backend::Software => {
            localpin_credentials::enroll(account, generation, pin, &budget).map_err(|_| ())
        }
        Backend::Tpm2 => {
            let mut permit = budget
                .try_work(
                    account.uid,
                    KdfParameters::ENROLLMENT,
                    WorkKind::TpmPinDerivation,
                )
                .map_err(|_| ())?;
            localpin_tpm::NativeOperation::resource_manager()
                .map_err(|_| ())?
                .enroll(
                    account,
                    generation,
                    pin,
                    &mut permit,
                    &mut localpin_credentials::OsRandom,
                )
                .map_err(|_| ())
        }
    }?;
    record.with_profile(profile).map_err(|_| ())
}

/// Execute the installed one-shot helper's bounded private stdin/stdout contract.
///
/// No argv/env credential, path, endpoint or command is read. A request selects
/// only one reviewed operation and backend. Malformed input produces no response;
/// valid input yields a sanitized result or a bounded protected credential record.
/// All secret-bearing owners drop before exit.
pub fn worker_main() -> i32 {
    if crate::protect_process_secrets().is_err() {
        return 1;
    }
    let Ok((id, request)) = read_request(&mut io::stdin().lock()) else {
        return 1;
    };
    let response = match request {
        WorkerRequest::Record { credential, pin } => {
            let outcome = dispatch(&credential, &pin);
            drop((credential, pin));
            let mut response = Zeroizing::new(vec![0; RESPONSE_BYTES]);
            response[..4].copy_from_slice(b"LPWR");
            response[4..12].copy_from_slice(&id.to_be_bytes());
            response[12] = match outcome {
                BackendOutcome::Match => 1,
                BackendOutcome::Mismatch => 2,
                BackendOutcome::Unavailable(_) | BackendOutcome::Cancelled => 3,
            };
            response
        }
        WorkerRequest::Enroll {
            account,
            generation,
            backend,
            profile,
            pin,
        } => {
            let record = dispatch_enrollment(account, generation, backend, profile, &pin);
            drop(pin);
            let record = record.and_then(|record| record.encode().map_err(|_| ()));
            let mut response = Zeroizing::new(vec![0; ENROLLMENT_RESPONSE_HEADER]);
            response[..4].copy_from_slice(b"LPWE");
            response[4..12].copy_from_slice(&id.to_be_bytes());
            match record {
                Ok(record) => {
                    response[12] = 1;
                    response[13..17].copy_from_slice(&(record.expose().len() as u32).to_be_bytes());
                    response.extend_from_slice(record.expose());
                }
                Err(()) => response[12] = 3,
            }
            response
        }
    };
    let mut output = io::stdout().lock();
    if output
        .write_all(&response)
        .and_then(|()| output.flush())
        .is_ok()
    {
        0
    } else {
        1
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    const PHC: &[u8] = b"$argon2id$v=19$m=65536,t=3,p=1$BwcHBwcHBwcHBwcHBwcHBw$CUNrJW+K3R42xrH7g4MDA7wv0ihz8Hcf0glJGhH5HZ4";
    static NEXT_FIXTURE: AtomicUsize = AtomicUsize::new(0);

    fn record(uid: u32) -> CredentialRecord {
        CredentialRecord::new(
            AccountId {
                uid: Uid::new(uid).unwrap(),
                incarnation: Incarnation::new([1; 16]).unwrap(),
            },
            Generation::new(1).unwrap(),
            Backend::Software,
            PHC,
        )
        .unwrap()
    }

    fn permit(budget: &ResourceBudget, uid: u32) -> WorkPermit {
        budget
            .try_work(
                Uid::new(uid).unwrap(),
                KdfParameters::ENROLLMENT,
                WorkKind::Verification,
            )
            .unwrap()
    }

    fn fixture(executable: &str, arguments: &[&str], reap_delay: Duration) -> WorkerSupervisor {
        let mut supervisor =
            WorkerSupervisor::build(PathBuf::from(executable), reap_delay).unwrap();
        supervisor.fixture_arguments = arguments.iter().map(std::ffi::OsString::from).collect();
        supervisor
    }

    fn verify(
        supervisor: &WorkerSupervisor,
        budget: &ResourceBudget,
        uid: u32,
        duration: Duration,
    ) -> BackendOutcome {
        supervisor.verify(
            &record(uid),
            Pin::parse(b"123456").unwrap(),
            permit(budget, uid),
            Instant::now() + duration,
            || false,
        )
    }

    fn await_empty(supervisor: &WorkerSupervisor) {
        let deadline = Instant::now() + Duration::from_secs(3);
        while supervisor.occupied() != 0 && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(supervisor.occupied(), 0);
    }

    #[test]
    fn canonical_private_request_rejects_truncation_trailing_and_excessive_length() {
        let credential = record(1000);
        let request =
            encode_record_request(&credential, &Pin::parse(b"123456").unwrap(), 17, false).unwrap();
        let (
            id,
            WorkerRequest::Record {
                credential: decoded,
                pin,
            },
        ) = read_request(&mut request.as_slice()).unwrap()
        else {
            panic!("wrong operation")
        };
        assert_eq!(id, 17);
        assert_eq!(decoded.account(), credential.account());
        assert_eq!(decoded.generation(), credential.generation());
        assert_eq!(pin.expose(), b"123456");
        for length in 0..request.len() {
            assert!(read_request(&mut &request[..length]).is_err());
        }
        let mut trailing = request.to_vec();
        trailing.push(0);
        assert!(read_request(&mut trailing.as_slice()).is_err());
        let mut excessive = *b"LPW2\0\0\0\0\0\0\0\x01\0\0\0\0";
        excessive[12..].copy_from_slice(&((MAX_RECORD_BYTES + 1) as u32).to_be_bytes());
        assert!(read_request(&mut excessive.as_slice()).is_err());
    }

    fn enrollment_permit(budget: &ResourceBudget, uid: u32) -> WorkPermit {
        budget
            .try_work(
                Uid::new(uid).unwrap(),
                KdfParameters::ENROLLMENT,
                WorkKind::Enrollment,
            )
            .unwrap()
    }

    fn enrollment_response(credential: &CredentialRecord, id: u64) -> Zeroizing<Vec<u8>> {
        let record = credential.encode().unwrap();
        let mut response = Zeroizing::new(b"LPWE".to_vec());
        response.extend_from_slice(&id.to_be_bytes());
        response.push(1);
        response.extend_from_slice(&(record.expose().len() as u32).to_be_bytes());
        response.extend_from_slice(record.expose());
        response
    }

    #[test]
    fn enrollment_request_is_exact_bounded_and_preserves_the_trusted_binding() {
        let credential = record(1000);
        let request = encode_enrollment_request(
            credential.account(),
            credential.generation(),
            Backend::Software,
            CredentialProfile::for_enrollment(
                Backend::Software,
                CredentialKind::NumericPin,
                &Pin::parse(b"01234567").unwrap(),
            )
            .unwrap(),
            &Pin::parse(b"01234567").unwrap(),
            17,
        );
        assert_eq!(
            request.len(),
            REQUEST_HEADER + ENROLLMENT_BINDING_BYTES + 2 + 8
        );
        let (
            id,
            WorkerRequest::Enroll {
                account,
                generation,
                backend,
                profile,
                pin,
            },
        ) = read_request(&mut request.as_slice()).unwrap()
        else {
            panic!("wrong operation")
        };
        assert_eq!(id, 17);
        assert_eq!(account, credential.account());
        assert_eq!(generation, credential.generation());
        assert_eq!(backend, Backend::Software);
        assert_eq!(pin.expose(), b"01234567");
        assert_eq!(profile.length, 8);
        for length in 0..request.len() {
            assert!(read_request(&mut &request[..length]).is_err());
        }
        for (start, end) in [(4, 12), (16, 20), (20, 36), (36, 44)] {
            let mut invalid = request.to_vec();
            invalid[start..end].fill(0);
            assert!(read_request(&mut invalid.as_slice()).is_err());
        }
        let mut trailing = request.to_vec();
        trailing.push(0);
        assert!(read_request(&mut trailing.as_slice()).is_err());
    }

    #[test]
    fn enrollment_results_require_exact_id_account_generation_backend_and_payload() {
        let credential = record(1000);
        let valid = enrollment_response(&credential, 17);
        let decode = |bytes: &[u8], id, account, generation, backend| {
            decode_enrollment_response(
                bytes,
                id,
                account,
                generation,
                backend,
                credential.profile(),
            )
        };
        assert!(
            decode(
                &valid,
                17,
                credential.account(),
                credential.generation(),
                Backend::Software,
            )
            .is_some()
        );
        for length in 0..valid.len() {
            assert!(
                decode(
                    &valid[..length],
                    17,
                    credential.account(),
                    credential.generation(),
                    Backend::Software,
                )
                .is_none()
            );
        }
        let mut wrong_incarnation = credential.account();
        wrong_incarnation.incarnation = Incarnation::new([2; 16]).unwrap();
        for (id, account, generation, backend) in [
            (
                18,
                credential.account(),
                credential.generation(),
                Backend::Software,
            ),
            (
                17,
                record(1001).account(),
                credential.generation(),
                Backend::Software,
            ),
            (
                17,
                wrong_incarnation,
                credential.generation(),
                Backend::Software,
            ),
            (
                17,
                credential.account(),
                Generation::new(2).unwrap(),
                Backend::Software,
            ),
            (
                17,
                credential.account(),
                credential.generation(),
                Backend::Tpm2,
            ),
        ] {
            assert!(decode(&valid, id, account, generation, backend).is_none());
        }
        for (offset, byte) in [(0, b'X'), (12, 3), (13, 1), (17, b'X')] {
            let mut invalid = valid.to_vec();
            invalid[offset] = byte;
            assert!(
                decode(
                    &invalid,
                    17,
                    credential.account(),
                    credential.generation(),
                    Backend::Software
                )
                .is_none()
            );
        }
        let mut trailing = valid.to_vec();
        trailing.push(0);
        assert!(
            decode(
                &trailing,
                17,
                credential.account(),
                credential.generation(),
                Backend::Software
            )
            .is_none()
        );
        let invalid = CredentialRecord::new(
            credential.account(),
            credential.generation(),
            Backend::Software,
            b"invalid",
        )
        .unwrap();
        assert!(
            decode(
                &enrollment_response(&invalid, 17),
                17,
                credential.account(),
                credential.generation(),
                Backend::Software
            )
            .is_none()
        );
    }

    #[test]
    fn enrollment_and_trial_refuse_wrong_work_kinds_before_spawning() {
        let supervisor = fixture("/usr/bin/sleep", &["1"], Duration::ZERO);
        let budget = ResourceBudget::default();
        let credential = record(1000);
        assert!(
            supervisor
                .enroll(
                    credential.account(),
                    credential.generation(),
                    Backend::Software,
                    CredentialKind::NumericPin,
                    Pin::parse(b"01234567").unwrap(),
                    permit(&budget, 1000),
                    Instant::now() + Duration::from_secs(1),
                    || false,
                )
                .is_err()
        );
        assert_eq!(supervisor.occupied(), 0);
        assert_eq!(
            supervisor.trial_verify(
                &credential,
                Pin::parse(b"012345").unwrap(),
                permit(&budget, 1000),
                Instant::now() + Duration::from_secs(1),
                || false,
            ),
            unavailable()
        );
        assert_eq!(supervisor.occupied(), 0);
        assert_eq!(
            supervisor.verify(
                &credential,
                Pin::parse(b"012345").unwrap(),
                enrollment_permit(&budget, 1000),
                Instant::now() + Duration::from_secs(1),
                || false,
            ),
            unavailable()
        );
        assert_eq!(supervisor.occupied(), 0);
    }

    #[test]
    fn cancelled_enrollment_keeps_the_shared_uid_memory_and_process_capacity_until_reap() {
        let supervisor = fixture("/usr/bin/sleep", &["1"], Duration::from_millis(150));
        let budget = ResourceBudget::default();
        let credential = record(1000);
        let mut polls = 0;
        let start = Instant::now();
        assert!(
            supervisor
                .enroll(
                    credential.account(),
                    credential.generation(),
                    Backend::Software,
                    CredentialKind::NumericPin,
                    Pin::parse(b"01234567").unwrap(),
                    enrollment_permit(&budget, 1000),
                    start + Duration::from_secs(1),
                    || {
                        polls += 1;
                        polls >= 4
                    },
                )
                .is_err()
        );
        assert!(start.elapsed() < Duration::from_millis(250));
        assert_eq!(supervisor.occupied(), 1);
        for kind in [
            WorkKind::Verification,
            WorkKind::Enrollment,
            WorkKind::TpmPinDerivation,
        ] {
            assert!(
                budget
                    .try_work(credential.account().uid, KdfParameters::ENROLLMENT, kind)
                    .is_err()
            );
        }
        await_empty(&supervisor);
        assert!(
            budget
                .try_work(
                    credential.account().uid,
                    KdfParameters::ENROLLMENT,
                    WorkKind::Verification
                )
                .is_ok()
        );
    }

    #[test]
    fn malformed_oversized_and_late_enrollment_worker_results_fail_closed() {
        let credential = record(1000);
        let valid = enrollment_response(&credential, 1);
        for (payload, sleep, deadline) in [
            ("b'LPWE'".to_owned(), 0, 500),
            (format!("bytes({})", MAX_ENROLLMENT_RESPONSE + 1), 0, 500),
            (format!("bytes({:?})", valid.as_slice()), 1, 80),
        ] {
            let code = format!(
                "import sys,time; sys.stdin.buffer.read(); sys.stdout.buffer.write({payload}); sys.stdout.buffer.flush(); time.sleep({sleep})"
            );
            let supervisor = fixture("/usr/bin/python3", &["-c", &code], Duration::ZERO);
            let start = Instant::now();
            assert!(
                supervisor
                    .enroll(
                        credential.account(),
                        credential.generation(),
                        Backend::Software,
                        CredentialKind::NumericPin,
                        Pin::parse(b"01234567").unwrap(),
                        enrollment_permit(&ResourceBudget::default(), 1000),
                        start + Duration::from_millis(deadline),
                        || false,
                    )
                    .is_err()
            );
            assert!(start.elapsed() < Duration::from_millis(750));
            await_empty(&supervisor);
        }
    }

    #[test]
    fn fixed_result_requires_exact_length_identity_and_outcome() {
        let mut response = *b"LPWR\0\0\0\0\0\0\0\x11\x01";
        assert_eq!(decode_response(&response, 17), Some(BackendOutcome::Match));
        assert!(decode_response(&response, 18).is_none());
        for length in 0..response.len() {
            assert!(decode_response(&response[..length], 17).is_none());
        }
        response[12] = 2;
        assert_eq!(
            decode_response(&response, 17),
            Some(BackendOutcome::Mismatch)
        );
        response[12] = 3;
        assert_eq!(decode_response(&response, 17), Some(unavailable()));
        response[12] = 0;
        assert!(decode_response(&response, 17).is_none());
    }

    #[test]
    fn malformed_partial_crashed_and_late_processes_fail_closed() {
        for arguments in [
            &["LPWR"][..],
            &["wrong-format"][..],
            &["LPWR\\000\\000\\000\\000\\000\\000\\000\\001\\001extra"][..],
        ] {
            let supervisor = fixture("/usr/bin/printf", arguments, Duration::ZERO);
            assert_eq!(
                verify(
                    &supervisor,
                    &ResourceBudget::default(),
                    1000,
                    Duration::from_secs(1)
                ),
                unavailable()
            );
            await_empty(&supervisor);
        }
        let crashed = fixture("/usr/bin/false", &[], Duration::ZERO);
        assert_eq!(
            verify(
                &crashed,
                &ResourceBudget::default(),
                1000,
                Duration::from_secs(1)
            ),
            unavailable()
        );
        await_empty(&crashed);
        let late = fixture("/usr/bin/sleep", &["1"], Duration::ZERO);
        let start = Instant::now();
        assert_eq!(
            verify(
                &late,
                &ResourceBudget::default(),
                1000,
                Duration::from_millis(25)
            ),
            unavailable()
        );
        assert!(start.elapsed() >= Duration::from_millis(25));
        assert!(start.elapsed() < Duration::from_millis(250));
        await_empty(&late);
    }

    #[test]
    fn native_fifo_stall_deadline_retains_uid_memory_and_process_until_delayed_reap() {
        let path = std::env::temp_dir().join(format!(
            "localpin-worker-fifo-{}-{}",
            std::process::id(),
            NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed)
        ));
        rustix::fs::mkfifoat(
            rustix::fs::CWD,
            &path,
            rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
        )
        .unwrap();
        let stalled = fixture(
            "/usr/bin/cat",
            &[path.to_str().unwrap()],
            Duration::from_millis(450),
        );
        let budget = ResourceBudget::default();
        let start = Instant::now();
        assert_eq!(
            verify(&stalled, &budget, 1000, Duration::from_millis(40)),
            unavailable()
        );
        assert!(start.elapsed() >= Duration::from_millis(40));
        assert!(start.elapsed() < Duration::from_millis(250));
        assert_eq!(stalled.occupied(), 1);
        assert!(
            budget
                .try_work(
                    Uid::new(1000).unwrap(),
                    KdfParameters::ENROLLMENT,
                    WorkKind::Verification
                )
                .is_err()
        );

        // The same process table has spare capacity for an unrelated UID while
        // the killed native FIFO-open caller remains deliberately unreaped.
        let mut responsive = stalled.clone();
        responsive.executable = PathBuf::from("/usr/bin/python3");
        responsive.fixture_arguments = vec![
            "-c".into(),
            "import sys; sys.stdin.buffer.read(); sys.stdout.buffer.write(b'LPWR' + (2).to_bytes(8, 'big') + bytes([1]))".into(),
        ];
        let other_start = Instant::now();
        assert_eq!(
            verify(&responsive, &budget, 1001, Duration::from_millis(200)),
            BackendOutcome::Match
        );
        assert!(other_start.elapsed() < Duration::from_millis(200));
        assert_eq!(stalled.occupied(), 1);
        await_empty(&stalled);
        assert!(
            budget
                .try_work(
                    Uid::new(1000).unwrap(),
                    KdfParameters::ENROLLMENT,
                    WorkKind::Verification
                )
                .is_ok()
        );
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn cancellation_closes_result_path_and_charges_slot_until_reap() {
        let supervisor = fixture("/usr/bin/sleep", &["1"], Duration::from_millis(100));
        let budget = ResourceBudget::default();
        let mut polls = 0;
        let start = Instant::now();
        let result = supervisor.verify(
            &record(1000),
            Pin::parse(b"123456").unwrap(),
            permit(&budget, 1000),
            start + Duration::from_secs(1),
            || {
                polls += 1;
                polls >= 3
            },
        );
        assert_eq!(result, unavailable());
        assert!(start.elapsed() < Duration::from_millis(250));
        assert_eq!(supervisor.occupied(), 1);
        assert!(
            budget
                .try_work(
                    Uid::new(1000).unwrap(),
                    KdfParameters::ENROLLMENT,
                    WorkKind::Verification
                )
                .is_err()
        );
        await_empty(&supervisor);
    }

    #[test]
    fn even_a_valid_buffered_match_is_rejected_when_native_cleanup_exceeds_deadline() {
        let marker = std::env::temp_dir().join(format!(
            "localpin-worker-result-{}-{}",
            std::process::id(),
            NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed)
        ));
        let code = format!(
            "import sys,time; sys.stdin.buffer.read(); sys.stdout.buffer.write(b'LPWR' + (1).to_bytes(8, 'big') + bytes([1])); sys.stdout.buffer.flush(); open({:?}, 'w').close(); time.sleep(1)",
            marker.to_str().unwrap()
        );
        let supervisor = fixture(
            "/usr/bin/python3",
            &["-c", &code],
            Duration::from_millis(100),
        );
        let start = Instant::now();
        assert_eq!(
            verify(
                &supervisor,
                &ResourceBudget::default(),
                1000,
                Duration::from_millis(150)
            ),
            unavailable()
        );
        assert!(start.elapsed() >= Duration::from_millis(150));
        assert!(start.elapsed() < Duration::from_millis(400));
        assert!(
            marker.exists(),
            "fixture wrote a valid match before entering its native sleep"
        );
        assert_eq!(supervisor.occupied(), 1);
        await_empty(&supervisor);
        std::fs::remove_file(marker).unwrap();
    }

    #[test]
    fn exited_leader_cannot_leave_a_same_group_descendant_holding_private_ipc() {
        let marker = std::env::temp_dir().join(format!(
            "localpin-worker-descendant-{}-{}",
            std::process::id(),
            NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed)
        ));
        let code = format!(
            "import os,sys,time\nsys.stdin.buffer.read()\npid=os.fork()\nif pid == 0:\n open({marker:?}, 'w').write(str(os.getpid()))\n time.sleep(10)\n os._exit(0)\nwhile not os.path.exists({marker:?}):\n time.sleep(0.001)\nsys.stdout.buffer.write(b'LPWR' + (1).to_bytes(8, 'big') + bytes([1]))\nsys.stdout.buffer.flush()\nos._exit(0)\n",
            marker = marker.to_str().unwrap()
        );
        let supervisor = fixture("/usr/bin/python3", &["-c", &code], Duration::ZERO);
        let budget = ResourceBudget::default();
        let start = Instant::now();
        let result = verify(&supervisor, &budget, 1000, Duration::from_millis(500));
        assert!(matches!(
            result,
            BackendOutcome::Match | BackendOutcome::Unavailable(_)
        ));
        assert!(start.elapsed() < Duration::from_millis(800));
        let pid: u32 = std::fs::read_to_string(&marker).unwrap().parse().unwrap();
        let deadline = Instant::now() + Duration::from_secs(1);
        let mut running = true;
        while Instant::now() < deadline {
            running = std::fs::read_to_string(format!("/proc/{pid}/stat")).is_ok_and(|stat| {
                stat.rsplit_once(')')
                    .is_some_and(|(_, tail)| !tail.starts_with(" Z "))
            });
            if !running {
                break;
            }
            thread::sleep(Duration::from_millis(5));
        }
        assert!(
            !running,
            "descendant survived its exited process-group leader"
        );
        // Container PID 1 may leave an orphan zombie unreaped. The supervisor
        // must keep its capacity charged in that case, rather than replace it.
        if supervisor.occupied() != 0 {
            assert!(
                budget
                    .try_work(
                        Uid::new(1000).unwrap(),
                        KdfParameters::ENROLLMENT,
                        WorkKind::Verification
                    )
                    .is_err()
            );
        }
        std::fs::remove_file(marker).unwrap();
    }

    #[test]
    fn exhausted_native_capacity_refuses_replacement_without_waiting() {
        let supervisor = fixture("/usr/bin/sleep", &["1"], Duration::from_millis(400));
        let budget = ResourceBudget::default();
        for uid in 1000..1000 + MAX_WORKERS as u32 {
            assert_eq!(
                verify(&supervisor, &budget, uid, Duration::from_millis(10)),
                unavailable()
            );
        }
        assert_eq!(supervisor.occupied(), MAX_WORKERS);
        assert!(
            budget
                .try_work(
                    Uid::new(2000).unwrap(),
                    KdfParameters::ENROLLMENT,
                    WorkKind::Verification
                )
                .is_err()
        );
        // Even incorrectly independent admission controllers cannot overrun the
        // supervisor's separate hard process cap.
        let start = Instant::now();
        assert_eq!(
            verify(
                &supervisor,
                &ResourceBudget::default(),
                2001,
                Duration::from_secs(1)
            ),
            unavailable()
        );
        assert!(start.elapsed() < Duration::from_millis(100));
        assert_eq!(supervisor.occupied(), MAX_WORKERS);
        await_empty(&supervisor);
        assert!(
            budget
                .try_work(
                    Uid::new(2000).unwrap(),
                    KdfParameters::ENROLLMENT,
                    WorkKind::Verification
                )
                .is_ok()
        );
    }

    #[test]
    fn installed_helper_requires_absolute_root_trusted_nonwritable_ancestors() {
        assert!(WorkerSupervisor::new("relative-worker").is_err());
        assert!(WorkerSupervisor::new("/tmp/localpin-worker").is_err());
        assert!(WorkerSupervisor::new("/usr/bin/../bin/cat").is_err());
        // Sandboxed tests may map host root to the overflow UID. Production
        // always passes literal root (0); only this validation test adapts.
        let mapped_root = std::fs::metadata("/").unwrap().uid();
        validate_executable_owner(Path::new("/usr/bin/cat"), mapped_root).unwrap();
        assert!(
            validate_executable_owner(Path::new("/usr/bin/cat"), mapped_root.wrapping_add(1))
                .is_err()
        );
    }

    #[test]
    fn worker_dispatch_uses_exact_software_record_and_candidate() {
        assert_eq!(
            dispatch(&record(1000), &Pin::parse(b"123456").unwrap()),
            BackendOutcome::Match
        );
        assert_eq!(
            dispatch(&record(1000), &Pin::parse(b"000001").unwrap()),
            BackendOutcome::Mismatch
        );
        let invalid = CredentialRecord::new(
            record(1000).account(),
            Generation::new(1).unwrap(),
            Backend::Software,
            b"invalid",
        )
        .unwrap();
        assert_eq!(
            dispatch(&invalid, &Pin::parse(b"123456").unwrap()),
            unavailable()
        );
        let supervisor = fixture("/usr/bin/sleep", &["1"], Duration::ZERO);
        assert_eq!(
            supervisor.verify(
                &invalid,
                Pin::parse(b"123456").unwrap(),
                permit(&ResourceBudget::default(), 1000),
                Instant::now() + Duration::from_secs(1),
                || false
            ),
            unavailable()
        );
        assert_eq!(supervisor.occupied(), 0);
    }
}
