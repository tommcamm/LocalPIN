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
    secret::Pin,
    throttle::{BackendFailure, BackendOutcome},
    types::Backend,
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
        let parameters = match parameters(credential) {
            Ok(parameters) => parameters,
            Err(()) => return unavailable(),
        };
        let kind = match credential.backend() {
            Backend::Software => WorkKind::Verification,
            Backend::Tpm2 => WorkKind::TpmPinDerivation,
        };
        if !permit.covers(credential.account().uid, parameters, kind)
            || Instant::now() >= deadline
            || cancelled()
        {
            return unavailable();
        }
        let id = match self
            .shared
            .next_id
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |id| id.checked_add(1))
        {
            Ok(id) => id,
            Err(_) => return unavailable(),
        };
        let request = match encode_request(credential, &pin, id) {
            Ok(request) => request,
            Err(()) => return unavailable(),
        };
        drop(pin);
        let slot = match self.reserve_slot() {
            Some(slot) => slot,
            None => return unavailable(),
        };
        let result = self.spawn(slot, permit);
        let mut stream = match result {
            Ok(stream) => stream,
            Err(_) => {
                if let Ok(mut slots) = self.shared.slots.lock() {
                    slots[slot] = None;
                }
                return unavailable();
            }
        };
        // The guard retires the child even if cancellation code unwinds.
        let mut guard = ActiveGuard {
            shared: self.shared.clone(),
            slot,
            completed: false,
        };
        let mut sent = 0;
        let mut response = [0u8; RESPONSE_BYTES + 1];
        let mut received = 0;
        let mut eof = false;
        let mut status = None;
        loop {
            if Instant::now() >= deadline || cancelled() {
                return unavailable();
            }
            if sent < request.len() {
                match stream.write(&request[sent..]) {
                    Ok(0) => return unavailable(),
                    Ok(n) => {
                        sent += n;
                        if sent == request.len()
                            && stream.shutdown(std::net::Shutdown::Write).is_err()
                        {
                            return unavailable();
                        }
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                    Err(_) => return unavailable(),
                }
            }
            if !eof {
                match stream.read(&mut response[received..]) {
                    Ok(0) => eof = true,
                    Ok(n) => {
                        received += n;
                        if received > RESPONSE_BYTES {
                            return unavailable();
                        }
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                    Err(_) => return unavailable(),
                }
            }
            if status.is_none() {
                match self.try_reap_active(slot) {
                    Ok(found) => status = found,
                    Err(_) => return unavailable(),
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
                        return unavailable();
                    }
                    return decode_response(&response[..received], id).unwrap_or_else(unavailable);
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

fn encode_request(
    credential: &CredentialRecord,
    pin: &Pin,
    id: u64,
) -> Result<Zeroizing<Vec<u8>>, ()> {
    let record = credential.encode().map_err(|_| ())?;
    let mut output = Zeroizing::new(Vec::with_capacity(
        REQUEST_HEADER + record.expose().len() + 6,
    ));
    output.extend_from_slice(b"LPW1");
    output.extend_from_slice(&id.to_be_bytes());
    output.extend_from_slice(&(record.expose().len() as u32).to_be_bytes());
    output.extend_from_slice(record.expose());
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

fn read_request(input: &mut impl Read) -> Result<(u64, CredentialRecord, Pin), ()> {
    let mut header = [0; REQUEST_HEADER];
    input.read_exact(&mut header).map_err(|_| ())?;
    if &header[..4] != b"LPW1" {
        return Err(());
    }
    let id = u64::from_be_bytes(header[4..12].try_into().map_err(|_| ())?);
    let length = u32::from_be_bytes(header[12..16].try_into().map_err(|_| ())?) as usize;
    if id == 0 || length == 0 || length > MAX_RECORD_BYTES {
        return Err(());
    }
    let mut bytes = Zeroizing::new(vec![0; length + 6]);
    input.read_exact(&mut bytes).map_err(|_| ())?;
    let mut trailing = [0];
    if input.read(&mut trailing).map_err(|_| ())? != 0 {
        return Err(());
    }
    let credential = CredentialRecord::decode(&bytes[..length]).map_err(|_| ())?;
    let pin = Pin::parse(&bytes[length..]).map_err(|_| ())?;
    parameters(&credential)?;
    Ok((id, credential, pin))
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

/// Execute the installed one-shot helper's private stdin/stdout contract.
///
/// No argv/env credential, path, endpoint, backend override or command is read.
/// Malformed requests produce no response. A valid request yields one fixed-size
/// sanitized backend result, and all secret-bearing owners drop before exit.
pub fn worker_main() -> i32 {
    let request = read_request(&mut io::stdin().lock());
    let Ok((id, credential, pin)) = request else {
        return 1;
    };
    let outcome = dispatch(&credential, &pin);
    drop((credential, pin));
    let mut response = [0; RESPONSE_BYTES];
    response[..4].copy_from_slice(b"LPWR");
    response[4..12].copy_from_slice(&id.to_be_bytes());
    response[12] = match outcome {
        BackendOutcome::Match => 1,
        BackendOutcome::Mismatch => 2,
        BackendOutcome::Unavailable(_) | BackendOutcome::Cancelled => 3,
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
    use localpin_core::types::{AccountId, Generation, Incarnation, Uid};
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
        let request = encode_request(&credential, &Pin::parse(b"123456").unwrap(), 17).unwrap();
        let (id, decoded, pin) = read_request(&mut request.as_slice()).unwrap();
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
        let mut excessive = *b"LPW1\0\0\0\0\0\0\0\x01\0\0\0\0";
        excessive[12..].copy_from_slice(&((MAX_RECORD_BYTES + 1) as u32).to_be_bytes());
        assert!(read_request(&mut excessive.as_slice()).is_err());
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
