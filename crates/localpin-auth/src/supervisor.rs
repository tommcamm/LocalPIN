//! Bounded children; live and retired groups consume capacity until reaped.
#![forbid(unsafe_code)]

use crate::{
    Conversation, MAX_PASSWORD_WORKERS, PASSWORD_TIMEOUT, PasswordPrompt, PromptStyle, ipc,
};
use localpin_core::{
    enrollment::{PasswordWorker, PasswordWorkerError, PasswordWorkerRequest},
    types::{Clock, TimePoint},
};
use localpin_protocol::transport::BootInstant;
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
use zeroize::{Zeroize, Zeroizing};

const POLL: Duration = Duration::from_millis(2);

#[derive(Clone, Copy)]
enum EligibilityStage {
    Entropy,
    Reserve,
    Launch,
    IpcWrite,
    IpcRead,
    FrameSize,
    ProcessState,
    Reap,
    TerminalExit,
    IncompleteRequest,
    Deadline,
    Decode,
    IncompleteFrame,
    Binding,
    WorkerUnavailable,
    WorkerResult,
}

impl EligibilityStage {
    fn name(self) -> &'static str {
        match self {
            Self::Entropy => "entropy",
            Self::Reserve => "reserve",
            Self::Launch => "launch",
            Self::IpcWrite => "ipc-write",
            Self::IpcRead => "ipc-read",
            Self::FrameSize => "frame-size",
            Self::ProcessState => "process-state",
            Self::Reap => "reap",
            Self::TerminalExit => "terminal-exit",
            Self::IncompleteRequest => "incomplete-request",
            Self::Deadline => "deadline",
            Self::Decode => "decode",
            Self::IncompleteFrame => "incomplete-frame",
            Self::Binding => "binding",
            Self::WorkerUnavailable => "worker-unavailable",
            Self::WorkerResult => "worker-result",
        }
    }
}

fn diagnostic_allowed(last: &AtomicU64, seconds: u64) -> bool {
    let now = seconds.max(1);
    let previous = last.load(Ordering::Relaxed);
    (previous == 0 || now.saturating_sub(previous) >= 60)
        && last
            .compare_exchange(previous, now, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
}

fn eligibility_diagnostic(stage: EligibilityStage, kind: Option<io::ErrorKind>) -> String {
    match kind {
        Some(kind) => format!(
            "localpin: eligibility supervisor unavailable stage={} io-kind={kind:?}",
            stage.name()
        ),
        None => format!(
            "localpin: eligibility supervisor unavailable stage={}",
            stage.name()
        ),
    }
}

fn eligibility_failure(
    stage: EligibilityStage,
    kind: Option<io::ErrorKind>,
) -> localpin_core::eligibility::EligibilityError {
    // One static category per minute across every supervisor/account. No UID,
    // token, frame, candidate, path or native error string enters this record.
    // Password enrollment and ordinary account-policy denial are not logged.
    static LAST_DIAGNOSTIC: AtomicU64 = AtomicU64::new(0);
    let seconds = rustix::time::clock_gettime(rustix::time::ClockId::Boottime).tv_sec;
    if diagnostic_allowed(&LAST_DIAGNOSTIC, u64::try_from(seconds).unwrap_or(0)) {
        eprintln!("{}", eligibility_diagnostic(stage, kind));
    }
    localpin_core::eligibility::EligibilityError::Unavailable
}

struct Entry {
    uid: u32,
    child: Child,
    group: rustix::process::Pid,
    status: Option<ExitStatus>,
    retired: bool,
}

impl Entry {
    fn terminate(&mut self) {
        if self.status.is_none() {
            let _ = rustix::process::kill_process_group(self.group, rustix::process::Signal::KILL);
            let _ = self.child.kill();
        }
    }

    fn reap(&mut self) -> io::Result<Option<ExitStatus>> {
        if self.status.is_none() {
            use rustix::process::{WaitId, WaitIdOptions, waitid};
            if waitid(
                WaitId::Pid(self.group),
                WaitIdOptions::EXITED | WaitIdOptions::NOHANG | WaitIdOptions::NOWAIT,
            )?
            .is_none()
            {
                return Ok(None);
            }
            // Keep the zombie PID pinned until same-group descendants are killed.
            match rustix::process::kill_process_group(self.group, rustix::process::Signal::KILL) {
                Ok(()) | Err(rustix::io::Errno::SRCH) => {}
                Err(error) => return Err(error.into()),
            }
            self.status = self.child.try_wait()?;
        }
        match rustix::process::test_kill_process_group(self.group) {
            Err(rustix::io::Errno::SRCH) => Ok(self.status),
            Ok(()) => Ok(None),
            Err(error) => Err(error.into()),
        }
    }
}

enum Slot {
    Starting(u32),
    Child(Entry),
}
impl Slot {
    fn uid(&self) -> u32 {
        match self {
            Self::Starting(uid) => *uid,
            Self::Child(entry) => entry.uid,
        }
    }
}
struct Shared {
    slots: Mutex<[Option<Slot>; MAX_PASSWORD_WORKERS]>,
}

/// A shared bounded supervisor for the separately reviewed privileged helper.
///
/// Process groups contain cooperative descendants. An installed worker sandbox
/// must additionally prevent group escapes and bound PAM helper descendants.
/// Dropping a caller requests termination; only the reaper releases capacity.
#[derive(Clone)]
pub struct PasswordSupervisor {
    executable: PathBuf,
    shared: Arc<Shared>,
    timeout: Duration,
    #[cfg(test)]
    arguments: Vec<String>,
}

impl PasswordSupervisor {
    /// Require a canonical absolute, root-owned, non-writable helper installation.
    /// No caller-selected arguments or inherited environment reach this helper.
    pub fn new(executable: impl AsRef<Path>) -> io::Result<Self> {
        validate_executable(executable.as_ref())?;
        Self::build(executable.as_ref().to_owned(), PASSWORD_TIMEOUT)
    }

    fn build(executable: PathBuf, timeout: Duration) -> io::Result<Self> {
        let shared = Arc::new(Shared {
            slots: Mutex::new(std::array::from_fn(|_| None)),
        });
        let reaping = shared.clone();
        thread::Builder::new()
            .name("localpin-password-reaper".into())
            .spawn(move || {
                loop {
                    let mut empty = false;
                    if let Ok(mut slots) = reaping.slots.lock() {
                        for slot in slots.iter_mut() {
                            let Some(Slot::Child(entry)) = slot else {
                                continue;
                            };
                            if entry.retired {
                                match entry.reap() {
                                    Ok(Some(_)) => *slot = None,
                                    Ok(None) | Err(_) => entry.terminate(),
                                }
                            }
                        }
                        empty = slots.iter().all(Option::is_none);
                    }
                    if empty && Arc::strong_count(&reaping) == 1 {
                        break;
                    }
                    thread::sleep(POLL);
                }
            })?;
        Ok(Self {
            executable,
            shared,
            timeout,
            #[cfg(test)]
            arguments: Vec::new(),
        })
    }

    /// Bind only a broker-owned conversation and trusted boot-clock adapter.
    pub fn bind<'a, C: Clock>(
        &'a self,
        conversation: &'a mut dyn Conversation,
        clock: &'a mut C,
    ) -> BoundPasswordWorker<'a, C> {
        BoundPasswordWorker {
            supervisor: self,
            conversation,
            clock,
        }
    }

    /// Number of live/retired charged groups, including failed cleanup.
    pub fn occupied(&self) -> usize {
        self.shared
            .slots
            .lock()
            .map(|slots| slots.iter().filter(|s| s.is_some()).count())
            .unwrap_or(MAX_PASSWORD_WORKERS)
    }

    pub(crate) fn run_eligibility(
        &self,
        uid: u32,
        deadline: BootInstant,
        cancelled: &mut dyn FnMut() -> bool,
    ) -> Result<(), localpin_core::eligibility::EligibilityError> {
        use localpin_core::eligibility::EligibilityError;
        let deadline = deadline.min(BootInstant::now() + Duration::from_secs(2));
        if uid == 0 || uid == u32::MAX || BootInstant::now() >= deadline || cancelled() {
            return Err(EligibilityError::Unavailable);
        }
        let mut token = [0; 16];
        getrandom::fill(&mut token)
            .map_err(|_| eligibility_failure(EligibilityStage::Entropy, None))?;
        if token == [0; 16] {
            return Err(eligibility_failure(EligibilityStage::Entropy, None));
        }
        let index = self
            .reserve(uid)
            .map_err(|_| eligibility_failure(EligibilityStage::Reserve, None))?;
        let mut stream = match self.spawn(index, uid) {
            Ok(stream) => stream,
            Err(error) => {
                if let Ok(mut slots) = self.shared.slots.lock() {
                    slots[index] = None;
                }
                return Err(eligibility_failure(
                    EligibilityStage::Launch,
                    Some(error.kind()),
                ));
            }
        };
        let mut guard = Guard {
            shared: self.shared.clone(),
            index,
            reaped: false,
        };
        let mut request = [0; 24];
        request[..4].copy_from_slice(b"LPE1");
        request[4..20].copy_from_slice(&token);
        request[20..24].copy_from_slice(&uid.to_be_bytes());
        let mut sent = 0;
        let mut incoming = Vec::new();
        let mut eof = false;
        let mut status = None;
        loop {
            if BootInstant::now() >= deadline {
                return Err(eligibility_failure(EligibilityStage::Deadline, None));
            }
            if cancelled() {
                return Err(EligibilityError::Unavailable);
            }
            if sent < request.len() {
                match stream.write(&request[sent..]) {
                    Ok(0) => {
                        return Err(eligibility_failure(
                            EligibilityStage::IpcWrite,
                            Some(io::ErrorKind::WriteZero),
                        ));
                    }
                    Ok(n) => sent += n,
                    Err(error)
                        if matches!(
                            error.kind(),
                            io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                        ) => {}
                    Err(error) => {
                        return Err(eligibility_failure(
                            EligibilityStage::IpcWrite,
                            Some(error.kind()),
                        ));
                    }
                }
            }
            if !eof {
                let mut buffer = [0; ipc::HEADER + 2];
                match stream.read(&mut buffer) {
                    Ok(0) => eof = true,
                    Ok(n) => {
                        if incoming.len() + n > ipc::HEADER + 1 {
                            return Err(eligibility_failure(EligibilityStage::FrameSize, None));
                        }
                        incoming.extend_from_slice(&buffer[..n]);
                    }
                    Err(error)
                        if matches!(
                            error.kind(),
                            io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                        ) => {}
                    Err(error) => {
                        return Err(eligibility_failure(
                            EligibilityStage::IpcRead,
                            Some(error.kind()),
                        ));
                    }
                }
            }
            if status.is_none() {
                let mut slots = self
                    .shared
                    .slots
                    .lock()
                    .map_err(|_| eligibility_failure(EligibilityStage::ProcessState, None))?;
                let Some(Slot::Child(entry)) = &mut slots[index] else {
                    return Err(eligibility_failure(EligibilityStage::ProcessState, None));
                };
                status = entry.reap().map_err(|error| {
                    eligibility_failure(EligibilityStage::Reap, Some(error.kind()))
                })?;
                if status.is_some() {
                    slots[index] = None;
                    guard.reaped = true;
                }
            }
            if eof && let Some(status) = status {
                if !status.success() {
                    return Err(eligibility_failure(EligibilityStage::TerminalExit, None));
                }
                if sent != request.len() {
                    return Err(eligibility_failure(
                        EligibilityStage::IncompleteRequest,
                        None,
                    ));
                }
                if BootInstant::now() >= deadline {
                    return Err(eligibility_failure(EligibilityStage::Deadline, None));
                }
                if cancelled() {
                    return Err(EligibilityError::Unavailable);
                }
                let (frame, length) = ipc::decode(&incoming)
                    .map_err(|error| {
                        eligibility_failure(EligibilityStage::Decode, Some(error.kind()))
                    })?
                    .ok_or_else(|| eligibility_failure(EligibilityStage::IncompleteFrame, None))?;
                if length != incoming.len()
                    || frame.kind != ipc::RESULT
                    || frame.token != token
                    || frame.sequence != 2
                    || frame.payload.expose().len() != 1
                {
                    return Err(eligibility_failure(EligibilityStage::Binding, None));
                }
                return match frame.payload.expose()[0] {
                    0 => Ok(()),
                    1 => Err(EligibilityError::AccountRestricted),
                    2 => Err(eligibility_failure(
                        EligibilityStage::WorkerUnavailable,
                        None,
                    )),
                    _ => Err(eligibility_failure(EligibilityStage::WorkerResult, None)),
                };
            }
            thread::sleep(POLL.min(deadline.saturating_duration_since(BootInstant::now())));
        }
    }

    fn reserve(&self, uid: u32) -> Result<usize, PasswordWorkerError> {
        let mut slots = self
            .shared
            .slots
            .lock()
            .map_err(|_| PasswordWorkerError::Unavailable)?;
        if slots.iter().flatten().any(|entry| entry.uid() == uid) {
            return Err(PasswordWorkerError::Unavailable);
        }
        let index = slots
            .iter()
            .position(Option::is_none)
            .ok_or(PasswordWorkerError::Unavailable)?;
        slots[index] = Some(Slot::Starting(uid));
        Ok(index)
    }

    fn spawn(&self, index: usize, uid: u32) -> io::Result<UnixStream> {
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
        command.args(&self.arguments);
        let mut child = command.spawn()?;
        let group = rustix::process::Pid::from_raw(child.id() as i32).ok_or_else(ipc::invalid)?;
        let mut slots = match self.shared.slots.lock() {
            Ok(slots) => slots,
            Err(_) => {
                let _ = child.kill();
                std::mem::forget(child);
                return Err(ipc::invalid());
            }
        };
        slots[index] = Some(Slot::Child(Entry {
            uid,
            child,
            group,
            status: None,
            retired: false,
        }));
        Ok(parent)
    }

    fn run(
        &self,
        request: PasswordWorkerRequest,
        conversation: &mut dyn Conversation,
        remaining: Duration,
    ) -> Result<(), PasswordWorkerError> {
        let deadline = BootInstant::now()
            .checked_add(self.timeout.min(remaining))
            .ok_or(PasswordWorkerError::Unavailable)?;
        if conversation.cancelled() {
            return Err(PasswordWorkerError::Cancelled);
        }
        let mut token = [0; 16];
        getrandom::fill(&mut token).map_err(|_| PasswordWorkerError::Unavailable)?;
        if token == [0; 16] {
            return Err(PasswordWorkerError::Unavailable);
        }
        let index = self.reserve(request.binding().account().uid.get())?;
        let mut stream = match self.spawn(index, request.binding().account().uid.get()) {
            Ok(stream) => stream,
            Err(_) => {
                if let Ok(mut slots) = self.shared.slots.lock() {
                    slots[index] = None;
                }
                return Err(PasswordWorkerError::Unavailable);
            }
        };
        let mut guard = Guard {
            shared: self.shared.clone(),
            index,
            reaped: false,
        };
        let mut outgoing = Zeroizing::new(ipc::Request::encode(request, token).to_vec());
        let mut sent = 0;
        let mut incoming = Zeroizing::new(Vec::new());
        let mut prompted = false;
        let mut result = None;
        let mut eof = false;
        let mut status = None;
        loop {
            if BootInstant::now() >= deadline {
                return Err(PasswordWorkerError::TimedOut);
            }
            if conversation.cancelled() {
                return Err(PasswordWorkerError::Cancelled);
            }
            if sent < outgoing.len() {
                match stream.write(&outgoing[sent..]) {
                    Ok(0) => return Err(PasswordWorkerError::Unavailable),
                    Ok(n) => {
                        sent += n;
                        if sent == outgoing.len() {
                            outgoing.zeroize();
                            outgoing.clear();
                            sent = 0;
                        }
                    }
                    Err(e)
                        if matches!(
                            e.kind(),
                            io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                        ) => {}
                    Err(_) => return Err(PasswordWorkerError::Unavailable),
                }
            }
            if !eof {
                let mut buffer = Zeroizing::new([0; ipc::HEADER + crate::MAX_PASSWORD_BYTES + 1]);
                match stream.read(buffer.as_mut()) {
                    Ok(0) => eof = true,
                    Ok(n) => {
                        if incoming.len() + n > ipc::HEADER + crate::MAX_PASSWORD_BYTES {
                            return Err(PasswordWorkerError::Unavailable);
                        }
                        incoming.extend_from_slice(&buffer[..n]);
                    }
                    Err(e)
                        if matches!(
                            e.kind(),
                            io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                        ) => {}
                    Err(_) => return Err(PasswordWorkerError::Unavailable),
                }
            }
            if let Some((frame, length)) =
                ipc::decode(&incoming).map_err(|_| PasswordWorkerError::Unavailable)?
            {
                if frame.token != token
                    || result.is_some()
                    || length != incoming.len()
                    || !outgoing.is_empty()
                {
                    return Err(PasswordWorkerError::Unavailable);
                }
                incoming.zeroize();
                incoming.clear();
                match frame.kind {
                    ipc::PROMPT
                        if !prompted
                            && frame.sequence == 1
                            && frame.payload.expose().is_empty() =>
                    {
                        prompted = true;
                        let answer = conversation.password(PasswordPrompt {
                            style: PromptStyle::EchoOff,
                            text: "Existing account password: ",
                            deadline,
                        })?;
                        if BootInstant::now() >= deadline {
                            return Err(PasswordWorkerError::TimedOut);
                        }
                        if conversation.cancelled() {
                            return Err(PasswordWorkerError::Cancelled);
                        }
                        if !crate::valid_password(answer.expose()) {
                            return Err(PasswordWorkerError::Rejected);
                        }
                        ipc::write_frame(&mut *outgoing, ipc::ANSWER, &token, 1, answer.expose())
                            .map_err(|_| PasswordWorkerError::Unavailable)?;
                    }
                    ipc::RESULT if frame.sequence == 2 && frame.payload.expose().len() == 1 => {
                        result = Some(match frame.payload.expose()[0] {
                            0 if prompted => Ok(()),
                            1 => Err(PasswordWorkerError::Rejected),
                            2 => Err(PasswordWorkerError::Unavailable),
                            _ => return Err(PasswordWorkerError::Unavailable),
                        });
                    }
                    _ => return Err(PasswordWorkerError::Unavailable),
                }
            }
            if status.is_none() {
                let mut slots = self
                    .shared
                    .slots
                    .lock()
                    .map_err(|_| PasswordWorkerError::Unavailable)?;
                let Some(Slot::Child(entry)) = &mut slots[index] else {
                    return Err(PasswordWorkerError::Unavailable);
                };
                status = entry.reap().map_err(|_| PasswordWorkerError::Unavailable)?;
                if status.is_some() {
                    slots[index] = None;
                    guard.reaped = true;
                }
            }
            if eof && let Some(status) = status {
                if !status.success() || !incoming.is_empty() || !outgoing.is_empty() {
                    return Err(PasswordWorkerError::Unavailable);
                }
                if BootInstant::now() >= deadline {
                    return Err(PasswordWorkerError::TimedOut);
                }
                if conversation.cancelled() {
                    return Err(PasswordWorkerError::Cancelled);
                }
                return result.unwrap_or(Err(PasswordWorkerError::Unavailable));
            }
            thread::sleep(POLL.min(deadline.saturating_duration_since(BootInstant::now())));
        }
    }
}

/// Core adapter retaining no reusable authorization after one worker invocation.
pub struct BoundPasswordWorker<'a, C: Clock> {
    supervisor: &'a PasswordSupervisor,
    conversation: &'a mut dyn Conversation,
    clock: &'a mut C,
}

impl<C: Clock> PasswordWorker for BoundPasswordWorker<'_, C> {
    fn verify_existing_password(
        &mut self,
        request: PasswordWorkerRequest,
    ) -> Result<TimePoint, PasswordWorkerError> {
        let before = self
            .clock
            .now()
            .map_err(|_| PasswordWorkerError::Unavailable)?;
        let start = request.started_at();
        if before.boot != start.boot || before.millis < start.millis {
            return Err(PasswordWorkerError::Unavailable);
        }
        if before.millis - start.millis >= PASSWORD_TIMEOUT.as_millis() as u64 {
            return Err(PasswordWorkerError::TimedOut);
        }
        let age = Duration::from_millis(before.millis - start.millis);
        self.supervisor
            .run(request, self.conversation, PASSWORD_TIMEOUT - age)?;
        let after = self
            .clock
            .now()
            .map_err(|_| PasswordWorkerError::Unavailable)?;
        if after.boot != before.boot || after.millis < before.millis {
            return Err(PasswordWorkerError::Unavailable);
        }
        if after.millis - start.millis >= PASSWORD_TIMEOUT.as_millis() as u64 {
            return Err(PasswordWorkerError::TimedOut);
        }
        if self.conversation.cancelled() {
            return Err(PasswordWorkerError::Cancelled);
        }
        Ok(after)
    }
}

struct Guard {
    shared: Arc<Shared>,
    index: usize,
    reaped: bool,
}
impl Drop for Guard {
    fn drop(&mut self) {
        if !self.reaped
            && let Ok(mut slots) = self.shared.slots.lock()
            && let Some(Slot::Child(entry)) = &mut slots[self.index]
        {
            entry.retired = true;
            entry.terminate();
        }
    }
}

fn validate_executable(path: &Path) -> io::Result<()> {
    if !path.is_absolute()
        || path
            .components()
            .any(|part| matches!(part, Component::CurDir | Component::ParentDir))
    {
        return Err(ipc::invalid());
    }
    for ancestor in path.ancestors() {
        let metadata = std::fs::symlink_metadata(ancestor)?;
        if metadata.file_type().is_symlink()
            || metadata.uid() != 0
            || metadata.mode() & 0o022 != 0
            || (ancestor == path && (!metadata.is_file() || metadata.mode() & 0o111 == 0))
            || (ancestor != path && !metadata.is_dir())
        {
            return Err(io::Error::other("untrusted password worker installation"));
        }
    }
    Ok(())
}

#[cfg(test)]
pub(crate) fn fixture(
    executable: PathBuf,
    arguments: Vec<String>,
    timeout: Duration,
) -> PasswordSupervisor {
    let mut supervisor = PasswordSupervisor::build(executable, timeout).unwrap();
    supervisor.arguments = arguments;
    supervisor
}

#[cfg(test)]
mod diagnostic_tests {
    use super::*;

    #[test]
    fn eligibility_diagnostics_share_a_one_minute_suspend_inclusive_budget() {
        let last = AtomicU64::new(0);
        assert!(diagnostic_allowed(&last, 100));
        for now in [100, 101, 159, 99] {
            assert!(!diagnostic_allowed(&last, now));
        }
        assert!(diagnostic_allowed(&last, 160));
        let last = Arc::new(AtomicU64::new(0));
        let barrier = Arc::new(std::sync::Barrier::new(8));
        let callers = (0..8)
            .map(|_| {
                let last = last.clone();
                let barrier = barrier.clone();
                thread::spawn(move || {
                    barrier.wait();
                    diagnostic_allowed(&last, 100)
                })
            })
            .collect::<Vec<_>>();
        assert_eq!(
            callers
                .into_iter()
                .map(|caller| caller.join().unwrap())
                .filter(|allowed| *allowed)
                .count(),
            1
        );
    }

    #[test]
    fn eligibility_diagnostic_formats_only_static_stage_and_error_kind() {
        let native = io::Error::other("synthetic-secret-path-and-token-20317");
        let line = eligibility_diagnostic(EligibilityStage::Launch, Some(native.kind()));
        assert_eq!(
            line,
            "localpin: eligibility supervisor unavailable stage=launch io-kind=Other"
        );
        assert!(!line.contains("synthetic"));
        assert!(!line.contains("20317"));
        assert_eq!(
            eligibility_diagnostic(EligibilityStage::WorkerUnavailable, None),
            "localpin: eligibility supervisor unavailable stage=worker-unavailable"
        );
    }

    #[test]
    fn missing_eligibility_worker_logs_launch_category_without_account_or_path() {
        const CHILD: &str = "LOCALPIN_ELIGIBILITY_DIAGNOSTIC_CHILD";
        const TEST: &str = "supervisor::diagnostic_tests::missing_eligibility_worker_logs_launch_category_without_account_or_path";
        if std::env::var_os(CHILD).is_some() {
            let supervisor = fixture(
                PathBuf::from("/nonexistent-localpin-eligibility-worker"),
                Vec::new(),
                Duration::from_secs(2),
            );
            assert_eq!(
                supervisor.run_eligibility(
                    20317,
                    BootInstant::now() + Duration::from_secs(1),
                    &mut || false,
                ),
                Err(localpin_core::eligibility::EligibilityError::Unavailable)
            );
            assert_eq!(supervisor.occupied(), 0);
            return;
        }
        let output = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", TEST, "--nocapture"])
            .env_clear()
            .env(CHILD, "1")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let diagnostic = String::from_utf8(output.stderr).unwrap();
        assert_eq!(
            diagnostic,
            "localpin: eligibility supervisor unavailable stage=launch io-kind=NotFound\n"
        );
        assert!(!diagnostic.contains("20317"));
        assert!(!diagnostic.contains("nonexistent"));
    }
}
