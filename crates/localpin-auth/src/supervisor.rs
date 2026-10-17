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
    sync::{Arc, Mutex},
    thread,
    time::Duration,
};
use zeroize::{Zeroize, Zeroizing};

const POLL: Duration = Duration::from_millis(2);

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
