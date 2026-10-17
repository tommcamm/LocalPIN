//! Bounded Linux filesystem Unix sockets and an authenticated protocol client.
//!
//! All data reads use `recvmsg` with no control capacity. Linux discards received
//! descriptors and sets `MSG_CTRUNC`; that flag poisons the connection before any
//! data is decoded. A single absolute monotonic deadline covers partial I/O and
//! interrupted syscalls. Socket credentials establish identity, not eligibility.

use std::fmt;
use std::fs::{File, Metadata};
use std::io::{ErrorKind, IoSliceMut};
use std::os::fd::AsFd;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Component, Path, PathBuf};
use std::time::Duration;

mod time;
pub use time::BootInstant;
use time::BootInstant as Instant;

use localpin_core::secret::Pin;
use rustix::event::{PollFd, PollFlags, poll};
use rustix::fs::{CWD, Mode, OFlags, ResolveFlags, openat2};
use rustix::io::{Errno, FdFlags, fcntl_getfd, fcntl_setfd};
use rustix::net::sockopt;
use rustix::net::{
    AddressFamily, RecvAncillaryBuffer, RecvFlags, ReturnFlags, SendFlags, SocketAddrUnix,
    SocketFlags, SocketType, connect, recvmsg, send, socket_with,
};
use rustix::time::{
    Itimerspec, TimerfdClockId, TimerfdFlags, TimerfdTimerFlags, timerfd_create, timerfd_settime,
};
use zeroize::Zeroizing;

use crate::{
    Backend, ErrorCode, Id, MAX_BODY_BYTES, MAX_FRAME_BYTES, ProtocolError, Request,
    RequestDecoder, RequestEnvelope, Response, ResponseDecoder, ResponseEnvelope, Status,
    VerificationOutcome, encode_request, encode_response,
};

/// Initial connection and authenticated greeting budget.
pub const CONNECT_TIMEOUT: Duration = Duration::from_millis(250);
/// Maximum unavailable-path response budget.
pub const UNAVAILABLE_TIMEOUT: Duration = Duration::from_secs(2);
/// Maximum genuine TPM operation budget.
pub const TPM_TIMEOUT: Duration = Duration::from_secs(5);

/// One absolute monotonic deadline, shared by every retry in an operation.
#[derive(Clone, Copy, Debug)]
pub struct Deadline(Instant);

impl Deadline {
    /// Start a budget now. An overflowing budget expires immediately.
    pub fn after(budget: Duration) -> Self {
        let now = Instant::now();
        Self(now.checked_add(budget).unwrap_or(now))
    }

    /// Use an existing monotonic deadline without renewing its budget.
    pub fn at(deadline: Instant) -> Self {
        Self(deadline)
    }

    /// Whether the deadline has passed.
    pub fn expired(self) -> bool {
        Instant::now() >= self.0
    }

    fn remaining(self) -> Result<Duration, TransportError> {
        self.0
            .checked_duration_since(Instant::now())
            .filter(|left| !left.is_zero())
            .ok_or(TransportError::Timeout)
    }

    fn capped(self, budget: Duration) -> Self {
        Self(self.0.min(Self::after(budget).0))
    }
}

/// Sanitized transport errors never include paths, frame bytes or secrets.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransportError {
    /// The operation's absolute deadline elapsed.
    Timeout,
    /// The peer closed, or the connection has already failed closed.
    Closed,
    /// A path is not exclusively controlled by root or changed during connect.
    UnsafePath,
    /// The privileged server's kernel identity could not be authenticated.
    UntrustedPeer,
    /// Activation metadata or the inherited listener is invalid.
    Activation,
    /// An operating-system error category, with input context removed.
    Io(ErrorKind),
    /// A bounded protocol rejection.
    Protocol(ProtocolError),
    /// A sanitized terminal rejection issued by the authenticated server.
    Rejected(ErrorCode),
}

impl fmt::Display for TransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Timeout => f.write_str("transport deadline elapsed"),
            Self::Closed => f.write_str("transport connection is closed"),
            Self::UnsafePath => f.write_str("socket path is not trusted"),
            Self::UntrustedPeer => f.write_str("socket peer is not trusted"),
            Self::Activation => f.write_str("invalid socket activation"),
            Self::Io(_) => f.write_str("socket I/O is unavailable"),
            Self::Protocol(error) => error.fmt(f),
            Self::Rejected(_) => f.write_str("server rejected the operation"),
        }
    }
}

impl std::error::Error for TransportError {}

impl From<std::io::Error> for TransportError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error.kind())
    }
}

impl From<Errno> for TransportError {
    fn from(error: Errno) -> Self {
        Self::Io(std::io::Error::from(error).kind())
    }
}

impl From<ProtocolError> for TransportError {
    fn from(error: ProtocolError) -> Self {
        Self::Protocol(error)
    }
}

/// Kernel credentials captured at Unix socket connection time.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PeerCredentials {
    /// Kernel user ID; never replace this with a client-supplied target.
    pub uid: u32,
    /// Kernel group ID.
    pub gid: u32,
    /// Kernel process ID in this PID namespace.
    pub pid: u32,
}

/// Obtain `SO_PEERCRED`; session/process liveness needs additional live checks.
///
/// For a socket-activated server the client's PID can be the process that
/// created/listened on the socket (systemd), rather than the accepting broker.
/// Clients therefore authenticate a root UID and root-controlled filesystem
/// path; they do not compare the peer PID with a broker PID file.
pub fn peer_credentials(stream: &UnixStream) -> Result<PeerCredentials, TransportError> {
    let peer = sockopt::socket_peercred(stream)?;
    let pid = u32::try_from(peer.pid.as_raw_pid()).map_err(|_| TransportError::UntrustedPeer)?;
    if pid == 0 {
        return Err(TransportError::UntrustedPeer);
    }
    Ok(PeerCredentials {
        uid: peer.uid.as_raw(),
        gid: peer.gid.as_raw(),
        pid,
    })
}

fn wait(stream: &impl AsFd, flags: PollFlags, deadline: Deadline) -> Result<(), TransportError> {
    deadline.remaining()?;
    // A relative poll timeout uses CLOCK_MONOTONIC and pauses during suspend.
    // The absolute CLOCK_BOOTTIME timer becomes ready on resume if the budget
    // elapsed while suspended, even when the socket itself remains silent.
    let timer = timerfd_create(
        TimerfdClockId::Boottime,
        TimerfdFlags::CLOEXEC | TimerfdFlags::NONBLOCK,
    )?;
    timerfd_settime(
        &timer,
        TimerfdTimerFlags::ABSTIME,
        &Itimerspec {
            it_interval: Default::default(),
            it_value: deadline.0.as_timespec().ok_or(TransportError::Timeout)?,
        },
    )?;
    loop {
        deadline.remaining()?;
        let mut fds = [
            PollFd::new(stream, flags),
            PollFd::new(&timer, PollFlags::IN),
        ];
        match poll(&mut fds, None) {
            Ok(_) if !fds[1].revents().is_empty() || deadline.expired() => {
                return Err(TransportError::Timeout);
            }
            Ok(_) if fds[0].revents().contains(PollFlags::NVAL) => {
                return Err(TransportError::Closed);
            }
            Ok(_) => {
                deadline.remaining()?;
                return Ok(());
            }
            Err(Errno::INTR) => continue,
            Err(error) => return Err(error.into()),
        }
    }
}

/// A nonblocking Unix stream whose framing, control messages and I/O are bounded.
///
/// Any I/O or decoding error shuts down the stream permanently. This prevents a
/// caller from interpreting a suffix of a failed frame as a fresh request.
pub struct SocketConnection {
    stream: UnixStream,
    closed: bool,
}

impl SocketConnection {
    /// Wrap an accepted/connected Unix stream and enforce close-on-exec.
    pub fn new(stream: UnixStream) -> Result<Self, TransportError> {
        if sockopt::socket_domain(&stream)? != AddressFamily::UNIX
            || sockopt::socket_type(&stream)? != SocketType::STREAM
        {
            return Err(TransportError::UntrustedPeer);
        }
        stream.set_nonblocking(true)?;
        fcntl_setfd(&stream, fcntl_getfd(&stream)? | FdFlags::CLOEXEC)?;
        Ok(Self {
            stream,
            closed: false,
        })
    }

    /// Borrow the stream for peer checks or non-consuming readiness checks.
    ///
    /// Never consume protocol data through this reference: doing so bypasses
    /// ancillary rejection and bounded framing.
    pub fn raw_stream(&self) -> &UnixStream {
        &self.stream
    }

    /// Shut down both directions and forbid further framing operations.
    pub fn close(&mut self) {
        self.closed = true;
        let _ = self.stream.shutdown(std::net::Shutdown::Both);
    }

    fn check(&self, deadline: Deadline) -> Result<(), TransportError> {
        if self.closed {
            return Err(TransportError::Closed);
        }
        deadline.remaining().map(|_| ())
    }

    fn read_exact(&self, mut bytes: &mut [u8], deadline: Deadline) -> Result<(), TransportError> {
        while !bytes.is_empty() {
            self.check(deadline)?;
            // With no control capacity Linux discards/closes SCM_RIGHTS and
            // reports CTRUNC. No client-supplied descriptor becomes owned here.
            let mut control = RecvAncillaryBuffer::default();
            match recvmsg(
                &self.stream,
                &mut [IoSliceMut::new(bytes)],
                &mut control,
                RecvFlags::DONTWAIT | RecvFlags::CMSG_CLOEXEC,
            ) {
                Ok(message) => {
                    if message
                        .flags
                        .intersects(ReturnFlags::CTRUNC | ReturnFlags::TRUNC)
                    {
                        return Err(ProtocolError::Ancillary.into());
                    }
                    if message.bytes == 0 {
                        return Err(ProtocolError::Truncated.into());
                    }
                    deadline.remaining()?;
                    bytes = &mut bytes[message.bytes..];
                }
                Err(Errno::INTR) => continue,
                Err(Errno::AGAIN) => wait(&self.stream, PollFlags::IN, deadline)?,
                Err(error) => return Err(error.into()),
            }
        }
        Ok(())
    }

    fn frame(
        &self,
        deadline: Deadline,
    ) -> Result<(Zeroizing<[u8; MAX_FRAME_BYTES]>, usize), TransportError> {
        let mut bytes = Zeroizing::new([0; MAX_FRAME_BYTES]);
        self.read_exact(&mut bytes[..4], deadline)?;
        let len = u32::from_be_bytes(bytes[..4].try_into().expect("fixed length")) as usize;
        if len > MAX_BODY_BYTES {
            return Err(ProtocolError::Oversized.into());
        }
        self.read_exact(&mut bytes[4..4 + len], deadline)?;
        Ok((bytes, len + 4))
    }

    /// Receive exactly one request without consuming bytes of the next frame.
    pub fn read_request(&mut self, deadline: Deadline) -> Result<RequestEnvelope, TransportError> {
        let result = (|| {
            let (bytes, len) = self.frame(deadline)?;
            RequestDecoder::default()
                .push(&bytes[..len])?
                .1
                .ok_or(ProtocolError::Truncated.into())
        })();
        if result.is_err() {
            self.close();
        }
        result
    }

    /// Receive exactly one server response with the same control-message checks.
    pub fn read_response(
        &mut self,
        deadline: Deadline,
    ) -> Result<ResponseEnvelope, TransportError> {
        let result = (|| {
            let (bytes, len) = self.frame(deadline)?;
            ResponseDecoder::default()
                .push(&bytes[..len])?
                .1
                .ok_or(ProtocolError::Truncated.into())
        })();
        if result.is_err() {
            self.close();
        }
        result
    }

    fn write(&mut self, mut bytes: &[u8], deadline: Deadline) -> Result<(), TransportError> {
        let result = (|| {
            while !bytes.is_empty() {
                self.check(deadline)?;
                match send(
                    &self.stream,
                    bytes,
                    SendFlags::DONTWAIT | SendFlags::NOSIGNAL,
                ) {
                    Ok(0) => return Err(TransportError::Closed),
                    Ok(n) => {
                        deadline.remaining()?;
                        bytes = &bytes[n..];
                    }
                    Err(Errno::INTR) => continue,
                    Err(Errno::AGAIN) => wait(&self.stream, PollFlags::OUT, deadline)?,
                    Err(error) => return Err(error.into()),
                }
            }
            Ok(())
        })();
        if result.is_err() {
            self.close();
        }
        result
    }

    /// Encode and send a bounded request before its absolute deadline.
    pub fn write_request(
        &mut self,
        request: &RequestEnvelope,
        deadline: Deadline,
    ) -> Result<(), TransportError> {
        self.write(encode_request(request)?.as_bytes(), deadline)
    }

    /// Encode and send a bounded response before its absolute deadline.
    pub fn write_response(
        &mut self,
        response: &ResponseEnvelope,
        deadline: Deadline,
    ) -> Result<(), TransportError> {
        self.write(encode_response(response)?.as_bytes(), deadline)
    }
}

const RESOLVE: ResolveFlags = ResolveFlags::BENEATH
    .union(ResolveFlags::NO_SYMLINKS)
    .union(ResolveFlags::NO_MAGICLINKS);
const PATH_FLAGS: OFlags = OFlags::PATH.union(OFlags::NOFOLLOW).union(OFlags::CLOEXEC);

struct TrustedSocketPath {
    parent: File,
    name: PathBuf,
    original: Metadata,
    owner: u32,
}

fn trusted_directory(file: &File, owner: u32) -> Result<(), TransportError> {
    let metadata = file.metadata()?;
    if !metadata.is_dir() || metadata.uid() != owner || metadata.mode() & 0o7022 != 0 {
        return Err(TransportError::UnsafePath);
    }
    Ok(())
}

fn trusted_parent(path: &Path) -> Result<(File, PathBuf), TransportError> {
    if !path.is_absolute() {
        return Err(TransportError::UnsafePath);
    }
    let root = File::from(openat2(
        CWD,
        "/",
        PATH_FLAGS | OFlags::DIRECTORY,
        Mode::empty(),
        ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    )?);
    trusted_parent_at(
        root,
        path.strip_prefix("/")
            .map_err(|_| TransportError::UnsafePath)?,
        0,
    )
}

fn trusted_parent_at(
    mut parent: File,
    relative: &Path,
    owner: u32,
) -> Result<(File, PathBuf), TransportError> {
    trusted_directory(&parent, owner)?;
    let mut parts = relative.components().peekable();
    while let Some(component) = parts.next() {
        let Component::Normal(name) = component else {
            return Err(TransportError::UnsafePath);
        };
        if parts.peek().is_none() {
            return Ok((parent, name.into()));
        }
        parent = File::from(
            openat2(
                &parent,
                name,
                PATH_FLAGS | OFlags::DIRECTORY,
                Mode::empty(),
                RESOLVE,
            )
            .map_err(|_| TransportError::UnsafePath)?,
        );
        trusted_directory(&parent, owner)?;
    }
    Err(TransportError::UnsafePath)
}

fn inspect_socket(parent: &File, name: &Path, owner: u32) -> Result<Metadata, TransportError> {
    trusted_directory(parent, owner)?;
    let socket = File::from(
        openat2(parent, name, PATH_FLAGS, Mode::empty(), RESOLVE)
            .map_err(|_| TransportError::UnsafePath)?,
    );
    let metadata = socket.metadata()?;
    if !metadata.file_type().is_socket()
        || metadata.uid() != owner
        || metadata.nlink() != 1
        || metadata.mode() & 0o7000 != 0
    {
        return Err(TransportError::UnsafePath);
    }
    Ok(metadata)
}

impl TrustedSocketPath {
    fn new(path: &Path) -> Result<Self, TransportError> {
        let (parent, name) = trusted_parent(path)?;
        let original = inspect_socket(&parent, &name, 0)?;
        Ok(Self {
            parent,
            name,
            original,
            owner: 0,
        })
    }

    fn recheck(&self) -> Result<(), TransportError> {
        let now = inspect_socket(&self.parent, &self.name, self.owner)?;
        if now.dev() != self.original.dev() || now.ino() != self.original.ino() {
            return Err(TransportError::UnsafePath);
        }
        Ok(())
    }
}

/// Bind a fresh root-owned filesystem socket without removing an existing node.
///
/// All ancestors must be root-owned, free of symlinks and group/world write
/// permission. Normal accounts may connect to the mode-0666 socket; their kernel
/// credentials and live eligibility still gate every operation.
pub fn bind_listener(path: &Path) -> Result<UnixListener, TransportError> {
    let (_parent, _name) = trusted_parent(path)?;
    let listener = UnixListener::bind(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o666))?;
    validate_listener(&listener, path)?;
    Ok(listener)
}

/// Verify a listening filesystem Unix stream socket and mark it nonblocking.
pub fn validate_listener(
    listener: &UnixListener,
    expected_path: &Path,
) -> Result<(), TransportError> {
    let trusted = TrustedSocketPath::new(expected_path)?;
    if sockopt::socket_domain(listener)? != AddressFamily::UNIX
        || sockopt::socket_type(listener)? != SocketType::STREAM
        || !sockopt::socket_acceptconn(listener)?
        || listener.local_addr()?.as_pathname() != Some(expected_path)
    {
        return Err(TransportError::Activation);
    }
    fcntl_setfd(listener, fcntl_getfd(listener)? | FdFlags::CLOEXEC)?;
    listener.set_nonblocking(true)?;
    trusted.recheck()
}

/// Acquire exactly one systemd listener at startup, before spawning threads.
///
/// Requires the real systemd `LISTEN_PID`/`LISTEN_FDS=1` contract, refuses the
/// development-only descriptor-offset extension and validates the inherited
/// socket independently. Optional `LISTEN_FDNAMES` must name `localpin`.
/// `listenfd` clears activation environment variables internally.
pub fn take_activation_listener(
    expected_path: &Path,
) -> Result<Option<UnixListener>, TransportError> {
    let pid = std::env::var_os("LISTEN_PID");
    let count = std::env::var_os("LISTEN_FDS");
    let name = std::env::var_os("LISTEN_FDNAMES");
    let offset = std::env::var_os("LISTEN_FDS_FIRST_FD");
    if !activation_environment(
        pid.as_deref(),
        count.as_deref(),
        name.as_deref(),
        offset.as_deref(),
        std::process::id(),
    )? {
        return Ok(None);
    }
    let mut inherited = listenfd::ListenFd::from_env();
    if inherited.len() != 1 {
        return Err(TransportError::Activation);
    }
    let listener = inherited
        .take_unix_listener(0)
        .map_err(|_| TransportError::Activation)?
        .ok_or(TransportError::Activation)?;
    validate_listener(&listener, expected_path)?;
    Ok(Some(listener))
}

fn activation_environment(
    pid: Option<&std::ffi::OsStr>,
    count: Option<&std::ffi::OsStr>,
    name: Option<&std::ffi::OsStr>,
    offset: Option<&std::ffi::OsStr>,
    expected_pid: u32,
) -> Result<bool, TransportError> {
    if pid.is_none() && count.is_none() && name.is_none() && offset.is_none() {
        return Ok(false);
    }
    if pid != Some(std::ffi::OsStr::new(&expected_pid.to_string()))
        || count != Some(std::ffi::OsStr::new("1"))
        || offset.is_some()
        || name.is_some_and(|name| name != "localpin")
    {
        return Err(TransportError::Activation);
    }
    Ok(true)
}

/// A client bound to one authenticated root server and its fresh connection ID.
pub struct Client {
    connection: SocketConnection,
    id: Id,
    peer: PeerCredentials,
}

impl Client {
    /// Connect, authenticate root socket/peer identity and read the greeting.
    /// Reuse a `CONNECT_TIMEOUT` deadline for the complete setup exchange.
    pub fn connect(path: &Path, deadline: Deadline) -> Result<Self, TransportError> {
        let deadline = deadline.capped(CONNECT_TIMEOUT);
        deadline.remaining()?;
        let trusted = TrustedSocketPath::new(path)?;
        Self::connect_authenticated(path, deadline, trusted, 0, 0)
    }

    fn connect_authenticated(
        path: &Path,
        deadline: Deadline,
        trusted: TrustedSocketPath,
        required_uid: u32,
        required_gid: u32,
    ) -> Result<Self, TransportError> {
        let deadline = deadline.capped(CONNECT_TIMEOUT);
        deadline.remaining()?;
        let fd = socket_with(
            AddressFamily::UNIX,
            SocketType::STREAM,
            SocketFlags::NONBLOCK | SocketFlags::CLOEXEC,
            None,
        )?;
        let address = SocketAddrUnix::new(path).map_err(|_| TransportError::UnsafePath)?;
        match connect(&fd, &address) {
            Ok(()) => {}
            Err(Errno::INPROGRESS | Errno::AGAIN) => {
                wait(&fd, PollFlags::OUT, deadline)?;
                sockopt::socket_error(&fd)??;
            }
            Err(error) => return Err(error.into()),
        }
        let stream = UnixStream::from(fd);
        let peer = peer_credentials(&stream)?;
        if peer.uid != required_uid || peer.gid != required_gid {
            return Err(TransportError::UntrustedPeer);
        }
        trusted.recheck()?;
        let mut connection = SocketConnection::new(stream)?;
        let greeting = connection.read_response(deadline)?;
        if !matches!(greeting.response, Response::Hello) {
            return Err(ProtocolError::OutOfOrder.into());
        }
        Ok(Self {
            connection,
            id: greeting.connection,
            peer,
        })
    }

    /// The kernel server identity, including the activation socket creator PID.
    pub fn peer(&self) -> PeerCredentials {
        self.peer
    }

    /// The fresh server-issued connection binding.
    pub fn id(&self) -> Id {
        self.id
    }

    /// Send one request and read one bound response under a shared deadline.
    pub fn request(
        &mut self,
        request: Request,
        deadline: Deadline,
    ) -> Result<ResponseEnvelope, TransportError> {
        self.connection.write_request(
            &RequestEnvelope {
                connection: self.id,
                request,
            },
            deadline,
        )?;
        self.receive(deadline)
    }

    /// Receive the next private enrollment prompt without sending another request.
    /// Binding and duplicate greetings are checked before any prompt is exposed.
    pub fn receive(&mut self, deadline: Deadline) -> Result<ResponseEnvelope, TransportError> {
        let response = self.connection.read_response(deadline)?;
        if response.connection != self.id || matches!(response.response, Response::Hello) {
            self.connection.close();
            return Err(ProtocolError::Binding.into());
        }
        Ok(response)
    }

    /// Read own-account nonsecret status within two seconds.
    /// An unexpected response or terminal server error closes the connection.
    pub fn status(&mut self) -> Result<Status, TransportError> {
        let response = self.request(Request::Status, Deadline::after(UNAVAILABLE_TIMEOUT))?;
        match response.response {
            Response::Status(status) => Ok(status),
            Response::Error(error) => {
                self.close();
                Err(TransportError::Rejected(error))
            }
            _ => {
                self.close();
                Err(ProtocolError::OutOfOrder.into())
            }
        }
    }

    /// Perform one verification exchange and permanently close its connection.
    ///
    /// The caller selects the credential backend obtained from trusted status.
    /// Challenge acquisition is bounded to two seconds; the actual attempt is
    /// bounded to two seconds for software and five seconds for TPM. Only an
    /// exact challenge followed by a terminal verification outcome is accepted;
    /// no response can serve as reusable authorization for another operation.
    pub fn verify(
        &mut self,
        pin: Pin,
        backend: Backend,
    ) -> Result<VerificationOutcome, TransportError> {
        let result = (|| {
            let response =
                self.request(Request::BeginVerify, Deadline::after(UNAVAILABLE_TIMEOUT))?;
            let challenge = match response.response {
                Response::VerifyChallenge { challenge, .. } if challenge != self.id => challenge,
                Response::Error(error) => return Err(TransportError::Rejected(error)),
                _ => return Err(ProtocolError::OutOfOrder.into()),
            };
            let budget = match backend {
                Backend::Software => UNAVAILABLE_TIMEOUT,
                Backend::Tpm => TPM_TIMEOUT,
            };
            let response =
                self.request(Request::Verify { challenge, pin }, Deadline::after(budget))?;
            match response.response {
                Response::Verification(outcome) => Ok(outcome),
                Response::Error(error) => Err(TransportError::Rejected(error)),
                _ => Err(ProtocolError::OutOfOrder.into()),
            }
        })();
        self.close();
        result
    }

    /// Close this connection and discard any pending exchange.
    pub fn close(&mut self) {
        self.connection.close();
    }
}

#[cfg(test)]
mod tests;
