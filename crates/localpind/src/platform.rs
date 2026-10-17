//! Live Linux peer identity and fail-closed logind session routing.
//!
//! Routing does not establish account restrictions or an account incarnation.
//! A separate reviewed authority must provide those before PIN activation.
//! Linux 6.5 `SO_PEERPIDFD` is required: numeric PID acquisition is never used
//! as a fallback for a missing socket-bound process reference.

use std::fs::File;
use std::io::{self, Read};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::time::Duration;

use dbus::Path;
use dbus::arg::{PropMap, RefArg};
use dbus::blocking::Connection;
use dbus::blocking::stdintf::org_freedesktop_dbus::Properties;
use dbus::channel::Channel;
use localpin_core::eligibility::{EligibilityError, SessionReference};
use localpin_protocol::transport::BootInstant as Instant;
use rustix::event::{PollFd, PollFlags, Timespec, poll};
use sha2::{Digest, Sha256};

const MAX_PROC_BYTES: u64 = 16 * 1024;
const MAX_SESSIONS: usize = 64;
const MAX_PROPERTIES: usize = 64;
const LOGIN_MANAGER: &str = "/org/freedesktop/login1";
const LOGIN_INTERFACE: &str = "org.freedesktop.login1.Manager";
const SESSION_INTERFACE: &str = "org.freedesktop.login1.Session";
const USER_INTERFACE: &str = "org.freedesktop.login1.User";
const SYSTEM_BUS_ADDRESS: &str = "unix:path=/run/dbus/system_bus_socket";
const MAX_RESOLUTION_TIME: Duration = Duration::from_secs(2);

/// Credentials and a retained process reference acquired from a Unix socket.
#[derive(Debug)]
pub struct Peer {
    uid: u32,
    gid: u32,
    pid: u32,
    pidfd: OwnedFd,
    start_time: u64,
}

impl Peer {
    /// Capture kernel credentials and a socket-bound pidfd, or fail closed.
    ///
    /// An already-exited or replaced peer, unsupported kernel, unreadable procfs,
    /// or mismatching real/effective/saved/filesystem credentials is rejected.
    pub fn from_socket(socket: &UnixStream) -> io::Result<Self> {
        let credentials = rustix::net::sockopt::socket_peercred(socket)?;
        let pidfd = socket_peer_pidfd(socket)?;
        let pid = credentials.pid.as_raw_nonzero().get() as u32;
        let mut peer = Self {
            uid: credentials.uid.as_raw(),
            gid: credentials.gid.as_raw(),
            pid,
            pidfd,
            start_time: 0,
        };
        peer.check_pidfd()?;
        let start_time = peer.process_identity()?;
        peer.start_time = start_time;
        peer.ensure_live()?;
        Ok(peer)
    }

    /// Initial kernel Unix peer UID; never taken from request fields.
    pub fn uid(&self) -> u32 {
        self.uid
    }

    /// Initial kernel Unix peer GID.
    pub fn gid(&self) -> u32 {
        self.gid
    }

    /// Process identifier, usable only while this retained reference is live.
    pub fn pid(&self) -> u32 {
        self.pid
    }

    /// Recheck exit, PID binding, process start time and current credentials.
    pub fn ensure_live(&self) -> io::Result<()> {
        self.check_pidfd()?;
        if self.process_identity()? != self.start_time {
            return Err(identity_error());
        }
        self.check_pidfd()
    }

    fn check_pidfd(&self) -> io::Result<()> {
        let mut fds = [PollFd::new(&self.pidfd, PollFlags::IN)];
        if poll(
            &mut fds,
            Some(&Timespec {
                tv_sec: 0,
                tv_nsec: 0,
            }),
        )? != 0
        {
            return Err(identity_error());
        }
        // A real pidfd exposes its current PID here. After exit/reaping it may
        // become -1; an arbitrary file descriptor cannot pass this check.
        let fdinfo = bounded_read(&format!("/proc/self/fdinfo/{}", self.pidfd.as_raw_fd()))?;
        if pidfd_pid(&fdinfo)? != self.pid {
            return Err(identity_error());
        }
        Ok(())
    }

    fn process_identity(&self) -> io::Result<u64> {
        let status = bounded_read(&format!("/proc/{}/status", self.pid))?;
        if !credentials_match(&status, self.uid, self.gid) {
            return Err(identity_error());
        }
        let stat = bounded_read(&format!("/proc/{}/stat", self.pid))?;
        process_start_time(&stat, self.pid)
    }
}

/// The sole local unsafe boundary: acquire the socket's actual peer pidfd.
///
/// The kernel retains the socket peer's `struct pid`, so this cannot silently
/// switch to a recycled numeric PID. Kernels without this option fail closed.
#[allow(unsafe_code)]
fn socket_peer_pidfd(socket: &UnixStream) -> io::Result<OwnedFd> {
    let mut descriptor: libc::c_int = -1;
    let mut length = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    // SAFETY: socket remains borrowed and valid throughout the call. Both
    // output pointers refer to writable, correctly sized stack allocations.
    // SO_PEERPIDFD returns a fresh owned descriptor on success, with CLOEXEC.
    let result = unsafe {
        libc::getsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERPIDFD,
            (&mut descriptor as *mut libc::c_int).cast(),
            &mut length,
        )
    };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    if descriptor < 0 {
        return Err(identity_error());
    }
    // SAFETY: a successful SO_PEERPIDFD call installed this fresh descriptor;
    // taking ownership immediately also closes it on every validation failure.
    let descriptor = unsafe { OwnedFd::from_raw_fd(descriptor) };
    if length as usize != std::mem::size_of::<libc::c_int>() {
        return Err(identity_error());
    }
    Ok(descriptor)
}

fn bounded_read(path: &str) -> io::Result<String> {
    let mut bytes = Vec::new();
    File::open(path)?
        .take(MAX_PROC_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_PROC_BYTES {
        return Err(identity_error());
    }
    String::from_utf8(bytes).map_err(|_| identity_error())
}

fn identity_error() -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, "peer identity unavailable")
}

fn pidfd_pid(fdinfo: &str) -> io::Result<u32> {
    let mut entries = fdinfo
        .lines()
        .filter_map(|line| line.strip_prefix("Pid:\t"));
    let pid = entries.next().ok_or_else(identity_error)?;
    if entries.next().is_some() {
        return Err(identity_error());
    }
    pid.parse().map_err(|_| identity_error())
}

fn credentials_match(status: &str, uid: u32, gid: u32) -> bool {
    fn field_matches(status: &str, prefix: &str, expected: u32) -> bool {
        let mut fields = status.lines().filter_map(|line| line.strip_prefix(prefix));
        let Some(values) = fields.next() else {
            return false;
        };
        let values: Vec<_> = values.split_ascii_whitespace().collect();
        fields.next().is_none()
            && values.len() == 4
            && values
                .iter()
                .all(|value| value.parse::<u32>() == Ok(expected))
    }
    field_matches(status, "Uid:", uid) && field_matches(status, "Gid:", gid)
}

fn process_start_time(stat: &str, pid: u32) -> io::Result<u64> {
    let prefix = format!("{pid} (");
    if !stat.starts_with(&prefix) {
        return Err(identity_error());
    }
    // comm may contain whitespace and ')' characters. The final ')' ends it;
    // field 22 is the twentieth field after comm (field 2).
    let (_, tail) = stat.rsplit_once(')').ok_or_else(identity_error)?;
    let mut fields = tail.split_ascii_whitespace();
    if matches!(fields.next(), None | Some("Z" | "X" | "x")) {
        return Err(identity_error());
    }
    fields
        .nth(18)
        .ok_or_else(identity_error)?
        .parse()
        .map_err(|_| identity_error())
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct SessionIdentity {
    bus_id: String,
    owner: String,
    path: String,
    id: String,
    uid: u32,
    created: u64,
}

impl SessionIdentity {
    fn reference(&self) -> Result<SessionReference, EligibilityError> {
        let mut hash = Sha256::new();
        hash.update(b"LocalPIN live logind session reference v1\0");
        for field in [&self.bus_id, &self.owner, &self.path, &self.id] {
            hash.update((field.len() as u64).to_be_bytes());
            hash.update(field.as_bytes());
        }
        hash.update(self.uid.to_be_bytes());
        hash.update(self.created.to_be_bytes());
        let digest = hash.finalize();
        let mut reference = [0; 16];
        reference.copy_from_slice(&digest[..16]);
        SessionReference::new(reference)
    }
}

/// One eligible live logind session, pinned to the current service incarnation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedSession {
    identity: SessionIdentity,
    reference: SessionReference,
}

impl ResolvedSession {
    /// Opaque stable reference for this exact live logind/session incarnation.
    ///
    /// Separate resolver instances produce the same reference for unchanged
    /// authoritative identity. This is a public identity digest, not a bearer
    /// authorization or a substitute for fresh property/liveness checks.
    pub fn reference(&self) -> SessionReference {
        self.reference
    }
}

/// Repeated native D-Bus queries to the live logind service.
///
/// Every method call uses the remainder of the supplied absolute deadline.
/// libdbus connection/authentication itself has no cancellation API; callers
/// must keep that work charged to their bounded worker/connection slot and
/// refuse late results. No method result is used after the deadline.
#[derive(Debug, Default)]
pub struct SessionResolver;

impl SessionResolver {
    /// Construct a resolver without contacting a service.
    pub fn new() -> Self {
        Self
    }

    /// Resolve the own-UID direct session or unique user-manager candidate.
    pub fn resolve(
        &mut self,
        peer: &Peer,
        deadline: Instant,
    ) -> Result<ResolvedSession, EligibilityError> {
        let identity = self.resolve_identity(peer, deadline)?;
        let reference = identity.reference()?;
        remaining(deadline)?;
        Ok(ResolvedSession {
            identity,
            reference,
        })
    }

    /// Repeat routing and all properties and reject replacement/disappearance.
    pub fn revalidate(
        &mut self,
        peer: &Peer,
        session: &ResolvedSession,
        deadline: Instant,
    ) -> Result<SessionReference, EligibilityError> {
        if self.resolve_identity(peer, deadline)? != session.identity {
            return Err(EligibilityError::IneligibleSession);
        }
        Ok(session.reference)
    }

    fn resolve_identity(
        &mut self,
        peer: &Peer,
        deadline: Instant,
    ) -> Result<SessionIdentity, EligibilityError> {
        let deadline = deadline.min(Instant::now() + MAX_RESOLUTION_TIME);
        if peer.uid == 0 || peer.uid == u32::MAX {
            return Err(EligibilityError::WrongAccount);
        }
        remaining(deadline)?;
        peer.ensure_live()
            .map_err(|_| EligibilityError::Unavailable)?;
        // Pin the supported host bus path. An inherited DBUS_SYSTEM_BUS_ADDRESS
        // must never redirect an authority lookup to a caller-controlled bus.
        let mut channel =
            Channel::open_private(SYSTEM_BUS_ADDRESS).map_err(|_| EligibilityError::Unavailable)?;
        channel
            .register()
            .map_err(|_| EligibilityError::Unavailable)?;
        let bus = Connection::from(channel);
        let owner: (String,) = bus
            .with_proxy(
                "org.freedesktop.DBus",
                "/org/freedesktop/DBus",
                remaining(deadline)?,
            )
            .method_call(
                "org.freedesktop.DBus",
                "GetNameOwner",
                ("org.freedesktop.login1",),
            )
            .map_err(|_| EligibilityError::Unavailable)?;
        if !owner.0.starts_with(':') || owner.0.len() > 255 {
            return Err(EligibilityError::UnknownProperties);
        }
        let (bus_id,): (String,) = bus
            .with_proxy(
                "org.freedesktop.DBus",
                "/org/freedesktop/DBus",
                remaining(deadline)?,
            )
            .method_call("org.freedesktop.DBus", "GetId", ())
            .map_err(|_| EligibilityError::Unavailable)?;
        if bus_id.len() != 32 || !bus_id.bytes().all(|value| value.is_ascii_hexdigit()) {
            return Err(EligibilityError::UnknownProperties);
        }
        let mut logind = BusLogind {
            bus,
            bus_id,
            owner: owner.0,
            deadline,
        };
        let identity = route(&mut logind, peer.pid, peer.uid)?;
        let (current_owner,): (String,) = logind
            .bus
            .with_proxy(
                "org.freedesktop.DBus",
                "/org/freedesktop/DBus",
                remaining(deadline)?,
            )
            .method_call(
                "org.freedesktop.DBus",
                "GetNameOwner",
                ("org.freedesktop.login1",),
            )
            .map_err(|_| EligibilityError::Unavailable)?;
        if current_owner != logind.owner {
            return Err(EligibilityError::Unavailable);
        }
        peer.ensure_live()
            .map_err(|_| EligibilityError::Unavailable)?;
        remaining(deadline)?;
        Ok(identity)
    }
}

fn remaining(deadline: Instant) -> Result<Duration, EligibilityError> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|value| !value.is_zero())
        .ok_or(EligibilityError::Unavailable)
}

#[derive(Clone, Debug)]
struct Session {
    identity: SessionIdentity,
    remote: bool,
    state: String,
    seat: String,
    class: String,
    desktop: String,
    kind: String,
}

impl Session {
    fn eligible(&self, uid: u32) -> Result<bool, EligibilityError> {
        if self.identity.uid != uid {
            return Err(EligibilityError::WrongAccount);
        }
        if !matches!(
            self.state.as_str(),
            "active" | "online" | "opening" | "closing"
        ) {
            return Err(EligibilityError::UnknownProperties);
        }
        Ok(!self.remote
            && matches!(self.state.as_str(), "active" | "online")
            && !self.seat.is_empty()
            && self.class == "user"
            // The supported Fedora 44 KDE observations report exactly KDE.
            // Broader desktop aliases require separate evidence and review.
            && self.desktop == "KDE"
            && matches!(self.kind.as_str(), "wayland" | "x11"))
    }
}

trait Logind {
    fn direct(&mut self, pid: u32) -> Result<Option<Session>, EligibilityError>;
    fn manager_uid(&mut self, pid: u32) -> Result<u32, EligibilityError>;
    fn sessions(&mut self, uid: u32) -> Result<Vec<Session>, EligibilityError>;
}

fn route(
    logind: &mut impl Logind,
    pid: u32,
    uid: u32,
) -> Result<SessionIdentity, EligibilityError> {
    if let Some(session) = logind.direct(pid)? {
        return if session.eligible(uid)? {
            Ok(session.identity)
        } else {
            Err(EligibilityError::IneligibleSession)
        };
    }
    if logind.manager_uid(pid)? != uid {
        return Err(EligibilityError::WrongAccount);
    }
    let sessions = logind.sessions(uid)?;
    if sessions.len() > MAX_SESSIONS {
        return Err(EligibilityError::Unavailable);
    }
    let mut selected = None;
    for session in sessions {
        if session.identity.uid != uid {
            return Err(EligibilityError::WrongAccount);
        }
        if session.eligible(uid)? && selected.replace(session.identity).is_some() {
            return Err(EligibilityError::AmbiguousSession);
        }
    }
    selected.ok_or(EligibilityError::NoSession)
}

struct BusLogind {
    bus: Connection,
    bus_id: String,
    owner: String,
    deadline: Instant,
}

impl BusLogind {
    fn session(&self, path: Path<'static>) -> Result<Session, EligibilityError> {
        let properties = self
            .bus
            .with_proxy(&self.owner, path.clone(), remaining(self.deadline)?)
            .get_all(SESSION_INTERFACE)
            .map_err(|_| EligibilityError::Unavailable)?;
        session_properties(&self.bus_id, &self.owner, &path, &properties)
    }
}

impl Logind for BusLogind {
    fn direct(&mut self, pid: u32) -> Result<Option<Session>, EligibilityError> {
        let result: Result<(Path<'static>,), dbus::Error> = self
            .bus
            .with_proxy(&self.owner, LOGIN_MANAGER, remaining(self.deadline)?)
            .method_call(LOGIN_INTERFACE, "GetSessionByPID", (pid,));
        match result {
            Ok((path,)) => self.session(path).map(Some),
            Err(error) if error.name() == Some("org.freedesktop.login1.NoSessionForPID") => {
                Ok(None)
            }
            Err(_) => Err(EligibilityError::Unavailable),
        }
    }

    fn manager_uid(&mut self, pid: u32) -> Result<u32, EligibilityError> {
        let (path,): (Path<'static>,) = self
            .bus
            .with_proxy(&self.owner, LOGIN_MANAGER, remaining(self.deadline)?)
            .method_call(LOGIN_INTERFACE, "GetUserByPID", (pid,))
            .map_err(|_| EligibilityError::Unavailable)?;
        self.bus
            .with_proxy(&self.owner, path, remaining(self.deadline)?)
            .get(USER_INTERFACE, "UID")
            .map_err(|_| EligibilityError::Unavailable)
    }

    fn sessions(&mut self, uid: u32) -> Result<Vec<Session>, EligibilityError> {
        type ListedSession = (String, u32, String, String, Path<'static>);
        let (listed,): (Vec<ListedSession>,) = self
            .bus
            .with_proxy(&self.owner, LOGIN_MANAGER, remaining(self.deadline)?)
            .method_call(LOGIN_INTERFACE, "ListSessions", ())
            .map_err(|_| EligibilityError::Unavailable)?;
        if listed.len() > MAX_SESSIONS {
            return Err(EligibilityError::Unavailable);
        }
        let mut sessions = Vec::new();
        for (id, owner_uid, _, _, path) in listed {
            if owner_uid != uid {
                continue;
            }
            let session = self.session(path)?;
            if session.identity.id != id || session.identity.uid != owner_uid {
                return Err(EligibilityError::UnknownProperties);
            }
            sessions.push(session);
        }
        Ok(sessions)
    }
}

fn session_properties(
    bus_id: &str,
    owner: &str,
    path: &str,
    properties: &PropMap,
) -> Result<Session, EligibilityError> {
    if properties.len() > MAX_PROPERTIES {
        return Err(EligibilityError::UnknownProperties);
    }
    fn value<'a>(properties: &'a PropMap, name: &str) -> Result<&'a dyn RefArg, EligibilityError> {
        properties
            .get(name)
            .map(|value| value.0.as_ref())
            .ok_or(EligibilityError::UnknownProperties)
    }
    fn string(properties: &PropMap, name: &str) -> Result<String, EligibilityError> {
        let text = value(properties, name)?
            .as_str()
            .ok_or(EligibilityError::UnknownProperties)?;
        if text.len() > 255 || text.contains('\0') {
            return Err(EligibilityError::UnknownProperties);
        }
        Ok(text.to_owned())
    }
    fn first(
        properties: &PropMap,
        name: &str,
    ) -> Result<Box<dyn RefArg + 'static>, EligibilityError> {
        let mut fields = value(properties, name)?
            .as_iter()
            .ok_or(EligibilityError::UnknownProperties)?;
        let first = fields
            .next()
            .ok_or(EligibilityError::UnknownProperties)?
            .box_clone();
        if fields.next().is_none() || fields.next().is_some() {
            return Err(EligibilityError::UnknownProperties);
        }
        Ok(first)
    }
    let id = string(properties, "Id")?;
    let uid = u32::try_from(
        first(properties, "User")?
            .as_u64()
            .ok_or(EligibilityError::UnknownProperties)?,
    )
    .map_err(|_| EligibilityError::UnknownProperties)?;
    let created = value(properties, "TimestampMonotonic")?
        .as_u64()
        .ok_or(EligibilityError::UnknownProperties)?;
    let remote = match value(properties, "Remote")?.as_u64() {
        Some(0) => false,
        Some(1) => true,
        _ => return Err(EligibilityError::UnknownProperties),
    };
    let seat = first(properties, "Seat")?
        .as_str()
        .ok_or(EligibilityError::UnknownProperties)?
        .to_owned();
    if id.is_empty() || created == 0 || seat.len() > 255 || path.len() > 512 {
        return Err(EligibilityError::UnknownProperties);
    }
    Ok(Session {
        identity: SessionIdentity {
            bus_id: bus_id.to_owned(),
            owner: owner.to_owned(),
            path: path.to_owned(),
            id,
            uid,
            created,
        },
        remote,
        state: string(properties, "State")?,
        seat,
        class: string(properties, "Class")?,
        desktop: string(properties, "Desktop")?,
        kind: string(properties, "Type")?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use dbus::arg::Variant;
    use std::io::Write;
    use std::os::unix::net::UnixListener;
    use std::process::{Command, Stdio};

    fn session(id: &str) -> Session {
        Session {
            identity: SessionIdentity {
                bus_id: "1234567890abcdef1234567890abcdef".into(),
                owner: ":1.2".into(),
                path: format!("/session/{id}"),
                id: id.into(),
                uid: 1000,
                created: 10,
            },
            remote: false,
            state: "online".into(),
            seat: "seat0".into(),
            class: "user".into(),
            desktop: "KDE".into(),
            kind: "wayland".into(),
        }
    }

    struct Inventory {
        direct: Option<Session>,
        owner: u32,
        sessions: Vec<Session>,
    }
    impl Logind for Inventory {
        fn direct(&mut self, _: u32) -> Result<Option<Session>, EligibilityError> {
            Ok(self.direct.clone())
        }
        fn manager_uid(&mut self, _: u32) -> Result<u32, EligibilityError> {
            Ok(self.owner)
        }
        fn sessions(&mut self, _: u32) -> Result<Vec<Session>, EligibilityError> {
            Ok(self.sessions.clone())
        }
    }

    #[test]
    fn direct_ineligible_never_uses_an_eligible_fallback() {
        for variation in 0..8 {
            let mut direct = session("direct");
            match variation {
                0 => direct.remote = true,
                1 => direct.state = "closing".into(),
                2 => direct.state = "opening".into(),
                3 => direct.seat.clear(),
                4 => direct.class = "greeter".into(),
                5 => direct.desktop = "GNOME".into(),
                6 => direct.kind = "tty".into(),
                _ => direct.identity.uid = 1001,
            }
            let mut inventory = Inventory {
                direct: Some(direct),
                owner: 1000,
                sessions: vec![session("other")],
            };
            assert!(route(&mut inventory, 42, 1000).is_err());
        }
    }

    #[test]
    fn manager_requires_one_candidate_and_matching_owner() {
        for count in 0..=3 {
            let mut inventory = Inventory {
                direct: None,
                owner: 1000,
                sessions: (0..count).map(|id| session(&id.to_string())).collect(),
            };
            assert_eq!(route(&mut inventory, 42, 1000).is_ok(), count == 1);
        }
        let mut inventory = Inventory {
            direct: None,
            owner: 1001,
            sessions: vec![session("only")],
        };
        assert_eq!(
            route(&mut inventory, 42, 1000),
            Err(EligibilityError::WrongAccount)
        );
    }

    #[test]
    fn unknown_candidates_cannot_hide_ambiguity_and_inactive_online_is_eligible() {
        assert!(session("inactive").eligible(1000).unwrap());
        let mut unknown = session("unknown");
        unknown.state = "unrecognized".into();
        let mut inventory = Inventory {
            direct: None,
            owner: 1000,
            sessions: vec![session("known"), unknown],
        };
        assert_eq!(
            route(&mut inventory, 42, 1000),
            Err(EligibilityError::UnknownProperties)
        );
    }

    #[test]
    fn process_metadata_parsers_reject_mismatches_and_exited_pidfds() {
        assert!(credentials_match(
            "Uid:\t1000 1000 1000 1000\nGid:\t100 100 100 100\n",
            1000,
            100
        ));
        assert!(!credentials_match(
            "Uid:\t1000 0 1000 1000\nGid:\t100 100 100 100\n",
            1000,
            100
        ));
        assert!(!credentials_match(
            "Uid:\t1000 1000 1000\nGid:\t100 100 100 100\n",
            1000,
            100
        ));
        assert_eq!(pidfd_pid("Pid:\t42\n").unwrap(), 42);
        assert!(pidfd_pid("Pid:\t-1\n").is_err());
        assert!(pidfd_pid("Pid:\t42\nPid:\t42\n").is_err());
        let stat = format!("42 (strange ) name) S {} 777 0 0", "0 ".repeat(18));
        assert_eq!(process_start_time(&stat, 42).unwrap(), 777);
        assert!(process_start_time(&stat, 43).is_err());
        assert!(process_start_time(&stat.replace(") S ", ") Z "), 42).is_err());
    }

    #[test]
    fn native_socket_peer_reference_survives_only_while_peer_lives() {
        let (server, _client) = UnixStream::pair().unwrap();
        let peer = Peer::from_socket(&server).unwrap();
        assert_eq!(peer.pid(), std::process::id());
        peer.ensure_live().unwrap();
    }

    #[test]
    fn socket_fixture_child() {
        let Some(path) = std::env::var_os("LOCALPIN_M5_TEST_PEER_SOCKET") else {
            return;
        };
        let mut socket = UnixStream::connect(path).unwrap();
        socket.write_all(&[1]).unwrap();
        let mut byte = [0];
        socket.read_exact(&mut byte).unwrap();
    }

    #[test]
    fn native_exited_peer_is_rejected_even_while_socket_remains() {
        let mut random = [0; 8];
        getrandom::fill(&mut random).unwrap();
        let path = std::env::temp_dir().join(format!(
            "localpin-m5-peer-{}-{}",
            std::process::id(),
            u64::from_ne_bytes(random)
        ));
        let listener = UnixListener::bind(&path).unwrap();
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "platform::tests::socket_fixture_child"])
            .env("LOCALPIN_M5_TEST_PEER_SOCKET", &path)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let (mut socket, _) = listener.accept().unwrap();
        std::fs::remove_file(&path).unwrap();
        let mut ready = [0];
        socket.read_exact(&mut ready).unwrap();
        let peer = Peer::from_socket(&socket).unwrap();
        assert_eq!(peer.pid(), child.id());
        child.kill().unwrap();
        child.wait().unwrap();
        assert!(peer.ensure_live().is_err());
        // Capturing after the original socket peer has exited cannot bind to a
        // different process, even if its numeric PID were to be recycled.
        assert!(Peer::from_socket(&socket).is_err());
    }

    #[test]
    fn session_identity_fences_service_restart_and_id_replacement() {
        let original = session("same").identity;
        let mut changed = original.clone();
        changed.created += 1;
        assert_ne!(original, changed);
        changed = original.clone();
        changed.owner = ":1.3".into();
        assert_ne!(original, changed);
        changed = original.clone();
        changed.bus_id = "abcdef1234567890abcdef1234567890".into();
        assert_ne!(original, changed);
        assert_eq!(original.reference(), original.clone().reference());
        assert_ne!(original.reference(), changed.reference());
        assert!(remaining(Instant::now()).is_err());
    }

    #[test]
    fn missing_authoritative_property_is_rejected() {
        let mut properties = PropMap::new();
        properties.insert("Id".into(), Variant(Box::new("c1".to_owned())));
        assert!(matches!(
            session_properties(
                "1234567890abcdef1234567890abcdef",
                ":1.2",
                "/session/c1",
                &properties
            ),
            Err(EligibilityError::UnknownProperties)
        ));
    }

    #[test]
    fn complete_native_property_types_are_parsed_and_required() {
        let mut properties = PropMap::new();
        for (key, text) in [
            ("Id", "c1"),
            ("State", "online"),
            ("Class", "user"),
            ("Desktop", "KDE"),
            ("Type", "wayland"),
        ] {
            properties.insert(key.into(), Variant(Box::new(text.to_owned())));
        }
        properties.insert(
            "User".into(),
            Variant(Box::new((1000_u32, Path::from("/user/u1000")))),
        );
        properties.insert(
            "Seat".into(),
            Variant(Box::new(("seat0".to_owned(), Path::from("/seat/seat0")))),
        );
        properties.insert("Remote".into(), Variant(Box::new(false)));
        properties.insert("TimestampMonotonic".into(), Variant(Box::new(100_u64)));
        assert!(
            session_properties(
                "1234567890abcdef1234567890abcdef",
                ":1.2",
                "/session/c1",
                &properties
            )
            .unwrap()
            .eligible(1000)
            .unwrap()
        );
        for required in [
            "Id",
            "State",
            "Class",
            "Desktop",
            "Type",
            "User",
            "Seat",
            "Remote",
            "TimestampMonotonic",
        ] {
            let mut incomplete = properties
                .iter()
                .map(|(name, value)| (name.clone(), Variant(value.0.box_clone())))
                .collect();
            let _: Option<Variant<Box<dyn RefArg>>> = PropMap::remove(&mut incomplete, required);
            assert!(
                session_properties(
                    "1234567890abcdef1234567890abcdef",
                    ":1.2",
                    "/session/c1",
                    &incomplete
                )
                .is_err(),
                "accepted missing {required}"
            );
        }
    }
}
