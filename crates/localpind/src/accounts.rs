//! Local-files account lifecycle with a root-owned shadow-record sentinel.
//!
//! Each authority retains both its global lifecycle lease and a native password
//! database read lock through final authorization delivery. Normal account tools
//! remove the sentinel when deleting an account; recreation cannot inherit it.

use std::{
    collections::BTreeSet,
    fs::File,
    io::{Read, Write},
    os::{fd::AsRawFd, unix::fs::MetadataExt},
};

use localpin_core::{
    enrollment::{LifecycleAuthority, LifecycleError},
    types::{AccountId, Clock, Incarnation, Uid},
};
use rustix::fs::{
    AtFlags, FlockOperation, IFlags, Mode, OFlags, ResolveFlags, flock, ioctl_getflags,
    ioctl_setflags, openat2,
};
use zeroize::Zeroizing;

const REGISTRY_ROOT: &str = "/var/lib/localpin-accounts";
const STORAGE_ROOT: &str = "/var/lib/localpin";
const INTEGRATION_ROOT: &str = "/var/lib/localpin-integration";
const MAGIC: &[u8; 8] = b"LPACCT03";
const MAX_REGISTRY: usize = 16 * 1024;
const MAX_INPUT: u64 = 64 * 1024;
const MAX_ACCOUNTS: usize = 128;
// Only privileged migration removes the legacy appliance flags. New accounts
// never freeze these paths; normal distribution updates can replace them.
const LEGACY_DIRECTORIES: &[&str] = &["/etc", "/etc/pam.d", "/etc/authselect", "/etc/security"];
const LEGACY_FILES: &[&str] = &[
    "/etc/passwd",
    "/etc/shadow",
    "/etc/group",
    "/etc/gshadow",
    "/etc/environment",
    "/etc/pam.d/kde",
    "/etc/pam.d/localpin-enroll",
    "/etc/pam.d/localpin-eligibility",
    "/etc/authselect/password-auth",
    "/etc/authselect/postlogin",
    "/etc/authselect/nsswitch.conf",
    "/etc/security/faillock.conf",
    "/etc/security/pam_env.conf",
];

/// Sanitized root administration failure. No account hashes or names are shown.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AccountError {
    /// Root credentials are required.
    Privilege,
    /// A lease is held, or a protected input still has a writable reference.
    Busy,
    /// Required trusted state, paths, native locking or filesystem support is missing.
    Unavailable,
    /// The registry or requested account list is invalid.
    Invalid,
}

type Result<T> = std::result::Result<T, AccountError>;

impl From<std::io::Error> for AccountError {
    fn from(_: std::io::Error) -> Self {
        Self::Unavailable
    }
}
impl From<rustix::io::Errno> for AccountError {
    fn from(error: rustix::io::Errno) -> Self {
        if error == rustix::io::Errno::WOULDBLOCK {
            Self::Busy
        } else {
            Self::Unavailable
        }
    }
}

fn fixed_open(path: &str, flags: OFlags) -> Result<File> {
    let root = File::from(rustix::fs::open(
        "/",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )?);
    let relative = path.strip_prefix('/').ok_or(AccountError::Invalid)?;
    let metadata_file = File::from(openat2(
        &root,
        relative,
        OFlags::PATH | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    )?);
    let before = metadata_file.metadata()?;
    if !before.is_file() && !before.is_dir() {
        return Err(AccountError::Unavailable);
    }
    let file = File::from(openat2(
        &root,
        relative,
        flags | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    )?);
    let after = file.metadata()?;
    if before.dev() != after.dev() || before.ino() != after.ino() {
        return Err(AccountError::Unavailable);
    }
    // Ancestors are part of the trusted platform, and cannot be writable by an
    // ordinary user. Descriptor-relative openat2 rejects symlink substitution.
    let mut prefix = String::new();
    for part in path
        .trim_start_matches('/')
        .split('/')
        .filter(|p| !p.is_empty())
    {
        prefix.push('/');
        prefix.push_str(part);
        let metadata = std::fs::symlink_metadata(&prefix)?;
        if metadata.uid() != 0 || metadata.mode() & 0o022 != 0 || metadata.file_type().is_symlink()
        {
            return Err(AccountError::Unavailable);
        }
    }
    Ok(file)
}

fn child(dir: &File, name: &str, flags: OFlags, mode: Mode) -> Result<File> {
    let before = if flags.contains(OFlags::CREATE) {
        None
    } else {
        let reference = File::from(openat2(
            dir,
            name,
            OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
            ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
        )?);
        let metadata = reference.metadata()?;
        if !metadata.is_file() {
            return Err(AccountError::Unavailable);
        }
        Some(metadata)
    };
    let file = File::from(openat2(
        dir,
        name,
        flags | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        mode,
        ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    )?);
    if let Some(before) = before {
        let after = file.metadata()?;
        if before.dev() != after.dev() || before.ino() != after.ino() {
            return Err(AccountError::Unavailable);
        }
    }
    Ok(file)
}

fn safe_record(file: &File) -> Result<()> {
    let m = file.metadata()?;
    if m.gid() != 0 {
        return Err(AccountError::Unavailable);
    }
    safe_record_owned(file, 0)
}

fn safe_record_owned(file: &File, owner: u32) -> Result<()> {
    let m = file.metadata()?;
    if !m.is_file()
        || m.uid() != owner
        || (owner == 0 && m.gid() != 0)
        || m.nlink() != 1
        || m.mode() & 0o7777 != 0o600
    {
        return Err(AccountError::Unavailable);
    }
    Ok(())
}

// Administration always orders integration -> registry -> native password ->
// storage. Python already owns the first lease and passes that same open-file
// description to fixed native children. Never explicitly unlock an adopted fd:
// flock ownership is shared with its parent until every duplicate is closed.
struct IntegrationLease {
    root: File,
    control: File,
    lock: File,
}

impl IntegrationLease {
    fn open(inherited: Option<i32>) -> Result<Option<Self>> {
        root_required()?;
        Self::open_with(INTEGRATION_ROOT, inherited, 0, 0, |path| {
            fixed_open(path, OFlags::RDONLY | OFlags::DIRECTORY)
        })
    }

    fn open_with(
        path: &str,
        inherited: Option<i32>,
        owner: u32,
        group: u32,
        open: impl Fn(&str) -> Result<File>,
    ) -> Result<Option<Self>> {
        match std::fs::symlink_metadata(path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound && inherited.is_none() => {
                return Ok(None);
            }
            Err(_) => return Err(AccountError::Unavailable),
            Ok(metadata) if !metadata.is_dir() => return Err(AccountError::Unavailable),
            Ok(_) => {}
        }
        let root = open(path)?;
        let control = open(&format!("{path}/control"))?;
        Self::validate_directories(&root, &control, path, owner, group, &open)?;
        let lock = match inherited {
            Some(fd) => duplicate_integration_lock(fd)?,
            None => child(
                &control,
                "lock",
                OFlags::RDWR | OFlags::CREATE,
                Mode::RUSR | Mode::WUSR,
            )?,
        };
        let lease = Self {
            root,
            control,
            lock,
        };
        lease.validate(path, owner, group, &open)?;
        flock(&lease.lock, FlockOperation::NonBlockingLockExclusive)?;
        // A replaced lock/directory must not authorize changes after acquisition.
        lease.validate(path, owner, group, &open)?;
        Ok(Some(lease))
    }

    fn validate(
        &self,
        path: &str,
        owner: u32,
        group: u32,
        open: &impl Fn(&str) -> Result<File>,
    ) -> Result<()> {
        Self::validate_directories(&self.root, &self.control, path, owner, group, open)?;
        let held = self.lock.metadata()?;
        let actual = child(&self.control, "lock", OFlags::RDONLY, Mode::empty())?.metadata()?;
        if !held.is_file()
            || held.uid() != owner
            || held.gid() != group
            || held.mode() & 0o7777 != 0o600
            || held.nlink() != 1
            || held.dev() != actual.dev()
            || held.ino() != actual.ino()
        {
            return Err(AccountError::Unavailable);
        }
        Ok(())
    }

    fn validate_directories(
        root: &File,
        control: &File,
        path: &str,
        owner: u32,
        group: u32,
        open: &impl Fn(&str) -> Result<File>,
    ) -> Result<()> {
        for (held, name, mode) in [
            (root, path.to_owned(), 0o755),
            (control, format!("{path}/control"), 0o700),
        ] {
            let actual = open(&name)?.metadata()?;
            let metadata = held.metadata()?;
            if !metadata.is_dir()
                || metadata.uid() != owner
                || metadata.gid() != group
                || metadata.mode() & 0o7777 != mode
                || metadata.dev() != actual.dev()
                || metadata.ino() != actual.ino()
            {
                return Err(AccountError::Unavailable);
            }
        }
        Ok(())
    }
}

/// Duplicate an untrusted numeric descriptor without borrowing invalid Rust fd
/// ownership. The integer-only fcntl calls cannot access caller memory.
#[allow(unsafe_code)]
fn duplicate_integration_lock(fd: i32) -> Result<File> {
    use std::os::fd::FromRawFd;

    if fd < 3 {
        return Err(AccountError::Invalid);
    }
    // SAFETY: F_GETFD takes an integer descriptor and no pointer argument. Bad
    // descriptors return -1; no Rust borrowed-fd validity invariant is assumed.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags < 0 {
        return Err(AccountError::Unavailable);
    }
    // SAFETY: F_SETFD takes integer flags. Prevent the inherited original from
    // leaking through any later exec, while retaining the parent's open file.
    if unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) } < 0 {
        return Err(AccountError::Unavailable);
    }
    // SAFETY: F_DUPFD_CLOEXEC returns a new exclusively owned fd on success.
    let duplicate = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 3) };
    if duplicate < 0 {
        return Err(AccountError::Unavailable);
    }
    // SAFETY: successful fcntl above transferred this new descriptor exclusively
    // to this function. File closes only the duplicate, never the supplied fd.
    Ok(unsafe { File::from_raw_fd(duplicate) })
}

struct Lease {
    directory: File,
    lock: File,
}

impl Lease {
    fn open(exclusive: bool, create: bool) -> Result<Self> {
        let directory = fixed_open(REGISTRY_ROOT, OFlags::RDONLY | OFlags::DIRECTORY)?;
        if directory.metadata()?.mode() & 0o7777 != 0o700 {
            return Err(AccountError::Unavailable);
        }
        let lock = if create {
            match child(
                &directory,
                "lock",
                OFlags::RDWR | OFlags::CREATE | OFlags::EXCL,
                Mode::RUSR | Mode::WUSR,
            ) {
                Ok(file) => file,
                Err(_) => child(&directory, "lock", OFlags::RDONLY, Mode::empty())?,
            }
        } else {
            child(&directory, "lock", OFlags::RDONLY, Mode::empty())?
        };
        safe_record(&lock)?;
        flock(
            &lock,
            if exclusive {
                FlockOperation::NonBlockingLockExclusive
            } else {
                FlockOperation::NonBlockingLockShared
            },
        )?;
        let lease = Self { directory, lock };
        lease.validate()?;
        Ok(lease)
    }

    fn validate(&self) -> Result<()> {
        safe_record(&self.lock)?;
        let actual = child(&self.directory, "lock", OFlags::RDONLY, Mode::empty())?.metadata()?;
        let held = self.lock.metadata()?;
        if actual.dev() != held.dev() || actual.ino() != held.ino() {
            return Err(AccountError::Unavailable);
        }
        let actual = fixed_open(REGISTRY_ROOT, OFlags::RDONLY | OFlags::DIRECTORY)?.metadata()?;
        let held = self.directory.metadata()?;
        if actual.dev() != held.dev() || actual.ino() != held.ino() || held.mode() & 0o7777 != 0o700
        {
            return Err(AccountError::Unavailable);
        }
        Ok(())
    }

    fn read(&self) -> Result<Registry> {
        Registry::decode(&self.read_bytes()?)
    }

    fn read_bytes(&self) -> Result<Zeroizing<Vec<u8>>> {
        self.validate()?;
        let file = child(&self.directory, "registry", OFlags::RDONLY, Mode::empty())?;
        safe_record(&file)?;
        if file.metadata()?.len() > MAX_REGISTRY as u64 {
            return Err(AccountError::Invalid);
        }
        let mut bytes = Zeroizing::new(Vec::new());
        (&file)
            .take(MAX_REGISTRY as u64 + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() > MAX_REGISTRY {
            return Err(AccountError::Invalid);
        }
        // A visible replacement whose writer crashed before acknowledgement is
        // made durable before a reader can use it as authority.
        file.sync_all()?;
        self.directory.sync_all()?;
        Ok(bytes)
    }

    fn write(&self, registry: &Registry) -> Result<()> {
        self.write_checked(registry, || Ok(()))
    }

    fn write_checked(
        &self,
        registry: &Registry,
        mut before_publish: impl FnMut() -> Result<()>,
    ) -> Result<()> {
        self.validate()?;
        replace_registry(&self.directory, registry, 0, |at| {
            if at == RegistryBoundary::FileSynced {
                before_publish()?;
            }
            Ok(())
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RegistryBoundary {
    TempCreated,
    Written,
    FileSynced,
    Renamed,
    DirectorySynced,
}

fn replace_registry(
    directory: &File,
    registry: &Registry,
    owner: u32,
    mut fault: impl FnMut(RegistryBoundary) -> Result<()>,
) -> Result<()> {
    match child(directory, ".pending", OFlags::RDONLY, Mode::empty()) {
        Ok(old) => {
            safe_record_owned(&old, owner)?;
            rustix::fs::unlinkat(directory, ".pending", AtFlags::empty())?;
        }
        Err(AccountError::Unavailable) => {
            // Missing and unsafe temp paths are distinguished using a
            // no-follow metadata lookup; an unsafe entry is never removed.
            match rustix::fs::statat(directory, ".pending", AtFlags::SYMLINK_NOFOLLOW) {
                Err(rustix::io::Errno::NOENT) => {}
                _ => return Err(AccountError::Unavailable),
            }
        }
        Err(error) => return Err(error),
    }
    let mut pending = child(
        directory,
        ".pending",
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL,
        Mode::RUSR | Mode::WUSR,
    )?;
    safe_record_owned(&pending, owner)?;
    fault(RegistryBoundary::TempCreated)?;
    pending.write_all(&registry.encode())?;
    fault(RegistryBoundary::Written)?;
    pending.sync_all()?;
    fault(RegistryBoundary::FileSynced)?;
    rustix::fs::renameat(directory, ".pending", directory, "registry")?;
    fault(RegistryBoundary::Renamed)?;
    directory.sync_all()?;
    fault(RegistryBoundary::DirectorySynced)?;
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Binding {
    account: AccountId,
    name: String,
    marker: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Registry {
    bindings: Vec<Binding>,
}

fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 32
        && name.bytes().enumerate().all(|(i, c)| {
            c.is_ascii_lowercase() || c == b'_' || (i > 0 && (c.is_ascii_digit() || c == b'-'))
        })
}

fn marker(text: &str) -> Option<u64> {
    if text.is_empty() || text.starts_with('0') || !text.bytes().all(|c| c.is_ascii_digit()) {
        return None;
    }
    text.parse::<u64>()
        .ok()
        .filter(|value| *value < u64::from(u32::MAX))
}

impl Registry {
    fn revoked() -> Self {
        Self {
            bindings: Vec::new(),
        }
    }

    fn active(&self) -> bool {
        !self.bindings.is_empty()
    }

    fn validate(&self) -> Result<()> {
        if self.bindings.len() > MAX_ACCOUNTS {
            return Err(AccountError::Invalid);
        }
        let mut uids = BTreeSet::new();
        let mut names = BTreeSet::new();
        let mut markers = BTreeSet::new();
        let mut previous_uid = 0;
        for binding in &self.bindings {
            if !(1000..=59999).contains(&binding.account.uid.get())
                || binding.account.uid.get() <= previous_uid
                || !valid_name(&binding.name)
                || marker(&binding.marker.to_string()) != Some(binding.marker)
                || !uids.insert(binding.account.uid.get())
                || !names.insert(binding.name.as_str())
                || !markers.insert(binding.marker)
            {
                return Err(AccountError::Invalid);
            }
            previous_uid = binding.account.uid.get();
        }
        Ok(())
    }

    fn encode(&self) -> Vec<u8> {
        let mut out = MAGIC.to_vec();
        out.extend_from_slice(&(self.bindings.len() as u16).to_be_bytes());
        for binding in &self.bindings {
            out.extend_from_slice(&binding.account.uid.get().to_be_bytes());
            out.extend_from_slice(&binding.account.incarnation.get());
            out.extend_from_slice(&binding.marker.to_be_bytes());
            out.push(binding.name.len() as u8);
            out.extend_from_slice(binding.name.as_bytes());
        }
        out
    }

    fn decode(mut input: &[u8]) -> Result<Self> {
        if take::<8>(&mut input)? != *MAGIC {
            return Err(AccountError::Invalid);
        }
        let count = u16::from_be_bytes(take(&mut input)?) as usize;
        if count > MAX_ACCOUNTS {
            return Err(AccountError::Invalid);
        }
        let mut bindings = Vec::with_capacity(count);
        for _ in 0..count {
            let uid = Uid::new(u32::from_be_bytes(take(&mut input)?))
                .map_err(|_| AccountError::Invalid)?;
            let incarnation =
                Incarnation::new(take(&mut input)?).map_err(|_| AccountError::Invalid)?;
            let marker = u64::from_be_bytes(take(&mut input)?);
            let length = usize::from(take::<1>(&mut input)?[0]);
            let (name, rest) = input
                .split_at_checked(length)
                .ok_or(AccountError::Invalid)?;
            input = rest;
            bindings.push(Binding {
                account: AccountId { uid, incarnation },
                name: std::str::from_utf8(name)
                    .map_err(|_| AccountError::Invalid)?
                    .to_owned(),
                marker,
            });
        }
        if !input.is_empty() {
            return Err(AccountError::Invalid);
        }
        let registry = Self { bindings };
        registry.validate()?;
        Ok(registry)
    }
}

fn take<const N: usize>(input: &mut &[u8]) -> Result<[u8; N]> {
    let (head, rest) = input.split_at_checked(N).ok_or(AccountError::Invalid)?;
    *input = rest;
    head.try_into().map_err(|_| AccountError::Invalid)
}

/// A native password-database lock retained through actual broker delivery.
///
/// Linux OFD locks conflict with glibc's POSIX lckpwdf lock and systemd's OFD
/// lock, and closing another same-process descriptor cannot release this lock.
struct PasswordLease {
    file: File,
}

impl PasswordLease {
    fn open(exclusive: bool, create: bool) -> Result<Self> {
        let directory = fixed_open("/etc", OFlags::RDONLY | OFlags::DIRECTORY)?;
        let file = if create {
            match child(
                &directory,
                ".pwd.lock",
                OFlags::RDWR | OFlags::CREATE | OFlags::EXCL,
                Mode::RUSR | Mode::WUSR,
            ) {
                Ok(file) => {
                    file.sync_all()?;
                    directory.sync_all()?;
                    file
                }
                Err(_) => child(&directory, ".pwd.lock", OFlags::RDWR, Mode::empty())?,
            }
        } else {
            child(
                &directory,
                ".pwd.lock",
                if exclusive {
                    OFlags::RDWR
                } else {
                    OFlags::RDONLY
                },
                Mode::empty(),
            )?
        };
        safe_record(&file)?;
        native_database_lock(&file, exclusive)?;
        let lease = Self { file };
        lease.validate()?;
        Ok(lease)
    }

    fn validate(&self) -> Result<()> {
        safe_record(&self.file)?;
        let actual = fixed_open("/etc/.pwd.lock", OFlags::RDONLY)?.metadata()?;
        let held = self.file.metadata()?;
        if actual.dev() != held.dev() || actual.ino() != held.ino() {
            return Err(AccountError::Unavailable);
        }
        Ok(())
    }
}

#[allow(unsafe_code)]
fn native_database_lock(file: &File, exclusive: bool) -> Result<()> {
    let mut lock = libc::flock {
        l_type: if exclusive {
            libc::F_WRLCK
        } else {
            libc::F_RDLCK
        } as libc::c_short,
        l_whence: libc::SEEK_SET as libc::c_short,
        l_start: 0,
        l_len: 0,
        l_pid: 0,
    };
    // SAFETY: fcntl's fixed F_OFD_SETLK command borrows this correctly sized
    // live flock for this call. It receives no caller-controlled command/path,
    // transfers no ownership, and the File owns the resulting kernel lease.
    let result = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_OFD_SETLK, &mut lock) };
    if result != 0 {
        return Err(match std::io::Error::last_os_error().raw_os_error() {
            Some(libc::EAGAIN | libc::EACCES) => AccountError::Busy,
            _ => AccountError::Unavailable,
        });
    }
    Ok(())
}

/// Production lifecycle retaining registry and native account locks until drop.
pub struct SystemLifecycle {
    lease: Lease,
    password: PasswordLease,
}

impl SystemLifecycle {
    /// Open existing trusted authority. Missing and legacy state never creates identity.
    pub fn open() -> std::result::Result<Self, LifecycleError> {
        let lease = Lease::open(false, false).map_err(|_| LifecycleError::Unavailable)?;
        let password =
            PasswordLease::open(false, false).map_err(|_| LifecycleError::Unavailable)?;
        if !lease
            .read()
            .map_err(|_| LifecycleError::Unavailable)?
            .active()
        {
            return Err(LifecycleError::Unavailable);
        }
        Ok(Self { lease, password })
    }
}

impl LifecycleAuthority for SystemLifecycle {
    fn current_incarnation(
        &mut self,
        uid: Uid,
    ) -> std::result::Result<Incarnation, LifecycleError> {
        self.password
            .validate()
            .map_err(|_| LifecycleError::Unavailable)?;
        let registry = self.lease.read().map_err(|_| LifecycleError::Unavailable)?;
        let binding = registry
            .bindings
            .iter()
            .find(|binding| binding.account.uid == uid)
            .ok_or(LifecycleError::Unsupported)?;
        let passwd = read_input("/etc/passwd").map_err(|_| LifecycleError::Unavailable)?;
        let shadow = read_input("/etc/shadow").map_err(|_| LifecycleError::Unavailable)?;
        validate_binding(
            std::str::from_utf8(&passwd).map_err(|_| LifecycleError::Unavailable)?,
            std::str::from_utf8(&shadow).map_err(|_| LifecycleError::Unavailable)?,
            binding,
        )
        .map_err(|_| LifecycleError::Unavailable)?;
        Ok(binding.account.incarnation)
    }
}

fn root_required() -> Result<()> {
    if rustix::process::getuid().as_raw() != 0 || rustix::process::geteuid().as_raw() != 0 {
        Err(AccountError::Privilege)
    } else {
        Ok(())
    }
}

/// Read-only root preflight for both fixed KDE native authentication substacks.
/// This selector never authenticates, creates state or touches account/tally data.
pub fn check_policy() -> Result<()> {
    root_required()?;
    if localpin_auth::kde_native_policy_compatible(b"kde")
        && localpin_auth::kde_native_policy_compatible(b"kde-fingerprint")
    {
        Ok(())
    } else {
        Err(AccountError::Unavailable)
    }
}

fn read_input(path: &str) -> Result<Zeroizing<Vec<u8>>> {
    let file = fixed_open(path, OFlags::RDONLY)?;
    let before = file.metadata()?;
    if !before.is_file() || before.nlink() != 1 || before.gid() != 0 || before.len() > MAX_INPUT {
        return Err(AccountError::Unavailable);
    }
    let mut bytes = Zeroizing::new(Vec::new());
    (&file).take(MAX_INPUT + 1).read_to_end(&mut bytes)?;
    let after = file.metadata()?;
    if bytes.len() as u64 > MAX_INPUT
        || before.dev() != after.dev()
        || before.ino() != after.ino()
        || before.ctime() != after.ctime()
        || before.ctime_nsec() != after.ctime_nsec()
        || before.len() != after.len()
    {
        return Err(AccountError::Unavailable);
    }
    Ok(bytes)
}

fn validate_local_account(passwd: &str, shadow: &str, uid: Uid) -> Result<String> {
    let entries: Vec<Vec<_>> = passwd
        .lines()
        .map(|line| line.split(':').collect())
        .collect();
    let matches: Vec<_> = entries
        .iter()
        .filter(|fields| fields.len() == 7 && fields[2].parse::<u32>() == Ok(uid.get()))
        .collect();
    if matches.len() != 1 {
        return Err(AccountError::Invalid);
    }
    let entry = matches[0];
    if !valid_name(entry[0])
        || entry[1] != "x"
        || !entry[5].starts_with('/')
        || entry[3].parse::<u32>().is_err()
        || entries
            .iter()
            .filter(|fields| fields.first() == Some(&entry[0]))
            .count()
            != 1
        || shadow
            .lines()
            .filter(|line| line.split(':').next() == Some(entry[0]))
            .count()
            != 1
        || shadow
            .lines()
            .any(|line| line.split(':').next() == Some(entry[0]) && line.split(':').count() != 9)
    {
        return Err(AccountError::Invalid);
    }
    Ok(entry[0].to_owned())
}

fn validate_binding(passwd: &str, shadow: &str, binding: &Binding) -> Result<()> {
    if validate_local_account(passwd, shadow, binding.account.uid)? != binding.name {
        return Err(AccountError::Unavailable);
    }
    let row = shadow
        .lines()
        .find(|line| line.split(':').next() == Some(binding.name.as_str()))
        .ok_or(AccountError::Unavailable)?;
    if row.split(':').nth(8).and_then(marker) != Some(binding.marker) {
        return Err(AccountError::Unavailable);
    }
    Ok(())
}

fn legacy_registry(bytes: &[u8]) -> bool {
    // These are the old bounded appliance layouts, not an active authority for
    // current readers. A prefix alone, corrupt/truncated body or unknown format
    // cannot grant permission to remove administrator-owned immutable flags.
    if bytes.len() > MAX_REGISTRY
        || bytes.len() < 12
        || !matches!(&bytes[..8], b"LPACCT01" | b"LPACCT02")
    {
        return false;
    }
    let snapshots = usize::from(u16::from_be_bytes([bytes[8], bytes[9]]));
    if snapshots != 0 && snapshots != 20 {
        return false;
    }
    let end = 10 + snapshots * 84;
    let Some(count) = bytes.get(end..end + 2) else {
        return false;
    };
    let accounts = usize::from(u16::from_be_bytes([count[0], count[1]]));
    if accounts > MAX_ACCOUNTS
        || (snapshots == 0) != (accounts == 0)
        || bytes.len() != end + 2 + accounts * 20
    {
        return false;
    }
    let mut seen = BTreeSet::new();
    for entry in bytes[end + 2..].as_chunks::<20>().0 {
        let uid = u32::from_be_bytes([entry[0], entry[1], entry[2], entry[3]]);
        if Uid::new(uid).is_err() || !seen.insert(uid) || entry[4..].iter().all(|byte| *byte == 0) {
            return false;
        }
    }
    true
}

fn previous_authority(lease: &Lease) -> (Option<Registry>, bool) {
    let Ok(bytes) = lease.read_bytes() else {
        return (None, false);
    };
    (Registry::decode(&bytes).ok(), legacy_registry(&bytes))
}

fn immutable_transition(flags: IFlags, legacy: bool) -> Result<Option<IFlags>> {
    if !flags.contains(IFlags::IMMUTABLE) {
        return Ok(None);
    }
    if !legacy {
        return Err(AccountError::Unavailable);
    }
    Ok(Some(flags & !IFlags::IMMUTABLE))
}

fn account_input_flags(legacy: bool) -> Result<()> {
    for path in LEGACY_FILES.iter().chain(LEGACY_DIRECTORIES.iter().rev()) {
        let file = fixed_open(path, OFlags::RDONLY)?;
        match ioctl_getflags(&file) {
            Ok(flags) => {
                if let Some(updated) = immutable_transition(flags, legacy)? {
                    ioctl_setflags(&file, updated)?;
                    file.sync_all()?;
                    if ioctl_getflags(&file)?.contains(IFlags::IMMUTABLE) {
                        return Err(AccountError::Unavailable);
                    }
                }
            }
            Err(rustix::io::Errno::NOTTY | rustix::io::Errno::OPNOTSUPP) => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

fn discard_legacy_cache(directory: &File) -> Result<()> {
    for name in ["cache-window", "cache-window.pending"] {
        match rustix::fs::statat(directory, name, AtFlags::SYMLINK_NOFOLLOW) {
            Err(rustix::io::Errno::NOENT) => {}
            Err(error) => return Err(error.into()),
            Ok(_) => {
                let file = child(directory, name, OFlags::RDONLY, Mode::empty())?;
                safe_record(&file)?;
                rustix::fs::unlinkat(directory, name, AtFlags::empty())?;
            }
        }
    }
    directory.sync_all()?;
    Ok(())
}

/// Durably revoke all bindings before explicit account/integration maintenance.
/// Legacy appliance flags are removed only after this revocation is durable.
pub fn begin_mutation() -> Result<()> {
    begin_mutation_with_integration_lock(None)
}

/// Revoke under the installed integration lease, optionally adopted from the
/// root integration helper's verified descriptor.
pub fn begin_mutation_with_integration_lock(inherited: Option<i32>) -> Result<()> {
    root_required()?;
    let _integration = IntegrationLease::open(inherited)?;
    let lease = Lease::open(true, true)?;
    let (previous, legacy) = previous_authority(&lease);
    close_desktop_gate()?;
    lease.write(&Registry::revoked())?;
    discard_legacy_cache(&lease.directory)?;
    let _password = PasswordLease::open(true, true)?;
    account_input_flags(legacy)?;
    if let Some(previous) = previous {
        let passwd = read_input("/etc/passwd")?;
        let shadow = read_input("/etc/shadow")?;
        let passwd_text = std::str::from_utf8(&passwd).map_err(|_| AccountError::Invalid)?;
        let shadow_text = std::str::from_utf8(&shadow).map_err(|_| AccountError::Invalid)?;
        let clear = managed_markers_to_clear(passwd_text, shadow_text, &previous);
        if !clear.is_empty() {
            publish_shadow(&shadow_with_markers(shadow_text, &clear)?)?;
        }
    }
    Ok(())
}

fn managed_markers_to_clear(passwd: &str, shadow: &str, previous: &Registry) -> Vec<Binding> {
    previous
        .bindings
        .iter()
        .filter(|binding| validate_binding(passwd, shadow, binding).is_ok())
        .cloned()
        .map(|mut binding| {
            binding.marker = 0;
            binding
        })
        .collect()
}

fn storage_guard() -> Result<localpin_storage::Storage> {
    localpin_storage::Storage::open(fixed_open(
        STORAGE_ROOT,
        OFlags::RDONLY | OFlags::DIRECTORY,
    )?)
    .map_err(|error| {
        if error == localpin_storage::Error::Busy {
            AccountError::Busy
        } else {
            AccountError::Unavailable
        }
    })
}

// Compatibility entrypoints for existing package scripts. There is no mutable
// cache window with marker authority and no journal from which to restore state.
fn package_check(inherited: Option<i32>) -> Result<()> {
    root_required()?;
    let _integration = IntegrationLease::open(inherited)?;
    let lease = Lease::open(true, false)?;
    close_desktop_gate()?;
    let _password = PasswordLease::open(false, false)?;
    let _storage = storage_guard()?;
    let registry = lease.read()?;
    if !registry.active() {
        return Err(AccountError::Unavailable);
    }
    let passwd = read_input("/etc/passwd")?;
    let shadow = read_input("/etc/shadow")?;
    for binding in &registry.bindings {
        validate_binding(
            std::str::from_utf8(&passwd).map_err(|_| AccountError::Invalid)?,
            std::str::from_utf8(&shadow).map_err(|_| AccountError::Invalid)?,
            binding,
        )?;
    }
    Ok(())
}

/// Validate quiescent package identity state; marker authority needs no cache window.
pub fn cache_window_begin() -> Result<()> {
    cache_window_begin_with_integration_lock(None)
}

/// Validate package identity under an optionally inherited integration lease.
pub fn cache_window_begin_with_integration_lock(inherited: Option<i32>) -> Result<()> {
    package_check(inherited)
}

/// Revalidate identity state after package work, without rebuilding authority.
pub fn cache_window_finish() -> Result<()> {
    cache_window_finish_with_integration_lock(None)
}

/// Revalidate package identity under an optionally inherited integration lease.
pub fn cache_window_finish_with_integration_lock(inherited: Option<i32>) -> Result<()> {
    package_check(inherited)
}

struct ProvisionAuthority {
    accounts: Vec<AccountId>,
}
impl LifecycleAuthority for ProvisionAuthority {
    fn current_incarnation(
        &mut self,
        uid: Uid,
    ) -> std::result::Result<Incarnation, LifecycleError> {
        self.accounts
            .iter()
            .find(|account| account.uid == uid)
            .map(|account| account.incarnation)
            .ok_or(LifecycleError::Unsupported)
    }
}

fn shadow_with_markers(shadow: &str, bindings: &[Binding]) -> Result<Zeroizing<Vec<u8>>> {
    if !shadow.ends_with('\n') {
        return Err(AccountError::Invalid);
    }
    let mut output = Zeroizing::new(Vec::new());
    for line in shadow.lines() {
        if let Some(binding) = bindings
            .iter()
            .find(|binding| line.split(':').next() == Some(binding.name.as_str()))
        {
            if line.split(':').count() != 9 {
                return Err(AccountError::Invalid);
            }
            let (prefix, _) = line.rsplit_once(':').ok_or(AccountError::Invalid)?;
            output.extend_from_slice(prefix.as_bytes());
            output.push(b':');
            // Zero is used only for clearing a known old marker after durable
            // revocation; active registries never permit it.
            if binding.marker != 0 {
                output.extend_from_slice(binding.marker.to_string().as_bytes());
            }
        } else {
            output.extend_from_slice(line.as_bytes());
        }
        output.push(b'\n');
    }
    if output.len() as u64 > MAX_INPUT {
        return Err(AccountError::Invalid);
    }
    Ok(output)
}

/// Replace only shadow's reserved markers while preserving its native metadata
/// and SELinux label. Unknown xattrs refuse provisioning rather than dropping
/// ACLs, integrity signatures or administrator metadata.
fn publish_shadow(bytes: &[u8]) -> Result<()> {
    let directory = fixed_open("/etc", OFlags::RDONLY | OFlags::DIRECTORY)?;
    let old = fixed_open("/etc/shadow", OFlags::RDONLY)?;
    replace_shadow(&directory, &old, bytes, 0, 0, |_| Ok(()))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ShadowBoundary {
    Created,
    Metadata,
    Written,
    FileSynced,
    Renamed,
    DirectorySynced,
}

fn replace_shadow(
    directory: &File,
    old: &File,
    bytes: &[u8],
    owner: u32,
    group: u32,
    mut fault: impl FnMut(ShadowBoundary) -> Result<()>,
) -> Result<()> {
    let metadata = old.metadata()?;
    if !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.uid() != owner
        || metadata.gid() != group
        || metadata.mode() & 0o022 != 0
    {
        return Err(AccountError::Unavailable);
    }
    let mut names = [0; 4096];
    let count = rustix::fs::flistxattr(old, &mut names[..])?;
    let label = if count == 0 {
        None
    } else if &names[..count] == b"security.selinux\0" {
        let mut label = vec![0; 4096];
        let length = rustix::fs::fgetxattr(old, "security.selinux", &mut label[..])?;
        label.truncate(length);
        Some(label)
    } else {
        return Err(AccountError::Unavailable);
    };
    const TEMP: &str = ".localpin-shadow.pending";
    match rustix::fs::statat(directory, TEMP, AtFlags::SYMLINK_NOFOLLOW) {
        Err(rustix::io::Errno::NOENT) => {}
        Err(error) => return Err(error.into()),
        Ok(_) => {
            let pending = child(directory, TEMP, OFlags::RDONLY, Mode::empty())?;
            let m = pending.metadata()?;
            if m.uid() != owner
                || m.gid() != group
                || !m.is_file()
                || m.nlink() != 1
                || m.mode() & 0o077 != 0
            {
                return Err(AccountError::Unavailable);
            }
            rustix::fs::unlinkat(directory, TEMP, AtFlags::empty())?;
        }
    }
    let mut pending = child(
        directory,
        TEMP,
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL,
        Mode::RUSR | Mode::WUSR,
    )?;
    fault(ShadowBoundary::Created)?;
    rustix::fs::fchown(
        &pending,
        Some(rustix::fs::Uid::from_raw(owner)),
        Some(rustix::fs::Gid::from_raw(group)),
    )?;
    if let Some(label) = label {
        rustix::fs::fsetxattr(
            &pending,
            "security.selinux",
            &label,
            rustix::fs::XattrFlags::empty(),
        )?;
    }
    fault(ShadowBoundary::Metadata)?;
    pending.write_all(bytes)?;
    fault(ShadowBoundary::Written)?;
    rustix::fs::fchmod(&pending, Mode::from_raw_mode(metadata.mode() & 0o7777))?;
    pending.sync_all()?;
    fault(ShadowBoundary::FileSynced)?;
    let current = child(directory, "shadow", OFlags::RDONLY, Mode::empty())?.metadata()?;
    if current.dev() != metadata.dev()
        || current.ino() != metadata.ino()
        || current.ctime() != metadata.ctime()
        || current.ctime_nsec() != metadata.ctime_nsec()
    {
        return Err(AccountError::Unavailable);
    }
    rustix::fs::renameat(directory, TEMP, directory, "shadow")?;
    fault(ShadowBoundary::Renamed)?;
    directory.sync_all()?;
    fault(ShadowBoundary::DirectorySynced)?;
    Ok(())
}

/// Provision fresh disabled incarnations and rotate their root shadow markers.
/// The broker must be stopped. Old state is quarantined and never adopted.
pub fn seal(uids: &[Uid]) -> Result<()> {
    seal_with_integration_lock(uids, None)
}

/// Provision under an optionally inherited integration lease.
pub fn seal_with_integration_lock(uids: &[Uid], inherited: Option<i32>) -> Result<()> {
    provision(uids, false, inherited)
}

/// Explicit root recovery, including replacing an unknown reserved shadow field.
/// This never retains the old incarnation, marker, credentials or throttle state.
pub fn recover(uids: &[Uid]) -> Result<()> {
    recover_with_integration_lock(uids, None)
}

/// Recover under an optionally inherited integration lease.
pub fn recover_with_integration_lock(uids: &[Uid], inherited: Option<i32>) -> Result<()> {
    provision(uids, true, inherited)
}

fn provision(uids: &[Uid], recover_unknown: bool, inherited: Option<i32>) -> Result<()> {
    root_required()?;
    if uids.is_empty()
        || uids.len() > MAX_ACCOUNTS
        || uids.iter().any(|uid| !(1000..=59999).contains(&uid.get()))
        || uids
            .iter()
            .map(|uid| uid.get())
            .collect::<BTreeSet<_>>()
            .len()
            != uids.len()
    {
        return Err(AccountError::Invalid);
    }
    let _integration = IntegrationLease::open(inherited)?;
    let lease = Lease::open(true, true)?;
    let (previous, legacy) = previous_authority(&lease);
    close_desktop_gate()?;
    lease.write(&Registry::revoked())?;
    discard_legacy_cache(&lease.directory)?;
    let _password = PasswordLease::open(true, true)?;
    account_input_flags(legacy)?;
    let mut storage = storage_guard()?;
    let passwd = read_input("/etc/passwd")?;
    let shadow = read_input("/etc/shadow")?;
    let passwd_text = std::str::from_utf8(&passwd).map_err(|_| AccountError::Invalid)?;
    let shadow_text = std::str::from_utf8(&shadow).map_err(|_| AccountError::Invalid)?;
    let faillock = read_input("/etc/security/faillock.conf")?;
    let tally_directory =
        localpin_auth::reviewed_faillock_directory(&faillock).ok_or(AccountError::Unavailable)?;
    let mut used_markers: BTreeSet<u64> = shadow_text
        .lines()
        .filter_map(|line| line.split(':').nth(8).and_then(marker))
        .collect();
    let mut bindings = Vec::new();
    for uid in uids {
        let name = validate_local_account(passwd_text, shadow_text, *uid)?;
        validate_reserved_field(shadow_text, *uid, &name, previous.as_ref(), recover_unknown)?;
        provision_missing_tally(tally_directory, *uid, &name)?;
        let mut incarnation = [0; 16];
        getrandom::fill(&mut incarnation).map_err(|_| AccountError::Unavailable)?;
        let mut chosen = None;
        for _ in 0..16 {
            // Fedora glibc clamps numeric shadow fields to u32 despite the
            // public sp_flag unsigned-long type. This is a root record sentinel;
            // the independent actual incarnation remains 128-bit.
            let mut bytes = [0; 4];
            getrandom::fill(&mut bytes).map_err(|_| AccountError::Unavailable)?;
            let value = u64::from(u32::from_be_bytes(bytes));
            if value != 0 && value < u64::from(u32::MAX) && used_markers.insert(value) {
                chosen = Some(value);
                break;
            }
        }
        bindings.push(Binding {
            account: AccountId {
                uid: *uid,
                incarnation: Incarnation::new(incarnation)
                    .map_err(|_| AccountError::Unavailable)?,
            },
            name,
            marker: chosen.ok_or(AccountError::Unavailable)?,
        });
    }
    bindings.sort_by_key(|binding| binding.account.uid.get());
    let updated = shadow_with_markers(shadow_text, &bindings)?;
    publish_shadow(&updated)?;
    let mut authority = ProvisionAuthority {
        accounts: bindings.iter().map(|binding| binding.account).collect(),
    };
    let mut clock = crate::BootClock::new().map_err(|_| AccountError::Unavailable)?;
    for binding in &bindings {
        storage
            .reprovision(
                binding.account,
                clock.now().map_err(|_| AccountError::Unavailable)?,
                &mut authority,
            )
            .map_err(|_| AccountError::Unavailable)?;
    }
    let registry = Registry { bindings };
    registry.validate()?;
    lease.write_checked(&registry, || {
        _password.validate()?;
        let current_passwd = read_input("/etc/passwd")?;
        let current_shadow = read_input("/etc/shadow")?;
        if *current_passwd != *passwd || *current_shadow != *updated {
            return Err(AccountError::Unavailable);
        }
        for binding in &registry.bindings {
            validate_binding(
                passwd_text,
                std::str::from_utf8(&current_shadow).map_err(|_| AccountError::Invalid)?,
                binding,
            )?;
        }
        Ok(())
    })
}

fn validate_reserved_field(
    shadow: &str,
    uid: Uid,
    name: &str,
    previous: Option<&Registry>,
    recover_unknown: bool,
) -> Result<()> {
    let reserved = shadow
        .lines()
        .find(|line| line.split(':').next() == Some(name))
        .and_then(|line| line.split(':').nth(8))
        .ok_or(AccountError::Invalid)?;
    if reserved.is_empty()
        || recover_unknown
        || previous.is_some_and(|registry| {
            registry.bindings.iter().any(|binding| {
                binding.account.uid == uid
                    && binding.name == name
                    && marker(reserved) == Some(binding.marker)
            })
        })
    {
        Ok(())
    } else {
        Err(AccountError::Unavailable)
    }
}

/// Report whether trusted current authority establishes this supported UID.
pub fn supported(uid: Uid) -> bool {
    SystemLifecycle::open()
        .and_then(|mut authority| authority.current_incarnation(uid))
        .is_ok()
}

// Direct account administration also invalidates any previous desktop test
// approval. Missing installation is normal for pre-M8 component deployments;
// this function never creates activation state or opens a gate.
fn close_desktop_gate() -> Result<()> {
    const DIRECTORY: &str = "/var/lib/localpin-integration";
    match std::fs::symlink_metadata(DIRECTORY) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(_) => return Err(AccountError::Unavailable),
        Ok(_) => {}
    }
    let directory = fixed_open(DIRECTORY, OFlags::RDONLY | OFlags::DIRECTORY)?;
    remove_gate(&directory, 0, 0)
}

fn remove_gate(directory: &File, owner: u32, group: u32) -> Result<()> {
    match rustix::fs::statat(directory, "gate", AtFlags::SYMLINK_NOFOLLOW) {
        Err(rustix::io::Errno::NOENT) => {}
        Err(error) => return Err(error.into()),
        Ok(_) => {
            let file = child(directory, "gate", OFlags::RDONLY, Mode::empty())?;
            let m = file.metadata()?;
            if !m.is_file()
                || m.uid() != owner
                || m.gid() != group
                || m.nlink() != 1
                || m.mode() & 0o7777 != 0o644
            {
                return Err(AccountError::Unavailable);
            }
            rustix::fs::unlinkat(directory, "gate", AtFlags::empty())?;
        }
    }
    directory.sync_all()?;
    Ok(())
}

fn provision_missing_tally(tally_directory: &'static str, uid: Uid, name: &str) -> Result<()> {
    let directory = fixed_open(tally_directory, OFlags::RDONLY | OFlags::DIRECTORY)?;
    if directory.metadata()?.gid() != 0 || directory.metadata()?.mode() & 0o7777 != 0o755 {
        return Err(AccountError::Unavailable);
    }
    // Existing password accounting is never reset or normalized here. A root
    // provisioner may establish a missing empty baseline only while every old
    // incarnation is already durably revoked. Eligibility itself never does it.
    match rustix::fs::statat(&directory, name, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(_) => {
            let file = child(&directory, name, OFlags::RDONLY, Mode::empty())?;
            let m = file.metadata()?;
            if !m.is_file()
                || m.uid() != uid.get()
                || m.gid() != 0
                || m.nlink() != 1
                || m.mode() & 0o7777 != 0o660
                || m.len() >= MAX_INPUT
                || m.len() % 64 != 0
            {
                return Err(AccountError::Unavailable);
            }
            return Ok(());
        }
        Err(rustix::io::Errno::NOENT) => {}
        Err(error) => return Err(error.into()),
    }
    publish_tally(&directory, name, uid.get(), 0, |_| Ok(()))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TallyBoundary {
    Created,
    Owned,
    Canonical,
    FileSynced,
    Linked,
    DirectorySynced,
}

fn publish_tally(
    directory: &File,
    name: &str,
    uid: u32,
    gid: u32,
    mut fault: impl FnMut(TallyBoundary) -> Result<()>,
) -> Result<()> {
    // Keep incomplete ownership/mode setup unnamed. A crash before link drops
    // the anonymous inode; the final name can only refer to canonical state.
    let file = File::from(rustix::fs::openat(
        directory,
        ".",
        OFlags::TMPFILE | OFlags::RDWR | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::RUSR | Mode::WUSR,
    )?);
    fault(TallyBoundary::Created)?;
    rustix::fs::fchown(
        &file,
        Some(rustix::fs::Uid::from_raw(uid)),
        Some(rustix::fs::Gid::from_raw(gid)),
    )?;
    fault(TallyBoundary::Owned)?;
    rustix::fs::fchmod(&file, Mode::from_raw_mode(0o660))?;
    fault(TallyBoundary::Canonical)?;
    file.sync_all()?;
    fault(TallyBoundary::FileSynced)?;
    // linkat never replaces an existing tally. Password accounting that won a
    // concurrent creation race is preserved and the administrator must retry.
    rustix::fs::linkat(&file, "", directory, name, AtFlags::EMPTY_PATH)?;
    fault(TallyBoundary::Linked)?;
    directory.sync_all()?;
    fault(TallyBoundary::DirectorySynced)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};

    struct Fixture {
        path: std::path::PathBuf,
        directory: File,
        owner: u32,
    }
    impl Fixture {
        fn new() -> Self {
            let mut random = [0; 8];
            getrandom::fill(&mut random).unwrap();
            let path = std::env::temp_dir().join(format!(
                "localpin-account-{}-{}",
                std::process::id(),
                u64::from_be_bytes(random)
            ));
            std::fs::DirBuilder::new()
                .mode(0o700)
                .create(&path)
                .unwrap();
            let directory = File::open(&path).unwrap();
            let owner = directory.metadata().unwrap().uid();
            Self {
                path,
                directory,
                owner,
            }
        }
        fn replace(&self, registry: &Registry) {
            replace_registry(&self.directory, registry, self.owner, |_| Ok(())).unwrap();
        }
        fn read(&self) -> Registry {
            Registry::decode(&std::fs::read(self.path.join("registry")).unwrap()).unwrap()
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.path).unwrap();
        }
    }
    fn binding(uid: u32, name: &str, marker: u64, incarnation: u8) -> Binding {
        Binding {
            account: AccountId {
                uid: Uid::new(uid).unwrap(),
                incarnation: Incarnation::new([incarnation; 16]).unwrap(),
            },
            name: name.into(),
            marker,
        }
    }
    fn sample() -> Registry {
        Registry {
            bindings: vec![binding(1000, "alice", 42, 7)],
        }
    }

    fn integration_fixture() -> Fixture {
        let fixture = Fixture::new();
        std::fs::set_permissions(&fixture.path, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(fixture.path.join("control"))
            .unwrap();
        fixture
    }

    fn integration_test_open(path: &str) -> Result<File> {
        // Only tests inject fixture ownership and ancestors. Production uses
        // fixed_open and the constant canonical installation path exclusively.
        if !std::fs::symlink_metadata(path)?.is_dir() {
            return Err(AccountError::Unavailable);
        }
        Ok(File::open(path)?)
    }

    fn integration_test_lease(
        fixture: &Fixture,
        inherited: Option<i32>,
    ) -> Result<Option<IntegrationLease>> {
        IntegrationLease::open_with(
            fixture.path.to_str().unwrap(),
            inherited,
            fixture.owner,
            fixture.directory.metadata().unwrap().gid(),
            integration_test_open,
        )
    }

    // Return true after the parent has checked the exact-test child. Only the
    // child creates its fixture: subprocesses from parallel tests could retain
    // an inherited lock beyond our final drop, until exec or process exit.
    fn run_in_subprocess(test: &str) -> bool {
        const CHILD: &str = "LOCALPIN_TEST_ACCOUNT_LOCK_CHILD";
        if std::env::var_os(CHILD).as_deref() == Some(std::ffi::OsStr::new(test)) {
            return false;
        }
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", test, "--nocapture"])
            .env(CHILD, test)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        true
    }

    #[test]
    fn integration_lock_adoption_retains_parent_lock_until_every_duplicate_closes() {
        if run_in_subprocess(
            "accounts::tests::integration_lock_adoption_retains_parent_lock_until_every_duplicate_closes",
        ) {
            return;
        }
        let fixture = integration_fixture();
        let parent = integration_test_lease(&fixture, None).unwrap().unwrap();
        assert!(matches!(
            integration_test_lease(&fixture, None),
            Err(AccountError::Busy)
        ));
        rustix::io::fcntl_setfd(&parent.lock, rustix::io::FdFlags::empty()).unwrap();
        let adopted = integration_test_lease(&fixture, Some(parent.lock.as_raw_fd()))
            .unwrap()
            .unwrap();
        assert!(
            rustix::io::fcntl_getfd(&parent.lock)
                .unwrap()
                .contains(rustix::io::FdFlags::CLOEXEC)
        );
        assert!(
            rustix::io::fcntl_getfd(&adopted.lock)
                .unwrap()
                .contains(rustix::io::FdFlags::CLOEXEC)
        );
        drop(adopted);
        assert!(matches!(
            integration_test_lease(&fixture, None),
            Err(AccountError::Busy)
        ));
        let adopted = integration_test_lease(&fixture, Some(parent.lock.as_raw_fd()))
            .unwrap()
            .unwrap();
        drop(parent);
        assert!(matches!(
            integration_test_lease(&fixture, None),
            Err(AccountError::Busy)
        ));
        drop(adopted);
        assert!(integration_test_lease(&fixture, None).unwrap().is_some());
    }

    #[test]
    fn integration_lock_refuses_wrong_fds_metadata_and_replaced_paths() {
        let fixture = integration_fixture();
        let parent = integration_test_lease(&fixture, None).unwrap().unwrap();
        let other = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(fixture.path.join("other"))
            .unwrap();
        for fd in [
            0,
            1,
            2,
            -1,
            i32::MAX,
            other.as_raw_fd(),
            fixture.directory.as_raw_fd(),
        ] {
            assert!(integration_test_lease(&fixture, Some(fd)).is_err());
        }
        let lock = fixture.path.join("control/lock");
        std::fs::set_permissions(&lock, std::fs::Permissions::from_mode(0o640)).unwrap();
        assert!(integration_test_lease(&fixture, Some(parent.lock.as_raw_fd())).is_err());
        std::fs::set_permissions(&lock, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::hard_link(&lock, fixture.path.join("alias")).unwrap();
        assert!(integration_test_lease(&fixture, Some(parent.lock.as_raw_fd())).is_err());
        std::fs::remove_file(fixture.path.join("alias")).unwrap();
        std::fs::rename(&lock, fixture.path.join("old-lock")).unwrap();
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&lock)
            .unwrap();
        assert!(integration_test_lease(&fixture, Some(parent.lock.as_raw_fd())).is_err());
        std::fs::remove_file(&lock).unwrap();
        std::os::unix::fs::symlink(fixture.path.join("old-lock"), &lock).unwrap();
        assert!(integration_test_lease(&fixture, Some(parent.lock.as_raw_fd())).is_err());
    }

    #[test]
    fn integration_directories_are_validated_before_creating_a_lock() {
        for (name, mode) in [("", 0o700), ("control", 0o755)] {
            let fixture = integration_fixture();
            std::fs::set_permissions(
                fixture.path.join(name),
                std::fs::Permissions::from_mode(mode),
            )
            .unwrap();
            assert!(integration_test_lease(&fixture, None).is_err());
            assert!(!fixture.path.join("control/lock").exists());
        }
        let fixture = integration_fixture();
        for (owner, group) in [
            (
                fixture.owner + 1,
                fixture.directory.metadata().unwrap().gid(),
            ),
            (
                fixture.owner,
                fixture.directory.metadata().unwrap().gid() + 1,
            ),
        ] {
            assert!(
                IntegrationLease::open_with(
                    fixture.path.to_str().unwrap(),
                    None,
                    owner,
                    group,
                    integration_test_open
                )
                .is_err()
            );
            assert!(!fixture.path.join("control/lock").exists());
        }
        let missing = fixture.path.join("missing");
        assert!(
            IntegrationLease::open_with(
                missing.to_str().unwrap(),
                None,
                fixture.owner,
                0,
                integration_test_open
            )
            .unwrap()
            .is_none()
        );
        assert!(
            IntegrationLease::open_with(
                missing.to_str().unwrap(),
                Some(fixture.directory.as_raw_fd()),
                fixture.owner,
                0,
                integration_test_open
            )
            .is_err()
        );
        std::fs::rename(
            fixture.path.join("control"),
            fixture.path.join("original-control"),
        )
        .unwrap();
        std::os::unix::fs::symlink(
            fixture.path.join("original-control"),
            fixture.path.join("control"),
        )
        .unwrap();
        assert!(integration_test_lease(&fixture, None).is_err());
        assert!(!fixture.path.join("original-control/lock").exists());
    }

    #[test]
    fn integration_lock_rechecks_fixed_paths_after_acquisition() {
        let fixture = integration_fixture();
        let calls = std::cell::Cell::new(0);
        let result = IntegrationLease::open_with(
            fixture.path.to_str().unwrap(),
            None,
            fixture.owner,
            fixture.directory.metadata().unwrap().gid(),
            |path| {
                calls.set(calls.get() + 1);
                if calls.get() == 7 {
                    let lock = fixture.path.join("control/lock");
                    std::fs::rename(&lock, fixture.path.join("retired-lock")).unwrap();
                    std::fs::OpenOptions::new()
                        .write(true)
                        .create_new(true)
                        .mode(0o600)
                        .open(lock)
                        .unwrap();
                }
                integration_test_open(path)
            },
        );
        assert!(matches!(result, Err(AccountError::Unavailable)));
    }

    #[test]
    fn integration_lock_process_probe() {
        let Some(path) = std::env::var_os("LOCALPIN_TEST_INTEGRATION_PATH") else {
            return;
        };
        let path = std::path::Path::new(&path);
        let metadata = std::fs::metadata(path).unwrap();
        let inherited = std::env::var("LOCALPIN_TEST_INTEGRATION_FD")
            .ok()
            .map(|value| value.parse().unwrap());
        let result = IntegrationLease::open_with(
            path.to_str().unwrap(),
            inherited,
            metadata.uid(),
            metadata.gid(),
            integration_test_open,
        );
        if std::env::var("LOCALPIN_TEST_INTEGRATION_EXPECT").unwrap() == "busy" {
            assert!(matches!(result, Err(AccountError::Busy)));
        } else {
            assert!(result.unwrap().is_some());
        }
    }

    #[test]
    fn integration_python_parent_hands_off_lock_and_direct_native_process_is_busy() {
        let fixture = integration_fixture();
        let script = r#"
import fcntl, os, subprocess, sys
binary, root = sys.argv[1:]
def probe(expect, inherited=None):
    env = dict(os.environ, LOCALPIN_TEST_INTEGRATION_PATH=root, LOCALPIN_TEST_INTEGRATION_EXPECT=expect)
    env.pop('LOCALPIN_TEST_INTEGRATION_FD', None)
    if inherited is not None:
        env['LOCALPIN_TEST_INTEGRATION_FD'] = str(inherited)
    result = subprocess.run([binary, '--exact', 'accounts::tests::integration_lock_process_probe', '--nocapture'], env=env,
                            pass_fds=() if inherited is None else (inherited,), capture_output=True)
    assert result.returncode == 0, result.stdout + result.stderr
fd = os.open(root + '/control/lock', os.O_RDWR | os.O_CREAT | os.O_CLOEXEC, 0o600)
fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
probe('busy')
probe('acquired', fd)
probe('busy')
os.close(fd)
probe('acquired')
"#;
        let output = std::process::Command::new("/usr/bin/python3")
            .arg("-c")
            .arg(script)
            .arg(std::env::current_exe().unwrap())
            .arg(&fixture.path)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    const PASSWD: &str = "alice:x:1000:1000:Alice:/home/alice:/bin/bash\n";
    const SHADOW: &str = "alice:$y$j9T$salt$hash:20000:0:99999:7:::42\n";

    #[test]
    fn registry_is_bounded_exact_and_refuses_legacy_or_ambiguous_authority() {
        let registry = sample();
        assert_eq!(Registry::decode(&registry.encode()), Ok(registry.clone()));
        assert_eq!(
            Registry::decode(&Registry::revoked().encode()),
            Ok(Registry::revoked())
        );
        assert!(!Registry::revoked().active());
        for magic in [b"LPACCT01", b"LPACCT02"] {
            let mut bytes = registry.encode();
            bytes[..8].copy_from_slice(magic);
            assert_eq!(Registry::decode(&bytes), Err(AccountError::Invalid));
        }
        let bytes = registry.encode();
        for length in 0..bytes.len() {
            assert_eq!(
                Registry::decode(&bytes[..length]),
                Err(AccountError::Invalid)
            );
        }
        let mut trailing = bytes;
        trailing.push(0);
        assert_eq!(Registry::decode(&trailing), Err(AccountError::Invalid));
        for bad in [
            binding(1000, "bob", 43, 8),
            binding(1001, "alice", 43, 8),
            binding(1001, "bob", 42, 8),
            binding(1001, "bob", 0, 8),
            binding(1001, "bob", u64::MAX, 8),
            binding(1001, "Bad", 43, 8),
        ] {
            let mut bad_registry = registry.clone();
            bad_registry.bindings.push(bad);
            assert_eq!(
                Registry::decode(&bad_registry.encode()),
                Err(AccountError::Invalid)
            );
        }
    }

    #[test]
    fn only_complete_bounded_legacy_registry_proves_ownership_of_old_immutable_flags() {
        for magic in [b"LPACCT01", b"LPACCT02"] {
            let mut revoked = magic.to_vec();
            revoked.extend_from_slice(&[0; 4]);
            assert!(legacy_registry(&revoked));
            let mut active = magic.to_vec();
            active.extend_from_slice(&20_u16.to_be_bytes());
            active.extend_from_slice(&[0; 20 * 84]);
            active.extend_from_slice(&1_u16.to_be_bytes());
            active.extend_from_slice(&1000_u32.to_be_bytes());
            active.extend_from_slice(&[7; 16]);
            assert!(legacy_registry(&active));
            for length in 0..active.len() {
                assert!(!legacy_registry(&active[..length]));
            }
            let mut bad = active.clone();
            bad.push(0);
            assert!(!legacy_registry(&bad));
            let mut bad = active.clone();
            bad[8..10].copy_from_slice(&19_u16.to_be_bytes());
            assert!(!legacy_registry(&bad));
            let mut bad = active.clone();
            bad[10 + 20 * 84..12 + 20 * 84].copy_from_slice(&129_u16.to_be_bytes());
            assert!(!legacy_registry(&bad));
            let mut bad = active.clone();
            bad[12 + 20 * 84..16 + 20 * 84].fill(0);
            assert!(!legacy_registry(&bad));
            let mut bad = active.clone();
            bad[16 + 20 * 84..].fill(0);
            assert!(!legacy_registry(&bad));
            let mut duplicate = active.clone();
            duplicate[10 + 20 * 84..12 + 20 * 84].copy_from_slice(&2_u16.to_be_bytes());
            duplicate.extend_from_slice(&active[12 + 20 * 84..]);
            assert!(!legacy_registry(&duplicate));
            assert!(!legacy_registry(&vec![0; MAX_REGISTRY + 1]));
        }
        assert!(!legacy_registry(&sample().encode()));
        assert!(!legacy_registry(&Registry::revoked().encode()));
        assert!(!legacy_registry(b"LPACCT02garbage"));
        assert!(!legacy_registry(b"UNKNOWN!\0\0\0\0"));
    }

    #[test]
    fn fresh_current_unknown_or_missing_authority_never_clears_administrator_immutable_flags() {
        for legacy in [false, true] {
            assert_eq!(immutable_transition(IFlags::empty(), legacy), Ok(None));
            assert_eq!(immutable_transition(IFlags::NODUMP, legacy), Ok(None));
        }
        let hardened = IFlags::IMMUTABLE | IFlags::NODUMP;
        assert_eq!(
            immutable_transition(hardened, false),
            Err(AccountError::Unavailable)
        );
        assert_eq!(
            immutable_transition(hardened, true),
            Ok(Some(IFlags::NODUMP))
        );
        let current = sample().encode();
        for proof in [
            Some(current.as_slice()),
            Some(b"LPACCT02corrupt".as_slice()),
            None,
        ] {
            let legacy = proof.is_some_and(legacy_registry);
            assert!(!legacy);
            assert_eq!(
                immutable_transition(hardened, legacy),
                Err(AccountError::Unavailable)
            );
        }
    }

    #[test]
    fn marker_tracks_shadow_record_across_native_rewrites_but_never_uid_recreation() {
        let old = binding(1000, "alice", 42, 7);
        assert_eq!(validate_binding(PASSWD, SHADOW, &old), Ok(()));
        // A service account addition and regular password/aging updates preserve
        // the same record sentinel, independent of whole-file inode/contents.
        let passwd = format!("daemon:x:999:999::/var/lib/daemon:/sbin/nologin\n{PASSWD}");
        let shadow = format!(
            "daemon:!:20000::::::\n{}",
            SHADOW.replace("salt$hash:20000", "new$hash:20001")
        );
        assert_eq!(validate_binding(&passwd, &shadow, &old), Ok(()));
        for changed in [
            SHADOW.replace(":42\n", ":\n"),
            SHADOW.replace(":42\n", ":43\n"),
            SHADOW.replace(":42\n", ":042\n"),
            SHADOW.replace(":42\n", ":18446744073709551615\n"),
            SHADOW.replace("alice:", "bob:"),
            String::new(),
            format!("{SHADOW}{SHADOW}"),
        ] {
            assert!(validate_binding(PASSWD, &changed, &old).is_err());
        }
        for changed in [
            PASSWD.replace(":1000:1000:", ":1001:1000:"),
            PASSWD.replace("alice:", "bob:"),
            format!("{PASSWD}{PASSWD}"),
            String::new(),
        ] {
            assert!(validate_binding(&changed, SHADOW, &old).is_err());
        }
        let fresh = binding(1000, "alice", 43, 8);
        assert!(validate_binding(PASSWD, SHADOW, &fresh).is_err());
        assert_ne!(old.account, fresh.account);
    }

    #[test]
    fn provisioning_changes_only_selected_reserved_fields() {
        let shadow = format!("root:!:20000::::::\n{SHADOW}bob:!:20000::::::\n");
        let updated = shadow_with_markers(&shadow, &[binding(1000, "alice", 43, 8)]).unwrap();
        assert_eq!(&*updated, shadow.replace(":42\n", ":43\n").as_bytes());
        assert!(shadow_with_markers(shadow.trim_end(), &sample().bindings).is_err());
        assert!(shadow_with_markers("alice:!:20000::::\n", &sample().bindings).is_err());
        for value in [
            "",
            "0",
            "00",
            "042",
            "+42",
            "-1",
            "18446744073709551615",
            "18446744073709551616",
        ] {
            assert_eq!(marker(value), None);
        }
        assert_eq!(marker("4294967294"), Some(u64::from(u32::MAX - 1)));
        assert_eq!(marker("4294967295"), None);
        assert_eq!(marker("4294967296"), None);
    }

    #[test]
    fn normal_provisioning_never_overwrites_unknown_reserved_state() {
        let uid = Uid::new(1000).unwrap();
        assert_eq!(
            validate_reserved_field(&SHADOW.replace(":42\n", ":\n"), uid, "alice", None, false),
            Ok(())
        );
        assert_eq!(
            validate_reserved_field(SHADOW, uid, "alice", Some(&sample()), false),
            Ok(())
        );
        assert_eq!(
            validate_reserved_field(SHADOW, uid, "alice", None, false),
            Err(AccountError::Unavailable)
        );
        assert_eq!(
            validate_reserved_field(SHADOW, uid, "alice", Some(&Registry::revoked()), false),
            Err(AccountError::Unavailable)
        );
        assert_eq!(
            validate_reserved_field(
                &SHADOW.replace(":42\n", ":43\n"),
                uid,
                "alice",
                Some(&sample()),
                false
            ),
            Err(AccountError::Unavailable)
        );
        assert_eq!(
            validate_reserved_field(SHADOW, uid, "alice", None, true),
            Ok(())
        );
    }

    #[test]
    fn mutation_clears_only_exact_managed_identity_and_leaves_foreign_fields_untouched() {
        let previous = Registry {
            bindings: vec![binding(1000, "alice", 42, 7), binding(1001, "bob", 43, 8)],
        };
        let passwd = format!("{PASSWD}bob:x:1001:1001::/home/bob:/bin/bash\n");
        let shadow = format!("{SHADOW}bob:!:20000::::::99\n");
        let clear = managed_markers_to_clear(&passwd, &shadow, &previous);
        assert_eq!(clear, vec![binding(1000, "alice", 0, 7)]);
        assert_eq!(
            &*shadow_with_markers(&shadow, &clear).unwrap(),
            shadow.replace(":42\n", ":\n").as_bytes()
        );
        let reused = passwd.replace("alice:x:1000:", "alice:x:1002:");
        assert!(managed_markers_to_clear(&reused, &shadow, &previous).is_empty());
        assert!(managed_markers_to_clear(&passwd, &shadow, &Registry::revoked()).is_empty());
        assert!(
            managed_markers_to_clear(&passwd, &SHADOW.replace(":42\n", ":123\n"), &previous)
                .is_empty()
        );
    }

    #[test]
    fn shadow_publication_crashes_are_atomic_and_retry_preserves_native_metadata() {
        for point in [
            ShadowBoundary::Created,
            ShadowBoundary::Metadata,
            ShadowBoundary::Written,
            ShadowBoundary::FileSynced,
            ShadowBoundary::Renamed,
            ShadowBoundary::DirectorySynced,
        ] {
            let fixture = Fixture::new();
            let path = fixture.path.join("shadow");
            let mut old = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&path)
                .unwrap();
            old.write_all(SHADOW.as_bytes()).unwrap();
            old.sync_all().unwrap();
            let m = old.metadata().unwrap();
            let updated = shadow_with_markers(SHADOW, &[binding(1000, "alice", 43, 8)]).unwrap();
            assert_eq!(
                replace_shadow(&fixture.directory, &old, &updated, m.uid(), m.gid(), |at| {
                    if at == point {
                        Err(AccountError::Unavailable)
                    } else {
                        Ok(())
                    }
                }),
                Err(AccountError::Unavailable)
            );
            let current = std::fs::read(&path).unwrap();
            assert!(current == SHADOW.as_bytes() || current == *updated);
            let actual = File::open(&path).unwrap();
            assert_eq!(
                actual.metadata().unwrap().mode() & 0o7777,
                m.mode() & 0o7777
            );
            assert_eq!(actual.metadata().unwrap().uid(), m.uid());
            assert_eq!(actual.metadata().unwrap().gid(), m.gid());
            replace_shadow(
                &fixture.directory,
                &actual,
                &updated,
                m.uid(),
                m.gid(),
                |_| Ok(()),
            )
            .unwrap();
            assert_eq!(std::fs::read(&path).unwrap(), *updated);
        }
    }

    #[test]
    fn shadow_replacement_refuses_unrecognized_metadata_without_discarding_it() {
        let fixture = Fixture::new();
        let path = fixture.path.join("shadow");
        let old = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .unwrap();
        (&old).write_all(SHADOW.as_bytes()).unwrap();
        let m = old.metadata().unwrap();
        rustix::fs::fsetxattr(
            &old,
            "user.localpin-fixture",
            b"keep",
            rustix::fs::XattrFlags::empty(),
        )
        .unwrap();
        assert_eq!(
            replace_shadow(
                &fixture.directory,
                &old,
                b"changed",
                m.uid(),
                m.gid(),
                |_| Ok(())
            ),
            Err(AccountError::Unavailable)
        );
        assert_eq!(std::fs::read(&path).unwrap(), SHADOW.as_bytes());
        rustix::fs::fremovexattr(&old, "user.localpin-fixture").unwrap();
        std::os::unix::fs::symlink("shadow", fixture.path.join(".localpin-shadow.pending"))
            .unwrap();
        assert_eq!(
            replace_shadow(
                &fixture.directory,
                &old,
                b"changed",
                m.uid(),
                m.gid(),
                |_| Ok(())
            ),
            Err(AccountError::Unavailable)
        );
        assert_eq!(std::fs::read(&path).unwrap(), SHADOW.as_bytes());
    }

    #[test]
    fn native_shared_ofd_lease_conflicts_with_posix_and_ofd_writers_and_survives_other_close() {
        if run_in_subprocess(
            "accounts::tests::native_shared_ofd_lease_conflicts_with_posix_and_ofd_writers_and_survives_other_close",
        ) {
            return;
        }
        let fixture = Fixture::new();
        let path = fixture.path.join("native-lock");
        let first = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .unwrap();
        let reader = std::fs::OpenOptions::new().read(true).open(&path).unwrap();
        native_database_lock(&reader, false).unwrap();
        let second_reader = File::open(&path).unwrap();
        native_database_lock(&second_reader, false).unwrap();
        drop(second_reader);
        drop(File::open(&path).unwrap());
        assert_eq!(native_database_lock(&first, true), Err(AccountError::Busy));
        assert!(rustix::fs::fcntl_lock(&first, FlockOperation::NonBlockingLockExclusive).is_err());
        drop(reader);
        native_database_lock(&first, true).unwrap();
        let other = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        assert_eq!(native_database_lock(&other, false), Err(AccountError::Busy));
        drop(first);
        rustix::fs::fcntl_lock(&other, FlockOperation::NonBlockingLockExclusive).unwrap();
        let reader = File::open(&path).unwrap();
        assert_eq!(
            native_database_lock(&reader, false),
            Err(AccountError::Busy)
        );
    }

    #[test]
    fn registry_publication_crashes_leave_only_original_or_complete_replacement() {
        let old = sample();
        let new = Registry {
            bindings: vec![binding(1000, "alice", 43, 8)],
        };
        for point in [
            RegistryBoundary::TempCreated,
            RegistryBoundary::Written,
            RegistryBoundary::FileSynced,
            RegistryBoundary::Renamed,
            RegistryBoundary::DirectorySynced,
        ] {
            let fixture = Fixture::new();
            fixture.replace(&old);
            assert_eq!(
                replace_registry(&fixture.directory, &new, fixture.owner, |at| {
                    if at == point {
                        Err(AccountError::Unavailable)
                    } else {
                        Ok(())
                    }
                }),
                Err(AccountError::Unavailable)
            );
            let read = fixture.read();
            assert!(read == old || read == new);
            fixture.replace(&Registry::revoked());
            assert_eq!(fixture.read(), Registry::revoked());
        }
    }

    #[test]
    fn unsafe_registry_temporary_or_gate_is_never_replaced() {
        let fixture = Fixture::new();
        fixture.replace(&sample());
        let pending = fixture.path.join(".pending");
        std::os::unix::fs::symlink("registry", &pending).unwrap();
        assert_eq!(
            replace_registry(
                &fixture.directory,
                &Registry::revoked(),
                fixture.owner,
                |_| Ok(())
            ),
            Err(AccountError::Unavailable)
        );
        assert_eq!(fixture.read(), sample());
        let group = fixture.directory.metadata().unwrap().gid();
        let gate = fixture.path.join("gate");
        std::fs::write(&gate, b"LPINT01\nactive\n").unwrap();
        std::fs::set_permissions(&gate, std::fs::Permissions::from_mode(0o666)).unwrap();
        assert_eq!(
            remove_gate(&fixture.directory, fixture.owner, group),
            Err(AccountError::Unavailable)
        );
        std::fs::set_permissions(&gate, std::fs::Permissions::from_mode(0o644)).unwrap();
        remove_gate(&fixture.directory, fixture.owner, group).unwrap();
        assert!(!gate.exists());
    }
    #[test]
    fn permanent_shared_lease_excludes_revocation_until_all_readers_drop() {
        if run_in_subprocess(
            "accounts::tests::permanent_shared_lease_excludes_revocation_until_all_readers_drop",
        ) {
            return;
        }
        let fixture = Fixture::new();
        let path = fixture.path.join("lock");
        let first = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .unwrap();
        let second = File::open(&path).unwrap();
        let admin = File::open(&path).unwrap();
        flock(&first, FlockOperation::NonBlockingLockShared).unwrap();
        flock(&second, FlockOperation::NonBlockingLockShared).unwrap();
        assert_eq!(
            flock(&admin, FlockOperation::NonBlockingLockExclusive),
            Err(rustix::io::Errno::WOULDBLOCK)
        );
        drop(first);
        assert_eq!(
            flock(&admin, FlockOperation::NonBlockingLockExclusive),
            Err(rustix::io::Errno::WOULDBLOCK)
        );
        drop(second);
        flock(&admin, FlockOperation::NonBlockingLockExclusive).unwrap();
    }

    #[test]
    fn tally_creation_crashes_leave_absent_or_fully_canonical_state() {
        for boundary in [
            TallyBoundary::Created,
            TallyBoundary::Owned,
            TallyBoundary::Canonical,
            TallyBoundary::FileSynced,
            TallyBoundary::Linked,
            TallyBoundary::DirectorySynced,
        ] {
            let fixture = Fixture::new();
            let gid = fixture.directory.metadata().unwrap().gid();
            assert_eq!(
                publish_tally(&fixture.directory, "fixture", fixture.owner, gid, |at| {
                    if at == boundary {
                        Err(AccountError::Unavailable)
                    } else {
                        Ok(())
                    }
                }),
                Err(AccountError::Unavailable)
            );
            let path = fixture.path.join("fixture");
            if matches!(
                boundary,
                TallyBoundary::Linked | TallyBoundary::DirectorySynced
            ) {
                let metadata = path.metadata().unwrap();
                assert_eq!(metadata.uid(), fixture.owner);
                assert_eq!(metadata.gid(), gid);
                assert_eq!(metadata.mode() & 0o7777, 0o660);
                assert_eq!(metadata.nlink(), 1);
                assert_eq!(metadata.len(), 0);
            } else {
                assert!(!path.exists());
                // No stale partial final path can prevent a privileged retry.
                publish_tally(
                    &fixture.directory,
                    "fixture",
                    fixture.owner,
                    gid,
                    |_| Ok(()),
                )
                .unwrap();
            }
        }
    }

    #[test]
    fn atomic_tally_publication_never_overwrites_password_accounting() {
        let fixture = Fixture::new();
        let gid = fixture.directory.metadata().unwrap().gid();
        let path = fixture.path.join("fixture");
        let file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o660)
            .open(&path)
            .unwrap();
        (&file).write_all(&[9; 64]).unwrap();
        file.sync_all().unwrap();
        let m = file.metadata().unwrap();
        let before = (
            m.dev(),
            m.ino(),
            m.len(),
            m.ctime(),
            m.ctime_nsec(),
            m.mode(),
            m.nlink(),
        );
        assert_eq!(
            publish_tally(
                &fixture.directory,
                "fixture",
                fixture.owner,
                gid,
                |_| Ok(())
            ),
            Err(AccountError::Unavailable)
        );
        assert_eq!(std::fs::read(&path).unwrap(), [9; 64]);
        assert_eq!(
            {
                let m = file.metadata().unwrap();
                (
                    m.dev(),
                    m.ino(),
                    m.len(),
                    m.ctime(),
                    m.ctime_nsec(),
                    m.mode(),
                    m.nlink(),
                )
            },
            before
        );
    }
}
