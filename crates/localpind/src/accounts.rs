//! Enforcing lifecycle for an explicitly opted-in immutable Fedora appliance.
//!
//! The global shared lease is retained by each authority object through broker
//! delivery. Root administration first takes the exclusive lease and durably
//! revokes every incarnation, then clears immutable flags. Ordinary unmanaged
//! Unix accounts never acquire an incarnation from this module.

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
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

const REGISTRY_ROOT: &str = "/var/lib/localpin-accounts";
const STORAGE_ROOT: &str = "/var/lib/localpin";
const MAGIC: &[u8; 8] = b"LPACCT02";
const MAX_REGISTRY: usize = 16 * 1024;
const MAX_INPUT: u64 = 64 * 1024;
const MAX_ACCOUNTS: usize = 128;
const CACHE_MAGIC: &[u8; 8] = b"LPACCH01";
const CACHE_JOURNAL: &str = "cache-window";
const CACHE_PENDING: &str = "cache-window.pending";
const MAX_CACHE_JOURNAL: usize = 2 * MAX_REGISTRY + 16;
const DIRECTORIES: &[&str] = &["/etc", "/etc/pam.d", "/etc/authselect", "/etc/security"];
const FILES: &[&str] = &[
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
const LINKS: &[(&str, &str)] = &[
    ("/etc/pam.d/password-auth", "/etc/authselect/password-auth"),
    ("/etc/pam.d/postlogin", "/etc/authselect/postlogin"),
    ("/etc/nsswitch.conf", "/etc/authselect/nsswitch.conf"),
];

/// Sanitized root administration failure. No account hashes or names are shown.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AccountError {
    /// Root credentials are required.
    Privilege,
    /// A lease is held, or a protected input still has a writable reference.
    Busy,
    /// Required state, paths, immutable flags or filesystem support is missing.
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
        Registry::decode(&bytes)
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
struct Snapshot {
    dev: u64,
    ino: u64,
    size: u64,
    ctime: i64,
    nanos: i64,
    mode: u32,
    links: u64,
    digest: [u8; 32],
}

impl Snapshot {
    fn metadata(m: &std::fs::Metadata, digest: [u8; 32]) -> Self {
        Self {
            dev: m.dev(),
            ino: m.ino(),
            size: m.len(),
            ctime: m.ctime(),
            nanos: m.ctime_nsec(),
            mode: m.mode(),
            links: m.nlink(),
            digest,
        }
    }

    fn encode(&self, out: &mut Vec<u8>) {
        for n in [
            self.dev,
            self.ino,
            self.size,
            self.ctime as u64,
            self.nanos as u64,
        ] {
            out.extend_from_slice(&n.to_be_bytes());
        }
        out.extend_from_slice(&self.mode.to_be_bytes());
        out.extend_from_slice(&self.links.to_be_bytes());
        out.extend_from_slice(&self.digest);
    }
    fn decode(input: &mut &[u8]) -> Result<Self> {
        Ok(Self {
            dev: number(input)?,
            ino: number(input)?,
            size: number(input)?,
            ctime: number(input)? as i64,
            nanos: number(input)? as i64,
            mode: u32::from_be_bytes(take(input)?),
            links: number(input)?,
            digest: take(input)?,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Registry {
    inputs: Vec<Snapshot>,
    accounts: Vec<AccountId>,
}
impl Registry {
    fn revoked() -> Self {
        Self {
            inputs: Vec::new(),
            accounts: Vec::new(),
        }
    }
    fn active(&self) -> bool {
        !self.inputs.is_empty()
    }
    fn encode(&self) -> Vec<u8> {
        let mut out = MAGIC.to_vec();
        out.extend_from_slice(&(self.inputs.len() as u16).to_be_bytes());
        for snapshot in &self.inputs {
            snapshot.encode(&mut out);
        }
        out.extend_from_slice(&(self.accounts.len() as u16).to_be_bytes());
        for account in &self.accounts {
            out.extend_from_slice(&account.uid.get().to_be_bytes());
            out.extend_from_slice(&account.incarnation.get());
        }
        out
    }
    fn decode(mut input: &[u8]) -> Result<Self> {
        if take::<8>(&mut input)? != *MAGIC {
            return Err(AccountError::Invalid);
        }
        let count = u16::from_be_bytes(take(&mut input)?) as usize;
        if count != 0 && count != DIRECTORIES.len() + FILES.len() + LINKS.len() {
            return Err(AccountError::Invalid);
        }
        let inputs = (0..count)
            .map(|_| Snapshot::decode(&mut input))
            .collect::<Result<Vec<_>>>()?;
        let count = u16::from_be_bytes(take(&mut input)?) as usize;
        if count > MAX_ACCOUNTS || (inputs.is_empty() && count != 0) {
            return Err(AccountError::Invalid);
        }
        let mut accounts = Vec::new();
        let mut seen = BTreeSet::new();
        for _ in 0..count {
            let uid = u32::from_be_bytes(take(&mut input)?);
            if !seen.insert(uid) {
                return Err(AccountError::Invalid);
            }
            accounts.push(AccountId {
                uid: Uid::new(uid).map_err(|_| AccountError::Invalid)?,
                incarnation: Incarnation::new(take(&mut input)?)
                    .map_err(|_| AccountError::Invalid)?,
            });
        }
        if !input.is_empty() {
            return Err(AccountError::Invalid);
        }
        Ok(Self { inputs, accounts })
    }
}
fn take<const N: usize>(input: &mut &[u8]) -> Result<[u8; N]> {
    let (head, rest) = input.split_at_checked(N).ok_or(AccountError::Invalid)?;
    *input = rest;
    head.try_into().map_err(|_| AccountError::Invalid)
}
fn number(input: &mut &[u8]) -> Result<u64> {
    Ok(u64::from_be_bytes(take(input)?))
}

fn input_snapshot() -> Result<Vec<Snapshot>> {
    input_snapshot_for_cache(false)
}

fn input_snapshot_for_cache(allow_etc_unfrozen: bool) -> Result<Vec<Snapshot>> {
    let mut output = Vec::new();
    for (path, directory) in DIRECTORIES
        .iter()
        .map(|p| (*p, true))
        .chain(FILES.iter().map(|p| (*p, false)))
    {
        let file = fixed_open(
            path,
            OFlags::RDONLY
                | if directory {
                    OFlags::DIRECTORY
                } else {
                    OFlags::empty()
                },
        )?;
        let before = file.metadata()?;
        if before.gid() != 0
            || (!directory && (!before.is_file() || before.nlink() != 1))
            || before.mode() & 0o022 != 0
        {
            return Err(AccountError::Unavailable);
        }
        // Only the enforcing guest's Btrfs filesystem is in this domain.
        let filesystem = rustix::fs::fstatfs(&file)?.f_type as u64;
        let frozen = ioctl_getflags(&file)?.contains(IFlags::IMMUTABLE);
        if filesystem != 0x9123_683e || (!frozen && !(allow_etc_unfrozen && path == "/etc")) {
            return Err(AccountError::Unavailable);
        }
        let digest = if directory {
            [0; 32]
        } else {
            if before.len() > MAX_INPUT {
                return Err(AccountError::Unavailable);
            }
            let mut bytes = Zeroizing::new(Vec::new());
            (&file).take(MAX_INPUT + 1).read_to_end(&mut bytes)?;
            if bytes.len() as u64 > MAX_INPUT {
                return Err(AccountError::Unavailable);
            }
            Sha256::digest(&*bytes).into()
        };
        let snapshot = Snapshot::metadata(&before, digest);
        if Snapshot::metadata(&file.metadata()?, digest) != snapshot
            || ioctl_getflags(&file)?.contains(IFlags::IMMUTABLE) != frozen
        {
            return Err(AccountError::Unavailable);
        }
        output.push(snapshot);
    }
    for (path, expected) in LINKS {
        let (parent, name) = path.rsplit_once('/').ok_or(AccountError::Invalid)?;
        let dir = fixed_open(parent, OFlags::RDONLY | OFlags::DIRECTORY)?;
        let link = rustix::fs::statat(&dir, name, AtFlags::SYMLINK_NOFOLLOW)?;
        let target = rustix::fs::readlinkat(&dir, name, Vec::new())?;
        if target.to_bytes() != expected.as_bytes()
            || link.st_uid != 0
            || link.st_gid != 0
            || link.st_nlink != 1
        {
            return Err(AccountError::Unavailable);
        }
        let m = std::fs::symlink_metadata(path)?;
        if !m.file_type().is_symlink() {
            return Err(AccountError::Unavailable);
        }
        output.push(Snapshot::metadata(
            &m,
            Sha256::digest(target.to_bytes()).into(),
        ));
    }
    Ok(output)
}

// The only refreshable authority bytes are /etc's size and ctime fields.
// Identity, mode, link count and digest remain exact, as does every other input.
fn cache_inputs_match(original: &[Snapshot], current: &[Snapshot]) -> bool {
    if original.len() != DIRECTORIES.len() + FILES.len() + LINKS.len()
        || current.len() != original.len()
    {
        return false;
    }
    let mut first = original[0].clone();
    first.size = current[0].size;
    first.ctime = current[0].ctime;
    first.nanos = current[0].nanos;
    first == current[0] && original[1..] == current[1..]
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CacheWindow {
    original: Registry,
    restored: Option<Registry>,
}

impl CacheWindow {
    fn validate(&self) -> Result<()> {
        if !self.original.active() || self.original.accounts.is_empty() {
            return Err(AccountError::Invalid);
        }
        if let Some(restored) = &self.restored
            && (restored.accounts != self.original.accounts
                || !cache_inputs_match(&self.original.inputs, &restored.inputs))
        {
            return Err(AccountError::Invalid);
        }
        Ok(())
    }

    fn encode(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let original = self.original.encode();
        let restored = self
            .restored
            .as_ref()
            .map(Registry::encode)
            .unwrap_or_default();
        if original.len() > MAX_REGISTRY || restored.len() > MAX_REGISTRY {
            return Err(AccountError::Invalid);
        }
        let mut bytes = CACHE_MAGIC.to_vec();
        for value in [original, restored] {
            bytes.extend_from_slice(&(value.len() as u32).to_be_bytes());
            bytes.extend_from_slice(&value);
        }
        Ok(bytes)
    }

    fn decode(mut bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_CACHE_JOURNAL || take::<8>(&mut bytes)? != *CACHE_MAGIC {
            return Err(AccountError::Invalid);
        }
        let original = Self::registry(&mut bytes)?.ok_or(AccountError::Invalid)?;
        let restored = Self::registry(&mut bytes)?;
        if !bytes.is_empty() {
            return Err(AccountError::Invalid);
        }
        let value = Self { original, restored };
        value.validate()?;
        Ok(value)
    }

    fn registry(bytes: &mut &[u8]) -> Result<Option<Registry>> {
        let length = u32::from_be_bytes(take(bytes)?) as usize;
        if length > MAX_REGISTRY {
            return Err(AccountError::Invalid);
        }
        let (value, rest) = bytes
            .split_at_checked(length)
            .ok_or(AccountError::Invalid)?;
        *bytes = rest;
        if length == 0 {
            Ok(None)
        } else {
            Registry::decode(value).map(Some)
        }
    }
}

fn read_cache_window(directory: &File, owner: u32) -> Result<Option<CacheWindow>> {
    match rustix::fs::statat(directory, CACHE_JOURNAL, AtFlags::SYMLINK_NOFOLLOW) {
        Err(rustix::io::Errno::NOENT) => return Ok(None),
        Err(error) => return Err(error.into()),
        Ok(_) => {}
    }
    let file = child(directory, CACHE_JOURNAL, OFlags::RDONLY, Mode::empty())?;
    safe_record_owned(&file, owner)?;
    let before = Snapshot::metadata(&file.metadata()?, [0; 32]);
    if before.size > MAX_CACHE_JOURNAL as u64 {
        return Err(AccountError::Invalid);
    }
    let mut bytes = Zeroizing::new(Vec::new());
    (&file)
        .take(MAX_CACHE_JOURNAL as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > MAX_CACHE_JOURNAL || Snapshot::metadata(&file.metadata()?, [0; 32]) != before {
        return Err(AccountError::Unavailable);
    }
    file.sync_all()?;
    directory.sync_all()?;
    CacheWindow::decode(&bytes).map(Some)
}

fn remove_cache_record(directory: &File, name: &str, owner: u32) -> Result<()> {
    match rustix::fs::statat(directory, name, AtFlags::SYMLINK_NOFOLLOW) {
        Err(rustix::io::Errno::NOENT) => return Ok(()),
        Err(error) => return Err(error.into()),
        Ok(_) => {}
    }
    let file = child(directory, name, OFlags::RDONLY, Mode::empty())?;
    safe_record_owned(&file, owner)?;
    rustix::fs::unlinkat(directory, name, AtFlags::empty())?;
    Ok(())
}

fn discard_cache_window(directory: &File, owner: u32) -> Result<()> {
    remove_cache_record(directory, CACHE_JOURNAL, owner)?;
    remove_cache_record(directory, CACHE_PENDING, owner)?;
    directory.sync_all()?;
    Ok(())
}

fn write_cache_window(
    directory: &File,
    window: &CacheWindow,
    owner: u32,
    mut fault: impl FnMut(RegistryBoundary) -> Result<()>,
) -> Result<()> {
    let bytes = window.encode()?;
    if let Some(old) = read_cache_window(directory, owner)?
        && (old.original != window.original || (old.restored.is_some() && old != *window))
    {
        return Err(AccountError::Unavailable);
    }
    remove_cache_record(directory, CACHE_PENDING, owner)?;
    let mut file = child(
        directory,
        CACHE_PENDING,
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL,
        Mode::RUSR | Mode::WUSR,
    )?;
    safe_record_owned(&file, owner)?;
    fault(RegistryBoundary::TempCreated)?;
    file.write_all(&bytes)?;
    fault(RegistryBoundary::Written)?;
    file.sync_all()?;
    fault(RegistryBoundary::FileSynced)?;
    rustix::fs::renameat(directory, CACHE_PENDING, directory, CACHE_JOURNAL)?;
    fault(RegistryBoundary::Renamed)?;
    directory.sync_all()?;
    fault(RegistryBoundary::DirectorySynced)?;
    Ok(())
}

fn validate_cache_finish(
    live: &Registry,
    window: Option<&CacheWindow>,
    inputs: &[Snapshot],
) -> Result<()> {
    let valid = match window {
        None => live.active() && live.inputs == inputs,
        Some(CacheWindow {
            restored: Some(restored),
            ..
        }) => (!live.active() || live == restored) && restored.inputs == inputs,
        Some(window) => !live.active() && cache_inputs_match(&window.original.inputs, inputs),
    };
    if valid {
        Ok(())
    } else {
        Err(AccountError::Unavailable)
    }
}

/// Production lifecycle reader retaining a shared mutation lease until dropped.
pub struct SystemLifecycle {
    lease: Lease,
}
impl SystemLifecycle {
    /// Acquire the fixed root-owned registry and a nonblocking shared lease.
    /// Missing, corrupt, revoked or unsupported state never creates identity.
    pub fn open() -> std::result::Result<Self, LifecycleError> {
        let lease = Lease::open(false, false).map_err(|_| LifecycleError::Unavailable)?;
        let authority = Self { lease };
        authority
            .validate()
            .map_err(|_| LifecycleError::Unavailable)?;
        Ok(authority)
    }
    fn validate(&self) -> Result<Registry> {
        let registry = self.lease.read()?;
        if !registry.active() || registry.inputs != input_snapshot()? {
            return Err(AccountError::Unavailable);
        }
        Ok(registry)
    }
}
impl LifecycleAuthority for SystemLifecycle {
    fn current_incarnation(
        &mut self,
        uid: Uid,
    ) -> std::result::Result<Incarnation, LifecycleError> {
        self.validate()
            .map_err(|_| LifecycleError::Unavailable)?
            .accounts
            .iter()
            .find(|a| a.uid == uid)
            .map(|a| a.incarnation)
            .ok_or(LifecycleError::Unsupported)
    }
}

fn root_required() -> Result<()> {
    if rustix::process::getuid().as_raw() != 0 || rustix::process::geteuid().as_raw() != 0 {
        Err(AccountError::Privilege)
    } else {
        Ok(())
    }
}

fn password_database_lock() -> Result<File> {
    let directory = fixed_open("/etc", OFlags::RDONLY | OFlags::DIRECTORY)?;
    let file = match child(
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
    };
    safe_record(&file)?;
    let actual = child(&directory, ".pwd.lock", OFlags::RDONLY, Mode::empty())?.metadata()?;
    let held = file.metadata()?;
    if actual.dev() != held.dev() || actual.ino() != held.ino() {
        return Err(AccountError::Unavailable);
    }
    // Same whole-file POSIX write lock used by glibc lckpwdf/shadow-utils.
    // Do not open/close another descriptor for this inode after acquisition:
    // POSIX record locks are process-associated and any such close releases it.
    rustix::fs::fcntl_lock(&file, FlockOperation::NonBlockingLockExclusive)?;
    Ok(file)
}

fn set_frozen(frozen: bool) -> Result<()> {
    // All fixed paths are opened without symlinks. Link targets above are the
    // pinned real authselect files, never followed from an arbitrary link.
    for path in FILES.iter().chain(DIRECTORIES.iter().rev()) {
        let file = fixed_open(path, OFlags::RDONLY)?;
        let mut flags = ioctl_getflags(&file)?;
        flags.set(IFlags::IMMUTABLE, frozen);
        ioctl_setflags(&file, flags)?;
        file.sync_all()?;
        if ioctl_getflags(&file)?.contains(IFlags::IMMUTABLE) != frozen {
            return Err(AccountError::Unavailable);
        }
    }
    Ok(())
}

/// A short-lived kernel proof that protected inodes have no existing writer.
///
/// Immutable flags prevent later write opens; they do not invalidate an already
/// writable descriptor. Linux read leases reject such descriptors and writable
/// shared mappings, including mappings retaining a file after its descriptor
/// was closed. Hold every lease until active registry publication is durable.
struct WriterBarrier {
    files: Vec<File>,
}

impl WriterBarrier {
    fn acquire() -> Result<Self> {
        let mut files = Vec::with_capacity(FILES.len());
        for path in FILES {
            let file = fixed_open(path, OFlags::RDONLY)?;
            if !ioctl_getflags(&file)?.contains(IFlags::IMMUTABLE) {
                return Err(AccountError::Unavailable);
            }
            kernel_read_lease(&file, true)?;
            files.push(file);
        }
        let barrier = Self { files };
        barrier.validate()?;
        Ok(barrier)
    }

    fn validate(&self) -> Result<()> {
        if self.files.len() != FILES.len() {
            return Err(AccountError::Unavailable);
        }
        for file in &self.files {
            kernel_read_lease(file, false)?;
            if !ioctl_getflags(file)?.contains(IFlags::IMMUTABLE) {
                return Err(AccountError::Unavailable);
            }
        }
        Ok(())
    }
}

/// Tiny native boundary for Linux file leases, absent from rustix's safe API.
/// No pointer, borrowed data, ownership transfer or caller-chosen command enters
/// this ABI: fcntl receives only a live borrowed descriptor and integer constants.
#[allow(unsafe_code)]
fn kernel_read_lease(file: &File, acquire: bool) -> Result<()> {
    let command = if acquire {
        libc::F_SETLEASE
    } else {
        libc::F_GETLEASE
    };
    // SAFETY: the File remains borrowed through the call; both commands accept
    // an integer third argument (F_GETLEASE ignores it), never a memory pointer.
    let value = unsafe { libc::fcntl(file.as_raw_fd(), command, libc::F_RDLCK) };
    if value < 0 {
        let error = std::io::Error::last_os_error();
        return Err(if error.raw_os_error() == Some(libc::EAGAIN) {
            AccountError::Busy
        } else {
            AccountError::Unavailable
        });
    }
    if (!acquire && value != libc::F_RDLCK) || (acquire && value != 0) {
        return Err(AccountError::Unavailable);
    }
    Ok(())
}

fn cache_storage_guard() -> Result<localpin_storage::Storage> {
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

fn set_cache_directory_frozen(frozen: bool) -> Result<()> {
    let file = fixed_open("/etc", OFlags::RDONLY | OFlags::DIRECTORY)?;
    let mut flags = ioctl_getflags(&file)?;
    if flags.contains(IFlags::IMMUTABLE) != frozen {
        flags.set(IFlags::IMMUTABLE, frozen);
        ioctl_setflags(&file, flags)?;
        file.sync_all()?;
    }
    if ioctl_getflags(&file)?.contains(IFlags::IMMUTABLE) != frozen {
        return Err(AccountError::Unavailable);
    }
    Ok(())
}

fn cache_operation(operation: impl FnOnce(&Lease) -> Result<()>) -> Result<()> {
    root_required()?;
    let lease = Lease::open(true, false)?;
    let result = (|| {
        close_desktop_gate()?;
        let _storage = cache_storage_guard()?;
        operation(&lease)
    })();
    if result.is_err() {
        // An interrupted or refused cache operation cannot leave old identity
        // available. Preserve the safe journal for retry or fresh recovery.
        lease.write(&Registry::revoked())?;
    }
    result
}

/// Suspend an exact active domain while only /etc permits package cache edits.
///
/// The broker must be stopped. Protected regular inputs and all other directory
/// immutable flags remain set; the same incarnations are retained only in the
/// bounded durable cache journal. No caller-selected path or program is run.
pub fn cache_window_begin() -> Result<()> {
    cache_operation(|lease| {
        let live = lease.read()?;
        let old = read_cache_window(&lease.directory, 0)?;
        let original = match old {
            Some(window) if window.restored.is_none() => {
                if live.active() && live != window.original {
                    return Err(AccountError::Unavailable);
                }
                window.original
            }
            Some(_) => return Err(AccountError::Unavailable),
            None if live.active() && !live.accounts.is_empty() => live.clone(),
            None => return Err(AccountError::Unavailable),
        };
        let inputs = if live.active() {
            input_snapshot()?
        } else {
            input_snapshot_for_cache(true)?
        };
        if (live.active() && live.inputs != inputs)
            || !cache_inputs_match(&original.inputs, &inputs)
        {
            return Err(AccountError::Unavailable);
        }
        let writers = WriterBarrier::acquire()?;
        write_cache_window(
            &lease.directory,
            &CacheWindow {
                original,
                restored: None,
            },
            0,
            |_| Ok(()),
        )?;
        // The exact source is durable before either revocation or unfreezing.
        lease.write(&Registry::revoked())?;
        writers.validate()?;
        set_cache_directory_frozen(false)
    })
}

/// Refreeze /etc and restore only the journal's unchanged account incarnations.
///
/// Only /etc size/ctime may be refreshed. A durable exact final-registry witness
/// precedes publication so interrupted completion never adopts new metadata.
/// Repeating a completed finish validates the already-active full snapshot.
pub fn cache_window_finish() -> Result<()> {
    cache_operation(|lease| {
        let live = lease.read()?;
        let pending = read_cache_window(&lease.directory, 0)?;
        let inputs = if pending.as_ref().is_some_and(|w| w.restored.is_none()) {
            input_snapshot_for_cache(true)?
        } else {
            input_snapshot()?
        };
        validate_cache_finish(&live, pending.as_ref(), &inputs)?;
        let Some(mut window) = pending else {
            // No authority is reconstructed on this idempotent completion.
            return Ok(());
        };
        let writers = WriterBarrier::acquire()?;
        let restored = match window.restored.clone() {
            Some(restored) => restored,
            None => {
                set_cache_directory_frozen(true)?;
                let inputs = input_snapshot()?;
                if !cache_inputs_match(&window.original.inputs, &inputs) {
                    return Err(AccountError::Unavailable);
                }
                let restored = Registry {
                    inputs,
                    accounts: window.original.accounts.clone(),
                };
                window.restored = Some(restored.clone());
                write_cache_window(&lease.directory, &window, 0, |_| Ok(()))?;
                restored
            }
        };
        lease.write_checked(&restored, || {
            writers.validate()?;
            if restored.inputs != input_snapshot()? {
                return Err(AccountError::Unavailable);
            }
            Ok(())
        })?;
        discard_cache_window(&lease.directory, 0)
    })
}

/// Durably revoke all accounts before allowing any supported account mutation.
///
/// A crash leaves a revoked registry even if only some immutable flags cleared.
/// This command does not run arbitrary programs or authorize integration edits.
pub fn begin_mutation() -> Result<()> {
    root_required()?;
    let lease = Lease::open(true, true)?;
    close_desktop_gate()?;
    lease.write(&Registry::revoked())?;
    discard_cache_window(&lease.directory, 0)?;
    let _password_database_lock = password_database_lock()?;
    set_frozen(false)
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
            .find(|a| a.uid == uid)
            .map(|a| a.incarnation)
            .ok_or(LifecycleError::Unsupported)
    }
}

/// Seal policy/account files and provision fresh disabled account incarnations.
///
/// The broker must be stopped. Every invocation first revokes old incarnations;
/// interrupted provisioning is recovered only by this privileged operation with
/// fresh randomness. Old storage is quarantined, never repaired for an own user.
pub fn seal(uids: &[Uid]) -> Result<()> {
    root_required()?;
    if uids.is_empty() || uids.len() > MAX_ACCOUNTS {
        return Err(AccountError::Invalid);
    }
    let unique: BTreeSet<_> = uids.iter().map(|uid| uid.get()).collect();
    if unique.len() != uids.len() {
        return Err(AccountError::Invalid);
    }
    let lease = Lease::open(true, true)?;
    close_desktop_gate()?;
    lease.write(&Registry::revoked())?;
    discard_cache_window(&lease.directory, 0)?;
    let _password_database_lock = password_database_lock()?;
    set_frozen(true)?;
    let writers = WriterBarrier::acquire()?;
    let inputs = input_snapshot()?;
    // Local source proof is deliberately independent of NSS resolution. The
    // password-free eligibility authority additionally checks its exact policy.
    let passwd = read_input("/etc/passwd")?;
    let shadow = read_input("/etc/shadow")?;
    let passwd = std::str::from_utf8(&passwd).map_err(|_| AccountError::Invalid)?;
    let shadow = std::str::from_utf8(&shadow).map_err(|_| AccountError::Invalid)?;
    let faillock = read_input("/etc/security/faillock.conf")?;
    let tally_directory =
        localpin_auth::reviewed_faillock_directory(&faillock).ok_or(AccountError::Unavailable)?;
    for uid in uids {
        let name = validate_local_account(passwd, shadow, *uid)?;
        provision_missing_tally(tally_directory, *uid, &name)?;
    }
    let mut storage = localpin_storage::Storage::open(fixed_open(
        STORAGE_ROOT,
        OFlags::RDONLY | OFlags::DIRECTORY,
    )?)
    .map_err(|e| {
        if e == localpin_storage::Error::Busy {
            AccountError::Busy
        } else {
            AccountError::Unavailable
        }
    })?;
    let mut accounts = Vec::new();
    for uid in uids {
        let mut bytes = [0; 16];
        getrandom::fill(&mut bytes).map_err(|_| AccountError::Unavailable)?;
        accounts.push(AccountId {
            uid: *uid,
            incarnation: Incarnation::new(bytes).map_err(|_| AccountError::Unavailable)?,
        });
    }
    let mut authority = ProvisionAuthority {
        accounts: accounts.clone(),
    };
    let mut clock = crate::BootClock::new().map_err(|_| AccountError::Unavailable)?;
    for account in &accounts {
        storage
            .reprovision(
                *account,
                clock.now().map_err(|_| AccountError::Unavailable)?,
                &mut authority,
            )
            .map_err(|_| AccountError::Unavailable)?;
    }
    if inputs != input_snapshot()? {
        return Err(AccountError::Unavailable);
    }
    let registry = Registry { inputs, accounts };
    lease.write_checked(&registry, || {
        writers.validate()?;
        if registry.inputs != input_snapshot()? {
            return Err(AccountError::Unavailable);
        }
        Ok(())
    })
}

fn read_input(path: &str) -> Result<Zeroizing<Vec<u8>>> {
    let file = fixed_open(path, OFlags::RDONLY)?;
    let mut bytes = Zeroizing::new(Vec::new());
    file.take(MAX_INPUT + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_INPUT {
        return Err(AccountError::Unavailable);
    }
    Ok(bytes)
}

fn validate_local_account(passwd: &str, shadow: &str, uid: Uid) -> Result<String> {
    let matches = passwd
        .lines()
        .filter_map(|line| {
            let fields: Vec<_> = line.split(':').collect();
            (fields.len() == 7 && fields[2].parse::<u32>() == Ok(uid.get())).then_some(fields)
        })
        .collect::<Vec<_>>();
    if matches.len() != 1 {
        return Err(AccountError::Invalid);
    }
    let entry = &matches[0];
    if entry[0].is_empty()
        || entry[0].len() > 32
        || !entry[0]
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
        || entry[1] != "x"
        || !entry[5].starts_with('/')
        || entry[3].parse::<u32>().is_err()
    {
        return Err(AccountError::Invalid);
    }
    if passwd
        .lines()
        .filter(|line| line.split(':').next() == Some(entry[0]))
        .count()
        != 1
        || shadow
            .lines()
            .filter(|line| {
                let fields: Vec<_> = line.split(':').collect();
                fields.len() == 9 && fields[0] == entry[0]
            })
            .count()
            != 1
    {
        return Err(AccountError::Invalid);
    }
    Ok(entry[0].to_owned())
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

/// Report whether the fixed production authority can establish a supported UID.
pub fn supported(uid: Uid) -> bool {
    SystemLifecycle::open()
        .and_then(|mut a| a.current_incarnation(uid))
        .is_ok()
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
                "localpin-account-registry-{}-{}",
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

    #[test]
    fn lifecycle_administration_removes_only_a_safe_gate_and_never_reopens_it() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        let fixture = Fixture::new();
        let group = fixture.directory.metadata().unwrap().gid();
        let gate = fixture.path.join("gate");
        remove_gate(&fixture.directory, fixture.owner, group).unwrap();
        assert!(!gate.exists());
        std::fs::write(&gate, b"LPINT01\nactive\n").unwrap();
        std::fs::set_permissions(&gate, std::fs::Permissions::from_mode(0o644)).unwrap();
        remove_gate(&fixture.directory, fixture.owner, group).unwrap();
        assert!(!gate.exists());
        std::fs::write(&gate, b"LPINT01\nactive\n").unwrap();
        std::fs::set_permissions(&gate, std::fs::Permissions::from_mode(0o666)).unwrap();
        assert_eq!(
            remove_gate(&fixture.directory, fixture.owner, group),
            Err(AccountError::Unavailable)
        );
        std::fs::set_permissions(&gate, std::fs::Permissions::from_mode(0o644)).unwrap();
        std::fs::hard_link(&gate, fixture.path.join("other")).unwrap();
        assert_eq!(
            remove_gate(&fixture.directory, fixture.owner, group),
            Err(AccountError::Unavailable)
        );
        std::fs::remove_file(&gate).unwrap();
        symlink("other", &gate).unwrap();
        assert_eq!(
            remove_gate(&fixture.directory, fixture.owner, group),
            Err(AccountError::Unavailable)
        );
        assert_eq!(
            std::fs::read(fixture.path.join("other")).unwrap(),
            b"LPINT01\nactive\n"
        );
    }
    fn account(uid: u32, incarnation: u8) -> AccountId {
        AccountId {
            uid: Uid::new(uid).unwrap(),
            incarnation: Incarnation::new([incarnation; 16]).unwrap(),
        }
    }
    fn sample() -> Registry {
        Registry {
            inputs: vec![
                Snapshot {
                    dev: 1,
                    ino: 2,
                    size: 3,
                    ctime: 4,
                    nanos: 5,
                    mode: 0o100600,
                    links: 1,
                    digest: [6; 32]
                };
                DIRECTORIES.len() + FILES.len() + LINKS.len()
            ],
            accounts: vec![account(1000, 1), account(1001, 2)],
        }
    }

    fn cache_sample() -> Registry {
        let mut original = sample();
        original.inputs[0].mode = 0o040755;
        original.inputs[0].links = 2;
        original.inputs[0].digest = [0; 32];
        original
    }

    fn cache_ready(original: &Registry) -> CacheWindow {
        let mut restored = original.clone();
        restored.inputs[0].size += 32;
        restored.inputs[0].ctime += 1;
        restored.inputs[0].nanos += 1;
        CacheWindow {
            original: original.clone(),
            restored: Some(restored),
        }
    }

    #[test]
    fn cache_window_refresh_is_exactly_three_etc_metadata_fields() {
        let original = cache_sample();
        type Mutation = (fn(&mut Snapshot), bool);
        let mutations: [Mutation; 8] = [
            (|s| s.dev += 1, false),
            (|s| s.ino += 1, false),
            (|s| s.size += 1, true),
            (|s| s.ctime += 1, true),
            (|s| s.nanos += 1, true),
            (|s| s.mode ^= 1, false),
            (|s| s.links += 1, false),
            (|s| s.digest[0] ^= 1, false),
        ];
        for position in 0..original.inputs.len() {
            for (change, allowed_on_etc) in mutations {
                let mut inputs = original.inputs.clone();
                change(&mut inputs[position]);
                assert_eq!(
                    cache_inputs_match(&original.inputs, &inputs),
                    position == 0 && allowed_on_etc
                );
            }
        }
        assert!(!cache_inputs_match(&original.inputs, &original.inputs[1..]));
        assert_eq!(original.inputs.len(), 20);
        let encoded = original.encode();
        let ready = cache_ready(&original).restored.unwrap().encode();
        assert_eq!(&encoded[..26], &ready[..26]);
        assert_eq!(&encoded[50..], &ready[50..]);
    }

    #[test]
    fn cache_window_journal_is_versioned_bounded_and_cannot_change_accounts() {
        let original = cache_sample();
        for window in [
            CacheWindow {
                original: original.clone(),
                restored: None,
            },
            cache_ready(&original),
        ] {
            let encoded = window.encode().unwrap();
            assert_eq!(CacheWindow::decode(&encoded).unwrap(), window);
            for boundary in 0..encoded.len() {
                assert!(CacheWindow::decode(&encoded[..boundary]).is_err());
            }
            let mut trailing = encoded.clone();
            trailing.push(0);
            assert!(CacheWindow::decode(&trailing).is_err());
            let mut oversized = encoded;
            oversized[8..12].copy_from_slice(&((MAX_REGISTRY + 1) as u32).to_be_bytes());
            assert!(CacheWindow::decode(&oversized).is_err());
        }
        let mut bad = cache_ready(&original);
        bad.restored.as_mut().unwrap().accounts[0] = account(1000, 9);
        assert_eq!(bad.encode(), Err(AccountError::Invalid));
        let mut bad = cache_ready(&original);
        bad.restored.as_mut().unwrap().inputs[1].ctime += 1;
        assert_eq!(bad.encode(), Err(AccountError::Invalid));
        assert!(
            CacheWindow {
                original: Registry::revoked(),
                restored: None
            }
            .encode()
            .is_err()
        );
    }

    #[test]
    fn cache_window_atomic_checkpoint_crashes_keep_only_old_or_complete_witness() {
        for boundary in [
            RegistryBoundary::TempCreated,
            RegistryBoundary::Written,
            RegistryBoundary::FileSynced,
            RegistryBoundary::Renamed,
            RegistryBoundary::DirectorySynced,
        ] {
            let fixture = Fixture::new();
            let original = cache_sample();
            let pending = CacheWindow {
                original: original.clone(),
                restored: None,
            };
            let ready = cache_ready(&original);
            write_cache_window(&fixture.directory, &pending, fixture.owner, |_| Ok(())).unwrap();
            assert_eq!(
                write_cache_window(&fixture.directory, &ready, fixture.owner, |at| {
                    if at == boundary {
                        Err(AccountError::Unavailable)
                    } else {
                        Ok(())
                    }
                }),
                Err(AccountError::Unavailable)
            );
            let visible = read_cache_window(&fixture.directory, fixture.owner)
                .unwrap()
                .unwrap();
            assert_eq!(
                visible,
                if matches!(
                    boundary,
                    RegistryBoundary::Renamed | RegistryBoundary::DirectorySynced
                ) {
                    ready.clone()
                } else {
                    pending.clone()
                }
            );
            write_cache_window(&fixture.directory, &ready, fixture.owner, |_| Ok(())).unwrap();
            assert_eq!(
                read_cache_window(&fixture.directory, fixture.owner).unwrap(),
                Some(ready)
            );
            // A final witness cannot be replaced by an original-only epoch.
            assert_eq!(
                write_cache_window(&fixture.directory, &pending, fixture.owner, |_| Ok(())),
                Err(AccountError::Unavailable)
            );
        }
    }

    #[test]
    fn cache_window_finish_handles_each_crash_state_without_resnapshotting() {
        let original = cache_sample();
        let pending = CacheWindow {
            original: original.clone(),
            restored: None,
        };
        // Crash after original journal but before revoke: begin can retain its
        // exact original proof; finish first refuses and the wrapper revokes.
        assert_eq!(
            validate_cache_finish(&original, Some(&pending), &original.inputs),
            Err(AccountError::Unavailable)
        );
        assert!(
            validate_cache_finish(&Registry::revoked(), Some(&pending), &original.inputs).is_ok()
        );
        let ready = cache_ready(&original);
        let restored = ready.restored.as_ref().unwrap();
        assert!(
            validate_cache_finish(&Registry::revoked(), Some(&ready), &restored.inputs).is_ok()
        );
        // Published registry with a retained witness, then deleted witness.
        assert!(validate_cache_finish(restored, Some(&ready), &restored.inputs).is_ok());
        assert!(validate_cache_finish(restored, None, &restored.inputs).is_ok());
        let mut changed = restored.inputs.clone();
        changed[0].ctime += 1;
        assert_eq!(
            validate_cache_finish(restored, Some(&ready), &changed),
            Err(AccountError::Unavailable)
        );
        assert_eq!(
            validate_cache_finish(restored, None, &changed),
            Err(AccountError::Unavailable)
        );
        assert_eq!(
            validate_cache_finish(&Registry::revoked(), None, &restored.inputs),
            Err(AccountError::Unavailable)
        );
        assert_eq!(
            validate_cache_finish(&original, Some(&ready), &restored.inputs),
            Err(AccountError::Unavailable)
        );
    }

    #[test]
    fn cache_window_cancellation_discards_both_epoch_records_durably() {
        let fixture = Fixture::new();
        let original = cache_sample();
        let window = CacheWindow {
            original,
            restored: None,
        };
        write_cache_window(&fixture.directory, &window, fixture.owner, |_| Ok(())).unwrap();
        // A crash may leave a canonical but incomplete unpublished checkpoint.
        let temporary = std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(fixture.path.join(CACHE_PENDING))
            .unwrap();
        temporary.sync_all().unwrap();
        fixture.replace(&Registry::revoked());
        discard_cache_window(&fixture.directory, fixture.owner).unwrap();
        assert_eq!(
            read_cache_window(&fixture.directory, fixture.owner).unwrap(),
            None
        );
        assert!(!fixture.path.join(CACHE_PENDING).exists());
        assert_eq!(fixture.read(), Registry::revoked());
        assert_eq!(
            validate_cache_finish(&fixture.read(), None, &window.original.inputs),
            Err(AccountError::Unavailable)
        );
    }

    #[test]
    fn cache_window_refuses_symlink_hardlink_and_unknown_pending_records() {
        let fixture = Fixture::new();
        let window = CacheWindow {
            original: cache_sample(),
            restored: None,
        };
        let other = fixture.path.join("other");
        std::fs::write(&other, b"unrelated").unwrap();
        std::fs::set_permissions(&other, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::os::unix::fs::symlink("other", fixture.path.join(CACHE_JOURNAL)).unwrap();
        assert!(read_cache_window(&fixture.directory, fixture.owner).is_err());
        assert!(discard_cache_window(&fixture.directory, fixture.owner).is_err());
        std::fs::remove_file(fixture.path.join(CACHE_JOURNAL)).unwrap();
        std::fs::hard_link(&other, fixture.path.join(CACHE_JOURNAL)).unwrap();
        assert!(read_cache_window(&fixture.directory, fixture.owner).is_err());
        assert!(discard_cache_window(&fixture.directory, fixture.owner).is_err());
        std::fs::remove_file(fixture.path.join(CACHE_JOURNAL)).unwrap();
        std::os::unix::fs::symlink("other", fixture.path.join(CACHE_PENDING)).unwrap();
        assert!(
            write_cache_window(&fixture.directory, &window, fixture.owner, |_| Ok(())).is_err()
        );
        assert_eq!(std::fs::read(&other).unwrap(), b"unrelated");
    }
    #[test]
    fn versioned_registry_is_exact_bounded_and_never_invents_ids() {
        let active = sample();
        let bytes = active.encode();
        assert_eq!(Registry::decode(&bytes).unwrap(), active);
        assert_eq!(
            Registry::decode(&Registry::revoked().encode()).unwrap(),
            Registry::revoked()
        );
        for index in 0..bytes.len() {
            assert!(Registry::decode(&bytes[..index]).is_err());
        }
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(Registry::decode(&trailing).is_err());
        let mut bad = bytes.clone();
        bad[0] = 0;
        assert!(Registry::decode(&bad).is_err());
        let mut duplicate = active.clone();
        duplicate.accounts.push(account(1000, 3));
        assert!(Registry::decode(&duplicate.encode()).is_err());
        let mut excess = active;
        excess.accounts = (1..=129).map(|uid| account(uid, 1)).collect();
        assert!(Registry::decode(&excess.encode()).is_err());
    }
    #[test]
    fn local_source_requires_unique_uid_and_shadow_identity() {
        let valid = "fixture:x:1000:1000::/home/fixture:/bin/bash\n";
        let shadow = "fixture:!:20000:0:99999:7:::\n";
        let uid = Uid::new(1000).unwrap();
        assert!(validate_local_account(valid, shadow, uid).is_ok());
        assert!(validate_local_account(&(valid.to_owned() + valid), shadow, uid).is_err());
        assert!(validate_local_account(valid, "", uid).is_err());
        assert!(validate_local_account(valid, &(shadow.to_owned() + shadow), uid).is_err());
        assert!(
            validate_local_account("fixture:x:1000:1000::relative:/bin/bash", shadow, uid).is_err()
        );
    }
    #[test]
    fn provisioning_authority_is_explicit_and_incarnation_bound() {
        let mut authority = ProvisionAuthority {
            accounts: vec![account(1000, 7)],
        };
        assert_eq!(
            authority.current_incarnation(Uid::new(1000).unwrap()),
            Ok(account(1000, 7).incarnation)
        );
        assert_eq!(
            authority.current_incarnation(Uid::new(1001).unwrap()),
            Err(LifecycleError::Unsupported)
        );
    }

    #[test]
    fn interrupted_registry_replacement_has_only_old_or_complete_authority() {
        for boundary in [
            RegistryBoundary::TempCreated,
            RegistryBoundary::Written,
            RegistryBoundary::FileSynced,
            RegistryBoundary::Renamed,
            RegistryBoundary::DirectorySynced,
        ] {
            for activation in [false, true] {
                let fixture = Fixture::new();
                let active = sample();
                let revoked = Registry::revoked();
                let (old, next) = if activation {
                    (&revoked, &active)
                } else {
                    (&active, &revoked)
                };
                fixture.replace(old);
                assert_eq!(
                    replace_registry(&fixture.directory, next, fixture.owner, |at| {
                        if at == boundary {
                            Err(AccountError::Unavailable)
                        } else {
                            Ok(())
                        }
                    }),
                    Err(AccountError::Unavailable)
                );
                let published = matches!(
                    boundary,
                    RegistryBoundary::Renamed | RegistryBoundary::DirectorySynced
                );
                assert_eq!(&fixture.read(), if published { next } else { old });
                // Root recovery never adopts a pending identity; it first
                // installs a durable revocation, discarding a canonical temp.
                fixture.replace(&revoked);
                assert!(!fixture.read().active());
            }
        }
    }

    #[test]
    fn permanent_shared_lease_excludes_revocation_until_all_readers_drop() {
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
    fn registry_recovery_refuses_unsafe_pending_path() {
        let fixture = Fixture::new();
        fixture.replace(&sample());
        std::os::unix::fs::symlink("registry", fixture.path.join(".pending")).unwrap();
        assert_eq!(
            replace_registry(
                &fixture.directory,
                &Registry::revoked(),
                fixture.owner,
                |_| Ok(())
            ),
            Err(AccountError::Unavailable)
        );
        assert!(fixture.read().active());
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
        let before = Snapshot::metadata(&file.metadata().unwrap(), [0; 32]);
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
            Snapshot::metadata(&file.metadata().unwrap(), [0; 32]),
            before
        );
    }

    #[test]
    fn kernel_read_lease_rejects_preopened_writer_then_proves_drain() {
        let fixture = Fixture::new();
        let path = fixture.path.join("writer");
        let writer = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .unwrap();
        let reader = File::open(&path).unwrap();
        assert_eq!(kernel_read_lease(&reader, true), Err(AccountError::Busy));
        drop(writer);
        kernel_read_lease(&reader, true).unwrap();
        kernel_read_lease(&reader, false).unwrap();
    }

    struct WritableMapping {
        address: *mut libc::c_void,
        length: usize,
    }
    impl WritableMapping {
        #[allow(unsafe_code)]
        fn new(file: File) -> Self {
            let length = 4096;
            // SAFETY: this test owns a regular temporary file sized to length.
            // No mapped memory is dereferenced or exposed as a Rust reference;
            // Drop unmaps the exact same owned kernel extent.
            let address = unsafe {
                libc::mmap(
                    std::ptr::null_mut(),
                    length,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_SHARED,
                    file.as_raw_fd(),
                    0,
                )
            };
            assert_ne!(address, libc::MAP_FAILED);
            drop(file);
            Self { address, length }
        }
    }
    impl Drop for WritableMapping {
        #[allow(unsafe_code)]
        fn drop(&mut self) {
            // SAFETY: new owns this exact live mapping; no alias escapes.
            assert_eq!(unsafe { libc::munmap(self.address, self.length) }, 0);
        }
    }

    #[test]
    fn kernel_read_lease_rejects_writable_mapping_after_descriptor_closed() {
        let fixture = Fixture::new();
        let path = fixture.path.join("mapping");
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .unwrap();
        file.set_len(4096).unwrap();
        // Close the only writable descriptor while the shared writable VMA
        // retains its kernel file reference, then challenge the barrier.
        let mapping = WritableMapping::new(file);
        let reader = File::open(&path).unwrap();
        assert_eq!(kernel_read_lease(&reader, true), Err(AccountError::Busy));
        drop(mapping);
        kernel_read_lease(&reader, true).unwrap();
        kernel_read_lease(&reader, false).unwrap();
    }

    #[test]
    fn old_registry_without_writer_barrier_is_never_adopted() {
        let mut old = sample().encode();
        old[..8].copy_from_slice(b"LPACCT01");
        assert_eq!(Registry::decode(&old), Err(AccountError::Invalid));
    }

    #[test]
    fn final_missing_read_lease_prevents_active_registry_publication() {
        let fixture = Fixture::new();
        fixture.replace(&Registry::revoked());
        let path = fixture.path.join("gate");
        std::fs::write(&path, []).unwrap();
        let reader = File::open(&path).unwrap();
        kernel_read_lease(&reader, true).unwrap();
        drop(reader);
        let unleased = File::open(&path).unwrap();
        assert_eq!(
            replace_registry(&fixture.directory, &sample(), fixture.owner, |at| {
                if at == RegistryBoundary::FileSynced {
                    kernel_read_lease(&unleased, false)?;
                }
                Ok(())
            }),
            Err(AccountError::Unavailable)
        );
        assert!(!fixture.read().active());
    }
}
