//! Descriptor-relative Linux filesystem operations for protected broker state.

use std::fs::{File, Metadata};
use std::io::{Read, Write};
use std::os::unix::fs::MetadataExt;

use rustix::fs::{
    AtFlags, FlockOperation, Mode, OFlags, ResolveFlags, flock, mkdirat, openat2, renameat,
    unlinkat,
};
use rustix::io::Errno;
use zeroize::Zeroizing;

use crate::{Boundary, Error, FaultInjector, Result};

const PENDING: &str = ".pending";
const FILE_MODE: u32 = 0o600;
const DIRECTORY_MODE: u32 = 0o700;
const OPEN_FLAGS: OFlags = OFlags::NOFOLLOW
    .union(OFlags::CLOEXEC)
    .union(OFlags::NONBLOCK);
const RESOLVE_FLAGS: ResolveFlags = ResolveFlags::BENEATH
    .union(ResolveFlags::NO_SYMLINKS)
    .union(ResolveFlags::NO_MAGICLINKS);

/// A validated, held directory descriptor, independent of later path renames.
#[derive(Debug)]
pub(crate) struct Dir {
    file: File,
    owner: u32,
}

impl Dir {
    pub(crate) fn open(root: File) -> Result<Self> {
        Self::validate(root, 0)
    }

    /// Unit fixtures exercise the same checks with the fixture's owner.
    #[cfg(test)]
    pub(crate) fn test(root: File) -> Result<Self> {
        let owner = root.metadata()?.uid();
        Self::validate(root, owner)
    }

    fn validate(file: File, owner: u32) -> Result<Self> {
        let dir = Self { file, owner };
        dir.validate_self()?;
        Ok(dir)
    }

    fn validate_self(&self) -> Result<()> {
        let metadata = self.file.metadata()?;
        if !metadata.is_dir()
            || metadata.uid() != self.owner
            || metadata.mode() & 0o7777 != DIRECTORY_MODE
        {
            return Err(Error::UnsafePath);
        }
        Ok(())
    }

    fn open_at(&self, name: &str, flags: OFlags, mode: Mode) -> Result<File> {
        check_name(name)?;
        self.validate_self()?;
        // O_PATH never opens the underlying device or FIFO. Linux openat2
        // rejects combining it with O_NONBLOCK, so only metadata descriptors
        // omit that otherwise mandatory flag.
        let guards = if flags.contains(OFlags::PATH) {
            OPEN_FLAGS - OFlags::NONBLOCK
        } else {
            OPEN_FLAGS
        };
        openat2(&self.file, name, flags | guards, mode, RESOLVE_FLAGS)
            .map(File::from)
            .map_err(path_error)
    }

    pub(crate) fn child(&self, name: &str) -> Result<Self> {
        let file = self.open_at(name, OFlags::RDONLY | OFlags::DIRECTORY, Mode::empty())?;
        Self::validate(file, self.owner)
    }

    pub(crate) fn create_child(&self, name: &str) -> Result<Self> {
        check_name(name)?;
        self.validate_self()?;
        match mkdirat(&self.file, name, Mode::from_raw_mode(DIRECTORY_MODE)) {
            Ok(()) | Err(Errno::EXIST) => {}
            Err(error) => return Err(path_error(error)),
        }
        let child = self.child(name)?;
        // Also synchronize an existing entry: its creator may have failed
        // before making the new directory durable.
        self.sync()?;
        Ok(child)
    }

    pub(crate) fn create_child_new(&self, name: &str) -> Result<Self> {
        check_name(name)?;
        self.validate_self()?;
        match mkdirat(&self.file, name, Mode::from_raw_mode(DIRECTORY_MODE)) {
            Ok(()) => {}
            Err(Errno::EXIST) => return Err(Error::Conflict),
            Err(error) => return Err(path_error(error)),
        }
        let child = self.child(name)?;
        self.sync()?;
        Ok(child)
    }

    pub(crate) fn sync(&self) -> Result<()> {
        self.validate_self()?;
        self.file.sync_all()?;
        Ok(())
    }

    pub(crate) fn names(&self) -> Result<Vec<String>> {
        self.validate_self()?;
        let entries = rustix::fs::Dir::read_from(&self.file)?;
        let mut names = Vec::new();
        for entry in entries {
            let entry = entry?;
            let name = entry.file_name().to_str().map_err(|_| Error::UnsafePath)?;
            if matches!(name, "." | "..") {
                continue;
            }
            check_name(name)?;
            if names.len() == 16 {
                return Err(Error::Oversized);
            }
            names.push(name.to_owned());
        }
        names.sort_unstable();
        Ok(names)
    }

    /// Remove only a validated obsolete generation, under the caller's lock.
    pub(crate) fn remove_child(&self, name: &str, fault: &mut impl FaultInjector) -> Result<()> {
        let child = self.child(name)?;
        let expected = child.file.metadata()?;
        for record in ["credential", "throttle", PENDING] {
            match child.inspect_regular(record) {
                Ok(_) => {
                    unlinkat(&child.file, record, AtFlags::empty()).map_err(path_error)?;
                    fault.check(Boundary::FileRemoved)?;
                    child.sync()?;
                    fault.check(Boundary::DirectorySynced)?;
                }
                Err(Error::Io(std::io::ErrorKind::NotFound)) => {}
                Err(error) => return Err(error),
            }
        }
        // The caller has no recursive deletion capability. Any unknown entry
        // keeps rmdir from succeeding; metadata attacks are refused above.
        if !same_inode(&expected, &self.child(name)?.file.metadata()?) {
            return Err(Error::UnsafePath);
        }
        unlinkat(&self.file, name, AtFlags::REMOVEDIR).map_err(path_error)?;
        fault.check(Boundary::DirectoryRemoved)?;
        self.sync()?;
        fault.check(Boundary::DirectorySynced)?;
        Ok(())
    }

    fn validate_regular(&self, file: &File) -> Result<Metadata> {
        let metadata = file.metadata()?;
        if !metadata.is_file()
            || metadata.uid() != self.owner
            || metadata.mode() & 0o7777 != FILE_MODE
            || metadata.nlink() != 1
        {
            return Err(Error::UnsafePath);
        }
        Ok(metadata)
    }

    fn inspect_regular(&self, name: &str) -> Result<Metadata> {
        // Inspect with O_PATH first so a hostile device or FIFO is never
        // activated merely to discover that it is not a regular file. The
        // eventual data descriptor is independently constrained and checked.
        let file = self.open_at(name, OFlags::PATH, Mode::empty())?;
        self.validate_regular(&file)
    }

    pub(crate) fn read(&self, name: &str, max: usize) -> Result<Zeroizing<Vec<u8>>> {
        let limit = u64::try_from(max.checked_add(1).ok_or(Error::Oversized)?)
            .map_err(|_| Error::Oversized)?;
        let expected = self.inspect_regular(name)?;
        let mut file = self.open_at(name, OFlags::RDONLY, Mode::empty())?;
        let metadata = self.validate_regular(&file)?;
        if !same_inode(&expected, &metadata) {
            return Err(Error::UnsafePath);
        }
        if metadata.len() >= limit {
            return Err(Error::Oversized);
        }
        let mut bytes = Zeroizing::new(Vec::new());
        (&mut file).take(limit).read_to_end(&mut bytes)?;
        if bytes.len() > max {
            return Err(Error::Oversized);
        }
        self.validate_regular(&file)?;
        // An earlier writer can have failed after rename, leaving a visible
        // but unacknowledged version. Reload makes both data and entry durable
        // before it can be treated as authoritative again.
        file.sync_all()?;
        self.sync()?;
        Ok(bytes)
    }

    /// Replace one record. The caller must hold this directory's stable lock.
    pub(crate) fn replace(
        &self,
        name: &str,
        bytes: &[u8],
        fault: &mut impl FaultInjector,
    ) -> Result<()> {
        check_name(name)?;
        // These inodes are permanent serialization points, never records.
        if matches!(name, PENDING | "lock" | "broker.lock") {
            return Err(Error::UnsafePath);
        }
        match self.inspect_regular(name) {
            Ok(_) => {}
            Err(Error::Io(std::io::ErrorKind::NotFound)) => {}
            Err(error) => return Err(error),
        }
        match self.inspect_regular(PENDING) {
            Ok(_) => {
                unlinkat(&self.file, PENDING, AtFlags::empty()).map_err(path_error)?;
                self.sync()?;
            }
            Err(Error::Io(std::io::ErrorKind::NotFound)) => {}
            Err(error) => return Err(error),
        }
        let mut temporary = self.open_at(
            PENDING,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL,
            Mode::from_raw_mode(FILE_MODE),
        )?;
        self.validate_regular(&temporary)?;
        fault.check(Boundary::TempCreated)?;
        temporary.write_all(bytes)?;
        fault.check(Boundary::Written)?;
        self.validate_regular(&temporary)?;
        temporary.sync_all()?;
        fault.check(Boundary::FileSynced)?;
        if !same_inode(
            &self.validate_regular(&temporary)?,
            &self.inspect_regular(PENDING)?,
        ) {
            return Err(Error::UnsafePath);
        }
        match self.inspect_regular(name) {
            Ok(_) => {}
            Err(Error::Io(std::io::ErrorKind::NotFound)) => {}
            Err(error) => return Err(error),
        }
        renameat(&self.file, PENDING, &self.file, name).map_err(path_error)?;
        fault.check(Boundary::Renamed)?;
        self.sync()?;
        fault.check(Boundary::DirectorySynced)?;
        Ok(())
    }

    /// Open the permanent lock inode and take an exclusive, nonblocking lock.
    pub(crate) fn lock(&self, name: &str) -> Result<File> {
        let file = match self.open_at(
            name,
            OFlags::RDWR | OFlags::CREATE | OFlags::EXCL,
            Mode::from_raw_mode(FILE_MODE),
        ) {
            Ok(file) => file,
            Err(Error::Io(std::io::ErrorKind::AlreadyExists)) => {
                self.inspect_regular(name)?;
                self.open_at(name, OFlags::RDWR, Mode::empty())?
            }
            Err(error) => return Err(error),
        };
        let metadata = self.validate_regular(&file)?;
        flock(&file, FlockOperation::NonBlockingLockExclusive).map_err(|error| {
            if error == Errno::WOULDBLOCK {
                Error::Busy
            } else {
                error.into()
            }
        })?;
        // A removed or replaced lock inode must never serialize independently
        // from the current directory entry.
        if !same_inode(&metadata, &self.inspect_regular(name)?) {
            return Err(Error::UnsafePath);
        }
        file.sync_all()?;
        self.sync()?;
        Ok(file)
    }
}

fn same_inode(left: &Metadata, right: &Metadata) -> bool {
    left.dev() == right.dev() && left.ino() == right.ino()
}

fn check_name(name: &str) -> Result<()> {
    if name.is_empty()
        || name.len() > 255
        || matches!(name, "." | "..")
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-'))
    {
        return Err(Error::UnsafePath);
    }
    Ok(())
}

fn path_error(error: Errno) -> Error {
    match error {
        Errno::LOOP | Errno::NOTDIR | Errno::XDEV => Error::UnsafePath,
        _ => error.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::{DirBuilder, OpenOptions, Permissions};
    use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt, symlink};
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static NEXT_FIXTURE: AtomicUsize = AtomicUsize::new(0);

    struct Fixture {
        path: PathBuf,
        dir: Dir,
        _serial: std::sync::MutexGuard<'static, ()>,
    }

    impl Fixture {
        fn new() -> Self {
            let serial = crate::tests::TEST_SERIAL
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            let path = std::env::temp_dir().join(format!(
                "localpin-fs-{}-{}",
                std::process::id(),
                NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed)
            ));
            DirBuilder::new()
                .mode(DIRECTORY_MODE)
                .create(&path)
                .unwrap();
            let dir = Dir::test(File::open(&path).unwrap()).unwrap();
            Self {
                path,
                dir,
                _serial: serial,
            }
        }

        fn record(&self, name: &str, bytes: &[u8]) {
            let mut file = OpenOptions::new()
                .create_new(true)
                .write(true)
                .mode(FILE_MODE)
                .open(self.path.join(name))
                .unwrap();
            file.write_all(bytes).unwrap();
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.path).unwrap();
        }
    }

    struct NeverFail;

    impl FaultInjector for NeverFail {
        fn check(&mut self, _: Boundary) -> Result<()> {
            Ok(())
        }
    }

    fn unsafe_path<T>(result: Result<T>) {
        assert!(matches!(result, Err(Error::UnsafePath)));
    }

    #[test]
    fn rejects_symlinks_hardlinks_fifos_and_socket_files() {
        let fixture = Fixture::new();
        fixture.record("original", b"secret");
        symlink("original", fixture.path.join("symlink")).unwrap();
        unsafe_path(fixture.dir.read("symlink", 32));
        unsafe_path(fixture.dir.replace("symlink", b"new", &mut NeverFail));
        std::fs::hard_link(fixture.path.join("original"), fixture.path.join("hardlink")).unwrap();
        unsafe_path(fixture.dir.read("hardlink", 32));
        unsafe_path(fixture.dir.read("original", 32));
        match rustix::fs::mkfifoat(&fixture.dir.file, "fifo", Mode::from_raw_mode(FILE_MODE)) {
            Ok(()) => {
                unsafe_path(fixture.dir.read("fifo", 32));
                unsafe_path(fixture.dir.lock("fifo"));
            }
            Err(Errno::PERM | Errno::ACCESS) => {
                eprintln!("FIFO fixture unavailable: sandbox denies mkfifoat");
            }
            Err(error) => panic!("unexpected mkfifoat result: {error}"),
        }
        match std::os::unix::net::UnixListener::bind(fixture.path.join("socket")) {
            Ok(_socket) => unsafe_path(fixture.dir.read("socket", 32)),
            Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
                eprintln!("socket fixture unavailable: sandbox denies UnixListener::bind");
            }
            Err(error) => panic!("unexpected UnixListener::bind result: {error}"),
        }
    }

    #[test]
    fn checks_exact_modes_and_refuses_to_repair_existing_entries() {
        let fixture = Fixture::new();
        fixture.record("state", b"secret");
        for mode in [0o400, 0o640, 0o660, 0o1600, 0o2600, 0o4600] {
            std::fs::set_permissions(fixture.path.join("state"), Permissions::from_mode(mode))
                .unwrap();
            unsafe_path(fixture.dir.read("state", 32));
        }
        std::fs::create_dir(fixture.path.join("unsafe")).unwrap();
        std::fs::set_permissions(fixture.path.join("unsafe"), Permissions::from_mode(0o750))
            .unwrap();
        unsafe_path(fixture.dir.create_child("unsafe"));
        assert_eq!(
            std::fs::metadata(fixture.path.join("unsafe"))
                .unwrap()
                .mode()
                & 0o7777,
            0o750
        );
        std::fs::set_permissions(&fixture.path, Permissions::from_mode(0o1700)).unwrap();
        unsafe_path(Dir::test(File::open(&fixture.path).unwrap()));
    }

    #[test]
    fn enforces_bounded_reads_and_single_components() {
        let fixture = Fixture::new();
        fixture.record("state", b"12345");
        assert_eq!(&*fixture.dir.read("state", 5).unwrap(), b"12345");
        assert!(matches!(
            fixture.dir.read("state", 4),
            Err(Error::Oversized)
        ));
        for name in ["", ".", "..", "../state", "a/b", "/state", "a\0b", "æ"] {
            unsafe_path(fixture.dir.read(name, 32));
            unsafe_path(fixture.dir.create_child(name));
            unsafe_path(fixture.dir.lock(name));
        }
    }

    #[test]
    fn rejects_unsafe_directory_modes_after_opening_the_descriptor() {
        let fixture = Fixture::new();
        fixture.record("state", b"secret");
        std::fs::set_permissions(&fixture.path, Permissions::from_mode(0o777)).unwrap();
        unsafe_path(fixture.dir.read("state", 32));
        unsafe_path(fixture.dir.names());
        unsafe_path(fixture.dir.lock("lock"));
        unsafe_path(fixture.dir.create_child("generation-1"));
        unsafe_path(fixture.dir.replace("state", b"bad", &mut NeverFail));
        std::fs::set_permissions(&fixture.path, Permissions::from_mode(DIRECTORY_MODE)).unwrap();
        assert_eq!(&*fixture.dir.read("state", 32).unwrap(), b"secret");
    }

    #[test]
    fn refuses_a_pending_inode_substitution_before_rename() {
        struct Substitute(PathBuf);
        impl FaultInjector for Substitute {
            fn check(&mut self, boundary: Boundary) -> Result<()> {
                if boundary == Boundary::FileSynced {
                    std::fs::remove_file(self.0.join(PENDING)).unwrap();
                    symlink("state", self.0.join(PENDING)).unwrap();
                }
                Ok(())
            }
        }

        let fixture = Fixture::new();
        fixture.record("state", b"old");
        unsafe_path(
            fixture
                .dir
                .replace("state", b"new", &mut Substitute(fixture.path.clone())),
        );
        assert_eq!(&*fixture.dir.read("state", 3).unwrap(), b"old");
    }

    #[test]
    fn stable_lock_contends_and_is_never_replaced() {
        let fixture = Fixture::new();
        let first = fixture.dir.lock("lock").unwrap();
        let before = first.metadata().unwrap();
        assert!(matches!(fixture.dir.lock("lock"), Err(Error::Busy)));
        unsafe_path(fixture.dir.replace("lock", b"new", &mut NeverFail));
        drop(first);
        let next = fixture.dir.lock("lock").unwrap();
        assert!(same_inode(&before, &next.metadata().unwrap()));
    }

    #[test]
    fn replaces_atomically_and_recovers_only_safe_pending_files() {
        let fixture = Fixture::new();
        let _lock = fixture.dir.lock("lock").unwrap();
        fixture
            .dir
            .replace("state", b"old", &mut NeverFail)
            .unwrap();
        fixture.record(PENDING, b"interrupted");
        fixture
            .dir
            .replace("state", b"new", &mut NeverFail)
            .unwrap();
        assert_eq!(&*fixture.dir.read("state", 3).unwrap(), b"new");
        assert!(!fixture.path.join(PENDING).exists());
        symlink("state", fixture.path.join(PENDING)).unwrap();
        unsafe_path(fixture.dir.replace("state", b"bad", &mut NeverFail));
        assert_eq!(&*fixture.dir.read("state", 3).unwrap(), b"new");
    }

    #[test]
    fn creates_protected_children_without_reusing_new_entries() {
        let fixture = Fixture::new();
        fixture.dir.create_child_new("1000").unwrap();
        fixture.dir.create_child("1000").unwrap();
        assert!(matches!(
            fixture.dir.create_child_new("1000"),
            Err(Error::Conflict)
        ));
        symlink("1000", fixture.path.join("1001")).unwrap();
        unsafe_path(fixture.dir.child("1001"));
        unsafe_path(fixture.dir.create_child("1001"));
    }

    #[test]
    fn injected_boundaries_leave_only_old_or_complete_new_records() {
        struct FailAt(Boundary);
        impl FaultInjector for FailAt {
            fn check(&mut self, boundary: Boundary) -> Result<()> {
                if boundary == self.0 {
                    Err(Error::Injected)
                } else {
                    Ok(())
                }
            }
        }

        for boundary in [
            Boundary::TempCreated,
            Boundary::Written,
            Boundary::FileSynced,
            Boundary::Renamed,
            Boundary::DirectorySynced,
        ] {
            let fixture = Fixture::new();
            let _lock = fixture.dir.lock("lock").unwrap();
            fixture
                .dir
                .replace("state", b"old", &mut NeverFail)
                .unwrap();
            assert!(matches!(
                fixture.dir.replace("state", b"new", &mut FailAt(boundary)),
                Err(Error::Injected)
            ));
            let expected = if matches!(boundary, Boundary::Renamed | Boundary::DirectorySynced) {
                b"new"
            } else {
                b"old"
            };
            assert_eq!(&*fixture.dir.read("state", 3).unwrap(), expected);
            fixture
                .dir
                .replace("state", b"end", &mut NeverFail)
                .unwrap();
            assert_eq!(&*fixture.dir.read("state", 3).unwrap(), b"end");
        }
    }

    #[test]
    fn bounded_directory_names_reject_invalid_components() {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;

        let fixture = Fixture::new();
        fixture.record("active", b"pointer");
        fixture.dir.create_child("generation-1").unwrap();
        assert_eq!(fixture.dir.names().unwrap(), ["active", "generation-1"]);
        fixture.record("invalid name", b"bad");
        unsafe_path(fixture.dir.names());
        std::fs::remove_file(fixture.path.join("invalid name")).unwrap();
        let invalid_utf8 = fixture.path.join(OsString::from_vec(vec![0xff]));
        File::create(&invalid_utf8).unwrap();
        unsafe_path(fixture.dir.names());
        std::fs::remove_file(invalid_utf8).unwrap();
        for number in 0..15 {
            fixture.record(&number.to_string(), b"");
        }
        assert!(matches!(fixture.dir.names(), Err(Error::Oversized)));
    }

    #[test]
    fn cleanup_removes_known_generation_files_and_refuses_unknown_content() {
        let fixture = Fixture::new();
        let child = fixture.dir.create_child("generation-1").unwrap();
        for name in ["credential", "throttle"] {
            child.replace(name, b"record", &mut NeverFail).unwrap();
        }
        fixture.record("generation-1/.pending", b"interrupted");
        fixture
            .dir
            .remove_child("generation-1", &mut NeverFail)
            .unwrap();
        assert!(fixture.dir.names().unwrap().is_empty());

        fixture.dir.create_child("generation-2").unwrap();
        symlink("../active", fixture.path.join("generation-2/credential")).unwrap();
        unsafe_path(fixture.dir.remove_child("generation-2", &mut NeverFail));
        std::fs::remove_file(fixture.path.join("generation-2/credential")).unwrap();
        fixture.record("generation-2/unknown", b"preserved");
        assert!(matches!(
            fixture.dir.remove_child("generation-2", &mut NeverFail),
            Err(Error::Io(std::io::ErrorKind::DirectoryNotEmpty))
        ));
        assert_eq!(
            std::fs::read(fixture.path.join("generation-2/unknown")).unwrap(),
            b"preserved"
        );
    }

    #[test]
    fn cleanup_retries_after_each_deletion_boundary() {
        struct FailAt(Boundary);
        impl FaultInjector for FailAt {
            fn check(&mut self, boundary: Boundary) -> Result<()> {
                if boundary == self.0 {
                    Err(Error::Injected)
                } else {
                    Ok(())
                }
            }
        }
        for boundary in [Boundary::FileRemoved, Boundary::DirectorySynced] {
            let fixture = Fixture::new();
            fixture.dir.create_child("generation-1").unwrap();
            fixture.record("generation-1/credential", b"record");
            assert!(matches!(
                fixture
                    .dir
                    .remove_child("generation-1", &mut FailAt(boundary)),
                Err(Error::Injected)
            ));
            fixture
                .dir
                .remove_child("generation-1", &mut NeverFail)
                .unwrap();
            assert!(fixture.dir.names().unwrap().is_empty());
        }
        let fixture = Fixture::new();
        fixture.dir.create_child("generation-1").unwrap();
        assert!(matches!(
            fixture
                .dir
                .remove_child("generation-1", &mut FailAt(Boundary::DirectoryRemoved)),
            Err(Error::Injected)
        ));
        // Reload synchronizes the containing directory even when the failed
        // removal is already absent from the current namespace.
        fixture.dir.sync().unwrap();
        assert!(fixture.dir.names().unwrap().is_empty());
    }

    #[test]
    fn rejects_a_different_owner_when_tested_as_root() {
        let fixture = Fixture::new();
        fixture.record("state", b"secret");
        let file = File::open(fixture.path.join("state")).unwrap();
        match rustix::fs::fchown(&file, Some(rustix::fs::Uid::from_raw(1)), None) {
            Ok(()) => unsafe_path(fixture.dir.read("state", 32)),
            Err(Errno::PERM | Errno::ACCESS | Errno::INVAL) => {
                // The same predicate is exercised without privilege by an
                // impossible expected owner on a held fixture descriptor.
                eprintln!("chown fixture unavailable: privilege or UID namespace restriction");
                let other = Dir {
                    file: File::open(&fixture.path).unwrap(),
                    owner: fixture.dir.owner.wrapping_add(1),
                };
                unsafe_path(other.read("state", 32));
            }
            Err(error) => panic!("unexpected chown result: {error}"),
        }
    }
}
