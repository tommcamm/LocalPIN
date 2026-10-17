//! Password-free policy for the immutable, managed Fedora 44 local-account domain.
//!
//! Lifecycle ownership/serialization is a separate authority. This worker never
//! provisions accounts, repairs state or verifies a password. Missing tallies
//! refuse service, including after reboot; only explicit privileged provisioning
//! may establish a disabled baseline. No account material leaves the child.

use crate::{PasswordSupervisor, ipc, pam};
use localpin_core::eligibility::EligibilityError;
use localpin_protocol::transport::BootInstant;
use sha2::{Digest, Sha256};
use std::{
    ffi::CString,
    fs::{Metadata, OpenOptions},
    io::{self, Read},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
};
use zeroize::Zeroizing;

const MAX_FILE: usize = 65_536;
const MAX_DATABASE: usize = 1_048_576;
const SERVICE: &str = "/etc/pam.d/localpin-eligibility";
const POLICY: &str = "auth required pam_env.so\nauth required pam_faildelay.so delay=2000000\nauth requisite pam_faillock.so preauth silent\naccount required pam_unix.so\naccount required pam_nologin.so\n";
const STOCK_KDE_DIGEST: &str = "7d91b3ad73a998e8b10f9edccd74ba04179a778c4a5e61d9176872f43c7bbac3";
const LOCALPIN_KDE_POLICY: &[u8] = include_bytes!("../policy/kde-localpin.review-required");

/// Shared bounded supervisor for password-free account-policy children.
///
/// Construct once per broker: its live/retired process groups remain globally
/// charged across operations and cannot escape an exhausted caller deadline.
#[derive(Clone)]
pub struct EligibilitySupervisor(PasswordSupervisor);

impl EligibilitySupervisor {
    /// Validate the fixed privileged helper installation, without running PAM.
    pub fn new(executable: impl AsRef<Path>) -> io::Result<Self> {
        PasswordSupervisor::new(executable).map(Self)
    }

    /// Check one UID without a password, with the caller's absolute boot deadline.
    pub fn check_password_free(
        &self,
        uid: u32,
        deadline: BootInstant,
        cancelled: &mut dyn FnMut() -> bool,
    ) -> Result<(), EligibilityError> {
        self.0.run_eligibility(uid, deadline, cancelled)
    }

    /// Live, starting and retired policy worker groups still consuming capacity.
    pub fn occupied(&self) -> usize {
        self.0.occupied()
    }
}

/// Serve a single private request, with sanitized status and no conversation.
pub fn serve_eligibility_worker() -> io::Result<()> {
    rustix::process::set_dumpable_behavior(rustix::process::DumpableBehavior::NotDumpable)?;
    rustix::process::setrlimit(
        rustix::process::Resource::Core,
        rustix::process::Rlimit {
            current: Some(0),
            maximum: Some(0),
        },
    )?;
    let mut request = [0; 24];
    io::stdin().lock().read_exact(&mut request)?;
    let token: [u8; 16] = request[4..20].try_into().map_err(|_| ipc::invalid())?;
    let uid = u32::from_be_bytes(request[20..24].try_into().map_err(|_| ipc::invalid())?);
    if request[..4] != *b"LPE1" || token == [0; 16] || uid == 0 || uid == u32::MAX {
        return Err(ipc::invalid());
    }
    let code = match check(uid) {
        Ok(()) => 0,
        Err(EligibilityError::AccountRestricted) => 1,
        Err(_) => 2,
    };
    ipc::write_frame(&mut io::stdout().lock(), ipc::RESULT, &token, 2, &[code])
}

fn unavailable<T>(_: T) -> EligibilityError {
    EligibilityError::Unavailable
}

fn same_metadata(a: &Metadata, b: &Metadata) -> bool {
    a.dev() == b.dev()
        && a.ino() == b.ino()
        && a.uid() == b.uid()
        && a.gid() == b.gid()
        && a.mode() == b.mode()
        && a.nlink() == b.nlink()
        && a.len() == b.len()
        && a.mtime() == b.mtime()
        && a.mtime_nsec() == b.mtime_nsec()
        && a.ctime() == b.ctime()
        && a.ctime_nsec() == b.ctime_nsec()
}

struct Snapshot {
    path: PathBuf,
    metadata: Metadata,
    bytes: Zeroizing<Vec<u8>>,
    uid: u32,
    mode: Option<u32>,
    bound: usize,
}

impl Snapshot {
    fn read(
        path: impl AsRef<Path>,
        uid: u32,
        mode: Option<u32>,
        bound: usize,
    ) -> Result<Self, EligibilityError> {
        let path = path.as_ref();
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
            .open(path)
            .map_err(unavailable)?;
        let metadata = file.metadata().map_err(unavailable)?;
        if !metadata.is_file()
            || metadata.uid() != uid
            || metadata.gid() != 0
            || metadata.nlink() != 1
            || metadata.len() > bound as u64
            || mode.is_some_and(|mode| metadata.mode() & 0o7777 != mode)
            || (mode.is_none() && metadata.mode() & 0o022 != 0)
        {
            return Err(EligibilityError::Unavailable);
        }
        let mut bytes = Zeroizing::new(Vec::new());
        (&file)
            .take(bound as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(unavailable)?;
        if bytes.len() > bound || !same_metadata(&metadata, &file.metadata().map_err(unavailable)?)
        {
            return Err(EligibilityError::Unavailable);
        }
        Ok(Self {
            path: path.to_owned(),
            metadata,
            bytes,
            uid,
            mode,
            bound,
        })
    }

    fn unchanged(&self) -> Result<(), EligibilityError> {
        let after = Self::read(&self.path, self.uid, self.mode, self.bound)?;
        if !same_metadata(&self.metadata, &after.metadata) || *self.bytes != *after.bytes {
            return Err(EligibilityError::Unavailable);
        }
        Ok(())
    }
}

fn directory(path: &Path) -> Result<(), EligibilityError> {
    let metadata = std::fs::symlink_metadata(path).map_err(unavailable)?;
    if !metadata.is_dir()
        || metadata.uid() != 0
        || metadata.gid() != 0
        || metadata.mode() & 0o022 != 0
    {
        return Err(EligibilityError::Unavailable);
    }
    Ok(())
}

/// Only Fedora's exact authselect links are accepted. Their parent directories
/// and the linked regular files are frozen by the lifecycle authority.
fn policy_path(path: &str) -> Result<PathBuf, EligibilityError> {
    let metadata = std::fs::symlink_metadata(path).map_err(unavailable)?;
    if !metadata.file_type().is_symlink() {
        return Ok(PathBuf::from(path));
    }
    let expected = match path {
        "/etc/pam.d/password-auth" => "/etc/authselect/password-auth",
        "/etc/pam.d/postlogin" => "/etc/authselect/postlogin",
        "/etc/nsswitch.conf" => "/etc/authselect/nsswitch.conf",
        _ => return Err(EligibilityError::Unavailable),
    };
    let target = std::fs::read_link(path).map_err(unavailable)?;
    if target != Path::new(expected) || metadata.uid() != 0 || metadata.gid() != 0 {
        return Err(EligibilityError::Unavailable);
    }
    Ok(target)
}

fn digest_is(bytes: &[u8], expected: &str) -> bool {
    let digest = Sha256::digest(bytes);
    let hex = b"0123456789abcdef";
    expected.len() == 64
        && digest.iter().enumerate().all(|(i, byte)| {
            expected.as_bytes()[2 * i] == hex[(byte >> 4) as usize]
                && expected.as_bytes()[2 * i + 1] == hex[(byte & 15) as usize]
        })
}

fn canonical(text: &str) -> String {
    text.lines()
        .filter_map(|line| {
            let line = line.trim();
            (!line.is_empty() && !line.starts_with('#'))
                .then(|| line.split_ascii_whitespace().collect::<Vec<_>>().join(" "))
        })
        .collect::<Vec<_>>()
        .join("\n")
        + "\n"
}

// ADR 0013 adds exactly one integrated layout to ADR 0012's measured stock
// layout. Never normalize this policy: placement, controls, path, arguments and
// every original downstream byte are part of the compatibility contract.
fn kde_policy(bytes: &[u8]) -> bool {
    digest_is(bytes, STOCK_KDE_DIGEST) || bytes == LOCALPIN_KDE_POLICY
}

fn nss_policy(text: &str) -> bool {
    ["passwd", "group", "shadow"].iter().all(|database| {
        let mut matches = text
            .lines()
            .map(|line| line.split('#').next().unwrap_or("").trim())
            .filter_map(|line| line.split_once(':'))
            .filter(|(key, _)| key.trim() == *database);
        matches
            .next()
            .is_some_and(|(_, value)| value.split_ascii_whitespace().eq(["files"]))
            && matches.next().is_none()
    })
}

fn policy() -> Result<Vec<Snapshot>, EligibilityError> {
    for path in [
        "/",
        "/etc",
        "/etc/pam.d",
        "/etc/authselect",
        "/etc/security",
        "/usr",
        "/usr/lib64",
        "/usr/lib64/security",
    ] {
        directory(Path::new(path))?;
    }
    let expected = [
        (
            "/etc/pam.d/postlogin",
            "c1ecd4d1a5b5de7d26e3336cd33551d1d65e13751b5f46405183472895838a9d",
        ),
        (
            "/etc/security/faillock.conf",
            "662303cf89938c12d95a7fc59d92cbe76c398312527fa908894fb319809093b3",
        ),
    ];
    let mut snapshots = Vec::new();
    // Exact native inputs measured in the enforcing Fedora 44 reference guest.
    // An upgrade makes the policy unavailable until explicitly reviewed again.
    // libpam is opened by this same fixed absolute name in the ABI boundary.
    for (path, digest) in [
        (
            "/usr/lib64/libpam.so.0.85.1",
            "e8a3e3aa67cc17d4c659892fe63b9695ae202b6f107170f1ef5bb345570a8760",
        ),
        (
            "/usr/lib64/security/pam_env.so",
            "5a54893c723005dc9b33b1f7da87fd30d9f8a0aefc333f7b0fd7585dd7dc848f",
        ),
        (
            "/usr/lib64/security/pam_faildelay.so",
            "c284c89bcc9163a15e533ef1c335c198da59735f6d86e40c364fa1ccc84954a3",
        ),
        (
            "/usr/lib64/security/pam_faillock.so",
            "babb242bec2f6a080f64c294d8641582c8ffbeda0ffe43eae5b2a3d3c4eb034b",
        ),
        (
            "/usr/lib64/security/pam_unix.so",
            "1b14e350075868d3118959858fec47a2cfdbab31506e8482c31d0c550ab00222",
        ),
        (
            "/usr/lib64/security/pam_nologin.so",
            "4a9f97b38509ce458d33d9563525dbde8243f1c472d260905899a7a7d80358fd",
        ),
    ] {
        let snapshot = Snapshot::read(path, 0, None, 4 * MAX_DATABASE)?;
        if !digest_is(&snapshot.bytes, digest) {
            return Err(EligibilityError::Unavailable);
        }
        snapshots.push(snapshot);
    }
    if std::fs::read_link("/usr/lib64/libpam.so.0").map_err(unavailable)?
        != Path::new("libpam.so.0.85.1")
    {
        return Err(EligibilityError::Unavailable);
    }
    let kde = Snapshot::read(policy_path("/etc/pam.d/kde")?, 0, None, MAX_FILE)?;
    if !kde_policy(&kde.bytes) {
        return Err(EligibilityError::Unavailable);
    }
    snapshots.push(kde);
    for (path, digest) in expected {
        let snapshot = Snapshot::read(policy_path(path)?, 0, None, MAX_FILE)?;
        if !digest_is(&snapshot.bytes, digest) {
            return Err(EligibilityError::Unavailable);
        }
        snapshots.push(snapshot);
    }
    let password = Snapshot::read(policy_path("/etc/pam.d/password-auth")?, 0, None, MAX_FILE)?;
    if ![
        "2e53f704372b6c7fb69cdc4dfd6c27456d642c83feff8b1588fa1f9cb1126cd0",
        "de00ea01b5ffe6b08efd7027e437bdd4a3bad18e231e9593f6b45cc64b334276",
    ]
    .iter()
    .any(|digest| digest_is(&password.bytes, digest))
    {
        return Err(EligibilityError::Unavailable);
    }
    snapshots.push(password);
    let service = Snapshot::read(SERVICE, 0, None, MAX_FILE)?;
    if canonical(std::str::from_utf8(&service.bytes).map_err(unavailable)?) != POLICY {
        return Err(EligibilityError::Unavailable);
    }
    snapshots.push(service);
    let enrollment = Snapshot::read("/etc/pam.d/localpin-enroll", 0, None, MAX_FILE)?;
    if canonical(std::str::from_utf8(&enrollment.bytes).map_err(unavailable)?)
        != pam::SUPPORTED_POLICY
    {
        return Err(EligibilityError::Unavailable);
    }
    snapshots.push(enrollment);
    let nss = Snapshot::read(policy_path("/etc/nsswitch.conf")?, 0, None, MAX_FILE)?;
    if !nss_policy(std::str::from_utf8(&nss.bytes).map_err(unavailable)?) {
        return Err(EligibilityError::Unavailable);
    }
    snapshots.push(nss);
    for path in ["/etc/security/pam_env.conf", "/etc/environment"] {
        snapshots.push(Snapshot::read(path, 0, None, MAX_FILE)?);
    }
    Ok(snapshots)
}

fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 32
        && name.bytes().enumerate().all(|(i, c)| {
            c.is_ascii_lowercase() || c == b'_' || (i > 0 && (c.is_ascii_digit() || c == b'-'))
        })
}

fn decimal(value: &str) -> Option<u32> {
    (!value.is_empty() && value.bytes().all(|c| c.is_ascii_digit()))
        .then(|| value.parse().ok())
        .flatten()
}

fn age(value: &str) -> Option<Option<u64>> {
    if value.is_empty() || value == "-1" {
        return Some(None);
    }
    decimal(value)
        .filter(|value| *value <= 1_000_000)
        .map(|value| Some(u64::from(value)))
}

fn crypt_chars(bytes: &[u8]) -> bool {
    bytes
        .iter()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'/'))
}

fn supported_hash(hash: &str) -> bool {
    if let Some(body) = hash.strip_prefix("$6$") {
        let body = if let Some(body) = body.strip_prefix("rounds=") {
            let Some((rounds, body)) = body.split_once('$') else {
                return false;
            };
            let Some(rounds_number) = decimal(rounds) else {
                return false;
            };
            if !(1000..=999_999_999).contains(&rounds_number) || rounds.starts_with('0') {
                return false;
            }
            body
        } else {
            body
        };
        let Some((salt, digest)) = body.split_once('$') else {
            return false;
        };
        return (1..=16).contains(&salt.len())
            && crypt_chars(salt.as_bytes())
            && digest.len() == 86
            && crypt_chars(digest.as_bytes())
            && b"./01".contains(&digest.as_bytes()[85]);
    }
    // Fedora/libxcrypt default cost 5 only. Other parameter sets require their
    // own real-account evidence rather than accepting arbitrary modular syntax.
    if let Some(body) = hash.strip_prefix("$y$j9T$") {
        let Some((salt, digest)) = body.split_once('$') else {
            return false;
        };
        return salt.len() == 22
            && crypt_chars(salt.as_bytes())
            && b"./01".contains(&salt.as_bytes()[21])
            && digest.len() == 43
            && crypt_chars(digest.as_bytes())
            && b"./0123456789ABCD".contains(&digest.as_bytes()[42]);
    }
    false
}

fn raw_policy(
    uid: u32,
    passwd: &[u8],
    shadow: &[u8],
    today: u64,
) -> Result<CString, EligibilityError> {
    if !(1000..60_000).contains(&uid) || today > 1_000_000 {
        return Err(EligibilityError::Unavailable);
    }
    let passwd = std::str::from_utf8(passwd).map_err(unavailable)?;
    let shadow = std::str::from_utf8(shadow).map_err(unavailable)?;
    if !passwd.ends_with('\n')
        || !shadow.ends_with('\n')
        || passwd.contains('\0')
        || shadow.contains('\0')
    {
        return Err(EligibilityError::Unavailable);
    }
    let mut target = None;
    for line in passwd.lines() {
        let fields: Vec<_> = line.split(':').collect();
        if fields.len() != 7 {
            return Err(EligibilityError::Unavailable);
        }
        if decimal(fields[2]) == Some(uid) {
            if target.is_some()
                || !valid_name(fields[0])
                || fields[1] != "x"
                || decimal(fields[3]).is_none()
                || fields[5] != format!("/home/{}", fields[0])
            {
                return Err(EligibilityError::Unavailable);
            }
            if !matches!(fields[6], "/bin/bash" | "/usr/bin/bash") {
                return Err(EligibilityError::AccountRestricted);
            }
            target = Some(fields[0]);
        }
    }
    let name = target.ok_or(EligibilityError::Unavailable)?;
    if passwd
        .lines()
        .filter(|line| line.split(':').next() == Some(name))
        .count()
        != 1
    {
        return Err(EligibilityError::Unavailable);
    }
    let mut found = false;
    for line in shadow.lines() {
        let fields: Vec<_> = line.split(':').collect();
        if fields.len() != 9 {
            return Err(EligibilityError::Unavailable);
        }
        if fields[0] != name {
            continue;
        }
        if found {
            return Err(EligibilityError::Unavailable);
        }
        found = true;
        if fields[1].is_empty() || fields[1].starts_with(['!', '*']) {
            return Err(EligibilityError::AccountRestricted);
        }
        if !supported_hash(fields[1]) || !fields[8].is_empty() {
            return Err(EligibilityError::Unavailable);
        }
        let ages: Vec<_> = fields[2..8]
            .iter()
            .map(|value| age(value))
            .collect::<Option<_>>()
            .ok_or(EligibilityError::Unavailable)?;
        let last = ages[0].ok_or(EligibilityError::Unavailable)?;
        if last == 0
            || last > today
            || ages[5].is_some_and(|expiry| today >= expiry)
            || ages[2].is_some_and(|maximum| today - last >= maximum)
        {
            return Err(EligibilityError::AccountRestricted);
        }
    }
    if !found {
        return Err(EligibilityError::Unavailable);
    }
    CString::new(name).map_err(unavailable)
}

fn no_nologin() -> Result<(), EligibilityError> {
    for path in ["/run/nologin", "/etc/nologin"] {
        match std::fs::symlink_metadata(path) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Ok(_) => return Err(EligibilityError::AccountRestricted),
            Err(_) => return Err(EligibilityError::Unavailable),
        }
    }
    Ok(())
}

fn tally(uid: u32, name: &str, now: u64) -> Result<Snapshot, EligibilityError> {
    directory(Path::new("/run"))?;
    directory(Path::new("/run/faillock"))?;
    let tally = Snapshot::read(format!("/run/faillock/{name}"), uid, Some(0o660), MAX_FILE)?;
    if tally.bytes.len() % 64 != 0 || tally.bytes.len() >= MAX_FILE {
        return Err(EligibilityError::Unavailable);
    }
    // The supported platform is x86_64 Fedora; Linux-PAM's 64-byte native tally
    // ABI is reviewed. Unknown status/reserved bits and future times refuse.
    for record in tally.bytes.as_chunks::<64>().0 {
        let status = u16::from_le_bytes([record[54], record[55]]);
        let time = u64::from_le_bytes(record[56..64].try_into().map_err(unavailable)?);
        if record[52..54] != [0, 0] || status & !7 != 0 || status & 6 == 6 || time > now {
            return Err(EligibilityError::Unavailable);
        }
    }
    Ok(tally)
}

fn check(uid: u32) -> Result<(), EligibilityError> {
    if rustix::process::getuid().as_raw() != 0
        || rustix::process::geteuid().as_raw() != 0
        || std::env::consts::ARCH != "x86_64"
    {
        return Err(EligibilityError::Unavailable);
    }
    let policies = policy()?;
    let passwd = Snapshot::read("/etc/passwd", 0, None, MAX_DATABASE)?;
    let shadow = Snapshot::read("/etc/shadow", 0, None, MAX_DATABASE)?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(unavailable)?
        .as_secs();
    let user = raw_policy(uid, &passwd.bytes, &shadow.bytes, now / 86_400)?;
    if pam::username(uid).as_ref() != Some(&user) {
        return Err(EligibilityError::Unavailable);
    }
    no_nologin()?;
    let tally = tally(uid, user.to_str().map_err(unavailable)?, now)?;
    let result = pam::password_free(&user);
    // Recheck every input even after a PAM denial. Never interpret an inability
    // to prove unchanged state as a trustworthy account-policy result.
    for snapshot in &policies {
        snapshot.unchanged()?;
    }
    passwd.unchanged()?;
    shadow.unchanged()?;
    tally.unchanged()?;
    no_nologin()?;
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    const HASH: &str = "$6$fixture$......................................................................................";

    fn supervisor(mode: &str) -> EligibilitySupervisor {
        EligibilitySupervisor(crate::supervisor::fixture(
            PathBuf::from("/usr/bin/python3"),
            vec![
                "-c".into(),
                r#"
import os, struct, sys, time
mode = sys.argv[1]
r = b''
while len(r) < 24:
    p = os.read(0, 24-len(r))
    if not p: sys.exit(1)
    r += p
if r[:4] != b'LPE1': sys.exit(2)
if mode == 'stall': time.sleep(10)
token = bytes([9])*16 if mode == 'replay' else r[4:20]
kind = 1 if mode == 'prompt' else 3
code = {'allowed': 0, 'restricted': 1}.get(mode, 2)
f = bytes([kind])+token+struct.pack('!IH',2,1)+bytes([code])
os.write(1,f)
if mode == 'duplicate': os.write(1,f)
"#
                .into(),
                mode.into(),
            ],
            std::time::Duration::from_secs(2),
        ))
    }

    #[test]
    fn password_free_supervisor_binds_one_noninteractive_result() {
        for (mode, expected) in [
            ("allowed", Ok(())),
            ("restricted", Err(EligibilityError::AccountRestricted)),
            ("unknown", Err(EligibilityError::Unavailable)),
            ("replay", Err(EligibilityError::Unavailable)),
            ("prompt", Err(EligibilityError::Unavailable)),
            ("duplicate", Err(EligibilityError::Unavailable)),
        ] {
            let supervisor = supervisor(mode);
            assert_eq!(
                supervisor.check_password_free(
                    1000,
                    BootInstant::now() + std::time::Duration::from_secs(1),
                    &mut || false
                ),
                expected,
                "{mode}"
            );
            let until = BootInstant::now() + std::time::Duration::from_secs(2);
            while supervisor.occupied() != 0 && BootInstant::now() < until {
                std::thread::sleep(std::time::Duration::from_millis(2));
            }
            assert_eq!(supervisor.occupied(), 0);
        }
    }

    #[test]
    fn password_free_supervisor_deadline_and_cancellation_retire_native_work() {
        let supervisor = supervisor("stall");
        for cancel in [false, true] {
            let start = BootInstant::now();
            assert_eq!(
                supervisor.check_password_free(
                    1000,
                    start + std::time::Duration::from_millis(80),
                    &mut || cancel && start.elapsed() >= std::time::Duration::from_millis(20)
                ),
                Err(EligibilityError::Unavailable)
            );
            assert!(start.elapsed() < std::time::Duration::from_secs(1));
            let until = BootInstant::now() + std::time::Duration::from_secs(2);
            while supervisor.occupied() != 0 && BootInstant::now() < until {
                std::thread::sleep(std::time::Duration::from_millis(2));
            }
            assert_eq!(supervisor.occupied(), 0);
        }
    }

    #[test]
    fn strict_supported_hashes_reject_unusable_and_unknown_formats() {
        assert!(supported_hash(HASH));
        assert!(supported_hash(&HASH.replacen("$6$", "$6$rounds=5000$", 1)));
        let yescrypt = format!("$y$j9T${}${}", ".".repeat(22), ".".repeat(43));
        assert!(supported_hash(&yescrypt));
        for hash in [
            "",
            "!",
            "*",
            "$6$malformed",
            "$y$j9T$bad$bad",
            "$1$old$hash",
        ] {
            assert!(!supported_hash(hash));
        }
        assert!(!supported_hash(&yescrypt.replace("j9T", "jAT")));
        assert!(!supported_hash(&format!(
            "{}z",
            &yescrypt[..yescrypt.len() - 1]
        )));
        assert!(!supported_hash(&HASH.replacen(
            "$6$",
            "$6$rounds=0005000$",
            1
        )));
    }

    #[test]
    fn password_free_raw_locks_expiry_forced_change_and_identity() {
        let passwd = b"root:x:0:0:root:/root:/bin/bash\nfixture:x:1000:1000:fixture:/home/fixture:/bin/bash\n";
        let shadow = |hash: &str, last: &str, maximum: &str, expiry: &str| {
            format!("root:!:20000:0:99999:7:::\nfixture:{hash}:{last}:0:{maximum}:7::{expiry}:\n")
        };
        assert!(
            raw_policy(
                1000,
                passwd,
                shadow(HASH, "20000", "99999", "").as_bytes(),
                20001
            )
            .is_ok()
        );
        for record in [
            shadow(&format!("!{HASH}"), "20000", "99999", ""),
            shadow(HASH, "0", "99999", ""),
            shadow(HASH, "20000", "1", ""),
            shadow(HASH, "20000", "99999", "20001"),
        ] {
            assert_eq!(
                raw_policy(1000, passwd, record.as_bytes(), 20001),
                Err(EligibilityError::AccountRestricted)
            );
        }
        assert_eq!(
            raw_policy(
                1001,
                passwd,
                shadow(HASH, "20000", "99999", "").as_bytes(),
                20001
            ),
            Err(EligibilityError::Unavailable)
        );
    }

    #[test]
    fn nss_and_private_policy_refuse_alternative_authorities() {
        assert!(nss_policy("passwd: files\ngroup: files\nshadow: files\n"));
        assert!(!nss_policy(
            "passwd: files sss\ngroup: files\nshadow: files\n"
        ));
        assert!(!nss_policy(
            "passwd: files\npasswd: files\ngroup: files\nshadow: files\n"
        ));
        assert_eq!(
            canonical(include_str!(
                "../policy/localpin-eligibility.review-required"
            )),
            POLICY
        );
        assert_ne!(
            canonical(&format!("auth sufficient pam_permit.so\n{POLICY}")),
            POLICY
        );
    }

    #[test]
    fn kde_policy_preserves_the_measured_stock_bytes_and_one_exact_module_block() {
        let prefix = b"# BEGIN LOCALPIN\nauth [success=done default=ignore] /usr/lib64/security/pam_localpin.so\n# END LOCALPIN\n";
        let stock = LOCALPIN_KDE_POLICY.strip_prefix(prefix).unwrap();
        assert!(digest_is(stock, STOCK_KDE_DIGEST));
        assert!(kde_policy(stock));
        assert!(kde_policy(LOCALPIN_KDE_POLICY));
        assert!(digest_is(
            LOCALPIN_KDE_POLICY,
            "ea0adc6291dccb0360f5d3565c5dad1f8b886d037f0bcadbbfbf70625383375d"
        ));

        let integrated = std::str::from_utf8(LOCALPIN_KDE_POLICY).unwrap();
        for changed in [
            integrated.replace("success=done default=ignore", "default=ignore success=done"),
            integrated.replace("success=done", "success=ok"),
            integrated.replace("default=ignore", "default=bad"),
            integrated.replace("pam_localpin.so\n", "pam_localpin.so debug\n"),
            integrated.replace("/usr/lib64/security/pam_localpin.so", "pam_localpin.so"),
            integrated.replace("pam_localpin.so", "pam_pinlock.so"),
            integrated.replace("password-auth", "system-auth"),
            integrated.replace("auth        substack", "auth        include "),
            integrated.replace("auth [success=done", "account [success=done"),
            integrated.replace("# BEGIN LOCALPIN\n", "# BEGIN LOCALPIN kde\n"),
            format!("auth required pam_access.so\n{integrated}"),
            format!("{integrated}auth sufficient pam_permit.so\n"),
            String::from_utf8(stock.to_vec()).unwrap() + std::str::from_utf8(prefix).unwrap(),
            integrated.replace('\n', "\r\n"),
        ] {
            assert!(!kde_policy(changed.as_bytes()));
        }
        assert!(!kde_policy(
            &LOCALPIN_KDE_POLICY[..LOCALPIN_KDE_POLICY.len() - 1]
        ));
        assert!(!kde_policy(b""));
    }
}
