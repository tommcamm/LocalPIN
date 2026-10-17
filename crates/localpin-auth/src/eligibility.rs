//! Password-free policy for managed local accounts on Fedora 44 x86_64.
//!
//! Lifecycle ownership/serialization is a separate authority. This worker never
//! provisions accounts, repairs state or verifies a password. Missing tallies
//! refuse service; only explicit privileged provisioning may establish a disabled
//! baseline. The reviewed persistent policy retains native accounting across
//! ordinary reboot without recreating a missing tally. No account material
//! leaves the child.

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
const LOCALPIN_FINGERPRINT_POLICY: &[u8] =
    include_bytes!("../policy/kde-fingerprint-localpin.review-required");
const KDE_PASSWORD_POLICY: &str = include_str!("../policy/localpin-kde-password.review-required");
const KDE_FINGERPRINT_POLICY: &str =
    include_str!("../policy/localpin-kde-fingerprint.review-required");
const VOLATILE_FAILLOCK_DIGEST: &str =
    "662303cf89938c12d95a7fc59d92cbe76c398312527fa908894fb319809093b3";
const PERSISTENT_FAILLOCK_DIGEST: &str =
    "63ea06f1db780b94e59f1cdfa4d50981309d6b40c5f7bdb78853ea6038730249";

/// Exact reviewed native configuration required by installed M8 activation.
pub const PERSISTENT_FAILLOCK_CONFIG: &[u8] = b"dir = /var/lib/faillock\n";
/// The sole persistent native password-accounting directory supported by M8.
pub const PERSISTENT_FAILLOCK_DIRECTORY: &str = "/var/lib/faillock";

/// Select one fixed accounting directory from an exact reviewed config digest.
///
/// The legacy volatile variant remains for earlier component evidence. Unknown
/// configurations never select a path, and missing persistent state never falls
/// back to volatile state. This function does not read or change any filesystem.
pub fn reviewed_faillock_directory(configuration: &[u8]) -> Option<&'static str> {
    if digest_is(configuration, PERSISTENT_FAILLOCK_DIGEST) {
        Some(PERSISTENT_FAILLOCK_DIRECTORY)
    } else if digest_is(configuration, VOLATILE_FAILLOCK_DIGEST) {
        Some("/run/faillock")
    } else {
        None
    }
}

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
    native_tally_access: bool,
}

impl Snapshot {
    fn read(
        path: impl AsRef<Path>,
        uid: u32,
        mode: Option<u32>,
        bound: usize,
    ) -> Result<Self, EligibilityError> {
        Self::read_access(path, uid, mode, bound, false)
    }

    fn read_tally(path: impl AsRef<Path>, uid: u32) -> Result<Self, EligibilityError> {
        // Linux-PAM 1.7.2 opens an existing tally O_RDWR even for preauth,
        // and check_tally treats EACCES/ENOENT as success. Prove that exact
        // access before invoking PAM; a readable but unwritable tally cannot
        // establish native lockout eligibility. Never create or write it.
        Self::read_access(path, uid, Some(0o660), MAX_FILE, true)
    }

    fn read_access(
        path: impl AsRef<Path>,
        uid: u32,
        mode: Option<u32>,
        bound: usize,
        native_tally_access: bool,
    ) -> Result<Self, EligibilityError> {
        let path = path.as_ref();
        // Trust the Fedora-installed stable SONAME, not one build's digest or
        // versioned filename. Re-resolve it on every snapshot/post-check so a
        // package replacement during this transaction makes PIN unavailable.
        let resolved = native_library_path(path)?;
        let file = OpenOptions::new()
            .read(true)
            .write(native_tally_access)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
            .open(&resolved)
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
            native_tally_access,
        })
    }

    fn unchanged(&self) -> Result<(), EligibilityError> {
        let after = Self::read_access(
            &self.path,
            self.uid,
            self.mode,
            self.bound,
            self.native_tally_access,
        )?;
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
        "/etc/pam.d/fingerprint-auth" => "/etc/authselect/fingerprint-auth",
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

/// Conservative syntax boundary shared by every reviewed PAM policy parser.
/// Native Linux-PAM token delimiters are ASCII space, tab and newline. Do not
/// reinterpret Unicode/control whitespace, attached comments or continuations
/// as a known graph. Unicode is harmless only inside a full-line comment whose
/// prefix consists exclusively of ASCII space/tab followed by '#'.
pub(crate) fn pam_syntax_supported(text: &str) -> bool {
    if text.bytes().any(|byte| {
        byte == b'\\' || byte == 0x7f || (byte < 0x20 && !matches!(byte, b'\t' | b'\n'))
    }) {
        return false;
    }
    text.split('\n').all(|line| {
        let line = line.trim_start_matches([' ', '\t']);
        line.is_empty()
            || line.starts_with('#')
            || (!line.contains('#')
                && line
                    .bytes()
                    .all(|byte| byte == b'\t' || (0x20..=0x7e).contains(&byte)))
    })
}

fn canonical(text: &str) -> String {
    text.lines()
        .filter_map(|line| {
            let line = line.split('#').next().unwrap_or("").trim();
            (!line.is_empty()).then(|| line.split_ascii_whitespace().collect::<Vec<_>>().join(" "))
        })
        .collect::<Vec<_>>()
        .join("\n")
        + "\n"
}

// PAM policy formatting and comments may change in an ordinary package update.
// Active directives, controls, module arguments and their order remain exact.
fn canonical_policy(bytes: &[u8], expected: &[u8]) -> bool {
    let (Ok(text), Ok(expected)) = (std::str::from_utf8(bytes), std::str::from_utf8(expected))
    else {
        return false;
    };
    pam_syntax_supported(text)
        && pam_syntax_supported(expected)
        && canonical(text) == canonical(expected)
}

fn kde_policy(bytes: &[u8]) -> bool {
    digest_is(bytes, STOCK_KDE_DIGEST) || canonical_policy(bytes, LOCALPIN_KDE_POLICY)
}

fn nss_policy(text: &str) -> bool {
    ["passwd", "group", "shadow"].iter().all(|database| {
        let mut matches = text
            .lines()
            .map(|line| line.split('#').next().unwrap_or("").trim())
            .filter_map(|line| line.split_once(':'))
            .filter(|(key, _)| key.trim() == *database);
        matches.next().is_some_and(|(_, value)| {
            let providers: Vec<_> = value.split_ascii_whitespace().collect();
            providers == ["files"]
                || providers == ["files", "systemd"]
                || (*database == "group" && providers == ["files", "[SUCCESS=merge]", "systemd"])
        }) && matches.next().is_none()
    })
}

// Linux-PAM accepts type names case-insensitively and treats unknown types as
// failing authentication handlers. Never discard such active lines while
// extracting the reviewed authentication/account sections: doing so could
// select the correction and bypass a native required restriction.
fn canonical_pam_types(text: &str) -> bool {
    pam_syntax_supported(text)
        && canonical(text)
            .lines()
            .filter(|line| !line.is_empty())
            .all(|line| {
                line.split_once(' ').is_some_and(|(kind, rest)| {
                    !rest.is_empty()
                        && matches!(
                            kind,
                            "auth"
                                | "-auth"
                                | "account"
                                | "-account"
                                | "password"
                                | "-password"
                                | "session"
                                | "-session"
                        )
                })
            })
}

fn postlogin_policy(text: &str) -> bool {
    canonical_pam_types(text)
        && !canonical(text)
            .lines()
            .any(|line| line.starts_with("auth ") || line.starts_with("-auth "))
}

fn password_auth_policy(text: &str) -> bool {
    if !canonical_pam_types(text) {
        return false;
    }
    let text = canonical(text);
    let mut auth: Vec<_> = text
        .lines()
        .filter(|line| line.starts_with("auth ") || line.starts_with("-auth "))
        .collect();
    let accounts: Vec<_> = text
        .lines()
        .filter(|line| line.starts_with("account ") || line.starts_with("-account "))
        .collect();
    if auth.first() != Some(&"auth required pam_env.so") {
        return false;
    }
    auth.remove(0);
    if auth.first() != Some(&"auth required pam_faildelay.so delay=2000000") {
        return false;
    }
    auth.remove(0);
    let faillock = auth.first() == Some(&"auth required pam_faillock.so preauth silent");
    if faillock {
        auth.remove(0);
    }
    if !matches!(
        auth.first(),
        Some(&"auth sufficient pam_unix.so" | &"auth sufficient pam_unix.so nullok")
    ) {
        return false;
    }
    auth.remove(0);
    if faillock {
        if auth.first() != Some(&"auth required pam_faillock.so authfail") {
            return false;
        }
        auth.remove(0);
    }
    for optional in [
        "auth optional pam_gnome_keyring.so only_if=login auto_start",
        "auth optional pam_kwallet5.so only_if=login auto_start",
        "auth optional pam_oo7.so only_if=login auto_start",
    ] {
        if auth.first() == Some(&optional) {
            auth.remove(0);
        }
    }
    auth == ["auth required pam_deny.so"]
        && if faillock {
            accounts
                == [
                    "account required pam_faillock.so",
                    "account required pam_unix.so",
                ]
        } else {
            accounts == ["account required pam_unix.so"]
        }
}

fn fingerprint_auth_policy(text: &str) -> bool {
    if !canonical_pam_types(text) {
        return false;
    }
    let text = canonical(text);
    let mut auth: Vec<_> = text
        .lines()
        .filter(|line| line.starts_with("auth ") || line.starts_with("-auth "))
        .collect();
    let accounts: Vec<_> = text
        .lines()
        .filter(|line| line.starts_with("account ") || line.starts_with("-account "))
        .collect();
    if auth.first() != Some(&"auth required pam_env.so") {
        return false;
    }
    auth.remove(0);
    let faillock = auth.first() == Some(&"auth required pam_faillock.so preauth silent");
    if faillock {
        auth.remove(0);
    }
    if auth.first() != Some(&"auth [success=done default=bad] pam_fprintd.so") {
        return false;
    }
    auth.remove(0);
    if faillock {
        if auth.first() != Some(&"auth required pam_faillock.so authfail") {
            return false;
        }
        auth.remove(0);
    }
    for optional in [
        "auth optional pam_gnome_keyring.so only_if=login auto_start",
        "auth optional pam_kwallet5.so only_if=login auto_start",
        "auth optional pam_oo7.so only_if=login auto_start",
    ] {
        if auth.first() == Some(&optional) {
            auth.remove(0);
        }
    }
    auth == ["auth required pam_deny.so"]
        && if faillock {
            accounts
                == [
                    "account required pam_faillock.so",
                    "account required pam_unix.so",
                    "account required pam_permit.so",
                ]
        } else {
            accounts
                == [
                    "account required pam_unix.so",
                    "account required pam_permit.so",
                ]
        }
}

fn fingerprint_auth_compatible(text: &str) -> bool {
    pam_syntax_supported(text)
        && (canonical(text) == "auth required pam_debug.so auth=authinfo_unavail\n"
            || fingerprint_auth_policy(text))
}

/// Check whether a KDE native substack may use LocalPIN's accounting correction.
///
/// This noninteractive policy selector never authenticates a user, touches a
/// candidate or changes a tally. Unknown/custom policy selects the original
/// authselect substack, preserving additional factors and site restrictions.
/// The PAM adapter's explicit `policy` invocation is its sole consumer.
pub fn kde_native_policy_supported(service: &[u8]) -> bool {
    native_policy_matches(service, false)
}

/// Check native policy compatibility without enabling a disabled authenticator.
///
/// Fedora's authselect profile without `with-fingerprint` contains only a
/// rejecting pam_debug entry. It is compatible with PIN eligibility, but never
/// selects the fingerprint accounting correction: the guard still returns
/// ignore and executes that original rejecting entry.
pub fn kde_native_policy_compatible(service: &[u8]) -> bool {
    native_policy_matches(service, true)
}

fn native_policy_matches(service: &[u8], permit_disabled_fingerprint: bool) -> bool {
    let (path, validate): (&str, fn(&str) -> bool) = match service {
        b"kde" => ("/etc/pam.d/password-auth", password_auth_policy),
        b"kde-fingerprint" => (
            "/etc/pam.d/fingerprint-auth",
            if permit_disabled_fingerprint {
                fingerprint_auth_compatible
            } else {
                fingerprint_auth_policy
            },
        ),
        _ => return false,
    };
    let check = || -> Result<(), EligibilityError> {
        for directory_path in ["/", "/etc", "/etc/pam.d", "/etc/authselect"] {
            directory(Path::new(directory_path))?;
        }
        let snapshot = Snapshot::read(policy_path(path)?, 0, None, MAX_FILE)?;
        if !validate(std::str::from_utf8(&snapshot.bytes).map_err(unavailable)?) {
            return Err(EligibilityError::Unavailable);
        }
        let postlogin = Snapshot::read(policy_path("/etc/pam.d/postlogin")?, 0, None, MAX_FILE)?;
        if !postlogin_policy(std::str::from_utf8(&postlogin.bytes).map_err(unavailable)?) {
            return Err(EligibilityError::Unavailable);
        }
        snapshot.unchanged()?;
        postlogin.unchanged()
    };
    check().is_ok()
}

fn native_library_path(path: &Path) -> Result<PathBuf, EligibilityError> {
    if path != Path::new("/usr/lib64/libpam.so.0") {
        return Ok(path.to_owned());
    }
    let metadata = std::fs::symlink_metadata(path).map_err(unavailable)?;
    if !metadata.file_type().is_symlink() {
        return Ok(path.to_owned());
    }
    let target = std::fs::read_link(path).map_err(unavailable)?;
    let name = target.to_str().ok_or(EligibilityError::Unavailable)?;
    if metadata.uid() != 0
        || metadata.gid() != 0
        || !name.starts_with("libpam.so.0.")
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(EligibilityError::Unavailable);
    }
    Ok(Path::new("/usr/lib64").join(target))
}

fn policy() -> Result<(Vec<Snapshot>, &'static str), EligibilityError> {
    for path in [
        "/",
        "/etc",
        "/etc/pam.d",
        "/etc/authselect",
        "/etc/security",
        "/usr",
        "/usr/lib64",
        "/usr/lib64/security",
        "/usr/bin",
    ] {
        directory(Path::new(path))?;
    }
    let mut snapshots = Vec::new();
    // Fedora owns the stable Linux-PAM ABI and native modules. DNF may replace
    // their builds without revoking an account incarnation. Each live operation
    // still requires safe root ownership, bounded regular files and unchanged
    // inputs through completion; missing or racing packages fail closed.
    for path in [
        "/usr/lib64/libpam.so.0",
        "/usr/lib64/security/pam_env.so",
        "/usr/lib64/security/pam_faildelay.so",
        "/usr/lib64/security/pam_faillock.so",
        "/usr/lib64/security/pam_unix.so",
        "/usr/lib64/security/pam_nologin.so",
        "/usr/bin/unix_chkpwd",
    ] {
        snapshots.push(Snapshot::read(path, 0, None, 4 * MAX_DATABASE)?);
    }
    let kde = Snapshot::read(policy_path("/etc/pam.d/kde")?, 0, None, MAX_FILE)?;
    if !kde_policy(&kde.bytes) {
        return Err(EligibilityError::Unavailable);
    }
    if canonical_policy(&kde.bytes, LOCALPIN_KDE_POLICY) {
        for (path, expected) in [
            ("/etc/pam.d/kde-fingerprint", LOCALPIN_FINGERPRINT_POLICY),
            (
                "/etc/pam.d/localpin-kde-password",
                KDE_PASSWORD_POLICY.as_bytes(),
            ),
            (
                "/etc/pam.d/localpin-kde-fingerprint",
                KDE_FINGERPRINT_POLICY.as_bytes(),
            ),
        ] {
            let snapshot = Snapshot::read(path, 0, None, MAX_FILE)?;
            if !canonical_policy(&snapshot.bytes, expected) {
                return Err(EligibilityError::Unavailable);
            }
            snapshots.push(snapshot);
        }
    }
    snapshots.push(kde);
    // The integrated authentication route owns its substacks. Authselect may
    // regenerate its files on upgrades, but additional account restrictions or
    // postlogin auth hooks need an explicit compatibility extension before PIN.
    for path in [
        "/etc/pam.d/password-auth",
        "/etc/pam.d/fingerprint-auth",
        "/etc/pam.d/postlogin",
    ] {
        let snapshot = Snapshot::read(policy_path(path)?, 0, None, MAX_FILE)?;
        let text = std::str::from_utf8(&snapshot.bytes).map_err(unavailable)?;
        if (path.ends_with("password-auth") && !password_auth_policy(text))
            || (path.ends_with("fingerprint-auth") && !fingerprint_auth_compatible(text))
            || (path.ends_with("postlogin") && !postlogin_policy(text))
        {
            return Err(EligibilityError::Unavailable);
        }
        snapshots.push(snapshot);
    }
    let faillock = Snapshot::read("/etc/security/faillock.conf", 0, None, MAX_FILE)?;
    let tally_directory =
        reviewed_faillock_directory(&faillock.bytes).ok_or(EligibilityError::Unavailable)?;
    snapshots.push(faillock);
    let service = Snapshot::read(SERVICE, 0, None, MAX_FILE)?;
    if !canonical_policy(&service.bytes, POLICY.as_bytes()) {
        return Err(EligibilityError::Unavailable);
    }
    snapshots.push(service);
    let enrollment = Snapshot::read("/etc/pam.d/localpin-enroll", 0, None, MAX_FILE)?;
    if !canonical_policy(&enrollment.bytes, pam::SUPPORTED_POLICY.as_bytes()) {
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
    Ok((snapshots, tally_directory))
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
        // Root provisioning reserves the unused shadow flag for a live
        // account-generation marker. userdel/useradd clears it; normal password
        // and aging administration retain it. The lifecycle authority checks its
        // exact binding to the protected random incarnation independently.
        let marker = fields[8];
        if !supported_hash(fields[1])
            || (!marker.is_empty()
                && (marker.starts_with('0')
                    || !marker.bytes().all(|byte| byte.is_ascii_digit())
                    || marker
                        .parse::<u64>()
                        .ok()
                        .filter(|value| *value != 0 && *value < u64::from(u32::MAX))
                        .is_none()))
        {
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

fn tally(
    uid: u32,
    name: &str,
    now: u64,
    tally_directory: &'static str,
) -> Result<Snapshot, EligibilityError> {
    // Check every fixed ancestor; a persistent policy never probes the legacy
    // volatile directory if its own directory or tally is missing.
    for ancestor in Path::new(tally_directory).ancestors() {
        directory(ancestor)?;
    }
    let tally = Snapshot::read_tally(format!("{tally_directory}/{name}"), uid)?;
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
    let (policies, tally_directory) = policy()?;
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
    let tally = tally(
        uid,
        user.to_str().map_err(unavailable)?,
        now,
        tally_directory,
    )?;
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
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};

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
    fn faillock_config_selects_only_exact_reviewed_directories() {
        let stock = include_bytes!("../tests/fixtures/faillock-stock.conf");
        assert!(digest_is(stock, VOLATILE_FAILLOCK_DIGEST));
        assert_eq!(reviewed_faillock_directory(stock), Some("/run/faillock"));
        assert!(digest_is(
            PERSISTENT_FAILLOCK_CONFIG,
            PERSISTENT_FAILLOCK_DIGEST
        ));
        assert_eq!(
            reviewed_faillock_directory(PERSISTENT_FAILLOCK_CONFIG),
            Some(PERSISTENT_FAILLOCK_DIRECTORY)
        );
        // Equivalent-looking syntax, extra policy and caller-selected paths
        // are not alternate authorities. The byte-exact immutable input owns
        // the selection, rather than a generic configuration parser.
        for changed in [
            b"dir=/var/lib/faillock\n".as_slice(),
            b"dir = /var/lib/faillock",
            b"dir = /var/lib/faillock\r\n",
            b"dir = /var/lib/faillock\ndeny = 0\n",
            b"dir = /run/faillock\n",
            b"dir = /tmp/faillock\n",
            b"# dir = /var/lib/faillock\n",
            b"",
        ] {
            assert_eq!(reviewed_faillock_directory(changed), None);
        }
    }

    #[test]
    #[ignore = "requires unprivileged user/mount namespaces and bubblewrap; no host authentication"]
    fn native_tally_requires_write_access_without_mutating_canonical_state() {
        const CHILD: &str = "LOCALPIN_TALLY_ACCESS_CHILD";
        const TEST: &str = "eligibility::tests::native_tally_requires_write_access_without_mutating_canonical_state";
        if let Some(mode) = std::env::var_os(CHILD) {
            assert_eq!(rustix::process::getuid().as_raw(), 0);
            let path = Path::new("/fixture/tally");
            // Both mounts expose the same canonical root:root 0660 record.
            // An ordinary read succeeds on the read-only mount. The preflight
            // must reject lost write access independently of PAM's mapping.
            let ordinary = Snapshot::read(path, 0, Some(0o660), MAX_FILE).unwrap();
            ordinary.unchanged().unwrap();
            let before = std::fs::read(path).unwrap();
            let metadata = std::fs::metadata(path).unwrap();
            match mode.to_str().unwrap() {
                "read-only" => {
                    assert!(matches!(
                        Snapshot::read_tally(path, 0),
                        Err(EligibilityError::Unavailable)
                    ));
                    // Exercise the after-PAM reopen separately: unchanged
                    // bytes are insufficient when native access is denied.
                    let mut saved = ordinary;
                    saved.native_tally_access = true;
                    assert_eq!(saved.unchanged(), Err(EligibilityError::Unavailable));
                }
                "writable" => {
                    let native = Snapshot::read_tally(path, 0).unwrap();
                    assert!(native.native_tally_access);
                    native.unchanged().unwrap();
                }
                _ => panic!("unsupported private tally test mode"),
            }
            assert_eq!(std::fs::read(path).unwrap(), before);
            assert!(same_metadata(&metadata, &std::fs::metadata(path).unwrap()));
            assert!(matches!(
                Snapshot::read_tally("/fixture/missing", 0),
                Err(EligibilityError::Unavailable)
            ));
            assert!(!Path::new("/fixture/missing").exists());
            return;
        }
        assert_ne!(rustix::process::getuid().as_raw(), 0, "refusing host root");
        let mut random = [0; 8];
        getrandom::fill(&mut random).unwrap();
        let fixture = std::env::temp_dir().join(format!(
            "localpin-tally-access-{}-{}",
            std::process::id(),
            u64::from_be_bytes(random)
        ));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&fixture)
            .unwrap();
        let path = fixture.join("tally");
        std::fs::write(&path, [0; 64]).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o660)).unwrap();
        for (mode, binding) in [("read-only", "--ro-bind"), ("writable", "--bind")] {
            let output = std::process::Command::new("/usr/bin/unshare")
                .args([
                    "--user",
                    "--map-root-user",
                    "--net",
                    "--",
                    "/usr/bin/bwrap",
                    "--unshare-all",
                    "--share-net",
                    "--die-with-parent",
                    "--clearenv",
                    "--uid",
                    "0",
                    "--gid",
                    "0",
                    "--ro-bind",
                    "/usr",
                    "/usr",
                    "--symlink",
                    "usr/lib64",
                    "/lib64",
                    "--symlink",
                    "usr/lib",
                    "/lib",
                    "--proc",
                    "/proc",
                    "--dev",
                    "/dev",
                    "--ro-bind",
                ])
                .arg(std::env::current_exe().unwrap())
                .args(["/test", binding])
                .arg(&fixture)
                .args([
                    "/fixture",
                    "--setenv",
                    CHILD,
                    mode,
                    "--",
                    "/test",
                    "--ignored",
                    "--exact",
                    TEST,
                    "--nocapture",
                ])
                .env_clear()
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{mode}: {}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
        std::fs::remove_dir_all(fixture).unwrap();
    }

    #[test]
    fn owned_kde_policy_accepts_distro_formatting_but_refuses_changed_controls() {
        let prefix = "# BEGIN LOCALPIN\nauth [success=done default=ignore] /usr/lib64/security/pam_localpin.so\n# END LOCALPIN\n";
        let integrated = std::str::from_utf8(LOCALPIN_KDE_POLICY).unwrap();
        let stock = integrated
            .strip_prefix(prefix)
            .unwrap()
            .replace("localpin-kde-password", "password-auth");
        assert!(digest_is(stock.as_bytes(), STOCK_KDE_DIGEST));
        assert!(kde_policy(stock.as_bytes()));
        assert!(kde_policy(LOCALPIN_KDE_POLICY));
        assert!(kde_policy(
            integrated.replace("auth        ", "auth\t").as_bytes()
        ));
        assert!(kde_policy(
            format!("# Fedora update\n{integrated}\n").as_bytes()
        ));
        assert!(!kde_policy(
            integrated
                .replace(
                    "auth        substack      localpin-kde-password",
                    "auth substack localpin-kde-password # Fedora comment"
                )
                .as_bytes()
        ));
        for changed in [
            integrated.replace("success=done", "success=ok"),
            integrated.replace("default=ignore", "default=bad"),
            integrated.replace("pam_localpin.so\n", "pam_localpin.so debug\n"),
            integrated.replace("/usr/lib64/security/pam_localpin.so", "pam_localpin.so"),
            integrated.replace("pam_localpin.so", "pam_pinlock.so"),
            integrated.replace("localpin-kde-password", "password-auth"),
            integrated.replace("auth        substack", "auth        include "),
            integrated.replace("auth [success=done", "account [success=done"),
            format!("auth required pam_access.so\n{integrated}"),
            format!("{integrated}auth sufficient pam_permit.so\n"),
            stock + prefix,
        ] {
            assert!(!kde_policy(changed.as_bytes()));
        }
        assert!(!kde_policy(b""));
        assert!(!kde_policy(format!("{integrated}\0").as_bytes()));
    }

    #[test]
    fn fingerprint_policy_counts_only_real_rejection_and_never_unavailable() {
        let policy = canonical(KDE_FINGERPRINT_POLICY);
        assert_eq!(
            policy,
            "auth [success=3 default=ignore] /usr/lib64/security/pam_localpin.so policy\nauth substack fingerprint-auth\nauth sufficient pam_permit.so\nauth requisite pam_deny.so\nauth required pam_env.so\nauth requisite pam_faillock.so preauth silent\nauth [success=1 auth_err=bad maxtries=bad default=die] pam_fprintd.so\nauth [default=die] pam_faillock.so authfail\nauth required pam_faillock.so authsucc\n"
        );
        for changed in [
            policy.replace("default=die] pam_fprintd", "default=bad] pam_fprintd"),
            policy.replace("preauth silent", "preauth silent deny=0"),
            policy.replace("success=1", "success=2"),
            policy.replace("authfail", "authsucc"),
        ] {
            assert!(!canonical_policy(
                changed.as_bytes(),
                KDE_FINGERPRINT_POLICY.as_bytes()
            ));
        }
        assert!(nss_policy(
            "passwd: files systemd\ngroup: files [SUCCESS=merge] systemd\nshadow: files systemd\n"
        ));
        assert!(!nss_policy(
            "passwd: systemd files\ngroup: files\nshadow: files\n"
        ));
        assert!(!nss_policy(
            "passwd: files [SUCCESS=return] systemd\ngroup: files\nshadow: files\n"
        ));
    }

    #[test]
    fn generated_password_auth_refuses_unimplemented_authentication_factors() {
        let base = "auth required pam_env.so\nauth required pam_faildelay.so delay=2000000\nauth sufficient pam_unix.so nullok\nauth required pam_deny.so\naccount required pam_unix.so\n";
        assert!(password_auth_policy(base));
        let locked = base
            .replace(
                "auth sufficient pam_unix",
                "auth required pam_faillock.so preauth silent\nauth sufficient pam_unix",
            )
            .replace(
                "auth required pam_deny",
                "auth required pam_faillock.so authfail\nauth required pam_deny",
            )
            .replace(
                "account required pam_unix",
                "account required pam_faillock.so\naccount required pam_unix",
            );
        assert!(password_auth_policy(&locked));
        for changed in [
            base.replace(
                "auth sufficient pam_unix",
                "auth required pam_u2f.so cue\nauth sufficient pam_unix",
            ),
            base.replace(
                "account required pam_unix",
                "account required pam_access.so\naccount required pam_unix",
            ),
            base.replace("pam_unix.so nullok", "pam_unix.so nullok obscure"),
            base.replace("pam_unix.so nullok", "pam_sss.so forward_pass"),
            base.replace("pam_env.so", "pam_env.so readenv=1"),
        ] {
            assert!(!password_auth_policy(&changed));
        }
    }

    #[test]
    fn disabled_fingerprint_is_compatible_but_never_selects_sensor_correction() {
        let disabled = "# Generated without with-fingerprint\nauth required pam_debug.so auth=authinfo_unavail\n";
        assert!(fingerprint_auth_compatible(disabled));
        assert!(!fingerprint_auth_policy(disabled));
        assert!(fingerprint_auth_compatible(
            "# Disabled fingerprint ☃\nauth\trequired pam_debug.so auth=authinfo_unavail\n"
        ));
        for altered in [
            disabled.replace("authinfo_unavail", "success"),
            format!("{disabled}auth sufficient pam_fprintd.so\n"),
            format!("{disabled}account required pam_permit.so\n"),
        ] {
            assert!(!fingerprint_auth_compatible(&altered));
        }
    }

    #[test]
    fn native_graphs_never_ignore_noncanonical_or_unknown_pam_types() {
        let password = "auth required pam_env.so\nauth required pam_faildelay.so delay=2000000\nauth sufficient pam_unix.so\nauth required pam_deny.so\naccount required pam_unix.so\n";
        let fingerprint = "auth required pam_env.so\nauth [success=done default=bad] pam_fprintd.so\nauth required pam_deny.so\naccount required pam_unix.so\naccount required pam_permit.so\n";
        assert!(password_auth_policy(password));
        assert!(fingerprint_auth_policy(fingerprint));
        for added in [
            "AUTH requisite pam_deny.so\n",
            "-AUTH requisite pam_deny.so\n",
            "ACCOUNT required pam_deny.so\n",
            "unknown requisite pam_deny.so\n",
            "auth\n",
            "@include another-policy\n",
        ] {
            assert!(!password_auth_policy(&format!("{added}{password}")));
            assert!(!fingerprint_auth_policy(&format!("{added}{fingerprint}")));
        }
    }

    #[test]
    fn postlogin_rejects_auth_hooks_and_unrecognized_active_types() {
        let baseline = "session optional pam_unix.so\n-session optional pam_systemd.so\n";
        assert!(postlogin_policy(baseline));
        assert!(postlogin_policy("# No active hooks\n"));
        for added in [
            "auth requisite pam_deny.so\n",
            "AUTH requisite pam_deny.so\n",
            "-AUTH requisite pam_deny.so\n",
            "unknown requisite pam_deny.so\n",
            "session\n",
            "@include another-policy\n",
        ] {
            assert!(!postlogin_policy(&format!("{added}{baseline}")));
        }
    }

    #[test]
    fn pam_canonicalization_never_repairs_unsupported_native_syntax() {
        let password = "auth required pam_env.so\nauth required pam_faildelay.so delay=2000000\nauth sufficient pam_unix.so\nauth required pam_deny.so\naccount required pam_unix.so\n";
        let disabled = "auth required pam_debug.so auth=authinfo_unavail\n";
        assert!(pam_syntax_supported(" \t# Unicode comment ☃\n"));
        assert!(canonical_policy(
            format!("# Unicode comment ☃\n{password}").as_bytes(),
            password.as_bytes()
        ));
        for malformed in [
            format!("\u{a0}{password}"),
            format!("\u{a0}# hidden comment\n{password}"),
            password.replace("auth required pam_env.so", "auth\u{b}required pam_env.so"),
            password.replace("auth required pam_env.so", "auth\u{c}required pam_env.so"),
            password.replace("pam_env.so", "pam_env.so#attached"),
            password.replace("pam_env.so", "pam_env.so # inline"),
            password.replace("pam_env.so", "pam_env.so λ"),
            password.replace('\n', "\r\n"),
            format!("# continued \\\n{password}"),
            password.replace("pam_env.so", "pam_env.so\0"),
        ] {
            assert!(!pam_syntax_supported(&malformed));
            assert!(!password_auth_policy(&malformed));
            assert!(!canonical_policy(malformed.as_bytes(), password.as_bytes()));
            assert!(!postlogin_policy(&malformed));
        }
        assert!(!fingerprint_auth_compatible(&format!("\u{a0}{disabled}")));
        assert!(!fingerprint_auth_compatible(&format!(
            "\u{a0}# comment\n{disabled}"
        )));
    }

    #[test]
    fn managed_shadow_marker_is_bounded_and_canonical() {
        let passwd = b"fixture:x:1000:1000::/home/fixture:/bin/bash\n";
        let base = format!("fixture:{HASH}:20000:0:99999:7:::\n");
        for marker in ["1", "4294967294"] {
            let marked = base.trim_end().to_owned() + marker + "\n";
            assert!(raw_policy(1000, passwd, marked.as_bytes(), 20001).is_ok());
        }
        for marker in [
            "0",
            "01",
            "+1",
            "-1",
            "4294967295",
            "4294967296",
            "18446744073709551615",
            "18446744073709551616",
            "bad",
        ] {
            let marked = base.trim_end().to_owned() + marker + "\n";
            assert_eq!(
                raw_policy(1000, passwd, marked.as_bytes(), 20001),
                Err(EligibilityError::Unavailable)
            );
        }
    }
}
