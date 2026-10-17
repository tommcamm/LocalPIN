//! Fixed, root-controlled desktop activation gate. Enrollment never opens it.

use std::{fs::File, io::Read, os::unix::fs::MetadataExt};

use rustix::fs::{Mode, OFlags, ResolveFlags, openat2};

/// Persistent activation state, separate from account/credential authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Gate {
    /// Missing, malformed, unsafe, explicitly disabled or expired state.
    Disabled,
    /// A bounded, current-boot administrator test window.
    Trial,
    /// Explicit activation after administrator-recorded desktop tests.
    Active,
}

fn valid_boot(boot: &str) -> bool {
    boot.len() == 36
        && boot.bytes().enumerate().all(|(i, b)| {
            if [8, 13, 18, 23].contains(&i) {
                b == b'-'
            } else {
                b.is_ascii_hexdigit() && !b.is_ascii_uppercase()
            }
        })
}

fn parse(bytes: &[u8], boot: &str, now: u64) -> Gate {
    if bytes == b"LPINT01\nactive\n" {
        return Gate::Active;
    }
    let Ok(text) = std::str::from_utf8(bytes) else {
        return Gate::Disabled;
    };
    let fields: Vec<_> = text.split('\n').collect();
    if fields.len() != 6
        || fields[0] != "LPINT01"
        || fields[1] != "trial"
        || !fields[5].is_empty()
        || !valid_boot(fields[2])
        || fields[2] != boot
    {
        return Gate::Disabled;
    }
    let number = |s: &str| {
        if s.is_empty() || s.len() > 20 || !s.bytes().all(|b| b.is_ascii_digit()) {
            None
        } else {
            s.parse::<u64>().ok()
        }
    };
    match (number(fields[3]), number(fields[4])) {
        (Some(start), Some(end))
            if start <= now
                && now < end
                && end
                    .checked_sub(start)
                    .is_some_and(|duration| duration <= 600_000) =>
        {
            Gate::Trial
        }
        _ => Gate::Disabled,
    }
}

/// Read the fixed activation record without following symlinks or trusting
/// writable ancestors. All errors deny only PIN; ordinary PAM continues.
pub fn gate() -> Gate {
    read().unwrap_or(Gate::Disabled)
}

/// Whether the current gate permits a fresh desktop PIN operation.
pub fn permits_pin() -> bool {
    matches!(gate(), Gate::Trial | Gate::Active)
}

fn read() -> std::io::Result<Gate> {
    let root = File::open("/")?;
    for path in ["var", "var/lib", "var/lib/localpin-integration"] {
        let directory = File::from(openat2(
            &root,
            path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
            ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
        )?);
        let m = directory.metadata()?;
        if m.uid() != 0 || m.gid() != 0 || m.mode() & 0o022 != 0 {
            return Ok(Gate::Disabled);
        }
    }
    let mut file = File::from(openat2(
        &root,
        "var/lib/localpin-integration/gate",
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NONBLOCK | OFlags::NOFOLLOW,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    )?);
    let before = file.metadata()?;
    if !before.is_file()
        || before.uid() != 0
        || before.gid() != 0
        || before.mode() & 0o7777 != 0o644
        || before.nlink() != 1
        || before.len() > 160
    {
        return Ok(Gate::Disabled);
    }
    let mut bytes = Vec::new();
    (&mut file).take(161).read_to_end(&mut bytes)?;
    let after = file.metadata()?;
    let named = std::fs::symlink_metadata("/var/lib/localpin-integration/gate")?;
    if bytes.len() > 160
        || named.dev() != before.dev()
        || named.ino() != before.ino()
        || !named.is_file()
        || before.len() != after.len()
        || before.ctime() != after.ctime()
        || before.ctime_nsec() != after.ctime_nsec()
        || before.mtime() != after.mtime()
        || before.mtime_nsec() != after.mtime_nsec()
    {
        return Ok(Gate::Disabled);
    }
    let boot = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")?;
    let now = rustix::time::clock_gettime(rustix::time::ClockId::Boottime);
    let millis = u64::try_from(now.tv_sec)
        .ok()
        .and_then(|s| s.checked_mul(1000))
        .and_then(|s| s.checked_add(u64::try_from(now.tv_nsec).ok()? / 1_000_000));
    Ok(millis.map_or(Gate::Disabled, |now| parse(&bytes, boot.trim(), now)))
}

#[cfg(test)]
mod tests {
    use super::*;
    const BOOT: &str = "01234567-89ab-cdef-0123-456789abcdef";

    #[test]
    fn trial_expires_across_suspend_and_reboot() {
        let bytes = format!("LPINT01\ntrial\n{BOOT}\n1000\n601000\n");
        assert_eq!(parse(bytes.as_bytes(), BOOT, 1000), Gate::Trial);
        assert_eq!(parse(bytes.as_bytes(), BOOT, 600999), Gate::Trial);
        for now in [999, 601000, u64::MAX] {
            assert_eq!(parse(bytes.as_bytes(), BOOT, now), Gate::Disabled);
        }
        assert_eq!(
            parse(bytes.as_bytes(), "different-boot", 2000),
            Gate::Disabled
        );
    }

    #[test]
    fn only_exact_activation_and_bounded_trials_are_accepted() {
        assert_eq!(parse(b"LPINT01\nactive\n", BOOT, 0), Gate::Active);
        for bytes in [
            b"".as_slice(),
            b"LPINT01\nactive",
            b"LPINT01\nactive\nextra\n",
            b"LPINT02\nactive\n",
            b"\xff",
        ] {
            assert_eq!(parse(bytes, BOOT, 1000), Gate::Disabled);
        }
        for (start, end) in [
            ("0", "600001"),
            ("1000", "1000"),
            ("1001", "1000"),
            ("-1", "1000"),
            ("+1", "1000"),
            ("0", "18446744073709551616"),
        ] {
            let trial = format!("LPINT01\ntrial\n{BOOT}\n{start}\n{end}\n");
            assert_eq!(parse(trial.as_bytes(), BOOT, 1000), Gate::Disabled);
        }
    }
}
