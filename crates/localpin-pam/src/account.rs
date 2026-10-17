//! Bounded files-only target binding; never invoke potentially blocking NSS.

use std::fs::{File, OpenOptions};
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

const MAX_PASSWD: usize = 1024 * 1024;

fn trusted_directory(path: &str) -> bool {
    std::fs::symlink_metadata(path).is_ok_and(|metadata| {
        metadata.is_dir() && metadata.uid() == 0 && metadata.mode() & 0o022 == 0
    })
}

fn read_passwd() -> Option<Vec<u8>> {
    if !trusted_directory("/") || !trusted_directory("/etc") {
        return None;
    }
    let file: File = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open("/etc/passwd")
        .ok()?;
    let metadata = file.metadata().ok()?;
    if !metadata.is_file()
        || metadata.uid() != 0
        || metadata.mode() & 0o022 != 0
        || metadata.len() > MAX_PASSWD as u64
    {
        return None;
    }
    let mut bytes = Vec::new();
    file.take((MAX_PASSWD + 1) as u64)
        .read_to_end(&mut bytes)
        .ok()?;
    (bytes.len() <= MAX_PASSWD).then_some(bytes)
}

fn decimal(bytes: &[u8]) -> Option<u32> {
    if bytes.is_empty() || !bytes.iter().all(u8::is_ascii_digit) {
        return None;
    }
    bytes.iter().try_fold(0_u32, |value, byte| {
        value.checked_mul(10)?.checked_add(u32::from(byte - b'0'))
    })
}

fn binds(bytes: &[u8], name: &[u8], real: u32, effective: u32) -> bool {
    if real == 0
        || real != effective
        || name.is_empty()
        || name.len() > 256
        || name.contains(&0)
        || !bytes.ends_with(b"\n")
        || bytes.contains(&0)
    {
        return false;
    }
    let mut named = 0;
    let mut identified = 0;
    for line in bytes[..bytes.len() - 1].split(|byte| *byte == b'\n') {
        let mut fields = line.split(|byte| *byte == b':');
        let Some(record_name) = fields.next() else {
            return false;
        };
        let Some(_password) = fields.next() else {
            return false;
        };
        let Some(record_uid) = fields.next().and_then(decimal) else {
            return false;
        };
        let Some(_gid) = fields.next().and_then(decimal) else {
            return false;
        };
        if record_name.is_empty() || fields.count() != 3 {
            return false;
        }
        if record_name == name {
            named += 1;
            if record_uid != real {
                return false;
            }
        }
        if record_uid == real {
            identified += 1;
            if record_name != name {
                return false;
            }
        }
    }
    named == 1 && identified == 1
}

pub(crate) fn supported(name: &[u8], real: u32, effective: u32) -> bool {
    if real == 0 || real != effective {
        return false;
    }
    read_passwd().is_some_and(|bytes| binds(&bytes, name, real, effective))
}

#[cfg(test)]
mod tests {
    use super::*;

    const PASSWD: &[u8] =
        b"root:x:0:0:root:/root:/bin/bash\nfixture:x:2000:2000:fixture:/home/fixture:/bin/bash\n";

    #[test]
    fn exact_unique_name_and_nonroot_real_effective_identity_are_required() {
        assert!(binds(PASSWD, b"fixture", 2000, 2000));
        for (name, real, effective) in [
            (b"root".as_slice(), 0, 0),
            (b"fixture".as_slice(), 2000, 0),
            (b"fixture".as_slice(), 0, 2000),
            (b"fixture".as_slice(), 2001, 2001),
            (b"foreign".as_slice(), 2000, 2000),
        ] {
            assert!(!binds(PASSWD, name, real, effective));
        }
        for extra in [
            b"alias:x:2000:2000::/home/alias:/bin/bash\n".as_slice(),
            b"fixture:x:2001:2000::/home/fixture:/bin/bash\n",
            b"fixture:x:2000:2000::/home/fixture:/bin/bash\n",
        ] {
            assert!(!binds(&[PASSWD, extra].concat(), b"fixture", 2000, 2000));
        }
    }

    #[test]
    fn malformed_and_noncanonical_databases_fail_closed() {
        for bytes in [
            b"fixture:x:2000:2000::/home/fixture:/bin/bash".as_slice(),
            b"fixture:x:2000:2000::/home/fixture:/bin/bash\n\n",
            b"fixture:x:+2000:2000::/home/fixture:/bin/bash\n",
            b"fixture:x:4294967296:2000::/home/fixture:/bin/bash\n",
            b"fixture:x:2000:2000::/home/fixture:/bin/bash:extra\n",
            b"fixture:x:2000:2000:\0:/home/fixture:/bin/bash\n",
        ] {
            assert!(!binds(bytes, b"fixture", 2000, 2000));
        }
    }
}
