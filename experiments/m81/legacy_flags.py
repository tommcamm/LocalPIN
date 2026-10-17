#!/usr/bin/python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Real immutable-flag migration proof in isolated disposable-VM namespaces.

No real guest account database is read or changed. No TPM is opened and no
authentication secret is loaded. The host must independently validate the
clone's live libvirt topology before staging and running this fixed fixture.
"""
import argparse
import array
import fcntl
import hashlib
import json
import os
from pathlib import Path
import platform
import stat
import subprocess
import sys
import tempfile
import uuid

WORK = Path('/root/localpin-m8')
ACCOUNT = Path('/usr/libexec/localpin/localpin-account')
REGISTRY = Path('/var/lib/localpin-accounts/registry')
DIRECTORIES = ('/etc', '/etc/pam.d', '/etc/authselect', '/etc/security')
FILES = tuple('/etc/' + name for name in (
    'passwd', 'shadow', 'group', 'gshadow', 'environment', 'pam.d/kde',
    'pam.d/localpin-enroll', 'pam.d/localpin-eligibility',
    'authselect/password-auth', 'authselect/postlogin', 'authselect/nsswitch.conf',
    'security/faillock.conf', 'security/pam_env.conf'))
GETFLAGS, SETFLAGS = 0x80086601, 0x40086602
IMMUTABLE, NODUMP = 0x10, 0x40
REVOKED = b'LPACCT03\0\0'


def require(value, message):
    if not value:
        raise RuntimeError(message)


def command(args):
    return subprocess.run(args, capture_output=True, timeout=30)


def checked(args):
    result = command(args)
    require(result.returncode == 0, 'fixed fixture command refused')
    return result.stdout


def guard(expected_uuid):
    require(os.getuid() == os.geteuid() == 0 and platform.machine() == 'x86_64', 'guest root/x86_64 required')
    require(str(uuid.UUID(expected_uuid)) == expected_uuid
            and Path('/sys/class/dmi/id/product_uuid').read_text().strip() == expected_uuid, 'clone UUID mismatch')
    require(checked(['systemd-detect-virt', '--vm']).strip() == b'kvm', 'dedicated KVM clone required')
    require(checked(['getenforce']).strip() == b'Enforcing', 'SELinux enforcing required')
    release = dict(row.split('=', 1) for row in Path('/usr/lib/os-release').read_text().splitlines() if '=' in row)
    require(release.get('ID', '').strip('"') == 'fedora' and release.get('VERSION_ID', '').strip('"') == '44'
            and release.get('VARIANT_ID', '').strip('"') == 'kde', 'Fedora KDE 44 required')
    info = WORK.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 0
            and stat.S_IMODE(info.st_mode) == 0o700, 'private fixed guest work directory required')
    for name, value in (('localpin-m8-guard', expected_uuid + '\n'),
                        ('localpin-m8-emulator', expected_uuid + '\nemulator2.0\n')):
        path = Path('/run') / name
        info = path.lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_uid == info.st_gid == 0
                and stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1
                and path.read_text() == value, 'private clone/emulator marker mismatch')
    require(stat.S_ISCHR(Path('/dev/tpmrm0').lstat().st_mode), 'private emulator device missing')
    info = ACCOUNT.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_uid == info.st_gid == 0
            and info.st_nlink == 1 and not info.st_mode & 0o022, 'unsafe installed account helper')


def flags(path, value=None):
    require(str(path) in (*DIRECTORIES, *FILES), 'flag operation escaped fixed synthetic paths')
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        words = array.array('L', [0 if value is None else value])
        fcntl.ioctl(descriptor, GETFLAGS if value is None else SETFLAGS, words, True)
        return words[0]
    finally:
        os.close(descriptor)


def write_registry(data):
    REGISTRY.unlink(missing_ok=True)
    if data is not None:
        descriptor = os.open(REGISTRY, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, 'wb') as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())


def child(expected_uuid):
    guard(expected_uuid)
    source_sha256 = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    helper_sha256 = hashlib.sha256(ACCOUNT.read_bytes()).hexdigest()
    version = checked(['rpm', '-q', '--qf', '%{EVR}', 'localpin']).decode('ascii')
    checked(['mount', '--make-rprivate', '/'])
    result = {}
    with tempfile.TemporaryDirectory(prefix='m81-legacy-flags-', dir=WORK) as temporary:
        root = Path(temporary)
        require(checked(['stat', '-f', '-c', '%T', str(root)]).strip() == b'btrfs', 'private Btrfs fixture required')
        for name in ('etc', 'var', 'run'):
            (root / name).mkdir(mode=0o755)
        for path in DIRECTORIES[1:]:
            (root / path.lstrip('/')).mkdir(mode=0o755)
        for path in (*FILES, '/etc/.pwd.lock'):
            target = root / path.lstrip('/')
            target.write_bytes(b'root:!:20000:0:99999:7:::\n' if path == '/etc/shadow' else b'# synthetic fixture\n')
            target.chmod(0o600)
        accounts = root / 'var/lib/localpin-accounts'
        accounts.mkdir(mode=0o700, parents=True)
        (accounts / 'lock').write_bytes(b'')
        (accounts / 'lock').chmod(0o600)
        mounted = []
        try:
            for name in ('etc', 'var', 'run'):
                checked(['mount', '--bind', str(root / name), '/' + name])
                mounted.append('/' + name)
            original = {path: flags(path) for path in (*FILES, *DIRECTORIES)}

            # A native writer forces refusal after durable revocation and
            # before any immutable transition. No timing/polling assertion.
            target = '/etc/passwd'
            write_registry(b'LPACCT02\0\0\0\0')
            flags(target, original[target] | IMMUTABLE | NODUMP)
            descriptor = os.open('/etc/.pwd.lock', os.O_RDWR | os.O_CLOEXEC)
            try:
                fcntl.lockf(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                code = command([str(ACCOUNT), 'begin-mutation']).returncode
                require(code != 0 and REGISTRY.read_bytes() == REVOKED
                        and flags(target) == original[target] | IMMUTABLE | NODUMP,
                        'revocation did not precede the native-lock/unfreeze boundary')
            finally:
                os.close(descriptor)
                flags(target, original[target])
            result['durable_revocation_before_unfreeze_barrier'] = True

            for magic in (b'LPACCT01', b'LPACCT02'):
                write_registry(magic + b'\0\0\0\0')
                try:
                    for path, value in original.items():
                        flags(path, value | IMMUTABLE | NODUMP)
                    require(command([str(ACCOUNT), 'begin-mutation']).returncode == 0,
                            'recognized complete legacy migration refused')
                    require(REGISTRY.read_bytes() == REVOKED
                            and all(flags(path) == value | NODUMP for path, value in original.items()),
                            'recognized migration failed revocation or changed unrelated inode flags')
                finally:
                    for path, value in original.items():
                        flags(path, value)
            result['complete_legacy_01_and_02_unfreeze_only_immutable_bit'] = True

            name = b'lp61test'
            current = b'LPACCT03\0\1' + (21061).to_bytes(4, 'big') + b'i' * 16 + (7).to_bytes(8, 'big') + bytes([len(name)]) + name
            cases = {'fresh_missing': None, 'empty': b'', 'unknown': b'UNKNOWN!\0\0\0\0',
                     'corrupt_legacy': b'LPACCT02garbage', 'truncated_legacy': b'LPACCT02\0\0',
                     'current_revoked': REVOKED, 'current_active': current}
            for label, data in cases.items():
                for target in ('/etc/passwd', '/etc'):
                    write_registry(data)
                    expected = original[target] | IMMUTABLE | NODUMP
                    flags(target, expected)
                    try:
                        require(command([str(ACCOUNT), 'begin-mutation']).returncode != 0
                                and flags(target) == expected and REGISTRY.read_bytes() == REVOKED,
                                'fresh/unknown/current authority changed a foreign immutable flag')
                    finally:
                        flags(target, original[target])
                result[label + '_foreign_file_and_directory_flags_preserved'] = True
        finally:
            # Every candidate is one of the fixture's known synthetic paths.
            # Unfreeze those exact inodes before unmounting or deleting them.
            if '/etc' in mounted:
                for path in (*FILES, *reversed(DIRECTORIES)):
                    flags(path, flags(path) & ~IMMUTABLE)
            for path in reversed(mounted):
                checked(['umount', path])
    require(checked(['getenforce']).strip() == b'Enforcing', 'SELinux changed')
    require(hashlib.sha256(ACCOUNT.read_bytes()).hexdigest() == helper_sha256,
            'installed account helper changed during the proof')
    print(json.dumps({'passed': True, 'scope': 'installed helper on isolated Btrfs synthetic account inputs',
                      'runner_sha256': source_sha256, 'installed_helper_sha256': helper_sha256,
                      'localpin_version': version, 'selinux': 'Enforcing', 'observations': result,
                      'real_guest_account_databases_changed': False, 'tpm_opened': False,
                      'authentication_secrets_loaded': False}, sort_keys=True))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--expected-uuid', required=True)
    parser.add_argument('--disposable-vm-confirmed', action='store_true', required=True)
    parser.add_argument('--emulated-tpm-confirmed', action='store_true', required=True)
    parser.add_argument('--namespace-child', action='store_true', help=argparse.SUPPRESS)
    args = parser.parse_args()
    guard(args.expected_uuid)
    if args.namespace_child:
        child(args.expected_uuid)
    else:
        result = command(['unshare', '--mount', '--pid', '--fork', '--mount-proc', sys.executable,
                          str(Path(__file__).resolve()), '--expected-uuid', args.expected_uuid,
                          '--disposable-vm-confirmed', '--emulated-tpm-confirmed', '--namespace-child'])
        if result.returncode != 0:
            path = WORK / 'm81-legacy-flags-failure.log'
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
            with os.fdopen(descriptor, 'wb') as stream:
                stream.write(result.stdout + result.stderr)
            raise RuntimeError('isolated immutable-flag proof refused; inspect guest-root-only log')
        sys.stdout.buffer.write(result.stdout)


if __name__ == '__main__':
    try:
        main()
    except Exception:
        print(json.dumps({'passed': False, 'error': 'guarded immutable-flag proof refused; inspect guest-root-only log'}))
        raise SystemExit(1) from None
