#!/usr/bin/python3 -I
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Fixed-path, non-setuid Fedora appliance activation and console recovery.

There is deliberately no alternate root, command, policy, secret or environment
override. Importable functions permit synthetic filesystem tests; the installed
entry point always uses the fixed production paths below.
"""
import argparse
import contextlib
import difflib
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import stat
import subprocess
import sys
import time
import uuid

STATE = Path('/var/lib/localpin-integration')
CONTROL = STATE / 'control'
MANIFEST = CONTROL / 'manifest.json'
GATE = STATE / 'gate'
KDE = Path('/etc/pam.d/kde')
MODULE = Path('/usr/lib64/security/pam_localpin.so')
ACCOUNT = '/usr/libexec/localpin/localpin-account'
POLICY = Path('/usr/share/localpin/policy')
PERSISTENT = b'dir = /var/lib/faillock\n'
STOCK = '7d91b3ad73a998e8b10f9edccd74ba04179a778c4a5e61d9176872f43c7bbac3'
INTEGRATED = 'ea0adc6291dccb0360f5d3565c5dad1f8b886d037f0bcadbbfbf70625383375d'
DEFAULT_AUTH = '2e53f704372b6c7fb69cdc4dfd6c27456d642c83feff8b1588fa1f9cb1126cd0'
FAILLOCK_AUTH = 'de00ea01b5ffe6b08efd7027e437bdd4a3bad18e231e9593f6b45cc64b334276'
POSTLOGIN = 'c1ecd4d1a5b5de7d26e3336cd33551d1d65e13751b5f46405183472895838a9d'
PREFIX = b'# BEGIN LOCALPIN\nauth [success=done default=ignore] /usr/lib64/security/pam_localpin.so\n# END LOCALPIN\n'
LEGACY_PREFIX = b'# BEGIN local screen-unlock PIN\nauth sufficient pam_pinlock.so retries=1\n# END local screen-unlock PIN\n'
ENV = {'PATH': '/usr/sbin:/usr/bin', 'LANG': 'C', 'LC_ALL': 'C'}
NATIVE = {
    '/usr/lib64/libpam.so.0.85.1': 'e8a3e3aa67cc17d4c659892fe63b9695ae202b6f107170f1ef5bb345570a8760',
    '/usr/lib64/security/pam_env.so': '5a54893c723005dc9b33b1f7da87fd30d9f8a0aefc333f7b0fd7585dd7dc848f',
    '/usr/lib64/security/pam_faildelay.so': 'c284c89bcc9163a15e533ef1c335c198da59735f6d86e40c364fa1ccc84954a3',
    '/usr/lib64/security/pam_faillock.so': 'babb242bec2f6a080f64c294d8641582c8ffbeda0ffe43eae5b2a3d3c4eb034b',
    '/usr/lib64/security/pam_unix.so': '1b14e350075868d3118959858fec47a2cfdbab31506e8482c31d0c550ab00222',
    '/usr/lib64/security/pam_nologin.so': '4a9f97b38509ce458d33d9563525dbde8243f1c472d260905899a7a7d80358fd',
    '/usr/bin/unix_chkpwd': '0cb285f3c1819e3ca92545b448fed4d0b6a41ce81899ad11d9512d80b18b7e79',
}
PRIVATE = ('localpin-enroll', 'localpin-eligibility')
BINARIES = [MODULE, *(Path('/usr/libexec/localpin') / n for n in (
    'localpind', 'localpin-account', 'localpin-worker', 'localpin-auth-worker',
    'localpin-eligibility-worker')), Path('/usr/bin/localpinctl')]
PROTECTED = [Path('/etc') / n for n in ('passwd', 'shadow', 'group', 'gshadow', 'environment')]
PROTECTED += [KDE, *(Path('/etc/pam.d') / n for n in PRIVATE)]
PROTECTED += [Path('/etc/authselect') / n for n in ('password-auth', 'postlogin', 'nsswitch.conf')]
PROTECTED += [Path('/etc/security/faillock.conf'), Path('/etc/security/pam_env.conf')]


class Refusal(RuntimeError):
    """Sanitized administrative refusal; no secret material in exceptions."""


def require(condition, message):
    if not condition:
        raise Refusal(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def safe_parents(path):
    for parent in reversed(path.absolute().parents):
        info = parent.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 0
                and not info.st_mode & 0o022, 'unsafe protected path ancestor')


def read(path, bound=65536, owner=0, mode=None):
    path = Path(path)
    safe_parents(path)
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_uid == owner
                and before.st_gid == 0 and before.st_nlink == 1
                and before.st_size <= bound
                and (stat.S_IMODE(before.st_mode) == mode if mode is not None
                     else not before.st_mode & 0o022), 'unsafe protected file')
        data = b''
        while len(data) <= bound:
            part = os.read(fd, min(65536, bound + 1 - len(data)))
            if not part:
                break
            data += part
        after = os.fstat(fd)
        require(len(data) <= bound and fingerprint(before) == fingerprint(after),
                'protected file changed while reading')
        current = path.lstat()
        require((current.st_dev, current.st_ino) == (before.st_dev, before.st_ino),
                'protected file was replaced while reading')
        return data
    finally:
        os.close(fd)


def fingerprint(info):
    return [info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns]


def sync_dir(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def atomic_write(path, data, mode=0o600):
    safe_parents(path)
    if path.exists() or path.is_symlink():
        read(path, max(len(data), 65536))
    temporary = path.parent / ('.localpin-' + uuid.uuid4().hex)
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, mode)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, 'wb', closefd=False) as stream:
            stream.write(data)
            stream.flush()
            os.fsync(fd)
        os.replace(temporary, path)
        sync_dir(path.parent)
    finally:
        os.close(fd)
        temporary.unlink(missing_ok=True)


def run(args, *, check=True, timeout=30):
    # Fixed programs and argument lists only; no shell and no inherited secrets.
    result = subprocess.run(args, env=ENV, stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
    if check:
        require(result.returncode == 0, 'required administrative operation failed; gate remains closed')
    return result


def service_active(unit):
    return run(['/usr/bin/systemctl', 'is-active', '--quiet', unit], check=False).returncode == 0


def stop():
    run(['/usr/bin/systemctl', 'stop', 'localpin.socket', 'localpin.service'])


def start():
    run(['/usr/bin/systemctl', 'start', 'localpin.socket', 'localpin.service'])


def disable_boot():
    run(['/usr/bin/systemctl', 'disable', 'localpin.socket'])


def close_gate():
    atomic_write(GATE, b'LPINT01\ndisabled\n', 0o644)
    run(['/usr/sbin/restorecon', str(GATE)])


def boot():
    value = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    require(str(uuid.UUID(value)) == value, 'invalid kernel boot identity')
    return value


def now_ms():
    return time.clock_gettime_ns(time.CLOCK_BOOTTIME) // 1_000_000


def gate_state():
    try:
        data = read(GATE, 160, mode=0o644)
    except FileNotFoundError:
        return 'disabled'
    if data == b'LPINT01\nactive\n':
        return 'active'
    fields = data.split(b'\n')
    if len(fields) == 6 and fields[:2] == [b'LPINT01', b'trial'] and fields[-1] == b'':
        try:
            first, last = int(fields[3]), int(fields[4])
            if (fields[2].decode() == boot() and fields[3].isdigit() and fields[4].isdigit()
                    and first <= now_ms() < last and 0 < last - first <= 600000):
                return 'trial'
        except (ValueError, UnicodeError):
            pass
    return 'disabled'


def ensure_dirs():
    for path, mode in [(STATE, 0o755), (CONTROL, 0o700)]:
        safe_parents(path)
        path.mkdir(mode=mode, exist_ok=True)
        info = path.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 0
                and stat.S_IMODE(info.st_mode) == mode, 'unsafe integration state directory')
    run(['/usr/sbin/restorecon', '-R', str(STATE)])


@contextlib.contextmanager
def locked():
    ensure_dirs()
    path = CONTROL / 'lock'
    fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_uid == info.st_gid == 0
                and info.st_nlink == 1 and stat.S_IMODE(info.st_mode) == 0o600, 'unsafe integration lock')
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise Refusal('another integration operation is in progress') from None
        yield
    finally:
        os.close(fd)


def load():
    try:
        state = json.loads(read(MANIFEST, mode=0o600))
    except FileNotFoundError:
        return None
    except (ValueError, UnicodeError):
        raise Refusal('corrupt integration manifest; use documented manual console recovery') from None
    require(isinstance(state, dict) and state.get('schema') == 1
            and state.get('phase') in ('preparing', 'prepared', 'active', 'disabled', 'suspended'),
            'unsupported integration state; use documented console recovery')
    return state


def save(state):
    atomic_write(MANIFEST, json.dumps(state, sort_keys=True, separators=(',', ':')).encode() + b'\n')


def snapshot(paths, *, metadata=True):
    values = {}
    for path in paths:
        data = read(path, 16 * 1024 * 1024)
        values[str(path)] = {'sha256': digest(data)}
        if metadata:
            values[str(path)]['metadata'] = fingerprint(path.lstat())
    return values


def binary_snapshot():
    return snapshot(BINARIES, metadata=False)


def validate_policy(*, integrated=False):
    auth = digest(read('/etc/authselect/password-auth'))
    require(auth != FAILLOCK_AUTH,
            'activation refused: parallel fingerprint failures accumulate under with-faillock; reviewed desktop compatibility is required')
    require(auth == DEFAULT_AUTH, 'unknown password-auth profile; activation refused')
    require(digest(read('/etc/authselect/postlogin')) == POSTLOGIN, 'unknown postlogin policy')
    for path, expected in [('/etc/pam.d/password-auth', '/etc/authselect/password-auth'),
                           ('/etc/pam.d/postlogin', '/etc/authselect/postlogin'),
                           ('/etc/nsswitch.conf', '/etc/authselect/nsswitch.conf')]:
        require(Path(path).is_symlink() and os.readlink(path) == expected
                and Path(path).lstat().st_uid == 0, 'noncanonical authselect link')
    text = read('/etc/authselect/nsswitch.conf').decode('ascii')
    for database in ('passwd', 'group', 'shadow'):
        entries = [line.partition(':')[2].split() for raw in text.splitlines()
                   if (line := raw.split('#')[0].strip()).partition(':')[0].strip() == database]
        require(entries == [['files']], 'files-only appliance NSS provisioning is required')
    require(read('/etc/security/faillock.conf') == PERSISTENT,
            'persistent accounting required: migrate native tallies offline and install the exact reviewed faillock configuration before prepare')
    tally = Path('/var/lib/faillock')
    safe_parents(tally)
    info = tally.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 0
            and stat.S_IMODE(info.st_mode) == 0o755, 'unsafe persistent faillock directory')
    require(run(['/usr/bin/stat', '-f', '-c', '%T', str(tally)]).stdout.strip() == b'btrfs',
            'persistent faillock requires the reviewed persistent Btrfs filesystem')
    require(digest(read(KDE)) == (INTEGRATED if integrated else STOCK), 'unknown or changed KDE PAM policy')
    for path, expected in NATIVE.items():
        require(digest(read(path, 4 * 1024 * 1024)) == expected, 'unreviewed native PAM binary; activation refused')
    require(os.readlink('/usr/lib64/libpam.so.0') == 'libpam.so.0.85.1', 'unreviewed libpam link')
    require(run(['/usr/sbin/getenforce']).stdout.strip() == b'Enforcing', 'SELinux enforcing is required')
    for name in PRIVATE:
        source = read(POLICY / (name + '.review-required'))
        if integrated:
            require(read(Path('/etc/pam.d') / name) == source, 'changed private PAM policy')
    require(digest(read(POLICY / 'kde-localpin.review-required')) == INTEGRATED, 'invalid packaged KDE policy')
    binary_snapshot()


def enrollment_binding(uids, *, require_enrolled=True, include_throttle=False):
    result = {}
    for uid in uids:
        path = Path('/var/lib/localpin/users') / str(uid) / 'active'
        pointer = read(path, 35, mode=0o600)
        require(len(pointer) == 35 and pointer[:6] == b'LPA3\0\x01'
                and int.from_bytes(pointer[6:10], 'big') == uid
                and pointer[34] in ((1, 2) if require_enrolled else (0, 1, 2)),
                'each selected account must be freshly enrolled before desktop testing')
        generation = int.from_bytes(pointer[26:34], 'big')
        credential = path.parent / ('generation-' + str(generation)) / 'credential'
        material = pointer + (read(credential, mode=0o600) if pointer[34] else b'')
        if include_throttle:
            material += read(credential.parent / 'throttle', 16384, mode=0o600)
        result[str(uid)] = digest(material)
    return result


def upgrade_binding(state):
    return {'registry': registry_binding(read('/var/lib/localpin-accounts/registry', 16384, mode=0o600)),
            'accounts': enrollment_binding(state['uids'], require_enrolled=False, include_throttle=True)}


def registry_binding(registry):
    """Compare the exact authority except the reviewed /etc cache-window fields.

    LPACCT02 has twenty 84-byte snapshots, then bounded 20-byte account IDs.
    Native cache-window-finish independently verifies all immutable inputs and
    preserves the original IDs. Only /etc directory size/ctime/nanoseconds may
    change during ldconfig; its device/inode/mode/link count stay in this hash.
    This parser never creates or supplies account authority.
    """
    require(len(registry) >= 1692 and registry[:8] == b'LPACCT02'
            and int.from_bytes(registry[8:10], 'big') == 20,
            'unsupported account registry; package transaction refused')
    count = int.from_bytes(registry[1690:1692], 'big')
    require(count <= 128 and len(registry) == 1692 + count * 20,
            'invalid account registry; package transaction refused')
    return digest(registry[:26] + registry[50:])


def current(state, *, binaries=True):
    require(state is not None and state['phase'] in ('prepared', 'active', 'suspended'),
            'prepare the supported appliance before testing or activation')
    validate_policy(integrated=True)
    require(snapshot(PROTECTED) == state.get('protected'), 'protected policy/account state changed; recovery required')
    if binaries:
        require(binary_snapshot() == state.get('binaries'), 'installed LocalPIN binaries changed; package recovery and fresh desktop tests required')


def prepare(uids, *, dry_run=False):
    state = load()
    require(state is None or state['phase'] == 'disabled', 'existing integration transaction; use recovery before preparing again')
    require(uids and len(uids) <= 128 and len(set(uids)) == len(uids)
            and all(1000 <= uid <= 59999 for uid in uids), 'explicit unique supported UID list required')
    validate_policy()
    original = read(KDE)
    expected = read(POLICY / 'kde-localpin.review-required')
    require(expected == PREFIX + original, 'packaged PAM block does not preserve exact stock policy')
    if dry_run:
        return {'operation': 'prepare', 'dry_run': True, 'uids': sorted(uids),
                'reenrollment_required': True, 'gate': 'disabled',
                'diff': ''.join(difflib.unified_diff(original.decode().splitlines(True), expected.decode().splitlines(True),
                                                     fromfile='/etc/pam.d/kde', tofile='/etc/pam.d/kde (prepared)'))}
    close_gate()
    backup = CONTROL / ('backup-' + uuid.uuid4().hex)
    backup.mkdir(mode=0o700)
    originals = {}
    for path in [KDE, *(Path('/etc/pam.d') / name for name in PRIVATE)]:
        data = read(path)
        atomic_write(backup / path.name, data)
        originals[path.name] = {'sha256': digest(data), 'mode': stat.S_IMODE(path.lstat().st_mode)}
    sync_dir(CONTROL)
    state = {'schema': 1, 'phase': 'preparing', 'uids': sorted(uids),
             'backup': backup.name, 'originals': originals, 'tests': None,
             'package_version': '0.1.0-alpha.1', 'created_at': int(time.time())}
    save(state)  # Recovery intent is durable before the first protected edit.
    stop()
    disable_boot()
    run([ACCOUNT, 'begin-mutation'])
    for name in PRIVATE:
        atomic_write(Path('/etc/pam.d') / name, read(POLICY / (name + '.review-required')), 0o644)
    atomic_write(KDE, expected, originals['kde']['mode'])
    run(['/usr/sbin/restorecon', str(KDE), *(str(Path('/etc/pam.d') / n) for n in PRIVATE)])
    run([ACCOUNT, 'seal', *(arg for uid in sorted(uids) for arg in ('--uid', str(uid)))], timeout=60)
    state.update(phase='prepared', protected=snapshot(PROTECTED), binaries=binary_snapshot())
    save(state)
    start()
    return {'phase': 'prepared', 'gate': 'disabled', 'reenrollment_required': True,
            'next': 'Enroll each selected account, open a trial, verify real desktop PIN/password/console recovery, record tests, then activate.'}


def trial(state):
    current(state)
    binding = enrollment_binding(state['uids'])
    begin = now_ms()
    state.update(phase='prepared', tests=None, trial={'boot': boot(), 'start': begin,
                 'end': begin + 600000, 'enrollment': binding})
    close_gate()
    save(state)
    atomic_write(GATE, f'LPINT01\ntrial\n{boot()}\n{begin}\n{begin + 600000}\n'.encode(), 0o644)
    run(['/usr/sbin/restorecon', str(GATE)])
    return {'phase': 'trial', 'expires_in_seconds': 600, 'automatic_expiry': True}


def record_tests(state):
    current(state)
    require(gate_state() == 'trial' and state.get('trial', {}).get('boot') == boot(),
            'a live trial in this boot is required')
    require(enrollment_binding(state['uids']) == state['trial']['enrollment'],
            'enrollment changed during desktop tests')
    state['tests'] = {'kind': 'administrator-attestation', 'boot': boot(),
                      'pin': True, 'password': True, 'console_recovery': True,
                      'enrollment': state['trial']['enrollment'], 'recorded_at': int(time.time())}
    save(state)
    return {'tests': 'administrator-attested', 'automatic_desktop_verification': False}


def activate(state):
    current(state)
    tests = state.get('tests')
    require(tests and tests.get('kind') == 'administrator-attestation' and tests.get('boot') == boot()
            and all(tests.get(name) is True for name in ('pin', 'password', 'console_recovery'))
            and state.get('trial', {}).get('boot') == boot()
            and tests.get('enrollment') == state['trial'].get('enrollment')
            and gate_state() == 'trial', 'record actual desktop tests during a current trial before activation')
    require(enrollment_binding(state['uids']) == tests['enrollment'], 'tested enrollment changed')
    close_gate()
    # Enabling is the explicit persistent opt-in. Preparation and trial alone
    # never arrange startup after reboot. A failure leaves the gate closed.
    run(['/usr/bin/systemctl', 'enable', '--now', 'localpin.socket'])
    state['phase'] = 'active'
    save(state)
    atomic_write(GATE, b'LPINT01\nactive\n', 0o644)
    run(['/usr/sbin/restorecon', str(GATE)])
    return {'phase': 'active', 'tests': 'administrator-attested', 'survives_reboot': True}


def removable_policy(data, original):
    """Remove only our exact leading block, preserving subsequent admin edits."""
    require(digest(original) == STOCK, 'invalid original KDE backup')
    if data == original:
        return data
    require(data.startswith(PREFIX), 'changed or missing owned block; refusing to overwrite administrator PAM edits')
    remainder = data[len(PREFIX):]
    require(b'LOCALPIN' not in remainder and b'pam_localpin' not in remainder
            and b'pam_pinlock' not in remainder, 'ambiguous additional PIN policy; manual console review required')
    return remainder


def disable(state, *, dry_run=False):
    if state is None:
        require(digest(read(KDE)) == STOCK, 'unowned or changed KDE policy; manual review required')
        if not dry_run:
            close_gate()
            stop()
            disable_boot()
        return {'phase': 'disabled', 'dry_run': dry_run}
    require(isinstance(state.get('backup'), str) and state['backup'].startswith('backup-')
            and '/' not in state['backup'] and '..' not in state['backup'], 'invalid backup reference')
    backup = CONTROL / state['backup']
    original = read(backup / 'kde', mode=0o600)
    require(digest(original) == state['originals']['kde']['sha256'], 'changed original backup')
    before = read(KDE)
    replacement = removable_policy(before, original)
    restorations = []
    for name in PRIVATE:
        path = Path('/etc/pam.d') / name
        old = read(backup / name, mode=0o600)
        require(digest(old) == state['originals'][name]['sha256'], 'changed private-policy backup')
        try:
            live = read(path)
        except FileNotFoundError:
            live = None
        if live is None or live == read(POLICY / (name + '.review-required')) or live == old:
            restorations.append((path, old, state['originals'][name]['mode']))
    if dry_run:
        return {'operation': 'disable', 'dry_run': True, 'preserves_admin_edits': True,
                'revokes_all_managed_enrollments': True,
                'diff': ''.join(difflib.unified_diff(before.decode().splitlines(True), replacement.decode().splitlines(True)))}
    close_gate()  # Even a later refusal cannot leave the PIN route enabled.
    stop()
    disable_boot()
    run([ACCOUNT, 'begin-mutation'])
    atomic_write(KDE, replacement, state['originals']['kde']['mode'])
    run(['/usr/sbin/restorecon', str(KDE)])
    for path, old, mode in restorations:
        atomic_write(path, old, mode)
        run(['/usr/sbin/restorecon', str(path)])
    # An administrator's unrelated private-policy edit remains untouched.
    state.update(phase='disabled', tests=None)
    save(state)
    return {'phase': 'disabled', 'password_policy': 'original stock policy or preserved administrator suffix',
            'enrollments_revoked': True, 'persistent_faillock_preserved': True}


def package_check(state, *, removal=False):
    if removal:
        require(gate_state() == 'disabled' and (state is None or state['phase'] == 'disabled'),
                'disable integration before package removal')
        require(not remaining_references(), 'PAM still references LocalPIN; removal refused')
    elif state and state['phase'] in ('prepared', 'active'):
        current(state)
    elif state and state['phase'] == 'suspended':
        current(state, binaries=False)
    else:
        require(state is None or state['phase'] == 'disabled', 'incomplete package/integration transaction; recover first')
        require(digest(read(KDE)) == STOCK, 'unowned or unknown KDE policy; package transaction refused')
    return {'package_check': 'passed', 'schema': 1, 'removal': removal}


def package_suspend(state):
    package_check(state)
    if state is None or state['phase'] == 'disabled':
        return {'suspended': False}
    if state['phase'] == 'suspended':
        close_gate()
        stop()
        if 'upgrade_binding' not in state:
            state['upgrade_binding'] = upgrade_binding(state)
            save(state)
        return {'suspended': True, 'enrollment_preserved': True, 'gate': 'disabled'}
    previous = {'socket': service_active('localpin.socket'), 'service': service_active('localpin.service')}
    close_gate()
    state.update(phase='suspended', tests=None, services=previous)
    save(state)  # Durable recovery intent precedes service stop and replacement.
    stop()
    state['upgrade_binding'] = upgrade_binding(state)
    save(state)
    return {'suspended': True, 'enrollment_preserved': True, 'gate': 'disabled'}


def package_resume(state):
    if state is None or state['phase'] == 'disabled':
        return {'resumed': False}
    require(state['phase'] == 'suspended', 'no suspended upgrade to resume')
    close_gate()
    stop()
    current(state, binaries=False)
    if state.get('cache_window'):
        # The native helper restores only the exact suspended authority, after
        # refreezing /etc and checking every other snapshot and incarnation.
        run([ACCOUNT, 'cache-window-finish'])
    require(upgrade_binding(state) == state.get('upgrade_binding'),
            'account, credential or throttle state changed during package transaction; recovery required')
    state.update(binaries=binary_snapshot(), tests=None, cache_window=False)
    save(state)
    units = [name for key, name in [('socket', 'localpin.socket'), ('service', 'localpin.service')]
             if state['services'][key]]
    if units:
        run(['/usr/bin/systemctl', 'start', *units])
    state['phase'] = 'prepared'
    save(state)
    return {'resumed': True, 'enrollment_preserved': True, 'gate': 'disabled',
            'next': 'Repeat trial and desktop tests before activation.'}


def package_cache_begin(state):
    if state is None or state['phase'] == 'disabled':
        return {'cache_window': False}
    require(state['phase'] == 'suspended', 'suspend the package before its cache window')
    close_gate()
    stop()
    current(state, binaries=False)
    if not state.get('cache_window'):
        require(upgrade_binding(state) == state.get('upgrade_binding'),
                'account, credential or throttle state changed before package transaction')
        state['cache_window'] = True
        save(state)  # Intent must survive a crash inside the native operation.
    run([ACCOUNT, 'cache-window-begin'])
    return {'cache_window': True, 'account_authority': 'suspended', 'gate': 'disabled'}


def remaining_references():
    """Removal must not strand a reference in any other PAM service."""
    directory = Path('/etc/pam.d')
    safe_parents(directory / 'placeholder')
    entries = list(directory.iterdir())
    require(len(entries) <= 512, 'oversized PAM service inventory; removal refused')
    references = []
    for entry in entries:
        path = entry
        info = entry.lstat()
        if stat.S_ISLNK(info.st_mode):
            require(info.st_uid == info.st_gid == 0, 'unsafe PAM symlink; removal refused')
            target = Path(os.path.normpath(os.path.join(entry.parent, os.readlink(entry))))
            require(target.parent == Path('/etc/authselect') and target.name == entry.name,
                    'unknown PAM symlink; removal refused')
            path = target
        data = read(path)
        if b'pam_localpin' in data:
            references.append(entry.name)
    return references


def candidate_check(candidate, schema):
    """RPM's native EVR comparison; never execute a string as a program."""
    match = re.fullmatch(r'([0-9]+):([A-Za-z0-9.+~^]+)-([A-Za-z0-9.+~^]+)', candidate)
    require(match is not None and match[1] == '0' and match[2] == '0.1.0' and schema == 1,
            'unsupported package policy/schema transition; disable integration and use the reviewed migration procedure')
    result = run(['/usr/bin/rpm', '-q', '--queryformat', '%{EPOCHNUM}:%{VERSION}-%{RELEASE}', 'localpin'])
    previous = re.fullmatch(r'([0-9]+):([A-Za-z0-9.+~^]+)-([A-Za-z0-9.+~^]+)', result.stdout.decode('ascii'))
    require(previous is not None, 'installed package version is unavailable')
    import rpm  # Fedora python3-rpm, required by the native package.
    require(rpm.labelCompare(tuple(match.groups()), tuple(previous.groups())) >= 0,
            'package downgrade refused; preserve password recovery and use an explicitly reviewed migration')


def migrate_legacy(*, dry_run=False):
    state = load()
    require(state is None or state['phase'] == 'disabled', 'disable LocalPIN before legacy migration')
    before = read(KDE)
    require(before.startswith(LEGACY_PREFIX) and digest(before[len(LEGACY_PREFIX):]) == STOCK,
            'unknown legacy PIN block or changed original policy; manual migration review required')
    after = before[len(LEGACY_PREFIX):]
    if dry_run:
        return {'operation': 'migrate-legacy', 'dry_run': True, 'imports_old_verifier': False,
                'diff': ''.join(difflib.unified_diff(before.decode().splitlines(True), after.decode().splitlines(True)))}
    close_gate()
    journal = CONTROL / 'legacy-migration.json'
    source_backup = CONTROL / 'legacy-kde'
    try:
        saved = read(source_backup, mode=0o600)
        require(saved == before, 'missing or changed legacy policy backup; migration refused')
    except FileNotFoundError:
        require(not journal.exists(), 'legacy migration backup missing; migration refused')
        atomic_write(source_backup, before)
    if journal.exists():
        old = json.loads(read(journal, mode=0o600))
        require(old == {'schema': 1, 'original': digest(before), 'restored': STOCK}, 'changed migration intent')
    else:
        atomic_write(journal, json.dumps({'schema': 1, 'original': digest(before), 'restored': STOCK}).encode())
    stop()
    run([ACCOUNT, 'begin-mutation'])
    atomic_write(KDE, after, 0o644)
    run(['/usr/sbin/restorecon', str(KDE)])
    return {'legacy_pin_block_removed': True, 'password_policy': 'exact-stock', 'imports_old_verifier': False,
            'next': 'Verify stock password recovery, prepare the appliance, then freshly enroll and test LocalPIN.'}


def status(state):
    gate = gate_state()
    return {'schema_version': 1, 'phase': state['phase'] if state else 'unprepared',
            'gate': gate, 'tested': state.get('tests', {}).get('kind')
            if state and state.get('tests') and gate == 'active' else 'not-recorded',
            'supported_account_domain': 'restricted Fedora 44 Btrfs appliance',
            'fingerprint_faillock_combination': 'activation-refused'}


def main():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=['status', 'prepare', 'trial', 'record-tests', 'activate', 'migrate-legacy',
                                             'disable', 'recover', 'package-check', 'package-suspend', 'package-cache-begin', 'package-resume'])
    parser.add_argument('--uid', type=int, action='append', default=[])
    parser.add_argument('--dry-run', action='store_true')
    parser.add_argument('--removal', action='store_true')
    parser.add_argument('--candidate-evr')
    parser.add_argument('--candidate-schema', type=int)
    parser.add_argument('--pin', action='store_true', help='Administrator attests actual desktop PIN test passed')
    parser.add_argument('--password', action='store_true', help='Administrator attests actual desktop full-password test passed')
    parser.add_argument('--recovery', action='store_true', help='Administrator attests actual console recovery test passed')
    args = parser.parse_args()
    require(os.getuid() == os.geteuid(), 'setuid installation is unsupported')
    require(not args.uid or args.operation == 'prepare', 'UID selection applies only to prepare')
    require(not args.dry_run or args.operation in ('prepare', 'disable', 'recover', 'migrate-legacy'), 'dry-run unavailable for this operation')
    require(not args.removal or args.operation == 'package-check', 'removal applies only to package-check')
    require(not (args.pin or args.password or args.recovery) or args.operation == 'record-tests', 'test attestations apply only to record-tests')
    require((args.candidate_evr is None) == (args.candidate_schema is None), 'candidate version and schema must be supplied together')
    require(args.candidate_evr is None or (args.operation == 'package-check' and not args.removal), 'candidate checks apply only to upgrades')
    if args.operation == 'status' and os.geteuid() != 0:
        print(json.dumps({'schema_version': 1, 'gate': gate_state(), 'tested': 'ask-administrator'}))
        return
    require(os.getuid() == os.geteuid() == 0, 'run this fixed administrative tool as root (for example with sudo)')
    if args.operation == 'record-tests':
        require(args.pin and args.password and args.recovery, 'explicit PIN, password and console-recovery attestations required')
    if args.candidate_evr:
        candidate_check(args.candidate_evr, args.candidate_schema)
    if args.dry_run or args.operation in ('status', 'package-check'):
        state = load()
        if args.operation == 'prepare':
            result = prepare(args.uid, dry_run=True)
        elif args.operation in ('disable', 'recover'):
            result = disable(state, dry_run=True)
        elif args.operation == 'migrate-legacy':
            result = migrate_legacy(dry_run=True)
        elif args.operation == 'package-check':
            result = package_check(state, removal=args.removal)
        else:
            result = status(state)
    else:
        with locked():
            if args.operation in ('disable', 'recover'):
                # Even a corrupt manifest must not leave desktop PIN active.
                close_gate()
            state = load()
            if args.operation == 'prepare':
                result = prepare(args.uid)
            elif args.operation == 'migrate-legacy':
                result = migrate_legacy()
            elif args.operation in ('disable', 'recover'):
                # Recovery closes the gate even when changed files require a
                # manual decision. It never overwrites an unknown owned block.
                result = disable(state)
            else:
                action = {'trial': trial, 'record-tests': record_tests, 'activate': activate,
                          'package-suspend': package_suspend, 'package-cache-begin': package_cache_begin,
                          'package-resume': package_resume}[args.operation]
                result = action(state)
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except (OSError, Refusal, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        # Only explicit fixed refusal messages are safe; OS errors can contain
        # sensitive paths/values. Preserve a useful fixed action for other errors.
        error = sys.exception()
        print('localpin-integration: ' + (str(error) if isinstance(error, Refusal)
              else 'required protected state or operation unavailable; use console recovery'), file=sys.stderr)
        raise SystemExit(1) from None
