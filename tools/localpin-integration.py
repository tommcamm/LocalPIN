#!/usr/bin/python3 -I
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Fixed-path, non-setuid Fedora KDE activation and console recovery.

There is deliberately no alternate root, command, policy, secret or environment
override. Importable functions permit synthetic filesystem tests; the installed
entry point always uses the fixed production paths below.
"""
import argparse
import contextlib
import difflib
import fcntl
import hashlib
import importlib.machinery
import importlib.util
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
FINGERPRINT = Path('/etc/pam.d/kde-fingerprint')
MODULE = Path('/usr/lib64/security/pam_localpin.so')
ACCOUNT = '/usr/libexec/localpin/localpin-account'
REGISTRY = Path('/var/lib/localpin-accounts/registry')
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
NATIVE = tuple(Path('/usr/lib64/security') / ('pam_' + name + '.so') for name in
               ('env', 'faildelay', 'faillock', 'unix', 'nologin')) + (Path('/usr/bin/unix_chkpwd'),)
PRIVATE = ('localpin-enroll', 'localpin-eligibility', 'localpin-kde-password', 'localpin-kde-fingerprint')
BINARIES = [MODULE, *(Path('/usr/libexec/localpin') / n for n in (
    'localpind', 'localpin-account', 'localpin-worker', 'localpin-auth-worker',
    'localpin-eligibility-worker')), Path('/usr/bin/localpinctl')]
# Mutable account databases and authselect output are rechecked by the native
# authority/worker at each operation. They are not an installation fingerprint.
PROTECTED = [KDE, FINGERPRINT, *(Path('/etc/pam.d') / n for n in PRIVATE),
             Path('/etc/security/faillock.conf')]
ACCOUNT_MUTATIONS = frozenset(('begin-mutation', 'seal', 'recover', 'cache-window-begin', 'cache-window-finish'))
_integration_lock_fd = None


class Refusal(RuntimeError):
    """Sanitized administrative refusal; no secret material in exceptions."""


class SetupScopeRefusal(Refusal):
    """Onboarding must leave another account's managed installation alone."""


class AccountingRequired(Refusal):
    """Persistent native accounting needs the documented offline handoff."""


def accounting_module():
    executable = Path(__file__).resolve()
    name = 'localpin-accounting.py' if executable.suffix == '.py' else 'localpin-accounting'
    loader = importlib.machinery.SourceFileLoader('localpin_accounting', str(executable.with_name(name)))
    module = importlib.util.module_from_spec(importlib.util.spec_from_loader(loader.name, loader))
    loader.exec_module(module)
    return module


def accounting_pending():
    journal = CONTROL / 'accounting/transaction.json'
    if not journal.exists() and not journal.is_symlink():
        return False
    try:
        value = json.loads(read(journal, 4 * 1024 * 1024, mode=0o600))
    except FileNotFoundError:
        return False
    require(isinstance(value, dict) and value.get('schema') == 1,
            'invalid accounting maintenance journal; use emergency recovery')
    return value.get('phase') not in ('complete', 'aborted')


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
    passed = ()
    if args[0] == ACCOUNT and len(args) > 1 and args[1] in ACCOUNT_MUTATIONS:
        require(_integration_lock_fd is not None, 'account mutation requires the integration transaction lock')
        validate_lock(_integration_lock_fd)
        args = [*args, '--integration-lock-fd', str(_integration_lock_fd)]
        passed = (_integration_lock_fd,)
    result = subprocess.run(args, env=ENV, stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout,
                            pass_fds=passed)
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


def validate_lock(fd):
    path = CONTROL / 'lock'
    safe_parents(path)
    for directory, mode in ((STATE, 0o755), (CONTROL, 0o700)):
        info = directory.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 0
                and stat.S_IMODE(info.st_mode) == mode, 'unsafe integration state directory')
    info = os.fstat(fd)
    current = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_uid == info.st_gid == 0
            and info.st_nlink == 1 and stat.S_IMODE(info.st_mode) == 0o600
            and (current.st_dev, current.st_ino) == (info.st_dev, info.st_ino),
            'unsafe or replaced integration lock')


@contextlib.contextmanager
def locked():
    global _integration_lock_fd
    require(_integration_lock_fd is None, 'nested integration transaction is unsupported')
    ensure_dirs()
    path = CONTROL / 'lock'
    fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK, 0o600)
    try:
        validate_lock(fd)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise Refusal('another integration operation is in progress') from None
        validate_lock(fd)
        _integration_lock_fd = fd
        # Accounting backups retain exact original xattrs, including SELinux.
        # Relabel only the lock and its directories, never private backup files.
        run(['/usr/sbin/restorecon', str(STATE), str(CONTROL), str(path)])
        yield
    finally:
        _integration_lock_fd = None
        os.close(fd)


def load():
    try:
        state = json.loads(read(MANIFEST, mode=0o600))
    except FileNotFoundError:
        return None
    except (ValueError, UnicodeError):
        raise Refusal('corrupt integration manifest; use documented manual console recovery') from None
    require(isinstance(state, dict) and state.get('schema') in (1, 2)
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


def canonical(data):
    """Compare reviewed PAM directives, permitting comments and whitespace."""
    return '\n'.join(' '.join(line.split()) for raw in data.decode('ascii').splitlines()
                     if (line := raw.partition('#')[0].strip()))


def reviewed_pam_syntax(data):
    """Admit the reviewed ASCII subset before normalizing a live KDE policy.

    Recovery deliberately keeps its existing permissive canonical comparison.
    Preparation accepts LF and space/tab, with printable ASCII full-line
    comments, but no continuation, other controls or inline comment syntax.
    """
    if any(byte not in (9, 10) and (not 0x20 <= byte <= 0x7e or byte == 0x5c)
           for byte in data):
        return False
    for line in data.split(b'\n'):
        active = line.lstrip(b' \t')
        if active and not active.startswith(b'#') and b'#' in active:
            return False
    return True


def service_policy(path, *, integrated):
    name = 'kde-localpin' if path == KDE else 'kde-fingerprint-localpin'
    data = read(POLICY / (name + '.review-required'))
    if not integrated:
        if path == KDE:
            require(data.startswith(PREFIX), 'invalid packaged KDE block')
            data = data[len(PREFIX):]
        data = data.replace(b'localpin-kde-password', b'password-auth').replace(
            b'localpin-kde-fingerprint', b'fingerprint-auth')
    return data


def transform_service(path, data, *, install):
    """Change one owned auth substack, preserving every other source byte."""
    old = b'password-auth' if path == KDE else b'fingerprint-auth'
    new = b'localpin-kde-password' if path == KDE else b'localpin-kde-fingerprint'
    source, target = (old, new) if install else (new, old)
    pattern = rb'(?m)^([ \t]*auth[ \t]+substack[ \t]+)' + re.escape(source) + rb'([ \t]*(?:#.*)?$)'
    result, count = re.subn(pattern, lambda match: match[1] + target + match[2], data)
    require(count == 1, 'missing or ambiguous KDE auth substack; console review required')
    return (PREFIX + result) if install and path == KDE else result


def native_policy_files():
    # The stable SONAME is the Linux-PAM ABI contract. Fedora owns and updates
    # its implementation; do not pin a particular distribution build's hash.
    link = Path('/usr/lib64/libpam.so.0')
    safe_parents(link)
    info = link.lstat()
    target = os.readlink(link)
    require(stat.S_ISLNK(info.st_mode) and info.st_uid == info.st_gid == 0
            and re.fullmatch(r'libpam\.so\.0\.[0-9.]+', target), 'unsafe libpam SONAME link')
    for path in (*NATIVE, link.parent / target):
        data = read(path, 16 * 1024 * 1024)
        require(data[:6] == b'\x7fELF\x02\x01' and data[18:20] == b'\x3e\x00',
                'native x86_64 PAM runtime required')


def validate_policy(*, integrated=False, allow_volatile=False):
    release = dict(line.split('=', 1) for line in read('/usr/lib/os-release').decode('ascii').splitlines()
                   if '=' in line and not line.startswith('#'))
    require(release.get('ID', '').strip('"') == 'fedora'
            and release.get('VERSION_ID', '').strip('"') == '44'
            and os.uname().machine == 'x86_64', 'Fedora KDE 44 x86_64 is required')
    run([ACCOUNT, 'check-policy'])
    require(all(line.split()[0] not in ('auth', '-auth')
                for line in canonical(read('/etc/authselect/postlogin')).splitlines()),
            'postlogin auth hooks require explicit support')
    for path, expected in [('/etc/pam.d/password-auth', '/etc/authselect/password-auth'),
                           ('/etc/pam.d/postlogin', '/etc/authselect/postlogin'),
                           ('/etc/nsswitch.conf', '/etc/authselect/nsswitch.conf')]:
        require(Path(path).is_symlink() and os.readlink(path) == expected
                and Path(path).lstat().st_uid == 0, 'noncanonical authselect link')
    text = read('/etc/authselect/nsswitch.conf').decode('ascii')
    for database in ('passwd', 'group', 'shadow'):
        entries = [line.partition(':')[2].split() for raw in text.splitlines()
                   if (line := raw.split('#')[0].strip()).partition(':')[0].strip() == database]
        allowed = (['files'], ['files', 'systemd'])
        if database == 'group':
            allowed += (['files', '[SUCCESS=merge]', 'systemd'],)
        require(len(entries) == 1 and entries[0] in allowed,
                'local files accounts with optional systemd NSS are required')
    accounting = read('/etc/security/faillock.conf')
    if accounting != PERSISTENT and not (allow_volatile and digest(accounting) ==
            '662303cf89938c12d95a7fc59d92cbe76c398312527fa908894fb319809093b3'):
        raise AccountingRequired('persistent accounting required: migrate native tallies offline and install the exact reviewed faillock configuration before prepare')
    tally = Path('/var/lib/faillock')
    safe_parents(tally)
    info = tally.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 0
            and stat.S_IMODE(info.st_mode) == 0o755, 'unsafe persistent faillock directory')
    require(run(['/usr/bin/stat', '-f', '-c', '%T', str(tally)]).stdout.strip() in (b'btrfs', b'ext2/ext3', b'xfs'),
            'persistent faillock requires a supported local persistent filesystem')
    for path in (KDE, FINGERPRINT):
        policy = read(path)
        require(reviewed_pam_syntax(policy), 'unsupported KDE PAM syntax')
        require(canonical(policy) == canonical(service_policy(path, integrated=integrated)),
                'unknown or changed KDE PAM policy')
    native_policy_files()
    require(run(['/usr/sbin/getenforce']).stdout.strip() == b'Enforcing', 'SELinux enforcing is required')
    for name in PRIVATE:
        source = read(POLICY / (name + '.review-required'))
        if integrated:
            require(read(Path('/etc/pam.d') / name) == source, 'changed private PAM policy')
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
    return {'registry': registry_binding(read(REGISTRY, 16384, mode=0o600)),
            'accounts': enrollment_binding(state['uids'], require_enrolled=False, include_throttle=True)}


def registry_accounts(registry, *, allow_empty=False):
    """Parse only the current authority format, including explicit revocation."""
    require(len(registry) >= 10 and registry[:8] == b'LPACCT03',
            'unsupported account registry; package transaction refused')
    count = int.from_bytes(registry[8:10], 'big')
    require((0 if allow_empty else 1) <= count <= 128,
            'invalid account registry; package transaction refused')
    offset = 10
    previous = 0
    names, markers = set(), set()
    accounts = {}
    for _ in range(count):
        require(offset + 29 <= len(registry), 'truncated account registry')
        uid = int.from_bytes(registry[offset:offset + 4], 'big')
        incarnation = registry[offset + 4:offset + 20]
        marker = int.from_bytes(registry[offset + 20:offset + 28], 'big')
        length = registry[offset + 28]
        name = bytes(registry[offset + 29:offset + 29 + length])
        require(previous < uid <= 59999 and uid >= 1000 and incarnation != bytes(16)
                and 0 < marker < 2**32 - 1 and 1 <= length <= 32
                and len(name) == length and re.fullmatch(rb'[a-z_][a-z0-9_-]*', name),
                'invalid account registry binding')
        require(name not in names and marker not in markers, 'duplicate account registry binding')
        names.add(name)
        markers.add(marker)
        accounts[uid] = incarnation
        previous = uid
        offset += 29 + length
    require(offset == len(registry), 'invalid account registry length')
    return accounts


def registry_binding(registry):
    """Bind every incarnation/marker exactly; never infer account continuity."""
    registry_accounts(registry)
    return digest(registry)


def setup_scope(state, uid):
    """Check both integration intent and live registry before setup mutations.

    The caller holds the integration transaction lock for mutations. Native
    account tools retain their own account/password/storage locking.
    """
    require(type(uid) is int and 1000 <= uid <= 59999, 'supported setup UID required')
    if state is not None:
        uids = state.get('uids')
        require(isinstance(uids, list) and uids
                and all(type(value) is int and 1000 <= value <= 59999 for value in uids)
                and len(uids) == len(set(uids)), 'invalid managed account scope; use console recovery')
        if uids != [uid]:
            raise SetupScopeRefusal('setup supports only this account; use administrator tooling for other or multiple managed accounts')
    try:
        registry = read(REGISTRY, 16384, mode=0o600)
    except FileNotFoundError:
        registry = None
    accounts = registry_accounts(registry, allow_empty=True) if registry is not None else {}
    if accounts and list(accounts) != [uid]:
        raise SetupScopeRefusal('setup supports only this account; use administrator tooling for other or multiple managed accounts')
    if state and state['phase'] in ('prepared', 'active'):
        require(list(accounts) == [uid], 'account authority unavailable; use console recovery')
    return accounts


def setup_enrollment(uid, incarnation):
    """Read the authoritative pointer; missing/corrupt state is never unenrolled."""
    pointer = read(Path('/var/lib/localpin/users') / str(uid) / 'active', 35, mode=0o600)
    require(len(pointer) == 35 and pointer[:6] == b'LPA3\0\x01'
            and int.from_bytes(pointer[6:10], 'big') == uid
            and pointer[10:26] == incarnation
            and int.from_bytes(pointer[26:34], 'big') > 0
            and pointer[34] in (0, 1, 2), 'credential state unavailable; use console recovery')
    if pointer[34] == 0:
        return False, None
    # This does not attempt a PIN or load a TPM. Trial and activation use the
    # same exact pointer/credential binding and the broker validates metadata.
    return True, enrollment_binding([uid])


def setup_trial(state, binding):
    """Require exact gate/manifest timing, boot and enrollment agreement."""
    trial = state.get('trial')
    if not isinstance(trial, dict) or binding is None:
        return False, 0
    begin, end = trial.get('start'), trial.get('end')
    if (type(begin) is not int or type(end) is not int or not 0 <= begin < end < 2**64
            or end - begin > 600000 or trial.get('boot') != boot()
            or trial.get('enrollment') != binding):
        return False, 0
    try:
        gate = read(GATE, 160, mode=0o644)
    except FileNotFoundError:
        return False, 0
    expected = f'LPINT01\ntrial\n{trial["boot"]}\n{begin}\n{end}\n'.encode()
    remaining = end - now_ms()
    if gate != expected or not 0 < remaining <= end - begin:
        return False, 0
    return True, (remaining + 999) // 1000


def setup_trial_reference(state):
    """Opaque equality reference for one validated trial, never authorization."""
    return digest(json.dumps(state['trial'], sort_keys=True, separators=(',', ':')).encode())


def setup_attestation(state, binding, *, live_trial):
    tests = state.get('tests')
    return bool(isinstance(tests, dict) and tests.get('kind') == 'administrator-attestation'
                and all(tests.get(name) is True for name in ('pin', 'password', 'console_recovery'))
                and (state['phase'] == 'active' or (binding is not None and live_trial
                     and tests.get('enrollment') == binding and tests.get('boot') == boot()
                     and state['trial'].get('enrollment') == binding)))


def setup_status(uid):
    """Root-only read-only onboarding report. No locks, state creation or auth."""
    state = load()
    phase = state['phase'] if state else 'unprepared'
    result = {'schema_version': 1, 'phase': phase, 'blocker': 'none', 'enrolled': False,
              'trial_valid': False, 'trial_remaining_seconds': 0, 'trial_ref': None,
              'tests_recorded': False}
    if accounting_pending():
        result['blocker'] = 'accounting-maintenance'
        return result
    try:
        accounts = setup_scope(state, uid)
    except SetupScopeRefusal:
        result['blocker'] = 'multiuser'
        return result
    if state and (state['schema'] != 2 or phase in ('preparing', 'suspended')):
        result['blocker'] = 'recovery'
        return result
    try:
        if phase in ('unprepared', 'disabled'):
            validate_policy()
            require(gate_state() == 'disabled', 'unexpected live integration gate; use console recovery')
        else:
            current(state)
    except AccountingRequired:
        result['blocker'] = 'accounting'
        return result
    except Refusal:
        result['blocker'] = 'recovery' if state else 'policy'
        return result
    if phase in ('prepared', 'active'):
        result['enrolled'], binding = setup_enrollment(uid, accounts[uid])
        result['trial_valid'], result['trial_remaining_seconds'] = setup_trial(state, binding)
        if result['trial_valid']:
            result['trial_ref'] = setup_trial_reference(state)
        result['tests_recorded'] = setup_attestation(state, binding, live_trial=result['trial_valid'])
        if phase == 'active':
            # Activation persists across boots and ordinary own-user credential
            # replacement/removal. The tests are historical evidence, while the
            # gate and current installation binding are activation authority.
            if gate_state() != 'active':
                result['blocker'] = 'recovery'
        elif gate_state() == 'active':
            result['blocker'] = 'recovery'
    # A concurrent integration transaction cannot produce an actionable report
    # assembled from two different manifests/authorities. The next mutation
    # always repeats its scope checks inside the integration lock.
    require(load() == state and setup_scope(state, uid) == accounts,
            'integration changed during setup inspection; rerun setup')
    return result


def current(state, *, binaries=True):
    require(state is not None and state['phase'] in ('prepared', 'active', 'suspended'),
            'prepare the supported Fedora KDE integration before testing or activation')
    require(state.get('schema') == 2, 'legacy appliance integration requires disable and fresh preparation')
    validate_policy(integrated=True)
    require(snapshot(PROTECTED, metadata=False) == state.get('protected'), 'owned policy changed; recovery required')
    if binaries:
        require(binary_snapshot() == state.get('binaries'), 'installed LocalPIN binaries changed; package recovery and fresh desktop tests required')


def prepare(uids, *, dry_run=False):
    state = load()
    require(state is None or state['phase'] == 'disabled', 'existing integration transaction; use recovery before preparing again')
    require(uids and len(uids) <= 128 and len(set(uids)) == len(uids)
            and all(1000 <= uid <= 59999 for uid in uids), 'explicit unique supported UID list required')
    validate_policy()
    original = read(KDE)
    expected = transform_service(KDE, original, install=True)
    fingerprint = read(FINGERPRINT)
    fingerprint_expected = transform_service(FINGERPRINT, fingerprint, install=True)
    if dry_run:
        return {'operation': 'prepare', 'dry_run': True, 'uids': sorted(uids),
                'reenrollment_required': True, 'gate': 'disabled',
                'diff': ''.join(''.join(difflib.unified_diff(before.decode().splitlines(True), after.decode().splitlines(True),
                                                     fromfile=str(path), tofile=str(path) + ' (prepared)'))
                                for path, before, after in [(KDE, original, expected),
                                                            (FINGERPRINT, fingerprint, fingerprint_expected)])}
    close_gate()
    backup = CONTROL / ('backup-' + uuid.uuid4().hex)
    backup.mkdir(mode=0o700)
    originals = {}
    for path in [KDE, FINGERPRINT, *(Path('/etc/pam.d') / name for name in PRIVATE)]:
        data = read(path)
        atomic_write(backup / path.name, data)
        originals[path.name] = {'sha256': digest(data), 'mode': stat.S_IMODE(path.lstat().st_mode)}
    sync_dir(CONTROL)
    state = {'schema': 2, 'phase': 'preparing', 'uids': sorted(uids),
             'backup': backup.name, 'originals': originals, 'tests': None,
             'package_version': '0.1.0-alpha.1', 'created_at': int(time.time())}
    save(state)  # Recovery intent is durable before the first protected edit.
    stop()
    disable_boot()
    run([ACCOUNT, 'begin-mutation'])
    for name in PRIVATE:
        atomic_write(Path('/etc/pam.d') / name, read(POLICY / (name + '.review-required')), 0o644)
    atomic_write(KDE, expected, originals['kde']['mode'])
    atomic_write(FINGERPRINT, fingerprint_expected, originals['kde-fingerprint']['mode'])
    run(['/usr/sbin/restorecon', str(KDE), str(FINGERPRINT), *(str(Path('/etc/pam.d') / n) for n in PRIVATE)])
    run([ACCOUNT, 'seal', *(arg for uid in sorted(uids) for arg in ('--uid', str(uid)))], timeout=60)
    state.update(phase='prepared', protected=snapshot(PROTECTED, metadata=False), binaries=binary_snapshot())
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


def removable_policy(data, original, path=None):
    """Remove only our exact leading block, preserving subsequent admin edits."""
    path = KDE if path is None else path
    require((path == KDE and digest(original) == STOCK)
            or canonical(original) == canonical(service_policy(path, integrated=False)),
            'invalid original KDE backup')
    if data == original:
        return data
    if path == KDE:
        require(data.startswith(PREFIX), 'changed or missing owned block; refusing to overwrite administrator PAM edits')
        remainder = data[len(PREFIX):]
    else:
        remainder = data
    require(b'LOCALPIN' not in remainder and b'pam_localpin' not in remainder
            and b'pam_pinlock' not in remainder, 'ambiguous additional PIN policy; manual console review required')
    if b'localpin-kde-' in remainder:
        remainder = transform_service(path, remainder, install=False)
    require(b'localpin-' not in remainder, 'ambiguous owned substack; manual console review required')
    return original if canonical(remainder) == canonical(original) else remainder


def disable(state, *, dry_run=False):
    if state is None:
        require(all(canonical(read(path)) == canonical(service_policy(path, integrated=False))
                    for path in (KDE, FINGERPRINT)), 'unowned or changed KDE policy; manual review required')
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
    if state.get('schema') == 2:
        old = read(backup / FINGERPRINT.name, mode=0o600)
        require(digest(old) == state['originals'][FINGERPRINT.name]['sha256'], 'changed fingerprint-policy backup')
        restorations.append((FINGERPRINT, removable_policy(read(FINGERPRINT), old, FINGERPRINT),
                             state['originals'][FINGERPRINT.name]['mode']))
    for name in PRIVATE:
        if name not in state['originals']:
            continue  # Legacy appliance manifests predate the two KDE substacks.
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
        require(all(canonical(read(path)) == canonical(service_policy(path, integrated=False))
                    for path in (KDE, FINGERPRINT)), 'unowned or unknown KDE policy; package transaction refused')
    return {'package_check': 'passed', 'schema': 2, 'removal': removal}


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
    state.update(resume_phase=state['phase'], phase='suspended', services=previous)
    save(state)  # Durable recovery intent precedes service stop and replacement.
    stop()
    state['upgrade_binding'] = upgrade_binding(state)
    save(state)
    return {'suspended': True, 'enrollment_preserved': True, 'gate': 'disabled'}


def package_resume(state):
    if state is None or state['phase'] == 'disabled':
        return {'resumed': False}
    require(state['phase'] == 'suspended'
            or (state.get('resume_pending') is True and state['phase'] == state.get('resume_phase')),
            'no suspended upgrade to resume')
    require(state.get('resume_phase', 'prepared') in ('prepared', 'active'), 'invalid upgrade resume phase')
    close_gate()
    stop()
    current(state, binaries=False)
    require(upgrade_binding(state) == state.get('upgrade_binding'),
            'account, credential or throttle state changed during package transaction; recovery required')
    state.update(binaries=binary_snapshot())
    save(state)
    units = [name for key, name in [('socket', 'localpin.socket'), ('service', 'localpin.service')]
             if state['services'][key]]
    if units:
        run(['/usr/bin/systemctl', 'start', *units])
    state['phase'] = state.get('resume_phase', 'prepared')
    state['resume_pending'] = True
    save(state)
    if state['phase'] == 'active':
        atomic_write(GATE, b'LPINT01\nactive\n', 0o644)
        run(['/usr/sbin/restorecon', str(GATE)])
    return {'resumed': True, 'enrollment_preserved': True,
            'gate': 'active' if state['phase'] == 'active' else 'disabled'}


def package_cache_begin(state):
    """Compatibility verb: ordinary RPM cache writes need no authority window."""
    if state is None or state['phase'] == 'disabled':
        return {'cache_window': False}
    require(state['phase'] == 'suspended', 'suspend the package before its cache window')
    close_gate()
    stop()
    current(state, binaries=False)
    require(upgrade_binding(state) == state.get('upgrade_binding'),
            'account, credential or throttle state changed before package transaction')
    return {'cache_window': False, 'account_authority': 'account-marker', 'gate': 'disabled'}


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
        if b'pam_localpin' in data or b'localpin-kde-password' in data or b'localpin-kde-fingerprint' in data:
            references.append(entry.name)
    return references


def candidate_check(candidate, schema):
    """RPM's native EVR comparison; never execute a string as a program."""
    match = re.fullmatch(r'([0-9]+):([A-Za-z0-9.+~^]+)-([A-Za-z0-9.+~^]+)', candidate)
    require(match is not None and match[1] == '0' and match[2] == '0.1.0' and schema == 2,
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
            'supported_account_domain': 'Fedora KDE 44 x86_64 local files accounts',
            'fingerprint_faillock_combination': 'KDE-specific native accounting',
            'distribution_updates': 'stable PAM ABI; owned KDE policy; account markers'}


def main():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=['status', 'setup-status', 'prepare-accounting', 'prepare', 'trial', 'record-tests', 'activate', 'migrate-legacy',
                                             'disable', 'recover', 'package-check', 'package-suspend', 'package-cache-begin', 'package-resume'])
    parser.add_argument('--uid', type=int, action='append', default=[])
    parser.add_argument('--setup-uid', type=int, help='Require a single-account setup transaction for this UID')
    parser.add_argument('--setup-trial', help='Require the exact trial reference confirmed during setup')
    parser.add_argument('--dry-run', action='store_true')
    parser.add_argument('--removal', action='store_true')
    parser.add_argument('--candidate-evr')
    parser.add_argument('--candidate-schema', type=int)
    parser.add_argument('--pin', action='store_true', help='Administrator attests actual desktop PIN test passed')
    parser.add_argument('--password', action='store_true', help='Administrator attests actual desktop full-password test passed')
    parser.add_argument('--recovery', action='store_true', help='Administrator attests actual console recovery test passed')
    args = parser.parse_args()
    require(os.getuid() == os.geteuid(), 'setuid installation is unsupported')
    require(not args.uid or args.operation in ('prepare', 'setup-status'), 'UID selection applies only to prepare or setup-status')
    require(args.operation != 'setup-status' or len(args.uid) == 1, 'setup-status requires exactly one UID')
    require(args.setup_uid is None or args.operation in ('prepare-accounting', 'prepare', 'trial', 'record-tests', 'activate'),
            'setup UID precondition applies only to setup mutations')
    require(args.setup_uid is None or (1000 <= args.setup_uid <= 59999
            and (args.operation != 'prepare' or args.uid == [args.setup_uid])),
            'setup preparation requires exactly its selected UID')
    require(args.operation != 'prepare-accounting' or args.setup_uid is not None,
            'accounting maintenance requires exactly its setup owner')
    require(args.setup_trial is None or (args.setup_uid is not None
            and args.operation in ('record-tests', 'activate')
            and re.fullmatch(r'[0-9a-f]{64}', args.setup_trial)),
            'setup trial reference requires a setup attestation or activation')
    require(args.setup_uid is None or args.operation not in ('record-tests', 'activate')
            or args.setup_trial is not None, 'setup attestation and activation require the confirmed trial reference')
    require(not args.dry_run or args.operation in ('prepare', 'disable', 'recover', 'migrate-legacy'), 'dry-run unavailable for this operation')
    require(not args.removal or args.operation == 'package-check', 'removal applies only to package-check')
    require(not (args.pin or args.password or args.recovery) or args.operation == 'record-tests', 'test attestations apply only to record-tests')
    require((args.candidate_evr is None) == (args.candidate_schema is None), 'candidate version and schema must be supplied together')
    require(args.candidate_evr is None or (args.operation == 'package-check' and not args.removal), 'candidate checks apply only to upgrades')
    if args.operation == 'status' and os.geteuid() != 0:
        print(json.dumps({'schema_version': 1, 'gate': gate_state(), 'tested': 'ask-administrator'}))
        return
    require(os.getuid() == os.geteuid() == 0, 'run this fixed administrative tool as root (for example with sudo)')
    if args.operation == 'setup-status':
        print(json.dumps(setup_status(args.uid[0]), sort_keys=True))
        return
    if args.operation == 'package-check':
        require(not accounting_pending(), 'accounting maintenance pending; preserve the installed recovery helper')
    if args.operation == 'record-tests':
        require(args.pin and args.password and args.recovery, 'explicit PIN, password and console-recovery attestations required')
    if args.candidate_evr:
        candidate_check(args.candidate_evr, args.candidate_schema)
    if args.dry_run or args.operation in ('status', 'package-check'):
        state = load()
        if args.setup_uid is not None:
            setup_scope(state, args.setup_uid)
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
            require(not accounting_pending(), 'accounting maintenance pending; use emergency recovery')
            if args.operation in ('disable', 'recover'):
                # Even a corrupt manifest must not leave desktop PIN active.
                close_gate()
            state = load()
            if args.setup_uid is not None:
                setup_scope(state, args.setup_uid)
                require(state is None or (state.get('schema') == 2
                        and state['phase'] not in ('preparing', 'suspended')),
                        'incomplete or legacy integration; use documented console recovery')
                if args.operation in ('trial', 'record-tests', 'activate'):
                    require(state is not None and state['phase'] == 'prepared',
                            'setup state changed; inspect the current installation before continuing')
                if args.operation in ('record-tests', 'activate'):
                    binding = enrollment_binding(state['uids']) if state else None
                    require(state is not None and setup_trial(state, binding)[0],
                            'a live trial bound to this enrollment is required; repeat desktop tests')
                    require(setup_trial_reference(state) == args.setup_trial,
                            'trial changed during setup; repeat the desktop test confirmations')
            if args.operation == 'prepare-accounting':
                accounting = accounting_module()
                try:
                    result = accounting.schedule(sys.modules[__name__], args.setup_uid)
                except accounting.RPMBusy:
                    raise Refusal('package transaction in progress; finish package operations before rerunning localpin setup') from None
                except RuntimeError:
                    raise Refusal('accounting maintenance could not be scheduled; use administrator recovery') from None
            elif args.operation == 'prepare':
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
