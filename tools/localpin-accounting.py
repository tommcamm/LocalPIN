#!/usr/bin/python3 -I
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Fixed-path first-install accounting maintenance; never a live migration.

All commands require actual root. The service executes in a dedicated root
cgroup. No alternate root, policy, program or path can be supplied by a caller.
Importable copy primitives are exercised only against synthetic fixtures.
"""
import argparse
import contextlib
import fcntl
import hashlib
import importlib.machinery
import importlib.util
import json
import os
from pathlib import Path
import pwd
import re
import select
import signal
import stat
import subprocess
import sys
import time
import uuid

STATE = Path('/var/lib/localpin-integration')
CONTROL = STATE / 'control'
WORK = CONTROL / 'accounting'
JOURNAL = WORK / 'transaction.json'
BACKUP = WORK / 'backup'
RESUME = STATE / 'setup-resume.json'
SOURCE = Path('/run/faillock')
TARGET = Path('/var/lib/faillock')
CONFIG = Path('/etc/security/faillock.conf')
REGISTRY = Path('/var/lib/localpin-accounts/registry')
CGROUP = Path('/sys/fs/cgroup')
RPM_LOCK = Path('/usr/lib/sysimage/rpm/.rpm.lock')
PERSISTENT = b'dir = /var/lib/faillock\n'
VOLATILE_SHA = '662303cf89938c12d95a7fc59d92cbe76c398312527fa908894fb319809093b3'
AUTH_UNITS = ('display-manager.service', 'sddm.service', 'sshd.service', 'sshd.socket',
              'getty@.service', 'serial-getty@.service', 'console-getty.service',
              'user@.service', 'systemd-user-sessions.service',
              'localpin.socket', 'localpin.service', 'crond.service', 'atd.service')
NORMAL_SLICES = ('system.slice', 'user.slice', 'machine.slice')
STOCK_MOUNT_GROUPS = ('dev-hugepages.mount', 'dev-mqueue.mount',
                     'sys-fs-fuse-connections.mount', 'sys-kernel-config.mount',
                     'sys-kernel-debug.mount', 'sys-kernel-tracing.mount')
RESTORE_UNITS = ('display-manager.service', 'sshd.service', 'sshd.socket')
TERMINAL_PHASES = ('complete', 'aborted')
JOURNAL_BOUND = 4 * 1024 * 1024
ENV = {'PATH': '/usr/sbin:/usr/bin', 'LANG': 'C', 'LC_ALL': 'C'}
OPERATION_NAMES = ('rpm-lock-path', 'selinux-status', 'display-manager-status',
                   'restore-unit-status', 'mask-status', 'label-work', 'schedule-maintenance',
                   'persistent-filesystem', 'label-persistent', 'label-resume',
                   'mask-authentication', 'stop-sessions', 'isolate-maintenance',
                   'unmask-owned', 'restore-graphical', 'restore-listeners',
                   'restoration-jobs', 'restoration-status', 'emergency', 'begin-maintenance')


class MaintenanceRefusal(RuntimeError):
    """Only fixed, nonsecret refusal messages may enter diagnostic evidence."""


class RPMBusy(MaintenanceRefusal):
    """Native RPM transaction already owns its POSIX transaction lock."""


class CommandRefusal(MaintenanceRefusal):
    def __init__(self, operation, returncode, detail):
        super().__init__('fixed accounting maintenance operation refused')
        self.command = {'operation': operation, 'returncode': returncode, 'detail': detail}


def require(value, message):
    if not value:
        raise MaintenanceRefusal(message)


def command(args, *, operation, check=True, timeout=30):
    require(operation in OPERATION_NAMES, 'unknown fixed accounting operation')
    try:
        result = subprocess.run(args, env=ENV, stdin=subprocess.DEVNULL,
                                capture_output=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        raise CommandRefusal(operation, None, 'timeout') from None
    if check and result.returncode:
        # Do not export command output, paths, unit instances or OS messages.
        # These categories retain useful systemd rejection information only.
        detail = 'command-failed'
        for marker, category in ((b'File exists', 'file-exists'),
                                 (b'already exists', 'file-exists'),
                                 (b'is masked', 'unit-masked'),
                                 (b'not found', 'unit-not-found'),
                                 (b'Access denied', 'access-denied'),
                                 (b'Permission denied', 'access-denied'),
                                 (b'Job failed', 'job-failed')):
            if marker in result.stderr:
                detail = category
                break
        raise CommandRefusal(operation, result.returncode, detail)
    return result


def integration():
    loader = importlib.machinery.SourceFileLoader('localpin_integration', '/usr/libexec/localpin/localpin-integration')
    module = importlib.util.module_from_spec(importlib.util.spec_from_loader(loader.name, loader))
    loader.exec_module(module)
    return module


def boot():
    value = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    require(str(uuid.UUID(value)) == value, 'invalid boot identity')
    return value


def safe_directory(path, *, mode=None):
    info = path.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 0
            and not info.st_mode & 0o022
            and (mode is None or stat.S_IMODE(info.st_mode) == mode),
            'unsafe fixed accounting directory')
    require(not any(name in os.listxattr(path) for name in ('system.posix_acl_access', 'system.posix_acl_default')),
            'unexpected accounting directory ACL requires separate review')


def canonical_tally_metadata(info, account, *, native_source=False):
    # Native login/sudo can create a volatile tally with its primary group.
    # Installed LocalPIN still requires root-group persistent accounting. The
    # sole optional GID conversion is explicit, offline, backed up and confined
    # to the new persistent copy; the volatile source is never chowned.
    groups = (0, account.pw_gid) if native_source else (0,)
    return (info.st_uid == account.pw_uid and info.st_gid in groups
            and stat.S_IMODE(info.st_mode) == 0o660 and info.st_size < 65536 and info.st_size % 64 == 0)


def valid_native_records(data, now):
    if len(data) >= 65536 or len(data) % 64:
        return False
    for offset in range(0, len(data), 64):
        record = data[offset:offset + 64]
        status = int.from_bytes(record[54:56], 'little')
        when = int.from_bytes(record[56:64], 'little')
        if record[52:54] != b'\0\0' or status & ~7 or status & 6 == 6 or when > now:
            return False
    return True


def capture(path, *, tally=False, native_source=False):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC | os.O_NOATIME)
    try:
        info = os.fstat(descriptor)
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
                and info.st_size <= 65536, 'unsafe bounded accounting file')
        if tally:
            require(re.fullmatch(r'[a-z_][a-z0-9_-]{0,31}\$?', path.name) is not None,
                    'noncanonical native tally name')
            account = pwd.getpwnam(path.name)
            require(canonical_tally_metadata(info, account, native_source=native_source),
                    'noncanonical native tally metadata or length')
        else:
            require(info.st_uid == info.st_gid == 0 and stat.S_IMODE(info.st_mode) == 0o644,
                    'unsafe native accounting configuration')
        data = os.read(descriptor, 65537)
        require(len(data) == info.st_size, 'accounting file changed while reading')
        if tally:
            require(valid_native_records(data, int(time.time())), 'malformed or future native accounting records')
        attrs = {name: os.getxattr(descriptor, name).hex() for name in sorted(os.listxattr(descriptor))}
        require(len(attrs) <= 16 and sum(len(name) + len(value) for name, value in attrs.items()) <= 8192,
                'oversized accounting extended attributes')
        require('security.selinux' in attrs, 'native accounting SELinux label missing')
        require(not any(name in attrs for name in ('system.posix_acl_access', 'system.posix_acl_default')),
                'unexpected accounting ACL requires separate review')
        return {'uid': info.st_uid, 'gid': info.st_gid, 'mode': stat.S_IMODE(info.st_mode),
                'atime_ns': info.st_atime_ns, 'mtime_ns': info.st_mtime_ns,
                'size': len(data), 'sha256': hashlib.sha256(data).hexdigest(),
                'xattrs': attrs}, data
    finally:
        os.close(descriptor)


def equivalent(left, right):
    return all(left[key] == right[key] for key in ('uid', 'gid', 'mode', 'size', 'sha256', 'xattrs'))


def copy_exact(path, snapshot, data):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        os.fchown(descriptor, snapshot['uid'], snapshot['gid'])
        os.fchmod(descriptor, snapshot['mode'])
        view = memoryview(data)
        while view:
            count = os.write(descriptor, view)
            require(count > 0, 'short accounting copy')
            view = view[count:]
        for name, value in snapshot['xattrs'].items():
            os.setxattr(descriptor, name, bytes.fromhex(value))
        os.utime(descriptor, ns=(snapshot['atime_ns'], snapshot['mtime_ns']))
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def fsync_directory(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)



def unique_fields(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'duplicate accounting journal field')
        result[key] = value
    return result


def read_journal(m):
    try:
        value = json.loads(m.read(JOURNAL, JOURNAL_BOUND, mode=0o600), object_pairs_hook=unique_fields)
    except FileNotFoundError:
        return None
    require(isinstance(value, dict) and type(value.get('schema')) is int and value['schema'] == 1
            and type(value.get('uid')) is int and 1000 <= value['uid'] <= 59999
            and isinstance(value.get('request_id'), str)
            and re.fullmatch('[0-9a-f]{64}', value['request_id'])
            and value.get('phase') in ('requested', 'masking', 'quiescing', 'barrier-started', 'quiescent', 'backed-up',
                                       'copied', 'switched', 'complete', 'aborted', 'failed'),
            'invalid accounting maintenance journal; use emergency recovery')
    require(isinstance(value.get('boot'), str) and str(uuid.UUID(value['boot'])) == value['boot'],
            'invalid maintenance boot identity')
    require(type(value.get('isolation_requested', True)) is bool,
            'invalid maintenance isolation marker')
    require('restoration' not in value or value['restoration'] in ('not-needed', 'pending', 'restored'),
            'invalid maintenance restoration state')
    require('failure_operation' not in value or value['failure_operation'] in OPERATION_NAMES,
            'invalid maintenance failure operation')
    return value


def save(m, state, phase):
    state['phase'] = phase
    data = json.dumps(state, sort_keys=True).encode() + b'\n'
    require(len(data) <= JOURNAL_BOUND, 'oversized accounting journal')
    m.atomic_write(JOURNAL, data)


def validate_rpm_lock(m, fd):
    m.safe_parents(RPM_LOCK)
    info = os.fstat(fd)
    current = RPM_LOCK.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_uid == info.st_gid == 0
            and stat.S_IMODE(info.st_mode) == 0o644 and info.st_nlink == 1
            and (info.st_dev, info.st_ino) == (current.st_dev, current.st_ino),
            'unsafe or replaced native RPM transaction lock')


@contextlib.contextmanager
def rpm_locked(m):
    # RPM 6 uses process-owned POSIX fcntl whole-file locks, not flock. Never
    # create, replace or truncate the distribution's existing transaction lock.
    require(command(['/usr/bin/rpm', '--eval', '%{_rpmlock_path}'], operation='rpm-lock-path').stdout.strip()
            == str(RPM_LOCK).encode(), 'unsupported native RPM transaction lock path')
    m.safe_parents(RPM_LOCK)
    fd = os.open(RPM_LOCK, os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        validate_rpm_lock(m, fd)
        try:
            fcntl.lockf(fd, fcntl.LOCK_EX | fcntl.LOCK_NB, 0, 0, os.SEEK_SET)
        except BlockingIOError:
            raise RPMBusy('native RPM transaction is active; rerun setup after it finishes') from None
        validate_rpm_lock(m, fd)
        require(command(['/usr/bin/rpm', '--eval', '%{_rpmlock_path}'], operation='rpm-lock-path').stdout.strip()
                == str(RPM_LOCK).encode(), 'unsupported native RPM transaction lock path')
        yield fd
    finally:
        os.close(fd)


def record_failure(m, error, *, recovery=False):
    """Best-effort bounded root-only evidence; never persist raw OS text/logs."""
    try:
        state = read_journal(m)
        if state is None:
            return
        path = WORK / ('recovery-failure.json' if recovery else 'failure.json')
        # The first failure is the cause; a later cleanup failure is separate.
        if path.exists() or path.is_symlink():
            return
        value = {'schema': 1, 'phase': state.get('failure_phase', state['phase']),
                 'exception': type(error).__name__,
                 'errno': error.errno if isinstance(error, OSError) else None}
        if isinstance(error, (MaintenanceRefusal, m.Refusal)):
            value['reason'] = str(error)
        if isinstance(error, CommandRefusal):
            value['command'] = error.command
        data = json.dumps(value, sort_keys=True).encode() + b'\n'
        if len(data) <= 4096:
            m.atomic_write(path, data)
    except (OSError, RuntimeError, ValueError, KeyError, TypeError):
        pass


def schedule(m, uid):
    """Called while integration holds its existing administrative lock."""
    with rpm_locked(m):
        return schedule_locked(m, uid)


def schedule_locked(m, uid):
    require(m.load() is None and not REGISTRY.exists(), 'accounting maintenance requires a fresh unprepared installation')
    require(m.setup_scope(None, uid) == {}, 'account authority must be empty before accounting maintenance')
    m.validate_policy(allow_volatile=True)
    before, _ = capture(CONFIG)
    require(before['sha256'] == VOLATILE_SHA, 'unsupported native accounting configuration')
    if WORK.exists() or WORK.is_symlink():
        previous = read_journal(m)
        require(previous is not None and previous['phase'] == 'aborted',
                'prior accounting maintenance requires administrator review')
        require(previous.get('restoration') != 'pending', 'login restoration is still pending; use administrator recovery')
        safe_directory(WORK, mode=0o700)
        archive = CONTROL / ('accounting-aborted-' + previous['request_id'])
        require(not archive.exists() and not archive.is_symlink(), 'accounting archive already exists')
        os.rename(WORK, archive)
        fsync_directory(CONTROL)
    require(command(['/usr/sbin/getenforce'], operation='selinux-status').stdout.strip() == b'Enforcing', 'SELinux enforcing required')
    require(command(['/usr/bin/systemctl', 'is-active', '--quiet', 'display-manager.service'], operation='display-manager-status', check=False).returncode == 0,
            'active supported display manager required')
    WORK.mkdir(mode=0o700)
    fsync_directory(CONTROL)
    state = {'schema': 1, 'uid': uid, 'boot': boot(), 'request_id': os.urandom(32).hex(),
             'isolation_requested': False}
    state['restore_units'] = [unit for unit in RESTORE_UNITS if command(
        ['/usr/bin/systemctl', 'is-active', '--quiet', unit], operation='restore-unit-status', check=False).returncode == 0]
    state['owned_masks'] = [unit for unit in AUTH_UNITS if command(
        ['/usr/bin/systemctl', 'show', '--property=UnitFileState', '--value', unit],
        operation='mask-status', check=False).stdout.strip() not in (b'masked', b'masked-runtime')]
    save(m, state, 'requested')
    command(['/usr/sbin/restorecon', '-R', str(WORK)], operation='label-work')
    # The fixed system service sleeps briefly before isolating, allowing sudo and
    # the wizard to return. It is not a descendant of the user's session cgroup.
    command(['/usr/bin/systemctl', 'start', '--no-block', 'localpin-accounting-delay.service'], operation='schedule-maintenance')
    return {'scheduled': True}


def inventory(directory, *, native_source=False, private=False):
    require(not directory.is_symlink(), 'symlink accounting directory refused')
    if not directory.exists():
        require(not private, 'private accounting backup directory missing')
        return {}
    safe_directory(directory, mode=0o700 if private else 0o755)
    paths = sorted(directory.iterdir())
    require(len(paths) <= 128, 'oversized accounting inventory')
    return {path.name: capture(path, tally=True, native_source=native_source) for path in paths}


def verify_inventory(directory, expected, *, native_source=False):
    current = inventory(directory, native_source=native_source)
    require(set(current) == set(expected), 'accounting inventory changed')
    for name, (snapshot, data) in expected.items():
        require(equivalent(snapshot, current[name][0]) and current[name][1] == data,
                'accounting bytes or security metadata changed')


def migrate(m, state):
    """Caller has killed old workers and frozen every other userspace cgroup."""
    require(state['boot'] == boot() and not REGISTRY.exists(), 'same-boot fresh accounting transaction required')
    for path in (Path('/etc'), Path('/etc/security'), Path('/run'), Path('/var'), Path('/var/lib')):
        safe_directory(path)
    before, data = capture(CONFIG)
    require(before['sha256'] == VOLATILE_SHA, 'reviewed volatile configuration required')
    if not TARGET.exists():
        TARGET.mkdir(mode=0o755)
        fsync_directory(TARGET.parent)
    safe_directory(TARGET, mode=0o755)
    require(command(['/usr/bin/stat', '-f', '-c', '%T', str(TARGET)], operation='persistent-filesystem').stdout.strip()
            in (b'btrfs', b'ext2/ext3', b'xfs'), 'supported persistent accounting filesystem required')
    source = inventory(SOURCE, native_source=True)
    targets = inventory(TARGET)
    desired = {name: (dict(snapshot, gid=0), raw) for name, (snapshot, raw) in source.items()}
    for name, (snapshot, _) in desired.items():
        require(name not in targets or equivalent(snapshot, targets[name][0]),
                'conflicting persistent tally; no overwrite or reset permitted')
    BACKUP.mkdir(mode=0o700)
    for directory in ('volatile', 'persistent'):
        (BACKUP / directory).mkdir(mode=0o700)
    copy_exact(BACKUP / 'faillock.conf', before, data)
    for directory, items in (('volatile', source), ('persistent', targets)):
        for name, (snapshot, raw) in items.items():
            copy_exact(BACKUP / directory / name, snapshot, raw)
        fsync_directory(BACKUP / directory)
    fsync_directory(BACKUP)
    fsync_directory(WORK)
    state['source'] = {name: snapshot for name, (snapshot, _) in source.items()}
    state['persistent'] = {name: snapshot for name, (snapshot, _) in {**targets, **desired}.items()}
    save(m, state, 'backed-up')
    for name, (snapshot, raw) in desired.items():
        if name not in targets:
            copy_exact(TARGET / name, snapshot, raw)
    fsync_directory(TARGET)
    verify_inventory(SOURCE, source, native_source=True)
    verify_inventory(TARGET, {**targets, **desired})
    current, raw = capture(CONFIG)
    require(equivalent(before, current) and raw == data, 'native configuration changed')
    save(m, state, 'copied')
    temporary = CONFIG.parent / ('.localpin-accounting-' + state['request_id'])
    changed = dict(before, size=len(PERSISTENT), sha256=hashlib.sha256(PERSISTENT).hexdigest())
    copy_exact(temporary, changed, PERSISTENT)
    os.replace(temporary, CONFIG)
    fsync_directory(CONFIG.parent)
    save(m, state, 'switched')
    command(['/usr/sbin/restorecon', '-R', str(TARGET), str(CONFIG)], operation='label-persistent')
    fsync_directory(TARGET)
    fsync_directory(CONFIG.parent)
    require(capture(CONFIG)[1] == PERSISTENT, 'persistent configuration verification failed')
    verify_inventory(SOURCE, source, native_source=True)
    verify_inventory(TARGET, {**targets, **desired})
    state['restoration'] = 'pending'
    save(m, state, 'complete')


def publish_hint(m, state, outcome):
    require(outcome in ('ready', 'aborted'), 'invalid setup outcome hint')
    hint = {'schema_version': 1, 'uid': state['uid'], 'request_id': state['request_id'], 'state': outcome}
    m.atomic_write(RESUME, json.dumps(hint, sort_keys=True).encode() + b'\n', 0o644)
    command(['/usr/sbin/restorecon', str(RESUME)], operation='label-resume')


def cgroup_events(path):
    return dict(line.split() for line in (path / 'cgroup.events').read_text().splitlines())


def cgroup_write(path, name, value):
    with (path / name).open('w') as stream:
        stream.write(value)


def wait_cgroup(path, field, value):
    deadline = time.monotonic() + 10
    while cgroup_events(path).get(field) != value:
        require(time.monotonic() < deadline, 'kernel cgroup barrier timed out')
        time.sleep(0.02)


def wait_init_scope_idle():
    # Short-lived systemd executors can outlast the target's isolation job.
    # Wait before the barrier; the frozen inventory still requires PID1 alone.
    deadline = time.monotonic() + 10
    while (CGROUP / 'init.scope/cgroup.procs').read_text().split() != ['1']:
        require(time.monotonic() < deadline, 'unexpected init scope processes')
        time.sleep(0.02)


def cgroup_layout():
    # Cgroup v2 is a kernel-enforced barrier, unlike a process-name scan.
    require((CGROUP / 'cgroup.controllers').exists(), 'unified cgroup v2 required')
    own = Path('/proc/self/cgroup').read_text().strip()
    require(own == '0::/localpinmaintenance.slice/localpin-accounting.service',
            'accounting helper must run in its fixed independent system cgroup')
    require_root_kernel_tasks()
    require((CGROUP / 'init.scope/cgroup.procs').read_text().split() == ['1'],
            'unexpected init scope processes')
    allowed = {*NORMAL_SLICES, *STOCK_MOUNT_GROUPS, 'init.scope', 'localpinmaintenance.slice'}
    groups = [path for path in CGROUP.iterdir() if path.is_dir()]
    require(all(path.name in allowed for path in groups), 'unsupported top-level cgroup; maintenance refused')
    require(all(cgroup_events(path).get('populated') == '0'
                for path in groups if path.name in STOCK_MOUNT_GROUPS),
            'unexpected task in stock mount cgroup')
    maintenance = CGROUP / 'localpinmaintenance.slice'
    require(not (maintenance / 'cgroup.procs').read_text().strip()
            and [p.name for p in maintenance.iterdir() if p.is_dir()] == ['localpin-accounting.service'],
            'unrelated maintenance cgroup tasks')
    normal = [CGROUP / name for name in (*NORMAL_SLICES, *STOCK_MOUNT_GROUPS) if (CGROUP / name).exists()]
    require(all((path / 'cgroup.freeze').exists() and (path / 'cgroup.events').exists()
                for path in [*normal, CGROUP / 'init.scope'])
            and all((path / 'cgroup.kill').exists() for path in normal),
            'required kernel cgroup controls unavailable')
    return normal


def require_root_kernel_tasks():
    """Fedora leaves kernel threads in the root cgroup; exclude userspace."""
    values = (CGROUP / 'cgroup.procs').read_text().split()
    require(len(values) <= 32768 and all(value.isdecimal() and int(value) > 0 for value in values),
            'invalid root cgroup task inventory')
    for value in values:
        try:
            data = (Path('/proc') / value / 'status').read_bytes()
        except FileNotFoundError:
            # A task may exit between the cgroup inventory and procfs lookup.
            continue
        require(len(data) <= 8192 and re.findall(rb'^Kthread:\s*([01])\s*$', data, re.M) == [b'1'],
                'unexpected userspace task in root cgroup')


def thaw():
    # PID1 first so the administrator can always request emergency recovery.
    errors = []
    for name in ('init.scope', *NORMAL_SLICES, *STOCK_MOUNT_GROUPS):
        path = CGROUP / name
        if path.exists():
            try:
                cgroup_write(path, 'cgroup.freeze', '0')
            except OSError:
                errors.append(name)
    require(not errors, 'kernel cgroup thaw failed; reboot into emergency recovery')


def mask_authentication(state):
    # Kept until migration is verified. On failure these runtime masks and the
    # maintenance target preserve an administrator emergency route.
    units = state.get('owned_masks')
    require(isinstance(units, list) and all(unit in AUTH_UNITS for unit in units), 'invalid owned maintenance masks')
    if units:
        command(['/usr/bin/systemctl', 'mask', '--runtime', *units], operation='mask-authentication')


def refresh_owned_masks(state):
    units = state.get('owned_masks')
    require(isinstance(units, list) and all(unit in AUTH_UNITS for unit in units), 'invalid owned maintenance masks')
    # Preserve masks another administrator installed during the delayed handoff.
    state['owned_masks'] = [unit for unit in units if command(
        ['/usr/bin/systemctl', 'show', '--property=UnitFileState', '--value', unit],
        operation='mask-status', check=False).stdout.strip() not in (b'masked', b'masked-runtime')]


def unmask_owned(state):
    units = state.get('owned_masks')
    require(isinstance(units, list) and all(unit in AUTH_UNITS for unit in units), 'invalid owned maintenance masks')
    # Runtime masks disappear at reboot. The old transaction owns no mask in
    # the new boot, even if an administrator now masks the same unit name.
    if 'boot' in state and state['boot'] != boot():
        return
    if units:
        command(['/usr/bin/systemctl', 'unmask', '--runtime', *units], operation='unmask-owned')


def restore_login(state):
    restored = state.get('restore_units')
    require(isinstance(restored, list) and all(unit in RESTORE_UNITS for unit in restored), 'invalid login restoration units')
    command(['/usr/bin/systemctl', '--no-block', 'isolate', 'graphical.target'], operation='restore-graphical')
    if restored:
        command(['/usr/bin/systemctl', '--no-block', 'start', *restored], operation='restore-listeners')


def release_owned_masks(m, state):
    unmask_owned(state)
    units = state['owned_masks']
    state['owned_masks'] = []
    try:
        # Consume ownership before submitting restoration: a later retry must
        # preserve any new administrator masks, including in this same boot.
        save(m, state, state['phase'])
    except BaseException:
        state['owned_masks'] = units
        raise


def login_restored(state):
    result = command(['/usr/bin/systemctl', 'list-jobs', '--no-legend', '--no-pager', '--plain'],
                     operation='restoration-jobs', timeout=2)
    require(len(result.stdout) <= 1024 * 1024, 'oversized restoration job inventory')
    for line in result.stdout.splitlines():
        fields = line.split()
        require(len(fields) == 4 and fields[0].isdigit(), 'invalid restoration job inventory')
        # The helper's own oneshot start job cannot finish until we return.
        if fields[1:3] not in ([b'localpin-accounting.service', b'start'],
                               [b'localpin-accounting-delay.service', b'start']):
            return False
    units = ('graphical.target', 'systemd-logind.service', 'systemd-user-sessions.service',
             *state['restore_units'])
    return all(command(['/usr/bin/systemctl', 'is-active', '--quiet', unit],
                       operation='restoration-status', check=False, timeout=2).returncode == 0
               for unit in units)


def observe_restoration(m, state):
    deadline = time.monotonic() + 30
    while not login_restored(state):
        if time.monotonic() >= deadline:
            return  # A queued restoration is explicitly still pending.
        time.sleep(0.25)
    state['restoration'] = 'restored'
    try:
        save(m, state, state['phase'])
    except BaseException:
        state['restoration'] = 'pending'
        raise


def restore_and_observe(m, state):
    state['restoration'] = 'pending'
    save(m, state, state['phase'])
    release_owned_masks(m, state)
    restore_login(state)
    observe_restoration(m, state)


def finish_terminal(m, state):
    """A proven terminal accounting result survives UI/restoration failures."""
    # Publish before reopening login: a fast next-login autostart must not race
    # a still-absent hint while the helper observes restoration jobs.
    publish_terminal_hint(m, state)
    try:
        restore_and_observe(m, state)
    except (OSError, RuntimeError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        record_failure(m, error, recovery=True)
    report_outcome(state)


def publish_terminal_hint(m, state):
    try:
        publish_hint(m, state, 'ready' if state['phase'] == 'complete' else 'aborted')
    except (OSError, RuntimeError, ValueError, subprocess.SubprocessError) as error:
        record_failure(m, error, recovery=True)


def report_outcome(state):
    # Safe abort exits normally to avoid OnFailure=emergency.target. The journal
    # carries the actual migration result, independently of the service exit.
    try:
        print(json.dumps({'result': state['phase'], 'restoration': state.get('restoration', 'pending'),
                          'failed_operation': state.get('failure_operation')}, sort_keys=True), flush=True)
    except OSError:
        pass  # Losing a journal stream cannot invalidate proven accounting.


def recover_emergency():
    thaw()
    command(['/usr/bin/systemctl', '--no-block', 'isolate', 'emergency.target'], operation='emergency', check=False)


def abort_untouched_request(m, error=None):
    """Restore stock login after a verified refusal before the kernel barrier.

    This narrow path has made no accounting snapshot, copy or policy switch.
    It must not certify an interrupted in-barrier or post-copy transaction.
    """
    validated = False
    try:
        with m.locked():
            state = read_journal(m)
            require(state is not None and state['phase'] in ('requested', 'masking', 'quiescing')
                    and state['boot'] == boot() and 'source' not in state
                    and not BACKUP.exists() and not BACKUP.is_symlink()
                    and not REGISTRY.exists() and m.load() is None,
                    'automatic abort requires an untouched same-boot request')
            require(capture(CONFIG)[0]['sha256'] == VOLATILE_SHA,
                    'automatic abort requires original volatile policy')
            inventory(SOURCE, native_source=True)
            masks_requested = state['phase'] != 'requested'
            if isinstance(error, CommandRefusal):
                state['failure_operation'] = error.command['operation']
            state['restoration'] = 'pending' if masks_requested or state.get('isolation_requested', True) else 'not-needed'
            save(m, state, 'aborted')
        validated = True
        publish_terminal_hint(m, state)
        if state.get('isolation_requested', True):
            restore_and_observe(m, state)
        elif masks_requested:
            # A batched mask can partly succeed. Undo only our masks, without
            # submitting either isolation transaction against a live desktop.
            release_owned_masks(m, state)
            state['restoration'] = 'not-needed'
            save(m, state, 'aborted')
    except (OSError, RuntimeError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as recovery_error:
        if validated:
            record_failure(m, recovery_error, recovery=True)
        else:
            return False
    report_outcome(state)
    return True


def desktop_untouched(m):
    """Only a still-requested false marker proves no service command ran."""
    try:
        state = read_journal(m)
        return (state is not None and state['phase'] == 'requested'
                and state.get('isolation_requested') is False)
    except (OSError, RuntimeError, ValueError, KeyError, TypeError):
        return False


def watchdog(read_fd, parent_pidfd):
    # Separate process in the helper slice: SIGKILL/crash of the worker must
    # never leave PID1 frozen. EOF means the parent died without completion.
    readable, _, _ = select.select([read_fd], [], [], 90)
    success = bool(readable and os.read(read_fd, 1) == b'1')
    if success:
        return
    try:
        signal.pidfd_send_signal(parent_pidfd, signal.SIGKILL)
    except OSError:
        pass
    recover_emergency()


def run_maintenance(m):
    with rpm_locked(m):
        try:
            return run_maintenance_locked(m)
        except BaseException as error:
            # Retain the native transaction lock through verified abort or
            # emergency selection, including failures before the barrier.
            record_failure(m, error)
            if abort_untouched_request(m, error) or desktop_untouched(m):
                return
            recover_emergency()
            raise


def run_maintenance_locked(m):
    with m.locked():
        state = read_journal(m)
        require(state is not None and state['phase'] == 'requested' and state['boot'] == boot(),
                'fresh same-boot maintenance request required')
        require(m.load() is None and not REGISTRY.exists(), 'installation changed before maintenance')
        m.setup_scope(None, state['uid'])
        m.validate_policy(allow_volatile=True)
        refresh_owned_masks(state)
        # Keep mask failure distinct from any request that can stop sessions.
        save(m, state, 'masking')
        mask_authentication(state)
        state['isolation_requested'] = True
        save(m, state, 'quiescing')
        # Let desktop workers finish while their normal services (including
        # CUPS) are available. Isolation would otherwise stop both concurrently.
        # A slice stop alone does not wait for every delegated manager's stop
        # job. Include loaded manager/runtime instances explicitly, so their
        # shutdown workers finish before isolation stops CUPS and other peers.
        command(['/usr/bin/systemctl', 'stop', 'display-manager.service',
                 'user@*.service', 'user-runtime-dir@*.service', 'user.slice'],
                operation='stop-sessions', timeout=45)
        # This target deliberately has no service dependency: the already
        # running IgnoreOnIsolate worker can wait for its isolation job while
        # retaining both locks, before the independent kernel exclusion proof.
        command(['/usr/bin/systemctl', 'isolate', 'localpin-accounting.target'], operation='isolate-maintenance', timeout=45)
        wait_init_scope_idle()
        groups = cgroup_layout()
        # The target isolation stopped ordinary services and sessions. The final
        # kernel barrier freezes survivors and PID1 (which can create slices),
        # then kills every old non-init task so no parsed old PAM state resumes.
        require(hasattr(os, 'pidfd_open') and hasattr(signal, 'pidfd_send_signal'),
                'identity-bound watchdog signaling unavailable')
        parent_pidfd = os.pidfd_open(os.getpid(), 0)
        try:
            read_fd, write_fd = os.pipe2(os.O_CLOEXEC)
        except BaseException:
            os.close(parent_pidfd)
            raise
        try:
            child = os.fork()
        except BaseException:
            for fd in (read_fd, write_fd, parent_pidfd):
                os.close(fd)
            raise
        if child == 0:
            os.close(write_fd)
            try:
                watchdog(read_fd, parent_pidfd)
            finally:
                os.close(read_fd)
                os.close(parent_pidfd)
                os._exit(0)
        os.close(read_fd)
        os.close(parent_pidfd)
        try:
            # Persist exclusion from the pre-barrier automatic abort *before*
            # the first freezer write, even if saving a later failure fails.
            save(m, state, 'barrier-started')
            # Fully drained slices can disappear while PID1 finishes their
            # cleanup. Freeze the manager before taking the authoritative
            # inventory; the earlier inventory only validated prerequisites.
            cgroup_write(CGROUP / 'init.scope', 'cgroup.freeze', '1')
            wait_cgroup(CGROUP / 'init.scope', 'frozen', '1')
            groups = cgroup_layout()
            for path in groups:
                cgroup_write(path, 'cgroup.freeze', '1')
                wait_cgroup(path, 'frozen', '1')
            # Recheck top-level identity after PID1 is frozen.
            require(cgroup_layout() == groups, 'cgroup topology changed before exclusion')
            for path in groups:
                cgroup_write(path, 'cgroup.kill', '1')
                wait_cgroup(path, 'populated', '0')
            state['barrier'] = {'init_frozen': cgroup_events(CGROUP / 'init.scope')['frozen'] == '1',
                                'empty_frozen_slices': {path.name: cgroup_events(path) for path in groups},
                                'old_tasks_killed': True}
            save(m, state, 'quiescent')
            migrate(m, state)
        except BaseException as error:
            # Only a terminal journal permits ordinary boot. No automatic
            # rollback can discard failures recorded after a partial switch.
            state['failure_phase'] = state['phase']
            record_failure(m, error)
            save(m, state, 'failed')
            raise
        finally:
            thaw()
            os.write(write_fd, b'1')
            os.close(write_fd)
            os.waitpid(child, 0)
        finish_terminal(m, state)


def guard(m):
    state = read_journal(m)
    require(state is None or state['phase'] in TERMINAL_PHASES,
            'incomplete accounting maintenance: boot emergency.target for administrator recovery; do not reset tallies')


def recover(m):
    """Explicit administrator recovery: verify authority; never reset or copy."""
    with rpm_locked(m):
        return recover_locked(m)


def recover_locked(m):
    with m.locked():
        state = read_journal(m)
        require(state is not None and (state['phase'] != 'complete' or state.get('restoration') == 'pending'),
                'no interrupted accounting transaction')
        data = capture(CONFIG)[1]
        if state['phase'] in TERMINAL_PHASES:
            # The completed migration is already durable. Native failures may
            # legitimately change tallies after login; never restore or compare
            # them against a historical snapshot to retry service restoration.
            require(data == PERSISTENT if state['phase'] == 'complete' else
                    hashlib.sha256(data).hexdigest() == VOLATILE_SHA,
                    'terminal accounting policy changed; manual review required')
            if state['phase'] == 'complete':
                safe_directory(TARGET, mode=0o755)
                current = inventory(TARGET)
                expected = state.get('persistent')
                require(isinstance(expected, dict) and set(expected) <= set(current),
                        'completed accounting history is missing; manual review required')
            else:
                inventory(SOURCE, native_source=True)
        elif data == PERSISTENT:
            expected = state.get('persistent')
            require(isinstance(expected, dict) and isinstance(state.get('source'), dict),
                    'durable accounting snapshot unavailable; manual review required')
            safe_directory(TARGET, mode=0o755)
            current = inventory(TARGET)
            require(set(current) == set(expected), 'persistent inventory differs from durable snapshot')
            for name, snapshot in expected.items():
                require(equivalent(snapshot, current[name][0]), 'persistent accounting differs; preserve for manual review')
            original = inventory(BACKUP / 'volatile', native_source=True, private=True)
            require(set(original) == set(state['source']), 'private source backup missing')
            for name, snapshot in state['source'].items():
                require(equivalent(snapshot, original[name][0]), 'private source backup differs')
            state['restoration'] = 'pending'
            save(m, state, 'complete')
        else:
            require(hashlib.sha256(data).hexdigest() == VOLATILE_SHA and state['boot'] == boot(),
                    'volatile authority cannot be recovered after reboot; preserve backups for manual review')
            current = inventory(SOURCE, native_source=True)
            if 'source' in state:
                require(set(current) == set(state['source']), 'volatile source inventory changed')
                require(all(equivalent(snapshot, current[name][0]) for name, snapshot in state['source'].items()),
                        'volatile source differs; preserve for manual review')
            state['restoration'] = 'pending'
            save(m, state, 'aborted')
    if state.get('isolation_requested', True):
        thaw()
        finish_terminal(m, state)
    else:
        release_owned_masks(m, state)
        state['restoration'] = 'not-needed'
        save(m, state, state['phase'])
        publish_hint(m, state, 'aborted')
        report_outcome(state)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=('run', 'guard', 'begin', 'recover'))
    args = parser.parse_args()
    require(os.getuid() == os.geteuid() == 0, 'actual root required')
    m = integration()
    if args.operation == 'guard':
        guard(m)
    elif args.operation == 'recover':
        recover(m)
    elif args.operation == 'begin':
        state = read_journal(m)
        require(state is not None and state['phase'] == 'requested' and state['boot'] == boot(),
                'same-boot accounting request required')
        time.sleep(3)
        command(['/usr/bin/systemctl', '--no-block', 'start', 'localpin-accounting.service'], operation='begin-maintenance')
    else:
        require(Path('/proc/self/cgroup').read_text().strip() ==
                '0::/localpinmaintenance.slice/localpin-accounting.service',
                'run is reserved for the fixed accounting service')
        try:
            run_maintenance(m)
        except BaseException as error:
            record_failure(m, error)
            if isinstance(error, RPMBusy) or desktop_untouched(m):
                abort_untouched_request(m)
                # A concurrent administrative lock may prevent recording the
                # abort; retain the pending journal without disturbing RPM.
                return
            raise


if __name__ == '__main__':
    try:
        main()
    except (OSError, RuntimeError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        print('localpin-accounting: maintenance refused; use the administrator emergency recovery runbook', file=sys.stderr)
        raise SystemExit(1) from None
