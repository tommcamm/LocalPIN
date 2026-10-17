#!/usr/bin/python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""One-shot accounting migration from actual tty3 in the guarded M8 clone.

This fixture is not packaged. Invoke only through ordinary sudo from the
dedicated lp61test login on active tty3. Every tally and original configuration
is backed up privately before copying; counters are never reset or replaced.
The topology-verified host must pause all other guest operations until return.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import stat
import subprocess
import sys
import time
import traceback
import uuid

WORK = Path('/root/localpin-m8')
SOURCE = Path('/run/faillock')
TARGET = Path('/var/lib/faillock')
CONFIG = Path('/etc/security/faillock.conf')
BACKUP = WORK / 'm82-accounting-backup'
PERSISTENT = b'dir = /var/lib/faillock\n'
VOLATILE_SHA = '662303cf89938c12d95a7fc59d92cbe76c398312527fa908894fb319809093b3'
NATIVE_GROUP_REFUSAL_RUNNER = '12eff7a6b81dbb9801a415decdd23d9956869d6083c66e3d059e6fa78ff5d591'
GRAPHICAL_QUIESCENCE_REFUSAL_RUNNER = '997dc89686ba36a1ca9b38cbb053cb5e3d549fa7b1885c14ee67605f41df7b29'
REGISTRY = Path('/var/lib/localpin-accounts/registry')
RESTORE_UNITS = ('display-manager.service', 'sshd.service', 'sshd.socket')
AUTH_PROGRAMS = {
    'sudo', 'su', 'runuser', 'login', 'agetty', 'sshd', 'sshd-session', 'sshd-auth', 'unix_chkpwd',
    'sddm', 'sddm-helper', 'kscreenlocker_g', 'passwd', 'chpasswd', 'useradd',
    'usermod', 'userdel', 'chage', 'chfn', 'chsh', 'polkit-agent-he',
    'localpin-auth-w', 'localpin-eligib',
}


def require(value, message):
    if not value:
        raise RuntimeError(message)


def command(args, *, check=True):
    result = subprocess.run(args, capture_output=True, timeout=30)
    if check:
        require(result.returncode == 0, 'fixed offline maintenance command refused')
    return result


def active(unit):
    return command(['/usr/bin/systemctl', 'is-active', '--quiet', unit], check=False).returncode == 0


def loaded(unit):
    result = command(['/usr/bin/systemctl', 'show', unit, '--property=LoadState', '--value'], check=False)
    return result.returncode == 0 and result.stdout.strip() == b'loaded'


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
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
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


def sessions():
    result = command(['/usr/bin/loginctl', 'list-sessions', '--no-legend', '--no-pager'])
    identifiers = [line.split()[0] for line in result.stdout.decode().splitlines() if line.strip()]
    require(len(identifiers) <= 32 and all(re.fullmatch(r'[A-Za-z0-9]+', value) for value in identifiers),
            'unexpected session inventory')
    values = []
    for identifier in identifiers:
        result = command(['/usr/bin/loginctl', 'show-session', identifier,
                          '--property=Id', '--property=User', '--property=TTY', '--property=Remote',
                          '--property=Type', '--property=Class', '--property=State'])
        values.append(dict(line.split('=', 1) for line in result.stdout.decode().splitlines() if '=' in line))
    return values


def current_ancestors():
    values = set()
    process = os.getpid()
    while process > 1:
        require(process not in values, 'cyclic process ancestry')
        values.add(process)
        text = Path('/proc') / str(process) / 'stat'
        process = int(text.read_text().rsplit(')', 1)[1].split()[1])
    return values


def terminal_origin():
    require(os.environ.get('SUDO_UID') == '21061' and os.environ.get('SUDO_USER') == 'lp61test'
            and os.environ.get('SUDO_TTY') == '/dev/tty3' and os.isatty(0)
            and Path('/sys/class/tty/tty0/active').read_text().strip() == 'tty3',
            'ordinary dedicated-user sudo originating on active tty3 required')
    # Fedora sudo may allocate its normal private PTY. Retain that behavior;
    # prove the originating root sudo still has the actual tty3 descriptor.
    matched = []
    for process in current_ancestors():
        root = Path('/proc') / str(process)
        try:
            name = (root / 'comm').read_text().strip()
            descriptor = os.readlink(root / 'fd/0')
            status = (root / 'status').read_text().splitlines()
        except FileNotFoundError:
            continue
        effective = next((line.split()[2] for line in status if line.startswith('Uid:')), None)
        if name == 'sudo' and descriptor == '/dev/tty3' and effective == '0':
            matched.append(process)
    require(bool(matched), 'root sudo ancestry does not retain originating tty3')
    return {'stdin_tty': os.ttyname(0), 'origin': '/dev/tty3', 'sudo_ancestor_count': len(matched)}


def require_quiet():
    require(Path('/sys/class/tty/tty0/active').read_text().strip() == 'tty3',
            'maintenance VT lost foreground')
    values = sessions()
    user_sessions = [value for value in values if value.get('Class') not in ('manager', 'manager-early')]
    require(len(user_sessions) == 1 and user_sessions[0].get('TTY') == 'tty3'
            and user_sessions[0].get('User') == '21061' and user_sessions[0].get('Remote') == 'no'
            and user_sessions[0].get('Type') == 'tty',
            'another graphical, remote or local login session remains')
    allowed = current_ancestors()
    for entry in Path('/proc').iterdir():
        if not entry.name.isdecimal() or int(entry.name) in allowed:
            continue
        try:
            name = (entry / 'comm').read_text().strip()
        except FileNotFoundError:
            continue
        require(name not in AUTH_PROGRAMS, 'another native authenticator or account writer remains')
    require(not REGISTRY.exists(), 'managed account authority appeared during offline migration')
    return values


def quiesce():
    units = [unit for unit in ('localpin.socket', 'localpin.service',
                              'sshd.socket', 'sshd.service', 'display-manager.service') if loaded(unit)]
    require('display-manager.service' in units, 'expected display manager unit missing')
    command(['/usr/bin/systemctl', 'stop', *units])
    # Stop other getty listeners before examining/terminating existing sessions.
    result = command(['/usr/bin/systemctl', 'list-units', '--type=service', '--state=active',
                      '--plain', '--no-legend', '--no-pager',
                      'getty@*.service', 'serial-getty@*.service', 'console-getty.service'])
    other_gettys = [line.split()[0] for line in result.stdout.decode().splitlines() if line.strip()]
    other_gettys = [unit for unit in other_gettys if unit != 'getty@tty3.service']
    require(all(re.fullmatch(r'(?:getty|serial-getty)@[A-Za-z0-9_.-]+\.service|console-getty\.service', unit)
                for unit in other_gettys), 'unexpected getty unit identity')
    if other_gettys:
        command(['/usr/bin/systemctl', 'stop', *other_gettys])
    for session in sessions():
        if session.get('Class') in ('manager', 'manager-early'):
            continue
        if session.get('TTY') == 'tty3' and session.get('User') == '21061':
            continue
        command(['/usr/bin/loginctl', 'terminate-session', session['Id']])
    # The same dedicated UID remains logged in on tty3, so its user manager
    # survives graphical logout. Stop the real KDE session targets explicitly;
    # otherwise a locker worker can outlive its old display-manager session.
    user_systemctl = m.user_environment() + ['/usr/bin/systemctl', '--user']
    graphical_targets = ('graphical-session.target', 'plasma-workspace.target')
    for target in graphical_targets:
        result = command(user_systemctl + ['show', target, '--property=LoadState', '--value'])
        require(result.stdout.strip() == b'loaded', 'reviewed KDE graphical target unavailable')
    command(user_systemctl + ['stop', *graphical_targets])
    deadline = time.monotonic() + 15
    while True:
        try:
            values = require_quiet()
            break
        except RuntimeError:
            if time.monotonic() >= deadline:
                raise
            time.sleep(0.2)
    return other_gettys, values


def migrate(*, canonicalize_native_groups=False):
    other_gettys, remaining_sessions = quiesce()
    for path in (Path('/etc'), Path('/etc/security'), Path('/run'), Path('/var'), Path('/var/lib')):
        safe_directory(path)
    before_config, data = capture(CONFIG)
    require(before_config['sha256'] == VOLATILE_SHA,
            'expected exact reviewed all-comment native accounting configuration')
    if SOURCE.exists():
        safe_directory(SOURCE, mode=0o755)
    if not TARGET.exists():
        TARGET.mkdir(mode=0o755)
        TARGET.chmod(0o755)
    safe_directory(TARGET, mode=0o755)
    require(command(['/usr/bin/stat', '-f', '-c', '%T', str(TARGET)]).stdout.strip() == b'btrfs',
            'persistent private Btrfs accounting target required')
    source_paths = sorted(SOURCE.iterdir()) if SOURCE.exists() else []
    target_paths = sorted(TARGET.iterdir())
    require(len(source_paths) <= 128 and len(target_paths) <= 128, 'oversized native accounting inventory')
    source = {path.name: capture(path, tally=True, native_source=True) for path in source_paths}
    targets = {path.name: capture(path, tally=True) for path in target_paths}
    group_changes = sum(snapshot['gid'] != 0 for snapshot, _ in source.values())
    require(group_changes == 0 or canonicalize_native_groups,
            'native primary-group tallies require the explicit offline canonicalization option')
    desired = {name: (dict(snapshot, gid=0), value) for name, (snapshot, value) in source.items()}
    for name, (snapshot, _) in source.items():
        require(name not in targets or equivalent(desired[name][0], targets[name][0]),
                'different persistent tally exists; never overwrite or reset a counter')
    require_quiet()
    BACKUP.mkdir(mode=0o700)
    (BACKUP / 'volatile').mkdir(mode=0o700)
    (BACKUP / 'persistent').mkdir(mode=0o700)
    copy_exact(BACKUP / 'faillock.conf', before_config, data)
    for name, (snapshot, value) in source.items():
        copy_exact(BACKUP / 'volatile' / name, snapshot, value)
    for name, (snapshot, value) in targets.items():
        copy_exact(BACKUP / 'persistent' / name, snapshot, value)
    for path in (BACKUP / 'volatile', BACKUP / 'persistent', BACKUP):
        fsync_directory(path)
    m.sync_json(WORK / 'm82-accounting-before.json', {
        'config': before_config, 'volatile': {name: value[0] for name, value in source.items()},
        'persistent': {name: value[0] for name, value in targets.items()},
        'sessions': remaining_sessions, 'other_gettys_stopped': other_gettys,
        'canonicalize_native_groups_explicitly_requested': canonicalize_native_groups,
        'planned_destination_gid_changes': group_changes})
    copied = 0
    for name, (snapshot, value) in desired.items():
        if name not in targets:
            copy_exact(TARGET / name, snapshot, value)
            copied += 1
    fsync_directory(TARGET)
    # Recheck the entire live source and configuration immediately before the
    # atomic policy switch. Failed/interrupted copies remain for private review.
    require_quiet()
    require(sorted(path.name for path in SOURCE.iterdir()) == sorted(source) if SOURCE.exists() else not source,
            'native source inventory changed while offline')
    for name, (snapshot, value) in source.items():
        current, raw = capture(SOURCE / name, tally=True, native_source=True)
        require(equivalent(snapshot, current) and value == raw,
                'native source tally changed while offline')
        current, raw = capture(TARGET / name, tally=True)
        require(equivalent(desired[name][0], current) and value == raw,
                'persistent copy did not preserve native tally with the reviewed root group')
    current, raw = capture(CONFIG)
    require(equivalent(before_config, current) and raw == data, 'native configuration changed while offline')
    temporary = CONFIG.parent / ('.localpin-m82-' + uuid.uuid4().hex)
    changed = dict(before_config, size=len(PERSISTENT), sha256=hashlib.sha256(PERSISTENT).hexdigest())
    copy_exact(temporary, changed, PERSISTENT)
    os.replace(temporary, CONFIG)
    fsync_directory(CONFIG.parent)
    command(['/usr/sbin/restorecon', '-R', str(TARGET), str(CONFIG)])
    fsync_directory(TARGET)
    fsync_directory(CONFIG.parent)
    after_config, raw = capture(CONFIG)
    require(raw == PERSISTENT, 'persistent native accounting configuration mismatch')
    after = {path.name: capture(path, tally=True)[0] for path in sorted(TARGET.iterdir())}
    for name, (snapshot, _) in {**targets, **desired}.items():
        require(equivalent(snapshot, after[name]), 'restored label or metadata changed a native tally')
    for name, (snapshot, value) in source.items():
        current, raw = capture(SOURCE / name, tally=True, native_source=True)
        require(equivalent(snapshot, current) and value == raw, 'volatile source changed during migration')
    require_quiet()
    m.sync_json(WORK / 'm82-accounting-after.json', {'config': after_config, 'persistent': after})
    return {'source_tally_count': len(source), 'new_persistent_copies': copied,
            'nonempty_source_tally_count': sum(bool(value) for _, value in source.values()),
            'source_native_record_count': sum(len(value) // 64 for _, value in source.values()),
            'existing_identical_tallies_retained': len(set(source) & set(targets)),
            'native_tally_counter_bytes_uid_mode_xattrs_preserved': True,
            'source_gid_and_tallies_unchanged': True,
            'destination_gid_changes': group_changes,
            'destination_gid_canonicalization_explicitly_requested': canonicalize_native_groups,
            'destination_group_is_root': True,
            'persistent_btrfs': True, 'exact_configuration_atomically_installed': True,
            'backup_and_destination_fsynced_before_configuration_switch': True,
            'actual_sudo_from_active_tty3': True, 'other_authentication_quiesced': True,
            'no_counter_reset_or_conflict_overwrite': True}


def reviewed_native_group_retry(args):
    """Archive one specifically reviewed pre-copy refusal, never auto-retry."""
    names = ('intent', 'failure', 'restoration')
    paths = {name: WORK / ('m82-accounting-' + name + '.json') for name in names}
    require(not BACKUP.exists()
            and not any((WORK / ('m82-accounting-' + name + '.json')).exists()
                        for name in ('before', 'after', 'result', 'retry-review')),
            'retry has possible migration state; preserve and inspect without retry')
    for path in paths.values():
        info = path.lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_uid == info.st_gid == 0
                and info.st_nlink == 1 and stat.S_IMODE(info.st_mode) == 0o600
                and info.st_size <= 65536, 'unsafe prior-attempt evidence')
    intent = json.loads(paths['intent'].read_text())
    failure = json.loads(paths['failure'].read_text())
    restoration = json.loads(paths['restoration'].read_text())
    require(intent.get('uuid') == args.expected_uuid and intent.get('boot') == m.boot_id()
            and intent.get('runner_sha256') == NATIVE_GROUP_REFUSAL_RUNNER
            and isinstance(failure.get('traceback'), str)
            and failure['traceback'].strip().endswith('RuntimeError: noncanonical native tally metadata or length'),
            'retry is restricted to the reviewed original native-group pre-copy refusal')
    previous = intent.get('previous_units')
    require(isinstance(previous, dict) and set(previous) == set(RESTORE_UNITS)
            and all(type(value) is bool for value in previous.values())
            and restoration == {unit: True for unit, was_active in previous.items() if was_active}
            and all(active(unit) for unit, was_active in previous.items() if was_active),
            'previous access/display restoration not established')
    original, _ = capture(CONFIG)
    require(original['sha256'] == VOLATILE_SHA and TARGET.exists(),
            'original volatile configuration or pre-copy target unavailable')
    safe_directory(TARGET, mode=0o755)
    require(not any(TARGET.iterdir()), 'nonempty target may contain prior copy state; no retry')
    archives = {name: WORK / ('m82-accounting-attempt1-' + name + '.json') for name in names}
    require(not any(path.exists() for path in archives.values()), 'prior attempt archive already exists')
    m.sync_json(WORK / 'm82-accounting-retry-review.json', {
        'kind': 'explicit-reviewed-native-primary-group-refusal',
        'previous_runner_sha256': NATIVE_GROUP_REFUSAL_RUNNER,
        'uuid': args.expected_uuid, 'boot': m.boot_id(),
        'original_configuration_unchanged': True, 'target_empty': True,
        'no_backups_or_before_after_result': True, 'previous_units_restored': True})
    for name in names:
        os.rename(paths[name], archives[name])
    fsync_directory(WORK)


def reviewed_graphical_quiescence_retry(args):
    """Preserve the specifically reviewed second pre-copy refusal as attempt2."""
    names = ('intent', 'failure', 'restoration')
    paths = {name: WORK / ('m82-accounting-' + name + '.json') for name in names}
    old_paths = {name: WORK / ('m82-accounting-attempt1-' + name + '.json') for name in names}
    review = WORK / 'm82-accounting-retry-review.json'
    require(not BACKUP.exists()
            and not any((WORK / ('m82-accounting-' + name + '.json')).exists()
                        for name in ('before', 'after', 'result', 'attempt2-review')),
            'quiescence retry has possible migration state; preserve and inspect')
    for path in (*paths.values(), *old_paths.values(), review):
        info = path.lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_uid == info.st_gid == 0
                and info.st_nlink == 1 and stat.S_IMODE(info.st_mode) == 0o600
                and info.st_size <= 65536, 'unsafe reviewed attempt evidence')
    intent = json.loads(paths['intent'].read_text())
    failure = json.loads(paths['failure'].read_text())
    restoration = json.loads(paths['restoration'].read_text())
    prior = json.loads(old_paths['intent'].read_text())
    first_review = json.loads(review.read_text())
    require(intent.get('uuid') == args.expected_uuid and intent.get('boot') == m.boot_id()
            and intent.get('runner_sha256') == GRAPHICAL_QUIESCENCE_REFUSAL_RUNNER
            and isinstance(failure.get('traceback'), str)
            and failure['traceback'].strip().endswith('RuntimeError: another native authenticator or account writer remains')
            and prior.get('runner_sha256') == NATIVE_GROUP_REFUSAL_RUNNER
            and prior.get('uuid') == args.expected_uuid and prior.get('boot') == m.boot_id()
            and first_review.get('kind') == 'explicit-reviewed-native-primary-group-refusal'
            and first_review.get('uuid') == args.expected_uuid and first_review.get('boot') == m.boot_id(),
            'retry is restricted to the exact reviewed second graphical-quiescence refusal')
    previous = intent.get('previous_units')
    require(isinstance(previous, dict) and set(previous) == set(RESTORE_UNITS)
            and all(type(value) is bool for value in previous.values())
            and restoration == {unit: True for unit, was_active in previous.items() if was_active}
            and all(active(unit) for unit, was_active in previous.items() if was_active),
            'second-attempt access/display restoration not established')
    original, _ = capture(CONFIG)
    require(original['sha256'] == VOLATILE_SHA and TARGET.exists(),
            'original volatile configuration or pre-copy target unavailable')
    safe_directory(TARGET, mode=0o755)
    require(not any(TARGET.iterdir()), 'nonempty target may contain prior copy state; no retry')
    archives = {name: WORK / ('m82-accounting-attempt2-' + name + '.json') for name in names}
    require(not any(path.exists() for path in archives.values()), 'second-attempt archive already exists')
    m.sync_json(WORK / 'm82-accounting-attempt2-review.json', {
        'kind': 'explicit-reviewed-lingering-graphical-worker-refusal',
        'previous_runner_sha256': GRAPHICAL_QUIESCENCE_REFUSAL_RUNNER,
        'uuid': args.expected_uuid, 'boot': m.boot_id(),
        'original_configuration_unchanged': True, 'target_empty': True,
        'no_backups_or_before_after_result': True, 'previous_units_restored': True,
        'first_attempt_evidence_retained': True})
    for name in names:
        os.rename(paths[name], archives[name])
    fsync_directory(WORK)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--expected-uuid', required=True)
    parser.add_argument('--disposable-vm-confirmed', action='store_true', required=True)
    parser.add_argument('--emulated-tpm-confirmed', action='store_true', required=True)
    parser.add_argument('--reviewed-retry-after-native-group-refusal', action='store_true')
    parser.add_argument('--reviewed-retry-after-graphical-quiescence-refusal', action='store_true')
    parser.add_argument('--canonicalize-native-groups', action='store_true',
                        help='Explicit offline conversion of only new destination tally GIDs to root; preserves exact original backups and counters')
    args = parser.parse_args()
    require(os.getuid() == os.geteuid() == 0 and str(uuid.UUID(args.expected_uuid)) == args.expected_uuid,
            'canonical clone UUID and actual root required')
    origin = terminal_origin()
    for name in ('run.py', 'guard.py'):
        info = (WORK / name).lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_uid == info.st_gid == 0
                and info.st_nlink == 1 and not info.st_mode & 0o022, 'unsafe fixed M8 helper')
    global m
    sys.path.insert(0, str(WORK))
    import run as m
    m.guard(args.expected_uuid)
    require(not (args.reviewed_retry_after_native_group_refusal
                 and args.reviewed_retry_after_graphical_quiescence_refusal),
            'select only the specifically reviewed prior refusal')
    if args.reviewed_retry_after_native_group_refusal or args.reviewed_retry_after_graphical_quiescence_refusal:
        require(not REGISTRY.exists() and not active('localpin.socket') and not active('localpin.service'),
                'clean unmanaged inactive installation required for reviewed retry')
        if args.reviewed_retry_after_native_group_refusal:
            reviewed_native_group_retry(args)
        else:
            reviewed_graphical_quiescence_retry(args)
    require(not REGISTRY.exists() and not BACKUP.exists()
            and not (WORK / 'm82-accounting-intent.json').exists(),
            'fresh unmanaged accounting fixture required; inspect any prior attempt')
    require(not active('localpin.socket') and not active('localpin.service'),
            'clean inactive LocalPIN installation required')
    previous = {unit: active(unit) for unit in RESTORE_UNITS}
    m.sync_json(WORK / 'm82-accounting-intent.json', {
        'uuid': args.expected_uuid, 'boot': m.boot_id(),
        'runner_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        'previous_units': previous, 'terminal_origin': origin,
        'canonicalize_native_groups_explicitly_requested': args.canonicalize_native_groups})
    result = None
    failure = None
    restored = {}
    try:
        result = migrate(canonicalize_native_groups=args.canonicalize_native_groups)
    except BaseException:
        failure = traceback.format_exc()
    finally:
        for unit in ('sshd.socket', 'sshd.service', 'display-manager.service'):
            if previous[unit]:
                try:
                    command(['/usr/bin/systemctl', 'start', unit])
                    restored[unit] = active(unit)
                except BaseException:
                    restored[unit] = False
        m.sync_json(WORK / 'm82-accounting-restoration.json', restored)
    if failure is not None:
        m.sync_json(WORK / 'm82-accounting-failure.json', {'traceback': failure})
        raise RuntimeError('offline migration refused; inspect guest-private failure and restoration evidence')
    require(all(restored.values()), 'previously active access/display unit did not restart')
    require(command(['/usr/sbin/getenforce']).stdout.strip() == b'Enforcing', 'SELinux enforcing changed')
    value = {'phase': 'm82-offline-accounting', 'passed': True, 'selinux': 'Enforcing',
             'runner_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
             'observations': result, 'previously_active_access_display_units_restored': True,
             'private_backups_and_snapshots_guest_root_only': True}
    m.sync_json(WORK / 'm82-accounting-result.json', value)
    print(json.dumps(value, sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except (OSError, RuntimeError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        print(json.dumps({'phase': 'm82-offline-accounting', 'passed': False,
                          'error': 'offline accounting refused; inspect guest-root-only evidence'}))
        raise SystemExit(1) from None
