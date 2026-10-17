#!/usr/bin/python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Guest-only M8.1 maintenance proof. Prepare first; run only after UI acceptance.

Execute through a host harness that independently checks libvirt topology.
The guest UUID/markers, root-only work directory, active gate and enrolled TPM
account are checked again here. Select the fixed upgrade/reinstall/sysusers/
authselect phase and explicitly confirm the disposable VM and emulated TPM.
Raw native logs, credentials, markers and exact snapshots remain guest-root-only.
No authentication configuration, repository, counter, gate or enrollment repair
is attempted on failure. A no-op DNF upgrade is explicitly not upgrade evidence.
"""
import argparse
import base64
import fcntl
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import stat
import struct
import subprocess
import sys
import time
import traceback
import uuid

EXPECTED_UUID = None
WORK = Path('/root/localpin-m8')
PHASE = 'refused'
ALLOWED_PHASES = ('upgrade', 'reinstall', 'sysusers', 'authselect')
ENV = {'PATH': '/usr/sbin:/usr/bin', 'LANG': 'C', 'LC_ALL': 'C', 'TERM': 'dumb'}
GATE = Path('/var/lib/localpin-integration/gate')
REGISTRY = Path('/var/lib/localpin-accounts/registry')
STATE = Path('/var/lib/localpin/users')
KDE_NAMES = ('kde', 'kde-fingerprint', 'localpin-kde-password',
             'localpin-kde-fingerprint', 'localpin-enroll', 'localpin-eligibility')
NATIVE_PACKAGES = ('pam', 'authselect', 'authselect-libs', 'shadow-utils', 'systemd',
                   'kscreenlocker', 'plasma-workspace', 'selinux-policy-targeted',
                   'glibc-common', 'tpm2-tss', 'localpin')
NATIVE_PATHS = ('/usr/lib64/libpam.so.0', '/usr/lib64/security/pam_env.so',
                '/usr/lib64/security/pam_faildelay.so', '/usr/lib64/security/pam_faillock.so',
                '/usr/lib64/security/pam_unix.so', '/usr/lib64/security/pam_nologin.so',
                '/usr/bin/unix_chkpwd')
SERVICE_ACCOUNT = 'lp81upg'
RUN = None


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def metadata(info):
    return {'device': info.st_dev, 'inode': info.st_ino, 'mode': stat.S_IMODE(info.st_mode),
            'uid': info.st_uid, 'gid': info.st_gid, 'links': info.st_nlink,
            'size': info.st_size, 'mtime_ns': info.st_mtime_ns, 'ctime_ns': info.st_ctime_ns}


def read_file(path, *, owner=0, private=False, bound=65536, mode=None):
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_uid == owner and info.st_gid == 0
            and info.st_nlink == 1 and info.st_size <= bound
            and (stat.S_IMODE(info.st_mode) == mode if mode is not None
                 else not info.st_mode & (0o077 if private else 0o022)),
            'unsafe bounded maintenance input')
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        before = os.fstat(descriptor)
        require(metadata(before) == metadata(info), 'maintenance input replaced before open')
        content = bytearray()
        while len(content) <= bound:
            part = os.read(descriptor, min(65536, bound + 1 - len(content)))
            if not part:
                break
            content.extend(part)
        require(len(content) <= bound and metadata(os.fstat(descriptor)) == metadata(before)
                and metadata(path.lstat()) == metadata(before), 'maintenance input changed while reading')
        return {'bytes_b64': base64.b64encode(content).decode('ascii'),
                'sha256': hashlib.sha256(content).hexdigest(), 'metadata': metadata(before)}
    finally:
        os.close(descriptor)


def content(record):
    return base64.b64decode(record['bytes_b64'], validate=True)


def private_write(name, value):
    require(RUN is not None and re.fullmatch(r'[a-z0-9.-]+', name), 'private output path refused')
    target = RUN / name
    descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    with os.fdopen(descriptor, 'w') as stream:
        json.dump(value, stream, sort_keys=True, indent=2)
        stream.write('\n')
        stream.flush()
        os.fsync(stream.fileno())
    descriptor = os.open(RUN, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def query(args, *, check=True, timeout=45):
    result = subprocess.run(args, capture_output=True, timeout=timeout, env=ENV)
    require(not check or result.returncode == 0, 'bounded native maintenance query refused')
    return result


def packages(names=()):
    arguments = ['rpm', '-q' if names else '-qa', '--qf', '%{NAME}\t%{EPOCHNUM}:%{VERSION}-%{RELEASE}.%{ARCH}\n', *names]
    rows = [row for row in query(arguments).stdout.decode('ascii').splitlines()
            if not row.startswith('gpg-pubkey\t')]
    require(len(rows) <= 20000 and all(re.fullmatch(r'[A-Za-z0-9_.+~-]+\t[0-9]+:[A-Za-z0-9_.+~^-]+', row)
                                      for row in rows), 'unexpected native package identity')
    return sorted(rows)


def bindings(registry):
    require(len(registry) <= 16384 and registry[:8] == b'LPACCT03' and len(registry) >= 10,
            'current live marker authority required')
    count = int.from_bytes(registry[8:10], 'big')
    require(1 <= count <= 128, 'bounded active marker authority required')
    cursor, rows, previous, names, markers = 10, [], 0, set(), set()
    for _ in range(count):
        require(cursor + 29 <= len(registry), 'truncated account authority')
        uid = int.from_bytes(registry[cursor:cursor + 4], 'big')
        incarnation = registry[cursor + 4:cursor + 20]
        marker = int.from_bytes(registry[cursor + 20:cursor + 28], 'big')
        length = registry[cursor + 28]
        cursor += 29
        require(1 <= length <= 32 and cursor + length <= len(registry), 'invalid authority name length')
        name = registry[cursor:cursor + length].decode('ascii')
        cursor += length
        require(1000 <= uid <= 59999 and uid > previous and incarnation != bytes(16)
                and 1 <= marker < 4294967295 and name not in names and marker not in markers
                and re.fullmatch('[a-z_][a-z0-9_-]*', name), 'invalid authority binding')
        previous = uid
        names.add(name)
        markers.add(marker)
        rows.append((uid, name, marker))
    require(cursor == len(registry), 'trailing account authority bytes')
    return rows


def native_files():
    result = {}
    authselect = [name for name in query(['rpm', '-ql', 'authselect-libs']).stdout.decode('ascii').splitlines()
                  if re.fullmatch(r'/usr/lib64/libauthselect\.so\.[0-9]+', name)]
    require(len(authselect) == 1, 'one packaged authselect runtime SONAME required')
    for name in (*NATIVE_PATHS, authselect[0]):
        path = Path(name)
        # Native SONAME links may change during a legitimate package transaction;
        # their canonical root-owned target and exact image are recorded privately.
        target = path.resolve(strict=True)
        require(str(target).startswith('/usr/') and not target.is_symlink(), 'native target escaped usr')
        key = 'packaged-authselect-runtime' if name == authselect[0] else name
        result[key] = {'target': str(target), **read_file(target, bound=4 * 1024 * 1024)}
    return result


def snapshot():
    files = {str(REGISTRY): read_file(REGISTRY, private=True, bound=16384),
             str(GATE): read_file(GATE, bound=160)}
    require(content(files[str(GATE)]) == b'LPINT01\nactive\n', 'active gate required for maintenance proof')
    managed = bindings(content(files[str(REGISTRY)]))
    shadow = query(['getent', '-s', 'files', 'shadow']).stdout.decode('ascii')
    markers = []
    for uid, name, expected in managed:
        record = pwd.getpwnam(name)
        require(record.pw_uid == uid, 'managed UID changed')
        matching = [row.split(':') for row in shadow.splitlines() if row.split(':')[0] == name]
        require(len(matching) == 1 and len(matching[0]) == 9
                and matching[0][8] == str(expected), 'managed shadow marker changed')
        # Only the reserved marker is copied; password hashes never leave this
        # process via a command, log or public result.
        markers.append({'uid': uid, 'name': name, 'marker': expected})
        root = STATE / str(uid)
        info = root.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 0
                and stat.S_IMODE(info.st_mode) == 0o700, 'unsafe managed storage directory')
        active = root / 'active'
        files[str(active)] = read_file(active, private=True)
        pointer = content(files[str(active)])
        require(len(pointer) == 35 and pointer[:6] == b'LPA3\0\x01', 'committed active pointer required')
        active_generation = int.from_bytes(pointer[26:34], 'big')
        generations = sorted(root.glob('generation-*'))
        require(1 <= len(generations) <= 128, 'bounded managed generation list required')
        found_credential = False
        for directory in generations:
            require(re.fullmatch('generation-[1-9][0-9]*', directory.name) is not None,
                    'unexpected managed generation name')
            m = directory.lstat()
            require(stat.S_ISDIR(m.st_mode) and m.st_uid == m.st_gid == 0
                    and stat.S_IMODE(m.st_mode) == 0o700, 'unsafe managed generation directory')
            for basename in ('credential', 'throttle'):
                path = directory / basename
                if path.exists() or path.is_symlink():
                    files[str(path)] = read_file(path, private=True)
                    found_credential |= basename == 'credential'
        require(found_credential and str(root / ('generation-' + str(active_generation)) / 'throttle') in files,
                'enrolled active credential/throttle required')
        tally = Path('/var/lib/faillock') / name
        files[str(tally)] = read_file(tally, owner=uid, mode=0o660)
        require(files[str(tally)]['metadata']['mode'] == 0o660
                and len(content(files[str(tally)])) % 64 == 0, 'canonical native tally required')
    for basename in KDE_NAMES:
        path = Path('/etc/pam.d') / basename
        files[str(path)] = read_file(path)
    return {'files': files, 'managed_markers': markers, 'native_files': native_files(),
            'native_packages': packages(NATIVE_PACKAGES), 'all_packages': packages(),
            'boot_id': m8common.boot_id()}


def maintenance_command(args, timeout):
    descriptor = os.open(RUN / 'native-command.log', os.O_WRONLY | os.O_CREAT | os.O_EXCL
                         | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    started = time.monotonic()
    result_code, timed_out = None, False
    with os.fdopen(descriptor, 'wb') as log:
        try:
            result_code = subprocess.run(args, stdout=log, stderr=subprocess.STDOUT,
                                         timeout=timeout, env=ENV).returncode
        except subprocess.TimeoutExpired:
            timed_out = True
        log.flush()
        os.fsync(log.fileno())
    # History output can identify transaction details and repository messages;
    # it stays private even when the transaction fails or has no package changes.
    history = query(['dnf', 'history', 'info', 'last'], check=False, timeout=60)
    private_write('native-history.json', {'returncode': history.returncode,
                  'stdout_b64': base64.b64encode(history.stdout).decode('ascii'),
                  'stderr_b64': base64.b64encode(history.stderr).decode('ascii')})
    return {'returncode': result_code, 'timed_out': timed_out,
            'elapsed_seconds': round(time.monotonic() - started, 3),
            'native_log_guest_root_only': True, 'native_history_guest_root_only': True}


def compare(before, after):
    files_before, files_after = before['files'], after['files']
    require(files_before.keys() == files_after.keys(), 'maintenance changed protected record set')
    bytes_equal = all(files_before[path]['bytes_b64'] == files_after[path]['bytes_b64'] for path in files_before)
    metadata_equal = all(files_before[path]['metadata'] == files_after[path]['metadata'] for path in files_before)
    markers_equal = before['managed_markers'] == after['managed_markers']
    return {'registry_active_pointer_credentials_throttles_tallies_kde_bytes_preserved': bytes_equal,
            'all_protected_file_metadata_preserved': metadata_equal,
            'managed_shadow_markers_preserved': markers_equal,
            'boot_unchanged': before['boot_id'] == after['boot_id']}


def main():
    global RUN, m8common, PHASE, EXPECTED_UUID
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('phase', choices=ALLOWED_PHASES)
    parser.add_argument('--expected-uuid', required=True)
    parser.add_argument('--disposable-vm-confirmed', action='store_true', required=True)
    parser.add_argument('--emulated-tpm-confirmed', action='store_true', required=True)
    args = parser.parse_args()
    PHASE = args.phase
    EXPECTED_UUID = str(uuid.UUID(args.expected_uuid))
    require(EXPECTED_UUID == args.expected_uuid and args.disposable_vm_confirmed
            and args.emulated_tpm_confirmed, 'explicit canonical disposable-emulator confirmation required')
    runner_digest = globals().get('RUNNER_SHA256')
    if runner_digest is None and '__file__' in globals():
        runner_digest = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    require(isinstance(runner_digest, str) and re.fullmatch('[0-9a-f]{64}', runner_digest),
            'source-verifiable runner digest required')
    require(PHASE in ALLOWED_PHASES, 'unknown fixed maintenance phase')
    require(os.getuid() == os.geteuid() == 0, 'guest root required')
    require(Path('/sys/class/dmi/id/product_uuid').read_text().strip().lower() == EXPECTED_UUID,
            'dedicated clone UUID mismatch')
    info = WORK.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 0
            and stat.S_IMODE(info.st_mode) == 0o700, 'private guest work directory required')
    for filename in ('run.py', 'guard.py'):
        read_file(WORK / filename)
    sys.path.insert(0, str(WORK))
    import run as m8common
    secrets = m8common.guard(EXPECTED_UUID)
    descriptor = os.open(WORK / '.m81-maintenance.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    with os.fdopen(descriptor, 'rb') as lock:
        info = os.fstat(lock.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_uid == info.st_gid == 0
                and info.st_nlink == 1 and stat.S_IMODE(info.st_mode) == 0o600, 'unsafe maintenance serialization lock')
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        RUN = WORK / ('m81-maintenance-' + PHASE)
        RUN.mkdir(mode=0o700, exist_ok=False)
        # An old result/intent is never overwritten or silently retried. Review
        # root-only transaction evidence before preparing a deliberate new run.
        require(query(['systemctl', 'is-active', 'localpin.socket']).stdout.strip() == b'active',
                'activated socket required')
        require(query(['systemctl', 'is-active', 'localpin.service']).stdout.strip() == b'active',
                'live enrolled broker required')
        require(query(['/usr/libexec/localpin/localpin-account', 'check-policy']).returncode == 0,
                'reviewed KDE native policy required before maintenance')
        before = snapshot()
        private_write('before.json', before)
        private_write('intent.json', {'phase': PHASE, 'uuid': EXPECTED_UUID,
                      'boot_id': before['boot_id'], 'native_packages': before['native_packages'],
                      'runner_sha256': runner_digest})
        if PHASE == 'upgrade':
            command = ['dnf', 'upgrade', '--refresh', '-y']
            timeout = 1800
        elif PHASE == 'reinstall':
            command = ['dnf', 'reinstall', '-y', 'pam', 'authselect-libs']
            timeout = 900
        elif PHASE == 'sysusers':
            require(not any(row.split(':')[0] == SERVICE_ACCOUNT for row in Path('/etc/passwd').read_text().splitlines()),
                    'fresh unrelated service-account fixture required')
            command = ['systemd-sysusers', '--inline',
                       'u ' + SERVICE_ACCOUNT + ' - "LocalPIN M8.1 maintenance fixture" /var/lib/' + SERVICE_ACCOUNT + ' /usr/sbin/nologin']
            timeout = 60
        else:
            command = ['authselect', 'apply-changes']
            timeout = 60
        execution = maintenance_command(command, timeout)
        after = snapshot()
        private_write('after.json', after)
        preservation = compare(before, after)
        changed = sorted(set(before['all_packages']) ^ set(after['all_packages']))
        native_replacements = [path for path in before['native_files']
                               if before['native_files'][path] != after['native_files'][path]]
        result = {'phase': PHASE, 'scope': 'actual guarded Fedora44 KDE native maintenance',
                  'runner_sha256': runner_digest,
                  'execution': execution, 'preservation': preservation,
                  'native_packages_before': before['native_packages'],
                  'native_packages_after': after['native_packages'],
                  'package_identity_changes': len(changed),
                  'native_image_or_inode_replacements': native_replacements,
                  'raw_snapshots_guest_root_only': True,
                  'upgrade_transaction_proved': PHASE == 'upgrade' and bool(changed) and execution['returncode'] == 0,
                  'noop_is_not_upgrade_proof': PHASE == 'upgrade' and not changed,
                  'runtime_reinstallation_proved': PHASE == 'reinstall' and execution['returncode'] == 0
                      and '/usr/lib64/security/pam_unix.so' in native_replacements,
                  'passed': False}
        if PHASE == 'sysusers' and execution['returncode'] == 0:
            account = pwd.getpwnam(SERVICE_ACCOUNT)
            require(0 < account.pw_uid < 1000 and account.pw_shell == '/usr/sbin/nologin',
                    'systemd-sysusers did not create an unrelated system account')
            result['unrelated_system_account_created'] = True
        private_write('comparison.json', result)
        require(execution['returncode'] == 0 and not execution['timed_out'], 'native maintenance command failed')
        require(all(preservation.values()), 'native maintenance did not preserve exact managed state')
        require(query(['getenforce']).stdout.strip() == b'Enforcing', 'SELinux changed during maintenance')
        require(query(['/usr/libexec/localpin/localpin-account', 'check-policy']).returncode == 0,
                'native KDE policy unsupported after maintenance')
        value = m8common.status()
        require(value.get('availability') == 'available' and value.get('enrolled_backend') == 'tpm2',
                'existing enrolled account unavailable after maintenance')
        # Only after proving unchanged state do an actual broker authorization.
        # Its expected durable throttle update is captured separately and never
        # mistaken for a package-caused mutation of the before/after snapshot.
        verified = m8common.command(m8common.user_command('/usr/libexec/localpin/m8-client', 'verify'),
                                    data=m8common.framed(secrets[m8common.NAME]['pin']), timeout=20)
        require(verified.stdout.strip() == b'Granted', 'same enrolled PIN failed after maintenance')
        require(m8common.tally() == {'bytes': len(content(after['files'][str(m8common.TALLY)])),
                                   'sha256': after['files'][str(m8common.TALLY)]['sha256']},
                'post-maintenance PIN changed native password accounting')
        private_write('post-verification.json', snapshot())
        result['same_enrolled_pin_verified_after_preservation_check'] = True
        result['selinux_enforcing'] = True
        result['passed'] = True
        private_write('result.json', result)
        print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except BaseException:
        if RUN is not None and RUN.is_dir():
            try:
                private_write('failure.json', {'phase': PHASE, 'traceback': traceback.format_exc()})
            except BaseException:
                pass
        print(json.dumps({'phase': PHASE if PHASE in ALLOWED_PHASES else 'refused', 'passed': False,
                          'error': 'guarded native maintenance refused; inspect guest-root-only evidence'}))
        raise SystemExit(1) from None
