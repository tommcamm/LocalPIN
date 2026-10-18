#!/usr/bin/env python3
"""Guarded production-manager lifecycle evidence; never run on the host.

Every mutation is performed in the explicit Fedora clone on dedicated accounts.
The root runner exports booleans and sanitized outcomes, never hashes or secrets.
No lifecycle or eligibility authority is replaced with a synthetic authority.
"""
import argparse
import errno
import fcntl
import hashlib
import json
import mmap
import os
from pathlib import Path
import selectors
import shutil
import stat
import struct
import subprocess
import time

from run import ACCOUNT, NAME, OTHER, PROBE, UID, WORK
from run import client, command, frame, guard, require, start, status, stop, user_command, worker

REGISTRY = Path('/var/lib/localpin-accounts/registry')
STORAGE = Path('/var/lib/localpin')
INPUTS = [Path('/etc') / p for p in ['passwd', 'shadow', 'group', 'gshadow', 'environment',
          'pam.d/kde', 'pam.d/localpin-enroll', 'pam.d/localpin-eligibility',
          'authselect/password-auth', 'authselect/postlogin', 'authselect/nsswitch.conf',
          'security/faillock.conf', 'security/pam_env.conf']]


def incarnation(uid=UID):
    """Decode only the public durable account identity from the production record."""
    data = REGISTRY.read_bytes()
    require(data[:8] == b'LPACCT02', 'registry magic')
    snapshots = struct.unpack_from('>H', data, 8)[0]
    offset = 10 + snapshots * 84
    require(offset + 2 <= len(data), 'registry snapshots bound')
    count = struct.unpack_from('>H', data, offset)[0]
    require(count <= 128 and len(data) == offset + 2 + count * 20, 'registry account bound')
    for n in range(count):
        entry = offset + 2 + n * 20
        if struct.unpack_from('>I', data, entry)[0] == uid:
            return data[entry + 4:entry + 20]
    return None


def frozen_digest():
    return {str(path): hashlib.sha256(path.read_bytes()).digest() for path in INPUTS}


def durable_revoke():
    command([ACCOUNT, 'begin-mutation'])
    require(incarnation() is None, 'revocation was not durable before mutation')


def housekeeping():
    """Explicit offline clone administration, only after durable all-account revoke."""
    require(incarnation() is None, 'quarantine cleanup requires revoked registry')
    for uid in [UID, OTHER]:
        retired = STORAGE / 'retired' / str(uid)
        if not retired.exists():
            continue
        info = retired.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not retired.is_symlink(), 'unsafe retired root')
        entries = list(retired.iterdir())
        if len(entries) >= 8:
            for entry in entries:
                require(len(entry.name) == 32 and all(c in '0123456789abcdef' for c in entry.name), 'unexpected retired name')
                require(entry.is_dir() and not entry.is_symlink() and entry.stat().st_uid == 0, 'unsafe retired entry')
                shutil.rmtree(entry)
            fd = os.open(retired, os.O_DIRECTORY | os.O_RDONLY)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)


def fresh(secrets, *, enroll=False):
    stop()
    durable_revoke()
    housekeeping()
    command([ACCOUNT, 'seal', '--uid', str(UID), '--uid', str(OTHER)])
    require(incarnation() is not None, 'fresh incarnation absent')
    start()
    require(status()['availability'] == 'disabled', 'fresh provisioning must be disabled')
    if enroll:
        require(b'Enrolled(Software)' in client('enroll', secrets[NAME]['password'], secrets[NAME]['pin']).stdout,
                'production enrollment failed')
        require(client('verify', secrets[NAME]['pin']).stdout.strip() == b'Granted', 'baseline PIN rejected')


def deny(operation, *inputs):
    result = client(operation, *inputs, check=False)
    require(b'Granted' not in result.stdout and b'Enrolled(' not in result.stdout,
            'unavailable operation gained authority')
    return {'denied': True, 'exit_nonzero': result.returncode != 0}


def enrollment_denied_without_repair(secrets):
    before = tree_digest()
    result = deny('enroll', secrets[NAME]['password'], secrets[NAME]['pin'])
    require(tree_digest() == before, 'own enrollment repaired or changed lifecycle/state')
    return result


def tree_digest():
    """Protected state observation; returned values are never included in evidence."""
    result = {}
    for root in [Path('/var/lib/localpin-accounts'), STORAGE]:
        for path in sorted(root.rglob('*')):
            info = path.lstat()
            require(not stat.S_ISLNK(info.st_mode), 'unexpected state symlink')
            result[str(path)] = (info.st_mode, info.st_uid, info.st_gid, info.st_ino,
                                 hashlib.sha256(path.read_bytes()).digest() if path.is_file() else None)
    return result


def wait_ready(process, timeout=15):
    watcher = selectors.DefaultSelector()
    watcher.register(process.stdout, selectors.EVENT_READ)
    try:
        require(watcher.select(timeout), 'production client readiness deadline')
        require(process.stdout.readline().strip() == b'ready', 'production client did not reach retained transaction')
    finally:
        watcher.close()


def finish(process, data=b''):
    try:
        out, err = process.communicate(data, timeout=20)
        return process.returncode, out, err
    except subprocess.TimeoutExpired:
        process.kill()
        process.communicate(timeout=5)
        raise RuntimeError('client cleanup deadline')


def desktop_ready():
    command(['systemctl', 'restart', 'plasmalogin.service'], timeout=35)
    end = time.monotonic() + 25
    while time.monotonic() < end:
        result = command(['loginctl', 'list-sessions', '--no-legend'])
        sessions = [line.split() for line in result.stdout.splitlines()]
        if any(len(parts) >= 6 and parts[1:4] == [str(UID).encode(), NAME.encode(), b'seat0']
               and parts[5] == b'user' for parts in sessions) and Path(f'/run/user/{UID}/bus').exists():
            return
        time.sleep(.25)
    raise RuntimeError('dedicated KDE session did not restart')


def end_desktop():
    command(['systemctl', 'stop', 'plasmalogin.service'], timeout=35)
    command(['loginctl', 'terminate-user', NAME], check=False)
    end = time.monotonic() + 12
    while time.monotonic() < end:
        if command(['pgrep', '-u', str(UID)], check=False).returncode == 1:
            return
        time.sleep(.1)
    raise RuntimeError('dedicated desktop account processes did not exit')


def bypass(secrets):
    fresh(secrets, enroll=True)
    before = frozen_digest()
    cases = [
        ('useradd', ['useradd', '-u', '21064', '-M', 'lp61bypass'], None),
        ('usermod', ['usermod', '-s', '/bin/sh', NAME], None),
        ('userdel', ['userdel', 'lp61other'], None),
        ('chpasswd', ['chpasswd'], (NAME + ':' + secrets[NAME]['password'] + '\n').encode()),
        ('chage', ['chage', '-d', '0', NAME], None),
    ]
    outcomes = {}
    for name, args, data in cases:
        result = command(args, data=data, check=False, timeout=22)
        require(result.returncode != 0 and frozen_digest() == before, name + ' bypass changed protected inputs')
        outcomes[name] = {'rejected': True, 'account_policy_unchanged': True}
    # AccountsService is the real privileged GUI backend, called over the system bus.
    lookup = command(['busctl', 'call', 'org.freedesktop.Accounts', '/org/freedesktop/Accounts',
                      'org.freedesktop.Accounts', 'FindUserById', 'x', str(UID)], check=False)
    require(lookup.returncode == 0, 'AccountsService must exist for GUI bypass coverage')
    object_path = lookup.stdout.decode().split('"')[1]
    result = command(['busctl', 'call', 'org.freedesktop.Accounts', object_path,
                      'org.freedesktop.Accounts.User', 'SetShell', 's', '/bin/sh'], check=False)
    require(result.returncode != 0 and frozen_digest() == before, 'AccountsService GUI bypass changed shell')
    outcomes['accountsservice_gui_backend'] = {'rejected': True, 'account_policy_unchanged': True}
    require(client('verify', secrets[NAME]['pin']).stdout.strip() == b'Granted', 'bypass disturbed healthy enrollment')
    # A descriptor opened before seal cannot write after FS_IMMUTABLE_FL is set.
    stop()
    durable_revoke()
    unchanged_byte = Path('/etc/passwd').read_bytes()[:1]
    descriptor = os.open('/etc/passwd', os.O_WRONLY | os.O_CLOEXEC)
    seal_refused = False
    try:
        result = command([ACCOUNT, 'seal', '--uid', str(UID), '--uid', str(OTHER)], check=False)
        if result.returncode != 0:
            require(incarnation() is None, 'failed seal with open writer must remain revoked')
            seal_refused = True
        else:
            try:
                # A forbidden successful write is detectable without damaging
                # the clone's recovery account or exporting account contents.
                os.pwrite(descriptor, unchanged_byte, 0)
            except OSError as error:
                require(error.errno in (errno.EPERM, errno.EACCES), 'unexpected immutable descriptor error')
            else:
                raise RuntimeError('pre-open writable descriptor bypassed immutable seal')
    finally:
        os.close(descriptor)
    if seal_refused:
        command([ACCOUNT, 'seal', '--uid', str(UID), '--uid', str(OTHER)])
    start()
    require(frozen_digest() == before, 'pre-open descriptor changed account inputs')
    outcomes['preopened_writable_descriptor'] = {'safe_seal_refusal': seal_refused,
                                                'write_rejected_after_seal': not seal_refused}
    # A shared writable mapping retains its writer even after closing the FD.
    stop()
    durable_revoke()
    descriptor = os.open('/etc/passwd', os.O_RDWR | os.O_CLOEXEC)
    mapping = mmap.mmap(descriptor, 0, access=mmap.ACCESS_WRITE)
    os.close(descriptor)
    try:
        result = command([ACCOUNT, 'seal', '--uid', str(UID), '--uid', str(OTHER)], check=False)
        require(result.returncode != 0 and incarnation() is None,
                'seal accepted preexisting shared writable mapping after FD close')
    finally:
        mapping.close()
    command([ACCOUNT, 'seal', '--uid', str(UID), '--uid', str(OTHER)])
    start()
    require(frozen_digest() == before, 'mapping guard changed account inputs')
    outcomes['preexisting_shared_writable_mapping'] = {'seal_refused_after_fd_close': True,
                                                      'remained_revoked': True}
    # The native shadow-utils POSIX lock refuses a seal while administration owns it.
    stop()
    durable_revoke()
    descriptor = os.open('/etc/.pwd.lock', os.O_RDWR | os.O_CLOEXEC)
    try:
        fcntl.lockf(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        result = command([ACCOUNT, 'seal', '--uid', str(UID), '--uid', str(OTHER)], check=False)
        require(result.returncode != 0 and incarnation() is None, 'seal crossed active password database mutation')
    finally:
        os.close(descriptor)
    command([ACCOUNT, 'seal', '--uid', str(UID), '--uid', str(OTHER)])
    start()
    outcomes['in_progress_shadow_utils_lock'] = {'seal_rejected': True, 'remained_revoked': True}
    return outcomes


def leases(secrets):
    fresh(secrets)
    process = subprocess.Popen(user_command('hold-enrollment'), stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        process.stdin.write(frame(secrets[NAME]['password']) + frame(secrets[NAME]['pin']))
        process.stdin.flush()
        wait_ready(process)
        identity = incarnation()
        result = command([ACCOUNT, 'begin-mutation'], check=False)
        require(result.returncode != 0 and b'Busy' in result.stderr and incarnation() == identity,
                'revocation crossed retained production enrollment grant')
        code, output, _ = finish(process, frame(b''))
        require(code == 0 and b'Enrolled(Software)' in output, 'held enrollment failed to complete')
    finally:
        if process.poll() is None:
            process.kill()
            process.communicate(timeout=5)
    # A completed BeginVerify challenge must lose all authority across revocation.
    process = subprocess.Popen(user_command('hold-challenge'), stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        wait_ready(process)
        durable_revoke()
        code, output, _ = finish(process, frame(secrets[NAME]['pin']))
        require(b'Granted' not in output, 'stale pre-revocation challenge verified successfully')
    finally:
        if process.poll() is None:
            process.kill()
            process.communicate(timeout=5)
    fresh(secrets)
    return {'enrollment_grant_serializes_revocation': True,
            'stale_challenge_crossing_revocation_denied': True,
            'fresh_recovery_disabled': True}


def mutations(secrets):
    fresh(secrets, enroll=True)
    original = incarnation()
    home = Path('/home/' + NAME)
    inode = home.stat().st_ino
    durable_revoke()
    require(status()['availability'] == 'unavailable', 'revoked account still available')
    stop()
    end_desktop()
    command(['userdel', NAME])
    command(['useradd', '-u', str(UID), '-M', '-d', str(home), '-s', '/bin/bash', NAME])
    command(['chpasswd'], data=(NAME + ':' + secrets[NAME]['password'] + '\n').encode())
    require(home.stat().st_ino == inode, 'identical recreation must preserve same home inode')
    command([ACCOUNT, 'seal', '--uid', str(UID), '--uid', str(OTHER)])
    require(incarnation() != original, 'identical recreation inherited incarnation')
    start()
    desktop_ready()
    require(status()['availability'] == 'disabled', 'identical recreation inherited enrollment')
    deny('verify', secrets[NAME]['pin'])
    require(b'Enrolled(Software)' in client('enroll', secrets[NAME]['password'], secrets[NAME]['pin']).stdout,
            'fresh recreated account could not enroll')
    recreated = incarnation()
    durable_revoke()
    stop()
    end_desktop()
    command(['usermod', '-l', 'lp61renamed', NAME])
    command(['usermod', '-l', NAME, 'lp61renamed'])
    command(['usermod', '-u', '21063', NAME])
    command(['usermod', '-u', str(UID), NAME])
    command([ACCOUNT, 'seal', '--uid', str(UID), '--uid', str(OTHER)])
    require(incarnation() != recreated, 'rename/UID restore inherited incarnation')
    start()
    desktop_ready()
    require(status()['availability'] == 'disabled', 'rename/UID restore inherited enrollment')
    deny('verify', secrets[NAME]['pin'])
    return {'identical_uid_name_home_inode_recreation': True, 'new_incarnation': True,
            'old_pin_denied': True, 'fresh_password_enrollment': True,
            'rename_restore_fresh_incarnation': True, 'uid_change_restore_fresh_incarnation': True}


def state(secrets):
    outcomes = {}
    for name, path, mode in [
        ('missing_registry', REGISTRY, 'missing'),
        ('corrupt_registry', REGISTRY, 'corrupt'),
        ('missing_registry_lock', REGISTRY.parent / 'lock', 'missing'),
        ('unsafe_registry_lock', REGISTRY.parent / 'lock', 'unsafe'),
        ('corrupt_storage_active', STORAGE / 'users' / str(UID) / 'active', 'corrupt'),
        ('missing_storage_active', STORAGE / 'users' / str(UID) / 'active', 'missing'),
        ('missing_storage_lock', STORAGE / 'users' / str(UID) / 'lock', 'missing'),
        ('unsafe_storage_lock', STORAGE / 'users' / str(UID) / 'lock', 'unsafe'),
    ]:
        fresh(secrets)
        backup = path.read_bytes()
        metadata = path.stat()
        if mode == 'missing':
            path.unlink()
        elif mode == 'unsafe':
            path.chmod(0o644)
        else:
            path.write_bytes(b'corrupt-m61-fixture')
        try:
            require(status()['availability'] == 'unavailable', name + ' did not fail closed')
            outcomes[name] = enrollment_denied_without_repair(secrets)
            stop()
            start()
            outcomes[name]['broker_restart_still_unavailable'] = status()['availability'] == 'unavailable'
            require(outcomes[name]['broker_restart_still_unavailable'], name + ' restart fabricated continuity')
            enrollment_denied_without_repair(secrets)
        finally:
            stop()
            # Explicit root restoration only makes the following recovery possible.
            path.write_bytes(backup)
            path.chmod(stat.S_IMODE(metadata.st_mode))
            os.chown(path, metadata.st_uid, metadata.st_gid)
        fresh(secrets)
        require(status()['availability'] == 'disabled', name + ' privileged recovery failed')
        outcomes[name]['privileged_fresh_disabled_recovery'] = True
    return outcomes


def crashes(secrets):
    source = WORK / 'src' / 'experiments' / 'm61' / 'fault.c'
    tracer = WORK / 'fault'
    command(['cc', '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror', str(source), '-o', str(tracer)])
    matrix = [
        ('revocation_before_file_sync', 'begin-mutation', 'registry-temp', 'before', 1),
        ('revocation_after_file_sync', 'begin-mutation', 'registry-temp', 'after', 1),
        ('revocation_after_rename', 'begin-mutation', 'registry-rename', 'after', 1),
        ('revocation_after_directory_sync', 'begin-mutation', 'registry-dir', 'after', 1),
        ('thaw_after_first_flag', 'begin-mutation', 'freeze', 'after', 1),
        ('seal_after_first_freeze', 'seal', 'freeze', 'after', 1),
        ('seal_before_state_sync', 'seal', 'storage-temp', 'before', 1),
        ('seal_after_state_sync', 'seal', 'storage-temp', 'after', 1),
        ('seal_before_active_registry_sync', 'seal', 'registry-temp', 'before', 2),
        ('seal_after_active_registry_rename', 'seal', 'registry-rename', 'after', 2),
        ('seal_after_active_registry_directory_sync', 'seal', 'registry-dir', 'after', 2),
        ('tally_after_anonymous_create', 'seal', 'tally-create', 'after', 1),
        ('tally_after_owner_assignment', 'seal', 'tally-owned', 'after', 1),
        ('tally_after_canonical_mode', 'seal', 'tally-canonical', 'after', 1),
        ('tally_after_file_sync', 'seal', 'tally-file-sync', 'after', 1),
        ('tally_after_publication', 'seal', 'tally-link', 'after', 1),
        ('tally_after_directory_sync', 'seal', 'tally-dir-sync', 'after', 1),
    ]
    outcomes = {}
    for name, operation, selector, side, nth in matrix:
        fresh(secrets, enroll=True)
        old = incarnation()
        stop()
        if operation == 'seal':
            durable_revoke()
            housekeeping()
        if selector.startswith('tally-'):
            tally = Path('/run/faillock/lp61other')
            info = tally.lstat()
            require(info.st_uid == OTHER and info.st_gid == 0 and stat.S_IMODE(info.st_mode) == 0o660
                    and tally.read_bytes() == b'', 'tally crash tests require an empty dedicated unused tally')
            tally.unlink()
        result = command([str(tracer), operation, selector, side, str(nth)], timeout=30)
        fault = json.loads(result.stdout)
        require(fault['triggered'] is True, 'crash boundary did not execute')
        current = incarnation()
        if selector.startswith('tally-') and tally.exists():
            info = tally.lstat()
            require(info.st_uid == OTHER and info.st_gid == 0 and stat.S_IMODE(info.st_mode) == 0o660
                    and info.st_nlink == 1 and tally.read_bytes() == b'', 'crash published noncanonical tally')
        # Before revocation's atomic rename the old frozen incarnation may survive.
        old_allowed = operation == 'begin-mutation' and selector == 'registry-temp'
        require(old_allowed or current != old, 'old authority survived a completed revocation boundary')
        start()
        observed = status()['availability']
        if current is None:
            require(observed == 'unavailable', 'crashed revoked manager fabricated authority')
            enrollment_denied_without_repair(secrets)
        elif current != old:
            require(observed == 'disabled', 'partially provisioned state became enabled')
            deny('verify', secrets[NAME]['pin'])
        else:
            require(observed == 'available', 'pre-revocation crash changed frozen authority')
        fresh(secrets)
        require(incarnation() != old and status()['availability'] == 'disabled', 'crash recovery reused old authority')
        outcomes[name] = {'kernel_boundary_triggered': True, 'postcrash': observed,
                          'fresh_disabled_recovery': True}
        if selector.startswith('tally-'):
            outcomes[name]['tally_missing_or_fully_canonical'] = True
    return outcomes


def reboot_prepare(secrets):
    fresh(secrets, enroll=True)
    durable_revoke()
    # Guard and services must survive a reboot for the follow-up evidence phase.
    stop()
    unit = Path('/etc/systemd/system/localpin-m61-guard.service')
    unit.write_text('''[Unit]\nDescription=Disposable M6.1 UUID guard\nBefore=localpin-m61.service\n[Service]\nType=oneshot\nExecStart=/usr/bin/cp /root/localpin-m61/clone-uuid /run/localpin-m61-guard\nRemainAfterExit=yes\n[Install]\nWantedBy=multi-user.target\n''')
    (WORK / 'clone-uuid').write_text(Path('/sys/class/dmi/id/product_uuid').read_text())
    command(['systemctl', 'daemon-reload'])
    command(['systemctl', 'enable', 'localpin-m61.socket', 'localpin-m61-guard.service'])
    (WORK / 'reboot-state.json').write_text(json.dumps({'boot_id': Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
                                                      'expected': 'unavailable'}))
    start()
    require(status()['availability'] == 'unavailable', 'pre-reboot revoked state unavailable')
    return {'revoked_before_reboot': True, 'reboot_required': True}


def reboot_verify(secrets):
    previous = json.loads((WORK / 'reboot-state.json').read_text())
    require(previous['boot_id'] != Path('/proc/sys/kernel/random/boot_id').read_text().strip(), 'actual reboot required')
    require(incarnation() is None, 'reboot reactivated revoked incarnation')
    require(status()['availability'] == 'unavailable', 'revocation did not survive reboot')
    enrollment_denied_without_repair(secrets)
    fresh(secrets)
    require(status()['availability'] == 'disabled', 'postreboot privileged recovery failed')
    return {'actual_kernel_boot_id_changed': True, 'revocation_survived_reboot': True,
            'own_enrollment_cannot_repair': True, 'privileged_fresh_disabled_recovery': True}


def reboot_active_prepare(secrets):
    require(Path('/etc/systemd/system/localpin-m61-guard.service').exists(), 'run reboot-prepare setup first')
    fresh(secrets, enroll=True)
    (WORK / 'reboot-active-state.json').write_text(json.dumps({
        'boot_id': Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
        'incarnation': incarnation().hex()}))
    return {'active_credential_before_reboot': True, 'reboot_required': True}


def reboot_active_verify(secrets):
    previous = json.loads((WORK / 'reboot-active-state.json').read_text())
    require(previous['boot_id'] != Path('/proc/sys/kernel/random/boot_id').read_text().strip(), 'actual second reboot required')
    previous_identity = bytes.fromhex(previous['incarnation'])
    require(incarnation() == previous_identity, 'reboot lost durable active account incarnation')
    require(not Path('/run/faillock/' + NAME).exists(), 'active reboot case requires actual volatile tally loss')
    require(status()['availability'] == 'unavailable', 'missing postboot policy tally was treated as eligible')
    deny('verify', secrets[NAME]['pin'])
    enrollment_denied_without_repair(secrets)
    require(not Path('/run/faillock/' + NAME).exists(), 'own enrollment fabricated missing policy tally')
    fresh(secrets)
    require(incarnation() != previous_identity and status()['availability'] == 'disabled',
            'postboot privileged recovery reused active incarnation')
    return {'actual_second_kernel_boot_id_changed': True, 'active_incarnation_durable': True,
            'missing_volatile_tally_unavailable': True, 'old_pin_denied': True,
            'own_enrollment_cannot_repair': True, 'privileged_recovery_fresh_disabled_incarnation': True}


def main():
    parser = argparse.ArgumentParser()
    phases = {'bypass': bypass, 'leases': leases, 'mutations': mutations, 'state': state,
              'crashes': crashes, 'reboot-prepare': reboot_prepare, 'reboot-verify': reboot_verify,
              'reboot-active-prepare': reboot_active_prepare, 'reboot-active-verify': reboot_active_verify}
    parser.add_argument('--phase', choices=phases, required=True)
    parser.add_argument('--disposable-vm-confirmed', action='store_true', required=True)
    args = parser.parse_args()
    secrets = guard()
    result = phases[args.phase](secrets)
    require(command(['getenforce']).stdout.strip() == b'Enforcing', 'SELinux changed')
    path = WORK / 'evidence.json'
    evidence = json.loads(path.read_text()) if path.exists() else {}
    evidence['lifecycle-' + args.phase] = result
    path.write_text(json.dumps(evidence, indent=2) + '\n')
    path.chmod(0o600)
    print(json.dumps({'lifecycle-' + args.phase: result, 'selinux': 'Enforcing'}, indent=2))


if __name__ == '__main__':
    main()
