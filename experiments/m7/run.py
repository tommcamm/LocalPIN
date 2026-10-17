#!/usr/bin/env python3
"""Actual M7 adapter/production-authority tests, only in a disposable M6.1 clone.

This is a guarded experiment manager, not an installer or activation command.
The account authority revokes before every protected policy/account mutation.
No secret values are printed or exported.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import uuid

_spec = importlib.util.spec_from_file_location('localpin_m61_component', '/root/localpin-m61/run.py')
component = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(component)

WORK = Path('/root/localpin-m7')
MODULE = Path('/usr/lib64/security/pam_localpin.so')
KDE = Path('/etc/pam.d/kde')
BACKUP = WORK / 'backup'
STOCK_DIGEST = '7d91b3ad73a998e8b10f9edccd74ba04179a778c4a5e61d9176872f43c7bbac3'
INTEGRATED_DIGEST = 'ea0adc6291dccb0360f5d3565c5dad1f8b886d037f0bcadbbfbf70625383375d'
command, require = component.command, component.require


def user_environment():
    # runuser invokes its own PAM account/session policy. Under with-faillock,
    # even an observation could therefore alter the tally being measured.
    # setpriv changes only process identity; no PAM service is entered here.
    return ['/usr/bin/setpriv', '--reuid=' + str(component.UID),
            '--regid=' + str(component.UID), '--clear-groups', '--', '/usr/bin/env',
            f'XDG_RUNTIME_DIR=/run/user/{component.UID}',
            f'DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/{component.UID}/bus']


def user_command(operation):
    return user_environment() + [
        '/usr/bin/systemd-run', '--user', '--quiet', '--collect', '--wait', '--pipe',
        '--unit=localpin-m7-' + uuid.uuid4().hex, component.PROBE, operation]


# This separately imported M6.1 module instance belongs only to the M7 fixture.
# Its status/enrollment/client helpers resolve this no-PAM launcher dynamically;
# the M6.1 default and all production executables remain unchanged.
component.user_command = user_command


def guard():
    require(os.getuid() == os.geteuid() == 0, 'guest root required')
    marker = Path('/run/localpin-m7-guard')
    info = marker.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022,
            'unsafe M7 clone guard')
    require(marker.read_text().strip().lower() ==
            Path('/sys/class/dmi/id/product_uuid').read_text().strip().lower(), 'M7 clone UUID mismatch')
    require(command(['getenforce']).stdout.strip() == b'Enforcing', 'SELinux must remain enforcing')
    if Path('/dev/tpm0').exists() or Path('/dev/tpmrm0').exists():
        # The host console independently refuses physical/passthrough TPMs and
        # requires the exact private libvirt emulator XML. This root-private,
        # UUID-bound marker is the guest-side opt-in, never a production knob.
        component.emulated_tpm_guard()
        return component.guard(allow_emulated_tpm=True)
    return component.guard()


def sync_write(path, data, mode):
    with path.open('xb') as stream:
        os.fchmod(stream.fileno(), mode)
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    fd = os.open(path.parent, os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def sync_directory(path):
    fd = os.open(path, os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def install():
    guard()
    require(not BACKUP.exists() and not MODULE.exists(), 'existing experiment state refused')
    require(digest(KDE) == STOCK_DIGEST, 'unknown KDE graph')
    sample = WORK / 'kde-localpin.review-required'
    require(digest(sample) == INTEGRATED_DIGEST, 'unknown integrated graph')
    BACKUP.mkdir(mode=0o700)
    sync_write(BACKUP / 'kde', KDE.read_bytes(), 0o600)
    original_mode = stat.S_IMODE(KDE.stat().st_mode)
    sync_write(BACKUP / 'manifest.json', json.dumps({
        'original_mode': original_mode,
        'module_sha256': digest(WORK / 'liblocalpin_pam.so'),
        'original_sha256': STOCK_DIGEST,
        'integrated_sha256': INTEGRATED_DIGEST,
    }).encode(), 0o600)
    component.stop()
    command([component.ACCOUNT, 'begin-mutation'])
    sync_write(MODULE, (WORK / 'liblocalpin_pam.so').read_bytes(), 0o755)
    command(['restorecon', str(MODULE)])
    probe = Path('/usr/libexec/localpin/m7-pam-probe')
    sync_write(probe, (WORK / 'pam-probe').read_bytes(), 0o755)
    command(['restorecon', str(probe)])
    # The clone is offline for authentication edits; backup is already durable.
    KDE.write_bytes(sample.read_bytes())
    KDE.chmod(original_mode)
    command(['restorecon', str(KDE)])
    with KDE.open('rb') as stream:
        os.fsync(stream.fileno())
    sync_directory(KDE.parent)
    component.reseal()
    require(component.worker() == 0, 'integrated production eligibility unavailable')
    enroll()
    return {'original_policy_backup_durable': True, 'exact_integrated_graph': True,
            'fresh_incarnations': True, 'production_eligibility': True,
            'module_sha256': digest(MODULE)}


def enroll():
    secrets = guard()[component.NAME]
    require(component.status()['availability'] == 'disabled', 'fresh disabled baseline required')
    result = component.client('enroll', secrets['password'], secrets['pin'])
    require(b'Enrolled(Software)' in result.stdout, 'production password enrollment failed')
    require(component.client('verify', secrets['pin']).stdout.strip() == b'Granted', 'real PIN baseline failed')


def reset():
    guard()
    component.stop()
    command([component.ACCOUNT, 'begin-mutation'])
    component.prune_test_quarantines()
    component.reseal()
    enroll()


def bus(method):
    return command(user_environment() +
                   ['/usr/bin/busctl', '--user', 'call', 'org.freedesktop.ScreenSaver',
                    '/ScreenSaver', 'org.freedesktop.ScreenSaver', method]).stdout.strip()


def locked():
    return bus('GetActive') == b'b true'


def locker_pid():
    result = command(['pgrep', '-u', str(component.UID), '-f', '^/usr/libexec/kscreenlocker_greet'], check=False)
    return [int(value) for value in result.stdout.split()]


def tally():
    path = Path('/run/faillock') / component.NAME
    data = path.read_bytes()
    require(len(data) % 64 == 0, 'noncanonical native tally')
    return {'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()}


def pam(*values):
    unit = 'localpin-m7-pam-' + uuid.uuid4().hex
    args = component.user_command('status')
    # Retain actual own-UID user-manager routing, replace only command executable.
    args = args[:-2] + ['/usr/libexec/localpin/m7-pam-probe']
    args = [('--unit=' + unit if value.startswith('--unit=') else value) for value in args]
    result = command(args, data=b''.join(component.frame(value) for value in values), timeout=70)
    return [json.loads(line) for line in result.stdout.splitlines()]


def repeated():
    secrets = guard()[component.NAME]
    wrong = 'not-the-disposable-password'
    before = tally()
    values = [secrets['pin'], wrong, secrets['password'], '', '１２３４５６', secrets['password']]
    rows = pam(*values)
    expected = [True, False, True, False, False, True]
    require(len(rows) == len(expected), 'incomplete repeated-handle evidence')
    require(all((row['auth'] == 0) == good and row['prompts'] == 1
                and (not good or row['setcred'] == 0) for row, good in zip(rows, expected)),
            'reused real KDE PAM handle failed')
    return {'same_handle_calls': len(rows), 'results': rows,
            'fresh_password_after_pin': True, 'empty_unicode_denied': True,
            'before_tally': before, 'after_tally': tally()}


def restore():
    guard()
    require(digest(KDE) == INTEGRATED_DIGEST, 'changed integrated graph; manual recovery required')
    manifest = json.loads((BACKUP / 'manifest.json').read_text())
    require(digest(MODULE) == manifest['module_sha256'], 'changed module; manual recovery required')
    require(digest(BACKUP / 'kde') == STOCK_DIGEST, 'changed backup')
    component.stop()
    command([component.ACCOUNT, 'begin-mutation'])
    KDE.write_bytes((BACKUP / 'kde').read_bytes())
    KDE.chmod(manifest['original_mode'])
    command(['restorecon', str(KDE)])
    with KDE.open('rb') as stream:
        os.fsync(stream.fileno())
    sync_directory(KDE.parent)
    MODULE.unlink()
    sync_directory(MODULE.parent)
    require(digest(KDE) == STOCK_DIGEST, 'original graph not restored')
    return {'original_policy_restored': True, 'module_removed': True, 'accounts_revoked': True}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--phase', choices=['install', 'repeated', 'reset', 'restore'], required=True)
    parser.add_argument('--disposable-vm-confirmed', action='store_true', required=True)
    args = parser.parse_args()
    guard()
    result = globals()[args.phase]()
    require(command(['getenforce']).stdout.strip() == b'Enforcing', 'SELinux changed')
    evidence_path = WORK / 'evidence.json'
    evidence = json.loads(evidence_path.read_text()) if evidence_path.exists() else {}
    evidence[args.phase] = result
    evidence_path.write_text(json.dumps(evidence, indent=2) + '\n')
    evidence_path.chmod(0o600)
    print(json.dumps({args.phase: result, 'selinux': 'Enforcing'}, indent=2))


if __name__ == '__main__':
    main()
