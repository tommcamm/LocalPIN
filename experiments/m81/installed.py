#!/usr/bin/python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Fixed-path installed M8.1 RPM/reboot proof inside the guarded emulator clone.

Stage beside the root-owned M8 common helpers in /root/localpin-m8. The host
must independently verify live libvirt topology before every execution. Private
snapshots and native logs remain in that directory; stdout contains booleans,
package versions and this runner's source hash. This runner never reboots.
"""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import traceback
import uuid

WORK = Path('/root/localpin-m8')
REGISTRY = Path('/var/lib/localpin-accounts/registry')
MANIFEST = Path('/var/lib/localpin-integration/control/manifest.json')
POLICIES = tuple(Path('/etc/pam.d') / name for name in (
    'kde', 'kde-fingerprint', 'localpin-enroll', 'localpin-eligibility',
    'localpin-kde-password', 'localpin-kde-fingerprint'))
PHASES = ('package-upgrade', 'downgrade-refusal', 'reboot-prepare', 'reboot-verify',
          'suspend', 'suspended-reboot-verify', 'resume', 'erase')


def require(value, message):
    if not value:
        raise RuntimeError(message)


def file_digest(path, *, private=False, bound=65536):
    m.owned_file(path, private=private, owner=0, max_size=bound)
    return hashlib.sha256(path.read_bytes()).hexdigest()


def snapshot():
    m.owned_file(REGISTRY, private=True, owner=0, max_size=16384)
    data = REGISTRY.read_bytes()
    require(data[:8] == b'LPACCT03' and 10 < len(data) <= 16384, 'active marker registry required')
    root = Path('/var/lib/localpin/users') / str(m.UID)
    for path in (root / 'active', *root.glob('generation-*/credential')):
        m.owned_file(path, private=True, owner=0)
    tally = m.TALLY.lstat()
    require(stat.S_ISREG(tally.st_mode) and tally.st_uid == m.UID and tally.st_gid == 0
            and stat.S_IMODE(tally.st_mode) == 0o660 and tally.st_nlink == 1
            and tally.st_size <= 65536 and tally.st_size % 64 == 0, 'unsafe canonical native tally')
    native = {}
    for path in (Path('/usr/lib64/libpam.so.0'), *[Path('/usr/lib64/security') / ('pam_' + name + '.so')
                 for name in ('unix', 'faillock', 'env', 'nologin')]):
        target = path.resolve(strict=True)
        require(str(target).startswith('/usr/'), 'native library target escaped usr')
        native[str(path)] = file_digest(target, bound=16 * 1024 * 1024)
    return {'boot': m.boot_id(), 'registry': file_digest(REGISTRY, private=True),
            'records': m.credential_records(), 'throttle': m.throttle(), 'tally': m.tally(),
            'policies': {str(path): file_digest(path) for path in POLICIES},
            'native_fingerprints': native}


def same(before, after):
    for key in ('registry', 'records', 'throttle', 'tally', 'policies'):
        require(before[key] == after[key], 'account, credential, throttle, tally or PAM bytes changed')


def active():
    require(json.loads(m.admin('status').stdout)['gate'] == 'active', 'active integration gate required')
    manifest = m.private_json(MANIFEST)
    tests = manifest.get('tests', {})
    require(manifest.get('schema') == 2 and manifest.get('phase') == 'active'
            and tests.get('kind') == 'administrator-attestation'
            and all(tests.get(key) is True for key in ('pin', 'password', 'console_recovery')),
            'previously tested active integration required')
    observed = m.status()
    require(observed.get('availability') == 'available' and observed.get('enrolled_backend') == 'tpm2',
            'same available TPM enrollment required')
    require(m.command(['systemctl', 'is-enabled', 'localpin.socket']).stdout.strip() == b'enabled',
            'persistent socket boot opt-in required')


def native(args, label):
    result = m.command(args, check=False, timeout=180)
    m.sync_json(WORK / ('m81-installed-' + label + '.log.json'),
                {'returncode': result.returncode, 'stdout': result.stdout.decode(errors='replace'),
                 'stderr': result.stderr.decode(errors='replace')})
    return result.returncode


def prove_pin(secrets, before):
    rows = m.pam(secrets[m.NAME]['pin'])
    require(len(rows) == 1 and rows[0]['auth'] == rows[0]['setcred'] == 0 and rows[0]['prompts'] == 1,
            'existing PIN failed through actual KDE PAM')
    require(m.credential_records() == before['records'] and m.tally() == before['tally']
            and file_digest(REGISTRY, private=True) == before['registry'],
            'PIN verification replaced enrollment or native accounting')


def perform(phase, secrets):
    result = {}
    checkpoint = WORK / ('m81-installed-' + ('suspended' if phase in (
        'suspend', 'suspended-reboot-verify', 'resume') else 'reboot') + '.checkpoint.json')
    if phase in ('reboot-verify', 'suspended-reboot-verify', 'resume'):
        before = m.private_json(checkpoint)
        after = snapshot()
        m.sync_json(WORK / ('m81-installed-' + phase + '.before.json'), after)
        same(before, after)
        changed_boot = m.boot_id() != before['boot']
        if phase != 'resume':
            require(changed_boot, 'actual host-controlled reboot required')
        if phase == 'reboot-verify':
            active()
            prove_pin(secrets, before)
        else:
            manifest = m.private_json(MANIFEST)
            require(manifest['phase'] == 'suspended' and manifest.get('resume_phase') == 'active'
                    and json.loads(m.admin('status').stdout)['gate'] == 'disabled',
                    'interrupted upgrade must retain its closed gate and active resume intent')
            if phase == 'resume':
                m.admin('package-resume')
                after = snapshot()
                m.sync_json(WORK / ('m81-installed-' + phase + '.after.json'), after)
                same(before, after)
                active()
                prove_pin(secrets, before)
        return {'same_enrollment_registry_throttle_tally_and_policies': True,
                'boot_changed': changed_boot, 'fresh_enrollment_performed': False,
                'native_kde_pam_pin_verified': phase != 'suspended-reboot-verify',
                'gate': 'disabled' if phase == 'suspended-reboot-verify' else 'active'}

    active()
    require(not m.FAULT.exists() and not m.locked(), 'repair faults and unlock desktop before lifecycle proof')
    before = snapshot()
    m.sync_json(WORK / ('m81-installed-' + phase + '.before.json'), before)
    if phase in ('reboot-prepare', 'suspend'):
        require(not checkpoint.exists(), 'existing private reboot checkpoint requires review')
        m.sync_json(checkpoint, before)
        if phase == 'suspend':
            m.admin('package-suspend')
            same(before, snapshot())
            state = m.private_json(MANIFEST)
            require(state['phase'] == 'suspended' and state.get('resume_phase') == 'active'
                    and json.loads(m.admin('status').stdout)['gate'] == 'disabled', 'suspension failed closed')
        return {'private_continuity_checkpoint_durable': True, 'reboot_requested': False,
                'activation_gate_closed': phase == 'suspend'}
    if phase == 'erase':
        manifest = m.private_json(MANIFEST)
        backup = manifest.get('backup', '')
        require(re.fullmatch('backup-[0-9a-f]{32}', backup), 'unsafe recovery backup reference')
        originals = {path: file_digest(MANIFEST.parent / backup / path.name, private=True)
                     for path in POLICIES[:2]}
        require(all(value == manifest['originals'][path.name]['sha256'] for path, value in originals.items()),
                'changed original service backup')
        require(native(['rpm', '-e', 'localpin'], phase) == 0, 'RPM erase failed; inspect private log')
        require(not m.rpm_installed() and not m.MODULE.exists(), 'RPM erase retained package/module')
        require(REGISTRY.read_bytes() == b'LPACCT03\0\0', 'RPM erase retained account authority')
        require(all(file_digest(path) == value for path, value in originals.items())
                and m.tally() == before['tally'], 'erase changed original KDE policy or native tally')
        return {'package_and_module_removed': True, 'both_original_kde_services_restored': True,
                'authority_revoked': True, 'native_password_tally_preserved': True}
    installed = m.command(['rpm', '-q', '--qf', '%{EVR}', 'localpin']).stdout.decode()
    package = m.rpm_path('upgrade_rpm' if phase == 'package-upgrade' else 'install_rpm')
    args = ['rpm', '-Uvh', *(['--oldpackage'] if phase == 'downgrade-refusal' else []), str(package)]
    code = native(args, phase)
    require((code == 0) == (phase == 'package-upgrade'), 'unexpected RPM result; inspect private log')
    after = snapshot()
    m.sync_json(WORK / ('m81-installed-' + phase + '.after.json'), after)
    same(before, after)
    active()
    version = m.command(['rpm', '-q', '--qf', '%{EVR}', 'localpin']).stdout.decode()
    require(version != installed if phase == 'package-upgrade' else version == installed,
            'RPM version did not match upgrade/downgrade result')
    return {'same_enrollment_registry_throttle_tally_and_policies': True,
            'automatic_active_gate_preserved': True, 'version_before': installed, 'version_after': version,
            'compatible_upgrade_completed': phase == 'package-upgrade',
            'explicit_downgrade_refused': phase == 'downgrade-refusal'}


def main():
    global m
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('phase', choices=PHASES)
    parser.add_argument('--expected-uuid', required=True)
    parser.add_argument('--disposable-vm-confirmed', action='store_true', required=True)
    parser.add_argument('--emulated-tpm-confirmed', action='store_true', required=True)
    args = parser.parse_args()
    require(str(uuid.UUID(args.expected_uuid)) == args.expected_uuid and os.getuid() == os.geteuid() == 0,
            'canonical clone UUID and actual guest root required')
    info = WORK.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 0
            and stat.S_IMODE(info.st_mode) == 0o700, 'private fixed guest work directory required')
    for name in ('run.py', 'guard.py'):
        info = (WORK / name).lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_uid == info.st_gid == 0
                and info.st_nlink == 1 and not info.st_mode & 0o022, 'unsafe common helper source')
    sys.path.insert(0, str(WORK))
    import run as m
    secrets = m.guard(args.expected_uuid)
    lock = WORK / '.m81-maintenance.lock'
    descriptor = os.open(lock, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    with os.fdopen(descriptor, 'rb') as stream:
        m.owned_file(lock, private=True, owner=0)
        fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
        result = perform(args.phase, secrets)
        require(m.command(['getenforce']).stdout.strip() == b'Enforcing', 'SELinux changed')
        value = {'phase': args.phase, 'passed': True, 'selinux': 'Enforcing',
                 'runner_sha256': file_digest(Path(__file__), bound=65536), 'observations': result,
                 'native_package_versions': m.native_environment()['packages'], 'raw_snapshots_guest_root_only': True}
        m.sync_json(WORK / ('m81-installed-' + args.phase + '.result.json'), value)
        print(json.dumps(value, sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except Exception:
        if 'm' in globals():
            try:
                m.sync_json(WORK / 'm81-installed-failure.json', {'traceback': traceback.format_exc()})
            except BaseException:
                pass
        print(json.dumps({'passed': False, 'error': 'installed lifecycle proof refused; inspect guest-root-only evidence'}))
        raise SystemExit(1) from None
