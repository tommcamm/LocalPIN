#!/usr/bin/python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Actual administrator-VT recovery proof for the guarded M8.2 clone.

No passwords, TPM operations, module repair or desktop-test attestations occur
here. The host prepares the missing-module fault and observes actual KDE
failure/password UI separately. Run through the fixed administrator wrapper
from the already authenticated root shell originating on actual guest tty3.
"""
import argparse
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
CONTROL = Path('/var/lib/localpin-integration/control')
MANIFEST = CONTROL / 'manifest.json'
GATE = Path('/var/lib/localpin-integration/gate')
REGISTRY = Path('/var/lib/localpin-accounts/registry')
TALLY = Path('/var/lib/faillock/lp61test')
MODULE = Path('/usr/lib64/security/pam_localpin.so')
SAVED_MODULE = WORK / 'pam_localpin.so.saved'
FAULT = WORK / 'fault.json'
POLICIES = ('kde', 'kde-fingerprint', 'localpin-enroll', 'localpin-eligibility',
            'localpin-kde-password', 'localpin-kde-fingerprint')
OFFLINE_RUNNER_SHA = '752f10ff086d41e26dfa7e3bec491f91498f60688309b6e40421087ff387ce30'
COMPLETED_RECOVERY_RUNNER_SHA = '42b0b4e7feec09c9e6d609320d1384563c29cf8052ecf4ab2513b9c3a1344539'


def require(value, message):
    if not value:
        raise RuntimeError(message)


def snapshot_file(path, *, bound=65536, owner=0):
    """Private exact metadata/digest checkpoint, excluding read-induced atime."""
    for parent in path.parents:
        info = parent.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 0
                and not info.st_mode & 0o022, 'unsafe fixed recovery path ancestor')
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        before = os.fstat(descriptor)
        safe_mode = (not before.st_mode & 0o022 if owner == 0
                     else owner == 21061 and stat.S_IMODE(before.st_mode) == 0o660)
        require(stat.S_ISREG(before.st_mode) and before.st_uid == owner and before.st_gid == 0
                and before.st_nlink == 1 and before.st_size <= bound and safe_mode,
                'unsafe bounded recovery input')
        data = os.read(descriptor, bound + 1)
        after = os.fstat(descriptor)
        fields = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink',
                  'st_size', 'st_mtime_ns', 'st_ctime_ns')
        require(len(data) == before.st_size
                and all(getattr(before, field) == getattr(after, field) for field in fields),
                'recovery input changed during checkpoint')
        actual = path.lstat()
        require((actual.st_dev, actual.st_ino) == (before.st_dev, before.st_ino),
                'recovery input replaced during checkpoint')
        return {**{field: getattr(before, field) for field in fields},
                'sha256': hashlib.sha256(data).hexdigest(),
                'xattrs': {name: os.getxattr(descriptor, name).hex()
                           for name in sorted(os.listxattr(descriptor))}}
    finally:
        os.close(descriptor)


def services():
    return {unit: {kind: m.command(['/usr/bin/systemctl', kind, unit], check=False).stdout.decode().strip()
                   for kind in ('is-active', 'is-enabled')}
            for unit in ('localpin.socket', 'localpin.service')}


def tally_snapshot():
    # The accounting helper validates canonical UID/GID/mode/native records and
    # ACLs. Include inode/ctime here to prove recovery did not replace the tally.
    accounting.capture(TALLY, tally=True)
    return snapshot_file(TALLY, owner=21061)


def fault_binding():
    fault = m.private_json(FAULT)
    require(fault.get('kind') == 'missing-module'
            and isinstance(fault.get('sha256'), str)
            and re.fullmatch('[0-9a-f]{64}', fault['sha256']) is not None
            and not MODULE.exists() and not MODULE.is_symlink(), 'actual missing-module fixture required')
    saved = snapshot_file(SAVED_MODULE, bound=32 * 1024 * 1024)
    require(saved['sha256'] == fault['sha256'], 'saved module does not match private fault intent')
    return {'fault': snapshot_file(FAULT), 'saved_module': saved}


def backup_reference(state, *, allow_disabled=False):
    phases = ('prepared', 'active', 'disabled') if allow_disabled else ('prepared', 'active')
    require(state.get('schema') == 2 and state.get('phase') in phases
            and state.get('uids') == [21061] and isinstance(state.get('backup'), str)
            and re.fullmatch('backup-[0-9a-f]{32}', state['backup']) is not None,
            'supported sole-account prepared/active integration required')
    path = CONTROL / state['backup']
    info = path.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 0
            and stat.S_IMODE(info.st_mode) == 0o700, 'unsafe protected original-policy backup')
    originals = state.get('originals')
    require(isinstance(originals, dict) and set(originals) == set(POLICIES),
            'complete current original-policy manifest required')
    expected = {}
    for name in POLICIES:
        descriptor = originals[name]
        require(isinstance(descriptor, dict) and isinstance(descriptor.get('sha256'), str)
                and re.fullmatch('[0-9a-f]{64}', descriptor['sha256']) is not None
                and type(descriptor.get('mode')) is int and descriptor['mode'] == 0o644,
                'unsafe original-policy manifest entry')
        snapshot = snapshot_file(path / name)
        require(snapshot['st_mode'] & 0o7777 == 0o600 and snapshot['sha256'] == descriptor['sha256'],
                'protected original-policy backup mismatch')
        expected[name] = {'sha256': snapshot['sha256'], 'mode': descriptor['mode']}
    return expected


def optional_gate_snapshot():
    # Native begin-mutation intentionally unlinks the gate after closing it.
    # The production gate reader treats an absent gate as disabled.
    try:
        GATE.lstat()
    except FileNotFoundError:
        return None
    return snapshot_file(GATE)


def require_closed_gate():
    observed = optional_gate_snapshot()
    if observed is not None:
        require(observed['st_mode'] & 0o7777 == 0o644
                and GATE.read_bytes() == b'LPINT01\ndisabled\n', 'recovery retained a live or unknown gate')
    return observed


def private_checkpoint():
    paths = [MANIFEST, REGISTRY, FAULT, SAVED_MODULE,
             *(Path('/etc/pam.d') / name for name in POLICIES),
             Path('/etc/security/faillock.conf'),
             *(Path('/etc') / name for name in ('passwd', 'group', 'shadow', 'gshadow'))]
    root = Path('/var/lib/localpin/users/21061')
    credentials = sorted(path for path in root.rglob('*') if path.is_file())
    require(len(credentials) <= 256, 'oversized private credential checkpoint')
    paths.extend(credentials)
    files = {str(path): snapshot_file(path, bound=32 * 1024 * 1024 if path == SAVED_MODULE else 65536)
             for path in paths}
    files[str(GATE)] = optional_gate_snapshot()
    return {'files': files, 'tally': tally_snapshot(), 'services': services(),
            'boot': m.boot_id(), 'fault': fault_binding()}


def run_recovery(expected_uuid):
    state = m.private_json(MANIFEST)
    expected = backup_reference(state)
    before = private_checkpoint()
    m.sync_json(WORK / 'm82-console-recovery-before.json', before)
    dry_run = m.admin('recover', '--dry-run', check=False)
    m.sync_json(WORK / 'm82-console-recovery-dry-run.json', {
        'returncode': dry_run.returncode, 'stdout': dry_run.stdout.decode(errors='replace'),
        'stderr': dry_run.stderr.decode(errors='replace')})
    require(dry_run.returncode == 0, 'actual recover dry-run refused; inspect private evidence')
    dry = json.loads(dry_run.stdout)
    require(dry.get('operation') == 'disable' and dry.get('dry_run') is True,
            'unexpected recover dry-run result')
    require(private_checkpoint() == before, 'recover dry-run changed protected state or native accounting')
    recovered = m.admin('recover', check=False)
    m.sync_json(WORK / 'm82-console-recovery-operation.json', {
        'returncode': recovered.returncode, 'stdout': recovered.stdout.decode(errors='replace'),
        'stderr': recovered.stderr.decode(errors='replace')})
    require(recovered.returncode == 0, 'actual recover refused; inspect private evidence')
    result = json.loads(recovered.stdout)
    require(result.get('phase') == 'disabled' and result.get('enrollments_revoked') is True,
            'actual recovery did not report disabled/revoked state')
    return verify_recovered_state(expected_uuid, before, expected)


def verify_recovered_state(expected_uuid, before, expected, *, checkpoint='after'):
    """Observation only: no administrator mutation or authentication calls."""
    require(m.boot_id() == before['boot'], 'recovery crossed a reboot')
    disabled = m.private_json(MANIFEST)
    require(disabled.get('schema') == 2 and disabled.get('phase') == 'disabled'
            and disabled.get('tests') is None
            and REGISTRY.read_bytes() == b'LPACCT03\0\0', 'recovery retained integration or account authority')
    closed_gate = require_closed_gate()
    policies = {}
    for name in POLICIES:
        current = snapshot_file(Path('/etc/pam.d') / name)
        require(current['sha256'] == expected[name]['sha256']
                and current['st_mode'] & 0o7777 == expected[name]['mode'],
                'recovery did not restore original policy exactly')
        policies[name] = current
    require(tally_snapshot() == before['tally'], 'recovery changed native counter bytes or metadata')
    require(fault_binding() == before['fault'], 'recovery changed or repaired the prepared module fault')
    units = services()
    require(all(value['is-active'] == 'inactive' for value in units.values())
            and units['localpin.socket']['is-enabled'] == 'disabled'
            and units['localpin.service']['is-enabled'] in ('static', 'disabled'),
            'recovery retained running broker or boot opt-in')
    m.guard(expected_uuid)
    m.sync_json(WORK / ('m82-console-recovery-' + checkpoint + '.json'), {
        'policies': policies, 'manifest': snapshot_file(MANIFEST), 'gate': closed_gate,
        'registry': snapshot_file(REGISTRY), 'tally': tally_snapshot(), 'services': units})
    return {'actual_administrator_tty3_recovery': True, 'boot_unchanged': True,
            'actual_recover_dry_run_unchanged': True, 'actual_recover_completed': True,
            'original_kde_services_and_private_policies_restored': True,
            'restored_policy_count': len(POLICIES), 'account_authority_revoked': True,
            'gate_and_manifest_disabled': True, 'native_counter_bytes_and_metadata_unchanged': True,
            'gate_representation': 'absent' if closed_gate is None else 'canonical-disabled',
            'broker_units_inactive': True, 'socket_boot_opt_in_disabled': True,
            'service_not_boot_enabled': True, 'missing_module_fault_retained_for_password_ui': True,
            'password_or_attestation_input_performed': False}


def review_completed_recovery(expected_uuid, origin):
    """Finish observation of the exact completed 42b0 run without rerunning it."""
    suffixes = ('intent', 'before', 'dry-run', 'operation', 'failure')
    records = {}
    for suffix in suffixes:
        path = WORK / ('m82-console-recovery-' + suffix + '.json')
        snapshot_file(path)
        records[suffix] = m.private_json(path)
    require(not any((WORK / ('m82-console-recovery-' + suffix + '.json')).exists()
                    for suffix in ('after', 'result', 'observer-intent', 'observer-after',
                                   'observer-result', 'observer-failure')),
            'existing recovery completion observation must be preserved')
    intent = records['intent']
    require(intent.get('runner_sha256') == COMPLETED_RECOVERY_RUNNER_SHA
            and intent.get('terminal_guard_runner_sha256') == OFFLINE_RUNNER_SHA
            and intent.get('uuid') == expected_uuid and intent.get('boot') == m.boot_id()
            and intent.get('installed_helper_sha256') == hashlib.sha256(Path(m.ADMIN).read_bytes()).hexdigest()
            and records['before'].get('boot') == intent['boot'],
            'completion review requires the exact original command runner, helper, UUID and boot')
    failure = records['failure'].get('traceback')
    require(isinstance(failure, str) and failure.strip().endswith(
        "FileNotFoundError: [Errno 2] No such file or directory: '/var/lib/localpin-integration/gate'"),
        'completion review is limited to the known missing-gate post-observation failure')
    dry = records['dry-run']
    operation = records['operation']
    require(dry.get('returncode') == 0 and operation.get('returncode') == 0
            and isinstance(dry.get('stdout'), str) and isinstance(operation.get('stdout'), str),
            'original actual recovery commands did not both complete successfully')
    dry_result = json.loads(dry['stdout'])
    operation_result = json.loads(operation['stdout'])
    require(dry_result.get('operation') == 'disable' and dry_result.get('dry_run') is True
            and operation_result.get('phase') == 'disabled'
            and operation_result.get('enrollments_revoked') is True,
            'original actual recovery command results are not established')
    # In that exact runner, the operation record was written only after the
    # dry-run equality assertion passed, and the known failure occurred after
    # both return codes and structured results had already been checked.
    expected = backup_reference(m.private_json(MANIFEST), allow_disabled=True)
    source = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    m.sync_json(WORK / 'm82-console-recovery-observer-intent.json', {
        'uuid': expected_uuid, 'boot': m.boot_id(), 'terminal_origin': origin,
        'command_runner_sha256': COMPLETED_RECOVERY_RUNNER_SHA, 'observer_runner_sha256': source,
        'original_failure_preserved': True, 'actual_recovery_commands_will_not_be_repeated': True})
    try:
        observations = verify_recovered_state(expected_uuid, records['before'], expected,
                                             checkpoint='observer-after')
    except BaseException:
        m.sync_json(WORK / 'm82-console-recovery-observer-failure.json', {'traceback': traceback.format_exc()})
        raise RuntimeError('recovery completion observation refused; original commands were not repeated') from None
    value = {'phase': 'm82-actual-console-recovery-completion-review', 'passed': True,
             'selinux': 'Enforcing', 'command_runner_sha256': COMPLETED_RECOVERY_RUNNER_SHA,
             'observer_runner_sha256': source, 'actual_recovery_commands_repeated': False,
             'original_failure_preserved': True, 'observations': observations,
             'raw_snapshots_and_operation_output_guest_root_only': True}
    m.sync_json(WORK / 'm82-console-recovery-observer-result.json', value)
    return value


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--expected-uuid', required=True)
    parser.add_argument('--disposable-vm-confirmed', required=True, action='store_true')
    parser.add_argument('--emulated-tpm-confirmed', required=True, action='store_true')
    parser.add_argument('--review-completed-recovery', action='store_true',
                        help='Observe only the known completed 42b0 recovery; never rerun recovery commands')
    args = parser.parse_args()
    require(os.getuid() == os.geteuid() == 0 and str(uuid.UUID(args.expected_uuid)) == args.expected_uuid,
            'canonical clone UUID and actual guest root required')
    global m, accounting
    sys.path.insert(0, str(WORK))
    for name in ('run.py', 'guard.py', 'offline_accounting.py'):
        snapshot_file(WORK / name)
    require(hashlib.sha256((WORK / 'offline_accounting.py').read_bytes()).hexdigest() == OFFLINE_RUNNER_SHA,
            'expected reviewed terminal-origin helper source required')
    import run as m
    import offline_accounting as accounting
    m.guard(args.expected_uuid)
    origin = accounting.terminal_origin()
    if args.review_completed_recovery:
        value = review_completed_recovery(args.expected_uuid, origin)
        print(json.dumps(value, sort_keys=True))
        return
    require(not any((WORK / ('m82-console-recovery-' + suffix + '.json')).exists()
                    for suffix in ('intent', 'before', 'dry-run', 'operation', 'after', 'result', 'failure')),
            'existing console recovery attempt must be preserved and reviewed')
    fault_binding()
    backup_reference(m.private_json(MANIFEST))
    m.sync_json(WORK / 'm82-console-recovery-intent.json', {
        'uuid': args.expected_uuid, 'boot': m.boot_id(), 'terminal_origin': origin,
        'runner_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        'terminal_guard_runner_sha256': OFFLINE_RUNNER_SHA,
        'installed_helper_sha256': hashlib.sha256(Path(m.ADMIN).read_bytes()).hexdigest()})
    try:
        observations = run_recovery(args.expected_uuid)
    except BaseException:
        m.sync_json(WORK / 'm82-console-recovery-failure.json', {'traceback': traceback.format_exc()})
        raise RuntimeError('console recovery refused; inspect private operation and failure evidence') from None
    value = {'phase': 'm82-actual-console-recovery', 'passed': True, 'selinux': 'Enforcing',
             'runner_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
             'command_runner_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
             'observer_runner_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
             'observations': observations, 'raw_snapshots_and_operation_output_guest_root_only': True}
    m.sync_json(WORK / 'm82-console-recovery-result.json', value)
    print(json.dumps(value, sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except (OSError, RuntimeError, ValueError, KeyError, TypeError):
        print(json.dumps({'phase': 'm82-actual-console-recovery', 'passed': False,
                          'error': 'actual console recovery refused; inspect guest-root-only evidence'}))
        raise SystemExit(1) from None
