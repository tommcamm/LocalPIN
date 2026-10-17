#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Actual RPM/authority/CLI lifecycle matrix, only inside the guarded M8 clone.

This is a test fixture, never shipped in the RPM. No physical TPM, alternate
production authority, enrollment import, counter reset or SELinux permissive
mode is used. Secret inputs stay guest-root private and are never exported.
"""
import argparse
import array
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
import time
import uuid

from guard import owned_file, require

WORK = Path('/root/localpin-m8')
KDE = Path('/etc/pam.d/kde')
MODULE = Path('/usr/lib64/security/pam_localpin.so')
ADMIN = '/usr/libexec/localpin/localpin-integration'
ACCOUNT = '/usr/libexec/localpin/localpin-account'
NAME, UID = 'lp61test', 21061
OTHER = 21062
TALLY = Path('/var/lib/faillock') / NAME
FAULT = WORK / 'fault.json'
PHASES = ('inspect', 'install', 'refusal-matrix', 'prepare', 'enroll', 'isolated',
          'trial', 'fault-missing-module', 'fault-selinux-worker', 'repair-fault',
          'activate', 'package-failure', 'upgrade', 'downgrade-refusal',
          'fingerprint-refusal', 'legacy-prepare', 'legacy-migrate',
          'reboot-prepare', 'reboot-verify', 'locked-tally', 'disable',
          'recover', 'uninstall', 'cache-interrupt', 'cache-reboot-verify', 'cache-resume')


def command(args, *, data=None, check=True, timeout=45):
    try:
        result = subprocess.run(args, input=data, capture_output=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        raise RuntimeError('bounded guest command timed out: ' + Path(args[0]).name) from None
    # Never interpolate native output: it may contain authentication material.
    if check:
        require(result.returncode == 0, 'guest command refused: ' + Path(args[0]).name)
    return result


def private_json(path):
    owned_file(path, private=True, owner=0)
    return json.loads(path.read_text())


def sync_json(path, value):
    require(path.parent == WORK, 'fixture writes must remain in private work directory')
    temp = WORK / ('.pending-' + uuid.uuid4().hex)
    descriptor = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(descriptor, 'w') as stream:
            json.dump(value, stream, indent=2)
            stream.write('\n')
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp, path)
        sync_directory(WORK)
    finally:
        temp.unlink(missing_ok=True)


def sync_directory(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def boot_id():
    return str(uuid.UUID(Path('/proc/sys/kernel/random/boot_id').read_text().strip()))


def guard(expected_uuid):
    require(os.getuid() == os.geteuid() == 0, 'guest root required')
    expected_uuid = str(uuid.UUID(expected_uuid))
    require(Path('/sys/class/dmi/id/product_uuid').read_text().strip().lower() == expected_uuid,
            'M8 clone UUID mismatch')
    require(command(['systemd-detect-virt', '--vm']).stdout.strip() == b'kvm', 'dedicated KVM clone required')
    require(command(['getenforce']).stdout.strip() == b'Enforcing', 'SELinux must remain enforcing')
    values = dict(line.split('=', 1) for line in Path('/etc/os-release').read_text().splitlines()
                  if '=' in line and not line.startswith('#'))
    require(values.get('ID', '').strip('"') == 'fedora'
            and values.get('VERSION_ID', '').strip('"') == '44'
            and values.get('VARIANT_ID', '').strip('"') == 'kde', 'Fedora 44 KDE required')
    parent = WORK.lstat()
    require(stat.S_ISDIR(parent.st_mode) and parent.st_uid == 0 and not parent.st_mode & 0o077,
            'private guest experiment directory required')
    for name, text in [('localpin-m8-guard', expected_uuid + '\n'),
                       ('localpin-m8-emulator', expected_uuid + '\nemulator2.0\n')]:
        marker = Path('/run') / name
        owned_file(marker, private=True, owner=0)
        require(marker.read_text() == text, 'M8 private clone/emulator marker mismatch')
    # The host independently proves this is libvirt's private emulator through
    # active+inactive XML. Guest device existence alone cannot prove provenance.
    require(stat.S_ISCHR(Path('/dev/tpmrm0').lstat().st_mode), 'native emulator resource manager absent')
    secrets = private_json(WORK / 'secrets.json')
    require(set(secrets) == {NAME, 'lp61other'}, 'unexpected fixture account list')
    for name, uid in ((NAME, UID), ('lp61other', OTHER)):
        record = pwd.getpwnam(name)
        value = secrets[name]
        require(record.pw_uid == uid and record.pw_dir == '/home/' + name
                and record.pw_shell == '/bin/bash' and value.get('uid') == uid,
                'dedicated clone account identity changed')
        require(isinstance(value.get('password'), str)
                and re.fullmatch('[a-z]{30}', value['password']) is not None
                and isinstance(value.get('pin'), str)
                and re.fullmatch('[0-9]{6}', value['pin']) is not None
                and value['pin'] not in ('000000', value['password']), 'invalid private fixture secret schema')
    return secrets


def user_environment():
    # No runuser/su: their PAM account/session calls can change native counters.
    return ['/usr/bin/setpriv', '--reuid=' + str(UID), '--regid=' + str(UID),
            '--clear-groups', '--', '/usr/bin/env', f'XDG_RUNTIME_DIR=/run/user/{UID}',
            f'DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/{UID}/bus']


def user_command(*args):
    return user_environment() + ['/usr/bin/systemd-run', '--user', '--quiet', '--collect',
                                 '--wait', '--pipe', '--unit=localpin-m8-' + uuid.uuid4().hex, *args]


def framed(value):
    data = value.encode()
    require(len(data) <= 512, 'oversized private fixture input')
    return struct.pack('>H', len(data)) + data


def status():
    result = command(user_command('/usr/libexec/localpin/m8-client', 'status'))
    return json.loads(result.stdout)


def pam(*candidates):
    result = command(user_command('/usr/libexec/localpin/m8-pam-probe'),
                     data=b''.join(framed(value) for value in candidates), timeout=75)
    return [json.loads(line) for line in result.stdout.splitlines()]


def bus(method):
    require(method in ('GetActive', 'Lock'), 'unknown locker method')
    return command(user_environment() + ['/usr/bin/busctl', '--user', 'call',
                   'org.freedesktop.ScreenSaver', '/ScreenSaver',
                   'org.freedesktop.ScreenSaver', method]).stdout.strip()


def locked():
    return bus('GetActive') == b'b true'


def locker_pid():
    result = command(['pgrep', '-u', str(UID), '-f', '^/usr/libexec/kscreenlocker_greet'], check=False)
    require(result.returncode in (0, 1), 'greeter observation failed')
    return [int(value) for value in result.stdout.split()]


def tally():
    if not TALLY.exists():
        return None
    data = TALLY.read_bytes()
    require(len(data) % 64 == 0 and len(data) <= 65_536, 'noncanonical native tally')
    return {'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()}


def binding():
    module_digest = (digest(MODULE) if MODULE.exists() else
                     private_json(FAULT)['sha256'] if FAULT.exists() else None)
    manifest = Path('/var/lib/localpin-integration/control/manifest.json')
    trial_value = private_json(manifest).get('trial') if manifest.exists() else None
    return {'boot_id': boot_id(), 'kde_sha256': digest(KDE), 'module_sha256': module_digest,
            'trial': trial_value}


def record_ui(phase, observations):
    require(phase in ('baseline', 'legacy-password', 'pin', 'password', 'recovery', 'selinux-recovery'),
            'unsupported UI evidence phase')
    require(observations.get('unlocked') is True, 'UI result must prove actual unlock')
    require(observations.get('same_greeter_after_denial') is True
            if phase in ('recovery', 'selinux-recovery') else True, 'recovery did not retain same greeter')
    path = WORK / 'ui.json'
    value = private_json(path) if path.exists() else {}
    value[phase] = {'binding': binding(), 'observations': observations}
    sync_json(path, value)


def package_binding():
    return {'admin_sha256': digest(Path(ADMIN)),
            'module_sha256': digest(MODULE) if MODULE.exists() else private_json(FAULT)['sha256'],
            'service_sha256': digest(Path('/usr/lib/systemd/system/localpin.service')),
            'packaged_selinux_sha256': digest(Path('/usr/share/selinux/packages/localpin.pp')),
            'evr': command(['rpm', '-q', '--qf', '%{EVR}', 'localpin']).stdout.decode()}


def record_console_recovery(observations):
    require(observations.get('unlocked') is True and observations.get('same_greeter_after_denial') is True
            and observations.get('console_recovery', {}).get('boot_unchanged') is True
            and observations['console_recovery'].get('exact_original_kde_restored') is True,
            'actual console repair of failed greeter was not proved')
    sync_json(WORK / 'console-recovery.json', {'binding': package_binding(), 'observations': observations})


def rpm_path(key):
    name = private_json(WORK / 'packages.json').get(key)
    require(isinstance(name, str) and re.fullmatch(r'localpin-[A-Za-z0-9_.+~-]+\.rpm', name)
            is not None, 'invalid staged package basename')
    path = WORK / name
    owned_file(path, owner=0, max_size=128 * 1024 * 1024)
    require(command(['rpm', '-qp', '--qf', '%{NAME}', str(path)]).stdout == b'localpin',
            'staged RPM has unexpected package name')
    return path


def rpm_installed():
    return command(['rpm', '-q', 'localpin'], check=False).returncode == 0


def native_environment():
    names = ('pam', 'systemd', 'authselect', 'kscreenlocker', 'selinux-policy-targeted',
             'glibc-common', 'tpm2-tss')
    result = command(['rpm', '-q', '--qf', '%{NAME}\t%{EPOCHNUM}:%{VERSION}-%{RELEASE}.%{ARCH}\n', *names])
    packages = dict(line.split('\t', 1) for line in result.stdout.decode().splitlines())
    require(set(packages) == set(names), 'complete native package inventory required')
    return {'packages': packages,
            'kernel_release': command(['uname', '-r']).stdout.decode().strip(),
            'authselect_profile': command(['authselect', 'current', '--raw']).stdout.decode().strip()}


def inspect(_secrets):
    require(not locked(), 'start M8 lifecycle from an unlocked dedicated desktop')
    session = command(['loginctl', 'list-sessions', '--no-legend']).stdout
    require(NAME.encode() in session, 'real dedicated desktop session required')
    return {'selinux': 'Enforcing', 'private_emulator': True, 'physical_tpm': False,
            'dedicated_desktop_present': True, 'package_installed': rpm_installed(),
            'native_environment': native_environment()}


def install(_secrets):
    require(not rpm_installed(), 'clean package baseline required')
    require(not Path('/var/lib/localpin-accounts/registry').exists(), 'clean registry baseline required')
    before = digest(KDE)
    environment = native_environment()
    command(['rpm', '-Uvh', str(rpm_path('install_rpm'))], timeout=180)
    require(rpm_installed() and digest(KDE) == before, 'RPM installation changed existing KDE policy')
    require(not Path('/var/lib/localpin-accounts/registry').exists(), 'RPM installation enrolled account state')
    require(command(['systemctl', 'is-active', 'localpin.socket'], check=False).returncode != 0,
            'RPM unexpectedly activated broker socket')
    sync_json(WORK / 'install.json', {'stock_kde_sha256': before})
    return {'package_installed': True, 'existing_kde_unchanged': True,
            'no_enrollment': True, 'socket_inactive': True, 'native_environment': environment}


def admin(*args, check=True):
    return command([ADMIN, *args], check=check, timeout=90)


def prepare(_secrets):
    require(not FAULT.exists(), 'repair fixture fault first')
    before = digest(KDE)
    admin('prepare', '--uid', str(UID), '--dry-run')
    require(digest(KDE) == before, 'prepare dry-run mutated KDE')
    admin('prepare', '--uid', str(UID))
    require(status()['availability'] == 'disabled', 'prepare did not provision fresh disabled account')
    require(TALLY.exists(), 'persistent native tally missing after preparation')
    sync_json(WORK / 'ui.json', {})
    return {'dry_run_unchanged': True, 'fresh_disabled_account': True,
            'persistent_native_tally': True}


def enroll(secrets):
    require(status()['availability'] == 'disabled', 'fresh disabled baseline required')
    value = secrets[NAME]
    result = command(user_command('python3', '/usr/libexec/localpin/m8-pty.py', 'enroll-tpm'),
                     data=framed(value['password']) + framed(value['pin']), timeout=85)
    observation = json.loads(result.stdout)
    value = status()
    require(observation.get('secret_echo_absent') is True and observation.get('exit_success') is True
            and value['availability'] == 'available' and value['enrolled_backend'] == 'tpm2',
            'installed CLI TPM enrollment failed')
    return {'installed_cli_pty': observation, 'native_tpm_enrollment': True,
            'status': {key: value.get(key) for key in ('availability', 'enrolled_backend')}}


def isolated(secrets):
    before = tally()
    result = command(user_command('/usr/libexec/localpin/m8-client', 'verify'),
                     data=framed(secrets[NAME]['pin']), timeout=15)
    require(result.stdout.strip() == b'Granted', 'actual enrolled PIN did not verify through broker')
    require(tally() == before, 'isolated PIN verification changed native password tally')
    return {'production_broker_pin_verified': True, 'native_password_tally_unchanged': True}


def trial(_secrets):
    admin('trial')
    sync_json(WORK / 'ui.json', {})
    return {'bounded_trial_requested': True}


def fault_missing_module(_secrets):
    require(not FAULT.exists(), 'repair existing fault first')
    require(not locked(), 'fault needs a fresh unlocked desktop')
    owned_file(MODULE, owner=0, max_size=32 * 1024 * 1024)
    saved = WORK / 'pam_localpin.so.saved'
    require(not saved.exists() and not saved.is_symlink(), 'saved module already exists')
    sync_json(FAULT, {'kind': 'missing-module', 'sha256': digest(MODULE)})
    MODULE.rename(saved)
    sync_directory(MODULE.parent)
    sync_directory(WORK)
    return {'module_absent': not MODULE.exists(), 'durable_fault_intent': True}


def avc_count():
    # Boot-scoped audit journal remains reliable if auditd's wall-clock search
    # interval differs from the private VM clock. Count actual AVC messages,
    # never the service's error text or a declared fault condition.
    result = command(['journalctl', '-b', '--no-pager', '-o', 'json',
                      '--grep=avc:.*denied'], check=False)
    require(result.returncode in (0, 1), 'boot-scoped audit evidence unavailable')
    count = 0
    for event in (json.loads(line) for line in result.stdout.splitlines()):
        text = event.get('MESSAGE', '')
        if (event.get('_TRANSPORT') in ('audit', 'kernel')
                and re.search(r'scontext=\S*:localpin_broker_t:', text)
                and re.search(r'tcontext=\S*:default_t:', text)
                and 'tclass=file' in text and 'name="localpin-worker"' in text):
            count += 1
    return count


def fault_selinux_worker(_secrets):
    require(not FAULT.exists() and not locked(), 'repair existing fault/unlock desktop first')
    path = Path('/usr/libexec/localpin/localpin-worker')
    owned_file(path, owner=0, max_size=32 * 1024 * 1024)
    sync_json(FAULT, {'kind': 'selinux-worker', 'sha256': digest(path), 'avc_before': avc_count(),
                     'denial_audit_enabled': True})
    command(['chcon', '-t', 'default_t', str(path)])
    # Existing supervisors bind executable metadata and can refuse a changed
    # ctime before exec. Recreate only the normal broker process so this case
    # reaches SELinux's kernel exec check. -DB changes denial logging only;
    # Enforcing and every allow rule remain unchanged.
    command(['semodule', '-DB'], timeout=90)
    command(['systemctl', 'reset-failed', 'localpin.service'], check=False)
    command(['systemctl', 'restart', 'localpin.service'])
    return {'backend_worker_label_changed': True, 'selinux': 'Enforcing', 'durable_fault_intent': True}


def repair_fault(_secrets):
    value = private_json(FAULT)
    if value['kind'] == 'missing-module':
        saved = WORK / 'pam_localpin.so.saved'
        owned_file(saved, owner=0, max_size=32 * 1024 * 1024)
        require(not MODULE.exists() and not MODULE.is_symlink() and digest(saved) == value['sha256'],
                'changed module fault; manual fixture recovery required')
        saved.rename(MODULE)
        command(['restorecon', str(MODULE)])
        sync_directory(MODULE.parent)
    elif value['kind'] == 'selinux-worker':
        path = Path('/usr/libexec/localpin/localpin-worker')
        require(digest(path) == value['sha256'], 'changed worker; manual fixture recovery required')
        require(avc_count() > value['avc_before'], 'actual enforcing SELinux denial was not observed')
        command(['restorecon', str(path)])
        command(['systemctl', 'reset-failed', 'localpin.service'], check=False)
        command(['systemctl', 'restart', 'localpin.service'])
        if value.get('denial_audit_enabled'):
            command(['semodule', '-B'], timeout=90)
    else:
        raise RuntimeError('unknown fixture fault; manual recovery required')
    FAULT.unlink()
    sync_directory(WORK)
    return {'exact_component_restored': True, 'selinux': 'Enforcing'}


def activate(_secrets):
    require(not FAULT.exists(), 'repair fixture fault before activation')
    evidence = private_json(WORK / 'ui.json')
    current = binding()
    for phase in ('pin', 'password', 'recovery'):
        require(evidence.get(phase, {}).get('binding') == current,
                'actual same-trial PIN/password/recovery desktop evidence missing')
    console = private_json(WORK / 'console-recovery.json')
    expected = package_binding()
    require(all(console.get('binding', {}).get(key) == value
                for key, value in expected.items() if key != 'evr'),
            'actual text-console recovery must be proved for this package before activation')
    admin('record-tests', '--pin', '--password', '--recovery')
    admin('activate')
    require(command(['systemctl', 'is-enabled', 'localpin.socket']).stdout.strip() == b'enabled',
            'activation did not persist socket boot opt-in')
    return {'actual_ui_pin_password_recovery_required': True,
            'actual_console_recovery_proved_for_package': True, 'activation_completed': True,
            'socket_enabled_for_boot': True}


def credential_records():
    root = Path('/var/lib/localpin/users') / str(UID)
    records = [root / 'active', *sorted(root.glob('generation-*/credential'))]
    require(len(records) >= 2, 'actual active credential snapshot absent')
    return {str(path.relative_to(root)): digest(path) for path in records}


def credentials():
    registry = Path('/var/lib/localpin-accounts/registry').read_bytes()
    authority, accounts = normalized_registry(registry)
    return {'registry': hashlib.sha256(registry).hexdigest(),
            'registry_authority_except_etc_metadata': hashlib.sha256(authority).hexdigest(),
            'account_ids': hashlib.sha256(accounts).hexdigest(),
            'records': credential_records()}


def throttle():
    root = Path('/var/lib/localpin/users') / str(UID)
    pointer = (root / 'active').read_bytes()
    require(len(pointer) == 35 and pointer[:6] == b'LPA3\0\x01', 'unsupported active generation')
    path = root / ('generation-' + str(int.from_bytes(pointer[26:34], 'big'))) / 'throttle'
    owned_file(path, private=True, owner=0)
    return digest(path)


def normalized_registry(data):
    # LPACCT02 orders /etc first, then the remaining immutable directories,
    # files and links. A reviewed package cache window may refresh only that
    # directory's size/ctime/nanoseconds. Everything else stays byte exact.
    require(data[:8] == b'LPACCT02' and len(data) >= 12, 'unsupported private registry format')
    count = int.from_bytes(data[8:10], 'big')
    require(count == 20, 'exact reviewed private registry snapshot layout required')
    end = 10 + count * 84
    require(len(data) >= end + 2, 'truncated private registry')
    accounts = int.from_bytes(data[end:end + 2], 'big')
    require(0 < accounts <= 128 and len(data) == end + 2 + accounts * 20,
            'invalid private account identity list')
    normalized = bytearray(data)
    normalized[26:50] = bytes(24)
    return bytes(normalized), data[end:]


def upgrade(_secrets):
    before = credentials()
    before_throttle = throttle()
    policy = digest(KDE)
    protected = {str(path): {'sha256': digest(path), 'inode': path.stat().st_ino}
                 for path in [KDE, Path('/etc/pam.d/localpin-enroll'), Path('/etc/pam.d/localpin-eligibility')]}
    command(['rpm', '-Uvh', str(rpm_path('upgrade_rpm'))], timeout=180)
    require(digest(KDE) == policy, 'package upgrade changed integrated KDE')
    after = credentials()
    require(throttle() == before_throttle, 'package upgrade changed committed throttle state')
    require({key: value for key, value in after.items() if key != 'registry'}
            == {key: value for key, value in before.items() if key != 'registry'},
            'package upgrade changed account/credential authority beyond reviewed cache metadata')
    require(protected == {str(path): {'sha256': digest(path), 'inode': path.stat().st_ino}
                          for path in map(Path, protected)}, 'upgrade rewrote protected PAM inode')
    state = json.loads(admin('status').stdout)
    require(state['gate'] == 'disabled', 'upgrade reopened activation without fresh desktop tests')
    sync_json(WORK / 'ui.json', {})
    return {'rpm_upgrade_completed': True, 'same_enrollment': True, 'kde_unchanged': True,
            'protected_pam_inodes_unchanged': True, 'same_account_ids': True,
            'registry_authority_except_etc_metadata_unchanged': True,
            'committed_throttle_unchanged': True,
            'activation_gate_disabled_pending_retest': True}


def package_failure(_secrets):
    before, policy = credentials(), digest(KDE)
    manifest = private_json(Path('/var/lib/localpin-integration/control/manifest.json'))
    backup_name = manifest['backup']
    require(re.fullmatch(r'backup-[a-f0-9]{32}', backup_name), 'unknown integration backup name')
    backup = Path('/var/lib/localpin-integration/control') / backup_name / 'kde'
    owned_file(backup, private=True, owner=0)
    original = backup.read_bytes()
    saved = WORK / 'package-failure-kde.saved'
    require(not saved.exists(), 'existing package failure fixture requires review')
    descriptor = os.open(saved, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, 'wb') as stream:
        stream.write(original)
        stream.flush()
        os.fsync(stream.fileno())
    sync_directory(WORK)
    changed = original + b'\n# disposable corrupt-backup transaction fixture\n'
    try:
        backup.write_bytes(changed)
        result = command(['rpm', '-e', 'localpin'], check=False, timeout=180)
        require(result.returncode != 0 and rpm_installed(), 'unsafe original backup did not block RPM erase')
        require(digest(KDE) == policy and credentials() == before,
                'failed package transaction changed policy or original enrollment')
    finally:
        require(backup.read_bytes() == changed, 'package backup changed unexpectedly; inspect fixture')
        backup.write_bytes(original)
        with backup.open('rb') as stream:
            os.fsync(stream.fileno())
    require(backup.read_bytes() == saved.read_bytes(), 'exact package backup restore failed')
    saved.unlink()
    return {'actual_rpm_erase_refused': True, 'unsafe_backup_detected': True,
            'installed_package_policy_enrollment_retained': True, 'exact_backup_restored': True}


def downgrade_refusal(_secrets):
    before, policy = credentials(), digest(KDE)
    version = command(['rpm', '-q', '--qf', '%{EVR}', 'localpin']).stdout
    result = command(['rpm', '-Uvh', '--oldpackage', str(rpm_path('install_rpm'))], check=False, timeout=180)
    require(result.returncode != 0, 'explicit RPM downgrade unexpectedly succeeded')
    require(command(['rpm', '-q', '--qf', '%{EVR}', 'localpin']).stdout == version
            and credentials() == before and digest(KDE) == policy,
            'refused downgrade changed package, policy or enrollment')
    return {'explicit_rpm_downgrade_refused': True, 'package_policy_enrollment_unchanged': True}


def fingerprint_refusal(_secrets):
    require(not Path('/var/lib/localpin-accounts/registry').exists(),
            'fingerprint refusal fixture requires unprepared account domain')
    password_auth = Path('/etc/authselect/password-auth')
    nss = Path('/etc/authselect/nsswitch.conf')
    before_auth, before_nss, before_kde = digest(password_auth), nss.read_bytes(), digest(KDE)
    require(before_auth == '2e53f704372b6c7fb69cdc4dfd6c27456d642c83feff8b1588fa1f9cb1126cd0',
            'unknown baseline authselect graph')
    args = ['authselect', 'select', 'local', 'with-silent-lastlog', 'with-mdns4', 'with-fingerprint']
    try:
        command([*args, 'with-faillock', '--force'])
        require(digest(password_auth) == 'de00ea01b5ffe6b08efd7027e437bdd4a3bad18e231e9593f6b45cc64b334276',
                'native authselect did not create observed unsafe fingerprint graph')
        result = admin('prepare', '--uid', str(UID), '--dry-run', check=False)
        require(result.returncode != 0 and b'parallel fingerprint failures' in result.stderr,
                'unsafe native fingerprint/faillock composition did not produce specific refusal')
        require(digest(KDE) == before_kde, 'fingerprint refusal changed KDE policy')
    finally:
        command([*args, '--force'])
        # Restore only this clone's exact pre-existing files-only fixture after
        # native authselect regeneration; production activation never does so.
        nss.write_bytes(before_nss)
        command(['restorecon', str(nss)])
    require(digest(password_auth) == before_auth and nss.read_bytes() == before_nss
            and digest(KDE) == before_kde, 'fingerprint fixture did not restore exact baseline')
    return {'native_authselect_unsafe_fingerprint_graph': True,
            'specific_parallel_fingerprint_faillock_refusal': True,
            'kde_unchanged': True, 'exact_default_profile_restored': True}


def legacy_prepare(_secrets):
    require(not Path('/var/lib/localpin-accounts/registry').exists(),
            'legacy fixture requires no prior managed account domain')
    require(digest(KDE) == private_json(WORK / 'install.json')['stock_kde_sha256'],
            'legacy fixture requires exact stock policy')
    before = private_json(WORK / 'ui.json').get('baseline', {}).get('binding', {})
    current = binding()
    require(all(before.get(key) == current[key] for key in ('boot_id', 'kde_sha256')),
            'actual original full-password desktop recovery must be tested first')
    prefix = (b'# BEGIN local screen-unlock PIN\nauth sufficient pam_pinlock.so retries=1\n'
              b'# END local screen-unlock PIN\n')
    original = KDE.read_bytes()
    backup = WORK / 'legacy-stock.saved'
    require(not backup.exists(), 'existing legacy fixture needs review')
    descriptor = os.open(backup, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, 'wb') as stream:
        stream.write(original)
        stream.flush()
        os.fsync(stream.fileno())
    sync_directory(WORK)
    KDE.write_bytes(prefix + original)
    command(['restorecon', str(KDE)])
    return {'exact_legacy_owned_prefix_staged': True, 'old_verifier_imported': False,
            'new_localpin_module_not_stacked': b'pam_localpin' not in KDE.read_bytes()}


def legacy_migrate(_secrets):
    require(private_json(WORK / 'ui.json').get('legacy-password', {}).get('binding') == binding(),
            'actual legacy-stack original full-password route must be tested first')
    before = KDE.read_bytes()
    admin('migrate-legacy', '--dry-run')
    require(KDE.read_bytes() == before, 'legacy migration dry-run changed policy')
    admin('migrate-legacy')
    require(KDE.read_bytes() == (WORK / 'legacy-stock.saved').read_bytes(),
            'legacy migration failed exact original password policy restoration')
    require(not list(Path('/var/lib/localpin/users').glob('*/generation-*/credential')),
            'legacy migration unexpectedly imported or created credentials')
    return {'dry_run_unchanged': True, 'exact_original_password_policy_restored': True,
            'old_owned_block_removed': True, 'old_verifier_imported': False}


def reboot_prepare(_secrets):
    require(not FAULT.exists() and not locked(), 'repair faults and unlock desktop before reboot')
    require(status()['enrolled_backend'] == 'tpm2' and status()['availability'] == 'available',
            'available native TPM enrollment required')
    value = {'boot_id': boot_id(), 'credentials': credentials(), 'tally': tally(), 'throttle': throttle(),
             'kde_sha256': digest(KDE)}
    require(value['tally'] is not None, 'persistent native tally absent')
    sync_json(WORK / 'reboot.json', value)
    return {'private_same_enrollment_snapshot_durable': True,
            'actual_tpm_enrollment': True, 'reboot_requested': False}


def reboot_verify(secrets):
    before = private_json(WORK / 'reboot.json')
    require(boot_id() != before['boot_id'], 'actual reboot required')
    require(credentials() == before['credentials'] and digest(KDE) == before['kde_sha256'],
            'account/credential/policy identity changed across reboot')
    require(tally() == before['tally'], 'native password tally changed or disappeared across reboot')
    require(throttle() == before['throttle'], 'committed throttle changed across ordinary reboot')
    require(status()['availability'] == 'available' and status()['enrolled_backend'] == 'tpm2',
            'same TPM enrollment unavailable after reboot')
    rows = pam(secrets[NAME]['pin'])
    require(len(rows) == 1 and rows[0]['auth'] == rows[0]['setcred'] == 0 and rows[0]['prompts'] == 1,
            'same native TPM enrollment failed through actual KDE PAM after reboot')
    require(credentials() == before['credentials'], 'verification replaced original enrollment')
    return {'boot_changed': True, 'same_registry_active_pointer_and_credential': True,
            'persistent_native_tally_unchanged': True, 'committed_throttle_unchanged_before_pin': True,
            'native_tpm_kde_pam_granted': True,
            'fresh_enrollment_performed': False, 'pam': rows[0]}


CACHE_PROTECTED = ['/etc/pam.d', '/etc/authselect', '/etc/security']
CACHE_PROTECTED += ['/etc/' + name for name in ('passwd', 'shadow', 'group', 'gshadow', 'environment')]
CACHE_PROTECTED += ['/etc/pam.d/' + name for name in ('kde', 'localpin-enroll', 'localpin-eligibility')]
CACHE_PROTECTED += ['/etc/authselect/' + name for name in ('password-auth', 'postlogin', 'nsswitch.conf')]
CACHE_PROTECTED += ['/etc/security/' + name for name in ('faillock.conf', 'pam_env.conf')]


def immutable(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        flags = array.array('I', [0])
        fcntl.ioctl(descriptor, 0x80086601, flags, True)  # FS_IOC_GETFLAGS, read only.
        return bool(flags[0] & 0x10)
    finally:
        os.close(descriptor)


def cache_window_closed_authority():
    manifest = private_json(Path('/var/lib/localpin-integration/control/manifest.json'))
    require(manifest['phase'] == 'suspended' and manifest.get('cache_window') is True,
            'explicit interrupted package cache window required')
    require(Path('/var/lib/localpin-accounts/registry').read_bytes() == b'LPACCT02\0\0\0\0',
            'cache window did not durably revoke account authority')
    require(not immutable('/etc') and all(immutable(path) for path in CACHE_PROTECTED),
            'cache window released protected inputs beyond the /etc directory')
    require(json.loads(admin('status').stdout)['gate'] == 'disabled', 'cache window reopened gate')


def cache_interrupt(_secrets):
    require(not FAULT.exists() and not locked(), 'repair fault/unlock desktop first')
    require(status()['availability'] == 'available' and status()['enrolled_backend'] == 'tpm2',
            'native TPM enrollment required before interruption')
    require(immutable('/etc') and all(immutable(path) for path in CACHE_PROTECTED),
            'complete immutable baseline required')
    sync_json(WORK / 'cache-interrupt.json', {'boot_id': boot_id(), 'credentials': credentials(), 'throttle': throttle(),
              'tally': tally(), 'kde_sha256': digest(KDE)})
    admin('package-suspend')
    admin('package-cache-begin')
    cache_window_closed_authority()
    require(credential_records() == private_json(WORK / 'cache-interrupt.json')['credentials']['records'],
            'cache interruption changed TPM credential bytes')
    require(throttle() == private_json(WORK / 'cache-interrupt.json')['throttle'],
            'cache interruption changed committed throttle state')
    return {'account_authority_revoked': True, 'only_etc_directory_released': True,
            'protected_inputs_still_immutable': True, 'credential_unchanged': True,
            'activation_gate_disabled': True, 'reboot_requested': False}


def cache_reboot_verify(_secrets):
    before = private_json(WORK / 'cache-interrupt.json')
    require(boot_id() != before['boot_id'], 'actual mid-window reboot required')
    cache_window_closed_authority()
    require(credential_records() == before['credentials']['records'] and tally() == before['tally']
            and throttle() == before['throttle']
            and digest(KDE) == before['kde_sha256'], 'mid-window reboot changed protected state')
    result = command(user_command('/usr/libexec/localpin/m8-client', 'status'), check=False)
    require(result.returncode != 0 or json.loads(result.stdout).get('availability') != 'available',
            'interrupted cache window recovered account authority without explicit completion')
    return {'boot_changed': True, 'authority_remains_revoked_before_explicit_resume': True,
            'pin_unavailable': True, 'credential_and_native_tally_unchanged': True,
            'protected_inputs_still_immutable': True, 'selinux': 'Enforcing'}


def cache_resume(_secrets):
    before = private_json(WORK / 'cache-interrupt.json')
    require(boot_id() != before['boot_id'], 'actual mid-window reboot required')
    cache_window_closed_authority()
    admin('package-resume')
    after = credentials()
    require({key: value for key, value in after.items() if key != 'registry'}
            == {key: value for key, value in before['credentials'].items() if key != 'registry'},
            'explicit cache completion changed original credential/incarnation authority')
    require(immutable('/etc') and all(immutable(path) for path in CACHE_PROTECTED),
            'cache completion did not restore full immutable boundary')
    require(tally() == before['tally'] and throttle() == before['throttle']
            and digest(KDE) == before['kde_sha256'],
            'cache completion changed protected policy or tally')
    require(status()['availability'] == 'available' and status()['enrolled_backend'] == 'tpm2',
            'explicit cache completion did not recover same TPM enrollment')
    require(json.loads(admin('status').stdout)['gate'] == 'disabled',
            'explicit cache completion enabled desktop without new tests')
    sync_json(WORK / 'ui.json', {})
    return {'same_tpm_enrollment_available': True, 'same_account_ids': True,
            'committed_throttle_unchanged': True,
            'registry_authority_except_etc_metadata_unchanged': True,
            'protected_inputs_immutable': True, 'fresh_enrollment_performed': False,
            'activation_gate_disabled_pending_retest': True}


def locked_tally(secrets):
    require(status()['availability'] == 'available', 'native tally permit baseline unavailable')
    before = credentials()
    rows = []
    for _ in range(3):
        previous = tally()
        result = command(user_command('/usr/libexec/localpin/m8-client', 'disable'),
                         data=framed('not-the-disposable-password'), check=False, timeout=75)
        require(result.returncode != 0 and tally() != previous,
                'actual private-password failure did not produce native failure accounting')
        rows.append({'actual_wrong_password_denied': True, 'native_tally_changed': True})
    observed = status()
    require(observed['availability'] != 'available', 'locked native tally did not disable PIN eligibility')
    result = command(user_command('/usr/libexec/localpin/m8-client', 'verify'),
                     data=framed(secrets[NAME]['pin']), check=False, timeout=15)
    require(result.stdout.strip() != b'Granted' and credentials() == before,
            'locked native tally authorized PIN or changed enrolled identity')
    # Leave the actual native failures intact through disable/uninstall. The
    # reviewed default KDE graph can still admit a full password; this fixture
    # must not claim that an absent original auth-phase lockout exists.
    return {'native_preauth_permit_before_failures': True, 'actual_password_failures': rows,
            'native_locked_tally_denies_pin': True, 'same_enrollment_retained': True,
            'native_tally_reset_performed': False,
            'availability_after': observed['availability'], 'reason_after': observed.get('reason')}


def disable(_secrets):
    before = digest(KDE)
    admin('disable', '--dry-run')
    require(digest(KDE) == before, 'disable dry-run mutated policy')
    admin('disable')
    require(digest(KDE) == private_json(WORK / 'install.json')['stock_kde_sha256'],
            'disable did not restore exact original KDE policy')
    require(command(['systemctl', 'is-enabled', 'localpin.socket'], check=False).stdout.strip() == b'disabled',
            'disable retained socket boot opt-in')
    return {'dry_run_unchanged': True, 'exact_original_kde_restored': True,
            'socket_boot_opt_in_disabled': True, 'persistent_tally_retained': TALLY.exists()}


def recover(_secrets):
    admin('recover')
    require(digest(KDE) == private_json(WORK / 'install.json')['stock_kde_sha256'],
            'recovery did not restore original KDE policy')
    require(command(['systemctl', 'is-enabled', 'localpin.socket'], check=False).stdout.strip() == b'disabled',
            'recovery retained socket boot opt-in')
    return {'text_console_recovery_completed': True, 'exact_original_kde_restored': True,
            'socket_boot_opt_in_disabled': True}


def uninstall(_secrets):
    before = digest(KDE)
    stock = private_json(WORK / 'install.json')['stock_kde_sha256']
    require(before in (stock, 'ea0adc6291dccb0360f5d3565c5dad1f8b886d037f0bcadbbfbf70625383375d'),
            'erase fixture requires exact stock or exact active owned KDE policy')
    before_tally = tally()
    command(['rpm', '-e', 'localpin'], timeout=180)
    require(not rpm_installed() and digest(KDE) == stock, 'uninstall did not preserve/restore exact stock KDE policy')
    require(not MODULE.exists(), 'PAM module remained after RPM erase')
    require(Path('/var/lib/localpin-accounts/registry').read_bytes() == b'LPACCT02\0\0\0\0',
            'erase left account authority live')
    require(tally() == before_tally, 'erase changed native password accounting')
    return {'package_removed': True, 'restored_kde_unchanged': True,
            'active_owned_route_restored_before_module_removal': before != stock,
            'module_removed': True, 'authority_revoked': True,
            'native_tally_unchanged': True, 'persistent_tally_retained': TALLY.exists()}


def refusal_matrix(_secrets):
    require(rpm_installed() and not Path('/var/lib/localpin-accounts/registry').exists(),
            'refusal matrix requires installed unprepared baseline')
    before = KDE.read_bytes()
    require(not FAULT.exists(), 'repair existing fixture first')
    backup = WORK / 'kde.refusal.saved'
    require(not backup.exists(), 'existing refusal backup needs review')
    # Durable exact backup precedes the one synthetic changed-file case. This
    # is the disposable guest's policy, never the host policy or generated PAM.
    descriptor = os.open(backup, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, 'wb') as stream:
        stream.write(before)
        stream.flush()
        os.fsync(stream.fileno())
    sync_directory(WORK)
    changed = before + b'\n# disposable M8 unknown-layout fixture\n'
    try:
        KDE.write_bytes(changed)
        result = admin('prepare', '--uid', str(UID), '--dry-run', check=False)
        require(result.returncode != 0 and KDE.read_bytes() == changed,
                'unknown-layout dry-run did not refuse without mutation')
    finally:
        require(KDE.read_bytes() == changed, 'changed refusal fixture needs manual review')
        KDE.write_bytes(before)
        command(['restorecon', str(KDE)])
    require(KDE.read_bytes() == backup.read_bytes(), 'refusal backup restoration differs')
    backup.unlink()
    # Missing component must refuse before any enrollment/policy mutation.
    saved = WORK / 'pam_localpin.so.refusal.saved'
    require(not saved.exists(), 'existing component refusal backup needs review')
    MODULE.rename(saved)
    try:
        result = admin('prepare', '--uid', str(UID), '--dry-run', check=False)
        require(result.returncode != 0 and KDE.read_bytes() == before,
                'missing-component dry-run did not refuse without policy mutation')
    finally:
        require(not MODULE.exists(), 'unexpected module while restoring refusal fixture')
        saved.rename(MODULE)
        command(['restorecon', str(MODULE)])
    require(not Path('/var/lib/localpin-accounts/registry').exists(), 'refusal tests created enrollment')
    return {'changed_kde_refused_without_mutation': True,
            'missing_module_refused_without_mutation': True, 'exact_components_restored': True}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('phase', choices=PHASES)
    parser.add_argument('--expected-uuid', required=True, type=lambda value: str(uuid.UUID(value)))
    parser.add_argument('--disposable-vm-confirmed', action='store_true', required=True)
    parser.add_argument('--emulated-tpm-confirmed', action='store_true', required=True)
    args = parser.parse_args()
    secrets = guard(args.expected_uuid)
    result = globals()[args.phase.replace('-', '_')](secrets)
    require(command(['getenforce']).stdout.strip() == b'Enforcing', 'SELinux changed')
    value = {'phase': args.phase, 'passed': True, 'selinux': 'Enforcing', 'observations': result}
    path = WORK / 'evidence.json'
    evidence = private_json(path) if path.exists() else {}
    evidence[args.phase] = value
    sync_json(path, evidence)
    print(json.dumps(value, indent=2))


if __name__ == '__main__':
    main()
