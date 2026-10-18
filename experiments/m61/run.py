#!/usr/bin/env python3
"""M6.1 real-account evidence runner, ONLY inside an explicitly guarded Fedora VM.

No host namespace substitutes, fixture authorities, physical TPM or KDE adapter.
The default guard refuses every TPM; M7 alone can explicitly opt into a private
libvirt emulator after independently checking its clone and emulator markers.
The operator supplies an independent clone, actual built binaries in work/bin,
and dedicated secrets in work/secrets.json (never exported). See README.md.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import struct
import subprocess
import time
import uuid

WORK = Path('/root/localpin-m61')
UID = 21061
OTHER = 21062
NAME = 'lp61test'
ACCOUNT = '/usr/libexec/localpin/localpin-account'
PROBE = '/usr/libexec/localpin/m61-client'


def require(value, message):
    if not value:
        raise RuntimeError(message)


def command(args, *, data=None, check=True, timeout=30):
    result = subprocess.run(args, input=data, capture_output=True, timeout=timeout)
    if check:
        require(result.returncode == 0, 'command failed: ' + args[0] + ': ' + result.stderr.decode(errors='replace')[:1000])
    return result


def emulated_tpm_guard():
    """M7-only private emulator opt-in; host XML validation remains independent."""
    require(os.getuid() == os.geteuid() == 0, 'guest root required')
    marker = Path('/run/localpin-m7-emulator')
    parent = marker.parent.lstat()
    require(stat.S_ISDIR(parent.st_mode) and parent.st_uid == 0 and not parent.st_mode & 0o022,
            'unsafe emulator marker directory')
    info = marker.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_uid == 0
            and stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1,
            'unsafe private emulator marker')
    dmi_uuid = str(uuid.UUID(Path('/sys/class/dmi/id/product_uuid').read_text().strip()))
    require(marker.read_text() == dmi_uuid + '\nemulator2.0\n', 'emulator marker mismatch')


def validate_secrets(secrets):
    """Validate fresh software fixtures without printing private input values."""
    require(isinstance(secrets, dict), 'invalid dedicated secret schema')
    for name, uid in ((NAME, UID), ('lp61other', OTHER)):
        account = secrets.get(name)
        require(isinstance(account, dict) and account.get('uid') == uid,
                'invalid dedicated account schema')
        password = account.get('password')
        require(isinstance(password, str) and 0 < len(password.encode()) <= 512,
                'invalid private fixture password')
        for key in ('pin', 'new_pin'):
            value = account.get(key)
            require(isinstance(value, str) and re.fullmatch('[0-9]{8,16}', value) is not None,
                    'fresh software fixture PINs require 8–16 ASCII digits; use new guest-only inputs')
        require(account['pin'] != account['new_pin'], 'rotation requires distinct fixture PINs')
    return secrets


def guard(*, allow_emulated_tpm=False):
    require(os.getuid() == os.geteuid() == 0, 'guest root required')
    marker = Path('/run/localpin-m61-guard')
    info = marker.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022, 'unsafe clone guard')
    require(marker.read_text().strip().lower() == Path('/sys/class/dmi/id/product_uuid').read_text().strip().lower(), 'clone UUID mismatch')
    require(command(['getenforce']).stdout.strip() == b'Enforcing', 'SELinux must remain enforcing')
    require(command(['systemd-detect-virt', '--vm']).stdout.strip() == b'kvm', 'dedicated KVM clone required')
    os_release = Path('/etc/os-release').read_text()
    require('VERSION_ID=44' in os_release and 'VARIANT_ID=kde' in os_release, 'Fedora 44 KDE required')
    if allow_emulated_tpm:
        emulated_tpm_guard()
    else:
        require(not Path('/dev/tpm0').exists() and not Path('/dev/tpmrm0').exists(),
                'no TPM may be attached')
    secret = WORK / 'secrets.json'
    info = secret.stat()
    require(info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0o600, 'private dedicated secrets required')
    return validate_secrets(json.loads(secret.read_text()))


def frame(value):
    data = value.encode() if isinstance(value, str) else value
    require(len(data) <= 512, 'oversized fixture input')
    return struct.pack('>H', len(data)) + data


def user_command(operation):
    return ['runuser', '-u', NAME, '--', 'env', f'XDG_RUNTIME_DIR=/run/user/{UID}',
            f'DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/{UID}/bus',
            'systemd-run', '--user', '--quiet', '--collect', '--wait', '--pipe',
            '--unit=localpin-m61-' + uuid.uuid4().hex, PROBE, operation]


def client(operation, *inputs, check=True):
    return command(user_command(operation), data=b''.join(frame(value) for value in inputs), check=check, timeout=70)


def status():
    return json.loads(client('status').stdout)


def worker(uid=UID):
    token = os.urandom(16)
    result = command(['/usr/libexec/localpin/localpin-eligibility-worker'],
                     data=b'LPE1' + token + struct.pack('>I', uid))
    # The private codec is length-prefixed; only the terminal outcome is exported.
    output = result.stdout
    require(len(output) >= 24 and output[-1] in (0, 1, 2) and token in output, 'invalid policy worker result')
    return output[-1]


def stop():
    command(['systemctl', 'stop', 'localpin-m61.socket', 'localpin-m61.service'])


def start():
    # Repeated component matrices intentionally restart these clone-only units.
    # On a fresh clone systemd may not have loaded these units yet; reset-failed
    # then reports "not loaded". The following start still validates both units.
    command(['systemctl', 'reset-failed', 'localpin-m61.socket', 'localpin-m61.service'], check=False)
    command(['systemctl', 'start', 'localpin-m61.socket', 'localpin-m61.service'])


def reseal():
    stop()
    command([ACCOUNT, 'seal', '--uid', str(UID), '--uid', str(OTHER)])
    start()


def prune_test_quarantines():
    """Explicit clone-only offline maintenance after durable ALL-account revoke."""
    require(Path('/var/lib/localpin-accounts/registry').read_bytes() == b'LPACCT02\0\0\0\0',
            'quarantine maintenance requires durably revoked domain')
    root = Path('/var/lib/localpin/retired')
    if not root.exists(): return
    require(root.is_dir() and not root.is_symlink() and root.stat().st_uid == 0,
            'unsafe quarantine root')
    require(all(entry.name in (str(UID), str(OTHER)) and entry.is_dir() and not entry.is_symlink()
                for entry in root.iterdir()), 'unknown account quarantine')
    shutil.rmtree(root)


def install():
    destination = Path('/usr/libexec/localpin')
    destination.mkdir(mode=0o755, exist_ok=True)
    for name in ['localpind', 'localpin-account', 'localpin-worker', 'localpin-auth-worker',
                 'localpin-eligibility-worker', 'localpinctl', 'm61-client']:
        source = WORK / 'bin' / name
        require(source.is_file(), 'missing built artifact')
        target = destination / name
        target.write_bytes(source.read_bytes())
        target.chmod(0o755)
    for name in ['localpin-enroll', 'localpin-eligibility']:
        target = Path('/etc/pam.d') / name
        target.write_bytes((WORK / 'policy' / (name + '.review-required')).read_bytes())
        target.chmod(0o644)
    nss = Path('/etc/authselect/nsswitch.conf')
    original = nss.read_text()
    updated = re.sub(r'^(passwd|group|shadow):[^\n]*', r'\1: files', original, flags=re.M)
    require(updated != original, 'expected stock NSS baseline')
    nss.write_text(updated)
    for name in ['localpin', 'localpin-accounts']:
        directory = Path('/var/lib') / name
        directory.mkdir(mode=0o700, exist_ok=True)
        directory.chmod(0o700)
    Path('/run/localpin').mkdir(mode=0o755, exist_ok=True)
    Path('/etc/systemd/system/localpin-m61.socket').write_text('''[Unit]
Description=M6.1 disposable component socket
[Socket]
ListenStream=/run/localpin/broker.sock
SocketMode=0666
FileDescriptorName=localpin
[Install]
WantedBy=sockets.target
''')
    Path('/etc/systemd/system/localpin-m61.service').write_text('''[Unit]
Description=M6.1 disposable component broker (M8 confinement not certified)
Requires=localpin-m61.socket
After=localpin-m61.socket systemd-logind.service
[Service]
ExecStart=/usr/libexec/localpin/localpind
User=root
Group=root
LimitCORE=0
KillMode=control-group
TimeoutStopSec=2
''')
    command(['restorecon', '-RF', str(destination), '/var/lib/localpin', '/var/lib/localpin-accounts',
             '/etc/pam.d/localpin-enroll', '/etc/pam.d/localpin-eligibility'])
    command(['systemctl', 'daemon-reload'])
    command([ACCOUNT, 'seal', '--uid', str(UID), '--uid', str(OTHER)])
    start()
    return {'policy_worker': worker(), 'status': status(),
            'filesystem': command(['findmnt', '-no', 'FSTYPE', '-T', '/etc']).stdout.decode().strip()}


def flows(secrets):
    secrets = secrets[NAME]
    password = secrets['password']
    pin = secrets['pin']
    new_pin = secrets['new_pin']
    require(worker() == 0, 'healthy production policy baseline failed')
    before = status()
    require(before['availability'] == 'disabled', 'privileged disabled baseline required')
    require(b'Enrolled(Software)' in client('enroll', password, pin).stdout, 'actual enrollment failed')
    require(client('verify', pin).stdout.strip() == b'Granted', 'production PIN verification failed')
    require(b'Enrolled(Software)' in client('change', password, new_pin).stdout, 'actual rotation failed')
    require(client('verify', pin).stdout.strip() == b'Mismatch', 'old PIN survived rotation')
    require(client('verify', new_pin).stdout.strip() == b'Granted', 'new PIN failed')
    require(client('disable', password).stdout.strip() == b'Disabled', 'own disable failed')
    require(status()['availability'] == 'disabled', 'disable did not persist')
    client('enroll', password, pin)
    recovered = command([PROBE, 'recover', str(UID)])
    require(recovered.stdout.strip() == b'RecoveryDisabled', 'kernel-root recovery failed')
    require(status()['availability'] == 'disabled', 'recovery not authoritative')
    return {'disabled_baseline': True, 'enrollment': True, 'production_pin_success': True,
            'rotation_old_pin_rejected': True, 'own_disable': True, 'root_recovery': True,
            'password_free_healthy': True, 'final_status': status()}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--phase', choices=['install', 'flows'], required=True)
    parser.add_argument('--disposable-vm-confirmed', action='store_true', required=True)
    args = parser.parse_args()
    secrets = guard()
    result = install() if args.phase == 'install' else flows(secrets)
    require(command(['getenforce']).stdout.strip() == b'Enforcing', 'SELinux changed')
    evidence_path = WORK / 'evidence.json'
    evidence = json.loads(evidence_path.read_text()) if evidence_path.exists() else {}
    evidence[args.phase] = result
    evidence_path.write_text(json.dumps(evidence, indent=2) + '\n')
    evidence_path.chmod(0o600)
    print(json.dumps({args.phase: result, 'selinux': 'Enforcing'}, indent=2))


if __name__ == '__main__':
    main()
