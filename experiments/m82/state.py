#!/usr/bin/python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Private byte checkpoints and installed Busy proof in the guarded M8 clone.

Stage beside run.py and guard.py. A topology-verified host must guard every
invocation. No checkpoint hashes or account/credential bytes leave guest root.
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

WORK = Path('/root/localpin-m8')
ROOTS = ('/var/lib/localpin', '/var/lib/localpin-accounts',
         '/var/lib/localpin-integration', '/var/lib/faillock')
FILES = ('/etc/passwd', '/etc/group', '/etc/shadow', '/etc/gshadow',
         '/etc/security/faillock.conf', '/etc/pam.d/kde', '/etc/pam.d/kde-fingerprint',
         '/etc/pam.d/localpin-enroll', '/etc/pam.d/localpin-eligibility',
         '/etc/pam.d/localpin-kde-password', '/etc/pam.d/localpin-kde-fingerprint')


def require(value, message):
    if not value:
        raise RuntimeError(message)


def checkpoint(case):
    require(re.fullmatch('[a-z0-9][a-z0-9-]{0,47}', case) is not None, 'invalid case')
    return WORK / ('m82-state-' + case + '.json')


def snapshot():
    paths = [Path(path) for path in FILES]
    for root in ROOTS:
        path = Path(root)
        if path.exists():
            paths.extend(sorted(path.rglob('*')))
    result = {}
    for path in paths:
        if not path.exists():
            result[str(path)] = None
            continue
        info = path.lstat()
        require(not stat.S_ISLNK(info.st_mode), 'unexpected checkpoint symlink')
        if stat.S_ISREG(info.st_mode):
            require(info.st_size <= 1024 * 1024, 'oversized checkpoint record')
            result[str(path)] = {'sha256': hashlib.sha256(path.read_bytes()).hexdigest(),
                                 'uid': info.st_uid, 'gid': info.st_gid,
                                 'mode': stat.S_IMODE(info.st_mode)}
        else:
            require(stat.S_ISDIR(info.st_mode), 'unexpected checkpoint record type')
    result['services'] = {
        unit: {kind: m.command(['systemctl', kind, unit], check=False).stdout.decode().strip()
               for kind in ('is-active', 'is-enabled')}
        for unit in ('localpin.socket', 'localpin.service')}
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('save', 'same', 'busy'))
    parser.add_argument('--case', required=True)
    parser.add_argument('--expected-uuid', required=True)
    parser.add_argument('--disposable-vm-confirmed', action='store_true', required=True)
    parser.add_argument('--emulated-tpm-confirmed', action='store_true', required=True)
    args = parser.parse_args()
    global m
    sys.path.insert(0, str(WORK))
    import run as m
    m.guard(args.expected_uuid)
    path = checkpoint(args.case)
    if args.action == 'save':
        require(not path.exists(), 'existing checkpoint must be reviewed')
        m.sync_json(path, snapshot())
        result = {'private_checkpoint_saved': True}
    elif args.action == 'same':
        require(snapshot() == m.private_json(path), 'protected bytes or service state changed')
        result = {'protected_bytes_ownership_modes_and_services_equal': True}
    else:
        lock = Path('/var/lib/localpin-integration/control/lock')
        info = lock.lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_uid == info.st_gid == 0
                and info.st_nlink == 1 and stat.S_IMODE(info.st_mode) == 0o600,
                'unsafe installed integration lock')
        before = snapshot()
        outcomes = []
        descriptor = os.open(lock, os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW)
        try:
            opened = os.fstat(descriptor)
            require((opened.st_dev, opened.st_ino) == (info.st_dev, info.st_ino),
                    'integration lock replaced')
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            for command in (['begin-mutation'], ['seal', '--uid', '21062'],
                            ['recover', '--uid', '21062'], ['cache-window-begin'],
                            ['cache-window-finish']):
                completed = m.command([m.ACCOUNT, *command], check=False)
                require(completed.returncode != 0 and b'Busy' in completed.stderr,
                        'native account mutation did not refuse Busy')
                require(snapshot() == before, 'Busy command changed protected state')
                outcomes.append({'operation': command[0], 'busy': True, 'state_equal': True})
        finally:
            os.close(descriptor)
        result = {'installed_native_mutations': outcomes, 'production_locking_unchanged': True}
    print(json.dumps({'phase': 'm82-state-' + args.action, 'case': args.case,
                      'passed': True, 'selinux': 'Enforcing', 'observations': result,
                      'runner_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}))


if __name__ == '__main__':
    main()
