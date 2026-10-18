#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Guest-root flexible-credential cases for the independently guarded M8 clone.

Stage beside M8 run.py/guard.py. Test-only secret injection targets the private
PTY fixture; the installed CLI still reads its actual controlling terminal.
No automatic desktop attestation or activation is performed.
"""
import argparse
import json
import os
from pathlib import Path
import secrets
import stat
import string
import sys

CASES = {
    'software10': ('numeric-pin', 'software', 10),
    'software8': ('numeric-pin', 'software', 8),
    'software16': ('numeric-pin', 'software', 16),
    'spaced-software': ('passcode', 'software', 16),
    'digit-passcode': ('passcode', 'software', 12),
    'long-software': ('passcode', 'software', 64),
    'overlap-software': ('passcode', 'software', 30),
    'tpm4': ('numeric-pin', 'tpm2', 4),
    'tpm16': ('numeric-pin', 'tpm2', 16),
    'spaced-tpm': ('passcode', 'tpm2', 16),
}


def predictable(value):
    repeated = any(len(value) >= 2 * period and len(value) % period == 0
                   and all(char == value[index % period] for index, char in enumerate(value))
                   for period in range(1, 5))
    sequence = value.isascii() and value.isdigit() and any(
        all((ord(left) - 48 + step) % 10 == ord(right) - 48
            for left, right in zip(value, value[1:])) for step in (1, 9))
    return repeated or sequence or value.lower() in {
        'password', 'password1', 'password123', 'qwerty123', 'qwertyuiop',
        'letmein123', 'welcome1', 'iloveyou', 'changeme', 'localpin'}


def numeric(length):
    while True:
        value = '0' + ''.join(secrets.choice(string.digits) for _ in range(length - 1))
        if not predictable(value):
            return value


def create_cases(m):
    path = m.WORK / 'flexible-cases.private.json'
    if path.exists():
        return m.private_json(path)['cases']
    values = {}
    for name, (kind, backend, length) in CASES.items():
        if kind == 'numeric-pin' or name == 'digit-passcode':
            value = numeric(length)
        elif name.startswith('spaced-'):
            value = '  ' + ''.join(secrets.choice(string.ascii_lowercase) for _ in range(length - 4)) + '  '
        else:
            value = ''.join(secrets.choice(string.ascii_lowercase) for _ in range(length))
        while predictable(value):
            value = ''.join(secrets.choice(string.ascii_lowercase) for _ in range(length))
        values[name] = {'kind': kind, 'backend': backend, 'secret': value}
    m.sync_json(path, {'schema': 1, 'cases': values})
    return values


def native_history(m):
    # This is the separately retained genuine native rejection, never an empty
    # replacement or a synthetic serialized faillock record.
    expected = m.private_json(m.WORK / 'm83-native-history-private.json')
    path = Path('/var/lib/faillock/lp61other')
    info = path.lstat()
    m.require(path.read_bytes() == bytes.fromhex(expected['bytes'])
              and info.st_uid == expected['uid'] and info.st_gid == 0
              and stat.S_IMODE(info.st_mode) == expected['mode']
              and {name: os.getxattr(path, name).hex() for name in os.listxattr(path)} == expected['xattrs'],
              'separate genuine native failure history changed')


def complete_case(m, private, name, checkpoint, *, observation_only):
    native_history(m)
    m.require(checkpoint['boot'] == m.boot_id()
              and Path('/var/lib/localpin/users/21061/active').read_bytes().hex() == checkpoint['active'],
              'committed generation or boot changed before observation')
    result = checkpoint['result']
    status = m.status()
    expected = {'kind': result['kind'], 'length': result['length'], 'policy_version': 1}
    m.require(status['enrolled_backend'] == result['backend'] and status['credential_profile'] == expected
              and status['availability'] in ('available', 'cooldown'), 'committed profile is unavailable')
    result['observation_only'] = observation_only
    if status['availability'] == 'cooldown':
        # A committed replacement can retain the prior cooldown. Do not repeat
        # the mutation, reset state or claim verification/desktop acceptance.
        return result
    value = create_cases(m)[name]
    verification = m.command(m.user_command('/usr/libexec/localpin/m8-client', 'verify'),
                             data=m.framed(value['secret']), timeout=15)
    m.require(verification.stdout.strip() == b'Granted', 'committed credential failed real broker verification')
    native_history(m)
    m.trial(private)
    result.update(passed=True, production_broker_verified=True,
                  verification_pending=False, fresh_bounded_trial_open=True)
    m.sync_json(m.WORK / ('flexible-case-' + name + '.json'), result)
    return result


def run_case(m, private, name, *, observe_only=False):
    native_history(m)
    result_path = m.WORK / ('flexible-case-' + name + '.json')
    m.require(not result_path.exists(), 'case already completed; preserve its observation')
    committed = m.WORK / ('flexible-case-' + name + '-committed.private.json')
    if observe_only:
        return complete_case(m, private, name, m.private_json(committed), observation_only=True)
    value = create_cases(m)[name]
    kind, backend, length = CASES[name]
    m.require(value['kind'] == kind and value['backend'] == backend
              and len(value['secret']) == length and not predictable(value['secret']),
              'private case metadata/predictability disagrees')
    intent = m.WORK / ('flexible-case-' + name + '-intent.private.json')
    m.require(not intent.exists(), 'case already attempted; wait/observe without repeating its mutation')
    m.sync_json(intent, {'case': name, 'boot': m.boot_id(), 'candidate': 'recorded before mutation'})
    current = m.status()
    operation = ('enroll-tpm' if backend == 'tpm2' else 'enroll-software') if current['enrolled'] is False else (
        'change' if current['enrolled_backend'] == backend else
        'migrate-tpm' if backend == 'tpm2' else 'migrate-software')
    response = m.command(m.user_command('python3', '/usr/libexec/localpin/flexible-pty.py',
                                      operation, '--kind', kind),
                         data=m.framed(private[m.NAME]['password']) + m.framed(value['secret']), timeout=100)
    terminal = json.loads(response.stdout)
    m.require(terminal['exit_success'] and terminal['secret_echo_absent']
              and terminal['masked_new_input_observed'] and terminal['preparation_before_password'],
              'installed private terminal case did not pass')
    status = m.status()
    m.require(status['availability'] in ('available', 'cooldown') and status['enrolled_backend'] == backend
              and status['credential_profile'] == {'kind': kind, 'length': length, 'policy_version': 1}
              and status['credential_upgrade_recommended'] is False,
              'committed profile disagrees with selected case')
    m.sync_json(m.WORK / 'flexible-current.private.json', {'schema': 1, **value})
    result = {'phase': 'flexible-installed-case', 'passed': False, 'case': name,
              'candidate': m.command(['rpm', '-q', '--qf', '%{EVR}', 'localpin']).stdout.decode(),
              'kind': kind, 'backend': backend, 'length': length, 'policy_version': 1,
              'credential_version': 2, 'mutation': operation, 'installed_cli_pty': terminal,
              'credential_committed': True, 'postcommit_availability': status['availability'],
              'verification_pending': True, 'observation_only': False,
              'production_broker_verified': False, 'separate_native_failure_history_preserved': True,
              'fresh_bounded_trial_open': False, 'selinux': 'Enforcing'}
    checkpoint = {'boot': m.boot_id(), 'active': Path('/var/lib/localpin/users/21061/active').read_bytes().hex(),
                  'result': result}
    m.sync_json(committed, checkpoint)
    return complete_case(m, private, name, checkpoint, observation_only=False)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('case', choices=tuple(CASES))
    parser.add_argument('--observe-only', action='store_true')
    parser.add_argument('--expected-uuid', required=True)
    parser.add_argument('--expected-localpin-evr', required=True)
    parser.add_argument('--disposable-vm-confirmed', action='store_true', required=True)
    parser.add_argument('--emulated-tpm-confirmed', action='store_true', required=True)
    args = parser.parse_args()
    sys.path.insert(0, '/root/localpin-m8')
    import run as m
    private = m.guard(args.expected_uuid)
    m.require(m.command(['rpm', '-q', '--qf', '%{EVR}', 'localpin']).stdout.decode()
              == args.expected_localpin_evr, 'installed candidate changed')
    print(json.dumps(run_case(m, private, args.case, observe_only=args.observe_only)))


if __name__ == '__main__':
    main()
