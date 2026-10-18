#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Pinned dispatcher for test-only credential cases in the independent M8 clone."""
import argparse
import ipaddress
import importlib.util
import json
from pathlib import Path
import re
import shlex
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'm8'))
from host import Host
from guard import require

spec = importlib.util.spec_from_file_location('flexible_matrix_cases', Path(__file__).with_name('matrix.py'))
matrix = importlib.util.module_from_spec(spec)
spec.loader.exec_module(matrix)


def public_result(value, case, evr):
    """Reject unknown fields rather than accidentally exporting a guest secret."""
    allowed = {'phase', 'passed', 'case', 'candidate', 'kind', 'backend', 'length',
               'policy_version', 'credential_version', 'mutation', 'installed_cli_pty',
               'production_broker_verified', 'separate_native_failure_history_preserved',
               'fresh_bounded_trial_open', 'selinux', 'credential_committed',
               'postcommit_availability', 'verification_pending', 'observation_only'}
    require(isinstance(value, dict) and set(value) == allowed, 'unexpected result fields')
    kind, backend, length = matrix.CASES[case]
    require(value['phase'] == 'flexible-installed-case' and value['case'] == case
            and value['candidate'] == evr and value['kind'] == kind
            and value['backend'] == backend and value['length'] == length
            and value['policy_version'] == 1 and value['credential_version'] == 2
            and value['mutation'] in ('change', 'enroll-tpm', 'enroll-software',
                                      'migrate-tpm', 'migrate-software')
            and value['selinux'] == 'Enforcing', 'result identity disagrees')
    require(value['credential_committed'] is True and value['separate_native_failure_history_preserved'] is True
            and value['postcommit_availability'] in ('available', 'cooldown')
            and type(value['observation_only']) is bool, 'commit observation invalid')
    pending = value['verification_pending']
    require(type(pending) is bool and (not pending or value['postcommit_availability'] == 'cooldown'),
            'invalid verification state')
    for field in ('passed', 'production_broker_verified', 'fresh_bounded_trial_open'):
        require(value[field] is (not pending), 'verification result disagrees with pending state')
    terminal = value['installed_cli_pty']
    require(isinstance(terminal, dict) and set(terminal) == {
        'operation', 'kind', 'length', 'actual_installed_cli', 'real_controlling_terminal',
        'preparation_before_password', 'masked_new_input_observed', 'secret_echo_absent',
        'private_prompt_count', 'exit_success'}, 'unexpected terminal result fields')
    require(terminal['operation'] == value['mutation'] and terminal['kind'] == kind
            and terminal['length'] == length and terminal['private_prompt_count'] == 5,
            'terminal case identity disagrees')
    for field in ('actual_installed_cli', 'real_controlling_terminal', 'preparation_before_password',
                  'masked_new_input_observed', 'secret_echo_absent', 'exit_success'):
        require(terminal[field] is True, 'terminal case did not pass')
    return value


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('case', choices=tuple(matrix.CASES))
    parser.add_argument('--observe-only', action='store_true')
    parser.add_argument('--expected-localpin-evr', required=True)
    parser.add_argument('--address', required=True, type=lambda value: str(ipaddress.IPv4Address(value)))
    parser.add_argument('--access-dir', required=True, type=lambda value: Path(value).resolve())
    parser.add_argument('--disposable-vm-confirmed', action='store_true', required=True)
    parser.add_argument('--emulated-tpm-confirmed', action='store_true', required=True)
    args = parser.parse_args()
    require(re.fullmatch(r'[A-Za-z0-9._+~^:-]{1,128}', args.expected_localpin_evr) is not None,
            'invalid package identity')
    import libvirt
    host = Host(args, libvirt)
    try:
        host.guard()
        remote_args = ['python3', '/root/localpin-m8/flexible-matrix.py', args.case,
                             '--expected-uuid', host.uuid,
                             '--expected-localpin-evr', args.expected_localpin_evr,
                             '--disposable-vm-confirmed', '--emulated-tpm-confirmed']
        if args.observe_only:
            remote_args.append('--observe-only')
        remote = shlex.join(remote_args)
        command = ['ssh', '-F', '/dev/null', '-o', 'BatchMode=yes', '-o', 'IdentitiesOnly=yes',
                   '-o', 'StrictHostKeyChecking=yes', '-o', 'GlobalKnownHostsFile=/dev/null',
                   '-o', 'UserKnownHostsFile=' + str(args.access_dir / 'known_hosts'),
                   '-o', 'ConnectTimeout=8', '-o', 'ServerAliveInterval=5',
                   '-o', 'ServerAliveCountMax=2', '-i', str(args.access_dir / 'id_ed25519'),
                   'root@' + args.address, remote]
        result = subprocess.run(command, capture_output=True, timeout=120)
        host.guard()
        require(result.returncode == 0 and len(result.stdout) <= 65536,
                'guest case refused; inspect only guest-root-private evidence')
        print(json.dumps(public_result(json.loads(result.stdout), args.case, args.expected_localpin_evr), indent=2))
    finally:
        host.connection.close()


if __name__ == '__main__':
    main()
