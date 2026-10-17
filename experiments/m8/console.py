#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Actual stock KDE keyboard tests with independent M8 host+guest guards.

Reuse only M7's bounded keyboard/greeter-observation algorithms. All domain,
SSH, account, policy, fault and evidence bindings are M8 specific.
"""
import argparse
import importlib.util
import ipaddress
import json
from pathlib import Path
import subprocess
import time

from guard import require
from host import Host

_spec = importlib.util.spec_from_file_location('localpin_m8_reviewed_keyboard',
                                              Path(__file__).resolve().parents[1] / 'm7' / 'console.py')
m7 = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(m7)
PHASES = ('baseline', 'legacy-password', 'pin', 'password', 'recovery', 'selinux-recovery',
          'restricted-recovery', 'suspended-recovery', 'administrative-recovery', 'restored-password',
          'unlock-existing')


def public_observations(value):
    if isinstance(value, dict):
        return {key: public_observations(item) for key, item in value.items() if key != 'sha256'}
    if isinstance(value, list):
        return [public_observations(item) for item in value]
    return value


class Console(m7.Console):
    def __init__(self, args, libvirt):
        self.host = Host(args, libvirt)
        self.args, self.libvirt = args, libvirt
        self.connection, self.domain = self.host.connection, self.host.domain
        self.uuid = self.host.uuid
        self.ssh = ['ssh', '-o', 'BatchMode=yes', '-o', 'IdentitiesOnly=yes',
                    '-o', 'StrictHostKeyChecking=yes', '-o', 'GlobalKnownHostsFile=/dev/null',
                    '-o', 'UserKnownHostsFile=' + str(args.access_dir / 'known_hosts'),
                    '-o', 'ConnectTimeout=8', '-o', 'ServerAliveInterval=5',
                    '-o', 'ServerAliveCountMax=2', '-i', str(args.access_dir / 'id_ed25519'),
                    'root@' + args.address, 'python3 -']
        self.guard_domain()

    def guard_domain(self):
        self.host.guard()

    def guest(self, body, *, timeout=60):
        self.guard_domain()
        script = '\n'.join([
            'import json, signal, sys',
            'from pathlib import Path',
            f'signal.alarm({max(1, min(110, int(timeout) - 1))})',
            "sys.path.insert(0, '/root/localpin-m8')",
            'import run as m',
            f'secrets = m.guard({self.uuid!r})',
            body,
        ]) + '\n'
        try:
            result = subprocess.run(self.ssh, input=script.encode(), capture_output=True,
                                    timeout=timeout, check=False)
        except subprocess.TimeoutExpired:
            raise RuntimeError('bounded guarded M8 guest observation timed out') from None
        require(result.returncode == 0, 'guarded pinned SSH operation failed; inspect guest locally')
        require(len(result.stdout) <= 65_536, 'oversized guest observation')
        return json.loads(result.stdout)

    def observe(self, *, status=False, timeout=60):
        return self.guest('\n'.join([
            "result = {'locked': m.locked(), 'greeter_pids': m.locker_pid(), 'tally': m.tally()}",
            "journal = m.command(['journalctl', '-b', '--no-pager', '-o', 'json',",
            r"                     r'--grep=pam_unix\(kde:auth\).*authentication failure'], check=False)",
            'assert journal.returncode in (0, 1)',
            'events = [json.loads(line) for line in journal.stdout.splitlines()]',
            "events = [event for event in events if 'user=' + m.NAME in event.get('MESSAGE', '')]",
            "result['native_auth_failure_events'] = len(events)",
            "result['greeter_native_failure_events'] = sum(int(event['_PID']) in result['greeter_pids'] for event in events)",
            *(["value = m.status()", "result['broker_status'] = {key: value.get(key) for key in ('availability', 'enrolled_backend')}" ]
              if status else []),
            'print(json.dumps(result))',
        ]), timeout=timeout)

    def candidate(self, selector):
        require(selector in ('pin', 'password'), 'only private fixture PIN/password selectors accepted')
        value = self.guest('\n'.join([
            f"candidate = secrets[m.NAME][{selector!r}]",
            "assert all(char in 'abcdefghijklmnopqrstuvwxyz0123456789' for char in candidate)",
            "print(json.dumps({'candidate': candidate}))",
        ]))['candidate']
        require(isinstance(value, str) and 0 < len(value) <= 64 and all(char in m7.KEYS for char in value),
                'candidate cannot use reviewed keyboard mapping')
        return value

    def require_fault(self, kind):
        value = self.guest("print(json.dumps({'kind': m.private_json(m.FAULT)['kind']}))")
        require(value['kind'] == kind, 'UI recovery does not match prepared actual component fault')

    def denied(self):
        before = self.lock()
        self.type_candidate('pin')
        self.key(28)
        deadline = time.monotonic() + 12
        while time.monotonic() < deadline:
            result = self.observe(timeout=max(2, min(10, deadline - time.monotonic())))
            require(result['locked'] is True and result['greeter_pids'] == before['greeter_pids'],
                    'fault candidate did not retain same locked greeter')
            if result['greeter_native_failure_events'] > before['greeter_native_failure_events']:
                time.sleep(4)  # KDE's asynchronous native failure delay.
                return before, result
            time.sleep(.2)
        raise RuntimeError('native fault denial from actual greeter not observed')

    def run(self):
        phase = self.args.phase
        self.guard_domain()
        initial = self.observe(status=phase in ('pin', 'password'))
        if phase == 'unlock-existing':
            require(initial['locked'] is True, 'explicit existing-lock recovery requires locked desktop')
            self.key(42)
            self.wait(True, greeter=True)
            result = self.unlock('password')
        elif phase in ('baseline', 'legacy-password', 'password', 'restored-password'):
            require(initial['locked'] is False, 'start each UI phase from unlocked dedicated desktop')
            self.lock()
            result = self.unlock('password')
        elif phase == 'pin':
            require(initial['locked'] is False, 'start each UI phase from unlocked dedicated desktop')
            require(initial['broker_status']['availability'] == 'available', 'actual enrollment unavailable')
            self.lock()
            result = self.unlock('pin', enter_required=True)
            require(result['before_enter_tally'] == result['after_tally'],
                    'successful PIN changed original native password counter')
            result['native_password_tally_unchanged'] = True
        elif phase in ('recovery', 'selinux-recovery'):
            require(initial['locked'] is False, 'start each UI phase from unlocked dedicated desktop')
            self.require_fault('missing-module' if phase == 'recovery' else 'selinux-worker')
            result = self.denied_then_password('pin')
        elif phase == 'suspended-recovery':
            require(initial['locked'] is False, 'start each UI phase from unlocked dedicated desktop')
            self.guest('m.cache_window_closed_authority()\nprint(json.dumps({"suspended": True}))')
            result = self.denied_then_password('pin')
        elif phase == 'restricted-recovery':
            require(initial['locked'] is False, 'start each UI phase from unlocked dedicated desktop')
            value = self.guest("print(json.dumps({'availability': m.status()['availability']}))")
            require(value['availability'] != 'available', 'native eligibility restriction not active')
            result = self.denied_then_password('pin')
        else:
            require(initial['locked'] is False, 'start each UI phase from unlocked dedicated desktop')
            self.require_fault('missing-module')
            before, denied = self.denied()
            recovery = self.guest('\n'.join([
                "before_boot = m.boot_id()",
                "value = m.recover(secrets)",
                "assert m.boot_id() == before_boot and m.locked()",
                "value['boot_unchanged'] = True",
                'print(json.dumps(value))',
            ]), timeout=115)
            require(self.observe()['greeter_pids'] == before['greeter_pids'],
                    'administrative recovery replaced failed greeter')
            result = {**self.unlock('password'), 'same_greeter_after_denial': True,
                      'native_pin_denial_observed': True,
                      'native_failure_journal_greeter_verified': True,
                      'console_recovery': recovery,
                      'denied_tally': denied['tally']}
            self.guest(f'm.record_console_recovery({result!r})\nprint(json.dumps({{"recorded": True}}))')
        if phase in ('baseline', 'legacy-password', 'pin', 'password', 'recovery', 'selinux-recovery'):
            self.guest(f'm.record_ui({phase!r}, {result!r})\nprint(json.dumps({{"recorded": True}}))')
        self.guard_domain()
        value = {'phase': phase, 'passed': True, 'selinux': 'Enforcing',
                 'observations': public_observations(result)}
        print(json.dumps(value, indent=2))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('phase', choices=PHASES)
    parser.add_argument('--address', required=True, type=lambda value: str(ipaddress.IPv4Address(value)))
    parser.add_argument('--access-dir', required=True, type=lambda value: Path(value).resolve())
    parser.add_argument('--disposable-vm-confirmed', action='store_true', required=True)
    parser.add_argument('--emulated-tpm-confirmed', action='store_true', required=True)
    args = parser.parse_args()
    import libvirt
    controller = Console(args, libvirt)
    try:
        controller.run()
    finally:
        controller.close()


if __name__ == '__main__':
    main()
