#!/usr/bin/python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Reuse frozen recovery assertions from an actual free administrator VT.

Repeated graphical logins can move KDE onto tty3. Require a real tty3..tty6
sudo origin and its actual logind tty session instead of assuming tty3 is free.
No password input, module repair or desktop attestation occurs in this helper.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import sys

BASE_SHA = 'e48d54646ac76b2e391b5957b17cabf3a696d7d266b91494abe709840bcf814f'
ACCOUNTING_SHA = '752f10ff086d41e26dfa7e3bec491f91498f60688309b6e40421087ff387ce30'
WORK = Path('/root/localpin-m8')


def valid_origin(tty, active, sudo_uid, sudo_user):
    return (isinstance(tty, str) and re.fullmatch(r'/dev/tty[3-6]', tty) is not None
            and tty == '/dev/' + active and sudo_uid == '21061' and sudo_user == 'lp61test')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--expected-uuid', required=True)
    parser.add_argument('--disposable-vm-confirmed', action='store_true', required=True)
    parser.add_argument('--emulated-tpm-confirmed', action='store_true', required=True)
    args = parser.parse_args()
    sys.path.insert(0, str(WORK))
    import run as m
    import offline_accounting as accounting
    m.guard(args.expected_uuid)
    source = WORK / 'console_recovery_base.py'
    m.owned_file(source, owner=0)
    m.require(hashlib.sha256(source.read_bytes()).hexdigest() == BASE_SHA
              and hashlib.sha256((WORK / 'offline_accounting.py').read_bytes()).hexdigest() == ACCOUNTING_SHA,
              'frozen reviewed recovery helpers required')
    tty = os.environ.get('SUDO_TTY')
    active = Path('/sys/class/tty/tty0/active').read_text().strip()
    m.require(valid_origin(tty, active, os.environ.get('SUDO_UID'), os.environ.get('SUDO_USER'))
              and os.isatty(0), 'actual dedicated-user sudo on a free local VT required')
    matches = []
    for pid in accounting.current_ancestors():
        process = Path('/proc') / str(pid)
        try:
            name = (process / 'comm').read_text().strip()
            origin = os.readlink(process / 'fd/0')
            status = dict(line.split(':', 1) for line in (process / 'status').read_text().splitlines() if ':' in line)
        except FileNotFoundError:
            continue
        if name == 'sudo' and origin == tty and status['Uid'].split()[1] == '0':
            matches.append(pid)
    m.require(matches, 'root sudo must retain the actual VT descriptor')
    sessions = accounting.sessions()
    m.require(any(row.get('User') == '21061' and row.get('TTY') == active
                  and row.get('Type') == 'tty' and row.get('Class') == 'user'
                  and row.get('State') == 'active' for row in sessions),
              'actual dedicated-account local text login required')
    result = WORK / 'm83-console-recovery-result.json'
    m.require(not result.exists() and not (WORK / 'm83-console-recovery-intent.json').exists(),
              'existing recovery attempt requires review')
    specification = importlib.util.spec_from_file_location('m83_frozen_recovery', source)
    base = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(base)
    base.m, base.accounting = m, accounting
    base.fault_binding()
    base.backup_reference(m.private_json(base.MANIFEST))
    m.sync_json(WORK / 'm83-console-recovery-intent.json', {
        'boot': m.boot_id(), 'origin': tty, 'root_sudo_ancestor_verified': True,
        'source_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest()})
    observations = base.run_recovery(args.expected_uuid)
    observations.pop('actual_administrator_tty3_recovery', None)
    observations['actual_administrator_text_console_recovery'] = True
    value = {'phase': 'actual-console-recovery', 'passed': True, 'selinux': 'Enforcing',
             'origin': tty, 'root_sudo_ancestor_verified': True,
             'reviewed_recovery_helper_sha256': BASE_SHA,
             'observations': observations, 'raw_checkpoints_guest_root_only': True}
    m.sync_json(result, value)
    print(json.dumps(value))


if __name__ == '__main__':
    main()
