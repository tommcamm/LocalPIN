#!/usr/bin/python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Sanitized observation of a real Konsole resumed by the installed launcher.

Only for the independently guarded M8 disposable clone. Input remains actual
libvirt keyboard events; this helper never answers a prompt or attests tests.
Raw terminal buffers and native counter snapshots remain guest-root private.
"""
import argparse
import importlib.util
import json
from pathlib import Path
import re
import sys

MAINTENANCE_CONFIRMATION = (
    'Have you saved your work, and approve logging out all users and stopping services and background jobs for this maintenance?'
)


def base_module():
    adjacent = Path(__file__).with_name('wizard_base.py')
    source = adjacent if adjacent.exists() else Path(__file__).resolve().parents[1] / 'm82/wizard.py'
    specification = importlib.util.spec_from_file_location('m83_reviewed_wizard_base', source)
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    module.CONFIRMATIONS[MAINTENANCE_CONFIRMATION] = 'accounting-maintenance-confirmation'
    return module


def terminal_prompt(text):
    """Accept Konsole line wrapping while matching fixed product prompts only."""
    base = base_module()
    # getAllDisplayedText(false) joins soft line wraps; trim only empty terminal
    # lines, retaining the prompt's trailing space and visible menu boundaries.
    normalized = text.rstrip('\n')
    result = base.prompt(normalized.encode())
    if result['id'] is not None:
        return result
    # Konsole may omit trailing prompt whitespace on an otherwise empty line.
    result = base.prompt((normalized + ' ').encode())
    if result['id'] is not None:
        return result
    # Konsole can retain a soft-wrap newline inside a word even when requested
    # not to preserve line breaks. Match only a complete fixed trailing block,
    # so an older confirmation cannot authorize a different current question.
    flat = normalized.replace('\n', '')
    for heading in base.CONFIRMATIONS:
        block = heading + '\n  1. Yes\n  2. No / pause\n' + base.CHOICE
        if flat.rstrip().endswith(block.replace('\n', '').rstrip()):
            return base.prompt(block.encode())
    result = base.prompt(flat.encode())
    if result['id'] is not None:
        return result
    return {'id': None, 'kind': 'unknown-or-running', 'answers': []}


def is_setup_process(commandline):
    fields = commandline.rstrip(b'\0').split(b'\0')
    return fields in ([b'/usr/bin/localpin', b'setup'],
                      [b'localpin', b'setup'],
                      [b'/usr/bin/localpinctl', b'setup'])


def observe_live(m, expected):
    secrets = m.guard(expected)
    m.require(not m.locked(), 'unlocked actual KDE session required before observing prompts')
    listing = m.command(m.user_environment() + ['busctl', '--user', '--no-pager', 'list'])
    services = [line.split()[0] for line in listing.stdout.decode().splitlines()
                if re.fullmatch(r'org\.kde\.konsole-[0-9]+', line.split()[0])]
    m.require(len(services) <= 8, 'unexpected number of Konsole services')
    candidates = []
    for service in services:
        prefix = m.user_environment() + ['busctl', '--user', '--json=short', 'call', service,
                                        '/Sessions/1', 'org.kde.konsole.Session']
        foreground = m.command(prefix + ['foregroundProcessId'], check=False)
        if foreground.returncode:
            continue
        pid = json.loads(foreground.stdout)['data'][0]
        if not isinstance(pid, int) or pid <= 0:
            continue
        try:
            if not is_setup_process(Path(f'/proc/{pid}/cmdline').read_bytes()):
                continue
        except FileNotFoundError:
            continue
        buffer = m.command(prefix + ['getAllDisplayedText', 'b', 'false'])
        text = json.loads(buffer.stdout)['data'][0]
        m.require(isinstance(text, str) and len(text.encode()) <= 1024 * 1024,
                  'oversized private resumed terminal buffer')
        echo_absent = not any(value in text for account in secrets.values()
                              for key, value in account.items() if key in ('password', 'pin'))
        m.require(echo_absent, 'private credential appeared in resumed terminal output')
        # The guest-root-only checkpoint aids diagnosis without exporting text.
        m.sync_json(m.WORK / 'm83-live-wizard-private.json', {'text': text, 'pid': pid})
        candidates.append({'prompt': terminal_prompt(text),
                           'sudo_password_prompt_count': text.count('[sudo] password for lp61test:'),
                           'account_password_prompt_count': text.count('Existing account password:'),
                           'actual_konsole': True, 'actual_installed_setup_process': True,
                           'secret_echo_absent': True})
    m.require(len(candidates) == 1, 'one actual resumed LocalPIN setup Konsole required')
    return {'phase': 'resumed-wizard-observation', 'passed': True, **candidates[0]}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--expected-uuid', required=True)
    parser.add_argument('--disposable-vm-confirmed', action='store_true', required=True)
    parser.add_argument('--emulated-tpm-confirmed', action='store_true', required=True)
    args = parser.parse_args()
    sys.path.insert(0, '/root/localpin-m8')
    import run as m
    print(json.dumps(observe_live(m, args.expected_uuid), indent=2))


if __name__ == '__main__':
    main()
