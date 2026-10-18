#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Actual flexible-credential KDE tests, retaining the independent M8 guards.

Never run on the host desktop or an original/shared VM. All candidate values
remain guest-root private or transient in this guarded controller; no candidate,
credential/tally bytes or private digest is printed or written as public evidence.
"""
import argparse
import importlib.util
import ipaddress
import json
from pathlib import Path
import sys

M8 = Path(__file__).resolve().parents[1] / 'm8'
sys.path.insert(0, str(M8))
spec = importlib.util.spec_from_file_location('flexible_reviewed_m8_console', M8 / 'console.py')
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)

KEYS = {char: (code,) for char, code in base.m7.KEYS.items()}
KEYS.update({char.upper(): (42, code) for char, code in base.m7.KEYS.items() if char.isalpha()})
for plain, shifted, code in [
    ('1', '!', 2), ('2', '@', 3), ('3', '#', 4), ('4', '$', 5), ('5', '%', 6),
    ('6', '^', 7), ('7', '&', 8), ('8', '*', 9), ('9', '(', 10), ('0', ')', 11),
    ('-', '_', 12), ('=', '+', 13), ('[', '{', 26), (']', '}', 27),
    (';', ':', 39), ("'", '"', 40), ('`', '~', 41), ('\\', '|', 43),
    (',', '<', 51), ('.', '>', 52), ('/', '?', 53),
]:
    KEYS[plain], KEYS[shifted] = (code,), (42, code)
# Linux input KEY_SEMICOLON is 39; KEY_APOSTROPHE is 40.
KEYS[' '] = (57,)


def keyboard_events(value):
    """Bound and map exact printable ASCII using the guest's US keyboard layout."""
    base.require(isinstance(value, str) and 4 <= len(value) <= 64
                 and all(char in KEYS for char in value), 'unrepresentable bounded credential')
    return [KEYS[char] for char in value]


class Console(base.Console):
    def candidate(self, selector):
        if selector == 'password':
            return super().candidate(selector)
        base.require(selector == 'pin', 'only enrolled credential/password selectors accepted')
        value = self.guest("\n".join([
            "value = m.private_json(m.WORK / 'flexible-current.private.json')",
            "assert value.get('schema') == 1",
            "candidate = value['secret']",
            "assert isinstance(candidate, str) and 4 <= len(candidate) <= 64",
            "assert all(32 <= ord(char) <= 126 for char in candidate)",
            "status = m.status()",
            "profile = status['credential_profile']",
            "assert profile == {'kind': value['kind'], 'length': len(candidate), 'policy_version': 1}",
            "assert status['enrolled_backend'] == value['backend']",
            "assert (value['kind'] == 'numeric-pin' and candidate.isascii() and candidate.isdigit()) or value['kind'] == 'passcode'",
            "print(json.dumps({'candidate': candidate}))",
        ]))['candidate']
        keyboard_events(value)
        return value

    def type_candidate(self, selector):
        self.clear_input()
        value = self.candidate(selector)
        try:
            for event in keyboard_events(value):
                self.key(*event)
        finally:
            # Immutable Python strings cannot promise erasure. Do not log/cache.
            del value


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('phase', choices=('pin', 'password', 'recovery', 'restored-password'))
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
