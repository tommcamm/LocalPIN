#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Nonshipping private-PTY driver for the actual installed credential form.

Run through M8's guarded real user-manager command. Two bounded private frames
on stdin supply the guest-only password and credential; neither is an argument
or environment variable to the installed CLI. Only sanitized facts are printed.
"""
import argparse
import json
import os
from pathlib import Path
import pty
import select
import signal
import stat
import struct
import subprocess
import termios
import time
import uuid

COMMANDS = {
    'change': ['change'],
    'enroll-software': ['enroll', '--backend', 'software'],
    'enroll-tpm': ['enroll', '--backend', 'tpm2-required'],
    'migrate-software': ['migrate', '--backend', 'software'],
    'migrate-tpm': ['migrate', '--backend', 'tpm2-required'],
    'disable': ['disable'],
}


def guard_marker(path=Path('/run/localpin-m61-guard')):
    """Read only an existing root-controlled disposable-clone marker."""
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(descriptor)
        if not (stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1
                and not info.st_mode & 0o022 and 0 < info.st_size <= 128):
            raise RuntimeError('unsafe disposable-clone marker')
        value = os.read(descriptor, 129)
    finally:
        os.close(descriptor)
    try:
        canonical = str(uuid.UUID(value.decode('ascii').strip())) + '\n'
    except (ValueError, UnicodeDecodeError):
        raise RuntimeError('invalid disposable-clone marker') from None
    if value != canonical.encode('ascii'):
        raise RuntimeError('noncanonical disposable-clone marker')


def guard():
    """Refuse direct workstation use before consuming secrets or launching CLI.

    The root dispatcher remains responsible for binding this marker to the
    clone's DMI identity and independently proving its private TPM topology.
    """
    if os.getuid() != 21061 or os.geteuid() != 21061:
        raise RuntimeError('dedicated disposable desktop UID required')
    try:
        guard_marker()
        for command, expected in [
            (['/usr/bin/systemd-detect-virt', '--vm'], b'kvm'),
            (['/usr/bin/getenforce'], b'Enforcing'),
        ]:
            result = subprocess.run(command, capture_output=True, timeout=5, check=False)
            if result.returncode != 0 or result.stdout.strip() != expected:
                raise RuntimeError('dedicated enforcing KVM guest required')
        values = dict(line.split('=', 1) for line in Path('/etc/os-release').read_text().splitlines()
                      if '=' in line and not line.startswith('#'))
        if not (values.get('ID', '').strip('"') == 'fedora'
                and values.get('VERSION_ID', '').strip('"') == '44'
                and values.get('VARIANT_ID', '').strip('"') == 'kde'):
            raise RuntimeError('Fedora 44 KDE guest required')
    except (OSError, subprocess.TimeoutExpired):
        raise RuntimeError('disposable guest guard unavailable') from None


def frame(stream, maximum):
    header = stream.read(2)
    if len(header) != 2:
        raise RuntimeError('private frame missing')
    length = struct.unpack('>H', header)[0]
    if length > maximum:
        raise RuntimeError('private frame exceeds bound')
    value = stream.read(length)
    if len(value) != length:
        raise RuntimeError('private frame truncated')
    return value


def run(args):
    import sys
    guard()
    password = frame(sys.stdin.buffer, 512)
    credential = frame(sys.stdin.buffer, 64) if args.operation != 'disable' else None
    if sys.stdin.buffer.read(1):
        raise RuntimeError('unexpected private input')
    prompts = []
    if credential is not None:
        prefix = b'PIN' if args.kind == 'numeric-pin' else b'passcode'
        prompts.extend([
            ((b'Type [1] (q to cancel): ', b'Type [2] (q to cancel): '),
             b'1' if args.kind == 'numeric-pin' else b'2', 'type'),
            ((b'New ' + prefix + b'      ',), credential, 'new'),
            ((b'Confirm ' + prefix + b'  ',), credential, 'confirm'),
        ])
    prompts.extend([((b'Type yes: ',), b'yes', 'mutation'),
                    ((b'Existing account password: ',), password, 'password')])
    child, descriptor = pty.fork()
    if child == 0:
        os.execv('/usr/bin/localpin', ['localpin', *COMMANDS[args.operation]])
    transcript, pending = bytearray(), bytearray()
    sent, reaped, status = 0, False, None
    deadline = time.monotonic() + 90
    try:
        while time.monotonic() < deadline:
            ready, _, _ = select.select([descriptor], [], [], .1)
            if ready:
                try:
                    data = os.read(descriptor, 4096)
                except OSError:
                    data = b''
                if data:
                    transcript.extend(data)
                    pending.extend(data)
                    if len(transcript) > 65536:
                        raise RuntimeError('terminal output exceeded bound')
                    if sent < len(prompts) and any(prompt in pending for prompt in prompts[sent][0]):
                        if prompts[sent][2] in ('new', 'confirm', 'password'):
                            if termios.tcgetattr(descriptor)[3] & termios.ECHO:
                                raise RuntimeError('private prompt echo is enabled')
                        os.write(descriptor, prompts[sent][1] + b'\n')
                        sent += 1
                        pending.clear()
            observed, status = os.waitpid(child, os.WNOHANG)
            if observed == child:
                reaped = True
                break
        if not reaped:
            raise RuntimeError('private terminal test deadline')
        while select.select([descriptor], [], [], .05)[0]:
            try:
                data = os.read(descriptor, 4096)
            except OSError:
                break
            if not data:
                break
            transcript.extend(data)
        if os.waitstatus_to_exitcode(status) != 0 or sent != len(prompts):
            raise RuntimeError('installed terminal flow refused')
        if any(value and value in transcript for value in (password, credential)):
            raise RuntimeError('secret echoed in installed terminal')
        if credential is not None and transcript.count(b'*') < 2 * len(credential):
            raise RuntimeError('new credential masking was not observed')
        return {'operation': args.operation, 'kind': args.kind if credential is not None else None,
                'length': len(credential) if credential is not None else None,
                'actual_installed_cli': True, 'real_controlling_terminal': True,
                'preparation_before_password': credential is not None,
                'masked_new_input_observed': credential is not None,
                'secret_echo_absent': True, 'private_prompt_count': sent, 'exit_success': True}
    finally:
        if not reaped:
            try:
                os.kill(child, signal.SIGKILL)
            except ProcessLookupError:
                pass
            os.waitpid(child, 0)
        os.close(descriptor)
        for buffer in (transcript, pending):
            for index in range(len(buffer)):
                buffer[index] = 0


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('operation', choices=tuple(COMMANDS))
    parser.add_argument('--kind', choices=('numeric-pin', 'passcode'), default='numeric-pin')
    args = parser.parse_args()
    print(json.dumps(run(args)))


if __name__ == '__main__':
    main()
