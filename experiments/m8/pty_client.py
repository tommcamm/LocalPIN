#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""M8 private PTY fixture; staged in the disposable clone, never in the RPM."""
import json
import os
import pty
import select
import signal
import struct
import sys
import time


def read_frame():
    header = sys.stdin.buffer.read(2)
    if len(header) != 2: raise RuntimeError('private input missing')
    length = struct.unpack('>H', header)[0]
    if length > 512: raise RuntimeError('private input bound')
    data = sys.stdin.buffer.read(length)
    if len(data) != length: raise RuntimeError('private input truncated')
    return data


def main():
    operation = sys.argv[1]
    commands = {'enroll': ['enroll', '--backend', 'software'],
                'enroll-tpm': ['enroll', '--backend', 'tpm2-required'], 'change': ['change'],
                'disable': ['disable'], 'recover': ['recover', '--user', 'lp61test']}
    if operation not in commands: raise RuntimeError('unsupported fixture operation')
    password = read_frame() if operation != 'recover' else None
    pin = read_frame() if operation in ('enroll', 'enroll-tpm', 'change') else None
    pid, descriptor = pty.fork()
    if pid == 0:
        os.execv('/usr/bin/localpinctl', ['localpinctl', *commands[operation]])
    transcript = bytearray()
    pending = bytearray()
    prompts = [(b'Type yes: ', b'yes')]
    if password is not None: prompts.append((b'Existing account password: ', password))
    if pin is not None:
        prompts.extend([(b'New six-digit PIN: ', pin), (b'Confirm new PIN: ', pin)])
    sent = 0
    deadline = time.monotonic() + 70
    status = None
    reaped = False
    try:
        while time.monotonic() < deadline:
            ready, _, _ = select.select([descriptor], [], [], .1)
            if ready:
                try: data = os.read(descriptor, 4096)
                except OSError: data = b''
                if not data: break
                transcript.extend(data)
                pending.extend(data)
                if sent < len(prompts) and prompts[sent][0] in pending:
                    os.write(descriptor, prompts[sent][1] + b'\n')
                    sent += 1
                    pending.clear()
            observed, status = os.waitpid(pid, os.WNOHANG)
            if observed == pid:
                reaped = True
                break
        # Closing the final PTY descriptor can precede the child's actual exit.
        # Observe/reap it within the original deadline, without extending it.
        while not reaped and time.monotonic() < deadline:
            observed, status = os.waitpid(pid, os.WNOHANG)
            if observed == pid:
                reaped = True
                break
            time.sleep(.01)
        if not reaped: raise RuntimeError('CLI PTY deadline')
        while select.select([descriptor], [], [], .05)[0]:
            try: data = os.read(descriptor, 4096)
            except OSError: break
            if not data: break
            transcript.extend(data)
        if os.waitstatus_to_exitcode(status) != 0 or sent != len(prompts):
            raise RuntimeError('installed CLI flow refused')
        if any(value and value in transcript for value in (password, pin)):
            raise RuntimeError('secret echoed in installed CLI PTY')
        print(json.dumps({'operation': operation, 'exit_success': True, 'real_controlling_terminal': True,
                          'private_prompt_count': sent, 'secret_echo_absent': True}))
    finally:
        if not reaped:
            try: os.kill(pid, signal.SIGKILL)
            except ProcessLookupError: pass
            os.waitpid(pid, 0)
        os.close(descriptor)
        for index in range(len(transcript)): transcript[index] = 0
        for index in range(len(pending)): pending[index] = 0


if __name__ == '__main__':
    main()
