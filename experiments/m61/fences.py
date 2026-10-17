#!/usr/bin/env python3
"""Pause actual library operations to verify concurrent production revocation.

Run only in the guarded Fedora clone. The fixture delegates all authority and
result decisions to production code; this runner only schedules owned processes.
"""
import argparse
import json
from pathlib import Path
import subprocess
import time

from run import ACCOUNT, NAME, OTHER, UID, WORK, client, command, frame, guard, require, start, stop, user_command
from lifecycle import fresh, incarnation

CONTROL = Path('/run/localpin-m61-fences')
USER = Path('/var/lib/localpin/users') / str(UID)


def wait_marker(name, process, timeout=15):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        require(process.poll() is None, 'owned fixture exited before ' + name)
        if (CONTROL / name).exists():
            return
        time.sleep(.001)
    raise RuntimeError('fixture did not reach ' + name)


def one(mode, secrets):
    fresh(secrets, enroll=mode in ('success', 'delivery'))
    stop()
    identity = incarnation()
    # These checks make a staging/publication observation unambiguous: it
    # cannot be caused by a credential or pointer left by an earlier operation.
    if mode in ('stage', 'publish'):
        require((USER / 'generation-1').is_dir(), 'fresh disabled generation absent')
        require(not (USER / 'generation-2').exists(), 'stale generation would invalidate pause')
        require(not (USER / '.pending').exists(), 'stale pending pointer would invalidate pause')
    CONTROL.mkdir(mode=0o700, exist_ok=True)
    require(CONTROL.stat().st_uid == 0 and CONTROL.stat().st_mode & 0o777 == 0o700,
            'unsafe control directory')
    for name in ['ready', 'paused', 'release', 'timed-out']:
        (CONTROL / name).unlink(missing_ok=True)
    fixture = subprocess.Popen([str(WORK / 'm61-fences'), mode], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    operation = None
    try:
        wait_marker('ready', fixture)
        op = 'enroll' if mode in ('stage', 'publish') else 'verify'
        values = [secrets[NAME]['password'], secrets[NAME]['pin']] if op == 'enroll' else [secrets[NAME]['pin']]
        operation = subprocess.Popen(user_command(op), stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        operation.stdin.write(b''.join(frame(value) for value in values))
        operation.stdin.flush()
        operation.stdin.close()
        operation.stdin = None
        wait_marker('paused', fixture)
        at = time.monotonic()
        mutation = command([ACCOUNT, 'begin-mutation'], check=False, timeout=1)
        busy_ms = round((time.monotonic() - at) * 1000, 3)
        require(mutation.returncode != 0 and b'Busy' in mutation.stderr, 'concurrent revocation did not report Busy')
        require(incarnation() == identity, 'busy revocation changed incarnation')
        (CONTROL / 'release').write_text('release\n')
        out, err = operation.communicate(timeout=15)
        require(operation.returncode == 0, 'actual client operation failed after release')
        expected = b'Enrolled(Software)' if op == 'enroll' else b'Granted'
        require(expected in out, 'production result changed during scheduling probe')
        require(not (CONTROL / 'timed-out').exists(), 'scheduling pause exceeded 500ms')
        command([ACCOUNT, 'begin-mutation'])
        require(incarnation() is None, 'revocation failed after operation release')
        result = client('verify', secrets[NAME]['pin'], check=False)
        require(b'Granted' not in result.stdout, 'revoked PIN granted after completed operation')
        return {'fresh_state_precondition': True, 'actual_production_authorities': True,
                'concurrent_revocation_busy': True, 'busy_response_ms': busy_ms,
                'incarnation_unchanged_while_leased': True, 'actual_result_completed': True,
                'pause_under_500ms': True, 'revocation_after_release': True, 'old_pin_denied': True}
    finally:
        if operation is not None and operation.poll() is None:
            operation.kill()
            operation.communicate(timeout=5)
        fixture.terminate()
        try:
            fixture.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            fixture.kill()
            fixture.communicate(timeout=5)
        start()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--disposable-vm-confirmed', required=True, action='store_true')
    parser.parse_args()
    secrets = guard()
    result = {mode: one(mode, secrets) for mode in ['stage', 'publish', 'success', 'delivery']}
    fresh(secrets)
    require(command(['getenforce']).stdout.strip() == b'Enforcing', 'SELinux changed')
    path = WORK / 'evidence.json'
    evidence = json.loads(path.read_text())
    evidence['concurrent-production-fences'] = result
    path.write_text(json.dumps(evidence, indent=2) + '\n')
    path.chmod(0o600)
    print(json.dumps({'concurrent-production-fences': result, 'selinux': 'Enforcing'}, indent=2))


if __name__ == '__main__':
    main()
