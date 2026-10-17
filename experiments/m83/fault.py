#!/usr/bin/python3 -I
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Kill the actual accounting worker only inside the guarded disposable clone.

Not packaged or imported by production. A guest-private test drop-in runs this
wrapper in the real maintenance service's cgroup. The unchanged product helper
creates the real watchdog; the fixture never supplies product test flags,
changes native counters, or replaces production authority.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import sys
import time
import uuid

WORK = Path('/root/localpin-m8')
MARKER = WORK / 'm83-accounting-fault.json'
JOURNAL = Path('/var/lib/localpin-integration/control/accounting/transaction.json')
PID1_EVENTS = Path('/sys/fs/cgroup/init.scope/cgroup.events')
HELPER = '/usr/libexec/localpin/localpin-accounting'
COMMAND = (HELPER, 'run')
EXPECTED_CGROUP = '0::/localpinmaintenance.slice/localpin-accounting.service'
ALLOWED_PHASES = ('barrier-started', 'quiescent')
JOURNAL_BOUND = 4 * 1024 * 1024
ENV = {'PATH': '/usr/sbin:/usr/bin', 'LANG': 'C', 'LC_ALL': 'C'}


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def _object(pairs):
    value = {}
    for key, item in pairs:
        require(key not in value, 'duplicate protected journal field')
        value[key] = item
    return value


def read_journal():
    """Bounded read of only the fixed protected root journal, never printed."""
    for path in reversed(JOURNAL.parents):
        info = path.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 0
                and not info.st_mode & 0o022, 'unsafe journal ancestor')
    fd = os.open(JOURNAL, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_uid == before.st_gid == 0
                and before.st_nlink == 1 and stat.S_IMODE(before.st_mode) == 0o600
                and before.st_size <= JOURNAL_BOUND, 'unsafe protected journal')
        chunks = []
        remaining = JOURNAL_BOUND + 1
        while remaining:
            part = os.read(fd, min(65536, remaining))
            if not part:
                break
            chunks.append(part)
            remaining -= len(part)
        data = b''.join(chunks)
        after = os.fstat(fd)
        require(len(data) == before.st_size and before.st_mtime_ns == after.st_mtime_ns
                and before.st_ctime_ns == after.st_ctime_ns, 'journal changed during observation')
    finally:
        os.close(fd)
    value = json.loads(data, object_pairs_hook=_object)
    require(isinstance(value, dict) and value.get('schema') == 1
            and type(value.get('uid')) is int and 1000 <= value['uid'] <= 59999
            and isinstance(value.get('request_id'), str)
            and re.fullmatch('[0-9a-f]{64}', value['request_id']) is not None
            and isinstance(value.get('phase'), str), 'unrecognized accounting journal')
    return value


def target_observed(journal, target, pid1_frozen):
    require(target in ALLOWED_PHASES, 'unsupported fault phase')
    return journal.get('phase') == target and pid1_frozen


def pid1_frozen():
    values = dict(line.split() for line in PID1_EVENTS.read_text().splitlines())
    return values.get('frozen') == '1'


def stopped(pid):
    found, status = os.waitpid(pid, os.WNOHANG | os.WUNTRACED)
    if found == 0:
        return False
    require(found == pid and os.WIFSTOPPED(status), 'worker exited before bound fault point')
    return True


def kill_observed_worker(pid, target, journal, *, record, read_current=read_journal,
                         frozen=pid1_frozen, stopped_check=stopped):
    """Bind the durable fault marker to a stopped worker at the actual phase."""
    if not target_observed(journal, target, frozen()):
        return False
    os.kill(pid, signal.SIGSTOP)
    deadline = time.monotonic() + 5
    while not stopped_check(pid):
        require(time.monotonic() < deadline, 'worker did not stop for fault binding')
        time.sleep(0.001)
    current = read_current()
    if (not target_observed(current, target, frozen())
            or current['request_id'] != journal['request_id']):
        os.kill(pid, signal.SIGCONT)
        return False
    facts = {'schema': 1, 'phase': 'accounting-worker-crash', 'target_phase': target,
             'observed_phase': current['phase'], 'request_id': current['request_id'],
             'worker_stopped': True, 'pid1_frozen_before_kill': True,
             'fixed_production_worker': True, 'sigkill_sent': False}
    # The marker is durable before the worker is killed. It contains no source
    # snapshots, account names, credentials or raw journal/log content.
    record(facts)
    os.kill(pid, signal.SIGKILL)
    found, status = os.waitpid(pid, 0)
    require(found == pid and os.WIFSIGNALED(status) and os.WTERMSIG(status) == signal.SIGKILL,
            'actual worker SIGKILL not established')
    record(dict(facts, sigkill_sent=True, worker_exit_signal='SIGKILL'))
    return True


def guarded_module(expected_uuid):
    require(os.getuid() == os.geteuid() == 0, 'actual guest root required')
    require(str(uuid.UUID(expected_uuid)) == expected_uuid, 'canonical clone identity required')
    require(Path('/proc/self/cgroup').read_text().strip() == EXPECTED_CGROUP,
            'fixture must run in the real accounting service cgroup')
    for name in ('guard.py', 'run.py'):
        info = (WORK / name).lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_uid == info.st_gid == 0
                and info.st_nlink == 1 and not info.st_mode & 0o022
                and info.st_size <= 1024 * 1024, 'unsafe fixed guest guard fixture')
    sys.path.insert(0, str(WORK))
    specification = importlib.util.spec_from_file_location('m83_accounting_guarded_run', WORK / 'run.py')
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    module.guard(expected_uuid)
    info = Path(HELPER).lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_uid == info.st_gid == 0
            and info.st_nlink == 1 and stat.S_IMODE(info.st_mode) == 0o755,
            'fixed packaged worker required')
    require(not MARKER.exists() and not MARKER.is_symlink(), 'prior fault evidence must be retained separately')
    return module


def run_fault(m, target):
    require(target in ALLOWED_PHASES, 'unsupported fault phase')
    child = subprocess.Popen(COMMAND, env=ENV, stdin=subprocess.DEVNULL,
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, close_fds=True)
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        require(child.poll() is None, 'worker completed without observing requested fault phase')
        journal = read_journal()
        if kill_observed_worker(child.pid, target, journal,
                                record=lambda value: m.sync_json(MARKER, value)):
            return
        time.sleep(0.001)
    # A missed observation does not claim a crash. The product worker is left
    # untouched to finish rather than inventing a different injection point.
    raise RuntimeError('requested fault phase not observed within fixture deadline')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--expected-uuid', required=True)
    parser.add_argument('--phase', choices=ALLOWED_PHASES, required=True)
    parser.add_argument('--disposable-vm-confirmed', action='store_true', required=True)
    parser.add_argument('--emulated-tpm-confirmed', action='store_true', required=True)
    args = parser.parse_args()
    module = guarded_module(args.expected_uuid)
    run_fault(module, args.phase)


if __name__ == '__main__':
    try:
        main()
    except (OSError, RuntimeError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        print('m83-accounting-fault: guarded observation or crash injection refused', file=sys.stderr)
        raise SystemExit(1) from None
