#!/usr/bin/python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Observe the installed wizard in an actual guarded KDE Konsole.

This fixture never supplies terminal input, invokes an integration mutation, or
claims an operator attestation. The independently topology-verified host sends
actual keyboard events to the clone. Only sanitized prompt identifiers and
fixed observations leave the guest; the output-only script transcript is
readable only by guest root. Stage beside the M8 run.py and guard.py helpers.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import uuid

WORK = Path('/root/localpin-m8')
RUNTIME = Path('/run/localpin-m82')
UID = 21061
NAME = 'lp61test'
MAX_LOG = 1024 * 1024
CHOICE = 'Choose a number (q to cancel): '
ANSI = re.compile(r'\x1b\[[0-?]*[ -/]*[@-~]')
CASE = re.compile(r'[a-z0-9][a-z0-9-]{0,47}')
MODES = {'setup': 'setup', 'menu': '', 'disable': 'disable'}
PROGRAMS = ('localpin', 'localpinctl')

# Exact strings from the installed menu/setup code. A changed/unrecognized
# prompt is reported as unknown; it never triggers an automatic answer.
CONFIRMATIONS = {
    'Check system readiness with administrator access?': 'readiness',
    'Have you successfully rehearsed administrator-console recovery for this installed package BEFORE the final/current preparation and enrollment?': 'prior-console-recovery',
    'Apply these system changes for your account?': 'apply-preparation',
    'Create a new PIN for this account?': 'active-new-pin',
    'Start a new ten-minute desktop trial?': 'start-trial',
    'Have you performed a real PIN unlock successfully during THIS trial?': 'pin-unlock-confirmation',
    'Have full-password unlock and the applicable desktop failure checks passed during THIS trial?': 'password-failure-confirmation',
    'Record the completed tests and activate LocalPIN?': 'activate-confirmation',
}
PRIVATE_PROMPTS = {
    '[sudo] password for lp61test: ': ('sudo-password', 'password'),
    'Existing account password: ': ('account-password', 'password'),
    'New six-digit PIN: ': ('new-pin', 'pin'),
    'Confirm new PIN: ': ('confirm-pin', 'pin'),
    "Create or replace this account's TPM PIN credential? Type yes: ": ('confirm-tpm-enrollment', None),
    "Create or replace this account's software PIN credential? Type yes: ": ('confirm-software-enrollment', None),
    "Disable this account's LocalPIN credential? Type yes: ": ('confirm-disable', None),
}
FIXED_MESSAGES = {
    'paused': 'Setup paused. Completed preparation and enrollment are retained.',
    'accounting_handoff': 'One-time maintenance needed: preserve native password-failure counters',
    'console_recovery_handoff': 'Next: rehearse recovery from an administrator TEXT CONSOLE',
    'active_noop': 'Desktop integration is already active. Setup will preserve it;',
    'active_new_pin_ready': 'Your new PIN is ready. Desktop integration remains active.',
    'activated': 'LocalPIN is active. Lock your KDE session,',
    'enrollment_retained': '[3/5] Your committed PIN enrollment is retained.',
    'account_unavailable': 'The broker cannot currently establish an available PIN',
    'trial_changed': 'The trial expired or enrollment changed.',
    'administrator_recovery_required': 'Existing setup, package, account, or activation state needs administrator recovery.',
}


def require(value, message):
    if not value:
        raise RuntimeError(message)


def normalize(data):
    return ANSI.sub('', data.decode('utf-8', errors='replace')).replace('\r\n', '\n')


def prompt(data):
    """Pure bounded classifier; never return transcript excerpts or credentials."""
    require(len(data) <= MAX_LOG, 'oversized private terminal transcript')
    text = normalize(data)
    for suffix, (identifier, secret) in PRIVATE_PROMPTS.items():
        if text.endswith(suffix):
            return {'id': identifier, 'kind': 'private', 'secret_selector': secret,
                    'answers': ['yes', 'cancel'] if secret is None else ['guest-private-secret']}
    if text.endswith(CHOICE):
        segment = text.rsplit(CHOICE, 1)[0]
        # Only the immediately preceding heading/list can classify this
        # question. An earlier answered confirmation must not label a new one.
        lines = segment.splitlines()
        options = []
        while lines and re.fullmatch(r'  [1-7]\. .+', lines[-1]):
            options.insert(0, lines.pop())
        heading = lines[-1] if lines else ''
        identifier = CONFIRMATIONS.get(heading)
        if identifier is not None and options != ['  1. Yes', '  2. No / pause']:
            identifier = None
        if heading == 'PIN protection' and options == [
                '  1. TPM 2.0 — hardware bound; requires a separately validated TPM deployment',
                '  2. Software — no TPM binding; copied verifier data can be guessed offline']:
            identifier = 'backend'
        elif heading == 'What would you like to do?' and options == [
                '  1. Set up or resume setup', '  2. Check status',
                '  3. Diagnose a problem', '  4. Change my PIN',
                '  5. Switch PIN protection', '  6. Disable my PIN', '  7. Exit']:
            identifier = 'menu'
        if identifier is not None:
            answers = ({'1': 'tpm2-required', '2': 'software', 'q': 'cancel'}
                       if identifier == 'backend' else
                       {'1': 'setup', '2': 'status', '3': 'doctor', '4': 'change',
                        '5': 'migrate', '6': 'disable', '7': 'exit', 'q': 'cancel'}
                       if identifier == 'menu' else {'1': 'yes', '2': 'pause', 'q': 'cancel'})
            return {'id': identifier, 'kind': 'choice', 'answers': answers}
    return {'id': None, 'kind': 'unknown-or-running', 'answers': []}


def exit_code(data):
    matches = re.findall(rb'Script done on [^\n]*\[COMMAND_EXIT_CODE="([0-9]+)"\]', data)
    return int(matches[-1]) if matches else None


def source_hash():
    return hashlib.sha256(Path(__file__).read_bytes()).hexdigest()


def work_path(case, suffix):
    require(CASE.fullmatch(case) is not None, 'invalid fixed fixture case')
    return WORK / ('m82-' + case + '.' + suffix)


def root_file(path, *, gid=0, mode=0o600, max_size=65536):
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_gid == gid
            and info.st_nlink == 1 and stat.S_IMODE(info.st_mode) == mode
            and info.st_size <= max_size, 'unsafe private fixture file')
    return info


def write_private(path, value):
    require(path.parent == WORK, 'private fixture write escaped work directory')
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, 'w') as stream:
        json.dump(value, stream, sort_keys=True, indent=2)
        stream.write('\n')
        stream.flush()
        os.fsync(stream.fileno())
    m.sync_directory(WORK)


def guard(expected):
    require(str(uuid.UUID(expected)) == expected and os.getuid() == os.geteuid() == 0,
            'canonical clone UUID and actual guest root required')
    for name in ('run.py', 'guard.py'):
        info = (WORK / name).lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_uid == info.st_gid == 0
                and info.st_nlink == 1 and not info.st_mode & 0o022,
                'unsafe fixed M8 helper')
    global m
    sys.path.insert(0, str(WORK))
    import run as m
    return m.guard(expected)


def runtime_directory():
    info = RUNTIME.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 0
            and stat.S_IMODE(info.st_mode) == 0o711, 'unsafe terminal runtime directory')


def package_version():
    result = m.command(['/usr/bin/rpm', '-q', '--qf', '%{EVR}', 'localpin'])
    value = result.stdout.decode('ascii')
    require(re.fullmatch(r'[A-Za-z0-9._+~^:-]{1,128}', value) is not None,
            'unexpected installed RPM identity')
    return value


def start(args):
    require(args.expected_localpin_evr is not None
            and package_version() == args.expected_localpin_evr,
            'exact installed LocalPIN RPM mismatch')
    require(not work_path(args.case, 'intent.json').exists(),
            'existing terminal case must be reviewed rather than overwritten')
    require(m.bus('GetActive') in (b'b true', b'b false'), 'actual KDE locker unavailable')
    for executable in ('/usr/bin/konsole', '/usr/bin/script', '/usr/bin/' + args.program):
        target = Path(executable).resolve(strict=True)
        info = target.lstat()
        require(str(target).startswith('/usr/') and stat.S_ISREG(info.st_mode)
                and info.st_uid == info.st_gid == 0 and not info.st_mode & 0o022,
                'unsafe required installed terminal executable')
    require(Path('/usr/bin/localpin').is_symlink()
            and Path('/usr/bin/localpin').resolve() == Path('/usr/bin/localpinctl').resolve(),
            'packaged localpin alias missing')
    if not RUNTIME.exists():
        RUNTIME.mkdir(mode=0o711)
        RUNTIME.chmod(0o711)
    runtime_directory()
    path = RUNTIME / ('m82-' + args.case + '.typescript')
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o620)
    try:
        os.fchown(descriptor, 0, UID)
        os.fchmod(descriptor, 0o620)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    info = root_file(path, gid=UID, mode=0o620, max_size=MAX_LOG)
    unit = 'localpin-m82-' + args.case + '.service'
    # The shell command consumed by script is a constant from these two closed
    # allowlists. No input, secret, path or operator string becomes shell text.
    command = '/usr/bin/' + args.program + (' ' + MODES[args.mode] if MODES[args.mode] else '')
    intent = {'case': args.case, 'uuid': args.expected_uuid, 'boot': m.boot_id(),
              'runner_sha256': source_hash(), 'evr': args.expected_localpin_evr,
              'mode': args.mode, 'program': args.program, 'unit': unit,
              'log': str(path), 'log_dev': info.st_dev, 'log_ino': info.st_ino}
    write_private(work_path(args.case, 'intent.json'), intent)
    native = m.user_environment() + [
        '/usr/bin/systemd-run', '--user', '--quiet', '--collect', '--unit=' + unit,
        '--setenv=LANG=C', '--setenv=LC_ALL=C',
        '/usr/bin/konsole', '--separate', '--nofork', '--title', 'LocalPIN ' + args.case,
        '-e', '/usr/bin/script',
        '--quiet', '--flush', '--return', '--command', command, str(path)]
    launched = subprocess.run(native, capture_output=True, timeout=20)
    write_private(work_path(args.case, 'launch.json'), {
        'returncode': launched.returncode,
        'stdout': launched.stdout.decode(errors='replace'),
        'stderr': launched.stderr.decode(errors='replace')})
    require(launched.returncode == 0, 'Konsole launch refused; inspect guest-root launch log')
    return {'phase': 'm82-wizard-start', 'passed': True, 'case': args.case,
            'runner_sha256': intent['runner_sha256'], 'evr': intent['evr'],
            'mode': args.mode, 'program': args.program, 'actual_kde_konsole_requested': True,
            'input_transport': 'host-controlled actual libvirt keyboard',
            'transcript_guest_root_read_only': True}


def observe(args, secrets):
    path = work_path(args.case, 'intent.json')
    root_file(path)
    intent = json.loads(path.read_text())
    require(intent['uuid'] == args.expected_uuid and intent['case'] == args.case
            and intent['boot'] == m.boot_id() and intent['runner_sha256'] == source_hash(),
            'terminal case identity, boot or runner changed')
    runtime_directory()
    log = RUNTIME / ('m82-' + args.case + '.typescript')
    require(intent['log'] == str(log), 'terminal transcript path mismatch')
    info = root_file(log, gid=UID, mode=0o620, max_size=MAX_LOG)
    require((info.st_dev, info.st_ino) == (intent['log_dev'], intent['log_ino']),
            'terminal transcript inode replaced')
    data = log.read_bytes()
    # A failed echo check never returns the raw offending content.
    echo_absent = not any(value.encode() in data for account in secrets.values()
                          for key, value in account.items() if key in ('password', 'pin'))
    text = normalize(data)
    code = exit_code(data)
    return {'phase': 'm82-wizard-' + args.action, 'passed': True, 'case': args.case,
            'runner_sha256': intent['runner_sha256'], 'evr': intent['evr'],
            'mode': intent['mode'], 'program': intent['program'],
            'prompt': prompt(data) if code is None else {'id': None, 'kind': 'exited', 'answers': []},
            'complete': code is not None, 'exit_code': code,
            'transcript_bytes': len(data), 'secret_echo_absent': echo_absent,
            'sudo_password_prompt_count': text.count('[sudo] password for lp61test: '),
            'account_password_prompt_count': text.count('Existing account password: '),
            'messages': {key: message in text for key, message in FIXED_MESSAGES.items()},
            'selinux': 'Enforcing', 'raw_transcript_guest_root_only': True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('start', 'status', 'finish'))
    parser.add_argument('--case', required=True)
    parser.add_argument('--mode', choices=tuple(MODES), default='setup')
    parser.add_argument('--program', choices=PROGRAMS, default='localpin')
    parser.add_argument('--expected-localpin-evr')
    parser.add_argument('--expect-exit', type=int, default=0)
    parser.add_argument('--expected-uuid', required=True)
    parser.add_argument('--disposable-vm-confirmed', required=True, action='store_true')
    parser.add_argument('--emulated-tpm-confirmed', required=True, action='store_true')
    args = parser.parse_args()
    require(CASE.fullmatch(args.case) is not None and 0 <= args.expect_exit <= 255,
            'invalid bounded terminal case arguments')
    secrets = guard(args.expected_uuid)
    if args.action == 'start':
        value = start(args)
    else:
        value = observe(args, secrets)
        if args.action == 'finish':
            require(value['complete'] and value['exit_code'] == args.expect_exit
                    and value['secret_echo_absent'], 'terminal result incomplete, unexpected exit or echoed secret')
            write_private(work_path(args.case, 'result.json'), value)
    print(json.dumps(value, sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except (OSError, RuntimeError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        print(json.dumps({'phase': 'm82-wizard-refused', 'passed': False,
                          'error': 'guarded terminal fixture refused; inspect guest-root-only evidence'}))
        raise SystemExit(1) from None
