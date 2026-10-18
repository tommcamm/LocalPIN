#!/usr/bin/env python3
"""Guarded M7 guest-only failure setup/recovery; never run on an ordinary system."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import signal
import stat

_spec = importlib.util.spec_from_file_location('localpin_m7_experiment', '/root/localpin-m7/run.py')
m7 = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(m7)
c = m7.component
FAULT = m7.WORK / 'fault.json'
HELD_MODULE = m7.MODULE.with_name('pam_localpin.so.m7-held')
RESTRICTION = m7.WORK / 'restriction-private.json'
NOLOGIN = Path('/run/nologin')
NOLOGIN_BYTES = b'M7 dedicated disposable clone restriction\n'
RESTRICTIONS = {
    'password-locked': ['passwd', '-l'],
    'account-expired': ['chage', '-E', '1'],
    'password-expired': ['chage', '-M', '1', '-d', '1'],
    'forced-change': ['chage', '-d', '0'],
    'restricted-shell': ['usermod', '-s', '/usr/sbin/nologin'],
}
PROFILE_DIGESTS = {
    False: '2e53f704372b6c7fb69cdc4dfd6c27456d642c83feff8b1588fa1f9cb1126cd0',
    True: 'de00ea01b5ffe6b08efd7027e437bdd4a3bad18e231e9593f6b45cc64b334276',
}


def save_fault(state):
    if not FAULT.exists():
        m7.sync_write(FAULT, json.dumps(state).encode(), 0o600)
    else:
        with FAULT.open('w') as stream:
            json.dump(state, stream)
            stream.flush()
            os.fsync(stream.fileno())


def process_start(pid):
    return (Path('/proc') / str(pid) / 'stat').read_text().rsplit(') ', 1)[1].split()[19]


def signal_broker(number, state, *, expected=False):
    # A pidfd prevents a PID reused after validation from receiving the signal.
    args = ['systemctl', 'show', '-p', 'MainPID', '--value', 'localpin-m61.service']
    pid = int(m7.command(args).stdout.strip())
    m7.require(pid > 1, 'live actual broker required')
    descriptor = os.pidfd_open(pid)
    try:
        start = process_start(pid)
        process = Path('/proc') / str(pid)
        ids = [line.split()[1:] for line in (process / 'status').read_text().splitlines()
               if line.startswith('Uid:')]
        m7.require(ids == [['0', '0', '0', '0']]
                   and os.readlink(process / 'exe') == '/usr/libexec/localpin/localpind',
                   'process is not the fixed root broker')
        m7.require(int(m7.command(args).stdout.strip()) == pid,
                   'broker process changed while opening stable reference')
        if expected:
            m7.require(pid == state['pid'] and start == state['start'],
                       'stalled broker process identity changed; inspect clone manually')
        else:
            state['pid'], state['start'] = pid, start
            save_fault(state)
        signal.pidfd_send_signal(descriptor, number)
    finally:
        os.close(descriptor)


def finish_fault():
    FAULT.unlink()
    m7.sync_directory(FAULT.parent)


def regular(path, *, private=False):
    info = path.lstat()
    m7.require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1
               and not info.st_mode & (0o077 if private else 0o022), 'unsafe fixture file')
    return info


def account_record(path):
    regular(path)
    data = path.read_bytes()
    m7.require(len(data) <= 1024 * 1024 and data.endswith(b'\n') and b'\0' not in data,
               'unsupported account fixture input')
    prefix = c.NAME.encode() + b':'
    records = [row for row in data.splitlines(keepends=True) if row.startswith(prefix)]
    m7.require(len(records) == 1, 'unique dedicated account record required')
    m7.require(valid_record(path.name, records[0]), 'dedicated account identity/record changed')
    if path.name == 'passwd':
        fields = [row.rstrip(b'\n').split(b':') for row in data.splitlines(keepends=True)]
        m7.require(all(len(row) == 7 and row[2].isdigit() for row in fields)
                   and sum(int(row[2]) == c.UID for row in fields) == 1,
                   'ambiguous dedicated account UID')
    return records[0]


def valid_record(name, record):
    if not (record.startswith(c.NAME.encode() + b':') and record.endswith(b'\n')
            and record.count(b'\n') == 1 and b'\0' not in record):
        return False
    fields = record[:-1].split(b':')
    return ((name == 'passwd' and len(fields) == 7 and fields[2] == str(c.UID).encode())
            or (name == 'shadow' and len(fields) == 9))


def backup_restriction():
    m7.require(not RESTRICTION.exists(), 'existing private restriction backup')
    # Only the dedicated target rows are retained, in a guest-root-private file.
    # Neither hashes nor these record bytes enter returned evidence or argv.
    records = {name: account_record(Path('/etc') / name).hex() for name in ('passwd', 'shadow')}
    m7.sync_write(RESTRICTION, json.dumps(records).encode(), 0o600)


def restore_restriction():
    regular(RESTRICTION, private=True)
    m7.require(RESTRICTION.stat().st_size <= 8192, 'oversized private restriction backup')
    records = json.loads(RESTRICTION.read_text())
    m7.require(set(records) == {'passwd', 'shadow'}, 'unknown restriction backup')
    prefix = c.NAME.encode() + b':'
    replacements = []
    for name in ('passwd', 'shadow'):
        record = bytes.fromhex(records[name])
        m7.require(valid_record(name, record),
                   'invalid private restriction backup')
        path = Path('/etc') / name
        account_record(path)  # Refuse uncertain current record structure.
        rows = path.read_bytes().splitlines(keepends=True)
        replacements.append((path, b''.join(record if row.startswith(prefix) else row for row in rows)))
    # Validate both records before writing either database while revoked.
    for path, data in replacements:
        path.write_bytes(data)
        with path.open('rb') as stream:
            os.fsync(stream.fileno())
    m7.sync_directory(Path('/etc'))


def freshen():
    c.prune_test_quarantines()
    c.reseal()
    m7.enroll()


def set_profile(faillock):
    m7.require(m7.digest(Path('/etc/authselect/password-auth')) in PROFILE_DIGESTS.values(),
               'unknown/custom password graph; inspect clone manually')
    c.stop()
    m7.command([c.ACCOUNT, 'begin-mutation'])
    args = ['authselect', 'select', 'local', 'with-silent-lastlog', 'with-mdns4', 'with-fingerprint']
    m7.command(args + (['with-faillock'] if faillock else []) + ['--force'])
    nss = Path('/etc/authselect/nsswitch.conf')
    text, count = re.subn(r'^(passwd|group|shadow):[^\n]*', r'\1: files', nss.read_text(), flags=re.M)
    m7.require(count == 3 and all(len(re.findall(r'^' + name + ':', text, flags=re.M)) == 1
                                 for name in ('passwd', 'group', 'shadow')), 'unknown generated NSS layout')
    nss.write_text(text)
    with nss.open('rb') as stream:
        os.fsync(stream.fileno())
    m7.require(m7.digest(Path('/etc/authselect/password-auth')) == PROFILE_DIGESTS[faillock],
               'authselect did not produce the exact reviewed password graph')
    freshen()
    return {'with_faillock': faillock, 'exact_reviewed_graph': True,
            'files_only_nss': True, 'fresh_incarnations_and_enrollment': True}


def profile(faillock):
    m7.guard()
    m7.require(not FAULT.exists(), 'repair failure setup first')
    state = {'kind': 'profile-faillock' if faillock else 'profile-default', 'applied': False}
    save_fault(state)
    result = set_profile(faillock)
    finish_fault()
    return result


def prepare(kind):
    secrets = m7.guard()
    m7.require(not FAULT.exists(), 'repair previous fault first')
    if kind in RESTRICTIONS:
        m7.require(not RESTRICTION.exists() and not RESTRICTION.is_symlink(),
                   'existing private restriction backup; inspect clone manually')
    if kind == 'nologin':
        m7.require(not NOLOGIN.exists() and not NOLOGIN.is_symlink(), 'existing nologin restriction refused')
    state = {'kind': kind, 'applied': False}
    # Record intent before changes so an interrupted setup has a named recovery.
    save_fault(state)
    if kind in RESTRICTIONS:
        backup_restriction()
        c.stop()
        m7.command([c.ACCOUNT, 'begin-mutation'])
        m7.command(RESTRICTIONS[kind] + [c.NAME])
        c.prune_test_quarantines()
        c.reseal()
        state['worker_outcome'] = c.worker()
        m7.require(state['worker_outcome'] != 0, 'account restriction failed to deny production eligibility')
        state['status'] = c.status()
        m7.require(state['status']['availability'] != 'available', 'restricted account became PIN available')
        state['fresh_disabled_incarnations'] = True
    elif kind == 'nologin':
        m7.require(not NOLOGIN.exists() and not NOLOGIN.is_symlink(), 'existing nologin restriction refused')
        m7.sync_write(NOLOGIN, NOLOGIN_BYTES, 0o644)
        state['worker_outcome'] = c.worker()
        m7.require(state['worker_outcome'] != 0, 'runtime restriction failed to deny PIN eligibility')
        state['status'] = c.status()
        m7.require(state['status']['availability'] != 'available', 'runtime restriction allowed PIN')
    elif kind == 'lockout':
        m7.require(m7.digest(Path('/etc/authselect/password-auth')) == PROFILE_DIGESTS[True],
                   'lockout case requires the exact with-faillock profile')
        wrong = 'not-the-disposable-password'
        m7.require(wrong not in (secrets[c.NAME]['pin'], secrets[c.NAME]['password']), 'fixture collision')
        rows = m7.pam(wrong, wrong, wrong)
        m7.require(len(rows) == 3 and all(row['auth'] != 0 and row['prompts'] == 1 for row in rows),
                   'original PAM wrong-password lockout baseline failed')
        state['password_failures'] = rows
        state['locked_counter'] = m7.tally()
        state['worker_outcome'] = c.worker()
        m7.require(state['worker_outcome'] != 0, 'production eligibility bypassed native lockout')
        state['status'] = c.status()
        m7.require(state['status']['availability'] != 'available' and m7.tally() == state['locked_counter'],
                   'policy check bypassed or changed the original lockout tally')
    elif kind == 'cooldown':
        credential_profile = c.status()['credential_profile']
        m7.require(credential_profile is not None and credential_profile['kind'] == 'numeric-pin',
                   'cooldown fixture requires an enrolled numeric PIN profile')
        wrong = '0' * credential_profile['length']
        m7.require(wrong not in (secrets[c.NAME]['pin'], secrets[c.NAME]['password']), 'fixture collision')
        results = [c.client('verify', wrong).stdout.strip().decode() for _ in range(5)]
        m7.require(all(value == 'Mismatch' for value in results[:4]), 'mismatch baseline')
        state['outcomes'] = results
        state['status'] = c.status()
        m7.require(state['status']['availability'] == 'cooldown', 'actual durable cooldown not reached')
    elif kind in ('broker-stopped', 'broker-crashed', 'broker-stalled'):
        if kind == 'broker-stopped':
            c.stop()
        else:
            signal_number = signal.SIGKILL if kind == 'broker-crashed' else signal.SIGSTOP
            signal_broker(signal_number, state)
            if kind == 'broker-crashed':
                # Prevent a new socket activation from replacing the crashed process.
                m7.command(['systemctl', 'stop', 'localpin-m61.socket'])
    elif kind == 'missing-module':
        manifest = json.loads((m7.BACKUP / 'manifest.json').read_text())
        regular(m7.MODULE)
        m7.require(m7.digest(m7.MODULE) == manifest['module_sha256'], 'changed module')
        m7.require(not HELD_MODULE.exists() and not HELD_MODULE.is_symlink(), 'existing held module')
        m7.MODULE.rename(HELD_MODULE)
        m7.sync_directory(m7.MODULE.parent)
    elif kind == 'corrupt-state':
        # Deliberately malformed protected active pointer; actual privileged
        # revocation/provisioning, followed by enrollment, supplies recovery.
        c.stop()
        path = Path('/var/lib/localpin/users') / str(c.UID) / 'active'
        regular(path, private=True)
        path.write_bytes(b'M7 intentional malformed state\n')
        with path.open('rb') as stream:
            os.fsync(stream.fileno())
        state['path'] = str(path)
        c.start()
        state['status'] = c.status()
        m7.require(state['status']['availability'] == 'unavailable', 'corruption did not refuse PIN')
    elif kind == 'worker-missing':
        path = Path('/usr/libexec/localpin/localpin-worker')
        held = path.with_name('localpin-worker.m7-held')
        regular(path)
        m7.require(not held.exists() and not held.is_symlink(), 'actual native worker required')
        state['worker_sha256'] = m7.digest(path)
        save_fault(state)
        path.rename(held)
        m7.sync_directory(path.parent)
    else:
        raise RuntimeError('unsupported fault')
    state['applied'] = True
    save_fault(state)
    return {key: value for key, value in state.items() if key not in ('pid', 'path', 'start')}


def repair():
    m7.guard()
    regular(FAULT, private=True)
    m7.require(FAULT.stat().st_size <= 65_536, 'oversized fault recovery marker')
    state = json.loads(FAULT.read_text())
    kind = state['kind']
    if kind in RESTRICTIONS:
        if RESTRICTION.exists():
            c.stop()
            m7.command([c.ACCOUNT, 'begin-mutation'])
            restore_restriction()
            # Explicit fixture administrator recovery; never eligibility/module
            # behavior. This also recovers extra failed UI submissions.
            m7.command(['faillock', '--user', c.NAME, '--reset'])
            freshen()
            state['restored'] = True
            save_fault(state)
            RESTRICTION.unlink()
            m7.sync_directory(RESTRICTION.parent)
        else:
            m7.require(not state.get('applied') or
                       (state.get('restored') and c.worker() == 0
                        and c.status()['availability'] == 'available'),
                       'missing private restriction recovery backup')
    elif kind.startswith('profile-'):
        m7.require(kind in ('profile-faillock', 'profile-default'), 'unknown recovery profile')
        set_profile(kind == 'profile-faillock')
    elif kind == 'nologin':
        if NOLOGIN.exists() or NOLOGIN.is_symlink():
            regular(NOLOGIN)
            m7.require(NOLOGIN.read_bytes() == NOLOGIN_BYTES, 'changed runtime restriction; inspect clone')
            NOLOGIN.unlink()
            m7.sync_directory(NOLOGIN.parent)
        m7.require(c.worker() == 0, 'runtime restriction recovery failed')
    elif kind == 'lockout':
        m7.command(['faillock', '--user', c.NAME, '--reset'])
        m7.require(c.worker() == 0 and c.status()['availability'] == 'available',
                   'explicit administrator lockout reset failed')
    elif kind == 'broker-stalled':
        if 'pid' in state:
            signal_broker(signal.SIGCONT, state, expected=True)
        c.start()
    elif kind in ('broker-stopped', 'broker-crashed'):
        c.start()
    elif kind == 'missing-module':
        expected = json.loads((m7.BACKUP / 'manifest.json').read_text())['module_sha256']
        if HELD_MODULE.exists():
            regular(HELD_MODULE)
            m7.require(not m7.MODULE.exists() and not m7.MODULE.is_symlink()
                       and m7.digest(HELD_MODULE) == expected,
                       'changed missing-module case')
            HELD_MODULE.rename(m7.MODULE)
            m7.command(['restorecon', str(m7.MODULE)])
            m7.sync_directory(m7.MODULE.parent)
        else:
            regular(m7.MODULE)
            m7.require(m7.digest(m7.MODULE) == expected, 'original module changed during interrupted setup')
    elif kind == 'corrupt-state':
        m7.reset()
    elif kind == 'worker-missing':
        path = Path('/usr/libexec/localpin/localpin-worker')
        held = path.with_name('localpin-worker.m7-held')
        expected = state.get('worker_sha256')
        if expected is None:
            original = c.WORK / 'bin/localpin-worker'
            regular(original)
            expected = m7.digest(original)
        if held.exists():
            regular(held)
            m7.require(not path.exists() and not path.is_symlink() and m7.digest(held) == expected,
                       'changed held worker')
            held.rename(path)
            m7.command(['restorecon', str(path)])
            m7.sync_directory(path.parent)
        else:
            regular(path)
            m7.require(m7.digest(path) == expected,
                       'original worker changed during interrupted setup')
    elif kind == 'cooldown':
        m7.reset()
    else:
        raise RuntimeError('unsupported recovery')
    finish_fault()
    return {'repaired': kind, 'status': c.status()}


def password(kind):
    secrets = m7.guard()
    m7.require(not FAULT.exists(), 'repair failure setup first')
    entry = secrets[c.NAME]
    if kind != 'ordinary-password':
        m7.require('ordinary_password' not in entry, 'fixture password already configured')
        entry['ordinary_password'] = entry['password']
        if kind == 'profile-password':
            credential_profile = c.status()['credential_profile']
            m7.require(credential_profile is not None and credential_profile['kind'] == 'numeric-pin'
                       and credential_profile['length'] == len(entry['pin']),
                       'password-overlap fixture requires the current enrolled numeric profile')
            entry['password'] = '4815162342481516'[:credential_profile['length']]
        else:
            entry['password'] = '481516'
    else:
        entry['password'] = entry.pop('ordinary_password')
    m7.require(entry['password'] != entry['pin'], 'PIN/password collision')
    c.stop()
    m7.command([c.ACCOUNT, 'begin-mutation'])
    m7.command(['chpasswd'], data=(c.NAME + ':' + entry['password'] + '\n').encode())
    path = c.WORK / 'secrets.json'
    path.write_text(json.dumps(secrets))
    path.chmod(0o600)
    c.prune_test_quarantines()
    c.reseal()
    m7.enroll()
    return {'six_digit_password': kind == 'six-password',
            'password_matches_numeric_profile': kind == 'profile-password',
            'fresh_incarnation_and_enrollment': True}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('action', choices=['prepare', 'repair', 'six-password', 'profile-password', 'ordinary-password',
                                         'profile-faillock', 'profile-default'])
    parser.add_argument('--kind', choices=['cooldown', 'broker-stopped', 'broker-crashed',
                        'broker-stalled', 'missing-module', 'corrupt-state', 'worker-missing',
                        'nologin', 'lockout', *RESTRICTIONS])
    parser.add_argument('--disposable-vm-confirmed', action='store_true', required=True)
    args = parser.parse_args()
    if args.action == 'prepare':
        m7.require(args.kind is not None, 'fault kind required')
        result = prepare(args.kind)
    elif args.action == 'repair':
        result = repair()
    elif args.action in ('profile-faillock', 'profile-default'):
        result = profile(args.action == 'profile-faillock')
    else:
        result = password(args.action)
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
