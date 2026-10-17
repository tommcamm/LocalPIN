#!/usr/bin/env python3
"""Actual Fedora account/PAM restriction matrix; guarded disposable clone only."""
import argparse
import json
from pathlib import Path
import subprocess
import time

import run as m


def password(candidate, service='original'):
    result = m.command([str(m.WORK / 'password-check'), service, m.NAME], data=candidate.encode())
    return json.loads(result.stdout)


def counter():
    path = Path('/run/faillock') / m.NAME
    st = path.stat()
    return path.read_bytes(), (st.st_dev, st.st_ino, st.st_uid, st.st_gid,
                              st.st_mode, st.st_size, st.st_mtime_ns, st.st_ctime_ns)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--disposable-vm-confirmed', action='store_true', required=True)
    parser.parse_args()
    secrets = m.guard()[m.NAME]
    m.command(['cc', '-std=c11', '-O2', '-Wall', '-Wextra', '-Wpedantic', '-Werror',
               str(m.WORK / 'password.c'), '-l:libpam.so.0', '-o', str(m.WORK / 'password-check')])
    original_record = next(line for line in Path('/etc/shadow').read_bytes().splitlines()
                           if line.startswith((m.NAME + ':').encode()))
    original_passwd = next(line for line in Path('/etc/passwd').read_bytes().splitlines()
                           if line.startswith((m.NAME + ':').encode()))
    kde = Path('/etc/pam.d/kde').read_bytes()
    results = []

    def restore():
        for path, record in [('/etc/shadow', original_record), ('/etc/passwd', original_passwd)]:
            lines = Path(path).read_bytes().splitlines()
            Path(path).write_bytes(b'\n'.join(record if line.startswith((m.NAME + ':').encode()) else line
                                           for line in lines) + b'\n')
        Path('/etc/pam.d/kde').write_bytes(kde)

    def prepare(operation):
        m.stop()
        m.command([m.ACCOUNT, 'begin-mutation'])
        m.prune_test_quarantines()
        restore()
        operation()
        m.reseal()

    def check(label, expected):
        before = counter()
        start = time.monotonic()
        actual = m.worker()
        elapsed = time.monotonic() - start
        m.require(actual == expected, 'wrong real eligibility outcome: ' + label)
        m.require(counter() == before, 'eligibility changed password accounting: ' + label)
        state = m.status()
        m.require((state['reason'] == 'none') == (expected == 0), 'broker policy wiring mismatch: ' + label)
        if expected:
            m.require(m.client('verify', secrets['pin'], check=False).returncode != 0,
                      'restricted account acquired a broker PIN challenge')
        results.append({'case': label, 'worker_outcome': actual, 'broker_reason': state['reason'],
                        'counter_bytes_and_metadata_unchanged': True, 'elapsed_ms': round(elapsed * 1000, 2)})

    m.command(['faillock', '--user', m.NAME, '--reset'])
    check('fedora-default-yescrypt', 0)
    baseline = password(secrets['password'])
    m.require(baseline['auth'] == baseline['account'] == 0 and baseline['prompts'] == 1,
              'original KDE password recovery baseline failed')
    for label, operation, expected in [
        ('locked', lambda: m.command(['passwd', '-l', m.NAME]), 1),
        ('expired-account', lambda: m.command(['chage', '-E', '1', m.NAME]), 1),
        ('expired-password', lambda: m.command(['chage', '-M', '1', '-d', '1', m.NAME]), 1),
        ('forced-password-change', lambda: m.command(['chage', '-d', '0', m.NAME]), 1),
        ('empty-password', lambda: m.command(['passwd', '-d', m.NAME]), 1),
        ('restricted-shell', lambda: m.command(['usermod', '-s', '/usr/sbin/nologin', m.NAME]), 1),
        ('unknown-required-policy', lambda: Path('/etc/pam.d/kde').write_bytes(kde + b'auth required pam_access.so\n'), 2),
    ]:
        prepare(operation)
        check(label, expected)
    prepare(lambda: m.command(['chpasswd', '--crypt-method', 'SHA512'],
                             data=(m.NAME + ':' + secrets['password'] + '\n').encode()))
    check('sha512-crypt-real-account', 0)
    sha_password = password(secrets['password'])
    m.require(sha_password['auth'] == sha_password['account'] == 0, 'real SHA512 password baseline failed')
    # Deliberate authoritative-state corruption, while durably revoked. Account
    # tools reject some malformed hashes; this tests the real worker's refusal.
    def malformed():
        rows = Path('/etc/shadow').read_bytes().splitlines()
        out = []
        for row in rows:
            fields = row.split(b':')
            if fields[0] == m.NAME.encode(): fields[1] = b'$y$jAT$unknown$malformed'
            out.append(b':'.join(fields))
        Path('/etc/shadow').write_bytes(b'\n'.join(out) + b'\n')
    prepare(malformed)
    check('malformed-unsupported-hash', 2)
    prepare(lambda: None)
    check('restored-default-yescrypt', 0)
    # Volatile runtime restrictions remain mutable; the production preflight
    # checks them on every call without changing the original PAM service.
    Path('/run/nologin').write_text('M6.1 dedicated VM restriction fixture\n')
    try:
        check('global-nologin', 1)
    finally:
        Path('/run/nologin').unlink()
    check('nologin-removed', 0)

    m.stop()
    m.command([m.ACCOUNT, 'begin-mutation'])
    m.command(['authselect', 'select', 'local', 'with-silent-lastlog', 'with-mdns4',
               'with-fingerprint', 'with-faillock', '--force'])
    nss = Path('/etc/authselect/nsswitch.conf')
    import re
    nss.write_text(re.sub(r'^(passwd|group|shadow):[^\n]*', r'\1: files', nss.read_text(), flags=re.M))
    m.reseal()
    check('with-faillock-healthy', 0)
    m.require(password(secrets['password'])['auth'] == 0, 'original with-faillock password baseline failed')
    for _ in range(3):
        m.require(password('dedicated-wrong-password', 'enroll')['auth'] != 0, 'wrong-password fixture unexpectedly accepted')
    check('active-faillock', 1)
    locked_counter = counter()
    denied = password(secrets['password'])
    m.require(denied['auth'] != 0 and counter() == locked_counter,
              'eligibility reset/bypassed original failure lockout')
    # This is an explicit fixture-admin reset, outside the eligibility path.
    m.command(['faillock', '--user', m.NAME, '--reset'])
    check('explicit-admin-faillock-reset', 0)
    recovered = password(secrets['password'])
    m.require(recovered['auth'] == recovered['account'] == 0, 'original password recovery failed')
    m.require(m.command(['getenforce']).stdout.strip() == b'Enforcing', 'SELinux changed')
    report = {'cases': results, 'original_password_recovery': True, 'sha512_password_recovery': True,
              'with_faillock_password_recovery': True, 'original_correct_password_denied_during_lockout': True,
              'eligibility_counter_mutations': 0, 'actual_production_worker_and_broker': True, 'selinux': 'Enforcing'}
    evidence = json.loads((m.WORK / 'evidence.json').read_text())
    evidence['eligibility'] = report
    (m.WORK / 'evidence.json').write_text(json.dumps(evidence, indent=2) + '\n')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
