#!/usr/bin/python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Installed native PAM type/whitespace refusal proof in the guarded test VM.

Only the dedicated fixture account and three fixed generated authselect files
are exercised. Host topology validation is mandatory before execution. Raw
native outcomes, original policies and failure details remain guest-root-only.
"""
import argparse
import base64
import ctypes
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import traceback
import uuid

WORK = Path('/root/localpin-m8')
RUN = None
TARGETS = tuple(Path('/etc/authselect') / name for name in ('password-auth', 'fingerprint-auth', 'postlogin'))
PREFIXES = (('uppercase_auth', b'AUTH requisite pam_deny.so\n'),
            ('unknown_type', b'unknown requisite pam_deny.so\n'),
            ('nbsp_auth', '\u00a0auth requisite pam_deny.so\n'.encode()),
            ('nbsp_comment', '\u00a0# policy review\n'.encode()))


def require(value, message):
    if not value:
        raise RuntimeError(message)


def private_write(name, value):
    require(RUN is not None and re.fullmatch('[a-z0-9._-]+', name), 'fixed private output required')
    descriptor = os.open(RUN / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    with os.fdopen(descriptor, 'w') as stream:
        json.dump(value, stream, sort_keys=True, indent=2)
        stream.write('\n')
        stream.flush()
        os.fsync(stream.fileno())
    m.sync_directory(RUN)


def policy_bytes(path):
    require(path in TARGETS, 'policy input escaped fixed generated files')
    m.owned_file(path, owner=0)
    return path.read_bytes()


def restore_bytes(path, value):
    # Preserve the existing root-owned inode, permissions and SELinux label.
    policy_bytes(path)
    descriptor = os.open(path, os.O_WRONLY | os.O_TRUNC | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(descriptor, 'wb') as stream:
        stream.write(value)
        stream.flush()
        os.fsync(stream.fileno())


def tally_bytes():
    info = m.TALLY.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_uid == m.UID and info.st_gid == 0
            and stat.S_IMODE(info.st_mode) == 0o660 and info.st_nlink == 1
            and info.st_size <= 65536 and info.st_size % 64 == 0, 'canonical native tally required')
    descriptor = os.open(m.TALLY, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(descriptor, 'rb') as stream:
        value = stream.read(65537)
    require(len(value) <= 65536 and len(value) % 64 == 0, 'native tally changed beyond its bound')
    return value


def supported():
    return m.command([m.ACCOUNT, 'check-policy'], check=False).returncode == 0


def password_success(secrets):
    rows = m.pam(secrets[m.NAME]['password'])
    require(len(rows) == 1 and rows[0]['auth'] == rows[0]['setcred'] == 0,
            'restored native full-password route failed')
    require(tally_bytes() == b'', 'genuine full-password success did not clear native history')


def fingerprint_authenticate():
    class Message(ctypes.Structure):
        _fields_ = [('style', ctypes.c_int), ('text', ctypes.c_char_p)]
    class Response(ctypes.Structure):
        _fields_ = [('text', ctypes.c_void_p), ('code', ctypes.c_int)]
    Callback = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_int,
                               ctypes.POINTER(ctypes.POINTER(Message)),
                               ctypes.POINTER(ctypes.POINTER(Response)), ctypes.c_void_p)
    allocator = ctypes.CDLL(None)
    allocator.calloc.argtypes = [ctypes.c_size_t, ctypes.c_size_t]
    allocator.calloc.restype = ctypes.c_void_p
    prompts = []
    @Callback
    def converse(count, messages, responses, _opaque):
        if not (0 < count <= 16 and messages and responses):
            return 19
        styles = [messages[index].contents.style for index in range(count)]
        prompts.extend(styles)
        if any(style not in (3, 4) for style in styles):
            return 19
        memory = allocator.calloc(count, ctypes.sizeof(Response))
        if not memory:
            return 5
        responses[0] = ctypes.cast(memory, ctypes.POINTER(Response))
        return 0
    class Conversation(ctypes.Structure):
        _fields_ = [('callback', Callback), ('data', ctypes.c_void_p)]
    native = ctypes.CDLL('/usr/lib64/libpam.so.0')
    native.pam_start.argtypes = [ctypes.c_char_p, ctypes.c_char_p,
                                ctypes.POINTER(Conversation), ctypes.POINTER(ctypes.c_void_p)]
    native.pam_authenticate.argtypes = [ctypes.c_void_p, ctypes.c_int]
    native.pam_end.argtypes = [ctypes.c_void_p, ctypes.c_int]
    handle, conversation = ctypes.c_void_p(), Conversation(converse, None)
    require(native.pam_start(b'kde-fingerprint', b'lp61test', ctypes.byref(conversation), ctypes.byref(handle)) == 0,
            'fixed native fingerprint service did not start')
    result = native.pam_authenticate(handle, 0)
    require(native.pam_end(handle, result) == 0, 'fixed fingerprint service did not finish')
    return {'native_factor_denied': result != 0, 'no_interactive_prompt': not any(style in (1, 2) for style in prompts)}


def main():
    global RUN, m
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--expected-uuid', required=True)
    parser.add_argument('--expected-localpin-evr', required=True)
    parser.add_argument('--disposable-vm-confirmed', action='store_true', required=True)
    parser.add_argument('--emulated-tpm-confirmed', action='store_true', required=True)
    parser.add_argument('--fingerprint-probe', action='store_true', help=argparse.SUPPRESS)
    args = parser.parse_args()
    require(os.getuid() == os.geteuid() == 0 and str(uuid.UUID(args.expected_uuid)) == args.expected_uuid,
            'actual guest root and canonical clone UUID required')
    info = WORK.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 0
            and stat.S_IMODE(info.st_mode) == 0o700, 'private fixed guest directory required')
    for name in ('run.py', 'guard.py'):
        info = (WORK / name).lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_uid == info.st_gid == 0
                and info.st_nlink == 1 and not info.st_mode & 0o022, 'unsafe common helper source')
    sys.path.insert(0, str(WORK))
    import run as m
    secrets = m.guard(args.expected_uuid)
    evr = m.command(['rpm', '-q', '--qf', '%{EVR}', 'localpin']).stdout.decode('ascii')
    require(evr == args.expected_localpin_evr, 'reviewed strict-policy RPM must be installed first')
    if args.fingerprint_probe:
        print(json.dumps(fingerprint_authenticate()))
        return
    descriptor = os.open(WORK / '.m81-maintenance.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    with os.fdopen(descriptor, 'rb') as lock:
        m.owned_file(WORK / '.m81-maintenance.lock', private=True, owner=0)
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        require(supported() and m.status().get('availability') == 'available'
                and m.status().get('enrolled_backend') == 'tpm2', 'supported existing TPM enrollment required')
        require(json.loads(m.admin('status').stdout)['gate'] in ('trial', 'active'), 'live trial or active gate required')
        raw = m.command(['authselect', 'current', '--raw']).stdout.decode('ascii').strip()
        tokens = raw.split()
        require(tokens[0] == 'local' and tokens.count('with-fingerprint') == tokens.count('with-faillock') == 1
                and all(re.fullmatch('[a-z0-9-]+', token) for token in tokens), 'known native local profile required')
        RUN = WORK / 'm81-policy-types'
        RUN.mkdir(mode=0o700, exist_ok=False)
        originals = {path: policy_bytes(path) for path in TARGETS}
        source_sha = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
        registry_sha = hashlib.sha256(Path('/var/lib/localpin-accounts/registry').read_bytes()).hexdigest()
        credentials = m.credential_records()
        private_write('intent.json', {'runner_sha256': source_sha, 'localpin_evr': evr, 'original_profile': raw,
                      'original_policies': {str(path): base64.b64encode(value).decode() for path, value in originals.items()},
                      'registry_sha256': registry_sha, 'credentials': credentials})
        observations = {}
        restored = False
        try:
            for path in TARGETS:
                for label, prefix in PREFIXES:
                    password_success(secrets)
                    wrong = secrets[m.NAME]['password'] + '-policy-probe'
                    rows = m.pam(wrong)
                    before = tally_bytes()
                    require(len(rows) == 1 and rows[0]['auth'] != 0 and len(before) > 0,
                            'genuine native failure history was not established')
                    key = path.name + '-' + label
                    restore_bytes(path, prefix + originals[path])
                    try:
                        require(not supported(), 'strict policy check accepted a noncanonical active type')
                        require(m.status().get('availability') != 'available', 'PIN eligibility accepted unsupported active syntax')
                        pin = m.command(m.user_command('/usr/libexec/localpin/m8-client', 'verify'),
                                        data=m.framed(secrets[m.NAME]['pin']), check=False, timeout=20)
                        require(pin.stdout.strip() != b'Granted', 'unsupported policy granted existing PIN')
                        if path.name == 'fingerprint-auth':
                            probe = subprocess.run([sys.executable, str(Path(__file__).resolve()), *sys.argv[1:],
                                                    '--fingerprint-probe'], capture_output=True, timeout=30)
                            require(probe.returncode == 0, 'bounded native fingerprint probe refused')
                            factor = json.loads(probe.stdout)
                            require(factor['native_factor_denied'] and factor['no_interactive_prompt'],
                                    'native fingerprint restriction was bypassed or prompted')
                        else:
                            rows = m.pam(secrets[m.NAME]['password'])
                            factor = {'native_factor_denied': len(rows) == 1 and rows[0]['auth'] != 0}
                            require(factor['native_factor_denied'], 'native full-password restriction was bypassed')
                        after = tally_bytes()
                        require(len(after) >= len(before) > 0, 'native restriction erased existing failure history')
                        observations[key] = {'policy_check_refused': True, 'pin_eligibility_refused': True,
                                             'existing_pin_denied': True, 'native_factor_denied': True,
                                             'native_failure_history_not_erased': True}
                        private_write(key + '.json', {'factor': factor, 'before_tally_b64': base64.b64encode(before).decode(),
                                      'after_tally_b64': base64.b64encode(after).decode()})
                    finally:
                        restore_bytes(path, originals[path])
                    require(supported(), 'exact native policy restoration was not supported')
                    password_success(secrets)
        finally:
            for path, value in originals.items():
                restore_bytes(path, value)
            try:
                m.command(['authselect', 'select', *tokens])
            finally:
                for path, value in originals.items():
                    restore_bytes(path, value)
                restored = all(policy_bytes(path) == value for path, value in originals.items())
                observed = m.command(['authselect', 'current', '--raw'], check=False)
                restored &= observed.returncode == 0 and observed.stdout.decode('ascii').strip() == raw
                private_write('restoration.json', {'exact_original_bytes_and_profile_restored': restored})
        require(restored and supported(), 'original native profile/policies were not restored')
        before_pin = tally_bytes()
        pin = m.pam(secrets[m.NAME]['pin'])
        require(len(pin) == 1 and pin[0]['auth'] == pin[0]['setcred'] == 0 and tally_bytes() == before_pin,
                'same restored PIN failed or reset native history')
        require(hashlib.sha256(Path('/var/lib/localpin-accounts/registry').read_bytes()).hexdigest() == registry_sha
                and m.credential_records() == credentials, 'policy tests replaced account or enrollment')
        require(m.command(['getenforce']).stdout.strip() == b'Enforcing', 'SELinux changed')
        result = {'passed': True, 'runner_sha256': source_sha, 'localpin_evr': evr, 'selinux': 'Enforcing',
                  'observations': observations, 'exact_original_bytes_and_profile_restored': True,
                  'same_existing_tpm_pin_verified': True, 'native_history_cleared_only_by_genuine_password_success': True,
                  'manual_tally_reset_performed': False, 'raw_evidence_guest_root_only': True}
        private_write('result.json', result)
        print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except Exception:
        if RUN is not None:
            try:
                private_write('failure.json', {'traceback': traceback.format_exc()})
            except Exception:
                pass
        print(json.dumps({'passed': False, 'error': 'guarded installed policy-type proof refused; inspect guest-root-only evidence'}))
        raise SystemExit(1) from None
