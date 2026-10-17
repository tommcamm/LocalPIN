#!/usr/bin/python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Toggle the stock disabled-fingerprint profile in the guarded M8.1 clone.

Requires the new RPM containing kde_native_policy_compatible to be installed.
Stage this and updates.py in the private M8 work directory; use the independently
validated host controller. No outside authentication files or real TPM are used.
"""
import argparse
import ctypes
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import traceback
import uuid

WORK = Path('/root/localpin-m8')
RUN = None


def fingerprint_authenticate():
    # Lab-only public Linux-PAM ABI probe. The fixed fingerprint service should
    # take the native disabled branch, deny without a prompt, and leave the tally.
    class Message(ctypes.Structure):
        _fields_ = [('style', ctypes.c_int), ('text', ctypes.c_char_p)]
    class Response(ctypes.Structure):
        _fields_ = [('text', ctypes.c_void_p), ('code', ctypes.c_int)]
    Callback = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_int,
                              ctypes.POINTER(ctypes.POINTER(Message)),
                              ctypes.POINTER(ctypes.POINTER(Response)), ctypes.c_void_p)
    calls = []
    allocator = ctypes.CDLL(None)
    allocator.calloc.argtypes = [ctypes.c_size_t, ctypes.c_size_t]
    allocator.calloc.restype = ctypes.c_void_p
    @Callback
    def conversation(count, messages, responses, opaque):
        if not (0 < count <= 16 and messages and responses):
            return 19
        styles = [messages[index].contents.style for index in range(count)]
        calls.extend(styles)
        if any(style not in (3, 4) for style in styles):
            return 19
        # pam_debug may publish informational status through the ordinary PAM
        # conversation. Acknowledge it without providing an authentication
        # candidate; PAM owns/frees the calloc response array after success.
        allocated = allocator.calloc(count, ctypes.sizeof(Response))
        if not allocated:
            return 5
        responses[0] = ctypes.cast(allocated, ctypes.POINTER(Response))
        return 0
    class Conversation(ctypes.Structure):
        _fields_ = [('callback', Callback), ('data', ctypes.c_void_p)]
    native = ctypes.CDLL('/usr/lib64/libpam.so.0')
    native.pam_start.argtypes = [ctypes.c_char_p, ctypes.c_char_p,
                                ctypes.POINTER(Conversation), ctypes.POINTER(ctypes.c_void_p)]
    native.pam_start.restype = ctypes.c_int
    native.pam_authenticate.argtypes = [ctypes.c_void_p, ctypes.c_int]
    native.pam_authenticate.restype = ctypes.c_int
    native.pam_end.argtypes = [ctypes.c_void_p, ctypes.c_int]
    native.pam_end.restype = ctypes.c_int
    handle, conv = ctypes.c_void_p(), Conversation(conversation, None)
    started = native.pam_start(b'kde-fingerprint', b'lp61test', ctypes.byref(conv), ctypes.byref(handle))
    if started != 0:
        raise RuntimeError('fixed fingerprint service did not start')
    result = native.pam_authenticate(handle, 0)
    if native.pam_end(handle, result) != 0:
        raise RuntimeError('fixed fingerprint service did not finish')
    return {'pam_return': result, 'interactive_prompts': sum(style in (1, 2) for style in calls),
            'informational_messages': sum(style in (3, 4) for style in calls)}


def main():
    global RUN
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--expected-uuid', required=True)
    parser.add_argument('--expected-localpin-evr', required=True)
    parser.add_argument('--disposable-vm-confirmed', action='store_true', required=True)
    parser.add_argument('--emulated-tpm-confirmed', action='store_true', required=True)
    args = parser.parse_args()
    expected = str(uuid.UUID(args.expected_uuid))
    if not (os.getuid() == os.geteuid() == 0 and expected == args.expected_uuid
            and args.disposable_vm_confirmed and args.emulated_tpm_confirmed
            and Path('/sys/class/dmi/id/product_uuid').read_text().strip().lower() == expected):
        raise RuntimeError('guarded explicit disposable VM confirmation required')
    info = WORK.lstat()
    if not (stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 0
            and stat.S_IMODE(info.st_mode) == 0o700):
        raise RuntimeError('private guest work directory required')
    sys.path.insert(0, str(WORK))
    import updates as proof
    import run as common
    secrets = common.guard(expected)
    proof.m8common = common
    lock = os.open(WORK / '.m81-maintenance.lock', os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC)
    lock_metadata = os.fstat(lock)
    proof.require(stat.S_ISREG(lock_metadata.st_mode) and lock_metadata.st_uid == lock_metadata.st_gid == 0
                  and lock_metadata.st_nlink == 1 and stat.S_IMODE(lock_metadata.st_mode) == 0o600,
                  'safe maintenance serialization lock required')
    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    proof.require(proof.query(['rpm', '-q', '--qf', '%{EVR}', 'localpin']).stdout.decode('ascii')
                  == args.expected_localpin_evr, 'new compatibility RPM must be installed first')
    RUN = WORK / 'm81-profile-without-fingerprint'
    RUN.mkdir(mode=0o700, exist_ok=False)
    proof.RUN = RUN
    raw = proof.query(['authselect', 'current', '--raw']).stdout.decode('ascii').strip()
    tokens = raw.split()
    proof.require(tokens[0] == 'local' and tokens.count('with-fingerprint') == 1
                  and tokens.count('with-faillock') == 1
                  and all(re.fullmatch('[a-z0-9-]+', token) for token in tokens),
                  'known local fingerprint/faillock profile required')
    digest = globals().get('RUNNER_SHA256')
    if digest is None:
        digest = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    proof.require(re.fullmatch('[0-9a-f]{64}', digest) is not None, 'source digest required')
    before = proof.snapshot()
    proof.private_write('before.json', before)
    proof.private_write('intent.json', {'runner_sha256': digest, 'original_authselect': raw,
                        'expected_localpin_evr': args.expected_localpin_evr})
    disabled = False
    restored = False
    try:
        disabled = True
        proof.query(['authselect', 'disable-feature', 'with-fingerprint'])
        canonical = '\n'.join(' '.join(row.split()) for rawrow in
                              Path('/etc/authselect/fingerprint-auth').read_text().splitlines()
                              if (row := rawrow.partition('#')[0].strip()))
        proof.require(canonical == 'auth required pam_debug.so auth=authinfo_unavail',
                      'stock disabled fingerprint graph required')
        proof.query(['/usr/libexec/localpin/localpin-account', 'check-policy'])
        without = proof.snapshot()
        proof.private_write('without-fingerprint.json', without)
        equal = proof.compare(before, without)
        proof.require(all(equal.values()), 'profile toggle changed exact enrolled account state')
        tally = common.tally()
        probe = fingerprint_authenticate()
        proof.private_write('native-disabled-probe.json', {'probe': probe,
                            'native_tally_unchanged': common.tally() == tally})
        proof.require(probe['pam_return'] != 0 and probe['interactive_prompts'] == 0
                      and common.tally() == tally, 'disabled factor prompted, granted or changed native counters')
        result = common.command(common.user_command('/usr/libexec/localpin/m8-client', 'verify'),
                                data=common.framed(secrets[common.NAME]['pin']), timeout=20)
        proof.require(result.stdout.strip() == b'Granted' and common.tally() == tally,
                      'same enrolled PIN failed under stock disabled fingerprint profile')
        proof.private_write('after-disabled-pin.json', proof.snapshot())
    finally:
        if disabled:
            proof.query(['authselect', 'select', *tokens])
            restored = proof.query(['authselect', 'current', '--raw']).stdout.decode('ascii').strip() == raw
        proof.private_write('restore.json', {'original_profile_restored': restored})
    proof.require(restored, 'original fingerprint profile was not restored')
    proof.query(['/usr/libexec/localpin/localpin-account', 'check-policy'])
    final = proof.snapshot()
    proof.private_write('after-restoration.json', final)
    proof.require(before['managed_markers'] == final['managed_markers'], 'restoration changed identity')
    changed = [path for path, value in before['files'].items()
               if value['bytes_b64'] != final['files'][path]['bytes_b64']]
    proof.require(all(path.endswith('/throttle') for path in changed),
                  'restoration changed state beyond the actual successful PIN throttle update')
    result = {'phase': 'without-fingerprint-profile', 'passed': True, 'runner_sha256': digest,
              'localpin_evr': args.expected_localpin_evr,
              'preservation_before_pin': equal, 'native_disabled_factor': probe,
              'disabled_factor_never_enabled_by_correction': True,
              'same_existing_tpm_pin_verified_without_reenrollment': True,
              'native_tally_unchanged': True, 'original_profile_restored': restored,
              'only_expected_pin_throttle_update_after_authorization': True,
              'selinux_enforcing': proof.query(['getenforce']).stdout.strip() == b'Enforcing',
              'raw_snapshots_guest_root_only': True}
    proof.require(result['selinux_enforcing'], 'SELinux changed')
    proof.private_write('result.json', result)
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except BaseException:
        if RUN is not None and RUN.is_dir():
            try:
                descriptor = os.open(RUN / 'failure.log', os.O_WRONLY | os.O_CREAT | os.O_EXCL
                                     | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
                with os.fdopen(descriptor, 'w') as stream:
                    stream.write(traceback.format_exc())
            except BaseException:
                pass
        print(json.dumps({'phase': 'without-fingerprint-profile', 'passed': False,
                          'error': 'guarded profile proof refused; inspect guest-root-only evidence'}))
        raise SystemExit(1) from None
