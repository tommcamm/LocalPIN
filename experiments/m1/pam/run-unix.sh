#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# Internal opt-in runner; invoke via LOCALPIN_PAM_UNIX=1 ./run.sh.
set -euo pipefail
umask 077
work=${1:?private build directory required}
if ! command -v bwrap >/dev/null || ! command -v python3 >/dev/null; then
    printf '%s\n' 'INFRA: synthetic pam_unix check requires bubblewrap and Python 3.' >&2
    exit 77
fi
# Probe before generating fixtures. Mount /usr only; never expose the host /etc.
namespace=(bwrap --unshare-all --die-with-parent --new-session
    --ro-bind /usr /usr --symlink usr/lib64 /lib64 --symlink usr/lib /lib
    --symlink usr/bin /bin --proc /proc --dev /dev --tmpfs /tmp)
if ! "${namespace[@]}" /usr/bin/true; then
    printf '%s\n' 'INFRA: unprivileged namespaces unavailable; run this optional check in a disposable VM.' >&2
    exit 77
fi
mkdir "$work/etc"
python3 - "$work/etc" <<'PY'
import ctypes
import pathlib
import sys

etc = pathlib.Path(sys.argv[1])
crypt = ctypes.CDLL('libcrypt.so.2')
crypt.crypt.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
crypt.crypt.restype = ctypes.c_char_p
# Public synthetic fixtures only. Never parameterize this with host credentials.
users = [
    ('localpin_synthetic', b'481516'),
    ('localpin_ordinary', b'synthetic-password'),
    ('localpin_bytes', b'\x80\xff\xc3\xa9 \t'),
]
passwd = ['root:x:0:0:synthetic namespace root:/:/bin/false']
shadow = ['root:*:20000:0:99999:7:::']
for uid, (user, password) in enumerate(users, 1000):
    hashed = crypt.crypt(password, b'$6$localpin-m1$')
    if hashed is None or not hashed.startswith(b'$6$'):
        raise RuntimeError('synthetic password hashing unavailable')
    passwd.append(f'{user}:x:{uid}:1000:Synthetic PAM fixture:/:/bin/false')
    shadow.append(f'{user}:{hashed.decode("ascii")}:20000:0:99999:7:::')
(etc / 'passwd').write_text('\n'.join(passwd) + '\n')
(etc / 'shadow').write_text('\n'.join(shadow) + '\n')
(etc / 'shadow').chmod(0o600)
(etc / 'group').write_text('root:x:0:\nsynthetic:x:1000:\n')
(etc / 'nsswitch.conf').write_text('passwd: files\ngroup: files\nshadow: files\n')
(etc / 'login.defs').write_text('ENCRYPT_METHOD SHA512\n')
PY
# Namespace UID 0 has no host-root privilege. Only this generated /etc is visible.
# /fixture is writable so pam_start_confdir services are created there, not /etc.
"${namespace[@]}" --uid 0 --gid 0 --ro-bind "$work/etc" /etc \
    --bind "$work" /fixture --chdir /fixture \
    /fixture/harness /fixture /usr/lib64/security --unix
