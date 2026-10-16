#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
set -euo pipefail
umask 077
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../.." && pwd)
# Override with an extracted pam-devel include directory when absent on host.
include=${LOCALPIN_PAM_INCLUDE:-/usr/include}
libpam=${PAM_LIBRARY:-/usr/lib64/libpam.so.0}
security=${PAM_MODULE_DIR:-/usr/lib64/security}
if [[ ! -f "$include/security/pam_appl.h" || ! -f "$include/security/pam_modules.h" || ! -f "$include/security/pam_ext.h" ]]; then
    printf '%s\n' 'INFRA: PAM development headers unavailable; set LOCALPIN_PAM_INCLUDE or install pam-devel in the test VM.' >&2
    exit 77
fi
if [[ ! -f "$libpam" || ! -f "$security/pam_permit.so" || ! -f "$security/pam_deny.so" ]]; then
    printf '%s\n' 'INFRA: Linux-PAM library/permit/deny baseline modules unavailable.' >&2
    exit 77
fi
work=$(mktemp -d "${TMPDIR:-/tmp}/localpin-m1-pam.XXXXXXXX")
trap 'rm -rf -- "$work"' EXIT
cc=${CC:-cc}
flags=(-std=c11 -Wall -Wextra -Wpedantic -Werror -g -O2 -fstack-protector-strong -D_FORTIFY_SOURCE=3 -isystem "$include")
if [[ ${LOCALPIN_PAM_SANITIZE:-0} == 1 ]]; then
    flags+=(-fsanitize=address,undefined -fno-omit-frame-pointer)
fi
"$cc" "${flags[@]}" -fPIC -shared -Wl,-z,relro,-z,now -o "$work/pam_m1_fixture.so" "$root/experiments/m1/pam/module.c" "$libpam"
"$cc" "${flags[@]}" -Wl,-z,relro,-z,now -o "$work/harness" "$root/experiments/m1/pam/harness.c" "$libpam"
if [[ ${LOCALPIN_PAM_UNIX:-0} == 1 ]]; then
    "$root/experiments/m1/pam/run-unix.sh" "$work"
else
    "$work/harness" "$work" "$security"
fi
