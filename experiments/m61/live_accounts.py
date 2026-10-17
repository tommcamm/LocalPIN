#!/usr/bin/env python3
"""Exercise Fedora account tools in disposable user/mount/PID namespaces.

This is native compatibility evidence for the live shadow-marker authority,
not the installed SELinux/TPM acceptance matrix. No guest account is changed:
the child bind-mounts synthetic /etc, /var, /run and /home before invoking tools.
Run as root only inside the UUID-guarded Fedora KDE 44 KVM test clone.
"""

from __future__ import annotations

import ctypes
import argparse
import fcntl
import json
import os
from pathlib import Path
import platform
import shutil
import struct
import subprocess
import sys
import tempfile
import time
import uuid


USER = "localpin_fixture"
UID = 23001
# glibc's NSS parser deliberately clamps numeric fields to unsigned 32-bit,
# even though struct spwd.sp_flag has unsigned-long storage on x86_64.
MARKER = 3291981167  # above INT_MAX, below UINT32_MAX; incarnation remains 128-bit


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def run(*args, input=None, timeout=20):
    result = subprocess.run(args, input=input, text=True, capture_output=True, timeout=timeout)
    require(result.returncode == 0, f"{args[0]} failed: {result.stderr.strip()}")
    return result.stdout


def shadow(name=USER):
    matches = [line.split(":") for line in Path("/etc/shadow").read_text().splitlines()
               if line.split(":", 1)[0] == name]
    require(len(matches) == 1 and len(matches[0]) == 9, "missing/ambiguous shadow fixture")
    return matches[0]


def set_marker():
    rows = Path("/etc/shadow").read_text().splitlines()
    for i, line in enumerate(rows):
        if line.startswith(USER + ":"):
            fields = line.split(":")
            fields[8] = str(MARKER)
            rows[i] = ":".join(fields)
    Path("/etc/shadow").write_text("\n".join(rows) + "\n")


def marker_preserved():
    require(shadow()[8] == str(MARKER), "native tool lost the shadow marker")


def record_lock(fd, lock_type, ofd):
    # Linux x86_64 struct flock; using OFD here makes ownership independent of
    # unrelated opens/closes by this process, matching the production authority.
    request = struct.pack("hh4xqqi4x", lock_type, os.SEEK_SET, 0, 0, 0)
    fcntl.fcntl(fd, fcntl.F_OFD_SETLK if ofd else fcntl.F_SETLK, request)


def guard(expected_uuid):
    require(os.getuid() == os.geteuid() == 0 and platform.machine() == "x86_64", "guest root/x86_64 required")
    expected_uuid = str(uuid.UUID(expected_uuid))
    require(str(uuid.UUID(Path("/sys/class/dmi/id/product_uuid").read_text().strip())) == expected_uuid,
            "test clone UUID mismatch")
    require(run("systemd-detect-virt", "--vm").strip() == "kvm", "KVM test clone required")
    require(run("getenforce").strip() == "Enforcing", "SELinux must remain enforcing")
    distro = dict(line.split("=", 1) for line in Path("/etc/os-release").read_text().splitlines() if "=" in line)
    require(distro.get("ID", "").strip('"') == "fedora"
            and distro.get("VERSION_ID", "").strip('"') == "44"
            and distro.get("VARIANT_ID", "").strip('"') == "kde", "Fedora KDE 44 required")


def wait_for_native_lock(process):
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        require(process.poll() is None, "native mutation exited instead of waiting for database lock")
        state = Path(f"/proc/{process.pid}/wchan").read_text().strip()
        if state == "locks_lock_inode_wait":
            return
        inode = str(Path("/etc/.pwd.lock").stat().st_ino)
        for line in Path("/proc/locks").read_text().splitlines():
            fields = line.split()
            if "->" in fields and fields[-3].rsplit(":", 1)[-1] == inode:
                return
        time.sleep(0.01)
    raise RuntimeError("native mutation did not enter the kernel record-lock wait (wchan=" + state + ")")


def blocked_mutation(args):
    readers = [os.open("/etc/.pwd.lock", os.O_RDWR | os.O_CLOEXEC) for _ in range(2)]
    for reader in readers:
        record_lock(reader, fcntl.F_RDLCK, True)
    unrelated = os.open("/etc/.pwd.lock", os.O_RDONLY)
    os.close(unrelated)
    before = [Path(path).read_bytes() for path in ("/etc/passwd", "/etc/shadow")]
    mutation = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        wait_for_native_lock(mutation)
        require(before == [Path(path).read_bytes() for path in ("/etc/passwd", "/etc/shadow")],
                "native mutation changed account data while readers held the lease")
        os.close(readers.pop())
        wait_for_native_lock(mutation)
        os.close(readers.pop())
        _, error = mutation.communicate(timeout=20)
        require(mutation.returncode == 0, "native mutation failed after lock release: " + error.decode())
    finally:
        for reader in readers:
            os.close(reader)
        if mutation.poll() is None:
            mutation.kill()
            mutation.communicate(timeout=5)


def child(expected_uuid):
    guard(expected_uuid)
    versions = run("rpm", "-q", "shadow-utils", "glibc.x86_64", "systemd", "accountsservice").splitlines()
    login_defs = Path("/etc/login.defs").read_text()
    run("mount", "--make-rprivate", "/")
    with tempfile.TemporaryDirectory(prefix="localpin-accounts-") as temporary:
        root = Path(temporary)
        for directory in ("etc", "var", "run", "home"):
            (root / directory).mkdir()
        etc = root / "etc"
        (etc / "default").mkdir()
        (etc / "pam.d").mkdir()
        (etc / "security").mkdir()
        shutil.copytree("/etc/selinux", etc / "selinux", symlinks=True)
        files = {
            "passwd": "root:x:0:0:root:/root:/bin/bash\n",
            "shadow": "root:!:20000:0:99999:7:::\n",
            "group": "root:x:0:\n",
            "gshadow": "root:!::\n",
            "subuid": "",
            "subgid": "",
            "login.defs": login_defs,
            "nsswitch.conf": "passwd: files\ngroup: files\nshadow: files\n",
            "shells": "/bin/bash\n/usr/bin/bash\n/bin/sh\n",
            ".pwd.lock": "",
            "pam.d/chpasswd": "password required pam_unix.so yescrypt shadow\n",
            "pam.d/passwd": "password required pam_unix.so yescrypt shadow\n",
            "pam.d/newusers": "password required pam_unix.so yescrypt shadow\n",
        }
        for name, contents in files.items():
            path = etc / name
            path.write_text(contents)
            path.chmod(0o600 if name in ("shadow", "gshadow", ".pwd.lock") else 0o644)
        for directory in ("etc", "var", "run", "home"):
            run("mount", "--bind", str(root / directory), "/" + directory)
        for directory in ("/var/log", "/var/mail", "/var/lib", "/run/lock"):
            Path(directory).mkdir(parents=True, exist_ok=True)

        # These are ordinary invocations (no --prefix); they use lckpwdf and
        # therefore the exact native lock path the production reader retains.
        add = ("useradd", "-M", "-N", "-g", "0", "-u", str(UID), "-d", "/home/" + USER,
               "-s", "/bin/bash", "-K", "SUB_UID_COUNT=0", "-K", "SUB_GID_COUNT=0", USER)
        run(*add)
        require(shadow()[8] == "", "new account unexpectedly has a marker")
        set_marker()

        # libc must parse/serialize the marker losslessly. A regression guard
        # records the native parser's 32-bit limit, which a 64-bit type obscures.
        class Spwd(ctypes.Structure):
            _fields_ = [("name", ctypes.c_char_p), ("password", ctypes.c_char_p),
                        *[(key, ctypes.c_long) for key in ("last", "min", "max", "warn", "inact", "expire")],
                        ("flag", ctypes.c_ulong)]
        libc = ctypes.CDLL(None)
        libc.sgetspent.argtypes = [ctypes.c_char_p]
        libc.sgetspent.restype = ctypes.POINTER(Spwd)
        row = ":".join(shadow()).encode()
        parsed = libc.sgetspent(row)
        require(bool(parsed) and parsed.contents.flag == MARKER, "glibc truncated shadow marker")
        excessive = row.rsplit(b":", 1)[0] + b":" + str(1 << 32).encode()
        require(libc.sgetspent(excessive).contents.flag == (1 << 32) - 1,
                "glibc reserved-field width changed; review marker compatibility")
        empty = row.rsplit(b":", 1)[0] + b":"
        require(libc.sgetspent(empty).contents.flag == (1 << 64) - 1,
                "glibc empty-field sentinel differs from ULONG_MAX")

        run("usermod", "-c", "Fixture renamed comment", USER)
        marker_preserved()
        run("usermod", "-l", USER + "_renamed", USER)
        require(shadow(USER + "_renamed")[8] == str(MARKER), "rename lost the marker")
        run("usermod", "-l", USER, USER + "_renamed")
        marker_preserved()
        run("usermod", "-L", USER)
        marker_preserved()
        run("usermod", "-U", USER)
        marker_preserved()
        run("chage", "-M", "90000", USER)
        marker_preserved()
        # chpasswd's PAM update exercises pam_unix's shadow serialization.
        run("chpasswd", input=USER + ":Fixture-Only-Password-41!\n")
        marker_preserved()
        run("passwd", "-l", USER)
        marker_preserved()
        run("passwd", "-u", USER)
        marker_preserved()
        run("newusers", input=f"{USER}:Fixture-Only-Password-42!:{UID}:0:Fixture:/home/{USER}:/bin/bash\n")
        marker_preserved()
        run("systemd-sysusers", "--inline", "u localpin_package 23002:0 'Package fixture' / /usr/sbin/nologin")
        marker_preserved()
        require(shadow("localpin_package")[8] == "", "sysusers assigned a new marker")

        # Shared OFD ownership survives an unrelated close. Both shadow-utils
        # and systemd-sysusers must wait until all readers release the lock.
        blocked_mutation(["usermod", "-c", "Waited for OFD reader", USER])
        marker_preserved()
        blocked_mutation(["systemd-sysusers", "--inline", "u localpin_package_two 23003:0 'Package'"])
        marker_preserved()

        # A native glibc writer excludes newly arriving OFD readers as well.
        writer = subprocess.Popen([sys.executable, "-c",
            "import ctypes,sys;libc=ctypes.CDLL(None);assert libc.lckpwdf()==0;"
            "print('locked',flush=True);sys.stdin.buffer.read(1);assert libc.ulckpwdf()==0"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        require(writer.stdout.readline() == b"locked\n", "glibc writer could not acquire native lock")
        reader = os.open("/etc/.pwd.lock", os.O_RDONLY | os.O_CLOEXEC)
        try:
            try:
                record_lock(reader, fcntl.F_RDLCK, True)
            except BlockingIOError:
                pass
            else:
                raise RuntimeError("OFD reader bypassed native glibc writer")
        finally:
            os.close(reader)
            writer.communicate(input=b"x", timeout=5)
        require(writer.returncode == 0, "glibc writer cleanup failed")

        # Delete/recreate with every public field identical must lose the marker
        # even while LocalPIN is absent. This is the incarnation proof.
        old_password_hash = shadow()[1]
        blocked_mutation(["userdel", USER])
        require(not any(line.startswith(USER + ":") for line in Path("/etc/shadow").read_text().splitlines()),
                "userdel retained shadow identity")
        # Importing the identical old password hash is still a new account.
        run(*add[:-1], "-p", old_password_hash, USER)
        require(shadow()[8] == "", "recreated account inherited the old marker")
        print(json.dumps({"passed": True, "versions": versions,
                          "isolated_mount_pid_namespaces": True,
                          "guarded_fedora44_kde_kvm": True,
                          "glibc_reserved_field_width": 32,
                          "glibc_unsigned_marker": True,
                          "marker_preserved": ["usermod", "chage", "chpasswd/PAM", "passwd", "newusers", "systemd-sysusers"],
                          "native_mutations_wait_for_ofd_readers": ["usermod", "systemd-sysusers", "userdel"],
                          "ofd_readers_refuse_native_glibc_writer": True,
                          "identical_uid_name_home_password_hash_recreation_loses_marker": True}, indent=2))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--uuid", required=True, help="independently validated disposable clone UUID")
    parser.add_argument("--namespace-child", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.namespace_child:
        child(args.uuid)
    else:
        guard(args.uuid)
        subprocess.run(["unshare", "--mount", "--pid", "--fork", "--mount-proc",
                        sys.executable, str(Path(__file__).resolve()), "--uuid", args.uuid,
                        "--namespace-child"], check=True)


if __name__ == "__main__":
    main()
