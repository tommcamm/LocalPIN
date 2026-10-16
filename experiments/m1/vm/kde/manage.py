#!/usr/bin/env python3
"""Guarded guest-only installation of a KDE candidate capture module that never authorizes."""
# SPDX-License-Identifier: MIT OR Apache-2.0
import argparse
from contextlib import contextmanager
import grp
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import stat
import signal
import subprocess
import tempfile

TARGET = "localpintest"
PAM = Path("/etc/pam.d/kde")
MODULE = Path("/usr/lib64/security/pam_localpin_m1_fallback.so")
STATE = Path("/var/lib/localpin-m1-kde")
MARKER = Path("/etc/localpin-m1-vm-guard")
BLOCK = (b"# BEGIN LOCALPIN M1 FALLBACK-ONLY (NEVER AUTHORIZES)\n"
         b"auth [default=ignore] /usr/lib64/security/pam_localpin_m1_fallback.so\n"
         b"# END LOCALPIN M1 FALLBACK-ONLY\n")


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def run(argv):
    p = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
    require(p.returncode == 0, f"{Path(argv[0]).name} failed (exit {p.returncode}); raw output suppressed")
    return p.stdout


@contextmanager
def recovery_window():
    # Complete a bounded restoration before accepting another interruption.
    previous = {sig: signal.signal(sig, signal.SIG_IGN) for sig in (signal.SIGINT, signal.SIGTERM)}
    try:
        yield
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)


def interrupted(signum, frame):
    del signum, frame
    raise RuntimeError("interrupted; recovering original policy where installed and retaining durable backup")


def digest(data):
    return hashlib.sha256(data).hexdigest()


def guard():
    require(os.getuid() == os.geteuid() == 0, "guest root required")
    marker = MARKER.lstat()
    require(stat.S_ISREG(marker.st_mode) and marker.st_uid == marker.st_gid == 0
            and stat.S_IMODE(marker.st_mode) == 0o600 and marker.st_nlink == 1,
            "unsafe VM guard marker")
    uuid = Path("/sys/class/dmi/id/product_uuid").read_text().strip()
    require(re.fullmatch(r"[0-9a-fA-F-]{36}", uuid) is not None, "invalid guest UUID")
    require(MARKER.read_text() == f"LOCALPIN-M1-DISPOSABLE-VM\ntarget={TARGET}\nuuid={uuid}\n",
            "marker does not match this VM")
    require(Path("/sys/fs/selinux/enforce").read_text().strip() == "1", "SELinux must be Enforcing")
    run(["systemd-detect-virt", "--vm", "--quiet"])
    local = [line.split(":") for line in Path("/etc/passwd").read_text().splitlines()
             if line.split(":", 1)[0] == TARGET]
    require(len(local) == 1 and 1000 <= int(local[0][2]) < 60000, "ordinary local test account required")
    account = pwd.getpwnam(TARGET)
    require(account.pw_uid == int(local[0][2]), "NSS and local test identity differ")
    group_ids = os.getgrouplist(TARGET, account.pw_gid)
    require(not any(g.gr_gid in group_ids and g.gr_name in {"root", "wheel", "sudo"}
                    for g in grp.getgrall()), "test account must not have administrative group membership")


def safe_file(path):
    st = path.lstat()
    require(stat.S_ISREG(st.st_mode) and st.st_uid == st.st_gid == 0
            and st.st_nlink == 1 and not st.st_mode & 0o022, f"unsafe root-owned file: {path}")
    return st


def sync_dir(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def atomic(path, data, mode, context=None):
    descriptor, temporary = tempfile.mkstemp(prefix=".localpin-m1-", dir=path.parent)
    temporary = Path(temporary)
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(data)
            os.fchmod(output.fileno(), mode)
            os.fchown(output.fileno(), 0, 0)
            if context is not None:
                os.setxattr(output.fileno(), "security.selinux", context.encode() + b"\0")
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
        sync_dir(path.parent)
    finally:
        temporary.unlink(missing_ok=True)


def label(path, reference=None):
    run(["restorecon", "-F", str(path)])
    wanted = run(["matchpathcon", "-n", str(path)]).decode().strip()
    actual = os.getxattr(path, "security.selinux").rstrip(b"\0").decode()
    require(actual == wanted, f"SELinux label mismatch: {path}")
    if reference is not None:
        expected_type = os.getxattr(reference, "security.selinux").rstrip(b"\0").decode().split(":")[2]
        require(actual.split(":")[2] == expected_type, "module label differs from distribution PAM module type")
    return actual


def build(directory, contact_fixture=False):
    module = directory / "module.so"
    include = os.environ.get("LOCALPIN_PAM_INCLUDE", "/usr/include")
    definitions = ["-DLOCALPIN_M1_CONTACT_FIXTURE=1"] if contact_fixture else []
    run(["cc", *definitions, "-std=c11", "-O2", "-Wall", "-Wextra", "-Wpedantic", "-Werror",
         "-fstack-protector-strong", "-D_FORTIFY_SOURCE=3", "-fPIC", "-shared",
         "-isystem", include, "-Wl,-z,relro,-z,now", str(Path(__file__).with_name("module.c")),
         "-o", str(module), "-l:libpam.so.0"])
    return module.read_bytes()


def plan(original):
    require(b"LOCALPIN M1" not in original, "M1 block already present")
    require(not re.search(rb"^\s*[^#\n].*pam_(?:pinlock|localpin)\S*", original, re.M), "another PIN module is already active")
    first = re.search(rb"^\s*-?auth\s+", original, re.M)
    require(first is not None, "unrecognized KDE PAM layout: no auth section")
    require(b"\x00" not in original and len(original) <= 65536, "invalid KDE PAM file")
    return original[:first.start()] + BLOCK + original[first.start():]


def state_dir():
    st = STATE.lstat()
    require(stat.S_ISDIR(st.st_mode) and st.st_uid == st.st_gid == 0
            and stat.S_IMODE(st.st_mode) == 0o700, "unsafe M1 state directory")


def load():
    state_dir()
    safe_file(STATE / "state.json")
    saved = json.loads((STATE / "state.json").read_text())
    require(saved.get("schema") == 1, "unknown M1 state schema")
    require(saved.get("build_mode", "capture-only") in {"capture-only", "contact-fixture"}, "unknown M1 module build mode")
    safe_file(STATE / "kde.original")
    safe_file(STATE / "module.so")
    original = (STATE / "kde.original").read_bytes()
    module = (STATE / "module.so").read_bytes()
    require(digest(original) == saved["original_sha256"] and digest(module) == saved["module_sha256"],
            "M1 backups have changed")
    require(digest(plan(original)) == saved["installed_sha256"], "M1 policy manifest mismatch")
    return saved, original, module


def install(contact_fixture=False):
    require(not STATE.exists() and not STATE.is_symlink(), "M1 state already exists; inspect/restore it first")
    require(not MODULE.exists() and not MODULE.is_symlink(), "experiment module path already exists")
    st = safe_file(PAM)
    original = PAM.read_bytes()
    installed = plan(original)
    old_context = os.getxattr(PAM, "security.selinux").rstrip(b"\0").decode()
    require(old_context == run(["matchpathcon", "-n", str(PAM)]).decode().strip(),
            "original PAM file has a nonstandard SELinux label")
    with tempfile.TemporaryDirectory(prefix="localpin-m1-kde-build-") as temporary:
        module = build(Path(temporary), contact_fixture)
    STATE.mkdir(mode=0o700)
    sync_dir(STATE.parent)
    atomic(STATE / "kde.original", original, 0o600)
    atomic(STATE / "module.so", module, 0o600)
    saved = {"schema": 1, "build_mode": "contact-fixture" if contact_fixture else "capture-only", "original_sha256": digest(original), "installed_sha256": digest(installed),
             "module_sha256": digest(module), "original_mode": stat.S_IMODE(st.st_mode), "original_context": old_context}
    atomic(STATE / "state.json", json.dumps(saved, indent=2).encode() + b"\n", 0o600)
    # The complete manifest and backup are durable before integration is changed.
    try:
        atomic(MODULE, module, 0o755, run(["matchpathcon", "-n", str(MODULE)]).decode().strip())
        label(MODULE, Path("/usr/lib64/security/pam_unix.so"))
        require(digest(PAM.read_bytes()) == saved["original_sha256"], "KDE policy changed while preparing")
        atomic(PAM, installed, saved["original_mode"], old_context)
        label(PAM)
        require(digest(PAM.read_bytes()) == saved["installed_sha256"], "installed PAM digest mismatch")
    except BaseException:
        # SIGINT/SIGTERM also reach this path; a second signal must not interrupt
        # the original-byte/default-label recovery window.
        with recovery_window():
            if digest(PAM.read_bytes()) == saved["installed_sha256"]:
                atomic(PAM, original, saved["original_mode"], saved["original_context"])
                require(label(PAM) == old_context, "automatic policy recovery label mismatch")
                require(digest(PAM.read_bytes()) == saved["original_sha256"], "automatic policy recovery digest mismatch")
        raise
    return {"installed": True, "fallback_only": True, **saved}


def _restore():
    saved, original, module = load()
    safe_file(PAM)
    current = digest(PAM.read_bytes())
    require(current in {saved["installed_sha256"], saved["original_sha256"]},
            "KDE file changed; refusing to overwrite unrelated changes")
    if current != saved["original_sha256"]:
        atomic(PAM, original, saved["original_mode"], saved["original_context"])
    require(label(PAM) == saved["original_context"], "restored PAM label differs from original")
    require(digest(PAM.read_bytes()) == saved["original_sha256"], "restored PAM digest mismatch")
    if MODULE.exists() or MODULE.is_symlink():
        safe_file(MODULE)
        require(digest(MODULE.read_bytes()) == digest(module), "module changed; refusing to delete it")
        MODULE.unlink()
        sync_dir(MODULE.parent)
    for filename in ("state.json", "kde.original", "module.so"):
        (STATE / filename).unlink()
    STATE.rmdir()
    sync_dir(STATE.parent)
    return {"restored": True, "original_sha256": saved["original_sha256"], "module_removed": True}


def restore():
    with recovery_window():
        return _restore()


def missing_module(put_back):
    saved, _, module = load()
    safe_file(PAM)
    require(digest(PAM.read_bytes()) == saved["installed_sha256"], "KDE policy differs from exact installed experiment")
    if put_back:
        require(not MODULE.exists() and not MODULE.is_symlink(), "module must be absent before restoration")
        atomic(MODULE, module, 0o755, run(["matchpathcon", "-n", str(MODULE)]).decode().strip())
        context = label(MODULE, Path("/usr/lib64/security/pam_unix.so"))
        return {"module_restored": True, "context": context}
    safe_file(MODULE)
    require(digest(MODULE.read_bytes()) == saved["module_sha256"], "module changed; refusing to remove it")
    MODULE.unlink()
    sync_dir(MODULE.parent)
    return {"module_deliberately_missing": True, "pam_control": "default=ignore"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("compile-only", "check", "install", "status", "restore", "simulate-missing-module", "restore-module"))
    parser.add_argument("--snapshot-confirmed", action="store_true")
    parser.add_argument("--contact-fixture", action="store_true", help="optional fixed PING/PONG contact only; no candidate is transmitted")
    args = parser.parse_args()
    os.umask(0o077)
    require(not args.contact_fixture or args.operation in {"compile-only", "install"}, "contact build flag applies only to compile/install")
    if args.operation == "compile-only":
        with tempfile.TemporaryDirectory(prefix="localpin-m1-kde-compile-") as temporary:
            module = build(Path(temporary), args.contact_fixture)
        # Pure policy operations verify byte restoration and rejection of own block.
        original = b"# synthetic fixture\nauth substack password-auth\naccount include password-auth\n"
        require(plan(original).replace(BLOCK, b"", 1) == original, "policy insertion changed original bytes")
        print(json.dumps({"compiled": True, "fallback_only": True, "build_mode": "contact-fixture" if args.contact_fixture else "capture-only", "module_bytes": len(module), "pure_policy_check": True}))
        return
    signal.signal(signal.SIGINT, interrupted)
    signal.signal(signal.SIGTERM, interrupted)
    guard()
    if args.operation == "check":
        safe_file(PAM)
        planned = plan(PAM.read_bytes())
        result = {"guard_passed": True, "selinux": "Enforcing", "planned_sha256": digest(planned), "fallback_only": True}
    elif args.operation == "install":
        require(args.snapshot_confirmed, "a restorable clean VM snapshot must be confirmed")
        result = install(args.contact_fixture)
    elif args.operation == "restore":
        result = restore()
    elif args.operation in {"simulate-missing-module", "restore-module"}:
        result = missing_module(args.operation == "restore-module")
    else:
        saved, _, _ = load()
        safe_file(PAM)
        result = {"manifest": saved, "current_pam_sha256": digest(PAM.read_bytes()), "module_present": MODULE.exists()}
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    try:
        main()
    except (OSError, RuntimeError, ValueError, KeyError, subprocess.SubprocessError) as error:
        print(f"M1 KDE experiment stopped: {type(error).__name__}: {error}", file=__import__("sys").stderr)
        raise SystemExit(1)
