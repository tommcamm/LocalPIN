#!/usr/bin/env python3
"""Guest-only M1 PAM experiments; never run mutation tests on an everyday host."""
# SPDX-License-Identifier: MIT OR Apache-2.0
import argparse
import ctypes
import ctypes.util
import datetime
import grp
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import secrets
import signal
import stat
import struct
import subprocess
import tempfile

TARGET = "localpintest"
MARKER = Path("/etc/localpin-m1-vm-guard")
ORDINARY = b"LocalPIN-M1-synthetic-password!"
SIX_DIGIT = b"481516"
WRONG = b"wrong-LocalPIN-M1-fixture"
NAIVE = b"001122"


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def command(argv, *, data=None, timeout=30):
    result = subprocess.run(argv, input=data, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, timeout=timeout)
    require(result.returncode == 0, f"{Path(argv[0]).name} failed (exit {result.returncode}); no raw output exported")
    return result.stdout


def guard():
    require(os.getuid() == 0 and os.geteuid() == 0, "run as guest root")
    st = MARKER.lstat()
    require(stat.S_ISREG(st.st_mode) and st.st_uid == st.st_gid == 0
            and stat.S_IMODE(st.st_mode) == 0o600 and st.st_nlink == 1,
            "unsafe VM guard marker")
    uuid = Path("/sys/class/dmi/id/product_uuid").read_text().strip()
    require(re.fullmatch(r"[0-9a-fA-F-]{36}", uuid) is not None, "invalid VM UUID")
    require(MARKER.read_text() == f"LOCALPIN-M1-DISPOSABLE-VM\ntarget={TARGET}\nuuid={uuid}\n",
            "VM guard marker does not match this guest")
    require(Path("/sys/fs/selinux/enforce").read_text().strip() == "1", "SELinux must be Enforcing")
    command(["systemd-detect-virt", "--vm"])
    entries = [line.split(":") for line in Path("/etc/passwd").read_text().splitlines()
               if line.split(":", 1)[0] == TARGET]
    require(len(entries) == 1 and 1000 <= int(entries[0][2]) < 60000,
            "dedicated local ordinary test account required")
    account = pwd.getpwnam(TARGET)
    require(account.pw_uid == int(entries[0][2]), "local and NSS identities differ")
    groups = os.getgrouplist(TARGET, account.pw_gid)
    privileged = [g.gr_name for g in grp.getgrall() if g.gr_gid in groups and g.gr_name in {"wheel", "sudo"}]
    require(not privileged, "test account must not belong to wheel/sudo")
    return {"target": TARGET, "selinux": "Enforcing", "virtual_machine": True}


def graph():
    """Resolve actual includes under /etc/pam.d; keep raw files out of reports."""
    pending = ["password-auth"]
    services = {}
    while pending:
        service = pending.pop()
        if service in services:
            continue
        require(re.fullmatch(r"[A-Za-z0-9_.-]+", service) is not None
                and service not in {".", "..", "baseline", "capture", "naive"}, "unexpected PAM service name")
        path = Path("/etc/pam.d") / service
        data = path.read_bytes()
        text = data.decode("utf-8")
        require(len(data) <= 65536 and len(services) < 32, "PAM graph exceeds fixture limits")
        services[service] = {"sha256": hashlib.sha256(data).hexdigest(), "text": text}
        for line in text.splitlines():
            match = re.match(r"^\s*-?(?:auth|account|password|session)\s+(?:include|substack)\s+(\S+)", line)
            if match:
                pending.append(match.group(1))
    return services


def build(work):
    source = Path(__file__).resolve().parent
    include = os.environ.get("LOCALPIN_PAM_INCLUDE", "/usr/include")
    flags = ["-std=c11", "-O2", "-Wall", "-Wextra", "-Wpedantic", "-Werror",
             "-fstack-protector-strong", "-D_FORTIFY_SOURCE=3", "-isystem", include,
             "-Wl,-z,relro,-z,now"]
    command(["cc", *flags, "-fPIC", "-shared", str(source / "module.c"),
             "-o", str(work / "pam_m1_vm_fixture.so"), "-l:libpam.so.0"])
    command(["cc", *flags, str(source / "harness.c"), "-o", str(work / "harness"), "-l:libpam.so.0"])


def configure(work, services):
    # The target UID can read/execute fixtures but cannot alter their policy/code.
    work.chmod(0o755)
    for service in services:
        (work / service).symlink_to(Path("/etc/pam.d") / service)
    for mode in ("baseline", "capture", "naive"):
        text = ""
        if mode != "baseline":
            text = f"auth [success=done default=ignore] {work}/pam_m1_vm_fixture.so {mode}\n"
        text += "auth substack password-auth\naccount include password-auth\n"
        path = work / mode
        path.write_text(text)
        path.chmod(0o644)
    for filename in ("harness", "pam_m1_vm_fixture.so"):
        (work / filename).chmod(0o755)


def authenticate(work, mode, candidates, observe_account=True):
    read_fd, write_fd = os.pipe()
    try:
        # Input is bounded below PIPE_BUF and contains no real account password.
        payload = b"".join(struct.pack("!I", len(value)) + value for value in candidates)
        require(len(payload) <= 4096, "candidate fixture pipe bound exceeded")
        os.write(write_fd, payload)
        os.close(write_fd)
        write_fd = -1
        result = subprocess.run([str(work / "harness"), str(work), mode, str(read_fd), str(len(candidates)),
                                 "account" if observe_account else "auth-only"], pass_fds=(read_fd,),
                                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                timeout=45)
        require(result.returncode == 0, f"guarded native harness failed (exit {result.returncode}); no raw PAM messages exported")
        return json.loads(result.stdout)
    finally:
        os.close(read_fd)
        if write_fd >= 0:
            os.close(write_fd)


def shadow_record():
    records = [line for line in Path("/etc/shadow").read_text().splitlines()
               if line.split(":", 1)[0] == TARGET]
    require(len(records) == 1 and len(records[0].split(":")) == 9, "unexpected test-account shadow record")
    return records[0]


def set_password(password):
    # Root assigns a public test fixture without depending on enrollment quality
    # policy. No authentication policy files are modified.
    library = ctypes.util.find_library("crypt")
    require(library is not None, "libxcrypt unavailable for fixture assignment")
    crypt = ctypes.CDLL(library).crypt
    crypt.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
    crypt.restype = ctypes.c_char_p
    hashed = crypt(password, b"$6$" + secrets.token_hex(8).encode() + b"$")
    require(hashed is not None and hashed.startswith(b"$6$"), "fixture hashing failed")
    command(["chpasswd", "--encrypted"], data=TARGET.encode() + b":" + hashed + b"\n")
    today = str((datetime.date.today() - datetime.date(1970, 1, 1)).days)
    command(["chage", "-d", today, "-m", "0", "-M", "99999", "-W", "7", "-I", "-1", "-E", "-1", TARGET])


def restore_shadow(original):
    fields = original.split(":")
    # The original hash is delivered over stdin, never a command-line argument.
    command(["chpasswd", "--encrypted"], data=f"{TARGET}:{fields[1]}\n".encode())
    args = ["chage"]
    for option, value in zip(("-d", "-m", "-M", "-W", "-I", "-E"), fields[2:8]):
        args.extend((option, value or "-1"))
    command([*args, TARGET])
    require(shadow_record() == original, "shadow rollback differs; restore the clean VM snapshot")


def faillock_policy(services):
    lines = [line for value in services.values() for line in value["text"].splitlines()
             if re.match(r"^\s*-?(auth|account)\s", line) and "pam_faillock.so" in line]
    if not lines:
        return None
    options = {}
    path = Path("/etc/security/faillock.conf")
    if path.exists():
        for line in path.read_text().splitlines():
            match = re.match(r"^\s*([a-z_]+)\s*=\s*(\S+)\s*(?:#.*)?$", line)
            if match:
                options[match.group(1)] = match.group(2)
    overrides = set()
    for line in lines:
        require("conf=" not in line, "custom faillock conf unsupported by VM fixture")
        for key, value in re.findall(r"\b(deny|dir)=(\S+)", line):
            if key == "deny":
                overrides.add(value)
            else:
                require(value in {"/var/run/faillock", "/run/faillock"}, "custom faillock directory unsupported")
    require(len(overrides) <= 1, "conflicting faillock denial limits")
    threshold = int(next(iter(overrides), options.get("deny", "3")))
    require(1 <= threshold <= 10, "faillock threshold outside bounded VM fixture")
    require(options.get("dir", "/var/run/faillock") in {"/run/faillock", "/var/run/faillock"},
            "custom faillock storage unsupported")
    existing = Path("/run/faillock") / TARGET
    require(not existing.exists() or existing.stat().st_size == 0,
            "existing test-account failure records; use a fresh dedicated account/snapshot")
    return threshold


def reset_faillock(threshold):
    if threshold is not None:
        command(["faillock", "--user", TARGET, "--reset"])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--compile-only", action="store_true", help="compile locally; no PAM or account operations")
    parser.add_argument("--check-env", action="store_true", help="guest guard and policy inventory only")
    parser.add_argument("--run-mutate", action="store_true", help="temporarily modify only localpintest account state")
    parser.add_argument("--snapshot-confirmed", action="store_true", help="operator confirms a restorable clean VM snapshot exists")
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    os.umask(0o077)
    require(sum((args.compile_only, args.check_env, args.run_mutate)) == 1, "choose exactly one operation")
    if args.compile_only:
        with tempfile.TemporaryDirectory(prefix="localpin-m1-vm-pam-build-") as temporary:
            build(Path(temporary))
        print("COMPILE PASS; no PAM transaction or account mutation performed")
        return
    environment = guard()
    services = graph()
    threshold = faillock_policy(services)
    report = {"schema": 1, "guard": environment,
              "policy": {name: value["sha256"] for name, value in services.items()},
              "faillock_threshold": threshold, "results": [], "target_shadow_record_restored": False,
              "faillock_reset": False, "whole_vm_snapshot_restored": False}
    if args.check_env:
        print(json.dumps({**report, "check_only": True}, indent=2))
        return
    require(args.snapshot_confirmed, "confirm a restorable clean VM snapshot before changing the dedicated account")
    original = shadow_record()
    mutated = False

    def interrupted(signum, frame):
        del signum, frame
        raise RuntimeError("interrupted; rolling back dedicated test account")

    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)

    def record(name, observations, assertion):
        require(assertion(observations), f"assertion failed: {name}; sanitized observations={json.dumps(observations)}")
        report["results"].append({"case": name, "observations": observations, "passed": True})

    try:
        with tempfile.TemporaryDirectory(prefix="localpin-m1-vm-pam-") as temporary:
            work = Path(temporary)
            build(work)
            configure(work, services)
            mutated = True
            set_password(ORDINARY)
            reset_faillock(threshold)
            record("real password positive baseline", authenticate(work, "baseline", [ORDINARY]),
                   lambda r: r[0]["auth"] == r[0]["account"] == 0 and r[0]["prompts"] == 1)
            record("real password negative baseline", authenticate(work, "baseline", [WRONG], False),
                   lambda r: r[0]["auth"] == 7 and r[0]["prompts"] == 1)
            reset_faillock(threshold)
            record("same-entry ordinary password", authenticate(work, "capture", [ORDINARY]),
                   lambda r: r[0]["auth"] == 0 and r[0]["prompts"] == r[0]["capture_calls"] == 1)
            set_password(SIX_DIGIT)
            record("six-digit password positive baseline", authenticate(work, "baseline", [SIX_DIGIT]),
                   lambda r: r[0]["auth"] == r[0]["account"] == 0 and r[0]["prompts"] == 1)
            record("same-entry six-digit password", authenticate(work, "capture", [SIX_DIGIT]),
                   lambda r: r[0]["auth"] == 0 and r[0]["prompts"] == r[0]["capture_calls"] == 1)
            record("reused handle correct-wrong-correct", authenticate(work, "capture", [SIX_DIGIT, WRONG, SIX_DIGIT], False),
                   lambda r: [v["auth"] for v in r] == [0, 7, 0]
                   and all(v["prompts"] == 1 for v in r))
            reset_faillock(threshold)
            command(["usermod", "--lock", TARGET])
            record("locked password rejects real auth", authenticate(work, "baseline", [SIX_DIGIT]),
                   lambda r: r[0]["auth"] == 7)
            reset_faillock(threshold)
            record("naive PIN bypasses locked password auth", authenticate(work, "naive", [NAIVE]),
                   lambda r: r[0]["auth"] == 0 and r[0]["naive_success"] == 1)
            set_password(SIX_DIGIT)
            command(["chage", "--expiredate", "1", TARGET])
            record("expired account phase denies", authenticate(work, "baseline", [SIX_DIGIT]),
                   lambda r: r[0]["auth"] == 0 and r[0]["account"] == 13)
            record("naive PIN success still needs expired-account check", authenticate(work, "naive", [NAIVE]),
                   lambda r: r[0]["auth"] == 0 and r[0]["account"] == 13)
            set_password(SIX_DIGIT)
            command(["chage", "--lastday", "0", TARGET])
            record("expired password phase denies normal unlock eligibility", authenticate(work, "baseline", [SIX_DIGIT]),
                   lambda r: r[0]["auth"] == 0 and r[0]["account"] == 12)  # PAM_NEW_AUTHTOK_REQD
            record("naive PIN success still needs password-expiry check", authenticate(work, "naive", [NAIVE]),
                   lambda r: r[0]["auth"] == 0 and r[0]["account"] == 12)
            set_password(SIX_DIGIT)
            if threshold is not None:
                reset_faillock(threshold)
                for _ in range(threshold):
                    require(authenticate(work, "baseline", [WRONG], False)[0]["auth"] == 7,
                            "wrong password unexpectedly accepted")
                record("active faillock denies correct password", authenticate(work, "baseline", [SIX_DIGIT], False),
                       lambda r: r[0]["auth"] == 7)
                record("naive PIN bypasses active auth failure lockout", authenticate(work, "naive", [NAIVE], False),
                       lambda r: r[0]["auth"] == 0 and r[0]["naive_success"] == 1)
                # Account modules may reset counters: observe only after lockout assertions.
                record("account phase observed under failure lockout", authenticate(work, "naive", [NAIVE]),
                       lambda r: r[0]["auth"] == 0)
                reset_faillock(threshold)
                record("password recovery after fixture counter reset", authenticate(work, "baseline", [SIX_DIGIT]),
                       lambda r: r[0]["auth"] == r[0]["account"] == 0)
            else:
                report["not_tested"] = ["pam_faillock absent from active policy; test a lockout-enabled VM profile separately"]
    finally:
        # SIGKILL, guest power loss, or rollback failure still needs the VM snapshot.
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        if mutated:
            try:
                restore_shadow(original)
                report["target_shadow_record_restored"] = True
            finally:
                reset_faillock(threshold)
                report["faillock_reset"] = threshold is not None
    report["versions"] = command(["rpm", "-q", "pam", "pam-devel", "authselect", "kscreenlocker", "selinux-policy-targeted"]).decode().splitlines()
    report["not_tested"] = report.get("not_tested", []) + [
        "stock KDE conversation and keyboard input", "production LocalPIN adapter/backend/eligibility worker",
        "production broker SELinux domain and service sandbox", "whole-VM rollback: restore the clean snapshot separately"]
    rendered = json.dumps(report, indent=2) + "\n"
    if args.report:
        require(args.report.parent.exists(), "report parent directory must already exist")
        fd = os.open(args.report, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "w") as output:
            output.write(rendered)
    print(rendered, end="")


if __name__ == "__main__":
    try:
        main()
    except (OSError, RuntimeError, subprocess.SubprocessError, ValueError) as error:
        # Exceptions are deliberately restricted to sanitized operational text.
        print(f"M1 VM PAM stopped: {type(error).__name__}: {error}", file=__import__("sys").stderr)
        raise SystemExit(1)
