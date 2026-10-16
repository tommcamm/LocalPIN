#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Opt-in, guarded disposable-VM SELinux experiment. Never use on an everyday host."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time

GUARD = Path("/etc/localpin-m1-vm-guard")
BIN = Path("/usr/libexec/localpin-m1")
RUNTIME = Path("/run/localpin-m1")
CANARY = Path("/run/localpin-m1-canary")
STATE = Path("/var/lib/localpin-m1")
PAM = Path("/etc/localpin-m1-pam")
UNIT_ROOT = Path("/run/systemd/system")
MODES = ("broker", "client", "denied", "worker")
MISSING_ACCOUNT = "localpin_m1_missing_account"


class ExperimentError(Exception):
    pass


def require(condition, reason):
    if not condition:
        raise ExperimentError(reason)


def command(args, *, cwd=None, timeout=60, check=True):
    result = subprocess.run(args, cwd=cwd, stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            timeout=timeout, check=False, text=True,
                            env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"})
    if check and result.returncode != 0:
        raise ExperimentError(f"{Path(args[0]).name} failed (exit {result.returncode}); inspect guest diagnostics")
    return result


def validate_marker(path, product_uuid):
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and not path.is_symlink() and info.st_nlink == 1
            and info.st_uid == 0 and info.st_gid == 0 and stat.S_IMODE(info.st_mode) == 0o600,
            "VM guard must be a single-link root:root regular file, mode 0600")
    require(re.fullmatch(r"[0-9a-fA-F-]{36}", product_uuid) is not None, "invalid DMI UUID")
    require(path.read_text() == f"LOCALPIN-M1-DISPOSABLE-VM\ntarget=localpintest\nuuid={product_uuid}\n",
            "VM guard content/target/UUID mismatch")


def preflight():
    require(os.getuid() == 0 and os.geteuid() == 0, "guest root is required; do not escalate on an everyday host")
    require(command(["systemd-detect-virt", "--vm"]).stdout.strip() in {"kvm", "qemu"},
            "requires disposable QEMU/KVM guest")
    require(command(["getenforce"]).stdout.strip() == "Enforcing", "SELinux must be Enforcing")
    validate_marker(GUARD, Path("/sys/class/dmi/id/product_uuid").read_text().strip())
    account = pwd.getpwnam("localpintest")
    require(account.pw_uid > 0, "non-root dedicated localpintest required")
    result = command(["getent", "passwd", MISSING_ACCOUNT], check=False)
    require(result.returncode == 2 and not result.stdout, "fixed missing-account fixture already exists or NSS unavailable")
    require(Path("/usr/share/selinux/devel/Makefile").is_file(), "install guest selinux-policy-devel/make")
    require(Path("/usr/include/security/pam_appl.h").is_file(), "install guest pam-devel")
    require(Path("/usr/sbin/unix_chkpwd").is_file(), "packaged unix_chkpwd unavailable")
    modules = command(["semodule", "-l"]).stdout.splitlines()
    require(not any(line.split()[0] == "localpin_m1" for line in modules if line.split()),
            "experiment policy already exists; restore the clean snapshot")
    paths = [BIN, RUNTIME, CANARY, STATE, PAM,
             *(UNIT_ROOT / f"localpin-m1-{mode}.service" for mode in MODES)]
    require(not any(path.exists() or path.is_symlink() for path in paths),
            "experiment path already exists; restore the clean snapshot")
    return account


def policy(locker_type):
    text = Path(__file__).with_name("localpin_m1.te.in").read_text()
    rule = "# No actual locker type was supplied."
    if locker_type:
        require(re.fullmatch(r"[a-z][a-z0-9_]{0,100}_t", locker_type) is not None,
                "invalid observed locker SELinux type")
        require(not locker_type.startswith("localpin_m1_"), "fixture domain is not an observed locker")
        rule = (f"gen_require(`type {locker_type};')\n"
                f"allow {locker_type} localpin_m1_runtime_t:dir search;\n"
                f"allow {locker_type} localpin_m1_runtime_t:sock_file write;\n"
                f"allow {locker_type} localpin_m1_broker_t:unix_stream_socket connectto;")
    return text.replace("@LOCKER_RULE@", rule)


def unit(mode, account):
    oneshot = mode != "broker"
    unprivileged = mode in {"client", "denied"}
    identity = f"User=localpintest\nGroup={account.pw_gid}\n" if unprivileged else "User=root\nGroup=root\n"
    argument = f"broker {account.pw_uid}" if mode == "broker" else mode
    # Helper domain transitions and native PAM requirements must be tested apart
    # from the broker. Do not silently force the broker's NNP policy on PAM.
    nnp = "no" if mode == "worker" else "yes"
    return (f"[Unit]\nDescription=Disposable LocalPIN M1 {mode} fixture\n"
            f"[Service]\nType={'oneshot' if oneshot else 'simple'}\n"
            f"ExecStart={BIN / mode} {argument}\n{identity}"
            f"SELinuxContext=system_u:system_r:localpin_m1_{mode}_t:s0\n"
            f"NoNewPrivileges={nnp}\nCapabilityBoundingSet=\nAmbientCapabilities=\n"
            "ProtectSystem=strict\nProtectHome=yes\nPrivateTmp=yes\nPrivateDevices=yes\n"
            "PrivateNetwork=yes\nRestrictAddressFamilies=AF_UNIX\n"
            "ProtectKernelTunables=yes\nProtectKernelModules=yes\nProtectControlGroups=yes\n"
            "LockPersonality=yes\nLimitCORE=0\nTasksMax=8\nMemoryMax=64M\n"
            "TimeoutStartSec=8\nTimeoutStopSec=2\nKillMode=control-group\nSendSIGKILL=yes\n"
            "StandardInput=null\nStandardOutput=null\nStandardError=journal\n"
            + (f"ReadWritePaths={RUNTIME}\nRuntimeMaxSec=35\n" if mode == "broker" else ""))


def context_type(context):
    """Export a bounded type only; never a SELinux user, role or MCS range."""
    fields = context.rstrip("\0\n").split(":")
    require(len(fields) >= 4 and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,127}", fields[2]) is not None,
            "invalid executable context metadata")
    return fields[2]


def executable_labels():
    labels = {}
    for name, path, expected in [*( (mode, BIN / mode, f"localpin_m1_{mode}_exec_t") for mode in MODES),
                                  ("unix_chkpwd", Path("/usr/sbin/unix_chkpwd"), "chkpwd_exec_t")]:
        actual = context_type(os.getxattr(path, "security.selinux", follow_symlinks=False).decode("ascii"))
        matched = context_type(command(["matchpathcon", "-n", str(path)]).stdout)
        labels[name] = {"actual_type": actual, "policy_type": matched, "expected_type": expected}
        # Fixed fixture identifiers and validated bounded policy type names only.
        print(f"M1 setup executable={name} actual_type={actual} policy_type={matched} expected_type={expected}",
              file=sys.stderr)
        require(actual == matched == expected, f"{name} executable label mismatch")
    return labels


def cleanup(installed_units, created, policy_install_attempted):
    """Return fixed diagnostic stages, preserving resources if stop is unconfirmed."""
    errors = []
    stopped = True
    for path in installed_units:
        try:
            result = command(["systemctl", "stop", path.name], timeout=8, check=False)
            if result.returncode != 0:
                stopped = False
                errors.append(f"stop {path.name}")
        except (OSError, subprocess.TimeoutExpired):
            stopped = False
            errors.append(f"stop {path.name}")
    if not stopped:
        return errors  # Retain paths/policy while fixture tasks may still exist.
    # Never-started oneshot units can be unloaded immediately after stop. There
    # is no failed state requiring reset once every fixture is stopped and its
    # definition is removed; reset-failed on an unloaded unit is a false error.
    for path in installed_units:
        try:
            path.unlink(missing_ok=True)
        except OSError:
            errors.append("unit removal")
    if installed_units:
        try:
            result = command(["systemctl", "daemon-reload"], timeout=8, check=False)
            if result.returncode != 0:
                errors.append("unit reload")
        except (OSError, subprocess.TimeoutExpired):
            errors.append("unit reload")
    for path in reversed(created):
        try:
            shutil.rmtree(path)
        except OSError:
            errors.append("fixture path removal")
    if policy_install_attempted:
        try:
            modules = command(["semodule", "-l"]).stdout.splitlines()
            if any(line.split()[0] == "localpin_m1" for line in modules if line.split()):
                result = command(["semodule", "-r", "localpin_m1"], check=False)
                if result.returncode != 0:
                    errors.append("policy removal")
        except (OSError, subprocess.TimeoutExpired, ExperimentError):
            errors.append("policy cleanup query")
    return errors


def failure_message(stage, primary_error, cleanup_errors):
    """Preserve the operation failure; native exceptions never supply raw text."""
    message = None
    if primary_error is not None:
        reason = str(primary_error) if isinstance(primary_error, ExperimentError) else type(primary_error).__name__
        message = f"{stage}: {reason}"
    if cleanup_errors:
        detail = "cleanup incomplete (" + ", ".join(cleanup_errors) + "); restore the clean VM snapshot"
        message = f"{message}; {detail}" if message else detail
    return message


def check_service_result(text, mode):
    values = dict(line.split("=", 1) for line in text.splitlines() if "=" in line)
    require({"Result", "ExecMainStatus"}.issubset(values), f"{mode} service result properties missing")
    require(values["Result"] == "success" and values["ExecMainStatus"] == "0",
            f"{mode} fixture did not finish successfully")


def execute(locker_type):
    account = preflight()  # Every prerequisite precedes any guest mutation.
    report = {"schema_version": 1, "fixture": "guarded disposable VM only",
              "selinux": "Enforcing", "checks": {},
              "locker_type_policy_target": locker_type,
              "actual_locker_contact_tested": False,
              "real_password_authentication_tested": False,
              "complete_product_policy": False}
    source = Path(__file__).resolve().parent
    created, installed_units = [], []
    policy_install_attempted = False
    primary_error = None
    stage = "fixture preparation"

    def interrupted(signum, frame):
        del signum, frame
        raise ExperimentError("interrupted; attempting fixture cleanup")

    signal.signal(signal.SIGINT, interrupted)
    signal.signal(signal.SIGTERM, interrupted)
    try:
        with tempfile.TemporaryDirectory(prefix="localpin-m1-policy-") as temporary:
            build = Path(temporary)
            (build / "localpin_m1.te").write_text(policy(locker_type))
            shutil.copyfile(source / "localpin_m1.fc", build / "localpin_m1.fc")
            stage = "policy build"
            command(["make", "-f", "/usr/share/selinux/devel/Makefile", "localpin_m1.pp"], cwd=build)
            stage = "fixture compile"
            command(["gcc", "-std=c11", "-Wall", "-Wextra", "-Wpedantic", "-Werror", "-O2",
                     "-fstack-protector-strong", "-D_FORTIFY_SOURCE=3", "-Wl,-z,relro,-z,now",
                     str(source / "fixture.c"), "-lpam", "-o", str(build / "fixture")])
            stage = "fixture paths"
            for path, mode in [(BIN, 0o755), (RUNTIME, 0o755), (CANARY, 0o755),
                               (STATE, 0o700), (PAM, 0o755)]:
                path.mkdir(mode=mode)
                created.append(path)
                path.chmod(mode)
            for mode in MODES:
                shutil.copyfile(build / "fixture", BIN / mode)
                (BIN / mode).chmod(0o755)
            (CANARY / "public-marker").write_text("PUBLIC M1 MAC CANARY\n")
            (CANARY / "public-marker").chmod(0o444)
            (STATE / "private-marker").write_text("PUBLIC M1 DAC CANARY\n")
            (STATE / "private-marker").chmod(0o600)
            (PAM / "permit").write_text("auth required /usr/lib64/security/pam_permit.so\n")
            (PAM / "deny").write_text("auth required /usr/lib64/security/pam_deny.so\n")
            # A timed-out/failed installer may have committed the module already.
            policy_install_attempted = True
            stage = "policy installation"
            command(["semodule", "-i", str(build / "localpin_m1.pp")])
            stage = "fixture labeling"
            command(["restorecon", "-R", *(str(path) for path in created)])
            stage = "executable label verification"
            report["executable_labels"] = executable_labels()
            stage = "unit installation"
            for mode in MODES:
                path = UNIT_ROOT / f"localpin-m1-{mode}.service"
                with path.open("x") as output:
                    installed_units.append(path)
                    output.write(unit(mode, account))
            stage = "unit reload"
            command(["systemctl", "daemon-reload"])
            stage = "broker start"
            command(["systemctl", "start", "localpin-m1-broker.service"])
            stage = "broker readiness"
            until = time.monotonic() + 5
            while not (RUNTIME / "contact.sock").exists() and time.monotonic() < until:
                time.sleep(0.05)
            require((RUNTIME / "contact.sock").is_socket(), "broker socket not ready; inspect guest AVCs")
            require(stat.S_IMODE((RUNTIME / "contact.sock").stat().st_mode) == 0o666,
                    "socket DAC baseline is not shared")
            require((RUNTIME / "contact.sock").stat().st_uid == 0,
                    "socket is not root-owned")
            report["checks"]["root_owned_broker_socket"] = True
            for mode in ("client", "denied", "worker"):
                stage = f"{mode} start"
                command(["systemctl", "start", f"localpin-m1-{mode}.service"], timeout=12)
                stage = f"{mode} result"
                status = command(["systemctl", "show", f"localpin-m1-{mode}.service",
                                  "--property=Result", "--property=ExecMainStatus"]).stdout
                check_service_result(status, mode)
                report["checks"][mode] = True
            report["checks"]["mac_canary_and_root_state_denied_to_clients"] = True
            report["checks"]["worker_private_permit_deny_and_missing_account_helper"] = True
            stage = "final enforcing check"
            require(command(["getenforce"]).stdout.strip() == "Enforcing", "SELinux mode changed during test")
    except Exception as error:
        primary_error = error
    finally:
        # Signals initiate this cleanup once. SIGKILL/power loss still require
        # snapshot restoration, as does any unconfirmed stop/removal below.
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        cleanup_errors = cleanup(installed_units, created, policy_install_attempted)
    message = failure_message(stage, primary_error, cleanup_errors)
    require(message is None, message)
    report["cleanup_completed"] = True
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-in-disposable-vm", action="store_true",
                        help="explicitly authorize installing then removing this guest-only fixture")
    parser.add_argument("--locker-type", help="optional SELinux type observed from the actual guest locker")
    args = parser.parse_args()
    require(args.run_in_disposable_vm, "read README; explicit disposable-VM switch and guard required")
    print(json.dumps(execute(args.locker_type), indent=2, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except ExperimentError as error:
        # ExperimentError strings are fixed stage descriptions, never native output.
        print(f"M1 VM SELinux experiment failed: {error}. No pass recorded.", file=sys.stderr)
        raise SystemExit(1)
    except (OSError, subprocess.TimeoutExpired, KeyError):
        # Never print raw helper/PAM/audit output or potentially identifying paths.
        print("M1 VM SELinux experiment failed; inspect fixed guest fixture stages and AVCs. No pass recorded.", file=sys.stderr)
        raise SystemExit(1)
