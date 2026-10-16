#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Opt-in confined own-user PAM worker experiment; disposable guarded VM only."""
import argparse
import hashlib
import importlib.util
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

HERE = Path(__file__).resolve().parent
BIN = Path("/usr/libexec/localpin-m1-positive")
CONF = Path("/etc/localpin-m1-positive-pam")
UNIT = Path("/run/systemd/system/localpin-m1-positive@.service")
MODULE = "localpin_m1_positive"
PUBLIC_PASSWORD = b"LocalPIN-M1-worker-public-fixture!"
EXPECTED_POLICY = "2e53f704372b6c7fb69cdc4dfd6c27456d642c83feff8b1588fa1f9cb1126cd0"


def load(name, path):
    specification = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


pam_fixture = load("m1_positive_account_fixture", HERE.parent / "pam" / "run.py")
boundary = load("m1_positive_boundary_helpers", HERE.parent / "selinux" / "run.py")
command = boundary.command
require = boundary.require


def unit_text():
    return f"""[Unit]
Description=Disposable confined LocalPIN M1 positive password worker
[Service]
Type=oneshot
User=localpintest
ExecStart={BIN}/worker %i
SELinuxContext=system_u:system_r:localpin_m1_positive_t:s0
NoNewPrivileges=no
CapabilityBoundingSet=CAP_DAC_READ_SEARCH CAP_AUDIT_WRITE
AmbientCapabilities=
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
PrivateNetwork=no
RestrictAddressFamilies=AF_UNIX AF_NETLINK
IPAddressDeny=any
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
LockPersonality=yes
LimitCORE=0
TasksMax=8
MemoryMax=64M
TimeoutStartSec=20
TimeoutStopSec=2
KillMode=control-group
SendSIGKILL=yes
Environment=LC_ALL=C
StandardInput=null
StandardOutput=journal
StandardError=journal
"""


def reviewed_policy(data):
    require(len(data) <= 65536 and hashlib.sha256(data).hexdigest() == EXPECTED_POLICY,
            "password-auth differs from the reviewed local-password-only graph")
    return data


def no_forbidden_grants():
    for target, kind, permission in [("shadow_t", "file", "read"), ("updpwd_t", "process", "transition")]:
        text = command(["sesearch", "-A", "-s", "localpin_m1_positive_t", "-t", target,
                        "-c", kind, "-p", permission]).stdout
        require(not re.search(r"^\s*allow\s", text, re.MULTILINE),
                f"compiled positive-worker policy unexpectedly grants {target} {permission}")


def compile_worker(work):
    include = os.environ.get("LOCALPIN_PAM_INCLUDE", "/usr/include")
    command(["gcc", "-std=c11", "-O2", "-Wall", "-Wextra", "-Wpedantic", "-Werror",
             "-fstack-protector-strong", "-D_FORTIFY_SOURCE=3", "-isystem", include,
             "-Wl,-z,relro,-z,now", str(HERE / "worker.c"), "-l:libpam.so.0", "-o", str(work / "worker")])


def run_case(name, instances, report):
    instance = f"localpin-m1-positive@{name}.service"
    instances.append(instance)  # Include a failed or timed-out start in teardown.
    command(["systemctl", "start", instance], timeout=25)
    status = command(["systemctl", "show", instance, "--property=Result", "--property=ExecMainStatus"]).stdout
    boundary.check_service_result(status, name)
    # C independently asserts exact numerical authentication/account outcomes,
    # ordinary UID, empty active capabilities, domain and direct-shadow denial.
    report["results"].append({"case": name, "native_assertions_passed": True})


def cleanup(instances, created, unit_created, policy_attempted):
    errors, stopped = [], True
    for name in instances:
        try:
            if command(["systemctl", "stop", name], timeout=8, check=False).returncode:
                stopped = False
                errors.append("worker stop")
        except (OSError, subprocess.TimeoutExpired):
            stopped = False
            errors.append("worker stop")
    if not stopped:
        return errors
    if unit_created:
        try:
            UNIT.unlink(missing_ok=True)
            if command(["systemctl", "daemon-reload"], check=False).returncode:
                errors.append("unit reload")
        except (OSError, subprocess.TimeoutExpired):
            errors.append("unit removal/reload")
    for path in reversed(created):
        try:
            shutil.rmtree(path)
        except OSError:
            errors.append("fixture path removal")
    if policy_attempted:
        try:
            modules = command(["semodule", "-l"]).stdout.splitlines()
            if any(line.split()[0] == MODULE for line in modules if line.split()):
                if command(["semodule", "-r", MODULE], check=False).returncode:
                    errors.append("policy removal")
        except (OSError, subprocess.TimeoutExpired, boundary.ExperimentError):
            errors.append("policy cleanup")
    return errors


def execute():
    pam_fixture.guard()  # Shared root/mode/UUID/Enforcing/local ordinary-user guard.
    raw_policy = reviewed_policy(Path("/etc/pam.d/password-auth").read_bytes())
    require(not any(path.exists() or path.is_symlink() for path in (BIN, CONF, UNIT)), "positive fixture path collision")
    modules = command(["semodule", "-l"]).stdout.splitlines()
    require(not any(line.split()[0] == MODULE for line in modules if line.split()), "positive fixture module collision")
    helper = Path("/usr/sbin/unix_chkpwd")
    info = helper.stat()
    require(info.st_uid == 0 and bool(info.st_mode & stat.S_ISUID), "reviewed helper requires packaged setuid-root unix_chkpwd")
    require(boundary.context_type(os.getxattr(helper, "security.selinux").decode("ascii")) == "chkpwd_exec_t",
            "unexpected packaged helper label")
    report = {"schema_version": 1, "selinux": "Enforcing", "fixture": "disposable confined own-user worker",
              "password_auth_sha256": EXPECTED_POLICY, "results": [], "direct_shadow_read_rule": False,
              "password_update_transition": False, "target_shadow_record_restored": False,
              "whole_vm_snapshot_restored": False, "production_worker_complete": False}
    created, instances = [], []
    unit_created = policy_attempted = mutated = False
    original = primary = None
    stage = "fixture build"

    def interrupt(signum, frame):
        del signum, frame
        raise boundary.ExperimentError("interrupted; restoring dedicated account and fixture")

    signal.signal(signal.SIGINT, interrupt)
    signal.signal(signal.SIGTERM, interrupt)
    try:
        with tempfile.TemporaryDirectory(prefix="localpin-m1-positive-") as temporary:
            build = Path(temporary)
            compile_worker(build)
            for suffix in ("te", "fc"):
                shutil.copyfile(HERE / f"{MODULE}.{suffix}", build / f"{MODULE}.{suffix}")
            command(["make", "-f", "/usr/share/selinux/devel/Makefile", f"{MODULE}.pp"], cwd=build)
            for path in (BIN, CONF):
                path.mkdir(mode=0o755)
                created.append(path)
                path.chmod(0o755)
            shutil.copyfile(build / "worker", BIN / "worker")
            (BIN / "worker").chmod(0o755)
            (CONF / "password-auth").write_bytes(raw_policy)
            (CONF / "worker").write_text("auth substack password-auth\naccount include password-auth\n")
            (CONF / "permit").write_text("auth required /usr/lib64/security/pam_permit.so\naccount required /usr/lib64/security/pam_permit.so\n")
            (CONF / "deny").write_text("auth required /usr/lib64/security/pam_deny.so\n")
            for path in CONF.iterdir():
                path.chmod(0o444)
            stage = "policy installation"
            policy_attempted = True
            command(["semodule", "-i", str(build / f"{MODULE}.pp")])
            command(["restorecon", "-R", str(BIN), str(CONF)])
            actual = boundary.context_type(os.getxattr(BIN / "worker", "security.selinux").decode("ascii"))
            matched = boundary.context_type(command(["matchpathcon", "-n", str(BIN / "worker")]).stdout)
            require(actual == matched == "localpin_m1_positive_exec_t", "positive executable label mismatch")
            stage = "compiled policy boundary checks"
            no_forbidden_grants()
            with UNIT.open("x") as output:
                unit_created = True
                output.write(unit_text())
            command(["systemctl", "daemon-reload"])
            for name in ("permit", "deny"):
                stage = f"infrastructure {name} baseline"
                run_case(name, instances, report)
            original = pam_fixture.shadow_record()
            mutated = True
            stage = "assigning public dedicated-account fixture"
            pam_fixture.set_password(PUBLIC_PASSWORD)
            for name in ("correct", "wrong"):
                stage = name
                run_case(name, instances, report)
            stage = "locked"
            command(["usermod", "--lock", "localpintest"])
            run_case("locked", instances, report)
            pam_fixture.set_password(PUBLIC_PASSWORD)
            stage = "expired-account"
            command(["chage", "--expiredate", "1", "localpintest"])
            run_case("expired-account", instances, report)
            pam_fixture.set_password(PUBLIC_PASSWORD)
            stage = "expired-password"
            command(["chage", "--lastday", "0", "localpintest"])
            run_case("expired-password", instances, report)
            pam_fixture.set_password(PUBLIC_PASSWORD)
            stage = "recovery"
            run_case("recovery", instances, report)
            require(command(["getenforce"]).stdout.strip() == "Enforcing", "SELinux changed during test")
            reviewed_policy(Path("/etc/pam.d/password-auth").read_bytes())
    except Exception as error:
        primary = error
    finally:
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        errors = cleanup(instances, created, unit_created, policy_attempted)
        if mutated:
            try:
                pam_fixture.restore_shadow(original)
                report["target_shadow_record_restored"] = True
            except Exception:
                errors.append("exact dedicated-account restoration")
    message = boundary.failure_message(stage, primary, errors)
    require(message is None, message)
    report["cleanup_completed"] = True
    report["versions"] = command(["rpm", "-q", "pam", "pam-devel", "systemd", "selinux-policy-targeted"]).stdout.splitlines()
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--compile-only", action="store_true")
    parser.add_argument("--run-mutate", action="store_true")
    parser.add_argument("--snapshot-confirmed", action="store_true")
    args = parser.parse_args()
    os.umask(0o077)
    require(args.compile_only != args.run_mutate, "choose compile-only or guarded run-mutate")
    if args.compile_only:
        with tempfile.TemporaryDirectory(prefix="localpin-m1-positive-build-") as temporary:
            compile_worker(Path(temporary))
        print("C compile passed; no policy/PAM/account operation executed")
        return
    require(args.snapshot_confirmed, "operator must confirm a restorable clean snapshot")
    print(json.dumps(execute(), indent=2, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except boundary.ExperimentError as error:
        print(f"M1 positive worker failed: {error}. No pass recorded.", file=sys.stderr)
        raise SystemExit(1)
    except Exception as error:
        print(f"M1 positive worker failed: {type(error).__name__}. No pass recorded; inspect guest diagnostics.", file=sys.stderr)
        raise SystemExit(1)
