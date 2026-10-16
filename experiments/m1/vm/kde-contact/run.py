#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Guarded root-only broker hold for a separate genuine KDE contact experiment."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time

HERE = Path(__file__).resolve().parent
CONTROL = Path("/run/localpin-m1-kde-control")
LIFETIME = 600


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


boundary = load("m1_kde_contact_boundary", HERE.parent / "selinux" / "run.py")
pam_guard = load("m1_kde_contact_guard", HERE.parent / "pam" / "run.py")
command, require = boundary.command, boundary.require


def read_owned(path, limit=4096):
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as source:
        info = os.fstat(source.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_uid == info.st_gid == 0
                and stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1,
                "unsafe root control file")
        value = source.read(limit + 1)
        require(len(value) <= limit, "oversized root control file")
        return value


def control_guard():
    pam_guard.guard()
    info = CONTROL.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 0
            and stat.S_IMODE(info.st_mode) == 0o700 and not CONTROL.is_symlink(),
            "unsafe root control directory")


def write_new(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as output:
        output.write(data)
        output.flush()
        os.fsync(output.fileno())


def write_state(phase):
    temporary = CONTROL / ".state-new"
    write_new(temporary, json.dumps({"schema_version": 1, "phase": phase, "selinux": "Enforcing",
                                  "lifetime_seconds": LIFETIME}).encode() + b"\n")
    os.replace(temporary, CONTROL / "state.json")


def request(action):
    control_guard()
    state = json.loads(read_owned(CONTROL / "state.json"))
    require(state.get("phase") in {"ready", "denied", "finishing"}, "invalid root control state")
    if action == "status":
        return state
    require(state["phase"] in {"ready", "denied"}, "fixture is already finishing")
    if action == "deny" and state["phase"] == "denied":
        return {"request": "deny", "already_applied": True}
    write_new(CONTROL / f"{action}.request", (action + "\n").encode())
    return {"request": action, "queued": True}


def consume(action):
    path = CONTROL / f"{action}.request"
    if not path.exists() and not path.is_symlink():
        return False
    require(read_owned(path) == (action + "\n").encode(), "invalid root control request")
    path.unlink()
    return True


def extended_source(text):
    # Reuse the reviewed fixture unchanged except for two explicit lifetime
    # constants in a temporary compilation copy. Original source stays frozen.
    require(text.count("alarm(35);") == 1 and text.count("poll(&ready, 1, 30000)") == 1,
            "reviewed broker lifetime literals changed")
    return text.replace("alarm(35);", "alarm(600);").replace("poll(&ready, 1, 30000)", "poll(&ready, 1, 600000)")


def deny_new_connections():
    path = boundary.RUNTIME / "contact.sock"
    info = path.lstat()
    require(stat.S_ISSOCK(info.st_mode) and info.st_uid == info.st_gid == 0,
            "owned broker socket unavailable for DAC denial")
    os.chmod(path, 0o000, follow_symlinks=False)
    require(stat.S_IMODE(path.stat().st_mode) == 0, "socket DAC denial not applied")


def hold(locker_type):
    account = boundary.preflight()  # Exact shared VM guard and no fixture collisions.
    require(not CONTROL.exists() and not CONTROL.is_symlink(), "root control directory already exists")
    created, installed_units = [], []
    policy_attempted = False
    primary = None
    stage = "broker hold preparation"
    report = {"schema_version": 1, "fixture": "disposable KDE contact broker hold",
              "selinux": "Enforcing", "broker_ready": False, "dac_deny_applied": False,
              "actual_locker_contact_proven_by_orchestrator": False,
              "password_or_account_operation": False, "locker_type_policy_target": locker_type}

    def interrupt(signum, frame):
        del signum, frame
        raise boundary.ExperimentError("interrupted; stopping owned contact fixture")

    signal.signal(signal.SIGINT, interrupt)
    signal.signal(signal.SIGTERM, interrupt)
    try:
        with tempfile.TemporaryDirectory(prefix="localpin-m1-kde-contact-") as temporary:
            build = Path(temporary)
            (build / "fixture.c").write_text(extended_source((HERE.parent / "selinux" / "fixture.c").read_text()))
            (build / "localpin_m1.te").write_text(boundary.policy(locker_type))
            shutil.copyfile(HERE.parent / "selinux" / "localpin_m1.fc", build / "localpin_m1.fc")
            stage = "broker hold compilation"
            command(["make", "-f", "/usr/share/selinux/devel/Makefile", "localpin_m1.pp"], cwd=build)
            command(["gcc", "-std=c11", "-O2", "-Wall", "-Wextra", "-Wpedantic", "-Werror",
                     "-fstack-protector-strong", "-D_FORTIFY_SOURCE=3", "-Wl,-z,relro,-z,now",
                     str(build / "fixture.c"), "-l:libpam.so.0", "-o", str(build / "broker")])
            for path, mode in [(boundary.BIN, 0o755), (boundary.RUNTIME, 0o755),
                               (boundary.STATE, 0o700), (CONTROL, 0o700)]:
                path.mkdir(mode=mode)
                created.append(path)
                path.chmod(mode)
            shutil.copyfile(build / "broker", boundary.BIN / "broker")
            (boundary.BIN / "broker").chmod(0o755)
            marker = boundary.STATE / "private-marker"
            marker.write_text("PUBLIC M1 DAC CANARY\n")
            marker.chmod(0o600)
            stage = "broker hold policy installation"
            policy_attempted = True
            command(["semodule", "-i", str(build / "localpin_m1.pp")])
            command(["restorecon", "-R", str(boundary.BIN), str(boundary.RUNTIME), str(boundary.STATE)])
            actual = boundary.context_type(os.getxattr(boundary.BIN / "broker", "security.selinux").decode("ascii"))
            matched = boundary.context_type(command(["matchpathcon", "-n", str(boundary.BIN / "broker")]).stdout)
            require(actual == matched == "localpin_m1_broker_exec_t", "broker hold entrypoint label mismatch")
            path = boundary.UNIT_ROOT / "localpin-m1-broker.service"
            text = boundary.unit("broker", account).replace("RuntimeMaxSec=35\n", "RuntimeMaxSec=600\n")
            with path.open("x") as output:
                installed_units.append(path)
                output.write(text)
            command(["systemctl", "daemon-reload"])
            stage = "broker hold start"
            command(["systemctl", "start", path.name])
            until = time.monotonic() + 5
            socket = boundary.RUNTIME / "contact.sock"
            while not socket.exists() and time.monotonic() < until:
                time.sleep(0.05)
            require(socket.is_socket() and socket.stat().st_uid == 0
                    and stat.S_IMODE(socket.stat().st_mode) == 0o666, "broker hold socket not ready")
            write_state("ready")
            report["broker_ready"] = True
            print("M1 KDE contact broker ready; root status/deny/finish controls available", file=sys.stderr, flush=True)
            # Finish before the independent service/native hard ceiling can
            # expire and look like an unexpected daemon crash.
            deadline, checked = time.monotonic() + LIFETIME - 10, 0.0
            stage = "broker hold control loop"
            while time.monotonic() < deadline:
                if consume("finish"):
                    report["completion"] = "finish request"
                    break
                if consume("deny"):
                    deny_new_connections()
                    report["dac_deny_applied"] = True
                    write_state("denied")
                if time.monotonic() - checked >= 2:
                    require(command(["systemctl", "is-active", "localpin-m1-broker.service"], check=False).returncode == 0,
                            "owned contact broker stopped during hold")
                    require(command(["getenforce"]).stdout.strip() == "Enforcing", "SELinux changed during hold")
                    checked = time.monotonic()
                time.sleep(0.25)
            else:
                report["completion"] = "bounded hold deadline"
            write_state("finishing")
    except Exception as error:
        primary = error
    finally:
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        errors = boundary.cleanup(installed_units, created, policy_attempted)
    message = boundary.failure_message(stage, primary, errors)
    require(message is None, message)
    report["cleanup_completed"] = True
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--hold", action="store_true")
    action.add_argument("--status", action="store_true")
    action.add_argument("--deny", action="store_true")
    action.add_argument("--finish", action="store_true")
    parser.add_argument("--snapshot-confirmed", action="store_true")
    parser.add_argument("--locker-type", choices=["unconfined_t"], default="unconfined_t")
    args = parser.parse_args()
    os.umask(0o077)
    if args.hold:
        require(args.snapshot_confirmed, "operator must confirm a restorable clean snapshot")
        result = hold(args.locker_type)
    else:
        result = request("status" if args.status else "deny" if args.deny else "finish")
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except boundary.ExperimentError as error:
        print(f"M1 KDE contact fixture failed: {error}. No pass recorded.", file=sys.stderr)
        raise SystemExit(1)
    except Exception as error:
        print(f"M1 KDE contact fixture failed: {type(error).__name__}. No pass recorded.", file=sys.stderr)
        raise SystemExit(1)
