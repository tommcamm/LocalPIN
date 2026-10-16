#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Real logind registration fixtures, never another desktop or authentication."""
from contextlib import contextmanager
import argparse
import array
import ctypes
import ctypes.util
import fcntl
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time

HERE = Path(__file__).resolve().parent
BIN = Path("/usr/libexec/localpin-m1-sessions")
PROPERTIES = ("User", "Type", "Class", "Remote", "Active", "State", "Seat", "Desktop", "Leader", "Service", "VTNr", "TTY", "Scope")
CASES = ("tty", "remote-metadata", "greeter-metadata", "root-metadata", "graphical-metadata")


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


pam = load("m1_sessions_guard", HERE.parent / "pam" / "run.py")
inventory = load("m1_sessions_inventory", HERE.parents[1] / "platform" / "inventory.py")
require = pam.require


def command(args, *, check=True, timeout=12):
    p = subprocess.run(args, capture_output=True, text=True, stdin=subprocess.DEVNULL, timeout=timeout,
                       env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"})
    require(not check or p.returncode == 0, f"{Path(args[0]).name} failed; inspect guest diagnostics")
    return p


def properties(identifier):
    require(re.fullmatch(r"[A-Za-z0-9_-]{1,64}", identifier) is not None, "invalid session ID")
    text = command(["loginctl", "show-session", identifier, "--no-pager", *(f"-p{name}" for name in PROPERTIES)]).stdout
    values = dict(line.split("=", 1) for line in text.splitlines() if "=" in line)
    require(set(PROPERTIES).issubset(values) and values["User"].isdigit() and values["Leader"].isdigit(),
            "incomplete logind properties")
    return values


def sessions():
    data = json.loads(command(["loginctl", "list-sessions", "--json=short", "--no-pager"]).stdout)
    require(isinstance(data, list) and len(data) < 128, "unexpected logind list")
    return {entry["session"]: properties(entry["session"]) for entry in data}


def vt_state():
    values = array.array("H", [0, 0, 0])
    fd = os.open("/dev/tty0", os.O_RDONLY | os.O_NOCTTY | os.O_CLOEXEC)
    try:
        fcntl.ioctl(fd, 0x5603, values, True)  # VT_GETSTATE only: never VT_ACTIVATE.
    finally:
        os.close(fd)
    require(1 <= values[0] <= 63, "invalid active VT")
    return values[0], values[2]


def active_baseline():
    active = command(["loginctl", "show-seat", "seat0", "--value", "--property=ActiveSession"]).stdout.strip()
    require(re.fullmatch(r"[A-Za-z0-9_-]{1,64}", active) is not None, "seat0 has no stable active session")
    return active, vt_state()[0]


def select_spare(snapshot, active, used_mask):
    occupied = {int(item["VTNr"]) for item in snapshot.values() if item["VTNr"].isdigit()}
    for number in range(7, 16):
        if number != active and number not in occupied and not used_mask & (1 << number):
            return number
    raise RuntimeError("no unused bounded spare VT")


def verify_spare(number, baseline):
    require(active_baseline() == baseline, "active session/VT changed; no further registration")
    snapshot = sessions()
    active, used = vt_state()
    require(select_spare(snapshot, active, used) == number, "spare VT occupancy changed")
    for prefix in ("getty", "autovt"):
        p = command(["systemctl", "is-active", f"{prefix}@tty{number}.service"], check=False)
        require(p.returncode in {3, 4} and p.stdout.strip() in {"inactive", "unknown"}, "spare VT has a getty")


def compile_helper(destination, source="helper.c", shared=False):
    command(["cc", "-std=c11", "-O2", "-Wall", "-Wextra", "-Wpedantic", "-Werror",
             "-fstack-protector-strong", "-D_FORTIFY_SOURCE=3", "-Wl,-z,relro,-z,now", "-isystem",
             os.environ.get("LOCALPIN_PAM_INCLUDE", "/usr/include"), *(["-fPIC", "-shared"] if shared else []), str(HERE / source),
             "-o", str(destination), "-l:libpam.so.0"], timeout=30)


def direct_session(pid):
    lib = ctypes.CDLL(ctypes.util.find_library("systemd"))
    libc = ctypes.CDLL(None)
    lib.sd_pid_get_session.argtypes = [ctypes.c_int, ctypes.POINTER(ctypes.c_void_p)]
    lib.sd_pid_get_session.restype = ctypes.c_int
    libc.free.argtypes = [ctypes.c_void_p]
    pointer = ctypes.c_void_p()
    result = lib.sd_pid_get_session(pid, ctypes.byref(pointer))
    require(result >= 0 and pointer.value, "owned helper has no direct logind session")
    try:
        return ctypes.string_at(pointer).decode("ascii")
    finally:
        libc.free(pointer)


@contextmanager
def cleanup_window():
    previous = {sig: signal.signal(sig, signal.SIG_IGN) for sig in (signal.SIGINT, signal.SIGTERM)}
    try:
        yield
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)


def finish(unit, directory, registered, baseline_ids):
    errors = []
    if directory.exists():
        (directory / "release").touch(mode=0o600, exist_ok=True)
    # Stop exactly the prechecked, randomly named launch unit. Never terminate
    # any user/seat or guess a session to kill, including after partial startup.
    try:
        result = command(["systemctl", "stop", unit], timeout=8, check=False)
        if result.returncode:
            status = command(["systemctl", "show", unit, "-pLoadState"], check=False).stdout
            require("LoadState=not-found" in status, "owned helper stop uncertain")
    except Exception:
        errors.append("owned helper stop")
    if registered:
        require(registered not in baseline_ids, "refusing cleanup of baseline session")
    deadline = time.monotonic() + 25
    while True:
        remaining = {identifier for identifier, p in sessions().items()
                     if identifier not in baseline_ids and p["Service"] == "localpin-m1-session"}
        if not remaining or time.monotonic() >= deadline:
            break
        time.sleep(0.1)
    if remaining:
        errors.append("owned logind session still present")
    require(not errors, "session cleanup incomplete; restore clean VM snapshot")


def execute():
    pam.guard()
    require(not BIN.exists() and not BIN.is_symlink(), "session fixture path already exists")
    require(Path("/usr/lib64/security/pam_systemd.so").is_file(), "guest pam_systemd required")
    uid = __import__("pwd").getpwnam("localpintest").pw_uid
    initial = sessions()
    baseline = active_baseline()
    require(sum(inventory.session_candidate(p, uid) for p in initial.values()) == 1,
            "fixture needs exactly one existing target KDE candidate")
    spare = select_spare(initial, *vt_state())
    verify_spare(spare, baseline)
    report = {"schema": 1, "fixture": "root-declared logind registration metadata only", "selinux": "Enforcing",
              "authorization_proven": False, "second_real_desktop_tested": False, "multiple_seats_tested": False,
              "real_remote_login_tested": False, "results": [], "cleanup_completed": False}
    require(not any(p["Service"] == "localpin-m1-session" for p in initial.values()),
            "an earlier fixture session remains")
    created = retain = False
    root = Path(tempfile.mkdtemp(prefix="localpin-m1-sessions-", dir="/run"))
    try:
        root.chmod(0o700)
        config = root / "pam"
        config.mkdir(mode=0o700)
        compile_helper(root / "helper")
        compile_helper(root / "limits.so", "limits.c", shared=True)
        BIN.mkdir(mode=0o755)
        created = True
        shutil.copyfile(root / "helper", BIN / "helper")
        (BIN / "helper").chmod(0o755)
        command(["restorecon", "-R", str(BIN)])
        shutil.copyfile(root / "limits.so", BIN / "limits.so")
        (BIN / "limits.so").chmod(0o644)
        # Match the packaged PAM library type; no file-context policy is changed.
        context = os.getxattr("/usr/lib64/security/pam_systemd.so", "security.selinux")
        os.setxattr(BIN / "limits.so", "security.selinux", context)
        require(os.getxattr(BIN / "limits.so", "security.selinux") == context, "private module label mismatch")
        (config / "localpin-m1-session").write_text(
            f"session required {BIN}/limits.so\nsession required /usr/lib64/security/pam_systemd.so\n")
        for mode in CASES:
            verify_spare(spare, baseline)
            directory = root / mode
            directory.mkdir(mode=0o700)
            unit = f"localpin-m1-session-{root.name.rsplit('-', 1)[-1]}-{mode}.service"
            registered, leader = None, None
            primary = cleanup_error = None
            require("LoadState=not-found" in command(["systemctl", "show", unit, "-pLoadState"], check=False).stdout,
                    "launch unit already exists")
            try:
                command(["systemd-run", "--quiet", f"--unit={unit}", "--service-type=exec",
                         "--property=RuntimeMaxSec=50s", "--property=TimeoutStopSec=2s",
                         "--property=KillMode=process", "--property=LimitCORE=0",
                         "--property=StandardOutput=null", "--property=StandardError=journal",
                         str(BIN / "helper"), mode, str(config), str(directory), str(spare)])
                ready = directory / "ready.json"
                deadline = time.monotonic() + 10
                while not ready.exists() and time.monotonic() < deadline:
                    time.sleep(0.05)
                require(ready.exists(), "session helper did not register; inspect fixed guest helper stage")
                data = json.loads(ready.read_text())
                registered, leader = data["session"], data["leader"]
                require(registered not in initial and isinstance(leader, int) and leader > 1,
                        "unexpected existing session/leader")
                observed = properties(registered)
                require(observed["Service"] == "localpin-m1-session" and observed["Leader"] == str(leader),
                        "registered session ownership mismatch")
                require(direct_session(leader) == registered, "sd-login direct membership mismatch")
                require(active_baseline() == baseline, "fixture changed active seat0 session or VT")
                expected_uid = 0 if mode == "root-metadata" else uid
                require(observed["User"] == str(expected_uid), "logind UID differs from declared fixture")
                expected = {"Type": "tty" if mode == "tty" else "wayland",
                            "Class": "greeter" if mode == "greeter-metadata" else "user",
                            "Remote": "yes" if mode == "remote-metadata" else "no",
                            "Seat": "" if mode == "tty" else "seat0",
                            "Desktop": "" if mode == "tty" else "KDE",
                            "VTNr": "0" if mode == "tty" else str(spare)}
                require(all(observed[key] == value for key, value in expected.items()),
                        "actual logind metadata differs from requested fixture")
                require(mode != "tty" or observed["TTY"].startswith("pts/"), "actual PTY was not registered")
                require(re.fullmatch(r"session-[A-Za-z0-9_-]+\.scope", observed["Scope"]) is not None,
                        "unexpected owned session scope")
                runtime = command(["systemctl", "show", observed["Scope"], "--value", "-pRuntimeMaxUSec"]).stdout.strip()
                require(runtime == "45s", "logind scope runtime bound not applied")
                candidate = inventory.session_candidate(observed, uid)
                require(candidate == (mode == "graphical-metadata"), "unexpected actual metadata candidate result")
                candidate_count = sum(inventory.session_candidate(p, uid) for p in sessions().values())
                require(candidate_count == (2 if candidate else 1), "actual enumeration count mismatch")
                if observed["Seat"]:
                    require(observed["Active"] == "no", "fixture session unexpectedly active")
                report["results"].append({"case": mode, "registered_by_pam_systemd": True, "scope_runtime_seconds": 45,
                    "sd_login_direct_mapping": True, "active_desktop_unchanged": True,
                    "graphical": observed["Type"] in {"wayland", "x11"}, "remote": observed["Remote"] == "yes",
                    "user_class": observed["Class"] == "user", "has_seat": bool(observed["Seat"]),
                    "discovery_candidate": candidate, "actual_candidate_count": candidate_count,
                    "ambiguous_metadata": candidate_count > 1, "root_uid_own_request_candidate":
                    inventory.session_candidate(observed, 0) if mode == "root-metadata" else None})
            except Exception as error:
                primary = error
            finally:
                with cleanup_window():
                    try:
                        finish(unit, directory, registered, set(initial))
                    except Exception as error:
                        cleanup_error = error
                        retain = True
            require(primary is None and cleanup_error is None,
                    f"{mode}: operation_failed={primary is not None}; cleanup_failed={cleanup_error is not None}; inspect fixed helper diagnostics")
            require(active_baseline() == baseline, "active desktop changed during cleanup")
        require(set(sessions()) == set(initial), "session inventory changed; investigate before continuing")
        report["cleanup_completed"] = True
        report["versions"] = command(["rpm", "-q", "systemd", "pam", "selinux-policy-targeted"]).stdout.splitlines()
    finally:
        with cleanup_window():
            if not retain:
                if created:
                    shutil.rmtree(BIN)
                shutil.rmtree(root)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--compile-only", action="store_true")
    parser.add_argument("--run-in-disposable-vm", action="store_true")
    parser.add_argument("--snapshot-confirmed", action="store_true")
    args = parser.parse_args()
    require(args.compile_only != args.run_in_disposable_vm, "choose compile-only or guarded VM run")
    os.umask(0o077)
    if args.compile_only:
        with tempfile.TemporaryDirectory(prefix="localpin-m1-session-build-") as temporary:
            compile_helper(Path(temporary) / "helper")
            compile_helper(Path(temporary) / "limits.so", "limits.c", shared=True)
        print("C compile passed; no PAM/session/system operation executed")
        return
    require(args.snapshot_confirmed, "confirm a restorable clean VM snapshot")
    def interrupted(signum, frame):
        del signum, frame
        raise RuntimeError("interrupted; closing only owned session fixtures")
    signal.signal(signal.SIGINT, interrupted)
    signal.signal(signal.SIGTERM, interrupted)
    print(json.dumps(execute(), indent=2))


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(f"M1 session fixture stopped: {type(error).__name__}; no pass recorded. Inspect guest fixed helper diagnostics; restore snapshot on incomplete cleanup.", file=sys.stderr)
        raise SystemExit(1)
