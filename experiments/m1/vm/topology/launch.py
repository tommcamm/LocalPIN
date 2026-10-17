#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Clone-only seat0 classic Plasma launcher. Readiness never proves a GUI test."""
import argparse
from contextlib import contextmanager
import ctypes
from decimal import Decimal
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
import tempfile
import time

HERE = Path(__file__).resolve().parent
CONTROL = Path("/run/localpin-m1-topology")
BIN = Path("/usr/libexec/localpin-m1-topology")
UNIT = "localpin-m1-topology-launch.service"
CLONE = Path("/etc/localpin-m1-topology-clone-guard")


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


pam = load("m1_topology_account_guard", HERE.parent / "pam" / "run.py")
sessions = load("m1_topology_session_helpers", HERE.parent / "sessions" / "run.py")
require = pam.require
command = sessions.command


def guard():
    pam.guard()
    info = CLONE.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_uid == info.st_gid == 0
            and stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1,
            "unsafe topology clone marker")
    uuid = Path("/sys/class/dmi/id/product_uuid").read_text().strip()
    require(CLONE.read_text() == f"LOCALPIN-M1-TOPOLOGY-CLONE\ntarget=localpintest\nuuid={uuid}\n",
            "topology clone marker mismatch")


def safe(path, *, directory=False):
    info = path.lstat()
    require((stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode))
            and info.st_uid == info.st_gid == 0 and stat.S_IMODE(info.st_mode) == (0o700 if directory else 0o600)
            and (directory or info.st_nlink == 1), "unsafe private topology control")


def write_new(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as output:
        output.write(data)
        output.flush()
        os.fsync(output.fileno())


def read_json(path):
    safe(path)
    require(path.stat().st_size <= 65536, "oversized topology control")
    return json.loads(path.read_bytes())


def build(work):
    flags = ["-std=c11", "-O2", "-Wall", "-Wextra", "-Wpedantic", "-Werror",
             "-fstack-protector-strong", "-D_FORTIFY_SOURCE=3", "-Wl,-z,relro,-z,now", "-isystem",
             os.environ.get("LOCALPIN_PAM_INCLUDE", "/usr/include")]
    for name, shared in (("launch", False), ("limits", True)):
        command(["cc", *flags, *(["-fPIC", "-shared"] if shared else
                                ["-isystem", os.environ.get("LOCALPIN_SYSTEMD_INCLUDE", "/usr/include")]),
                 str(HERE / f"{name}.c"), "-o", str(work / ("limits.so" if shared else "launch")),
                 "-l:libpam.so.0", *([] if shared else ["-l:libsystemd.so.0"])], timeout=30)


def stop_timeout_usec(value):
    """Parse the C-locale systemctl duration; refuse unknown or long bounds."""
    require(isinstance(value, str) and re.fullmatch(r"\d+(?:\.\d+)?(?:us|ms|s|min|h|d)(?: \d+(?:\.\d+)?(?:us|ms|s|min|h|d))*", value) is not None,
            "owned scope stop timeout is unknown or infinite")
    scale = {"us": 1, "ms": 1000, "s": 1000000, "min": 60000000, "h": 3600000000, "d": 86400000000}
    amount = sum(Decimal(number) * scale[unit] for number, unit in re.findall(r"(\d+(?:\.\d+)?)(us|ms|s|min|h|d)", value))
    require(amount == amount.to_integral_value() and 0 < amount <= 45000000,
            "owned scope stop timeout exceeds the reviewed 45-second bound")
    return int(amount)


def verify_scope_limits(scope):
    text = command(["systemctl", "show", scope, "-pRuntimeMaxUSec", "-pTasksMax", "-pMemoryMax", "-pTimeoutStopUSec"]).stdout
    values = dict(line.split("=", 1) for line in text.splitlines() if "=" in line)
    require(values.get("RuntimeMaxUSec") == "15min" and values.get("TasksMax") == "1024"
            and values.get("MemoryMax") == "3221225472", "owned migrated scope resource bounds missing or different")
    return stop_timeout_usec(values.get("TimeoutStopUSec"))


def starttime(pid):
    require(isinstance(pid, int) and pid > 1, "invalid topology process")
    # The final ')' separates comm, which can contain spaces, from fixed fields.
    text = Path(f"/proc/{pid}/stat").read_text()
    return int(text[text.rfind(")") + 2:].split()[19])


def tagged_processes(uid):
    """Observe fixture environment inheritance; never kill by tag or by UID."""
    result = []
    entries = [path for path in Path("/proc").iterdir() if path.name.isdigit()]
    require(len(entries) <= 32768, "process inventory exceeds fixture bound")
    for path in entries:
        try:
            with (path / "status").open("rb") as source:
                status = source.read(65537)
            require(len(status) <= 65536, "oversized process status")
            match = re.search(rb"^Uid:\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)$", status, re.M)
            require(match is not None, "process UID metadata unavailable")
            if int(match[1]) != uid:
                continue
            with (path / "environ").open("rb") as source:
                environment = source.read(1048577)
            require(len(environment) <= 1048576, "oversized target process environment")
            if b"LOCALPIN_M1_TOPOLOGY=clone-native-drm" in environment.split(b"\0"):
                result.append({"pid": int(path.name), "starttime": starttime(int(path.name))})
        except (FileNotFoundError, ProcessLookupError):
            continue  # A process that disappeared supplies no live cleanup target.
    return result


def new_registration(manifest, *, allow_finished=False):
    path = CONTROL / "registered.json"
    if not path.exists():
        return None
    data = read_json(path)
    require(re.fullmatch(r"[A-Za-z0-9_-]{1,64}", data["session"]) is not None
            and data["session"] not in manifest["baseline_ids"] and data["uid"] == manifest["uid"]
            and data["vt"] == manifest["vt"] and data.get("registration_only") is True,
            "registration is not this new dedicated fixture")
    require(isinstance(data.get("leader"), int) and data["leader"] > 1, "invalid recorded helper leader")
    scope = f"session-{data['session']}.scope"
    if allow_finished and data["session"] not in sessions.sessions():
        # Native root publication is durable before desktop startup. A fast
        # startup refusal can close its session before prepare reads readiness;
        # the controller may clean the recorded scope only after proving it gone.
        return {**data, "scope": scope, "leader_starttime": None}
    observed = sessions.properties(data["session"])
    require(observed["Service"] == "localpin-m1-topology" and observed["User"] == str(manifest["uid"])
            and observed["Leader"] == str(data["leader"]) and observed["Seat"] == "seat0"
            and observed["VTNr"] == str(manifest["vt"]) and observed["Type"] == "wayland"
            and observed["Class"] == "user" and observed["Remote"] == "no"
            and observed["Scope"] == f"session-{data['session']}.scope", "fresh session ownership differs")
    if allow_finished and not Path(f"/proc/{data['leader']}").exists():
        return {**data, "scope": scope, "leader_starttime": None}
    ticks = starttime(data["leader"])
    require(ticks > 0, "helper leader unavailable")
    return {**data, "scope": observed["Scope"], "leader_starttime": ticks}


def manifest():
    safe(CONTROL, directory=True)
    data = read_json(CONTROL / "manifest.json")
    require(data.get("schema") == 1 and data.get("unit") == UNIT and data["uid"] == pwd.getpwnam("localpintest").pw_uid,
            "topology manifest mismatch")
    return data


def prepare():
    guard()
    require(not any(path.exists() or path.is_symlink() for path in (CONTROL, BIN)), "topology fixture path collision")
    require("LoadState=not-found" in command(["systemctl", "show", UNIT, "-pLoadState"], check=False).stdout,
            "topology launch unit already exists")
    for executable in ("plasma_session", "kwin_wayland_wrapper", "kwin_wayland", "plasmashell", "dbus-run-session"):
        require(Path("/usr/bin", executable).is_file(), "packaged classic Plasma prerequisite missing")
    require(Path("/usr/lib64/security/pam_systemd.so").is_file(), "pam_systemd unavailable")
    before = sessions.sessions()
    uid = pwd.getpwnam("localpintest").pw_uid
    require(not tagged_processes(uid), "an earlier tagged topology process remains")
    require(sum(sessions.inventory.session_candidate(value, uid) for value in before.values()) == 1,
            "one existing genuine target desktop candidate required before launcher")
    baseline = sessions.active_baseline()
    require(baseline[0] in before and sessions.inventory.session_candidate(before[baseline[0]], uid)
            and before[baseline[0]]["VTNr"] == str(baseline[1]), "the first genuine target desktop must be active")
    vt = sessions.select_spare(before, *sessions.vt_state())
    sessions.verify_spare(vt, baseline)
    require(not Path(f"/run/user/{uid}/localpin-m1-topology").exists(), "private target directory already exists")
    created = []
    launched = False
    try:
        with tempfile.TemporaryDirectory(prefix="localpin-m1-topology-build-") as temporary:
            work = Path(temporary)
            build(work)
            for path, mode in ((CONTROL, 0o700), (BIN, 0o755)):
                path.mkdir(mode=mode)
                created.append(path)
                path.chmod(mode)
            for name in ("launch", "limits.so"):
                shutil.copyfile(work / name, BIN / name)
                (BIN / name).chmod(0o755 if name == "launch" else 0o644)
            shutil.copyfile(HERE / "private-session-bus.conf", BIN / "private-session-bus.conf")
            (BIN / "private-session-bus.conf").chmod(0o644)
        command(["restorecon", "-R", str(BIN)])
        context = os.getxattr("/usr/lib64/security/pam_systemd.so", "security.selinux")
        os.setxattr(BIN / "limits.so", "security.selinux", context)
        require(os.getxattr(BIN / "limits.so", "security.selinux") == context, "private session module label mismatch")
        (CONTROL / "pam").mkdir(mode=0o700)
        write_new(CONTROL / "pam/localpin-m1-topology",
                  f"session required {BIN}/limits.so\nsession required /usr/lib64/security/pam_systemd.so\n".encode())
        data = {"schema": 1, "unit": UNIT, "uid": uid, "vt": vt, "baseline_ids": list(before),
                "protected_desktop_ids": [identifier for identifier, value in before.items()
                                          if sessions.inventory.session_candidate(value, uid)],
                "first_active_session": baseline[0], "first_active_vt": baseline[1], "mode": "seat0-classic-private-bus"}
        write_new(CONTROL / "manifest.json", json.dumps(data).encode())
        sessions.verify_spare(vt, baseline)
        launched = True  # A failed/timed-out start may already have registered.
        command(["systemd-run", "--quiet", f"--unit={UNIT}", "--service-type=exec", "--property=User=root",
                 "--property=RuntimeMaxSec=16min", "--property=TimeoutStopSec=5s", "--property=KillMode=process",
                 "--property=LimitCORE=0", "--property=StandardInput=null", "--property=StandardOutput=null",
                 "--property=StandardError=journal", str(BIN / "launch"), str(vt)])
        deadline = time.monotonic() + 15
        while not (CONTROL / "registered.json").exists() and time.monotonic() < deadline:
            time.sleep(0.1)
        require((CONTROL / "registered.json").exists(), "native session did not register; retain fixture and run finish or restore clone")
        registration = new_registration(data)
        require(registration is not None, "registered topology session unavailable")
        write_new(CONTROL / "owned-session.json", json.dumps(registration).encode())
        stop_usec = verify_scope_limits(registration["scope"])
        require(not (CONTROL / "ready.json").exists(), "desktop started before controller activation")
        return {"prepared": True, "awaiting_activation": True, "desktop_child_started": False,
                "registration_only": True, "gui_test_proven": False,
                "session": registration["session"], "scope": registration["scope"], "vt": vt,
                "uid": uid, "private_bus": True, "canonical_user_runtime": True, "scope_runtime_seconds": 900,
                "scope_tasks_max": 1024, "scope_memory_max_bytes": 3221225472,
                "scope_timeout_stop_usec": stop_usec, "scope_stop_client_timeout_seconds": 55}
    except BaseException:
        if not launched:
            for path in reversed(created):
                shutil.rmtree(path)
        # After launch, never guess a session; durable controls + scope deadline
        # support explicit finish. Uncertain registration requires clone rollback.
        raise


def verified_owned(data):
    owned = read_json(CONTROL / "owned-session.json")
    fresh = new_registration(data)
    require(fresh is not None and all(fresh[key] == owned[key]
            for key in ("session", "scope", "uid", "vt", "leader", "leader_starttime")),
            "new session identity changed before activation")
    return fresh


def verify_first_desktop(data):
    current = sessions.sessions()
    first = data["first_active_session"]
    require(first in data["protected_desktop_ids"] and first in current
            and sessions.inventory.session_candidate(current[first], data["uid"])
            and current[first]["VTNr"] == str(data["first_active_vt"]),
            "protected first desktop identity changed before activation")


def publish_activation(session):
    # A complete gate appears atomically; the native reader never sees a
    # newly created but empty/partial approval file. Rename refuses overwrite.
    temporary, final = CONTROL / "activate-approved.tmp", CONTROL / "activate-approved"
    write_new(temporary, f"{session}\n".encode("ascii"))
    libc = ctypes.CDLL(None, use_errno=True)
    libc.renameat2.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    libc.renameat2.restype = ctypes.c_int
    if libc.renameat2(-100, os.fsencode(temporary), -100, os.fsencode(final), 1):  # RENAME_NOREPLACE
        raise OSError(ctypes.get_errno(), "atomic activation approval failed")
    fd = os.open(CONTROL, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def activate():
    """Deliberately switch only the pinned new clone session before its fork."""
    guard()
    data = manifest()
    require(not any((CONTROL / name).exists() for name in ("release", "closed.json", "ready.json", "activate-approved")),
            "activation is no longer pending; inspect status and finish")
    owned = verified_owned(data)
    verify_first_desktop(data)
    require(sessions.active_baseline() in ((data["first_active_session"], data["first_active_vt"]),
                                          (owned["session"], owned["vt"])),
            "unrelated active session/VT; refuse activation")
    verify_scope_limits(owned["scope"])
    command(["loginctl", "activate", owned["session"]])
    deadline = time.monotonic() + 10
    active = False
    while time.monotonic() < deadline:
        active = (sessions.properties(owned["session"])["Active"] == "yes"
                  and sessions.active_baseline() == (owned["session"], owned["vt"]))
        if active:
            break
        time.sleep(0.1)
    require(active, "owned session did not become active on its exact VT; no desktop gate published")
    verified_owned(data)
    verify_first_desktop(data)
    require(sessions.properties(owned["session"])["Active"] == "yes"
            and sessions.active_baseline() == (owned["session"], owned["vt"]),
            "active session/VT changed before desktop approval")
    publish_activation(owned["session"])
    deadline = time.monotonic() + 15
    while not (CONTROL / "ready.json").exists() and not (CONTROL / "closed.json").exists() and time.monotonic() < deadline:
        time.sleep(0.1)
    require((CONTROL / "ready.json").exists(), "activated child did not start; retain fixture and run finish")
    ready = read_json(CONTROL / "ready.json")
    require(all(ready[key] == owned[key] for key in ("session", "leader", "uid", "vt"))
            and isinstance(ready.get("child"), int) and ready["child"] > 1
            and ready.get("activation_verified_before_fork") is True,
            "native activated-child report differs")
    return {"activated": True, "desktop_child_started": True, "activation_verified_before_fork": True,
            "registration_only": True, "gui_test_proven": False, "session": owned["session"],
            "scope": owned["scope"], "vt": owned["vt"], "uid": owned["uid"], "child": ready["child"]}


@contextmanager
def cleanup_window():
    handlers = {sig: signal.signal(sig, signal.SIG_IGN) for sig in (signal.SIGINT, signal.SIGTERM)}
    try:
        yield
    finally:
        for sig, handler in handlers.items():
            signal.signal(sig, handler)


def finish():
    guard()
    data = manifest()
    owned_path = CONTROL / "owned-session.json"
    owned = read_json(owned_path) if owned_path.exists() else new_registration(data, allow_finished=True)
    require(owned is not None, "no verified new session; retain resources and restore clone")
    require(owned["session"] not in data["baseline_ids"] and owned["scope"] == f"session-{owned['session']}.scope"
            and owned["uid"] == data["uid"], "owned scope manifest mismatch")
    with cleanup_window():
        if not (CONTROL / "release").exists():
            write_new(CONTROL / "release", b"release\n")
        deadline = time.monotonic() + 8
        while not (CONTROL / "closed.json").exists() and time.monotonic() < deadline:
            time.sleep(0.1)
        current = sessions.sessions()
        if owned["session"] in current:
            p = current[owned["session"]]
            require(p["Service"] == "localpin-m1-topology" and p["Scope"] == owned["scope"]
                    and p["User"] == str(owned["uid"]) and p["Leader"] == str(owned["leader"]),
                    "owned session identity changed; refuse scope stop")
            # The root helper can migrate out of its launch unit; stopping only
            # the recorded new scope covers its actual desktop descendants.
            if Path(f"/proc/{owned['leader']}").exists():
                require(starttime(owned["leader"]) == owned["leader_starttime"], "helper PID was reused")
            actual_timeout = command(["systemctl", "show", owned["scope"], "--value", "-pTimeoutStopUSec"]).stdout.strip()
            stop_timeout_usec(actual_timeout)
            command(["systemctl", "stop", owned["scope"]], timeout=55)
        command(["systemctl", "stop", UNIT], timeout=8, check=False)
        deadline = time.monotonic() + 25
        while time.monotonic() < deadline:
            if owned["session"] not in sessions.sessions():
                break
            time.sleep(0.1)
        require(owned["session"] not in sessions.sessions(), "owned logind session remains; retain resources and restore clone")
        scope_text = command(["systemctl", "show", owned["scope"], "-pActiveState", "-pControlGroup"], check=False).stdout
        scope_fields = dict(line.split("=", 1) for line in scope_text.splitlines() if "=" in line)
        require(scope_fields.get("ActiveState") in {"inactive", "failed"} and not scope_fields.get("ControlGroup"),
                "owned scope not empty/unloaded; retain fixture and restore clone")
        unit_text = command(["systemctl", "show", UNIT, "-pActiveState", "-pMainPID"], check=False).stdout
        unit_fields = dict(line.split("=", 1) for line in unit_text.splitlines() if "=" in line)
        require(unit_fields.get("ActiveState") in {"inactive", "failed"} and unit_fields.get("MainPID") == "0",
                "launch unit stop uncertain; retain fixture and restore clone")
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and tagged_processes(data["uid"]):
            time.sleep(0.1)
        require(not tagged_processes(data["uid"]),
                "a tagged desktop descendant remains outside cleanup; retain resources and restore clone")
        remaining = sessions.sessions()
        require(set(data["protected_desktop_ids"]).issubset(remaining),
                "the protected first desktop disappeared; investigate clone before continuing")
        target = Path(f"/run/user/{data['uid']}/localpin-m1-topology")
        if target.exists():
            info = target.lstat()
            require(stat.S_ISDIR(info.st_mode) and info.st_uid == data["uid"] and stat.S_IMODE(info.st_mode) == 0o700,
                    "private target path changed; retain fixture")
            shutil.rmtree(target)
        shutil.rmtree(BIN)
        shutil.rmtree(CONTROL)
    return {"cleanup_completed": True, "owned_scope_gone": True, "tagged_descendants_gone": True,
            "protected_first_desktop_retained": True,
            "whole_clone_snapshot_cleanup_required": True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("compile-only", "prepare", "activate", "status", "finish"))
    parser.add_argument("--snapshot-confirmed", action="store_true")
    args = parser.parse_args()
    os.umask(0o077)
    if args.operation == "compile-only":
        with tempfile.TemporaryDirectory(prefix="localpin-m1-topology-compile-") as temporary:
            build(Path(temporary))
        print("Compile PASS; no account, PAM, session, policy, or system mutation")
        return
    def interrupted(signum, frame):
        del signum, frame
        raise RuntimeError("interrupted; retain owned fixture controls for explicit finish or clone rollback")
    signal.signal(signal.SIGINT, interrupted)
    signal.signal(signal.SIGTERM, interrupted)
    guard()
    if args.operation == "prepare":
        require(args.snapshot_confirmed, "restorable clone snapshot confirmation required")
        result = prepare()
    elif args.operation == "finish":
        result = finish()
    elif args.operation == "activate":
        result = activate()
    else:
        result = {"manifest": manifest(), "registered": (CONTROL / "registered.json").exists(),
                  "activation_approved": (CONTROL / "activate-approved").exists(),
                  "ready": (CONTROL / "ready.json").exists(), "closed": (CONTROL / "closed.json").exists(),
                  "gui_test_proven": False}
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        reason = str(error) if isinstance(error, RuntimeError) else type(error).__name__
        print(f"M1 topology stopped: {reason}; no GUI pass recorded; retain controls or restore clone.", file=__import__("sys").stderr)
        raise SystemExit(1)
