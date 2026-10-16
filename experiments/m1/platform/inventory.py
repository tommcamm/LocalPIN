#!/usr/bin/env python3
"""Read-only M1 metadata collector. Never emits PAM text, arguments or usernames."""

from __future__ import annotations

import argparse
import ctypes
import ctypes.util
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess

MAX_PAM_BYTES = 1024 * 1024
MAX_FILES = 256
MAX_DEPTH = 128
NAME = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}\Z")
ENTRY = re.compile(
    r"^\s*(-?(?:auth|account|password|session))\s+"
    r"(?:(\[[^\]]*\])|(\S+))\s+(\S+)(.*)$"
)
PACKAGES = (
    "fedora-release", "fedora-release-kde", "kscreenlocker", "plasma-workspace",
    "pam", "authselect", "systemd", "selinux-policy", "selinux-policy-targeted",
    "swtpm", "tpm2-tss", "kernel-core",
)


def logical_lines(text: str):
    pending = ""
    start = 1
    for number, line in enumerate(text.splitlines(), 1):
        if not pending:
            start = number
        if line.endswith("\\"):
            pending += line[:-1] + " "
            continue
        yield start, pending + line
        pending = ""
    if pending:
        # Keep the unterminated continuation visibly invalid.
        yield start, pending + "\\"


def collect_pam_graph(pam_dir: Path, service: str, symlink_roots=()):
    """Inventory every phase; unsupported grammar and incomplete reads fail visibly.

    This is an inventory parser, not a PAM interpreter or activation validator.
    Includes are edges, never flattened: substack and include have different control
    behavior. Symlinks can resolve only into explicitly allowed directories.
    """
    if not NAME.fullmatch(service):
        raise ValueError("invalid service name")
    try:
        root = pam_dir.resolve()
        allowed = (root, *(Path(path).resolve() for path in symlink_roots))
    except (OSError, RuntimeError):
        return {"root_service_candidate": service, "service_identity_verified": False,
                "complete": False, "files": [], "edges": [],
                "errors": [{"service": service, "code": "invalid_read_root"}]}
    nodes, edges, errors = {}, [], []
    visiting = set()

    def error(name, code, line=None):
        item = {"service": name, "code": code}
        if line is not None:
            item["line"] = line
        errors.append(item)

    def visit(name, depth):
        if name in visiting:
            error(name, "include_cycle")
            return
        if name in nodes:
            return
        if depth > MAX_DEPTH or len(nodes) >= MAX_FILES:
            error(name, "graph_limit")
            return
        node = {"service": name, "status": "unreadable"}
        nodes[name] = node
        path = root / name
        try:
            target = path.resolve(strict=True)
            if not any(target.is_relative_to(directory) for directory in allowed):
                error(name, "symlink_outside_allowed_roots")
                return
            # O_NONBLOCK avoids a malicious/surprising FIFO hanging the collector.
            fd = os.open(target, os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC | os.O_NOFOLLOW)
            before = os.fstat(fd)
            if not stat.S_ISREG(before.st_mode):
                os.close(fd)
                error(name, "not_regular_file")
                return
            with os.fdopen(fd, "rb") as source:
                raw = source.read(MAX_PAM_BYTES + 1)
                after = os.fstat(source.fileno())
            if len(raw) > MAX_PAM_BYTES:
                error(name, "file_too_large")
                return
            if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
                after.st_size, after.st_mtime_ns, after.st_ctime_ns
            ):
                error(name, "changed_during_read")
                return
            if b"\0" in raw:
                error(name, "nul_byte")
                return
            text = raw.decode("utf-8", errors="surrogateescape")
            node.update(status="read", sha256=hashlib.sha256(raw).hexdigest(),
                        bytes=len(raw), symlink=path.is_symlink(),
                        phases={}, modules=[])
        except FileNotFoundError:
            error(name, "missing_file")
            return
        except (OSError, RuntimeError):
            # Do not include exception strings: they can contain identifying paths.
            error(name, "read_error")
            return
        visiting.add(name)
        try:
            for number, line in logical_lines(text):
                stripped = line.strip()
                if not stripped or stripped.startswith("#"):
                    continue
                if stripped.endswith("\\"):
                    error(name, "unterminated_continuation", number)
                    continue
                if stripped.startswith("@include"):
                    parts = stripped.split()
                    if len(parts) != 2 or parts[0] != "@include":
                        error(name, "unsupported_include", number)
                        continue
                    phase, control, module, rest = "all", "@include", parts[1], ""
                else:
                    match = ENTRY.fullmatch(line)
                    if not match:
                        error(name, "unsupported_syntax", number)
                        continue
                    phase, extended, simple, module, rest = match.groups()
                    phase = phase.lstrip("-")
                    control = extended or simple
                    node["phases"][phase] = node["phases"].get(phase, 0) + 1
                    if not extended and control not in {"required", "requisite", "sufficient", "optional", "include", "substack"}:
                        error(name, "unsupported_control", number)
                        continue
                if control in {"include", "substack", "@include"}:
                    # Do not guess Linux-PAM's behavior for noncanonical paths.
                    if not NAME.fullmatch(module) or (rest.strip() and not rest.lstrip().startswith("#")):
                        error(name, "unsupported_include_target", number)
                        continue
                    edges.append({"from": name, "to": module, "phase": phase,
                                  "kind": control, "line": number})
                    visit(module, depth + 1)
                else:
                    basename = module.rsplit("/", 1)[-1]
                    if not NAME.fullmatch(basename) or not basename.endswith(".so"):
                        error(name, "unsupported_module_path", number)
                        continue
                    node["modules"].append({"phase": phase, "module": basename,
                                            "line": number,
                                            "control_form": "extended" if control.startswith("[") else "simple"})
        finally:
            visiting.remove(name)

    visit(service, 0)
    return {"root_service_candidate": service, "service_identity_verified": False,
            "complete": not errors, "files": sorted(nodes.values(), key=lambda item: item["service"]),
            "edges": edges, "errors": errors,
            "warning": "Inventory only; hashes and parsed structure do not authorize PAM edits."}


def command(args):
    executable = shutil.which(args[0])
    if executable is None:
        return {"status": "missing_command"}, ""
    try:
        result = subprocess.run([executable, *args[1:]], stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                timeout=5, check=False, env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"})
    except subprocess.TimeoutExpired:
        return {"status": "timeout"}, ""
    except OSError:
        return {"status": "execution_error"}, ""
    if len(result.stdout) > 1024 * 1024:
        return {"status": "output_limit"}, ""
    status = {"status": "ok" if result.returncode == 0 else "command_failed",
              "exit_code": result.returncode}
    return status, result.stdout.decode("utf-8", errors="replace") if result.returncode == 0 else ""


def session_candidate(properties, peer_uid):
    """A discovery filter, deliberately not a production authorization decision."""
    return (peer_uid != 0 and properties.get("User") == str(peer_uid)
            and properties.get("Remote") == "no"
            and properties.get("Type") in {"wayland", "x11"}
            and properties.get("Class") == "user"
            and properties.get("State") in {"online", "active"}
            and bool(properties.get("Seat"))
            and properties.get("Desktop", "").lower() in {"kde", "plasma", "plasmax11"})


def pid_membership(pid):
    """Observe sd-login's direct-session and user-manager-owner distinction."""
    library = ctypes.util.find_library("systemd")
    if not library:
        return {"status": "missing_libsystemd"}, None
    try:
        systemd = ctypes.CDLL(library)
        libc = ctypes.CDLL(None)
        systemd.sd_pid_get_session.argtypes = [ctypes.c_int, ctypes.POINTER(ctypes.c_void_p)]
        systemd.sd_pid_get_session.restype = ctypes.c_int
        systemd.sd_pid_get_owner_uid.argtypes = [ctypes.c_int, ctypes.POINTER(ctypes.c_uint)]
        systemd.sd_pid_get_owner_uid.restype = ctypes.c_int
        libc.free.argtypes = [ctypes.c_void_p]
        session_pointer = ctypes.c_void_p()
        result = systemd.sd_pid_get_session(pid, ctypes.byref(session_pointer))
        direct = None
        if result >= 0 and session_pointer.value:
            try:
                direct = ctypes.string_at(session_pointer).decode("utf-8")
            finally:
                libc.free(session_pointer)
        owner = ctypes.c_uint()
        owner_result = systemd.sd_pid_get_owner_uid(pid, ctypes.byref(owner))
        return {"status": "observed", "direct_session_found": direct is not None,
                "direct_session_result": result,
                "user_manager_owner_found": owner_result >= 0,
                "user_manager_owner_is_peer": owner_result >= 0 and owner.value == os.getuid(),
                "user_manager_owner_result": owner_result}, direct
    except (OSError, AttributeError, UnicodeError):
        return {"status": "api_error"}, None


def collect_sessions(pid):
    membership, direct = pid_membership(pid)
    result, output = command(["loginctl", "list-sessions", "--json=short", "--no-pager"])
    report = {"query": result, "pid_membership": membership, "sessions": [],
              "authorization_proven": False}
    if result["status"] != "ok":
        return report
    try:
        sessions = json.loads(output)
        if not isinstance(sessions, list) or len(sessions) > 256:
            raise ValueError
        seats = {}
        for index, session in enumerate(sessions):
            identifier = session["session"]
            if not isinstance(identifier, str) or not NAME.fullmatch(identifier):
                raise ValueError
            status, values = command(["loginctl", "show-session", identifier, "--no-pager",
                                      "--property=User,Type,Class,Remote,Active,State,Seat,Desktop"])
            entry = {"session": f"session-{index + 1}", "query": status}
            if status["status"] == "ok":
                props = dict(line.split("=", 1) for line in values.splitlines() if "=" in line)
                seat = props.get("Seat", "")
                if seat:
                    seats.setdefault(seat, f"seat-{len(seats) + 1}")
                entry.update(peer_uid=props.get("User") == str(os.getuid()),
                             direct_pid_session=identifier == direct,
                             graphical=props.get("Type") in {"x11", "wayland"},
                             remote=props.get("Remote") != "no",
                             active=props.get("Active") == "yes",
                             user_class=props.get("Class") == "user",
                             seat=seats.get(seat),
                             kde_desktop=props.get("Desktop", "").lower() in {"kde", "plasma", "plasmax11"},
                             discovery_candidate=session_candidate(props, os.getuid()))
            report["sessions"].append(entry)
    except (ValueError, KeyError, TypeError):
        report["query"] = {"status": "unsupported_loginctl_output"}
        report["sessions"] = []
    return report


def collect_host(pid):
    packages = []
    for package in PACKAGES:
        result, version = command(["rpm", "-q", "--qf", "%{NAME}-%{EPOCHNUM}:%{VERSION}-%{RELEASE}.%{ARCH}\\n", package])
        packages.append({"package": package, "query": result,
                         "nevra": version.strip().splitlines() if version else []})
    selinux_status, selinux = command(["getenforce"])
    if selinux.strip() not in {"Enforcing", "Permissive", "Disabled"}:
        selinux = "unknown"
    try:
        os_release = {}
        for line in Path("/etc/os-release").read_text().splitlines():
            key, separator, value = line.partition("=")
            if separator and key in {"ID", "VERSION_ID", "VARIANT_ID"}:
                value = value.strip('"')
                if re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", value):
                    os_release[key] = value
    except OSError:
        os_release = {"status": "unreadable"}
    return {"os_release": os_release, "packages": packages,
            "selinux": {"query": selinux_status, "mode": selinux.strip()},
            "sessions": collect_sessions(pid),
            "compatibility_certified": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--service", required=True, help="explicit candidate, not autodetected")
    parser.add_argument("--pam-dir", type=Path, default=Path("/etc/pam.d"))
    parser.add_argument("--symlink-root", type=Path, action="append", default=[],
                        help="explicit additional read root, e.g. /etc/authselect")
    parser.add_argument("--host", action="store_true", help="also collect RPM/SELinux/logind metadata")
    parser.add_argument("--pid", type=int, default=os.getpid(), help="observe this process's sd-login membership")
    args = parser.parse_args()
    if args.pid < 1 or args.pid > 2**31 - 1 or not NAME.fullmatch(args.service):
        parser.error("invalid PID or service name")
    graph = collect_pam_graph(args.pam_dir, args.service, args.symlink_root)
    report = {"schema_version": 1, "pam": graph}
    if args.host:
        report["host_observation"] = collect_host(args.pid)
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if graph["complete"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
