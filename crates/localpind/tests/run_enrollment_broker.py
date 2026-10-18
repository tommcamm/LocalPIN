#!/usr/bin/env python3
"""Opt-in enrollment broker lifecycle and flexible-credential tests in tmpfs.

Covers legacy software verification, current numeric/passcode policy, explicit
kind changes, stale challenge metadata and unchanged throttle on profile refusal.
Host mounts stay read-only; synthetic historical records never leave tmpfs.

Requires unshare, bubblewrap, configured subordinate IDs and native Cargo build
dependencies. Never installs a service, edits accounts or accesses a real TPM.
Run outside a syscall-restricted agent sandbox; no host root privilege is used.
"""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys


def cargo_executable(root, arguments, name):
    """Use Cargo's actual artifact path, including target-directory overrides."""
    build = subprocess.run(
        ["cargo", *arguments, "--locked", "--message-format=json"],
        cwd=root, check=False, capture_output=True, text=True, timeout=120,
    )
    if build.returncode:
        print(build.stderr, file=sys.stderr, end="")
        raise RuntimeError(f"{name} build failed")
    executable = None
    for line in build.stdout.splitlines():
        item = json.loads(line)
        if item.get("reason") == "compiler-artifact" and item.get("target", {}).get("name") == name:
            executable = item.get("executable") or executable
    if executable is None:
        raise RuntimeError(f"Cargo did not return the {name} executable")
    return Path(executable).resolve()


def main():
    root = Path(__file__).resolve().parents[3]
    for executable in ("cargo", "unshare", "bwrap", "newuidmap", "newgidmap"):
        if shutil.which(executable) is None:
            raise RuntimeError(f"required namespace/build tool unavailable: {executable}")
    if os.getuid() == 0:
        raise RuntimeError("run as an ordinary host user; host root is never needed")
    executable = cargo_executable(root, ["test", "-p", "localpind", "--test", "enrollment_broker", "--no-run"], "enrollment_broker")
    worker = cargo_executable(root, ["build", "-p", "localpind", "--bin", "localpin-worker"], "localpin-worker")
    command = [
        "unshare", "--user", "--map-root-user", "--map-auto", "--mount", "--fork", "--kill-child",
        "bwrap", "--unshare-ipc", "--unshare-net", "--unshare-pid", "--die-with-parent", "--new-session", "--clearenv",
        "--tmpfs", "/", "--ro-bind", "/usr", "/usr",
        "--symlink", "usr/lib64", "/lib64", "--symlink", "usr/lib", "/lib", "--symlink", "usr/bin", "/bin",
        "--proc", "/proc", "--dev", "/dev", "--dir", "/app", "--dir", "/run", "--dir", "/tmp",
        "--ro-bind", str(executable), "/app/enrollment-broker-tests",
        "--ro-bind", str(worker), "/app/localpin-worker",
        "--setenv", "LOCALPIN_M6_ENROLLMENT_NAMESPACE", "1",
        "--cap-add", "CAP_SETUID", "--cap-add", "CAP_SETGID",
        "--", "/app/enrollment-broker-tests", "--exact", "enrollment_engine_complete_lifecycle_and_authorization_fences", "--ignored", "--nocapture", "--test-threads=1",
    ]
    subprocess.run(command, cwd=root, check=True, timeout=90)


if __name__ == "__main__":
    try:
        main()
    except (OSError, RuntimeError, subprocess.SubprocessError) as error:
        print(f"enrollment broker namespace test failed: {error}", file=sys.stderr)
        raise SystemExit(1) from None
