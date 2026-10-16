#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Fixed-contact tests in private unprivileged namespaces; no host /run or /etc."""
import argparse
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time

SOCKET = "/run/localpin-m1/contact.sock"


def inside(probe):
    Path(SOCKET).parent.mkdir(mode=0o700)
    count = 0

    def attempt(expected, response=None, *, delay=0, fragmented=False, fake_peer=False):
        nonlocal count
        Path(SOCKET).unlink(missing_ok=True)
        request = []
        server_error = []
        listener = None
        thread = None
        if response is not None:
            listener = socket.socket(socket.AF_UNIX)
            listener.bind(SOCKET)
            listener.listen(1)
            listener.settimeout(2)

            def serve():
                try:
                    connection, _ = listener.accept()
                    with connection:
                        connection.settimeout(2)
                        value = b""
                        while len(value) < 4:
                            part = connection.recv(4 - len(value))
                            if not part:
                                break
                            value += part
                        request.append(value)
                        time.sleep(delay)
                        if fragmented:
                            for byte in response:
                                connection.sendall(bytes([byte]))
                                time.sleep(0.002)
                        elif response:
                            connection.sendall(response)
                except (BrokenPipeError, ConnectionResetError):
                    if expected != 4:
                        server_error.append("unexpected peer disconnect")
                except BaseException as error:
                    server_error.append(type(error).__name__)

            thread = threading.Thread(target=serve, daemon=True)
            thread.start()
        started = time.monotonic()
        run = subprocess.run([probe, *( ["inject-untrusted-peer"] if fake_peer else [])],
                             capture_output=True, text=True, timeout=2, check=True)
        elapsed = time.monotonic() - started
        if thread:
            thread.join(timeout=2)
            listener.close()
            assert not thread.is_alive() and not server_error, server_error
            assert request == ([b""] if fake_peer else [b"PING"]), "wire request was not the fixed marker"
        observed = int(run.stdout.strip())
        assert observed == expected, (expected, observed)
        assert elapsed < 1.0, ("contact exceeded scheduler-tolerant deadline check", elapsed)
        if expected == 4:
            assert elapsed >= 0.15, ("stalled endpoint was not actually awaited", elapsed)
        count += 1
        print(f"PASS contact outcome={expected} elapsed_ms={elapsed * 1000:.1f}")

    attempt(3)  # no endpoint
    attempt(0, b"PONG")
    attempt(0, b"PONG", fragmented=True)
    attempt(8, b"NOPE")
    attempt(7, b"")
    attempt(4, b"PONG", delay=0.6)
    attempt(5, b"", fake_peer=True)
    print(f"RESULT contact checks={count}; fixed markers only; private namespace UID0")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inside", type=Path)
    args = parser.parse_args()
    if args.inside:
        inside(str(args.inside))
        return 0
    if shutil.which("bwrap") is None:
        print("INFRA: bubblewrap unavailable", file=sys.stderr)
        return 77
    source = Path(__file__).resolve().parent
    # Verify source agreement with the separate, already reviewed broker fixture.
    fixture = source.parent / "selinux" / "fixture.c"
    assert f'#define SOCKET_PATH "{SOCKET}"' in fixture.read_text()
    assert "return PAM_SUCCESS" not in (source / "module.c").read_text()
    with tempfile.TemporaryDirectory(prefix="localpin-m1-contact-test-") as temporary:
        work = Path(temporary)
        subprocess.run(["cc", "-std=c11", "-O2", "-Wall", "-Wextra", "-Wpedantic", "-Werror",
                        str(source / "contact_probe.c"), "-o", str(work / "probe")], check=True)
        command = ["bwrap", "--unshare-all", "--die-with-parent", "--new-session",
                   "--ro-bind", "/usr", "/usr", "--symlink", "usr/lib64", "/lib64",
                   "--symlink", "usr/lib", "/lib", "--symlink", "usr/bin", "/bin",
                   "--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp", "--tmpfs", "/run",
                   "--ro-bind", str(work), "/fixture", "--ro-bind", str(source), "/source",
                   "--uid", "0", "--gid", "0", "--chdir", "/fixture"]
        baseline = subprocess.run([*command, "/usr/bin/true"], capture_output=True)
        if baseline.returncode:
            print("INFRA: unprivileged namespaces unavailable", file=sys.stderr)
            return 77
        return subprocess.run([*command, "/usr/bin/python3", "/source/test_contact.py", "--inside", "/fixture/probe"], timeout=15).returncode


if __name__ == "__main__":
    raise SystemExit(main())
