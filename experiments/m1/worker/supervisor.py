#!/usr/bin/env python3
"""M1 process-isolation experiment; no authentication or production broker code."""

import ctypes
import os
from pathlib import Path
import signal
import subprocess
import sys
import threading
import time


class Supervisor:
    """Exercise reserve-before-spawn, deadline fencing, and bounded worker slots."""

    def __init__(self, state: Path, capacity: int = 2):
        self.state = state
        self.capacity = threading.BoundedSemaphore(capacity)
        self.guard = threading.Lock()
        self.active = set()
        self.children = []
        self.blocked_ready = set()

    def attempt(self, uid: int, mode: str, deadline: float = 0.3) -> str:
        """Return a synthetic outcome, retaining a marker for every started attempt."""
        if mode not in {"ok", "late", "native-block", "crash", "malformed"}:
            raise ValueError("unknown synthetic worker mode")
        if uid < 1:
            raise ValueError("synthetic non-root UID required")
        with self.guard:
            if uid in self.active or not self.capacity.acquire(blocking=False):
                return "busy"
            self.active.add(uid)
        child = None
        try:
            # A deliberately minimal marker, not the M3 throttle record format.
            # Exclusive creation and both fsyncs precede any backend invocation.
            marker = self.state / f"{uid}.reserved"
            with marker.open("xb") as output:
                output.write(b"synthetic-reservation\n")
                output.flush()
                os.fsync(output.fileno())
            directory = os.open(self.state, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
            started = time.monotonic()
            child = subprocess.Popen(
                [sys.executable, str(Path(__file__).resolve()), "--worker", mode],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                stdin=subprocess.DEVNULL,
                start_new_session=True,
            )
            self.children.append(child)
            remaining = max(0.0, deadline - (time.monotonic() - started))
            try:
                output, _ = child.communicate(timeout=remaining)
            except subprocess.TimeoutExpired as expired:
                if expired.output == b"READY\n":
                    self.blocked_ready.add(uid)
                return "unavailable"
            # A response observed after the deadline is never accepted, even if
            # native code finished successfully just as the timeout fired.
            if time.monotonic() - started >= deadline:
                return "unavailable"
            return "success" if child.returncode == 0 and output == b"OK\n" else "unavailable"
        finally:
            if child is not None:
                # Kill the entire disposable process group and reap the leader
                # before allowing another worker to consume this bounded slot.
                # communicate() may already have reaped a completed worker.
                # Never signal its numeric PGID after reaping: it can be reused.
                if child.returncode is None:
                    try:
                        os.killpg(child.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                child.communicate()
            with self.guard:
                self.active.remove(uid)
                self.capacity.release()


def worker(mode: str):
    """Synthetic native workloads; intentionally ignore cooperative cancellation."""
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    libc = ctypes.CDLL(None)
    if mode == "native-block":
        os.write(1, b"READY\n")
        libc.pause()
    elif mode == "late":
        os.write(1, b"READY\n")
        libc.sleep(2)
        os.write(1, b"OK\n")
    elif mode == "ok":
        os.write(1, b"OK\n")
    elif mode == "malformed":
        os.write(1, b"OK\nEXTRA\n")
    elif mode == "crash":
        os._exit(70)
    else:
        os._exit(64)


if __name__ == "__main__":
    if len(sys.argv) != 3 or sys.argv[1] != "--worker":
        raise SystemExit("Run test_supervisor.py; this is a test-only subprocess.")
    worker(sys.argv[2])
