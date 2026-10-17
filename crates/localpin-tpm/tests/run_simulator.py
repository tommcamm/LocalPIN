#!/usr/bin/env python3
"""Bounded opt-in test runner. Starts only a dedicated disposable process group."""
import os
from pathlib import Path
import signal
import subprocess
import tempfile


def main():
    repository = Path(__file__).resolve().parents[3]
    with tempfile.TemporaryDirectory(prefix="localpin-m4-native-tests-") as temporary:
        environment = os.environ.copy()
        environment["TMPDIR"] = temporary
        command = ["cargo", "test", "--locked", "-p", "localpin-tpm", "--features", "simulator", "--", "--ignored"]
        process = subprocess.Popen(command, cwd=repository, env=environment, start_new_session=True)
        try:
            return process.wait(timeout=120)
        except subprocess.TimeoutExpired:
            print("M4 native simulator test deadline expired", flush=True)
            return 1
        finally:
            # The process group contains only this runner's cargo/test/swtpm
            # descendants. Terminate them and bound waiting for the direct child.
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                try:
                    process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    # Kernel I/O can delay death even after SIGKILL. The fixture
                    # must fail without replacing its watchdog with an infinite
                    # wait; M5 owns production reaping and occupied-slot policy.
                    print("M4 test child did not reap after SIGKILL", flush=True)
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass


if __name__ == "__main__":
    raise SystemExit(main())
