#!/usr/bin/env python3
"""Regression evidence for a native call that does not respect thread deadlines."""

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

from supervisor import Supervisor


class WorkerIsolationTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="localpin-m1-worker-")
        self.addCleanup(self.directory.cleanup)
        self.state = Path(self.directory.name)
        self.supervisor = Supervisor(self.state)

    def tearDown(self):
        self.assertFalse(self.supervisor.active)
        for child in self.supervisor.children:
            self.assertIsNotNone(child.poll(), "worker must be reaped before slot reuse")

    def test_timely_success(self):
        with patch("supervisor.os.killpg") as kill_group:
            self.assertEqual(self.supervisor.attempt(1001, "ok", deadline=2), "success")
            kill_group.assert_not_called()

    def test_blocked_native_call_is_killed_and_reservation_remains(self):
        started = time.monotonic()
        self.assertEqual(self.supervisor.attempt(1001, "native-block"), "unavailable")
        self.assertLess(time.monotonic() - started, 1.5)
        self.assertIn(1001, self.supervisor.blocked_ready)
        self.assertEqual((self.state / "1001.reserved").read_bytes(), b"synthetic-reservation\n")

    def test_late_success_never_authorizes(self):
        self.assertEqual(self.supervisor.attempt(1001, "late"), "unavailable")
        self.assertIn(1001, self.supervisor.blocked_ready)

    def test_crash_and_malformed_response_remain_unavailable(self):
        for uid, mode in [(1001, "crash"), (1002, "malformed")]:
            with self.subTest(mode=mode):
                self.assertEqual(self.supervisor.attempt(uid, mode, deadline=2), "unavailable")

    def test_failed_reservation_never_starts_worker(self):
        (self.state / "1001.reserved").write_bytes(b"already-reserved")
        with self.assertRaises(FileExistsError):
            self.supervisor.attempt(1001, "ok")
        self.assertEqual(self.supervisor.children, [])

    def test_other_uid_responds_and_same_uid_and_global_capacity_are_bounded(self):
        with ThreadPoolExecutor(max_workers=2) as pool:
            first = pool.submit(self.supervisor.attempt, 1001, "native-block", 1.5)
            until = time.monotonic() + 1
            while not self.supervisor.children and time.monotonic() < until:
                time.sleep(0.005)
            self.assertTrue(self.supervisor.children)
            self.assertEqual(self.supervisor.attempt(1001, "ok"), "busy")
            self.assertEqual(self.supervisor.attempt(1002, "ok", deadline=1), "success")
            second = pool.submit(self.supervisor.attempt, 1003, "native-block", 0.4)
            until = time.monotonic() + 0.3
            while 1003 not in self.supervisor.active and time.monotonic() < until:
                time.sleep(0.005)
            self.assertIn(1003, self.supervisor.active)
            self.assertEqual(self.supervisor.attempt(1004, "ok"), "busy")
            self.assertEqual(second.result(), "unavailable")
            self.assertEqual(first.result(), "unavailable")
        self.assertEqual(len(self.supervisor.children), 3)


if __name__ == "__main__":
    unittest.main(verbosity=2)
