"""Synthetic broker-hold control-plane tests, without VM or socket creation."""
import importlib.util
from pathlib import Path
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location("m1_contact_hold_tests", Path(__file__).with_name("run.py"))
runner = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runner)


class ContactHoldTests(unittest.TestCase):
    def test_reviewed_source_changes_only_two_lifetime_literals(self):
        source = "prefix alarm(35); middle poll(&ready, 1, 30000) suffix"
        self.assertEqual(runner.extended_source(source),
                         "prefix alarm(600); middle poll(&ready, 1, 600000) suffix")
        with self.assertRaises(runner.boundary.ExperimentError):
            runner.extended_source(source + " alarm(35);")

    def test_commands_require_guard_before_state_or_request_access(self):
        with patch.object(runner, "control_guard", side_effect=runner.boundary.ExperimentError("guard refused")), \
             patch.object(runner, "read_owned") as read, patch.object(runner, "write_new") as write:
            with self.assertRaises(runner.boundary.ExperimentError):
                runner.request("deny")
            read.assert_not_called()
            write.assert_not_called()

    def test_control_reader_rejects_symlink(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary)
            (path / "target").write_text("synthetic")
            (path / "link").symlink_to(path / "target")
            with self.assertRaises(OSError):
                runner.read_owned(path / "link")

    def test_foreign_owned_control_file_is_rejected(self):
        info = SimpleNamespace(st_mode=stat.S_IFREG | 0o600, st_uid=1000, st_gid=0, st_nlink=1)
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "synthetic"
            path.write_text("synthetic")
            with patch.object(runner.os, "fstat", return_value=info):
                with self.assertRaises(runner.boundary.ExperimentError):
                    runner.read_owned(path)

    def test_denial_can_only_change_owned_socket(self):
        info = SimpleNamespace(st_mode=stat.S_IFSOCK | 0o666, st_uid=1001, st_gid=0)
        with patch.object(Path, "lstat", return_value=info), patch.object(runner.os, "chmod") as chmod:
            with self.assertRaises(runner.boundary.ExperimentError):
                runner.deny_new_connections()
            chmod.assert_not_called()


if __name__ == "__main__":
    unittest.main()
