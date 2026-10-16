"""Pure session-fixture selection/cleanup tests; no logind/VT/PAM calls."""
import importlib.util
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location("m1_sessions_run", Path(__file__).with_name("run.py"))
runner = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runner)


class SessionFixtureTests(unittest.TestCase):
    def test_spare_excludes_active_registered_and_kernel_open_vts(self):
        snapshot = {"existing": {"VTNr": "8"}}
        self.assertEqual(runner.select_spare(snapshot, 7, 1 << 9), 10)

    def test_no_spare_refuses(self):
        with self.assertRaises(RuntimeError):
            runner.select_spare({}, 1, 0xFFFF)

    def test_candidate_exclusions_use_real_property_fields_not_active(self):
        properties = {"User": "1001", "Type": "wayland", "Class": "user", "Remote": "no",
                      "State": "online", "Seat": "seat0", "Desktop": "KDE", "Active": "no"}
        self.assertTrue(runner.inventory.session_candidate(properties, 1001))
        for key, value in [("Remote", "yes"), ("Class", "greeter"), ("User", "0"), ("Type", "tty")]:
            with self.subTest(key=key):
                self.assertFalse(runner.inventory.session_candidate({**properties, key: value}, 1001))
        self.assertFalse(runner.inventory.session_candidate({**properties, "User": "0"}, 0))

    def test_cleanup_only_stops_exact_owned_unit_and_never_user_or_seat(self):
        calls = []
        def command(args, **kwargs):
            calls.append(args)
            return SimpleNamespace(returncode=0, stdout="")
        directory = SimpleNamespace(exists=lambda: False)
        with patch.object(runner, "command", side_effect=command), patch.object(runner, "sessions", return_value={}):
            runner.finish("localpin-m1-session-public-test.service", directory, "new", {"old"})
        self.assertEqual(calls, [["systemctl", "stop", "localpin-m1-session-public-test.service"]])

    def test_cleanup_refuses_baseline_session(self):
        directory = SimpleNamespace(exists=lambda: False)
        with patch.object(runner, "command", return_value=SimpleNamespace(returncode=0)):
            with self.assertRaises(RuntimeError):
                runner.finish("localpin-m1-session-public-test.service", directory, "old", {"old"})

    def test_invalid_session_identifier_never_invokes_command(self):
        with patch.object(runner, "command") as command:
            with self.assertRaises(RuntimeError):
                runner.properties("../not-a-session")
            command.assert_not_called()


if __name__ == "__main__":
    unittest.main()
