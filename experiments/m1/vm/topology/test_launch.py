"""Pure topology launcher guards/ownership checks; never touches PAM or systemd."""
import importlib.util
from pathlib import Path
from types import SimpleNamespace
import unittest
import tempfile
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location("m1_topology_launch_tests", Path(__file__).with_name("launch.py"))
runner = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runner)


class LauncherTests(unittest.TestCase):
    def test_guard_precedes_any_preparation_or_existing_path_lookup(self):
        with patch.object(runner, "guard", side_effect=RuntimeError("guard refused")), \
             patch.object(runner, "command") as command, patch.object(runner.sessions, "sessions") as sessions:
            with self.assertRaises(RuntimeError):
                runner.prepare()
            command.assert_not_called()
            sessions.assert_not_called()

    def test_cleanup_guard_precedes_control_or_scope_access(self):
        with patch.object(runner, "guard", side_effect=RuntimeError("guard refused")), \
             patch.object(runner, "manifest") as manifest, patch.object(runner, "command") as command:
            with self.assertRaises(RuntimeError):
                runner.finish()
            manifest.assert_not_called()
            command.assert_not_called()

    def test_existing_session_identifier_cannot_be_claimed(self):
        fixture = {"session": "existing", "uid": 1001, "vt": 8, "leader": 1234, "registration_only": True}
        with patch.object(Path, "exists", return_value=True), patch.object(runner, "read_json", return_value=fixture), \
             patch.object(runner.sessions, "properties") as properties:
            with self.assertRaises(RuntimeError):
                runner.new_registration({"baseline_ids": ["existing"], "uid": 1001, "vt": 8})
            properties.assert_not_called()

    def test_wrong_service_or_leader_cannot_be_claimed(self):
        fixture = {"session": "new", "uid": 1001, "vt": 8, "leader": 1234, "registration_only": True}
        props = {"Service": "plasmalogin", "User": "1001", "Leader": "1234", "Seat": "seat0", "VTNr": "8",
                 "Type": "wayland", "Class": "user", "Remote": "no", "Scope": "session-new.scope"}
        with patch.object(Path, "exists", return_value=True), patch.object(runner, "read_json", return_value=fixture), \
             patch.object(runner.sessions, "properties", return_value=props), patch.object(runner, "starttime") as start:
            with self.assertRaises(RuntimeError):
                runner.new_registration({"baseline_ids": [], "uid": 1001, "vt": 8})
            start.assert_not_called()

    def test_private_bus_has_final_manager_denies(self):
        text = Path(__file__).with_name("private-session-bus.conf").read_text()
        self.assertLess(text.index('<allow own="*"/>'), text.index('<deny own="org.freedesktop.systemd1"/>'))
        self.assertLess(text.index('<allow send_destination="*"'), text.index('<deny send_destination="org.freedesktop.systemd1"/>'))
        self.assertNotIn("<include", text)

    def test_finished_native_registration_requires_no_guessed_pid_or_session_lookup(self):
        fixture = {"session": "new", "uid": 1001, "vt": 8, "leader": 1234, "registration_only": True}
        with patch.object(Path, "exists", return_value=True), patch.object(runner, "read_json", return_value=fixture), \
             patch.object(runner.sessions, "sessions", return_value={}), \
             patch.object(runner.sessions, "properties") as properties, patch.object(runner, "starttime") as start:
            result = runner.new_registration({"baseline_ids": ["old"], "uid": 1001, "vt": 8}, allow_finished=True)
            self.assertEqual(result["scope"], "session-new.scope")
            self.assertIsNone(result["leader_starttime"])
            properties.assert_not_called()
            start.assert_not_called()

    def test_migrated_scope_requires_all_three_exact_resource_limits(self):
        valid = "RuntimeMaxUSec=15min\nTasksMax=1024\nMemoryMax=3221225472\nTimeoutStopUSec=45s\n"
        with patch.object(runner, "command", return_value=SimpleNamespace(stdout=valid)):
            self.assertEqual(runner.verify_scope_limits("session-public-fixture.scope"), 45000000)
        for invalid in (valid.replace("1024", "256"), valid.replace("15min", "infinity"),
                        valid.replace("3221225472", "infinity"), valid.replace("45s", "infinity"),
                        valid.replace("45s", "46s"), "RuntimeMaxUSec=15min\n"):
            with self.subTest(properties=invalid), patch.object(runner, "command", return_value=SimpleNamespace(stdout=invalid)):
                with self.assertRaises(RuntimeError):
                    runner.verify_scope_limits("session-public-fixture.scope")

    def test_scope_stop_timeout_requires_a_known_finite_bounded_duration(self):
        self.assertEqual(runner.stop_timeout_usec("45s"), 45000000)
        self.assertEqual(runner.stop_timeout_usec("5s"), 5000000)
        self.assertEqual(runner.stop_timeout_usec("40s 500ms"), 40500000)
        for value in (None, "", "infinity", "0", "0s", "1min", "45s 1ms", "unknown", "45seconds"):
            with self.subTest(value=value), self.assertRaises(RuntimeError):
                runner.stop_timeout_usec(value)

    def test_activation_guard_precedes_control_and_active_session_access(self):
        with patch.object(runner, "guard", side_effect=RuntimeError("guard refused")), \
             patch.object(runner, "manifest") as manifest, patch.object(runner, "command") as command:
            with self.assertRaises(RuntimeError):
                runner.activate()
            manifest.assert_not_called()
            command.assert_not_called()

    def test_activation_refuses_changed_leader_before_switch_or_gate(self):
        pinned = {"session": "new", "scope": "session-new.scope", "uid": 1001, "vt": 8,
                  "leader": 1234, "leader_starttime": 100}
        with patch.object(runner, "read_json", return_value=pinned), \
             patch.object(runner, "new_registration", return_value={**pinned, "leader_starttime": 101}):
            with self.assertRaises(RuntimeError):
                runner.verified_owned({})

    def test_inactive_or_wrong_vt_never_publishes_desktop_gate(self):
        data = {"first_active_session": "old", "first_active_vt": 2}
        owned = {"session": "new", "scope": "session-new.scope", "vt": 8}
        for active, observed in (("no", ("old", 2)), ("yes", ("new", 9))):
            with self.subTest(active=active, session_vt=observed), \
                 patch.object(runner, "guard"), patch.object(runner, "manifest", return_value=data), \
                 patch.object(Path, "exists", return_value=False), \
                 patch.object(runner, "verified_owned", return_value=owned), patch.object(runner, "verify_first_desktop"), \
                 patch.object(runner, "verify_scope_limits"), patch.object(runner, "command") as command, \
                 patch.object(runner.sessions, "active_baseline", side_effect=[("old", 2), observed]), \
                 patch.object(runner.sessions, "properties", return_value={"Active": active}), \
                 patch.object(runner.time, "monotonic", side_effect=[0, 1, 11]), \
                 patch.object(runner.time, "sleep"), patch.object(runner, "publish_activation") as publish:
                with self.assertRaises(RuntimeError):
                    runner.activate()
                command.assert_called_once_with(["loginctl", "activate", "new"])
                publish.assert_not_called()

    def test_activation_approval_is_complete_and_cannot_overwrite(self):
        with tempfile.TemporaryDirectory(prefix="m1-topology-gate-test-") as temporary, \
             patch.object(runner, "CONTROL", Path(temporary)):
            runner.publish_activation("new-session")
            self.assertEqual((Path(temporary) / "activate-approved").read_bytes(), b"new-session\n")
            with self.assertRaises(OSError):
                runner.publish_activation("different-session")
            self.assertEqual((Path(temporary) / "activate-approved").read_bytes(), b"new-session\n")


if __name__ == "__main__":
    unittest.main()
