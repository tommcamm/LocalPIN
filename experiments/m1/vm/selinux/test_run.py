"""Synthetic guard/policy/unit checks. Never loads policy or contacts systemd."""
from pathlib import Path
from types import SimpleNamespace
import importlib.util
import stat
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location("m1_selinux_run", Path(__file__).with_name("run.py"))
runner = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runner)
UUID = "00000000-0000-0000-0000-000000000001"


class Marker:
    def __init__(self):
        self.info = SimpleNamespace(st_mode=stat.S_IFREG | 0o600, st_nlink=1, st_uid=0, st_gid=0)
        self.text = f"LOCALPIN-M1-DISPOSABLE-VM\ntarget=localpintest\nuuid={UUID}\n"
        self.symlink = False

    def lstat(self):
        return self.info

    def is_symlink(self):
        return self.symlink

    def read_text(self):
        return self.text


class GuardAndPolicyTests(unittest.TestCase):
    def test_exact_marker_passes(self):
        runner.validate_marker(Marker(), UUID)

    def test_unsafe_owner_mode_links_and_symlink_refuse(self):
        for field, value in [("st_uid", 1000), ("st_gid", 1000), ("st_nlink", 2),
                             ("st_mode", stat.S_IFREG | 0o644)]:
            marker = Marker()
            setattr(marker.info, field, value)
            with self.subTest(field=field), self.assertRaises(runner.ExperimentError):
                runner.validate_marker(marker, UUID)
        marker = Marker()
        marker.symlink = True
        with self.assertRaises(runner.ExperimentError):
            runner.validate_marker(marker, UUID)

    def test_wrong_target_uuid_or_extra_data_refuses(self):
        for text in ["", Marker().text + "extra\n", Marker().text.replace("localpintest", "another")]:
            marker = Marker()
            marker.text = text
            with self.subTest(text=text), self.assertRaises(runner.ExperimentError):
                runner.validate_marker(marker, UUID)
        with self.assertRaises(runner.ExperimentError):
            runner.validate_marker(Marker(), UUID[:-1] + "2")

    def test_nonroot_refuses_before_any_command(self):
        with patch.object(runner.os, "getuid", return_value=1000), \
             patch.object(runner.os, "geteuid", return_value=0), \
             patch.object(runner, "command") as command:
            with self.assertRaises(runner.ExperimentError):
                runner.preflight()
            command.assert_not_called()

    def test_locker_type_cannot_inject_policy(self):
        for value in ["unconfined_t; allow domain domain:file *;", "domain", "localpin_m1_client_t"]:
            with self.subTest(value=value), self.assertRaises(runner.ExperimentError):
                runner.policy(value)
        text = runner.policy("unconfined_t")
        self.assertIn("allow unconfined_t localpin_m1_broker_t:unix_stream_socket connectto;", text)
        self.assertNotIn("@LOCKER_RULE@", text)

    def test_worker_and_broker_have_distinct_reviewed_sandboxes(self):
        account = SimpleNamespace(pw_uid=1001, pw_gid=1001)
        worker = runner.unit("worker", account)
        broker = runner.unit("broker", account)
        self.assertIn("NoNewPrivileges=no\n", worker)
        self.assertIn("NoNewPrivileges=yes\n", broker)
        self.assertIn("ReadWritePaths=/run/localpin-m1\n", broker)
        self.assertNotIn("ReadWritePaths=", worker)
        self.assertIn("CapabilityBoundingSet=\n", worker)
        self.assertIn("StandardError=journal\n", worker)
        self.assertNotIn("SELinuxContext=-", worker)
        for mode in runner.MODES:
            self.assertIn(f"SELinuxContext=system_u:system_r:localpin_m1_{mode}_t:s0\n",
                          runner.unit(mode, account))

    def test_direct_systemd_transition_uses_only_maintained_scoped_interface(self):
        text = runner.policy(None)
        for mode in runner.MODES:
            self.assertIn(f"init_domain(localpin_m1_{mode}_t, localpin_m1_{mode}_exec_t)", text)
        self.assertEqual(text.count("init_domain("), 4)
        self.assertNotIn("allow init_t domain:", text)

    def test_cleanup_stops_then_unlinks_and_reloads_without_resetting_unloaded_units(self):
        events = []
        unit = SimpleNamespace(name="localpin-m1-broker.service",
                               unlink=lambda **kwargs: events.append("unlink"))

        def command(args, **kwargs):
            del kwargs
            events.append(args[1])
            return SimpleNamespace(returncode=0, stdout="")

        with patch.object(runner, "command", side_effect=command):
            self.assertEqual(runner.cleanup([unit], [], False), [])
        self.assertEqual(events, ["stop", "unlink", "daemon-reload"])

    def test_failed_stop_retains_paths_policy_and_reports_exact_stage(self):
        unit = SimpleNamespace(name="localpin-m1-worker.service", unlink=lambda **kwargs: self.fail("must retain unit"))
        with patch.object(runner, "command", return_value=SimpleNamespace(returncode=1)), \
             patch.object(runner.shutil, "rmtree") as remove:
            self.assertEqual(runner.cleanup([unit], [Path("/synthetic/owned")], True),
                             ["stop localpin-m1-worker.service"])
            remove.assert_not_called()

    def test_cleanup_failure_does_not_mask_primary_operation_or_export_native_text(self):
        primary = runner.ExperimentError("broker socket not ready")
        message = runner.failure_message("broker readiness", primary, ["unit reload"])
        self.assertIn("broker readiness: broker socket not ready", message)
        self.assertIn("cleanup incomplete (unit reload)", message)
        self.assertNotIn("PRIVATE_NATIVE_TEXT", runner.failure_message("worker start", OSError("PRIVATE_NATIVE_TEXT"), []))

    def test_context_metadata_exports_only_bounded_type(self):
        self.assertEqual(runner.context_type("synthetic_u:synthetic_r:synthetic_exec_t:s0:c0.c1023\0"),
                         "synthetic_exec_t")
        for value in ["missing-fields", "u:r:bad type:s0", "u:r:" + "x" * 129 + ":s0"]:
            with self.subTest(value=value), self.assertRaises(runner.ExperimentError):
                runner.context_type(value)

    def test_executable_label_mismatch_refuses_before_service_start(self):
        with patch.object(runner.os, "getxattr", return_value=b"u:r:wrong_exec_t:s0"), \
             patch.object(runner, "command", return_value=SimpleNamespace(stdout="u:r:localpin_m1_broker_exec_t:s0\n")), \
             patch.object(runner.sys, "stderr"):
            with self.assertRaisesRegex(runner.ExperimentError, "broker executable label mismatch"):
                runner.executable_labels()

    def test_empty_or_incomplete_service_result_cannot_pass(self):
        for value in ["", "Result=success\n", "ExecMainStatus=0\n"]:
            with self.subTest(value=value), self.assertRaisesRegex(runner.ExperimentError, "properties missing"):
                runner.check_service_result(value, "synthetic")
        runner.check_service_result("Result=success\nExecMainStatus=0\n", "synthetic")


if __name__ == "__main__":
    unittest.main()
