"""Pure safety-contract checks; no account, PAM, systemd or policy operations."""
import importlib.util
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location("m1_positive_tests", Path(__file__).with_name("run.py"))
runner = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runner)


class PositiveWorkerContractTests(unittest.TestCase):
    def test_unknown_or_modified_policy_is_refused(self):
        for value in [b"", b"auth sufficient pam_permit.so\n", b"x" * 65537]:
            with self.subTest(size=len(value)), self.assertRaises(runner.boundary.ExperimentError):
                runner.reviewed_policy(value)

    def test_unit_keeps_audit_separate_from_ip_and_worker_unprivileged(self):
        text = runner.unit_text()
        for value in ["User=localpintest\n", "AmbientCapabilities=\n", "NoNewPrivileges=no\n",
                      "CapabilityBoundingSet=CAP_DAC_READ_SEARCH CAP_AUDIT_WRITE\n",
                      "RestrictAddressFamilies=AF_UNIX AF_NETLINK\n", "PrivateNetwork=no\n",
                      "IPAddressDeny=any\n", "SELinuxContext=system_u:system_r:localpin_m1_positive_t:s0\n"]:
            self.assertIn(value, text)
        self.assertNotIn("AF_INET", text)
        self.assertNotIn(runner.PUBLIC_PASSWORD.decode(), text)

    def test_compiled_shadow_or_password_update_allow_refuses(self):
        with patch.object(runner, "command", return_value=SimpleNamespace(stdout="allow x shadow_t:file read;\n")):
            with self.assertRaises(runner.boundary.ExperimentError):
                runner.no_forbidden_grants()
        with patch.object(runner, "command", side_effect=[SimpleNamespace(stdout=""),
                                                          SimpleNamespace(stdout="allow x updpwd_t:process transition;\n")]):
            with self.assertRaises(runner.boundary.ExperimentError):
                runner.no_forbidden_grants()

    def test_empty_compiled_forbidden_grants_check_passes(self):
        with patch.object(runner, "command", return_value=SimpleNamespace(stdout="")) as command:
            runner.no_forbidden_grants()
            self.assertEqual(command.call_count, 2)

    def test_unconfirmed_stop_retains_policy_and_paths(self):
        with patch.object(runner, "command", return_value=SimpleNamespace(returncode=1)), \
             patch.object(runner.shutil, "rmtree") as remove:
            self.assertEqual(runner.cleanup(["fixed.service"], [Path("/synthetic")], True, True), ["worker stop"])
            remove.assert_not_called()


if __name__ == "__main__":
    unittest.main()
