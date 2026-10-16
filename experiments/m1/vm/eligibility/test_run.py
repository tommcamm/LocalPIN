"""Pure denial/bounded-I/O checks; no real account, PAM, or VM operation."""
import importlib.util
from pathlib import Path
from types import SimpleNamespace
import os
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location("m1_eligibility_runner", Path(__file__).with_name("run.py"))
runner = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runner)


class EligibilityGuardTests(unittest.TestCase):
    def test_vm_guard_precedes_policy_or_account_operations(self):
        with patch.object(runner.pam, "guard", side_effect=RuntimeError("guard refusal")), \
             patch.object(runner, "policy") as policy, patch.object(runner.pam, "shadow_record") as shadow:
            with self.assertRaises(RuntimeError):
                runner.execute(SimpleNamespace(check_env=True))
            policy.assert_not_called()
            shadow.assert_not_called()

    def test_unknown_auth_or_external_config_refused(self):
        for name in ("password-auth", "faillock.conf", "kde", "postlogin"):
            with self.subTest(name=name), self.assertRaises(RuntimeError):
                runner.reviewed_content(name, b"auth sufficient pam_permit.so\n")

    def test_regular_counter_digest_is_bounded(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "counter"
            path.write_bytes(b"synthetic counter bytes")
            self.assertEqual(len(runner.counter_digest(path)), 64)

    def test_symlink_fifo_and_oversized_file_never_read(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            regular = base / "counter"
            regular.write_bytes(b"synthetic")
            link = base / "link"
            link.symlink_to(regular)
            fifo = base / "fifo"
            os.mkfifo(fifo)
            oversized = base / "oversized"
            with oversized.open("wb") as output:
                output.truncate(65537)
            for path in (link, fifo, oversized):
                with self.subTest(path=path.name), patch.object(runner.os, "read") as read:
                    with self.assertRaises((OSError, RuntimeError)):
                        runner.counter_digest(path)
                    read.assert_not_called()


if __name__ == "__main__":
    unittest.main()
