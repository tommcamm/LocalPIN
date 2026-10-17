#!/usr/bin/python3
"""Exercise release signing failure ordering with synthetic keys and packages."""
import importlib.util
import json
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location("sign_release", Path(__file__).with_name("sign-release.py"))
signing = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(signing)
FINGERPRINT = "A" * 40
SUBKEY = "B" * 40
KEY = "synthetic-secret-key"
PASSPHRASE = "synthetic-passphrase"


class SigningTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="localpin-sign-test-")
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        (self.directory / "localpin.rpm").write_bytes(b"synthetic-rpm")
        (self.directory / "RELEASE.json").write_text(json.dumps({"signing": {"signed": False, "fingerprint": None}}))
        (self.directory / "RELEASE-NOTES.md").write_text("Experimental release.\n")
        (self.directory / "SHA256SUMS").write_text("synthetic-checksum\n")
        self.calls = []
        self.homes = set()
        self.failure = None
        self.listed = FINGERPRINT
        self.environment = patch.dict(signing.os.environ, {
            "LOCALPIN_SIGNING_KEY": KEY,
            "LOCALPIN_SIGNING_FINGERPRINT": FINGERPRINT.lower(),
            "LOCALPIN_SIGNING_PASSPHRASE": PASSPHRASE,
            "GNUPGHOME": "/unrelated/keyring-must-not-be-used",
        })
        self.environment.start()
        self.addCleanup(self.environment.stop)
        self.processes = patch.object(signing.subprocess, "run", side_effect=self.fake_run)
        self.processes.start()
        self.addCleanup(self.processes.stop)

    def manifest(self):
        return json.loads((self.directory / "RELEASE.json").read_text())

    def fake_run(self, argv, **kwargs):
        self.calls.append(argv)
        env = kwargs["env"]
        self.assertFalse(any(name.startswith("LOCALPIN_SIGNING_") for name in env))
        self.assertEqual(env["LC_ALL"], "C")
        self.assertNotIn(KEY, " ".join(argv))
        self.assertNotIn(PASSPHRASE, " ".join(argv))
        home = Path(env["GNUPGHOME"])
        self.assertNotEqual(str(home), "/unrelated/keyring-must-not-be-used")
        self.assertTrue(home.is_dir())
        self.homes.add(home)
        if argv[0] == "gpg" and "--import" in argv:
            self.assertEqual(kwargs["input"], KEY.encode())
        if argv[0] == "gpg" and "--list-secret-keys" in argv:
            listing = f"sec:::::::::\nfpr:::::::::{self.listed}:\nssb:::::::::\nfpr:::::::::{SUBKEY}:\n"
            return subprocess.CompletedProcess(argv, 0, stdout=listing)
        if argv[0] == "rpmsign":
            passfile = home / "passphrase"
            self.assertEqual(passfile.read_text(), PASSPHRASE + "\n")
            self.assertEqual(stat.S_IMODE(passfile.stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(home.stat().st_mode), 0o700)
            self.assertIn(f"_openpgp_sign_id {FINGERPRINT}", argv)
            self.assertFalse(self.manifest()["signing"]["signed"])
            if self.failure == "rpmsign":
                raise subprocess.CalledProcessError(1, argv)
        if argv[0] == "gpg" and "--export" in argv:
            return subprocess.CompletedProcess(argv, 0, stdout=b"synthetic-public-key")
        if argv[0] == "rpmkeys":
            self.assertIn("--dbpath", argv)
            self.assertEqual(Path(argv[argv.index("--dbpath") + 1]), home / "rpmdb")
            if "--checksig" in argv:
                self.assertIn("_pkgverify_level signature", argv)
                self.assertFalse(self.manifest()["signing"]["signed"])
                if self.failure == "rpmkeys":
                    raise subprocess.CalledProcessError(1, argv)
        if argv[0] == "python3":
            self.assertEqual(argv[-2:], ["--finalize", str(self.directory)])
            self.assertEqual(self.manifest()["signing"], {"signed": True, "fingerprint": FINGERPRINT})
        if argv[0] == "gpgconf":
            self.assertEqual(argv, ["gpgconf", "--kill", "gpg-agent"])
            self.assertFalse(kwargs["check"])
        return subprocess.CompletedProcess(argv, 0, stdout=b"")

    def assert_cleanup(self):
        self.assertTrue(self.homes)
        self.assertTrue(all(not home.exists() for home in self.homes))
        self.assertEqual(self.calls[-1], ["gpgconf", "--kill", "gpg-agent"])

    def test_sign_verify_finalize_and_detach_sign_in_order(self):
        signing.sign(self.directory)
        names = [args[0] for args in self.calls]
        self.assertEqual(names, ["gpg", "gpg", "rpmsign", "gpg", "rpm", "rpmkeys", "rpmkeys", "python3", "gpg", "gpgconf"])
        self.assertIn("--detach-sign", self.calls[-2])
        self.assertEqual(self.calls[-2][-1], str(self.directory / "SHA256SUMS"))
        self.assertEqual((self.directory / "RPM-GPG-KEY-LocalPIN").read_bytes(), b"synthetic-public-key")
        self.assertIn(FINGERPRINT, (self.directory / "RELEASE-NOTES.md").read_text())
        self.assertEqual(self.manifest()["signing"], {"signed": True, "fingerprint": FINGERPRINT})
        self.assert_cleanup()

    def test_mismatched_primary_key_never_signs_or_marks_manifest(self):
        self.listed = "C" * 40
        with self.assertRaisesRegex(ValueError, "fingerprint"):
            signing.sign(self.directory)
        self.assertFalse(any(args[0] == "rpmsign" for args in self.calls))
        self.assertEqual(self.manifest()["signing"], {"signed": False, "fingerprint": None})
        self.assertEqual((self.directory / "RELEASE-NOTES.md").read_text(), "Experimental release.\n")
        self.assert_cleanup()

    def test_failed_rpm_signing_does_not_verify_or_mark_manifest(self):
        self.failure = "rpmsign"
        with self.assertRaises(subprocess.CalledProcessError):
            signing.sign(self.directory)
        self.assertFalse(any(args[0] == "rpmkeys" for args in self.calls))
        self.assertEqual(self.manifest()["signing"], {"signed": False, "fingerprint": None})
        self.assertFalse((self.directory / "RPM-GPG-KEY-LocalPIN").exists())
        self.assert_cleanup()

    def test_failed_signature_verification_does_not_mark_or_finalize(self):
        self.failure = "rpmkeys"
        with self.assertRaises(subprocess.CalledProcessError):
            signing.sign(self.directory)
        self.assertFalse(any(args[0] == "python3" for args in self.calls))
        self.assertFalse(any("--detach-sign" in args for args in self.calls))
        self.assertEqual(self.manifest()["signing"], {"signed": False, "fingerprint": None})
        self.assertEqual((self.directory / "RELEASE-NOTES.md").read_text(), "Experimental release.\n")
        self.assert_cleanup()

    def test_missing_secret_refuses_unsigned_fallback(self):
        with patch.dict(signing.os.environ, {"LOCALPIN_SIGNING_KEY": ""}):
            with self.assertRaisesRegex(ValueError, "refusing unsigned fallback"):
                signing.sign(self.directory)
        self.assertEqual(self.calls, [])
        self.assertFalse(self.manifest()["signing"]["signed"])

    def test_extra_or_symlinked_rpm_is_refused(self):
        extra = self.directory / "second.rpm"
        extra.write_bytes(b"second")
        with self.assertRaisesRegex(ValueError, "one regular"):
            signing.sign(self.directory)
        extra.unlink()
        candidate = self.directory / "localpin.rpm"
        candidate.unlink()
        candidate.symlink_to(self.directory / "RELEASE.json")
        with self.assertRaisesRegex(ValueError, "one regular"):
            signing.sign(self.directory)
        self.assertEqual(self.calls, [])


if __name__ == "__main__":
    unittest.main()
