"""Synthetic fixed-path activation/fault tests; never run host administration."""

import contextlib
import copy
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import types
import unittest
from unittest import mock


SPEC = importlib.util.spec_from_file_location(
    "localpin_integration_tested", Path(__file__).resolve().parents[1] / "localpin-integration.py"
)
integration = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(integration)

BOOT = "01234567-89ab-cdef-0123-456789abcdef"
ORIGINAL = b"# Fedora KDE fixture\nauth substack password-auth\naccount required pam_unix.so\n"
FINGERPRINT_ORIGINAL = b"# Fedora KDE fingerprint fixture\nauth substack fingerprint-auth\naccount required pam_unix.so\n"
BINDING = {"1000": "a" * 64}


def metadata(info, *, mode=None):
    """Represent our temporary fixture as a private root-owned test filesystem."""
    fields = {name: getattr(info, name) for name in (
        "st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_nlink",
        "st_size", "st_mtime_ns", "st_ctime_ns",
    )}
    fields.update(st_uid=0, st_gid=0)
    if mode is not None:
        fields["st_mode"] = mode
    return types.SimpleNamespace(**fields)


def prepared():
    return {"schema": 2, "phase": "prepared", "uids": [1000],
            "protected": {"policy": "unchanged"}, "binaries": {"binary": "old"},
            "tests": None, "trial": {"boot": BOOT, "start": 1000, "end": 601000,
                                      "enrollment": copy.deepcopy(BINDING)}}


class FilesystemFixture(unittest.TestCase):
    def setUp(self):
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        temporary = self.stack.enter_context(tempfile.TemporaryDirectory(prefix="localpin-integration-unit-"))
        self.root = Path(temporary)
        self.state = self.root / "state"
        self.control = self.state / "control"
        self.kde = self.root / "etc" / "pam.d" / "kde"
        self.fingerprint = self.kde.with_name("kde-fingerprint")
        self.policy = self.root / "policy"
        self.control.mkdir(parents=True, mode=0o700)
        self.kde.parent.mkdir(parents=True)
        self.policy.mkdir()
        self.kde.write_bytes(ORIGINAL)
        self.kde.chmod(0o644)
        self.fingerprint.write_bytes(FINGERPRINT_ORIGINAL)
        self.fingerprint.chmod(0o644)
        self.manifest = self.control / "manifest.json"
        self.gate = self.state / "gate"
        self.backup = self.control / "backup-test"
        self.backup.mkdir(mode=0o700)
        (self.backup / "kde").write_bytes(ORIGINAL)
        (self.backup / "kde").chmod(0o600)
        (self.backup / "kde-fingerprint").write_bytes(FINGERPRINT_ORIGINAL)
        (self.backup / "kde-fingerprint").chmod(0o600)
        (self.policy / "kde-localpin.review-required").write_bytes(
            integration.PREFIX + ORIGINAL.replace(b"password-auth", b"localpin-kde-password"))
        (self.policy / "kde-fingerprint-localpin.review-required").write_bytes(
            FINGERPRINT_ORIGINAL.replace(b"fingerprint-auth", b"localpin-kde-fingerprint"))
        self.original_private = {}
        for index, name in enumerate(integration.PRIVATE):
            data = ("# original private policy " + str(index) + "\n").encode()
            self.original_private[name] = data
            for path, mode in ((self.backup / name, 0o600), (self.kde.parent / name, 0o644)):
                path.write_bytes(data)
                path.chmod(mode)
            (self.policy / (name + ".review-required")).write_bytes(b"# packaged private policy\n")
        self.stack.enter_context(mock.patch.multiple(
            integration, STATE=self.state, CONTROL=self.control, MANIFEST=self.manifest,
            KDE=self.kde, FINGERPRINT=self.fingerprint, GATE=self.gate, POLICY=self.policy,
            STOCK=integration.digest(ORIGINAL),
        ))
        real_lstat = Path.lstat
        real_fstat = os.fstat

        def fixture_lstat(path):
            path = Path(path)
            if path.parent == Path("/etc/pam.d") and path.name in integration.PRIVATE:
                # prepare's two fixed private-policy inputs are synthetic too.
                return metadata(real_lstat(self.kde))
            if path == self.root or self.root in path.parents:
                return metadata(real_lstat(path))
            if path in self.root.parents:
                return metadata(real_lstat(path), mode=stat.S_IFDIR | 0o755)
            raise AssertionError("unexpected metadata access outside synthetic fixture")

        self.stack.enter_context(mock.patch.object(Path, "lstat", fixture_lstat))
        self.stack.enter_context(mock.patch.object(integration.os, "fstat", lambda fd: metadata(real_fstat(fd))))
        actual_read = integration.read

        def fixture_read(path, *args, **kwargs):
            path = Path(path)
            if path.parent == Path("/etc/pam.d") and path.name in integration.PRIVATE:
                path = self.kde.parent / path.name
            return actual_read(path, *args, **kwargs)

        self.stack.enter_context(mock.patch.object(integration, "read", side_effect=fixture_read))
        # Any accidental administrative call fails the test before execution.
        self.run = self.stack.enter_context(mock.patch.object(
            integration, "run", side_effect=AssertionError("host administrative command forbidden")
        ))

    def manifest_state(self):
        originals = {"kde": {"sha256": integration.digest(ORIGINAL), "mode": 0o644}}
        originals["kde-fingerprint"] = {"sha256": integration.digest(FINGERPRINT_ORIGINAL), "mode": 0o644}
        originals.update({name: {"sha256": integration.digest(data), "mode": 0o644}
                          for name, data in self.original_private.items()})
        return {"schema": 2, "phase": "prepared", "backup": "backup-test", "originals": originals}

    def write_manifest(self, data=None):
        self.manifest.write_bytes(json.dumps(self.manifest_state()).encode() if data is None else data)
        self.manifest.chmod(0o600)


class ManifestAndBackupTests(FilesystemFixture):
    def test_missing_manifest_is_unprepared_and_valid_manifest_is_read_only(self):
        self.assertIsNone(integration.load())
        self.write_manifest()
        before = self.manifest.read_bytes()
        self.assertEqual(integration.load(), self.manifest_state())
        self.assertEqual(self.manifest.read_bytes(), before)
        self.run.assert_not_called()

    def test_corrupt_and_unknown_manifest_schema_or_phase_refuse(self):
        for data in [b"{", b"null", b"[]", b'{"schema":3,"phase":"prepared"}',
                     b'{"schema":1,"phase":"unknown"}']:
            with self.subTest(data=data):
                self.write_manifest(data)
                with self.assertRaises(integration.Refusal):
                    integration.load()

    def test_manifest_symlink_hardlink_and_unsafe_mode_refuse(self):
        self.write_manifest()
        alternate = self.control / "alternate"
        self.manifest.rename(alternate)
        self.manifest.symlink_to(alternate)
        with self.assertRaises((OSError, integration.Refusal)):
            integration.load()
        self.manifest.unlink()
        os.link(alternate, self.manifest)
        with self.assertRaises(integration.Refusal):
            integration.load()
        self.manifest.unlink()
        alternate.rename(self.manifest)
        self.manifest.chmod(0o666)
        with self.assertRaises(integration.Refusal):
            integration.load()

    def test_manifest_wrong_owner_or_group_refuses(self):
        self.write_manifest()
        current_fstat = integration.os.fstat
        for owner, group in ((1000, 0), (0, 1000)):
            def untrusted_metadata(fd):
                info = current_fstat(fd)
                return types.SimpleNamespace(**{**vars(info), "st_uid": owner, "st_gid": group})

            with self.subTest(owner=owner, group=group), \
                    mock.patch.object(integration.os, "fstat", side_effect=untrusted_metadata), \
                    self.assertRaises(integration.Refusal):
                integration.load()

    def test_backup_references_cannot_escape_control_directory(self):
        for value in ["../backup-other", "backup-../other", "/backup-root", "other", 7, None]:
            state = self.manifest_state()
            state["backup"] = value
            with self.subTest(value=value), self.assertRaises(integration.Refusal):
                integration.disable(state, dry_run=True)

    def test_missing_changed_and_unsafe_backup_refuse_before_any_write(self):
        path = self.backup / "kde"
        state = self.manifest_state()
        path.unlink()
        with self.assertRaises(FileNotFoundError):
            integration.disable(state, dry_run=True)
        path.write_bytes(b"changed backup")
        path.chmod(0o600)
        with self.assertRaises(integration.Refusal):
            integration.disable(state, dry_run=True)
        path.write_bytes(ORIGINAL)
        alternate = self.backup / "alternate"
        path.rename(alternate)
        path.symlink_to(alternate)
        with self.assertRaises((OSError, integration.Refusal)):
            integration.disable(state, dry_run=True)
        path.unlink()
        os.link(alternate, path)
        with self.assertRaises(integration.Refusal):
            integration.disable(state, dry_run=True)
        path.unlink()
        alternate.rename(path)
        path.chmod(0o644)
        with self.assertRaises(integration.Refusal):
            integration.disable(state, dry_run=True)
        self.run.assert_not_called()

    def test_symlink_or_writable_backup_directory_refuses(self):
        other = self.control / "saved-originals"
        self.backup.rename(other)
        self.backup.symlink_to(other, target_is_directory=True)
        with self.assertRaises(integration.Refusal):
            integration.disable(self.manifest_state(), dry_run=True)
        self.backup.unlink()
        other.rename(self.backup)
        self.backup.chmod(0o777)
        with self.assertRaises(integration.Refusal):
            integration.disable(self.manifest_state(), dry_run=True)

    def test_disable_dry_run_preserves_edited_suffix_and_has_no_mutation(self):
        suffix = ORIGINAL + b"# administrator addition\nauth optional pam_env.so\n"
        self.kde.write_bytes(integration.PREFIX + suffix)
        with mock.patch.object(integration, "atomic_write") as write, \
                mock.patch.object(integration, "close_gate") as close, \
                mock.patch.object(integration, "stop") as stop, \
                mock.patch.object(integration, "save") as save:
            before = self.kde.read_bytes()
            result = integration.disable(self.manifest_state(), dry_run=True)
            self.assertTrue(result["preserves_admin_edits"])
            self.assertNotIn("-# administrator addition", result["diff"])
            self.assertEqual(self.kde.read_bytes(), before)
            for operation in (write, close, stop, save, self.run):
                operation.assert_not_called()

    def test_missing_private_backup_prevents_revoke_or_policy_write(self):
        (self.backup / integration.PRIVATE[-1]).unlink()
        with mock.patch.object(integration, "atomic_write") as write, \
                mock.patch.object(integration, "close_gate") as close, \
                mock.patch.object(integration, "stop") as stop, \
                mock.patch.object(integration, "save") as save, \
                self.assertRaises(FileNotFoundError):
            integration.disable(self.manifest_state())
        for operation in (write, close, stop, save, self.run):
            operation.assert_not_called()

    def test_owned_recovery_disables_boot_before_revocation_and_restoration(self):
        self.kde.write_bytes(integration.PREFIX + ORIGINAL)
        self.run.side_effect = None
        with mock.patch.object(integration, "atomic_write"), \
                mock.patch.object(integration, "close_gate"), \
                mock.patch.object(integration, "stop"), \
                mock.patch.object(integration, "save"):
            integration.disable(self.manifest_state())
        calls = self.run.call_args_list
        self.assertLess(calls.index(mock.call(["/usr/bin/systemctl", "disable", "localpin.socket"])),
                        calls.index(mock.call([integration.ACCOUNT, "begin-mutation"])))

    def test_recovery_restores_both_auth_substacks_and_preserves_each_administrator_suffix(self):
        originals = ((self.kde, ORIGINAL), (self.fingerprint, FINGERPRINT_ORIGINAL))
        expected = {}
        for path, original in originals:
            suffix = b"# administrator comment\r\nauth optional pam_env.so\n"
            path.write_bytes(integration.transform_service(path, original, install=True) + suffix)
            expected[path] = original + suffix
        self.run.side_effect = None
        with mock.patch.object(integration, "atomic_write") as write, \
                mock.patch.object(integration, "close_gate"), \
                mock.patch.object(integration, "stop"), \
                mock.patch.object(integration, "save"):
            integration.disable(self.manifest_state())
        for path, data in expected.items():
            self.assertIn(mock.call(path, data, 0o644), write.call_args_list)

    def test_changed_fingerprint_backup_refuses_before_either_service_is_written(self):
        self.kde.write_bytes(integration.transform_service(self.kde, ORIGINAL, install=True))
        self.fingerprint.write_bytes(integration.transform_service(self.fingerprint, FINGERPRINT_ORIGINAL, install=True))
        (self.backup / "kde-fingerprint").write_bytes(b"unknown fingerprint backup")
        with mock.patch.object(integration, "atomic_write") as write, \
                mock.patch.object(integration, "close_gate") as close, \
                self.assertRaises(integration.Refusal):
            integration.disable(self.manifest_state())
        write.assert_not_called()
        close.assert_not_called()
        self.run.assert_not_called()

    def test_schema_one_manifest_remains_recoverable_without_new_fingerprint_backup(self):
        state = self.manifest_state()
        state["schema"] = 1
        for name in ("kde-fingerprint", "localpin-kde-password", "localpin-kde-fingerprint"):
            state["originals"].pop(name)
            (self.backup / name).unlink()
        self.write_manifest(json.dumps(state).encode())
        self.assertEqual(integration.load(), state)
        self.kde.write_bytes(integration.PREFIX + ORIGINAL)
        before_fingerprint = self.fingerprint.read_bytes()
        self.run.side_effect = None
        with mock.patch.object(integration, "atomic_write") as write, \
                mock.patch.object(integration, "close_gate"), \
                mock.patch.object(integration, "stop"), \
                mock.patch.object(integration, "save"):
            integration.disable(state)
        self.assertIn(mock.call(self.kde, ORIGINAL, 0o644), write.call_args_list)
        self.assertFalse(any(call.args[0] == self.fingerprint for call in write.call_args_list))
        self.assertEqual(self.fingerprint.read_bytes(), before_fingerprint)


class OwnedPolicyTests(unittest.TestCase):
    def setUp(self):
        patcher = mock.patch.object(integration, "STOCK", integration.digest(ORIGINAL))
        patcher.start()
        self.addCleanup(patcher.stop)
        policy = mock.patch.object(integration, "service_policy", side_effect=lambda path, **kwargs:
                                   ORIGINAL if path == integration.KDE else FINGERPRINT_ORIGINAL)
        policy.start()
        self.addCleanup(policy.stop)

    def test_remove_only_exact_leading_owned_block_and_preserve_every_suffix_byte(self):
        suffix = ORIGINAL + b"# admin comment\r\nauth optional pam_env.so\n"
        self.assertEqual(integration.removable_policy(integration.PREFIX + suffix, ORIGINAL), suffix)
        self.assertEqual(integration.removable_policy(ORIGINAL, ORIGINAL), ORIGINAL)

    def test_modified_missing_duplicate_or_ambiguous_owned_policy_refuses(self):
        for data in [integration.PREFIX.replace(b"success=done", b"success=ok") + ORIGINAL,
                     b"# administrator preface\n" + integration.PREFIX + ORIGINAL,
                     integration.PREFIX + integration.PREFIX + ORIGINAL,
                     integration.PREFIX + ORIGINAL + b"auth required pam_pinlock.so\n",
                     integration.PREFIX + ORIGINAL + b"auth required pam_localpin.so\n"]:
            with self.subTest(data=data), self.assertRaises(integration.Refusal):
                integration.removable_policy(data, ORIGINAL)
        with self.assertRaises(integration.Refusal):
            integration.removable_policy(integration.PREFIX + ORIGINAL, b"unknown original")

    def test_transform_preserves_comments_whitespace_and_every_unowned_byte_for_both_services(self):
        for path, source, target in (
                (integration.KDE, b"password-auth", b"localpin-kde-password"),
                (integration.FINGERPRINT, b"fingerprint-auth", b"localpin-kde-fingerprint")):
            original = b"# auth substack " + source + b"\n\tauth  substack\t" + source + b"  # native comment\naccount required pam_unix.so\n"
            installed = integration.transform_service(path, original, install=True)
            prefix = integration.PREFIX if path == integration.KDE else b""
            expected = original.replace(b"substack\t" + source, b"substack\t" + target)
            self.assertEqual(installed, prefix + expected)
            self.assertEqual(integration.transform_service(path, installed[len(prefix):], install=False), original)
            for broken in (b"auth sufficient " + source + b"\n", original + b"auth substack " + source + b"\n"):
                with self.subTest(path=path, broken=broken), self.assertRaises(integration.Refusal):
                    integration.transform_service(path, broken, install=True)


class PrepareTransactionTests(FilesystemFixture):
    def setUp(self):
        super().setUp()
        self.events = []
        self.saved = []
        self.fault = None
        values = {self.kde: ORIGINAL, self.fingerprint: FINGERPRINT_ORIGINAL,
                  self.policy / "kde-localpin.review-required": integration.PREFIX + ORIGINAL.replace(
                      b"password-auth", b"localpin-kde-password"),
                  self.policy / "kde-fingerprint-localpin.review-required": FINGERPRINT_ORIGINAL.replace(
                      b"fingerprint-auth", b"localpin-kde-fingerprint")}
        for name in integration.PRIVATE:
            values[Path("/etc/pam.d") / name] = b"# original private policy\n"
            values[self.policy / (name + ".review-required")] = b"# packaged private policy\n"

        def event(kind, value=None):
            self.events.append((kind, value))
            if self.fault is not None and self.fault(kind, value):
                raise integration.Refusal("synthetic crash boundary")

        def write(path, data, mode=0o600):
            event("write", Path(path))

        def save(state):
            self.saved.append(copy.deepcopy(state))
            event("save", state["phase"])

        def run(args, **kwargs):
            event("run", tuple(args))
            return types.SimpleNamespace(returncode=0, stdout=b"")

        self.stack.enter_context(mock.patch.multiple(
            integration, load=mock.Mock(return_value=None), validate_policy=mock.Mock(),
            read=mock.Mock(side_effect=lambda path, *args, **kwargs: values[Path(path)]),
            atomic_write=mock.Mock(side_effect=write), save=mock.Mock(side_effect=save),
            close_gate=mock.Mock(side_effect=lambda: event("gate-closed")),
            stop=mock.Mock(side_effect=lambda: event("stop")),
            start=mock.Mock(side_effect=lambda: event("start")),
            sync_dir=mock.Mock(side_effect=lambda path: event("sync-dir", Path(path))),
            snapshot=mock.Mock(return_value={"protected": "new"}),
            binary_snapshot=mock.Mock(return_value={"binaries": "new"}),
        ))
        self.stack.enter_context(mock.patch.object(integration, "run", side_effect=run))

    def test_prepare_dry_run_does_not_create_backup_gate_or_journal(self):
        before = set(self.control.iterdir())
        result = integration.prepare([1000], dry_run=True)
        self.assertTrue(result["dry_run"])
        self.assertIn("pam_localpin.so", result["diff"])
        self.assertEqual(self.events, [])
        self.assertEqual(set(self.control.iterdir()), before)

    def test_durable_preparing_intent_precedes_revoke_protected_writes_and_seal(self):
        result = integration.prepare([1000])
        intent = self.events.index(("save", "preparing"))
        self.assertLess(self.events.index(("sync-dir", self.control)), intent)
        for index, (kind, value) in enumerate(self.events):
            if kind == "stop" or (kind == "run" and value[0] == integration.ACCOUNT):
                self.assertGreater(index, intent)
            if kind == "write" and (value == self.kde or value.parent == Path("/etc/pam.d")):
                self.assertGreater(index, intent)
        revoke = self.events.index(("run", (integration.ACCOUNT, "begin-mutation")))
        seal = self.events.index(("run", (integration.ACCOUNT, "seal", "--uid", "1000")))
        self.assertLess(revoke, self.events.index(("write", self.kde)))
        self.assertLess(seal, self.events.index(("save", "prepared")))
        self.assertLess(self.events.index(("run", ("/usr/bin/systemctl", "disable", "localpin.socket"))), revoke)
        self.assertFalse(any(kind == "run" and "enable" in value for kind, value in self.events))
        self.assertEqual(result["phase"], "prepared")
        self.assertTrue(result["reenrollment_required"])

    def test_failed_intent_save_prevents_revoke_and_protected_edits(self):
        self.fault = lambda kind, value: kind == "save" and value == "preparing"
        with self.assertRaises(integration.Refusal):
            integration.prepare([1000])
        self.assertNotIn(("stop", None), self.events)
        self.assertFalse(any(kind == "run" for kind, _ in self.events))
        self.assertNotIn(("write", self.kde), self.events)

    def test_revoke_write_or_seal_fault_retains_preparing_journal_and_never_starts(self):
        for boundary in ("revoke", "write", "seal"):
            with self.subTest(boundary=boundary):
                self.events.clear()
                self.saved.clear()
                self.fault = lambda kind, value: (
                    (boundary == "revoke" and kind == "run" and value == (integration.ACCOUNT, "begin-mutation"))
                    or (boundary == "write" and kind == "write" and value == self.kde)
                    or (boundary == "seal" and kind == "run" and value[:2] == (integration.ACCOUNT, "seal"))
                )
                with self.assertRaises(integration.Refusal):
                    integration.prepare([1000])
                self.assertEqual(self.saved[-1]["phase"], "preparing")
                self.assertNotIn(("start", None), self.events)


class TrialAndAttestationTests(unittest.TestCase):
    def setUp(self):
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(mock.patch.multiple(
            integration, current=mock.Mock(), enrollment_binding=mock.Mock(return_value=copy.deepcopy(BINDING)),
            boot=mock.Mock(return_value=BOOT), now_ms=mock.Mock(return_value=1000),
            close_gate=mock.Mock(), save=mock.Mock(), atomic_write=mock.Mock(), run=mock.Mock(),
        ))

    def gate(self, data, now=1000, current_boot=BOOT):
        with mock.patch.object(integration, "read", return_value=data), \
                mock.patch.object(integration, "now_ms", return_value=now), \
                mock.patch.object(integration, "boot", return_value=current_boot):
            return integration.gate_state()

    def test_trial_gate_is_bounded_and_bound_to_boot_and_inclusive_start(self):
        data = f"LPINT01\ntrial\n{BOOT}\n1000\n601000\n".encode()
        self.assertEqual(self.gate(data, 1000), "trial")
        self.assertEqual(self.gate(data, 600999), "trial")
        for now in (999, 601000, 2**64 - 1):
            self.assertEqual(self.gate(data, now), "disabled")
        self.assertEqual(self.gate(data, current_boot="different-boot"), "disabled")
        for bad in [data + b"extra\n", data.replace(b"601000", b"601001"),
                    data.replace(b"1000\n601000", b"1000\n1000"), b"LPINT01\ntrial\n"]:
            self.assertEqual(self.gate(bad), "disabled")

    def test_trial_clears_old_attestation_and_persists_binding_before_opening_gate(self):
        state = prepared()
        state["tests"] = {"kind": "old-attestation"}
        events = []
        integration.save.side_effect = lambda value: events.append(("save", copy.deepcopy(value)))
        integration.atomic_write.side_effect = lambda *args: events.append(("write", args))
        result = integration.trial(state)
        self.assertIsNone(state["tests"])
        self.assertEqual(state["trial"]["enrollment"], BINDING)
        self.assertEqual(state["trial"]["end"] - state["trial"]["start"], 600000)
        self.assertEqual([kind for kind, _ in events], ["save", "write"])
        self.assertTrue(result["automatic_expiry"])

    def test_recording_tests_requires_live_current_boot_trial_and_same_enrollment(self):
        for gate, recorded_boot, binding in [("disabled", BOOT, BINDING),
                                             ("trial", "previous-boot", BINDING),
                                             ("trial", BOOT, {"1000": "changed"})]:
            state = prepared()
            state["trial"]["boot"] = recorded_boot
            with self.subTest(gate=gate, boot=recorded_boot, binding=binding), \
                    mock.patch.object(integration, "gate_state", return_value=gate), \
                    mock.patch.object(integration, "enrollment_binding", return_value=binding), \
                    self.assertRaises(integration.Refusal):
                integration.record_tests(state)
        integration.save.assert_not_called()

    def test_activation_rejects_missing_stale_expired_or_changed_attestation(self):
        valid = {"kind": "administrator-attestation", "boot": BOOT,
                 "pin": True, "password": True, "console_recovery": True,
                 "enrollment": copy.deepcopy(BINDING)}
        for tests, gate, binding in [(None, "trial", BINDING),
                                      ({**valid, "kind": "automatic"}, "trial", BINDING),
                                      ({**valid, "boot": "old-boot"}, "trial", BINDING),
                                      (valid, "disabled", BINDING),
                                      (valid, "trial", {"1000": "changed"})]:
            state = prepared()
            state["tests"] = copy.deepcopy(tests)
            with self.subTest(tests=tests, gate=gate, binding=binding), \
                    mock.patch.object(integration, "gate_state", return_value=gate), \
                    mock.patch.object(integration, "enrollment_binding", return_value=binding), \
                    self.assertRaises(integration.Refusal):
                integration.activate(state)
        integration.atomic_write.assert_not_called()

    def test_activation_requires_all_flags_and_binding_to_this_trial(self):
        valid = {"kind": "administrator-attestation", "boot": BOOT,
                 "pin": True, "password": True, "console_recovery": True,
                 "enrollment": copy.deepcopy(BINDING)}
        for field in ("pin", "password", "console_recovery"):
            for value in (None, False, 1, "true"):
                state = prepared()
                state["tests"] = {**valid, field: value}
                with self.subTest(field=field, value=value), \
                        mock.patch.object(integration, "gate_state", return_value="trial"), \
                        self.assertRaises(integration.Refusal):
                    integration.activate(state)
        state = prepared()
        state["tests"] = valid
        state["trial"]["enrollment"] = {"1000": "different-trial"}
        with mock.patch.object(integration, "gate_state", return_value="trial"), \
                self.assertRaises(integration.Refusal):
            integration.activate(state)
        integration.atomic_write.assert_not_called()

    def test_explicit_record_then_activate_retains_operator_attestation_label(self):
        state = prepared()
        with mock.patch.object(integration, "gate_state", return_value="trial"):
            recorded = integration.record_tests(state)
            result = integration.activate(state)
        self.assertFalse(recorded["automatic_desktop_verification"])
        self.assertEqual(state["tests"]["kind"], "administrator-attestation")
        self.assertTrue(all(state["tests"][key] is True for key in ("pin", "password", "console_recovery")))
        self.assertEqual(result["phase"], "active")
        integration.atomic_write.assert_called_once_with(integration.GATE, b"LPINT01\nactive\n", 0o644)
        self.assertIn(mock.call(["/usr/bin/systemctl", "enable", "--now", "localpin.socket"]),
                      integration.run.call_args_list)

    def test_failed_boot_enable_leaves_gate_closed_and_does_not_publish_activation(self):
        state = prepared()
        with mock.patch.object(integration, "gate_state", return_value="trial"):
            integration.record_tests(state)
            integration.save.reset_mock()
            integration.run.side_effect = integration.Refusal("synthetic enable failure")
            with self.assertRaises(integration.Refusal):
                integration.activate(state)
        integration.close_gate.assert_called_once()
        integration.run.assert_called_once_with(["/usr/bin/systemctl", "enable", "--now", "localpin.socket"])
        integration.atomic_write.assert_not_called()
        integration.save.assert_not_called()
        self.assertEqual(state["phase"], "prepared")

    def test_boot_enable_precedes_durable_activation_and_gate_publication(self):
        state = prepared()
        events = []
        with mock.patch.object(integration, "gate_state", return_value="trial"):
            integration.record_tests(state)
            integration.close_gate.side_effect = lambda: events.append("close")
            integration.run.side_effect = lambda args: events.append("enable" if "enable" in args else "label")
            integration.save.side_effect = lambda value: events.append("save")
            integration.atomic_write.side_effect = lambda *args: events.append("gate")
            integration.activate(state)
        self.assertEqual(events, ["close", "enable", "save", "gate", "label"])


class PackageLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        self.events = []
        self.saved = []
        self.state = prepared()
        self.state.update(phase="active", tests={"kind": "administrator-attestation"},
                          upgrade_binding={"authorities": "unchanged"})

        def save(state):
            self.saved.append(copy.deepcopy(state))
            self.events.append(("save", state["phase"]))

        self.stack.enter_context(mock.patch.multiple(
            integration, current=mock.Mock(), gate_state=mock.Mock(return_value="disabled"),
            service_active=mock.Mock(side_effect=lambda unit: unit == "localpin.socket"),
            binary_snapshot=mock.Mock(return_value={"binary": "new"}),
            upgrade_binding=mock.Mock(return_value={"authorities": "unchanged"}),
            remaining_references=mock.Mock(return_value=[]),
            close_gate=mock.Mock(side_effect=lambda: self.events.append(("close", None))),
            stop=mock.Mock(side_effect=lambda: self.events.append(("stop", None))),
            atomic_write=mock.Mock(side_effect=lambda *args: self.events.append(("gate", args))),
            save=mock.Mock(side_effect=save),
            run=mock.Mock(side_effect=lambda args, **kwargs: self.events.append(("run", tuple(args)))),
            read=mock.Mock(return_value=ORIGINAL), STOCK=integration.digest(ORIGINAL),
        ))

    def test_suspend_durably_records_service_intent_before_stop_and_preserves_authorities(self):
        before = copy.deepcopy(self.state)
        result = integration.package_suspend(self.state)
        self.assertLess(self.events.index(("save", "suspended")), self.events.index(("stop", None)))
        self.assertEqual(self.saved[-1]["services"], {"socket": True, "service": False})
        self.assertEqual(self.state["resume_phase"], "active")
        for key in ("uids", "protected", "binaries", "tests"):
            self.assertEqual(self.state[key], before[key])
        self.assertTrue(result["enrollment_preserved"])
        integration.run.assert_not_called()

    def test_suspension_save_failure_never_stops_services(self):
        integration.save.side_effect = integration.Refusal("synthetic intent failure")
        with self.assertRaises(integration.Refusal):
            integration.package_suspend(self.state)
        integration.stop.assert_not_called()

    def test_suspended_upgrade_retry_keeps_original_service_record(self):
        self.state.update(phase="suspended", services={"socket": False, "service": True}, tests=None)
        before = copy.deepcopy(self.state)
        integration.package_suspend(self.state)
        self.assertEqual(self.state, before)
        integration.service_active.assert_not_called()
        integration.current.assert_called_once_with(self.state, binaries=False)

    def test_prepared_resume_refreshes_binaries_and_restarts_previous_units_with_gate_closed(self):
        self.state.update(phase="suspended", services={"socket": True, "service": False}, tests=None)
        before = copy.deepcopy(self.state)
        result = integration.package_resume(self.state)
        integration.current.assert_called_once_with(self.state, binaries=False)
        integration.run.assert_called_once_with(["/usr/bin/systemctl", "start", "localpin.socket"])
        self.assertEqual(self.state["phase"], "prepared")
        self.assertEqual(self.state["binaries"], {"binary": "new"})
        self.assertIsNone(self.state["tests"])
        self.assertEqual(self.state["protected"], before["protected"])
        self.assertEqual(self.state["uids"], before["uids"])
        self.assertTrue(result["enrollment_preserved"])
        self.assertEqual(result["gate"], "disabled")
        self.assertEqual([state["phase"] for state in self.saved], ["suspended", "prepared"])

    def test_active_upgrade_preserves_attestation_authorities_and_reopens_gate_after_restart(self):
        before = copy.deepcopy(self.state)
        integration.package_suspend(self.state)
        self.events.clear()
        self.saved.clear()
        integration.run.reset_mock()
        result = integration.package_resume(self.state)
        self.assertEqual(result["gate"], "active")
        self.assertEqual(self.state["phase"], "active")
        for key in ("uids", "protected", "tests", "upgrade_binding"):
            self.assertEqual(self.state[key], before[key])
        integration.upgrade_binding.assert_called_with(self.state)
        integration.atomic_write.assert_called_once_with(integration.GATE, b"LPINT01\nactive\n", 0o644)
        self.assertLess(self.events.index(("run", ("/usr/bin/systemctl", "start", "localpin.socket"))),
                        next(index for index, (kind, _) in enumerate(self.events) if kind == "gate"))
        self.assertEqual([state["phase"] for state in self.saved], ["suspended", "active"])

    def test_resume_start_failure_leaves_durable_suspended_state_for_retry(self):
        self.state.update(phase="suspended", services={"socket": True, "service": False}, tests=None)
        integration.run.side_effect = integration.Refusal("synthetic service start failure")
        with self.assertRaises(integration.Refusal):
            integration.package_resume(self.state)
        self.assertEqual(self.state["phase"], "suspended")
        self.assertEqual(self.saved[-1]["phase"], "suspended")

    def test_resume_retries_crash_after_durable_active_intent_before_gate_publication(self):
        self.state.update(phase="suspended", resume_phase="active",
                          services={"socket": True, "service": True})
        before = copy.deepcopy(self.state)
        ordinary_save = integration.save.side_effect

        def crash_after_durable_active_intent(state):
            ordinary_save(state)
            if state["phase"] == "active" and state.get("resume_pending") is True:
                raise integration.Refusal("synthetic crash after durable active resume intent")

        integration.save.side_effect = crash_after_durable_active_intent
        with self.assertRaises(integration.Refusal):
            integration.package_resume(self.state)
        witness = copy.deepcopy(self.saved[-1])
        self.assertEqual(witness["phase"], "active")
        self.assertIs(witness["resume_pending"], True)
        self.assertEqual(witness["resume_phase"], "active")
        integration.atomic_write.assert_not_called()
        for key in ("uids", "protected", "tests", "upgrade_binding", "services"):
            self.assertEqual(witness[key], before[key])

        # A new process reads only the durable manifest witness; it has no
        # knowledge of the earlier process's in-memory suspended state.
        integration.save.side_effect = ordinary_save
        integration.current.reset_mock()
        integration.run.reset_mock()
        self.events.clear()
        self.saved.clear()
        result = integration.package_resume(witness)
        integration.current.assert_called_once_with(witness, binaries=False)
        self.assertEqual(result["gate"], "active")
        self.assertEqual(witness["services"], before["services"])
        self.assertIn(mock.call(["/usr/bin/systemctl", "start", "localpin.socket", "localpin.service"]),
                      integration.run.call_args_list)
        integration.atomic_write.assert_called_once_with(integration.GATE, b"LPINT01\nactive\n", 0o644)
        self.assertLess(self.events.index(("save", "active")),
                        next(index for index, (kind, _) in enumerate(self.events) if kind == "gate"))
        for key in ("uids", "protected", "tests", "upgrade_binding", "services"):
            self.assertEqual(witness[key], before[key])

    def test_active_resume_witness_replay_refuses_changed_binding_before_service_start(self):
        self.state.update(phase="active", resume_phase="active", resume_pending=True,
                          services={"socket": True, "service": True})
        before = copy.deepcopy(self.state)
        integration.upgrade_binding.return_value = {"authorities": "changed after interrupted resume"}
        with self.assertRaises(integration.Refusal):
            integration.package_resume(self.state)
        integration.close_gate.assert_called_once()
        integration.stop.assert_called_once()
        integration.run.assert_not_called()
        integration.atomic_write.assert_not_called()
        integration.save.assert_not_called()
        self.assertEqual(self.state, before)

    def test_removal_refuses_live_or_referenced_integration(self):
        for phase, gate, policy in [("active", "disabled", ORIGINAL),
                                     ("disabled", "trial", ORIGINAL),
                                     ("disabled", "active", ORIGINAL),
                                     ("disabled", "disabled", integration.PREFIX + ORIGINAL),
                                     ("disabled", "disabled", b"auth required pam_localpin.so\n")]:
            state = {"phase": phase}
            with self.subTest(phase=phase, gate=gate, policy=policy), \
                    mock.patch.object(integration, "gate_state", return_value=gate), \
                    mock.patch.object(integration, "read", return_value=policy), \
                    mock.patch.object(integration, "remaining_references", return_value=["kde"] if b"pam_localpin" in policy else []), \
                    self.assertRaises(integration.Refusal):
                integration.package_check(state, removal=True)
        integration.run.assert_not_called()

    def test_resume_refuses_changed_account_credential_or_throttle_binding(self):
        self.state.update(phase="suspended", services={"socket": True, "service": False}, tests=None)
        integration.upgrade_binding.return_value = {"authorities": "changed"}
        with self.assertRaises(integration.Refusal):
            integration.package_resume(self.state)
        integration.run.assert_not_called()
        self.assertEqual(self.state["phase"], "suspended")


    def test_ordinary_cache_updates_require_no_native_authority_window_or_registry_rewrite(self):
        self.state.update(phase="suspended")
        before = copy.deepcopy(self.state)
        result = integration.package_cache_begin(self.state)
        self.assertFalse(result["cache_window"])
        self.assertEqual(result["account_authority"], "account-marker")
        self.assertEqual(self.state, before)
        integration.run.assert_not_called()
        integration.save.assert_not_called()
        integration.stop.assert_called_once()

    def test_cache_window_refuses_changed_authority_before_opening_directory(self):
        self.state.update(phase="suspended")
        integration.upgrade_binding.return_value = {"authorities": "changed"}
        with self.assertRaises(integration.Refusal):
            integration.package_cache_begin(self.state)
        integration.run.assert_not_called()
        integration.save.assert_not_called()

    def test_cache_policy_failure_keeps_gate_closed_and_never_mutates_authority(self):
        self.state.update(phase="suspended")
        integration.current.side_effect = integration.Refusal("unsupported policy")
        with self.assertRaises(integration.Refusal):
            integration.package_cache_begin(self.state)
        integration.save.assert_not_called()
        integration.run.assert_not_called()
        integration.close_gate.assert_called_once()
        self.assertEqual(self.state["phase"], "suspended")
        integration.stop.assert_called_once()

    def test_resume_does_not_invoke_obsolete_native_cache_helpers(self):
        self.state.update(phase="suspended",
                          services={"socket": True, "service": False})
        integration.package_resume(self.state)
        self.assertEqual(integration.run.call_args_list, [
            mock.call(["/usr/bin/systemctl", "start", "localpin.socket"]),
        ])
        self.assertEqual(self.saved[-1]["phase"], "prepared")

    def test_unknown_native_abi_or_policy_never_restarts_or_reopens_gate(self):
        self.state.update(phase="suspended", resume_phase="active",
                          services={"socket": True, "service": False})
        integration.current.side_effect = integration.Refusal("unknown native ABI or policy")
        with self.assertRaises(integration.Refusal):
            integration.package_resume(self.state)
        integration.run.assert_not_called()
        integration.atomic_write.assert_not_called()
        integration.save.assert_not_called()
        integration.close_gate.assert_called_once()
        self.assertEqual(self.state["phase"], "suspended")


class RegistryBindingTests(unittest.TestCase):
    @staticmethod
    def registry():
        return bytearray(b"LPACCT03" + (1).to_bytes(2, "big")
                         + (1000).to_bytes(4, "big") + b"i" * 16
                         + (3291981167).to_bytes(8, "big") + b"\x07fixture")

    def test_registry_binds_every_uid_incarnation_marker_and_name_byte(self):
        original = self.registry()
        expected = integration.registry_binding(original)
        self.assertEqual(expected, integration.digest(original))
        for offset in (13, 14, 29, 34, 37, 39, 45):
            changed = original.copy()
            changed[offset] ^= 1
            with self.subTest(offset=offset):
                self.assertNotEqual(integration.registry_binding(changed), expected)

    def test_unknown_truncated_or_unbounded_registry_cannot_supply_upgrade_binding(self):
        original = self.registry()
        for registry in [original[:boundary] for boundary in range(len(original))] + [
                         original + b"x", b"LPACCT01" + original[8:], b"LPACCT02" + original[8:],
                         original[:8] + b"\0\0" + original[10:],
                         original[:8] + (129).to_bytes(2, "big") + original[10:]]:
            with self.subTest(length=len(registry)), self.assertRaises(integration.Refusal):
                integration.registry_binding(registry)

    def test_invalid_uid_empty_incarnation_marker_sentinel_name_and_duplicate_refuse(self):
        original = self.registry()
        invalid = []
        for uid in (0, 999, 60000):
            invalid.append(original[:10] + uid.to_bytes(4, "big") + original[14:])
        invalid.append(original[:14] + bytes(16) + original[30:])
        for marker in (0, 2**32 - 1, 2**32, 2**64 - 1):
            invalid.append(original[:30] + marker.to_bytes(8, "big") + original[38:])
        invalid += [original[:38] + b"\0", original[:38] + b"\x21" + b"x" * 33,
                    original[:39] + b"Fixture", original[:39] + b"fix:ure",
                    original[:8] + b"\0\x02" + original[10:] + original[10:]]
        for registry in invalid:
            with self.subTest(registry=registry), self.assertRaises(integration.Refusal):
                integration.registry_binding(registry)

    def test_distinct_uids_cannot_duplicate_an_account_name_or_native_marker(self):
        original = self.registry()
        other = bytearray(original[10:])
        other[:4] = (1001).to_bytes(4, 'big')
        other[4:20] = b'j' * 16
        for change in ('name', 'marker'):
            entry = other.copy()
            if change == 'name':
                entry[20:28] = (3291981168).to_bytes(8, 'big')
            else:
                entry[29:] = b'fixturb'
            registry = original[:8] + b'\0\x02' + original[10:] + entry
            with self.subTest(duplicate=change), self.assertRaises(integration.Refusal):
                integration.registry_binding(registry)


class EnrollmentUpgradeBindingTests(unittest.TestCase):
    def test_upgrade_binds_exact_registry_pointer_credential_and_throttle_bytes(self):
        root = Path("/var/lib/localpin/users/1000")
        pointer = b"LPA3\0\x01" + (1000).to_bytes(4, "big") + b"i" * 16 + (7).to_bytes(8, "big") + b"\x01"
        values = {Path("/var/lib/localpin-accounts/registry"): bytes(RegistryBindingTests.registry()),
                  root / "active": pointer, root / "generation-7" / "credential": b"credential bytes",
                  root / "generation-7" / "throttle": b"durable PIN failures"}
        with mock.patch.object(integration, "read", side_effect=lambda path, *args, **kwargs: values[Path(path)]):
            expected = integration.upgrade_binding({"uids": [1000]})
            for path in values:
                original = values[path]
                if path.name == "registry":
                    # Change only the opaque incarnation, retaining valid format.
                    changed = bytearray(original)
                    changed[14] ^= 1
                    values[path] = bytes(changed)
                elif path.name == "active":
                    changed = bytearray(original)
                    changed[10] ^= 1
                    values[path] = bytes(changed)
                else:
                    values[path] += b" changed"
                with self.subTest(path=path):
                    self.assertNotEqual(integration.upgrade_binding({"uids": [1000]}), expected)
                values[path] = original
            self.assertEqual(integration.upgrade_binding({"uids": [1000]}), expected)


class NativeAbiTests(unittest.TestCase):
    def setUp(self):
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        self.header = bytearray(64)
        self.header[:6] = b"\x7fELF\x02\x01"
        self.header[18:20] = b"\x3e\x00"
        self.link = types.SimpleNamespace(st_mode=stat.S_IFLNK | 0o777, st_uid=0, st_gid=0)
        self.stack.enter_context(mock.patch.object(integration, "safe_parents"))
        self.stack.enter_context(mock.patch.object(Path, "lstat", return_value=self.link))
        self.target = self.stack.enter_context(mock.patch.object(integration.os, "readlink", return_value="libpam.so.0.85.1"))
        self.read = self.stack.enter_context(mock.patch.object(integration, "read", side_effect=lambda *args: bytes(self.header)))

    def test_compatible_fedora_pam_soname_updates_do_not_require_fixed_build_hashes(self):
        for target in ("libpam.so.0.85.1", "libpam.so.0.86.0"):
            with self.subTest(target=target):
                self.target.return_value = target
                integration.native_policy_files()
                self.assertIn(mock.call(Path("/usr/lib64") / target, 16 * 1024 * 1024), self.read.call_args_list)
                self.header[40] ^= 1  # Package builds may differ outside ELF ABI fields.

    def test_unknown_soname_unsafe_link_or_wrong_elf_abi_refuses(self):
        for target in ("libpam.so.1.0", "../libpam.so.0.85.1", "/tmp/libpam.so.0.85.1"):
            self.target.return_value = target
            with self.subTest(target=target), self.assertRaises(integration.Refusal):
                integration.native_policy_files()
        self.target.return_value = "libpam.so.0.85.1"
        for field, value in (("st_uid", 1000), ("st_gid", 1000), ("st_mode", stat.S_IFREG | 0o644)):
            original = getattr(self.link, field)
            setattr(self.link, field, value)
            with self.subTest(field=field), self.assertRaises(integration.Refusal):
                integration.native_policy_files()
            setattr(self.link, field, original)
        for offset, byte in ((0, 0), (4, 1), (5, 2), (18, 0xB7)):
            original = self.header[offset]
            self.header[offset] = byte
            with self.subTest(offset=offset), self.assertRaises(integration.Refusal):
                integration.native_policy_files()
            self.header[offset] = original


class CurrentPolicyTests(unittest.TestCase):
    def test_changed_owned_policies_and_legacy_active_state_refuse_before_binary_adoption(self):
        state = prepared()
        with mock.patch.object(integration, "validate_policy") as validate, \
                mock.patch.object(integration, "snapshot", return_value={"policy": "changed"}) as snapshot, \
                mock.patch.object(integration, "binary_snapshot") as binaries:
            with self.assertRaises(integration.Refusal):
                integration.current(state, binaries=False)
            snapshot.assert_called_once_with(integration.PROTECTED, metadata=False)
            binaries.assert_not_called()
            state["schema"] = 1
            validate.reset_mock()
            with self.assertRaises(integration.Refusal):
                integration.current(state, binaries=False)
            validate.assert_not_called()


class ReviewedPamSyntaxTests(unittest.TestCase):
    def test_reviewed_ascii_lines_and_only_full_line_comments_are_supported(self):
        for policy in (b'', b'\n \t\n', b' \t# full-line comment\n',
                       b'auth\t[success=done default=ignore] /usr/lib64/security/pam_localpin.so\n',
                       b'  account required pam_unix.so\t\n# punctuation ![]{};~\n'):
            with self.subTest(policy=policy):
                self.assertTrue(integration.reviewed_pam_syntax(policy))

    def test_parser_sensitive_controls_continuations_comments_and_unicode_are_refused(self):
        for policy in (b'auth required pam_unix.so # hidden suffix\n',
                       b'auth required pam_unix.so\\\n', b'# comment with continuation\\\n',
                       b'# CR comment\r\n', b'# control\x00\n', b'# DEL\x7f\n',
                       b'auth\vrequired pam_unix.so\n', b'auth\frequired pam_unix.so\n',
                       b'auth\x1crequired pam_unix.so\n', b'auth\x1drequired pam_unix.so\n',
                       b'auth\x1erequired pam_unix.so\n',
                       '\u00a0# apparent comment\n'.encode(),
                       'auth\u00a0required pam_unix.so\n'.encode(),
                       'auth\u2028required pam_unix.so\n'.encode(),
                       '# Unicode comment is outside ASCII prepare subset: \u00e9\n'.encode()):
            with self.subTest(policy=policy):
                self.assertFalse(integration.reviewed_pam_syntax(policy))


class NativePolicyGraphTests(unittest.TestCase):
    def setUp(self):
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        self.values = {
            Path('/usr/lib/os-release'): b'ID=fedora\nVERSION_ID=44\n',
            Path('/etc/authselect/postlogin'): b'# distribution session update\nsession optional pam_umask.so\n',
            Path('/etc/authselect/nsswitch.conf'): b'passwd: files systemd\ngroup: files [SUCCESS=merge] systemd\nshadow: files systemd\n',
            Path('/etc/security/faillock.conf'): integration.PERSISTENT,
            integration.KDE: ORIGINAL, integration.FINGERPRINT: FINGERPRINT_ORIGINAL,
        }
        for name in integration.PRIVATE:
            self.values[integration.POLICY / (name + '.review-required')] = b'# packaged private fixture\n'
        links = {'/etc/pam.d/password-auth': '/etc/authselect/password-auth',
                 '/etc/pam.d/postlogin': '/etc/authselect/postlogin',
                 '/etc/nsswitch.conf': '/etc/authselect/nsswitch.conf'}
        self.stack.enter_context(mock.patch.object(integration, 'read', side_effect=lambda path, *args, **kwargs: self.values[Path(path)]))
        self.stack.enter_context(mock.patch.object(integration, 'service_policy', side_effect=lambda path, **kwargs:
                                                  ORIGINAL if path == integration.KDE else FINGERPRINT_ORIGINAL))
        self.stack.enter_context(mock.patch.object(integration, 'safe_parents'))
        self.stack.enter_context(mock.patch.object(Path, 'is_symlink', return_value=True))
        self.stack.enter_context(mock.patch.object(Path, 'lstat', return_value=types.SimpleNamespace(
            st_uid=0, st_gid=0, st_mode=stat.S_IFDIR | 0o755)))
        self.stack.enter_context(mock.patch.object(integration.os, 'readlink', side_effect=lambda path: links[str(path)]))
        self.stack.enter_context(mock.patch.object(integration.os, 'uname', return_value=types.SimpleNamespace(machine='x86_64')))
        self.stack.enter_context(mock.patch.object(integration, 'run', side_effect=lambda args: types.SimpleNamespace(
            stdout=b'Enforcing\n' if args[0] == '/usr/sbin/getenforce' else b'btrfs\n')))
        self.native = self.stack.enter_context(mock.patch.object(integration, 'native_policy_files'))
        self.stack.enter_context(mock.patch.object(integration, 'binary_snapshot'))

    def test_stock_files_systemd_group_merge_and_session_only_postlogin_updates_are_supported(self):
        integration.validate_policy()
        self.native.assert_called_once()

    def test_live_kde_syntax_permits_ascii_comments_lf_and_space_tab_only(self):
        for service in (integration.KDE, integration.FINGERPRINT):
            original = self.values[service]
            self.values[service] = b' \t# ordinary ASCII comment\n\t\n' + original.replace(b'auth substack', b' \tauth\t substack')
        integration.validate_policy()
        self.native.assert_called_once()

    def test_normalization_cannot_make_unsupported_live_kde_syntax_preparable(self):
        for service in (integration.KDE, integration.FINGERPRINT):
            original = self.values[service]
            variants = (
                original.replace(b'\n', b'\r\n'),
                original.replace(b'-auth\n', b'-auth # inline comment\n'),
                b'# apparent comment with continuation\\\n' + original,
                b'# control in a comment\x0b\n' + original,
            )
            for policy in variants:
                self.assertEqual(integration.canonical(policy), integration.canonical(original))
                self.values[service] = policy
                self.native.reset_mock()
                for integrated in (False, True):
                    with self.subTest(service=service, policy=policy, integrated=integrated), \
                            self.assertRaisesRegex(integration.Refusal, 'unsupported KDE PAM syntax'):
                        integration.validate_policy(integrated=integrated)
                    self.native.assert_not_called()
            self.values[service] = original

    def test_unknown_nss_order_provider_or_action_refuses(self):
        path = Path('/etc/authselect/nsswitch.conf')
        original = self.values[path]
        for bad in (b'passwd: systemd files', b'passwd: files sss', b'group: files [SUCCESS=return] systemd'):
            database = bad.split(b':', 1)[0]
            self.values[path] = b'\n'.join(bad if row.startswith(database + b':') else row for row in original.splitlines()) + b'\n'
            with self.subTest(bad=bad), self.assertRaises(integration.Refusal):
                integration.validate_policy()

    def test_postlogin_auth_hook_or_changed_kde_graph_refuses(self):
        path = Path('/etc/authselect/postlogin')
        for directive in (b'auth optional pam_exec.so /tmp/hook\n', b'-auth optional pam_env.so\n'):
            self.values[path] = directive
            with self.subTest(directive=directive), self.assertRaises(integration.Refusal):
                integration.validate_policy()
        self.values[path] = b'session optional pam_umask.so\n'
        for service in (integration.KDE, integration.FINGERPRINT):
            self.values[service] += b'auth required pam_access.so\n'
            with self.subTest(service=service), self.assertRaises(integration.Refusal):
                integration.validate_policy()
            self.values[service] = ORIGINAL if service == integration.KDE else FINGERPRINT_ORIGINAL


class RemainingReferenceTests(FilesystemFixture):
    def setUp(self):
        super().setUp()
        actual_path = Path
        self.stack.enter_context(mock.patch.object(
            integration, "Path", side_effect=lambda value: self.kde.parent if value == "/etc/pam.d" else actual_path(value)
        ))

    def test_non_kde_service_reference_blocks_removal(self):
        service = self.kde.parent / "other-login"
        service.write_bytes(b"auth required /usr/lib64/security/pam_localpin.so\n")
        service.chmod(0o644)
        self.assertEqual(integration.remaining_references(), ["other-login"])
        with mock.patch.object(integration, "gate_state", return_value="disabled"), \
                self.assertRaises(integration.Refusal):
            integration.package_check({"phase": "disabled"}, removal=True)

    def test_owned_kde_substack_reference_also_blocks_removal(self):
        service = self.kde.parent / "other-login"
        for name in ("localpin-kde-password", "localpin-kde-fingerprint"):
            service.write_bytes(("auth substack " + name + "\n").encode())
            service.chmod(0o644)
            with self.subTest(name=name):
                self.assertEqual(integration.remaining_references(), ["other-login"])
                with mock.patch.object(integration, "gate_state", return_value="disabled"), \
                        self.assertRaises(integration.Refusal):
                    integration.package_check({"phase": "disabled"}, removal=True)

    def test_unknown_symlink_or_hardlinked_service_refuses_inventory(self):
        service = self.kde.parent / "other-login"
        service.symlink_to(self.kde)
        with self.assertRaises(integration.Refusal):
            integration.remaining_references()
        service.unlink()
        os.link(self.kde, service)
        with self.assertRaises(integration.Refusal):
            integration.remaining_references()


class CandidateVersionTests(unittest.TestCase):
    def setUp(self):
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        self.compare = mock.Mock(return_value=0)
        self.stack.enter_context(mock.patch.dict(sys.modules, {"rpm": types.SimpleNamespace(labelCompare=self.compare)}))
        self.run = self.stack.enter_context(mock.patch.object(
            integration, "run", return_value=types.SimpleNamespace(stdout=b"0:0.1.0-alpha.1.fc44")
        ))

    def test_equal_or_newer_supported_candidate_uses_native_rpm_comparison(self):
        for comparison in (0, 1):
            with self.subTest(comparison=comparison):
                self.compare.return_value = comparison
                integration.candidate_check("0:0.1.0-alpha.2.fc44", 2)
                self.compare.assert_called_with(("0", "0.1.0", "alpha.2.fc44"), ("0", "0.1.0", "alpha.1.fc44"))
        self.run.assert_called_with(["/usr/bin/rpm", "-q", "--queryformat", "%{EPOCHNUM}:%{VERSION}-%{RELEASE}", "localpin"])

    def test_invalid_candidate_syntax_policy_version_or_schema_never_invokes_rpm(self):
        for candidate, schema in [
            ("0.1.0-alpha.1", 2), ("1:0.1.0-alpha.1", 2),
            ("0:0.2.0-alpha.1", 2), ("0:0.1.0-alpha_1", 2),
            ("0:0.1.0-alpha.1;id", 2), ("0:0.1.0-alpha.1\n", 2),
            ("0:0.1.0-", 2), ("0:0.1.0-alpha.1", 0),
            ("0:0.1.0-alpha.1", 1), ("0:0.1.0-alpha.1", 3),
            ("0:0.1.0-alpha.1", None),
        ]:
            with self.subTest(candidate=candidate, schema=schema), self.assertRaises(integration.Refusal):
                integration.candidate_check(candidate, schema)
        self.run.assert_not_called()
        self.compare.assert_not_called()

    def test_native_downgrade_comparison_refuses_and_invalid_installed_evr_is_not_guessed(self):
        self.compare.return_value = -1
        with self.assertRaises(integration.Refusal):
            integration.candidate_check("0:0.1.0-alpha.1.fc44", 2)
        self.compare.reset_mock()
        self.run.return_value.stdout = b"unknown installed version"
        with self.assertRaises(integration.Refusal):
            integration.candidate_check("0:0.1.0-alpha.1.fc44", 2)
        self.compare.assert_not_called()


class LegacyMigrationTests(FilesystemFixture):
    def setUp(self):
        super().setUp()
        self.before = integration.LEGACY_PREFIX + ORIGINAL
        self.kde.write_bytes(self.before)
        self.events = []
        self.fault_path = None

        def write(path, data, mode=0o600):
            path = Path(path)
            self.events.append(("write", path, data))
            if path == self.fault_path:
                raise integration.Refusal("synthetic migration journal failure")

        self.stack.enter_context(mock.patch.multiple(
            integration, load=mock.Mock(return_value=None),
            close_gate=mock.Mock(side_effect=lambda: self.events.append(("close",))),
            stop=mock.Mock(side_effect=lambda: self.events.append(("stop",))),
            atomic_write=mock.Mock(side_effect=write),
        ))
        self.stack.enter_context(mock.patch.object(
            integration, "run", side_effect=lambda args, **kwargs: self.events.append(("run", tuple(args)))
        ))

    def test_dry_run_removes_only_known_legacy_block_without_state_or_policy_writes(self):
        before = set(self.control.iterdir())
        result = integration.migrate_legacy(dry_run=True)
        self.assertTrue(result["dry_run"])
        self.assertFalse(result["imports_old_verifier"])
        self.assertIn("pam_pinlock", result["diff"])
        self.assertEqual(self.events, [])
        self.assertEqual(self.kde.read_bytes(), self.before)
        self.assertEqual(set(self.control.iterdir()), before)

    def test_backup_and_journal_are_durable_before_revoke_and_exact_stock_replacement(self):
        result = integration.migrate_legacy()
        backup = next(i for i, value in enumerate(self.events) if value[:2] == ("write", self.control / "legacy-kde"))
        journal = next(i for i, value in enumerate(self.events) if value[:2] == ("write", self.control / "legacy-migration.json"))
        revoke = self.events.index(("run", (integration.ACCOUNT, "begin-mutation")))
        replacement = self.events.index(("write", self.kde, ORIGINAL))
        self.assertLess(backup, journal)
        self.assertLess(journal, self.events.index(("stop",)))
        self.assertLess(journal, revoke)
        self.assertLess(revoke, replacement)
        self.assertFalse(result["imports_old_verifier"])

    def test_backup_or_journal_fault_prevents_revoke_and_live_policy_edit(self):
        for name in ("legacy-kde", "legacy-migration.json"):
            with self.subTest(name=name):
                self.events.clear()
                self.fault_path = self.control / name
                with self.assertRaises(integration.Refusal):
                    integration.migrate_legacy()
                self.assertNotIn(("run", (integration.ACCOUNT, "begin-mutation")), self.events)
                self.assertNotIn(("write", self.kde, ORIGINAL), self.events)

    def test_changed_legacy_block_suffix_or_active_localpin_state_refuses(self):
        for data in [self.before.replace(b"retries=1", b"retries=2"),
                     self.before + b"# administrator change\n", ORIGINAL,
                     integration.PREFIX + ORIGINAL]:
            self.kde.write_bytes(data)
            with self.subTest(data=data), self.assertRaises(integration.Refusal):
                integration.migrate_legacy()
        integration.load.return_value = {"phase": "active"}
        self.kde.write_bytes(self.before)
        with self.assertRaises(integration.Refusal):
            integration.migrate_legacy()
        self.assertEqual(self.events, [])

    def write_migration_record(self):
        path = self.control / "legacy-migration.json"
        path.write_text(json.dumps({"schema": 1, "original": integration.digest(self.before),
                                    "restored": integration.STOCK}))
        path.chmod(0o600)

    def write_source_backup(self, data=None):
        path = self.control / "legacy-kde"
        path.write_bytes(self.before if data is None else data)
        path.chmod(0o600)
        return path

    def assert_no_revocation_or_live_write(self):
        self.assertNotIn(("run", (integration.ACCOUNT, "begin-mutation")), self.events)
        self.assertNotIn(("write", self.kde, ORIGINAL), self.events)
        self.assertEqual(self.kde.read_bytes(), self.before)

    def test_existing_journal_with_missing_source_backup_refuses_without_reconstruction(self):
        self.write_migration_record()
        with self.assertRaises(integration.Refusal):
            integration.migrate_legacy()
        self.assert_no_revocation_or_live_write()
        self.assertFalse(any(event[:2] == ("write", self.control / "legacy-kde") for event in self.events))

    def test_unknown_or_unsafe_existing_source_backup_is_never_overwritten(self):
        path = self.write_source_backup(b"unknown old policy")
        with self.assertRaises(integration.Refusal):
            integration.migrate_legacy()
        self.assertEqual(path.read_bytes(), b"unknown old policy")
        self.assert_no_revocation_or_live_write()
        self.assertFalse(any(event[0] == "write" for event in self.events))
        self.events.clear()
        path.write_bytes(self.before)
        path.chmod(0o644)
        with self.assertRaises(integration.Refusal):
            integration.migrate_legacy()
        self.assert_no_revocation_or_live_write()

    def test_matching_orphan_backup_is_preserved_and_existing_journal_retry_revalidates_it(self):
        backup = self.write_source_backup()
        integration.migrate_legacy()
        self.assertFalse(any(event[:2] == ("write", backup) for event in self.events))
        self.assertTrue(any(event[:2] == ("write", self.control / "legacy-migration.json") for event in self.events))
        self.events.clear()
        self.write_migration_record()
        integration.migrate_legacy()
        self.assertFalse(any(event[:2] == ("write", backup) for event in self.events))
        self.assertFalse(any(event[:2] == ("write", self.control / "legacy-migration.json") for event in self.events))
        self.assertIn(("write", self.kde, ORIGINAL), self.events)


class RecoveryEntrypointTests(unittest.TestCase):
    def test_corrupt_manifest_still_closes_gate_before_load_for_disable_and_recover(self):
        for operation in ("disable", "recover"):
            events = []

            def corrupt_manifest():
                events.append("load")
                raise integration.Refusal("synthetic corrupt manifest")

            with self.subTest(operation=operation), \
                    mock.patch.object(sys, "argv", ["localpin-integration", operation]), \
                    mock.patch.object(integration.os, "getuid", return_value=0), \
                    mock.patch.object(integration.os, "geteuid", return_value=0), \
                    mock.patch.object(integration, "locked", return_value=contextlib.nullcontext()), \
                    mock.patch.object(integration, "close_gate", side_effect=lambda: events.append("close")), \
                    mock.patch.object(integration, "load", side_effect=corrupt_manifest), \
                    self.assertRaises(integration.Refusal):
                integration.main()
            self.assertEqual(events, ["close", "load"])


if __name__ == "__main__":
    unittest.main()
