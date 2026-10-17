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
ORIGINAL = b"auth required pam_unix.so\naccount required pam_unix.so\n"
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
    return {"schema": 1, "phase": "prepared", "uids": [1000],
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
        self.policy = self.root / "policy"
        self.control.mkdir(parents=True, mode=0o700)
        self.kde.parent.mkdir(parents=True)
        self.policy.mkdir()
        self.kde.write_bytes(ORIGINAL)
        self.kde.chmod(0o644)
        self.manifest = self.control / "manifest.json"
        self.gate = self.state / "gate"
        self.backup = self.control / "backup-test"
        self.backup.mkdir(mode=0o700)
        (self.backup / "kde").write_bytes(ORIGINAL)
        (self.backup / "kde").chmod(0o600)
        self.original_private = {}
        for name in integration.PRIVATE:
            data = ("# original " + name + "\n").encode()
            self.original_private[name] = data
            for path, mode in ((self.backup / name, 0o600), (self.kde.parent / name, 0o644)):
                path.write_bytes(data)
                path.chmod(mode)
            (self.policy / (name + ".review-required")).write_bytes(b"# packaged private policy\n")
        self.stack.enter_context(mock.patch.multiple(
            integration, STATE=self.state, CONTROL=self.control, MANIFEST=self.manifest,
            KDE=self.kde, GATE=self.gate, POLICY=self.policy, STOCK=integration.digest(ORIGINAL),
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
        originals.update({name: {"sha256": integration.digest(data), "mode": 0o644}
                          for name, data in self.original_private.items()})
        return {"schema": 1, "phase": "prepared", "backup": "backup-test", "originals": originals}

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
        for data in [b"{", b"null", b"[]", b'{"schema":2,"phase":"prepared"}',
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
            self.assertIn("administrator addition", result["diff"])
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


class OwnedPolicyTests(unittest.TestCase):
    def setUp(self):
        patcher = mock.patch.object(integration, "STOCK", integration.digest(ORIGINAL))
        patcher.start()
        self.addCleanup(patcher.stop)

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


class PrepareTransactionTests(FilesystemFixture):
    def setUp(self):
        super().setUp()
        self.events = []
        self.saved = []
        self.fault = None
        values = {self.kde: ORIGINAL,
                  self.policy / "kde-localpin.review-required": integration.PREFIX + ORIGINAL}
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
            save=mock.Mock(side_effect=save),
            run=mock.Mock(side_effect=lambda args, **kwargs: self.events.append(("run", tuple(args)))),
            read=mock.Mock(return_value=ORIGINAL), STOCK=integration.digest(ORIGINAL),
        ))

    def test_suspend_durably_records_service_intent_before_stop_and_preserves_authorities(self):
        before = copy.deepcopy(self.state)
        result = integration.package_suspend(self.state)
        self.assertLess(self.events.index(("save", "suspended")), self.events.index(("stop", None)))
        self.assertEqual(self.saved[-1]["services"], {"socket": True, "service": False})
        self.assertIsNone(self.state["tests"])
        for key in ("uids", "protected", "binaries"):
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

    def test_resume_refreshes_only_binaries_restarts_previous_units_and_requires_new_tests(self):
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

    def test_resume_start_failure_leaves_durable_suspended_state_for_retry(self):
        self.state.update(phase="suspended", services={"socket": True, "service": False}, tests=None)
        integration.run.side_effect = integration.Refusal("synthetic service start failure")
        with self.assertRaises(integration.Refusal):
            integration.package_resume(self.state)
        self.assertEqual(self.state["phase"], "suspended")
        self.assertEqual(self.saved[-1]["phase"], "suspended")

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


    def test_cache_window_records_intent_before_native_authority_suspension(self):
        self.state.update(phase="suspended")
        integration.package_cache_begin(self.state)
        self.assertTrue(self.saved[-1]["cache_window"])
        self.assertLess(self.events.index(("save", "suspended")),
                        self.events.index(("run", (integration.ACCOUNT, "cache-window-begin"))))
        integration.stop.assert_called_once()

    def test_cache_window_refuses_changed_authority_before_opening_directory(self):
        self.state.update(phase="suspended")
        integration.upgrade_binding.return_value = {"authorities": "changed"}
        with self.assertRaises(integration.Refusal):
            integration.package_cache_begin(self.state)
        integration.run.assert_not_called()
        integration.save.assert_not_called()

    def test_cache_window_begin_failure_keeps_durable_retry_intent_and_services_stopped(self):
        self.state.update(phase="suspended")
        integration.run.side_effect = integration.Refusal("synthetic native failure")
        with self.assertRaises(integration.Refusal):
            integration.package_cache_begin(self.state)
        self.assertTrue(self.saved[-1]["cache_window"])
        self.assertEqual(self.state["phase"], "suspended")
        integration.stop.assert_called_once()

    def test_resume_finishes_native_cache_window_before_binding_or_restart(self):
        self.state.update(phase="suspended", cache_window=True,
                          services={"socket": True, "service": False})
        integration.package_resume(self.state)
        self.assertEqual(integration.run.call_args_list, [
            mock.call([integration.ACCOUNT, "cache-window-finish"]),
            mock.call(["/usr/bin/systemctl", "start", "localpin.socket"]),
        ])
        self.assertFalse(self.saved[0]["cache_window"])
        self.assertEqual(self.saved[-1]["phase"], "prepared")

    def test_native_cache_finish_failure_never_restarts_or_reopens_gate(self):
        self.state.update(phase="suspended", cache_window=True,
                          services={"socket": True, "service": False})
        integration.run.side_effect = integration.Refusal("synthetic snapshot mismatch")
        with self.assertRaises(integration.Refusal):
            integration.package_resume(self.state)
        integration.run.assert_called_once_with([integration.ACCOUNT, "cache-window-finish"])
        integration.save.assert_not_called()
        self.assertTrue(self.state["cache_window"])
        self.assertEqual(self.state["phase"], "suspended")


class RegistryBindingTests(unittest.TestCase):
    @staticmethod
    def registry():
        return bytearray(b"LPACCT02" + (20).to_bytes(2, "big")
                         + bytes(20 * 84) + (1).to_bytes(2, "big") + bytes(20))

    def test_cache_update_allows_only_etc_size_and_change_timestamp(self):
        original = self.registry()
        expected = integration.registry_binding(original)
        changed = original.copy()
        changed[26:50] = b"x" * 24
        self.assertEqual(integration.registry_binding(changed), expected)
        # Identity, protection metadata, canonical symlinks and every account
        # ID remain equality requirements even when their bytes are well formed.
        for offset in [10, 18, 50, 54, 62, 94, 10 + 17 * 84, 1692, 1711]:
            changed = original.copy()
            changed[offset] ^= 1
            with self.subTest(offset=offset):
                self.assertNotEqual(integration.registry_binding(changed), expected)

    def test_unknown_truncated_or_unbounded_registry_cannot_supply_upgrade_binding(self):
        original = self.registry()
        for registry in [b"", original[:-1], original + b"x",
                         b"LPACCT01" + original[8:], original[:8] + b"\0\x13" + original[10:],
                         original[:1690] + (129).to_bytes(2, "big") + bytes(129 * 20)]:
            with self.subTest(length=len(registry)), self.assertRaises(integration.Refusal):
                integration.registry_binding(registry)


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
                integration.candidate_check("0:0.1.0-alpha.2.fc44", 1)
                self.compare.assert_called_with(("0", "0.1.0", "alpha.2.fc44"), ("0", "0.1.0", "alpha.1.fc44"))
        self.run.assert_called_with(["/usr/bin/rpm", "-q", "--queryformat", "%{EPOCHNUM}:%{VERSION}-%{RELEASE}", "localpin"])

    def test_invalid_candidate_syntax_policy_version_or_schema_never_invokes_rpm(self):
        for candidate, schema in [
            ("0.1.0-alpha.1", 1), ("1:0.1.0-alpha.1", 1),
            ("0:0.2.0-alpha.1", 1), ("0:0.1.0-alpha_1", 1),
            ("0:0.1.0-alpha.1;id", 1), ("0:0.1.0-alpha.1\n", 1),
            ("0:0.1.0-", 1), ("0:0.1.0-alpha.1", 0),
            ("0:0.1.0-alpha.1", 2), ("0:0.1.0-alpha.1", None),
        ]:
            with self.subTest(candidate=candidate, schema=schema), self.assertRaises(integration.Refusal):
                integration.candidate_check(candidate, schema)
        self.run.assert_not_called()
        self.compare.assert_not_called()

    def test_native_downgrade_comparison_refuses_and_invalid_installed_evr_is_not_guessed(self):
        self.compare.return_value = -1
        with self.assertRaises(integration.Refusal):
            integration.candidate_check("0:0.1.0-alpha.1.fc44", 1)
        self.compare.reset_mock()
        self.run.return_value.stdout = b"unknown installed version"
        with self.assertRaises(integration.Refusal):
            integration.candidate_check("0:0.1.0-alpha.1.fc44", 1)
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
