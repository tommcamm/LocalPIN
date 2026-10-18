"""Synthetic resume hints and UI launch tests; never change host authentication."""

import contextlib
from importlib.machinery import SourceFileLoader
import importlib.util
import json
import os
from pathlib import Path
import stat
import tempfile
from concurrent.futures import ThreadPoolExecutor
import types
import unittest
from unittest import mock


SOURCE = Path(__file__).resolve().parents[1] / "localpin-setup-resume"
SPEC = importlib.util.spec_from_loader("localpin_setup_resume_tested",
                                      SourceFileLoader("localpin_setup_resume_tested", str(SOURCE)))
resume = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(resume)
UID = 1001
REQUEST = "a" * 64


class ResumeTests(unittest.TestCase):
    def setUp(self):
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        self.root = Path(self.stack.enter_context(tempfile.TemporaryDirectory(prefix="localpin-resume-")))
        self.root.chmod(0o755)
        self.hint = self.root / "setup-resume.json"
        self.value = {"schema_version": 1, "uid": UID, "request_id": REQUEST, "state": "ready"}
        self.write_hint()
        self.stack.enter_context(mock.patch.multiple(resume, PUBLIC_HINT=self.hint,
                                                    PUBLIC_PARENTS=(self.root,)))

    def write_hint(self, value=None):
        self.hint.write_text(json.dumps(self.value if value is None else value))
        self.hint.chmod(0o644)

    @contextlib.contextmanager
    def root_owned(self, **changes):
        def metadata(info):
            values = {name: getattr(info, name) for name in
                      ("st_mode", "st_uid", "st_gid", "st_size", "st_nlink")}
            values.update(st_uid=0, st_gid=0)
            values.update(changes)
            return types.SimpleNamespace(**values)
        original_lstat, original_fstat = Path.lstat, os.fstat
        with mock.patch.object(Path, "lstat", lambda path: metadata(original_lstat(path))), \
                mock.patch.object(os, "fstat", lambda fd: metadata(original_fstat(fd))):
            yield

    def test_only_exact_bounded_outcome_hint_for_current_uid_is_accepted(self):
        with self.root_owned():
            for state in ("ready", "aborted"):
                self.write_hint({**self.value, "state": state})
                self.assertEqual(resume.read_hint(UID), REQUEST)
            for key, value in (("schema_version", 2), ("schema_version", True), ("uid", UID + 1),
                               ("uid", True), ("request_id", "../injected"),
                               ("request_id", "A" * 64), ("state", "pending"),
                               ("state", "failed"), ("extra", "unrecognized")):
                with self.subTest(key=key, value=value):
                    self.write_hint({**self.value, key: value})
                    self.assertIsNone(resume.read_hint(UID))
            for data in (b"{}", b"null", b"[]", b"not json", b"\xff", b" " * 4097,
                         b'{"uid":1001,"uid":1001}', b"[" * 1500 + b"]" * 1500):
                self.hint.write_bytes(data)
                self.assertIsNone(resume.read_hint(UID))

    def test_aborted_hint_opens_only_fixed_setup_once_for_that_request(self):
        self.write_hint({**self.value, "state": "aborted"})
        with self.root_owned():
            request = resume.read_hint(UID)
        self.assertEqual(request, REQUEST)
        with mock.patch.object(resume, "read_hint", return_value=request), \
                mock.patch.object(resume.subprocess, "Popen") as launch:
            resume.resume(os.getuid(), self.root)
            resume.resume(os.getuid(), self.root)
            launch.assert_called_once()
            self.assertEqual(launch.call_args.args[0], resume.COMMAND)

    def test_hint_requires_root_ownership_exact_mode_and_single_regular_file(self):
        for changes in ({"st_uid": UID}, {"st_gid": UID}, {"st_nlink": 2},
                        {"st_mode": stat.S_IFREG | 0o666},
                        {"st_mode": stat.S_IFIFO | 0o644}):
            with self.subTest(changes=changes), self.root_owned(**changes):
                self.assertIsNone(resume.read_hint(UID))
        with self.root_owned():
            self.hint.chmod(0o600)
            self.assertIsNone(resume.read_hint(UID))
            self.hint.unlink()
            self.hint.symlink_to(self.root / "missing")
            self.assertIsNone(resume.read_hint(UID))

    def test_unsafe_parent_and_missing_hint_do_not_launch(self):
        with self.root_owned():
            self.root.chmod(0o777)
            self.assertIsNone(resume.read_hint(UID))
            self.root.chmod(0o755)
            self.hint.unlink()
            self.assertIsNone(resume.read_hint(UID))

    def test_fixed_command_launches_once_per_request_even_when_restarted(self):
        with mock.patch.object(resume, "read_hint", return_value=REQUEST), \
                mock.patch.object(subprocess := resume.subprocess, "Popen") as launch:
            resume.resume(os.getuid(), self.root)
            resume.resume(os.getuid(), self.root)
            launch.assert_called_once_with(
                ("/usr/bin/konsole", "--separate", "-e", "/usr/bin/localpin", "setup"),
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                close_fds=True, start_new_session=True)
            marker = self.root / ".cache/localpin/setup-resume" / REQUEST
            self.assertEqual(stat.S_IMODE(marker.stat().st_mode), 0o600)
            with mock.patch.object(resume, "read_hint", return_value="b" * 64):
                resume.resume(os.getuid(), self.root)
            self.assertEqual(launch.call_count, 2)

    def test_no_hint_never_claims_cache_or_launches(self):
        with mock.patch.object(resume, "read_hint", return_value=None), \
                mock.patch.object(resume.subprocess, "Popen") as launch:
            resume.resume(os.getuid(), self.root)
            launch.assert_not_called()
            self.assertFalse((self.root / ".cache").exists())

    def test_concurrent_autostarts_claim_only_one_launch(self):
        with mock.patch.object(resume, "read_hint", return_value=REQUEST), \
                mock.patch.object(resume.subprocess, "Popen") as launch, \
                ThreadPoolExecutor(max_workers=4) as threads:
            list(threads.map(lambda _: resume.resume(os.getuid(), self.root), range(4)))
            launch.assert_called_once()

    def test_entrypoint_is_only_the_current_normal_user_and_takes_no_arguments(self):
        for uid, euid, argv in ((0, 0, ["resume"]), (UID, 0, ["resume"]),
                               (UID, UID, ["resume", "--command=anything"])):
            with self.subTest(uid=uid, euid=euid, argv=argv), \
                    mock.patch.object(os, "getuid", return_value=uid), \
                    mock.patch.object(os, "geteuid", return_value=euid), \
                    mock.patch.object(resume.sys, "argv", argv), \
                    mock.patch.object(resume, "resume") as run:
                resume.main()
                run.assert_not_called()

    def test_failed_launch_allows_retry_and_symlink_cache_is_refused(self):
        with mock.patch.object(resume, "read_hint", return_value=REQUEST), \
                mock.patch.object(resume.subprocess, "Popen", side_effect=OSError) as launch:
            resume.resume(os.getuid(), self.root)
            resume.resume(os.getuid(), self.root)
            self.assertEqual(launch.call_count, 2)
        marker_dir = self.root / ".cache/localpin/setup-resume"
        marker_dir.rmdir()
        marker_dir.symlink_to(self.root, target_is_directory=True)
        with mock.patch.object(resume, "read_hint", return_value=REQUEST), \
                mock.patch.object(resume.subprocess, "Popen") as launch:
            resume.resume(os.getuid(), self.root)
            launch.assert_not_called()


if __name__ == "__main__":
    unittest.main()
