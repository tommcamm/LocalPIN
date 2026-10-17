# SPDX-License-Identifier: MIT OR Apache-2.0
"""Pure fault-fixture checks; no services, real worker, PAM or VM access."""
import contextlib
import importlib.util
import json
import os
from pathlib import Path
import signal
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('m83_fault_tested', Path(__file__).with_name('fault.py'))
fault = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(fault)


class FaultDispatchTests(unittest.TestCase):
    def journal(self, phase='quiescent'):
        return {'schema': 1, 'uid': 21061, 'request_id': 'a' * 64, 'phase': phase}

    def test_only_explicit_phase_with_actual_pid1_freeze_is_a_fault_point(self):
        for phase in fault.ALLOWED_PHASES:
            self.assertTrue(fault.target_observed(self.journal(phase), phase, True))
            self.assertFalse(fault.target_observed(self.journal(phase), phase, False))
        for phase in ('requested', 'quiescing', 'copied', 'complete', 'failed'):
            self.assertFalse(fault.target_observed(self.journal(phase), 'quiescent', True))
        with self.assertRaisesRegex(RuntimeError, 'unsupported fault phase'):
            fault.target_observed(self.journal(), 'copied', True)

    def test_worker_is_stopped_rechecked_and_marker_durable_before_actual_sigkill(self):
        events = []
        def kill(pid, sig):
            events.append(('signal', pid, sig))
        def record(value):
            events.append(('record', dict(value)))
        with patch.object(fault.os, 'kill', side_effect=kill), patch.object(fault.os, 'waitpid', return_value=(42, signal.SIGKILL)):
            self.assertTrue(fault.kill_observed_worker(42, 'quiescent', self.journal(), record=record,
                read_current=lambda: self.journal(), frozen=lambda: True, stopped_check=lambda pid: True))
        self.assertEqual(events[0], ('signal', 42, signal.SIGSTOP))
        self.assertEqual(events[1][0], 'record')
        self.assertFalse(events[1][1]['sigkill_sent'])
        self.assertEqual(events[2], ('signal', 42, signal.SIGKILL))
        self.assertTrue(events[3][1]['sigkill_sent'])
        self.assertEqual(events[3][1]['worker_exit_signal'], 'SIGKILL')
        self.assertNotIn('uid', events[3][1])

    def test_advanced_or_replaced_journal_resumes_worker_without_killing_or_claiming(self):
        for current in (self.journal('copied'), dict(self.journal(), request_id='b' * 64)):
            with self.subTest(current=current), patch.object(fault.os, 'kill') as kill:
                records = []
                self.assertFalse(fault.kill_observed_worker(42, 'quiescent', self.journal(), record=records.append,
                    read_current=lambda: current, frozen=lambda: True, stopped_check=lambda pid: True))
                self.assertEqual([call.args for call in kill.call_args_list], [(42, signal.SIGSTOP), (42, signal.SIGCONT)])
                self.assertEqual(records, [])

    def test_fsync_marker_failure_prevents_sigkill(self):
        with patch.object(fault.os, 'kill') as kill:
            def failed_record(value):
                raise OSError('synthetic marker sync failure')
            with self.assertRaises(OSError):
                fault.kill_observed_worker(42, 'quiescent', self.journal(), record=failed_record,
                    read_current=lambda: self.journal(), frozen=lambda: True, stopped_check=lambda pid: True)
        self.assertEqual([call.args for call in kill.call_args_list], [(42, signal.SIGSTOP)])

    def test_no_target_observation_never_signals_worker(self):
        with patch.object(fault.os, 'kill') as kill:
            self.assertFalse(fault.kill_observed_worker(42, 'quiescent', self.journal('requested'),
                record=lambda value: None, frozen=lambda: True))
        kill.assert_not_called()

    def test_real_worker_invocation_is_fixed_and_uses_no_test_flags_or_secret_environment(self):
        child = SimpleNamespace(pid=42, poll=lambda: None)
        module = SimpleNamespace(sync_json=lambda *args: None)
        with patch.object(fault.subprocess, 'Popen', return_value=child) as spawn, \
             patch.object(fault, 'read_journal', return_value=self.journal()), \
             patch.object(fault, 'kill_observed_worker', return_value=True):
            fault.run_fault(module, 'quiescent')
        args, kwargs = spawn.call_args
        self.assertEqual(args, (('/usr/libexec/localpin/localpin-accounting', 'run'),))
        self.assertEqual(kwargs['env'], {'PATH': '/usr/sbin:/usr/bin', 'LANG': 'C', 'LC_ALL': 'C'})
        self.assertTrue(kwargs['close_fds'])
        self.assertEqual(kwargs['stdin'], fault.subprocess.DEVNULL)
        self.assertEqual(kwargs['stdout'], fault.subprocess.DEVNULL)
        self.assertEqual(kwargs['stderr'], fault.subprocess.DEVNULL)


class ProtectedJournalTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.journal = self.root / 'transaction.json'
        self.journal.write_text(json.dumps({'schema': 1, 'uid': 21061, 'request_id': 'a' * 64, 'phase': 'quiescent'}))
        self.journal.chmod(0o600)

    @contextlib.contextmanager
    def safe_metadata(self, **changed):
        original_lstat, original_fstat = Path.lstat, os.fstat
        def metadata(info, file=False):
            names = ('st_mode', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
            value = {name: getattr(info, name) for name in names}
            value.update(st_uid=0, st_gid=0)
            if not file:
                value['st_mode'] &= ~0o022
            else:
                value.update(changed)
            return SimpleNamespace(**value)
        with patch.object(Path, 'lstat', lambda path: metadata(original_lstat(path))), \
             patch.object(os, 'fstat', lambda fd: metadata(original_fstat(fd), True)):
            yield

    def test_fixed_protected_journal_accepts_safe_metadata_and_rejects_unsafe_owners_modes_links(self):
        with patch.object(fault, 'JOURNAL', self.journal), self.safe_metadata():
            self.assertEqual(fault.read_journal()['phase'], 'quiescent')
        for changed in ({'st_uid': 1000}, {'st_gid': 1000}, {'st_nlink': 2},
                        {'st_mode': stat.S_IFREG | 0o644}, {'st_size': fault.JOURNAL_BOUND + 1}):
            with self.subTest(changed=changed), patch.object(fault, 'JOURNAL', self.journal), self.safe_metadata(**changed):
                with self.assertRaisesRegex(RuntimeError, 'unsafe protected journal'):
                    fault.read_journal()

    def test_duplicate_fields_and_dangling_symlinks_are_refused(self):
        self.journal.write_text('{"schema":1,"schema":1}')
        with patch.object(fault, 'JOURNAL', self.journal), self.safe_metadata():
            with self.assertRaisesRegex(RuntimeError, 'duplicate'):
                fault.read_journal()
        self.journal.unlink()
        self.journal.symlink_to(self.root / 'absent')
        with patch.object(fault, 'JOURNAL', self.journal), self.safe_metadata():
            with self.assertRaises(OSError):
                fault.read_journal()


if __name__ == '__main__':
    unittest.main()
