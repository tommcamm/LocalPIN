# SPDX-License-Identifier: MIT OR Apache-2.0
"""Synthetic maintenance diagnostics and recovery; never use host services."""
import contextlib
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('accounting_failures_tested', ROOT / 'tools/localpin-accounting.py')
a = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(a)


class CommandDiagnosticsTests(unittest.TestCase):
    def test_checked_command_failures_export_only_closed_categories(self):
        private = b'private-user private-path private-output'
        cases = ((b'File exists', 'file-exists'),
                 (b'already exists', 'file-exists'),
                 (b'is masked', 'unit-masked'),
                 (b'not found', 'unit-not-found'),
                 (b'Access denied', 'access-denied'),
                 (b'Permission denied', 'access-denied'),
                 (b'Job failed', 'job-failed'),
                 (b'unrecognized diagnostic', 'command-failed'))
        for stderr, category in cases:
            with self.subTest(category=category, stderr=stderr), patch.object(
                    a.subprocess, 'run', return_value=SimpleNamespace(
                        returncode=1, stdout=private, stderr=stderr + b' ' + private)):
                with self.assertRaises(a.CommandRefusal) as raised:
                    a.command(['/synthetic/systemctl', 'mask', '--runtime', 'synthetic.service'],
                              operation='mask-authentication')
                self.assertEqual(raised.exception.command,
                                 {'operation': 'mask-authentication', 'returncode': 1, 'detail': category})
                self.assertNotIn('private', str(raised.exception))
                self.assertNotIn('private', json.dumps(raised.exception.command))

    def test_timeout_diagnostics_do_not_export_captured_output(self):
        error = subprocess.TimeoutExpired('/private/path', 1, output=b'private-output', stderr=b'private-error')
        with patch.object(a.subprocess, 'run', side_effect=error):
            with self.assertRaises(a.CommandRefusal) as raised:
                a.command(['/synthetic/systemctl'], operation='isolate-maintenance', timeout=1)
        self.assertEqual(raised.exception.command,
                         {'operation': 'isolate-maintenance', 'returncode': None, 'detail': 'timeout'})
        self.assertNotIn('private', str(raised.exception))

    def test_unknown_operation_cannot_launch_a_command(self):
        with patch.object(a.subprocess, 'run') as run:
            with self.assertRaises(a.MaintenanceRefusal):
                a.command(['/synthetic/systemctl'], operation='private-arbitrary-operation')
        run.assert_not_called()

    def test_original_and_recovery_failure_evidence_are_separate_and_first_wins(self):
        with tempfile.TemporaryDirectory(prefix='localpin-diagnostic-fixture-') as directory:
            work = Path(directory)
            module = SimpleNamespace(
                Refusal=type('SyntheticRefusal', (RuntimeError,), {}),
                atomic_write=lambda path, data: path.write_bytes(data))
            with patch.object(a, 'WORK', work), patch.object(a, 'read_journal', return_value={'phase': 'quiescing'}):
                a.record_failure(module, a.CommandRefusal('isolate-maintenance', 1, 'job-failed'))
                original = (work / 'failure.json').read_bytes()
                a.record_failure(module, RuntimeError('private later error'))
                a.record_failure(module, a.CommandRefusal('unmask-owned', 1, 'access-denied'), recovery=True)
                recovery = (work / 'recovery-failure.json').read_bytes()
                a.record_failure(module, RuntimeError('private later cleanup'), recovery=True)
            self.assertEqual((work / 'failure.json').read_bytes(), original)
            self.assertEqual((work / 'recovery-failure.json').read_bytes(), recovery)
            self.assertEqual(json.loads(original)['command']['operation'], 'isolate-maintenance')
            self.assertEqual(json.loads(recovery)['command']['operation'], 'unmask-owned')
            self.assertNotIn(b'private', original + recovery)


class RestorationTests(unittest.TestCase):
    def test_own_start_jobs_do_not_prevent_observing_restored_login(self):
        jobs = (b'1 localpin-accounting.service start running\n'
                b'2 localpin-accounting-delay.service start running\n')
        with patch.object(a, 'command', return_value=SimpleNamespace(returncode=0, stdout=jobs)) as command:
            self.assertTrue(a.login_restored({'restore_units': ['display-manager.service', 'sshd.service']}))
        checked = [call.args[0][-1] for call in command.call_args_list
                   if call.kwargs['operation'] == 'restoration-status']
        self.assertIn('graphical.target', checked)
        self.assertIn('systemd-logind.service', checked)
        self.assertIn('systemd-user-sessions.service', checked)
        self.assertIn('display-manager.service', checked)
        self.assertIn('sshd.service', checked)

    def test_outstanding_user_stop_or_listener_start_prevents_restored_status(self):
        for job in (b'23 user@1001.service stop running\n', b'24 sshd.service start waiting\n',
                    b'25 localpin-accounting.service stop waiting\n'):
            with self.subTest(job=job), patch.object(
                    a, 'command', return_value=SimpleNamespace(returncode=0, stdout=job)) as command:
                self.assertFalse(a.login_restored({'restore_units': ['sshd.service']}))
                self.assertEqual(command.call_count, 1)

    def test_no_outstanding_jobs_does_not_establish_active_login_units(self):
        def command(args, **kwargs):
            return SimpleNamespace(stdout=b'', returncode=3 if args[-1] == 'systemd-logind.service' else 0)
        with patch.object(a, 'command', side_effect=command):
            self.assertFalse(a.login_restored({'restore_units': []}))

    def test_invalid_job_inventory_is_not_treated_as_restored_login(self):
        with patch.object(a, 'command', return_value=SimpleNamespace(stdout=b'unknown response\n', returncode=0)):
            with self.assertRaises(a.MaintenanceRefusal):
                a.login_restored({'restore_units': []})

    def test_observation_timeout_retains_pending_without_claiming_completion(self):
        state = {'phase': 'aborted', 'restoration': 'pending'}
        with patch.object(a, 'login_restored', return_value=False), \
                patch.object(a.time, 'monotonic', side_effect=[100, 131]), \
                patch.object(a.time, 'sleep') as sleep, patch.object(a, 'save') as save:
            a.observe_restoration(None, state)
        self.assertEqual(state['restoration'], 'pending')
        save.assert_not_called()
        sleep.assert_not_called()

    def test_observation_persistence_failure_retains_pending(self):
        state = {'phase': 'complete', 'restoration': 'pending'}
        with patch.object(a, 'login_restored', return_value=True), \
                patch.object(a, 'save', side_effect=OSError('synthetic persistence refusal')):
            with self.assertRaises(OSError):
                a.observe_restoration(None, state)
        self.assertEqual(state['restoration'], 'pending')

    def test_pending_is_durable_before_restoration_and_failed_queue_keeps_terminal_outcome(self):
        state = {'phase': 'complete', 'restoration': 'pending', 'owned_masks': []}
        events = []
        def save(module, current, phase):
            events.append(('save', current['restoration'], phase))
        def fail(current):
            events.append(('restore', current['restoration'], current['phase']))
            raise a.CommandRefusal('restore-graphical', 1, 'job-failed')
        with patch.object(a, 'save', side_effect=save), patch.object(a, 'restore_login', side_effect=fail), \
                patch.object(a, 'record_failure') as record, patch.object(a, 'publish_hint') as hint, \
                patch.object(a, 'report_outcome') as report, patch.object(a, 'recover_emergency') as emergency:
            a.finish_terminal(None, state)
        self.assertEqual(events, [('save', 'pending', 'complete'), ('save', 'pending', 'complete'),
                                  ('restore', 'pending', 'complete')])
        self.assertEqual(state, {'phase': 'complete', 'restoration': 'pending', 'owned_masks': []})
        self.assertTrue(record.call_args.kwargs['recovery'])
        hint.assert_called_once_with(None, state, 'ready')
        report.assert_called_once_with(state)
        emergency.assert_not_called()

    def test_complete_pending_retry_accepts_changed_valid_counters_without_historical_comparison(self):
        state = {'phase': 'complete', 'restoration': 'pending', 'isolation_requested': True,
                 'persistent': {'synthetic-account': {'sha256': 'historical'}},
                 'restore_units': [], 'owned_masks': []}
        module = SimpleNamespace(locked=contextlib.nullcontext)
        current = {'synthetic-account': ({'sha256': 'changed-after-password-attempt'}, b'changed valid tally')}
        with patch.object(a, 'read_journal', return_value=state), \
                patch.object(a, 'capture', return_value=({}, a.PERSISTENT)), \
                patch.object(a, 'safe_directory') as safe_directory, \
                patch.object(a, 'inventory', return_value=current) as inventory, \
                patch.object(a, 'equivalent') as equivalent, patch.object(a, 'save') as save, \
                patch.object(a, 'thaw') as thaw, patch.object(a, 'restore_login') as restore, \
                patch.object(a, 'login_restored', return_value=True), \
                patch.object(a, 'publish_hint') as hint, patch.object(a, 'report_outcome'):
            a.recover_locked(module)
        inventory.assert_called_once_with(a.TARGET)
        safe_directory.assert_called_once_with(a.TARGET, mode=0o755)
        equivalent.assert_not_called()
        thaw.assert_called_once_with()
        restore.assert_called_once_with(state)
        self.assertEqual(state['phase'], 'complete')
        self.assertEqual(state['restoration'], 'restored')
        self.assertEqual(save.call_count, 3)
        hint.assert_called_once_with(module, state, 'ready')

    def test_complete_pending_retry_refuses_missing_historical_tallies(self):
        state = {'phase': 'complete', 'restoration': 'pending', 'isolation_requested': True,
                 'persistent': {'synthetic-account': {'sha256': 'historical'}}}
        module = SimpleNamespace(locked=contextlib.nullcontext)
        with patch.object(a, 'read_journal', return_value=state), \
                patch.object(a, 'capture', return_value=({}, a.PERSISTENT)), \
                patch.object(a, 'safe_directory'), patch.object(a, 'inventory', return_value={}), \
                patch.object(a, 'finish_terminal') as finish, patch.object(a, 'thaw') as thaw:
            with self.assertRaisesRegex(a.MaintenanceRefusal, 'history is missing'):
                a.recover_locked(module)
        finish.assert_not_called()
        thaw.assert_not_called()

    def test_complete_pending_retry_refuses_absent_canonical_accounting_directory(self):
        state = {'phase': 'complete', 'restoration': 'pending', 'isolation_requested': True,
                 'persistent': {}}
        module = SimpleNamespace(locked=contextlib.nullcontext)
        with patch.object(a, 'read_journal', return_value=state), \
                patch.object(a, 'capture', return_value=({}, a.PERSISTENT)), \
                patch.object(a, 'safe_directory', side_effect=FileNotFoundError('synthetic directory absent')), \
                patch.object(a, 'inventory') as inventory, patch.object(a, 'finish_terminal') as finish:
            with self.assertRaises(FileNotFoundError):
                a.recover_locked(module)
        inventory.assert_not_called()
        finish.assert_not_called()

    def test_aborted_terminal_pending_retry_after_reboot_accepts_current_native_history(self):
        state = {'phase': 'aborted', 'restoration': 'pending', 'isolation_requested': True,
                 'boot': 'previous-boot', 'restore_units': [], 'owned_masks': []}
        stock = (ROOT / 'crates/localpin-auth/tests/fixtures/faillock-stock.conf').read_bytes()
        module = SimpleNamespace(locked=contextlib.nullcontext)
        current = {'synthetic-account': ({'sha256': 'current-boot-history'}, b'current valid tally')}
        with patch.object(a, 'read_journal', return_value=state), \
                patch.object(a, 'capture', return_value=({}, stock)), \
                patch.object(a, 'inventory', return_value=current) as inventory, \
                patch.object(a, 'boot', return_value='new-boot') as boot, \
                patch.object(a, 'equivalent') as equivalent, patch.object(a, 'save'), \
                patch.object(a, 'thaw'), patch.object(a, 'restore_login') as restore, \
                patch.object(a, 'login_restored', return_value=True), \
                patch.object(a, 'publish_hint') as hint, patch.object(a, 'report_outcome'):
            a.recover_locked(module)
        inventory.assert_called_once_with(a.SOURCE, native_source=True)
        equivalent.assert_not_called()
        boot.assert_called_once_with()
        restore.assert_called_once_with(state)
        self.assertEqual(state['restoration'], 'restored')
        hint.assert_called_once_with(module, state, 'aborted')

    def test_unavailable_journal_stream_does_not_overturn_a_terminal_outcome(self):
        for phase in ('complete', 'aborted'):
            state = {'phase': phase, 'restoration': 'restored'}
            with self.subTest(phase=phase), patch('builtins.print', side_effect=BrokenPipeError):
                a.report_outcome(state)
            self.assertEqual(state['phase'], phase)

    def test_terminal_hint_is_published_before_graphical_login_reopens(self):
        for phase, outcome in (('complete', 'ready'), ('aborted', 'aborted')):
            with self.subTest(phase=phase), tempfile.TemporaryDirectory(
                    prefix='localpin-hint-order-fixture-') as directory:
                root = Path(directory)
                journal, hint = root / 'transaction.json', root / 'setup-resume.json'
                state = {'phase': phase, 'restoration': 'pending', 'boot': 'same-boot',
                         'uid': 1000, 'request_id': 'a' * 64, 'owned_masks': [], 'restore_units': []}
                events = []
                def write(path, data, mode=0o600):
                    events.append('hint-published' if path == hint else 'journal-saved')
                    path.write_bytes(data)
                def command(args, **kwargs):
                    events.append(kwargs['operation'])
                    if kwargs['operation'] == 'restore-graphical':
                        self.assertEqual(json.loads(hint.read_bytes())['state'], outcome)
                    return SimpleNamespace(returncode=0, stdout=b'')
                module = SimpleNamespace(atomic_write=write)
                with patch.object(a, 'JOURNAL', journal), patch.object(a, 'RESUME', hint), \
                        patch.object(a, 'boot', return_value='same-boot'), \
                        patch.object(a, 'command', side_effect=command), \
                        patch.object(a, 'login_restored', return_value=True), \
                        patch.object(a, 'report_outcome'), patch.object(a, 'record_failure') as failure:
                    a.finish_terminal(module, state)
                self.assertLess(events.index('hint-published'), events.index('restore-graphical'))
                self.assertLess(events.index('label-resume'), events.index('restore-graphical'))
                self.assertEqual(json.loads(journal.read_bytes())['restoration'], 'restored')
                failure.assert_not_called()


class MaskOwnershipTests(unittest.TestCase):
    def test_released_ownership_is_durable_before_failed_queue_and_not_reused_by_retry(self):
        with tempfile.TemporaryDirectory(prefix='localpin-mask-release-fixture-') as directory:
            journal = Path(directory) / 'transaction.json'
            state = {'phase': 'aborted', 'restoration': 'pending', 'boot': 'same-boot',
                     'owned_masks': ['sshd.service'], 'restore_units': []}
            masks = {'sshd.service': 'maintenance'}
            operations = []
            module = SimpleNamespace(atomic_write=lambda path, data: path.write_bytes(data))
            def command(args, **kwargs):
                operation = kwargs['operation']
                operations.append(operation)
                if operation == 'unmask-owned':
                    self.assertEqual(masks.pop('sshd.service'), 'maintenance')
                elif operation == 'restore-graphical':
                    self.assertEqual(json.loads(journal.read_bytes())['owned_masks'], [])
                    if operations.count('restore-graphical') == 1:
                        raise a.CommandRefusal(operation, 1, 'job-failed')
                return SimpleNamespace(returncode=0, stdout=b'')
            with patch.object(a, 'JOURNAL', journal), patch.object(a, 'boot', return_value='same-boot'), \
                    patch.object(a, 'command', side_effect=command), \
                    patch.object(a, 'login_restored', return_value=True):
                with self.assertRaises(a.CommandRefusal):
                    a.restore_and_observe(module, state)
                persisted = json.loads(journal.read_bytes())
                self.assertEqual(persisted['owned_masks'], [])
                self.assertEqual(persisted['restoration'], 'pending')
                masks['sshd.service'] = 'administrator'
                a.restore_and_observe(module, persisted)
            self.assertEqual(operations.count('unmask-owned'), 1)
            self.assertEqual(masks, {'sshd.service': 'administrator'})
            self.assertEqual(json.loads(journal.read_bytes())['restoration'], 'restored')

    def test_later_boot_does_not_remove_an_administrators_current_runtime_masks(self):
        state = {'boot': 'original-boot', 'owned_masks': ['user@.service', 'sshd.service']}
        with patch.object(a, 'boot', return_value='new-boot'), patch.object(a, 'command') as command:
            a.unmask_owned(state)
        command.assert_not_called()

    def test_worker_refresh_preserves_masks_added_during_the_delayed_handoff(self):
        state = {'owned_masks': ['sddm.service', 'sshd.service', 'user@.service']}
        statuses = {'sddm.service': b'masked-runtime\n', 'sshd.service': b'masked\n',
                    'user@.service': b'static\n'}
        with patch.object(a, 'command', side_effect=lambda args, **kwargs:
                          SimpleNamespace(returncode=0, stdout=statuses[args[-1]])):
            a.refresh_owned_masks(state)
        self.assertEqual(state['owned_masks'], ['user@.service'])
        with patch.object(a, 'command') as command:
            a.unmask_owned(state)
        command.assert_called_once_with(['/usr/bin/systemctl', 'unmask', '--runtime', 'user@.service'],
                                        operation='unmask-owned')

    def test_invalid_owned_unit_is_rejected_before_querying_or_changing_services(self):
        with patch.object(a, 'command') as command:
            with self.assertRaises(a.MaintenanceRefusal):
                a.refresh_owned_masks({'owned_masks': ['private-unreviewed.service']})
        command.assert_not_called()


if __name__ == '__main__':
    unittest.main()
