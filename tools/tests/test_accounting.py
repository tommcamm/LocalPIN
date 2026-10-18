# SPDX-License-Identifier: MIT OR Apache-2.0
"""Synthetic accounting transactions only; no host PAM, cgroups or services."""
import hashlib
import contextlib
import importlib.util
import json
import os
from pathlib import Path
import signal
import stat
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('accounting_tested', ROOT / 'tools/localpin-accounting.py')
a = importlib.util.module_from_spec(spec)
spec.loader.exec_module(a)


class RecordTests(unittest.TestCase):
    def test_records_reject_future_reserved_malformed_and_unknown_status(self):
        record = bytearray(64)
        record[54] = 1
        record[56:64] = (100).to_bytes(8, 'little')
        self.assertTrue(a.valid_native_records(bytes(record), 100))
        self.assertTrue(a.valid_native_records(b'', 100))
        self.assertFalse(a.valid_native_records(bytes(record), 99))
        self.assertFalse(a.valid_native_records(bytes(record[:-1]), 100))
        for offset, value in ((52, 1), (54, 8), (54, 6)):
            changed = record.copy()
            changed[offset] = value
            self.assertFalse(a.valid_native_records(changed, 100))

    def test_only_source_primary_gid_can_be_converted(self):
        account = SimpleNamespace(pw_uid=21061, pw_gid=21061)
        native = SimpleNamespace(st_uid=21061, st_gid=21061, st_mode=stat.S_IFREG | 0o660, st_size=64)
        self.assertTrue(a.canonical_tally_metadata(native, account, native_source=True))
        self.assertFalse(a.canonical_tally_metadata(native, account))
        native.st_gid = 21062
        self.assertFalse(a.canonical_tally_metadata(native, account, native_source=True))

    def test_exact_copy_preserves_data_metadata_xattrs_and_refuses_replace(self):
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / 'tally'
            raw = b'synthetic tally bytes'
            snap = {'uid': os.getuid(), 'gid': os.getgid(), 'mode': 0o660,
                    'atime_ns': 1000000000, 'mtime_ns': 2000000000,
                    'xattrs': {'user.localpin': b'exact'.hex()}}
            a.copy_exact(target, snap, raw)
            self.assertEqual(target.read_bytes(), raw)
            self.assertEqual(target.stat().st_mtime_ns, snap['mtime_ns'])
            self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o660)
            self.assertEqual(os.getxattr(target, 'user.localpin'), b'exact')
            with self.assertRaises(FileExistsError):
                a.copy_exact(target, snap, b'')
            self.assertEqual(target.read_bytes(), raw)

    def test_capture_preserves_source_access_timestamp(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'faillock.conf'
            path.write_bytes(b'synthetic config')
            path.chmod(0o644)
            os.utime(path, ns=(1000000000, 2000000000))
            original = os.fstat
            def metadata(fd):
                info = original(fd)
                names = ('st_mode', 'st_nlink', 'st_size', 'st_atime_ns', 'st_mtime_ns')
                return SimpleNamespace(**{name: getattr(info, name) for name in names}, st_uid=0, st_gid=0)
            with patch.object(a.os, 'fstat', side_effect=metadata), patch.object(a.os, 'listxattr', return_value=['security.selinux']), patch.object(a.os, 'getxattr', return_value=b'synthetic-label'):
                snapshot, raw = a.capture(path)
            self.assertEqual(raw, b'synthetic config')
            self.assertEqual(snapshot['atime_ns'], 1000000000)
            self.assertEqual(path.stat().st_atime_ns, 1000000000)


class CgroupLayoutTests(unittest.TestCase):
    def test_init_scope_waits_for_transient_executor_to_leave(self):
        with patch.object(Path, 'read_text', side_effect=['1\n42\n', '1\n']) as read, patch.object(a.time, 'monotonic', side_effect=[100, 100.01]), patch.object(a.time, 'sleep') as sleep:
            a.wait_init_scope_idle()
        self.assertEqual(read.call_count, 2)
        sleep.assert_called_once_with(0.02)

    def test_init_scope_wait_refuses_missing_inventory_without_retry(self):
        with patch.object(Path, 'read_text', side_effect=FileNotFoundError) as read, patch.object(a.time, 'sleep') as sleep:
            with self.assertRaises(FileNotFoundError):
                a.wait_init_scope_idle()
        read.assert_called_once_with()
        sleep.assert_not_called()

    def test_init_scope_wait_never_accepts_malformed_or_noninit_inventory(self):
        for value in ('', 'invalid\n', '1\n1\n', '2\n', '1\n42\n'):
            with self.subTest(value=value), patch.object(Path, 'read_text', return_value=value), patch.object(a.time, 'monotonic', side_effect=[100, 110]), patch.object(a.time, 'sleep') as sleep:
                with self.assertRaisesRegex(RuntimeError, 'unexpected init scope processes'):
                    a.wait_init_scope_idle()
                sleep.assert_not_called()

    def test_root_cgroup_accepts_only_proven_kernel_threads_and_disappearing_tasks(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'cgroup.procs').write_text('42\n99\n')
            with patch.object(a, 'CGROUP', root), patch.object(Path, 'read_bytes', return_value=b'Name:\tkworker\nKthread:\t1\n'):
                a.require_root_kernel_tasks()
            for status in (b'Name:\tkworker\nKthread:\t0\n', b'Name:\tkworker\n', b'Kthread:\t1\nKthread:\t0\n'):
                with self.subTest(status=status), patch.object(a, 'CGROUP', root), patch.object(Path, 'read_bytes', return_value=status):
                    with self.assertRaisesRegex(RuntimeError, 'userspace task'):
                        a.require_root_kernel_tasks()
            with patch.object(a, 'CGROUP', root), patch.object(Path, 'read_bytes', side_effect=FileNotFoundError):
                a.require_root_kernel_tasks()
            with patch.object(a, 'CGROUP', root), patch.object(Path, 'read_bytes', side_effect=PermissionError):
                with self.assertRaises(PermissionError):
                    a.require_root_kernel_tasks()
            (root / 'cgroup.procs').write_text('0\n')
            with patch.object(a, 'CGROUP', root), self.assertRaisesRegex(RuntimeError, 'invalid root'):
                a.require_root_kernel_tasks()

    def test_only_empty_reviewed_mount_cgroups_join_the_barrier(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'cgroup.controllers').touch()
            (root / 'cgroup.procs').write_text('')
            for name in ('init.scope', 'system.slice', *a.STOCK_MOUNT_GROUPS):
                directory = root / name
                directory.mkdir()
                (directory / 'cgroup.procs').write_text('1\n' if name == 'init.scope' else '')
                (directory / 'cgroup.events').write_text('populated 0\nfrozen 0\n')
                (directory / 'cgroup.freeze').touch()
                (directory / 'cgroup.kill').touch()
            maintenance = root / 'localpinmaintenance.slice'
            maintenance.mkdir()
            (maintenance / 'cgroup.procs').write_text('')
            (maintenance / 'localpin-accounting.service').mkdir()
            original_read = Path.read_text
            def read(path, *args, **kwargs):
                if path == Path('/proc/self/cgroup'):
                    return '0::/localpinmaintenance.slice/localpin-accounting.service\n'
                return original_read(path, *args, **kwargs)
            with patch.object(a, 'CGROUP', root), patch.object(Path, 'read_text', read):
                self.assertEqual({p.name for p in a.cgroup_layout()}, {'system.slice', *a.STOCK_MOUNT_GROUPS})
                init_procs = root / 'init.scope/cgroup.procs'
                init_procs.write_text('1\n42\n')
                with self.assertRaisesRegex(RuntimeError, 'unexpected init scope processes'):
                    a.cgroup_layout()
                init_procs.write_text('1\n')
                first = root / a.STOCK_MOUNT_GROUPS[0] / 'cgroup.events'
                first.write_text('populated 1\nfrozen 0\n')
                with self.assertRaisesRegex(RuntimeError, 'unexpected task in stock mount'):
                    a.cgroup_layout()
                first.write_text('populated 0\nfrozen 0\n')
                (root / 'foreign.service').mkdir()
                with self.assertRaisesRegex(RuntimeError, 'unsupported top-level'):
                    a.cgroup_layout()


class NativeRPMLockTests(unittest.TestCase):
    CHILD = '''import fcntl, os, sys
fd = os.open(sys.argv[1], os.O_RDWR)
try:
    fcntl.lockf(fd, fcntl.LOCK_EX | fcntl.LOCK_NB, 0, 0, os.SEEK_SET)
except BlockingIOError:
    print('busy', flush=True)
else:
    print('locked', flush=True)
    if len(sys.argv) > 2:
        sys.stdin.read(1)
os.close(fd)
'''

    def setUp(self):
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        directory = Path(self.stack.enter_context(tempfile.TemporaryDirectory()))
        self.path = directory / '.rpm.lock'
        self.path.touch(mode=0o644)
        self.path.chmod(0o644)
        self.m = SimpleNamespace(safe_parents=lambda path: None)
        self.stack.enter_context(patch.object(a, 'RPM_LOCK', self.path))
        self.stack.enter_context(patch.object(a, 'command', return_value=SimpleNamespace(stdout=str(self.path).encode())))
        original = os.fstat
        def metadata(fd):
            info = original(fd)
            names = ('st_mode', 'st_nlink', 'st_dev', 'st_ino')
            return SimpleNamespace(**{name: getattr(info, name) for name in names}, st_uid=0, st_gid=0)
        self.stack.enter_context(patch.object(a.os, 'fstat', side_effect=metadata))

    def child(self, hold=False):
        return subprocess.Popen([sys.executable, '-c', self.CHILD, str(self.path), *(['hold'] if hold else [])],
                                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    def test_existing_native_transaction_excludes_setup_without_waiting(self):
        child = self.child(hold=True)
        try:
            self.assertEqual(child.stdout.readline().strip(), 'locked')
            with self.assertRaisesRegex(a.RPMBusy, 'native RPM transaction is active'):
                with a.rpm_locked(self.m):
                    self.fail('setup entered a busy native transaction')
        finally:
            child.communicate('x', timeout=5)
        self.assertEqual(child.returncode, 0)

    def test_setup_excludes_native_transaction_then_releases_it(self):
        with a.rpm_locked(self.m):
            child = self.child()
            output, _ = child.communicate(timeout=5)
            self.assertEqual(output.strip(), 'busy')
        child = self.child()
        output, _ = child.communicate(timeout=5)
        self.assertEqual(output.strip(), 'locked')

    def test_changed_macro_or_missing_file_refuses_without_creating_lock(self):
        with patch.object(a, 'command', return_value=SimpleNamespace(stdout=b'/alternate/.rpm.lock')):
            with self.assertRaisesRegex(RuntimeError, 'unsupported native RPM'):
                with a.rpm_locked(self.m):
                    self.fail('alternate lock accepted')
        with patch.object(a, 'command', side_effect=[SimpleNamespace(stdout=str(self.path).encode()), SimpleNamespace(stdout=b'/new-native/.rpm.lock')]):
            with self.assertRaisesRegex(RuntimeError, 'unsupported native RPM'):
                with a.rpm_locked(self.m):
                    self.fail('lock path changed before acquisition was accepted')
        self.path.unlink()
        with self.assertRaises(FileNotFoundError):
            with a.rpm_locked(self.m):
                self.fail('missing lock created')
        self.assertFalse(self.path.exists())

    def test_validation_failure_after_acquisition_closes_descriptor_and_unlocks(self):
        with patch.object(a, 'validate_rpm_lock', side_effect=[None, a.MaintenanceRefusal('synthetic replaced lock')]):
            with self.assertRaisesRegex(RuntimeError, 'replaced lock'):
                with a.rpm_locked(self.m):
                    self.fail('invalid lock accepted')
        child = self.child()
        output, _ = child.communicate(timeout=5)
        self.assertEqual(output.strip(), 'locked')


class TransactionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.paths = {}
        for name, relative in (('SOURCE', 'run/faillock'), ('TARGET', 'var/lib/faillock'),
                               ('CONFIG', 'etc/security/faillock.conf'), ('WORK', 'control/accounting'),
                               ('BACKUP', 'control/accounting/backup'), ('JOURNAL', 'control/accounting/transaction.json'),
                               ('RESUME', 'setup-resume.json'), ('REGISTRY', 'registry')):
            path = self.root / relative
            self.paths[name] = path
            path.parent.mkdir(parents=True, exist_ok=True)
            self.addCleanup(patch.stopall)
            patch.object(a, name, path).start()
        a.SOURCE.mkdir()
        a.TARGET.mkdir()
        a.WORK.mkdir(exist_ok=True)
        a.CONFIG.write_bytes((ROOT / 'crates/localpin-auth/tests/fixtures/faillock-stock.conf').read_bytes())
        self.state = {'schema': 1, 'uid': 21061, 'boot': 'test-boot', 'request_id': 'a' * 64,
                      'owned_masks': [], 'restore_units': []}
        self.events = []
        def atomic(path, data, mode=0o600):
            self.events.append(('journal' if path == a.JOURNAL else 'hint', json.loads(data).get('phase')))
            path.write_bytes(data)
            path.chmod(mode)
        self.m = SimpleNamespace(atomic_write=atomic, locked=contextlib.nullcontext, Refusal=type('SyntheticRefusal', (RuntimeError,), {}))
        patch.object(a, 'rpm_locked', lambda module: contextlib.nullcontext()).start()
        patch.object(a, 'safe_directory').start()
        patch.object(a, 'boot', return_value='test-boot').start()
        patch.object(a, 'capture', side_effect=self.capture).start()
        patch.object(a, 'command', return_value=SimpleNamespace(stdout=b'btrfs', returncode=0)).start()
        original_copy = a.copy_exact
        def copy(path, snapshot, raw):
            self.events.append(('copy', str(path)))
            # Synthetic test users cannot chown to the fixture UID/GID.
            original_copy(path, dict(snapshot, uid=os.getuid(), gid=os.getgid()), raw)
        patch.object(a, 'copy_exact', side_effect=copy).start()
        self.addCleanup(patch.stopall)

    def capture(self, path, **kwargs):
        raw = path.read_bytes()
        return {'uid': 21061 if kwargs.get('tally') else 0,
                'gid': 21061 if kwargs.get('native_source') else 0,
                'mode': 0o660 if kwargs.get('tally') else 0o644,
                'size': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(),
                'atime_ns': 1000000000, 'mtime_ns': 2000000000, 'xattrs': {}}, raw

    def test_all_accounts_copied_and_backed_up_before_policy_and_ready_hint(self):
        a.SOURCE.joinpath('alice').write_bytes(bytes(64))
        a.SOURCE.joinpath('bob').write_bytes(bytes(128))
        a.migrate(self.m, self.state)
        self.assertEqual(a.CONFIG.read_bytes(), a.PERSISTENT)
        for name in ('alice', 'bob'):
            self.assertEqual((a.TARGET / name).read_bytes(), (a.SOURCE / name).read_bytes())
            self.assertEqual((a.BACKUP / 'volatile' / name).read_bytes(), (a.SOURCE / name).read_bytes())
        self.assertEqual(self.state['phase'], 'complete')
        phases = [value for kind, value in self.events if kind == 'journal']
        self.assertEqual(phases, ['backed-up', 'copied', 'switched', 'complete'])
        self.assertFalse(a.RESUME.exists())
        with patch.object(a, 'login_restored', return_value=True):
            a.finish_terminal(self.m, self.state)
        self.assertEqual(json.loads(a.RESUME.read_text())['uid'], self.state['uid'])
        self.assertEqual(stat.S_IMODE(a.BACKUP.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE((a.BACKUP / 'volatile').stat().st_mode), 0o700)

    def test_conflicting_destination_refuses_before_backup_or_config_change(self):
        a.SOURCE.joinpath('alice').write_bytes(bytes(64))
        a.TARGET.joinpath('alice').write_bytes(bytes(128))
        before = a.CONFIG.read_bytes()
        with self.assertRaisesRegex(RuntimeError, 'conflicting'):
            a.migrate(self.m, self.state)
        self.assertEqual(a.CONFIG.read_bytes(), before)
        self.assertFalse(a.BACKUP.exists())
        self.assertEqual(a.TARGET.joinpath('alice').read_bytes(), bytes(128))

    def test_partial_copy_failure_never_switches_config_and_retains_source_and_backup(self):
        a.SOURCE.joinpath('alice').write_bytes(bytes(64))
        before = a.CONFIG.read_bytes()
        original_copy = a.copy_exact
        def fail_destination(path, snapshot, raw):
            if path.parent == a.TARGET:
                raise OSError('synthetic disk failure')
            return original_copy(path, snapshot, raw)
        with patch.object(a, 'copy_exact', side_effect=fail_destination), self.assertRaises(OSError):
            a.migrate(self.m, self.state)
        self.assertEqual(a.CONFIG.read_bytes(), before)
        self.assertEqual(a.SOURCE.joinpath('alice').read_bytes(), bytes(64))
        self.assertEqual((a.BACKUP / 'volatile/alice').read_bytes(), bytes(64))
        self.assertFalse(a.RESUME.exists())

    def test_boot_mismatch_refuses_before_any_copy_or_policy_mutation(self):
        self.state['boot'] = 'different-boot'
        before = a.CONFIG.read_bytes()
        with self.assertRaisesRegex(RuntimeError, 'same-boot'):
            a.migrate(self.m, self.state)
        self.assertEqual(a.CONFIG.read_bytes(), before)
        self.assertFalse(a.BACKUP.exists())

    def test_oversized_journal_refuses_before_write(self):
        state = dict(self.state, oversized='x' * a.JOURNAL_BOUND)
        with self.assertRaisesRegex(RuntimeError, 'oversized accounting journal'):
            a.save(self.m, state, 'requested')
        self.assertFalse(a.JOURNAL.exists())

    def test_post_switch_recovery_verifies_private_backups_and_can_finish_after_reboot(self):
        a.SOURCE.joinpath('alice').write_bytes(bytes(64))
        a.migrate(self.m, self.state)
        self.state['phase'] = 'failed'
        a.RESUME.unlink(missing_ok=True)
        checked_modes = []
        def directories(path, *, mode=None):
            if path == a.BACKUP / 'volatile':
                checked_modes.append(mode)
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), mode)
        with patch.object(a, 'read_journal', return_value=self.state), patch.object(a, 'boot', return_value='later-boot'), patch.object(a, 'safe_directory', side_effect=directories), patch.object(a, 'thaw'), patch.object(a, 'restore_login'):
            a.recover(self.m)
        self.assertEqual(checked_modes, [0o700])
        self.assertEqual(self.state['phase'], 'complete')
        self.assertTrue(a.RESUME.exists())

    def test_post_switch_recovery_refuses_changed_counters_without_overwriting(self):
        a.SOURCE.joinpath('alice').write_bytes(bytes(64))
        a.migrate(self.m, self.state)
        self.state['phase'] = 'failed'
        a.TARGET.joinpath('alice').write_bytes(bytes(128))
        with patch.object(a, 'read_journal', return_value=self.state), patch.object(a, 'thaw'), patch.object(a, 'restore_login') as restore:
            with self.assertRaisesRegex(RuntimeError, 'persistent accounting differs'):
                a.recover(self.m)
        self.assertEqual(a.TARGET.joinpath('alice').read_bytes(), bytes(128))
        self.assertEqual(self.state['phase'], 'failed')
        restore.assert_not_called()

    def test_volatile_recovery_aborts_same_boot_and_refuses_lost_source_after_reboot(self):
        a.SOURCE.joinpath('alice').write_bytes(bytes(64))
        self.state['phase'] = 'failed'
        with patch.object(a, 'read_journal', return_value=self.state), patch.object(a, 'thaw'), patch.object(a, 'restore_login'):
            a.recover(self.m)
        self.assertEqual(self.state['phase'], 'aborted')
        self.state['phase'] = 'failed'
        with patch.object(a, 'read_journal', return_value=self.state), patch.object(a, 'boot', return_value='later-boot'):
            with self.assertRaisesRegex(RuntimeError, 'cannot be recovered after reboot'):
                a.recover(self.m)
        self.assertEqual(self.state['phase'], 'failed')

    def test_prebarrier_refusal_automatically_restores_only_untouched_sameboot_authority(self):
        a.SOURCE.joinpath('alice').write_bytes(bytes(64))
        self.state['phase'] = 'quiescing'
        self.m.load = lambda: None
        with patch.object(a, 'read_journal', return_value=self.state), patch.object(a, 'restore_login') as restore:
            self.assertTrue(a.abort_untouched_request(self.m))
        self.assertEqual(self.state['phase'], 'aborted')
        restore.assert_called_once_with(self.state)
        for changes in ({'phase': 'failed'}, {'phase': 'barrier-started'}, {'phase': 'copied'}, {'phase': 'quiescing', 'boot': 'older-boot'},
                        {'phase': 'quiescing', 'source': {}}):
            state = dict(self.state, **changes)
            with self.subTest(changes=changes), patch.object(a, 'read_journal', return_value=state), patch.object(a, 'restore_login') as restore:
                self.assertFalse(a.abort_untouched_request(self.m))
                restore.assert_not_called()

    def test_unisolated_busy_request_aborts_without_any_service_action(self):
        self.state.update(phase='requested', isolation_requested=False)
        self.m.load = lambda: None
        with patch.object(a, 'read_journal', return_value=self.state), patch.object(a, 'restore_login') as restore, patch.object(a, 'command') as command:
            self.assertTrue(a.abort_untouched_request(self.m))
        self.assertEqual(self.state['phase'], 'aborted')
        restore.assert_not_called()
        self.assertTrue(all(call.kwargs['operation'] == 'label-resume' for call in command.call_args_list))

    def failure_fixture(self):
        self.state.update(phase='requested', isolation_requested=False,
                          owned_masks=['user@.service'], restore_units=['display-manager.service'])
        self.m.load = lambda: None
        self.m.setup_scope = lambda *args: {}
        self.m.validate_policy = lambda **kwargs: None
        patch.object(a, 'read_journal', return_value=self.state).start()
        patch.object(a, 'refresh_owned_masks').start()

    def test_mask_failure_unmasks_partial_result_without_stopping_or_isolating(self):
        self.failure_fixture()
        operations = []
        def command(args, **kwargs):
            operation = kwargs['operation']
            operations.append(operation)
            if operation == 'mask-authentication':
                raise a.CommandRefusal(operation, 1, 'file-exists')
            return SimpleNamespace(returncode=0, stdout=b'')
        before = a.CONFIG.read_bytes()
        with patch.object(a, 'command', side_effect=command), patch.object(a, 'recover_emergency') as emergency:
            a.run_maintenance(self.m)
        self.assertEqual(operations, ['mask-authentication', 'label-resume', 'unmask-owned'])
        emergency.assert_not_called()
        self.assertEqual(self.state['phase'], 'aborted')
        self.assertEqual(self.state['restoration'], 'not-needed')
        self.assertFalse(self.state['isolation_requested'])
        self.assertEqual(json.loads(a.RESUME.read_text())['state'], 'aborted')
        self.assertEqual(json.loads((a.WORK / 'failure.json').read_text())['command']['operation'], 'mask-authentication')
        self.assertEqual(a.CONFIG.read_bytes(), before)
        self.assertFalse(a.BACKUP.exists())

    def test_isolation_failure_waits_for_restoration_and_preserves_original_failure(self):
        self.failure_fixture()
        operations = []
        def command(args, **kwargs):
            operation = kwargs['operation']
            operations.append(operation)
            if operation == 'isolate-maintenance':
                raise a.CommandRefusal(operation, 1, 'job-failed')
            return SimpleNamespace(returncode=0, stdout=b'')
        with patch.object(a, 'command', side_effect=command), patch.object(a, 'login_restored', side_effect=[False, True]), patch.object(a.time, 'sleep'), patch.object(a, 'recover_emergency') as emergency:
            a.run_maintenance(self.m)
        self.assertEqual(operations[:3], ['mask-authentication', 'stop-sessions', 'isolate-maintenance'])
        self.assertIn('restore-graphical', operations)
        self.assertEqual(self.state['phase'], 'aborted')
        self.assertEqual(self.state['restoration'], 'restored')
        self.assertEqual(self.state['failure_operation'], 'isolate-maintenance')
        emergency.assert_not_called()
        self.assertFalse(a.BACKUP.exists())

    def test_mask_cleanup_failure_stays_pending_without_losing_original_failure(self):
        self.failure_fixture()
        def command(args, **kwargs):
            operation = kwargs['operation']
            if operation in ('mask-authentication', 'unmask-owned'):
                raise a.CommandRefusal(operation, 1, 'command-failed')
            return SimpleNamespace(returncode=0, stdout=b'')
        with patch.object(a, 'command', side_effect=command), patch.object(a, 'recover_emergency') as emergency:
            a.run_maintenance(self.m)
        self.assertEqual(self.state['restoration'], 'pending')
        self.assertEqual(json.loads((a.WORK / 'failure.json').read_text())['command']['operation'], 'mask-authentication')
        self.assertEqual(json.loads((a.WORK / 'recovery-failure.json').read_text())['command']['operation'], 'unmask-owned')
        emergency.assert_not_called()


class RecoveryAndBarrierTests(unittest.TestCase):
    def test_untouched_lock_refusal_never_selects_emergency_even_if_abort_lock_is_busy(self):
        m = SimpleNamespace(Refusal=type('SyntheticRefusal', (RuntimeError,), {}))
        with patch.object(a.sys, 'argv', ['accounting', 'run']), patch.object(a.os, 'getuid', return_value=0), patch.object(a.os, 'geteuid', return_value=0), patch.object(a, 'integration', return_value=m), patch.object(Path, 'read_text', return_value='0::/localpinmaintenance.slice/localpin-accounting.service\n'), patch.object(a, 'run_maintenance', side_effect=m.Refusal('integration busy')), patch.object(a, 'record_failure'), patch.object(a, 'abort_untouched_request', return_value=False), patch.object(a, 'desktop_untouched', return_value=True), patch.object(a, 'recover_emergency') as emergency:
            a.main()
        emergency.assert_not_called()

    def test_scheduling_refuses_busy_native_rpm_before_any_journal_or_service_action(self):
        with patch.object(a, 'rpm_locked', side_effect=a.RPMBusy('busy')), patch.object(a, 'schedule_locked') as schedule:
            with self.assertRaises(a.RPMBusy):
                a.schedule(None, 21061)
        schedule.assert_not_called()

    def barrier_fixture(self):
        state = {'schema': 1, 'uid': 21061, 'boot': 'same-boot', 'phase': 'requested', 'owned_masks': []}
        events = []
        groups = [Path('/synthetic/system.slice'), Path('/synthetic/user.slice')]
        @contextlib.contextmanager
        def rpm_lock(module):
            events.append(('rpm-locked',))
            yield
        m = SimpleNamespace(locked=contextlib.nullcontext, load=lambda: None,
                            setup_scope=lambda *args: {},
                            validate_policy=lambda **kwargs: events.append(('policy-validated', kwargs)))
        patches = [patch.object(a, 'read_journal', return_value=state),
                   patch.object(a, 'record_failure'),
                   patch.object(a, 'abort_untouched_request', return_value=False),
                   patch.object(a, 'desktop_untouched', return_value=False),
                   patch.object(a, 'boot', return_value='same-boot'),
                   patch.object(a, 'REGISTRY', Path('/nonexistent-synthetic-registry')),
                   patch.object(a, 'mask_authentication'),
                   patch.object(a, 'rpm_locked', rpm_lock),
                   patch.object(a, 'command', side_effect=lambda args, **kwargs: events.append(('command', tuple(args)))),
                   patch.object(a, 'wait_init_scope_idle', side_effect=lambda: events.append(('init-idle',))),
                   patch.object(a, 'cgroup_layout', return_value=groups),
                   patch.object(a.os, 'pidfd_open', side_effect=lambda *args: (events.append(('pidfd-open',)), os.open('/dev/null', os.O_RDONLY | os.O_CLOEXEC))[1]),
                   patch.object(a.os, 'fork', return_value=12345),
                   patch.object(a.os, 'write', return_value=1),
                   patch.object(a.os, 'waitpid', return_value=(12345, 0)),
                   patch.object(a, 'save', side_effect=lambda m, s, phase: events.append(('phase', phase))),
                   patch.object(a, 'cgroup_write', side_effect=lambda path, name, value: events.append((name, path.name, value))),
                   patch.object(a, 'wait_cgroup', side_effect=lambda path, field, value: events.append(('wait', path.name, field, value))),
                   patch.object(a, 'cgroup_events', return_value={'frozen': '1', 'populated': '0'}),
                   patch.object(a, 'migrate', side_effect=lambda *args: events.append(('migrate',))),
                   patch.object(a, 'thaw', side_effect=lambda: events.append(('thaw',))),
                   patch.object(a, 'recover_emergency', side_effect=lambda: events.append(('emergency',))),
                   patch.object(a, 'finish_terminal', side_effect=lambda m, s: events.append(('restore',)))]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)
        return m, state, groups, events

    def test_kernel_barrier_kills_and_observes_empty_groups_before_migration(self):
        m, state, groups, events = self.barrier_fixture()
        a.run_maintenance(m)
        migration = events.index(('migrate',))
        for path in groups:
            self.assertLess(events.index(('cgroup.kill', path.name, '1')), migration)
            self.assertLess(events.index(('wait', path.name, 'populated', '0')), migration)
        self.assertLess(events.index(('wait', 'init.scope', 'frozen', '1')), migration)
        self.assertEqual(a.cgroup_layout.call_count, 3)
        self.assertEqual(events[-2:], [('thaw',), ('restore',)])
        self.assertTrue(state['barrier']['init_frozen'])
        self.assertLess(events.index(('pidfd-open',)), events.index(('phase', 'barrier-started')))
        self.assertLess(events.index(('rpm-locked',)), events.index(('phase', 'quiescing')))
        self.assertLess(events.index(('rpm-locked',)), events.index(('policy-validated', {'allow_volatile': True})))
        self.assertLess(events.index(('policy-validated', {'allow_volatile': True})), events.index(('phase', 'quiescing')))
        self.assertLess(events.index(('phase', 'quiescing')), events.index(('command', ('/usr/bin/systemctl', 'isolate', 'localpin-accounting.target'))))
        drain = events.index(('command', ('/usr/bin/systemctl', 'stop', 'display-manager.service',
                                          'user@*.service', 'user-runtime-dir@*.service', 'user.slice')))
        self.assertLess(drain, events.index(('command', ('/usr/bin/systemctl', 'isolate', 'localpin-accounting.target'))))
        self.assertLess(events.index(('command', ('/usr/bin/systemctl', 'isolate', 'localpin-accounting.target'))), events.index(('init-idle',)))
        self.assertLess(events.index(('init-idle',)), events.index(('pidfd-open',)))
        self.assertTrue(state['isolation_requested'])

    def test_init_scope_that_never_becomes_idle_refuses_before_barrier(self):
        wait_idle = a.wait_init_scope_idle
        m, state, groups, events = self.barrier_fixture()
        with patch.object(a, 'wait_init_scope_idle', side_effect=wait_idle), patch.object(Path, 'read_text', return_value='1\n42\n'), patch.object(a.time, 'monotonic', side_effect=[100, 110]), patch.object(a.time, 'sleep') as sleep:
            with self.assertRaisesRegex(RuntimeError, 'unexpected init scope processes'):
                a.run_maintenance(m)
        sleep.assert_not_called()
        a.cgroup_layout.assert_not_called()
        self.assertNotIn(('phase', 'barrier-started'), events)
        self.assertNotIn(('pidfd-open',), events)
        self.assertFalse(any(event[0] in ('cgroup.freeze', 'cgroup.kill', 'migrate', 'thaw') for event in events))

    def test_init_scope_process_reappearing_after_freeze_refuses_and_thaws(self):
        m, state, groups, events = self.barrier_fixture()
        with patch.object(a, 'cgroup_layout', side_effect=[groups, a.MaintenanceRefusal('unexpected init scope processes')]):
            with self.assertRaisesRegex(RuntimeError, 'unexpected init scope processes'):
                a.run_maintenance(m)
        self.assertIn(('wait', 'init.scope', 'frozen', '1'), events)
        freezes = [event for event in events if event[0] == 'cgroup.freeze']
        self.assertEqual(freezes, [('cgroup.freeze', 'init.scope', '1')])
        self.assertFalse(any(event[0] in ('cgroup.kill', 'migrate') for event in events))
        self.assertEqual(events[-2:], [('thaw',), ('emergency',)])

    def test_empty_slice_disappearing_before_manager_freeze_is_not_used_afterward(self):
        m, state, groups, events = self.barrier_fixture()
        remaining = groups[:1]
        with patch.object(a, 'cgroup_layout', side_effect=[groups, remaining, remaining]):
            a.run_maintenance(m)
        init_wait = events.index(('wait', 'init.scope', 'frozen', '1'))
        slice_freeze = events.index(('cgroup.freeze', remaining[0].name, '1'))
        self.assertLess(init_wait, slice_freeze)
        self.assertNotIn(('cgroup.freeze', groups[1].name, '1'), events)
        self.assertNotIn(('cgroup.kill', groups[1].name, '1'), events)
        self.assertIn(('migrate',), events)

    def test_new_allowed_slice_joins_fresh_inventory_after_manager_is_frozen(self):
        m, state, groups, events = self.barrier_fixture()
        added = Path('/synthetic/machine.slice')
        refreshed = [*groups, added]
        inventories = []
        def layout():
            inventories.append(len(inventories) + 1)
            events.append(('inventory', inventories[-1]))
            if len(inventories) == 1:
                return groups
            self.assertIn(('wait', 'init.scope', 'frozen', '1'), events)
            return refreshed
        with patch.object(a, 'cgroup_layout', side_effect=layout):
            a.run_maintenance(m)
        self.assertEqual(inventories, [1, 2, 3])
        init_wait = events.index(('wait', 'init.scope', 'frozen', '1'))
        fresh_inventory = events.index(('inventory', 2))
        self.assertLess(init_wait, fresh_inventory)
        for path in refreshed:
            self.assertLess(fresh_inventory, events.index(('cgroup.freeze', path.name, '1')))
        migration = events.index(('migrate',))
        for event in (('wait', added.name, 'frozen', '1'),
                      ('cgroup.kill', added.name, '1'),
                      ('wait', added.name, 'populated', '0')):
            self.assertLess(events.index(event), migration)
        self.assertIn(added.name, state['barrier']['empty_frozen_slices'])

    def test_manager_freeze_timeout_never_freezes_normal_groups_or_migrates(self):
        m, state, groups, events = self.barrier_fixture()
        with patch.object(a, 'wait_cgroup', side_effect=RuntimeError('synthetic PID1 freeze timeout')):
            with self.assertRaisesRegex(RuntimeError, 'PID1 freeze timeout'):
                a.run_maintenance(m)
        freezes = [event for event in events if event[0] == 'cgroup.freeze']
        self.assertEqual(freezes, [('cgroup.freeze', 'init.scope', '1')])
        self.assertEqual(a.cgroup_layout.call_count, 1)
        self.assertFalse(any(event[0] == 'cgroup.kill' for event in events))
        self.assertNotIn(('migrate',), events)
        self.assertEqual(events[-2:], [('thaw',), ('emergency',)])

    def test_pidfd_failure_refuses_before_barrier_and_never_falls_back_to_numeric_pid(self):
        m, state, groups, events = self.barrier_fixture()
        with patch.object(a.os, 'pidfd_open', side_effect=OSError('synthetic pidfd unavailable')), patch.object(a.os, 'kill') as kill:
            with self.assertRaisesRegex(OSError, 'pidfd unavailable'):
                a.run_maintenance(m)
        self.assertNotIn(('phase', 'barrier-started'), events)
        self.assertFalse(any(event[0] == 'cgroup.freeze' for event in events))
        kill.assert_not_called()

    def test_fork_failure_closes_both_pipe_ends_and_parent_pidfd_before_barrier(self):
        m, state, groups, events = self.barrier_fixture()
        descriptors = []
        def pidfd_open(*args):
            fd = os.open('/dev/null', os.O_RDONLY | os.O_CLOEXEC)
            descriptors.append(fd)
            return fd
        original_pipe = os.pipe2
        def pipe(flags):
            result = original_pipe(flags)
            descriptors.extend(result)
            return result
        with patch.object(a.os, 'pidfd_open', side_effect=pidfd_open), patch.object(a.os, 'pipe2', side_effect=pipe), patch.object(a.os, 'fork', side_effect=OSError('synthetic fork failure')):
            with self.assertRaisesRegex(OSError, 'fork failure'):
                a.run_maintenance(m)
        for fd in descriptors:
            with self.assertRaises(OSError):
                os.fstat(fd)
        self.assertNotIn(('phase', 'barrier-started'), events)

    def test_barrier_marker_precedes_freeze_and_survives_failure_journal_write_error(self):
        m, state, groups, events = self.barrier_fixture()
        durable = {'phase': 'quiescing'}
        def save(module, value, phase):
            events.append(('phase', phase))
            if phase == 'failed':
                raise OSError('synthetic failed-state persistence failure')
            value['phase'] = phase
            durable['phase'] = phase
        with patch.object(a, 'save', side_effect=save), patch.object(a, 'wait_cgroup', side_effect=RuntimeError('freeze failed')):
            with self.assertRaisesRegex(OSError, 'persistence failure'):
                a.run_maintenance(m)
        marker = events.index(('phase', 'barrier-started'))
        first_freeze = next(i for i, event in enumerate(events) if event[0] == 'cgroup.freeze')
        self.assertLess(marker, first_freeze)
        self.assertEqual(durable['phase'], 'barrier-started')
        with patch.object(a, 'read_journal', return_value=dict(state, phase=durable['phase'])), patch.object(a, 'restore_login') as restore:
            self.assertFalse(a.abort_untouched_request(m))
        restore.assert_not_called()

    def test_freeze_timeout_never_migrates_and_thaws_into_emergency(self):
        m, state, groups, events = self.barrier_fixture()
        with patch.object(a, 'wait_cgroup', side_effect=RuntimeError('synthetic freeze timeout')):
            with self.assertRaisesRegex(RuntimeError, 'timeout'):
                a.run_maintenance(m)
        self.assertNotIn(('migrate',), events)
        self.assertEqual(events[-2:], [('thaw',), ('emergency',)])

    def test_topology_change_while_freezing_refuses_before_migration(self):
        m, state, groups, events = self.barrier_fixture()
        with patch.object(a, 'cgroup_layout', side_effect=[groups, groups, groups + [Path('/synthetic/foreign.slice')]]):
            with self.assertRaisesRegex(RuntimeError, 'topology changed'):
                a.run_maintenance(m)
        self.assertNotIn(('migrate',), events)
        self.assertEqual(events[-2:], [('thaw',), ('emergency',)])

    def test_migration_failure_always_thaws_and_requests_emergency(self):
        m, state, groups, events = self.barrier_fixture()
        with patch.object(a, 'migrate', side_effect=RuntimeError('synthetic disk failure')):
            with self.assertRaisesRegex(RuntimeError, 'disk failure'):
                a.run_maintenance(m)
        self.assertEqual(events[-2:], [('thaw',), ('emergency',)])

    def test_boot_guard_rejects_every_ambiguous_phase(self):
        for phase in ('requested', 'masking', 'quiescing', 'barrier-started', 'quiescent', 'backed-up', 'copied', 'switched', 'failed'):
            with self.subTest(phase=phase), patch.object(a, 'read_journal', return_value={'phase': phase}):
                with self.assertRaisesRegex(RuntimeError, 'emergency.target'):
                    a.guard(None)
        for state in (None, {'phase': 'complete'}, {'phase': 'aborted'}):
            with patch.object(a, 'read_journal', return_value=state):
                a.guard(None)

    def test_watchdog_always_recovers_even_if_parent_kill_fails(self):
        with patch.object(a.select, 'select', return_value=([], [], [])), patch.object(a.signal, 'pidfd_send_signal', side_effect=PermissionError) as signal_parent, patch.object(a.os, 'kill') as numeric_kill, patch.object(a, 'recover_emergency') as emergency:
            a.watchdog(7, 42)
        emergency.assert_called_once_with()
        signal_parent.assert_called_once_with(42, signal.SIGKILL)
        numeric_kill.assert_not_called()

    def test_watchdog_success_does_not_thaw_or_request_emergency(self):
        with patch.object(a.select, 'select', return_value=([7], [], [])), patch.object(a.os, 'read', return_value=b'1'), patch.object(a.signal, 'pidfd_send_signal') as signal_parent, patch.object(a, 'recover_emergency') as emergency:
            a.watchdog(7, 42)
        emergency.assert_not_called()
        signal_parent.assert_not_called()

    def test_private_backup_inventory_requires_0700(self):
        with tempfile.TemporaryDirectory() as temporary:
            with patch.object(a, 'safe_directory') as safe:
                self.assertEqual(a.inventory(Path(temporary), native_source=True, private=True), {})
                safe.assert_called_once_with(Path(temporary), mode=0o700)

    def test_inventory_refuses_dangling_symlink_and_missing_private_backup(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'native-tallies'
            path.symlink_to(Path(temporary) / 'absent')
            with self.assertRaisesRegex(RuntimeError, 'symlink'):
                a.inventory(path)
            with self.assertRaisesRegex(RuntimeError, 'backup directory missing'):
                a.inventory(Path(temporary) / 'missing-backup', private=True)

    def test_restoration_unmasks_only_owned_masks_and_restores_fixed_access_units(self):
        state = {'phase': 'aborted', 'owned_masks': ['user@.service'], 'restore_units': ['sshd.service']}
        with patch.object(a, 'command') as cmd, patch.object(a, 'save'), patch.object(a, 'observe_restoration'):
            a.restore_and_observe(None, state)
        self.assertEqual(cmd.call_args_list[0].args[0], ['/usr/bin/systemctl', 'unmask', '--runtime', 'user@.service'])
        self.assertEqual(cmd.call_args_list[-1].args[0], ['/usr/bin/systemctl', '--no-block', 'start', 'sshd.service'])
        self.assertEqual(state['owned_masks'], [])
        with self.assertRaises(RuntimeError):
            a.unmask_owned({'owned_masks': ['arbitrary.service']})

    def test_failure_evidence_includes_only_fixed_refusals_and_numeric_os_errors(self):
        state = {'phase': 'quiescing'}
        m = SimpleNamespace(Refusal=type('SyntheticRefusal', (RuntimeError,), {}))
        records = []
        m.atomic_write = lambda path, data: records.append(json.loads(data))
        with patch.object(a, 'read_journal', return_value=state):
            a.record_failure(m, a.MaintenanceRefusal('unsupported top-level cgroup; maintenance refused'))
            a.record_failure(m, OSError(13, 'sensitive-path-and-content'))
            a.record_failure(m, RuntimeError('unreviewed dynamic message'))
        self.assertIn('unsupported top-level', records[0]['reason'])
        self.assertEqual(records[1]['errno'], 13)
        self.assertNotIn('reason', records[1])
        self.assertNotIn('reason', records[2])
        self.assertNotIn('sensitive', json.dumps(records))


if __name__ == '__main__':
    unittest.main()
