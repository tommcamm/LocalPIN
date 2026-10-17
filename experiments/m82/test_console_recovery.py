# SPDX-License-Identifier: MIT OR Apache-2.0
"""Recovery precondition checks with no filesystem, PAM, service or TPM action."""
import unittest
from pathlib import Path
import tempfile
from unittest import mock

import console_recovery as fixture


class RecoveryScopeTests(unittest.TestCase):
    def test_missing_gate_is_disabled_and_existing_unknown_gate_refuses(self):
        with tempfile.TemporaryDirectory(prefix='localpin-m82-recovery-gate-') as temporary:
            gate = Path(temporary) / 'synthetic-gate'
            with mock.patch.object(fixture, 'GATE', gate):
                self.assertIsNone(fixture.require_closed_gate())
                gate.write_bytes(b'LPINT01\ndisabled\n')
                with mock.patch.object(fixture, 'snapshot_file', return_value={'st_mode': 0o100644}):
                    self.assertEqual(fixture.require_closed_gate(), {'st_mode': 0o100644})
                    for data in (b'LPINT01\nactive\n', b'unknown', b''):
                        gate.write_bytes(data)
                        with self.assertRaisesRegex(RuntimeError, 'live or unknown gate'):
                            fixture.require_closed_gate()

    def test_unsafe_backup_references_refuse_before_filesystem_access(self):
        for backup in ('../backup-anywhere', 'backup-../../etc',
                       'backup-' + '0' * 32 + '/kde', 'backup-short', '/absolute/backup'):
            with self.subTest(backup=backup):
                with self.assertRaisesRegex(RuntimeError, 'sole-account'):
                    fixture.backup_reference({'schema': 2, 'phase': 'prepared',
                                              'uids': [21061], 'backup': backup})

    def test_wrong_account_or_phase_refuses_before_filesystem_access(self):
        base = {'schema': 2, 'phase': 'prepared', 'uids': [21061],
                'backup': 'backup-' + '0' * 32}
        for changes in ({'uids': [21062]}, {'uids': [21061, 21062]},
                        {'phase': 'disabled'}, {'phase': 'suspended'}, {'schema': 1}):
            with self.subTest(changes=changes):
                with self.assertRaisesRegex(RuntimeError, 'sole-account'):
                    fixture.backup_reference(dict(base, **changes))


if __name__ == '__main__':
    unittest.main()
