# SPDX-License-Identifier: MIT OR Apache-2.0
"""Synthetic copy/conflict tests; no account databases, services, PAM or TPM."""
import errno
import hashlib
import os
from pathlib import Path
import stat
import tempfile
from types import SimpleNamespace
import unittest

import offline_accounting as fixture


class ExactCopyTests(unittest.TestCase):
    def test_native_record_validator_rejects_unknown_fields_without_reset(self):
        record = bytearray(64)
        record[54:56] = (1).to_bytes(2, 'little')
        record[56:64] = (100).to_bytes(8, 'little')
        self.assertTrue(fixture.valid_native_records(bytes(record), 100))
        self.assertTrue(fixture.valid_native_records(b'', 100))
        self.assertFalse(fixture.valid_native_records(bytes(record), 99))
        self.assertFalse(fixture.valid_native_records(bytes(record)[:-1], 100))
        for offset, value in ((52, 1), (54, 8), (54, 6)):
            malformed = record.copy()
            malformed[offset] = value
            self.assertFalse(fixture.valid_native_records(bytes(malformed), 100))

    def test_native_primary_group_requires_explicit_source_scope(self):
        account = SimpleNamespace(pw_uid=21061, pw_gid=21061)
        native = dict(st_uid=21061, st_gid=21061, st_mode=stat.S_IFREG | 0o660, st_size=0)
        self.assertFalse(fixture.canonical_tally_metadata(SimpleNamespace(**native), account))
        self.assertTrue(fixture.canonical_tally_metadata(SimpleNamespace(**native), account, native_source=True))
        self.assertTrue(fixture.canonical_tally_metadata(SimpleNamespace(**dict(native, st_gid=0)), account))
        self.assertFalse(fixture.canonical_tally_metadata(SimpleNamespace(**dict(native, st_gid=21062)), account, native_source=True))
        self.assertFalse(fixture.canonical_tally_metadata(SimpleNamespace(**dict(native, st_uid=21062)), account))
        self.assertFalse(fixture.canonical_tally_metadata(SimpleNamespace(**dict(native, st_size=63)), account))

    def snapshot(self, data):
        return {'uid': os.getuid(), 'gid': os.getgid(), 'mode': 0o640,
                'size': len(data), 'sha256': hashlib.sha256(data).hexdigest(),
                'atime_ns': 1000000000000000000, 'mtime_ns': 1100000000000000000,
                'xattrs': {}}

    def test_exact_copy_preserves_bytes_metadata_and_refuses_overwrite(self):
        data = bytes(range(64)) * 3
        snapshot = self.snapshot(data)
        with tempfile.TemporaryDirectory(prefix='localpin-m82-copy-') as temporary:
            target = Path(temporary) / 'synthetic-tally'
            fixture.copy_exact(target, snapshot, data)
            info = target.stat()
            self.assertEqual((info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)),
                             (snapshot['uid'], snapshot['gid'], snapshot['mode']))
            self.assertEqual(info.st_mtime_ns, snapshot['mtime_ns'])
            self.assertEqual(target.read_bytes(), data)
            with self.assertRaises(FileExistsError):
                fixture.copy_exact(target, snapshot, b'')
            self.assertEqual(target.read_bytes(), data)

    def test_xattrs_survive_native_filesystem_copy(self):
        data = b'synthetic accounting record'
        snapshot = self.snapshot(data)
        with tempfile.TemporaryDirectory(prefix='localpin-m82-copy-xattr-') as temporary:
            probe = Path(temporary) / 'probe'
            probe.write_bytes(b'')
            try:
                os.setxattr(probe, 'user.localpin-fixture', b'preserve-this-metadata')
            except OSError as error:
                if error.errno in (errno.EOPNOTSUPP, errno.ENOTSUP):
                    self.skipTest('temporary filesystem lacks user xattrs')
                raise
            snapshot['xattrs'] = {'user.localpin-fixture': b'preserve-this-metadata'.hex()}
            target = Path(temporary) / 'copy'
            fixture.copy_exact(target, snapshot, data)
            self.assertEqual(os.getxattr(target, 'user.localpin-fixture'), b'preserve-this-metadata')

    def test_conflicts_include_every_security_metadata_field(self):
        snapshot = self.snapshot(b'counter history')
        self.assertTrue(fixture.equivalent(snapshot, dict(snapshot, atime_ns=0, mtime_ns=0)))
        for field, changed in (('uid', snapshot['uid'] + 1), ('gid', snapshot['gid'] + 1),
                               ('mode', 0o600), ('size', 0), ('sha256', 'different'),
                               ('xattrs', {'security.selinux': 'different'})):
            with self.subTest(field=field):
                self.assertFalse(fixture.equivalent(snapshot, dict(snapshot, **{field: changed})))


if __name__ == '__main__':
    unittest.main()
