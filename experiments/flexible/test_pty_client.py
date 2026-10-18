# SPDX-License-Identifier: MIT OR Apache-2.0
import importlib.util
from pathlib import Path
import stat
from types import SimpleNamespace
import unittest
from unittest import mock

spec = importlib.util.spec_from_file_location('flexible_pty_client', Path(__file__).with_name('pty_client.py'))
client = importlib.util.module_from_spec(spec)
spec.loader.exec_module(client)

UUID = b'12345678-1234-4234-9234-123456789abc\n'
OS_RELEASE = 'ID=fedora\nVERSION_ID=44\nVARIANT_ID=kde\n'


class GuardTests(unittest.TestCase):
    def test_marker_accepts_only_bounded_root_controlled_regular_uuid(self):
        metadata = dict(st_mode=stat.S_IFREG | 0o644, st_uid=0, st_nlink=1, st_size=len(UUID))
        for changes, value, valid in [
            ({}, UUID, True),
            ({'st_uid': 21061}, UUID, False),
            ({'st_nlink': 2}, UUID, False),
            ({'st_mode': stat.S_IFREG | 0o666}, UUID, False),
            ({'st_mode': stat.S_IFDIR | 0o755}, UUID, False),
            ({'st_size': 129}, UUID, False),
            ({}, b'not-a-uuid\n', False),
            ({}, UUID.upper(), False),
        ]:
            with self.subTest(changes=changes, value=value), \
                    mock.patch.object(client.os, 'open', return_value=10) as opened, \
                    mock.patch.object(client.os, 'fstat', return_value=SimpleNamespace(**{**metadata, **changes})), \
                    mock.patch.object(client.os, 'read', return_value=value), \
                    mock.patch.object(client.os, 'close') as closed:
                if valid:
                    client.guard_marker()
                else:
                    with self.assertRaises(RuntimeError):
                        client.guard_marker()
                self.assertTrue(opened.call_args.args[1] & client.os.O_NOFOLLOW)
                self.assertFalse(opened.call_args.args[1] & client.os.O_CREAT)
                closed.assert_called_once_with(10)

    def test_nonfixture_uid_refuses_before_reading_frames_or_forking(self):
        with mock.patch.object(client.os, 'getuid', return_value=1000), \
                mock.patch.object(client.os, 'geteuid', return_value=1000), \
                mock.patch.object(client, 'frame') as frame, \
                mock.patch.object(client.pty, 'fork') as fork, \
                mock.patch.object(client, 'guard_marker') as marker:
            with self.assertRaises(RuntimeError):
                client.run(SimpleNamespace(operation='change', kind='numeric-pin'))
            frame.assert_not_called()
            fork.assert_not_called()
            marker.assert_not_called()

    def test_guest_checks_require_kvm_enforcing_and_fedora_kde(self):
        def result(value):
            return SimpleNamespace(returncode=0, stdout=value)

        for virtualization, selinux, release, valid in [
            (b'kvm\n', b'Enforcing\n', OS_RELEASE, True),
            (b'none\n', b'Enforcing\n', OS_RELEASE, False),
            (b'kvm\n', b'Permissive\n', OS_RELEASE, False),
            (b'kvm\n', b'Enforcing\n', OS_RELEASE.replace('44', '43'), False),
            (b'kvm\n', b'Enforcing\n', OS_RELEASE.replace('kde', 'workstation'), False),
        ]:
            with self.subTest(virtualization=virtualization, selinux=selinux, release=release), \
                    mock.patch.object(client.os, 'getuid', return_value=21061), \
                    mock.patch.object(client.os, 'geteuid', return_value=21061), \
                    mock.patch.object(client, 'guard_marker'), \
                    mock.patch.object(client.subprocess, 'run', side_effect=[result(virtualization), result(selinux)]), \
                    mock.patch.object(client.Path, 'read_text', return_value=release):
                if valid:
                    client.guard()
                else:
                    with self.assertRaises(RuntimeError):
                        client.guard()


if __name__ == '__main__':
    unittest.main()
