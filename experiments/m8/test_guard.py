#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""No VM access: reject dangerous topology and unsafe evidence prerequisites."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import xml.etree.ElementTree as ET

sys.path.insert(0, str(Path(__file__).resolve().parent))
from guard import manifest_identity, owned_file, validate_topology

SPEC = importlib.util.spec_from_file_location('localpin_m8_guest_tests', Path(__file__).with_name('run.py'))
guest = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(guest)

MANIFEST = {'name': 'localpin-m8', 'uuid': '11111111-2222-4333-8444-555555555555',
            'disk': '/var/lib/libvirt/images/localpin-m8.qcow2', 'independent_disk': True,
            'physical_tpm': False, 'host_filesystem_shares': False}
INACTIVE = '''<domain type="kvm"><name>localpin-m8</name><uuid>11111111-2222-4333-8444-555555555555</uuid>
<devices><disk type="file" device="disk"><driver type="qcow2"/>
<source file="/var/lib/libvirt/images/localpin-m8.qcow2"/></disk>
<disk type="file" device="cdrom"><readonly/></disk>
<tpm model="tpm-crb"><backend type="emulator" version="2.0"/></tpm></devices></domain>'''
ACTIVE = INACTIVE.replace('<backend type="emulator" version="2.0"/>',
                         '<backend type="emulator" version="2.0"><source type="unix" mode="connect" '
                         'path="/run/libvirt/qemu/swtpm/17-localpin-m8-swtpm.sock"/></backend>')
VOLUME = '''<volume><target><path>/var/lib/libvirt/images/localpin-m8.qcow2</path>
<format type="qcow2"/></target></volume>'''
ORIGINAL = '''<domain type="kvm"><name>localpin-m1</name><devices><disk type="file" device="disk">
<source file="/var/lib/libvirt/images/localpin-m1.qcow2"/></disk></devices></domain>'''


class TopologyTests(unittest.TestCase):
    def check(self, *, active=ACTIVE, inactive=INACTIVE, volume=VOLUME, others=None, manifest=None):
        return validate_topology(manifest or MANIFEST, active, inactive, volume,
                                 [ORIGINAL] if others is None else others)

    def reject(self, **kwargs):
        with self.assertRaises(RuntimeError):
            self.check(**kwargs)

    def test_exact_private_independent_emulator_accepted(self):
        self.assertEqual(self.check(), MANIFEST['uuid'])

    def test_live_emulator_without_reported_source_accepted(self):
        self.assertEqual(self.check(active=INACTIVE), MANIFEST['uuid'])

    def test_managed_var_run_socket_accepted(self):
        self.check(active=ACTIVE.replace('/run/libvirt/', '/var/run/libvirt/'))

    def test_physical_tpm_backend_rejected(self):
        self.reject(active=ACTIVE.replace('type="emulator"', 'type="passthrough"'))

    def test_external_tpm_source_rejected(self):
        self.reject(active=ACTIVE.replace('/run/libvirt/qemu/swtpm/17-localpin-m8-swtpm.sock', '/dev/tpm0'))

    def test_other_clone_emulator_source_rejected(self):
        self.reject(active=ACTIVE.replace('17-localpin-m8-swtpm', '17-localpin-m7-swtpm'))

    def test_caller_configured_tpm_source_rejected(self):
        self.reject(inactive=ACTIVE)

    def test_libvirt_default_profile_accepted_and_external_profile_refused(self):
        self.check(inactive=INACTIVE.replace('version="2.0"/>',
                                            'version="2.0"><profile name="default-v1"/></backend>'))
        self.reject(inactive=INACTIVE.replace('version="2.0"/>',
                                              'version="2.0"><profile name="external"/></backend>'))

    def test_qemu_commandline_and_unknown_backend_overrides_rejected(self):
        self.reject(active=ACTIVE.replace('</domain>',
                                          '<q:commandline xmlns:q="urn:qemu"/></domain>'))
        self.reject(active=ACTIVE.replace('</backend>', '<device path="/dev/tpm0"/></backend>'))

    def test_host_device_share_and_redirect_rejected(self):
        for element in ('<hostdev/>', '<filesystem/>', '<shmem/>', '<redirdev/>'):
            with self.subTest(element=element):
                self.reject(active=ACTIVE.replace('<devices>', '<devices>' + element))

    def test_second_disk_and_populated_cd_rejected(self):
        self.reject(active=ACTIVE.replace('<readonly/>', '<readonly/><source file="/host.iso"/>'))
        self.reject(active=ACTIVE.replace('</devices>', '<disk type="file" device="disk"/></devices>'))

    def test_shared_disk_rejected(self):
        self.reject(others=[ORIGINAL.replace('localpin-m1.qcow2', 'localpin-m8.qcow2')])

    def test_backing_volume_rejected(self):
        self.reject(volume=VOLUME.replace('</volume>', '<backingStore><path>/host.qcow2</path></backingStore></volume>'))

    def test_changed_domain_identity_rejected(self):
        self.reject(active=ACTIVE.replace('<name>localpin-m8</name>', '<name>localpin-m1</name>'))
        self.reject(active=ACTIVE.replace('type="kvm"', 'type="qemu"'))

    def test_unsafe_manifest_and_disk_rejected(self):
        for key, value in [('independent_disk', False), ('physical_tpm', True),
                           ('host_filesystem_shares', True), ('disk', '/host.qcow2'),
                           ('name', 'localpin-m1')]:
            with self.subTest(key=key):
                manifest = copy.deepcopy(MANIFEST)
                manifest[key] = value
                self.reject(manifest=manifest)


class PrivateInputTests(unittest.TestCase):
    def test_selinux_evidence_requires_causal_native_audit_record(self):
        text = ('avc: denied { execute } name="localpin-worker" '
                'scontext=system_u:system_r:localpin_broker_t:s0 '
                'tcontext=system_u:object_r:default_t:s0 tclass=file')
        rows = [{'_TRANSPORT': 'audit', 'MESSAGE': text},
                {'_TRANSPORT': 'stdout', 'MESSAGE': text},
                {'_TRANSPORT': 'kernel', 'MESSAGE': text.replace('localpin_broker_t', 'localpin_auth_t')},
                {'_TRANSPORT': 'audit', 'MESSAGE': text.replace('default_t', 'lib_t')},
                {'_TRANSPORT': 'audit', 'MESSAGE': text.replace('localpin-worker', 'other-worker')},
                {'_TRANSPORT': 'audit', 'MESSAGE': text.replace('tclass=file', 'tclass=dir')}]
        result = subprocess.CompletedProcess([], 0, '\n'.join(map(json.dumps, rows)).encode(), b'')
        with patch.object(guest, 'command', return_value=result):
            self.assertEqual(guest.avc_count(), 1)

    def test_package_registry_comparison_ignores_only_etc_cache_metadata(self):
        row = bytes(range(84))
        data = b'LPACCT02' + (20).to_bytes(2, 'big') + row * 20 + b'\0\1' + bytes(range(20))
        original = guest.normalized_registry(data)
        changed = bytearray(data)
        changed[26:50] = bytes(24)
        self.assertEqual(guest.normalized_registry(bytes(changed)), original)
        for offset in (10, 18, 50, 94, len(data) - 1):
            changed = bytearray(data)
            changed[offset] ^= 1
            self.assertNotEqual(guest.normalized_registry(bytes(changed)), original)
        with self.assertRaises(RuntimeError):
            guest.normalized_registry(data[:-1])
        for count in (0, 2, 19, 21, 129):
            with self.subTest(count=count), self.assertRaises(RuntimeError):
                guest.normalized_registry(b'LPACCT02' + count.to_bytes(2, 'big') + row * count + b'\0\1' + bytes(20))

    def test_symlink_hardlink_and_writable_files_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / 'key'
            path.write_text('synthetic')
            path.chmod(0o600)
            owned_file(path, private=True)
            (root / 'link').symlink_to(path)
            with self.assertRaises(RuntimeError):
                owned_file(root / 'link', private=True)
            os.link(path, root / 'hardlink')
            with self.assertRaises(RuntimeError):
                owned_file(path, private=True)
            (root / 'hardlink').unlink()
            path.chmod(0o644)
            with self.assertRaises(RuntimeError):
                owned_file(path, private=True)

    def test_bounded_inputs_and_explicit_large_artifact_bound(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'synthetic'
            path.write_bytes(b'x' * 70_000)
            path.chmod(0o600)
            with self.assertRaises(RuntimeError):
                owned_file(path)
            owned_file(path, max_size=100_000)

    def test_guest_phase_dispatch_matches_host(self):
        spec = importlib.util.spec_from_file_location('localpin_m8_host_tests', Path(__file__).with_name('host.py'))
        host = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(host)
        self.assertEqual(set(guest.PHASES), set(host.PHASES))

    def test_activation_refuses_missing_desktop_evidence_before_admin_action(self):
        current = {'boot_id': 'synthetic-boot', 'kde_sha256': 'synthetic-policy', 'module_sha256': 'synthetic-module'}
        for value in ({}, {'pin': {'binding': current}, 'password': {'binding': current}},
                      {phase: {'binding': {**current, 'boot_id': 'previous-boot'}}
                       for phase in ('pin', 'password', 'recovery')}):
            with self.subTest(value=value):
                with (patch.object(guest, 'FAULT', Path('/not-present-synthetic-m8-fault')),
                      patch.object(guest, 'private_json', return_value=value),
                      patch.object(guest, 'binding', return_value=current),
                      patch.object(guest, 'admin') as admin):
                    with self.assertRaises(RuntimeError):
                        guest.activate({})
                    admin.assert_not_called()


if __name__ == '__main__':
    unittest.main()
