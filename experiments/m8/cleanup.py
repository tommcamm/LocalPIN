#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Remove temporary access and only the independently identified M8 clone."""
import argparse
import ipaddress
import json
import os
from pathlib import Path
import subprocess
import time
import xml.etree.ElementTree as ET

from guard import owned_file, require
from host import Host


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--address', required=True, type=lambda value: str(ipaddress.IPv4Address(value)))
    parser.add_argument('--access-dir', required=True, type=lambda value: Path(value).resolve())
    parser.add_argument('--disposable-vm-confirmed', action='store_true', required=True)
    parser.add_argument('--emulated-tpm-confirmed', action='store_true', required=True)
    parser.add_argument('--remove-owned-clone', action='store_true', required=True)
    args = parser.parse_args()
    # These are sanitized successful runtime results, not mere operator claims.
    for name, phase in [('final-uninstall.json', 'uninstall'),
                        ('final-ui-uninstalled-password.json', 'restored-password')]:
        path = args.access_dir / name
        owned_file(path)
        value = json.loads(path.read_text())
        require(value.get('passed') is True and value.get('phase') == phase,
                'actual uninstall and restored graphical password evidence required')
    import libvirt
    host = Host(args, libvirt)
    record = {'passed': False, 'physical_tpm_touched': False}
    output = args.access_dir / 'cleanup.json'

    def save():
        descriptor = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, 'w') as stream:
            json.dump(record, stream, indent=2)
            stream.write('\n')
            stream.flush()
            os.fsync(stream.fileno())

    def no_references():
        for domain in host.connection.listAllDomains(0):
            if domain.UUIDString().lower() == host.uuid:
                continue
            flags = [libvirt.VIR_DOMAIN_XML_INACTIVE, 0] if domain.isActive() else [libvirt.VIR_DOMAIN_XML_INACTIVE]
            for flag in flags:
                tree = ET.fromstring(domain.XMLDesc(flag))
                require(all(node.get('file') != host.manifest['disk']
                            for node in tree.findall('./devices/disk//source')), 'another VM references clone disk')
        for pool in host.connection.listAllStoragePools(0):
            if pool.isActive():
                for volume in pool.listAllVolumes(0):
                    require(all(node.text != host.manifest['disk']
                                for node in ET.fromstring(volume.XMLDesc(0)).findall('.//backingStore/path')),
                            'another volume references clone disk')

    try:
        host.guard()
        require(host.domain.isPersistent() == 1 and host.domain.snapshotNum(0) == 0
                and host.domain.listAllCheckpoints(0) == [], 'clone has retained snapshots/checkpoints')
        no_references()
        public = args.access_dir / 'id_ed25519.pub'
        owned_file(public)
        parts = public.read_text().split()
        require(len(parts) == 3 and parts[0] == 'ssh-ed25519', 'unexpected temporary public-key format')
        script = f'''import json,os,shutil,stat,subprocess,sys
from pathlib import Path
sys.path.insert(0,'/root/localpin-m8');import run as m
m.guard({host.uuid!r})
assert not m.rpm_installed() and not m.MODULE.exists() and not m.FAULT.exists() and not m.locked()
assert m.digest(m.KDE)==m.private_json(m.WORK/'install.json')['stock_kde_sha256']
assert Path('/var/lib/localpin-accounts/registry').read_bytes()==b'LPACCT02\\0\\0\\0\\0'
for name in ('localpin.socket','localpin.service'):
 assert subprocess.run(['systemctl','is-active','--quiet',name],capture_output=True).returncode!=0
 assert subprocess.run(['systemctl','is-enabled','--quiet',name],capture_output=True).returncode!=0
keys=Path('/root/.ssh/authorized_keys');m.owned_file(keys,private=True,owner=0)
lines=keys.read_text().splitlines();key={parts[:2]!r}
def key_fields(line):
 fields=line.split()
 return fields[1:3] if fields and fields[0]=='restrict' else fields[:2]
assert any(key_fields(line)==key for line in lines)
remaining=[line for line in lines if key_fields(line)!=key]
auto=Path('/etc/plasmalogin.conf.d/90-localpin-m8.conf')
m.owned_file(auto,owner=0)
assert auto.read_text()=='[Autologin]\\nUser=lp61test\\nSession=plasma.desktop\\nRelogin=false\\n'
auto.unlink()
for name in ('m8-client','m8-pam-probe','m8-pty.py'):
 path=Path('/usr/libexec/localpin')/name
 m.owned_file(path,owner=0,max_size=32*1024*1024);path.unlink()
shutil.rmtree(m.WORK)
keys.write_text(''.join(line+'\\n' for line in remaining));keys.chmod(0o600)
assert all(key_fields(line)!=key for line in keys.read_text().splitlines())
print(json.dumps({{'temporary_ssh_key_removed':True,'clone_autologin_removed':True,'guest_private_secrets_removed':True,'accounts_revoked':True,'original_policy_restored':True}}))
'''
        command = ['ssh', '-o', 'BatchMode=yes', '-o', 'IdentitiesOnly=yes',
                   '-o', 'StrictHostKeyChecking=yes', '-o', 'GlobalKnownHostsFile=/dev/null',
                   '-o', 'UserKnownHostsFile=' + str(args.access_dir / 'known_hosts'),
                   '-o', 'ConnectTimeout=8', '-i', str(args.access_dir / 'id_ed25519'),
                   'root@' + args.address, 'python3 -']
        result = subprocess.run(command, input=script.encode(), capture_output=True, timeout=45)
        require(result.returncode == 0, 'guest cleanup incomplete; inspect before removing clone')
        record.update(json.loads(result.stdout))
        save()
        host.guard()
        volume = host.connection.storageVolLookupByPath(host.manifest['disk'])
        pool = volume.storagePoolLookupByVolume()
        host.domain.shutdown()
        deadline = time.monotonic() + 45
        while host.domain.isActive() and time.monotonic() < deadline:
            require(host.connection.lookupByName('localpin-m1').isActive() == 0, 'original VM started')
            time.sleep(.25)
        require(host.domain.isActive() == 0, 'graceful clone shutdown did not complete')
        no_references()
        host.domain.undefineFlags(libvirt.VIR_DOMAIN_UNDEFINE_TPM | libvirt.VIR_DOMAIN_UNDEFINE_NVRAM)
        record.update(clone_undefined=True, private_emulator_state_removed_by_libvirt=True)
        save()
        no_references()
        volume.delete(0)
        require(all(item.path() != host.manifest['disk'] for item in pool.listAllVolumes(0)),
                'independent volume remains')
        original = host.connection.lookupByName('localpin-m1')
        require(original.isPersistent() == 1 and original.isActive() == 0, 'original VM not off')
        record.update(owned_independent_volume_deleted=True, original_vm_remains_defined_and_off=True)
        for name in ('id_ed25519', 'id_ed25519.pub', 'known_hosts', 'offline.qcow2',
                     'offline-before-hostkey.qcow2', 'guest-policy.bin', 'artifacts.tar'):
            path = args.access_dir / name
            if path.exists():
                owned_file(path, max_size=40 * 1024 * 1024 * 1024)
                path.unlink()
        record.update(temporary_host_access_removed=True, offline_bootstrap_copies_removed=True, passed=True)
        save()
        print(json.dumps(record, indent=2))
    except Exception as error:
        record['error_type'] = type(error).__name__
        save()
        raise
    finally:
        host.connection.close()


if __name__ == '__main__':
    main()
