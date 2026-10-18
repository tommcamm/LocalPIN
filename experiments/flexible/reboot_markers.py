#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Recreate volatile fixture opt-ins after an independently verified clone reboot.

Prepared/trial tests require real password login after this step. This does not
start a broker, reopen a desktop gate, authenticate or claim desktop acceptance.
"""
import argparse
import ipaddress
import json
from pathlib import Path
import subprocess
import sys
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'm8'))
from host import Host
from guard import owned_file, require


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--address', required=True, type=lambda value: str(ipaddress.IPv4Address(value)))
    parser.add_argument('--access-dir', required=True, type=lambda value: Path(value).resolve())
    parser.add_argument('--disposable-vm-confirmed', action='store_true', required=True)
    parser.add_argument('--emulated-tpm-confirmed', action='store_true', required=True)
    args = parser.parse_args()
    import libvirt
    host = Host(args, libvirt)
    try:
        host.guard()
        intent = args.access_dir / 'reboot-intent.json'
        owned_file(intent, private=True)
        before = json.loads(intent.read_text())
        require(before['uuid'] == host.uuid and before['kind'] == 'ordinary', 'reboot intent identity differs')
        uuid.UUID(before['boot'])
        script = f'''import json,os,stat,subprocess,uuid
from pathlib import Path
assert os.getuid()==os.geteuid()==0
assert Path('/sys/class/dmi/id/product_uuid').read_text().strip().lower()=={host.uuid!r}
assert subprocess.run(['systemd-detect-virt','--vm'],capture_output=True,check=True).stdout.strip()==b'kvm'
assert subprocess.run(['getenforce'],capture_output=True,check=True).stdout.strip()==b'Enforcing'
boot=str(uuid.UUID(Path('/proc/sys/kernel/random/boot_id').read_text().strip()))
assert boot!={before['boot']!r}
work=Path('/root/localpin-m8');info=work.lstat()
assert stat.S_ISDIR(info.st_mode) and info.st_uid==0 and not info.st_mode&0o077
checkpoint=work/'flexible-reboot-private.json';info=checkpoint.lstat()
assert stat.S_ISREG(info.st_mode) and info.st_uid==0 and info.st_nlink==1 and not info.st_mode&0o077
assert json.loads(checkpoint.read_text())['boot']=={before['boot']!r}
markers=[('localpin-m8-guard',{host.uuid!r}+'\\n',0o600),('localpin-m8-emulator',{host.uuid!r}+'\\nemulator2.0\\n',0o600),('localpin-m61-guard',{host.uuid!r}+'\\n',0o644)]
assert all(not (Path('/run')/name).exists() and not (Path('/run')/name).is_symlink() for name,_,_ in markers)
for name,text,mode in markers:
 fd=os.open(Path('/run')/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,mode)
 os.fchmod(fd,mode)
 with os.fdopen(fd,'w') as stream:stream.write(text);stream.flush();os.fsync(stream.fileno())
print(json.dumps({{'boot_changed':True,'fixture_markers_recreated_after_independent_identity_checks':True,'broker_or_gate_started':False,'selinux':'Enforcing'}}))
'''
        command = ['ssh', '-F', '/dev/null', '-o', 'BatchMode=yes', '-o', 'IdentitiesOnly=yes',
                   '-o', 'StrictHostKeyChecking=yes', '-o', 'GlobalKnownHostsFile=/dev/null',
                   '-o', 'UserKnownHostsFile=' + str(args.access_dir / 'known_hosts'),
                   '-o', 'ConnectTimeout=5', '-i', str(args.access_dir / 'id_ed25519'),
                   'root@' + args.address, 'python3 -']
        result = subprocess.run(command, input=script.encode(), capture_output=True, timeout=15)
        host.guard()
        require(result.returncode == 0 and len(result.stdout) <= 1024,
                'new boot/markers unavailable; inspect privately before repeating')
        value = json.loads(result.stdout)
        require(value == {'boot_changed': True, 'fixture_markers_recreated_after_independent_identity_checks': True,
                          'broker_or_gate_started': False, 'selinux': 'Enforcing'}, 'unexpected marker result')
        print(json.dumps(value, indent=2))
    finally:
        host.connection.close()


if __name__ == '__main__':
    main()
