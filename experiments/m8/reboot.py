#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Request/observe one real reboot of the topology-verified disposable clone."""
import argparse
import ipaddress
import json
import os
from pathlib import Path
import subprocess
import time
import uuid

from guard import owned_file, require
from host import Host


def ssh(host, script, timeout=12):
    args = host.args
    return subprocess.run(['ssh', '-o', 'BatchMode=yes', '-o', 'IdentitiesOnly=yes',
                           '-o', 'StrictHostKeyChecking=yes', '-o', 'GlobalKnownHostsFile=/dev/null',
                           '-o', 'UserKnownHostsFile=' + str(args.access_dir / 'known_hosts'),
                           '-o', 'ConnectTimeout=3', '-i', str(args.access_dir / 'id_ed25519'),
                           'root@' + args.address, 'python3 -'], input=script.encode(),
                          capture_output=True, timeout=timeout)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('action', choices=('request', 'complete'))
    parser.add_argument('--kind', choices=('ordinary', 'cache'), required=True)
    parser.add_argument('--address', required=True, type=lambda value: str(ipaddress.IPv4Address(value)))
    parser.add_argument('--access-dir', required=True, type=lambda value: Path(value).resolve())
    parser.add_argument('--disposable-vm-confirmed', action='store_true', required=True)
    parser.add_argument('--emulated-tpm-confirmed', action='store_true', required=True)
    args = parser.parse_args()
    import libvirt
    host = Host(args, libvirt)
    intent = args.access_dir / 'reboot-intent.json'
    try:
        host.guard()
        if args.action == 'request':
            script = ("import json,sys\nsys.path.insert(0,'/root/localpin-m8')\nimport run as m\n"
                      f"m.guard({host.uuid!r})\n"
                      f"before=m.private_json(m.WORK/{('reboot.json' if args.kind == 'ordinary' else 'cache-interrupt.json')!r})\n"
                      "assert before['boot_id']==m.boot_id()\nprint(json.dumps({'boot':m.boot_id()}))\n")
            result = ssh(host, script)
            require(result.returncode == 0, 'durable guest pre-reboot snapshot not verified')
            value = {'uuid': host.uuid, 'kind': args.kind, 'boot': json.loads(result.stdout)['boot']}
            descriptor = os.open(intent, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
            with os.fdopen(descriptor, 'w') as stream:
                json.dump(value, stream)
                stream.flush()
                os.fsync(stream.fileno())
            host.domain.reboot(0)
            print(json.dumps({'reboot_requested': True, 'kind': args.kind, 'original_vm_off': True}))
            return
        owned_file(intent, private=True)
        value = json.loads(intent.read_text())
        require(value['uuid'] == host.uuid and value['kind'] == args.kind, 'reboot intent identity differs')
        uuid.UUID(value['boot'])
        script = f'''import json,os,subprocess,uuid
from pathlib import Path
assert os.getuid()==os.geteuid()==0
assert Path('/sys/class/dmi/id/product_uuid').read_text().strip().lower()=={host.uuid!r}
assert subprocess.run(['getenforce'],capture_output=True,check=True).stdout.strip()==b'Enforcing'
boot=str(uuid.UUID(Path('/proc/sys/kernel/random/boot_id').read_text().strip()))
assert boot!={value['boot']!r}
assert Path('/run/user/21061/bus').is_socket()
desktop=subprocess.run(['/usr/bin/setpriv','--reuid=21061','--regid=21061','--clear-groups','--','/usr/bin/env','XDG_RUNTIME_DIR=/run/user/21061','DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/21061/bus','/usr/bin/busctl','--user','call','org.freedesktop.ScreenSaver','/ScreenSaver','org.freedesktop.ScreenSaver','GetActive'],capture_output=True,timeout=5)
assert desktop.returncode==0 and desktop.stdout.strip() in (b'b true',b'b false')
for name,text,mode in [('localpin-m8-guard',{host.uuid!r}+'\\n',0o600),('localpin-m8-emulator',{host.uuid!r}+'\\nemulator2.0\\n',0o600),('localpin-m61-guard',{host.uuid!r}+'\\n',0o644)]:
 path=Path('/run')/name
 fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,mode)
 with os.fdopen(fd,'w') as stream:stream.write(text)
print(json.dumps({{'boot_changed':True,'markers_recreated_after_identity_check':True,'selinux':'Enforcing'}}))
'''
        deadline = time.monotonic() + 50
        while time.monotonic() < deadline:
            host.guard()
            try:
                result = ssh(host, script)
            except subprocess.TimeoutExpired:
                result = None
            if result is not None and result.returncode == 0:
                host.guard()
                print(json.dumps(json.loads(result.stdout), indent=2))
                return
            time.sleep(1)
        raise RuntimeError('new boot not ready within bounded interval; inspect before retry')
    finally:
        host.connection.close()


if __name__ == '__main__':
    main()
