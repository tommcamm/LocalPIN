#!/usr/bin/env python3
"""Native TPM route using only the explicitly guarded private VM emulator.

No physical TPM, caller-selected TCTI or synthetic credential record is used.
The host must independently validate the libvirt-managed emulator definition.
"""
import argparse
import importlib.util
import json
from pathlib import Path
import re
import stat
import time

_spec = importlib.util.spec_from_file_location('localpin_m7_tpm_component', '/root/localpin-m7/run.py')
m7 = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(m7)
c = m7.component
DRIVER = Path('/sys/bus/platform/drivers/tpm_crb_acpi')
FAULT = m7.WORK / 'tpm-fault.json'


def guard():
    c.emulated_tpm_guard()
    return m7.guard()


def regular(path, *, private=False):
    info = path.lstat()
    m7.require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1
               and not info.st_mode & (0o077 if private else 0o022) and info.st_size <= 65_536,
               'unsafe bounded TPM fixture file')


def device_name(device):
    return isinstance(device, str) and re.fullmatch(r'MSFT0101:[0-9]{2}', device) is not None


def resource_manager():
    m7.require(stat.S_ISCHR(Path('/dev/tpmrm0').lstat().st_mode), 'native resource manager required')


def physical_device(device):
    """Resolve the one platform TPM through reciprocal ACPI identity links."""
    m7.require(device_name(device), 'unexpected ACPI device name')
    acpi = Path('/sys/bus/acpi/devices') / device
    m7.require(acpi.is_symlink(), 'expected guest ACPI identity link')
    firmware = acpi.resolve(strict=True)
    m7.require(firmware.is_relative_to(Path('/sys/devices')) and firmware.name == device,
               'unexpected guest ACPI firmware identity')
    physical = firmware / 'physical_node'
    m7.require(physical.is_symlink(), 'missing ACPI physical TPM link')
    target = physical.resolve(strict=True)
    expected = (Path('/sys/devices/platform') / device).resolve(strict=True)
    m7.require(target == expected and (target / 'firmware_node').is_symlink()
               and (target / 'firmware_node').resolve(strict=True) == firmware,
               'ACPI and platform TPM identities are not reciprocal')
    return target


def bound_device(device):
    target = physical_device(device)
    entry = DRIVER / device
    native = Path('/sys/class/tpm/tpm0/device')
    m7.require(entry.is_symlink() and entry.resolve(strict=True) == target
               and (target / 'driver').resolve(strict=True) == DRIVER.resolve(strict=True)
               and native.is_symlink() and native.resolve(strict=True) == target,
               'native TPM class and bound platform driver identities differ')
    return target


def install_pty_helper():
    source = c.WORK / 'pty_client.py'
    regular(source)
    driver = Path('/usr/libexec/localpin/m7-pty.py')
    if driver.exists() or driver.is_symlink():
        regular(driver)
        m7.require(driver.read_bytes() == source.read_bytes(), 'changed installed PTY fixture')
    else:
        m7.sync_write(driver, source.read_bytes(), 0o755)
    m7.command(['restorecon', str(driver)])
    return driver


def enroll():
    secrets = guard()[c.NAME]
    resource_manager()
    m7.require(secrets['pin'] != secrets['password'], 'PIN/password collision invalidates native TPM proof')
    m7.require(not FAULT.exists() and not FAULT.is_symlink(), 'repair TPM fault first')
    driver = install_pty_helper()
    c.stop()
    m7.command([c.ACCOUNT, 'begin-mutation'])
    c.prune_test_quarantines()
    c.reseal()
    m7.require(c.status()['availability'] == 'disabled', 'fresh disabled incarnation required')
    args = c.user_command('status')[:-2] + ['python3', str(driver), 'enroll-tpm']
    output = m7.command(args, data=c.frame(secrets['password']) + c.frame(secrets['pin']), timeout=80)
    observation = json.loads(output.stdout)
    status = c.status()
    m7.require(observation['exit_success'] and observation['secret_echo_absent']
               and status['availability'] == 'available'
               and status['enrolled_backend'] == 'tpm2', 'actual installed TPM CLI enrollment failed')
    rows = m7.pam(secrets['pin'])
    m7.require(len(rows) == 1 and rows[0]['auth'] == rows[0]['setcred'] == 0
               and rows[0]['prompts'] == 1, 'actual native TPM PIN baseline failed')
    return {'installed_cli_pty': observation, 'status': status,
            'native_tpm_pam_baseline': rows[0], 'production_device_path': '/dev/tpmrm0',
            'physical_tpm': False, 'private_emulator': True}


def prepare():
    guard()
    resource_manager()
    m7.require(not FAULT.exists() and not FAULT.is_symlink(), 'existing TPM fault refused')
    status = c.status()
    m7.require(status['enrolled_backend'] == 'tpm2' and status['availability'] == 'available',
               'available actual TPM enrollment required')
    devices = [path for path in DRIVER.iterdir() if path.name.startswith('MSFT0101:')]
    m7.require(len(devices) == 1, 'expected one guest platform TPM CRB device')
    device = devices[0].name
    device_path = str(bound_device(device))
    # Intent is durable before unbinding, so an interrupted fixture is repairable.
    m7.sync_write(FAULT, json.dumps({'device': device, 'device_path': device_path}).encode(), 0o600)
    (DRIVER / 'unbind').write_text(device)
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline and Path('/dev/tpmrm0').exists():
        time.sleep(.05)
    m7.require(not Path('/dev/tpmrm0').exists(), 'guest native resource manager was not removed')
    return {'private_emulator': True, 'physical_tpm': False,
            'guest_crb_unbound': True, 'native_resource_manager_absent': True,
            'credential_backend': c.status()['enrolled_backend']}


def repair():
    secrets = guard()[c.NAME]
    regular(FAULT, private=True)
    m7.require(FAULT.stat().st_size <= 4096, 'oversized TPM fault marker')
    state = json.loads(FAULT.read_text())
    m7.require(set(state) == {'device', 'device_path'} and device_name(state['device']),
               'unknown ACPI device recovery marker')
    device = state['device']
    target = physical_device(device)
    m7.require(str(target) == state['device_path'],
               'guest ACPI TPM device identity changed')
    if not Path('/dev/tpmrm0').exists():
        # Some kernels allocate tpm1 after unbind/rebind. Never alias it to the
        # production fixed path: retain intent until native device 0 returns
        # through separately guarded VM recovery, then retry this same check.
        m7.require(not (target / 'driver').exists() and not (target / 'driver').is_symlink(),
                   'TPM already bound without native tpmrm0; retain intent and restore native device 0')
        (DRIVER / 'bind').write_text(device)
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline and not Path('/dev/tpmrm0').exists():
        time.sleep(.05)
    resource_manager()
    m7.require(bound_device(device) == target,
               'native device recovered through an unexpected driver')
    m7.require(secrets['pin'] != secrets['password'], 'PIN/password collision invalidates recovery proof')
    rows = m7.pam(secrets['pin'])
    m7.require(len(rows) == 1 and rows[0]['auth'] == rows[0]['setcred'] == 0
               and rows[0]['prompts'] == 1,
               'same TPM credential did not recover after driver rebind')
    FAULT.unlink()
    m7.sync_directory(m7.WORK)
    return {'native_resource_manager_restored': True, 'same_tpm_credential_usable': True,
            'native_tpm_pam_after_rebind': rows[0]}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('phase', choices=['enroll', 'prepare', 'repair'])
    parser.add_argument('--disposable-vm-confirmed', action='store_true', required=True)
    parser.add_argument('--emulated-tpm-confirmed', action='store_true', required=True)
    args = parser.parse_args()
    print(json.dumps(globals()[args.phase](), indent=2))


if __name__ == '__main__':
    main()
