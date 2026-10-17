#!/usr/bin/env python3
"""Installed CLI + actual production authorities, through genuine controlling PTYs."""
import argparse
import json
from pathlib import Path

import run as m
import lifecycle


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--disposable-vm-confirmed', action='store_true', required=True)
    parser.parse_args()
    secrets = m.guard()
    lifecycle.fresh(secrets)
    dedicated = secrets[m.NAME]
    driver = Path('/usr/libexec/localpin/m61-pty.py')
    driver.write_bytes((m.WORK / 'pty_client.py').read_bytes())
    driver.chmod(0o755)
    m.command(['restorecon', str(driver)])
    observations = []

    def cli(operation, pin=None):
        inputs = [dedicated['password']] if operation != 'recover' else []
        if pin: inputs.append(pin)
        data = b''.join(m.frame(value) for value in inputs)
        if operation == 'recover':
            args = ['python3', str(driver), operation]
        else:
            args = m.user_command(operation)[:-2] + ['python3', str(driver), operation]
        observation = json.loads(m.command(args, data=data, timeout=80).stdout)
        observations.append(observation)

    cli('enroll', dedicated['pin'])
    m.require(m.client('verify', dedicated['pin']).stdout.strip() == b'Granted', 'CLI enrollment not usable')
    cli('change', dedicated['new_pin'])
    m.require(m.client('verify', dedicated['pin']).stdout.strip() == b'Mismatch', 'old CLI PIN survived rotation')
    m.require(m.client('verify', dedicated['new_pin']).stdout.strip() == b'Granted', 'new CLI PIN failed')
    cli('disable')
    m.require(m.status()['availability'] == 'disabled', 'CLI disable did not commit')
    cli('enroll', dedicated['pin'])
    cli('recover')
    m.require(m.status()['availability'] == 'disabled', 'CLI recovery did not commit')
    password = json.loads(m.command([str(m.WORK / 'password-check'), 'original', m.NAME],
                                    data=dedicated['password'].encode()).stdout)
    m.require(password['auth'] == password['account'] == 0, 'original password recovery failed')
    report = {'installed_cli_pty_flows': observations, 'actual_broker_verification': True,
              'old_pin_after_change_refused': True, 'original_password_recovery': True,
              'final_availability': m.status()['availability'], 'selinux': 'Enforcing'}
    path = m.WORK / 'evidence.json'
    evidence = json.loads(path.read_text())
    evidence['cli'] = report
    path.write_text(json.dumps(evidence, indent=2) + '\n')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
