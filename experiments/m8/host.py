#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Pinned SSH dispatcher with independent live libvirt topology validation."""
import argparse
import ipaddress
import json
from pathlib import Path
import subprocess

from guard import manifest_identity, owned_file, require, validate_topology

PHASES = ("inspect", "install", "prepare", "enroll", "isolated", "activate",
          "refusal-matrix", "upgrade", "reboot-prepare", "reboot-verify",
          "disable", "recover", "uninstall", "trial", "fault-missing-module",
          "fault-selinux-worker", "repair-fault", "package-failure",
          "downgrade-refusal", "fingerprint-refusal", "legacy-prepare", "legacy-migrate", "locked-tally",
          "cache-interrupt", "cache-reboot-verify", "cache-resume")


class Host:
    def __init__(self, args, libvirt):
        self.args, self.libvirt = args, libvirt
        for name in ("id_ed25519", "known_hosts", "clone.json"):
            owned_file(args.access_dir / name, private=name == "id_ed25519")
        self.manifest = json.loads((args.access_dir / "clone.json").read_text())
        self.uuid = manifest_identity(self.manifest)
        self.connection = libvirt.open("qemu:///system")
        require(self.connection is not None, "libvirt system connection unavailable")
        self.domain = self.connection.lookupByUUIDString(self.uuid)

    def guard(self):
        require(self.domain.name() == "localpin-m8"
                and self.domain.UUIDString().lower() == self.uuid
                and self.domain.isActive() == 1,
                "identified M8 clone must be active")
        original = self.connection.lookupByName("localpin-m1")
        require(original.isActive() == 0, "original VM must remain off")
        volume = self.connection.storageVolLookupByPath(self.manifest["disk"])
        others = [domain.XMLDesc(self.libvirt.VIR_DOMAIN_XML_INACTIVE)
                  for domain in self.connection.listAllDomains(0)
                  if domain.UUIDString().lower() != self.uuid]
        validate_topology(self.manifest, self.domain.XMLDesc(0),
                          self.domain.XMLDesc(self.libvirt.VIR_DOMAIN_XML_INACTIVE),
                          volume.XMLDesc(0), others)

    def run(self):
        self.guard()
        # Every value in the remote command is from a fixed phase allowlist or
        # canonical UUID, not shell-interpolated caller text.
        remote = ("python3 /root/localpin-m8/run.py " + self.args.phase
                  + " --disposable-vm-confirmed --emulated-tpm-confirmed --expected-uuid " + self.uuid)
        command = ["ssh", "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes",
                   "-o", "StrictHostKeyChecking=yes", "-o", "GlobalKnownHostsFile=/dev/null",
                   "-o", "UserKnownHostsFile=" + str(self.args.access_dir / "known_hosts"),
                   "-o", "ConnectTimeout=8", "-o", "ServerAliveInterval=5",
                   "-o", "ServerAliveCountMax=2", "-i", str(self.args.access_dir / "id_ed25519"),
                   "root@" + self.args.address, remote]
        try:
            result = subprocess.run(command, capture_output=True, timeout=240, check=False)
        except subprocess.TimeoutExpired:
            raise RuntimeError("bounded guest phase timed out; inspect guest intent before retry") from None
        # stderr is deliberately not exported: native package tools may reveal
        # host/account details. Only the runner's sanitized JSON is evidence.
        require(result.returncode == 0, "guarded guest phase failed; inspect guest locally")
        require(len(result.stdout) <= 65_536, "oversized guest phase evidence")
        evidence = json.loads(result.stdout)
        require(evidence.get("phase") == self.args.phase and evidence.get("passed") is True,
                "guest evidence did not pass the requested phase")
        self.guard()
        print(json.dumps(evidence, indent=2))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("phase", choices=PHASES)
    parser.add_argument("--address", required=True, type=lambda value: str(ipaddress.IPv4Address(value)))
    parser.add_argument("--access-dir", required=True, type=lambda value: Path(value).resolve())
    parser.add_argument("--disposable-vm-confirmed", action="store_true", required=True)
    parser.add_argument("--emulated-tpm-confirmed", action="store_true", required=True)
    args = parser.parse_args()
    import libvirt  # Not needed for pure guard/unit tests.
    host = Host(args, libvirt)
    try:
        host.run()
    finally:
        host.connection.close()


if __name__ == "__main__":
    main()
