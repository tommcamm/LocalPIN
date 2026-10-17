#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Pure checks for the disposable M8 clone; importing this performs no I/O."""
import os
from pathlib import Path
import re
import stat
import uuid
import xml.etree.ElementTree as ET


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def owned_file(path, *, private=False, owner=None, max_size=65_536):
    info = Path(path).lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
            and info.st_uid == (os.getuid() if owner is None else owner)
            and not info.st_mode & (0o077 if private else 0o022)
            and info.st_size <= max_size, "unsafe bounded clone access file")


def manifest_identity(manifest):
    require(manifest.get("name") == "localpin-m8"
            and manifest.get("disk") == "/var/lib/libvirt/images/localpin-m8.qcow2"
            and manifest.get("independent_disk") is True
            and manifest.get("physical_tpm") is False
            and manifest.get("host_filesystem_shares") is False,
            "expected independent disposable M8 clone manifest")
    value = str(uuid.UUID(manifest["uuid"]))
    require(value == manifest["uuid"].lower(), "noncanonical clone UUID")
    return value


def validate_topology(manifest, active_xml, inactive_xml, volume_xml, other_xmls):
    """Accept one independent qcow2 and one private managed emulator only.

    The caller also checks the live domain/UUID and original domain inactivity
    through a single persistent libvirt connection before every guest action.
    """
    clone_uuid = manifest_identity(manifest)
    active = ET.fromstring(active_xml)
    inactive = ET.fromstring(inactive_xml)
    for tree in (active, inactive):
        require(tree.findtext("name") == "localpin-m8"
                and tree.findtext("uuid", "").lower() == clone_uuid,
                "clone domain identity changed")
        require(tree.get("type") == "kvm", "dedicated KVM clone required")
        require(not any(node.tag.rsplit('}', 1)[-1] == 'commandline' for node in tree),
                "arbitrary QEMU commandline overrides forbidden")
        for name in ("hostdev", "filesystem", "shmem", "redirdev"):
            require(not tree.findall(f"./devices/{name}"), "forbidden host device or share")
        disks = tree.findall("./devices/disk")
        primary = [device for device in disks if device.get("device") == "disk"]
        require(len(primary) == 1 and primary[0].get("type") == "file"
                and primary[0].find("driver") is not None
                and primary[0].find("driver").get("type") == "qcow2"
                and primary[0].find("source") is not None
                and primary[0].find("source").get("file") == manifest["disk"]
                and primary[0].find("backingStore/source") is None,
                "clone requires its one independent qcow2 disk")
        for device in disks:
            if device is primary[0]:
                continue
            require(device.get("device") == "cdrom" and device.get("type") == "file"
                    and device.find("readonly") is not None and device.find("source") is None,
                    "only an empty read-only CD-ROM may accompany clone disk")
        tpms = tree.findall("./devices/tpm")
        require(len(tpms) == 1 and tpms[0].get("model") == "tpm-crb",
                "exactly one private tpm-crb emulator required")
        backends = tpms[0].findall("backend")
        require(len(backends) == 1 and backends[0].get("type") == "emulator"
                and backends[0].get("version") == "2.0"
                and backends[0].find("device") is None,
                "physical or unknown TPM backend forbidden")
        require(all(node.tag in ('source', 'profile') for node in backends[0])
                and all(node.attrib == {'name': 'default-v1'}
                        for node in backends[0].findall('profile')),
                "unknown emulator backend override")
        sources = backends[0].findall("source")
        if tree is inactive:
            require(not sources, "configured emulator cannot specify an external source")
        else:
            require(len(sources) <= 1, "multiple emulator sources forbidden")
            if sources:
                require(sources[0].get("type") == "unix"
                        and sources[0].get("mode") == "connect"
                        and re.fullmatch(r"/(?:var/)?run/libvirt/qemu/swtpm/[0-9]+-localpin-m8-swtpm\.sock",
                                         sources[0].get("path", "")),
                        "active TPM source is not clone's private managed socket")
    volume = ET.fromstring(volume_xml)
    require(volume.findtext("target/path") == manifest["disk"]
            and volume.find("target/format") is not None
            and volume.find("target/format").get("type") == "qcow2"
            and volume.find("backingStore/path") is None,
            "clone volume has unknown format or backing storage")
    for xml in other_xmls:
        other = ET.fromstring(xml)
        require(all(node.get("file") != manifest["disk"]
                    for node in other.findall("./devices/disk/source")),
                "clone disk is referenced by another domain")
    return clone_uuid
