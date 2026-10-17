#!/usr/bin/env python3
"""Generate clone-only M1 topology proposals; never call libvirt or touch disks."""
# SPDX-License-Identifier: MIT OR Apache-2.0
import argparse
import copy
import json
import os
from pathlib import Path
import re
import secrets
import shlex
import stat
import uuid
import xml.etree.ElementTree as ET

QEMU = "http://libvirt.org/schemas/domain/qemu/1.0"
ET.register_namespace("qemu", QEMU)


def require(value, message):
    if not value:
        raise RuntimeError(message)


def write_new(path, value):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    with os.fdopen(fd, "w") as output:
        output.write(value)


def regular_bytes(path, limit, *, private=False):
    # O_NONBLOCK makes the type check safe even when the path is a FIFO.
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as source:
        info = os.fstat(source.fileno())
        require(stat.S_ISREG(info.st_mode), "input must be a regular file")
        if private:
            require(info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1,
                    "config must be an owned single-link regular 0600 file")
        require(info.st_size <= limit, "oversized input file")
        data = source.read(limit + 1)
    require(len(data) <= limit, "oversized input file")
    return data


def private_config(path):
    data = regular_bytes(path, 16384, private=True)
    config = json.loads(data)
    require(isinstance(config, dict) and set(config) == {
        "source_name", "source_uuid", "clone_name", "clone_uuid", "clone_disk", "memory_mib", "vcpus"},
        "unexpected configuration fields")
    for key in ("source_name", "clone_name"):
        require(isinstance(config[key], str) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,62}", config[key]), "invalid domain name")
    for key in ("source_uuid", "clone_uuid"):
        require(isinstance(config[key], str) and str(uuid.UUID(config[key])) == config[key], "noncanonical domain UUID")
    require(config["source_uuid"] != config["clone_uuid"] and config["source_name"] != config["clone_name"],
            "clone identity must differ from source")
    disk = config["clone_disk"]
    require(isinstance(disk, str) and Path(disk).is_absolute() and os.path.normpath(disk) == disk
            and disk.endswith(".qcow2") and "\x00" not in disk, "need a canonical absolute new qcow2 path")
    require(type(config["memory_mib"]) is int and 1024 <= config["memory_mib"] <= 16384,
            "memory outside bounded lab range")
    require(type(config["vcpus"]) is int and 1 <= config["vcpus"] <= 8, "vCPUs outside bounded lab range")
    return config


def address(parent, bus, slot):
    ET.SubElement(parent, "address", type="pci", domain="0x0000", bus=hex(bus), slot=hex(slot), function="0x0")


def alias(parent, value):
    for old in parent.findall("alias"):
        parent.remove(old)
    ET.SubElement(parent, "alias", name=value)


def override(root, device, **properties):
    element = root.find(f"{{{QEMU}}}override")
    if element is None:
        element = ET.SubElement(root, f"{{{QEMU}}}override")
    frontend = ET.SubElement(ET.SubElement(element, f"{{{QEMU}}}device", alias=device), f"{{{QEMU}}}frontend")
    for name, value in properties.items():
        ET.SubElement(frontend, f"{{{QEMU}}}property", name=name, type="unsigned" if isinstance(value, int) else "string", value=str(value))


def serialize(root):
    ET.indent(root, space="  ")
    return ET.tostring(root, encoding="unicode") + "\n"


def defer_inputs(root):
    """libvirt emits inputs before video; QEMU binds HID at realize, so defer."""
    devices = root.find("devices")
    commands = root.find(f"{{{QEMU}}}commandline")
    overrides = root.find(f"{{{QEMU}}}override")
    controllers = {int(x.get("index")): x for x in devices.findall("controller") if x.get("type") == "pci"}
    for element in list(devices.findall("input")):
        ident = element.find("alias").get("name")
        frontend = next(x for x in overrides if x.get("alias") == ident)
        props = {x.get("name"): x.get("value") for x in frontend.find(f"{{{QEMU}}}frontend")}
        addr = element.find("address")
        controller = controllers[int(addr.get("bus"), 0)]
        controller_alias = controller.find("alias")
        bus = controller_alias.get("name") if controller_alias is not None else f"pci.{controller.get('index')}"
        spec = {"driver": f"virtio-{element.get('type')}-pci", "id": ident, "bus": bus,
                "addr": addr.get("slot"), "display": props["display"], "head": int(props["head"])}
        ET.SubElement(commands, f"{{{QEMU}}}arg", value="-device")
        ET.SubElement(commands, f"{{{QEMU}}}arg", value=json.dumps(spec, separators=(",", ":")))
        overrides.remove(frontend)
        devices.remove(element)


def prepare(original, config, directory):
    info = directory.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == 0o700,
            "output must be an owned private 0700 directory")
    xml = regular_bytes(original, 2097152)
    require(b"<!DOCTYPE" not in xml and b"<!ENTITY" not in xml, "unsupported source XML")
    root = ET.fromstring(xml)
    require(root.tag == "domain" and root.get("type") == "kvm" and
            root.findtext("uuid") == config["source_uuid"] and root.findtext("name") == config["source_name"],
            "unexpected source identity")
    machine = root.find("os/type")
    require(machine is not None and machine.get("arch") == "x86_64" and machine.get("machine", "").startswith("pc-q35-"),
            "fixture requires x86_64 q35")
    require(root.find("os/nvram") is None, "NVRAM needs an independently copied clone path")
    require(not any(root.findall(f"devices/{kind}") for kind in
                    ("hostdev", "filesystem", "tpm", "shmem", "memory", "pstore", "lease", "smartcard", "vsock", "parallel")),
            "shared host devices/state are out of scope")
    require(not root.findall(f"{{{QEMU}}}*"), "unexpected original QEMU extensions")
    disk = config["clone_disk"]
    devices = root.find("devices")
    require(not devices.findall(".//log"), "inherited writable log endpoints are unsupported")
    for char in devices.findall("serial") + devices.findall("console"):
        require(char.get("type") == "pty" and char.find("source") is None
                and all(child.tag in {"target", "address", "alias"} for child in char),
                "only automatically allocated PTY serial/console backends are supported")
    for channel in devices.findall("channel"):
        if channel.get("type") == "spicevmc":
            continue  # Removed below with the other SPICE-only devices.
        target = channel.find("target")
        require(channel.get("type") == "unix" and channel.find("source") is None
                and target is not None and target.get("type") == "virtio"
                and target.get("name") == "org.qemu.guest_agent.0"
                and all(child.tag in {"target", "address", "alias"} for child in channel),
                "only a libvirt-allocated QGA Unix channel is supported")
    disks = [d for d in devices.findall("disk") if d.get("device") == "disk"]
    require(len(disks) == 1 and disks[0].get("type") == "file", "expected exactly one file-backed disk")
    old_disk = disks[0].find("source").get("file")
    require(disks[0].find("source").attrib == {"file": old_disk} and not list(disks[0].find("source"))
            and not any(disks[0].find(name) is not None for name in
                        ("backingStore", "mirror", "dataStore", "auth", "encryption", "reservations", "shareable", "transient")),
            "inherited disk sidecars/shared state are unsupported")
    require(old_disk and os.path.normpath(old_disk) != disk, "refusing original disk reuse")
    disks[0].find("source").set("file", disk)
    for old in devices.findall("disk"):
        if old is not disks[0]:
            devices.remove(old)
    clone_uuid = config["clone_uuid"]
    root.find("name").text = config["clone_name"]
    root.find("uuid").text = clone_uuid
    for name in ("memory", "currentMemory"):
        element = root.find(name)
        require(element is not None, "missing memory configuration")
        element.set("unit", "MiB")
        element.text = str(config["memory_mib"])
    root.find("vcpu").text = str(config["vcpus"])
    if root.find("genid") is not None:
        root.find("genid").text = str(uuid.uuid4())
    for label in root.findall("seclabel"):
        root.remove(label)
    for interface in devices.findall("interface"):
        require(interface.get("type") == "network" and interface.find("source").get("network") is not None,
                "only an existing libvirt-managed network is supported")
        mac = interface.find("mac")
        require(mac is not None, "explicit NIC MAC required")
        mac.set("address", "52:54:00:" + ":".join(f"{b:02x}" for b in secrets.token_bytes(3)))
        target = interface.find("target")
        if target is not None:
            interface.remove(target)
    for old in list(devices):
        if old.tag in {"graphics", "input", "sound", "audio", "redirdev", "redirfilter"} or (old.tag == "channel" and old.get("type") == "spicevmc"):
            devices.remove(old)
    features = root.find("features")
    require(features is not None, "missing features")
    for old in features.findall("ps2"):
        features.remove(old)
    ET.SubElement(features, "ps2", state="off")
    require(len(devices.findall("video")) == 1, "expected exactly one primary GPU")
    gpu0 = devices.find("video")
    require(gpu0.find("model").get("type") == "virtio", "expected primary virtio GPU")
    alias(gpu0, "ua-m1-seat0-gpu")
    gpu0.find("model").set("heads", "1")
    controllers = devices.findall("controller")
    indexes = [int(x.get("index")) for x in controllers if x.get("type") == "pci"]
    require(sorted(indexes) == list(range(max(indexes) + 1)), "noncontiguous PCI controller indexes")
    used_buses = {int(a.get("bus"), 0) for x in devices for a in x.findall("address") if a.get("type") == "pci"}
    free_ports = [int(x.get("index")) for x in controllers if x.get("type") == "pci" and x.get("model") == "pcie-root-port" and int(x.get("index")) not in used_buses]
    require(len(free_ports) >= 3, "need three free existing PCIe root ports")
    parent_port, keyboard_port, tablet_port = free_ports[:3]
    for kind, bus in [("keyboard", keyboard_port), ("tablet", tablet_port)]:
        name = f"ua-m1-seat0-{kind}"
        element = ET.SubElement(devices, "input", type=kind, bus="virtio")
        alias(element, name)
        address(element, bus, 0)
        override(root, name, display="ua-m1-seat0-gpu", head=0)
    # The primary-only XML offers an offline setup fallback. It shares only the
    # clone identity and clone disk, never the original identity or original disk.
    primary = copy.deepcopy(root)
    def add_vnc(tree, count):
        args = ET.SubElement(tree, f"{{{QEMU}}}commandline")
        for seat in range(count):
            ET.SubElement(args, f"{{{QEMU}}}arg", value="-vnc")
            ET.SubElement(args, f"{{{QEMU}}}arg", value=f"127.0.0.1:{98+seat},id=m1seat{seat},display=ua-m1-seat{seat}-gpu,head=0,connections=2")
    add_vnc(primary, 1)
    upstream_index, seat_index = max(indexes) + 1, max(indexes) + 2
    upstream = ET.SubElement(devices, "controller", type="pci", index=str(upstream_index), model="pcie-to-pci-bridge")
    ET.SubElement(upstream, "model", name="pcie-pci-bridge")
    alias(upstream, "ua-m1-seat1-upstream")
    address(upstream, parent_port, 0)
    bridge = ET.SubElement(devices, "controller", type="pci", index=str(seat_index), model="pci-bridge")
    ET.SubElement(bridge, "model", name="pci-bridge")
    ET.SubElement(bridge, "target", chassisNr=str(seat_index))
    alias(bridge, "ua-m1-seat1-bridge")
    address(bridge, upstream_index, 1)
    override(root, "ua-m1-seat1-bridge", driver="pci-bridge-seat")
    gpu1 = ET.SubElement(devices, "video")
    ET.SubElement(gpu1, "model", type="virtio", heads="1")
    alias(gpu1, "ua-m1-seat1-gpu")
    address(gpu1, seat_index, 2)
    for kind, slot in [("keyboard", 3), ("tablet", 4)]:
        name = f"ua-m1-seat1-{kind}"
        element = ET.SubElement(devices, "input", type=kind, bus="virtio")
        alias(element, name)
        address(element, seat_index, slot)
        override(root, name, display="ua-m1-seat1-gpu", head=0)
    add_vnc(root, 2)
    defer_inputs(primary)
    defer_inputs(root)
    common = '''# Clone-only M1 topology rule; installed offline before the two-GPU boot.
ACTION=="remove", GOTO="localpin_m1_topology_end"
# Exact emulated seat bridge, never an ordinary host/guest bridge.
SUBSYSTEM=="pci", ATTR{vendor}=="0x1b36", ATTR{device}=="0x000a", ENV{ID_AUTOSEAT}="", ENV{ID_SEAT}="seat1", TAG+="seat"
# Assign descendants before 73-seat-late.rules adds the seat tag.
SUBSYSTEMS=="pci", ATTRS{vendor}=="0x1b36", ATTRS{device}=="0x000a", ENV{ID_SEAT}="seat1"
'''
    suffix = 'LABEL="localpin_m1_topology_end"\n'
    master = 'SUBSYSTEM=="drm", KERNEL=="card[0-9]*", SUBSYSTEMS=="pci", ATTRS{vendor}=="0x1b36", ATTRS{device}=="0x000a", '
    hidden_rule = common + '# Stage 0: no master means no graphical seat/PLM greeter yet.\n' + master + 'TAG-="master-of-seat"\n' + suffix
    active_rule = common + '# Stage 1: expose the owned graphics device as a real seat master.\n' + master + 'TAG+="master-of-seat"\n' + suffix
    manifest = {"source_uuid": config["source_uuid"], "clone_name": config["clone_name"], "clone_uuid": clone_uuid,
                "clone_disk": disk, "original_disk": old_disk, "root_port": parent_port,
                "seat_bridge_controller_index": seat_index, "vnc_ports": [5998, 5999],
                "validation": "XML proposal only; root must validate generated native args and paused QEMU before guest boot"}
    for name, value in [("clone-primary-only.xml", serialize(primary)), ("clone-two-seat.xml", serialize(root)),
                        ("72-localpin-m1-topology-hidden.rules", hidden_rule), ("72-localpin-m1-topology-active.rules", active_rule),
                        ("manifest.json", json.dumps(manifest, indent=2) + "\n"),
                        ("vm.guard", f"LOCALPIN-M1-DISPOSABLE-VM\ntarget=localpintest\nuuid={clone_uuid}\n"),
                        ("topology.guard", f"LOCALPIN-M1-TOPOLOGY-CLONE\ntarget=localpintest\nuuid={clone_uuid}\n")]:
        write_new(directory/name, value)
    print("Private clone XML, rules, manifest and dual guard proposals written; no VM or disk operation performed")


def validate_native(path):
    native = regular_bytes(path, 2097152).decode("utf-8")
    args = shlex.split(native)
    devices = {}
    order = {}
    vncs = []
    for i, value in enumerate(args):
        if value == "-device":
            text = args[i+1]
            if text.startswith("{"):
                entry = json.loads(text)
            else:
                pieces = text.split(",")
                entry = {"driver": pieces[0], **dict(x.split("=", 1) for x in pieces[1:] if "=" in x)}
            require(entry.get("id") not in devices, "duplicate native device ID")
            devices[entry.get("id")] = entry
            order[entry.get("id")] = i
        if value == "-vnc":
            vncs.append(args[i+1])
    require("-spice" not in args and not any("spicevmc" in x for x in args), "SPICE remains in native arguments")
    require(vncs == [f"127.0.0.1:{98+s},id=m1seat{s},display=ua-m1-seat{s}-gpu,head=0,connections=2" for s in range(2)],
            "need exactly the two fixed loopback VNC servers")
    require(devices["ua-m1-seat1-bridge"]["driver"] == "pci-bridge-seat", "seat bridge override did not apply")
    require(devices["ua-m1-seat1-gpu"].get("bus") == "ua-m1-seat1-bridge", "secondary GPU is outside seat bridge")
    inputs = [x for x in devices.values() if x.get("driver") in {
        "virtio-keyboard-pci", "virtio-tablet-pci", "virtio-mouse-pci", "usb-kbd", "usb-tablet", "usb-mouse"}]
    require(len(inputs) == 4, "unexpected extra or missing input device")
    for seat in range(2):
        require(f"display=ua-m1-seat{seat}-gpu,head=0" in vncs[seat], "VNC routing missing")
        require("virtio" in devices[f"ua-m1-seat{seat}-gpu"]["driver"], "virtio GPU missing")
        for kind in ["keyboard", "tablet"]:
            entry = devices[f"ua-m1-seat{seat}-{kind}"]
            require(entry.get("driver") == f"virtio-{kind}-pci", "wrong input model")
            require(entry.get("display") == f"ua-m1-seat{seat}-gpu" and int(entry.get("head", -1)) == 0, "input binding missing")
            if seat == 1:
                require(entry.get("bus") == "ua-m1-seat1-bridge", "secondary input outside seat bridge")
            require(order[f"ua-m1-seat{seat}-gpu"] < order[f"ua-m1-seat{seat}-{kind}"],
                    "GPU must be realized before routed input; early failed bind is silently discarded by QEMU")
    require(any("i8042=off" in x or '"i8042":false' in x for x in args), "PS/2 controller was not disabled")
    print("Native argv routing assertions PASS; no QEMU process was started")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--prepare", action="store_true")
    group.add_argument("--validate-native", type=Path)
    parser.add_argument("--original", type=Path)
    parser.add_argument("--config", type=Path, help="explicit private 0600 lab configuration; see HARDWARE.md")
    parser.add_argument("--out", type=Path, help="existing private 0700 output directory")
    args = parser.parse_args()
    if args.validate_native:
        validate_native(args.validate_native)
    else:
        require(args.original is not None and args.config is not None and args.out is not None,
                "source XML, private configuration and output directory required")
        prepare(args.original, private_config(args.config), args.out)


if __name__ == "__main__":
    main()
