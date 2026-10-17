#!/usr/bin/env python3
"""Clone-only 20s event counter for fixed public F11/F12 and pointer markers.

Never export character keys, timestamps, raw input values or device paths. Run
only while no human is typing; stop this process before any password entry.
"""
# SPDX-License-Identifier: MIT OR Apache-2.0
import json
import os
from pathlib import Path
import selectors
import stat
import struct
import subprocess
import sys
import time
import uuid

EVENT = struct.Struct("@llHHi")


def require(value, message):
    if not value:
        raise RuntimeError(message)


def guarded_bytes(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as source:
        info = os.fstat(source.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_uid == info.st_gid == 0 and
                stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1, "unsafe clone guard")
        data = source.read(257)
    require(len(data) <= 256, "oversized clone guard")
    return data


def guard():
    require(os.getuid() == os.geteuid() == 0, "guest root required")
    identity = Path("/sys/class/dmi/id/product_uuid").read_text().strip()
    require(str(uuid.UUID(identity)) == identity, "noncanonical DMI UUID")
    require(Path("/sys/fs/selinux/enforce").read_text().strip() == "1", "Enforcing required")
    for path, heading in (("/etc/localpin-m1-vm-guard", "LOCALPIN-M1-DISPOSABLE-VM"),
                          ("/etc/localpin-m1-topology-clone-guard", "LOCALPIN-M1-TOPOLOGY-CLONE")):
        require(guarded_bytes(path) == f"{heading}\ntarget=localpintest\nuuid={identity}\n".encode(),
                "clone guard mismatch")
    result = subprocess.run(["systemd-detect-virt", "--vm"], capture_output=True, timeout=5)
    require(result.returncode == 0, "virtual machine required")


def main():
    require(len(sys.argv) == 1, "counter accepts no options")
    guard()
    require(EVENT.size == 24, "fixture supports only observed x86_64 event ABI")
    bridges = [p.resolve() for p in Path("/sys/bus/pci/devices").iterdir()
               if (p/"vendor").read_text().strip() == "0x1b36" and (p/"device").read_text().strip() == "0x000a"]
    require(len(bridges) == 1, "need exactly one owned special bridge")
    bridge = bridges[0]
    counters = {}
    descriptors = []
    selector = selectors.DefaultSelector()
    try:
        for event in Path("/sys/class/input").glob("event*"):
            name = (event/"device/name").read_text().strip()
            kind = {"QEMU Virtio Keyboard": "keyboard", "QEMU Virtio Tablet": "tablet"}.get(name)
            if kind is None:
                continue
            seat = 1 if event.resolve().is_relative_to(bridge) else 0
            key = f"seat{seat}_{kind}"
            require(key not in counters, "duplicate routed device")
            fd = os.open(Path("/dev/input")/event.name, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
            descriptors.append(fd)
            st = os.fstat(fd)
            require(stat.S_ISCHR(st.st_mode), "expected input character device")
            major, minor = (int(x) for x in (event/"dev").read_text().strip().split(":"))
            require(os.major(st.st_rdev) == major and os.minor(st.st_rdev) == minor, "event device changed")
            # Drain prior public/nonpublic events without retaining their values.
            for _ in range(32):
                try:
                    if not os.read(fd, EVENT.size*64):
                        break
                except BlockingIOError:
                    break
            else:
                raise RuntimeError("input remained busy during bounded initial drain")
            counters[key] = {"f11_down": 0, "f12_down": 0, "abs_low": 0, "abs_high": 0}
            selector.register(fd, selectors.EVENT_READ, key)
        require(set(counters) == {f"seat{s}_{k}" for s in range(2) for k in ["keyboard", "tablet"]}, "need four distinct routed devices")
        print("READY: fixed-public-input counter active for 20s; no human typing", file=sys.stderr, flush=True)
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            for selected, _ in selector.select(timeout=min(0.25, max(0, deadline-time.monotonic()))):
                data = os.read(selected.fd, EVENT.size*64)
                require(len(data) % EVENT.size == 0, "incomplete input event ABI")
                for offset in range(0, len(data), EVENT.size):
                    _, _, kind, code, value = EVENT.unpack_from(data, offset)
                    require(not (kind == 0 and code == 3), "input queue overflow; routing evidence incomplete")
                    count = counters[selected.data]
                    if kind == 1 and value == 1 and code in {87,88}:
                        count["f11_down" if code == 87 else "f12_down"] += 1
                    elif kind == 3 and code in {0,1}:
                        if 0 < value < 12288:
                            count["abs_low"] += 1
                        elif 20480 < value <= 32767:
                            count["abs_high"] += 1
                    # All other keys/events/values are discarded, never logged.
        checks = {
            "seat0_keyboard_f11_only": counters["seat0_keyboard"]["f11_down"] == 1 and counters["seat0_keyboard"]["f12_down"] == 0,
            "seat1_keyboard_f12_only": counters["seat1_keyboard"]["f12_down"] == 1 and counters["seat1_keyboard"]["f11_down"] == 0,
            "seat0_tablet_low_only": counters["seat0_tablet"]["abs_low"] > 0 and counters["seat0_tablet"]["abs_high"] == 0,
            "seat1_tablet_high_only": counters["seat1_tablet"]["abs_high"] > 0 and counters["seat1_tablet"]["abs_low"] == 0,
        }
        print(json.dumps({"fixture": "fixed public VNC input routing only", "fixed_markers": "F11/F12", "checks": checks,
                          "counters": counters, "routing_passed": all(checks.values()),
                          "second_desktop_proven": False, "password_or_authentication_tested": False}, indent=2))
        return 0 if all(checks.values()) else 1
    finally:
        selector.close()
        for fd in descriptors:
            os.close(fd)


if __name__ == "__main__":
    raise SystemExit(main())
