#!/usr/bin/env python3
"""Fixed public input markers to two operator-verified clone VNC consoles.

No framebuffer requests, password input, configurable destination or key input.
The operator must pair this with the bounded guest F11/F12/ABS counter and close
other viewers during that phase. Creating this file does not execute it.
"""
# SPDX-License-Identifier: MIT OR Apache-2.0
import json
import socket
import struct
import time

VERSION = b"RFB 003.008\n"
ENDPOINTS = (("seat-a", 5998, 0xFFC8, 1), ("seat-b", 5999, 0xFFC9, 3))


class ProbeError(Exception):
    pass


def remaining(sock, deadline):
    duration = deadline - time.monotonic()
    if duration <= 0:
        raise ProbeError("deadline")
    sock.settimeout(min(duration, 1.0))


def receive(sock, size, deadline):
    data = bytearray()
    while len(data) < size:
        remaining(sock, deadline)
        part = sock.recv(size - len(data))
        if not part:
            raise ProbeError("early-eof")
        data.extend(part)
    return bytes(data)


def send(sock, data, deadline):
    remaining(sock, deadline)
    sock.sendall(data)


def pause(sock, seconds, deadline):
    if deadline - time.monotonic() < seconds:
        raise ProbeError("deadline")
    time.sleep(seconds)
    remaining(sock, deadline)


def probe(alias, port, keysym, fraction):
    # Only this module's fixed endpoints/markers are accepted, even if a caller
    # imports it. The public CLI accepts no options or arbitrary data.
    if (alias, port, keysym, fraction) not in ENDPOINTS:
        raise ProbeError("invalid-fixed-endpoint")
    deadline = time.monotonic() + 4.0
    key_down = False
    key_up = struct.pack("!BBHI", 4, 0, 0, keysym)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        try:
            remaining(sock, deadline)
            sock.connect(("127.0.0.1", port))
            if receive(sock, 12, deadline) != VERSION:
                raise ProbeError("unsupported-rfb-version")
            send(sock, VERSION, deadline)
            choices = receive(sock, 1, deadline)[0]
            if not 1 <= choices <= 16:
                raise ProbeError("unsupported-security-list")
            if 1 not in receive(sock, choices, deadline):
                raise ProbeError("no-unauthenticated-fixture-mode")
            send(sock, b"\x01", deadline)  # Only the isolated no-auth fixture.
            if receive(sock, 4, deadline) != b"\0\0\0\0":
                raise ProbeError("security-result")
            send(sock, b"\x01", deadline)  # Shared, so another viewer is not evicted.
            header = receive(sock, 24, deadline)
            width, height = struct.unpack("!HH", header[:4])
            name_size = struct.unpack("!I", header[20:24])[0]
            if not (16 <= width <= 16384 and 16 <= height <= 16384 and name_size <= 1024):
                raise ProbeError("unbounded-server-init")
            receive(sock, name_size, deadline)  # Never print the desktop name.
            # QEMU initializes its absolute-pointer mode in SetEncodings. Raw
            # here advertises an encoding only; it requests no framebuffer.
            send(sock, struct.pack("!BBHi", 2, 0, 1, 0), deadline)
            if deadline - time.monotonic() < 0.8:
                raise ProbeError("insufficient-input-budget")
            send(sock, struct.pack("!BBHI", 4, 1, 0, keysym), deadline)
            key_down = True
            pause(sock, 0.05, deadline)
            send(sock, key_up, deadline)
            key_down = False
            # Two distinct button-free positions in the same low/high bin make
            # reruns observable even when the first coordinate is unchanged.
            send(sock, struct.pack("!BBHH", 5, 0, width * fraction // 4, height * fraction // 4), deadline)
            numerator = 1 if fraction == 1 else 7
            send(sock, struct.pack("!BBHH", 5, 0, width * numerator // 8, height * numerator // 8), deadline)
            # QEMU handles HUP before readable input in vnc_client_io. Closing
            # immediately can discard markers that were merely queued locally.
            # This is a bounded drain opportunity, not a delivery receipt; only
            # the paired guest counters can prove the intended device routing.
            pause(sock, 0.5, deadline)
            return {"console": alias, "fixed_key_pair_sent": True, "fixed_pointer_sent": True,
                    "encoding_initialized": True, "post_input_hold_ms": 500,
                    "framebuffer_requested": False, "routing_proven_by_sender": False}
        finally:
            if key_down:
                try:
                    send(sock, key_up, deadline)
                except (ProbeError, OSError):
                    pass  # Close always follows; report cannot count as a pass.


def main():
    import sys
    if len(sys.argv) != 1:
        print("Fixed-input probe accepts no options", file=sys.stderr)
        return 1
    results = []
    try:
        for endpoint in ENDPOINTS:
            results.append(probe(*endpoint))
    except (ProbeError, OSError):
        print(json.dumps({"completed": False, "category": "fixed-input-transport-failure",
                          "routing_proven_by_sender": False}))
        return 1
    print(json.dumps({"completed": True, "results": results, "routing_proven_by_sender": False}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
