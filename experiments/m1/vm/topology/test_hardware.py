"""Pure safety tests: synthetic XML/files and fake RFB sockets, never VM/input I/O."""
# SPDX-License-Identifier: MIT OR Apache-2.0
from contextlib import redirect_stdout
import importlib.util
import io
import json
import os
from pathlib import Path
import shlex
import struct
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import xml.etree.ElementTree as ET

HERE = Path(__file__).resolve().parent


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


hardware = load("m1_hardware_test", "prepare-hardware.py")
counter = load("m1_counter_test", "count-public-input.py")
probe = load("m1_probe_test", "probe-vnc.py")


class HardwareTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.config = {
            "source_name": "synthetic-source", "source_uuid": "11111111-1111-4111-8111-111111111111",
            "clone_name": "synthetic-clone", "clone_uuid": "22222222-2222-4222-8222-222222222222",
            "clone_disk": "/synthetic/clone.qcow2", "memory_mib": 8192, "vcpus": 4,
        }
        self.config_path = self.root / "private.json"
        self.config_path.write_text(json.dumps(self.config))
        self.config_path.chmod(0o600)
        self.source = self.root / "original.xml"
        self.source.write_text('''<domain type="kvm"><name>synthetic-source</name>
<uuid>11111111-1111-4111-8111-111111111111</uuid><memory unit="MiB">4096</memory>
<currentMemory unit="MiB">4096</currentMemory><vcpu>2</vcpu>
<os><type arch="x86_64" machine="pc-q35-10.2">hvm</type></os><features/>
<devices><disk type="file" device="disk"><source file="/synthetic/source.qcow2"/></disk>
<controller type="pci" index="0" model="pcie-root"/>
<controller type="pci" index="1" model="pcie-root-port"/>
<controller type="pci" index="2" model="pcie-root-port"/>
<controller type="pci" index="3" model="pcie-root-port"/>
<video><model type="virtio" heads="1" primary="yes"/></video>
<graphics type="spice"/><input type="keyboard" bus="ps2"/></devices></domain>''')

    def prepare(self):
        with redirect_stdout(io.StringIO()):
            hardware.prepare(self.source, hardware.private_config(self.config_path), self.root)

    def test_generation_is_private_and_never_changes_source(self):
        original = self.source.read_bytes()
        self.prepare()
        self.assertEqual(self.source.read_bytes(), original)
        tree = ET.parse(self.root / "clone-two-seat.xml").getroot()
        self.assertEqual(tree.findtext("uuid"), self.config["clone_uuid"])
        self.assertEqual(tree.findtext("memory"), "8192")
        self.assertIsNone(tree.find("devices/graphics"))
        self.assertEqual(tree.findall("devices/input"), [])
        args = [x.get("value") for x in tree.find(f"{{{hardware.QEMU}}}commandline")]
        specs = [json.loads(args[i + 1]) for i, arg in enumerate(args) if arg == "-device"]
        self.assertEqual(len(specs), 4)
        self.assertEqual({x["display"] for x in specs}, {"ua-m1-seat0-gpu", "ua-m1-seat1-gpu"})
        for filename, heading in (("vm.guard", "LOCALPIN-M1-DISPOSABLE-VM"),
                                  ("topology.guard", "LOCALPIN-M1-TOPOLOGY-CLONE")):
            path = self.root / filename
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(path.read_text(), f'{heading}\ntarget=localpintest\nuuid={self.config["clone_uuid"]}\n')

    def test_refuses_source_disk_reuse(self):
        self.config["clone_disk"] = "/synthetic/source.qcow2"
        self.config_path.write_text(json.dumps(self.config))
        with self.assertRaisesRegex(RuntimeError, "original disk reuse"):
            self.prepare()

    def test_refuses_source_identity_mismatch(self):
        self.config["source_uuid"] = "33333333-3333-4333-8333-333333333333"
        self.config_path.write_text(json.dumps(self.config))
        with self.assertRaisesRegex(RuntimeError, "source identity"):
            self.prepare()

    def test_refuses_shared_state_devices(self):
        for tag in ("hostdev", "filesystem", "tpm", "shmem", "memory", "pstore", "lease", "smartcard", "vsock", "parallel"):
            with self.subTest(tag=tag):
                source = self.source.read_text()
                self.source.write_text(source.replace("<devices>", f"<devices><{tag}/>"))
                with self.assertRaisesRegex(RuntimeError, "shared host devices"):
                    self.prepare()
                self.source.write_text(source)

    def test_refuses_inherited_writable_character_endpoints(self):
        endpoints = (
            '<channel type="unix"><source mode="bind" path="/synthetic/original.sock"/><target type="virtio" name="org.qemu.guest_agent.0"/></channel>',
            '<channel type="unix"><target type="virtio" name="other-agent"/></channel>',
            '<serial type="file"><source path="/synthetic/original.log"/></serial>',
            '<console type="pty"><source path="/dev/pts/99"/></console>',
            '<serial type="pty"><log file="/synthetic/original.log"/></serial>',
        )
        for endpoint in endpoints:
            with self.subTest(endpoint=endpoint):
                source = self.source.read_text()
                self.source.write_text(source.replace("<devices>", "<devices>" + endpoint))
                with self.assertRaisesRegex(RuntimeError, "endpoints|backends|channel"):
                    self.prepare()
                self.source.write_text(source)

    def test_accepts_only_auto_allocated_qga_and_pty(self):
        self.source.write_text(self.source.read_text().replace("<devices>", '''<devices>
<channel type="unix"><target type="virtio" name="org.qemu.guest_agent.0"/></channel>
<serial type="pty"><target type="isa-serial" port="0"/></serial>
<console type="pty"><target type="serial" port="0"/></console>'''))
        self.prepare()
        tree = ET.parse(self.root / "clone-two-seat.xml").getroot()
        self.assertIsNone(tree.find("devices/channel/source"))
        self.assertEqual(tree.find("devices/serial").get("type"), "pty")

    def test_refuses_disk_sidecars(self):
        for sidecar in ("backingStore", "mirror", "dataStore", "auth", "encryption", "reservations", "shareable", "transient"):
            with self.subTest(sidecar=sidecar):
                source = self.source.read_text()
                self.source.write_text(source.replace("</disk>", f"<{sidecar}/></disk>"))
                with self.assertRaisesRegex(RuntimeError, "disk sidecars/shared state"):
                    self.prepare()
                self.source.write_text(source)

    def test_fifo_inputs_refuse_without_waiting_for_a_writer(self):
        fifo = self.root / "fifo"
        os.mkfifo(fifo, 0o600)
        code = '''import importlib.util, sys
from pathlib import Path
spec = importlib.util.spec_from_file_location("fifo_test", sys.argv[1])
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
try:
    getattr(m, sys.argv[2])(Path(sys.argv[3]), *([64] if sys.argv[2] == "regular_bytes" else []))
except RuntimeError:
    sys.exit(0)
sys.exit(1)
'''
        for module, function in (("prepare-hardware.py", "private_config"),
                                 ("prepare-hardware.py", "regular_bytes"),
                                 ("count-public-input.py", "guarded_bytes")):
            with self.subTest(function=function):
                result = subprocess.run([sys.executable, "-c", code, str(HERE/module), function, str(fifo)],
                                        capture_output=True, timeout=3)
                self.assertEqual(result.returncode, 0, "FIFO did not fail its regular-file guard")

    def test_refuses_nonprivate_or_linked_configuration(self):
        self.config_path.chmod(0o644)
        with self.assertRaisesRegex(RuntimeError, "0600"):
            hardware.private_config(self.config_path)
        self.config_path.chmod(0o600)
        linked = self.root / "linked"
        linked.symlink_to(self.config_path)
        with self.assertRaises(OSError):
            hardware.private_config(linked)
        linked.unlink()
        os.link(self.config_path, linked)
        with self.assertRaisesRegex(RuntimeError, "single-link"):
            hardware.private_config(self.config_path)

    def test_refuses_same_domain_and_unsafe_clone_path(self):
        for key, value in (("clone_uuid", self.config["source_uuid"]), ("clone_name", self.config["source_name"]),
                           ("clone_disk", "/synthetic/../source.qcow2")):
            with self.subTest(key=key):
                self.config_path.write_text(json.dumps({**self.config, key: value}))
                with self.assertRaises(RuntimeError):
                    hardware.private_config(self.config_path)

    def test_refuses_output_overwrite(self):
        self.prepare()
        existing = (self.root / "clone-primary-only.xml").read_bytes()
        with self.assertRaises(FileExistsError):
            self.prepare()
        self.assertEqual((self.root / "clone-primary-only.xml").read_bytes(), existing)

    def native(self, *, early_input=False, public_listen=False):
        devices = [{"driver": "pci-bridge-seat", "id": "ua-m1-seat1-bridge"}]
        inputs = []
        for seat in range(2):
            devices.append({"driver": "virtio-vga" if not seat else "virtio-gpu-pci", "id": f"ua-m1-seat{seat}-gpu",
                            "bus": "pcie.0" if not seat else "ua-m1-seat1-bridge"})
            for kind in ("keyboard", "tablet"):
                inputs.append({"driver": f"virtio-{kind}-pci", "id": f"ua-m1-seat{seat}-{kind}",
                               "bus": "pci.2" if not seat else "ua-m1-seat1-bridge",
                               "display": f"ua-m1-seat{seat}-gpu", "head": 0})
        devices = inputs + devices if early_input else devices + inputs
        args = ["qemu-system-x86_64", "-machine", "pc-q35-10.2,i8042=off"]
        for device in devices:
            args += ["-device", json.dumps(device)]
        for seat in range(2):
            args += ["-vnc", f'{"0.0.0.0" if public_listen else "127.0.0.1"}:{98+seat},id=m1seat{seat},display=ua-m1-seat{seat}-gpu,head=0,connections=2']
        path = self.root / "native.txt"
        path.write_text(shlex.join(args))
        return path

    def test_native_requires_gpu_before_input_and_private_listener(self):
        with redirect_stdout(io.StringIO()):
            hardware.validate_native(self.native())
        with self.assertRaisesRegex(RuntimeError, "GPU must be realized before"):
            hardware.validate_native(self.native(early_input=True))
        with self.assertRaisesRegex(RuntimeError, "fixed loopback"):
            hardware.validate_native(self.native(public_listen=True))

    def test_counter_refuses_before_device_access_on_host(self):
        with patch.object(counter.os, "getuid", return_value=1000), patch.object(counter.os, "geteuid", return_value=1000):
            with self.assertRaisesRegex(RuntimeError, "guest root"):
                counter.guard()
        with patch.object(counter, "guard", side_effect=RuntimeError("missing dual guards")), patch.object(counter.sys, "argv", ["counter"]):
            with self.assertRaisesRegex(RuntimeError, "missing dual guards"):
                counter.main()

    def test_counter_requires_both_exact_dmi_bound_markers(self):
        identity = self.config["clone_uuid"]
        expected = {
            "/etc/localpin-m1-vm-guard": f"LOCALPIN-M1-DISPOSABLE-VM\ntarget=localpintest\nuuid={identity}\n".encode(),
            "/etc/localpin-m1-topology-clone-guard": f"LOCALPIN-M1-TOPOLOGY-CLONE\ntarget=localpintest\nuuid={identity}\n".encode(),
        }

        def read(path):
            return identity if str(path).endswith("product_uuid") else "1"

        for wrong_marker in (None, *expected):
            with self.subTest(wrong_marker=wrong_marker):
                markers = dict(expected)
                if wrong_marker:
                    markers[wrong_marker] = b"marker for another VM\n"
                with patch.object(counter.os, "getuid", return_value=0), patch.object(counter.os, "geteuid", return_value=0), \
                        patch.object(counter.Path, "read_text", read), \
                        patch.object(counter, "guarded_bytes", side_effect=markers.__getitem__) as guard_read, \
                        patch.object(counter.subprocess, "run", return_value=SimpleNamespace(returncode=0)) as vm_check:
                    if wrong_marker:
                        with self.assertRaisesRegex(RuntimeError, "guard mismatch"):
                            counter.guard()
                        vm_check.assert_not_called()
                    else:
                        counter.guard()
                        self.assertEqual({call.args[0] for call in guard_read.call_args_list}, set(expected))
                        vm_check.assert_called_once()

    def test_counter_guard_refuses_symlink_before_reading(self):
        link = self.root / "guard-link"
        link.symlink_to(self.config_path)
        with self.assertRaises(OSError):
            counter.guarded_bytes(link)


class FakeSocket:
    def __init__(self):
        self.response = bytearray(probe.VERSION + b"\x01\x01" + bytes(4) + struct.pack("!HH", 800, 600) + bytes(16) + struct.pack("!I", 0))
        self.sent = []
        self.address = None

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return None

    def settimeout(self, value):
        pass

    def connect(self, address):
        self.address = address

    def recv(self, size):
        value = bytes(self.response[:size])
        del self.response[:size]
        return value

    def sendall(self, data):
        self.sent.append(data)


class ProbeTests(unittest.TestCase):
    def test_fixed_routes_keys_and_two_positions_with_no_image_request(self):
        for endpoint in probe.ENDPOINTS:
            with self.subTest(endpoint=endpoint[0]):
                sock = FakeSocket()
                with patch.object(probe.socket, "socket", return_value=sock), patch.object(probe.time, "sleep") as sleep:
                    result = probe.probe(*endpoint)
                self.assertEqual(sock.address, ("127.0.0.1", endpoint[1]))
                self.assertEqual(sock.sent[3], struct.pack("!BBHi", 2, 0, 1, 0))
                self.assertEqual(sock.sent[4], struct.pack("!BBHI", 4, 1, 0, endpoint[2]))
                self.assertEqual(sock.sent[5], struct.pack("!BBHI", 4, 0, 0, endpoint[2]))
                self.assertNotEqual(sock.sent[6], sock.sent[7])
                self.assertEqual(len(sock.sent), 8)  # No framebuffer request, clipboard or extra key.
                self.assertEqual([x.args[0] for x in sleep.call_args_list], [0.05, 0.5])
                self.assertFalse(result["routing_proven_by_sender"])

    def test_refuses_arbitrary_destination_or_key(self):
        with patch.object(probe.socket, "socket") as socket:
            with self.assertRaisesRegex(probe.ProbeError, "invalid-fixed-endpoint"):
                probe.probe("other", 5900, ord("a"), 1)
            socket.assert_not_called()

    def test_cli_options_cannot_select_another_target(self):
        import sys
        with patch.object(sys, "argv", ["probe", "--host=example.invalid"]), redirect_stdout(io.StringIO()), patch("sys.stderr", io.StringIO()):
            self.assertEqual(probe.main(), 1)


if __name__ == "__main__":
    unittest.main()
