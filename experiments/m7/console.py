#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Guarded host keyboard controller for the one disposable M7 KDE clone.

This runs actual stock greeter input through libvirt, using pinned root SSH only
for guarded observations and transient candidate retrieval. It never installs
or changes protected guest state. Prepare each policy/fault phase separately
with the guest experiment manager before invoking this controller.
"""
import argparse
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import time
import uuid
import xml.etree.ElementTree as ET


ROOT = Path(__file__).resolve().parents[2]
PHASES = (
    "baseline", "pin", "password", "wrong-pin", "sixpassword", "profilepassword",
    "missing-module", "broker-stopped", "broker-crashed", "cooldown",
    "broker-stalled", "worker-missing", "corrupt-state", "tpm-fault",
    "disabled", "not-enrolled", "locked-account", "recovery",
    "nologin", "account-expired", "password-expired", "forced-change", "restricted-shell",
)
KEYS = dict(zip("1234567890", range(2, 12)))
KEYS.update(dict(zip("qwertyuiop", range(16, 26))))
KEYS.update(dict(zip("asdfghjkl", range(30, 39))))
KEYS.update(dict(zip("zxcvbnm", range(44, 51))))
KEYS["-"] = 12


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def owned_file(path, *, private=False):
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid()
            and info.st_nlink == 1 and not info.st_mode & (0o077 if private else 0o022),
            "unsafe clone access file")
    require(info.st_size <= 65536, "oversized clone access file")


class Console:
    def __init__(self, args, libvirt):
        self.args, self.libvirt = args, libvirt
        owned_file(args.access_dir / "id_ed25519", private=True)
        owned_file(args.access_dir / "known_hosts")
        owned_file(args.access_dir / "clone.json")
        self.manifest = json.loads((args.access_dir / "clone.json").read_text())
        require(self.manifest.get("name") == "localpin-m7"
                and self.manifest.get("independent_disk") is True
                and self.manifest.get("physical_tpm") is False
                and self.manifest.get("host_filesystem_shares") is False,
                "expected independent M7 clone manifest")
        self.uuid = str(uuid.UUID(self.manifest["uuid"]))
        self.connection = libvirt.open("qemu:///system")
        require(self.connection is not None, "libvirt system connection unavailable")
        self.domain = self.connection.lookupByUUIDString(self.uuid)
        self.original = self.connection.lookupByName("localpin-m1")
        self.guard_domain()
        self.ssh = [
            "ssh", "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes",
            "-o", "StrictHostKeyChecking=yes", "-o", "GlobalKnownHostsFile=/dev/null",
            "-o", f"UserKnownHostsFile={args.access_dir / 'known_hosts'}",
            "-o", "ConnectTimeout=8", "-o", "ServerAliveInterval=5",
            "-o", "ServerAliveCountMax=2", "-i", str(args.access_dir / "id_ed25519"),
            "root@" + args.address, "python3 -",
        ]

    def close(self):
        self.connection.close()

    def guard_domain(self):
        require(self.domain.name() == "localpin-m7" and self.domain.UUIDString().lower() == self.uuid
                and self.domain.isActive() == 1 and self.original.isActive() == 0,
                "M7 clone must be active and original localpin-m1 must remain off")
        tree = ET.fromstring(self.domain.XMLDesc(0))
        require(tree.findtext("name") == "localpin-m7" and tree.findtext("uuid").lower() == self.uuid,
                "clone domain identity changed")
        for name in ("hostdev", "filesystem"):
            require(not tree.findall(f"./devices/{name}"), "clone has forbidden host device/share/TPM")
        tpms = tree.findall("./devices/tpm")
        if self.args.emulated_tpm_confirmed:
            require(len(tpms) == 1 and tpms[0].get("model") == "tpm-crb",
                    "explicit emulator phase requires exactly one tpm-crb")
            backends = tpms[0].findall("backend")
            require(len(backends) == 1 and backends[0].get("type") == "emulator"
                    and backends[0].get("version") == "2.0"
                    and backends[0].find("device") is None,
                    "physical or unknown TPM backend is forbidden")
            sources = backends[0].findall("source")
            require(len(sources) <= 1, "multiple TPM sources are forbidden")
            if sources:
                require(sources[0].get("type") == "unix" and sources[0].get("mode") == "connect"
                        and re.fullmatch(r"/(?:var/)?run/libvirt/qemu/swtpm/[0-9]+-localpin-m7-swtpm\.sock",
                                         sources[0].get("path", "")) is not None,
                        "TPM source is not the clone's private libvirt emulator socket")
            inactive = ET.fromstring(self.domain.XMLDesc(self.libvirt.VIR_DOMAIN_XML_INACTIVE))
            configured = inactive.findall("./devices/tpm")
            require(len(configured) == 1 and configured[0].get("model") == "tpm-crb",
                    "configured TPM model differs from the active managed emulator")
            configured_backends = configured[0].findall("backend")
            require(len(configured_backends) == 1 and configured_backends[0].get("type") == "emulator"
                    and configured_backends[0].get("version") == "2.0"
                    and configured_backends[0].find("source") is None
                    and configured_backends[0].find("device") is None,
                    "configured emulator contains a caller-supplied source or device")
        else:
            require(not tpms, "TPM present without explicit emulator confirmation")
        disk_devices = tree.findall("./devices/disk")
        disks = [device for device in disk_devices if device.get("device") == "disk"]
        require(len(disks) == 1 and disks[0].get("type") == "file"
                and disks[0].find("driver") is not None and disks[0].find("driver").get("type") == "qcow2"
                and disks[0].find("source") is not None and disks[0].find("source").get("file") == self.manifest["disk"],
                "clone no longer uses its one independent disk")
        for device in disk_devices:
            if device is disks[0]:
                continue
            require(device.get("device") == "cdrom" and device.get("type") == "file"
                    and device.find("readonly") is not None and device.find("source") is None,
                    "only an empty read-only file CD-ROM may accompany the clone disk")
        original_xml = ET.fromstring(self.original.XMLDesc(0))
        require(all(source.get("file") != self.manifest["disk"]
                    for source in original_xml.findall("./devices/disk/source")),
                "clone disk is shared with original VM")

    def guest(self, body, *, timeout=60):
        self.guard_domain()
        # The imported guest script uses its own distinct name and separately
        # imports the M6.1 manager. No `import run` path ambiguity is possible.
        script = "\n".join([
            "import importlib.util, json, signal, stat",
            "from pathlib import Path",
            f"signal.alarm({max(1, min(50, int(timeout) - 1))})",
            "spec = importlib.util.spec_from_file_location('localpin_m7_console_guest', '/root/localpin-m7/run.py')",
            "m = importlib.util.module_from_spec(spec)",
            "spec.loader.exec_module(m)",
            "secrets = m.guard()",
            f"assert Path('/sys/class/dmi/id/product_uuid').read_text().strip().lower() == {self.uuid!r}",
            *(["marker = Path('/run/localpin-m7-emulator')",
               "info = marker.lstat()",
               "assert stat.S_ISREG(info.st_mode) and info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1",
               f"assert marker.read_text() == {self.uuid + chr(10) + 'emulator2.0' + chr(10)!r}"]
              if self.args.emulated_tpm_confirmed else []),
            body,
        ]) + "\n"
        try:
            result = subprocess.run(self.ssh, input=script.encode(), capture_output=True,
                                    timeout=min(60, timeout), check=False)
        except subprocess.TimeoutExpired:
            raise RuntimeError("bounded guarded guest observation timed out") from None
        # Never echo SSH stdout/stderr: stdout may contain a transient candidate.
        require(result.returncode == 0, "guarded pinned SSH guest operation failed")
        require(len(result.stdout) <= 65536, "oversized guest observation")
        try:
            return json.loads(result.stdout)
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise RuntimeError("invalid guarded guest response") from None

    def observe(self, *, status=False, timeout=60):
        return self.guest("\n".join([
            "result = {'locked': m.locked(), 'greeter_pids': m.locker_pid(),",
            "          'stock_policy': m.digest(m.KDE) == m.STOCK_DIGEST,",
            "          'integrated_policy': m.digest(m.KDE) == m.INTEGRATED_DIGEST}",
            "journal = m.command(['journalctl', '-b', '--no-pager', '-o', 'json',",
            "                     r'--grep=pam_unix\\(kde:auth\\).*authentication failure'], check=False)",
            "assert journal.returncode in (0, 1)",
            "events = [json.loads(line) for line in journal.stdout.splitlines()]",
            "events = [event for event in events if 'user=' + m.component.NAME in event.get('MESSAGE', '')]",
            "result['native_auth_failure_events'] = len(events)",
            "result['greeter_native_failure_events'] = sum(int(event['_PID']) in result['greeter_pids'] for event in events)",
            "try:",
            "    result['tally'] = m.tally()",
            "except FileNotFoundError:",
            "    result['tally'] = None",
            *( ["try:",
                "    state = m.component.status()",
                "    result['broker_status'] = {key: state.get(key) for key in ('availability', 'cooldown_ms', 'reason')}",
                "except Exception:",
                "    result['broker_status'] = {'available_to_controller': False}"] if status else []),
            "print(json.dumps(result))",
        ]), timeout=timeout)

    def candidate(self, selector):
        require(selector in ("pin", "password", "wrong", "wrongpin", "sixpassword", "profilepassword"),
                "unknown fixed candidate selector")
        response = self.guest("\n".join([
            "account = secrets[m.component.NAME]",
            f"selector = {selector!r}",
            "if selector == 'wrong':",
            "    candidate = 'not-the-disposable-password'",
            "    assert candidate not in (account['password'], account['pin'])",
            "elif selector == 'wrongpin':",
            "    profile = m.component.status()['credential_profile']",
            "    assert profile is not None and profile['kind'] == 'numeric-pin'",
            "    candidate = '0' * profile['length']",
            "    assert candidate not in (account['password'], account['pin'])",
            "elif selector == 'sixpassword':",
            "    candidate = account.get('sixpassword', account['password'])",
            "    assert len(candidate) == 6 and candidate.isascii() and candidate.isdigit()",
            "    assert candidate != account['pin']",
            "elif selector == 'profilepassword':",
            "    candidate = account['password']",
            "    profile = m.component.status()['credential_profile']",
            "    assert profile is not None and profile['kind'] == 'numeric-pin'",
            "    assert len(candidate) == profile['length'] and candidate.isascii() and candidate.isdigit()",
            "    assert candidate != account['pin']",
            "else:",
            "    candidate = account[selector]",
            "if selector == 'pin':",
            "    assert 8 <= len(candidate) <= 16 and candidate.isascii() and candidate.isdigit()",
            "    assert candidate != account['password']",
            "assert isinstance(candidate, str) and 0 < len(candidate) <= 64",
            "assert all(c in 'abcdefghijklmnopqrstuvwxyz0123456789-' for c in candidate)",
            "print(json.dumps({'candidate': candidate}))",
        ]))
        value = response.get("candidate")
        require(isinstance(value, str) and 0 < len(value) <= 64 and all(char in KEYS for char in value),
                "candidate cannot be represented by the reviewed keyboard mapping")
        return value

    def key(self, *codes):
        self.domain.sendKey(self.libvirt.VIR_KEYCODE_SET_LINUX, 40, list(codes), len(codes), 0)
        # sendKey returns before its delayed release. Leave a full release
        # interval so repeated letters and Ctrl+A cannot overlap later keys.
        time.sleep(0.08)

    def clear_input(self):
        self.guard_domain()
        self.key(29, 30)  # Left Ctrl+A, then Backspace: no clipboard or injection API.
        self.key(14)

    def type_candidate(self, selector):
        self.clear_input()
        candidate = self.candidate(selector)
        try:
            for char in candidate:
                self.key(KEYS[char])
        finally:
            # Python cannot guarantee erasure of immutable strings. The value
            # stays transient in this controller and is never printed or saved.
            del candidate

    def wait(self, locked, *, greeter=False):
        end = time.monotonic() + 15
        while time.monotonic() < end:
            result = self.observe(timeout=max(1, min(10, end - time.monotonic())))
            if result["locked"] is locked and (not greeter or len(result["greeter_pids"]) == 1):
                return result
            time.sleep(0.2)
        raise RuntimeError("KDE lock/unlock did not reach the expected state within 15 seconds")

    def lock(self):
        print("M7 UI: requesting dedicated desktop lock", file=sys.stderr, flush=True)
        require(self.observe()["locked"] is False, "start each UI phase from an unlocked dedicated desktop")
        self.guest("m.bus('Lock')\nprint(json.dumps({'requested_lock': True}))")
        self.wait(True)
        self.key(42)  # Shift wakes the stock greeter without submitting input.
        time.sleep(0.5)
        return self.wait(True, greeter=True)

    def unlock(self, selector, *, enter_required=False):
        print("M7 UI: typing selected private candidate", file=sys.stderr, flush=True)
        self.type_candidate(selector)
        return self.submit_typed(enter_required=enter_required)

    def submit_typed(self, *, enter_required=False):
        """Submit existing keyboard input after any separately observed startup."""
        without_enter = None
        if enter_required:
            time.sleep(0.8)
            without_enter = self.observe()
            require(without_enter["locked"] is True, "PIN unlocked before Enter")
        # Native noninteractive authenticators start alongside the password
        # conversation. Capture the submitted candidate's baseline only after
        # typing, immediately before Enter; keep lock-start accounting separate.
        before_enter = without_enter if without_enter is not None else self.observe()
        require(before_enter["locked"] is True, "desktop unlocked before candidate submission")
        started = time.monotonic()
        self.key(28)
        unlocked = self.wait(False)
        print("M7 UI: desktop unlocked", file=sys.stderr, flush=True)
        return {"unlocked": True, "enter_required_observed": without_enter is not None,
                "locked_before_enter": bool(without_enter and without_enter["locked"]),
                "unlock_elapsed_seconds": round(time.monotonic() - started, 3),
                "before_enter_tally": before_enter["tally"],
                "after_tally": unlocked["tally"]}

    def denied_then_password(self, selector, *, stock=False):
        before = self.lock()
        self.type_candidate(selector)
        self.key(28)
        # A genuine TPM operation may use its full five-second budget before
        # the original password route runs. Continued lock alone is not proof
        # of denial: wait for this exact greeter's native authentication event.
        deadline = time.monotonic() + 12
        while time.monotonic() < deadline:
            denied = self.observe(timeout=max(1, min(10, deadline - time.monotonic())))
            require(denied["locked"] is True and denied["greeter_pids"] == before["greeter_pids"],
                    "wrong candidate did not retain the same locked greeter")
            if (denied["native_auth_failure_events"] > before["native_auth_failure_events"]
                    and denied["greeter_native_failure_events"] > before["greeter_native_failure_events"]):
                break
            time.sleep(0.2)
        else:
            raise RuntimeError("native wrong-password completion from this greeter was not observed within 12 seconds")
        # KDE implements PAM_FAIL_DELAY asynchronously and disables input until
        # its randomized delay (up to three seconds here) ends. Logging precedes
        # that timer; leave four seconds before typing into the field again.
        time.sleep(4)
        print("M7 UI: denial retained same locked greeter; testing recovery", file=sys.stderr, flush=True)
        recovery = self.unlock("password")
        return {**recovery, "wrong_candidate_denied": True, "same_greeter_after_denial": True,
                "greeter_pid": before["greeter_pids"][0], "gui_submissions": 2,
                "before_tally": before["tally"], "denied_tally": denied["tally"],
                "native_auth_failure_events_before": before["native_auth_failure_events"],
                "native_auth_failure_events_after_denial": denied["native_auth_failure_events"],
                "native_failure_journal_greeter_verified": True,
                "stock_password_stack": stock}

    def locked_account(self):
        before = self.lock()
        rows = []
        for selector in ("pin", "password"):
            self.type_candidate(selector)
            self.key(28)
            time.sleep(4)
            denied = self.observe()
            require(denied["locked"] is True and denied["greeter_pids"] == before["greeter_pids"],
                    "locked account authorized a candidate or changed greeter")
            rows.append({"candidate_kind": selector, "remained_locked": True,
                         "same_greeter": True, "tally": denied["tally"],
                         "native_auth_failure_events": denied["native_auth_failure_events"]})
        return {"pin_denied": True, "password_denied": True, "left_locked_for_explicit_repair": True,
                "greeter_pid": before["greeter_pids"][0], "gui_submissions": 2,
                "before_tally": before["tally"], "submissions": rows}

    def run(self):
        phase = self.args.phase
        initial = self.observe(status=phase != "baseline")
        require(initial["stock_policy"] if phase == "baseline" else initial["integrated_policy"],
                "phase does not match the exact stock/integrated KDE policy")
        started = time.monotonic()
        if phase == "baseline":
            first = self.lock()
            direct = {**self.unlock("password"), "before_tally": first["tally"], "gui_submissions": 1}
            result = {"ordinary_password": direct,
                      "wrong_then_password": self.denied_then_password("wrong", stock=True)}
        elif phase == "wrong-pin":
            result = self.denied_then_password("wrongpin")
        elif phase == "locked-account":
            result = self.locked_account()
        elif phase == "recovery":
            require(initial["locked"] is True and len(initial["greeter_pids"]) == 1,
                    "explicit recovery requires the dedicated desktop already locked")
            result = {**self.unlock("password"), "greeter_pid": initial["greeter_pids"][0],
                      "gui_submissions": 1, "before_tally": initial["tally"]}
        elif phase not in ("pin", "password", "sixpassword", "profilepassword"):
            result = self.denied_then_password("pin")
        else:
            before = self.lock()
            selector = phase
            result = {**self.unlock(selector, enter_required=phase == "pin"),
                      "greeter_pid": before["greeter_pids"][0],
                      "lock_startup_tally": before["tally"], "gui_submissions": 1}
            result["before_tally"] = result["before_enter_tally"]
            if phase == "pin":
                require(result["after_tally"] == result["before_enter_tally"],
                        "PIN success changed the original password failure tally")
                result["password_tally_unchanged"] = True
        final = self.observe(status=phase != "baseline")
        require(final["locked"] is (phase == "locked-account"), "unexpected final desktop lock state")
        self.guard_domain()
        return {"passed": True, "phase": phase, "actual_libvirt_keyboard": True,
                "candidate_values_saved": False, "selinux": "Enforcing",
                "emulated_tpm_confirmed": self.args.emulated_tpm_confirmed,
                "physical_tpm": False,
                "initially_unlocked": initial["locked"] is False,
                "finally_unlocked": final["locked"] is False,
                "elapsed_seconds": round(time.monotonic() - started, 3),
                "initial_broker_status": initial.get("broker_status"),
                "final_broker_status": final.get("broker_status"), "result": result}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--phase", choices=PHASES, required=True)
    parser.add_argument("--address", required=True)
    parser.add_argument("--access-dir", type=Path, required=True)
    parser.add_argument("--disposable-vm-confirmed", action="store_true", required=True)
    parser.add_argument("--emulated-tpm-confirmed", action="store_true")
    args = parser.parse_args()
    os.umask(0o077)
    args.address = str(ipaddress.ip_address(args.address))
    args.access_dir = args.access_dir.resolve(strict=True)
    require(args.access_dir.is_dir() and args.access_dir.stat().st_uid == os.getuid()
            and not args.access_dir.stat().st_mode & 0o022, "unsafe private access directory")
    # Imported only after explicit invocation/confirmation; compile-only checks
    # need neither an installed libvirt module nor a connection to the host.
    import libvirt
    controller = Console(args, libvirt)
    try:
        result = controller.run()
    finally:
        controller.close()
    path = args.access_dir / "ui-results.json"
    if path.exists():
        owned_file(path, private=True)
        evidence = json.loads(path.read_text())
    else:
        evidence = {}
    evidence[args.phase] = result
    temporary = args.access_dir / ".ui-results-new"
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as output:
        output.write(json.dumps(evidence, indent=2) + "\n")
        output.flush()
        os.fsync(output.fileno())
    os.replace(temporary, path)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        # Neither exception messages from subprocesses nor their captured output
        # are printed, since an operation may be retrieving a private candidate.
        reason = str(error) if isinstance(error, RuntimeError) else type(error).__name__
        print(f"M7 keyboard controller stopped: {reason}; no UI pass recorded.", file=sys.stderr)
        raise SystemExit(1) from None
