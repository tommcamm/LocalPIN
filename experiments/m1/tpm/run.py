#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Synthetic M1 TPM experiment. Never opens a TPM device or uses a default TCTI."""

import argparse
import ctypes
import ctypes.util
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import select
import signal
import socket
import struct
import subprocess
import tempfile
import threading
import time

PARENT_ATTRS = "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|restricted|decrypt"
SEAL_ATTRS = "fixedtpm|fixedparent|userwithauth"


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def derive(pin, salt):
    """Test adapter only: request Argon2id version 0x13 explicitly."""
    lib = ctypes.CDLL(ctypes.util.find_library("argon2"))
    fn = lib.argon2_hash
    fn.argtypes = [ctypes.c_uint32, ctypes.c_uint32, ctypes.c_uint32,
                   ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p,
                   ctypes.c_size_t, ctypes.c_void_p, ctypes.c_size_t,
                   ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int, ctypes.c_uint32]
    fn.restype = ctypes.c_int
    out = ctypes.create_string_buffer(32)
    require(fn(3, 65536, 1, pin, len(pin), salt, len(salt), out, 32, None, 0, 2, 0x13) == 0,
            "Argon2id derivation failed")
    return out.raw


def packets(frames, direction="command"):
    data = b"".join(value for kind, value in frames if kind == direction)
    found = []
    while data:
        require(len(data) >= 10, "truncated recorded TPM header")
        size = struct.unpack(">I", data[2:6])[0]
        require(10 <= size <= len(data), "truncated recorded TPM packet")
        found.append(data[:size])
        data = data[size:]
    require(found, "wire recorder captured no TPM packets")
    return found


def auth_attributes(frames, command_code):
    command = next(packet for packet in packets(frames)
                   if struct.unpack(">I", packet[6:10])[0] == command_code)
    require(command[:2] == b"\x80\x02", "expected sessions command")
    # Create and Unseal have one command handle. Then authorizationSize,
    # sessionHandle, nonceCaller, attributes, HMAC.
    nonce_size = struct.unpack(">H", command[22:24])[0]
    return command[24 + nonce_size]


def stop_process(process):
    if process.poll() is not None:
        return
    process.send_signal(signal.SIGCONT)
    process.terminate()
    try:
        process.wait(timeout=2)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=2)


class Simulator:
    def __init__(self, root, label):
        self.root = root / label
        self.root.mkdir(mode=0o700)
        self.sock = self.root / "tpm.sock"
        self.proxy = self.root / "wire.sock"
        self.frames = []
        self.stopping = threading.Event()
        self.process_command = [
            "swtpm", "socket", "--tpm2", "--tpmstate", f"dir={self.root},mode=0600",
            "--ctrl", f"type=unixio,path={self.sock}.ctrl,mode=0600",
            "--server", f"type=unixio,path={self.sock},mode=0600",
            "--flags", "not-need-init,startup-clear"]
        self.process = subprocess.Popen(self.process_command,
                                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.listener = None
        try:
            deadline = time.monotonic() + 5
            while not self.sock.exists():
                require(self.process.poll() is None, "swtpm exited during startup")
                require(time.monotonic() < deadline, "swtpm socket did not appear")
                time.sleep(0.01)
            self.listener = socket.socket(socket.AF_UNIX)
            self.listener.bind(str(self.proxy))
            self.listener.listen()
            self.listener.settimeout(0.1)
            Path(str(self.proxy) + ".ctrl").symlink_to(Path(str(self.sock) + ".ctrl"))
            self.thread = threading.Thread(target=self.accept, daemon=True)
            self.thread.start()
            # The address is exclusively generated here, never caller-supplied.
            self.tcti = f"swtpm:path={self.proxy}"
        except BaseException:
            self.stopping.set()
            if self.listener is not None:
                self.listener.close()
            stop_process(self.process)
            raise

    def accept(self):
        while not self.stopping.is_set():
            try:
                client, _ = self.listener.accept()
            except TimeoutError:
                continue
            except OSError:
                return
            threading.Thread(target=self.relay, args=(client,), daemon=True).start()

    def relay(self, client):
        with client, socket.socket(socket.AF_UNIX) as upstream:
            upstream.connect(str(self.sock))
            peers = {client: upstream, upstream: client}
            while not self.stopping.is_set():
                ready, _, _ = select.select(list(peers), [], [], 0.1)
                for source in ready:
                    data = source.recv(65536)
                    if not data:
                        return
                    self.frames.append(("command" if source is client else "response", data))
                    try:
                        peers[source].sendall(data)
                    except BrokenPipeError:
                        return

    def command(self, name, *args):
        require(name.startswith("tpm2_"), "only TPM tools are accepted")
        return [name, "-T", self.tcti, *map(str, args)]

    def run(self, name, *args, expect=0):
        env = os.environ.copy()
        # Explicit -T wins; clearing defaults prevents accidental later regressions.
        env.pop("TPM2TOOLS_TCTI", None)
        # Tools restore context files into new transient slots; the direct simulator
        # has no resource manager. Release previous transient copies first.
        if name != "tpm2_flushcontext":
            subprocess.run(self.command("tpm2_flushcontext", "-t"), cwd=self.root,
                           env=env, capture_output=True, timeout=10, check=True)
        result = subprocess.run(self.command(name, *args), cwd=self.root, env=env,
                                capture_output=True, timeout=10)
        require((result.returncode == 0) == (expect == 0),
                f"{name}: unexpected exit {result.returncode}: {result.stderr.decode(errors='replace')}")
        return result

    def flush(self):
        self.run("tpm2_flushcontext", "-t")
        self.run("tpm2_flushcontext", "-l")
        self.run("tpm2_flushcontext", "-s")

    def parent(self, name):
        self.run("tpm2_createprimary", "-C", "o", "-G", "rsa2048:aes128cfb",
                 "-g", "sha256", "-a", PARENT_ATTRS, "-c", name + ".ctx")
        self.run("tpm2_readpublic", "-c", name + ".ctx", "-o", name + ".pub",
                 "-n", name + ".name")
        validate_parent((self.root / (name + ".pub")).read_bytes(),
                        (self.root / (name + ".name")).read_bytes())

    def session(self, name, parent="parent.ctx", decrypt=False):
        start = len(self.frames)
        self.run("tpm2_startauthsession", "--hmac-session", "--tpmkey-context", parent,
                 "-g", "sha256", "-G", "aes", "-S", name)
        command = next(packet for packet in packets(self.frames[start:])
                       if struct.unpack(">I", packet[6:10])[0] == 0x176)
        require(struct.unpack(">I", command[14:18])[0] == 0x40000007, "unexpected session bind")
        offset = 18
        nonce_size = struct.unpack(">H", command[offset:offset + 2])[0]
        offset += 2 + nonce_size
        salt_size = struct.unpack(">H", command[offset:offset + 2])[0]
        require(salt_size > 0, "unsalted session")
        offset += 2 + salt_size
        require(struct.unpack(">BHHHH", command[offset:offset + 9]) ==
                (0, 0x0006, 128, 0x0043, 0x000B), "unexpected session algorithms")
        self.run("tpm2_sessionconfig", name, "--enable-encrypt",
                 "--enable-decrypt" if decrypt else "--disable-decrypt")

    def properties(self):
        return self.run("tpm2_getcap", "properties-variable").stdout.decode()

    def counter(self):
        text = self.properties()
        value = re.search(r"TPM2_PT_LOCKOUT_COUNTER: (0x[0-9a-fA-F]+|\d+)", text)
        require(value is not None, "missing DA counter")
        return int(value.group(1), 0)

    def locked(self):
        value = re.search(r"^  inLockout:\s+([01])$", self.properties(), re.MULTILINE)
        require(value is not None, "missing DA inLockout property")
        return value.group(1) == "1"

    def restart(self):
        self.process.terminate()
        self.process.wait(timeout=2)
        for path in (self.sock, Path(str(self.sock) + ".ctrl")):
            path.unlink(missing_ok=True)
        self.process = subprocess.Popen(self.process_command,
                                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        deadline = time.monotonic() + 5
        while not self.sock.exists():
            require(self.process.poll() is None, "swtpm exited during restart")
            require(time.monotonic() < deadline, "swtpm restart socket did not appear")
            time.sleep(0.01)

    def close(self):
        self.stopping.set()
        self.listener.close()
        self.thread.join(timeout=1)
        stop_process(self.process)


def validate_parent(public, name):
    require(len(public) == 284, "parent public size mismatch")
    size, kind, alg, attrs, policy_size = struct.unpack(">HHHIH", public[:12])
    require((size, kind, alg, attrs, policy_size) == (282, 1, 0xB, 0x30072, 0),
            "parent template mismatch")
    require(struct.unpack(">HHHHHIH", public[12:28]) ==
            (6, 128, 0x43, 0x10, 2048, 0, 256), "parent algorithm mismatch")
    require(name == b"\x00\x0b" + hashlib.sha256(public[2:]).digest(), "parent Name mismatch")


def validate_seal(public, name):
    # TPM2B_PUBLIC for the one accepted keyed-hash/null scheme construction.
    require(len(public) >= 16, "truncated public")
    size, kind, alg, attrs, policy_size = struct.unpack(">HHHIH", public[:12])
    require(size == len(public) - 2 and kind == 0x0008 and alg == 0x000B,
            "public type/size/name algorithm mismatch")
    require(attrs == 0x52 and policy_size == 0, "attributes or policy mismatch")
    scheme, unique_size = struct.unpack(">HH", public[12:16])
    require(scheme == 0x0010 and unique_size == 32 and len(public) == 48,
            "keyed-hash scheme/unique mismatch")
    require(name == b"\x00\x0b" + hashlib.sha256(public[2:]).digest(), "Name mismatch")


def validate_identity(public, name, generation, enrolled):
    validate_seal(public, name)
    require(generation == enrolled["generation"] and public == enrolled["public"] and
            name == enrolled["name"], "enrolled identity/generation mismatch")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path, help="write only sanitized assertions/versions JSON")
    args = parser.parse_args()
    os.umask(0o077)
    results = {}
    versions = {}
    for command in (["swtpm", "--version"], ["tpm2_create", "--version"],
                    ["rpm", "-q", "swtpm", "libtpms", "tpm2-tools", "tpm2-tss", "libargon2"]):
        output = subprocess.run(command, capture_output=True, text=True, check=True)
        versions[command[0]] = output.stdout.strip()
    versions["python"] = platform.python_version()
    versions["kernel"] = platform.release()
    simulators = []
    with tempfile.TemporaryDirectory(prefix="localpin-m1-tpm-", dir="/tmp") as temporary:
        root = Path(temporary)
        try:
            a = Simulator(root, "a")
            simulators.append(a)
            b = Simulator(root, "b")
            simulators.append(b)
            salt = os.urandom(16)
            auth = derive(b"012345", salt)
            wrong = derive(b"012346", salt)
            secret = os.urandom(32)
            for filename, value in [("auth", auth), ("wrong", wrong), ("secret", secret)]:
                (a.root / filename).write_bytes(value)
            a.parent("parent")
            parent_public = (a.root / "parent.pub").read_bytes()
            parent_name = (a.root / "parent.name").read_bytes()
            fixed = a.run("tpm2_getcap", "properties-fixed").stdout.decode()
            results["simulator_properties"] = fixed
            # All DA changes below are confined to disposable simulator A.
            a.run("tpm2_dictionarylockout", "--setup-parameters", "--max-tries", "8",
                  "--recovery-time", "86400", "--lockout-recovery-time", "86400")
            a.session("create.session", decrypt=True)
            start = len(a.frames)
            a.run("tpm2_create", "-C", "parent.ctx", "-P", "session:create.session",
                  "-g", "sha256", "-a", SEAL_ATTRS,
                  "-p", "file:auth", "-i", "secret", "-u", "seal.pub", "-r", "seal.priv")
            wire = b"".join(data for _, data in a.frames[start:])
            require(auth_attributes(a.frames[start:], 0x153) & 0x60 == 0x60,
                    "Create parameter protection flags absent")
            require(secret not in wire and auth not in wire, "plaintext create secret/auth on transport")
            a.flush()
            a.restart()
            a.parent("parent")
            require((a.root / "parent.pub").read_bytes() == parent_public and
                    (a.root / "parent.name").read_bytes() == parent_name, "parent recreation mismatch")
            results["parent_recreation"] = "identical public and Name after transient flush, clean simulator process restart with saved state, and recreate"
            a.run("tpm2_load", "-C", "parent.ctx", "-u", "seal.pub", "-r", "seal.priv", "-c", "seal.ctx")
            a.run("tpm2_readpublic", "-c", "seal.ctx", "-o", "loaded.pub", "-n", "seal.name")
            public = (a.root / "seal.pub").read_bytes()
            name = (a.root / "seal.name").read_bytes()
            require((a.root / "loaded.pub").read_bytes() == public, "loaded object changed")
            enrolled = {"generation": 1, "public": public, "name": name}
            validate_identity(public, name, 1, enrolled)
            substituted = bytearray(public)
            substituted[-1] ^= 1
            substituted_name = b"\x00\x0b" + hashlib.sha256(substituted[2:]).digest()
            # Shape and self-consistent Name alone cannot establish enrolled identity.
            validate_seal(substituted, substituted_name)
            for candidate_public, candidate_name, candidate_generation in [
                    (substituted, substituted_name, 1), (public, name, 2)]:
                try:
                    validate_identity(candidate_public, candidate_name, candidate_generation, enrolled)
                except AssertionError:
                    continue
                raise AssertionError("substituted identity/generation accepted")
            for offset in (4, 6, 10, 12, 20):
                damaged = bytearray(public)
                damaged[offset] ^= 1
                try:
                    validate_seal(damaged, name)
                except AssertionError:
                    continue
                raise AssertionError("metadata mutation accepted")
            # An actual second object on this TPM can unseal with the same auth.
            # Successful TPM authorization by itself does not identify enrollment.
            other_secret = os.urandom(32)
            (a.root / "other.secret").write_bytes(other_secret)
            a.session("other-create.session", decrypt=True)
            a.run("tpm2_create", "-C", "parent.ctx", "-P", "session:other-create.session",
                  "-g", "sha256", "-a", SEAL_ATTRS, "-p", "file:auth", "-i", "other.secret",
                  "-u", "other.pub", "-r", "other.priv")
            a.run("tpm2_flushcontext", "other-create.session")
            a.run("tpm2_load", "-C", "parent.ctx", "-u", "other.pub", "-r", "other.priv", "-c", "other.ctx")
            a.run("tpm2_readpublic", "-c", "other.ctx", "-o", "other.loaded.pub", "-n", "other.name")
            other_public = (a.root / "other.loaded.pub").read_bytes()
            other_name = (a.root / "other.name").read_bytes()
            validate_seal(other_public, other_name)
            try:
                validate_identity(other_public, other_name, 1, enrolled)
            except AssertionError:
                pass
            else:
                raise AssertionError("same-TPM substituted object accepted")
            a.session("other-unseal.session")
            a.run("tpm2_unseal", "-c", "other.ctx", "-p", "session:other-unseal.session+file:auth", "-o", "other.out")
            require((a.root / "other.out").read_bytes() == other_secret, "second object unseal failed")
            a.run("tpm2_flushcontext", "other-unseal.session")
            results["metadata"] = "keyedhash/sha256/null; attrs=0x52; empty policy; Name/public/generation checked; mutations, generation mismatch, and actual same-TPM object substitution rejected"
            # A synthetic response without parameter encryption proves the relay
            # sees the secret. Tools may still use an implicit HMAC for auth.
            # This traffic never leaves the temporary socket.
            start = len(a.frames)
            a.run("tpm2_unseal", "-c", "seal.ctx", "-p", "file:auth", "-o", "control.out")
            control_responses = b"".join(value for kind, value in a.frames[start:] if kind == "response")
            require(secret in control_responses, "wire recording plaintext response control failed")
            a.session("unseal.session")
            start = len(a.frames)
            a.run("tpm2_unseal", "-c", "seal.ctx", "-p", "session:unseal.session+file:auth", "-o", "unsealed")
            require((a.root / "unsealed").read_bytes() == secret, "wrong unseal output")
            wire = b"".join(data for _, data in a.frames[start:])
            require(auth_attributes(a.frames[start:], 0x15E) & 0x60 == 0x40,
                    "Unseal encryption flag missing or inappropriate decryption flag set")
            require(secret not in wire and auth not in wire, "plaintext unseal secret/auth on transport")
            a.run("tpm2_flushcontext", "unseal.session")
            results["protected_sessions"] = "salted AES-128-CFB/SHA-256 HMAC and command protection flags verified on wire; plaintext response negative control passes; protected create/unseal contains neither raw auth nor 32-byte secret"
            # A native call blocks while the simulator is stopped; isolate the caller.
            reservation = root / "reservation.json"
            with reservation.open("w") as output:
                json.dump({"reserved": True, "completed": False, "generation": 1}, output)
                output.flush()
                os.fsync(output.fileno())
            directory_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            os.fsync(directory_fd)
            os.close(directory_fd)
            a.process.send_signal(signal.SIGSTOP)
            started = time.monotonic()
            worker = subprocess.Popen(a.command("tpm2_unseal", "-c", "seal.ctx", "-p", "file:auth", "-o", "late.out"),
                                      cwd=a.root, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            try:
                worker.wait(timeout=0.5)
                raise AssertionError("native call unexpectedly completed during stopped transport")
            except subprocess.TimeoutExpired:
                worker.kill()
                worker.wait(timeout=1)
            finally:
                a.process.send_signal(signal.SIGCONT)
            elapsed = time.monotonic() - started
            require(elapsed < 1.5 and not (a.root / "late.out").exists(), "native worker deadline not enforced")
            require(json.loads(reservation.read_text())["reserved"], "reservation lost")
            a.flush()
            require(not (a.root / "late.out").exists(), "late output appeared after transport resumed")
            a.session("recovered.session")
            a.run("tpm2_unseal", "-c", "seal.ctx", "-p", "session:recovered.session+file:auth", "-o", "recovered.out")
            require((a.root / "recovered.out").read_bytes() == secret, "fresh context recovery failed")
            a.run("tpm2_flushcontext", "recovered.session")
            results["native_timeout"] = {"deadline_seconds": 0.5, "killed_and_reaped_seconds": round(elapsed, 3),
                "late_output": False, "reservation_retained": True, "fresh_context_recovery": True,
                "limitation": "stopped simulator transport; not a kernel task stuck in uninterruptible device I/O"}
            before = a.counter()
            require(not a.locked(), "fresh simulator unexpectedly locked")
            maximum = re.search(r"TPM2_PT_MAX_AUTH_FAIL: (0x[0-9a-fA-F]+|\d+)", a.properties())
            require(maximum is not None and int(maximum.group(1), 0) == 8, "DA maximum not readable")
            require(a.counter() == before, "budget inspection consumed a guess")
            # Empty auth must be refused, and count as a DA-protected wrong auth.
            failure = a.run("tpm2_unseal", "-c", "seal.ctx", "-o", "empty.out", expect=1)
            require(b"0x98E" in failure.stderr or b"0x98e" in failure.stderr, "unexpected empty-auth error")
            require(a.counter() == before + 1, "empty auth did not increase DA counter")
            a.session("wrong.session")
            failure = a.run("tpm2_unseal", "-c", "seal.ctx", "-p", "session:wrong.session+file:wrong",
                            "-o", "wrong.out", expect=1)
            require(b"0x98E" in failure.stderr or b"0x98e" in failure.stderr, "unexpected wrong-auth error")
            require(a.counter() == before + 2, "wrong auth did not increase DA counter")
            a.run("tpm2_flushcontext", "wrong.session")
            results["wrong_auth_da"] = {"before": before, "after_empty_and_wrong": a.counter(), "error": "TPM_RC_AUTH_FAIL 0x98e"}
            # An empty policy session must not authorize an empty-policy object.
            a.run("tpm2_startauthsession", "--policy-session", "-S", "policy.session")
            failure = a.run("tpm2_unseal", "-c", "seal.ctx", "-p", "session:policy.session", "-o", "policy.out", expect=1)
            require(b"0x99D" in failure.stderr or b"0x99d" in failure.stderr, "unexpected policy rejection")
            a.run("tpm2_flushcontext", "policy.session")
            results["alternate_paths"] = "empty password rejected (AUTH_FAIL); empty policy session rejected (POLICY_FAIL); no policy/PCR authorization provisioned"
            b.parent("foreign")
            require((b.root / "foreign.name").read_bytes() != parent_name, "different simulator has same primary Name")
            for filename in ("seal.pub", "seal.priv"):
                (b.root / filename).write_bytes((a.root / filename).read_bytes())
            failure = b.run("tpm2_load", "-C", "foreign.ctx", "-u", "seal.pub", "-r", "seal.priv", "-c", "foreign-seal.ctx", expect=1)
            require(b"0x1DF" in failure.stderr or b"0x1df" in failure.stderr, "unexpected foreign blob rejection")
            results["foreign_tpm"] = "different primary Name; copied blob load rejected with INTEGRITY 0x1df"
            # The reserve is a preflight rule, never an atomic hardware reservation.
            def allowed(counter, maximum, reserve=2):
                return counter is not None and maximum is not None and 0 <= counter < maximum and maximum - counter > reserve
            require(not allowed(None, 8) and not allowed(6, 8) and allowed(5, 8), "reserve policy error")
            while a.counter() < 5:
                a.run("tpm2_unseal", "-c", "seal.ctx", "-p", "file:wrong", "-o", "wrong.out", expect=1)
            observation = a.counter()
            require(allowed(observation, 8), "expected preflight allowance")
            # Another client consumes a failure after our allowed observation.
            a.run("tpm2_unseal", "-c", "seal.ctx", "-p", "file:wrong", "-o", "other.out", expect=1)
            require(a.counter() == 6 and not allowed(a.counter(), 8), "reserve boundary wrong")
            # Our stale preflight can now consume one of the reserved attempts.
            a.run("tpm2_unseal", "-c", "seal.ctx", "-p", "file:wrong", "-o", "stale.out", expect=1)
            require(a.counter() == 7, "race did not reduce reserve")
            a.run("tpm2_unseal", "-c", "seal.ctx", "-p", "file:wrong", "-o", "last.out", expect=1)
            require(a.counter() == 8, "expected global lockout threshold")
            require(a.locked(), "global lockout property not set at threshold")
            failure = a.run("tpm2_unseal", "-c", "seal.ctx", "-p", "file:auth", "-o", "locked.out", expect=1)
            require(b"0x921" in failure.stderr, "correct auth was not rejected under lockout")
            results["reserve_and_race"] = {"max_tries": 8, "reserve": 2, "preflight_counter": observation,
                "other_client_counter": 6, "stale_submission_counter": 7,
                "in_lockout_before": False, "in_lockout_at_counter_8": True,
                "correct_auth_at_counter_8": "TPM_RC_LOCKOUT 0x921"}
        finally:
            for simulator in reversed(simulators):
                simulator.close()
    report = {"schema": 1, "fixture": "synthetic; disposable swtpm; no production TPM", "versions": versions,
              "results": results, "not_tested": ["real TPM/hierarchy authorization and resource manager",
              "tss-esapi Rust integration and secret erasure", "power cycle/clear/suspend lifecycle",
              "production broker scheduling, durable storage fault injection, per-UID responsiveness",
              "independent TPM specialist review"]}
    rendered = json.dumps(report, indent=2) + "\n"
    if args.report:
        args.report.write_text(rendered)
    print(rendered, end="")


if __name__ == "__main__":
    main()
