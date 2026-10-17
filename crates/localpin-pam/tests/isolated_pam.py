#!/usr/bin/env python3
"""Test the exact release PAM cdylib with real Linux-PAM in private namespaces.

Run as an ordinary host user:
  python3 crates/localpin-pam/tests/isolated_pam.py

Requires bubblewrap, unshare, subordinate UID/GID maps, a C compiler, PAM headers,
and pam_unix/pam_faillock. Builds the production release artifact without features
or adapter test selectors. Only synthetic accounts and a fake namespace-root
wire broker are used. Never exposes host /etc, runs as host root, or installs PAM.
"""
import ctypes
import json
import os
from pathlib import Path
import select
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time


SOCKET = Path("/run/localpin/broker.sock")
USER = "localpin_synthetic"
UID = 1000
CHALLENGE = bytes([0xCA]) * 16
SYNTHETIC_PASSWORD = b"481516"


def exact(stream, count):
    result = b""
    while len(result) < count:
        data = stream.recv(count - len(result))
        if not data:
            raise EOFError("client closed")
        result += data
    return result


def frame(operation, connection, payload=b""):
    body = bytes([1, operation]) + connection + payload
    return struct.pack("!I", len(body)) + body


class Broker:
    """Test-only authenticated peer implementing the actual public wire format."""

    def __init__(self):
        self.mode = "mismatch"
        self.requests = []
        self.connections = 0
        self.errors = []
        self.stopping = threading.Event()
        self.listener = None

    def start(self):
        self.stopping.clear()
        SOCKET.unlink(missing_ok=True)
        self.listener = socket.socket(socket.AF_UNIX)
        self.listener.bind(str(SOCKET))
        SOCKET.chmod(0o666)
        self.listener.listen(4)
        self.listener.settimeout(0.1)
        self.thread = threading.Thread(target=self.serve, daemon=True)
        self.thread.start()

    def stop(self):
        self.stopping.set()
        self.thread.join(timeout=4)
        assert not self.thread.is_alive(), "fake broker did not finish"
        self.listener.close()
        SOCKET.unlink(missing_ok=True)

    def receive(self, client, connection):
        size = struct.unpack("!I", exact(client, 4))[0]
        assert 18 <= size <= 4092, "adapter emitted oversized frame"
        body = exact(client, size)
        assert body[0] == 1 and body[2:18] == connection
        operation, payload = body[1], body[18:]
        assert operation in (1, 2, 3), "unlock adapter emitted a non-unlock request"
        if operation == 3:
            assert len(payload) == 22 and payload[:16] == CHALLENGE
            assert len(payload[16:]) == 6 and all(48 <= byte <= 57 for byte in payload[16:])
        else:
            assert payload == b"", "password bytes appeared in a non-PIN request"
        self.requests.append((operation, payload))
        return operation

    def serve(self):
        while not self.stopping.is_set():
            try:
                client, _ = self.listener.accept()
            except socket.timeout:
                continue
            self.connections += 1
            connection = self.connections.to_bytes(16, "big")
            with client:
                client.settimeout(3)
                try:
                    self.exchange(client, connection, self.mode)
                except (EOFError, BrokenPipeError, ConnectionResetError):
                    pass  # A rejected or completed client must close its socket.
                except Exception as error:
                    self.errors.append(str(error))

    def exchange(self, client, connection, mode):
        if mode == "crashed":
            return
        if mode == "silent":
            self.stopping.wait(2.4)
            return
        if mode == "malformed":
            client.sendall(struct.pack("!I", 4093))
            return
        client.sendall(frame(0x80, connection))
        assert self.receive(client, connection) == 1, "expected status before PIN verification"
        availability = {"not-enrolled": 1, "disabled": 2, "cooldown": 3,
                        "ineligible": 4, "unavailable": 5}.get(mode, 0)
        enrolled = 0 if mode == "not-enrolled" else 2
        cooldown = 1000 if mode == "cooldown" else 0
        reason = 3 if mode == "unavailable" else 0
        status = bytes([2, enrolled, availability]) + struct.pack("!I", cooldown) + bytes([1, 0, 0, reason])
        if mode == "binding":
            client.sendall(frame(0x81, CHALLENGE, status))
            return
        client.sendall(frame(0x81, connection, status))
        if availability:
            assert client.recv(1) == b"", "unavailable status must not cause a PIN request"
            return
        assert self.receive(client, connection) == 2
        if mode == "premature-grant":
            client.sendall(frame(0x86, connection, bytes([1])))
            return
        challenge = connection if mode == "reused-challenge" else CHALLENGE
        client.sendall(frame(0x82, connection, challenge + struct.pack("!I", 5000)))
        if mode == "reused-challenge":
            return
        assert self.receive(client, connection) == 3
        if mode == "verify-crash":
            return
        outcome = {"granted": bytes([1]), "mismatch": bytes([2]),
                   "final-cooldown": bytes([3]) + struct.pack("!I", 1000),
                   "storage-fault": bytes([4, 3]), "tpm-fault": bytes([4, 4])}.get(mode, bytes([2]))
        client.sendall(frame(0x86, connection, outcome))


class Pam:
    """One process and one PAM handle, deliberately reused for multiple calls."""

    def __init__(self, broker, service="kde", user=USER, identity="own"):
        self.broker = broker
        options = {} if identity == "mixed" else {"user": UID, "group": UID, "extra_groups": []}
        self.process = subprocess.Popen(
            ["/app/harness", service, user, identity], stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, **options,
        )

    def attempt(self, name, candidate, password=None, *, mode="mismatch", success=True,
                prompts=1, password_calls=1, operations=(), cancel=False,
                guard=False, account=False, failures=0, mutation=0):
        self.broker.mode = mode
        before = len(self.broker.requests)
        password = candidate if password is None else password
        line = f"{candidate.hex() or '-'} {password.hex() or '-'} {int(cancel)} {int(guard)} {int(account)} {mutation}\n"
        self.process.stdin.write(line)
        self.process.stdin.flush()
        started = time.monotonic()
        assert select.select([self.process.stdout], [], [], 8)[0], f"{name}: PAM deadline"
        output = self.process.stdout.readline()
        assert output, f"{name}: harness exited: {self.process.stderr.read()}"
        result = json.loads(output)
        if mode == "silent":
            assert time.monotonic() - started < 2.5, f"{name}: setup timeout exceeded"
        assert (result["rc"] == 0) == success, f"{name}: {result}"
        assert (result["cred"] == 0) == success, f"{name}: setcred result: {result}"
        assert result["prompts"] == prompts, f"{name}: {result}"
        assert result["password_calls"] == password_calls, f"{name}: {result}"
        assert result["new_password_failures"] == failures, f"{name}: {result}"
        assert result["stale_tokens"] == 0, f"{name}: {result}"
        assert (result["account"] == 0) != account, f"{name}: {result}"
        # Requests are appended before responding; the completed PAM call has
        # consumed all expected responses. No secret bytes are printed or saved.
        observed = self.broker.requests[before:]
        assert tuple(operation for operation, _ in observed) == tuple(operations), f"{name}: unexpected requests"
        if operations and operations[-1] == 3:
            assert observed[-1][1][16:] == candidate, f"{name}: changed PIN bytes"
        assert not self.broker.errors, f"fake broker: {self.broker.errors}"
        print(f"PASS {name}", flush=True)
        return result

    def close(self):
        self.process.stdin.close()
        assert self.process.wait(timeout=4) == 0, self.process.stderr.read()


def policy(module="/app/liblocalpin_pam.so", *, guard=None, unix=False, faillock=False):
    text = "auth optional /app/password_fixture.so inspect\n"
    if guard:
        text += f"auth {guard} /app/password_fixture.so guard\n"
    if faillock:
        text += "auth requisite pam_faillock.so preauth silent\n"
    text += f"auth [success=done default=ignore] {module}\n"
    if unix:
        text += "auth [success=1 default=bad] pam_unix.so nodelay try_first_pass\nauth [default=die] pam_faillock.so authfail\nauth required pam_faillock.so authsucc\n" if faillock else "auth required pam_unix.so nodelay try_first_pass\n"
    else:
        text += "auth required /app/password_fixture.so password\n"
    text += "account required /app/password_fixture.so account\n"
    return text


def setup_accounts():
    etc = Path("/etc")
    (etc / "pam.d").mkdir(parents=True)
    (etc / "security").mkdir()
    (etc / "passwd").write_text(f"root:x:0:0:synthetic root:/:/bin/false\n{USER}:x:{UID}:{UID}:synthetic:/:/bin/false\nother:x:1001:1001:synthetic:/:/bin/false\n")
    (etc / "group").write_text(f"root:x:0:\n{USER}:x:{UID}:\nother:x:1001:\n")
    (etc / "nsswitch.conf").write_text("passwd: files\ngroup: files\nshadow: files\n")
    (etc / "login.defs").write_text("ENCRYPT_METHOD SHA512\n")
    (etc / "security/faillock.conf").write_text("deny=3\nfail_interval=900\nunlock_time=600\ndir=/run/faillock\n")
    Path("/run/faillock").mkdir(mode=0o777)
    Path("/run/faillock").chmod(0o777)
    crypt = ctypes.CDLL("libcrypt.so.2")
    crypt.crypt.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
    crypt.crypt.restype = ctypes.c_char_p
    hashed = crypt.crypt(SYNTHETIC_PASSWORD, b"$6$localpin-m7$")
    assert hashed and hashed.startswith(b"$6$"), "synthetic crypt unavailable"

    def account(locked=False, expired=False):
        # Public synthetic hash; readability permits unprivileged pam_unix to
        # exercise the real password path without relying on a setuid helper.
        value = ("!" if locked else "") + hashed.decode("ascii")
        Path("/etc/shadow").write_text(f"root:!:20000:0:99999:7:::\n{USER}:{value}:20000:0:99999:7::{1 if expired else ''}:\n")
        Path("/etc/shadow").chmod(0o644)
    account()
    return account


def inside():
    assert os.getuid() == 0 and os.getgid() == 0
    mapping = Path("/proc/self/uid_map").read_text().splitlines()[0].split()
    assert int(mapping[0]) == 0 and int(mapping[1]) != 0, "host root is forbidden"
    assert not Path("/etc/passwd").exists(), "host /etc must not be mounted"
    account = setup_accounts()
    Path("/run/localpin").mkdir(mode=0o755)
    kde = Path("/etc/pam.d/kde")
    Path("/etc/pam.d/login").write_text(policy())
    broker = Broker()
    broker.start()
    # A broken PAM setup must not turn a failing LocalPIN test into false
    # evidence. Baseline known native permit/deny and pam_unix modules first.
    for native, success in (("pam_permit.so", True), ("pam_deny.so", False)):
        kde.write_text(f"auth required {native}\naccount required pam_permit.so\n")
        pam = Pam(broker)
        pam.attempt(f"native {native} infrastructure baseline", b"", success=success, prompts=0, password_calls=0)
        pam.close()
    kde.write_text("auth required pam_unix.so nodelay\naccount required pam_permit.so\n")
    pam = Pam(broker)
    pam.attempt("native pam_unix correct-password infrastructure baseline", SYNTHETIC_PASSWORD, password_calls=0)
    pam.attempt("native pam_unix wrong-password infrastructure baseline", b"wrong-synthetic", success=False, password_calls=0)
    pam.close()
    kde.write_text(policy())
    pam = Pam(broker)
    try:
        for name, candidate in [
            ("ordinary password", b"synthetic-password"),
            ("empty password", b""), ("five digits", b"12345"),
            ("seven digits", b"1234567"), ("Unicode digit lookalikes", "１２３４５６".encode()),
            ("all 255 non-NUL bytes", bytes(range(1, 256))),
            ("511-byte password", b"A" * 511),
            ("4096-byte password", b"B" * 4096),
        ]:
            pam.attempt(name, candidate)
        for name, candidate in [("six-digit account password after PIN mismatch", b"481516"),
                                ("leading-zero password", b"001122")]:
            pam.attempt(name, candidate, operations=(1, 2, 3))
        pam.attempt("PIN success short circuits password", b"001122", b"different-password", mode="granted", password_calls=0, operations=(1, 2, 3))
        pam.attempt("reused handle obtains fresh six-digit password", b"481516", operations=(1, 2, 3))
        pam.attempt("previous success cannot authorize wrong password", b"wrong", b"481516", success=False, failures=1)
        pam.attempt("failed PIN followed by fresh full password", b"synthetic-password")
        pam.attempt("cancelled conversation cannot authorize", b"481516", success=False, cancel=True, prompts=2)
        for mode, description in ((3, "nonzero response retcode"),
                                  (4, "null response string")):
            pam.attempt(f"conversation {description} cannot authorize", b"481516", success=False, cancel=mode, prompts=2)
        pam.attempt("reused handle after cancellation", b"481516", operations=(1, 2, 3))
        for mode in ("not-enrolled", "disabled", "cooldown", "ineligible", "unavailable"):
            pam.attempt(f"{mode} preserves six-digit password", b"481516", mode=mode, operations=(1,))
        for mode in ("binding", "premature-grant", "reused-challenge", "verify-crash",
                     "final-cooldown", "storage-fault", "tpm-fault", "crashed", "malformed", "silent"):
            operations = (1,) if mode == "binding" else (1, 2) if mode in ("premature-grant", "reused-challenge") else () if mode in ("crashed", "malformed", "silent") else (1, 2, 3)
            pam.attempt(f"{mode} preserves password", b"481516", mode=mode, operations=operations)
        broker.stop()
        pam.attempt("stopped broker preserves password", b"481516")
        broker.start()
        os.chown(SOCKET, UID, UID)
        pam.attempt("non-root socket is refused before candidate send", b"481516")
        os.chown(SOCKET, 0, 0)
        Path("/run/localpin").chmod(0o777)
        pam.attempt("writable socket directory is refused", b"481516")
        Path("/run/localpin").chmod(0o755)
        pam.attempt("original account phase remains authoritative", b"001122", b"wrong", mode="granted", password_calls=0, operations=(1, 2, 3), account=True)
    finally:
        pam.close()
    for service, user, identity in [("login", USER, "own"), ("kde", "root", "own"),
                                    ("kde", "other", "own"), ("kde", "missing", "own"),
                                    ("kde", USER, "mixed")]:
        pam = Pam(broker, service, user, identity)
        pam.attempt(f"unsupported target/service/identity {service}/{user}/{identity}", b"481516")
        pam.close()
    for mutation in (1, 2):
        pam = Pam(broker)
        pam.attempt(f"conversation mutation of PAM_{'USER' if mutation == 1 else 'SERVICE'} prevents PIN", b"481516", mutation=mutation)
        pam.close()
    # A deny-only suffix cannot make a second conversation call. Isolate the
    # module's handling of an error output pointer from other PAM helpers.
    kde.write_text(policy().replace("auth required /app/password_fixture.so password", "auth required pam_deny.so"))
    pam = Pam(broker)
    pam.attempt("conversation freed non-NULL error response is not accessed", b"481516", success=False, cancel=2, prompts=1, password_calls=0)
    pam.attempt("same handle captures fresh PIN after callback-owned error cleanup", b"001122", b"different-password", mode="granted", password_calls=0, operations=(1, 2, 3))
    pam.close()
    for guard in ("requisite", "required"):
        kde.write_text(policy(guard=guard))
        pam = Pam(broker)
        pam.attempt(f"preceding {guard} failure cannot be erased by PIN", b"001122", mode="granted", success=False, guard=True,
                    prompts=0 if guard == "requisite" else 1, password_calls=0 if guard == "requisite" else 1,
                    operations=() if guard == "requisite" else (1, 2, 3))
        pam.close()
    kde.write_text(policy(module="/app/missing-module.so"))
    pam = Pam(broker)
    pam.attempt("missing optional adapter preserves password route", b"481516")
    pam.close()
    # Baseline the real pam_unix and pam_faillock modules with the same synthetic
    # account, then place the exact production adapter ahead of that stack.
    kde.write_text(policy(unix=True, faillock=True))
    pam = Pam(broker)
    pam.attempt("pam_unix six-digit password after PIN mismatch", SYNTHETIC_PASSWORD, password_calls=0, operations=(1, 2, 3))
    pam.attempt("pam_unix wrong six-digit password after PIN mismatch", b"000000", success=False, password_calls=0, operations=(1, 2, 3))
    tally = Path(f"/run/faillock/{USER}")
    assert tally.stat().st_size > 0, "real pam_faillock must record a password failure"
    previous_tally = tally.read_bytes()
    pam.attempt("PIN success preserves original password failure tally", b"001122", mode="granted", password_calls=0, operations=(1, 2, 3))
    assert tally.read_bytes() == previous_tally, "PIN success must not reset the original password failure tally"
    pam.attempt("pam_unix fresh full password recovery", SYNTHETIC_PASSWORD, password_calls=0, operations=(1, 2, 3))
    assert tally.stat().st_size == 0, "normal password success accounting"
    for index in range(3):
        pam.attempt(f"pam_faillock retained failure {index + 1}", b"wrong-synthetic", success=False, password_calls=0)
    size = tally.stat().st_size
    pam.attempt("preexisting password lockout denies before PIN", b"001122", mode="granted", success=False, prompts=0, password_calls=0)
    assert tally.stat().st_size == size, "lockout must not reset original counters"
    pam.close()
    tally.unlink()
    account(locked=True)
    pam = Pam(broker)
    pam.attempt("locked password retains pam_unix denial", SYNTHETIC_PASSWORD, success=False, password_calls=0, operations=(1, 2, 3))
    pam.close()
    tally.unlink(missing_ok=True)
    account(expired=True)
    kde.write_text(policy(unix=True).replace("account required /app/password_fixture.so account", "account required pam_unix.so"))
    pam = Pam(broker)
    pam.attempt("expired synthetic account retains real pam_unix account denial", SYNTHETIC_PASSWORD, password_calls=0, operations=(1, 2, 3), account=True)
    pam.close()
    broker.stop()
    print("PASS isolated production PAM ABI, byte preservation, transport, repeated handles, pam_unix and failure accounting; namespace synthetic fixtures only")


def release_module(root):
    build = subprocess.run(["cargo", "build", "--locked", "--release", "-p", "localpin-pam", "--message-format=json"],
                           cwd=root, check=False, capture_output=True, text=True)
    if build.returncode:
        print(build.stderr, file=sys.stderr, end="")
        raise RuntimeError("production release PAM build failed")
    artifacts = []
    for line in build.stdout.splitlines():
        item = json.loads(line)
        if item.get("reason") == "compiler-artifact" and item.get("target", {}).get("name") == "localpin_pam":
            artifacts.extend(Path(name).resolve() for name in item["filenames"] if name.endswith(".so"))
    assert len(artifacts) == 1, "Cargo did not identify the production cdylib"
    return artifacts[0]


def main():
    if sys.argv[1:] == ["--inside"]:
        inside()
        return
    if sys.argv[1:]:
        raise RuntimeError("no adapter paths or test feature overrides are accepted")
    if os.getuid() == 0:
        raise RuntimeError("refusing host root; use an ordinary user with subordinate ID mappings")
    for name in ("cargo", "cc", "bwrap", "unshare", "newuidmap", "newgidmap"):
        if shutil.which(name) is None:
            raise RuntimeError(f"required build/namespace tool unavailable: {name}")
    tests = Path(__file__).resolve().parent
    root = tests.parents[2]
    module = release_module(root)
    include = Path(os.environ.get("LOCALPIN_PAM_INCLUDE", "/usr/include")).resolve()
    for header in ("pam_appl.h", "pam_ext.h", "pam_modules.h"):
        if not (include / "security" / header).is_file():
            raise RuntimeError("PAM development headers unavailable; set LOCALPIN_PAM_INCLUDE to an extracted pam-devel include directory")
    with tempfile.TemporaryDirectory(prefix="localpin-m7-pam-") as temporary:
        work = Path(temporary)
        flags = ["-std=c11", "-Wall", "-Wextra", "-Werror", "-O2", "-isystem", str(include)]
        subprocess.run(["cc", *flags, str(tests / "harness.c"), "-l:libpam.so.0", "-o", str(work / "harness")], check=True)
        subprocess.run(["cc", *flags, "-shared", "-fPIC", str(tests / "password_module.c"), "-l:libpam.so.0", "-o", str(work / "password_fixture.so")], check=True)
        command = [
            "unshare", "--user", "--map-root-user", "--map-auto", "--mount", "--fork", "--kill-child",
            "bwrap", "--unshare-ipc", "--unshare-net", "--unshare-pid", "--die-with-parent", "--new-session", "--clearenv",
            "--tmpfs", "/", "--ro-bind", "/usr", "/usr", "--symlink", "usr/lib64", "/lib64", "--symlink", "usr/lib", "/lib",
            "--symlink", "usr/bin", "/bin", "--symlink", "usr/sbin", "/sbin", "--proc", "/proc", "--dev", "/dev",
            "--dir", "/app", "--dir", "/run", "--dir", "/tmp",
            "--ro-bind", str(work / "harness"), "/app/harness",
            "--ro-bind", str(work / "password_fixture.so"), "/app/password_fixture.so",
            "--ro-bind", str(module), "/app/liblocalpin_pam.so",
            "--ro-bind", str(tests / "isolated_pam.py"), "/app/isolated_pam.py",
            "--cap-add", "CAP_SETUID", "--cap-add", "CAP_SETGID", "--cap-add", "CAP_CHOWN",
            "--", "/usr/bin/python3", "/app/isolated_pam.py", "--inside",
        ]
        subprocess.run(command, cwd=root, check=True, timeout=90)


if __name__ == "__main__":
    try:
        main()
    except (OSError, RuntimeError, AssertionError, subprocess.SubprocessError) as error:
        print(f"isolated production PAM test failed: {error}", file=sys.stderr)
        raise SystemExit(1) from None
