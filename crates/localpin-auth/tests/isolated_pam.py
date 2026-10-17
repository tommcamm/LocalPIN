#!/usr/bin/env python3
"""Actual PAM worker tests in private user/mount/PID/network namespaces.

Only a synthetic password and private passwd/shadow/faillock files are used.
The host /etc is never mounted and /usr is read-only. No host account/PAM edits.
Requires Linux user namespaces, bubblewrap, Python and pam_unix/pam_faillock.
Run: cargo build -p localpin-auth --bin localpin-auth-worker
     python3 crates/localpin-auth/tests/isolated_pam.py target/debug/localpin-auth-worker
"""
import pathlib
import os
import select
import shutil
import struct
import subprocess
import sys
import tempfile


HASH = "$6$localpinfixture$XZXgc8oU5RtAXcA956YrjeKHBgmmyTZodGnV5/z/3lpOyi/iOXSPI4LU79zTVTIuVQ0wiVXLiRN.RO3cr/adM."
PASSWORD = b"synthetic password"
POLICY = pathlib.Path(__file__).resolve().parents[1] / "policy" / "localpin-enroll.review-required"


def exact(stream, size):
    result = b""
    while len(result) < size:
        assert select.select([stream], [], [], 15)[0], "private worker deadline"
        data = os.read(stream.fileno(), size - len(result))
        assert data, "private worker closed before a result"
        result += data
    return result


def frame(stream):
    header = exact(stream, 23)
    return header[0], header[1:17], struct.unpack("!I", header[17:21])[0], exact(stream, struct.unpack("!H", header[21:23])[0])


def run(worker, etc, runtime, password, persistent=None):
    token = bytes([8]) * 16
    request = b"LPA1" + token + struct.pack("!I", 1000) + bytes([1])*16 + bytes([2])*16 + bytes([3])*16 + bytes([2]) + struct.pack("!Q", 2) + bytes([4])*16 + struct.pack("!Q", 100)
    assert len(request) == 105
    command = ["/usr/bin/unshare", "--user", "--map-root-user", "--net", "--", "/usr/bin/bwrap", "--unshare-all", "--share-net", "--die-with-parent", "--clearenv", "--uid", "0", "--gid", "0", "--ro-bind", "/usr", "/usr", "--symlink", "usr/lib64", "/lib64", "--symlink", "usr/lib", "/lib", "--symlink", "usr/bin", "/bin", "--symlink", "usr/sbin", "/sbin", "--proc", "/proc", "--dev", "/dev", "--ro-bind", str(etc), "/etc", "--bind", str(runtime), "/run", "--ro-bind", str(worker), "/worker", "--", "/worker"]
    if persistent is not None:
        command[-2:-2] = ["--bind", str(persistent), "/var/lib/faillock"]
    process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env={})
    try:
        process.stdin.write(request)
        process.stdin.flush()
        kind, nonce, sequence, data = frame(process.stdout)
        assert nonce == token
        prompted = kind == 1
        if prompted:
            assert sequence == 1 and data == b""
            process.stdin.write(bytes([2]) + token + struct.pack("!IH", 1, len(password)) + password)
            process.stdin.flush()
            kind, nonce, sequence, data = frame(process.stdout)
        assert kind == 3 and nonce == token and sequence == 2 and len(data) == 1
        process.stdin.close()
        assert process.wait(timeout=15) == 0, process.stderr.read().decode(errors="replace")
        assert process.stdout.read() == b"", "trailing private worker frame"
        return data[0], prompted
    except AssertionError as error:
        if process.poll() is not None:
            raise AssertionError(str(error) + ": " + process.stderr.read().decode(errors="replace")) from error
        raise
    finally:
        if process.poll() is None:
            process.kill()
            process.wait()


def main():
    import json
    if os.geteuid() == 0:
        raise SystemExit("Refusing host root: this runner uses unprivileged private user namespaces")
    if len(sys.argv) > 1:
        worker = pathlib.Path(sys.argv[1]).resolve(strict=True)
    else:
        repository = pathlib.Path(__file__).resolve().parents[3]
        built = subprocess.run(["cargo", "build", "--locked", "-p", "localpin-auth", "--bin", "localpin-auth-worker", "--message-format=json"], cwd=repository, check=True, text=True, stdout=subprocess.PIPE)
        outputs = [json.loads(line) for line in built.stdout.splitlines()]
        executables = [item["executable"] for item in outputs if item.get("reason") == "compiler-artifact" and item.get("target", {}).get("name") == "localpin-auth-worker" and item.get("executable")]
        assert len(executables) == 1, "cannot identify built private PAM helper"
        worker = pathlib.Path(executables[0]).resolve(strict=True)
    with tempfile.TemporaryDirectory(prefix="localpin-private-pam-") as temp:
        root = pathlib.Path(temp)
        etc, runtime = root / "etc", root / "run"
        (etc / "pam.d").mkdir(parents=True)
        (etc / "security").mkdir()
        (runtime / "faillock").mkdir(parents=True)
        (etc / "passwd").write_text("root:x:0:0:root:/:/bin/sh\nfixture:x:1000:1000:synthetic:/home/fixture:/bin/sh\n")
        (etc / "group").write_text("root:x:0:\nfixture:x:1000:\n")
        (etc / "nsswitch.conf").write_text("passwd: files\ngroup: files\nshadow: files\n")
        (etc / "security" / "faillock.conf").write_text("deny=3\nfail_interval=900\nunlock_time=600\ndir=/run/faillock\n")
        shadow = etc / "shadow"
        service = etc / "pam.d" / "localpin-enroll"

        def account(password_hash=HASH, last_change=20000, maximum=99999, expiry=""):
            shadow.write_text(f"root:!:20000:0:99999:7:::\nfixture:{password_hash}:{last_change}:0:{maximum}:7::{expiry}:\n")
            shadow.chmod(0o600)

        account()
        assert run(worker, etc, runtime, PASSWORD) == (2, False), "missing policy must refuse"
        service.write_text(POLICY.read_text())
        outcome = run(worker, etc, runtime, PASSWORD)
        assert outcome == (0, True), f"fresh real password: {outcome}"
        assert run(worker, etc, runtime, b"wrong synthetic") == (1, True), "wrong password"
        tally = runtime / "faillock" / "fixture"
        assert tally.stat().st_size > 0, "wrong password must retain PAM failure accounting"
        assert run(worker, etc, runtime, PASSWORD) == (0, True), "password recovery"
        assert tally.stat().st_size == 0, "normal successful PAM accounting"

        for _ in range(3):
            assert run(worker, etc, runtime, b"wrong synthetic") == (1, True)
        locked_size = tally.stat().st_size
        assert locked_size > 0
        assert run(worker, etc, runtime, PASSWORD) == (1, False), "existing lockout must reject even correct password"
        assert tally.stat().st_size == locked_size, "rejected lockout must not reset counters"
        tally.unlink()

        account(password_hash="!" + HASH)
        assert run(worker, etc, runtime, PASSWORD)[0] == 1, "locked password"
        tally.unlink(missing_ok=True)
        account(last_change=1, maximum=1)
        assert run(worker, etc, runtime, PASSWORD) == (1, True), "expired password must not authorize enrollment"
        account(expiry="1")
        assert run(worker, etc, runtime, PASSWORD) == (1, True), "expired account"
        account()
        for forbidden in ["auth sufficient pam_permit.so\n", "auth include system-auth\n", "auth sufficient pam_localpin.so\n", "auth sufficient pam_pinlock.so\n", "auth sufficient pam_fprintd.so\n", "auth sufficient pam_timestamp.so\n"]:
            service.write_text(forbidden + POLICY.read_text())
            assert run(worker, etc, runtime, PASSWORD) == (2, False), "unsupported shortcut policy"
        service.write_text(POLICY.read_text())
        persistent = root / "persistent-faillock"
        persistent.mkdir()
        (etc / "security" / "faillock.conf").write_bytes(b"dir = /var/lib/faillock\n")
        shutil.rmtree(runtime)
        runtime.mkdir()
        for _ in range(3):
            assert run(worker, etc, runtime, b"wrong synthetic", persistent) == (1, True)
        persistent_tally = persistent / "fixture"
        before = persistent_tally.read_bytes()
        assert len(before) == 3 * 64, "native failures must use the fixed persistent directory"
        assert not (runtime / "faillock" / "fixture").exists(), "persistent policy must not fall back to volatile accounting"
        # Recreate the entire private /run between fresh native worker processes.
        # This proves accounting survives volatile-runtime loss; actual reboot
        # and installed SELinux acceptance remain separate VM requirements.
        shutil.rmtree(runtime)
        runtime.mkdir()
        assert run(worker, etc, runtime, PASSWORD, persistent) == (1, False), "persistent native lockout must survive volatile-runtime loss"
        assert persistent_tally.read_bytes() == before, "denied locked password must preserve exact persistent counters"
        print("PASS: private real PAM password, failure accounting, lockout, locked/expired account, unsupported policy, persistent lockout across volatile-runtime loss")


if __name__ == "__main__":
    main()
