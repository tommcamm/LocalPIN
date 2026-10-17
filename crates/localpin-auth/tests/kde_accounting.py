#!/usr/bin/env python3
"""Exercise KDE auth-only substacks with real PAM/faillock in private namespaces.

No host PAM, identity, tally or D-Bus socket is exposed. A tiny test-only module
selects fingerprint return codes; the no-bus case uses the real pam_fprintd.
"""
import ctypes
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

POLICY = Path("/policies") if "--child" in sys.argv else Path(__file__).resolve().parents[1] / "policy"
HASH = "$6$localpinfixture$XZXgc8oU5RtAXcA956YrjeKHBgmmyTZodGnV5/z/3lpOyi/iOXSPI4LU79zTVTIuVQ0wiVXLiRN.RO3cr/adM."
PASSWORD = b"synthetic password"


def child():
    pam = ctypes.CDLL("/usr/lib64/libpam.so.0")
    libc = ctypes.CDLL(None)
    libc.calloc.argtypes = [ctypes.c_size_t, ctypes.c_size_t]
    libc.calloc.restype = ctypes.c_void_p
    libc.strdup.argtypes = [ctypes.c_char_p]
    libc.strdup.restype = ctypes.c_void_p

    class Message(ctypes.Structure):
        _fields_ = [("style", ctypes.c_int), ("text", ctypes.c_char_p)]

    class Response(ctypes.Structure):
        _fields_ = [("text", ctypes.c_void_p), ("code", ctypes.c_int)]

    Callback = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_int,
                               ctypes.POINTER(ctypes.POINTER(Message)),
                               ctypes.POINTER(ctypes.POINTER(Response)), ctypes.c_void_p)

    class Conversation(ctypes.Structure):
        _fields_ = [("callback", Callback), ("data", ctypes.c_void_p)]

    pam.pam_start.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.POINTER(Conversation),
                             ctypes.POINTER(ctypes.c_void_p)]
    pam.pam_authenticate.argtypes = [ctypes.c_void_p, ctypes.c_int]
    pam.pam_set_item.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p]
    pam.pam_end.argtypes = [ctypes.c_void_p, ctypes.c_int]
    FailDelay = ctypes.CFUNCTYPE(None, ctypes.c_int, ctypes.c_uint, ctypes.c_void_p)
    delay = FailDelay(lambda _result, _delay, _data: None)
    tally = Path("/run/faillock/fixture")
    fingerprint = Path("/etc/pam.d/localpin-kde-fingerprint")
    original = Path("/policies/localpin-kde-fingerprint.review-required").read_text().replace(
        "/usr/lib64/security/pam_localpin.so", "/app/liblocalpin_pam.so")
    password_policy = Path("/etc/pam.d/localpin-kde-password").read_text()
    native_password = Path("/etc/pam.d/password-auth")
    native_fingerprint = Path("/etc/pam.d/fingerprint-auth")
    password_original = native_password.read_text()
    fingerprint_original = native_fingerprint.read_text()
    outcomes = []

    def attempt(service, password=PASSWORD):
        @Callback
        def converse(count, messages, output, _data):
            memory = libc.calloc(count, ctypes.sizeof(Response))
            responses = ctypes.cast(memory, ctypes.POINTER(Response))
            for index in range(count):
                if messages[index].contents.style in (1, 2):
                    responses[index].text = libc.strdup(password)
            output[0] = responses
            return 0
        conversation = Conversation(converse, None)
        handle = ctypes.c_void_p()
        assert pam.pam_start(service.encode(), b"fixture", ctypes.byref(conversation), ctypes.byref(handle)) == 0
        assert pam.pam_set_item(handle, 10, ctypes.cast(delay, ctypes.c_void_p)) == 0
        result = pam.pam_authenticate(handle, 0)
        assert pam.pam_end(handle, result) == 0
        return result

    def sensor(result):
        fingerprint.write_text(original.replace("pam_fprintd.so", f"/app/fingerprint.so {result}"))

    # Match KDE's actual contract: authenticate only, never account management.
    assert attempt("kde", b"wrong synthetic") != 0
    before = tally.read_bytes()
    assert len(before) == 64
    # Disabling the authselect feature must never enable an enrolled sensor.
    # The corrected sensor fixture would accept if accidentally invoked.
    sensor(0)
    native_fingerprint.write_text("auth required pam_debug.so auth=authinfo_unavail\n")
    assert attempt("kde-fingerprint") == 9
    assert tally.read_bytes() == before
    assert not Path("/run/fprintd-called").exists(), "disabled fingerprint invoked the sensor"
    native_fingerprint.write_text(fingerprint_original)
    outcomes.append("disabled native fingerprint remains unavailable without invoking sensor or changing history")
    for code in (9, 28, 3, 4, 19):  # unavailable, missing module, service/system/conversation error
        sensor(code)
        for _ in range(4):
            assert attempt("kde-fingerprint") != 0
            assert tally.read_bytes() == before, f"service error {code} changed native history"
        outcomes.append(f"fingerprint return {code}: history preserved")
    # The actual fprintd module sees no private system bus or device.
    fingerprint.write_text(original)
    result = attempt("kde-fingerprint")
    assert result == 9, f"real fingerprint unavailable result: {result}"
    assert tally.read_bytes() == before
    outcomes.append(f"real pam_fprintd without bus: denied ({result}), history preserved")

    result = attempt("kde")
    assert result == 0, f"full password result: {result}"
    assert tally.read_bytes() == b"", "full password must reset in auth phase"
    outcomes.append("correct full password resets only after authentication success")
    for code in (7, 11):  # real rejection and retry exhaustion
        sensor(code)
        assert attempt("kde-fingerprint") != 0
        assert len(tally.read_bytes()) == 64
        sensor(0)
        assert attempt("kde-fingerprint") == 0
        assert tally.read_bytes() == b"", "real biometric success uses native authsucc"
    outcomes.append("genuine biometric failures counted; biometric success resets")

    # Policy changes must use the original graph dynamically, preserving added
    # factors in both services even after LocalPIN was already installed.
    assert attempt("kde", b"wrong synthetic") != 0
    before = tally.read_bytes()
    native_password.write_text("auth requisite pam_deny.so\n" + password_original)
    assert attempt("kde") != 0
    assert tally.read_bytes() == before
    native_password.write_text(password_original)
    native_fingerprint.write_text("auth requisite pam_deny.so\n" + fingerprint_original)
    sensor(0)
    assert attempt("kde-fingerprint") != 0
    assert tally.read_bytes() == before
    native_fingerprint.write_text(fingerprint_original)
    outcomes.append("new required native policy denies both corrected substacks")
    for directive in ("AUTH requisite pam_deny.so\n", "unknown requisite pam_deny.so\n",
                      "\u00a0auth requisite pam_deny.so\n", "\u00a0# hidden native-invalid type\n"):
        native_password.write_text(directive + password_original)
        assert attempt("kde") != 0, "noncanonical native password restriction was bypassed"
        assert tally.read_bytes().startswith(before), "native denial erased preexisting history"
        native_password.write_text(password_original)
        assert attempt("kde") == 0
        assert attempt("kde", b"wrong synthetic") != 0
        before = tally.read_bytes()
        native_fingerprint.write_text(directive + fingerprint_original)
        assert attempt("kde-fingerprint") != 0, "noncanonical native fingerprint restriction was bypassed"
        assert tally.read_bytes().startswith(before), "native fingerprint denial erased history"
        native_fingerprint.write_text(fingerprint_original)
        assert attempt("kde") == 0
        assert attempt("kde", b"wrong synthetic") != 0
        before = tally.read_bytes()
    outcomes.append("uppercase, unknown and Unicode-prefixed native PAM types retain original denial")
    postlogin = Path("/etc/pam.d/postlogin")
    postlogin_original = postlogin.read_text()
    for directive in ("AUTH requisite pam_deny.so\n", "unknown requisite pam_deny.so\n",
                      "\u00a0auth requisite pam_deny.so\n", "\u00a0# hidden native-invalid type\n"):
        postlogin.write_text(directive + postlogin_original)
        assert attempt("kde") != 0, "postlogin native restriction was bypassed"
        assert tally.read_bytes() == before, "postlogin rejection must not reach corrected authsucc"
        postlogin.write_text(postlogin_original)
    outcomes.append("uppercase, unknown and Unicode-prefixed postlogin PAM types deny without erasing history")

    # A missing guard/module must run the original stack, with its original
    # success/failure behavior, rather than jump into a privileged correction.
    kde = Path("/etc/pam.d/localpin-kde-password")
    kde.write_text(password_policy.replace("/app/liblocalpin_pam.so", "/missing-module.so"))
    assert attempt("kde") == 0
    assert tally.read_bytes() == before, "missing guard must use original auth-only accounting"
    kde.write_text(password_policy)
    assert attempt("kde") == 0
    assert tally.read_bytes() == b""
    outcomes.append("missing guard uses original native password path")

    sensor(7)
    for _ in range(3):
        assert attempt("kde-fingerprint") != 0
    before = tally.read_bytes()
    assert len(before) == 192
    sensor(0)
    assert attempt("kde-fingerprint") != 0, "locked account must reject even matching fingerprint"
    assert attempt("kde") != 0, "locked account must reject even correct password"
    assert tally.read_bytes() == before, "denial must retain exact native lockout"
    outcomes.append("native threshold denies matching fingerprint and correct password")
    print(json.dumps({"passed": outcomes}))


def main():
    if len(sys.argv) == 2 and sys.argv[1] == "--child":
        child()
        return
    if os.geteuid() == 0:
        raise SystemExit("Refusing host root; use an ordinary user with private namespaces")
    with tempfile.TemporaryDirectory(prefix="localpin-kde-accounting-") as temporary:
        root = Path(temporary)
        (root / "etc/pam.d").mkdir(parents=True)
        (root / "etc/security").mkdir()
        (root / "etc/authselect").mkdir()
        (root / "run/faillock").mkdir(parents=True)
        (root / "etc/passwd").write_text("root:x:0:0::/:/bin/sh\nfixture:x:1000:1000::/home/fixture:/bin/bash\n")
        (root / "etc/environment").write_text("")
        (root / "etc/security/pam_env.conf").write_text("")
        (root / "etc/group").write_text("root:x:0:\nfixture:x:1000:\n")
        (root / "etc/shadow").write_text(f"root:!:20000:0:99999:7:::\nfixture:{HASH}:20000:0:99999:7:::\n")
        (root / "etc/shadow").chmod(0o600)
        (root / "etc/nsswitch.conf").write_text("passwd: files\ngroup: files\nshadow: files\n")
        (root / "etc/security/faillock.conf").write_text("deny=3\nfail_interval=900\nunlock_time=600\ndir=/run/faillock\n")
        (root / "etc/pam.d/kde").write_text("auth substack localpin-kde-password\nauth include postlogin\n")
        (root / "etc/pam.d/kde-fingerprint").write_text("auth substack localpin-kde-fingerprint\nauth include postlogin\n")
        (root / "etc/pam.d/postlogin").write_text("session optional pam_unix.so\n")
        (root / "etc/pam.d/localpin-kde-password").write_text((POLICY / "localpin-kde-password.review-required").read_text().replace(
            "/usr/lib64/security/pam_localpin.so", "/app/liblocalpin_pam.so"))
        (root / "etc/pam.d/password-auth").write_text("auth required pam_env.so\nauth required pam_faildelay.so delay=2000000\nauth required pam_faillock.so preauth silent\nauth sufficient pam_unix.so nullok\nauth required pam_faillock.so authfail\nauth required pam_deny.so\naccount required pam_faillock.so\naccount required pam_unix.so\n")
        (root / "etc/pam.d/fingerprint-auth").write_text("auth required pam_env.so\nauth required pam_faillock.so preauth silent\nauth [success=done default=bad] pam_fprintd.so\nauth required pam_faillock.so authfail\nauth required pam_deny.so\naccount required pam_faillock.so\naccount required pam_unix.so\naccount required pam_permit.so\n")
        repository = Path(__file__).resolve().parents[3]
        built = subprocess.run(["cargo", "build", "--release", "--locked", "-p", "localpin-pam", "--message-format=json"], cwd=repository, check=True, text=True, stdout=subprocess.PIPE)
        artifacts = [json.loads(line) for line in built.stdout.splitlines()]
        modules = [Path(filename) for item in artifacts if item.get("reason") == "compiler-artifact" and item.get("target", {}).get("name") == "localpin_pam" for filename in item.get("filenames", []) if filename.endswith(".so")]
        assert len(modules) == 1
        (root / "liblocalpin_pam.so").write_bytes(modules[0].read_bytes())
        (root / "liblocalpin_pam.so").chmod(0o755)
        (root / "fingerprint.c").write_text("#include <stdlib.h>\n#include <stdio.h>\nint pam_sm_authenticate(void*p,int f,int n,const char**v){(void)p;(void)f;FILE*m=fopen(\"/run/fprintd-called\",\"w\");if(m)fclose(m);return n==1?atoi(v[0]):3;}\nint pam_sm_setcred(void*p,int f,int n,const char**v){(void)p;(void)f;(void)n;(void)v;return 0;}\n")
        subprocess.run(["cc", "-shared", "-fPIC", "-Wall", "-Wextra", "-Werror", str(root / "fingerprint.c"), "-o", str(root / "fingerprint.so")], check=True)
        command = ["unshare", "--user", "--map-root-user", "--net", "--", "bwrap", "--unshare-all", "--share-net", "--die-with-parent", "--clearenv", "--uid", "0", "--gid", "0", "--ro-bind", "/usr", "/usr", "--symlink", "usr/lib64", "/lib64", "--symlink", "usr/lib", "/lib", "--symlink", "usr/bin", "/bin", "--symlink", "usr/sbin", "/sbin", "--proc", "/proc", "--dev", "/dev", "--bind", str(root / "etc"), "/etc", "--bind", str(root / "run"), "/run", "--ro-bind", str(root), "/app", "--ro-bind", str(POLICY), "/policies", "--ro-bind", str(Path(__file__).resolve()), "/test.py", "--", "/usr/bin/python3", "/test.py", "--child"]
        subprocess.run(command, check=True, timeout=60, env={})


if __name__ == "__main__":
    main()
