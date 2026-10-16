#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Guarded password-free eligibility experiment for two exact Fedora VM policies."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import signal
import stat
import subprocess
import tempfile

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("m1_eligibility_pam_fixture", HERE.parent / "pam" / "run.py")
pam = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(pam)
require = pam.require
TARGET = "localpintest"
POLICIES = {
    "kde": "7d91b3ad73a998e8b10f9edccd74ba04179a778c4a5e61d9176872f43c7bbac3",
    "postlogin": "c1ecd4d1a5b5de7d26e3336cd33551d1d65e13751b5f46405183472895838a9d",
    "faillock.conf": "662303cf89938c12d95a7fc59d92cbe76c398312527fa908894fb319809093b3",
}
PASSWORD_AUTH = {
    "2e53f704372b6c7fb69cdc4dfd6c27456d642c83feff8b1588fa1f9cb1126cd0": "default",
    "de00ea01b5ffe6b08efd7027e437bdd4a3bad18e231e9593f6b45cc64b334276": "faillock",
}
PACKAGE_VERSIONS = ["pam-1.7.2-2.fc44.x86_64", "authselect-1.7.1-1.fc44.x86_64"]


def reviewed_content(name, data):
    value = hashlib.sha256(data).hexdigest()
    require(value in PASSWORD_AUTH if name == "password-auth" else value == POLICIES[name],
            f"unknown policy content: {name}")
    if name == "faillock.conf":
        require(not any(line.strip() and not line.lstrip().startswith(b"#") for line in data.splitlines()),
                "active external faillock configuration is unsupported")
    return value


def policy():
    require(pam.command(["rpm", "-q", "pam", "authselect"]).decode().splitlines() == PACKAGE_VERSIONS,
            "unreviewed PAM/authselect package versions")
    inputs = {}
    for name in (*POLICIES, "password-auth"):
        path = Path("/etc/security/faillock.conf") if name == "faillock.conf" else Path("/etc/pam.d") / name
        info = path.stat()
        require(stat.S_ISREG(info.st_mode) and info.st_uid == info.st_gid == 0 and info.st_nlink == 1
                and not info.st_mode & 0o022 and info.st_size <= 65536, "unsafe reviewed policy input")
        data = path.read_bytes()
        reviewed_content(name, data)
        inputs[name] = data
    require(not any(line.strip() and not line.lstrip().startswith(b"#") for line in inputs["faillock.conf"].splitlines()),
            "active external faillock configuration is unsupported")
    profile = PASSWORD_AUTH[hashlib.sha256(inputs["password-auth"]).hexdigest()]
    require(not any(Path(path).exists() or Path(path).is_symlink() for path in ("/run/nologin", "/etc/nologin")),
            "global nologin state already active; preserve it and stop the fixture")
    return profile, inputs


def build(work):
    flags = ["-std=c11", "-O2", "-Wall", "-Wextra", "-Wpedantic", "-Werror",
             "-fstack-protector-strong", "-D_FORTIFY_SOURCE=3", "-Wl,-z,relro,-z,now", "-isystem",
             os.environ.get("LOCALPIN_PAM_INCLUDE", "/usr/include")]
    pam.command(["cc", *flags, str(HERE / "check.c"), "-o", str(work / "check"), "-l:libpam.so.0"])
    pam.command(["cc", *flags, "-fPIC", "-shared", str(HERE / "gate.c"), "-o", str(work / "gate.so"), "-l:libpam.so.0"])


def target_identity():
    matches = [line for line in Path("/etc/passwd").read_text().splitlines() if line.split(":", 1)[0] == TARGET]
    require(len(matches) == 1, "local identity unavailable")
    return matches[0] + "\n"


def configure(work, profile, inputs):
    work.chmod(0o700)
    (work / "identity").write_text(target_identity())
    for name, data in inputs.items():
        (work / f"expected-{name}").write_bytes(data)
    auth = "auth required /usr/lib64/security/pam_env.so\nauth required /usr/lib64/security/pam_faildelay.so delay=2000000\n"
    if profile == "faillock":
        auth += "auth required /usr/lib64/security/pam_faillock.so preauth silent\n"
    auth += "auth required /usr/lib64/security/pam_permit.so\n"
    accounts = ("account required /usr/lib64/security/pam_nologin.so\n"
                f"account required /usr/lib64/security/pam_nologin.so file={work}/fixture-nologin\n"
                "account required /usr/lib64/security/pam_unix.so\n")
    (work / "localpin-m1-preflight").write_text(auth + accounts)
    (work / "localpin-m1-gated").write_text(f"auth [success=done default=die] {work}/gate.so\n")


def check(work, *, allow_missing):
    profile, inputs = policy()
    del profile
    for name, value in inputs.items():
        require((work / f"expected-{name}").read_bytes() == value, "policy changed during fixture")
    output = pam.command([str(work / "check"), str(work), "allow-missing-after-baseline" if allow_missing else "require-tally"], timeout=25)
    result = json.loads(output)
    require(result["conversation_calls"] == 0, "eligibility route attempted a conversation")
    return result


def counter_digest(path=None):
    path = Path("/run/faillock") / TARGET if path is None else Path(path)
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except FileNotFoundError:
        return None
    try:
        before = os.fstat(descriptor)
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 <= before.st_size <= 65536,
                "counter must be a bounded regular single-link file")
        data = bytearray()
        while len(data) < before.st_size:
            part = os.read(descriptor, before.st_size - len(data))
            require(bool(part), "counter truncated during digest")
            data.extend(part)
        after = os.fstat(descriptor)
        require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) ==
                (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns),
                "counter changed during bounded digest")
        return hashlib.sha256(data).hexdigest()
    finally:
        os.close(descriptor)


def execute(args):
    pam.guard()
    profile, inputs = policy()
    services = pam.graph()
    threshold = pam.faillock_policy(services)
    require((threshold == 3) if profile == "faillock" else threshold is None, "unexpected failure policy")
    report = {"schema": 1, "fixture": "root-private password-free checker plus simulated success gate",
              "profile": profile, "selinux": "Enforcing", "results": [], "target_shadow_record_restored": False,
              "policy_sha256": {name: hashlib.sha256(data).hexdigest() for name, data in inputs.items()},
              "production_eligibility_implemented": False, "whole_vm_snapshot_restored": False}
    if args.check_env:
        return {**report, "check_only": True}
    require(args.snapshot_confirmed, "restorable clean VM snapshot required")
    original = pam.shadow_record()
    mutated = False
    stage = [3]
    primary_error = None
    restoration_errors = []

    def interrupted(signum, frame):
        del signum, frame
        raise RuntimeError("interrupted; restoring only the dedicated fixture account")

    signal.signal(signal.SIGINT, interrupted)
    signal.signal(signal.SIGTERM, interrupted)
    try:
        with tempfile.TemporaryDirectory(prefix="localpin-m1-eligibility-") as temporary, \
             tempfile.TemporaryDirectory(prefix="localpin-m1-eligibility-baseline-") as baseline_temporary:
            work, baseline = Path(temporary), Path(baseline_temporary)
            build(work)
            configure(work, profile, inputs)
            pam.build(baseline)
            pam.configure(baseline, services)
            stage[0] = 10
            mutated = True
            pam.set_password(pam.SIX_DIGIT)
            pam.reset_faillock(threshold)
            stage[0] = 11
            positive = pam.authenticate(baseline, "baseline", [pam.SIX_DIGIT])[0]
            require(positive["auth"] == positive["account"] == 0, "healthy real-password baseline failed")
            # Missing tally is allowed only in this run after a known healthy
            # password/account baseline, not inferred from preauth success alone.
            allow_missing = counter_digest() is None
            report["healthy_password_baseline"] = positive
            report["missing_tally_after_healthy_baseline"] = allow_missing

            def record(name, eligible, *, stage_code, raw=None, preauth=None, account=None):
                stage[0] = stage_code
                before = counter_digest()
                result = check(work, allow_missing=allow_missing)
                report["last_observation"] = {"stage": stage_code, "values": result}
                after = counter_digest()
                require(result["eligible"] == eligible and result["gated_auth"] == (0 if eligible else 6),
                        f"eligibility gate mismatch: {name}; sanitized={json.dumps(result)}")
                require(result["counter_unchanged"] and before == after and result["policy_unchanged"],
                        f"checker changed or could not establish trusted counter/policy state: {name}")
                for key, wanted in (("raw_result", raw), ("preauth", preauth), ("account", account)):
                    require(wanted is None or result[key] == wanted, f"unexpected numeric policy outcome: {name}")
                report["results"].append({"case": name, "observation": result, "counter_digest_unchanged": True, "passed": True})

            record("healthy account permits simulated success", True, stage_code=20, raw=0, preauth=0, account=0)
            stage[0] = 21
            pam.command(["usermod", "--lock", TARGET])
            record("locked password denies simulated success", False, stage_code=22, raw=2)
            stage[0] = 23
            pam.set_password(pam.SIX_DIGIT)
            stage[0] = 24
            pam.command(["chage", "--expiredate", "1", TARGET])
            record("expired account denies simulated success", False, stage_code=25, raw=3)
            stage[0] = 26
            pam.set_password(pam.SIX_DIGIT)
            stage[0] = 27
            pam.command(["chage", "--lastday", "0", TARGET])
            record("expired password denies simulated success", False, stage_code=28, raw=4)
            stage[0] = 29
            pam.set_password(pam.SIX_DIGIT)
            stage[0] = 30
            before_malformed_setup = pam.shadow_record()
            malformed = subprocess.run(["chpasswd", "--encrypted"], input=b"localpintest:$6$malformed\n",
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
            if malformed.returncode == 0:
                record("malformed enabled hash denies simulated success", False, stage_code=31, raw=5)
            else:
                diagnostic = malformed.stderr.lower()
                require(malformed.returncode == 1 and b"invalid" in diagnostic
                        and not any(value in diagnostic for value in (b"permission", b"token", b"cannot lock")),
                        "malformed fixture failed for an unexpected setup category")
                require(pam.shadow_record() == before_malformed_setup, "rejected fixture setup changed target record")
                report["malformed_hash_setup"] = {"tool_exit": 1, "classification": "invalid_fixture_rejected",
                                                  "target_record_unchanged": True, "actual_account_case_tested": False}
                report.setdefault("not_tested", []).append("malformed enabled account hash: packaged chpasswd rejected fixture; strict parser tested only by pure C checks")
            stage[0] = 32
            pam.set_password(pam.SIX_DIGIT)
            (work / "fixture-nologin").touch(mode=0o600)
            record("private nologin fixture denies simulated success", False, stage_code=40, raw=0, preauth=0, account=7)
            (work / "fixture-nologin").unlink()
            identity = (work / "identity").read_bytes()
            (work / "identity").write_bytes(identity.replace(b"localpintest:", b"other-fixture:", 1))
            record("changed expected identity denies simulated success", False, stage_code=41, raw=1)
            (work / "identity").write_bytes(identity)
            if threshold:
                stage[0] = 50
                pam.reset_faillock(threshold)
                for _ in range(threshold):
                    wrong = pam.authenticate(baseline, "baseline", [pam.WRONG], False)[0]
                    require(wrong["auth"] == 7, "wrong password baseline did not deny")
                record("active failure lockout denies without resetting counter", False, stage_code=51, raw=0, preauth=7, account=-1)
                stage[0] = 52
                still_locked = pam.authenticate(baseline, "baseline", [pam.SIX_DIGIT], False)[0]
                require(still_locked["auth"] == 7, "checker cleared the existing failure lockout")
                report["correct_password_still_denied_after_checker"] = True
                pam.reset_faillock(threshold)
                record("healthy after explicit fixture counter reset", True, stage_code=54, raw=0, preauth=0, account=0)
                stage[0] = 55
                tally_path = Path("/run/faillock") / TARGET
                original_mode = stat.S_IMODE(tally_path.stat().st_mode)
                original_digest = counter_digest()
                try:
                    tally_path.chmod(0o640)
                    bad_mode = check(work, allow_missing=False)
                    require(not bad_mode["eligible"] and not bad_mode["counter_valid"] and bad_mode["gated_auth"] == 6
                            and bad_mode["preauth"] == -1 and counter_digest() == original_digest
                            and stat.S_IMODE(tally_path.stat().st_mode) == 0o640,
                            "noncanonical counter guard failed or normalized metadata")
                    report["results"].append({"case": "noncanonical tally mode denies before PAM without normalization",
                                              "observation": bad_mode, "counter_digest_unchanged": True,
                                              "noncanonical_mode_retained_by_checker": True, "passed": True})
                finally:
                    tally_path.chmod(original_mode)
            else:
                report.setdefault("not_tested", []).append("active failure lockout: enable reviewed with-faillock profile for separate run")
            require(target_identity() == (work / "identity").read_text(), "local identity changed during run")
    except BaseException as error:
        primary_error = {"stage": stage[0], "category": type(error).__name__}
    finally:
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        if mutated:
            try:
                pam.restore_shadow(original)
                report["target_shadow_record_restored"] = True
            except Exception as error:
                restoration_errors.append({"stage": 90, "category": type(error).__name__})
            try:
                pam.reset_faillock(threshold)
                report["fixture_counter_reset"] = threshold is not None
            except Exception as error:
                restoration_errors.append({"stage": 91, "category": type(error).__name__})
    report["completed"] = primary_error is None and not restoration_errors
    report["primary_failure"] = primary_error
    report["restoration_failures"] = restoration_errors
    report["snapshot_restore_required_for_failed_cleanup"] = bool(restoration_errors)
    report["last_stage"] = stage[0]
    try:
        report["versions"] = pam.command(["rpm", "-q", "pam", "authselect", "selinux-policy-targeted"]).decode().splitlines()
    except Exception:
        report["metadata_query_failed"] = True
    report["not_tested"] = report.get("not_tested", []) + ["production IPC or enrollment identity lifecycle", "account/policy changes after delivered authorization", "confined production eligibility worker", "whole-VM snapshot restoration"]
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--compile-only", action="store_true")
    parser.add_argument("--check-env", action="store_true")
    parser.add_argument("--run-mutate", action="store_true")
    parser.add_argument("--snapshot-confirmed", action="store_true")
    args = parser.parse_args()
    require(sum((args.compile_only, args.check_env, args.run_mutate)) == 1, "choose one operation")
    os.umask(0o077)
    if args.compile_only:
        with tempfile.TemporaryDirectory(prefix="localpin-m1-eligibility-compile-") as temporary:
            build(Path(temporary))
        print("Eligibility checker/gate compile PASS; no PAM, account or VM operation executed")
        return
    report = execute(args)
    print(json.dumps(report, indent=2))
    return 0 if report.get("completed", True) else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        print(f"M1 eligibility stopped: {type(error).__name__}: {error}", file=__import__("sys").stderr)
        raise SystemExit(1)
