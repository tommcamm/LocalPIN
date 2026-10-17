#!/usr/bin/env python3
"""Bounded ASan/UBSan PAM checks in existing synthetic namespace fixtures.

Requires nightly Rust with rust-src, GCC, PAM headers and the namespace tools
documented by the existing PAM runners. Does not install or activate anything.
Rust dependencies and std are rebuilt with ASan; project-owned C fixtures use
ASan/UBSan. Fedora libpam/modules, glibc and TPM libraries remain uninstrumented.
Leak detection is explicitly excluded; this is a memory-access/UB check.
"""

import argparse
import contextlib
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time
import traceback


REPOSITORY = Path(__file__).resolve().parents[2]
TARGET = "x86_64-unknown-linux-gnu"
RUSTFLAGS = "-Zsanitizer=address -Cforce-frame-pointers=yes"
ASAN = "detect_leaks=0:halt_on_error=1:abort_on_error=1:detect_stack_use_after_return=1"
UBSAN = "halt_on_error=1:print_stacktrace=1"


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def sanitizer_environment(command, ubsan=None):
    """Add runtime options after bwrap's clearenv, before its fixed payload."""
    command = list(map(str, command))
    if "bwrap" in command or "/usr/bin/bwrap" in command:
        index = command.index("bwrap") if "bwrap" in command else command.index("/usr/bin/bwrap")
        clear = command.index("--clearenv", index) + 1
        command[clear:clear] = [
            "--setenv", "ASAN_OPTIONS", ASAN, "--setenv", "UBSAN_OPTIONS", UBSAN,
        ]
        if ubsan is not None:
            payload = max(i for i, value in enumerate(command) if value == "--")
            command[payload:payload] = [
                "--dir", "/sanitizers", "--ro-bind", str(ubsan), "/sanitizers/libubsan.so.1",
                "--setenv", "LD_LIBRARY_PATH", "/sanitizers",
            ]
    return command


def compile_fixture(source, output, include, runtime, *, shared=False, log=None, ubsan=None,
                    commands=None):
    """Use a single LLVM ASan runtime for Rust and GCC-instrumented C.

    Compile GCC objects separately so its driver does not automatically add a
    second, conflicting libasan at link time. UBSan remains GCC's native runtime.
    The Rust compiler-rt ASan archive supplies the common C/Rust ASan ABI.
    """
    object_path = output.with_suffix(output.suffix + ".o")
    command = [
        "gcc", "-std=c11", "-Wall", "-Wextra", "-Werror", "-O1", "-g",
        "-fno-omit-frame-pointer", "-fsanitize=address,undefined",
        "-fno-sanitize-recover=all", "-fPIC", "-isystem", str(include),
        "-c", str(source), "-o", str(object_path),
    ]
    if commands is not None:
        commands.append(command)
    subprocess.run(command, check=True, stdout=log, stderr=log)
    command = ["gcc", str(object_path), "-l:libpam.so.0", str(ubsan) if ubsan else "-lubsan", "-ldl"]
    if ubsan:
        # Mixed real/effective UID cases use secure execution, which removes
        # LD_LIBRARY_PATH. The path exists only inside the synthetic namespace.
        command += ["-Wl,-rpath,/sanitizers"]
    if shared:
        command += ["-shared"]
    else:
        command += ["-Wl,--export-dynamic", "-Wl,--whole-archive", str(runtime),
                    "-Wl,--no-whole-archive", "-lpthread", "-lrt", "-lm"]
    command += ["-o", str(output)]
    if commands is not None:
        commands.append(command)
    subprocess.run(command, check=True, stdout=log, stderr=log)


class InstrumentedProcesses:
    """Narrow adapter for build commands and namespace runtime environment."""

    def __init__(self, include, runtime, log, ubsan, commands):
        self.include, self.runtime, self.log, self.ubsan = include, runtime, log, ubsan
        self.commands = commands

    def __getattr__(self, name):
        return getattr(subprocess, name)

    def run(self, command, **kwargs):
        if command[0] == "cc":
            source = next(Path(value) for value in command if str(value).endswith(".c"))
            output = Path(command[command.index("-o") + 1])
            compile_fixture(source, output, self.include, self.runtime,
                            shared="-shared" in command, log=self.log, ubsan=self.ubsan,
                            commands=self.commands)
            return subprocess.CompletedProcess(command, 0)
        kwargs.setdefault("stdout", self.log)
        kwargs.setdefault("stderr", self.log)
        return subprocess.run(sanitizer_environment(command, self.ubsan), **kwargs)

    def Popen(self, command, **kwargs):  # noqa: N802 -- match subprocess API
        return subprocess.Popen(sanitizer_environment(command), **kwargs)


def private_smoke(executable, module, log, ubsan):
    command = [
        "unshare", "--user", "--map-root-user", "--net", "--", "bwrap",
        "--unshare-all", "--share-net", "--die-with-parent", "--clearenv",
        "--ro-bind", "/usr", "/usr", "--symlink", "usr/lib64", "/lib64",
        "--symlink", "usr/lib", "/lib", "--proc", "/proc", "--dev", "/dev",
        "--tmpfs", "/etc", "--tmpfs", "/tmp", "--dir", "/app",
        "--ro-bind", str(executable), "/app/abi-smoke",
        "--ro-bind", str(module), "/app/liblocalpin_pam.so",
        "--", "/app/abi-smoke", "/app/liblocalpin_pam.so",
    ]
    subprocess.run(sanitizer_environment(command, ubsan), stdout=log, stderr=log,
                   check=True, timeout=30, env={})


def private_ffi_tests(executable, log):
    command = [
        "unshare", "--user", "--map-root-user", "--net", "--", "bwrap",
        "--unshare-all", "--share-net", "--die-with-parent", "--clearenv",
        "--ro-bind", "/usr", "/usr", "--symlink", "usr/lib64", "/lib64",
        "--symlink", "usr/lib", "/lib", "--proc", "/proc", "--dev", "/dev",
        "--tmpfs", "/etc", "--tmpfs", "/tmp", "--dir", "/app",
        "--ro-bind", str(executable), "/app/ffi-tests",
        "--", "/app/ffi-tests", "pam::tests", "--test-threads=1",
    ]
    completed = subprocess.run(sanitizer_environment(command), capture_output=True,
                               check=False, timeout=30, env={}, text=True)
    log.write(completed.stdout + completed.stderr)
    completed.check_returncode()
    count = re.search(r"test result: ok\. ([0-9]+) passed;", completed.stdout)
    if count is None or int(count[1]) == 0:
        raise RuntimeError("PAM FFI unit-test filter did not execute a passing test")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--toolchain", default="nightly")
    parser.add_argument("--pam-include", type=Path, default=Path("/usr/include"))
    parser.add_argument("--target-dir", type=Path)
    parser.add_argument("--ubsan-library", type=Path,
                        help="Extracted native libubsan.so.1 if the host runtime is absent")
    args = parser.parse_args()
    if os.getuid() == 0 or os.geteuid() == 0:
        raise SystemExit("Refusing host root; synthetic unprivileged namespaces are required")
    if os.uname().machine != "x86_64":
        raise SystemExit("Only the reviewed Fedora x86_64 ABI is covered")
    for name in ("cargo", "rustc", "gcc", "bwrap", "unshare", "newuidmap", "newgidmap"):
        if shutil.which(name) is None:
            raise SystemExit(f"Required build/namespace tool unavailable: {name}")
    include = args.pam_include.resolve(strict=True)
    if not (include / "security/pam_modules.h").is_file():
        raise SystemExit("PAM development headers unavailable")
    output = args.output_dir.resolve()
    output.mkdir(parents=True, mode=0o700, exist_ok=False)
    tracked = [Path(name) for name in subprocess.check_output(
        ["git", "ls-files", "-z", "--", "Cargo.toml", "Cargo.lock", "rust-toolchain.toml", "crates"],
        cwd=REPOSITORY).decode().split("\0") if name]
    subprocess.run(["git", "diff", "--quiet", "HEAD", "--",
                    "Cargo.toml", "Cargo.lock", "rust-toolchain.toml", "crates"],
                   cwd=REPOSITORY, check=True)
    if subprocess.check_output(["git", "ls-files", "--others", "--exclude-standard", "--",
                                "Cargo.toml", "Cargo.lock", "rust-toolchain.toml", "crates"],
                               cwd=REPOSITORY):
        raise RuntimeError("Untracked production inputs prevent candidate attribution")
    runner_source = Path(__file__).read_bytes()
    (output / "executed-runner.py").write_bytes(runner_source)
    target = (args.target_dir or output / "target").resolve()
    ubsan = args.ubsan_library.resolve(strict=True) if args.ubsan_library else None
    environment = dict(os.environ, CARGO_TARGET_DIR=str(target), RUSTFLAGS=RUSTFLAGS)
    # Cargo gives the encoded form precedence over RUSTFLAGS. An inherited
    # override must not silently disable the instrumentation claimed below.
    environment.pop("CARGO_ENCODED_RUSTFLAGS", None)
    result = {
        "schema": 1, "candidate": subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=REPOSITORY, text=True).strip(),
        "runner_sha256": hashlib.sha256(runner_source).hexdigest(),
        "date_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "rustflags": RUSTFLAGS, "asan_options": ASAN, "ubsan_options": UBSAN,
        "c_instrumentation": ["-O1", "-g", "-fno-omit-frame-pointer",
                              "-fsanitize=address,undefined", "-fno-sanitize-recover=all"],
        "rust_std_rebuilt": True, "native_libraries_instrumented": False,
        "leak_detection": False, "stages": [],
        "commands": [], "tools": {},
        "tracked_production_inputs": {str(path): hashlib.sha256((REPOSITORY / path).read_bytes()).hexdigest()
                                      for path in tracked},
        "pam_headers": {str(path.relative_to(include)): hashlib.sha256(path.read_bytes()).hexdigest()
                        for path in sorted((include / "security").glob("*.h"))},
        "native_inputs": {str(path): {"resolved": str(path.resolve(strict=True)),
                                      "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
                          for path in [Path(shutil.which("gcc")),
                                       Path("/usr/lib64/libpam.so.0"), Path("/usr/lib64/libc.so.6"),
                                       Path("/usr/lib64/libcrypt.so.2"),
                                       *(Path("/usr/lib64/security/pam_" + name + ".so")
                                         for name in ("env", "faildelay", "faillock", "unix",
                                                      "nologin", "permit", "deny"))]},
        "reused_runners": {str(path.relative_to(REPOSITORY)): hashlib.sha256(path.read_bytes()).hexdigest()
                           for path in [REPOSITORY / "crates/localpin-pam/tests/isolated_pam.py",
                                        REPOSITORY / "crates/localpin-auth/tests/isolated_pam.py"]},
    }
    failed = False

    def stage(name, action):
        nonlocal failed
        started = time.monotonic()
        path = output / (name + ".log")
        with path.open("w") as log, contextlib.redirect_stdout(log), contextlib.redirect_stderr(log):
            try:
                action(log)
            except (OSError, AssertionError, RuntimeError, subprocess.SubprocessError):
                traceback.print_exc()
                status = "failed"
                failed = True
            else:
                status = "passed"
        result["stages"].append({"name": name, "status": status,
                                 "elapsed_seconds": round(time.monotonic() - started, 3),
                                 "log": path.name,
                                 "log_sha256": hashlib.sha256(path.read_bytes()).hexdigest()})
        (output / "result.json").write_text(json.dumps(result, indent=2) + "\n")
        print(f"{name}: {status}", flush=True)
        return status == "passed"

    def inventory(log):
        for command in (["rustc", "+" + args.toolchain, "--version", "--verbose"],
                        ["gcc", "--version"], ["uname", "-srmo"]):
            result["commands"].append(command)
            completed = subprocess.run(command, capture_output=True, text=True, check=False, env=environment)
            result["tools"][command[0]] = completed.stdout.strip()
            log.write(completed.stdout + completed.stderr)
            completed.check_returncode()
        log.write("Rust ASan covers the selected crate dependencies and rebuilt std.\n"
                  "C ASan/UBSan covers abi_smoke.c, harness.c and password_module.c.\n"
                  "Fedora libpam, native PAM modules, glibc and TPM are not instrumented.\n")

    stage("inventory", inventory)
    build_command = ["cargo", "+" + args.toolchain, "build", "--locked", "--release",
                     "--target", TARGET, "-Zbuild-std", "-p", "localpin-pam", "-p", "localpin-auth"]
    result["commands"].append(build_command)
    if not stage("build", lambda log: subprocess.run(build_command, cwd=REPOSITORY,
                 env=environment, stdout=log, stderr=log, check=True, timeout=600)):
        raise SystemExit(1)
    sysroot_command = ["rustc", "+" + args.toolchain, "--print", "sysroot"]
    result["commands"].append(sysroot_command)
    sysroot = Path(subprocess.check_output(sysroot_command,
                                         env=environment, text=True).strip())
    runtimes = list((sysroot / "lib/rustlib" / TARGET / "lib").glob("librustc*rt.asan.a"))
    if len(runtimes) != 1:
        raise SystemExit("Cannot identify the toolchain's single LLVM ASan runtime")
    runtime = runtimes[0]
    module = target / TARGET / "release/liblocalpin_pam.so"
    worker = target / TARGET / "release/localpin-auth-worker"
    tests = REPOSITORY / "crates/localpin-pam/tests"
    smoke = output / "abi-smoke"
    stage("abi-smoke", lambda log: (
        compile_fixture(tests / "abi_smoke.c", smoke, include, runtime, log=log, ubsan=ubsan,
                        commands=result["commands"]),
        private_smoke(smoke, module, log, ubsan)))

    def ffi_units(log):
        command = ["cargo", "+" + args.toolchain, "test", "--locked", "--release",
                   "--target", TARGET, "-Zbuild-std", "-p", "localpin-pam", "-p", "localpin-auth",
                   "--lib", "--no-run", "--message-format=json"]
        result["commands"].append(command)
        built = subprocess.run(command, cwd=REPOSITORY, env=environment, capture_output=True,
                               text=True, check=False, timeout=600)
        log.write(built.stderr)
        if built.returncode:
            log.write(built.stdout)
            built.check_returncode()
        executables = [Path(item["executable"]) for line in built.stdout.splitlines()
                       if (item := json.loads(line)).get("reason") == "compiler-artifact"
                       and item.get("target", {}).get("name") in ("localpin_pam", "localpin_auth")
                       and item.get("profile", {}).get("test") and item.get("executable")]
        if len(executables) != 2:
            raise RuntimeError("Cargo did not identify exactly two PAM FFI unit-test binaries")
        for executable in executables:
            private_ffi_tests(executable, log)

    stage("rust-ffi-unit", ffi_units)

    def adapter(log):
        runner = load("localpin_instrumented_adapter", tests / "isolated_pam.py")
        runner.subprocess = InstrumentedProcesses(include, runtime, log, ubsan, result["commands"])
        runner.release_module = lambda _: module
        old_arguments = sys.argv
        old_include = os.environ.get("LOCALPIN_PAM_INCLUDE")
        try:
            sys.argv = [str(tests / "isolated_pam.py")]
            os.environ["LOCALPIN_PAM_INCLUDE"] = str(include)
            runner.main()
        finally:
            sys.argv = old_arguments
            if old_include is None:
                os.environ.pop("LOCALPIN_PAM_INCLUDE", None)
            else:
                os.environ["LOCALPIN_PAM_INCLUDE"] = old_include

    stage("adapter", adapter)

    def password(log):
        path = REPOSITORY / "crates/localpin-auth/tests/isolated_pam.py"
        runner = load("localpin_instrumented_password", path)
        runner.subprocess = InstrumentedProcesses(include, runtime, log, ubsan, result["commands"])
        old_arguments = sys.argv
        try:
            sys.argv = [str(path), str(worker)]
            runner.main()
        finally:
            sys.argv = old_arguments

    stage("password-worker", password)

    def source_recheck(_log):
        current = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=REPOSITORY,
                                          text=True).strip()
        if current != result["candidate"] or any(
            hashlib.sha256((REPOSITORY / path).read_bytes()).hexdigest() != digest
            for path, digest in result["tracked_production_inputs"].items()
        ):
            raise RuntimeError("Candidate source changed during instrumentation")

    stage("source-recheck", source_recheck)
    result["artifacts"] = {path.name: hashlib.sha256(path.read_bytes()).hexdigest()
                           for path in (module, worker, runtime, *([ubsan] if ubsan else []))}
    (output / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    raise SystemExit(1 if failed else 0)


if __name__ == "__main__":
    main()
