#!/usr/bin/python3
"""Build a native project RPM without installing it or altering host policy."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import struct
import subprocess
import tarfile
import tempfile
import tomllib

ROOT = Path(__file__).resolve().parents[2]
ARTIFACTS = ("localpind", "localpin-worker", "localpin-auth-worker", "localpin-eligibility-worker", "localpin-account", "localpinctl", "liblocalpin_pam.so")


def run(argv, **kwargs):
    return subprocess.run(argv, cwd=ROOT, check=True, **kwargs)


def native_elf(path):
    header = path.read_bytes()[:64]
    if len(header) < 64 or header[:6] != b"\x7fELF\x02\x01" or struct.unpack_from("<H", header, 18)[0] != 62:
        raise RuntimeError(f"not a native x86_64 ELF release artifact: {path.name}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path, help="new build directory (normally under /tmp)")
    parser.add_argument("--native-sysroot", type=Path, help="optional unpacked native development RPM root")
    parser.add_argument("--release", default="0.1.alpha1", help="RPM release, for example 0.2.alpha1 for an upgrade fixture")
    args = parser.parse_args()
    if platform.machine() != "x86_64":
        parser.error("only native x86_64 builds are supported")
    if not args.release or any(c not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._" for c in args.release):
        parser.error("invalid RPM release")
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    env = os.environ.copy()
    if args.native_sysroot:
        lib = args.native_sysroot.resolve() / "usr/lib64"
        if not (lib / "pkgconfig/tss2-esys.pc").is_file():
            parser.error("native sysroot has no TPM2-TSS development pkgconfig inputs")
        env["PKG_CONFIG_PATH"] = str(lib / "pkgconfig") + os.pathsep + env.get("PKG_CONFIG_PATH", "")
        env["LIBRARY_PATH"] = str(lib) + os.pathsep + env.get("LIBRARY_PATH", "")
    cargo_target = output / "cargo"
    run(["cargo", "build", "--release", "--workspace", "--locked", "--offline", "--target-dir", str(cargo_target)], env=env)
    version = tomllib.loads((ROOT / "Cargo.toml").read_text())["workspace"]["package"]["version"]
    rpm_version = version.split("-")[0]
    for name in ("BUILD", "RPMS", "SOURCES", "SPECS", "SRPMS", "TMP"):
        (output / name).mkdir()
    with tempfile.TemporaryDirectory(prefix="bundle-", dir=output) as temporary:
        bundle = Path(temporary) / f"localpin-{rpm_version}-native"
        (bundle / "native").mkdir(parents=True)
        for name in ARTIFACTS:
            artifact = cargo_target / "release" / name
            native_elf(artifact)
            shutil.copy2(artifact, bundle / "native" / name)
        for directory in ("crates", "packaging", "docs"):
            shutil.copytree(ROOT / directory, bundle / directory, ignore=shutil.ignore_patterns("__pycache__"))
        (bundle / "tools").mkdir()
        shutil.copy2(ROOT / "tools/localpin-integration.py", bundle / "tools/localpin-integration.py")
        for name in ("LICENSE-APACHE", "LICENSE-MIT", "Cargo.toml", "Cargo.lock", "rust-toolchain.toml"):
            shutil.copy2(ROOT / name, bundle / name)
        inputs = {
            "schema": 1,
            "project_version": version,
            "architecture": platform.machine(),
            "rustc": run(["rustc", "--version"], capture_output=True, text=True).stdout.strip(),
            "cargo_lock_sha256": hashlib.sha256((ROOT / "Cargo.lock").read_bytes()).hexdigest(),
            "native_artifact_sha256": {name: hashlib.sha256((bundle / "native" / name).read_bytes()).hexdigest() for name in ARTIFACTS},
            "native_rpm_inputs": run(["rpm", "-q", "pam", "dbus-libs", "tpm2-tss", "systemd", "selinux-policy-targeted"], capture_output=True, text=True).stdout.splitlines(),
            "build_command": "cargo build --release --workspace --locked --offline",
            "signed": False,
        }
        (bundle / "BUILD-INPUTS.json").write_text(json.dumps(inputs, indent=2) + "\n")
        source = output / "SOURCES" / f"localpin-{rpm_version}-native.tar.gz"
        with tarfile.open(source, "w:gz") as archive:
            archive.add(bundle, arcname=bundle.name)
    spec = (ROOT / "packaging/fedora/localpin.spec").read_text()
    spec = spec.replace("Release:        0.1.alpha1%{?dist}", f"Release:        {args.release}%{{?dist}}")
    spec_path = output / "SPECS/localpin.spec"
    spec_path.write_text(spec)
    # Build-requires are checked by rpmbuild. No --nodeps, mock root, package
    # installation, policy load, service start or authentication edit occurs.
    run(["rpmbuild", "-bb", "--define", f"_topdir {output}", "--define", f"_tmppath {output / 'TMP'}", str(spec_path)], env=env)
    packages = sorted((output / "RPMS").rglob("*.rpm"))
    for package in packages:
        print(package)


if __name__ == "__main__":
    main()
