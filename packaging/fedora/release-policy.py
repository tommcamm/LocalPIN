#!/usr/bin/python3
"""Validate a main-only experimental release; never mutate refs or publish."""
import argparse
import os
from pathlib import Path
import re
import subprocess
import tomllib

ROOT = Path(__file__).resolve().parents[2]


def release_identity(version):
    """Map reviewed Cargo prereleases to ordered RPM releases, above CI builds."""
    match = re.fullmatch(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)-(alpha|beta|rc)\.([1-9][0-9]*)", version)
    if not match:
        raise ValueError("only alpha.N, beta.N or rc.N experimental versions are publishable; M9 supported-release gates remain open")
    channel, sequence = match.group(4, 5)
    stage = {"alpha": 1, "beta": 2, "rc": 3}[channel]
    return f"v{version}", f"0.{stage}.{channel}{sequence}.release"


def rpm_prefix(version):
    """Use the Cargo channel/sequence for ordinary and CI RPM identities too."""
    return release_identity(version)[1].removesuffix(".release")


def main():
    if os.environ.get("GITHUB_REF") != "refs/heads/main":
        raise SystemExit("dispatch the release workflow from main")
    commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    if commit != os.environ.get("LOCALPIN_SOURCE_COMMIT", os.environ.get("GITHUB_SHA")):
        raise SystemExit("checkout does not match the selected release commit")
    version = tomllib.loads((ROOT / "Cargo.toml").read_text())["workspace"]["package"]["version"]
    tag, rpm_release = release_identity(version)
    if subprocess.run(["git", "show-ref", "--verify", "--quiet", f"refs/tags/{tag}"], cwd=ROOT).returncode != 1:
        raise SystemExit(f"tag {tag} already exists or tag lookup failed; release assets are never replaced")
    with open(os.environ["GITHUB_OUTPUT"], "a") as output:
        output.write(f"tag={tag}\nrpm_release={rpm_release}\n")
    print(f"Experimental release {tag} from {commit}; RPM Release {rpm_release}.fc44")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rpm-prefix", action="store_true", help="print the Cargo-derived RPM prefix without publishing or checking refs")
    args = parser.parse_args()
    if args.rpm_prefix:
        version = tomllib.loads((ROOT / "Cargo.toml").read_text())["workspace"]["package"]["version"]
        print(rpm_prefix(version))
    else:
        main()
