#!/usr/bin/python3
"""Publish a complete experimental bundle without replacing any tag or asset."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import urllib.error
import urllib.request


def verify_bundle(directory, tag, commit):
    data = json.loads((directory / "RELEASE.json").read_text())
    if data["tag"] != tag or data["source_commit"] != commit:
        raise ValueError("release manifest does not match the requested tag and source")
    spec = importlib.util.spec_from_file_location("release_policy", Path(__file__).with_name("release-policy.py"))
    policy = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(policy)
    expected_tag, expected_release = policy.release_identity(tag.removeprefix("v"))
    if expected_tag != tag:
        raise ValueError("invalid experimental tag")
    version = tag.removeprefix("v")
    rpm = data.get("rpm", {})
    rpm_name = f"localpin-{version.split('-')[0]}-{expected_release}.fc44.x86_64.rpm"
    source = f"localpin-{version}-source.tar.gz"
    if (data.get("schema") != 1 or data.get("experimental") is not True or data.get("project_version") != version
            or data.get("target") != "Fedora KDE 44 x86_64" or data.get("source_archive") != source
            or rpm.get("filename") != rpm_name or rpm.get("version") != version.split("-")[0]
            or rpm.get("release") != expected_release + ".fc44"):
        raise ValueError("release schema, target, version or RPM identity is inconsistent")
    required = {rpm_name, source, "BUILD-INPUTS.json", "NATIVE-RPMS.json", "SBOM.spdx.json", "RELEASE.json", "RELEASE-NOTES.md"}
    signing = data.get("signing", {})
    if signing.get("signed") is True:
        if not re.fullmatch(r"(?:[0-9A-F]{40}|[0-9A-F]{64})", signing.get("fingerprint") or ""):
            raise ValueError("signed release requires a full signing fingerprint")
        required.add("RPM-GPG-KEY-LocalPIN")
    elif signing.get("signed") is not False or signing.get("fingerprint") is not None:
        raise ValueError("invalid signing status")
    checked = set()
    for line in (directory / "SHA256SUMS").read_text().splitlines():
        digest, name = line.split("  ", 1)
        if not re.fullmatch(r"[0-9a-f]{64}", digest) or Path(name).name != name or name in checked:
            raise ValueError("invalid checksum entry")
        path = directory / name
        if path.is_symlink() or not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            raise ValueError(f"release asset checksum mismatch: {name}")
        checked.add(name)
    if checked != required:
        raise ValueError("release bundle has missing or unexpected assets")
    assets = sorted(directory.iterdir())
    if {p.name for p in assets} != checked | {"SHA256SUMS"} | ({"SHA256SUMS.asc"} if data["signing"]["signed"] else set()):
        raise ValueError("release directory contains missing or unchecked assets")
    if any(p.is_symlink() or not p.is_file() for p in assets):
        raise ValueError("release assets must be regular files")
    rpm_digest = hashlib.sha256((directory / rpm_name).read_bytes()).hexdigest()
    if rpm.get("sha256") != rpm_digest:
        raise ValueError("manifest RPM digest mismatch")
    inputs = json.loads((directory / "BUILD-INPUTS.json").read_text())
    sbom = json.loads((directory / "SBOM.spdx.json").read_text())
    artifacts = [p for p in sbom.get("packages", []) if p.get("SPDXID") == "SPDXRef-LocalPIN-RPM"]
    if (inputs.get("project_version") != version or inputs.get("signed") is not False
            or inputs.get("architecture") != "x86_64" or sbom.get("spdxVersion") != "SPDX-2.3"
            or len(artifacts) != 1 or artifacts[0].get("packageFileName") != rpm_name
            or artifacts[0].get("checksums") != [{"algorithm": "SHA256", "checksumValue": rpm_digest}]):
        raise ValueError("build manifest or SBOM does not match release")
    return assets


def verify_native_assets(directory):
    """Recheck final package/signatures in isolated public key databases."""
    data = json.loads((directory / "RELEASE.json").read_text())
    rpm = directory / data["rpm"]["filename"]
    env = {**os.environ, "LC_ALL": "C"}
    with tempfile.TemporaryDirectory(prefix="localpin-publish-verify-") as temporary:
        env["GNUPGHOME"] = temporary
        def run(argv):
            return subprocess.run(argv, env=env, check=True, capture_output=True, text=True).stdout
        try:
            actual = run(["rpm", "-qp", "--queryformat", "%{NAME}\\t%{VERSION}\\t%{RELEASE}\\t%{ARCH}", str(rpm)])
            if actual != f'localpin\t{data["rpm"]["version"]}\t{data["rpm"]["release"]}\tx86_64':
                raise ValueError("package header differs from release manifest")
            if not data["signing"]["signed"]:
                run(["rpmkeys", "--checksig", "--nosignature", str(rpm)])
                return
            public = directory / "RPM-GPG-KEY-LocalPIN"
            run(["gpg", "--batch", "--import", str(public)])
            listing = run(["gpg", "--batch", "--with-colons", "--list-keys", "--fingerprint"])
            fingerprints = []
            primary = False
            for line in listing.splitlines():
                fields = line.split(":")
                if fields[0] in ("pub", "sub"):
                    primary = fields[0] == "pub"
                elif fields[0] == "fpr" and primary:
                    fingerprints.append(fields[9])
                    primary = False
            if fingerprints != [data["signing"]["fingerprint"]]:
                raise ValueError("release public key differs from signing fingerprint")
            run(["gpg", "--batch", "--verify", str(directory / "SHA256SUMS.asc"), str(directory / "SHA256SUMS")])
            database = str(Path(temporary) / "rpmdb")
            run(["rpm", "--dbpath", database, "--initdb"])
            run(["rpmkeys", "--dbpath", database, "--import", str(public)])
            run(["rpmkeys", "--dbpath", database, "--define", "_pkgverify_level signature", "--checksig", str(rpm)])
        finally:
            subprocess.run(["gpgconf", "--kill", "gpg-agent"], env=env, capture_output=True, check=False)


def api(path, payload=None, missing_ok=False):
    request = urllib.request.Request(
        os.environ.get("GITHUB_API_URL", "https://api.github.com") + "/repos/" + os.environ["GITHUB_REPOSITORY"] + "/" + path,
        data=json.dumps(payload).encode() if payload is not None else None,
        headers={"Authorization": "Bearer " + os.environ["GH_TOKEN"], "Accept": "application/vnd.github+json",
                 "Content-Type": "application/json", "X-GitHub-Api-Version": "2022-11-28"},
    )
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            return json.load(response)
    except urllib.error.HTTPError as error:
        if missing_ok and error.code == 404:
            return None
        raise RuntimeError(f"GitHub API {path} failed: HTTP {error.code}") from None


def publish(directory, tag, commit):
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ValueError("full source commit required")
    if os.environ.get("GITHUB_REF") != "refs/heads/main" or commit != os.environ.get("GITHUB_SHA"):
        raise ValueError("publication requires the dispatched main commit")
    assets = verify_bundle(directory, tag, commit)
    verify_native_assets(directory)
    if api(f"git/ref/tags/{tag}", missing_ok=True) is not None or api(f"releases/tags/{tag}", missing_ok=True) is not None:
        raise ValueError("tag or release already exists; refusing to overwrite published history")
    if api(f"compare/{commit}...main")["status"] not in ("ahead", "identical"):
        raise ValueError("source commit is no longer on main")
    annotation = api("git/tags", {"tag": tag, "message": f"LocalPIN {tag} experimental Fedora KDE 44 prerelease", "object": commit, "type": "commit"})
    api("git/refs", {"ref": f"refs/tags/{tag}", "sha": annotation["sha"]})
    # gh uploads to a draft before publishing; any upload failure leaves a draft.
    subprocess.run(["gh", "release", "create", tag, *map(str, assets), "--repo", os.environ["GITHUB_REPOSITORY"],
                    "--verify-tag", "--draft", "--prerelease", "--latest=false", "--title", f"LocalPIN {tag} (experimental)",
                    "--notes-file", str(directory / "RELEASE-NOTES.md")], check=True)
    subprocess.run(["gh", "release", "edit", tag, "--repo", os.environ["GITHUB_REPOSITORY"], "--draft=false", "--prerelease", "--latest=false"], check=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--commit", required=True)
    args = parser.parse_args()
    publish(args.directory.resolve(), args.tag, args.commit)
