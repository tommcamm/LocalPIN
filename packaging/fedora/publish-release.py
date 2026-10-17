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


def require_signing_fingerprint(data):
    signing = data.get("signing", {})
    if signing.get("signed") is not True:
        raise ValueError("experimental release publication requires a signed RPM")
    fingerprint = signing.get("fingerprint") or ""
    if not re.fullmatch(r"(?:[0-9A-F]{40}|[0-9A-F]{64})", fingerprint):
        raise ValueError("signed release requires a full signing fingerprint")
    return fingerprint


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
    require_signing_fingerprint(data)
    required = {rpm_name, source, "BUILD-INPUTS.json", "NATIVE-RPMS.json", "SBOM.spdx.json", "RELEASE.json", "RELEASE-NOTES.md", "RPM-GPG-KEY-LocalPIN"}
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
    if {p.name for p in assets} != checked | {"SHA256SUMS", "SHA256SUMS.asc"}:
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
    fingerprint = require_signing_fingerprint(data)
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
            if fingerprints != [fingerprint]:
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
            error.close()
            return None
        try:
            message = json.loads(error.read(4096)).get("message", "")
        except (ValueError, AttributeError):
            message = ""
        finally:
            error.close()
        if not isinstance(message, str):
            message = ""
        token = os.environ.get("GH_TOKEN")
        if token:
            message = message.replace(token, "[redacted]")
        message = re.sub(r"[\x00-\x1f\x7f]", " ", message)[:512]
        detail = f": {message}" if message else ""
        hint = " Check the release job's contents: write permission and repository tag/workflow rules." if error.code == 403 else ""
        raise RuntimeError(f"GitHub API {path} failed: HTTP {error.code}{detail}.{hint}") from None


def verify_github_release(directory, tag, assets, *, draft):
    result = subprocess.run(["gh", "release", "view", tag, "--repo", os.environ["GITHUB_REPOSITORY"],
                             "--json", "tagName,name,body,isDraft,isPrerelease,assets,url"],
                            check=True, capture_output=True, text=True)
    release = json.loads(result.stdout)
    expected_notes = (directory / "RELEASE-NOTES.md").read_text().replace("\r\n", "\n").strip()
    actual_notes = (release.get("body") or "").replace("\r\n", "\n").strip()
    expected_assets = {path.name for path in assets}
    actual_assets = [asset.get("name") for asset in release.get("assets", [])]
    if (release.get("tagName") != tag or release.get("name") != f"LocalPIN {tag} (experimental)"
            or release.get("isDraft") is not draft or release.get("isPrerelease") is not True
            or not expected_notes or actual_notes != expected_notes
            or len(actual_assets) != len(expected_assets) or set(actual_assets) != expected_assets):
        raise ValueError("GitHub release state, description or uploaded assets do not match the verified bundle")
    expected_url = f'{os.environ.get("GITHUB_SERVER_URL", "https://github.com")}/{os.environ["GITHUB_REPOSITORY"]}/releases/tag/{tag}'
    if not draft and release.get("url") != expected_url:
        raise ValueError("published GitHub release URL differs from the repository's release page")
    return expected_url


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
    verify_github_release(directory, tag, assets, draft=True)
    subprocess.run(["gh", "release", "edit", tag, "--repo", os.environ["GITHUB_REPOSITORY"], "--draft=false", "--prerelease", "--latest=false"], check=True)
    url = verify_github_release(directory, tag, assets, draft=False)
    print(f"Published experimental release: {url}")
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a") as summary:
            summary.write(f"## Experimental release published\n\n[View {tag} on GitHub Releases]({url})\n\nVerified RPM/checksum signatures, release description and all {len(assets)} assets.\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--commit", required=True)
    args = parser.parse_args()
    publish(args.directory.resolve(), args.tag, args.commit)
