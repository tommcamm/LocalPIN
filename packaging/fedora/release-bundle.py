#!/usr/bin/python3
"""Assemble a traceable experimental release; never sign, install or publish."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
import tomllib
from urllib.parse import quote, urljoin

ROOT = Path(__file__).resolve().parents[2]
TARGET = "x86_64-unknown-linux-gnu"
VERSION = re.compile(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)-(alpha|beta|rc)\.([1-9][0-9]*)")
RPM_FORMAT = "%{NAME}\t%{EPOCHNUM}\t%{VERSION}\t%{RELEASE}\t%{ARCH}\t%{LICENSE}\n"


def run(argv, **kwargs):
    if argv[0] == "git":
        argv = ["git", "-c", f"safe.directory={ROOT}", *argv[1:]]
    return subprocess.run(argv, cwd=ROOT, check=True, text=True, capture_output=True, **kwargs).stdout.rstrip("\n")


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def changelog_summary(text, version, source_url):
    """Select a few committed changes without copying the historical changelog."""
    sections = [section.partition("\n") for section in re.split(r"(?m)^## +", text)[1:]]
    escaped_version = re.escape(version)
    version_heading = re.compile(rf"(?:v?{escaped_version}|\[v?{escaped_version}\])(?:\s+-\s+.*)?")
    released = [body for heading, _, body in sections if version_heading.fullmatch(heading.strip())]
    unreleased = [body for heading, _, body in sections if heading.strip() in ("Unreleased", "[Unreleased]")]
    selected = released or unreleased
    if len(selected) != 1:
        raise ValueError("Changelog must have one release version or Unreleased section")
    entries = []
    current = None
    for line in selected[0].splitlines():
        if line.startswith("- "):
            current = [line.rstrip()]
            entries.append(current)
        elif line.startswith((" ", "\t")) and current is not None:
            current.append(line.rstrip())
        elif line.strip():
            current = None
    if not entries:
        raise ValueError("Release changelog section must contain change bullets")
    summary = "\n".join("\n".join(entry) for entry in entries[:3])
    # Relative repository links otherwise resolve against the GitHub release URL.
    return re.sub(r"(\[[^\]]+\]\()([^\s)]+)(\))",
                  lambda match: match[1] + urljoin(source_url + "/CHANGELOG.md", match[2]) + match[3], summary)


def release_notes(version, commit, rpm_name, archive_name, workflow_url):
    source = f"https://github.com/tommcamm/LocalPIN/blob/{commit}"
    changes = changelog_summary((ROOT / "CHANGELOG.md").read_text(), version, source)
    return f"""LocalPIN {version} is an **experimental Fedora KDE 44 x86_64 prerelease**.

LocalPIN adds opt-in six-digit PIN unlocking to an existing KDE graphical session,
with the account password available for unlocking and recovery. It includes
enrollment and PIN changes, durable attempt limits, protected storage, TPM 2.0 or
explicitly selected Argon2id software credentials, and SELinux confinement.

There is no supported production release. Independent security review, physical
hardware validation and the remaining [M9 acceptance gates]({source}/docs/development/m9-release-readiness.md)
are open. CI checks do not complete those gates.

### Selected changes

{changes}

See the [complete changelog]({source}/CHANGELOG.md) for this source snapshot.

### Downloads

- **`{rpm_name}`**: the signed installable Fedora 44 x86_64 package.
- **`SHA256SUMS`**: the SHA256 checksum of that RPM.

Every published experimental release requires a verified embedded RPM signature.
Download the [public signing key](https://raw.githubusercontent.com/tommcamm/LocalPIN/{commit}/packaging/fedora/RPM-GPG-KEY-LocalPIN),
compare its fingerprint with a separately trusted maintainer fingerprint, then
follow the [signature and checksum verification steps]({source}/docs/releasing.md#verify-and-test-a-download)
before installation. The public checksum file detects changed downloads; the RPM
signature authenticates the package.

### Build evidence

The [workflow run]({workflow_url}) retains a `release-evidence-*` artifact for 90 days
with the full signed bundle: `{archive_name}`, source/build provenance in
`RELEASE.json` and `BUILD-INPUTS.json`, `SBOM.spdx.json`, the builder inventory
`NATIVE-RPMS.json`, the public key, release notes, and a separate full-bundle
`SHA256SUMS` with its detached `SHA256SUMS.asc` signature. The artifact's checksum
file covers the full evidence bundle; the release download covers only the RPM.
The SBOM includes development tools and is not a minimal runtime closure or
independent license review. Rebuilding needs Rust dependencies and native build tools.

### Installation and current limits

Start in a disposable Fedora KDE VM with SELinux enforcing. Installing the RPM
starts no broker and leaves PIN integration disabled. Follow the
[installation and recovery runbook]({source}/docs/integration-administration.md)
for persistent native faillock setup, enrollment, a timed trial, password fallback,
console recovery and explicit activation.

Local, non-root accounts and reviewed authselect/PAM layouts are required. Custom
policies and systemd-homed are outside the current target. Physical TPMs,
fingerprint devices, AccountsService GUI/DBus administration, alternate filesystem
durability and the full hardware matrix remain unvalidated. The
[M8.1 report]({source}/docs/development/m8.1-desktop-compatibility.md)
records the narrower installed-VM evidence and its limits.

Source: [`{commit}`](https://github.com/tommcamm/LocalPIN/commit/{commit}). Build and validation: [workflow run]({workflow_url}).
"""


def rpm_inventory(text):
    packages = []
    for line in text.splitlines():
        fields = line.split("\t")
        if len(fields) != 6 or any(not field for field in fields):
            raise ValueError("Malformed RPM inventory")
        name, epoch, version, release, arch, license_value = fields
        if not epoch.isdigit() or any("/" in value or "\x00" in value for value in fields[:5]) or "\x00" in license_value:
            raise ValueError("Invalid RPM identity")
        packages.append(dict(name=name, epoch=int(epoch), version=version, release=release,
                             architecture=arch, license=license_value))
    if not packages:
        raise ValueError("Empty RPM inventory")
    identities = [(p["name"], p["epoch"], p["version"], p["release"], p["architecture"]) for p in packages]
    if len(set(identities)) != len(identities):
        raise ValueError("Duplicate RPM identity")
    return sorted(packages, key=lambda p: (p["name"], p["architecture"], p["version"], p["release"]))


def nevra(package):
    return f'{package["name"]}-{package["version"]}-{package["release"]}.{package["architecture"]}'


def spdx(metadata, lock, native, runtime_inputs, *, version, commit, created, rpm_name, rpm_sha256):
    """Describe Cargo's resolved default-feature target graph and builder RPMs."""
    resolve = metadata.get("resolve")
    if not isinstance(resolve, dict) or not isinstance(resolve.get("nodes"), list):
        raise ValueError("Cargo metadata has no resolved dependency graph")
    packages = metadata.get("packages", [])
    by_id = {p["id"]: p for p in packages}
    nodes = {n["id"]: n for n in resolve["nodes"]}
    if len(by_id) != len(packages) or len(nodes) != len(resolve["nodes"]):
        raise ValueError("Duplicate Cargo package or graph node")
    roots = metadata.get("workspace_members", [])
    if not roots or any(root not in nodes or root not in by_id for root in roots):
        raise ValueError("Cargo workspace member missing from dependency graph")
    reached = set()
    pending = list(roots)
    edges = set()
    while pending:
        package_id = pending.pop()
        if package_id in reached:
            continue
        if package_id not in by_id or package_id not in nodes:
            raise ValueError("Unresolved Cargo dependency")
        reached.add(package_id)
        # Cargo's deps field records renaming and dependency kinds; dependencies
        # is retained for compatibility with older metadata producers.
        node = nodes[package_id]
        dependencies = [d["pkg"] for d in node["deps"]] if "deps" in node else node.get("dependencies", [])
        for dependency in dependencies:
            edges.add((package_id, dependency))
            pending.append(dependency)
    lock_packages = {(p["name"], p["version"], p.get("source")): p for p in lock.get("package", [])}
    result = [{"SPDXID": "SPDXRef-LocalPIN-RPM", "name": "localpin", "versionInfo": version,
               "downloadLocation": "NOASSERTION", "filesAnalyzed": False,
               "licenseConcluded": "NOASSERTION", "licenseDeclared": "MIT OR Apache-2.0",
               "checksums": [{"algorithm": "SHA256", "checksumValue": rpm_sha256}],
               "packageFileName": rpm_name}]
    relationships = [{"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES",
                      "relatedSpdxElement": "SPDXRef-LocalPIN-RPM"}]
    identifiers = {package_id: f"SPDXRef-Cargo-{index}" for index, package_id in enumerate(sorted(reached))}
    for package_id in sorted(reached):
        package = by_id[package_id]
        name, package_version, source = package["name"], package["version"], package.get("source")
        pinned = lock_packages.get((name, package_version, source))
        if pinned is None:
            raise ValueError(f"Cargo package missing from lockfile: {name} {package_version}")
        registry = source and source.startswith("registry+")
        checksum = pinned.get("checksum")
        if registry and not re.fullmatch(r"[a-f0-9]{64}", checksum or ""):
            raise ValueError(f"Registry package has no locked checksum: {name}")
        item = {"SPDXID": identifiers[package_id], "name": name, "versionInfo": package_version,
                "downloadLocation": f"https://crates.io/api/v1/crates/{quote(name)}/{quote(package_version)}/download" if registry and "crates.io" in source else "NOASSERTION",
                "filesAnalyzed": False, "licenseConcluded": "NOASSERTION",
                "licenseDeclared": package.get("license") or "NOASSERTION",
                "externalRefs": [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl",
                                  "referenceLocator": f"pkg:cargo/{quote(name)}@{quote(package_version)}"}],
                "comment": "Resolved for the default-feature Fedora release build; development-only graph edges may also be present."}
        if checksum:
            item["checksums"] = [{"algorithm": "SHA256", "checksumValue": checksum}]
        result.append(item)
    for root in roots:
        relationships.append({"spdxElementId": "SPDXRef-LocalPIN-RPM", "relationshipType": "CONTAINS", "relatedSpdxElement": identifiers[root]})
    for left, right in sorted(edges):
        relationships.append({"spdxElementId": identifiers[left], "relationshipType": "DEPENDS_ON", "relatedSpdxElement": identifiers[right]})
    native_names = {nevra(package) for package in native}
    if not runtime_inputs or not set(runtime_inputs) <= native_names:
        raise ValueError("Native runtime build inputs do not match installed RPM inventory")
    for index, package in enumerate(native):
        identifier = f"SPDXRef-RPM-{index}"
        evr = f'{package["epoch"]}:{package["version"]}-{package["release"]}'
        result.append({"SPDXID": identifier, "name": package["name"], "versionInfo": evr,
                       "downloadLocation": "NOASSERTION", "filesAnalyzed": False,
                       "licenseConcluded": "NOASSERTION", "licenseDeclared": "NOASSERTION",
                       "externalRefs": [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl",
                                         "referenceLocator": f'pkg:rpm/fedora/{quote(package["name"])}@{quote(evr, safe="")}?arch={quote(package["architecture"])}'}],
                       "comment": f'Installed in the disposable build environment. RPM license field: {package["license"]}'} )
        relationships.append({"spdxElementId": identifier, "relationshipType": "BUILD_DEPENDENCY_OF", "relatedSpdxElement": "SPDXRef-LocalPIN-RPM"})
        if nevra(package) in runtime_inputs:
            relationships.append({"spdxElementId": "SPDXRef-LocalPIN-RPM", "relationshipType": "DEPENDS_ON", "relatedSpdxElement": identifier})
    return {"spdxVersion": "SPDX-2.3", "dataLicense": "CC0-1.0", "SPDXID": "SPDXRef-DOCUMENT",
            "name": f"LocalPIN {version} Fedora 44 release inputs",
            "documentNamespace": f"https://github.com/tommcamm/LocalPIN/sbom/{commit}/{rpm_sha256}",
            "creationInfo": {"created": created, "creators": ["Tool: LocalPIN release-bundle.py"]},
            "documentComment": "Cargo target dependency graph and complete installed builder RPM inventory; not a claim of a minimal binary dependency closure or independent license review.",
            "packages": result, "relationships": relationships}


def finalize(output):
    """Refresh the final RPM digest and checksums after RPM signing."""
    output = Path(output)
    files = list(output.iterdir())
    if any(path.is_symlink() or not path.is_file() for path in files):
        raise ValueError("Release bundle must contain only regular files")
    manifest_path = output / "RELEASE.json"
    manifest = json.loads(manifest_path.read_text())
    rpm = output / manifest["rpm"]["filename"]
    if rpm.parent != output or rpm.suffix != ".rpm" or not rpm.is_file():
        raise ValueError("Invalid release RPM filename")
    manifest["rpm"]["sha256"] = digest(rpm)
    write_json(manifest_path, manifest)
    sbom_path = output / "SBOM.spdx.json"
    sbom = json.loads(sbom_path.read_text())
    artifacts = [package for package in sbom["packages"] if package["SPDXID"] == "SPDXRef-LocalPIN-RPM"]
    if len(artifacts) != 1:
        raise ValueError("SBOM has no unique release RPM")
    artifacts[0]["checksums"] = [{"algorithm": "SHA256", "checksumValue": digest(rpm)}]
    # A signed RPM has a different digest, and therefore a distinct SBOM identity.
    sbom["documentNamespace"] = f'https://github.com/tommcamm/LocalPIN/sbom/{manifest["source_commit"]}/{digest(rpm)}'
    write_json(sbom_path, sbom)
    paths = sorted(path for path in output.iterdir() if path.name not in ("SHA256SUMS", "SHA256SUMS.asc"))
    (output / "SHA256SUMS").write_text("".join(f"{digest(path)}  {path.name}\n" for path in paths))


def create(build, output, tag, commit):
    build, output = Path(build).resolve(), Path(output).resolve()
    version = tomllib.loads((ROOT / "Cargo.toml").read_text())["workspace"]["package"]["version"]
    if not VERSION.fullmatch(version) or tag != f"v{version}":
        raise ValueError("Release tag must match the Cargo alpha.N, beta.N or rc.N prerelease version")
    if not re.fullmatch(r"[a-f0-9]{40}|[a-f0-9]{64}", commit) or run(["git", "rev-parse", "HEAD"]) != commit:
        raise ValueError("Release commit must exactly match checked-out HEAD")
    if run(["git", "status", "--porcelain", "--untracked-files=all"]):
        raise ValueError("Release source must be clean, including untracked files")
    tag_ref = subprocess.run(["git", "-c", f"safe.directory={ROOT}", "show-ref", "--verify", "--quiet", f"refs/tags/{tag}"], cwd=ROOT)
    if tag_ref.returncode not in (0, 1):
        raise ValueError("Could not inspect release tag")
    if tag_ref.returncode == 0 and run(["git", "rev-parse", f"refs/tags/{tag}^{{commit}}"]) != commit:
        raise ValueError("Existing release tag points at a different commit")
    if output == ROOT or ROOT in output.parents:
        raise ValueError("Release output must be outside the checked-out source")
    rpms = sorted((build / "RPMS").rglob("*.rpm"))
    sources = sorted((build / "SOURCES").glob("*-native.tar.gz"))
    if len(rpms) != 1 or len(sources) != 1:
        raise ValueError("Expected one RPM and one native build-input archive")
    package = rpm_inventory(run(["rpm", "-qp", "--queryformat", RPM_FORMAT, str(rpms[0])]))
    if len(package) != 1 or package[0]["name"] != "localpin" or package[0]["version"] != version.split("-")[0] or package[0]["architecture"] != "x86_64":
        raise ValueError("RPM name, version or architecture does not match release")
    run(["rpmkeys", "--checksig", "--nosignature", str(rpms[0])])
    with tarfile.open(sources[0], "r:gz") as archive:
        prefix = sources[0].name.removesuffix(".tar.gz")
        member = archive.getmember(prefix + "/BUILD-INPUTS.json")
        if not member.isfile() or member.size > 1024 * 1024:
            raise ValueError("Invalid build-input manifest")
        inputs_bytes = archive.extractfile(member).read()
        inputs = json.loads(inputs_bytes)
        if inputs.get("schema") != 1 or inputs.get("project_version") != version or inputs.get("architecture") != "x86_64" or inputs.get("signed") is not False:
            raise ValueError("Build-input manifest does not match release")
        if inputs.get("cargo_lock_sha256") != digest(ROOT / "Cargo.lock"):
            raise ValueError("Build-input lockfile digest does not match source")
        hashes = inputs.get("native_artifact_sha256")
        expected = {"localpind", "localpin-worker", "localpin-auth-worker", "localpin-eligibility-worker", "localpin-account", "localpinctl", "liblocalpin_pam.so"}
        if not isinstance(hashes, dict) or set(hashes) != expected:
            raise ValueError("Native artifact manifest is incomplete")
        for name, expected_hash in hashes.items():
            member = archive.getmember(prefix + "/native/" + name)
            if not member.isfile() or member.size > 256 * 1024 * 1024:
                raise ValueError("Invalid native build artifact")
            with archive.extractfile(member) as stream:
                actual_hash = hashlib.file_digest(stream, "sha256").hexdigest()
            if actual_hash != expected_hash:
                raise ValueError("Native artifact digest mismatch")
    if run(["rpm", "-qp", "--queryformat", "%{FILEDIGESTALGO}", str(rpms[0])]) != "8":
        raise ValueError("Release RPM must use SHA256 file digests")
    rpm_files = dict(line.split("\t", 1) for line in run([
        "rpm", "-qp", "--queryformat", "[%{FILENAMES}\\t%{FILEDIGESTS}\\n]", str(rpms[0])]).splitlines())
    paths = {name: f"/usr/libexec/localpin/{name}" for name in hashes}
    paths["localpinctl"] = "/usr/bin/localpinctl"
    paths["liblocalpin_pam.so"] = "/usr/lib64/security/pam_localpin.so"
    if any(rpm_files.get(paths[name]) != value for name, value in hashes.items()):
        raise ValueError("RPM native files differ from the build-input manifest")
    manifests = [value for path, value in rpm_files.items() if path.endswith("/BUILD-INPUTS.json")]
    if manifests != [hashlib.sha256(inputs_bytes).hexdigest()]:
        raise ValueError("RPM embedded build-input manifest differs from the build archive")
    metadata = json.loads(run(["cargo", "metadata", "--format-version", "1", "--locked", "--offline", "--filter-platform", TARGET]))
    native = rpm_inventory(run(["rpm", "-qa", "--queryformat", RPM_FORMAT]))
    timestamp = int(run(["git", "show", "-s", "--format=%ct", commit]))
    created = datetime.fromtimestamp(timestamp, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    sbom = spdx(metadata, tomllib.loads((ROOT / "Cargo.lock").read_text()), native,
                inputs.get("native_rpm_inputs"), version=version, commit=commit,
                created=created, rpm_name=rpms[0].name, rpm_sha256=digest(rpms[0]))
    archive_name = f"localpin-{version}-source.tar.gz"
    workflow_url = f'{os.environ.get("GITHUB_SERVER_URL", "https://github.com")}/{os.environ.get("GITHUB_REPOSITORY", "tommcamm/LocalPIN")}/actions/runs/{os.environ.get("GITHUB_RUN_ID", "local")}'
    notes = release_notes(version, commit, rpms[0].name, archive_name, workflow_url)
    output.mkdir(parents=True, exist_ok=False)
    shutil.copy2(rpms[0], output / rpms[0].name)
    (output / "BUILD-INPUTS.json").write_bytes(inputs_bytes)
    run(["git", "archive", "--format=tar.gz", f"--prefix=localpin-{version}/", f"--output={output / archive_name}", commit])
    write_json(output / "NATIVE-RPMS.json", {"scope": "complete installed disposable build environment", "packages": native})
    write_json(output / "SBOM.spdx.json", sbom)
    write_json(output / "RELEASE.json", {"schema": 1, "experimental": True, "tag": tag,
               "project_version": version, "source_commit": commit, "source_archive": archive_name,
               "target": "Fedora KDE 44 x86_64", "cargo_target": TARGET,
               "cargo_features": "workspace default features", "build_inputs_signed": False,
               "workflow_run_url": workflow_url,
               "rpm": {"filename": rpms[0].name, "version": package[0]["version"], "release": package[0]["release"], "sha256": digest(rpms[0])},
               "signing": {"signed": False, "fingerprint": None}})
    (output / "RELEASE-NOTES.md").write_text(notes)
    finalize(output)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-dir", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--tag")
    parser.add_argument("--commit")
    parser.add_argument("--finalize", type=Path, help="refresh manifest RPM digest, SBOM digest and final checksums after signing")
    args = parser.parse_args()
    if args.finalize:
        if any((args.build_dir, args.output, args.tag, args.commit)):
            parser.error("--finalize cannot be combined with bundle creation arguments")
        finalize(args.finalize.resolve())
    else:
        if not all((args.build_dir, args.output, args.tag, args.commit)):
            parser.error("--build-dir, --output, --tag and --commit are required")
        create(args.build_dir, args.output, args.tag, args.commit)


if __name__ == "__main__":
    main()
