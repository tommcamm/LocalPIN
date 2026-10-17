#!/usr/bin/python3
"""Synthetic release provenance/SBOM checks; no package installation or Git writes."""
import copy
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location("release_bundle", Path(__file__).with_name("release-bundle.py"))
bundle = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(bundle)
COMMIT = "a" * 40
SOURCE = "registry+https://github.com/rust-lang/crates.io-index"
NATIVE_TEXT = "pam\t0\t1.7.2\t1.fc44\tx86_64\tBSD-3-Clause\n"


def metadata():
    return {"workspace_members": ["root"],
            "packages": [{"id": "root", "name": "localpin-core", "version": "0.1.0-alpha.1", "source": None, "license": "MIT OR Apache-2.0"},
                         {"id": "dep", "name": "zeroize", "version": "1.9.1", "source": SOURCE, "license": "Apache-2.0 OR MIT"}],
            "resolve": {"nodes": [{"id": "root", "deps": [{"name": "renamed", "pkg": "dep", "dep_kinds": [{"kind": None, "target": None}]}]},
                                  {"id": "dep", "deps": []}]}}


def lock():
    return {"package": [{"name": "localpin-core", "version": "0.1.0-alpha.1"},
                        {"name": "zeroize", "version": "1.9.1", "source": SOURCE, "checksum": "b" * 64}]}


class ReleaseNotesTests(unittest.TestCase):
    def test_versioned_changes_take_precedence_over_unreleased_and_history(self):
        changelog = """# Changelog
## Unreleased
- Future work.
## [0.1.0-alpha.1] - 2026-10-17
### Added
- This release's change.
## 0.1.0-alpha.0
- Historical work.
"""
        summary = bundle.changelog_summary(changelog, "0.1.0-alpha.1", "https://example.invalid/blob/commit")
        self.assertEqual(summary, "- This release's change.")

    def test_unreleased_summary_is_bounded_and_links_use_committed_source(self):
        changelog = """# Changelog
## Unreleased
### Added
- First change with [instructions](docs/releasing.md).
  Continuation with an [external link](https://example.invalid/reference).
- Second change with an [anchor](#changed).

### Changed
- Third change.
- Fourth change.
## 0.0.1
- Historical work.
"""
        source = f"https://github.com/tommcamm/LocalPIN/blob/{COMMIT}"
        summary = bundle.changelog_summary(changelog, "0.1.0-alpha.1", source)
        self.assertIn(f"[instructions]({source}/docs/releasing.md)", summary)
        self.assertIn("  Continuation with an [external link](https://example.invalid/reference).", summary)
        self.assertIn(f"[anchor]({source}/CHANGELOG.md#changed)", summary)
        self.assertIn("- Third change.", summary)
        self.assertNotIn("Fourth", summary)
        self.assertNotIn("Historical", summary)

    def test_missing_ambiguous_or_empty_changes_fail(self):
        for changelog in ("# Changelog\n## 0.0.1\n- Historical work.\n",
                          "## Unreleased\n## Unreleased\n- Duplicate section.\n",
                          "## Unreleased\nNo documented changes.\n"):
            with self.subTest(changelog=changelog), self.assertRaisesRegex(ValueError, "[Cc]hangelog"):
                bundle.changelog_summary(changelog, "0.1.0-alpha.1", "https://example.invalid/source")


class SbomTests(unittest.TestCase):
    def test_native_license_field_can_contain_a_url(self):
        packages = bundle.rpm_inventory("synthetic\t0\t1\t1.fc44\tx86_64\thttps://example.invalid/license/\n")
        self.assertEqual(packages[0]["license"], "https://example.invalid/license/")

    def sbom(self, graph=None, locked=None, runtime=None):
        return bundle.spdx(graph if graph is not None else metadata(), locked if locked is not None else lock(),
                           bundle.rpm_inventory(NATIVE_TEXT), runtime if runtime is not None else ["pam-1.7.2-1.fc44.x86_64"],
                           version="0.1.0-alpha.1", commit=COMMIT, created="2026-10-17T00:00:00Z",
                           rpm_name="localpin.rpm", rpm_sha256="c" * 64)

    def test_resolved_graph_and_native_inventory_are_linked(self):
        result = self.sbom()
        self.assertEqual(result["spdxVersion"], "SPDX-2.3")
        by_name = {p["name"]: p for p in result["packages"]}
        self.assertEqual(by_name["zeroize"]["checksums"][0]["checksumValue"], "b" * 64)
        self.assertEqual(by_name["pam"]["versionInfo"], "0:1.7.2-1.fc44")
        self.assertIn({"spdxElementId": by_name["localpin-core"]["SPDXID"], "relationshipType": "DEPENDS_ON",
                       "relatedSpdxElement": by_name["zeroize"]["SPDXID"]}, result["relationships"])
        self.assertIn({"spdxElementId": "SPDXRef-LocalPIN-RPM", "relationshipType": "DEPENDS_ON",
                       "relatedSpdxElement": by_name["pam"]["SPDXID"]}, result["relationships"])

    def test_unreachable_platform_package_is_not_in_sbom(self):
        graph = metadata()
        graph["packages"].append({"id": "other-platform", "name": "windows-only"})
        self.assertNotIn("windows-only", {p["name"] for p in self.sbom(graph)["packages"]})

    def test_missing_or_duplicate_graph_fails(self):
        for mutate in (lambda g: g.update(resolve=None),
                       lambda g: g["resolve"]["nodes"].pop(),
                       lambda g: g["resolve"]["nodes"].append(copy.deepcopy(g["resolve"]["nodes"][0])),
                       lambda g: g["workspace_members"].append("unknown")):
            with self.subTest(mutate=mutate):
                graph = metadata()
                mutate(graph)
                with self.assertRaises(ValueError):
                    self.sbom(graph)

    def test_missing_lock_package_or_checksum_fails(self):
        for locked in ({"package": []}, lock()):
            if locked["package"]:
                locked["package"][1].pop("checksum")
            with self.subTest(locked=locked), self.assertRaises(ValueError):
                self.sbom(locked=locked)

    def test_runtime_inventory_mismatch_fails(self):
        with self.assertRaisesRegex(ValueError, "runtime"):
            self.sbom(runtime=["pam-not-installed"])

    def test_invalid_native_inventory_fails(self):
        for text in ("", "pam\t0\t1\n", NATIVE_TEXT * 2, NATIVE_TEXT.replace("\t0\t", "\tbad\t")):
            with self.subTest(text=text), self.assertRaises(ValueError):
                bundle.rpm_inventory(text)


class BundleTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="localpin-release-test-")
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.root = self.directory / "source"
        self.root.mkdir()
        (self.root / "Cargo.toml").write_text('[workspace.package]\nversion = "0.1.0-alpha.1"\n')
        (self.root / "CHANGELOG.md").write_text("# Changelog\n\n## Unreleased\n\n- Synthetic release change.\n")
        (self.root / "Cargo.lock").write_text('''version = 4
[[package]]
name = "localpin-core"
version = "0.1.0-alpha.1"
[[package]]
name = "zeroize"
version = "1.9.1"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
''')
        self.build = self.directory / "build"
        (self.build / "RPMS/x86_64").mkdir(parents=True)
        (self.build / "SOURCES").mkdir()
        self.rpm = self.build / "RPMS/x86_64/localpin-0.1.0-0.1.alpha1.release.fc44.x86_64.rpm"
        self.rpm.write_bytes(b"synthetic RPM")
        self.output = self.directory / "bundle"
        self.hashes = {name: hashlib.sha256(name.encode()).hexdigest() for name in (
            "localpind", "localpin-worker", "localpin-auth-worker", "localpin-eligibility-worker",
            "localpin-account", "localpinctl", "liblocalpin_pam.so")}
        self.inputs = {"schema": 1, "project_version": "0.1.0-alpha.1", "architecture": "x86_64", "signed": False,
                       "cargo_lock_sha256": bundle.digest(self.root / "Cargo.lock"),
                       "native_artifact_sha256": self.hashes, "native_rpm_inputs": ["pam-1.7.2-1.fc44.x86_64"]}
        self.write_archive()
        self.dirty = ""
        self.head = COMMIT
        self.file_mismatch = False
        self.commands = []
        self.addCleanup(patch.stopall)
        patch.object(bundle, "ROOT", self.root).start()
        patch.object(bundle, "run", self.fake_run).start()
        patch.object(bundle.subprocess, "run", return_value=subprocess.CompletedProcess([], 1)).start()

    def write_archive(self, changed_artifact=False):
        self.inputs_bytes = json.dumps(self.inputs).encode()
        with tarfile.open(self.build / "SOURCES/localpin-0.1.0-native.tar.gz", "w:gz") as archive:
            entries = {"BUILD-INPUTS.json": self.inputs_bytes,
                       **{"native/" + name: name.encode() for name in self.hashes}}
            if changed_artifact:
                entries["native/localpinctl"] = b"changed"
            for name, data in entries.items():
                member = tarfile.TarInfo("localpin-0.1.0-native/" + name)
                member.size = len(data)
                archive.addfile(member, io.BytesIO(data))

    def fake_run(self, argv):
        self.commands.append(argv)
        if argv[:3] == ["git", "rev-parse", "HEAD"]:
            return self.head
        if argv[:2] == ["git", "status"]:
            return self.dirty
        if argv[:2] == ["git", "show"]:
            return "1792195200"
        if argv[:2] == ["git", "archive"]:
            Path(next(arg.split("=", 1)[1] for arg in argv if arg.startswith("--output="))).write_bytes(b"committed source archive")
            return ""
        if argv[0] == "cargo":
            self.assertEqual(argv, ["cargo", "metadata", "--format-version", "1", "--locked", "--offline", "--filter-platform", bundle.TARGET])
            return json.dumps(metadata())
        if argv[0] == "rpmkeys":
            return "synthetic RPM: digests OK"
        if argv[:2] == ["rpm", "-qa"]:
            return NATIVE_TEXT
        if argv[:2] == ["rpm", "-qp"]:
            query = argv[3]
            if query == bundle.RPM_FORMAT:
                return "localpin\t0\t0.1.0\t0.1.alpha1.release.fc44\tx86_64\tMIT OR Apache-2.0\n"
            if query == "%{FILEDIGESTALGO}":
                return "8"
            files = {f"/usr/libexec/localpin/{name}": value for name, value in self.hashes.items()}
            files["/usr/bin/localpinctl"] = files.pop("/usr/libexec/localpin/localpinctl")
            files["/usr/lib64/security/pam_localpin.so"] = files.pop("/usr/libexec/localpin/liblocalpin_pam.so")
            files["/usr/share/doc/localpin/BUILD-INPUTS.json"] = hashlib.sha256(self.inputs_bytes).hexdigest()
            if self.file_mismatch:
                files["/usr/bin/localpinctl"] = "0" * 64
            return "\n".join(f"{name}\t{value}" for name, value in files.items())
        raise AssertionError(f"Unexpected command: {argv}")

    def create(self, tag="v0.1.0-alpha.1", commit=COMMIT):
        bundle.create(self.build, self.output, tag, commit)

    def test_complete_bundle_binds_source_rpm_and_sbom(self):
        self.create()
        manifest = json.loads((self.output / "RELEASE.json").read_text())
        self.assertEqual(manifest["source_commit"], COMMIT)
        self.assertEqual(manifest["signing"], {"signed": False, "fingerprint": None})
        self.assertEqual(manifest["rpm"]["sha256"], bundle.digest(self.rpm))
        self.assertEqual((self.output / "BUILD-INPUTS.json").read_bytes(), self.inputs_bytes)
        self.assertEqual((self.output / manifest["source_archive"]).read_bytes(), b"committed source archive")
        for line in (self.output / "SHA256SUMS").read_text().splitlines():
            expected, name = line.split("  ")
            self.assertEqual(bundle.digest(self.output / name), expected)
        self.assertEqual(len(list(self.output.iterdir())), 8)

    def test_non_prerelease_or_mismatched_tag_fails(self):
        for version, tag in (("0.1.0", "v0.1.0"), ("0.1.0-alpha.0", "v0.1.0-alpha.0"),
                             ("0.1.0-alpha.1", "v0.1.0-alpha.2"), ("0.1.0-beta.01", "v0.1.0-beta.01")):
            (self.root / "Cargo.toml").write_text(f'[workspace.package]\nversion = "{version}"\n')
            with self.subTest(version=version), self.assertRaisesRegex(ValueError, "tag"):
                self.create(tag=tag)

    def test_description_identifies_downloads_evidence_verification_and_limits(self):
        with patch.dict(bundle.os.environ, {"GITHUB_SERVER_URL": "https://github.com",
                                           "GITHUB_REPOSITORY": "tommcamm/LocalPIN", "GITHUB_RUN_ID": "12345"}):
            self.create()
        manifest = json.loads((self.output / "RELEASE.json").read_text())
        notes = (self.output / "RELEASE-NOTES.md").read_text()
        source = f"https://github.com/tommcamm/LocalPIN/blob/{COMMIT}"
        for expected in ("experimental Fedora KDE 44 x86_64 prerelease", "six-digit PIN unlocking",
                         "Synthetic release change.", self.rpm.name, manifest["source_archive"],
                         "SHA256SUMS.asc", "Every published experimental release requires a verified embedded RPM signature.",
                         "release-evidence-*", "artifact for 90 days", "release download covers only the RPM",
                         "separately trusted maintainer fingerprint", "There is no supported production release.",
                         "leaves PIN integration disabled", "hardware matrix remain unvalidated.",
                         f"(https://raw.githubusercontent.com/tommcamm/LocalPIN/{COMMIT}/packaging/fedora/RPM-GPG-KEY-LocalPIN)",
                         f"({source}/CHANGELOG.md)", f"({source}/docs/integration-administration.md)",
                         f"({source}/docs/development/m9-release-readiness.md)",
                         f"({source}/docs/releasing.md#verify-and-test-a-download)",
                         f"({manifest['workflow_run_url']})"):
            with self.subTest(expected=expected):
                self.assertIn(expected, notes)
        downloads = notes.split("### Downloads\n", 1)[1].split("### Build evidence\n", 1)[0]
        self.assertEqual([line for line in downloads.splitlines() if line.startswith("- ")],
                         [f"- **`{self.rpm.name}`**: the signed installable Fedora 44 x86_64 package.",
                          "- **`SHA256SUMS`**: the SHA256 checksum of that RPM."])
        for evidence_file in (manifest["source_archive"], "RELEASE.json", "SBOM.spdx.json", "SHA256SUMS.asc"):
            with self.subTest(evidence_file=evidence_file):
                self.assertNotIn(evidence_file, downloads)
        self.assertEqual(manifest["workflow_run_url"], "https://github.com/tommcamm/LocalPIN/actions/runs/12345")

    def test_provenance_keeps_reviewed_main_and_generated_source_distinct(self):
        base = "d" * 40
        with patch.dict(bundle.os.environ, {"LOCALPIN_RELEASE_BASE_COMMIT": base}):
            self.create()
        manifest = json.loads((self.output / "RELEASE.json").read_text())
        self.assertEqual(manifest["reviewed_main_commit"], base)
        self.assertEqual(manifest["source_commit"], COMMIT)

    def test_dirty_source_or_wrong_head_fails(self):
        self.dirty = "?? unreviewed.txt"
        with self.assertRaisesRegex(ValueError, "clean"):
            self.create()
        self.dirty = ""
        self.head = "d" * 40
        with self.assertRaisesRegex(ValueError, "HEAD"):
            self.create()

    def test_changed_lockfile_or_native_artifact_fails(self):
        self.inputs["cargo_lock_sha256"] = "0" * 64
        self.write_archive()
        with self.assertRaisesRegex(ValueError, "lockfile"):
            self.create()
        self.inputs["cargo_lock_sha256"] = bundle.digest(self.root / "Cargo.lock")
        self.write_archive(changed_artifact=True)
        with self.assertRaisesRegex(ValueError, "artifact digest"):
            self.create()

    def test_rpm_payload_must_match_manifest(self):
        self.file_mismatch = True
        with self.assertRaisesRegex(ValueError, "RPM native files"):
            self.create()

    def test_signing_finalization_refreshes_rpm_sbom_and_checksums(self):
        self.create()
        notes = (self.output / "RELEASE-NOTES.md").read_bytes()
        manifest_path = self.output / "RELEASE.json"
        manifest = json.loads(manifest_path.read_text())
        rpm = self.output / manifest["rpm"]["filename"]
        rpm.write_bytes(b"synthetic signed RPM")
        manifest["signing"] = {"signed": True, "fingerprint": "D" * 40}
        bundle.write_json(manifest_path, manifest)
        (self.output / "RPM-GPG-KEY-LocalPIN").write_text("public key")
        (self.output / "SHA256SUMS.asc").write_text("detached signature")
        bundle.finalize(self.output)
        manifest = json.loads(manifest_path.read_text())
        self.assertEqual(manifest["rpm"]["sha256"], bundle.digest(rpm))
        self.assertTrue(manifest["signing"]["signed"])
        self.assertFalse(json.loads((self.output / "BUILD-INPUTS.json").read_text())["signed"])
        sbom = json.loads((self.output / "SBOM.spdx.json").read_text())
        self.assertEqual(sbom["packages"][0]["checksums"][0]["checksumValue"], bundle.digest(rpm))
        checksums = (self.output / "SHA256SUMS").read_text()
        self.assertIn("RPM-GPG-KEY-LocalPIN", checksums)
        self.assertNotIn("SHA256SUMS.asc", checksums)
        self.assertEqual((self.output / "RELEASE-NOTES.md").read_bytes(), notes)

    def test_finalize_rejects_symlink_and_traversal(self):
        self.create()
        (self.output / "foreign").symlink_to(self.root / "Cargo.lock")
        with self.assertRaisesRegex(ValueError, "regular"):
            bundle.finalize(self.output)
        (self.output / "foreign").unlink()
        manifest = json.loads((self.output / "RELEASE.json").read_text())
        manifest["rpm"]["filename"] = "../foreign.rpm"
        bundle.write_json(self.output / "RELEASE.json", manifest)
        with self.assertRaisesRegex(ValueError, "filename"):
            bundle.finalize(self.output)


if __name__ == "__main__":
    unittest.main()
