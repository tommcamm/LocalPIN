"""Publication guard regressions with synthetic bundles and mocked GitHub."""
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import subprocess
import unittest
import urllib.error
from unittest.mock import patch


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace("-", "_"), Path(__file__).with_name(name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


policy = load("release-policy")
publish = load("publish-release")
verify_native_assets = publish.verify_native_assets
signer = load("sign-release")
COMMIT = "a" * 40
TAG = "v0.1.0-alpha.1"
RPM = "localpin-0.1.0-0.1.alpha1.release.fc44.x86_64.rpm"


class GitHubApiTests(unittest.TestCase):
    def test_permission_error_preserves_reason_without_exposing_token(self):
        token = "synthetic-token-never-published"
        error = urllib.error.HTTPError("https://api.github.com/synthetic", 403, "Forbidden", {},
                                       io.BytesIO(json.dumps({"message": f"tag update denied\n{token}"}).encode()))
        with patch.dict(os.environ, {"GH_TOKEN": token, "GITHUB_REPOSITORY": "synthetic/localpin"}), patch.object(publish.urllib.request, "urlopen", side_effect=error):
            with self.assertRaises(RuntimeError) as raised:
                publish.api("git/refs", {"ref": "refs/tags/synthetic"})
        message = str(raised.exception)
        self.assertIn("HTTP 403", message)
        self.assertIn("tag update denied", message)
        self.assertIn("contents: write", message)
        self.assertNotIn(token, message)
        self.assertNotIn("\n", message)

    def test_missing_release_lookup_only_ignores_404(self):
        for status in (404, 403):
            error = urllib.error.HTTPError("https://api.github.com/synthetic", status, "failure", {}, io.BytesIO(b"{}"))
            with self.subTest(status=status), patch.dict(os.environ, {"GH_TOKEN": "synthetic", "GITHUB_REPOSITORY": "synthetic/localpin"}), patch.object(publish.urllib.request, "urlopen", side_effect=error):
                if status == 404:
                    self.assertIsNone(publish.api("releases/tags/synthetic", missing_ok=True))
                else:
                    with self.assertRaises(RuntimeError):
                        publish.api("releases/tags/synthetic", missing_ok=True)


class ReleasePolicyTests(unittest.TestCase):
    def test_prerelease_version_maps_to_ordered_rpm_identity(self):
        self.assertEqual(policy.release_identity("0.1.0-alpha.1"), (TAG, "0.1.alpha1.release"))
        self.assertEqual(policy.release_identity("1.2.3-beta.12"), ("v1.2.3-beta.12", "0.2.beta12.release"))
        self.assertEqual(policy.release_identity("1.2.3-rc.2"), ("v1.2.3-rc.2", "0.3.rc2.release"))
        self.assertEqual(policy.rpm_prefix("0.1.0-alpha.12"), "0.1.alpha12")
        self.assertEqual(load("build-rpm").default_release("0.1.0-beta.2"), "0.2.beta2")

    def test_supported_versions_and_injected_versions_are_refused(self):
        for version in ("1.0.0", "0.1.0-alpha.0", "0.1.0-alpha.01", "01.2.3-alpha.1", "0.1.0-dev.1", "0.1.0-alpha.1\ncontents=write", "0.1.0-alpha.1+metadata"):
            with self.subTest(version=version), self.assertRaises(ValueError):
                policy.release_identity(version)

    def test_non_main_dispatch_is_refused_before_git_access(self):
        with patch.dict(os.environ, {"GITHUB_REF": "refs/heads/topic"}), patch.object(policy.subprocess, "check_output") as git:
            with self.assertRaises(SystemExit):
                policy.main()
            git.assert_not_called()

    def test_signing_requires_explicit_key_and_full_fingerprint(self):
        with patch.dict(os.environ, {}, clear=True), self.assertRaisesRegex(ValueError, "refusing unsigned fallback"):
            signer.sign(Path("/nonexistent-synthetic-bundle"))

    def test_primary_fingerprint_does_not_accept_a_subkey(self):
        listing = "sec:::::::::\nfpr:::::::::PRIMARY:\nssb:::::::::\nfpr:::::::::SUBKEY:\n"
        self.assertEqual(signer.primary_fingerprints(listing), ["PRIMARY"])


class PublicationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="localpin-release-tests-")
        self.addCleanup(self.temporary.cleanup)
        self.output = Path(self.temporary.name)
        self.manifest = {"schema": 1, "experimental": True, "tag": TAG, "source_commit": COMMIT,
                         "reviewed_main_commit": COMMIT,
                         "project_version": "0.1.0-alpha.1", "target": "Fedora KDE 44 x86_64",
                         "source_archive": "localpin-0.1.0-alpha.1-source.tar.gz",
                         "rpm": {"filename": RPM, "version": "0.1.0", "release": "0.1.alpha1.release.fc44"},
                         "signing": {"signed": True, "fingerprint": "A" * 40}}
        self.write_bundle()
        self.environment = patch.dict(os.environ, {"GITHUB_REF": "refs/heads/main", "GITHUB_SHA": COMMIT,
                                                   "LOCALPIN_SOURCE_COMMIT": COMMIT,
                                                   "LOCALPIN_RELEASE_BASE_COMMIT": COMMIT,
                                                   "GITHUB_REPOSITORY": "synthetic/localpin", "GITHUB_STEP_SUMMARY": ""})
        self.environment.start()
        self.addCleanup(self.environment.stop)
        self.head = patch.object(publish.subprocess, "check_output", return_value=COMMIT + "\n")
        self.head.start()
        self.addCleanup(self.head.stop)
        self.native = patch.object(publish, "verify_native_assets")
        self.native.start()
        self.addCleanup(self.native.stop)

    def write_bundle(self):
        (self.output / "RELEASE-NOTES.md").write_text("Synthetic release fixture, never published.\n")
        (self.output / RPM).write_bytes(b"synthetic non-installable RPM fixture")
        digest = hashlib.sha256((self.output / RPM).read_bytes()).hexdigest()
        self.manifest["rpm"]["sha256"] = digest
        (self.output / "RELEASE.json").write_text(json.dumps(self.manifest))
        (self.output / "localpin-0.1.0-alpha.1-source.tar.gz").write_bytes(b"synthetic source")
        (self.output / "BUILD-INPUTS.json").write_text(json.dumps({"project_version": "0.1.0-alpha.1", "signed": False, "architecture": "x86_64"}))
        (self.output / "NATIVE-RPMS.json").write_text("{}")
        (self.output / "SBOM.spdx.json").write_text(json.dumps({"spdxVersion": "SPDX-2.3", "packages": [{"SPDXID": "SPDXRef-LocalPIN-RPM", "packageFileName": RPM, "checksums": [{"algorithm": "SHA256", "checksumValue": digest}]}]}))
        (self.output / "RPM-GPG-KEY-LocalPIN").write_text("synthetic public key")
        (self.output / "SHA256SUMS.asc").write_text("synthetic detached signature")
        self.checksums()

    def checksums(self):
        (self.output / "SHA256SUMS").write_text("".join(f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.name}\n"
                                                        for p in sorted(self.output.iterdir()) if p.name not in ("SHA256SUMS", "SHA256SUMS.asc")))

    def github_release(self, *, draft):
        return {"tagName": TAG, "name": f"LocalPIN {TAG} (experimental)",
                "body": (self.output / "RELEASE-NOTES.md").read_text(), "isDraft": draft, "isPrerelease": True,
                "url": f"https://github.com/synthetic/localpin/releases/tag/{TAG}",
                "assets": [{"name": name} for name in (RPM, "SHA256SUMS")]}

    def test_downloads_only_check_the_rpm_and_preserve_signed_evidence(self):
        evidence = {path.name: path.read_bytes() for path in self.output.iterdir()}
        with tempfile.TemporaryDirectory(prefix="localpin-download-tests-") as temporary:
            downloads = Path(temporary)
            assets = publish.prepare_downloads(self.output, downloads)
            self.assertEqual({path.name for path in assets}, {RPM, "SHA256SUMS"})
            self.assertEqual({path.name for path in downloads.iterdir()}, {RPM, "SHA256SUMS"})
            self.assertEqual((downloads / RPM).read_bytes(), evidence[RPM])
            # Ordinary sha256sum must succeed with only the two public downloads.
            subprocess.run(["sha256sum", "--check", "SHA256SUMS"], cwd=downloads, check=True, capture_output=True)
            self.assertEqual((downloads / "SHA256SUMS").read_text().splitlines(),
                             [f"{self.manifest['rpm']['sha256']}  {RPM}"])
        self.assertEqual({path.name: path.read_bytes() for path in self.output.iterdir()}, evidence)

    def test_changed_or_unchecked_assets_are_refused(self):
        (self.output / RPM).write_bytes(b"changed")
        with self.assertRaisesRegex(ValueError, "checksum mismatch"):
            publish.verify_bundle(self.output, TAG, COMMIT)
        self.write_bundle()
        (self.output / "unexpected").write_text("unchecked")
        with self.assertRaisesRegex(ValueError, "unchecked assets"):
            publish.verify_bundle(self.output, TAG, COMMIT)

    def test_missing_required_asset_or_mismatched_manifest_is_refused(self):
        (self.output / "SBOM.spdx.json").unlink()
        self.checksums()
        with self.assertRaisesRegex(ValueError, "missing or unexpected assets"):
            publish.verify_bundle(self.output, TAG, COMMIT)
        self.write_bundle()
        self.manifest["rpm"]["sha256"] = "b" * 64
        (self.output / "RELEASE.json").write_text(json.dumps(self.manifest))
        self.checksums()
        with self.assertRaisesRegex(ValueError, "manifest RPM digest mismatch"):
            publish.verify_bundle(self.output, TAG, COMMIT)

    def test_unexpected_reviewed_main_commit_is_refused(self):
        self.manifest["reviewed_main_commit"] = "b" * 40
        self.write_bundle()
        with self.assertRaisesRegex(ValueError, "reviewed main"):
            publish.verify_bundle(self.output, TAG, COMMIT)

    def test_signed_bundle_requires_checksum_signature_and_key(self):
        (self.output / "RPM-GPG-KEY-LocalPIN").unlink()
        self.checksums()
        with self.assertRaisesRegex(ValueError, "missing or unexpected assets"):
            publish.verify_bundle(self.output, TAG, COMMIT)
        (self.output / "RPM-GPG-KEY-LocalPIN").write_text("synthetic public key")
        (self.output / "SHA256SUMS.asc").unlink()
        self.checksums()
        with self.assertRaisesRegex(ValueError, "unchecked assets"):
            publish.verify_bundle(self.output, TAG, COMMIT)

    def test_unsigned_or_missing_signing_status_prevents_publication(self):
        for signing in ({"signed": False, "fingerprint": None}, {}, {"signed": "true", "fingerprint": "A" * 40}):
            with self.subTest(signing=signing):
                self.manifest["signing"] = signing
                self.write_bundle()
                with patch.object(publish, "api") as api, patch.object(publish, "verify_native_assets") as native:
                    with self.assertRaisesRegex(ValueError, "requires a signed RPM"):
                        publish.publish(self.output, TAG, COMMIT)
                    native.assert_not_called()
                    api.assert_not_called()

    def test_native_verifier_rejects_unsigned_manifest_before_running_tools(self):
        self.manifest["signing"] = {"signed": False, "fingerprint": None}
        self.write_bundle()
        with patch.object(publish.subprocess, "run") as tools:
            with self.assertRaisesRegex(ValueError, "requires a signed RPM"):
                verify_native_assets(self.output)
            tools.assert_not_called()

    def test_missing_fingerprint_prevents_publication(self):
        self.manifest["signing"]["fingerprint"] = None
        self.write_bundle()
        with patch.object(publish, "api") as api, self.assertRaisesRegex(ValueError, "full signing fingerprint"):
            publish.publish(self.output, TAG, COMMIT)
        api.assert_not_called()

    def test_invalid_checksum_or_rpm_signature_prevents_github_mutation(self):
        for invalid_signature in ("gpg", "rpmkeys"):
            def run(argv, **kwargs):
                if argv[0] == "rpm" and "-qp" in argv:
                    return subprocess.CompletedProcess(argv, 0, "localpin\t0.1.0\t0.1.alpha1.release.fc44\tx86_64")
                if argv[0] == "gpg" and "--list-keys" in argv:
                    return subprocess.CompletedProcess(argv, 0, f"pub:::::::::\nfpr:::::::::{'A' * 40}:\n")
                if (argv[0] == invalid_signature and
                        ("--verify" in argv or "--checksig" in argv)):
                    raise subprocess.CalledProcessError(1, argv)
                return subprocess.CompletedProcess(argv, 0, "")

            with self.subTest(invalid_signature=invalid_signature), patch.object(publish, "verify_native_assets", side_effect=verify_native_assets), patch.object(publish.subprocess, "run", side_effect=run), patch.object(publish, "api") as api:
                with self.assertRaises(subprocess.CalledProcessError):
                    publish.publish(self.output, TAG, COMMIT)
                api.assert_not_called()

    def test_native_verification_failure_prevents_any_github_mutation(self):
        with patch.object(publish, "verify_native_assets", side_effect=ValueError("invalid signature")), patch.object(publish, "api") as api:
            with self.assertRaisesRegex(ValueError, "invalid signature"):
                publish.publish(self.output, TAG, COMMIT)
            api.assert_not_called()

    def test_prepared_commit_can_differ_from_original_workflow_commit(self):
        with patch.dict(os.environ, {"GITHUB_SHA": "b" * 40}), patch.object(publish, "_publish_downloads") as uploads:
            publish.publish(self.output, TAG, COMMIT)
        self.assertEqual(uploads.call_args.args[2], COMMIT)

    def test_generated_release_checks_reviewed_base_and_tags_the_tested_child(self):
        child = "b" * 40
        with patch.object(publish, "verify_release_source") as verify, \
                patch.object(publish, "api", side_effect=[None, None, {"status": "ahead"}, {"sha": "c" * 40}, {}]) as api, \
                patch.object(publish.subprocess, "run"), patch.object(publish, "verify_github_release", return_value="https://example.invalid/release"):
            publish._publish_downloads(self.output, TAG, child, [self.output / RPM])
        verify.assert_called_once_with(COMMIT, child, "0.1.0-alpha.1")
        self.assertEqual(api.call_args_list[2].args, (f"compare/{COMMIT}...main",))
        self.assertEqual(api.call_args_list[3].args[1]["object"], child)

    def test_unexpected_generated_source_or_base_refuses_before_github_mutation(self):
        with patch.object(publish, "verify_release_source", side_effect=ValueError("unexpected code")), patch.object(publish, "api") as api:
            with self.assertRaisesRegex(ValueError, "unexpected code"):
                publish._publish_downloads(self.output, TAG, "b" * 40, [])
            api.assert_not_called()
        with patch.dict(os.environ, {"LOCALPIN_RELEASE_BASE_COMMIT": "b" * 40}), patch.object(publish, "api") as api:
            with self.assertRaisesRegex(ValueError, "dispatched main"):
                publish._publish_downloads(self.output, TAG, COMMIT, [])
            api.assert_not_called()

    def test_wrong_selected_commit_checkout_or_ref_prevents_publication(self):
        for environment, head in (({"LOCALPIN_SOURCE_COMMIT": "b" * 40}, COMMIT),
                                  ({}, "b" * 40), ({"GITHUB_REF": "refs/heads/topic"}, COMMIT)):
            with self.subTest(environment=environment, head=head), patch.dict(os.environ, environment), \
                    patch.object(publish.subprocess, "check_output", return_value=head), patch.object(publish, "api") as api:
                with self.assertRaisesRegex(ValueError, "selected"):
                    publish.publish(self.output, TAG, COMMIT)
                api.assert_not_called()

    def test_upload_failure_leaves_draft_without_publishing(self):
        with patch.object(publish, "api", side_effect=[None, None, {"status": "identical"}, {"sha": "c" * 40}, {}]), patch.object(publish.subprocess, "run", side_effect=subprocess.CalledProcessError(1, "gh")) as gh:
            with self.assertRaises(subprocess.CalledProcessError):
                publish.publish(self.output, TAG, COMMIT)
            self.assertEqual(gh.call_count, 1)
            self.assertIn("--draft", gh.call_args.args[0])

    def test_different_candidate_or_stable_tag_is_refused(self):
        with self.assertRaisesRegex(ValueError, "manifest does not match"):
            publish.verify_bundle(self.output, TAG, "b" * 40)
        self.manifest["tag"] = "v1.0.0"
        self.write_bundle()
        with self.assertRaisesRegex(ValueError, "supported-release gates"):
            publish.verify_bundle(self.output, "v1.0.0", COMMIT)

    def test_existing_tag_or_release_never_gets_overwritten(self):
        for results in (({"sha": COMMIT},), (None, {"id": 1})):
            with self.subTest(results=results), patch.object(publish, "api", side_effect=results) as api, patch.object(publish.subprocess, "run") as gh:
                with self.assertRaisesRegex(ValueError, "refusing to overwrite"):
                    publish.publish(self.output, TAG, COMMIT)
                self.assertTrue(all(call.args[1:] == () for call in api.call_args_list))
                gh.assert_not_called()

    def test_main_ancestry_is_required_before_creating_tag(self):
        with patch.object(publish, "api", side_effect=[None, None, {"status": "diverged"}]) as api, patch.object(publish.subprocess, "run") as gh:
            with self.assertRaisesRegex(ValueError, "no longer on main"):
                publish.publish(self.output, TAG, COMMIT)
            self.assertEqual(api.call_count, 3)
            gh.assert_not_called()

    def test_tag_then_draft_upload_then_publish(self):
        results = [subprocess.CompletedProcess([], 0), subprocess.CompletedProcess([], 0, json.dumps(self.github_release(draft=True))),
                   subprocess.CompletedProcess([], 0), subprocess.CompletedProcess([], 0, json.dumps(self.github_release(draft=False)))]
        with patch.object(publish, "api", side_effect=[None, None, {"status": "ahead"}, {"sha": "c" * 40}, {}]) as api, patch.object(publish.subprocess, "run", side_effect=results) as gh, patch("builtins.print") as output:
            publish.publish(self.output, TAG, COMMIT)
            self.assertEqual(api.call_args_list[3].args[0], "git/tags")
            self.assertEqual(api.call_args_list[4].args[1]["sha"], "c" * 40)
            self.assertIn("--draft", gh.call_args_list[0].args[0])
            self.assertIn("--prerelease", gh.call_args_list[0].args[0])
            uploaded = gh.call_args_list[0].args[0][4:gh.call_args_list[0].args[0].index("--repo")]
            self.assertEqual({Path(path).name for path in uploaded}, {RPM, "SHA256SUMS"})
            self.assertEqual(len(uploaded), 2)
            self.assertEqual(gh.call_args_list[1].args[0][:3], ["gh", "release", "view"])
            self.assertIn("--draft=false", gh.call_args_list[2].args[0])
            self.assertEqual(gh.call_args_list[3].args[0][:3], ["gh", "release", "view"])
            output.assert_called_once_with(f"Published experimental release: https://github.com/synthetic/localpin/releases/tag/{TAG}")
            self.assertNotIn("--clobber", str(gh.call_args_list))

    def test_incomplete_or_wrong_draft_is_not_published(self):
        for change in ({"body": "wrong description"}, {"assets": []},
                       {"assets": [{"name": name} for name in (RPM, "SHA256SUMS", "SBOM.spdx.json")]},
                       {"isPrerelease": False}, {"isDraft": False}):
            release = {**self.github_release(draft=True), **change}
            with self.subTest(change=change), patch.object(publish, "api", side_effect=[None, None, {"status": "ahead"}, {"sha": "c" * 40}, {}]), patch.object(publish.subprocess, "run", side_effect=[subprocess.CompletedProcess([], 0), subprocess.CompletedProcess([], 0, json.dumps(release))]) as gh:
                with self.assertRaisesRegex(ValueError, "description or uploaded assets"):
                    publish.publish(self.output, TAG, COMMIT)
                self.assertEqual(gh.call_count, 2)
                self.assertTrue(all("--draft=false" not in call.args[0] for call in gh.call_args_list))

    def test_final_release_must_be_public_prerelease_at_expected_url(self):
        for change in ({"isDraft": True}, {"url": "https://github.com/other/repository/releases/tag/other"}):
            release = {**self.github_release(draft=False), **change}
            with self.subTest(change=change), patch.object(publish.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, json.dumps(release))):
                with self.assertRaises(ValueError):
                    publish.verify_github_release(self.output, TAG, list(self.output.iterdir()), draft=False)


if __name__ == "__main__":
    unittest.main()
