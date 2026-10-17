"""Automatic release versioning with synthetic files and a mocked GitHub API."""
from datetime import date
import importlib.util
import io
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
import urllib.error
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location("prepare_release", Path(__file__).with_name("prepare-release.py"))
prepare = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(prepare)
COMMIT, PREPARED, TREE = "a" * 40, "b" * 40, "c" * 40
OLD, NEW = "0.1.0-alpha.1", "0.1.0-alpha.2"
DATE = date(2026, 10, 17)


class ReleaseFixture(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="localpin-release-prepare-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.files = {
            "Cargo.toml": f'[workspace]\nmembers = ["crates/localpin-core", "crates/localpin-protocol", "crates/localpin-credentials"]\n[workspace.package]\nversion = "{OLD}"\n[workspace.dependencies]\nlocalpin-core = {{path = "crates/localpin-core", version = "={OLD}"}}\n',
            "fuzz/Cargo.toml": f'[package]\nname = "localpin-fuzz"\nversion = "0.0.0"\n[dependencies]\nlocalpin-core = {{path = "../crates/localpin-core", version = "={OLD}"}}\n',
            "tools/localpin-integration.py": f"state = {{'package_version': '{OLD}'}}\n",
            "packaging/fedora/localpin.spec": 'Version:        0.1.0\nRelease:        0.1.alpha1%{?dist}\n%changelog\n- Historical package entry.\n',
            "CHANGELOG.md": '# Changelog\n## Unreleased\n### Added\n- Synthetic new feature.\n\n## [0.1.0-alpha.1] - 2026-10-16\n- Historical release.\n',
        }
        for name in ("localpin-core", "localpin-protocol", "localpin-credentials"):
            self.files[f"crates/{name}/Cargo.toml"] = f'[package]\nname = "{name}"\nversion.workspace = true\n'
        locked = 'version = 4\n\n' + ''.join(f'[[package]]\nname = "{name}"\nversion = "{OLD}"\n\n' for name in ("localpin-core", "localpin-protocol", "localpin-credentials"))
        locked += '[[package]]\nname = "third-party"\nversion = "1.2.3"\nsource = "registry+synthetic"\nchecksum = "synthetic"\n'
        self.files["Cargo.lock"] = self.files["fuzz/Cargo.lock"] = locked
        for name, content in self.files.items():
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content)

    def plan(self):
        return prepare.bump_files(self.root, OLD, NEW, DATE)


class VersionPlanTests(ReleaseFixture):
    def test_next_sequence_skips_used_numbers_without_changing_channel_or_base(self):
        tags = ["v0.1.0-alpha.1", "v0.1.0-alpha.9", "v0.1.0-beta.42", "v1.0.0-alpha.99", "v0.1.0-alpha.010"]
        self.assertEqual(prepare.next_version(OLD, tags), "0.1.0-alpha.10")
        self.assertEqual(prepare.next_version("1.2.3-rc.8", []), "1.2.3-rc.9")
        for invalid in ("1.0.0", "0.1.0-alpha.0", "0.1.0-dev.1"):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                prepare.next_version(invalid, tags)

    def test_plan_changes_only_release_metadata_and_preserves_historical_entries(self):
        edits = self.plan()
        self.assertEqual(set(edits), {"Cargo.toml", "fuzz/Cargo.toml", "Cargo.lock", "fuzz/Cargo.lock", "CHANGELOG.md", "packaging/fedora/localpin.spec", "tools/localpin-integration.py"})
        self.assertIn(f'version = "{NEW}"', edits["Cargo.toml"])
        self.assertIn(f'version = "={NEW}"', edits["fuzz/Cargo.toml"])
        self.assertIn('version = "0.0.0"', edits["fuzz/Cargo.toml"])
        for name in ("Cargo.lock", "fuzz/Cargo.lock"):
            self.assertEqual(edits[name].count(f'version = "{NEW}"'), 3)
            self.assertIn('version = "1.2.3"', edits[name])
        self.assertIn("Release:        0.1.alpha2%{?dist}", edits["packaging/fedora/localpin.spec"])
        self.assertTrue(edits["packaging/fedora/localpin.spec"].endswith('- Historical package entry.\n'))
        self.assertIn('## Unreleased\n\n## [0.1.0-alpha.2] - 2026-10-17\n', edits["CHANGELOG.md"])
        self.assertTrue(edits["CHANGELOG.md"].endswith('## [0.1.0-alpha.1] - 2026-10-16\n- Historical release.\n'))
        # Planning never mutates the working tree.
        self.assertTrue(all((self.root / name).read_text() == content for name, content in self.files.items()))

    def test_empty_unreleased_has_transparent_comparison_instead_of_invented_features(self):
        (self.root / "CHANGELOG.md").write_text('## Unreleased\n\n## [0.1.0-alpha.1]\n- Historical.\n')
        changelog = self.plan()["CHANGELOG.md"]
        self.assertIn('/compare/v0.1.0-alpha.1...v0.1.0-alpha.2', changelog)
        self.assertEqual(changelog.count('- Historical.'), 1)

    def test_inconsistent_inputs_fail_before_any_plan_is_returned(self):
        for name, before, after in (("Cargo.lock", OLD, "0.1.0-alpha.99"),
                                    ("fuzz/Cargo.toml", "=" + OLD, "^" + OLD),
                                    ("tools/localpin-integration.py", OLD, "unknown"),
                                    ("packaging/fedora/localpin.spec", "0.1.alpha1", "other"),
                                    ("CHANGELOG.md", "Unreleased", "Missing")):
            with self.subTest(name=name):
                path = self.root / name
                original = path.read_text()
                path.write_text(original.replace(before, after))
                with self.assertRaises(ValueError):
                    self.plan()
                path.write_text(original)

    def test_automatic_bumps_cannot_promote_channels_change_base_or_go_backwards(self):
        for new in (OLD, "0.1.0-beta.2", "0.2.0-alpha.2"):
            with self.subTest(new=new), self.assertRaisesRegex(ValueError, "same base version and channel"):
                prepare.bump_files(self.root, OLD, new, DATE)


class PreparationTests(ReleaseFixture):
    def setUp(self):
        super().setUp()
        self.output = self.root / "output"
        environment = patch.dict(os.environ, {"GITHUB_SHA": COMMIT, "GITHUB_REF": "refs/heads/main", "GITHUB_EVENT_NAME": "workflow_dispatch",
                                               "GITHUB_REPOSITORY": "synthetic/localpin", "GITHUB_OUTPUT": str(self.output), "GITHUB_STEP_SUMMARY": ""})
        environment.start()
        self.addCleanup(environment.stop)
        self.tags = ["v" + OLD]
        def git(root, *args):
            return {("rev-parse", "HEAD"): COMMIT, ("status", "--porcelain", "--untracked-files=all"): "",
                    ("tag", "--list"): "\n".join(self.tags), ("rev-parse", "HEAD^{tree}"): "d" * 40,
                    ("ls-tree", "-r", "--full-tree", "HEAD"): "\n".join(f"{'100755' if name.endswith('.py') else '100644'} blob {'e' * 40}\t{name}" for name in self.files)}[args]
        self.git = patch.object(prepare, "git", side_effect=git)
        self.git.start()
        self.addCleanup(self.git.stop)

    def run_prepare(self, responses):
        with patch.object(prepare, "api", side_effect=responses) as api:
            prepare.prepare(self.root)
        return api

    def test_bump_commits_only_generated_files_on_a_new_release_branch(self):
        api = self.run_prepare([{"object": {"sha": COMMIT}}, None, {"sha": TREE}, {"sha": PREPARED}, {"object": {"sha": PREPARED}}])
        self.assertEqual(api.call_args_list[-1].args, ("repos/synthetic/localpin/git/refs", {"sha": PREPARED, "ref": f"refs/heads/codex/release-v{NEW}-{COMMIT}"}))
        self.assertEqual(api.call_args_list[-1].kwargs, {})
        self.assertEqual(api.call_args_list[-2].args[1]["parents"], [COMMIT])
        tree = api.call_args_list[2].args[1]["tree"]
        self.assertTrue(all(not entry["path"].startswith('.github/') for entry in tree))
        self.assertEqual(next(entry['mode'] for entry in tree if entry['path'].endswith('.py')), '100755')
        self.assertIn('source_commit=' + PREPARED, self.output.read_text())
        self.assertIn('base_commit=' + COMMIT, self.output.read_text())
        self.assertIn('tag=v' + NEW, self.output.read_text())

    def test_unused_version_is_reused_without_any_write(self):
        self.tags = []
        api = self.run_prepare([{"object": {"sha": COMMIT}}])
        self.assertEqual(api.call_count, 1)
        self.assertIn('source_commit=' + COMMIT, self.output.read_text())
        self.assertIn('tag=v' + OLD, self.output.read_text())

    def test_retry_can_adopt_only_the_exact_generated_child(self):
        for actual_tree, succeeds in ((TREE, True), ("f" * 40, False)):
            self.output.unlink(missing_ok=True)
            responses = [{"object": {"sha": COMMIT}}, {"object": {"sha": PREPARED}},
                         {"parents": [{"sha": COMMIT}], "tree": {"sha": actual_tree}, "message": "Release-Date: 2026-10-17"}, {"sha": TREE}]
            with self.subTest(succeeds=succeeds), patch.object(prepare, "api", side_effect=responses) as api:
                if succeeds:
                    prepare.prepare(self.root)
                    self.assertIn('source_commit=' + PREPARED, self.output.read_text())
                else:
                    with self.assertRaisesRegex(ValueError, "different changes"):
                        prepare.prepare(self.root)
                    self.assertFalse(self.output.exists())
                self.assertTrue(all(len(call.args) == 1 or call.args[0].endswith('/trees') for call in api.call_args_list))

    def test_stale_dispatch_and_failed_ref_update_never_output_a_release(self):
        for responses in ([{"object": {"sha": PREPARED}}],
                          [{"object": {"sha": COMMIT}}, None, {"sha": TREE}, {"sha": PREPARED}, RuntimeError('branch exists')]):
            with self.subTest(responses=responses), patch.object(prepare, "api", side_effect=responses):
                with self.assertRaises((ValueError, RuntimeError)):
                    prepare.prepare(self.root)
                self.assertFalse(self.output.exists())

    def test_invalid_dispatch_ref_and_sha_refuse_before_api(self):
        for environment in ({"GITHUB_REF": "refs/heads/other"}, {"GITHUB_EVENT_NAME": "push"}, {"GITHUB_SHA": "bad"}):
            with self.subTest(environment=environment), patch.dict(os.environ, environment), patch.object(prepare, "api") as api:
                with self.assertRaises(ValueError):
                    prepare.prepare(self.root)
                api.assert_not_called()

    def test_git_lookup_errors_do_not_trigger_bumping(self):
        with patch.object(prepare, "git", side_effect=subprocess.CalledProcessError(1, 'git')), patch.object(prepare, "api") as api:
            with self.assertRaises(subprocess.CalledProcessError):
                prepare.prepare(self.root)
            api.assert_not_called()

    def test_api_failure_does_not_expose_response_or_credentials(self):
        error = urllib.error.HTTPError('https://example.invalid', 403, 'Forbidden', {}, io.BytesIO(b'synthetic-secret'))
        with patch.dict(os.environ, {"GH_TOKEN": "synthetic-secret"}), patch.object(prepare.urllib.request, "urlopen", side_effect=error):
            with self.assertRaises(RuntimeError) as raised:
                prepare.api('synthetic')
        self.assertNotIn('synthetic-secret', str(raised.exception))

    def test_only_a_404_counts_as_a_missing_candidate_branch(self):
        for status in (404, 403, 500):
            error = urllib.error.HTTPError('https://example.invalid', status, 'error', {}, io.BytesIO(b'{}'))
            with self.subTest(status=status), patch.dict(os.environ, {"GH_TOKEN": "synthetic"}), patch.object(prepare.urllib.request, "urlopen", side_effect=error):
                if status == 404:
                    self.assertIsNone(prepare.api('synthetic', missing_ok=True))
                else:
                    with self.assertRaises(RuntimeError):
                        prepare.api('synthetic', missing_ok=True)


if __name__ == "__main__":
    unittest.main()
