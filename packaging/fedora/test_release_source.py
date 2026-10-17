"""Release source checks use disposable Git repositories and synthetic files."""
import importlib.util
from pathlib import Path
import subprocess
from unittest.mock import patch
import unittest

from test_release_preparation import DATE, NEW, OLD, ReleaseFixture

SPEC = importlib.util.spec_from_file_location("verify_release_source", Path(__file__).with_name("verify-release-source.py"))
verifier = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(verifier)


class ReleaseSourceTests(ReleaseFixture):
    def setUp(self):
        super().setUp()
        self.git("init", "--initial-branch=main")
        (self.root / "tools/localpin-integration.py").chmod(0o755)
        self.code = self.root / "crates/localpin-core/source.rs"
        self.code.write_text("// Synthetic baseline code.\n")
        self.commit("Synthetic reviewed baseline")
        self.base = self.git("rev-parse", "HEAD")

    def git(self, *args):
        return subprocess.check_output(["git", "-c", f"safe.directory={self.root}",
                                        "-c", "user.name=Synthetic release tests",
                                        "-c", "user.email=synthetic@example.invalid", *args],
                                       cwd=self.root, text=True).strip()

    def commit(self, message):
        self.git("add", "--all")
        self.git("commit", "--quiet", "-m", message)
        return self.git("rev-parse", "HEAD")

    def write_release(self):
        for name, content in self.plan().items():
            (self.root / name).write_text(content)

    def test_exact_generated_child_and_unchanged_reviewed_source_are_accepted(self):
        verifier.verify_source(self.root, self.base, self.base, OLD)
        self.write_release()
        source = self.commit("Synthetic generated release")
        verifier.verify_source(self.root, self.base, source, NEW)
        self.assertEqual(self.git("status", "--porcelain", "--untracked-files=all"), "")
        self.assertEqual(self.git("rev-parse", "HEAD"), source)
        self.assertIn(DATE.isoformat(), (self.root / "CHANGELOG.md").read_text())

    def test_code_changes_or_extra_files_are_refused(self):
        self.write_release()
        self.code.write_text("// Unreviewed code change.\n")
        source = self.commit("Synthetic unexpected code")
        with self.assertRaisesRegex(ValueError, "version-only file set"):
            verifier.verify_source(self.root, self.base, source, NEW)
        self.git("reset", "--hard", self.base)
        self.write_release()
        (self.root / "unexpected").write_text("Synthetic extra file.\n")
        source = self.commit("Synthetic unexpected file")
        with self.assertRaisesRegex(ValueError, "preserve tracked paths"):
            verifier.verify_source(self.root, self.base, source, NEW)

    def test_other_content_in_a_version_file_is_refused(self):
        self.write_release()
        with (self.root / "tools/localpin-integration.py").open("a") as output:
            output.write("# Synthetic unreviewed change.\n")
        source = self.commit("Synthetic altered version file")
        with self.assertRaisesRegex(ValueError, "unexpected version-only content"):
            verifier.verify_source(self.root, self.base, source, NEW)

    def test_tracked_mode_changes_are_refused(self):
        self.write_release()
        (self.root / "tools/localpin-integration.py").chmod(0o644)
        source = self.commit("Synthetic altered executable mode")
        with self.assertRaisesRegex(ValueError, "file types and modes"):
            verifier.verify_source(self.root, self.base, source, NEW)

    def test_non_direct_or_merge_parents_are_refused(self):
        self.write_release()
        source = self.commit("Synthetic generated release")
        self.git("commit", "--allow-empty", "--quiet", "-m", "Synthetic extra parent")
        with self.assertRaisesRegex(ValueError, "exactly the reviewed main commit"):
            verifier.verify_source(self.root, self.base, self.git("rev-parse", "HEAD"), NEW)
        merge = self.git("commit-tree", self.git("rev-parse", f"{source}^{{tree}}"), "-p", source, "-p", self.base,
                         "-m", "Synthetic merge source")
        with self.assertRaisesRegex(ValueError, "exactly the reviewed main commit"):
            verifier.verify_source(self.root, self.base, merge, NEW)

    def test_missing_or_duplicate_target_changelog_headings_are_refused(self):
        for replacement in ("## [unknown] - 2026-10-17", "## [0.1.0-alpha.2] - 2026-10-17\n## [0.1.0-alpha.2] - 2026-10-18"):
            self.git("reset", "--hard", self.base)
            self.write_release()
            changelog = self.root / "CHANGELOG.md"
            changelog.write_text(changelog.read_text().replace("## [0.1.0-alpha.2] - 2026-10-17", replacement))
            source = self.commit("Synthetic invalid changelog")
            with self.subTest(replacement=replacement), self.assertRaisesRegex(ValueError, "exactly one dated"):
                verifier.verify_source(self.root, self.base, source, NEW)

    def test_non_commit_arguments_are_refused_before_git(self):
        for base, source in (("main", self.base), (self.base, "HEAD")):
            with self.subTest(base=base, source=source), patch.object(verifier, "_git") as git:
                with self.assertRaisesRegex(ValueError, "full reviewed base"):
                    verifier.verify_source(self.root, base, source, NEW)
                git.assert_not_called()


if __name__ == "__main__":
    unittest.main()
