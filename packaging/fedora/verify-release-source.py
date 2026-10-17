#!/usr/bin/python3
"""Independently verify a generated release commit against its reviewed base."""
from datetime import date
import importlib.util
import io
from pathlib import Path
import re
import subprocess
import tarfile
import tempfile
import tomllib

SPEC = importlib.util.spec_from_file_location("release_preparation", Path(__file__).with_name("prepare-release.py"))
preparation = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(preparation)
SHA = re.compile(r"[0-9a-f]{40}|[0-9a-f]{64}")


def _git(root, *args):
    return subprocess.check_output(["git", "-c", f"safe.directory={root}", *args], cwd=root)


def _tree(root, commit):
    entries = {}
    for entry in _git(root, "ls-tree", "-r", "-z", "--full-tree", commit).split(b"\0"):
        if entry:
            metadata, path = entry.split(b"\t", 1)
            mode, kind, _ = metadata.split()
            entries[path.decode("utf-8")] = (mode, kind)
    return entries


def verify_source(root, base, source, version):
    """Allow the reviewed commit or its exact generated, version-only child."""
    root = Path(root).resolve()
    if not SHA.fullmatch(base) or not SHA.fullmatch(source):
        raise ValueError("full reviewed base and release source commits required")
    preparation.policy.release_identity(version)
    if source == base:
        return
    parents = _git(root, "rev-list", "--parents", "-n", "1", source).decode("ascii").split()
    if parents != [source, base]:
        raise ValueError("generated release source must have exactly the reviewed main commit as its parent")
    base_tree, source_tree = _tree(root, base), _tree(root, source)
    if base_tree != source_tree:
        raise ValueError("generated release source must preserve tracked paths, file types and modes")
    changelog = _git(root, "show", f"{source}:CHANGELOG.md").decode("utf-8")
    headings = re.findall(rf"(?m)^## \[{re.escape(version)}\] - ([0-9]{{4}}-[0-9]{{2}}-[0-9]{{2}})[ \t]*$", changelog)
    if len(headings) != 1:
        raise ValueError("generated release source needs exactly one dated target changelog heading")
    release_date = date.fromisoformat(headings[0])
    # The archive is data only: do not check out or execute the reviewed source.
    with tempfile.TemporaryDirectory(prefix="localpin-release-source-") as temporary:
        baseline = Path(temporary)
        with tarfile.open(fileobj=io.BytesIO(_git(root, "archive", "--format=tar", base))) as archive:
            archive.extractall(baseline, filter="data")
        old_version = tomllib.loads((baseline / "Cargo.toml").read_text())["workspace"]["package"]["version"]
        edits = preparation.bump_files(baseline, old_version, version, release_date)
    changed = {path.decode("utf-8") for path in _git(root, "diff", "--no-ext-diff", "--no-textconv", "--no-renames", "--name-only", "-z", base, source, "--").split(b"\0") if path}
    if changed != set(edits):
        raise ValueError("generated release source differs from the exact version-only file set")
    for name, expected in edits.items():
        if base_tree.get(name) not in ((b"100644", b"blob"), (b"100755", b"blob")):
            raise ValueError("generated release metadata must use tracked regular files")
        if _git(root, "show", f"{source}:{name}") != expected.encode("utf-8"):
            raise ValueError(f"generated release source has unexpected version-only content in {name}")
