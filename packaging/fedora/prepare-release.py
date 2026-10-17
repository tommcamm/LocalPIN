#!/usr/bin/python3
"""Select an experimental release and, when needed, commit only its version bump."""
from datetime import datetime, timezone
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import tomllib
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("release_policy", Path(__file__).with_name("release-policy.py"))
policy = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(policy)
SHA = re.compile(r"[0-9a-f]{40}|[0-9a-f]{64}")


def git(root, *args):
    return subprocess.check_output(["git", "-c", f"safe.directory={root}", *args], cwd=root, text=True).strip()


def api(path, payload=None, *, missing_ok=False):
    request = urllib.request.Request(os.environ.get("GITHUB_API_URL", "https://api.github.com") + "/" + path,
                                     data=json.dumps(payload).encode() if payload is not None else None,
                                     headers={"Authorization": "Bearer " + os.environ["GH_TOKEN"],
                                              "Content-Type": "application/json", "Accept": "application/vnd.github+json",
                                              "X-GitHub-Api-Version": "2022-11-28"})
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            return json.load(response)
    except urllib.error.HTTPError as error:
        status = error.code
        error.close()
        if missing_ok and status == 404:
            return None
        # Never echo credential-bearing environments or server response bodies.
        raise RuntimeError(f"GitHub release preparation failed: HTTP {status}; check contents: write and release branch rules") from None


def next_version(version, tags):
    """Stay in the reviewed release channel and advance beyond all used sequences."""
    policy.release_identity(version)
    prefix, sequence = version.rsplit(".", 1)
    used = [int(sequence)]
    pattern = re.compile(re.escape("v" + prefix) + r"\.([1-9][0-9]*)")
    for tag in tags:
        match = pattern.fullmatch(tag)
        if match:
            used.append(int(match[1]))
    return f"{prefix}.{max(used) + 1}"


def replace_once(text, before, after):
    if text.count(before) != 1:
        raise ValueError(f"expected exactly one version field: {before}")
    return text.replace(before, after)


def bump_files(root, old, new, date):
    """Plan a bounded version-only edit without touching the checkout or Git refs."""
    policy.release_identity(new)
    if new.rsplit(".", 1)[0] != old.rsplit(".", 1)[0] or int(new.rsplit(".", 1)[1]) <= int(old.rsplit(".", 1)[1]):
        raise ValueError("automatic bumps must increase the sequence in the same base version and channel")
    workspace = tomllib.loads((root / "Cargo.toml").read_text())
    if workspace["workspace"]["package"]["version"] != old:
        raise ValueError("workspace version changed")
    manifests = ["Cargo.toml", "fuzz/Cargo.toml"]
    names = set()
    for member in workspace["workspace"]["members"]:
        if not re.fullmatch(r"crates/[a-z0-9-]+", member):
            raise ValueError("unsupported workspace member path")
        manifests.append(member + "/Cargo.toml")
        package = tomllib.loads((root / member / "Cargo.toml").read_text())["package"]
        if package.get("version") != {"workspace": True}:
            raise ValueError("workspace members must inherit the release version")
        names.add(package["name"])
    edits = {}
    for name in manifests:
        original = (root / name).read_text()
        data = tomllib.loads(original)
        # Every explicit path dependency must remain exactly pinned to this workspace.
        def validate(value):
            if isinstance(value, dict):
                if "path" in value and "version" in value and value["version"] != "=" + old:
                    raise ValueError(f"inconsistent local dependency version in {name}")
                for child in value.values():
                    validate(child)
        validate(data)
        updated = original.replace(f'"={old}"', f'"={new}"')
        if name == "Cargo.toml":
            updated = replace_once(updated, f'version = "{old}"', f'version = "{new}"')
        if updated != original:
            edits[name] = updated
    for name in ("Cargo.lock", "fuzz/Cargo.lock"):
        blocks = re.split(r"(?m)(?=^\[\[package\]\])", (root / name).read_text())
        found = set()
        for i, block in enumerate(blocks):
            if not block.startswith("[[package]]"):
                continue
            package = tomllib.loads(block)["package"][0]
            if package["name"] in names:
                if package.get("source") is not None or package["version"] != old:
                    raise ValueError(f"inconsistent local package in {name}")
                blocks[i] = replace_once(block, f'version = "{old}"', f'version = "{new}"')
                found.add(package["name"])
        expected = names if name == "Cargo.lock" else {"localpin-core", "localpin-protocol", "localpin-credentials"}
        if found != expected:
            raise ValueError(f"unexpected local package set in {name}")
        edits[name] = "".join(blocks)
    name = "tools/localpin-integration.py"
    edits[name] = replace_once((root / name).read_text(), f"'package_version': '{old}'", f"'package_version': '{new}'")
    name = "packaging/fedora/localpin.spec"
    spec = replace_once((root / name).read_text(), f"Release:        {policy.rpm_prefix(old)}%{{?dist}}",
                        f"Release:        {policy.rpm_prefix(new)}%{{?dist}}")
    entry = f"* {date.strftime('%a %b %d %Y')} LocalPIN contributors - {new.split('-')[0]}-{policy.rpm_prefix(new)}\n- Automated experimental release version update.\n\n"
    edits[name] = replace_once(spec, "%changelog\n", "%changelog\n" + entry)
    name = "CHANGELOG.md"
    changelog = (root / name).read_text()
    headings = list(re.finditer(r"(?m)^## +(?:\[Unreleased\]|Unreleased)\s*\n", changelog))
    if len(headings) != 1 or re.search(rf"(?m)^## +\[?{re.escape(new)}\]?(?:\s|$)", changelog):
        raise ValueError("expected one Unreleased section and no existing target version section")
    heading = headings[0]
    following = re.search(r"(?m)^## +", changelog[heading.end():])
    end = heading.end() + following.start() if following else len(changelog)
    body = changelog[heading.end():end].strip()
    if not re.search(r"(?m)^- +", body):
        body = f"- Experimental snapshot; see [changes since v{old}](https://github.com/tommcamm/LocalPIN/compare/v{old}...v{new})."
    edits[name] = changelog[:heading.start()] + f"## Unreleased\n\n## [{new}] - {date.isoformat()}\n\n{body}\n\n" + changelog[end:]
    return edits


def prepare(root=None):
    root = root or ROOT
    event_commit = os.environ.get("GITHUB_SHA", "")
    repository = os.environ.get("GITHUB_REPOSITORY", "")
    if (os.environ.get("GITHUB_REF") != "refs/heads/main"
            or os.environ.get("GITHUB_EVENT_NAME") != "workflow_dispatch"
            or not SHA.fullmatch(event_commit)
            or not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository)):
        raise ValueError("dispatch the release workflow from main")
    if git(root, "rev-parse", "HEAD") != event_commit or git(root, "status", "--porcelain", "--untracked-files=all"):
        raise ValueError("release preparation requires a clean checkout of the dispatched commit")
    version = tomllib.loads((root / "Cargo.toml").read_text())["workspace"]["package"]["version"]
    tag, _ = policy.release_identity(version)
    tags = git(root, "tag", "--list").splitlines()
    endpoint = f"repos/{repository}/git"
    current = api(endpoint + "/ref/heads/main")["object"]["sha"]
    if current != event_commit:
        raise ValueError("main advanced; start a new release run from current main")
    source = event_commit
    if tag in tags:
        new = next_version(version, tags)
        branch = f"codex/release-v{new}-{event_commit}"
        existing = api(endpoint + "/ref/heads/" + branch, missing_ok=True)
        candidate = api(endpoint + "/commits/" + existing["object"]["sha"]) if existing else None
        if candidate is not None and [parent["sha"] for parent in candidate["parents"]] != [event_commit]:
            raise ValueError("existing release branch has a different parent; refusing to overwrite it")
        if candidate:
            recorded = re.findall(r"(?m)^Release-Date: (\d{4}-\d{2}-\d{2})$", candidate["message"])
            if len(recorded) != 1:
                raise ValueError("existing release branch has no unique preparation date")
            date = datetime.fromisoformat(recorded[0]).date()
        else:
            date = datetime.now(timezone.utc).date()
        edits = bump_files(root, version, new, date)
        # Preserve each tracked file's executable bit; never create or edit a workflow.
        modes = {line.split("\t", 1)[1]: line.split()[0] for line in git(root, "ls-tree", "-r", "--full-tree", "HEAD").splitlines()}
        if any(modes.get(name) not in ("100644", "100755") for name in edits):
            raise ValueError("release version files must be tracked regular files")
        tree = api(endpoint + "/trees", {"base_tree": git(root, "rev-parse", "HEAD^{tree}"),
                    "tree": [{"path": name, "mode": modes[name], "type": "blob", "content": content} for name, content in sorted(edits.items())]})["sha"]
        if candidate is not None:
            if candidate["tree"]["sha"] != tree:
                raise ValueError("existing release branch has different changes; refusing to overwrite it")
            source = existing["object"]["sha"]
        else:
            source = api(endpoint + "/commits", {"message": f"chore(release): prepare {new}\n\nRelease-Date: {date.isoformat()}", "tree": tree, "parents": [event_commit]})["sha"]
            if not SHA.fullmatch(source):
                raise ValueError("invalid release commit from GitHub")
            updated = api(endpoint + "/refs", {"ref": "refs/heads/" + branch, "sha": source})
            if updated["object"]["sha"] != source:
                raise ValueError("release branch does not match the prepared commit")
        version = new
    tag, rpm_release = policy.release_identity(version)
    if tag in tags:
        raise ValueError("selected release tag is already used")
    with open(os.environ["GITHUB_OUTPUT"], "a") as output:
        output.write(f"tag={tag}\nrpm_release={rpm_release}\nsource_commit={source}\nbase_commit={event_commit}\n")
    print(f"Selected {tag} from {source}; CI, build and publication must use this exact commit")
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a") as summary:
            summary.write(f"## Prepared experimental release\n\n{tag}: [{source}](https://github.com/{repository}/commit/{source}), based on reviewed main [{event_commit}](https://github.com/{repository}/commit/{event_commit}).\n\nPublication requires all checks and RPM signing to pass.\n")


if __name__ == "__main__":
    prepare()
