# Experimental Fedora releases

The [Experimental release workflow](../.github/workflows/release.yml) creates a
versioned GitHub prerelease with a signed native Fedora KDE 44 x86_64 RPM. M9 is in
progress: independent specialist review, physical hardware validation and the
other [readiness gates](development/m9-release-readiness.md) remain open. The
workflow refuses stable versions. Publishing a prerelease does not close M9.

## Run the manual job

After the release workflow is reviewed and merged into `main`:

1. Review `CHANGELOG.md` on `main` and record new changes under `Unreleased`.
   The workflow reads the workspace version from `Cargo.toml`; only `alpha.N`,
   `beta.N` and `rc.N` versions are accepted. An unused committed version can
   release directly. If its tag already exists, the workflow automatically
   advances to the next unused number in the same prerelease channel.
2. Configure the `release` environment's signing credentials below before the
   first release. Open **Actions → Experimental release → Run workflow**, select
   **main**, and run it. Signing is required for every release; there is no
   signing toggle. No tag or version input is needed.
3. If a bump is needed, the preparation job updates the manifests, pinned
   workspace dependency versions, both lockfiles, RPM defaults and integration
   helper's package version together, and moves `Unreleased` changes into the
   new version's changelog section. It commits those generated changes to
   `codex/release-v<version>-<reviewed-main-commit>`, directly above the reviewed
   `main` commit. The
   version-only release commit can be published without merging, under the
   narrow release-automation exception to the ordinary PR workflow.
4. The same run reruns the complete CI workflow, then tests the shipping default
   feature set and builds a fresh RPM in Fedora 44. Every check, source archive,
   RPM and release uses the exact resulting source commit, including the version
   bump when one was made. It does not install or activate LocalPIN. All checks
   must pass before publication is possible.
5. Approve the `release` environment if its protection rules require it. The
   separate publication job signs the RPM and full evidence checksums, verifies
   their signatures, retains the evidence as a workflow artifact, creates an
   annotated tag at the tested commit, uploads the RPM and its checksum file
   to a draft, then publishes it as an experimental prerelease with `latest=false`.
   Before publishing, it checks the draft's description and complete asset list;
   afterward it verifies the public prerelease and prints its URL in the job
   summary. The release appears on the repository's
   [GitHub Releases page](https://github.com/tommcamm/LocalPIN/releases).

The workflow has no push/tag trigger and accepts dispatches only from `main`.
Build/check jobs have read-only repository access and no signing secrets. The
separate preparation job has `contents: write` to create the release branch and
generated version metadata; it has no release environment or signing
credentials. The separate publication job has `contents: write` for tag/release
creation. The built-in `GITHUB_TOKEN` is sufficient when repository rules permit
these operations; no personal access token is required.

Preparation requires the dispatched commit to remain the current `main` head.
The generated source commit is its direct child. A retry can reuse only the
exact candidate with the same parent and generated file contents; a different
existing branch stops preparation. Publication verifies that the reviewed base
remains on `main` and the source commit is that base or its generated direct
child. CI, building, signing and publication all use the selected source commit.

The release branch is retained for inspection. Development on `main` keeps its
committed version until a deliberate base-version or channel change is reviewed;
future release runs select the next number above existing same-channel tags.
There is no version synchronization PR to prepare after each release. Ordinary
development continues through reviewed PRs, and the release workflow never
pushes to `main`, force-pushes or merges PRs.

Each GitHub release has two uploaded assets: the signed Fedora 44 x86_64 RPM and
`SHA256SUMS`, containing only that RPM's checksum. The description links the
[repository public signing key](../packaging/fedora/RPM-GPG-KEY-LocalPIN) at the
release's source commit and the workflow run containing its build evidence.

The publication job retains the full signed bundle in the workflow artifact
`release-evidence-<source-commit>-<run-attempt>` for 90 days. Download it from the
linked run's **Artifacts** section while it remains available; archive a copy for
longer-term review. It contains:

- The signed RPM and a committed-source archive.
- `BUILD-INPUTS.json`, matching the manifest inside the RPM: compiler, lockfile,
  native input versions and hashes of the shipped native files.
- `RELEASE.json`: exact `source_commit`, `reviewed_main_commit`, workflow run,
  target, RPM identity/digest and final signing status/fingerprint.
- `SBOM.spdx.json`: SPDX 2.3 inventory of the resolved default-feature Cargo
  target graph, locked registry checksums and dependency relationships, plus the
  installed native builder RPM inventory. Development/build inputs can appear;
  this is not a minimal runtime closure or independent license review.
- `NATIVE-RPMS.json`, release notes and a full-bundle `SHA256SUMS`.
- `RPM-GPG-KEY-LocalPIN` and the full-bundle checksum signature `SHA256SUMS.asc`.

The evidence artifact's checksum file covers all evidence files and differs from
the RPM-only checksum attached to the release. Keep the downloads in separate
directories.

The alpha.2 RPM release is `0.1.alpha2.release.fc44`, above the same-version
`0.1.alpha2.ci.*` testing packages in RPM ordering. Alpha versions use
`0.1.alphaN.release`, beta versions `0.2.betaN.release`, and release candidates
`0.3.rcN.release`, followed by `.fc44`. Same-version CI packages are not newer
than the release RPM. These values do not promise an upgrade from arbitrary
historical fixtures; inspect the installed EVR and use a fresh VM when needed.

Existing tags/releases and their assets are never replaced. If publication
fails after tag creation, inspect that run and the tag/draft manually. A failure
while uploading leaves a draft for inspection. A new release run advances to a
new version when the committed tag already exists; it does not repair the old
draft. Do not move published tags or use asset clobbering. Repair a public release
with a new version and a corrective release. Source and RPM builds are traceable but
are not yet certified reproducible builds.

## Retry a failed release

An existing `v0.1.0-alpha.1` means that version has already been used. A new
manual run on current `main` advances to the next unused version, commits the
matching metadata on its release branch and continues to checks and publication.
Existing tags and release assets remain intact. A Git lookup failure stops the
job; it is not treated as permission to select another version.

If CI, building or signing fails after the automatic version commit, that commit
remains on its release branch. A retry reuses that candidate only when its parent
and generated contents match exactly. If publication already created a tag,
inspect the tag/draft; the next new release run selects a new version. Different
contents on an existing candidate branch require maintainer inspection; the
workflow never replaces it or silently changes the release source.

If `main` has advanced since dispatch, start a new run from current `main`.
Preparation refuses the stale dispatch rather than using an outdated base.
To change the base version or advance from alpha to beta or rc, prepare that
deliberate version change through a separate reviewed PR.

A [workflow rerun](https://docs.github.com/en/actions/how-tos/manage-workflow-runs/re-run-workflows-and-jobs)
keeps the original event commit and ref. Start a new manual run to use current
source and workflow code. The release evidence records both the reviewed main
commit and the actual source commit, which differs from the event's original
`GITHUB_SHA` when an automatic version bump was made.

## Configure RPM signing

Every experimental GitHub prerelease requires a verified embedded OpenPGP
signature on the RPM. The full evidence bundle's checksum file is also signed
and verified before publication; that detached signature remains in the workflow
artifact. Supported releases also require signed RPMs under the
project specification and M9 plan. Ordinary CI testing artifacts remain unsigned
and separate from releases. SHA256 checksums detect changed downloads; they do
not authenticate the publisher.
An RPM OpenPGP signature authenticates a package to a separately trusted key;
it does not establish that the software passed independent review. GitHub build
attestations, if added later, would be additional provenance rather than an RPM
signature. See the [RPM signing manual](https://rpm.org/docs/6.0.x/man/rpmsign.1).

The maintainer must choose and control the signing identity. Never commit private
key material or paste it into issues, PRs, workflow inputs or logs. The repository
contains only the public verification key. Prefer keeping a
primary key offline and using a dedicated release signing subkey with a rotation
and revocation procedure. The workflow imports the supplied secret material into
a temporary GnuPG home, checks its primary fingerprint, signs the RPM, verifies
it in a separate temporary RPM database, and removes the temporary keyring.

In **Settings → Environments**, create `release`. Restrict deployment branches
to `main`; configure required reviewer protection where your GitHub plan supports
it. Put signing credentials in this environment, never repository-wide PR CI:

| Environment setting | Value |
| --- | --- |
| Secret `RPM_SIGNING_KEY` | ASCII-armored private signing key/subkey export containing exactly one primary identity |
| Secret `RPM_SIGNING_PASSPHRASE` | Passphrase for that export; may be empty for an unprotected dedicated CI key |
| Variable `RPM_SIGNING_FINGERPRINT` | Full primary OpenPGP fingerprint, 40 or 64 hex digits, without spaces |

An encrypted, dedicated key is preferable. The passphrase and key are both
available to an approved signing job, so environment access and workflow review
remain part of the trust boundary. If key setup or signature verification fails,
the job stops before creating a tag or release; it never falls back to publishing
an unsigned RPM. Publication independently requires a signed bundle and verifies
both signatures before making changes on GitHub. The signing job hashes the
final signed package and updates the SBOM digest before signing the evidence
checksum file. The embedded `BUILD-INPUTS.json` intentionally
keeps `signed: false` because it describes the pre-sign build;
`RELEASE.json.signing` describes the final distributed RPM.

Publish the public key fingerprint through a maintainer-controlled trusted
channel and document key rotation/revocation before asking others to trust it.
A public key downloaded from the same project alone does not establish that trust.
When rotating the release identity, update the repository public key through a
reviewed PR together with the signing environment configuration.

## Troubleshoot signing setup

A failure while checking the imported fingerprint happens before passphrase
verification. The error reports only public primary fingerprints and distinguishes
a mismatched key from an export with no usable private signing material.

Check the dedicated key directory locally:

```sh
gpg --homedir "$localpin_key_dir" --list-keys --with-subkey-fingerprint
```

The recommended key has a certification primary `[C]` and a signing subkey `[S]`.
If it has only `[C]`, add a signing subkey before exporting:

```sh
gpg --homedir "$localpin_key_dir" --quick-add-key "$localpin_fpr" rsa4096 sign 1y
```

Set those variables to your dedicated key directory and its full primary
fingerprint first. After creating the subkey, export again using
`--armor --export-secret-subkeys "$localpin_fpr"` and replace the `release`
environment's `RPM_SIGNING_KEY`. Set `RPM_SIGNING_PASSPHRASE` to the signing
subkey's passphrase, and keep `RPM_SIGNING_FINGERPRINT` equal to the primary
fingerprint from that same export. Exporting secret subkeys from a certification
key with no subkeys can produce a stub-only export with no signing capability;
it cannot be used for releases. Never paste private exports or passphrases into
an issue, PR or workflow input.

For GitHub API HTTP 403 failures, inspect the reported server reason and the
release job's `contents: write` permission and repository rules. To use a workflow
fix merged into `main`, start a new manual run on `main`; retrying an old job does
not load the new code.

## Verify and test a download

In a disposable Fedora KDE 44 VM, download the RPM and `SHA256SUMS` from the
intended tagged prerelease. Download `RPM-GPG-KEY-LocalPIN` using the public key
link in that release's description. First compare the key's full fingerprint
with the maintainer's separately trusted fingerprint:

```sh
gpg --show-keys --with-fingerprint RPM-GPG-KEY-LocalPIN
sha256sum --check SHA256SUMS
sudo rpmkeys --import RPM-GPG-KEY-LocalPIN
rpmkeys --define '_pkgverify_level signature' --checksig --verbose ./localpin-*.x86_64.rpm
```

The release's checksum file is not separately signed. Require a valid RPM
signature from the trusted key; checksum success alone does not authenticate
the package.

For optional provenance review, download and unpack `release-evidence-*` from
the linked workflow run within 90 days. In that separate evidence directory,
check that `RELEASE.json.signing.signed` is `true` and the source commit and
signing fingerprint match the intended release. After checking the public key
against the separately trusted fingerprint, verify the full bundle:

```sh
gpg --import RPM-GPG-KEY-LocalPIN
gpg --verify SHA256SUMS.asc SHA256SUMS
sha256sum --check SHA256SUMS
```

Use SELinux enforcing and a recoverable snapshot for installation testing.
Installation leaves the broker stopped and integration disabled.
Follow the [installation and recovery runbook](integration-administration.md)
for the required persistent native faillock setup, account preparation,
enrollment, timed trial, real password/console recovery and explicit activation.
Use the [M9 matrix](development/m9-release-readiness.md) for candidate-bound
acceptance. Physical hardware requires its own noncritical test machine and
evidence; do not use the everyday machine or its physical TPM as a fault fixture.

## Before a supported release

Complete the [M9 checklist](development/m9-release-readiness.md), resolve blocking
findings, freeze record/protocol contracts, establish a maintained private
reporting channel and supported-version policy, and obtain independent review
and final-candidate physical acceptance. Then review a separate change enabling
supported releases and enforcing those evidence gates. A successful signed
prerelease cannot substitute for those requirements.
