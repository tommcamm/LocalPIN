# Experimental Fedora releases

The [Experimental release workflow](../.github/workflows/release.yml) creates a
versioned GitHub prerelease with a signed native Fedora KDE 44 x86_64 RPM. M9 is in
progress: independent specialist review, physical hardware validation and the
other [readiness gates](development/m9-release-readiness.md) remain open. The
workflow refuses stable versions. Publishing a prerelease does not close M9.

## Run the manual job

After the release workflow is reviewed and merged into `main`:

1. Review `Cargo.toml`'s workspace version and `CHANGELOG.md` on `main`. The
   initial version is `0.1.0-alpha.1`; a new release needs a new version committed
   through a PR, including workspace dependency versions and `Cargo.lock` where
   applicable. Only `alpha.N`, `beta.N` and `rc.N` versions are accepted.
2. Configure the `release` environment's signing credentials below before the
   first release. Open **Actions → Experimental release → Run workflow**, select
   **main**, and run it. Signing is required for every release; there is no
   signing toggle. No tag input is needed: the job derives
   `v0.1.0-alpha.1` from the committed version and builds the dispatched commit.
3. The job reruns the complete CI workflow, then tests the shipping default
   feature set and builds a fresh RPM in Fedora 44. It does not install or
   activate LocalPIN. All checks must pass before publication is possible.
4. Approve the `release` environment if its protection rules require it. The
   separate publication job signs the RPM and full evidence checksums, verifies
   their signatures, retains the evidence as a workflow artifact, creates an
   annotated tag at the tested commit, uploads the RPM and its checksum file
   to a draft, then publishes it as an experimental prerelease with `latest=false`.
   Before publishing, it checks the draft's description and complete asset list;
   afterward it verifies the public prerelease and prints its URL in the job
   summary. The release appears on the repository's
   [GitHub Releases page](https://github.com/tommcamm/LocalPIN/releases).

The workflow has no push/tag trigger and accepts dispatches only from `main`.
Build/check jobs have read-only repository access and no signing secrets. Only
the separate publication job has `contents: write`. The repository's Actions
policy must permit that requested permission and tag/release creation; repository
rules may impose additional restrictions. The built-in `GITHUB_TOKEN` is enough;
no personal access token is required.

Each GitHub release has two uploaded assets: the signed Fedora 44 x86_64 RPM and
`SHA256SUMS`, containing only that RPM's checksum. The description links the
[repository public signing key](../packaging/fedora/RPM-GPG-KEY-LocalPIN) at the
release's source commit and the workflow run containing its build evidence.

The publication job retains the full signed bundle in the workflow artifact
`release-evidence-$GITHUB_SHA-$GITHUB_RUN_ATTEMPT` for 90 days. Download it from the
linked run's **Artifacts** section while it remains available; archive a copy for
longer-term review. It contains:

- The signed RPM and a committed-source archive.
- `BUILD-INPUTS.json`, matching the manifest inside the RPM: compiler, lockfile,
  native input versions and hashes of the shipped native files.
- `RELEASE.json`: exact source commit, workflow run, target, RPM identity/digest
  and final signing status/fingerprint.
- `SBOM.spdx.json`: SPDX 2.3 inventory of the resolved default-feature Cargo
  target graph, locked registry checksums and dependency relationships, plus the
  installed native builder RPM inventory. Development/build inputs can appear;
  this is not a minimal runtime closure or independent license review.
- `NATIVE-RPMS.json`, release notes and a full-bundle `SHA256SUMS`.
- `RPM-GPG-KEY-LocalPIN` and the full-bundle checksum signature `SHA256SUMS.asc`.

The evidence artifact's checksum file covers all evidence files and differs from
the RPM-only checksum attached to the release. Keep the downloads in separate
directories.

The initial RPM release is `0.1.alpha1.release.fc44`, above the same-version
`0.1.alpha1.ci.*` testing packages in RPM ordering. Subsequent alpha versions use
`0.1.alphaN.release`, beta versions `0.2.betaN.release`, and release candidates
`0.3.rcN.release`, followed by `.fc44`. Same-version CI packages are not newer
than the release RPM. These values do not promise an upgrade from arbitrary
historical fixtures; inspect the installed EVR and use a fresh VM when needed.

Existing tags/releases and their assets are never replaced. If publication
fails after tag creation, inspect that run and the tag/draft manually; rerunning
refuses the existing tag. A failure while uploading leaves a draft for inspection.
Do not move published tags or use asset clobbering. Repair a public release with
a new version and a corrective release. Source and RPM builds are traceable but
are not yet certified reproducible builds.

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
release job's `contents: write` permission and repository rules. A
[workflow rerun](https://docs.github.com/en/actions/how-tos/manage-workflow-runs/re-run-workflows-and-jobs)
keeps the original commit and ref. To use a workflow fix merged into `main`,
start a new manual run on `main`; retrying an old job does not load the new code.

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
