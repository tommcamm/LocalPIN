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
   separate publication job signs the RPM and checksums, verifies their
   signatures, creates an annotated tag at the tested commit, uploads all assets
   to a draft, then publishes it as an experimental prerelease with `latest=false`.

The workflow has no push/tag trigger and accepts dispatches only from `main`.
Build/check jobs have read-only repository access and no signing secrets. Only
the separate publication job has `contents: write`. The repository's Actions
policy must permit that requested permission and tag/release creation; repository
rules may impose additional restrictions. The built-in `GITHUB_TOKEN` is enough;
no personal access token is required.

Each release contains:

- The Fedora 44 x86_64 RPM and a committed-source archive.
- `BUILD-INPUTS.json`, matching the manifest inside the RPM: compiler, lockfile,
  native input versions and hashes of the shipped native files.
- `RELEASE.json`: exact source commit, workflow run, target, RPM identity/digest
  and final signing status/fingerprint.
- `SBOM.spdx.json`: SPDX 2.3 inventory of the resolved default-feature Cargo
  target graph, locked registry checksums and dependency relationships, plus the
  installed native builder RPM inventory. Development/build inputs can appear;
  this is not a minimal runtime closure or independent license review.
- `NATIVE-RPMS.json`, release notes and `SHA256SUMS`.
- `RPM-GPG-KEY-LocalPIN` and the detached checksum signature `SHA256SUMS.asc`.

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

Every experimental GitHub prerelease requires verified OpenPGP signatures on
the RPM and checksum file. Supported releases also require signed RPMs under the
project specification and M9 plan. Ordinary CI testing artifacts remain unsigned
and separate from releases. SHA256 checksums detect changed downloads; they do
not authenticate the publisher.
An RPM OpenPGP signature authenticates a package to a separately trusted key;
it does not establish that the software passed independent review. GitHub build
attestations, if added later, would be additional provenance rather than an RPM
signature. See the [RPM signing manual](https://rpm.org/docs/6.0.x/man/rpmsign.1).

The maintainer must choose and control the signing identity. Do not commit key
material or paste it into issues, PRs, workflow inputs or logs. Prefer keeping a
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
final signed package and updates the SBOM digest before signing the checksum
file. The embedded `BUILD-INPUTS.json` intentionally
keeps `signed: false` because it describes the pre-sign build;
`RELEASE.json.signing` describes the final distributed RPM.

Publish the public key fingerprint through a maintainer-controlled trusted
channel and document key rotation/revocation before asking others to trust it.
A public key downloaded beside an RPM alone does not establish that trust.
No maintainer signing identity or environment secrets are created by this change.

## Verify and test a download

Download assets from the intended tagged prerelease and read `RELEASE.json`.
Its signing status must be `true`. First compare the public key's full
fingerprint with the maintainer's separately trusted fingerprint:

```sh
gpg --show-keys --with-fingerprint RPM-GPG-KEY-LocalPIN
gpg --import RPM-GPG-KEY-LocalPIN
gpg --verify SHA256SUMS.asc SHA256SUMS
sha256sum --check SHA256SUMS
sudo rpmkeys --import RPM-GPG-KEY-LocalPIN
rpmkeys --checksig --verbose ./localpin-*.x86_64.rpm
```

Use a disposable Fedora KDE 44 VM with SELinux enforcing and a recoverable
snapshot first. Installation leaves the broker stopped and integration disabled.
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
