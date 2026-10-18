# Fedora package and confinement contract

This is an experimental, project-distributed Fedora KDE 44 x86_64 RPM. Versioned
GitHub prereleases are signed; ordinary CI testing artifacts remain unsigned.
The current M8.1 implementation supports ordinary local account administration
and stable native PAM package updates through [ADR 0017](../../docs/adr/0017-shadow-record-account-authority.md)
and [ADR 0018](../../docs/adr/0018-kde-native-update-compatibility.md). Historical
[M8 acceptance](../../docs/development/m8-packaging-recovery.md) covers the earlier
immutable appliance. The
[M8.1 report](../../docs/development/m8.1-desktop-compatibility.md) and
[installed evidence](../../experiments/m81/results/installed-desktop-and-continuity.json)
record targeted Fedora 44 KDE cases that passed with SELinux enforcing and a
private TPM emulator. Actual DNF upgraded 26 packages and installed five kernel RPMs, native PAM/authselect
reinstallation replaced seven inodes, and compatible schema-2 RPM upgrades,
reboot/resume, desktop PIN/password and console recovery passed. Final source
checks and the compatible `.5` → `.6` RPM upgrade passed with exact protected-state
preservation and automatic restoration of prior activation; each earlier
installed case retains its recorded build scope in the report. GUI/DBus AccountsService, full
old-TPM-credential migration, alternate filesystems and physical devices remain
untested. M9 independent review and release gates remain open. Current hosted
build and test results are available in
[GitHub Actions](https://github.com/tommcamm/LocalPIN/actions/workflows/ci.yml);
package builds do not extend the recorded installed evidence.

## Versioned experimental releases

The maintainer can run the [manual release workflow](../../docs/releasing.md)
from `main` to select an unused experimental version and create a tagged GitHub
prerelease. When needed, it commits a version-only bump to a retained release
branch and tests and publishes that exact commit in the same run. It reruns CI
and includes source, an SPDX dependency inventory, provenance and
checksums, with required verified OpenPGP signing in the protected release
environment. Supported stable releases remain gated on independent M9 review
and hardware acceptance.

## Download a CI testing RPM

CI builds an experimental, unsigned RPM for Fedora KDE 44 x86_64 without
installing it. Use a disposable VM with SELinux enforcing and a recoverable
snapshot for testing. There is no supported production release.

1. Open the pull request's **Checks**, then the CI workflow run, or choose a run
   in [GitHub Actions](https://github.com/tommcamm/LocalPIN/actions/workflows/ci.yml).
2. Check the Fedora job result and the tested commit. Under **Artifacts**, download
   `localpin-fedora44-x86_64-<tested-commit>-<attempt>`; the Fedora job summary also
   links the download. GitHub requires sign-in, and artifacts expire after 14 days.
3. Extract the download. It contains the RPM, `BUILD-INPUTS.json`, `CI-BUILD.json`,
   and `SHA256SUMS`. In that directory, verify and inspect it:

   ```sh
   sha256sum --check SHA256SUMS
   cat CI-BUILD.json
   rpm -qpi ./localpin-*.x86_64.rpm
   rpm -qpl ./localpin-*.x86_64.rpm
   ```

`BUILD-INPUTS.json` matches the manifest embedded in the RPM and records native
artifact hashes, the Rust compiler, lockfile hash, and native package inputs.
`CI-BUILD.json` identifies the tested commit, workflow run, and RPM release.
Pull-request runs build GitHub's merge commit with the base branch; the PR head
commit is recorded separately. Checksums detect damaged or changed downloads;
they are not a package signature or independent security review. Artifacts from
unreviewed pull requests contain that pull request's code.

To install in the disposable Fedora KDE VM, from the extracted directory:

```sh
sudo dnf install ./localpin-*.x86_64.rpm
```

Installation leaves PIN integration disabled and starts no broker services.
From your own foreground KDE terminal, run:

```sh
localpin setup
```

The guide checks prerequisites, previews preparation and guides enrollment,
a timed trial, actual password/PIN tests, console recovery, fresh enrollment and
final activation. On a supported fresh installation, setup can perform the
one-time persistent-accounting migration after explicit approval to sign out
sessions and temporarily stop authentication. Setup resumes after password
login. Unsupported or interrupted state requires administrator recovery. The
[installation and recovery runbook](../../docs/integration-administration.md)
retains the complete manual administrator procedure. Record the tested commit
and package version with your results. The guided workflow requires fresh
installed acceptance; historical M8.1 evidence does not validate it.

CI derives its RPM release prefix from the committed Cargo workspace version:
for example, `0.1.0-alpha.2` uses `0.1.alpha2.ci.<run-number>.<attempt>`. Successive
workflow runs and reruns can upgrade earlier CI packages. This sequence does not
promise an upgrade from arbitrary historical fixtures, including `0.2.alpha1` or the
recorded `.5`/`.6` builds; start with a fresh disposable guest for those cases.
The artifact is a testing convenience, not a signed release or installed
desktop/hardware acceptance result.

## Build without installing

```sh
python3 packaging/fedora/build-rpm.py --output /tmp/localpin-rpm
```

The builder uses the pinned Rust toolchain and committed lockfile with
`--release --workspace --locked --offline`, checks native x86_64 ELF artifacts,
records hashes and RPM inputs in `BUILD-INPUTS.json`, compiles SELinux policy and
runs `rpmbuild -bb`. It never installs a package, loads policy or edits PAM.
Native inputs include TPM2-TSS 4.x and DBus development libraries, a C linker,
`rpm-build`, `checkpolicy`, `policycoreutils` and Python. An unpacked development
RPM root can be selected with `--native-sysroot PATH`. Dependencies must already
be cached. `--release 0.2.alpha1` produces a second compatible transaction fixture.

The binary source bundle includes crate/packaging sources and build metadata.
Fedora repository submission still requires a source-only recipe, Fedora Rust
packaging review, reproducible-build evaluation, dependency/SBOM review and
controlled signing. A successful local RPM build is not release certification.

## Installation and confinement

Installation supplies broker/workers, the root-only integration tool, the shared
`localpin` / `localpinctl` CLI, PAM
adapter, four fail-closed private PAM services, reviewed policy templates,
systemd units, tmpfiles rules, a disabled preset and SELinux policy. It starts
nothing and changes no KDE/authselect/faillock policy. `/usr/bin/localpin` is a
symlink to `localpinctl`; both names preserve the command interface. The RPM
requires sudo for the explicit foreground setup wizard and installs no sudoers
rule. The wizard uses absolute fixed paths, a closed operation set and no shell;
sudo handles its own password prompt and credential enrollment remains a
normal-user broker transaction. See [ADR 0019](../../docs/adr/0019-guided-setup-orchestration.md)
and the [administration runbook](../../docs/integration-administration.md).

The broker and each worker have distinct SELinux domains. Clients receive only
socket contact and public gate reads, with no credential, shadow, registry,
backup or TPM access. Only the backend can open the declared `/dev/tpmrm0`;
software-only deployments can install the supplied software unit override.
Native PAM children may transition to Fedora's maintained `chkpwd_t` expiry
helper. The broker retains read access to shadow for account-marker validation;
it cannot write account databases. The native `/etc/.pwd.lock` OFD reader needs
only a read-only descriptor and an SELinux lock permission.

The unit retains `NoNewPrivileges`, `ProtectSystem=strict`, separate writable
state/tally directories, no IP address families, bounded memory/processes and
core dumps disabled. `RestrictSUIDSGID` remains omitted because systemd 259's
filter conflicts with the required `openat2`; SELinux, capabilities and NNP
remain enforced. The only bounded capabilities are DAC read/search and native
PAM audit writes. Descendants cannot escape the supervised process group.

The two PAM workers can open existing native tallies read/write because
`pam_faillock preauth` uses that access mode. They cannot create, unlink, relabel
or change tally owner/mode. Eligibility verifies canonical preprovisioned
user:root 0660 files and compares their bytes/metadata around native checks.
This is a trusted-code invariant, not an assertion that SELinux prevents all
writes on that descriptor. Compile-only policy checks do not establish installed
permit/deny behavior; recorded targeted enforcing evidence is linked in the
[M8.1 report](../../docs/development/m8.1-desktop-compatibility.md). Physical
hardware and unseen policy changes need their own evidence.

## Updates and removal

Normal Fedora 44 `dnf upgrade` needs no account thaw or reseal. Fixed binary
hashes and filesystem snapshots no longer decide account identity. The native
PAM SONAME and root-owned installed files remain trusted distribution inputs;
unknown policy restrictions and incompatible ABIs fail closed.

Compatible LocalPIN upgrades use schema 2. The old tool checks RPM EVR/schema,
records suspension and stops services. The new low-priority transaction file
trigger waits for distribution cache triggers, validates unchanged registry,
credentials and throttles, and restores prior activation/service state. Disabled
or trial/prepared installations stay unactivated. There is no global `/etc`
immutable cache window. Private PAM services use `%config(noreplace)`. KDE's
files remain owned by plasma-workspace and are also `%config(noreplace)`; review
upstream `.rpmnew` changes before adopting new authentication semantics.

Final erase performs owned recovery and reference checks before removing the
tool, module or policy. Extra PAM references to the module or either owned KDE
substack refuse removal. Never force erase with `--noscripts`. Protected state,
tallies and backups are retained. The short console recovery command is:

```sh
sudo localpin-integration disable
```

Changed owned directives or missing/corrupt backups require a reviewed console
merge. Password fallback and actual recovery must be tested on the target VM or
hardware before activation; administrator attestation alone is not that proof.
