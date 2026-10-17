# Changelog

Changes are recorded here before versioned releases. See
[GitHub Releases](https://github.com/tommcamm/LocalPIN/releases) for published
experimental builds.

## Unreleased

## [0.1.0-alpha.2] - 2026-10-17

### Added

- Primary `localpin` CLI alias and inline terminal menu with guided
  `localpin setup`: readiness checks, preparation preview, explicit backend
  enrollment, trial/recovery guidance, resume and final activation. Privileged
  steps use a fixed sudo/helper interface with transaction-scoped single-account
  guards; secrets keep the existing private broker path. Existing `localpinctl`
  commands and status/doctor JSON stay compatible. Persistent accounting still
  requires an offline maintenance handoff and real recovery revokes enrollment.
  [ADR 0019](docs/adr/0019-guided-setup-orchestration.md) defines the boundary;
  new installed onboarding acceptance and all M9 gates remain outstanding.
- Isolated coverage-guided fuzz targets, native instrumentation harnesses,
  dependency policy and recorded component validation for M9. See the
  [review and validation report](docs/development/m9-review-validation.md) for
  the tested candidate and limits; independent review and physical hardware
  acceptance remain open.

### Fixed

- Guided setup can enroll a new PIN after own-user disable while preserving
  active desktop integration. Native account administration now shares the
  integration transaction lock, preventing concurrent provisioning from
  invalidating setup's single-account scope check before mutation.

### Changed

- The manual release workflow bumps an already-tagged experimental version,
  commits matching manifests, lockfiles, RPM defaults and integration metadata
  to a release branch, then tests and publishes that exact commit in the same run.
  The generated version-only commit records its reviewed `main` parent; existing
  tags and release assets stay intact. CI derives its testing RPM sequence from
  the committed workspace version.

- Report missing private signing material separately from mismatched public
  primary fingerprints. Release descriptions include features, selected changes,
  verification/recovery guidance and source/run links; publication verifies the
  draft description and assets, then reports the verified public release URL.
- Publish the signed RPM and its checksum as the two release downloads, with
  full signed build evidence retained in the workflow artifact for 90 days.
- Focus the README and setup documentation on installation, guided setup and
  everyday use, with explicit recovery and experimental-readiness limits.

## [0.1.0-alpha.1] - 2026-10-17

### Added

- Manual main-only experimental GitHub prereleases for Fedora KDE 44 x86_64,
  gated on CI, with RPM/source assets, SPDX dependency/native inventory,
  provenance/checksums and mandatory verified OpenPGP signing. Stable publication
  remains disabled while M9 gates are open. See [release instructions](docs/releasing.md).
- M9 requirement-to-evidence checklist and independent review/hardware runbook;
  deterministic record/stream adversarial campaigns and exhaustive verification
  state-model traces. These do not complete independent review, coverage-guided
  fuzzing, native instrumentation or physical hardware acceptance.

- Downloadable unsigned Fedora 44 x86_64 CI testing RPMs with build provenance,
  SHA256 checksums, 14-day retention, and a versioned release sequence for testing
  successive CI upgrades. See the [artifact guide](packaging/fedora/README.md#download-a-ci-testing-rpm).
- M8.1 ordinary Fedora KDE 44 x86_64 compatibility: native shadow-record
  account markers and account-tool locking replace the global immutable
  appliance; Linux-PAM's stable ABI replaces reference-build fingerprints.
  KDE-specific password/fingerprint substacks correct unavailable-sensor
  accounting and password success resets. Dynamic policy guards preserve
  additional native authentication factors and missing-module fallback.
  Compatible RPM updates retain activation, enrollment and attempt history.
  See [ADR 0017](docs/adr/0017-shadow-record-account-authority.md),
  [ADR 0018](docs/adr/0018-kde-native-update-compatibility.md) and
  [M8.1 evidence](docs/development/m8.1-desktop-compatibility.md).
- M8 native Fedora RPM packaging, systemd/SELinux confinement definitions,
  staged root prepare/trial/attest/activate gate, owned-block console recovery,
  compatible upgrade suspension/resume and removal reference checks. The
  49-case installed matrix passed on the restricted Fedora 44 x86_64 Btrfs
  appliance with SELinux enforcing and a private TPM emulator, retaining
  enrollment through reboot and interrupted cache-window recovery. Evidence is
  in the [M8 report](docs/development/m8-packaging-recovery.md); see
  [ADR 0015](docs/adr/0015-m8-activation-and-rpm.md),
  [ADR 0016](docs/adr/0016-package-cache-window.md) and the
  [administration runbook](docs/integration-administration.md).
- Exact persistent native faillock policy for M8 activation, retaining the
  legacy volatile component variant and refusing missing accounting state.
  [ADR 0014](docs/adr/0014-persistent-faillock.md) records the one-time offline
  transition and reboot continuity contract. M8 refused the known parallel
  fingerprint/faillock composition; M8.1 supersedes that refusal with reviewed
  KDE-specific accounting.
- Explicit exact-block legacy migration before fresh sealing/enrollment,
  without importing old verifiers; CLI status distinguishes trial from active
  integration and operator-attested tests from automatic evidence.
- Specification 1.4 records M8's persistent accounting, guarded activation,
  installed recovery paths and bounded compatible-upgrade authority window.
- M7 `localpin-pam` Rust cdylib: fresh byte-preserving PAM candidates, own-user
  KDE identity checks, authenticated durable broker grants, absolute software/TPM
  deadlines, panic containment and C allocator cleanup. Exact reviewed KDE policy
  compatibility is defined by [ADR 0013](docs/adr/0013-pam-unlock-contract.md).
  Passing native tests and required enforcing-KDE PIN/password/fault cases,
  guarded fixtures and explicit native recovery limits are recorded in
  the [M7 report](docs/development/m7-pam-integration.md).
- M6.1 production account lifecycle authority for the explicitly provisioned
  Fedora 44 x86_64 Btrfs appliance domain: durable opaque incarnations,
  revocation before account mutation, kernel immutable flags and writer-drain
  leases, privileged disabled-baseline provisioning and crash recovery.
- Password-free eligibility for the exact reviewed Fedora policy, strict
  SHA512-crypt/default yescrypt support, unchanged password failure accounting,
  and actionable lifecycle/eligibility status. M6.1's component gate is complete
  for this domain, including real-account flows, policy/accounting, lifecycle
  mutation/bypass, crash/reboot and four exact-point concurrency tests. See the
  [M6.1 report](docs/development/m6.1-account-authorities.md),
  [sanitized results](experiments/m61/results/2026-10-17-account-authorities.json) and
  [ADR 0012](docs/adr/0012-immutable-appliance-account-authority.md).
- M6 `localpin-auth` disposable password-only PAM worker and bounded supervisor,
  plus `localpinctl` terminal enrollment, change, disable, explicit migration,
  root recovery and versioned nonsecret doctor/status output.
- Connection-bound password grants, staged native backend creation/trial and
  durable generation commits; isolated failure/replay/cancellation regressions.
  [M6 evidence and remaining gates](docs/development/m6-enrollment-cli.md).
- M5 `localpind` broker with kernel-authenticated Unix sockets, strict socket
  activation, typed clients, live logind routing and socket-bound process identity;
  [M5 evidence report](docs/development/m5-bounded-broker.md).
- One-operation software/TPM worker with private bounded IPC, response deadlines,
  cancellation, asynchronous reaping and retained resource leases; durable
  reservation/completion and delivery under the M3 revocation lock. Prototype
  systemd units remain uninstalled.
- Native IPC, peer/session, cancellation/replay, capacity and stalled worker
  regressions; explicit fail-closed production account authority.
- M4 `localpin-credentials` with bounded canonical Argon2id-v19 PHC records,
  OS entropy, charged and zeroizing KDF memory, fixed vectors and a local benchmark.
- `localpin-tpm` with the pinned `tss-esapi` construction, validated public
  identities, protected sessions, shared DA-budget admission and disposable
  simulator tests; backend outcomes retain M2's durable completion boundary.
- Real software/backend storage tests for staged enrollment, reservation and
  success persistence failures, rotation and revocation; dependency review and
  [M4 evidence report](docs/development/m4-credential-backends.md).
- M3 `localpin-storage` crate with protected descriptor-relative Linux files,
  stable broker/per-UID locks, durable M2 throttle updates, staged credential
  generations, atomic revocation pointers and bounded generation recovery.
- Storage persistence-fault, crash/restart, process-contention and filesystem
  attack fixtures using synthetic lifecycle identities and credentials with
  actual file/process I/O; [M3 evidence report](docs/development/m3-protected-storage.md)
  and [ADR 0008](docs/adr/0008-protected-storage-and-recovery.md).
- Reviewed `rustix =1.1.5` dependency with `std`/`fs` features; protected storage
  requires Linux `openat2` and fails closed on unsupported kernels.
- M2 pure policy and protocol crates: bounded PIN/secret ownership, versioned
  record envelopes, resource admission, durable attempt phase contracts,
  enrollment transactions, revocation fences and simulated eligibility.
- Fixed-capacity version 1 IPC codecs, connection ordering and expiry/replay
  checks, with deterministic adversarial and model-based tests.
- Decisions for fifth-attempt cooldown, conservative reboot recovery and
  mandatory authoritative account-incarnation evidence; `zeroize =1.9.1`.
- Product specification and implementation roadmap for LocalPIN.
- Initial Rust workspace with a dependency-free `localpin-core` foundation.
- Pinned toolchain, repository checks, and Fedora CI configuration.
- Contribution and security-reporting guidance, issue and pull request templates,
  and MIT/Apache-2.0 licensing.
- M1 isolated PAM candidate/fallback experiments, including optional real
  `pam_unix` tests against namespace-private synthetic accounts.
- Sanitized PAM graph/session inventory and regression tests, a disposable TPM
  simulator experiment, and bounded native-worker deadline tests.
- Architecture decisions, evidence reports, enforcing Fedora KDE VM setup
  instructions and an isolated-experiment CI job.
- Guarded real-account/password-free eligibility, actual KDE fallback/contact,
  logind registration and
  enforcing SELinux broker/worker experiments with sanitized VM reports.
- Genuine same-UID KDE ambiguity/fallback and independently routed second-seat
  desktop/locker tests, guarded clone tooling and final recovery evidence,
  completing M1 feasibility.

### Changed

- Run full workspace runtime tests on the Fedora target while retaining Ubuntu
  formatting, Clippy, Python checks, and release builds. Install the native RPM
  manifest inputs explicitly in Fedora CI.
- Refresh the project overview, contributor and security guidance, issue/PR
  templates, and build/runbook introductions for the current M8.1 implementation.
  Require a dedicated branch and a pull request for maintainer review for every
  change; record the same workflow in repository agent guidance.

- Specification 1.3 records M6.1's narrow account domain and administrative
  restrictions. Ordinary unmanaged accounts remain unsupported; no KDE unlock
  adapter, package activation or production-readiness claim is introduced.
- Roadmap adds M6.1 for enforcing production account lifecycle and password-free
  eligibility, with real-account evidence required before M7's completion gate;
  installed password-worker/SELinux/RPM validation remains assigned to M8.
- Fresh M6 review hardened CLI, broker and credential-helper entry points against
  secret-bearing core dumps before input; subprocess regressions verify process
  dumpability and limits without generating crash artifacts.
- Terminal input cancels and restores settings if foreground ownership changes,
  with job-control signals guarded and an actual session/PTY regression.
- Separate M5 review fixed renewed request deadlines and suspend-paused IPC,
  worker and session timeouts; deadline propagation, absolute boot-time timerfds,
  delivery/lifetime limits and late cancellation now have regressions. See the
  [review report](docs/development/m5-review.md).
- Separate M4 review replaced cached dynamic TPM capability values with fresh
  bounded reads and added counter/policy/lockout/recovery simulator regressions;
  the native test runner also bounds its post-SIGKILL wait. See the
  [review report](docs/development/m4-review.md).
- Specification 1.2 settles throttle boundaries and explicitly restricts
  production account support pending an enforcing lifecycle authority.
- Separate M2 review hardened backend jobs against reservation/permit reuse and
  validates persisted cooldown origins after reboot and timestamp pruning.
- Session inventory repeats each `loginctl` property flag and rejects incomplete
  successful responses; guest discovery exposed the previous comma-list bug.

- Specification 1.1 clarifies that six-digit account passwords can consume a PIN
  attempt before fallback and that forwarded failures retain password accounting.

M6.1 account lifecycle/policy acceptance is complete only for the defined
appliance domain. M7's adapter and required native/desktop acceptance cases passed
for that domain; its report retains native accounting and TPM recovery limits.
M8 installed broker/password-worker confinement, staged activation, RPM lifecycle,
ordinary reboot and interrupted-upgrade recovery passed the recorded matrix for
the restricted Fedora 44 x86_64 Btrfs appliance. The unsafe fingerprint/faillock
composition remains activation-refused. Physical TPM validation and M9 independent
human/specialist review remain open. Current
[hosted CI results](https://github.com/tommcamm/LocalPIN/actions/workflows/ci.yml)
and testing RPMs are separate from installed acceptance and release certification.
