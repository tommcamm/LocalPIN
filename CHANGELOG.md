# Changelog

Changes will be recorded here before versioned releases. There are no releases yet.

## Unreleased

### Added

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
Packaging and activation remain unimplemented.
Installed broker/password-worker sandbox, physical TPM validation
and M9 human/specialist review remain open.
