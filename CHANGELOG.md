# Changelog

Changes will be recorded here before versioned releases. There are no releases yet.

## Unreleased

### Added

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

- Specification 1.2 settles throttle boundaries and explicitly restricts
  production account support pending an enforcing lifecycle authority.
- Separate M2 review hardened backend jobs against reservation/permit reuse and
  validates persisted cooldown origins after reboot and timestamp pruning.
- Session inventory repeats each `loginctl` property flag and rejects incomplete
  successful responses; guest discovery exposed the previous comma-list bug.

- Specification 1.1 clarifies that six-digit account passwords can consume a PIN
  attempt before fallback and that forwarded failures retain password accounting.

Production authentication, enrollment, PAM/TPM integration, packaging, and
activation remain unimplemented.
