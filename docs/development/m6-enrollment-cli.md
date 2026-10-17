# M6 trusted enrollment and CLI

Date: 2026-10-17. Status: development implementation; evidence and remaining
production gates are distinguished below.

## Delivered

`localpin-auth` supplies a disposable password-only PAM helper and a bounded
supervisor. The broker owns every authorization result, retains no client-side
success flag and binds the core grant to the UID, incarnation, action, proposed
generation and live socket. Conversation and commit each have a maximum
sixty-second interval. The helper is not setuid and receives no secret arguments
or inherited environment. Its narrow PAM ABI exception lives in `pam.rs`.

`localpinctl` supplies doctor/status with schema-versioned JSON, enrollment,
change, disable, explicit backend migration and root recovery. Real foreground
terminal input hides passwords and PINs and confirms mutations/new PINs. Input
via secret options, supported secret environment names, plaintext stdin or
release simulator selectors is rejected. Root recovery resolves an explicit
local account; own-user requests carry no target UID. Activation commands are
reserved for the separately reviewed administrative integration tooling.

The broker composes core authorization with the existing stable storage lock
and bounded backend workers. New credentials are staged, reopened and trial
verified before the atomic generation commit. Rotation and migration use fresh
password authorization; disable writes a revocation generation. Backend
creation and trials share ordinary verification's process/KDF limits. Status
distinguishes enrolled backend from integration activation and does not claim
password fallback or desktop testing merely because a record exists.

See [ADR 0011](../adr/0011-trusted-enrollment-and-cli.md) for policy, privilege,
conversation, cancellation and commit-boundary decisions.

## Validation

Standard checks use the pinned toolchain and TPM2-TSS 4.x/libdbus build inputs:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-features --locked
cargo build --workspace --all-features --release --locked
cargo deny --locked check advisories bans licenses sources
```

The opt-in protected enrollment suite uses multiple mapped UIDs, private
namespaces, real broker sockets, public protected storage and the actual backend
worker, with synthetic lifecycle/session/password authorities:

```sh
python3 crates/localpind/tests/run_enrollment_broker.py
python3 crates/localpin-auth/tests/isolated_pam.py
```

The [separate development review](m6-review.md) records findings and corrections.
No host PAM policy, real account password, physical TPM or enrolled state is
used by the ordinary tests.

Final local validation passed:

- Formatting, all-target/all-feature Clippy with warnings denied, the locked
  all-feature release build and the dependency policy audit (advisories, bans,
  licenses and sources, cargo-deny 0.20.2).
- The complete post-review workspace test run: 261 passed, nine explicit
  opt-in/subprocess entries ignored, plus the standalone three-scenario terminal
  job-control fixture. Those include 17 password-worker tests, 25 CLI unit tests,
  four CLI executable tests and four actual backend-helper process tests.
- The protected enrollment namespace suite: complete software enrollment,
  rotation, disable and root recovery; old PIN refusal, wrong/stale/unavailable
  password authority, account incarnation changes, cancellation at password,
  ready and pre-publication stages, invalid prompt and reconnect/replay denial.
  Its post-review top-level flow passed in 19.27 seconds. The existing protected broker
  namespace suite also passed in 8.86 seconds.
- Actual system Linux-PAM authentication in a private user/mount/PID/network
  namespace: fresh/wrong synthetic passwords, persistent failure tally, normal
  success accounting, three-failure lockout refusing the correct password
  without resetting counters, locked/expired passwords/accounts, and refusal
  of missing/unsupported service policy. The helper's fixed policy and real
  `pam_unix`/`pam_faillock` run here; lifecycle/session broker authorities remain
  synthetic in the separate broker suite.
- Real PTYs verify no echo, non-UTF-8 password bytes and terminal restoration
  after normal entry, control-key cancellation, oversized input and expiry.
  A separate single-threaded session/PTY fixture verifies silent foreground
  loss and restoration before `SIGTTIN`/`SIGTTOU` suspension. Subprocess tests
  verify dumpability is disabled and both core limits are zero without changing
  the test parent's process limits or creating core files.
  Storage fault hooks reject expiry, rollback, boot changes and incarnation
  revocation specifically after pointer tempfile fsync but before publication,
  preserving the exact previous credential and throttle.

The local syscall sandbox rejects IPC/namespace/audit operations required by
these tests. Native socket/process and namespace checks ran outside that tool
sandbox while retaining their own disposable test isolation; sandbox `EPERM`
was not counted as negative authentication evidence. The host is Fedora 44 with
Linux-PAM 1.7.2, TPM2-TSS 4.1.3 and libdbus 1.16.2. Missing native development
RPMs were extracted under `/tmp` for compilation; no system package installation
or host authentication changes were required. No new external Rust dependency
version was introduced.

## Remaining gates

Production accounts still fail closed under ADR 0006: no enforcing lifecycle or
complete account-policy authority exists. A trusted supported-domain provisioner
must create the disabled baseline before own-user enrollment. Missing/corrupt
state is never initialized through an unauthenticated enrollment request.

The fixed password service requires independent distribution-policy review.
Its disabled sample is not an installer. The existing broker systemd sandbox
does not establish the distinct PAM worker privilege boundary; M8 must validate
legitimate helpers, failure accounting and SELinux under installed confinement.
M7 owns real PAM/KDE integration, M8 owns packaging/activation and M9 owns
hardware and independent specialist review. No setup command claims these
requirements are complete. Hosted CI remains unverified locally.

The positive M6 broker/backend enrollment flow uses software credentials.
TPM primitive/simulator evidence remains in the M4 report; this change does not
claim end-to-end physical TPM enrollment or a real-hardware usability probe.
Doctor reports device-node detection separately and leaves unestablished TPM
usability unknown. `auto` and `tpm2-required` attempt supervised TPM creation
and trial, with no software selection on failure.
