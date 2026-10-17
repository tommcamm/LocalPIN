# M2 policy and protocol contracts

Date: 2026-10-17. Scope: pure Rust models and bounded parsers, using synthetic
fixtures. No VM, host authentication change, real credential backend or
production activation is involved.

## Delivered contracts

`localpin-core` implements:

- Non-root numeric UIDs, opaque account incarnations, nonwrapping generations,
  boot/connection/transaction identifiers, clock and OS-randomness interfaces.
- Exactly six ASCII PIN digits with leading zeroes; bounded, non-cloneable,
  redacted secret ownership erased through `zeroize` on drop.
- Pinned backend selection with explicit software acceptance; no runtime
  downgrade when a TPM credential becomes unavailable.
- Fixed bounded throttle records, credential envelopes and policy configuration
  parsing. Credential payloads still require M4 backend validation. The account
  envelope is a development contract pending a production lifecycle authority.
  The fixed config model codec does not establish the future installed
  `/etc/localpin/config.toml` syntax.
- Durable reserve-before-backend and complete-before-response phase types,
  conditional storage replacement, consumed abandoned attempts, poisoned state
  on uncertain persistence, account/generation fences, and owned single-use
  verification jobs binding one candidate to one reservation and work permit.
- Enrollment/rotation/migration, own-user disable and separate root recovery
  models; private worker-owned password authorization, staged verification and
  conditional durable mutation; connection, time and incarnation binding.
- Explicitly simulated account/session eligibility, direct mapping without
  fallback, exactly one own-UID user-manager candidate, and repeated eligibility
  checks before releasing verification authorization.
- Shared admission for 32 connections, one active KDF operation per UID and
  256 MiB of aggregate KDF memory. Software verification, enrollment and TPM PIN
  derivation all consume the same budget. Supervisors must retain permits until
  cancelled native workers have actually exited and been reaped.

`localpin-protocol` implements fixed-buffer, incremental version 1 request and
response codecs, all specified operations, separate root-only recovery, closed
sanitized status/error values, conversation payload bounds, connection ordering,
expiry and replay rejection. The whole frame, including its four-byte length
prefix, is at most 4096 bytes. Unknown versions, operations, discriminants,
trailing fields, ancillary capabilities and partial EOF are refused. See its
[wire contract](../../crates/localpin-protocol/README.md).

## Decisions and compatibility

[ADR 0005](../adr/0005-policy-time-and-revocation.md) defines the fifth submitted
guess, rolling-window equality, exact cooldown expiry, conservative reboot debt,
durability acknowledgements and revocation point. [ADR 0006](../adr/0006-account-incarnation-support.md)
requires a trusted enforcing lifecycle authority and explicitly refuses
unsupported ordinary Unix accounts. Specification 1.2 records that support
restriction. Equality of UID, username and home is never an incarnation proof.
[ADR 0007](../adr/0007-bounded-protocol-and-secret-ownership.md) records framing,
connection/worker boundaries and secret ownership.

No existing production records or protocol clients need migration: none exist.
The development record and wire versions reject unknown values instead of
guessing how to interpret them. M3 can develop storage with synthetic identities;
permanent account records remain blocked on a demonstrated lifecycle mechanism.

## Verification

The workspace suites include exact time/size boundaries, synthetic storage
failures before and after simulated writes, crash/reboot recovery, generation changes,
account replacement, account/session restrictions, expired and rebound
enrollment grants, protocol truncation/mutation/replay tests, and seeded
state-machine comparisons. The fixtures contain only clearly synthetic secrets.
The throttle model executes 32,768 seeded steps against a separate rolling-window
model and checks every single-bit mutation of its fixed record. These bounded
deterministic cases supplement the boundary tests; they are not continuous
coverage-guided fuzzing.

The separate [M2 review](m2-review.md) found and corrected a reusable backend-job
interface and missing cooldown-origin validation after recovery. Three fresh
review agents examined the full change; a reviewer who did not implement the
corrections rechecked both fixes. This is AI-assisted development review and
does not replace M9's independent specialist review.

Final local checks with the pinned Rust 1.99.1 toolchain:

| Check | Result |
| --- | --- |
| `cargo fmt --all -- --check` | Passed |
| `cargo clippy --workspace --all-targets --all-features --locked --offline -- -D warnings` | Passed |
| `cargo test --workspace --all-features --locked --offline` | 81 passed: 59 core unit, 6 public-API composition, 16 protocol; 4 ownership compile-fail doctests passed |
| `cargo build --workspace --all-features --release --locked --offline` | Passed |
| `.local/tools/bin/cargo-deny --locked check advisories bans licenses sources` | Passed with refreshed advisory data; checker version 0.20.2 |
| `git diff --check` | Passed |

Composition tests prove the model requires a durable reservation before invoking
the simulated verifier, two acknowledged writes plus current eligibility before
authorization, and rejection of a reserved matching result after durable disable.
Review also added regression coverage for fresh password authority before each
staging transition, retained cooldown after same-boot crash recovery prunes old
timestamps, exact work-permit UID/parameter/operation binding, and exhaustive
wire-action/backend conversion.

The pinned `cargo-deny 0.20.2` check refreshed its advisory database and passed
advisories, bans, licenses and sources for the final locked graph. The only
external dependency is `zeroize =1.9.1`, with `alloc` only and no transitive
dependencies. See the [dependency review](dependencies.md#m2-rust-dependency-review).

## Remaining gates

M2 establishes trusted adapter contracts, not those adapters' truthfulness.
M3 must implement descriptor-relative storage, cross-process locking, fsync and
crash recovery with fault injection. M4 must parse/validate cryptographic backend
payloads, acquire KDF capacity before allocation and implement actual verifiers.
M5/M6 must combine both state machines with live kernel-peer/server trust,
stable process/session references, deadlines and supervised password/native
workers. An IPC completion message alone is not a durable authorization.

No production lifecycle authority, filesystem durability, TPM, PAM, logind,
SELinux, socket transport, installable package or independent security review is
claimed by these tests. Hosted CI and Fedora-container execution of the M2
change have not been observed here. M1 guest experiments were not rerun because
their sources and platform behavior were not changed.
