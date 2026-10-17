# M3 protected storage and authoritative throttling

Date: 2026-10-17. Scope: actual Linux filesystem and process I/O with synthetic
account identities, password workers and credential backends. No host account,
PAM configuration, real credential or TPM was changed.

## Delivered implementation

The new `localpin-storage` crate integrates `localpin-core` with protected
descriptor-relative files. The production constructor takes an already trusted,
root-owned 0700 directory. Linux `openat2` enforces beneath/no-symlink/no-magic-link
resolution, with no permissive fallback on unsupported kernels. Descriptor checks
reject incorrect ownership, exact modes, types and hardlinks. Reads are bounded
and credential buffers have zeroizing ownership. Project Rust still forbids
unsafe code; `rustix =1.1.5` supplies the syscall boundary.

A permanent broker lock is mandatory and remains held while any UID guard
exists. Each UID has an independent permanent nonblocking lock, retained during
the policy callback, backend work and completion. Busy accounts do not hold a
shared blocking mutex. The future broker must retain the guard through final
eligibility checks and response delivery.

The durable throttle adapter compares the complete expected record, active
account/generation and next revision, writes and synchronizes the replacement,
and rechecks lifecycle before acknowledging it. The M2 owned verification job
therefore requires actual acknowledged disk reservation before invocation and
completion before success. A failed mutation poisons the guard, including a
failure after a successful rename. Reopening synchronizes visible authoritative
data and directory entries before trusting them.

Credential changes persist and reopen the proposed credential, trial verify its
exact bytes through trusted backend code, and consume an opaque stage capability
with a model-authorized commit intent. The new generation's complete data is
synchronized before the atomic `active` pointer switch. Disable and root
recovery install higher-generation tombstones. Old results cannot commit against
them. A previous generation is never another accepted PIN. Cleanup retains at
most the active generation and its immediate predecessor; orphaned staging and
interrupted deletions are reconciled under the UID lock. Destructive cleanup
requires a structurally complete selected snapshot first, so a damaged pointer
cannot erase valid recovery material merely by naming missing data.

Pending attempts and reboot cooldown debt survive credential changes. Recovery
is durable before verification, including the once-per-new-boot full cooldown
for persisted exposure. Disabled baselines can enroll after reboot. Only an
explicitly root-authorized recovery intent can replace damaged throttle state
with a disabled baseline. Missing state never implicitly provisions an account.

`CommitIntent` now exposes its preparation time so storage also rejects rollback
between model preparation and filesystem finalization. The guard can lend its
same lifecycle authority to M2 transitions and durable acknowledgement without
releasing the filesystem lock.

[ADR 0008](../adr/0008-protected-storage-and-recovery.md) records the layout,
trust boundary, synchronization order and recovery rules. The
[dependency inventory](dependencies.md#m3-filesystem-dependency-review) reviews
the exact locked dependency graph and successful advisory/license/source checks.

## Evidence

The storage suite exercises:

- Every record replacement boundary: exclusive temporary creation, completed
  write, file fsync, rename and directory fsync. Separate matrices cover initial
  provisioning, staging, reservation, successful completion, reboot recovery,
  rotation and disable. No injected error releases an unreserved job or an
  uncommitted success. Directory creation and generation cleanup have additional
  hooks, with deletion/restart tests.
- Twelve independent subprocesses contending for one account: exactly five
  invoke the synthetic verifier and seven receive cooldown. A separate process
  holds a UID lock while another UID remains available; killing the holder
  releases the lock. A second production-style broker lease is rejected, and
  dropping the storage object retains its singleton until the last UID guard
  drops. The multi-writer defense tests explicitly bypass only the singleton
  in test-only construction to exercise independent per-UID filesystem locks.
- Abrupt process exit immediately after acknowledged reservation, followed by
  same-boot consumed-attempt recovery and simulated-new-boot full cooldown.
  These use actual persisted bytes and OS process teardown.
- Missing, corrupt, oversized, wrong-UID and wrong-incarnation records; stale
  whole-record comparisons and revisions; abandoned stages, overwritten verified
  stage tokens, bounded history and interrupted cleanup. A matching in-flight
  result after durable disable fails even when given stale live-generation
  inputs. Lifecycle revocation during the success write also refuses success.
- Clock expiry before and after pointer replacement, preparation/commit time
  rollback and boot changes. After uncertainty, authoritative reload accepts
  only the selected complete generation and never automatically tries an older PIN.
- Symlinks, hardlinks, FIFO/socket types, unsafe file/directory modes, changed
  modes after descriptor acquisition, invalid components, bounded enumeration,
  substituted temporary inodes, and lock inode stability.

The test harness serializes independent fixture tests because `fork` can
temporarily inherit another test thread's flock descriptor until exec, extending
its lease beyond the parent's drop. This does not serialize the actual
multi-process contention scenarios. Production descriptors remain close-on-exec.

Disk-full and read-only error classes are injected returned storage failures;
no disk was filled or remounted. Most tests run as an ordinary user with a
test-only constructor checking the fixture owner's UID through the same metadata
predicates; production has no custom-owner constructor. The Unix-socket attack
fixture also passed outside the restricted syscall sandbox. Real chown to a
different UID was unavailable due privilege/UID namespace restrictions, so the
wrong-owner predicate was exercised using a deliberately different expected UID.

## Verification and remaining gates

Local checks with pinned Rust 1.99.1:

| Check | Result |
| --- | --- |
| `cargo fmt --all -- --check` | Passed |
| `cargo clippy --workspace --all-targets --all-features --locked --offline -- -D warnings` | Passed |
| `cargo test --workspace --all-features --locked --offline` | 121 tests passed: 59 core unit, 6 composition, 16 protocol, 40 storage; 4 ownership compile-fail doctests passed |
| `cargo build --workspace --all-features --release --locked --offline` | Passed |
| `.local/tools/bin/cargo-deny --locked check advisories bans licenses sources` | Passed with refreshed advisory data and a writable isolated Cargo cache; policy unchanged |
| `git diff --check` | Passed |

One ignored storage entry is a subprocess harness, invoked explicitly by the
passing parent tests rather than run as a standalone scenario. It is not a
deferred feature test.

Development review corrected disabled/reboot recovery, post-write lifecycle
checks, bounded generation cleanup, exact stage binding, and preservation of
recovery material when a shaped pointer names incomplete state. A fresh review
agent who authored none of this implementation or its tests found no blocking
issues and independently reran the storage suite. This remains AI-assisted
development review.

These tests establish syscall ordering and fail-closed process behavior. They
do not simulate sudden physical power loss, a lying disk/controller, filesystem
snapshot rollback or every filesystem. No Fedora-container or hosted CI run of
this change has been observed. M1 desktop experiments were not rerun because
their sources and integration were not changed.

ADR 0006 still blocks permanent production account enrollment until an enforcing
lifecycle authority has deletion/recreation and concurrency evidence. M4 owns
real software/TPM credential validation and execution. M5/M6 own kernel peer and
session trust, connection/deadline checks, workers and CLI integration. M7/M8 own
installed PAM, SELinux/package paths, mount/ancestor trust and recovery procedures.
M9's independent specialist security review remains required. Review agents in
this change are development assistance, not that release gate.
