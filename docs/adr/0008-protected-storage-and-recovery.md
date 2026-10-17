# ADR 0008: Protected storage and deterministic generation recovery

Date: 2026-10-17. Status: M3 Linux implementation, tested with synthetic account
identities. ADR 0006's production lifecycle gate remains in force.

## Decision

`localpin-storage` accepts an already trusted state-directory descriptor. The
production constructor requires UID 0 ownership and exact mode 0700. Installation
must establish ancestor, filesystem and mount trust. State access uses Linux
`openat2` with beneath/no-symlink/no-magic-link restrictions. Unsupported kernels
fail closed. All child names are fixed internal names or canonical numeric UIDs
and generations. Descriptor metadata establishes ownership, type and exact modes;
regular files require one link and mode 0600. Bounded reads erase owned buffers.

An exclusive, nonblocking `broker.lock` covers the broker and every outstanding
UID guard. An independent permanent `users/<uid>/lock` serializes each account.
Lock inodes are never replaced or removed by the adapter. A busy UID returns
immediately, allowing other UIDs to proceed. Workers must not receive these
close-on-exec descriptors. The broker must retain its UID guard through work,
final eligibility checks and response delivery.

Each UID has one fixed 35-byte `active` pointer and directories
`generation-<number>/`. The pointer binds account incarnation, generation and
pinned backend; backend zero is a revocation tombstone. The M2 invariant that
generation equals committed-state revision is encoded without a second revision
field. The selected directory contains a required bounded `throttle` and, when
enabled, a required bounded `credential`. Never reconstruct a missing throttle,
scan for a substitute generation, or try a previous credential.

Every record replacement exclusively creates a 0600 `.pending` file, writes the
whole record, synchronizes the file, renames it over the target, and synchronizes
the containing directory. Previously interrupted temporary files are inspected
before removal. Any uncertain mutation poisons its guard. Reload synchronizes
the selected file and containing directory before using visible state, including
a rename whose earlier acknowledgement failed. Newly linked directories and
stable lock entries are also synchronized.

Provisioning creates an exclusively new UID directory and a disabled generation
one. It refuses existing and partially initialized UID directories. A trusted
lifecycle authority must approve provisioning; unmanaged Unix accounts fail.
This is an internal provisioning API, not automatic verification recovery.

Enrollment stages the proposed generation, reopens and trial-verifies its exact
persisted credential, and returns a single-use stage capability. A model-issued
commit intent must match the complete old pointer and the next generation. The
adapter rechecks the staged bytes, persists the new throttle, and replaces
`active` only after all selected data is synchronized. The pointer's directory
sync is the revocation boundary. Clock and lifecycle checks bracket finalization;
expiry or uncertainty after a pointer write requires authoritative reload, never
rollback to the old accepted PIN.

Generation changes preserve attempt debt, applying M2's pending-reservation and
reboot recovery before binding the new generation. A disabled baseline can thus
enroll after reboot. Only an explicitly root-authorized administrative recovery
intent may replace damaged required throttle state with a fresh **disabled**
baseline. It cannot create an available verifier.

Startup first checks that the selected snapshot is structurally complete; a
well-shaped pointer to missing/damaged data cannot trigger destructive cleanup.
Verification remains unavailable and explicit administrative revocation can
still use the guard. Startup and successful generation changes remove orphaned stages and all history
except the committed generation and its immediate predecessor. Cleanup inspects
only known regular files, synchronizes unlinks, and refuses unexpected entries.
An interruption is resumed under the UID lock; previous data is never accepted
as another PIN. At most one recoverable previous generation is retained.

The `DurableThrottleStore` adapter compares the entire expected throttle and
checks identity, active generation and one-step revision under the retained UID
lock. Only acknowledged reservation permits backend invocation. Only acknowledged
completion permits success. The lifecycle authority is checked again after
persistence. M5 must enforce live session, connection and worker deadlines before
delivery. Revocation cannot retract authorization already delivered to PAM.

## Limits

This implements filesystem ordering, not a hardware power-loss certification.
Durability relies on the kernel, local filesystem and storage honoring fsync.
Coherent privileged edits, malicious filesystems and deliberate snapshot/root
rollback remain outside the software threat model. ACL/SELinux installation and
mount policy need later platform evidence. Root-directory creation, installed
configuration parsing, real lifecycle enforcement, password/credential backends,
socket activation and PAM integration remain their assigned milestone work.

`rustix` supplies the reviewed syscall boundary; LocalPIN continues to forbid
project-owned unsafe Rust. Its dependency review is in the build-input inventory.
The M3 report records actual fault, process and filesystem fixture evidence.
