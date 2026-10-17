# ADR 0016: A bounded account-authority window for native package caches

Date: 2026-10-17. Status: implemented; installed package acceptance remains
tracked in the [M8 report](../development/m8-packaging-recovery.md).

Fedora's native package triggers update `/etc/ld.so.cache`. ADR 0012 freezes
the `/etc` directory as well as every protected account/policy file, so an
otherwise compatible LocalPIN RPM transaction needs a narrow maintenance
window. Unsealing and provisioning new incarnations would lose enrollment;
silently resnapshotting account state would weaken identity continuity.

## Fixed operations and proof

The non-setuid root helper accepts only `cache-window-begin` and
`cache-window-finish`, without paths or programs. Both take the exclusive
lifecycle lease, close the desktop gate and acquire storage's singleton lease
to require the broker stopped. They leave the gate closed. Any refused operation
after lease acquisition durably revokes the live registry when possible.

Begin validates the exact active registry, immutable Btrfs inputs and writer
barrier. It synchronizes a bounded root:root 0600 `LPACCH01` journal at
`/var/lib/localpin-accounts/cache-window` containing the original registry before
durably revoking the live registry. Only then may it clear the immutable bit on
the `/etc` directory. Every protected regular inode and all other protected
directories remain immutable. Canonical PAM links retain their frozen parent;
the NSS link under `/etc` must match its original inode/timestamps and exact
target before authority can be restored.

Finish accepts only the same `/etc` device, inode, mode, link count and digest,
with actual root ownership/group, and exact snapshots for all other inputs.
Only `/etc` size and ctime seconds/nanoseconds may change. It refreezes `/etc`,
checks the complete immutable snapshot and writer barrier, and synchronizes an
exact final-registry witness in the journal before publishing that registry.
Account UIDs/incarnations are copied unchanged from the original; credentials
and throttle files are neither provisioned nor rewritten. Journal deletion and
the registry directory are synchronized after successful publication.

The registry retains its `LPACCT02` wire format: twenty 84-byte snapshots follow
the ten-byte header. The only refreshable bytes are offsets 26 through 49,
covering the first snapshot's size/ctime fields. Python's upgrade binding
normalizes only those bytes; native finish independently validates the whole
proof. Native state, credential and throttle equality bindings still apply.

## Crashes and cancellation

The journal distinguishes an original-only window from an exact final witness.
Begin can retry the former while the live registry is either that exact original
or already revoked. Finish of an original-only journal requires revocation. A
first finish after a crash before revocation refuses and revokes; retry can then
finish, or begin can reopen the maintenance window first.

A crash after final-witness synchronization can restore only that exact witness
with the exact current frozen snapshot. A crash after live publication but before
journal deletion is retryable without adopting new metadata. After journal
deletion, repeated finish accepts only an already-active registry matching the
complete current immutable snapshot and performs no authority reconstruction.
Missing proof with revoked state, changed protected inputs, unsafe journals and
unknown formats require explicit fresh recovery; old accounts are not guessed.

Ordinary `begin-mutation`, `seal` and `recover` durably revoke and delete/synchronize
both fixed cache journal paths before allowing any protected mutation or fresh
sealing. A stale maintenance journal cannot resurrect a prior incarnation.

## Supported maintenance boundary

This is only for a quiescent LocalPIN-compatible RPM transaction and its native
cache triggers. It is not a generic root transaction that preserves identities.
The account authority is revoked throughout the mutable-path window. The tool
does not prove continuous pathname binding while `/etc` is mutable: deliberate
root rename/mount replacement, flag clearing, rollback or graph-switch-and-restore
remains outside ADR 0012's trust boundary. Standard account tools do not rename
the entire `/etc` tree; ordinary account/policy administration must cancel the
journal through `begin-mutation` and create fresh incarnations.

The final low-priority RPM transaction file trigger finishes this window after
native cache processing and before restoring services. Interrupted transactions
retain the closed gate and journal for reviewed retry. Release compatibility
still requires actual enforcing-VM install/upgrade/recovery evidence.
