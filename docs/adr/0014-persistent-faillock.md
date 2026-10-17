# ADR 0014: Persistent native password accounting for installed activation

Status: accepted implementation decision; installed reboot and desktop acceptance
passed for the recorded restricted M8 appliance matrix. Date: 2026-10-17.

## Context

ADR 0012 deliberately refuses PIN when authoritative native faillock state is
missing. Fedora's measured all-comment configuration uses volatile
`/run/faillock`. The M7 TPM experiment restored device 0 and retained registry,
active-pointer and credential bytes across reboot, but lost that accounting
state. Fresh privileged provisioning and enrollment recovered the account; the
old enrollment did not survive. This is a lifecycle/eligibility limitation, not
evidence that the TPM credential was corrupted.

Installed activation needs normal reboot continuity while retaining the same
native password lockout authority. Reconstructing an empty tally after reboot,
resetting counters during PIN success or falling back to another directory would
lose that authority.

## Decision

Add exactly one supported `/etc/security/faillock.conf` byte sequence:

```text
dir = /var/lib/faillock
```

The file ends with one newline. Its SHA256 is
`63ea06f1db780b94e59f1cdfa4d50981309d6b40c5f7bdb78853ea6038730249`.
It changes only the native tally location; native denial, failure-interval and
unlock defaults remain the reviewed Linux-PAM defaults. Installed M8 activation
requires this exact persistent configuration and a root-controlled canonical
`/var/lib/faillock` on persistent storage with the reviewed SELinux access.
It must not place that directory on tmpfs or a volatile runtime bind mount.

The existing all-comment configuration with SHA256
`662303cf89938c12d95a7fc59d92cbe76c398312527fa908894fb319809093b3` remains
supported for earlier component experiments. It selects only `/run/faillock` and
retains its explicit missing-state recovery limit. It does not satisfy the new
installed-activation prerequisite.

Both the account provisioner and password-free eligibility worker use the same
digest-based selector from `localpin-auth`. There is no generic path parser,
environment override, caller-selected directory or automatic fallback. Equivalent
whitespace, extra configuration and other paths require separate review. The
configuration is still a frozen lifecycle input; changing between variants
requires durable global revocation, fresh sealing and enrollment.

Every selected directory and ancestor must be root controlled and free of
symlinks or ordinary-user write access. Tally metadata and the bounded native
64-byte record format remain unchanged. Eligibility reads the selected tally
before PAM, runs the existing password-free native preauth/account policy, and
rechecks the configuration and tally afterwards. It never creates, repairs,
resets or migrates accounting. Missing or corrupt persistent state leaves PIN
unavailable even if a legacy volatile tally exists.

Privileged sealing selects the same fixed directory after durably revoking old
incarnations and freezing inputs. It can atomically publish a missing canonical
empty tally only in that revoked state. Existing canonical tallies retain their
bytes and metadata. No migration or counter reset is implicit in activating the
new variant: an administrator must review any existing native accounting during
the one-time policy transition. Lost persistent state still requires explicit
privileged recovery and fresh enrollment.

### Explicit native-group migration

Installed M8.2 acceptance exposed a gap in the offline instructions: an ordinary
native login/sudo tally can have the account's primary GID, while LocalPIN's
existing persistent accounting validator requires GID 0. Production validation
remains strict; setup and provisioning do not silently change existing tallies.

The explicit one-time offline migration may create a root-group persistent copy
of a reviewed account-owned, mode-0660 native tally whose source GID is either
root or that account's primary group. Stop authenticators and revoke existing
LocalPIN authority first. Preserve an exact private backup including the source
GID, then preserve every counter byte, UID, mode, extended attribute and SELinux
label in the destination while deliberately setting only its GID to 0. Leave
the volatile source unchanged. New inode/ctime values necessarily differ;
preserve source atime/mtime where possible. Reject foreign groups, symlinks,
hardlinks, unexpected access/default ACLs, malformed records and conflicting
destinations; never reset or select a smaller tally. Synchronize copies before
the atomic configuration switch and restore distribution labels.

This is an administrator-approved maintenance step with interruption evidence,
not an expansion of eligible production metadata or an automatic repair.
[ADR 0020](0020-setup-accounting-maintenance.md) lets the guided CLI schedule a
fixed offline service for supported fresh installations after explicit sign-out
approval. Provisioning and eligibility still cannot perform this conversion. The
M8.2 fixture requires an explicit canonicalization option when a primary-group
source needs conversion; its exact before/after snapshots remain guest-private.
Successful source checks alone do not establish the new installed migration
case, counter continuity or the remaining release gates.

## Native contract

Linux-PAM v1.7.2's
[configuration parser](https://github.com/linux-pam/linux-pam/blob/v1.7.2/modules/pam_faillock/faillock_config.c)
reads `/etc/security/faillock.conf`, accepts the `dir` option with whitespace
around `=`, and sets an absolute tally directory. Both the native enrollment
service and password-free eligibility service already invoke `pam_faillock`
without a competing module-level `dir` or `conf` override. The reviewed
`password-auth` graphs likewise use the common configuration.

The same native implementation opens existing tallies `O_RDWR` even in preauth,
and treats an inaccessible or missing tally as a successful preauth result.
Eligibility therefore proves existing-file read/write access before entering
PAM and again during its post-check. It never uses create/truncate/write calls.
SELinux allows that existing-file descriptor access without tally creation,
deletion, ownership/mode changes or directory writes. Exact canonical ownership,
mode and before/after metadata/byte checks remain mandatory. A readable tally
on a read-only mount is unavailable, rather than evidence that native lockout
was checked. Policy and account input snapshots remain read-only.

This decision does not resolve ADR 0013's parallel fingerprint/account-phase
composition issue. Activation must still refuse the affected with-faillock and
parallel-fingerprint configuration until separately reviewed desktop evidence
establishes usable behavior. Persistent storage must not conceal native failures.

## Validation and retained gates

Unit tests pin both exact configuration choices and reject unknown alternatives.
The private native PAM harness exercises the exact persistent configuration,
records three real wrong-password failures, recreates private `/run`, and proves
that a fresh native worker still denies the correct password without changing
the persistent tally. Its user/mount namespaces contain synthetic identities;
host accounts, PAM, runtime and physical TPM state are not modified.

That runtime-loss test alone does not establish installed reboot acceptance.
The subsequent [M8 report](../development/m8-packaging-recovery.md) and
[sanitized installed results](../../experiments/m8/results/2026-10-17-fedora44-rpm-recovery.json)
record a passing enforcing Fedora 44 x86_64 Btrfs matrix using a private TPM
emulator: the same registry and credential survived ordinary reboot, native
counters were retained, PIN remained usable without fresh enrollment, and
applicable native lockout checks still denied access. Interrupted
[package-cache recovery](0016-package-cache-window.md) also retained enrollment.
The stock KDE password route retains its original reviewed graph; persistent
storage does not add a missing accounting hook. M9 retains
independent human/specialist review and physical TPM validation. Persistent native
accounting is not a guarantee against arbitrary storage rollback, power-loss
behavior or TPM device renumbering.
