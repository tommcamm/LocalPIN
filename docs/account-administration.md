# Managed account administration

M8.1 replaces the frozen appliance authority with a marker in each managed
account's native shadow record. The target is ordinary Fedora KDE 44 x86_64
with local accounts and SELinux enforcing, including routine `dnf upgrade`.
[ADR 0017](adr/0017-shadow-record-account-authority.md) defines the new lifecycle
contract. The [M8.1 report](development/m8.1-desktop-compatibility.md) records the
targeted native and installed acceptance for this architecture; M9 independent
review and physical hardware validation remain separate. The earlier
[M6.1](development/m6.1-account-authorities.md) and
[M8](development/m8-packaging-recovery.md) reports certify their historical
appliance implementation only. Use disposable guests for development and
acceptance, and follow the [integration runbook](integration-administration.md)
for installed desktop preparation and recovery.

## Account domain

A managed account requires a unique local passwd/shadow mapping agreeing with
NSS, UID 1000–59999, a name of at most 32 ASCII characters matching
`[a-z_][a-z0-9_-]*`, home `/home/<name>`, and shell `/bin/bash` or
`/usr/bin/bash`. The NSS adapter permits `files`, stock `files systemd`, and the
stock `files [SUCCESS=merge] systemd` group entry. The selected account must
still be a local files account; network identities and systemd-homed are
unsupported. Other NSS action rules require a reviewed extension.

The root-only authority stores an independently random 128-bit incarnation and
a nonzero 32-bit record marker. It writes the marker as canonical decimal in
that account's reserved ninth shadow field. Ordinary user deletion removes the
marker; recreation, including identical UID/name/home and an imported password
hash, cannot inherit the old PIN. A missing, changed or ambiguous marker makes
PIN unavailable. Using a changed login name or UID requires fresh provisioning.
Reverting the same native record to its original login/UID can restore the
original binding if its marker remained continuous. Normal
password/aging/group changes and unrelated service-account additions can retain
the native record and its marker, subject to current eligibility checks.

No new immutable flags are set. Native account tools and distribution updates
can rewrite `/etc`, passwd/shadow, authselect and PAM packages. Each live broker
operation retains a shared OFD read lock on `/etc/.pwd.lock` through actual
response delivery, conflicting with the exclusive native locks used by
shadow-utils and systemd-sysusers. This serializes ordinary mutation with
LocalPIN operations. Registry administration also uses a separate global lease.
Contention refuses the operation or reports Busy; there is no indefinite wait.

Direct privileged editing or reconstruction of account databases requires
`begin-mutation` first, including edits through `vipw` or `vigr` that respect the
native lock. The lock serializes an edit with live operations; it does not
revoke a retained record marker. Reconstructing a passwd entry against an orphan
shadow row can reconnect that old marker. After direct editing, provision and
enroll fresh identities. The same rule applies to replacing the lock inode,
copying markers, alternate-root/prefix mutation of live databases and restoring
old snapshots. Ordinary native account creation, deletion, password, aging and
group tools remain supported under the native-record contract. Root recovery
never imports old verifiers or claims continuity from copied UID/name/home
metadata.

## Provisioning and migration

The non-setuid [localpin-account helper](../crates/localpind/src/bin/localpin-account.rs)
requires both real and effective UID 0. It accepts fixed operations and numeric
UIDs, with no shell, program, alternate root or secret input. The experimental
RPM installs it as `/usr/libexec/localpin/localpin-account`.

Provision root:root 0700 `/var/lib/localpin-accounts` and `/var/lib/localpin`,
the installed fixed helpers/private PAM policies, and the reviewed persistent
password-accounting directory. Installed activation requires the exact
`dir = /var/lib/faillock` variant; preserve existing native counters during its
one-time offline transition. See the
[persistent accounting procedure](integration-administration.md#prepare-native-accounting-once).
Stop `localpin.socket` and `localpin.service` before provisioning because the
broker retains storage's singleton lease.

For a fresh account with an empty reserved field, use the complete UID list:

```sh
sudo /usr/libexec/localpin/localpin-account seal --uid 1000
```

`seal` closes the desktop gate and durably revokes previous bindings before
writing anything to the account databases. It accepts an empty reserved field
or a marker matching its existing valid registry, and refuses unknown reserved
state. It rotates markers/incarnations, atomically updates shadow while
preserving its owner/mode/SELinux label, quarantines old credential/throttle
state, provisions disabled baselines, and publishes only after durable
validation. Unknown extended attributes refuse provisioning rather than being
discarded. It creates no PIN and opens no desktop gate.

After successful preparation through the integration tool, start the broker and
enroll from each account's eligible local KDE session:

```sh
localpinctl doctor
localpinctl enroll --backend software
```

Software enrollment requires explicit acceptance. Select `tpm2-required` only
with the separately validated TPM deployment. Enrollment verifies the existing
account password in the fixed password-only worker; it cannot provision or
repair lifecycle authority. Complete actual PIN/password/console tests and
staged activation through the integration runbook.

`LPACCT01` and `LPACCT02` are refused. Migration durably revokes the old domain,
invalidates old cache journals, removes its known immutable flags only with
captured valid legacy-registry proof, and creates fresh disabled identities.
It requires fresh enrollment and desktop tests; there is no silent import of
old continuity.

An installed old appliance with a schema-1 activation manifest requires a
one-time package migration: disable with the old tools, verify full-password
recovery, retain offline backups, and remove the old experimental RPM. Install
the new package, provision fresh identities and enroll again before repeating
desktop tests and activation. The old RPM deliberately rejects an in-place
schema-2 upgrade even when integration is disabled; do not bypass its scriptlets.
See the [package migration runbook](integration-administration.md#updates)
for the distinction from later compatible schema-2 upgrades.

## Routine changes and explicit recovery

Use normal Fedora account creation/deletion, password, lock/expiry, group and
service-account tools. Their native locks serialize supported record changes;
LocalPIN still refuses a currently locked/expired/restricted account. Ordinary `dnf upgrade`
needs no cache-maintenance window or account reseal. PAM changes outside the
reviewed adapter can leave PIN unavailable while password recovery remains the
route. Compatibility requires the installed upgrade acceptance matrix.

For account deletion, the old binding becomes unusable when its native row is
removed. A newly created user needs privileged fresh provisioning. To use a
changed login name or UID, provision and enroll a fresh identity. Reversing a
rename/UID change on the same surviving marked record can match the old binding;
these edits are not recorded as permanent revocation. Account deletion removes
the authoritative marker and does not have that continuity.

For planned direct account/policy maintenance, including lock-respecting
`vipw`/`vigr` reconstruction, or desktop disable/reprepare, first use the
integration runbook to close the gate and restore owned policy.
Its lifecycle step is:

```sh
sudo /usr/libexec/localpin/localpin-account begin-mutation
```

This durably revokes every managed binding, removes legacy immutable flags only
when a valid trusted old registry was captured before revocation, and clears
only still-matching known managed markers under the native exclusive
lock. Foreign/changed markers are untouched. Complete maintenance, stop the
broker, run `seal` with the complete UID list, and enroll again. A crash after
revocation can leave an old marker present; explicit lifecycle recovery handles
that condition.

Fresh, missing, unknown and current `LPACCT03` authority never authorize removing
immutable flags from system inputs. Such custom hardening makes provisioning or
maintenance unavailable while preserving those flags. Corrupt old-registry
evidence, or a migration interrupted after revocation before flag removal,
requires deliberate offline root review of the old deployment and its flags
before fresh recovery. Neither `seal` nor `recover` guesses ownership of unknown
immutable hardening.

For missing/corrupt authority, interrupted provisioning or deliberate reserved
field recovery, stop the broker and use:

```sh
sudo /usr/libexec/localpin/localpin-account recover --uid 1000
```

This is an explicit root decision to replace a nonempty reserved field. Review
unknown native use of that field first. It rotates both marker and incarnation,
quarantines old state and creates disabled baselines. It never adopts partial
publication or retains the previous PIN. Errors leave authority revoked until
successful privileged recovery and fresh enrollment.

Own-user `localpinctl change` and `disable` require fresh password verification
and retain a healthy authoritative incarnation. The separate root broker
`localpinctl recover --user <account>` revokes credential state for an existing
identity; it does not repair the lifecycle registry or reserved field.

Old state stays under `/var/lib/localpin/retired/<uid>/<new-incarnation>/`.
The bound is sixteen retained entries per UID. Further provisioning refuses
until explicit offline maintenance reviews and removes obsolete entries. Never
move a quarantined verifier back into the active directory; no forensic erasure
of backups or snapshots is claimed.

## Eligibility, accounting and diagnostics

The supervised password-free eligibility worker checks current local records,
password hash/aging, nologin restrictions and canonical native faillock state.
It accepts the reviewed SHA512-crypt and Fedora default yescrypt forms, refuses
PAM conversations, and never calls failure/success/reset hooks. It compares
native inputs and tally bytes/metadata before and after each operation.
Distribution-owned Linux-PAM is loaded through its stable x86_64 SONAME;
individual build hashes are not a permanent platform allowlist.

A tally must already be a bounded, single-link canonical file owned by the
account and group root, mode 0660, under the reviewed root-controlled directory.
Eligibility never creates, resets or normalizes it. Privileged fresh
provisioning can establish a missing empty baseline after durable revocation;
existing counters remain exact. Lost/corrupt persistent accounting requires
explicit recovery. The legacy `/run/faillock` component policy can lose state at
reboot and is not the installed activation configuration.

[The KDE compatibility decision](adr/0018-kde-native-update-compatibility.md)
defines the owned password/fingerprint substacks and native counter behavior.
Unknown graphs remain refused. A PIN-format password can also consume a
LocalPIN attempt in the shared field; no native counter is suppressed to hide
that ambiguity.

Use `localpinctl doctor [--json]` or `status [--json]` in the selected account's
supported session. Diagnostics expose no shadow contents, marker, incarnation
or authentication grant.

| Reason | Action |
| --- | --- |
| `account-unsupported` | Check the local account/NSS domain and privileged provisioning. |
| `lifecycle-unavailable` | Check native-lock contention, registry/marker continuity and protected state; use explicit recovery when continuity is lost. |
| `eligibility-unavailable` | Inspect supported PAM policy, native components, password form and canonical accounting. |
| `account` | Check current locks, aging, forced changes and nologin restrictions. |
| `session` | Use an unambiguous supported local KDE session. |
| `storage` | Review protected ownership/consistency; own-user enrollment cannot repair it. |
| `busy` | Retry after the current bounded operation or native account tool finishes. |

Enrollment, root operator attestation and desktop activation are distinct. A
successful broker request does not certify real locker behavior. The
[M8.1 report](development/m8.1-desktop-compatibility.md) records actual installed
coverage and its limits. M9 independent review and physical hardware validation
remain separate gates; hosted CI execution remains unverified.
