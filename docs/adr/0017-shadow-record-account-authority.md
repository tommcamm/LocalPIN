# ADR 0017: Account continuity in the native shadow record

Date: 2026-10-17. Status: implemented; targeted native account-tool and installed
Fedora acceptance recorded in the [M8.1 report](../development/m8.1-desktop-compatibility.md).
Independent review and physical hardware gates remain open.
This supersedes ADR 0012's immutable authority and ADR 0016's cache window
for newly provisioned `LPACCT03` accounts. Historical M6.1–M8 evidence remains
evidence for the earlier implementation only.

## Identity without freezing the desktop

Freezing `/etc`, account databases and authselect prevents normal package and
account administration. Whole-file hashes and inode timestamps cannot replace
that mechanism: accepting unchanged individual rows after an unrelated account
update cannot distinguish deletion and identical recreation during a stopped
broker. A home inode also survives `userdel` without home removal. Neither
observation is an account lifecycle authority.

New privileged provisioning writes a fresh nonzero unsigned 32-bit decimal
sentinel in the managed account's ninth, reserved `/etc/shadow` field. Zero,
leading zeroes, values at or above `UINT32_MAX`, overflow and unknown forms are
unavailable. Fedora glibc clamps numeric shadow fields to 32 bits despite the
public `unsigned long sp_flag` type, so the marker uses only values that survive
native parsing/writing. The marker has a u64 wire slot for format clarity, but
its admitted value domain is 1–4294967294. This is not a secret entropy boundary. This is
a root-record continuity marker, not a password verifier, authentication secret,
or replacement for the independently generated random 128-bit incarnation.
Each registry binding contains UID, exact login name, marker and incarnation.
Every fresh provisioning rotates both random values; a marker already present
in any shadow row is never selected. LocalPIN never derives identity from UID,
name, password hash, home metadata, or the marker alone.

Ordinary deletion removes the containing shadow row. Native user creation
initializes its reserved field unset, including creation with an imported
password hash. A new account with identical UID, login, home and password hash
therefore lacks the old marker and cannot use the old registry or credentials.
Password changes, aging, primary/supplementary group changes and unrelated
service-account creation can preserve an existing record and its marker.
Eligibility independently evaluates the account's current restrictions. A
current rename or UID reassignment fails the exact binding; using LocalPIN under
the changed login/UID requires fresh provisioning. If that same native record
is changed back without losing its marker, the original binding can match again.
This is continuity of the same authoritative record, not sticky revocation on
every intermediate administration change. Deletion/recreation still removes
the marker and cannot regain continuity by restoring UID/name/home values.

This intentionally chooses the local-files account administration contract.
Linux-PAM 1.7.2 preserves the existing `struct spwd` fields when changing a
password, while new entries initialize the reserved field unset; see its
[native shadow writer](https://github.com/linux-pam/linux-pam/blob/v1.7.2/modules/pam_unix/passverify.c).
Shadow-utils 4.19 initializes the reserved field unset in
[useradd](https://github.com/shadow-maint/shadow/blob/4.19.0/src/useradd.c), and
[usermod](https://github.com/shadow-maint/shadow/blob/4.19.0/src/usermod.c)
preserves the old record. Systemd 259's
[sysusers implementation](https://github.com/systemd/systemd/blob/v259/src/sysusers/sysusers.c)
similarly preserves existing shadow records and initializes new ones unset.
Fedora glibc's numeric parsing boundary is visible in
[files-parse.c](https://github.com/bminor/glibc/blob/master/nss/nss_files/files-parse.c).
These source observations define cases for native executable tests; they are
not a claim that every future account tool preserves the contract.

## Serialization through authorization delivery

The broker retains two leases in each `SystemLifecycle` object: its existing
shared flock on `/var/lib/localpin-accounts/lock`, then a nonblocking whole-file
shared Linux OFD read lock on the existing `/etc/.pwd.lock`. The latter needs
only a read-only descriptor, including under systemd `ProtectSystem=strict`.
The object remains held by the operation's storage guard through enrollment,
backend finalization and actual response delivery. A root administration
operation takes the exclusive registry lease, then an exclusive native database
lock, then storage's singleton lease. No lock blocks or creates an application
work queue; contention makes the route unavailable or administration Busy.

Glibc `lckpwdf` uses a POSIX write lock on the same inode. Shadow-utils
[commonio locking](https://github.com/shadow-maint/shadow/blob/4.19.0/lib/commonio.c)
retains that lock through the final database unlock. Systemd's
[password database lock helper](https://github.com/systemd/systemd/blob/v259/src/basic/user-util.c)
uses a compatible OFD exclusive lock. Linux OFD and POSIX locks conflict, while
closing another descriptor in the broker does not accidentally release an OFD
lock. Unit tests demonstrate both directions of this conflict and the separate
registry-lease exclusion. The tiny function-scoped native boundary accepts only
a borrowed live descriptor, a fixed `F_OFD_SETLK` command and a complete native
`flock`; it transfers no pointers or ownership beyond the synchronous call.

Readers refuse unsafe ownership/modes, symlinks, multiply linked files, replaced
lock inodes, missing/revoked/unknown registry state and nonunique local mappings.
Every lookup rechecks the exact UID/name/marker under the native lock. Normal
account deletion cannot cross a previously checked finalization or delivery.
Authorizations already delivered may finish under the existing ADR 0010 rule.

This contract covers ordinary Fedora tools using the native lock, including
AccountsService's native-tool administration and systemd-sysusers. Direct root
database editing or reconstruction, including lock-respecting vipw/vigr,
`--prefix`/alternate-root mutation of the live databases, copying a marker into a recreated account,
restoring old account/authority snapshots and replacing the trusted lock inode
are explicit administrator changes to the authority. They are outside the
trusted-administrator threat model, just as deliberately restoring the old root
registry or broker was under ADR 0012. Administrators doing such work must first
run `begin-mutation` and then provision fresh identities. Native locking alone
cannot make arbitrary edits lifecycle-safe: restoring a passwd row that
reconnects a surviving orphan shadow record could restore its marker too.
User-writable home
files, supplementary membership or possession of the former password cannot
write the root-owned marker.

## Publication, migration and recovery

`LPACCT03` consists of its eight-byte magic, a big-endian u16 binding count and,
per binding, big-endian UID (u32), random incarnation (16 bytes), marker (u64),
name length (u8), and ASCII name bytes. Counts, lengths, duplicate UIDs, names,
markers and trailing bytes are bounded and validated. UIDs are strictly sorted
in the supported range 1000–59999. The marker's u64 slot admits only the native
32-bit value domain above. Count zero is durable
revocation. There are no native library hashes, filesystem type constants,
global account-file snapshots, immutable flags or policy timestamps in the new
identity format. PAM policy validation remains a separate fail-closed adapter.

`seal` and `recover` require actual/effective root and the broker stopped. They
close the desktop gate, synchronize a revoked registry, invalidate both old
cache-window journal paths and acquire the native exclusive lock. Immutable
flags are removed only when a safely read, bounded, structurally valid
`LPACCT01`/`LPACCT02` registry was captured before revocation. On fresh, missing,
unknown or current `LPACCT03` authority, any immutable input refuses the operation
without clearing that flag. Other inode flags are never cleared. They then
validate the local records and persistent
password accounting, prepare fresh markers and incarnations, and atomically
replace shadow. The shadow replacement preserves owner/mode and its exact
SELinux label; unknown xattrs refuse the operation rather than silently losing
ACLs or integrity metadata. The containing directory and new shadow file are
synchronized. Old credential/throttle state is quarantined and new disabled
baselines are durably provisioned before the active registry can be published.
The final prepublication check requires exact unchanged passwd/shadow bytes and
all expected markers. Registry publication retains atomic replacement and file
and directory synchronization.

Normal `seal` admits an empty reserved field or a marker matching the valid
registry captured before revocation. It refuses foreign reserved state.
`begin-mutation` captures that same proof, durably revokes, and clears only
still-matching managed UID/name/markers under the native exclusive lock;
foreign fields remain untouched. A crash between revocation and marker clearing
can require explicit `recover`. The separate `recover` verb is the privileged
decision to replace nonempty reserved state and always establishes fresh
identities; it never rehabilitates the old binding.

A crash before registry publication leaves all accounts revoked, even if some
new markers or disabled baselines are already durable. Retrying privileged
recovery creates fresh markers/incarnations and never adopts partial authority.
`LPACCT01` and `LPACCT02` remain refused by readers; migration always revokes,
unfreezes only with that captured legacy proof, and freshly provisions. Corrupt
legacy evidence, or a crash after revocation before legacy flags are removed,
can leave flags requiring deliberate offline administrator review/recovery. The
helper never guesses that unrelated immutable hardening belongs to LocalPIN.
An old cache journal cannot restore identity.
Own-user enrollment never changes markers, repairs a registry or establishes a
missing per-user tally, even after password authentication.

The retained `cache-window-begin`/`cache-window-finish` command names now perform
quiescent identity checks for package-script compatibility. They close the gate
and validate existing state; they neither thaw/refreeze `/etc`, change registry
bindings nor create a maintenance journal. Ordinary distribution updates need
no cache-maintenance window and can rewrite native account files while the
broker has no active operation. A changed PAM graph remains subject to the
independent policy adapter's compatibility decision.

## Acceptance boundary

Required native cases include real useradd/userdel with identical UID/name/home
and imported hash; retained home; passwd/chage/usermod and AccountsService;
systemd-sysusers service-account additions; mutation while a shared native lock
is held; broker restart/reboot; migration from immutable state; crash points in
shadow and registry publication; and ordinary `dnf upgrade` with SELinux
enforcing. The [M8.1 report](../development/m8.1-desktop-compatibility.md) records
the actual native-tool, locking, installed KDE/RPM, reboot, legacy flag and
distribution-update results and their limits. AccountsService's tool dispatch
was inspected; its GUI/DBus administration path, physical hardware, full legacy
credential migration and independent review retain separate acceptance gates.
The rootless model and native-lock tests alone cannot certify those cases.
