# ADR 0012: Immutable-appliance account lifecycle authority

Date: 2026-10-17. Status: accepted for the restricted domain below; implemented
and validated by the [M6.1 enforcing-VM evidence](../development/m6.1-account-authorities.md)
and [separate development review](../development/m6.1-review.md). This does not
lift ADR 0006 for ordinary unmanaged Fedora accounts.

## Domain and enforcement

The supported domain is an explicitly provisioned x86_64 Fedora KDE appliance
using local files accounts and the exact reviewed Fedora PAM policy. It is a
restricted account-administration model, not automatic adoption of an existing
desktop. Network identities, systemd-homed, unknown NSS or PAM graphs, unsupported
filesystems and ordinary unmanaged accounts remain unavailable.

While an incarnation is active, Linux immutable inode flags protect the four
account databases (`passwd`, `shadow`, `group`, `gshadow`), the exact reviewed
PAM/authselect/environment inputs, and their parent directories. `/etc` itself
is immutable to prevent replacing an entire containing directory. The production
authority verifies root ownership, safe modes, single-link regular files,
supported local filesystem type, immutable flags and a durable snapshot of
device/inode, timestamps, sizes, modes, link counts and content digests. Exact
canonical authselect symlinks and their protected parents are also pinned.
These snapshots detect loss of the enforcement setup; polling is not the
mechanism that prevents normal deletion/recreation. The kernel's immutable
checks prevent standard account tools and AccountsService from modifying the
protected databases during an active incarnation.

Actual guest bypass testing found that Btrfs permits `pwrite` through a writable
descriptor opened **before** the immutable bit was set. Immutable flags alone
therefore did not establish the lifecycle guarantee. Sealing now first freezes
every input, then acquires Linux `F_SETLEASE(F_RDLCK)` read leases on **every**
protected regular input through read-only descriptors. The kernel refuses a
read lease when an old writable descriptor or shared writable mapping exists,
including a mapping whose original descriptor has closed. All acquired leases
remain held through durable active-registry publication. After the registry
temporary file is synchronized, immediately before publication, the final gate
requires `F_GETLEASE == F_RDLCK` and the immutable bit on every held descriptor,
plus the unchanged complete input snapshot. Failure leaves the durable registry
revoked and requires retry after the old writer/mapping is released. Once this
barrier proves old writers drained, immutable flags deny subsequent write opens.

Registry magic `LPACCT02` records that writer-drain proof. Experimental
`LPACCT01` state is always refused; root recovery durably revokes it and creates
fresh disabled incarnations instead of adopting its unsupported continuity.
The only added production unsafe boundary is a function-scoped, documented
`fcntl` integer-argument wrapper for Linux file leases, which rustix does not
expose. It borrows a live file descriptor and transfers no pointer or ownership.

The implementation accepts the guest's Btrfs filesystem only when the inode-flag
ioctl succeeds and the required immutable bit is present. Other filesystem
acceptance requires equivalent testing before claiming support. Mount namespaces,
writable aliases, deliberate
root flag clearing, replacement of the trusted root registry, kernel compromise
and deliberate disk/snapshot rollback are administrative/root compromise, outside
the existing software-mode threat model. The supported administrator never
uses them to preserve an incarnation. A root actor able to alter the broker or
its authority cannot be made harmless by another root-owned metadata file.

## Administration and serialization

The non-setuid `localpin-account` executable requires real and effective UID 0
for mutations. It has no secret input, caller-selected program, shell launcher,
alternate root directory or test selector. Its fixed registry is
`/var/lib/localpin-accounts`, root:root 0700, with a permanent root:root 0600 lock
inode and a bounded versioned registry. The state root is separately
`/var/lib/localpin`; neither directory is created by own-user enrollment.

Every production lifecycle authority retains a nonblocking shared flock on the
same global inode for its entire lifetime. The broker retains that authority
inside the existing per-UID storage guard through staging, publication,
finalization and response delivery. Lock order is global lifecycle lease, then
native `/etc/.pwd.lock` POSIX write lock (administration only), broker storage
singleton (administration only), then stable UID storage lock. The native lock
is the same whole-file lock used by the reviewed shadow-utils through glibc
`lckpwdf`, so a supported account tool already in progress prevents sealing.
There is no blocking lock wait or application work queue. Root administration
takes the exclusive global lease; a live verification/enrollment produces Busy
until its bounded operation ends. Therefore no durable revocation boundary can
cross a previously checked authorization delivery or enrollment publication.
Previously delivered authorizations can still finish, as specified in ADR 0010.

The supported mutation procedure is:

1. Invoke `localpin-account begin-mutation`. It takes the exclusive lease,
   atomically writes and fsyncs an empty revoked registry and its directory,
   and only then clears immutable flags. This revokes **all** appliance account
   incarnations before any database can be changed.
2. Use normal Fedora administration while the domain is revoked. This covers
   creation/deletion, rename, UID/home/shell/group changes, password change,
   lock/unlock, expiration, authselect/policy changes and GUI/AccountsService
   operations. Tools cannot be used during the active state. A failed or
   interrupted tool does not restore continuity.
3. Stop the broker and invoke `localpin-account seal --uid UID ...`. All UIDs
   that should be supported must be listed explicitly. The operation durably
   revokes any previous registry again, freezes the canonical inputs, proves
   old writers and shared writable mappings drained through kernel read leases,
   verifies unique local passwd/shadow mappings, generates fresh opaque
   nonzero 128-bit incarnations with OS randomness, and provisions disabled
   storage baselines. It publishes an active registry only after every baseline
   and the final unchanged immutable snapshot are durable.
4. Restart the broker and enroll through the ordinary fresh-password flow.

Rename deliberately requires a new incarnation and fresh enrollment. This
avoids claiming continuity from unchanged UID/name/home fields. Mutations of an
unrelated account also revoke every managed incarnation because the protected
databases are global. This operational cost is visible and intentional.

`localpin-account recover --uid UID ...` performs the same explicitly privileged
fresh provisioning after a crash or missing/corrupt authority state. It does
not rehabilitate an old identity. The broker must be stopped because `Storage`
retains its separate singleton lease. Old or partially initialized UID state is
atomically moved into protected `retired/UID/NEW-INCARNATION` quarantine and
synchronized before a new disabled baseline is initialized. Existing quarantine
entries are never overwritten. Sixteen retained entries per UID is the hard
bound; further provisioning refuses until explicit offline administrator
maintenance removes reviewed obsolete quarantines.

## Crashes, password accounting and unsupported state

When mutation starts from an active sealed domain, a crash before durable
registry revocation leaves the still-immutable old domain intact. A domain
already revoked before sealing remains unavailable if sealing is interrupted.
A crash after revocation, during flag clearing, mutation,
refreezing or provisioning leaves the registry revoked. A crash around active
registry publication can yield only either a revoked registry or an active
registry whose required disabled baselines were already durable. Readers fsync
a visible registry and directory before treating it as authoritative. Restart
never manufactures missing state or upgrades a development incarnation.

Missing/corrupt registry, changed immutable snapshots, missing flags, unsafe lock
or input metadata, missing/corrupt disabled storage, unknown policy and lost
continuity make the account unavailable. Own-user enrollment has no call to
provision/recover and cannot fix these conditions after password authentication.
Every new administrative provisioning uses new randomness and quarantines old
credentials, staged generations and throttle state. Old grants/results retain
the revoked incarnation and cannot authorize a new account, including identical
UID/name/home recreation.

Faillock state remains separate mutable password accounting. Privileged seal
may establish a missing canonical empty tally while all old incarnations are
already revoked; existing canonical tallies retain their exact bytes and
metadata. Noncanonical existing tallies refuse provisioning. Eligibility never
creates, resets, adds to or normalizes them. Because Fedora's default tally
directory is volatile `/run/faillock`, reboot can lose it; a missing tally makes
PIN unavailable until explicit privileged recovery and fresh enrollment. This
conservative recovery does not claim persistent Fedora password failure
accounting or reset an existing password lockout. Normal password recovery stays
governed by the existing password-only PAM policy.

## Password-free eligibility contract

The lifecycle domain is further narrowed by the independent production
[eligibility worker](../../crates/localpin-auth/src/eligibility.rs). A supported
account has UID 1000–59999, a unique local passwd/shadow mapping, name matching
`[a-z_][a-z0-9_-]*` of at most 32 ASCII characters, home `/home/<name>`, and shell
`/bin/bash` or `/usr/bin/bash`. The passwd password field must be `x`; its UID/GID
must parse, and the NSS UID-to-name result must agree with the local record.
The `passwd`, `group` and `shadow` NSS entries must each specify exactly `files`,
once. Stock `files systemd` configurations are outside this domain until the
administrator explicitly changes them while revoked. Other account sources,
duplicate mappings and uncertain record structure refuse eligibility.

An empty hash, `!`/`*` lock marker, forced change (`lastchg=0`), future last-change
date, reached account expiry or reached maximum password age denies PIN use.
All shadow aging fields are strictly parsed and bounded; missing required
last-change evidence and unknown/reserved state are unavailable. Expired
passwords are denied at their maximum age, before an inactivity interval could
make them acceptable. This is conservative account authorization, not a
password-verification algorithm.

Supported encrypted-password representations use crypt's
`./0–9A–Za–z` alphabet and canonical unused final bits:

- SHA512-crypt `$6$`: salt length 1–16 and digest length 86. An explicit
  `rounds=` must be canonical decimal from 1000 through 999999999, without
  leading zeroes.
- Fedora/libxcrypt default yescrypt `$y$j9T$`: exactly 22 salt characters and
  43 digest characters. Other yescrypt parameter sets and other methods refuse
  eligibility until separately reviewed and demonstrated.

The private fixed
[localpin-eligibility policy](../../crates/localpin-auth/policy/localpin-eligibility.review-required)
contains `pam_env`, `pam_faildelay delay=2000000`, explicit
`pam_faillock preauth silent`, and `pam_unix`/`pam_nologin` account checks.
No password/token is supplied; any conversation request makes the invocation
unavailable. Both `/run/nologin` and `/etc/nologin` are checked directly before
and after PAM, in addition to the native nologin account check. Existence of
either restriction denies eligibility. The exact reviewed KDE/password-auth
graphs contain no `pam_access` or `pam_time` restriction to reproduce; an added
module or changed graph is unsupported, rather than silently omitted.

The helper requires these measured SHA256 policy inputs:

| Input | SHA256 |
| --- | --- |
| `/etc/pam.d/kde` | `7d91b3ad73a998e8b10f9edccd74ba04179a778c4a5e61d9176872f43c7bbac3` |
| `/etc/pam.d/postlogin` | `c1ecd4d1a5b5de7d26e3336cd33551d1d65e13751b5f46405183472895838a9d` |
| `/etc/pam.d/password-auth`, default profile | `2e53f704372b6c7fb69cdc4dfd6c27456d642c83feff8b1588fa1f9cb1126cd0` |
| `/etc/pam.d/password-auth`, reviewed faillock profile | `de00ea01b5ffe6b08efd7027e437bdd4a3bad18e231e9593f6b45cc64b334276` |
| `/etc/security/faillock.conf`, reviewed all-comment configuration | `662303cf89938c12d95a7fc59d92cbe76c398312527fa908894fb319809093b3` |

[ADR 0013](0013-pam-unlock-contract.md) extends only the KDE row with one exact
M7 integrated layout. Its original stock suffix is unchanged; unknown edits
remain unavailable. Both layouts remain immutable account-authority inputs, and
changing between them requires durable revocation, fresh sealing and enrollment.

It also requires the exact canonical private enrollment and eligibility policies,
and snapshots the protected `pam_env.conf` and `/etc/environment` inputs.
Canonical authselect symlinks must point to their exact protected absolute
targets. The measured native Fedora `pam-1.7.2-2.fc44.x86_64` implementation is
pinned by file hashes, including the fixed absolute libpam load path:

| Native input | SHA256 |
| --- | --- |
| `/usr/lib64/libpam.so.0.85.1` | `e8a3e3aa67cc17d4c659892fe63b9695ae202b6f107170f1ef5bb345570a8760` |
| `/usr/lib64/security/pam_env.so` | `5a54893c723005dc9b33b1f7da87fd30d9f8a0aefc333f7b0fd7585dd7dc848f` |
| `/usr/lib64/security/pam_faildelay.so` | `c284c89bcc9163a15e533ef1c335c198da59735f6d86e40c364fa1ccc84954a3` |
| `/usr/lib64/security/pam_faillock.so` | `babb242bec2f6a080f64c294d8641582c8ffbeda0ffe43eae5b2a3d3c4eb034b` |
| `/usr/lib64/security/pam_unix.so` | `1b14e350075868d3118959858fec47a2cfdbab31506e8482c31d0c550ab00222` |
| `/usr/lib64/security/pam_nologin.so` | `4a9f97b38509ce458d33d9563525dbde8243f1c472d260905899a7a7d80358fd` |

`libpam.so.0` must resolve to `libpam.so.0.85.1`. A changed native input or
unsupported policy version disables the route pending review. These constants
identify the implemented compatibility domain; the
[M6.1 evidence report](../development/m6.1-account-authorities.md) must state
which actual real-account cases passed before milestone acceptance is claimed.

M8 extension, 2026-10-17: the native account-expiry path additionally pins
Fedora's root-owned `/usr/bin/unix_chkpwd` from the same PAM package:

| Added M8 native input | SHA256 |
| --- | --- |
| `/usr/bin/unix_chkpwd` | `0cb285f3c1819e3ca92545b448fed4d0b6a41ce81899ad11d9512d80b18b7e79` |

The installed enforcing matrix verified its `chkpwd_exec_t` label and maintained
`chkpwd_t` transition. The actual linked policy allowed no helper-domain
`setpgid`; the service also denied `setsid`. This is the measured Fedora 44
policy boundary, not a claim about arbitrary future policy updates. The
[M8 report](../development/m8-packaging-recovery.md) records those checks.
[ADR 0014](0014-persistent-faillock.md) adds the exact persistent accounting
variant required for installed activation.
[ADR 0016](0016-package-cache-window.md) defines the narrow compatible-RPM
exception: authority is revoked while only `/etc`'s directory flag is released,
and exact validated completion can retain original account incarnations. These
are M8 extensions; the M6.1 component evidence above retains its historical scope.

Faillock preauth is performed under both supported password-auth profiles:
the separate enrollment password service itself uses native faillock accounting.
Its tally must be a bounded single-link regular file, target-UID:root, mode 0660,
under the canonical root:root `/run/faillock` directory. Unknown flags, reserved
bits, future times and malformed 64-byte native records refuse eligibility.
The helper compares target tally bytes and metadata, passwd/shadow, policy and
native snapshots before/after PAM and refuses any change. The eligibility path
contains no `authfail`, `authsucc` or resetting faillock account hook, and never
creates, normalizes or resets a counter. This preserves existing password
accounting; actual password transactions retain their original success/failure
effects, including the shared-field PIN/password ambiguity from ADR 0001.

PAM and NSS execute only in supervised children, never in the broker process.
A single shared supervisor retains at most four starting/live/retired process
groups; each check uses the caller's absolute suspend-inclusive deadline capped
at two seconds. The child receives a private random correlation token and UID,
and returns one sanitized allowed/restricted/unavailable result. Late,
cancelled, malformed or unreaped work cannot produce a usable authorization.
Eligibility does not replace the kernel peer/logind binding, lifecycle lease,
per-UID storage serialization or existing finalization/delivery fences.

[Account administration](../account-administration.md) records the operational
procedure and actionable `account-unsupported`, `lifecycle-unavailable` and
`eligibility-unavailable` status diagnostics. No status message grants permission
to repair lifecycle state through an own-user password transaction.

## Separate gates

This component authority does not activate KDE, install a PAM unlock adapter,
provide an RPM, or certify installed SELinux/systemd confinement. M7 retains
the actual stock-locker PIN/fallback matrix; M8 retains packaging, confinement,
activation and console recovery; M9 retains independent human/specialist review
and physical TPM/hardware validation. The everyday host is not an appliance
test target. Only a disposable Fedora KDE guest receives the immutable flags
and dedicated real account mutations for M6.1 evidence.
