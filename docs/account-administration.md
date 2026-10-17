# Managed account administration

This runbook describes the implemented M6.1 component domain. Acceptance and
actual validation are recorded separately in
[the M6.1 evidence report](development/m6.1-account-authorities.md).
[ADR 0012](adr/0012-immutable-appliance-account-authority.md) defines its
enforcement and trust boundary. These commands are for the explicitly
provisioned disposable Fedora KDE appliance; the everyday host is not a target.
M7 desktop unlock integration and M8 installation, packaging, service confinement
and console recovery remain separate gates.

## Supported account domain

The implementation supports the measured x86_64 Fedora 44 KDE policy on Btrfs.
It requires successful immutable-inode ioctls and kernel read leases, protected root-owned state, and
the exact reviewed PAM graph and native modules. Ordinary unmanaged accounts,
other filesystems, other PAM layouts, network identities and systemd-homed
remain unavailable.

Account eligibility additionally requires:

- UID from 1000 through 59999; exactly one local passwd record and matching
  local shadow record, agreeing with NSS.
- A name of at most 32 ASCII characters matching
  `[a-z_][a-z0-9_-]*`, home `/home/<name>`, and shell `/bin/bash` or
  `/usr/bin/bash`.
- Exactly one `files` source for each of `passwd`, `group` and `shadow` in
  `nsswitch.conf`. The stock `files systemd` entries require an explicit
  administrator change while the domain is revoked.
- An unlocked, nonempty supported password hash, valid account/password aging,
  no forced password change, no applicable nologin restriction, and healthy
  applicable faillock state. Hash support is strict SHA512-crypt, including
  canonical supported `rounds=`, and Fedora's default yescrypt `$y$j9T$` with
  22-character salt and 43-character digest. Other formats or parameter sets
  are unavailable.

Sealing freezes `/etc/passwd`, `/etc/shadow`, `/etc/group`, `/etc/gshadow`,
the relied-on PAM/authselect, NSS and environment files, and their parent
directories, including `/etc`. The complete fixed path list is in
[the lifecycle authority](../crates/localpind/src/accounts.rs). Existing
account tools, password-changing tools, AccountsService and policy/package
administration cannot update these protected files while the domain is active.
This affects every account on the appliance, including accounts without a PIN.
Sealing also refuses any protected file with a preexisting writable descriptor
or shared writable mapping. A successful kernel read lease proves those writers
have drained after immutable flags prevent new write opens. Close the writer
and retry privileged recovery; an unsuccessful seal leaves the domain revoked.
Registry format `LPACCT02` requires this barrier. Earlier experimental registries
are unavailable and require fresh privileged provisioning and re-enrollment.

The trust boundary excludes deliberate root flag clearing, writable aliases or
mount replacement, replacement of the trusted registry, kernel compromise and
deliberate snapshot rollback. An administrator must not use these to retain an
incarnation across an account change. The kernel flags enforce the supported
administration procedure; the snapshot comparison is not a detector for a
completed privileged clear/change/restore bypass.

## Provisioning prerequisites

The non-setuid [localpin-account tool](../crates/localpind/src/bin/localpin-account.rs)
requires real and effective UID 0. The M6.1 lab installs it as
`/usr/libexec/localpin/localpin-account`; release installation belongs to M8.
There is no shell/program argument, alternate state root or secret input.

Before sealing, the privileged deployment must supply root:root 0700
`/var/lib/localpin-accounts` and `/var/lib/localpin`, a root:root 0755
`/run/faillock`, the reviewed fixed helpers and PAM services, and all required
policy inputs. The fixed services are
[localpin-enroll](../crates/localpin-auth/policy/localpin-enroll.review-required)
and
[localpin-eligibility](../crates/localpin-auth/policy/localpin-eligibility.review-required).
Their filenames ending in `review-required` identify source templates, not a
general-purpose activation installer. The complete guarded lab setup is in
[the M6.1 runner](../experiments/m61/run.py).

Stop both socket activation and the broker before `seal` or lifecycle
`recover`: the broker holds a separate storage singleton lease. In the
disposable lab these units are `localpin-m61.socket` and
`localpin-m61.service`. Production unit names and their confinement are part
of M8. A successful `seal` establishes disabled baselines; it does not enroll
a PIN or activate KDE integration.

## Create, delete, rename or change an account

Use this procedure for account creation/deletion, rename, UID/home/shell/group
changes, password changes, locks, expiry, AccountsService operations and changes
to the protected authentication policy:

1. As root, run:

   ```sh
   /usr/libexec/localpin/localpin-account begin-mutation
   ```

   This takes the exclusive global lifecycle lease, durably revokes **every**
   managed incarnation, and only then removes the immutable flags. `Busy`
   means a bounded broker operation still owns a lease; wait and retry.

2. Perform the required normal Fedora administration. A failed or interrupted
   mutation leaves the domain revoked. It does not restore any previous PIN.

3. Stop socket activation and the broker. As root, reseal with the complete
   numeric UID list to support, for example:

   ```sh
   /usr/libexec/localpin/localpin-account seal --uid 21061 --uid 21062
   ```

   Use the appliance's actual selected UIDs. Every `seal` first revokes the
   previous registry again, creates fresh random incarnations, quarantines old
   credential state and durably provisions disabled baselines. It publishes an
   active registry only after successful validation and synchronization.

4. Start the broker and its socket. From each account's eligible local KDE
   session, use the ordinary foreground-terminal flow:

   ```sh
   localpinctl doctor
   localpinctl enroll --backend software
   ```

   Software enrollment is explicit. Use `tpm2-required` only in its separately
   validated deployment; the M6.1 account tests do not spend the everyday host's
   physical TPM guess budget. Enrollment verifies the existing account password
   through the separate password-only worker.

Every reseal requires fresh enrollment for all listed accounts. Renaming an
account grants no incarnation continuity. An identical UID/name/home recreation
receives a fresh identity and cannot inherit the former PIN or password grant.
Changes to an unrelated account also revoke all managed identities because the
protected account databases are shared.

## PIN changes, disable and recovery

Within a healthy sealed domain, an own-user `localpinctl change` or
`localpinctl disable` requires fresh existing-password verification. These
operations change the credential generation under the existing lifecycle
lease. They do not create or repair lifecycle state.

`localpinctl recover --user <account>` is a separate root-only broker operation
that revokes credential state for an existing authoritative account. It does
not repair an unavailable lifecycle registry or prove a new incarnation.

For lifecycle crash recovery, missing/corrupt required state, or explicit
re-provisioning, stop socket activation and the broker and invoke the root
lifecycle command with the complete supported UID list:

```sh
/usr/libexec/localpin/localpin-account recover --uid 21061 --uid 21062
```

This runs the same fresh provisioning path as `seal`. It never adopts pending
or old identities. After success, restart the broker and enroll again.
An error can leave the domain revoked or its inputs frozen; correct the
underlying supported-state problem and repeat privileged recovery. Own-user
enrollment cannot turn a successful password check into authority to repair
missing, corrupt or unsupported lifecycle/storage state.

Old UID state is moved into protected
`/var/lib/localpin/retired/<uid>/<new-incarnation>/` quarantine, preserving crash
evidence and preventing reuse. At most sixteen retained entries per UID are
allowed; further provisioning refuses. Review and remove obsolete entries only
through explicit offline administrator maintenance with the broker stopped.
Do not move an old quarantined enrollment back into the active users directory.
No forensic erasure of snapshots/backups is claimed.

## Password eligibility and accounting

The supervised [eligibility worker](../crates/localpin-auth/src/eligibility.rs)
supplies no password or alternative factor to PAM and refuses every conversation
request. Its private policy preserves `pam_env` and `pam_faildelay`, performs
explicit `pam_faillock preauth silent`, and runs `pam_unix` and `pam_nologin`
account checks. It never calls faillock `authfail`, `authsucc` or its resetting
account hook. Exact policy/native hashes and all input checks are recorded in
[ADR 0012](adr/0012-immutable-appliance-account-authority.md#password-free-eligibility-contract).

A tally must already be a canonical regular single-link file owned by the
target UID and group root, mode 0660, with bounded canonical records in the
root-controlled `/run/faillock` directory. The worker checks its bytes and
metadata before and after PAM. Missing, unreadable, changed, future-dated or
noncanonical state makes PIN unavailable. Eligibility does not create, reset,
normalize or add a failure record.

Privileged sealing may establish a missing empty tally only after the old
incarnations are durably revoked. Existing canonical tallies are preserved;
noncanonical existing tallies stop provisioning. Fedora's default `/run`
directory is volatile. After a reboot a missing tally leaves PIN unavailable
until explicit privileged recovery and fresh enrollment. An ordinary password
operation may also create native accounting state, but own-user enrollment
cannot repair required lifecycle or disabled-storage baselines.

The existing password route retains its normal accounting. In particular,
wrong password attempts can add faillock records and normal password success
can reset them according to that service's policy. A PIN-format password can
also consume a LocalPIN attempt when M7 integrates the shared field. No counter
is suppressed or reset to conceal that ambiguity.

## Diagnose an unavailable account

Use `localpinctl doctor [--json]` or `localpinctl status [--json]` from the
account's supported session. Output does not expose another account's state,
shadow data, incarnation identifiers or authentication grants. The relevant
sanitized reasons are:

| Reason | Action |
| --- | --- |
| `account-unsupported` | Ask the administrator to check the supported domain and explicitly provision a disabled baseline. |
| `lifecycle-unavailable` | The domain is revoked, busy, unsealed, or required state is missing/corrupt; check the cause and perform privileged recovery/resealing with fresh enrollment when needed. |
| `eligibility-unavailable` | Inspect the exact reviewed PAM/native policy, password format and canonical faillock state; an unknown policy or package update requires review. |
| `account` | Inspect locks, expiry, required password changes and restrictions through the normal password/recovery administration procedure. |
| `session` | Use the account's supported local KDE session; ambiguous or ineligible session routing refuses PIN use. |
| `storage` | Inspect protected state ownership, permissions and consistency; own-user enrollment cannot initialize or repair it. |
| `busy` | Wait for the current bounded operation to finish and retry. |

The client distinguishes installation, enrollment, test evidence and integration
activity. Reaching the broker or enrolling a PIN does not establish a tested
desktop unlock path. Continue to use the existing password route while the
remaining integration and packaging gates are open.
