# Fedora KDE installation and recovery

Use this runbook to install, prepare, test, activate, update, or remove LocalPIN
on Fedora KDE 44 x86_64 with ordinary local files accounts and the distribution's
local authselect profile. Start in a disposable VM with SELinux enforcing and a
recoverable snapshot. LocalPIN is experimental; there is no supported production
release. See [everyday use](usage.md) for backend choices and user commands, or
the [documentation index](README.md) for other guides.

## Guided setup

This section describes the M8.2 guided CLI. The published `v0.1.0-alpha.1`
predates it and provides `localpinctl` with the
[manual setup checklist](#manual-setup-checklist). For that release, use
`localpinctl` for manual commands shown as `localpin`; setup and the interactive
menu are unavailable. For guided setup, choose a
[CI testing RPM](../packaging/fedora/README.md#download-a-ci-testing-rpm) for the
intended exact source commit containing M8.2, or a versioned release that
explicitly includes this CLI. CI testing artifacts are unsigned and intended
for disposable VM testing; versioned releases require trusted-signature
verification below.

After verifying that matching RPM, the entry point is:

```sh
sudo dnf install ./localpin-*.x86_64.rpm
localpin setup
```

Run setup as the desktop owner from their own foreground KDE terminal, without
sudo. It uses sudo for a fixed set of packaged administrator operations after
showing the proposed changes and asking for confirmation. Sudo handles its own
password prompt. Enrollment stays in the normal-user process and still requires
fresh account-password verification and private PIN confirmation.

Setup checks the current account, supported policy, persistent accounting,
preparation, enrollment and activation state. It previews preparation, offers an
explicit TPM/software choice, and opens a bounded trial. It then walks through
real desktop/password tests and the console recovery procedure below. Recovery
revokes enrollment. Rerun setup after recovery to prepare and enroll again, test
the final enrollment in a new trial, attest the completed tests and explicitly
activate. No PIN value or user-owned progress file records setup state.

The [one-time offline accounting migration](#prepare-native-accounting-once)
can be scheduled by setup on a supported fresh installation after explicit
approval to save work and sign out. It runs in the same boot and returns to
password login; setup opens again automatically. Setup never copies live tallies
or resets counters. Multiuser installations, unknown
policies, legacy state, incomplete recovery and suspended updates stay with the
manual administrator procedure. Cancelling retains completed stages and can
leave the reported trial window open. Rerunning setup reads authoritative state;
it preserves healthy active installations and does not automatically prepare
them again.

Run `localpin` for a menu, or use the commands below for the complete manual
procedure. `localpinctl` remains a supported compatibility name. The
[new installed report](development/m8.2-installed-acceptance.md) separates actual
guided-flow observations from pending completion; historical results retain
their tested scope.

## Manual setup checklist

1. [Download and verify the RPM](#install-without-activation), then install it in
   the disposable VM. Installation leaves integration disabled.
2. [Prepare persistent native accounting](#prepare-native-accounting-once) from
   a maintenance console with other PAM authentication stopped. Preserve every
   existing tally.
3. [Prepare the selected accounts and enroll](#prepare-and-enroll) from each
   user's foreground KDE terminal.
4. [Start a trial and test](#test-and-activate) real PIN/password unlocking and
   the applicable failure paths, keeping an administrator console available.
5. [Rehearse console recovery](#console-recovery-and-removal), then prepare and
   enroll again, start a new trial, and repeat the desktop tests with the final
   enrollment.
6. [Record the completed tests and activate](#test-and-activate) explicitly.

## Compatibility and evidence

The current implementation uses
[shadow-record account markers](adr/0017-shadow-record-account-authority.md)
and [KDE-specific native authentication accounting](adr/0018-kde-native-update-compatibility.md).
It does not freeze `/etc` or require a reference VM's exact library build.
The earlier [M8 report](development/m8-packaging-recovery.md) describes the
superseded appliance implementation. The
[M8.1 report](development/m8.1-desktop-compatibility.md) records targeted installed
acceptance for the current design. Independent review, physical hardware
validation, and remaining release gates are still required before daily deployment.

## Install without activation

Download the signed experimental RPM and `SHA256SUMS` from the intended tagged
prerelease on [GitHub Releases](https://github.com/tommcamm/LocalPIN/releases).
Follow [Verify and test a download](releasing.md#verify-and-test-a-download):
check the signing key against a separately trusted fingerprint, check the
checksum, and require a valid RPM signature from that key before installation.
Use the [manual checklist](#manual-setup-checklist) for `v0.1.0-alpha.1`;
downloading that release does not provide `localpin setup`.

For unreleased changes, the
[CI testing RPM instructions](../packaging/fedora/README.md#download-a-ci-testing-rpm)
cover unsigned artifacts, their build metadata, and checksum checks. These
artifacts expire after 14 days; checksums do not authenticate the publisher.
Match `CI-BUILD.json` to the intended tested commit containing the guided CLI
before following the guided procedure.
Developers can also [build an RPM](../packaging/fedora/README.md#build-without-installing).

After completing the verification for your chosen artifact, install it in the
disposable Fedora KDE VM with SELinux enforcing, from the download directory:

```sh
sudo dnf install ./localpin-*.x86_64.rpm
```

Installation copies the broker, workers, CLI, PAM module, four disabled private
PAM services, reviewed templates, systemd units and SELinux policy. It does not
enroll users, edit the KDE/authselect/faillock configuration, or start or enable
the broker.

```sh
sudo localpin-integration status
```

The root-only, non-setuid integration tool uses fixed paths. The packaged
`localpin-integration` command is an alias for
`/usr/libexec/localpin/localpin-integration`. Missing, unsafe,
malformed and expired activation gates leave the existing password route.
Enrollment alone never opens the desktop PIN gate.

## Prepare native accounting once

### Automatic preparation for a fresh installation

Use a build containing [ADR 0020](adr/0020-setup-accounting-maintenance.md)'s
maintenance service; older guided builds only explain the manual handoff.
From your normal foreground KDE terminal, run `localpin setup`. With the exact
reviewed stock Fedora configuration and no prior managed account authority,
setup offers the migration before enrollment. Administrator approval is separate
from the later account-password verification used to create a PIN.

If a package operation is running, setup refuses before signing anyone out.
Let the package operation finish, then rerun `localpin setup`.

Save all work before confirming. Maintenance signs out **all users**, stops
system services and background jobs, and temporarily prevents authentication.
A system service takes over independently of the terminal, preserves all native
tallies and their exact backups, switches to persistent accounting, and restores
the graphical login and previously active supported login listeners. No reboot
precedes the copy: doing so would discard the volatile source counters.

Log back into KDE using your full password. A packaged autostart launcher opens
`localpin setup` once for this maintenance request; if no window appears, run
that command yourself. It rechecks privileged state before proceeding. Its
user-owned duplicate-window cache cannot authorize enrollment or activation.
Continue the actual PIN/password and console-recovery tests below.

Unknown policy, an existing managed installation, conflicting tallies or an
incomplete transaction requires administrator review. Automation is deliberately
limited to the current Fedora KDE target. It is not a general repair utility.
Keep a recoverable VM snapshot and verified console/offline recovery access.
If preflight refuses before entering the execution barrier, the service can
restore password login automatically only after proving this is the same boot,
the original accounting policy is intact, and no backup, counter copy or policy
switch has begun. The failed request is retained for diagnosis.

### Interrupted automatic maintenance

Protected maintenance state and exact backups live under
`/var/lib/localpin-integration/control/accounting/`. Do not delete that directory,
reset counters, overwrite persistent tallies with backups, or edit the journal
to claim completion. An incomplete transaction prevents ordinary boot and
selects emergency recovery. The watchdog releases the kernel execution barrier
if the migration worker dies; normal authentication remains withheld until the
accounting authority is verified.

From an administrator root recovery shell, run:

```sh
/usr/libexec/localpin/localpin-accounting recover
```

Before the switch, recovery requires the original volatile configuration and
the same boot, and verifies the source snapshot when one exists. It aborts
without copying or resetting counters. After the switch, recovery requires the
exact durable persistent snapshot and original private backups, then completes
forward and restores login. Different or newer accounting is retained for
manual review; recovery never overwrites it. After a verified abort, setup may
offer a new explicitly approved request while retaining the prior evidence.

Power loss before a durable snapshot can destroy `/run/faillock`. The helper
cannot reconstruct lost counters and refuses to certify preservation. Use the
prepared offline recovery path and inspect retained backups; a recoverable VM
snapshot remains the escape route for disposable testing. Fedora emergency
login itself depends on the VM's configured root recovery access.

### Manual maintenance procedure

Installed activation requires persistent native password accounting:

```text
dir = /var/lib/faillock
```

The directory must be root:root 0755 on persistent local Btrfs, ext4 or XFS
storage. Fedora KDE's default Btrfs is the principal installed test target;
accepting another local filesystem is not physical durability certification.
Only the exact configuration above, ending in a newline, is currently accepted.
Custom thresholds or extra PAM restrictions require explicit compatibility work.

Move from Fedora's default `/run/faillock` only from a maintenance console with
all graphical, remote and other PAM authentication stopped. Stop `localpin.socket`
and `localpin.service`, and revoke any existing domain with
`sudo /usr/libexec/localpin/localpin-account begin-mutation`. Back up the
original configuration and every native tally with its exact bytes, UID, GID,
mode, timestamps, extended attributes and SELinux label. Installed tallies require
the account's UID, root GID and mode 0660; production provisioning and eligibility
do not normalize existing metadata. Ordinary native login or sudo can create a
volatile tally with the account's primary GID. During this explicit offline
migration, after reviewing that native owner/group and saving its exact backup,
create the new persistent copy with GID 0. Preserve every counter byte, UID,
mode and extended attribute, including its SELinux label; leave the original
volatile file untouched. New-copy inode/ctime values necessarily differ; retain
the original atime/mtime where possible. No other group conversion is accepted.

Refuse symlinks, hardlinks, foreign groups, unexpected access/default ACLs,
malformed native records and existing different destinations. A destination
already identical to the reviewed canonical copy can remain unchanged; never
overwrite a conflict or choose the smaller tally. Synchronize each file and
destination directory before atomically replacing the configuration, then
restore distribution SELinux labels. Never reset counters. This GID conversion
is a deliberate maintenance action, never a live wizard/provisioning repair.

This is a one-time offline setup requirement. The activation tool refuses a live
copy while authenticators might be writing. Subsequent normal boots and package
updates retain the persistent tallies and enrollment. Missing accounting requires
explicit recovery, not automatic reconstruction. See [ADR 0014](adr/0014-persistent-faillock.md).

## Prepare and enroll

Use SELinux enforcing, the stock KDE services and supported local authselect
policy. `files systemd` NSS and Fedora's group `files [SUCCESS=merge] systemd`
form are supported. Network identities, systemd-homed, unknown NSS action clauses
and custom authentication restrictions remain outside this domain. Ordinary
`with-fingerprint` and `with-faillock` may be enabled together.
PIN also supports Fedora's disabled-fingerprint profile and keeps it disabled.

Inspect changes, selecting the numeric UIDs of accounts to support:

```sh
sudo localpin-integration prepare --uid 1000 --dry-run
sudo localpin-integration prepare --uid 1000
```

Preparation durably backs up both KDE services and all four private services,
records recovery intent, closes the gate, stops the broker, revokes old managed
incarnations and installs the owned policies. It changes only the two KDE auth
substack references and adds the PIN prefix to `kde`; their other directives and
source formatting are retained. It provisions fresh disabled account markers
under the native account lock, then starts the broker. Unknown policy and
incomplete transactions are refused. No global immutable flags are added.

From each selected user's foreground terminal in a local KDE session:

```sh
localpin doctor
localpin enroll --backend software
```

Choose `--backend tpm2-required` for a validated TPM deployment. The CLI first
prepares and confirms the new numeric PIN or passcode, then obtains
fresh existing-password verification interactively. New input uses one `*` per
character; the account password remains hidden. Preparation has a five-minute
deadline. Do not put secrets in arguments,
environment variables or pipes. See [account administration](account-administration.md)
for marker ownership, ordinary account changes and recovery.

TPM numeric PINs accept 4–16 digits (recommend 6); software PINs accept 8–16
(recommend 10). Optional passcodes accept 8–64 printable ASCII characters in
either backend (suggest 12+), preserving spaces and case exactly. The shared
form selects type and accepts any permitted length. Predictability warnings
require an explicit local override and do not replace broker format validation.
See [credential policy](adr/0021-flexible-credentials.md).

KDE keeps its stock Password field and explicit Enter submission. An account
password matching the enrolled exact length/format can consume a LocalPIN
attempt before exact-byte password fallback; with TPM protection it can also
consume shared dictionary-attack allowance. Test this overlap deliberately in
the disposable VM. Wrong LocalPIN candidates can count as native password
failures. Preserve native counters, cooldowns and TPM safety reserves; never
reset them to advance acceptance.

## Test and activate

```sh
sudo localpin-integration trial
```

The trial lasts ten minutes on suspend-inclusive boot time and expires at
reboot. Test actual PIN unlock, password unlock, unavailable fingerprint sensor,
a genuine failed biometric match where hardware is available, lockout handling,
and console recovery after a component failure. Keep an administrator console.
An expired trial leaves the password route available.

Exercise `recover` below before final activation, then prepare, enroll and repeat
the desktop tests with the final enrollment. After real tests pass:

```sh
sudo localpin-integration record-tests --pin --password --recovery
sudo localpin-integration activate
```

These flags record an administrator attestation, not an automated desktop test.
The attestation binds the boot, live trial, enrollment and installed policies and
binaries. Activation explicitly enables socket startup on later boots. A PIN
success never resets the native password/biometric tally. A successful password
or biometric match resets it through native `pam_faillock authsucc`; an unavailable
sensor or service error adds no false failure. Native preauth still denies a
locked account.

## Updates

Use ordinary `sudo dnf upgrade` for Fedora 44 updates. Native PAM is loaded through
its stable SONAME; per-operation checks replace fixed build hashes. No `/etc`
cache window, thawing or account resealing is required for ordinary distribution
updates. Stock KDE files are distribution `%config(noreplace)` files, while the
four private services are LocalPIN `%config(noreplace)` files. Review `.rpmnew`
files when an upstream service graph changes; unknown authentication semantics
must not be merged automatically.

A compatible LocalPIN RPM upgrade verifies its version/schema, durably suspends
integration, closes the gate and stops services before replacement. After native
RPM file triggers finish, it checks the exact account registry, credentials and
throttles, refreshes only the LocalPIN binary binding and restores previous
service/activation state. A prepared or disabled installation stays unactivated.
Failures retain password recovery and a closed gate. `package-resume` retries a
suspended compatible transaction. Unsupported schema changes and downgrades
require explicit disable/migration; they never silently reset state.

Credential envelope 2 and IPC 2 add numeric/passcode profile metadata. Supported
updates preserve legacy envelope-1 credential and throttle bytes, including
six-digit software PINs. Such PINs keep working with replacement advice; new
changes and backend migrations enforce the target backend's current policy.
There is no automatic credential conversion. While the broker is stopped,
package resume invokes the fixed root-only `localpin-account check-credentials`
operation using shared Rust parsers before reopening the gate. The check writes
nothing and performs no KDF work or TPM attempts. Mixed CLI/broker protocol
versions are rejected before secret transmission; PAM continues to password.
Update all components together and verify status schema 2/profile reporting.

[Flexible-credential validation](development/flexible-credentials.md) tracks the
new boundary and legacy-upgrade acceptance separately. Earlier M8.1–M8.3
installed results retain their exact tested build scope; they do not establish
this feature's installed behavior or physical-hardware/M9 readiness.

The old LPACCT01/LPACCT02 appliance registry and schema-1 activation cannot be
adopted as live desktop identity. Disable with the old tools, verify password
recovery, retain offline backups, and remove the old experimental RPM before
installing the new package and freshly provisioning/enrolling. The old RPM tool
deliberately rejects a schema-2 in-place upgrade, even when disabled. Do not
bypass its scriptlets. Legacy immutable flags are removed only after durable
privileged revocation. This one-time development migration differs from later
compatible schema-2 updates, which preserve the enrollment.

## Migrate the temporary PIN block

Do not stack the temporary `pam_pinlock` policy with LocalPIN. Verify working
full-password and administrator-console recovery before migration, keeping an
administrator console open. The manual helper accepts only its exact known
legacy prefix followed by the recorded stock KDE policy:

```sh
sudo localpin-integration migrate-legacy --dry-run
sudo localpin-integration migrate-legacy
```

The mutation durably saves the original legacy policy and migration intent,
closes the gate, stops the broker, revokes the old account domain and removes
the exact known block. It imports no verifier. An unfamiliar block or modified
stock remainder requires console review; do not force the migration. Verify
stock password recovery after removal, then use `localpin setup` for fresh
preparation, enrollment and tests. This legacy-policy operation is separate
from migration of an old experimental LocalPIN account-registry format.

## Console recovery and removal

Verify the VM/hardware's console-switch and return keys before relying on PIN.
Keep an authenticated administrator text console available throughout the trial.
For the recovery rehearsal in the disposable VM, stop the broker from that
console to exercise component unavailability:

```sh
sudo systemctl stop localpin.socket localpin.service
```

Return to the existing KDE session, lock it normally and verify a real unlock
with the full account password while the broker is unavailable. Return to the
administrator text console and perform owned recovery:

```sh
sudo localpin-integration recover --dry-run
sudo localpin-integration recover
```

Verify full-password unlocking again after recovery. Return to KDE and run
`localpin setup` to prepare and enroll again, then repeat real desktop tests in
a fresh trial. Confirm the console rehearsal only after completing it for this
installed package before the final preparation/enrollment. For recovery of an
actual fault, use the same console commands without trying to reproduce a fault
or spending a TPM's physical failure budget.

`disable` performs the same operation. It closes the gate, stops/disables broker
startup, durably revokes account identity, removes only the owned PIN block and
auth substack substitutions, and restores known private policies from protected
backups. Subsequent unrelated administrator suffix edits are retained. Native
tallies remain intact. No working broker, TPM or PIN module is required.

Changed owned directives, unsafe/missing backups or ambiguous references require
a console review of `/var/lib/localpin-integration/control/manifest.json` and its
named backup. Keep the package installed while reviewing; never guess a PAM
merge or force erase with `--noscripts`. Final RPM erase runs recovery while the
tool, module and policy remain installed, and refuses other PAM services still
referencing any owned module or substack. Credential, throttle, registry, tally
and backup data are retained for explicit administrator cleanup.
