# Fedora KDE installation and recovery

The current M8.1 implementation targets Fedora KDE 44 x86_64 with ordinary local
files accounts and the distribution's local authselect profile. It uses
[shadow-record account markers](adr/0017-shadow-record-account-authority.md)
and [KDE-specific native authentication accounting](adr/0018-kde-native-update-compatibility.md).
It does not freeze `/etc` or require a reference VM's exact library build.
The earlier [M8 report](development/m8-packaging-recovery.md) describes the
superseded appliance implementation. The
[M8.1 report](development/m8.1-desktop-compatibility.md) records targeted installed
acceptance for the current design. Independent review, physical hardware
validation, and remaining release gates are still required before daily deployment.

## Install without activation

Build the RPM using [the packaging instructions](../packaging/fedora/README.md)
and install it in a disposable enforcing Fedora KDE VM first. Installation
copies the broker, workers, CLI, PAM module, four disabled private PAM services,
reviewed templates, systemd units and SELinux policy. It does not enroll users,
edit the KDE/authselect/faillock configuration, or start or enable the broker.

```sh
sudo /usr/libexec/localpin/localpin-integration status
```

The root-only, non-setuid integration tool uses fixed paths. Missing, unsafe,
malformed and expired activation gates leave the existing password route.
Enrollment alone never opens the desktop PIN gate.

## Prepare native accounting once

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
`localpin-account begin-mutation`. Back up the original configuration and every
native tally with its exact bytes, owner, mode and SELinux label. Copy all
canonical native tallies to the persistent directory without overwriting an
existing different destination. Synchronize each file and destination directory
before atomically replacing the configuration, then restore distribution SELinux
labels. Never reset or choose the smaller tally to resolve a conflict.

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
sudo /usr/libexec/localpin/localpin-integration prepare --uid 1000 --dry-run
sudo /usr/libexec/localpin/localpin-integration prepare --uid 1000
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
localpinctl doctor
localpinctl enroll --backend software
```

Choose `--backend tpm2-required` for a validated TPM deployment. The CLI obtains
the existing password and new PIN interactively; do not put them in arguments,
environment variables or pipes. See [account administration](account-administration.md)
for marker ownership, ordinary account changes and recovery.

## Test and activate

```sh
sudo /usr/libexec/localpin/localpin-integration trial
```

The trial lasts ten minutes on suspend-inclusive boot time and expires at
reboot. Test actual PIN unlock, password unlock, unavailable fingerprint sensor,
a genuine failed biometric match where hardware is available, lockout handling,
and console recovery after a component failure. Keep an administrator console.
An expired trial leaves the password route available.

Exercise `recover` below before final activation, then prepare, enroll and repeat
the desktop tests with the final enrollment. After real tests pass:

```sh
sudo /usr/libexec/localpin/localpin-integration record-tests --pin --password --recovery
sudo /usr/libexec/localpin/localpin-integration activate
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

The old LPACCT01/LPACCT02 appliance registry and schema-1 activation cannot be
adopted as live desktop identity. Disable with the old tools, verify password
recovery, retain offline backups, and remove the old experimental RPM before
installing the new package and freshly provisioning/enrolling. The old RPM tool
deliberately rejects a schema-2 in-place upgrade, even when disabled. Do not
bypass its scriptlets. Legacy immutable flags are removed only after durable
privileged revocation. This one-time development migration differs from later
compatible schema-2 updates, which preserve the enrollment.

## Console recovery and removal

Verify the VM/hardware's console-switch and return keys before relying on PIN.
Authenticate to a text console with the full administrator password:

```sh
sudo /usr/libexec/localpin/localpin-integration recover --dry-run
sudo /usr/libexec/localpin/localpin-integration recover
```

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
