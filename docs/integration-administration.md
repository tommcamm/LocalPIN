# Fedora appliance installation and recovery

The M8 tools target only the provisioned Fedora 44 x86_64 Btrfs appliance in
[ADR 0012](adr/0012-immutable-appliance-account-authority.md). They do not adopt
an everyday Fedora account automatically. Installed validation and remaining
gates are recorded in the [M8 report](development/m8-packaging-recovery.md).
Physical hardware and independent specialist review remain M9 work.

## Install without activating

Build the native RPM using [the packaging instructions](../packaging/fedora/README.md).
Use the resulting RPM in the disposable enforcing VM first. Installation copies
the broker, workers, CLI, PAM adapter, disabled private PAM services, systemd
units and SELinux policy. It does not enroll an account, change KDE/authselect or
faillock configuration, or enable/start the broker.

The administrative tool is non-setuid and has fixed paths:

```sh
sudo /usr/libexec/localpin/localpin-integration status
```

Its JSON distinguishes prepared, timed trial, active and disabled states.
The public activation gate is separate from protected backups and manifests.
Missing, unsafe, malformed or expired gates permit only the existing password
route. Enrollment and broker PIN verification do not open the desktop gate.

## Prepare persistent accounting once

The original `/run/faillock` policy remains supported for older component
experiments. M8 activation requires the exact persistent configuration:

```text
dir = /var/lib/faillock
```

The directory must be root:root 0755 on the reviewed persistent Btrfs filesystem.
This changes the native tally location for every PAM consumer of the global
configuration, including ordinary passwords. It preserves the configured
thresholds, failure interval and unlock time. It does not change authselect.

Perform the transition from a maintenance console with graphical logins,
remote logins and other PAM authentication stopped. Durably revoke any existing
managed domain with `localpin-account begin-mutation` first, and stop both
`localpin.socket` and `localpin.service`. Preserve the original configuration
and **all existing canonical native tally bytes, ownership, modes and SELinux
labels** in root-protected offline backups. Move those records to the persistent
directory without replacing or resetting an existing destination. A mismatching
destination requires an administrator decision; never select the smaller tally.
Synchronize each file and its destination directory before atomically replacing
the configuration. Restore the distribution's correct SELinux labels.

The activation tool deliberately refuses the volatile configuration; it does
not attempt a live tally copy while native authenticators may be writing. A lost
old tally is unavailable state, rather than an empty counter that can be guessed
or reconstructed. Provisioning after this policy change creates fresh account
incarnations and requires enrollment once. Subsequent normal boots use the same
persistent state and enrollment. [ADR 0014](adr/0014-persistent-faillock.md)
describes the contract and native regression evidence.

## Prepare, enroll, test and activate

Prerequisites include files-only NSS, the exact reviewed native PAM inputs,
SELinux enforcing, the original measured KDE service and the supported account
lifecycle setup. The tool refuses the known `with-faillock`/parallel-fingerprint
combination before making changes. It never clears native counters or disables
another authenticator to conceal that incompatibility.

Inspect the proposed exact KDE change first, using all UIDs to support:

```sh
sudo /usr/libexec/localpin/localpin-integration prepare --uid 21061 --dry-run
sudo /usr/libexec/localpin/localpin-integration prepare --uid 21061
```

Substitute the appliance's selected numeric UID. Preparing first makes durable
protected backups and a recovery journal, closes the gate, stops the broker,
revokes the whole account domain, installs the reviewed private policies and
exact KDE block, and seals fresh disabled incarnations. It then starts the
broker. A failed preparation leaves the gate closed and retains its recovery
intent. Unknown policies and existing incomplete transactions are refused.

From each selected account's foreground terminal in its eligible local KDE
session, enroll explicitly:

```sh
localpinctl doctor
localpinctl enroll --backend software
```

Use `--backend tpm2-required` for the emulator test or a separately validated
physical deployment. The CLI asks for the existing account password and new PIN
interactively. Do not pass secrets in arguments, environment variables or stdin.

Open a ten-minute trial as root:

```sh
sudo /usr/libexec/localpin/localpin-integration trial
```

Every selected account must be enrolled. The trial expires on suspend-inclusive
boot time and cannot survive reboot. Test PIN unlock, the existing full-password
route, and administrative recovery after a component failure on the actual
locker. Retain an administrator console throughout. If the trial expires, the
ordinary password route remains available. Start another trial for another test.

Exercise the root console-recovery procedure below before final activation. It
revokes the test enrollment. Prepare and enroll again afterward, then repeat
the current PIN and password tests with the same installed package. Successful
password fallback with a missing module is a separate check; it does not by
itself test root recovery.

After completing the real desktop tests, the administrator records them and
activates the tested enrollment:

```sh
sudo /usr/libexec/localpin/localpin-integration record-tests --pin --password --recovery
sudo /usr/libexec/localpin/localpin-integration activate
```

These flags are an **administrator attestation**, not automated proof that a
desktop test ran. The recorded evidence is tied to the current boot, trial,
account/credential generations, protected policy inputs and installed binaries.
Activation refuses missing, stale or changed bindings. The M8 experiment runner
performs the actual UI tests separately before recording the attestation.
Successful activation explicitly enables the socket for future boots.
Preparation and trial alone leave boot startup disabled; recovery disables it.

## Recover a failed graphical unlock

Use the verified appliance keyboard shortcut to reach a text console. Console
switch/return keys depend on the deployed keyboard and compositor; verify them
in the VM before relying on PIN. Authenticate with the existing administrator
password and run:

```sh
sudo /usr/libexec/localpin/localpin-integration recover --dry-run
sudo /usr/libexec/localpin/localpin-integration recover
```

The real operation closes the PIN gate, stops socket activation and the broker,
durably revokes all managed incarnations, removes only the exact owned leading
KDE block and restores known private policies from protected backups. It does
not need a working PAM adapter or backend worker. It preserves subsequent
administrator KDE edits and persistent native accounting. No reboot or OS
reinstallation is required. `disable` runs the same recovery operation.

If the owned block itself changed or a backup is missing/corrupt, recovery
closes the gate and refuses to guess a PAM merge. From the console, inspect
`/var/lib/localpin-integration/control/manifest.json` and its named backup.
Verify the original KDE digest against `7d91b3ad73a998e8b10f9edccd74ba04179a778c4a5e61d9176872f43c7bbac3`
before using that backup. Preserve the changed file for review. If the lifecycle
helper is missing, restore the matching package/helper from the console before
revoking/unfreezing the managed domain. Do not clear immutable flags while
claiming the old enrollment remains valid.

## Upgrade, downgrade and uninstall

Compatible RPM release upgrades use schema 1 and unchanged reviewed policy.
Run upgrades as a LocalPIN-only maintenance transaction, with other account and
policy administration quiescent. General system upgrades are outside this
continuity procedure; revoke the domain before that maintenance and provision
fresh incarnations afterward.
The old tool checks candidate EVR with RPM's own version comparison, refuses
downgrades/unknown transitions, and durably records suspension before stopping
services. The upgrade closes the gate and preserves account incarnations,
credential generations and throttle records. RPM preserves the locally enabled
private `%config(noreplace)` policies. The new tool checks their exact bytes and
metadata plus unchanged credential/throttle bindings before resuming the
previous services. Desktop testing and activation must be repeated for the new
binaries; enrollment is retained.

Fedora's normal library-cache triggers run during this transaction. A fixed
native helper first durably suspends account authority and releases only the
`/etc` directory flag. Protected account files, PAM files and other protected
directories remain immutable throughout. The final package trigger refreezes
`/etc` and restores the original account incarnations only after exact input
checks. Only `/etc` directory size and change timestamps may differ. No native
RPM trigger is skipped, and no account or credential is silently resealed.
See [ADR 0016](adr/0016-package-cache-window.md) for crash boundaries.

An interrupted upgrade retains a suspended journal. After correcting the
package/input problem, retry:

```sh
sudo /usr/libexec/localpin/localpin-integration package-resume
```

Unknown policy/schema migrations require a separately reviewed procedure.
The tool does not import or silently reinterpret another version's state.

Uninstall runs owned recovery while the module, workers and SELinux policy are
still installed. It refuses to remove the package while any PAM service still
references LocalPIN. It then stops/disables the socket before removing files
and policy. Protected backups, retired state and persistent faillock records
remain available for explicit administrator retention/cleanup; uninstall never
deletes native password accounting.

## Migrate the temporary PIN block

The only recognized legacy prefix is the measured three-line
`# BEGIN local screen-unlock PIN` block containing
`auth sufficient pam_pinlock.so retries=1`, followed by the exact measured stock
KDE service. Other legacy edits require manual review.

First verify the existing full-password route and prepare a working console.
Then inspect and remove that exact prefix:

```sh
sudo /usr/libexec/localpin/localpin-integration migrate-legacy --dry-run
sudo /usr/libexec/localpin/localpin-integration migrate-legacy
```

The tool saves a durable protected original and journal before revocation or
edits. It imports no old hash, PIN or credential. Verify stock password recovery,
then follow prepare/enroll/trial/test/activate above. This ordering reflects the
existing immutable-authority contract: replacing any protected PAM policy
requires fresh account incarnations. The two PIN modules are never stacked.
