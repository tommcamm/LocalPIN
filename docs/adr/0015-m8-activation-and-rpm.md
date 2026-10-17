# ADR 0015: Staged activation, owned recovery and compatible RPM upgrades

Date: 2026-10-17. Status: M8 implementation decision; installed acceptance is
tracked separately in the [M8 report](../development/m8-packaging-recovery.md).

M8 retains ADR 0012's restricted account domain and ADR 0013's exact KDE layout.
It accepts only the default reviewed password-auth profile for activation.
The measured with-faillock/parallel-fingerprint composition is explicitly
refused until separate policy review and actual desktop evidence establish
usable accounting. Neither native counters nor other authenticators are altered
to make its tests pass.

Activation requires ADR 0014's exact persistent faillock configuration. Migration
of existing native accounting occurs offline under administrator control;
activation does not copy mutable live counters, manufacture lost history or
fall back to the volatile location.

## Gate and evidence

Preparing the exact integrated policy revokes the old domain and creates fresh
disabled account incarnations once. A separate root-controlled gate allows
enrollment and component verification while desktop PIN remains unavailable.
The PAM adapter checks the gate with the service/identity checks before capture,
after the conversation and after verification. It returns the normal fallback
outcome when the gate is absent, unsafe, malformed, disabled or expired.

`/var/lib/localpin-integration` is root:root 0755. Its `gate` is a single-link
root:root 0644 regular file opened beneath `/` without symlinks; control state,
locks, backups and journals live in a root:root 0700 `control` directory.
The exact active representation is `LPINT01\nactive\n`. Trial records carry the
current boot UUID and start/deadline on `CLOCK_BOOTTIME`, with at most ten
minutes of exposure. Trial authorization expires through suspend and reboot.
Expiry requires no background process or successful cleanup job.

The administrator runs actual desktop PIN, password and failure/console
recovery tests, then records an explicitly labelled operator attestation.
Attestation is not fabricated automated UI evidence. Activation binds it to
the trial boot, selected credential generations, protected account/policy
snapshots and installed binary digests. It requires all three completed-test
flags. CLI status distinguishes trial, active and attested state.
Only successful explicit activation enables `localpin.socket` for subsequent
boots. It closes the gate before enabling/starting the socket, and publishes
the active gate afterward. Preparation/trial alone do not enable boot startup;
disable and console recovery disable it before account mutation.

The console-recovery exercise runs before final activation and revokes its test
enrollment. The administrator then prepares and enrolls again, repeats PIN and
password tests, and attests the tested recovery procedure for the same installed
package. A missing-module password fallback alone does not prove the root
console-recovery procedure. The attestation binds the final enrollment; it does
not claim that destructive recovery preserved the earlier credential.

## Transactions and recovery

The fixed non-setuid Python administrative entry point uses isolated Python,
closed arguments, a fixed child environment, no shell, a nonblocking permanent
integration lock and bounded root-owned single-link files. Dry runs do not
create state or close/open gates. Root changes save and synchronize original
policies and recovery intent before revocation or edits; policy replacement is
atomic and synchronized. Native helper paths are fixed.

Recovery closes the gate and revokes before restoring policy. It removes only
the exact leading owned block and preserves subsequent administrator bytes.
Changed blocks, ambiguous additional PIN policy or corrupt backups refuse a
guessed merge. All required backups are validated before protected edits.
Missing workers or adapter binaries do not prevent known-policy recovery.
Persistent native accounting is never reset or removed by recovery/uninstall.

The legacy migration recognizes one exact measured prefix plus the measured
stock suffix. A protected original and migration intent precede edits. Old
verifiers are never imported. Because the lifecycle authority pins full PAM
bytes, legacy removal precedes fresh sealing/enrollment; component enrollment
under the old unknown graph cannot establish continuity across that change.
This refines the ordering in the original M8 roadmap while preserving the
verified password route and the prohibition on stacking PIN modules.

## RPM compatibility

Initial installation does not start/enable the socket, enroll or activate.
Private PAM services are packaged disabled as `%config(noreplace)`; reviewed
enabling samples are separate data files. SELinux and systemd confinement are
packaged explicitly. Project-distributed native binary RPMs are distinguished
from future Fedora repository source packages; signing remains M9.

Schema-1 upgrades within version 0.1.0 compare candidate EVR with RPM's native
version comparator and refuse downgrades/unknown transitions. They close the
gate and save service/suspension intent before stopping anything. With the
broker stopped, the old tool saves registry, credential and throttle equality
bindings. The new tool verifies unchanged protected policy metadata and state
before resuming services. LocalPIN binaries may change; test attestation is
invalidated and the gate stays closed until new desktop tests and activation.
Enrollment and throttle state remain committed. Fedora's library-cache triggers
need a writable `/etc` directory. The narrow cache window in
[ADR 0016](0016-package-cache-window.md) durably suspends account authority before
releasing only that directory flag; all protected files remain immutable. After
the native RPM triggers, the helper verifies the original authority and restores
the same incarnations with only `/etc` directory size/change timestamps refreshed.
The equality binding includes every other registry byte. Interrupted
suspension/resume is retryable; an unsuccessful package transaction cannot reopen
the gate.

Direct `localpin-account begin-mutation`, `seal` and `recover` also remove and
synchronize any existing safe desktop gate before revoking the account registry.
They never create a gate or carry an old approval into freshly provisioned
incarnations. Missing pre-M8 integration installation remains a normal component
case; an unsafe gate refuses administration before continuity is changed.

Final erase recovers while code/policy still exist, checks all PAM services for
remaining LocalPIN references, stops/disables the socket, then removes package
files and SELinux policy. Unknown state aborts removal for console review.
