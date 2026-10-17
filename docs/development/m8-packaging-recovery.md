# M8 Fedora packaging, activation and recovery

Date: 2026-10-17. **M8 implemented and installed acceptance passed for the
restricted Fedora 44 x86_64 Btrfs appliance below.** The
[49-case installed evidence](../../experiments/m8/results/2026-10-17-fedora44-rpm-recovery.json)
records executed results with SELinux enforcing. M9 independent human/specialist review, physical hardware
validation, signing and release remain open.

## Implemented scope

- Native x86_64 project-distributed RPM build with locked Rust inputs, build
  hashes, disabled private PAM defaults, systemd units, SELinux policy, tmpfiles
  and a disabled socket preset. Installation does not enroll or activate.
- Fixed root administration with dry-run diffs, protected original backups,
  durable intent, atomic edits, fresh lifecycle provisioning, ten-minute
  boot-bound trials, explicit operator test attestation and activation.
- Exact persistent faillock support shared by provisioning and eligibility.
  Offline accounting migration preserves native records once; normal boot no
  longer depends on volatile `/run/faillock` continuity. Missing or corrupt
  persistent state still denies PIN and never falls back to an empty tally.
- Explicit refusal of the measured with-faillock/parallel-fingerprint
  composition. This addresses activation safety; it does not claim KDE's native
  accounting behavior has been repaired or broaden the supported profile.
- Owned disable/text-console recovery, exact legacy-block migration without
  verifier import, compatible release upgrades preserving committed account,
  credential and throttle state, downgrade refusal and guarded final erase.
- CLI presentation distinguishing installation, enrollment, trial and explicit
  activation. Operator attestation is labelled as such; it is not automated
  desktop test evidence.

Contracts and procedures are in [ADR 0014](../adr/0014-persistent-faillock.md),
[ADR 0015](../adr/0015-m8-activation-and-rpm.md), the
[administration runbook](../integration-administration.md), and
[packaging instructions](../../packaging/fedora/README.md).

## Native access and confinement review

The service confines the broker and exec-transitioned one-operation workers to
dedicated SELinux domains and a common systemd resource/device/filesystem
sandbox. Only the backend has TPM device access. The broker's existing lifecycle
authority hashes protected account inputs, including shadow; its read-only
shadow permission is explicit and is not misrepresented as a complete inability
to read password hashes. Neither broker nor workers can update shadow.

Linux-PAM 1.7.2 opens even a preauth tally `O_RDWR` and treats inaccessible/missing
state as successful preauth. Eligibility now proves existing-file read/write
access before PAM and in its post-check. It uses no create/truncate/write call.
The native preauth-only policy and exact before/after snapshots enforce
non-mutation; SELinux permits only the required existing-file descriptor access,
without creation, deletion, mode/ownership changes or directory writes. Native
authentication gets existing-file access for its legitimate counter changes.
The service needs no CAP_CHOWN for correctly provisioned user:root 0660 tallies.

Review also corrected exact native loader/cache labels, boot-ID reads, Btrfs
filesystem inspection, process-group signal-zero reaping, D-Bus path traversal,
NoNewPrivileges domain transitions, systemd's service-derived socket SID, the
Fedora shadow-read attribute, boot tmpfiles ownership and service namespace mount
permissions. These are source-informed development findings, not independent M9
review. Installed enforcing observations remain the acceptance authority.

The enforcing VM also identified two compatibility requirements absent from the
initial source policy. Systemd 259's `RestrictSUIDSGID` blocks the required
`openat2` syscall, so that directive is removed while NoNewPrivileges, MAC,
capability and filesystem limits remain. Native `pam_unix` account checks execute
the measured Fedora `unix_chkpwd` helper; its exact hash is now pinned and the
workers may enter Fedora's maintained `chkpwd_t` domain. Effective policy
inspection confirms that domain cannot change its process group; the service
also denies `setsid`.

Fedora's normal RPM library-cache triggers exposed a separate immutable-`/etc`
conflict. [ADR 0016](../adr/0016-package-cache-window.md) specifies the bounded
authority suspension and directory-only cache window implemented for upgrades.
Protected account and PAM files never become writable during a compatible
upgrade. The real RPM transaction passed with Fedora's normal cache triggers.

## Local verification

Executed local checks include workspace formatting, strict all-target Clippy,
workspace tests/doctests, native release/RPM builds, the pinned cargo-deny
advisory/license/bans/source checks, protected/enrollment broker namespace tests,
native PAM fallback and gate tests, and isolated native persistent-tally tests.
The ordinary syscall sandbox denies required IPC/process/namespace operations;
those suites were rerun successfully with the required permissions and synthetic
private namespaces. No host authentication configuration, credential record or
physical TPM was used as a test fixture.

The activation unit suite covers backup and manifest hazards, non-mutating dry
runs, exact owned-block handling, preparation crash ordering, bounded trials,
attestation binding, upgrade suspension/resume failure boundaries, downgrade
refusal, legacy migration and remaining PAM references. VM guard tests reject
physical/shared TPMs, shared/backed disks, changed identities, host device or
filesystem shares and unbound evidence. Packaging checks compile policy and
inspect opt-in installation/scriptlet/resource-bound invariants.

Hosted CI source now includes these checks and a Fedora RPM build. Hosted CI
execution has not been verified and is not inferred from local success.
The [sanitized local check record](../../experiments/m8/results/2026-10-17-repository-checks.json)
records 307 passing workspace tests (10 separately ignored), six subsequently
added cache-window tests and two account-CLI tests executed separately, 51
administrative transaction tests, 21 VM guard tests, eight packaging/policy
checks and 77 isolated production-PAM pass records. The later Rust changes added
tests only. Native broker and access-denial suites were executed separately;
ignored entries alone are not passing evidence.

## Installed enforcing evidence

The experiment used a fresh independent clone of the existing clean Fedora 44
KDE snapshot. The original remained off. The clone had no host shares or
physical/passthrough TPM, and used its own libvirt-managed TPM2 emulator. SSH
access was bootstrapped through offline clone-only disk preparation and a pinned
host key. SELinux stayed enforcing throughout.

Executed: actual stock KDE password unlock; clean RPM installation with
unchanged KDE/no enrollment/inactive socket; changed KDE and missing module
preparation refusals; native authselect fingerprint/faillock-specific refusal;
actual legacy-stack password unlock; exact legacy migration and subsequent
stock-password unlock. Preparation durably reached the disabled prepared state.
The complete RPM pair then replayed clean installation, native TPM-required
enrollment, actual KDE PIN/password tests, and missing-module console recovery
on the same greeter without reboot. PIN unlock required Enter and preserved the
native tally. Recovery revoked its test enrollment; fresh preparation and
enrollment preceded the final activation tests. The product enabled its own
socket at explicit activation, without a fixture startup workaround.
The administrative recovery command ran through the pinned root SSH console
while the real greeter stayed locked. This proves command recovery of that
greeter; local VT switching and administrator login remain deployment checks.

The real compatible RPM upgrade preserved account IDs, TPM credential and
active pointer, committed throttle, and protected PAM digests/inodes. Only the
reviewed `/etc` directory registry metadata changed. Native glibc cache triggers
ran normally. The gate remained disabled pending retesting. Corrupt-backup
erase and explicit RPM downgrade were both refused with policy/enrollment
intact. A causal kernel audit event proved the injected worker-label denial
(`localpin_broker_t` to `default_t`, file `execute`, `localpin-worker`), with
actual same-greeter password fallback and subsequent label repair.

An ordinary real reboot preserved the exact registry, active pointer, original
TPM credential, committed throttle and persistent native tally. The original
PIN succeeded through KDE PAM without fresh enrollment. A second real reboot
interrupted the package cache window: authority remained revoked, the gate
disabled, and every protected input except the `/etc` directory stayed
immutable. PIN was denied while the same greeter admitted the full password.
Explicit resume restored the same account IDs, TPM credential and throttle;
only the permitted directory metadata changed, and the gate stayed disabled
until retesting.

Explicit disable restored the exact stock policy and removed boot startup;
actual graphical password unlock passed afterward. Only after all original
enrollment continuity checks completed did a separate incarnation exercise final
erase. Three real failed password authentications created 192 bytes of native
faillock records and made PIN unavailable. Actual same-greeter password recovery
preserved those bytes. Active RPM erase restored the owned password route before
removing the module, revoked account authority, and retained the exact failed
native tally. Actual graphical password unlock after uninstall preserved all
192 bytes. The default reviewed KDE graph does not itself enforce an auth-phase
faillock hook; this does not claim otherwise.

All 49 recorded cases passed. The two tested RPMs contain the complete native
implementation; their public package digests are in the evidence file. Later
source additions contain tests and documentation only. Diagnostic staging was
superseded by the full matching RPM replay.

Guarded cleanup removed temporary access, guest secrets/autologin, the clone,
its private emulator state, its independent disk, and both large offline
bootstrap copies. The original VM remains defined and off. No host PAM/account
configuration or physical TPM was modified.

## Retained limits

Support remains ADR 0012's restricted Fedora 44 x86_64 Btrfs appliance with exact
native policy/binary inputs and files-only NSS. Ordinary unmanaged Fedora
accounts and unknown policy/schema transitions remain unavailable. Persistent
accounting does not protect against deliberate root/storage rollback or make
driver rebind return the original device number. TPM unavailability retains
password fallback and never silently selects software.

M8 does not clear the physical TPM, change dictionary-attack settings, disable
another authenticator or reset native counters to conceal incompatibility.
The unsafe fingerprint/faillock composition remains refused. Another agent's
development review and simulator/VM execution do not substitute for M9's
independent review and physical hardware matrix.

The installed record includes the native package versions actually retained
from the run and the exact enforced PAM/helper and profile fingerprints. Kernel
release and several package EVRs were not retained before cleanup; the record
marks them unavailable rather than substituting host values. M9 must capture
the complete target inventory and exercise its broader compatibility matrix.
