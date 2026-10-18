# Accounting-maintenance abort and desktop shutdown validation

Date: 2026-10-18. Targeted installed validation for
[PR #13](https://github.com/tommcamm/LocalPIN/pull/13), under
[ADR 0020](../adr/0020-setup-accounting-maintenance.md). The inspected
[sanitized evidence](../../experiments/m83/results/pr13-maintenance-abort.json)
retains passing observations and failed acceptance attempts separately.

The final `vm13.4` candidate passed migration, native-history preservation,
CUPS shutdown ordering, actual password login and shipped setup resumption,
package removal and stock-password unlocking. The partial-mask refusal and
aborted-setup explanation passed on the initial candidate; that whole scenario
was not repeated on `vm13.4`.

## Environment and tested payload

Two independent disposable Fedora KDE 44 x86_64 clones used enforcing SELinux,
synthetic accounts and private managed TPM emulators. The M8 host/guest guards
restricted operations to exact clone identities, independent disks without
backing stores, and no host shares or physical devices. The original VM
remained defined and off; host authentication and physical TPMs were not used.
Initial and final native environments were identical:

| Component | Observed version |
| --- | --- |
| Kernel | `7.2.10-200.fc44.x86_64` |
| systemd | `0:259.9-1.fc44.x86_64` |
| PAM | `0:1.7.2-2.fc44.x86_64` |
| authselect | `0:1.7.1-1.fc44.x86_64` |
| kscreenlocker | `0:6.7.5-1.fc44.x86_64` |
| selinux-policy-targeted | `0:44.11-1.fc44.noarch` |
| glibc-common | `0:2.43-9.fc44.x86_64` |
| tpm2-tss | `0:4.1.3-9.fc44.x86_64` |

Authselect used
`local with-silent-lastlog with-mdns4 with-fingerprint with-faillock`.
Fingerprint configuration does not establish physical fingerprint operation.

The final RPM was
`localpin-0.1.0-0.1.alpha1.vm13.4.fc44.x86_64.rpm`, SHA256
`fb5ea182f4c8728297c433139a3a274fe7f40b1c9cec26b2f63825445e288cf2`.
Its source base was `559395c09b6c533ac44014cefd5f1efd4f39a3d9`, with
`tools/localpin-accounting.py` the sole changed runtime source since that base.
The tested helper source SHA256 matched its installed payload:

| Installed file | Final SHA256 |
| --- | --- |
| `/usr/libexec/localpin/localpin-accounting` | `b3fb8cd341becfe9f4b51b4ca58325043eab26fb88dd8f7a9a62fae47ecfb1c0` |
| `/usr/libexec/localpin/localpin-integration` | `fe205343c33c142bbc3b375d39b7decf2f3b0a1c98327d0e30af00a03656f48d` |
| `/usr/bin/localpin` | `819c3c41629c90c604ca5baeb77d965c8ce151b0d63ae286c5048a7ae8f215b4` |

The aggregate records initial/intermediate payload hashes and the final observer
source/unit hashes. The initial EVR was `0.1.0-0.1.alpha1.fc44`; its accounting
helper SHA256 was
`95ed64850f9172ae9a48816de37c16d240663d5a22874016ff578f8d079cb1c4`.
The integration helper and CLI were unchanged across these candidates. Final
follow-up changes did not modify masking or abort-UI behavior, but their earlier
installed evidence remains scoped to the initial candidate.

## Final installed acceptance

`vm13.4` retried the recovered abort on the same clone and boot, preserving
legitimate volatile failure history without a counter reset or reboot.

| Case | Observed result |
| --- | --- |
| Real user-service stop observer | Seven CUPS-active samples over `3,051,291` microseconds |
| Native CUPS stop | `189,379` microseconds after observer completion; systemd timestamp and native stop event both proved order |
| Migration | Complete; two native counters, including one nonempty counter, preserved bytes/security metadata before another login |
| Policy and backup | Volatile sources untouched; original backup metadata retained; only approved destination GID conversion; persistent policy installed; KDE PAM unchanged |
| Restoration | Recorded `restored`; required login services active, no unrelated systemd jobs and cgroups thawed; owned masks released |
| Actual password login/resume | Shipped launcher opened installed setup in a real Konsole; completed migration/restoration explained and readiness rechecked |
| Preparation boundary | Deliberate prior-recovery/preparation gate reached; setup cancelled before preparation, with no enrollment or account authority |
| Actual RPM removal | Final candidate erased; original stock KDE policy retained, native persistent accounting bytes/UID/GID/mode/mtime/xattrs retained; module absent and broker inactive |
| Post-removal password | Actual stock-password lock-screen unlock passed with SELinux enforcing |

The resumed setup did not automatically retry maintenance or echo secrets.
These observations verify the changed flow without claiming PIN enrollment or
activation on this candidate.

## Initial and intermediate observations

### Partial-mask refusal and abort explanation: passed on initial candidate

A clone-only regular unit file at `/run/systemd/system/atd.service` made the
real `systemctl mask --runtime` return exit status 1, categorized `file-exists`.
The worker recorded `mask-authentication`, aborted before isolation and marked
restoration `not-needed`. The original session/user manager, active CUPS/login
services, native tallies/security metadata and stock volatile policy survived.
No barrier, backup or copy began. Only owned masks were released, preserving
the conflict; an aborted hint was published without enrollment.

After an actual display-manager password login, the shipped launcher opened
installed setup in a real Konsole. It explained the abort, incomplete
preparation and failed operation and required deliberate retry approval.
Declining left the request unchanged; no automatic retry or secret echo
occurred. The exact conflict fixture was then verified and removed. This
reproduces an actual partial-mask failure, without establishing that the
physical-machine failure had the identical conflicting unit file.

### Initial migration passed; shutdown-order acceptance failed

The subsequent request migrated both native counters, including nonempty
history, with bytes/security metadata and backups preserved. Volatile sources
and KDE PAM remained unchanged, only the approved destination GID conversion
occurred, the kernel barrier ran, owned masks were released, restoration was
verified and the abort evidence was archived. No PIN was enrolled.

Nevertheless, CUPS began stopping at monotonic microsecond `432374139`, before
`user@21061.service` began stopping at `432453764`; CUPS stopped at `432512239`.
The user stop observer was killed without output (`observer_output_bytes=0`).
This candidate failed shutdown-order acceptance despite completing migration.

The correction explicitly waits for loaded `user@*.service` and
`user-runtime-dir@*.service` stop jobs, along with the display manager and
`user.slice`, before isolation. A slice stop alone did not establish that drain.

### Explicit manager drain passed ordering; barrier acceptance failed

In a fresh guarded clone, the manager-drain candidate completed seven
CUPS-active observer samples over `3,047,123` microseconds; native CUPS stop
followed `207,670` microseconds later. Maintenance then failed at
`barrier-started` with `FileNotFoundError`, errno `2`, before a source snapshot,
backup or tally copy. It entered emergency recovery.

A real emergency-console login authenticated with the synthetic root fixture.
The installed helper proved an untouched same-boot abort. Restoration remained
`pending` while its own console stop job could not finish. After that console
closed, a second installed recovery invocation from an independent
administrator context verified `restored`. Native counter bytes survived
without a copy. This proves same-boot recovery, not migration acceptance.

A drained empty slice can disappear while PID1 finishes lifecycle cleanup.
The correction freezes and observes `init.scope` first, recomputes the normal
cgroup inventory with PID1 frozen, then freezes/kills those groups. The final
topology equality check and kernel exclusion proof remain mandatory.

### PID1-only preflight safely refused vm13.3

`vm13.3` included the PID1-first inventory correction. Its observer completed
seven CUPS-active samples over `3,053,909` microseconds, then maintenance safely
aborted in `quiescing` with `unexpected init scope processes`. No barrier/copy
began, native bytes were preserved and login restoration was verified. A later
inventory contained only PID1. A transient systemd executor is a plausible
explanation, not a captured process identity.

The final correction waits up to ten seconds for exactly PID1 before the
barrier; extra processes are never admitted and the strict post-freeze check
remains unchanged. Synthetic regressions cover disappearing/new allowed
slices, freeze timeout, bounded PID1 waiting and refusal after a process
reappears. The final installed pass is recorded separately above.

## Local validation

| Check | Result |
| --- | --- |
| Python tools suite | 179 passed |
| M8.3 fixture suite | 16 passed |
| Fedora packaging, including release helpers | 86 passed |
| Final native RPM build | Passed |
| Rust checks at source base | 399 passed, 11 ignored; formatting, Clippy and release build passed |

Rust sources were unchanged by this VM follow-up. Local results are separate
from hosted CI; this report makes no hosted-pass claim. Ignored Rust tests are
not counted as installed coverage.

## Reproduction outline

Use the [M8.3 workflow](../../experiments/m83/README.md) and its linked host,
guest, real-Konsole and keyboard guards, in a disposable guest only.

1. Guard a fresh clone with volatile policy, enforcing SELinux, synthetic
   accounts and a private emulator. Install the exact RPM. Establish an unlocked
   KDE session and genuine non-owner failure history using stock PAM; keep
   snapshots private. Remove clone autologin before subsequent password logins.
2. Verify `atd.service` is inactive and its runtime unit path absent. Create a
   root-owned mode `0644` regular `/run/systemd/system/atd.service` with
   `[Service]` and `ExecStart=/usr/bin/true`, then reload systemd without starting
   it. Approve setup maintenance in the real Konsole. Verify partial-mask
   refusal, unchanged desktop/native state, owned-mask cleanup and aborted hint
   before new authentication.
3. Perform actual display-manager password login; observe the shipped abort
   explanation, decline retry and verify the unchanged request. Remove only the
   exact fixture after checking its type/contents and reload systemd.
4. Start CUPS and a root-installed synthetic-owner user service with
   `Type=oneshot`, `RemainAfterExit=yes`, `ExecStart=/usr/bin/true` and a bounded
   `ExecStop` observer. Take seven CUPS-active samples over at least three
   seconds, writing bounded nonsecret JSON. Record product/fixture hashes,
   boot identity, prior request and initial CUPS stop timestamp.
5. Approve ordinary setup maintenance and pause host-driven guest actions during
   exclusion. Before another login, verify complete/restored state, unchanged
   payloads, tally/backup preservation, thawed cgroups, completed jobs, active
   login services and native CUPS stop after observer completion. Empty or
   interrupted observer output is a failed observation.
6. Verify actual password login/shipped resume, cancel before preparation,
   perform ordinary package erase and actual stock-password unlock, then export
   only inspected sanitized facts and clean up exact task-owned resources.

For the intermediate barrier failure, preserve the boot and volatile authority.
Use installed recovery after actual emergency-console authentication; never
edit journals/counters. If the console's own stop job leaves restoration
pending, close it and recheck from an independent guarded administrator context.
Retry only after verified recovery, without resetting counters or rebooting.

## Cleanup and limits

Both task clones, independent volumes, private emulators, temporary guest/host
access and synthetic recovery secrets were removed using identity and
no-reference guards. Final cleanup followed actual erase and stock-password
unlock; the original VM remains defined and off. Raw logs, native counters,
credential state and terminal buffers are excluded from published evidence.

The tested CUPS availability/order does not prove a remote CUPS deadlock or the
destination/cause of the physical-machine blocked request. No full PIN
enrollment, activation, reboot, active-upgrade or hardware matrix was repeated.
Broader desktop coverage, physical TPM/fingerprint support, independent M9
review and final release-candidate reconciliation remain outstanding.
