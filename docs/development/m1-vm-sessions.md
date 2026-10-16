# M1 guest logind registration and discovery

Date: 2026-10-16. Status: all five guarded registration cases passed in the
Fedora 44 KDE VM with SELinux Enforcing, including fixture cleanup. A separate
manual test also established two genuine different-UID KDE desktops on seat0.
The registration cases remain observations of root-declared metadata; neither
experiment establishes production authorization or multiple-seat GUI support.

The [session fixture](../../experiments/m1/vm/sessions/README.md) and
[sanitized result](../../experiments/m1/vm/results/2026-10-16-session-registration.json)
record this experiment. The separate
[user-manager collector result](../../experiments/m1/vm/results/2026-10-16-session-discovery.json)
records the original desktop/session inventory; its process-membership values
belong to that collector, not a live greeter.

## Existing desktop and user manager

The actual guest greeter was observed separately with the ordinary target UID
as both its real and effective UID, in `unconfined_t`.
`sd_pid_get_session` returned -61, while user-manager ownership resolved to the
same UID. A corrected collector invoked from a `systemd-run --user` unit observed
the same membership shape, completed all property reads, and found exactly one
own-UID local seated KDE graphical candidate. Root/remote SSH and seatless
manager sessions were also enumerated and excluded. The
[platform report](m1-platform.md) records those observations and the corrected
repeated-property query used with `loginctl` v259.

This demonstrates why requiring every locker process to have a direct logind
session would miss the tested KDE flow. It does not attest a caller as a genuine
locker. The production broker still needs kernel peer credentials, stable process
references, revalidation and the documented same-UID impersonation limitation.

## Two genuine desktops on one seat

The [two-desktop result](../../experiments/m1/vm/results/2026-10-16-two-real-desktops.json)
records a separate manual stock Plasma Login Manager login through
`SwitchToGreeter`, while the original test desktop remained logged in and locked.
The user logged into the management desktop with its usual password. Both UIDs
then had a live `plasmashell`, a live `kwin_wayland` and an actual KDE/Wayland
session on seat0. This establishes two real desktops, rather than interpreting
the root-declared registration fixture as one.

The management desktop was active; the retained test desktop was inactive with
`LockedHint=true`. Discovery still returned one eligible own-UID candidate for
each UID. The inactive original test session remained its own UID's candidate,
and the active foreign management session was excluded for that test UID. This
supports filtering by the peer's UID and session eligibility instead of choosing
whichever session currently owns the seat.

The original test locker's live greeter had matching real/effective target UID,
`sd_pid_get_session=-61`, successful user-manager ownership lookup matching that
UID, and SELinux type `unconfined_t`. These observations establish process and
discovery behavior, not caller authenticity or a production broker decision.
The test did not create two real desktops for the same UID or a second seat.
Its export records `production_broker_authorization_tested=false` and
`whole_vm_snapshot_restored=false`; final environment rollback is recorded
separately from this per-run result.

## Guarded registration experiment

The root runner required the UUID-bound root:root 0600 disposable-VM marker,
SELinux Enforcing, a dedicated ordinary test account and a confirmed restorable
snapshot. It required exactly one existing target discovery candidate before
starting. The operator kept the current desktop and session inventory stable.

Each helper started in its own root system service, outside existing session and
user-manager cgroups. Its private configuration contained only session hooks:
a small resource-limit module followed by the packaged `pam_systemd.so`.
The helper called `pam_open_session`, kept the handle alive while inspected,
then called `pam_close_session`/`pam_end`. No authentication, account-management
or password-change call was made. The helper remained root; its target UID,
desktop, type and remote/class flags were declarations by the administrator.
Those declarations are test inputs, not evidence that another desktop or remote
connection existed.

Before every case, the runner checked that the original active seat0 session
and active VT were unchanged. It chose a spare VT in the bounded 7–15 range
that was absent from logind, unused according to the kernel's read-only
VT_GETSTATE mask, and had no active getty/autovt service. Seated cases registered
on that spare VT and were required to remain inactive. The fixture never
activated a VT/session, attached a device, took device/control ownership or
terminated a user or seat. The PTY case instead allocated its own pseudoterminal
and registered it without a seat.

## Observed results

All rows used newly registered sessions with the expected service, leader and
UID, validated against actual logind properties. Direct `sd_pid_get_session`
mapping agreed with each registered session. The existing desktop's active
session and VT remained unchanged throughout.

| Case | Actual registered metadata | Discovery result for the ordinary target UID |
|---|---|---|
| Private PTY | `tty`, local, user class, no seat | Excluded; original candidate count remained one |
| Remote-declared graphical fixture | Wayland/KDE, remote, user class, inactive spare seat0 VT | Excluded; candidate count remained one |
| Greeter-class fixture | Wayland/KDE, local, greeter class, inactive spare seat0 VT | Excluded; candidate count remained one |
| Root-UID graphical fixture | Wayland/KDE, local, user class, UID 0, inactive spare seat0 VT | Excluded for the ordinary target; an own-root request was also excluded |
| Additional local graphical metadata | Wayland/KDE, local, ordinary target UID, user class, inactive spare seat0 VT | Actual candidate count became two; ambiguity was observed |

The fifth case exercises the existing discovery filter against real logind
enumeration containing two matching records. It supports refusing an ambiguous
shared-user-manager mapping. It does not test a production broker's refusal
response, two running KDE compositors, another physical seat or concurrent GUI
unlock. The remote-declared row likewise tests a registered remote flag, not an
actual remote graphical login. A PTY registration is not an interactive console
login. Root metadata supplies a foreign-UID example relative to the ordinary
target; it does not replace testing another ordinary account's caller.

The private session module set a 45-second runtime bound on each new logind
scope, with tasks limited to eight and memory to 64 MiB. The runner read back
`RuntimeMaxUSec=45s` for all five scopes. A separate 50-second launch-service
limit, native 60-second alarm and process resource limits remained in place.
This matters because registration moves the leader out of the launch cgroup;
a timeout on that original cgroup alone is insufficient.

The helper's normal closure and exact owned-unit stop were followed by bounded
polling for registration disappearance. The final session-ID inventory matched
the starting inventory; no fixture registration remained. The runner reported
`cleanup_completed=true` and removed its installed helper/module and private
configuration directory. No existing PAM service, account password, authselect
feature or SELinux policy was edited by this fixture. Full clean-snapshot
restoration remained a separate pending operator action at this report update.

The executed guest inputs were systemd `259.9-1.fc44`, PAM `1.7.2-2.fc44` and
SELinux targeted policy `44.11-1.fc44`; the result records the package builds.
Local preparation also passed both C warning-clean compilations and six pure
selection/cleanup tests, which performed no host PAM, logind or VT operation.
Those local checks are separate from the five actual guest cases.

## Remaining gates

[ADR 0003](../adr/0003-session-and-worker-boundaries.md) retains the conservative
routing constraint: a direct ineligible mapping cannot fall back to another
session; a user-manager mapping requires exactly one eligible own-UID session.
These fixtures test API behavior and candidate discovery, not that production
contract. M5 still needs stable peer/process identity, PID reuse/exit, session
replacement/disappearance during verification, generation fencing and actual
broker responses under zero or ambiguous candidates.

M1 still needs actual multiple-seat GUI behavior and two real KDE desktops for
one UID, as well as fuller remote/TTY/foreign-ordinary-UID caller flows. The
[multiple-seat gap assessment](m1-multiseat-gap.md) records the current hardware
and stock login-manager limitations; the passed different-UID same-seat test does
not close that gap. A production PIN route also still needs the supported account
eligibility implementation, broker/backend failure handling and reviewed
integration. Neither candidate discovery nor passing metadata registrations is
permission for everyday-host activation.

The fixture README links the versioned systemd/PAM construction references.
The observed guest JSON supplies empirical results; those references explain
interfaces and do not constitute independent review or hardware certification.

## Final cleanup

After these observations, the [clean snapshot was restored and the VM restarted](../../experiments/m1/vm/results/2026-10-16-cleanup.json).
The temporary guest SSH key was explicitly removed before rollback, and the local
temporary key pair was deleted. Per-run pending/false snapshot fields describe
the time of collection; this separate record establishes final cleanup.
Post-restore SELinux mode was not independently queried.
