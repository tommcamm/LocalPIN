# M1 genuine KDE topology lab

Date: 2026-10-17. Status: the genuine same-UID two-desktop case and its actual
shared-user-manager locker's ambiguous discovery/password fallback passed in the
disposable Fedora 44 KDE clone with SELinux Enforcing. The independently routed
second-seat case also passed, including usable native desktops and one-entry
password unlocks on both consoles. Final guest cleanup and clone disposal are
complete. This report records topology feasibility and recovery; it does not
authorize production activation.

The [topology evidence contract](../../experiments/m1/vm/topology/README.md),
[clone-only launcher](../../experiments/m1/vm/topology/README-launcher.md) and
[session decision](../adr/0003-session-and-worker-boundaries.md) define the scope.
This experiment adds actual running desktops and a real locker transaction to
the earlier [logind registration observations](m1-vm-sessions.md). A registered
graphical session alone was never counted as a working desktop.
The [sanitized topology result](../../experiments/m1/vm/results/2026-10-17-topology.json)
and [final recovery record](../../experiments/m1/vm/results/2026-10-17-topology-cleanup.json)
separate the two passed cases from cleanup and later production contracts.

## Setup and provenance

The operator used an independently backed disposable clone with its own
UUID-bound root-only VM and topology-clone guards, temporary restricted root
management access and a restorable baseline. Only virtual graphics/input were
used. The operator separately verified the installed classic startup binaries
against `plasma-workspace` and `kwin` `6.7.5-1.fc44`; PAM was `1.7.2-2.fc44` and
systemd `259.9-1.fc44`. The launcher documentation distinguishes those package
observations from the versioned upstream source explanation; it does not claim
a complete review of the Fedora patches for those two KDE packages.

The first desktop was a normal Plasma Login Manager desktop whose KDE processes
and locker belonged to the shared user manager. A private session-only PAM
fixture registered the second local KDE/Wayland session for the same ordinary
test account. After a separately verified activation gate, it launched the
packaged classic Plasma path on a spare real VT, with a private session bus.
It retained the canonical PAM runtime directory and isolated its XDG
config/data/cache/state directories. This was an explicitly experimental native
launcher, not a second desktop created by the stock login manager. It made no
authentication, account-management or password-change call.

In the same-UID case, both desktops used different VTs on the same logind seat
and the same real emulated DRM card. That supplies the same-UID result separately
from the independent second-seat case below. Neither compositor was nested or
headless.
The private bus's denial of the systemd manager name constrains that bus only:
classic autostart can separately reach the canonical user manager. No complete
isolation of the two same-UID desktops is inferred. Before the gated retry and
after all tests, the shared manager's six observed display/session fields
matched: `DBUS_SESSION_BUS_ADDRESS`, `WAYLAND_DISPLAY`, `XDG_RUNTIME_DIR`,
`XDG_SEAT`, `XDG_SESSION_ID` and `XDG_VTNR`. This is a comparison of that explicit
allowlist, not proof that the full manager environment or all shared user state
was unchanged.

## Failed startup attempts and bounded repair

The first attempt reached its 256-task ceiling, produced thread-creation
failures and a shell crash/restart, and showed an unresponsive menu to the human
operator. It supplies no working-GUI or authentication pass. The ceiling was
raised to 1024 tasks while retaining the independently verified 3-GiB memory and
15-minute scope limits.

The second attempt had sufficient thread capacity but initialized KWin while its
new session was inactive. When inspected after activation, it had a disabled DRM
output and no input event FDs; the visible panel was a stale frame and human
input remained unresponsive. It also supplies no GUI or authentication pass.
Each failed attempt's exact owned scope was cleaned, with the original desktop
retained, before a fresh launch.

The reviewed two-phase launcher then separated registration from desktop
startup. `prepare` pinned the new session/scope/leader and resource limits before
forking a desktop. `activate` revalidated the original desktop and new
registration, activated only the recorded new session, and required its logind
active state, seat active-session property and kernel active VT to agree before
publishing a root-only atomic gate. The native parent repeated the active-session
and VT checks before forking. Cancellation before approval closes the private
PAM session without starting a desktop child.

The fresh gated attempt produced actual KWin input event FDs and a usable menu
confirmed by the human operator. This establishes that the revised startup
worked in this run. The source-based inactive-start explanation in the launcher
documentation remains an explanation of the tested repair, not a demonstrated
general upstream defect or guarantee for other hardware.

## Same-UID desktop and locker observations

The simultaneous inventory and post-unlock inventory agreed on two distinct
local KDE/Wayland user sessions for the same ordinary UID, with different VTs.
Each had a live packaged `kwin_wayland` and `plasmashell`; the same two process
pairs survived the password transaction. Both compositors held a real DRM card
FD. The second compositor also held actual input event FDs after gated startup,
and its journal selected the native DRM backend. Device FDs, process membership
and the human input check corroborate the GUI result; no claim of a warning-free
journal is made.

| Observation | Normal first desktop | Experimental classic second desktop |
|---|---|---|
| Live KDE/Wayland user session | Present throughout | Present throughout |
| Native compositor and shell | Both present before and after unlock | Both present before and after unlock |
| Process membership | Shared user manager; no direct session for KWin/locker | Direct mapping to its new session |
| Own-UID eligible discovery candidates during locker test | Two | Same two live sessions |
| Required routing behavior | Ambiguous user-manager mapping is unavailable | A valid direct mapping may resolve its own session |

The operator switched back to the first desktop and observed its actual stock
`kscreenlocker_greet`. Its observed UID matched the test account;
`sd_pid_get_session` returned `-61`, while user-manager ownership lookup succeeded
and matched that UID. Its live process belonged to the user-manager KWin service,
not directly to either graphical session. The locker ran in `unconfined_t`.

The [fallback-only routing probe](../../experiments/m1/vm/kde/routing.h) inside
that actual greeter emitted the following fixed numeric observations:

```text
direct_rc=-61 owner_rc=0 owner_match=1 enumeration_complete=1 candidates=2 decision=0
fallback capture set_item=0
```

Here `decision=0` means unavailable: the observer did not select the active, first
or another guessed session. `set_item=0` reports successful storage of the same
conversation response for the subsequent ordinary PAM path. Both records came
from the same freshly observed greeter process. The module always returns
`PAM_IGNORE`; it grants no PIN success, implements no production broker and logs
no candidate bytes.

An administrative setup unlock was explicitly excluded from authentication
results. The operator then requested a fresh lock and observed the first
desktop locked while both eligible sessions remained registered. The human
entered the ordinary password once and confirmed successful unlock. The
operator corroborated `GetActive=false` afterward and re-enumerated both live
sessions and both original compositor/shell pairs. This supplies the actual
ambiguous shared-manager password-fallback result. The second classic desktop's
valid direct session mapping does not need another ambiguity transaction to
satisfy this same-UID case; its result is separate from the independent-seat
locker tests below.

## Independent second seat

The clone had two independently routed emulated virtio GPUs and dedicated
virtual keyboards/tablets, with no host-device passthrough. A public fixed-input
phase verified each intended keyboard/pointer route and its cross-seat negative
before password entry; the [hardware/input fixture](../../experiments/m1/vm/topology/HARDWARE.md)
documents the bounded marker protocol and why a sender's successful write alone
does not prove delivery. The guest counters observed the actual intended routes.

The second GPU and input devices were assigned to the separate logind seat but
initially withheld its graphical master tag. After the first normal login
manager greeter had exited, a guarded clone-only stage operation exposed only
the owned secondary DRM device as a seat master. Both its preflight and
activation succeeded. The new seat reported `CanGraphical=yes` and `CanTTY=no`,
while the original seat's active-session/VT baseline was unchanged. Readiness
explicitly reported that a desktop was not yet proven; it did not invent a VT
for a seat without TTY support.

The human then logged into the other account through the stock Plasma Login
Manager on the second console and confirmed that its menu responded. This
sequence retained the installed login manager and avoided assuming that its
shared greeter user units could support two simultaneous greeters. The earlier
[source assessment](m1-multiseat-gap.md) describes that limitation; this successful
sequential introduction is an actual runtime result for the tested package and
topology, not proof of simultaneous-greeter support or a login-manager patch.

The concurrent and post-unlock inventories contained two actual local KDE/Wayland
user sessions for different UIDs on different seats. Each retained its original
live `kwin_wayland` and `plasmashell`. The compositors held different real DRM
card FDs and disjoint sets of actual input event FDs. Together with the public
marker routing and human console input, these observations supply independent
graphics/input evidence rather than treating two viewers, monitor heads or
metadata registrations as two seats.

| Observation | First seat | Second seat |
|---|---|---|
| Launch path | Normal stock login manager | Normal stock login manager after guarded seat introduction |
| Account | Ordinary test account | Separate management account |
| Native graphics/input | First emulated GPU and routed keyboard/tablet | Distinct emulated GPU and routed keyboard/tablet |
| Actual stock locker | Observed; matching user-manager owner, no direct session | Observed; matching user-manager owner, no direct session |
| Password result | Human confirmed one entry; unlocked state corroborated | Human confirmed one entry; unlocked state corroborated |
| Retained after unlock | Original session, compositor and shell | Original session, compositor and shell |

Each fresh lock was observed with exactly one eligible own-UID session. The
human entered the ordinary full password once on each console; subsequent
`GetActive=false` observations corroborated both unlocks. Both native desktops
remained alive. The actual first-seat greeter's target-scoped probe reported:

```text
direct_rc=-61 owner_rc=0 owner_match=1 enumeration_complete=1 candidates=1 decision=2
fallback capture set_item=0
```

`decision=2` means unique own session. Correlation with that live greeter excluded
older same-UID/count-two journal entries also present in the query output. The
other account's actual locker had matching user-manager ownership and no direct
session; the target-scoped fixture did not supply a routing log for that other
account. No second account's PIN authorization is inferred from its ordinary
password unlock.

## Evidence coverage and recovery

An independent read-only audit compared the private simultaneous inventory,
KWin input observations, fresh-lock record, actual locker membership, routing
journal, unlock-state check and post-unlock inventory. Nineteen cross-file
consistency assertions passed, including session distinction, retained process
identities, native device FDs, same-greeter routing/capture records and exclusion
of the setup unlock. A further seventeen independent-seat consistency checks
passed, covering device separation, fresh locks, actual greeters, retained
processes, current-greeter routing and the bounded activation result. The human's
usable-menu and one-entry password confirmations are operator observations, not
assertions inferred from process metadata.

The three inventory samples reported SELinux enforcing and audit enabled with
zero lost records and zero backlog; the independent-seat samples and final
post-unlock check agreed. The post-unlock AVC query returned no matching records.
These are bounded observations, not a guarantee of complete audit coverage or
an absence of all runtime warnings. RPM verification reported the intended KDE
PAM fixture difference and login-manager state-directory group/mode differences;
it reported no executable or library differences. This is not a claim that all
RPM paths were pristine. Raw machine/session/process/device identifiers,
environment addresses and journal records remain in ignored private storage.
No passwords, account hashes or raw PAM contents are reproduced here.

After the two actual topology cases passed, guest cleanup verified that the
native fixture units, scopes and tagged descendants were gone. The original KDE
PAM bytes, mode and SELinux label were restored, with SHA-256
`7d91b3ad73a998e8b10f9edccd74ba04179a778c4a5e61d9176872f43c7bbac3`;
the fallback-only module was removed and authselect remained valid. The
experiment used no account-password write operations. The temporary guest SSH
key was explicitly removed before disposal. The final guest check still
reported SELinux Enforcing and zero audit loss.

The independent clone was then shut down and undefined, and its independent
disk was deleted. The temporary local key pair, owned viewers and VNC listeners
were removed. Final read-only checks confirmed clone absence and that the
original VM remained off with unchanged XML. No host authentication or TPM state
was changed. The later recovery record completes the earlier guest-cleanup
record's pending-disposal step; historical per-run fields were not rewritten.

The strict validator now reports consistent topology evidence with no missing
fields. Its output explicitly retains `independent_attestation=false`,
`m1_completion_assessed=false` and `production_authorization_proven=false`.
The curated result's production authorization, solved UID lifecycle and M1
completion claims also remain false. This consistency check does not replace
the empirical observations or the separate milestone decision.

These observations do not settle production caller authenticity, process/session
races, account deletion or UID reuse, authenticated grants, durable state,
production worker policy or activation. Those contracts retain their existing
ADRs and milestone assignments. In particular, two eligible sessions require
refusal for an otherwise valid user-manager caller; same-UID malware remains a
documented threat-model limitation.
