# ADR 0003: Session discovery and privileged worker boundaries

Date: 2026-10-16.

Status: Accepted constraints for subsequent implementation; session, account
lifecycle and SELinux integration remain experimental and block activation.

## Context

The broker must restrict PIN verification to the Unix peer's own eligible local
graphical session. A Plasma process can run in a systemd user unit without a
direct logind session. Both the development process and the actual enforcing
VM greeter demonstrate that case: direct lookup returned -61 while user-manager
ownership matched the ordinary UID. A separate user-unit collector found one
eligible discovery candidate. The guest also passed bounded root-declared
logind metadata registrations, including an ambiguous two-candidate inventory;
a separate manual login established two real different-UID KDE desktops on seat0.
The inactive locked test desktop remained its UID's single candidate while the
active foreign desktop was excluded. Two real desktops for one UID and actual
multiple-seat GUI behavior remain untested. A claimed PAM service, PID, desktop
or session from the client is not authoritative. Same-UID malware can impersonate
a locker request, as already stated in the specification.

KDE's authentication-only flow does not automatically run the PAM account
phase. Password verification also loads privileged modules/helpers that need a
different sandbox from ordinary PIN requests. An apparently successful socket
connection with SELinux disabled does not establish the intended boundary.

## Decision

1. The kernel Unix-socket credentials supply the authoritative peer UID/GID.
   Client identity fields never override them. Non-root verification is own-UID
   only. The broker must acquire and retain a stable process reference when
   using process metadata, or reject a raced/disappeared peer; ordinary
   `sd_peer_*`/PID lookup alone is not sufficient authorization evidence. The
   exact credential/PID-reference procedure belongs to M5's tested IPC contract.
2. An eligible session is an own-UID, non-root, local, nonclosing `user` session
   on a seat, with a verified supported KDE desktop and `wayland` or `x11` type.
   Unknown properties fail discovery. An inactive but online locked session
   is not automatically excluded merely because another session owns the seat.
   The exact desktop identifiers and account type must be verified in the guest;
   the Python collector's filter is discovery code, not a production oracle.
3. Prefer a stable direct peer-to-logind-session mapping and validate that
   specific session. A direct mapping to an ineligible session never falls back
   to a different session. Where there is no direct session, require verified
   user-manager ownership matching the peer and enumerate all of that UID's
   eligible sessions. Permit that mapping only when exactly one candidate
   exists. Zero or several candidates make PIN unavailable. Never choose the
   first/active seat or trust an environment/session hint to break ambiguity.
   Revalidate liveness and eligibility before authorization is delivered.
4. Keep all same-UID caller impersonation limits explicit. Discovery prevents
   accidental cross-UID/session routing; it cannot prove the user sees a genuine
   KDE lock screen. A process executable path is not added as pretend attestation.
5. A PIN success must also pass explicit supported account eligibility checks.
   The exact password-free account policy is unresolved until locked/expired/
   forced-change/restricted-account guest tests establish its behavior. Never
   run a password challenge on a PIN route or replace a failed eligibility
   check with permission. Preserve existing required auth checks and failure
   counters. This blocks activation, and is tracked with the PAM experiment.
6. Ordinary broker processing never loads the password PAM stack. Fresh
   enrollment password verification uses a supervised, short-lived privileged
   worker with a dedicated password-only PAM service. Bind its result to UID,
   action, generation and a maximum 60-second commit interval; the client cannot
   assert success. Give worker/TPM native calls bounded process lifetimes and
   disregard late results after deadline/cancellation or generation change.
7. Broker and password worker use separate reviewed systemd/SELinux boundaries.
   The broker has no IP network, narrow state/runtime writes and resource-manager
   TPM access only. The password worker receives only the filesystem/helper/
   device permissions proved necessary for the supported PAM policy; it does
   not inherit restrictive broker settings without testing them. KDE receives
   socket-contact permission, no broker-state or TPM access. Enforcing-mode
   evidence is mandatory before these policies are accepted for packaging.
8. Initial integration/recovery administration is an explicit root invocation
   through the system's existing administrative mechanism. Do not add a setuid
   CLI, unauthenticated admin flag, general shell endpoint or a new polkit
   authorization path. Fresh own-user enrollment password authorization remains
   a distinct transaction and never grants integration authority.

## UID lifecycle limitation

UID, username and home-directory equality cannot identify an account that was
deleted and identically recreated. No immutable local-account identity has been
demonstrated. Enrolled-UID deletion/reuse therefore remains unsupported, with a
production activation refusal until a tested lifecycle mechanism enforces
revocation or the specification is explicitly amended and reviewed. Operator
instructions alone do not satisfy the required detection guarantee. M2 must not
encode those ordinary account fields as if they solve UID reuse.

## Evidence and required tests

The [platform report](../development/m1-platform.md) records source references,
exact observed packages/hashes, 20 synthetic inventory/discovery tests and both
host and enforcing-VM process observations. The actual greeter and a separately
observed user-manager collector had no direct session but matching user-manager
ownership. The collector completed property enumeration and found one own-UID
local seated KDE candidate. Its exported process-membership values concern the
collector, not a live greeter; neither observation attests caller authenticity.

The [guest registration report](../development/m1-vm-sessions.md) records five
passed cases through actual `pam_systemd` and logind: a private seatless PTY,
remote-declared graphical metadata, greeter class, root UID and additional local
KDE/Wayland metadata. Each newly registered session matched its declared
properties and direct sd-login membership, had its 45-second scope runtime
verified, and disappeared during cleanup. Seated fixtures stayed on a verified
unused inactive seat0 VT; the real desktop's active session/VT was unchanged.
Only the additional ordinary-user local graphical metadata raised the actual
candidate count from one to two. This proves an enumeration ambiguity exists;
it does not prove that a production broker refused it or that a second desktop,
remote connection or another seat was operating.

The separate
[two-real-desktop result](../../experiments/m1/vm/results/2026-10-16-two-real-desktops.json)
records a user-confirmed management login through the stock Plasma Login
Manager's `SwitchToGreeter` while the original locked test desktop was retained.
Both UIDs had live `plasmashell` and `kwin_wayland` processes and actual
KDE/Wayland sessions on seat0. Each UID had one own-UID discovery candidate;
the active foreign management desktop was excluded for the test UID, whose
inactive locked desktop remained eligible. The live test locker again lacked a
direct session (-61) while its user-manager owner matched its real/effective
UID. This establishes concurrent different-UID desktops and discovery behavior,
not a production authorization result, same-UID ambiguity or a second seat.

[Real-account PAM tests](../development/m1-vm-pam.md) and
[stock KDE fallback](../development/m1-vm-kde.md) establish separate candidate and
lock/expiry findings. The [enforcing boundary/worker report](../development/m1-vm-selinux.md)
records confined broker/client/negative-helper checks and a separate positive
own-user password worker against one reviewed policy copy. Password-worker
success does not establish password-free PIN eligibility, enrollment grant
binding or production service confinement. These experiments do not authorize a
production PIN path.

M1 must still exercise multiple-seat GUI behavior and two real KDE desktops for
one UID. The [gap assessment](../development/m1-multiseat-gap.md) records the
current hardware and stock login-manager limitations. Root-declared metadata,
a private PTY and the passed different-UID same-seat desktops do not replace
those cases or complete remote/TTY/foreign-ordinary-UID caller flows.
Production caller routing, supported account restrictions and the complete
broker-contact/password-worker contract remain implementation gates; each
experiment report states its narrower observations. Whole-VM snapshot
restoration is a separate operator action, not implied by fixture cleanup.
M5 must test stable kernel credentials/process references, PID reuse/exit,
session disappearance/replacement during verification, zero/ambiguous-candidate
refusal responses, generation fences and bounded stalled-worker cleanup. M6/M8
must test fresh authorization versus administrative integration and the supported
PAM helpers. M2/M3 must prove lifecycle/revocation fencing before accepting an
account-identity design.

## Consequences

The initial supported routing policy may refuse PIN for a UID with several KDE
sessions when its caller is owned by the shared user manager. The password route
remains available. Later broader support requires an explicit, tested decision;
it cannot rely on caller-supplied seat names. No production policy, service
installation or host authentication edit is introduced by this ADR.
