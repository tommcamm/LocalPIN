# ADR 0020: Setup-managed offline password-accounting maintenance

Date: 2026-10-17. Status: development implementation; installed evidence and
remaining limits are recorded separately in the acceptance report.

## Context

The guided CLI in ADR 0019 stops on Fedora's reviewed volatile faillock
configuration. ADR 0014 already permits a deliberate offline transition to
persistent accounting, preserving every native failure record. Requiring owners
to implement that transition manually obstructs fresh installation.

An ordinary reboot cannot precede the copy: `/run/faillock` is volatile. Copying
while authenticators run can lose failures. Merely pausing workers is also
insufficient: after resuming, a worker may still hold parsed old configuration
or an old tally descriptor.

## Decision

Extend the existing fixed sudo/helper interface with `prepare-accounting
--setup-uid N`. Only a fresh, unprepared installation with the exact reviewed
volatile configuration and supported Fedora KDE policy can schedule it. Setup
requires explicit approval to save work, terminate sessions and temporarily
stop system services. Installation itself remains passive.

A packaged system service takes over outside the initiating user's session.
The same-boot transaction owns the integration lock and a root-only journal and
backup directory. It isolates a dedicated maintenance target, establishes a
kernel cgroup boundary against new execution, and removes old userspace workers
before capturing native state. Unknown cgroup layouts are refused. The service
does not infer exclusion from process names or a desktop logout alone.

Scheduling and the independent worker both acquire Fedora's existing native RPM
transaction lock at `/usr/lib/sysimage/rpm/.rpm.lock` using a nonblocking POSIX
`fcntl` whole-file write lock. The helper verifies RPM's expanded lock path and
the existing root-controlled file; it never creates or replaces it. This matches
[RPM 6's locking implementation](https://github.com/rpm-software-management/rpm/blob/rpm-6.0.2-release/lib/rpmlock.cc)
and [transaction lifecycle](https://github.com/rpm-software-management/rpm/blob/rpm-6.0.2-release/lib/transaction.cc),
which retain exclusion through package scriptlets and triggers.
An active package transaction refuses scheduling before any journal or service
change. The worker independently reacquires this lock before the integration
lock and retains it through migration, verification and service restoration.
Only then does the worker isolate the empty maintenance target; the service's
`IgnoreOnIsolate` boundary keeps it independent of that target's start job.
A durable `masking` phase precedes authentication masking. The worker refreshes
its owned-mask list after the delayed handoff to preserve masks installed in the
interim. A partial masking failure removes only owned masks and never submits
an isolation transaction. A durable `isolation_requested` marker is saved only
after masking, immediately before the first session-stop command. A busy lock
before masking cannot stop or restore services; an untouched request is recorded
as aborted when the integration lock permits, otherwise pending evidence remains
for explicit recovery. Administrators must not race maintenance with unrelated
service configuration changes; the integration lock coordinates LocalPIN tools.

Before isolation, the worker synchronously stops the display manager and
`user.slice` while ordinary services remain available to desktop shutdown
workers. This avoids deliberately stopping CUPS concurrently with Plasma's
printing-worker teardown. This ordering addresses the observed dependency
hazard; it does not establish the destination or cause of the reported blocked
CUPS request, and needs fresh installed KDE acceptance.

The maintenance target conflicts with `user.slice` and orders itself after that
slice, the display manager, logind and user-session service. During isolation,
their stop jobs therefore finish before the target's start job completes. The
explicit slice stop also drains delegated user managers and runtime-directory
services that otherwise ignore isolation, so their lifecycle cleanup finishes
before the final freezer/kill boundary. This lets the desktop restore its virtual
terminal and avoids carrying stale user-manager state into the next login; an
otherwise empty target can complete while unrelated service stops are still
running. These ordering edges do not start those services or depend on the
maintenance worker. The bounded isolation command and subsequent kernel
exclusion proof remain mandatory.

The migration inventories every native tally because the configuration change
is global. It retains exact source backups, rejects unsafe metadata or
conflicting destinations, preserves every counter byte, and permits only ADR
0014's explicit destination-only primary-group-to-root conversion. Destination
copies and backups are synchronized before the atomic configuration switch.
The original volatile files remain untouched. Configuration, metadata and
distribution SELinux labels are verified before returning to normal login.

The journal distinguishes incomplete work from completion. No automatic retry
may reset accounting, choose a smaller tally, overwrite a conflict, or restore a
stale backup over a persistent tally. An early boot guard sends incomplete work
to administrator recovery before ordinary boot. The watchdog prevents a dead
worker from leaving PID1 frozen. Recovery must verify the authoritative state;
deleting the journal is not recovery. Power loss before a durable snapshot can
destroy volatile data; the implementation must report that limitation and
cannot claim to reconstruct lost failures.

A refusal before the execution barrier may automatically abort only when the
original same-boot volatile authority remains intact and no snapshot, backup or
copy has begun. A durable barrier-entry phase prevents an interrupted barrier
from being mistaken for that untouched state. The aborted request is retained.

Checked commands carry closed operation identifiers, exit status and bounded
fixed diagnostic categories. Raw command output is never retained. Original
failure evidence and restoration failure evidence have separate files; cleanup
does not replace the initiating failure.

Terminal accounting outcomes separately record login restoration as
`not-needed`, `pending` or `restored`. Queuing a nonblocking graphical isolation
does not prove restoration: the worker observes pending systemd jobs (excluding
its own start job) and the required active login services within a fixed bound.
Pending restoration blocks setup and another maintenance request. Administrator
recovery can retry restoration of a proven terminal transaction without copying
or comparing current tally bytes to stale snapshots; current policy, native
metadata and the presence of completed persistent history remain required.
Unsafe nonterminal interruptions retain the emergency path. A proven safe abort
exits normally to avoid the unit's emergency failure handler, while emitting its
actual result and restoration state to the journal.

After successful migration or a verified abort, a bounded, nonsecret root-owned
hint identifies the setup owner, request and distinct outcome. A packaged KDE
autostart launcher opens only the fixed
normal-user `localpin setup` command. A user cache suppresses duplicate windows;
it provides no authority. Setup rechecks privileged state, and enrollment still
requires a fresh account password. No secret or client authorization is saved
across logout. An abort explains the failed operation when known and requires
new explicit sign-out approval before any retry. It never supplies a successful
migration hint.

Actual PIN/password tests, administrator-console recovery rehearsal, fresh
enrollment after recovery, and explicit activation remain required. This
amends ADR 0019's manual accounting handoff without weakening ADR 0014's
preservation contract or changing the initial-login password requirement.

## Validation

Synthetic tests cover bounded state, fixed invocation, counter and metadata
preservation, unsafe inputs, conflicts, interruption decisions, and duplicate
resume suppression. Installed acceptance must separately exercise the actual
session termination, cgroup exclusion, password login, automatic resume,
PIN/password unlocking, console recovery, reboot and removal on enforcing
Fedora KDE with an independent disk and private TPM emulator. Source tests do
not establish those properties. Independent security review and physical
hardware validation remain M9 requirements.
