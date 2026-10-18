# Setup-managed accounting acceptance

The [PR #13 targeted follow-up](../../docs/development/accounting-maintenance-abort.md)
records installed mask-refusal, user/CUPS shutdown-order, kernel-barrier and
setup-resume results, including failed candidates and guarded cleanup.

These helpers run only in a newly independent disposable Fedora KDE 44 clone
using the [M8 host and guest guards](../m8/README.md). Keep the original VM off,
SELinux enforcing, one qcow2 volume with no backing store, a private managed TPM
emulator, pinned temporary SSH access, and synthetic dedicated accounts. Never
use host PAM, everyday credentials or a physical TPM.

Start from the clean snapshot with the stock volatile `/run/faillock` policy.
Do **not** perform the old offline accounting fixture first. Install the exact
candidate RPM and stage the unchanged M8 `run.py`/`guard.py`, unchanged M8.2
`wizard.py` as `wizard_base.py`, and this directory's `wizard.py`/`observe.py`
under guest-root-only `/root/localpin-m8`. The wrapper adds the exact maintenance
confirmation to the existing terminal observer; it adds no product inputs.

Use the M8.2 real-Konsole fixture to run normal-user `localpin setup`, with
actual libvirt keyboard events and guest-private secrets as described in the
[M8.2 workflow](../m82/README.md). Require the desktop to be unlocked before starting or observing prompts and
before every graphical keyboard action; verify the intended Konsole is the
foreground window on the active dedicated Wayland VT. Stop on idle lock rather
than submitting setup choices to the greeter. Keep failed fixture observations
separate from product refusals. Check cancellation before approval leaves
configuration, authority and service state unchanged. Create native failure
history for the separate synthetic account with the actual stock KDE PAM stack
and an incorrect password outside the six-digit PIN grammar. Keep all counter
snapshots root-private. Stop on native authentication refusal; never reset
native counters or emulator dictionary-attack state.

Before approving maintenance, remove the clone-only autologin configuration so
the next login requires an actual password. Approve the explicit saved-work and
service-interruption prompt. All host-driven guest actions must pause while the
maintenance service excludes userspace. Once access returns, inspect the
root-owned transaction, native backups/copies, persistent policy, cgroup thaw
and restored display/network/login services before authenticating again.

Log into the actual display manager with the dedicated account password. Prove
the shipped autostart launcher opened an installed `localpin setup` in an
actual Konsole, then observe its prompt without replacing its launcher:

```sh
python3 /root/localpin-m8/observe.py --expected-uuid CLONE_UUID \
  --disposable-vm-confirmed --emulated-tpm-confirmed
```

`observe.py` reads the actual terminal's D-Bus display buffer, binds its
foreground process to the installed setup command, and returns only fixed
prompt IDs and counts. Raw text stays guest-root private. It never sends
terminal text or marks desktop/recovery tests as passed. Host topology must be
validated before and after this operation and every keyboard action.

Repeated logins can assign KDE to tty3. Use a free VT for the recovery
rehearsal. Stage this directory's `console_recovery.py` as `m83-console.py`
and unchanged M8.2 `console_recovery.py` as `console_recovery_base.py`; keep
unchanged M8.2 `offline_accounting.py` beside them. The M8.3 wrapper requires
a real tty3..tty6 logind text login for the dedicated account and ordinary root
sudo ancestry retaining that same physical VT. It reuses the frozen M8.2
recovery assertions and does not relax product behavior.

Continue actual account-password/PIN enrollment and the existing trial,
PIN/password unlock, administrator-VT recovery, fresh re-enrollment and final
activation requirements. Recovery revokes the earlier enrollment. Preserve
failed observations and report any unperformed cases explicitly. Export only
inspected sanitized evidence, package/source identity and cleanup facts; never
export raw terminal buffers, native counters, registry data, secrets or raw
journals. Remove the task-owned clone and temporary access using the same
independent identity and no-reference guards after restoring stock policy.

Pure fixture checks need no VM access:

```sh
python3 -m unittest discover -s experiments/m83 -p 'test_*.py' -v
python3 -m py_compile experiments/m83/*.py
```

## Actual worker interruption

Use another fresh independently guarded clone with its synthetic administrator
recovery password established **before its first boot**. Before installing the
product or creating counter history, measure `/proc/consoles` and actual console
routing, attach the emulated serial channel if present, and prove a real stock
`emergency.target` password login to an authenticated root console followed by
a return to the graphical target. An unlocked root hash alone is insufficient.
Then install the exact final RPM. Retain a genuine non-owner native failure record across interruption,
recovery and retry. The root recovery password is a disposable fixture; the
first failed candidate exposed Fedora's default locked-root emergency-console
limitation and that failed observation remains recorded.

Stage `fault.py` root:root mode0755 at
`/usr/libexec/localpin/localpin-accounting-fault-fixture.py` and restore its
normal SELinux label. In this clone only, install this root-owned test drop-in
as `/etc/systemd/system/localpin-accounting.service.d/90-m83-fault.conf`:

```ini
[Service]
ExecStart=
ExecStart=/usr/bin/python3 -I /usr/libexec/localpin/localpin-accounting-fault-fixture.py --expected-uuid CLONE_UUID --phase quiescent --disposable-vm-confirmed --emulated-tpm-confirmed
```

Reload systemd and initiate the real maintenance request through normal setup.
The wrapper invokes the unchanged installed helper in its actual service
cgroup, waits for its protected transaction and actually frozen PID1, stops and
rechecks the exact worker/request/phase, durably records a guest-root-only fault
intent, then sends SIGKILL to that worker. The production watchdog must thaw the
kernel cgroups and return to emergency recovery. A missed phase or changed
request is a failed fixture observation; it cannot be reported as an actual
crash test. No production test option, fake accounting record or TPM reset is
used.

Authenticate at the actual emergency console with the synthetic root fixture.
Remove the exact drop-in and test wrapper, reload systemd, and invoke installed
`localpin-accounting recover` in that same boot. Verify original counters and
policy, restored login services and a durable aborted transaction. Then retry
the ordinary setup request and require real successful migration plus password
login/autoresume on the final candidate. A separate pending-transaction reboot
case must report loss of volatile authority and refuse empty-counter recovery;
it must never be relabeled as same-boot recovery.

## Pending-request boot guard

Use a separate fresh guarded clone with verified actual emergency-console access.
A clone-only drop-in for `localpin-accounting-delay.service` may add
`ExecStartPre=/usr/bin/sleep 300` to pause the real handoff before the worker
starts. Run normal setup and approve the real maintenance request. Immediately
stop the delayed service and verify the protected transaction is genuinely
`requested` with `isolation_requested=false`, original volatile policy and
native history unchanged, and no account authority. Remove the exact test
drop-in and reload systemd; never edit the product journal.

While that real request is pending, an ordinary `rpm -e localpin` must refuse
and retain the installed helper/units/counters. Then perform a real guest
reboot. Verify the shipped guard withholds normal startup, authenticate at the
actual root emergency console, and invoke installed `localpin-accounting recover`.
It must refuse because the old volatile authority was lost across boot, leaving
policy, journal and tally inventories unchanged. Do not create empty counters,
reset failures or force package erase. Export only sanitized outcomes and
dispose of this intentionally unrecovered task-owned clone using the exact UUID,
independent-volume and no-reference cleanup guards.

## Evidence scope and cleanup

The full native onboarding/console recovery/activation chain uses the exact
RPM5 candidate. Compatible RPM6, whose runtime matches RPM5, covers upgrade,
original-backup metadata/SELinux preservation, real reboot, duplicate-window
suppression and active erase. RPM9 separately proves actual busy-transaction
refusal and actual worker SIGKILL at a frozen-PID1 quiescent barrier. Its failed
emergency-console observation remains a failure: PID1 resumed and the pending
boot guard refused ordinary startup, but the stock emergency service repeatedly
deactivated and hit its start limit before recovery could be attempted. The
failed clone retained same-boot memory and volatile authority through diagnosis;
its independent disk/RAM archive and private credentials are now removed.
RPM10, whose only runtime change from RPM9 is ordering maintenance after the
display-manager/logind/user-session stop jobs, proves actual emergency password
login and same-boot installed recovery. Its subsequent owner login exposed a
separate systemd user-manager executor failure, recorded as a failure. Ordinary
diagnostic user-slice drain and another real password login regenerated the
manager. RPM11 additionally conflicts with and waits for `user.slice`, and
proves the real crash/root-console/same-boot recovery chain, healthy owner user
manager and password login, migration preserving the same native history, shipped automatic
resume with a fresh readiness check, and unprepared erase/stock-password
continuity. RPM11 also proves the real pending-request RPM erase fence and
boot guard: after an actual reboot naturally loses the old volatile record,
normal startup is withheld and actual root-console recovery refuses without
creating empty counters or changing journal, policy or current tally inventories.
This is refusal evidence, not counter preservation across that intentional
reboot. Each result names
its candidate; payload/source comparison records describe the relationship.
Earlier failures, the passing pre-barrier refusal and the idle-lock fixture
observation remain separate evidence.

After exporting only inspected sanitized results, require actual package erase,
no remaining authority, original KDE policy restoration and actual post-erase password
unlock before cleaning a successful normal-flow clone. Check the exact task UUID
and active/inactive topology again, no snapshots/checkpoints or shared/backing
references from any other domain/volume, and the original VM still off. Shut the
clone down gracefully, undefine only that clone with private emulator cleanup,
and delete only its independently recorded volume. Remove temporary SSH access
and synthetic recovery secrets. Failed task clones may instead be preserved in
private independent disk/RAM archives until diagnosis is complete; then remove
only those exact task-owned identities and files with the same no-reference
checks. Never expose saved RAM, raw journals, account hashes or private counters
as PR evidence. Report incomplete cleanup explicitly.

All task-owned test clones, independent disks, private emulator states, saved
RAM archives, raw journals, temporary access keys and synthetic root recovery
secrets have been removed. The original VM remains defined and off. The
`all-task-vm-cleanup.json` result records the final read-only identity inventory;
individual cleanup records retain each candidate scope.
