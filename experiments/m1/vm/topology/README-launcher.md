# Clone-only real classic Plasma launcher

This optional fixture starts a second **real** local KDE/Wayland session for
`localpintest` on a spare seat0 VT. The first desktop remains a normal Plasma
Login Manager desktop under its shared systemd user manager. The second is an
explicit experimental root session launcher with a private D-Bus and stock
classic Plasma startup. Registration or successful process creation never counts
as a working GUI, native DRM, locker or authentication result. The independent
[evidence checklist](README.md) defines those proofs.

Use only a disposable, independently backed clone with a restorable snapshot,
guest root management connection and SELinux Enforcing. Do not provision its
markers on the original VM or an everyday host. No host/guest `/etc/pam.d`,
authselect, password or account record is changed by this launcher. The graphical
applications can still leave user/runtime/journal artifacts; discard or restore
the whole clone afterward.

Both UUID-bound root:root, mode0600, single-link regular markers are mandatory.
The existing `/etc/localpin-m1-vm-guard` retains its documented exact contents.
The additional `/etc/localpin-m1-topology-clone-guard` contains exactly:

```text
LOCALPIN-M1-TOPOLOGY-CLONE
target=localpintest
uuid=<this clone's /sys/class/dmi/id/product_uuid>
```

The markers prevent accidental execution; they do not attest a VM or defeat a
malicious root operator. The ordinary local test user must belong to no
administrative group. Preparation requires exactly one existing eligible target
KDE session and refuses existing fixture paths, units or tagged processes.

## Startup and cleanup

Local compile and pure tests perform no PAM/session/account operations:

```sh
LOCALPIN_PAM_INCLUDE=/absolute/path/to/pam-devel/usr/include LOCALPIN_SYSTEMD_INCLUDE=/absolute/path/to/systemd-headers/usr/include python3 experiments/m1/vm/topology/launch.py compile-only
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s experiments/m1/vm/topology -p test_launch.py -v
```

After the first normal desktop is confirmed in the clone, run as guest root:

```sh
python3 experiments/m1/vm/topology/launch.py prepare --snapshot-confirmed
python3 experiments/m1/vm/topology/launch.py status
python3 experiments/m1/vm/topology/launch.py activate
```

Preparation installs only fixture-owned files under
`/usr/libexec/localpin-m1-topology` and `/run/localpin-m1-topology`. It starts the
fixed, previously absent `localpin-m1-topology-launch.service`. Native checks
repeat both markers, VM/Enforcing, dedicated unit, local ordinary identity and
unused VT constraints. A private session-only PAM configuration registers the
new logind session. It never calls authentication, account management, password
update or an authorization grant API.

The root PAM parent migrates into its new session scope and publishes its native
registration before any desktop child exists. Preparation validates and records
that exact scope/leader, verifies the resource limits, and returns
`awaiting_activation=true`. The native helper waits at most 120 seconds for a
root-only activation gate; run `activate` promptly. That separate operation
revalidates the protected first desktop, new registration and PID start time,
refuses an unrelated active session/VT, and deliberately calls
`loginctl activate` with only the recorded new ID. It requires the new
session's actual Active property, seat0 ActiveSession and kernel active VT to
agree before atomically publishing the complete gate. The native helper repeats
`sd_session_is_active` and the kernel VT check immediately before forking. A
release, signal or timeout before approval closes PAM without starting a child.

Its child then acquires the real spare controlling VT, drops all UID/GID identities and supplementary groups
to the test account, and launches:

```text
dbus-run-session --config-file=/usr/libexec/localpin-m1-topology/private-session-bus.conf -- /usr/bin/plasma_session --no-lockscreen
```

Here `--no-lockscreen` reaches **ksmserver only**, as in stock classic Wayland
startup. The wrapper starts KWin with its normal Wayland screenlocker enabled.
The private bus explicitly denies ownership of and messages to
`org.freedesktop.systemd1`; manager environment updates cannot succeed on it.
This constrains that private bus only. Stock autostart components can separately
invoke `systemd-run --user` through the canonical user-manager socket; an actual
first launch recorded such an invocation. Treat any resulting escaped processes
as a separate cleanup and observation concern. Do not infer that all access to
the canonical manager is blocked or that its environment stayed unchanged.
The canonical PAM-provided `/run/user/UID` is checked and retained. Only XDG
config/data/cache/state directories are isolated in a fresh target-owned runtime
subdirectory. DISPLAY and WAYLAND_DISPLAY are absent before classic startup, so
the stock wrapper allocates a fresh socket and KWin chooses its DRM backend.
No nested, virtual, replacement, no-lockscreen-KWin or shared systemd startup
flag is supplied. These source observations still require actual device/GUI
corroboration.

The returned session/VT/scope and child PID identify a **registration-only**
fixture. Explicit `activate` switches only that verified new clone session and
starts the desktop child; neither result claims a working desktop. The
supervising root operator can switch between recorded consoles for the separate
visible desktop/locker tests.
Do not invent a VT for a non-seat0 seat: this launcher is seat0-only.

Keep observations private until sanitized. Read the first normal greeter's live
direct-session/user-manager membership and enumerate both own-UID candidates.
The first shared-manager greeter must produce ambiguous/unavailable discovery
when both candidates exist. The second classic greeter can have a valid direct
mapping to its own session; do not describe it as user-manager-owned. Confirm
both actual compositors/shells, DRM card use, independent live screenlockers,
the real routing probe's response and one-entry full-password fallback. Check
the first shared manager's display/bus environment before and after. No
production PIN or routing attestation is supplied by this launcher.

From guest root, release and clean the exact owned fixture:

```sh
python3 experiments/m1/vm/topology/launch.py finish
```

The controller requests normal child/PAM shutdown, then stops only its recorded
new session scope if necessary, plus its exact launch unit. It verifies fresh
session identity against the durable root registration and excludes every
baseline session ID before scope cleanup. It never kills by UID, seat, process
name or environment tag. The inherited public fixture tag is only an additional
observation: leftover tagged descendants cause refusal and retained resources.
Success requires the owned scope gone/empty, launch unit stopped, no tagged
descendants and the protected first graphical desktop still registered. Transient
SSH baseline sessions need not remain connected. Target runtime directories,
fixture binaries and controls are removed only after those checks.

Preparation records the actual scope stop timeout and requires a known finite
value no greater than 45 seconds. Finish rechecks that bound and allows 55 seconds
for the normal `systemctl stop` job, preserving all ownership checks. The original
12-second client timeout was shorter than the guest's observed45-second scope
stop setting and could falsely report incomplete cleanup while its legitimate
stop job continued. The controller adds no force-kill path or manager default
change. A 55-second timeout retains all resources for inspection/clone rollback.

The session scope has independently verified 15-minute runtime, 1024-task and
3-GiB memory limits; the native parent also has a watchdog. The first launch's
256-task ceiling was reached during startup, with thread-creation failures and
a shell crash/restart. That attempt supplies no GUI/authentication pass. The
higher bounded ceiling requires a fresh fixture startup after verified cleanup;
raising it alone does not repair an incomplete existing desktop. A
partial/failed start can leave durable controls for explicit `finish`. A verified
native registration that already disappeared can be cleaned only after proving
its exact recorded scope gone. Unknown ownership, inaccessible process
inventory, unconfirmed stop or surviving descendants retain resources and
require clone rollback. SIGKILL/power loss also requires clone rollback. After
successful fixture cleanup, discard or restore the whole clone for complete
cleanup.

The first two inactive-start attempts supply no visible-GUI or authentication
pass. The second had healthy thread capacity, but its active KWin reported a
disabled DRM output and held no input event FDs; the displayed panel was a stale
frame. Both exact owned scopes were subsequently cleaned with the first desktop
retained. Activating before compositor initialization is an experimental repair:
KWin's [libinput initialization](https://github.com/KDE/kwin/blob/v6.7.5/src/backends/libinput/context.cpp)
assigns the seat immediately, and its [activation handler](https://github.com/KDE/kwin/blob/v6.7.5/src/backends/libinput/connection.cpp)
resumes only an already suspended context. systemd's
[device implementation](https://github.com/systemd/systemd/blob/v259.9/src/login/logind-session-device.c)
can return an already revoked evdev FD to an initially inactive session. These
sources suggest a startup explanation; they do not establish an upstream bug or
prove that the new handshake repairs input/DRM. Actual fresh output, input and
GUI evidence remains mandatory. No ACL, group or udev permission change is made.

## Source and local validation

The exact prepared Fedora PLM6.7.5 `src/daemon/Display.cpp:289–308` reuses an
existing same-user online PLM session. Stock greeter login therefore supplies
session switching rather than this second desktop. Root separately verified
that the clone's `plasma-workspace`/`kwin`6.7.5-1.fc44 packages own the classic
startup binaries. Fedora patch preparation for those two packages has not yet
been performed by this fixture author.

Versioned upstream sources establish the proposed path:

- [Classic startup](https://github.com/KDE/plasma-workspace/blob/v6.7.5/startkde/plasma-session/startup.cpp)
  starts the wrapper and core KDE processes directly; arguments go to ksmserver.
- [Normal startup's classic branch](https://github.com/KDE/plasma-workspace/blob/v6.7.5/startkde/startplasma.cpp)
  supplies the same ksmserver lock flag for Wayland.
- [Wrapper](https://github.com/KDE/kwin/blob/v6.7.5/src/helpers/wayland_wrapper/kwin_wrapper.cpp)
  passes a fresh Wayland socket and updates its session-bus launch environment.
- [KWin backend selection](https://github.com/KDE/kwin/blob/v6.7.5/src/main_wayland.cpp)
  chooses native DRM in the clean environment and retains default screenlocking.

Native warning-as-error compile and twelve pure launcher checks pass locally.
The native launcher uses libsystemd and its headers for the active-session check;
`LOCALPIN_SYSTEMD_INCLUDE` can point to exact copied distro headers when the guest
does not have systemd-devel installed. Tests include root-guard ordering,
changed-leader refusal, no gate after failed activation, and atomic nonoverwriting
gate publication. They perform no live session operation.
Separate actual temporary private-bus probes denied both ownership of the manager
name and a read-only Ping to that name with `AccessDenied`. The ordinary syscall
sandbox refused socket creation; those probes ran with scoped escalation and all
runtime files in a fresh `/tmp` directory. They did no PAM, account, session,
systemd-manager or VM operation. No successful GUI or authentication result is
claimed here until its separate sanitized evidence is recorded.
