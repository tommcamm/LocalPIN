# Guest-only logind registration metadata experiment

This fixture registers temporary sessions through the actual guest `pam_systemd`
and observes them through logind and `sd_pid_get_session`. It creates no second
KDE desktop and never authenticates a user. Root declares the metadata of its
own fixture leaders. A passed case establishes an API/discovery-filter contract,
not an authorization decision, remote login, or multiple-seat GUI acceptance.

The runner and native helper require the shared root:root 0600 UUID-bound VM
marker, real/effective root, a VM and SELinux Enforcing. The runner also checks
the dedicated ordinary `localpintest` identity and requires an explicit clean
snapshot confirmation. A single existing target KDE candidate is required.

The operator must keep the current desktop stable while this bounded test runs.
Do not lock/switch seats, start another login, or run other guest session tests
concurrently. Before each case it checks the unchanged active seat0 session and
active VT. It selects a spare VT in 7–15 that is absent from logind, absent from
the kernel VT_GETSTATE in-use bitmask and has no active getty/autovt unit. Only
read-only VT_GETSTATE is used; there is no VT_ACTIVATE, device attachment,
TakeControl, TakeDevice, seat activation, user termination or seat termination.

Inside the guarded guest, from the copied repository:

```sh
python3 experiments/m1/vm/sessions/run.py --run-in-disposable-vm --snapshot-confirmed
```

Keep captured JSON under a private guest/ignored host result directory before
reviewing a sanitized export. The final report exports booleans and counts, not
session IDs, leader PIDs, remote hosts, TTY paths, actual seat labels or UUIDs.
Raw helper readiness metadata remains in a root-only temporary `/run` directory.

A fresh root system service launches each owned helper outside existing session
and user-manager cgroups. Its private PAM configuration contains a session-only
resource-limit module and the packaged `pam_systemd.so`; it contains no auth,
account, password or original-service includes. The helper never calls
`pam_authenticate`, `pam_acct_mgmt` or `pam_chauthtok`. It holds its PAM handle
while the parent examines its newly registered session, then closes that handle.
The helper's UID remains root: these are root-declared registration fixtures,
not trusted desktop/caller identity proofs.

The cases are a real allocated private PTY registered as seatless tty; a
remote-declared KDE/Wayland registration; a greeter-class registration; a
root-UID registration; and a local KDE/Wayland registration that raises the
actual own-UID discovery candidate count from one to two. Seated registrations
use only the verified spare, inactive seat0 VT. All requested fields are checked
against logind's returned metadata. The last case demonstrates ambiguity in real
logind enumeration; it is explicitly not a second graphical compositor. The
remote-declared case does not create a remote connection.

The native alarm (60 s), launch-service runtime (50 s), and new session-scope
runtime (45 s) bound work even when logind moves the leader out of the launch
cgroup. The private session module uses supported PAM module data, consumed as
NUL-terminated strings by systemd v259, to impose scope memory 64 MiB/tasks 8.
The runner reads back RuntimeMaxUSec. Native address-space/CPU limits also follow
the leader. The module exports only session hooks; it has no auth-success hook.
It receives the packaged PAM module's SELinux label, without changing any
file-context rule or installing a new SELinux policy.

INT/TERM initiate Python cleanup, with further signals ignored during cleanup.
The parent releases and stops only its randomly named, prechecked helper unit,
then waits up to 25 seconds for owned fixture registrations to disappear.
Normal helper shutdown calls `pam_close_session`/`pam_end`; abrupt failure or the
hard alarm also relies on logind tracking the leader and closing inherited file
descriptors. Unknown/remaining registrations make the run fail and retain fixture
resources for inspection/snapshot restoration. No session is guessed or killed by
UID/seat. SIGKILL, power loss or a cleanup failure still require the snapshot.

Safe local checks, performing no PAM/session/VT operation:

```sh
LOCALPIN_PAM_INCLUDE=/absolute/path/to/pam-devel/usr/include python3 experiments/m1/vm/sessions/run.py --compile-only
python3 -m unittest discover -s experiments/m1/vm/sessions -p 'test_*.py' -v
```

Primary construction references are systemd v259's [login1 API](https://github.com/systemd/systemd/blob/v259/man/org.freedesktop.login1.xml),
[pam_systemd session registration and limits](https://github.com/systemd/systemd/blob/v259/src/login/pam_systemd.c),
and [seat attachment](https://github.com/systemd/systemd/blob/v259/src/login/logind-seat.c).
The login1 API directs session creation through PAM rather than direct client
CreateSession calls. Linux-PAM's [data API](https://github.com/linux-pam/linux-pam/blob/v1.7.2/libpam/pam_data.c)
refuses `pam_set_data` from applications, so the fixture uses a private session
module. Kernel [VT_GETSTATE](https://github.com/torvalds/linux/blob/master/drivers/tty/vt/vt_ioctl.c)
reports only the first sixteen VTs, hence the bounded selection. Exact installed
guest versions, observed outcomes and remaining gates must accompany any results.
