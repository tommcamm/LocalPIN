# Opt-in positive confined password-worker experiment

VM TEST ONLY. This separate fixture temporarily changes the dedicated ordinary
`localpintest` account's password/aging/lock fields, runs eight native worker
cases, restores the exact original shadow record and removes its policy/files.
Use the shared UUID-bound root:root 0600 disposable-VM marker, SELinux enforcing
and a clean restorable snapshot. Serialize it with all other account/UI tests.
Do not run it on an everyday host or supply a personal password.

```sh
python3 -m unittest discover -s experiments/m1/vm/worker-positive -p 'test_*.py' -v
python3 experiments/m1/vm/worker-positive/run.py --compile-only
sudo python3 experiments/m1/vm/worker-positive/run.py --run-mutate --snapshot-confirmed
```

Guest prerequisites: `gcc python3 pam-devel selinux-policy-devel make
policycoreutils setools-console libxcrypt shadow-utils`. Local compilation can
use `LOCALPIN_PAM_INCLUDE` with extracted matching headers. The default CI does
not run this mutation fixture.

The worker runs as the ordinary target UID in `localpin_m1_positive_t`, with exact
non-ignored `SELinuxContext` and no active/permitted/inheritable or ambient
capabilities. It verifies those properties and that direct shadow open is denied
before PAM. Only fixed public test-case names are accepted; synthetic candidates
are compiled into this test utility. No real password, candidate argument,
environment variable or unit property is accepted or logged.

The private read-only PAM service uses an unchanged copy of the reviewed Fedora
`password-auth` graph with digest
`2e53f704372b6c7fb69cdc4dfd6c27456d642c83feff8b1588fa1f9cb1126cd0`.
That exact local-password-only graph retains its existing required checks,
auth-substack control rules and account phase. Every other digest refuses before
account mutation. No KDE, authselect or existing PAM service is edited. Separate
permit/deny baselines run before the account is changed.

The eight cases are permit, deny, correct password, wrong password, locked
password, expired account, expired password and recovery. C asserts the exact
authentication/account return codes and prompt counts, emits numeric outcomes
with fixed case names, and returns nonzero on mismatch. Successful authentication
must run account management before it can count as a worker success. No broker
grant, credential enrollment, PIN backend or transaction/replay protocol exists.

The packaged setuid-root `unix_chkpwd` is required. The policy grants only its
specific domain transition and executable map, local passwd-file read, required
etc/locale reads and syslog/audit access. It avoids Fedora's broad
`auth_domtrans_chk_passwd`, which also permits password updates and unrelated
integrations. Before any mutation, `sesearch` must find no direct `shadow_t` read
and no `updpwd_t` transition for the worker.

This worker deliberately differs from the broker sandbox: NNP is disabled for
the native setuid/helper-domain path, and the capability bounding set retains
only DAC read/search and audit-write for that helper. The ordinary worker itself
has none of those active capabilities. AF_UNIX and AF_NETLINK in the initial
network namespace preserve native audit reporting; AF_INET/AF_INET6 are prohibited
and IP access is denied. Private devices/temp, strict system/home protection,
no cores, bounded tasks/memory/lifetime and group-wide teardown still apply.
These experimental choices need production review, not a claim of minimality.

The runner reuses the shared VM PAM account guard/assignment/exact-restoration
functions and the boundary fixture's sanitized command/result helpers. It never
rewrites the passed boundary fixture. Failure preserves the original stage and
records no pass. INT/TERM initiate teardown and account restoration. SIGKILL,
power loss, failed cleanup or failed restoration require snapshot recovery.
Journal output can include native messages about the fixed test account; export
only sanitized outcome metadata. Restore the whole VM snapshot separately.

On 2026-10-16, the guarded Fedora 44 VM passed all eight cases under enforcing
SELinux, and a later monitored rerun passed them again. Both runs reported
complete fixture cleanup and exact restoration of the original target shadow
record. The [sanitized result](../results/2026-10-16-worker-positive.json)
records PAM/pam-devel `1.7.2-2.fc44`, systemd `259.9-1.fc44` and targeted policy
`44.11-1.fc44`; the worker had neither a direct shadow-read rule nor a password
update transition. During the positive and boundary reruns, the enabled audit
subsystem's lost-event count stayed at 76 with an empty backlog before and after.
The [coverage record](../results/2026-10-16-audit-coverage.json) preserves the
preexisting loss, which limits conclusions from earlier missing log entries.
Whole-VM snapshot restoration remains a separate operator action.

This establishes only the copied, reviewed `password-auth` subtree under this
profile and this own-UID helper path. It does not establish the production
privileged worker, broker-bound authorization, faillock profile, pure
password-free PIN eligibility checks, multiple seats/sessions or the complete
release matrix. The successful fixture leaves `production_worker_complete`
false.
