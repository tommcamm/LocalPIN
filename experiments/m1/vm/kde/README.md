# Guest stock-KDE candidate-capture experiment

This module **always returns `PAM_IGNORE`**. Its PAM line uses `[default=ignore]`,
so it cannot grant PIN authentication even if a future code defect returned
success. It exists solely to test whether stock KDE can submit one candidate
through a capture module and the original password stack. It is separate from
the simulated-success account-policy fixture and has no scripted-conversation
appdata dependency.

Only service `kde` and target `localpintest` with matching real/effective UID are
captured. The module requests an echo-off response, copies it with
`pam_set_item(PAM_AUTHTOK)`, erases/frees its response, and returns ignore. Any
validation or API failure also returns ignore. After candidate transfer it emits one sanitized syslog event,
`LocalPIN M1 fallback capture set_item=<numeric result>`, so the operator can count
actual captures. It logs no input, input length/encoding, or PAM conversation text.

The installer requires guest root, a disposable VM, SELinux Enforcing, and the
same root:root 0600 UUID-bound `/etc/localpin-m1-vm-guard` described in
[the account harness](../pam/README.md). A clean restorable VM snapshot and a
separate administrator connection are mandatory. It is a temporary experiment,
not a product activation tool.

A compile-only check performs no system/PAM operations and is safe in the
workspace:

```sh
LOCALPIN_PAM_INCLUDE=/absolute/path/to/pam-devel/usr/include python3 experiments/m1/vm/kde/manage.py compile-only
```

Inside the guarded VM, inspect then install:

```sh
python3 experiments/m1/vm/kde/manage.py check
python3 experiments/m1/vm/kde/manage.py install --snapshot-confirmed
python3 experiments/m1/vm/kde/manage.py status
```

The installer builds a root-owned
`/usr/lib64/security/pam_localpin_m1_fallback.so`, verifies its default SELinux
label matches the distribution PAM module type, and inserts the marked
`[default=ignore]` block before the first original auth line in `/etc/pam.d/kde`.
It keeps every original policy byte and refuses an existing LocalPIN/pam_pinlock
module or unfamiliar layout. Original account/password/session lines are retained.
Temporary PAM/module inodes receive their validated target SELinux label before
atomic replacement, so the active path never depends on a later relabel step.
The complete original file, module, metadata and SHA-256 digests are synchronized
under root-only `/var/lib/localpin-m1-kde` before integration changes. These
backups contain no password values.

The operator controls the VM console and assigns synthetic ordinary/six-digit
passwords to the dedicated account using protected input. Test wrong-password
denial and successful unlock with one submission for each password, then test
missing-module fallback with a **new greeter/PAM handle**:

```sh
python3 experiments/m1/vm/kde/manage.py simulate-missing-module
```

A module already loaded by an existing greeter can remain mapped after unlinking;
that does not test the missing-module path. Remove the file before starting the
new lock-screen greeter, record its new PID, and verify ordinary full-password
unlock still works. To reintroduce the known experiment module:

```sh
python3 experiments/m1/vm/kde/manage.py restore-module
```

Restore promptly through the administrator connection:

```sh
python3 experiments/m1/vm/kde/manage.py restore
```

Restoration verifies the exact installed PAM digest, restores original bytes and
mode, verifies the original digest/SELinux label, removes only the known module,
and deletes experiment state. A changed PAM/module file is refused for manual
review; the installer never overwrites unrelated edits. SIGINT/SIGTERM during installation attempt original-byte and label recovery;
restoration ignores a second interruption while completing its bounded recovery
window. External commands have 30-second deadlines. An interrupted install retains
the durable original backup/manifest for this command. SIGKILL, power loss, or
uninterruptible filesystem I/O still require hypervisor snapshot recovery. If cleanup fails,
restore the clean VM snapshot through the hypervisor. Restore that snapshot after
exporting sanitized results to remove all other test-account, journal, package,
and experimental side effects.

This proves no PIN route, eligibility implementation, broker/TPM operation,
production SELinux domain, or recovery guarantee. Record actual UI observations,
versions, policy digests and restoration results in the
[VM PAM report](../../../../docs/development/m1-vm-pam.md); code compilation is not
an unlock test.

## Optional fixed broker-contact build

The original tested build remains `capture-only`. A separate opt-in build adds a
fixed, password-free contact before the conversation:

```sh
python3 experiments/m1/vm/kde/manage.py compile-only --contact-fixture
python3 experiments/m1/vm/kde/manage.py install --snapshot-confirmed --contact-fixture
```

Install only after any previous experiment has been restored. The manifest
records `build_mode=contact-fixture` and the exact module digest; restoration uses
the saved original PAM bytes and module, independent of this build choice.

The only endpoint is the existing SELinux fixture's
`/run/localpin-m1/contact.sock`. The module uses nonblocking Unix stream I/O,
checks `SO_PEERCRED` for a root server, sends exactly `PING`, and expects exactly
`PONG`. The contact function accepts no candidate argument and transmits no
password, PIN, username, or authorization token. One monotonic 250 ms budget is
shared by connect/send/receive, including partial operations and retries. It
never treats a late response as contact success. Scheduling and other PAM modules
can extend elapsed authentication time; this is not a product latency claim.

The fixed journal event is
`LocalPIN M1 fallback contact outcome=<number> selinux_type=<bounded type>`.
The SELinux field contains only a validated type of at most 128 ASCII
letters/digits/underscores, or `unavailable`; it excludes user/role/range. Outcome
codes are 0 success, 1 clock failure, 2 socket failure, 3 connect unavailable or
denied, 4 deadline, 5 untrusted peer, 6 send failure, 7 receive failure, and 8
unexpected fixed reply. Every outcome continues normal candidate capture and
returns `PAM_IGNORE`.

The operator must independently start/stop the confined fixture broker before
starting each fresh greeter transaction, keeping its bounded service lifetime in
mind. This module starts no broker and changes no SELinux policy. Observe actual
successful password unlocking both with the root-peer broker available and with
an intentionally unavailable/denied endpoint. Correlate the contact event's type
and numeric outcome with the relevant greeter; an event is not an unlock result.

`python3 experiments/m1/vm/kde/test_contact.py` tests the exact contact routine in
a private unprivileged user/mount/network namespace. No host `/etc` or `/run` is
exposed. Seven checks cover absent socket, root-peer fixed exchange, fragmented
reply, wrong reply, EOF, stalled-reply deadline and an injected untrusted-peer
credential result. The root-peer baseline is namespace UID 0; the bad-peer case
is a deliberate `getsockopt` test injection, not a second real host UID. Every
received request is checked to contain only the fixed `PING` marker. Namespace
unavailability exits 77.

## Optional live session-routing observation

The separate `--routing-fixture` build links libsystemd and observes the actual
greeter's own sd-login membership and current eligible own-UID session count.
It requires systemd development headers and cannot be combined with the contact
build. Use the same guarded `compile-only` or snapshot-confirmed `install`
commands with this flag; restoration retains the original-byte checks above.

The fixed journal event reports only numeric direct/owner API results, owner
agreement, enumeration completeness, candidate count and a diagnostic decision:
0 unavailable, 1 directly mapped eligible session, or 2 unique eligible session
for the verified user-manager owner. An ineligible direct mapping refuses.
Absent direct mapping requires `-ENODATA`, owner agreement and exactly one live
candidate; zero/multiple candidates refuse. A property-query error makes the
enumeration incomplete, logs count -1 and suppresses the unique-session result.
No session IDs, UIDs, PIDs or candidate bytes enter this event.

These observations exercise the discovery proposal in the actual locker. They
are not broker authentication, a race-proof snapshot or a production routing
contract. Every decision continues candidate capture and returns `PAM_IGNORE`.
Correlate the event's kernel journal identity with the independently observed
greeter and an actual one-entry normal-password unlock. The
[topology checklist](../topology/README.md) defines the concurrent-desktop proof.
