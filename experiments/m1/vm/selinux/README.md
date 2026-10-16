# Guest-only SELinux boundary experiment

This is an opt-in disposable Fedora KDE VM fixture. It temporarily installs its
own SELinux module, four fixture executables and four runtime systemd units. It
does not edit `/etc/pam.d`, authselect, a password, a real credential, a TPM or
the locker's configuration. It does not accept a real password. Keep a clean
restorable snapshot. No production service or policy is delivered.

The Python runner requires all of the following before mutation: real/effective
root, QEMU/KVM VM detection, SELinux `Enforcing`, a dedicated non-root
`localpintest`, no existing fixture paths/module, and a root:root single-link
regular `/etc/localpin-m1-vm-guard` file with mode 0600 and exactly:

```text
LOCALPIN-M1-DISPOSABLE-VM
target=localpintest
uuid=<the guest's exact /sys/class/dmi/id/product_uuid value>
```

It never creates that marker. The marker is shared with the separate VM PAM
experiment. The guard is an accident-prevention mechanism, not VM attestation.
The operator must confirm this really is the disposable guest.

Inside that guest, install `gcc python3 pam-devel selinux-policy-devel make
policycoreutils`. Compile/execute only after an operator has reviewed the
purpose-written `localpin_m1.te.in` and `localpin_m1.fc` for the installed policy.
The initial policy is a candidate; no enforcing execution result is claimed until
the runner completes and AVCs are reviewed.

```sh
python3 -m unittest discover -s experiments/m1/vm/selinux -p 'test_*.py' -v
sudo python3 experiments/m1/vm/selinux/run.py --run-in-disposable-vm
```

If the actual guest locker type was observed separately, optionally add
`--locker-type <observed_type_t>`. This inserts only search, socket-file write and
broker `connectto` rules for that type. It does not launch/inject into the actual
locker or count a real locker transaction as tested. An unconfined targeted
desktop may already possess those rights, so a passing fixture cannot establish
new mandatory confinement for that desktop.

The broker runs as root in `localpin_m1_broker_t`, accepts only a fixed `PING`
from the dedicated test UID using kernel peer credentials, and returns fixed
`PONG`. No password/PIN/verifier is involved. Clients validate root peer UID.
Both confined test clients run as `localpintest` with equal DAC and socket-file
permissions. Only `localpin_m1_client_t` has broker `connectto`; the
`localpin_m1_denied_t` fixture must receive a permission denial. Both must fail
to read a world-readable private-type canary (MAC test) and root:root 0700/0600
state (separate DAC barrier). The world-readable canary's bytes are public.

The separate root worker domain loads private permit/deny PAM services from
`/etc/localpin-m1-pam` using `pam_start_confdir`. It then executes the packaged
`unix_chkpwd` for the fixed nonexistent account `localpin_m1_missing_account`
with a public synthetic candidate in a pipe. Preflight refuses if that name
exists. A close-on-exec error pipe and the helper's expected missing-account
return distinguish executable/helper failure. This proves a negative native
helper path, not real password success, expiry/lockout eligibility, failure
accounting, or a complete enrollment-worker sandbox. It grants no direct shadow
read and deliberately avoids the broad `auth_use_pam` interface.

Broker and worker use different units. Both have no IP networking, private
temporary/device namespaces, no capabilities, strict read-only system/home
protection, no cores and process/memory/time limits. The broker has
`NoNewPrivileges=yes`; the worker explicitly has `NoNewPrivileges=no` because
native PAM helper privilege/domain transitions must be evaluated separately.
This is an unresolved production hardening choice. No generic shell or command
endpoint is exposed.

The policy explicitly combines the installed Fedora `init_daemon_domain` and
`init_domain` interfaces: the latter supplies direct `init_t` execution and the
scoped NNP/nosuid transition contract. Units require their exact SELinux context
without an ignore-errors prefix, and C verifies its actual domain. Correct file
labels alone do not establish that a transition occurred. Three initial guest
attempts stopped before a confined broker succeeded; the fourth passed the
bounded contact/MAC/DAC and negative-helper fixture. The report records that
result and the broader worker/locker limits.

On success the runner emits sanitized JSON only after cleanup. Failure emits no
pass and preserves its original fixed stage alongside cleanup failures. Fixed C
diagnostics go to the guest journal; candidates and PAM prompts are not printed.
Executable-label diagnostics compare actual, policy-matched and expected types
before service start. A domain mismatch exports only validated bounded type
names, excluding SELinux users, roles and ranges. No failed-state reset is needed
after fixtures are stopped and their definitions are removed.
INT/TERM trigger best-effort bounded cleanup; if unit shutdown cannot be
confirmed, it retains fixture resources and requires snapshot restoration.
Policy-install ambiguity is checked even after an installer error/timeout.
SIGKILL, power loss and cleanup errors always require restoring the snapshot.
Inspect guest AVCs for fixture types, record only cause/type/class/permission,
and keep raw journal/audit records out of Git. Never use `audit2allow`, change
SELinux mode, or add broad permissions to turn a failure into a pass.

The [evidence report](../../../../docs/development/m1-vm-selinux.md) states what
was actually run and what remains open. The fixture is not part of default CI.
