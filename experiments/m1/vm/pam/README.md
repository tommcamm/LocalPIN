# Guest-only real-account PAM experiment

This test deliberately changes the dedicated `localpintest` account temporarily.
Run it only inside the disposable Fedora KDE VM with its clean snapshot available.
It creates private PAM services and a test module; nothing is installed into KDE,
`/etc/pam.d`, or the distribution module directory.

Required guest packages include `gcc`, `pam-devel`, `python3`, `libxcrypt`,
`shadow-utils`, `authselect`, and the existing PAM/systemd/SELinux tools. Root
administration must use a separate management account or guest-root connection.
`localpintest` must be an ordinary local account outside root/wheel/sudo groups.

The Python runner and native harness independently require guest root, a VM,
SELinux Enforcing, and `/etc/localpin-m1-vm-guard`. That file must be a regular
single-link file owned by root:root with mode 0600 and exactly this content:

```text
LOCALPIN-M1-DISPOSABLE-VM
target=localpintest
uuid=<this guest's /sys/class/dmi/id/product_uuid>
```

Use the UUID exactly as reported by the guest, including case, and end every line
with a newline. The marker guards against accidental execution on another machine;
it is not authorization for an untrusted caller. An operator with root authority
can override any local test guard.

Check the environment first:

```sh
python3 experiments/m1/vm/pam/run.py --check-env
```

Confirm the hypervisor has a clean, restorable snapshot, then run as guest root:

```sh
python3 experiments/m1/vm/pam/run.py --run-mutate --snapshot-confirmed --report /root/m1-vm-pam.json
```

The report path must be new. Password candidates and hashes travel over inherited
pipes/stdin, never arguments or environment variables. All test passwords are
public synthetic fixtures embedded in this test; no administrator or existing
account password is requested. The runner reads only the dedicated account's
original shadow record into memory for restoration; it never exports that record
or its hash. The test process is experimental Python/native code and does not
promise complete secret erasure.

The runner uses `chpasswd --encrypted`, `chage`, and `usermod --lock` on that one
account. It preserves the original hash and aging fields in memory and verifies
the original target shadow line after restoration in `finally`. SIGINT/SIGTERM
initiate cleanup; SIGKILL, power loss, or cleanup failure require restoring the VM
snapshot. Account tools and PAM may also create audit/journal entries or shadow
backup files. `target_shadow_record_restored` proves only that dedicated record;
**restore the clean snapshot for complete VM cleanup**.

The native harness checks its guard as root, drops UID/GID/groups to
`localpintest`, then starts PAM. This exercises the real unprivileged password
module/helper path, while the root runner controls fixture state. Its private
root-owned service directory contains only code and policy links, with no password
files. It links the actual guest `password-auth` include/substack graph into
`pam_start_confdir`, preserving the original policy contents.

The suite records twelve cases without `pam_faillock`: correct/wrong baselines,
one-entry ordinary/six-digit passwords, repeated-handle attempts, locked hash,
account expiry, password expiry, and deliberately naive simulated PIN success
under those states. The naive module accepts any six digits to demonstrate the
policy bypass; **it is not a credential verifier or an eligibility implementation**.
`pam_acct_mgmt` observations are explicit because KDE does not call that phase.
The runner never calls `pam_chauthtok`.

If the active graph includes `pam_faillock`, the runner additionally requires its
standard `/run/faillock` directory, a bounded consistent denial threshold, and no
preexisting target failure records. It generates the configured number of wrong
password attempts, verifies that a correct password is denied, demonstrates the
naive auth short circuit, observes the account phase separately, then resets only
the dedicated user's fixture counter. Wrong-auth and lockout tests use auth-only
calls because account modules can reset counters. Unknown/custom layouts refuse
the test; changing the VM authselect profile is a separate operator action.

A compile-only check is safe outside the guest and performs no PAM transaction,
account lookup, or mutation:

```sh
LOCALPIN_PAM_INCLUDE=/absolute/path/to/pam-devel/usr/include python3 experiments/m1/vm/pam/run.py --compile-only
```

Real guest results belong in [the VM PAM report](../../../../docs/development/m1-vm-pam.md).
Stock KDE dialogs, nologin/access policy, actual LocalPIN broker/eligibility logic,
service-domain SELinux policy, session/seat checks and desktop recovery require
separate tests. Running this harness under an unconfined administrative context
with Enforcing enabled does not establish a confined production worker policy.
