# Guest password-free eligibility experiment

This root-private fixture tests whether a simulated PIN success can be gated on
account restrictions without consuming a password or resetting existing failure
counters. It is not a production eligibility worker, PIN verifier, or KDE module.
It installs no PAM service/module and never changes the KDE file. Its only
system mutations temporarily affect the dedicated `localpintest` account and its
fresh fixture failure counter, with the original shadow record restored afterward.

The runner imports the [real-account harness](../pam/README.md) for its independent
VM/root/Enforcing/ordinary-account guard and known-password baselines. A clean
restorable snapshot and separate administrative connection remain mandatory.
The native checker independently verifies guest root, the exact root:root 0600
UUID-bound marker, Enforcing mode, a VM, and its root-only private directory.

Compile without any PAM/account operation:

```sh
LOCALPIN_PAM_INCLUDE=/absolute/path/to/pam-devel/usr/include python3 experiments/m1/vm/eligibility/run.py --compile-only
```

Inside the guarded guest:

```sh
python3 experiments/m1/vm/eligibility/run.py --check-env
python3 experiments/m1/vm/eligibility/run.py --run-mutate --snapshot-confirmed
```

The runner refuses all except the two exact Fedora guest profiles already tested:
original KDE/postlogin files, default or `with-faillock` password-auth, installed
PAM/authselect versions, and the exact root-owned all-comment `faillock.conf`.
It records hashes without exporting configuration contents. Copies of these
reviewed inputs are private; the native checker compares actual inputs against
them before and after PAM and refuses any changed input before allowing the gate.
An existing global nologin restriction stops the experiment without altering it.

The password-free path:

1. Read fresh root-controlled local passwd/shadow records. Require the exact
   identity pinned for this run, matching NSS UID/GID, an ordinary local user,
   shadow linkage, the strictly parsed SHA512-crypt fixture format, an unlocked
   nonempty hash,
   and conservative account/password aging eligibility. No hash is verified or
   logged. This run-lifetime identity pin does not solve enrolled UID reuse.
2. Establish failure-counter health independently: standard root-controlled
   directory, regular single-link file, expected target owner/root group,
   canonical 0660 mode, bounded 64-byte-record-aligned size and readable/writable
   file descriptor. Missing state is accepted only after this same run's known
   healthy password/account baseline establishes the fixture's starting state.
3. Invoke private PAM auth containing the original required `pam_env` and exact
   `pam_faildelay delay=2000000`, optional explicit `pam_faillock preauth silent`,
   and a permit sentinel that supplies no password verification. Account checks
   use `pam_unix`, actual read-only `pam_nologin`, and an additional private
   nologin-file fixture. The conversation rejects every request/message.
4. Recheck local identity/shadow and reviewed policy. Compare tally bytes,
   device/inode, ownership/mode, size and mtime/ctime. Changes or unavailable
   state disable the gate. Atime is excluded because reading may change it.
5. Allow the private simulated-success PAM gate only when every condition
   succeeded. The gate accepts root-private in-process fixture state only;
   no client Boolean, secret candidate, IPC token or persistent grant exists.

The preauth module is deliberately not called for noncanonical tally files.
Linux-PAM 1.7.2 opens tallies read/write and may normalize ownership/permissions;
its preauth path also treats some open failures as success. Thus preauth alone is
not a trustworthy state-health check or a universally read-only operation.
The fixture never calls `pam_faillock account`, `authsucc` or `authfail` on the
eligibility route. Original password baselines populate/reset counters separately
and intentionally; those are not eligibility calls.

Six real-account default-profile cases cover healthy, locked hash, expired account,
expired password, an empty root-owned private
`pam_nologin file=` fixture, and mismatched expected identity. Only the tested
SHA512-crypt syntax is accepted; yescrypt and unknown hash formats are rejected
by this fixture rather than claimed supported. An attempted malformed-hash setup
is recorded separately when packaged `chpasswd --encrypted` rejects it; the
runner verifies that refusal left the target record unchanged and reports the
actual malformed-account checker case as not tested. It does not rewrite shadow
directly to bypass that tool. Strict malformed-hash rejection has a separate pure
C format test. The lockout profile adds active lockout with unchanged tally,
healthy recovery after explicit fixture-counter reset, and a noncanonical tally
mode that is refused before PAM without normalization. The account tools and
PAM can leave audit/backup artifacts; exact target-shadow restoration does not
restore the entire VM. Restore the clean snapshot after collecting sanitized
results. SIGKILL/power loss or failed cleanup also require that snapshot.

Source inspection and measured results belong in the
[eligibility report](../../../../docs/development/m1-vm-eligibility.md). Six
default-profile and nine lockout-profile cases passed in the Enforcing guest;
both reports record exact target-shadow restoration and no restoration failures.
The checker ran as root in `unconfined_t`; full snapshot restoration is pending.
No result
settles production race handling after an authorization has been delivered,
confined-worker permissions, enrolled identity lifecycle, other authselect
profiles, or the complete desktop/access-policy matrix.

Pure guard/bounded-read tests perform no real account operations:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s experiments/m1/vm/eligibility -p test_run.py -v
```

They verify guard-before-policy/account ordering, unknown-policy refusal, and
regular/symlink/FIFO/oversized counter handling. `test_format.c` exercises only
the strict fixture hash parser, linking the existing PAM library but never
calling a PAM/account function. Compile it with the same header include override
as the checker when system development headers are unavailable.

Failure reports contain a fixed numeric primary stage and error category,
separate shadow/counter restoration failures (stages 90/91), exact-target-record
restoration status, and the last sanitized checker observation. They never
contain command stderr, account records or hashes. `completed=false` returns
exit 1 even if partial cases passed; cleanup failure requires the snapshot.
The malformed fixture assignment is stage 30; its expected invalid-input tool
refusal is not an eligibility failure or a passing malformed-account test.
