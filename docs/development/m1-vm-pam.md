# M1 guest real-account PAM validation

Date: 2026-10-16. Status: guarded real-account harness passed twelve default-profile
cases and sixteen `with-faillock` cases in the disposable Fedora 44 KDE VM with
SELinux Enforcing. Separate [stock KDE fallback UI tests](m1-vm-kde.md) also passed.
Production eligibility and service confinement remain unresolved.

The [guest-only runner](../../experiments/m1/vm/pam/README.md) is separate from the
[synthetic experiment](m1-pam.md). It requires a disposable VM guard tied to the
guest UUID, SELinux Enforcing, a clean restorable snapshot, guest-root authority,
and the dedicated ordinary local account `localpintest`. It never modifies the
KDE PAM service or installs its experimental module.

## Implementation and local validation

The Python runner assigns public synthetic passwords to the dedicated account,
alters only that account's lock/aging state, and restores its original shadow
record in `finally`. Password/hash transfer uses inherited pipes or subprocess
stdin. Neither is logged or placed in command arguments/environment variables.
The runner reads the shadow file to find the target but retains only that
account's original record for restoration; no record or hash is exported.
Original shadow-record comparison is narrower than whole-VM restoration: audit logs and tool backup
files require the clean snapshot to restore the complete initial VM state.

The native harness independently checks root/VM/marker/Enforcing/local-account
conditions, drops to the target UID/GID/groups, and calls `pam_start_confdir`.
Its service files link the actual `password-auth` graph, so normal password
modules and unprivileged helpers execute without editing their policy.

Local verification performed on the development machine:

```sh
LOCALPIN_PAM_INCLUDE="$PWD/.local/m1/pam-devel/usr/include" python3 experiments/m1/vm/pam/run.py --compile-only
```

Result: both native files compile with C11, warning checks treated as errors,
stack protection and ELF relro/now. No PAM transaction or account mutation runs
in this mode. Running `--check-env` as the ordinary development user stopped at
`run as guest root`, before account or authentication operations. This is a guard
check and compile result, not guest evidence.

## Real guest results: default profile

The operator ran the guarded suite in the disposable `localpin-m1` VM after a
clean enforcing snapshot. The target was ordinary UID 1001 `localpintest`;
administration used a separate account/root connection. The active authselect
profile was `local` with `with-silent-lastlog`, `with-mdns4`, and
`with-fingerprint`; `with-faillock` was absent. Twelve cases passed in the
[default-profile result](../../experiments/m1/vm/results/2026-10-16-pam-default.json).
Relevant observed numeric outcomes:

| Condition | Authentication | Account phase |
|---|---|---|
| Correct ordinary/six-digit password | `PAM_SUCCESS` (0) | `PAM_SUCCESS` (0) |
| Wrong password | `PAM_AUTH_ERR` (7) | Intentionally not called |
| Locked password, real route | `PAM_AUTH_ERR` (7) | `PAM_SUCCESS` (0) |
| Locked password, naive fixture success | `PAM_SUCCESS` (0) | `PAM_SUCCESS` (0) |
| Expired account, real or naive fixture route | `PAM_SUCCESS` (0) | `PAM_ACCT_EXPIRED` (13) |
| Expired password, real or naive fixture route | `PAM_SUCCESS` (0) | `PAM_NEW_AUTHTOK_REQD` (12) |

Ordinary and six-digit same-entry fallback succeeded with one secret prompt.
Repeated authentication on the same handle returned `[0, 7, 0]` for fresh correct,
wrong, and correct candidates. The runner verified restoration of the original
dedicated target shadow record. No original record or password was included in
the exported observations.

These results demonstrate that account-only PAM checks fail to establish the
password-lock restriction on this profile: both auth and account succeed after a
naive simulated PIN bypass on a locked password. They also confirm that the
account phase contains expiry decisions absent from KDE's auth-only flow. The
naive fixture deliberately grants synthetic six-digit success and is never
installed in the KDE service.

This is the real `password-auth` subtree from a private service, with the harness
dropped to the target UID while retaining its original administrative SELinux
domain. It does not characterize the complete `kde`/`postlogin` graph or a confined
production worker. Whole-VM snapshot restoration remains a separate operator step. Package versions
and policy digests belong to the sanitized guest result records linked below.

## Real guest results: lockout-enabled profile

The operator temporarily enabled the `with-faillock` feature on the same profile,
then repeated the suite with a fresh dedicated-user counter. Sixteen cases passed
in the [lockout-profile result](../../experiments/m1/vm/results/2026-10-16-pam-faillock.json);
the configured denial threshold was three. The twelve default-profile cases ran
again, followed by these four observations:

| Condition | Observed result |
|---|---|
| Three wrong-password submissions, then the correct password | Correct-password authentication denied with `PAM_AUTH_ERR` (7) |
| Naive synthetic PIN success while the failure lockout was active | Authentication returned `PAM_SUCCESS` (0), demonstrating the unsafe short circuit |
| Explicit account phase after the lockout assertions | Naive auth and account both returned `PAM_SUCCESS` (0), although the preceding real-auth probe was denied |
| Dedicated fixture-counter reset, then the correct password | Authentication and account management both returned `PAM_SUCCESS` (0) |

Wrong submissions and lockout assertions used auth-only calls. This prevents an
account phase from clearing failure records before lockout behavior is measured.
The account observation intentionally follows those assertions. Its success is
not a PIN eligibility decision: it did not deny the already demonstrated failure
lockout, and account modules may reset counters. Treating this call as an
unexamined preflight risks changing the state being checked. The runner reset
only the dedicated test user's fixture counter and verified its original shadow
record after this run. The operator restored the original authselect features
after collecting the lockout-profile results.

Together, these tests show that preserving password fallback alone does not
preserve lock/expiry eligibility for a successful PIN route. A privileged eligibility
policy must explicitly account for password lock markers, expiry and active failure
lockout. It cannot be inferred from a successful naive module or from an account-only
call. The actual production eligibility implementation is still absent.
The subsequent [password-free eligibility experiment](m1-vm-eligibility.md)
tests a concrete guarded preflight direction for these exact two profiles;
its six/nine passing cases use a private simulated gate, root execution in
`unconfined_t`, and only tested SHA512-crypt account fixtures.

## Evidence and remaining gates

The [default-profile](../../experiments/m1/vm/results/2026-10-16-pam-default.json)
and [lockout-profile](../../experiments/m1/vm/results/2026-10-16-pam-faillock.json)
exports record numeric return codes, prompt counts and target-record/counter
restoration without passwords or original shadow records. Both runs used:

| Package | Installed version |
|---|---|
| `pam` and `pam-devel` | `1.7.2-2.fc44.x86_64` |
| `authselect` | `1.7.1-1.fc44.x86_64` |
| `kscreenlocker` | `6.7.5-1.fc44.x86_64` |
| `selinux-policy-targeted` | `44.11-1.fc44.noarch` |

The actual `password-auth` content digests were:

| Profile | SHA-256 |
|---|---|
| Default | `2e53f704372b6c7fb69cdc4dfd6c27456d642c83feff8b1588fa1f9cb1126cd0` |
| With failure lockout | `de00ea01b5ffe6b08efd7027e437bdd4a3bad18e231e9593f6b45cc64b334276` |

The [KDE UI report](m1-vm-kde.md) separately establishes stock-theme same-entry
fallback with a module that always ignores and never authorizes a PIN. The real-account
harness characterizes the `password-auth` subtree under the original administrative
SELinux domain after dropping UID. Neither test establishes a confined production
worker or a complete LocalPIN integration.

The [candidate/account decision](../adr/0001-pam-candidate-and-account-policy.md)
now includes the bounded experimental eligibility path. Production worker
integration, complete nologin/access policy, real backend failure handling,
production SELinux domains, complete session/seat coverage and recovery remain
separate evidence gates. The original target shadow
record, authselect features and KDE PAM file have been restored. At the time of
this report update, final clean-snapshot restoration was still pending other VM
experiments; restoration of a single record does not establish whole-VM cleanup.

## Final cleanup

After these observations, the [clean snapshot was restored and the VM restarted](../../experiments/m1/vm/results/2026-10-16-cleanup.json).
The temporary guest SSH key was explicitly removed before rollback, and the local
temporary key pair was deleted. Per-run pending/false snapshot fields describe
the time of collection; this separate record establishes final cleanup.
Post-restore SELinux mode was not independently queried.
