# M1 password-free eligibility policy experiment

Date: 2026-10-16. Status: six default-profile and nine `with-faillock` guest cases
passed with SELinux Enforcing. The experiment establishes a concrete, bounded
eligibility path after the earlier [real-account tests](m1-vm-pam.md)
demonstrated unsafe lock/expiry shortcuts. Its success gate is simulated; it
supplies no production authentication capability.

The [root-private experiment](../../experiments/m1/vm/eligibility/README.md)
recognizes only the previously measured Fedora PAM/authselect versions and exact
KDE, postlogin, default/lockout password-auth, and external faillock configuration
contents. Unknown layouts and configuration fail before mutation. The external
`faillock.conf` digest is
`662303cf89938c12d95a7fc59d92cbe76c398312527fa908894fb319809093b3`;
it is root:root, regular/single-link, mode 0644, with no active directives.
The checker compares fresh policy bytes with reviewed private copies around PAM.

The policy requires fresh local identity/shadow checks, rejects locked/empty
hash fields and conservative aging failures, and accepts only the strictly
parsed SHA512-crypt fixture format. It preserves required `pam_env` and exact
`pam_faildelay delay=2000000` prechecks, invokes explicit `pam_faillock preauth
silent` only for the reviewed lockout profile, and runs `pam_unix`/`pam_nologin`
account checks. It excludes the counter-resetting `pam_faillock account` hook.
It then revalidates identity/shadow/policy and tally consistency before allowing
a private simulated-success gate. No candidate enters this eligibility route.
Known-password baselines and intentional counter population run separately
through the original password policy.

The native checker compares the tally contents and device/inode, owner/group,
mode, size, mtime and ctime. It requires canonical ownership/mode and an openable
regular file before invoking PAM. Missing tally is a run-bound fixture starting
condition established after a known healthy password/account baseline; the test
does not treat an arbitrary missing production counter as healthy. A private
empty `pam_nologin file=` fixture tests denial without changing global nologin
state or disrupting administrative access.

## Guest evidence

The sanitized [default-profile result](../../experiments/m1/vm/results/2026-10-16-eligibility-default.json)
and [lockout-profile result](../../experiments/m1/vm/results/2026-10-16-eligibility-faillock.json)
record `completed=true`, no primary/restoration failures, exact original target
shadow-record restoration, and Enforcing mode. Both used
`pam-1.7.2-2.fc44.x86_64`, `authselect-1.7.1-1.fc44.x86_64`, and
`selinux-policy-targeted-44.11-1.fc44.noarch`. Root separately verified that the
original authselect profile was restored exactly. The checker ran as root in
the administrative `unconfined_t` domain.

| Case | Profiles | Observed result |
| --- | --- | --- |
| Healthy account | Both | Preauth/account 0/0; simulated gate 0 |
| Locked password hash | Both | Raw lock denial; PAM not invoked; gate 6 |
| Expired account | Both | Raw aging denial; PAM not invoked; gate 6 |
| Expired password | Both | Raw aging denial; PAM not invoked; gate 6 |
| Private nologin fixture | Both | Preauth/account 0/7; gate 6 |
| Mismatched expected identity | Both | Identity denial; PAM not invoked; gate 6 |
| Active failure lockout | Lockout | Preauth 7; account not invoked; gate 6 |
| Healthy after explicit fixture-counter reset | Lockout | Preauth/account 0/0; gate 0 |
| Noncanonical tally mode 0640 | Lockout | Counter-health denial before PAM; gate 6; mode retained |

Here 0 is `PAM_SUCCESS`, 6 is `PAM_PERM_DENIED`, and 7 is `PAM_AUTH_ERR`.
All cases recorded zero conversation calls and unchanged reviewed policy.
The cases with a canonical counter recorded identical counter bytes and checked
metadata before/after the checker. Active lockout remained effective: a separate
correct-password attempt still failed after the eligibility check. The deliberately
noncanonical counter returned `counter_valid=false` and
`counter_unchanged=false` from the native health guard; independent bounded reads
showed unchanged bytes, and the runner verified that mode 0640 was retained.
Those native false values describe refusal to establish canonical state, not
successful counter normalization or a passing health check.

The packaged `chpasswd --encrypted` rejected the deliberately malformed public
hash fixture with exit 1. The first attempt therefore stopped during setup and
restored the original target record. The completed reruns classify this separately
as `invalid_fixture_rejected`, verify the unchanged target record, and record
`actual_account_case_tested=false`. No malformed enabled real-account checker
result is claimed. The strict parser's malformed-hash rejection is covered only
by the pure C format test; the runner does not bypass the account tool by editing
shadow directly.

## Source findings and limits

The versioned [preauth implementation](https://github.com/linux-pam/linux-pam/blob/v1.7.2/modules/pam_faillock/pam_faillock.c)
selects the tally check rather than content reset/write. However,
[opening a tally](https://github.com/linux-pam/linux-pam/blob/v1.7.2/modules/pam_faillock/faillock.c)
uses read/write access and can normalize ownership/mode. Some open failures are
accepted by the preauth check; independent file health and unchanged-state checks
are therefore essential. The account branch can reset a tally and is excluded.
This is a reviewed upstream path, not a completed Fedora patch audit. The guest
results above measure the exact installed module under the guarded fixture
conditions; they do not establish universally read-only preauth behavior.

Local validation: native checker and gate compile with C11, warning checks as
errors, stack protection and ELF relro/now; Python syntax parses. Four pure
guard/refusal/bounded-read tests and a pure C hash-format test pass. Compile-only
performs no PAM transaction, account lookup or mutation. The fixture accepts only
strict tested SHA512-crypt syntax and rejects yescrypt/other formats. The guest
results establish no yescrypt support.

The identity pin is valid only for this experiment's lifetime and does not solve
an enrolled account's deletion/recreation with identical fields. A root process
reads shadow data and retains only the target record; no record/hash is exported,
and complete Python/native secret erasure is not claimed. Administrative-domain
execution does not establish a confined production eligibility worker. Policy or
account changes after a delivered authorization, production IPC/grant binding,
full access-policy coverage and full snapshot restoration remain separate
requirements. The target-record and profile restorations do not remove audit,
backup or other whole-VM artifacts. Final whole-VM cleanup was completed later; see the separate record below.
Fixed numeric stage diagnostics preserve primary failure separately from
restoration outcomes.

## Final cleanup

After these observations, the [clean snapshot was restored and the VM restarted](../../experiments/m1/vm/results/2026-10-16-cleanup.json).
The temporary guest SSH key was explicitly removed before rollback, and the local
temporary key pair was deleted. Per-run pending/false snapshot fields describe
the time of collection; this separate record establishes final cleanup.
Post-restore SELinux mode was not independently queried.
