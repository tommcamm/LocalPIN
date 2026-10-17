# M7 PAM adapter and KDE integration

Date: 2026-10-17. Status: implemented; required isolated native and disposable
stock-theme KDE/SELinux-enforcing PIN, fallback, restriction and fault acceptance
cases passed for ADR 0012's restricted domain. Additional in-place TPM rebind
and same-enrollment reboot recovery did not pass; their observed limitations
and explicit fresh recovery are recorded below, without a transparent-recovery claim.
M8 installed activation, packaging and confinement and M9 independent human
review and hardware acceptance remain separate gates.

## Implemented adapter

[`localpin-pam`](../../crates/localpin-pam/README.md) builds the production
`liblocalpin_pam.so` for the reviewed installed name
`/usr/lib64/security/pam_localpin.so`. It accepts no arguments or configurable
endpoint. Only exact service `kde` and an existing unique local account matching
both nonzero real and effective UID can enter the PIN route. The module reads
a root-owned regular `/etc/passwd`, with no symlink and a 1 MiB bound, directly
instead of invoking NSS. It rechecks that context after the application
conversation and before returning a grant. The broker independently enforces
ADR 0012's supported account, lifecycle, session and eligibility restrictions.

The local-file bound limits input and allocation. Opening with `O_NONBLOCK`
avoids blocking FIFO opens, and regular-file validation rejects special files;
neither guarantees a deadline for kernel regular-file I/O.
The adapter's explicit latency guarantees below apply to broker transport; the
original password stack and initial interactive input retain their own timing.

Each authentication call clears any previous `PAM_AUTHTOK`, makes one fresh
echo-off `Password: ` conversation and uses `pam_set_item` to copy the submitted
NUL-terminated candidate byte-for-byte into PAM's owned token. Only a successful
callback transfers its C conversation response; its terminator and string are
erased before the transferred string and response allocations are freed with
libc. On callback failure, allocation cleanup belongs to the application. The
module never inspects or frees the unowned error output, which may already be
dangling; application failure-path leaks cannot safely be repaired here. The
module borrows PAM items only within the
call and stores no candidate, token pointer, connection or prior-success flag
between invocations. Empty, whitespace, Unicode, long and non-UTF-8 passwords
remain on the original password route. Embedded NUL is outside the native PAM
string representation. Only six ASCII digits reach the broker.

The fixed `/run/localpin/broker.sock` endpoint uses the existing protocol
client's root-controlled path, root peer and fresh greeting checks. One status,
challenge and submitted verification must complete in the proper order with
the live connection binding. Available enrolled-backend status selects the
budget; cooldown or unavailable status prevents a PIN submission. Challenge
reuse, expired or malformed lifetimes, wrong bindings, unexpected variants and
terminal errors cannot authorize. Only terminal authoritative
`VerificationOutcome::Granted` returns `PAM_SUCCESS`; every other result maps to
`PAM_IGNORE` and the original password policy.

One common suspend-inclusive start produces absolute deadlines. Connect and
Hello are capped at 250 ms, while setup and the entire software path consume
one two-second budget. Only an authenticated enrolled TPM backend permits the
final verification to use the five-second deadline measured from that same
start. Intermediate status or challenge responses never renew either budget.
The adapter deliberately does not chain the generic client's independently
budgeted `status()` and `verify()` convenience methods.

`pam_sm_setcred` performs no authentication, conversation or broker operation.
It returns a successful no-op for the supported context and `PAM_IGNORE`
otherwise. Linux-PAM replays the selected authentication control path during
credential refresh, so this no-op lets `[success=done]` complete after a PIN
grant without cached module authorization. Both actual exported entry points
catch Rust unwinding panics and return fallback. Process aborts and invalid
native-pointer/application conversation contracts are outside that protection.

All unsafe code is isolated in `src/pam.rs`, which documents the Linux-PAM
layouts, constants, borrowed pointers and allocator contract. The cdylib links
the runtime `libpam.so.0` SONAME directly; it needs no unversioned development
symlink to build. Native symbol inspection found only the two required exported
entry points, `pam_sm_authenticate` and `pam_sm_setcred`; dynamic dependencies
are `libpam.so.0`, libc, libgcc_s and the platform loader, with immediate symbol
binding. The source review and pinned `zeroize` establish the intended erasure
implementation; the native harness does not intercept `free` or inspect freed
storage. Historical copies, native PAM token copies, compiler moves, swap and
dumps remain outside the module's erasure guarantee.

## Exact policy compatibility

[ADR 0013](../adr/0013-pam-unlock-contract.md) and the
[complete reviewed sample](../../crates/localpin-auth/policy/kde-localpin.review-required)
define the only integrated KDE layout accepted by the password-free eligibility
authority, alongside the measured stock layout. The fixed owned prefix uses
`auth [success=done default=ignore] /usr/lib64/security/pam_localpin.so`; the
original graph follows byte-for-byte with account, password and session
sections unchanged. Arbitrary module arguments, paths, control rewrites or
downstream edits fail the exact-layout check.

Changing that policy is a mutation of the immutable account-authority inputs.
The supported lifecycle sequence first durably revokes the domain, stops the
broker, installs the reviewed bytes, seals new incarnations, restarts and
requires fresh enrollment. Existing credentials cannot survive the policy
transition. This implementation is not an M8 activation or everyday-machine
installation tool.

## Local and isolated-native validation

The following adapter checks passed:

```text
cargo test --offline -p localpin-pam
  13 passed; 0 failed
cargo clippy --offline -p localpin-pam --all-targets -- -D warnings
  passed
cargo build --offline -p localpin-pam
  passed
```

The unit cases cover exact/duplicate/foreign/root/setuid target bindings,
malformed account input, unsupported invocation, repeated fresh capture without
cached success, no authentication in setcred, target changes during conversation
or broker work, terminal result mapping, unavailable status, wrong order or
binding, invalid/reused challenges and original shared software/TPM deadlines.
NULL handles and negative, zero and positive argument counts return fallback
without dereferencing arguments. Test-only thread-local panic injection exercises
both actual C exports and confirms that unwinding stops before returning to C;
this injection is absent from production artifacts.

The [isolated production-module harness](../../crates/localpin-pam/tests/README.md)
also passed all 63 application attempts using the exact release cdylib, real Linux-PAM and native
`pam_unix`/`pam_faillock`. It runs namespace root as the fake authenticated wire
broker and a different non-root mapped UID as the PAM application. Its private
tmpfs `/etc` and `/run` contain only synthetic identities and policies; host
accounts, policies, state and TPM devices are absent. No host service, account
or PAM rule is changed.

The completed local invocation used extracted development headers only for the
test C compiler:

```sh
LOCALPIN_PAM_INCLUDE=/home/tommy/Documents/localpin/.local/m1/pam-devel/usr/include \
  python3 crates/localpin-pam/tests/isolated_pam.py
```

The greeting-silence case passed its assertion that the complete PAM attempt
finished within 2.5 seconds while the fake broker withheld its greeting. This
exercises the production connection/greeting deadline, capped at 250 ms; no
precise latency sample was printed or recorded. The fake broker's interruptible
wait can end during runner cleanup, so it does not establish an observed
2.4-second server hold. Other original PAM policies may add their own independent
fallback delay.

Native permit/deny and correct/wrong password baselines precede adapter checks.
Cases preserve all 255 non-NUL candidate byte values, empty/Unicode/long values,
leading zeros and six-digit account passwords; exercise normal password fallback
without a second prompt, repeated authentication on a reused handle and fresh
recovery after cancellation or malformed/error-return conversations; and reject
target/service changes and unsupported identities. Native control-stack cases
cover preceding required/requisite failure, a missing module and explicit
account-phase denial. Broker modes cover unavailable/disabled/cooldown status,
malformed/order/binding/challenge responses, stopped/crashed peers and final
storage/TPM-unavailable responses. The actual password/lockout module cases
check original failure accounting, unchanged counters on PIN success, password
recovery, existing lockout, locked-password denial and expired account
management.

The error-return regression deliberately frees its callback allocations and
leaves a non-null output pointer. The adapter rejects that call without touching
the pointer, then accepts a fresh PIN on the same handle. A successful callback
alone transfers ownership; failed-callback cleanup belongs to the application.

These native tests establish the production adapter's ABI, token lifetime,
credential-phase behavior and authenticated public transport against controlled
wire responses. The fake broker's grant does not establish production durable
credential completion or eligibility. Its synthetic readable shadow fixtures
also do not establish installed privileged-helper behavior. Allocator ownership
and zeroization are source-reviewed rather than runtime-interposed evidence.

## Native KDE accounting and activation blocker

The reviewed `with-faillock` configuration starts KDE's parallel
`kde-fingerprint` authenticator even before a candidate is submitted. On this
clone, its unavailable fingerprint path records a valid native failure. The
same startup failure occurs with the original stock KDE policy. It is separate
from the PIN operation and is never erased or suppressed by LocalPIN.

This KDE build omits account management. Its original password policy therefore
does not perform the account-phase faillock reset after authentication: the
stock full-password control also retained the fingerprint failure. Correct
authentication can leave these failures accumulating until the original lockout
applies. Tests must attribute native concurrent writes, retain preexisting
counters, and prove that active lockout denies both routes; an aggregate
before-lock/after-unlock digest alone is insufficient.

This composition remains an **M8 activation blocker**. Activation must refuse it
until a separately reviewed policy decision and actual desktop tests establish
usable behavior. The experiment preserves the original services and accounting;
it does not fix this by changing password policy or resetting counters during
PIN success. [ADR 0013](../adr/0013-pam-unlock-contract.md) records the decision.

## Stock KDE and production-authority evidence

The desktop experiment uses a full independent copy of the M6.1 Fedora 44
x86_64 Btrfs guest, with no backing image, host filesystem share or passed-through
device. The original VM stays off. SELinux stays enforcing, and the KDE theme
and password stack retain their stock settings. The installed production broker,
account/eligibility/password/credential workers, CLI and adapter match the
recorded release artifact hashes. Clone-only SSH and autologin fixtures provide
access to a dedicated real Wayland desktop; they are not production setup tools.

The measured packages include Linux-PAM `1.7.2-2.fc44`, kscreenlocker and
plasma-workspace `6.7.5-1.fc44`, authselect `1.7.1-1.fc44`, tpm2-tss
`4.1.3-9.fc44` and selinux-policy `44.11-1.fc44`. The adapter has the same `lib_t`
label type as native `pam_unix`; this test does not establish M8 confinement.

The following executed phases use actual libvirt keyboard events, the native
stock-theme greeter and production authorities. Candidates are omitted from
the evidence. Timing includes desktop observation overhead and is a sample,
not a latency percentile or service guarantee.

| Case | Observed result |
| --- | --- |
| Original stock KDE baseline | Ordinary password unlocked with one submission in 0.317 seconds; wrong password stayed locked, then the original password recovered the same greeter. |
| PIN grant | A PIN distinct from the account password remained locked until Enter, then unlocked in 0.543 seconds. Native password tally stayed unchanged. |
| Ordinary full password | Unlocked with one submission in 0.414 seconds. |
| Wrong PIN then password | The exact greeter emitted a native authentication failure, stayed locked, then accepted the full password with one further submission. |
| Six-digit account password | Unlocked through original password fallback. Four additional wrong PIN requests reached the configured five-attempt cooldown, proving that this password submission also consumed one PIN guess. The original password and a fresh software enrollment were restored afterward. |
| Stopped, crashed and stalled broker | Each enrolled PIN was denied; full password recovered the same greeter. Stop, actual SIGKILL and actual SIGSTOP setup and repair are recorded separately. |
| Missing PAM module | A fresh greeter could not use PIN and accepted the full password. The exact original module was restored. |
| Corrupt active state and missing credential worker | Each actual production fault denied PIN and preserved same-greeter full-password recovery. Both faults were repaired. |
| Durable cooldown | PIN was denied while native full-password recovery remained usable. Fresh enrollment followed explicit test recovery. |

The final production module SHA256 is
`7b3f7d0656ad55beaa41373fbc023f4b581a5f51d44100dd22654757a9c6c2fc`.
The basic, eight software-fault and thirteen policy cases were rerun against this
ownership-corrected release; earlier artifact records were retained privately.
The structured guest record preserves the original installation digest and the
explicit module revision rather than relabeling an old run as the final artifact.

The wrong-candidate harness waits for a native authentication-failure journal
event from the exact greeter PID, then leaves four seconds for KDE's asynchronous
randomized PAM failure delay before typing recovery. Continued lock alone is
not counted as a completed denial. An earlier stalled-broker attempt typed
recovery too soon and failed the harness; its unsuccessful record is retained
in private development history alongside the corrected passing runs.

A separate actual Linux-PAM probe reuses one `kde` handle against the installed
production broker for six calls: PIN success, wrong password denial, full
password success, empty denial, Unicode denial and full password success.
Every call makes exactly one fresh prompt, and each successful authentication
also completes `pam_setcred`. This establishes repeated-handle behavior against
the production authorities; it supplements the keyboard observations rather
than representing a desktop unlock itself.

All thirteen policy/accounting desktop cases passed against the corrected final
module, with its actual guest digest checked before and after the matrix:

| Native condition | Observed result |
| --- | --- |
| `with-faillock` PIN success | Two successive PIN unlocks preserve the first and second parallel fingerprint failure records byte-for-byte from immediately before Enter through unlock. |
| Third fingerprint startup failure | Reaches the real native threshold. Actual greeter and native PAM probes deny both PIN and password without changing the locked counter. An explicitly recorded root reset permits same-greeter password recovery. |
| Wrong PIN fallback | A valid native `kde` password failure is recorded; the experiment explicitly resets the tally for recovery and records that reset. |
| Preexisting password failure | A real wrong password creates the native record. Successful PIN and full-password desktop controls each preserve it and their separately attributed fingerprint startup record. |
| Independently prepared native lockout | Three real wrong passwords cause lockout. Both PIN and password stay denied until explicit root reset. |
| Runtime `/run/nologin` | PIN is denied; the original password route recovers the same greeter. |
| Locked password | Both routes stay denied until exact account restoration and fresh enrollment. |
| Expired account, expired password, forced password change and restricted shell | Each protected account mutation first revokes the old incarnation. The former PIN cannot unlock; the password-free worker denies the restricted account. Original auth-only KDE password behavior remains intact, including password acceptance where its original account phase is omitted. |

Each restriction is explicitly repaired, and the final matrix verifies the exact
default password profile, fresh software enrollment, healthy eligibility, an
unlocked desktop and no fault, restriction or nologin marker. These recorded lab
resets and account repairs are separate administrator actions, never side
effects of PIN success. The stock-policy control and public native policy graphs
attribute the fingerprint behavior described above.

## Native TPM fault and recovery

The clone subsequently used exactly one private libvirt-managed TPM2 CRB
emulator, with no caller-selected TCTI or physical device. The installed CLI's
`enroll --backend tpm2-required` completed through a real controlling PTY with
four hidden prompts and no secret echo. The production native PAM probe and
actual KDE PIN unlock both passed through `/dev/tpmrm0`.

The fault fixture verifies the platform device, native class, driver and
reciprocal ACPI identity, records durable intent, then unbinds the actual CRB
driver. Native device 0 disappears while the credential stays TPM-backed. The
correct enrolled PIN is denied, the exact greeter emits its native failure, and
full password recovers that same greeter. This passes M7's actual TPM-fault
password-fallback requirement.

Two additional recovery strategies exposed limits and remain recorded as failed:

- An initial fixture assumed an absent driver path and refused before mutation.
  After inspecting the actual binding, the reviewed fixture used
  `/sys/bus/platform/drivers/tpm_crb_acpi`. On kernel
  `7.2.10-200.fc44.x86_64`, in-place rebind allocated `tpm1`/`tpmrm1`; the fixed
  production device 0 stayed unavailable. The experiment did not alias another
  node or change the production endpoint, and kept its fault intent.
- A guarded restart restored native device 0 with unchanged emulator XML,
  registry, active pointer and credential bytes. PIN remained unavailable because
  the reboot lost authoritative volatile faillock state. This is the deliberate
  [M6.1 restriction](m6.1-account-authorities.md), not permission to reconstruct
  or clear old counters. The attempt to preserve enrollment across that reboot
  therefore did not pass. Private equality fingerprints were never exported;
  throttle state was intentionally excluded from those equality claims.

Explicit privileged recovery then verified the missing-tally refusal, durably
revoked the old domain before retiring the known device-fault intent, and
provisioned fresh incarnations. Actual TPM-required CLI enrollment, native PAM
and KDE PIN unlock passed again. Private comparisons confirmed that the new
registry and credential differed from the originals. This is fresh enrollment,
not recovery of the old credential. Neither failed strategy is reported as a pass.

## Restoration, evidence and retained gates

The experiment revoked the domain, restored the original KDE bytes, mode and
SELinux context, synchronized restoration and removed the exact module. Fresh
stock greeters passed ordinary-password unlock and wrong-password/full-password
same-greeter recovery. Temporary guest SSH access and autologin were removed;
the clone shut down gracefully and was undefined, and its owned independent disk
and private emulator state were deleted. Local temporary SSH access files were
removed. The original VM stayed defined and off; host authentication and physical
TPM state were untouched.

[Sanitized KDE evidence](../../experiments/m7/results/2026-10-17-kde-integration.json)
records applied faults, actual UI outcomes, all explicit lab resets, final
artifacts, failed additional recovery strategies, fresh recovery and cleanup.
Its required-acceptance summary is separate from those failed strategy results.
[Repository checks](../../experiments/m7/results/2026-10-17-repository-checks.json)
record the final source hashes, 298 passing workspace tests/doctests, nine
intentionally ignored tests, 63 native PAM attempts, ABI smoke, format, strict
Clippy and dependency-policy checks. Hosted CI execution remains unverified.
A headless application or fake broker alone would not meet this acceptance gate.

M6.1's [production-authority evidence](m6.1-account-authorities.md) remains the
account/lifecycle prerequisite and supplies no automatic M7 UI acceptance.
Installed confinement and RPM lifecycle remain M8; independent human ABI and
security review and physical TPM validation remain M9.
