# ADR 0013: Exact KDE PAM integration and bounded unlock client

Date: 2026-10-17. Status: accepted M7 implementation contract; acceptance requires
the production adapter's isolated tests and disposable stock KDE evidence.
Installed activation, packaging and confinement remain M8 gates.

## Exact policy extension

[ADR 0012](0012-immutable-appliance-account-authority.md) pins the entire measured
KDE policy. Inserting a production adapter changes those bytes and must therefore
be an explicit compatibility extension. The password-free eligibility worker
accepts exactly two `/etc/pam.d/kde` layouts:

| Layout | SHA256 |
| --- | --- |
| Measured stock KDE service | `7d91b3ad73a998e8b10f9edccd74ba04179a778c4a5e61d9176872f43c7bbac3` |
| Exact M7 integrated service | `ea0adc6291dccb0360f5d3565c5dad1f8b886d037f0bcadbbfbf70625383375d` |

The [complete integrated sample](../../crates/localpin-auth/policy/kde-localpin.review-required)
prepends these exact bytes to the stock service:

```text
# BEGIN LOCALPIN
auth [success=done default=ignore] /usr/lib64/security/pam_localpin.so
# END LOCALPIN
```

The original 508 bytes follow unchanged, starting with `auth substack
password-auth` and `auth include postlogin`. All account, password and session
sections remain unchanged. The worker compares the integrated sample as exact
bytes; it does not strip an arbitrary block, normalize whitespace, accept a
different module path or arguments, or infer that an unknown graph is equivalent.
The stock digest stays supported for component checks and enrollment before
integration. This does not broaden either reviewed password-auth profile,
files-only NSS, native-library pins or other ADR 0012 restrictions.

The inserted success control skips the original authentication stack only after
the broker's independent password-free eligibility authority has reproduced its
required account and policy checks and the PIN success is durably completed.
All other adapter outcomes continue the original password route. In particular,
this policy never treats a module load failure as successful authentication.

## Lifecycle continuity

`/etc/pam.d/kde` remains an immutable, snapshotted account-authority input. Neither
this extension nor the module can authorize an in-place policy change while an
incarnation remains active. Administrators must use `begin-mutation` to durably
revoke the domain before changing KDE policy, stop the broker, install the exact
reviewed layout, seal fresh account incarnations, restart and freshly enroll.
Restoring stock policy also crosses that revocation and fresh-provisioning
boundary. Existing credentials cannot survive either policy transition.

M7's guarded disposable-VM installation exercises this sequence; it is not an
everyday-system activation tool. M8 must supply its own reviewed dry run,
protected backups, transactional edits and recovery procedures. Merely adding a
digest to the eligibility allowlist does not satisfy those requirements.

## Adapter identity, candidate and outcome contract

The adapter accepts no options and can attempt PIN authorization only for exact
PAM service `kde`. Real and effective UID must agree with the same non-root local
target identity. PAM item strings are borrowed for their call lifetime; the
adapter must not retain pointers, an authentication token or a success flag
between calls. The broker independently authenticates the kernel peer and live
eligible session; no client-supplied service, name or UID grants authority.

One successful echo-off conversation transfers one NUL-terminated candidate
after the user submits it. The adapter copies the exact candidate to `PAM_AUTHTOK`
through Linux-PAM before erasing and freeing its own C-allocated response. On
conversation failure the application retains cleanup responsibility; its output
may dangle, so the adapter must not inspect or free it. Only six ASCII
digits enter the PIN route. Empty, Unicode, whitespace and non-UTF-8 password
bytes remain available to the original password stack without transformation.
Embedded NUL is outside PAM's string representation. No process-wide or PAM-handle
cache is permitted; every repeated authentication requires a fresh candidate and
fresh broker result. Allocator ownership, malformed ABI arguments, cancellation
and panic containment require direct tests.

Only the terminal authoritative broker `Granted` result maps to `PAM_SUCCESS`.
Mismatch, cooldown, restriction, disabled credential, corrupt state, protocol or
transport failure and every other non-success outcome map to password fallback.
`pam_sm_setcred` does not authorize authentication or retain candidate state.
PAM account/session/password functions are outside the adapter's purpose.

The native contract was checked against Linux-PAM v1.7.2's
[`_pam_types.h`](https://raw.githubusercontent.com/linux-pam/linux-pam/v1.7.2/libpam/include/security/_pam_types.h)
for public layouts and allocator ownership,
[`pam_conv(3)`](https://raw.githubusercontent.com/linux-pam/linux-pam/v1.7.2/doc/man/pam_conv.3.xml)
for success-only response ownership transfer and application-owned failure cleanup,
[`pam_item.c`](https://raw.githubusercontent.com/linux-pam/linux-pam/v1.7.2/libpam/pam_item.c)
for copied token ownership and replacement erasure,
[`pam_auth.c`](https://raw.githubusercontent.com/linux-pam/linux-pam/v1.7.2/libpam/pam_auth.c)
and [`pam_misc.c`](https://raw.githubusercontent.com/linux-pam/linux-pam/v1.7.2/libpam/pam_misc.c)
for completed-authentication token cleanup, and
[`pam_dispatch.c`](https://raw.githubusercontent.com/linux-pam/linux-pam/v1.7.2/libpam/pam_dispatch.c)
for credential-phase dispatch. `pam_setcred` follows the cached authentication
control path; the adapter's successful no-op preserves credential refresh after
a PIN grant without making another authentication decision. Direct tests must
also exercise the actual measured Fedora build.

The shared-field accounting consequence from [ADR 0001](0001-pam-candidate-and-account-policy.md)
remains: a six-digit account password can consume a PIN attempt, and a wrong PIN
can increment the original password failure counter. Neither the adapter nor
eligibility resets or hides those counters. PIN success cannot bypass locked or
expired account policy or an existing password lockout.

The M7 stock-KDE control also found a native composition issue in the reviewed
`with-faillock` profile: KDE starts its parallel `kde-fingerprint` service before
the submitted candidate, and the unavailable fingerprint path records a valid
failure. The original password graph resets faillock in its account phase,
which this KDE build does not call. A successful ordinary password, as well as
a successful PIN, can therefore leave that native failure intact. Repeated
fresh greeters can reach the original lockout without a wrong password. LocalPIN
must preserve that accounting and refuse PIN when the lockout becomes active.
It must not clear the counter or disable another authenticator to conceal it.

This composition is an M8 activation blocker. Activation must detect and refuse
it until a separately reviewed compatibility decision and desktop evidence
establish a usable policy. The M7 experiment can test its actual preservation
and denial behavior; it is not approval to deploy that combination. Counter
tests distinguish asynchronous native fingerprint startup from the submitted
PIN, and compare with the unchanged stock KDE service. See the
[M7 report](../development/m7-pam-integration.md).

## Absolute client deadlines

PAM must retain its own suspend-inclusive `CLOCK_BOOTTIME` deadline because
native broker storage or system-bus work may stall despite server checks. The
250 ms connection budget includes root socket/peer authentication and Hello.
After candidate submission, the unavailable/software route has one absolute
two-second budget across connection, status, challenge and verification; each
stage consumes its remaining time. A status or intermediate response must not
renew that budget. Only a protected broker-selected TPM credential permits an
extension to five seconds from that same start. A caller assertion or malformed
response cannot extend the wait. Late results, unexpected variants, connection
binding failures and reused challenges cannot authorize.

The protocol client used by this adapter must expose this bounded exchange,
rather than chaining APIs that independently create fresh budgets. Tests must
stall setup, status, challenge and verification, check cumulative elapsed time,
and demonstrate that a genuine trusted TPM selection is the sole extension.
Interactive time waiting for the initial PAM candidate is user time; the adapter
must not include it in a broker-operation timeout or attempt background unlock.

## Evidence and limits

The exact-layout test verifies that removing the fixed prefix reproduces the
measured stock digest, pins the integrated digest and rejects changes to
control ordering, module path/options, service type, downstream graphs, placement
or line endings. This establishes the compatibility parser contract only.
The M7 acceptance report must separately record real stock-theme KDE PIN success,
password fallback, repeated calls, account restrictions, original counters and
broker/module/backend/state failure cases in an enforcing disposable guest.
Mock PAM success alone does not meet that gate. M9 retains independent human ABI
and security review and physical TPM validation.
