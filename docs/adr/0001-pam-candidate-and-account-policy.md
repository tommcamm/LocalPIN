# ADR 0001: PAM candidate reuse and explicit PIN eligibility

Date: 2026-10-16. Status: accepted experimental candidate contract; production
eligibility policy and activation remain blocked on enforcing-VM evidence.

## Context and evidence

LocalPIN must preserve a single submitted candidate through the PIN route and
existing full-password route. Six ASCII digits can be either a PIN or an account
password. KDE's packaged 6.7.5 worker reuses a PAM handle, runs authentication and
credential refresh, and does not run account management. Adding an early PIN
success can therefore skip authorization or failure-lockout checks in the
original auth stack; an account section alone does not protect that path.

The [M1 report](../development/m1-pam.md) records exact source inputs, observed
module behavior, baselines and remaining limits. Thirty synthetic assertions
passed, and five assertions against Fedora's packaged `pam_unix` passed inside a
namespace containing only synthetic accounts. The latter demonstrates same-entry
reuse for the tested `pam_unix` options, not the complete KDE/authselect policy.

## Decision

1. Capture one echo-off candidate using the PAM conversation. Only six ASCII
   digits enter the PIN route. Other candidate bytes remain unchanged, including
   whitespace, non-UTF-8 and Unicode sequences. The supported PAM representation
   is a NUL-terminated string; embedded NUL is outside that representation.
2. Transfer a copy to `PAM_AUTHTOK` through `pam_set_item` before erasing/freeing
   the adapter's conversation response. Treat PAM's token as borrowed. Do not
   keep a secret-bearing module cache, a previous success flag, or pointers past
   the current transaction. Repeated-handle and cancellation tests are required
   for the production Rust adapter and actual KDE build.
3. Short-circuit only on fresh authoritative PIN success after explicit
   eligibility checks and durable completion. All non-success PIN results
   continue the original password policy under a verified rule such as
   `[success=done default=ignore]`. The example is a test contract, not an
   installable Fedora configuration. Preserve every preceding required check and
   the original password module order. Unknown layouts refuse activation.
4. PIN success must require a privileged, fresh eligibility decision that
   covers the supported local account's password lock state, account/password
   expiry, active failure lockout, and relevant nologin/access restrictions. The
   policy must preserve applicable required prechecks from the original graph.
   Broker identity/session validation is an additional requirement. Neither a
   username lookup nor `pam_acct_mgmt` alone is accepted as proof of all these
   conditions. Missing, failed or ambiguous eligibility disables the PIN route
   and leaves original password policy authoritative.
5. Resolve the concrete worker policy by testing the exact supported Fedora
   graph in an enforcing VM. A separate password-only worker must not include
   LocalPIN, the previous PIN module, or alternative authentication shortcuts.
   Do not recursively invoke the screen-lock auth stack from the adapter. The
   system broker can host or invoke a narrowly scoped privileged eligibility
   worker; its APIs, deadlines, permissions and account-change races require
   evidence before this architecture is fixed.
6. Preserve existing failure accounting. A submitted six-digit account password
   may consume a LocalPIN PIN-format attempt before succeeding as a password.
   A wrong PIN passed to the password route can also increment original password
   failure counters. This is an unavoidable ambiguity of a single shared field;
   do not suppress or reset original counters to conceal it. Cooldown skips PIN
   verification but still submits that candidate to the original password stack.
   The exact fifth-attempt reservation/cooldown boundary remains an explicit M2
   state-machine decision with deterministic tests.

## Consequences and required tests

The candidate API is feasible for this Linux-PAM/`pam_unix` version and can guide
M2/M7 interfaces. It does not authorize deployment. A separate explicit password
conversation or refusal remains required if a supported downstream module cannot
reuse the candidate. No full password may be normalized, validated as a PIN, or
logged.

The production eligibility implementation remains a release blocker. VM evidence
must include locked password markers, expired account and password, nologin/access
restrictions, each supported authselect profile including `with-faillock`, required
checks before and inside substacks, and races with account changes. Test PIN
success and password success/failure while inspecting original counters; no
permissive stand-in or mocked account result passes that gate.

The original stack may delay password fallback independently. Mock timeout
results demonstrate mapping only; elapsed deadline guarantees need blocked-native
worker tests and end-to-end measurements. Existing fingerprint/smartcard services
and unrelated PAM services remain outside the LocalPIN activation target.
