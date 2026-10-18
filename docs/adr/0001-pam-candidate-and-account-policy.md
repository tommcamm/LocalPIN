# ADR 0001: PAM candidate reuse and explicit PIN eligibility

Date: 2026-10-16. Original M1 status: accepted experimental candidate contract and bounded
eligibility path, supported by Enforcing-VM evidence. Production eligibility
implementation and activation remain release blockers.

Credential-format amendment: [ADR 0021](0021-flexible-credentials.md) replaces the six-digit routing grammar with an enrolled type/length profile and a generation-bound challenge. Exact password reuse, eligibility and native accounting requirements remain in force.

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
reuse for the tested `pam_unix` options. Subsequent
[real-account VM tests](../development/m1-vm-pam.md) passed twelve default-profile
and sixteen lockout-profile cases, and the
[stock KDE UI tests](../development/m1-vm-kde.md) passed three fallback-only cases.
The locked-password and failure-lockout bypass demonstrated by naive fixture
success reinforces the explicit eligibility requirement; no production PIN
success branch was installed in KDE.

The subsequent [password-free eligibility experiment](../development/m1-vm-eligibility.md)
passed six default-profile and nine lockout-profile cases in the Enforcing guest.
It denied locked/expired accounts, a private nologin restriction, identity
mismatch, active failure lockout and noncanonical counter state before its
private simulated-success gate. Active lockout remained effective after the
checker, and eligible canonical-state checks preserved the measured tally.
This establishes the experimental policy below, with root execution in
`unconfined_t` and synthetic SHA512-crypt account passwords.

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
5. Use the measured password-free preflight below as the experimental policy
   direction for the exact reviewed Fedora graph. A separate password-only
   worker must not include
   LocalPIN, the previous PIN module, or alternative authentication shortcuts.
   Do not recursively invoke the screen-lock auth stack from the adapter. The
   system broker can host or invoke a narrowly scoped privileged eligibility
   worker; its APIs, deadlines, permissions and account-change races require
   production implementation and further evidence before activation.
6. Preserve existing failure accounting. A submitted six-digit account password
   may consume a LocalPIN PIN-format attempt before succeeding as a password.
   A wrong PIN passed to the password route can also increment original password
   failure counters. This is an unavoidable ambiguity of a single shared field;
   do not suppress or reset original counters to conceal it. Cooldown skips PIN
   verification but still submits that candidate to the original password stack.
   The exact fifth-attempt reservation/cooldown boundary remains an explicit M2
   state-machine decision with deterministic tests.

## Experimental eligibility path

For the two exact reviewed authselect graphs, the root-private fixture first
checks fresh local passwd/shadow identity, password lock markers and conservative
account/password aging. It accepts only the tested, strictly parsed SHA512-crypt
format. It independently establishes bounded, canonical failure-counter state
before PAM; a missing tally is acceptable only after the same run's healthy
password/account baseline established that fixture starting condition.

Its private password-free PAM route preserves required `pam_env` and
`pam_faildelay delay=2000000`, adds explicit `pam_faillock preauth silent` for the
reviewed lockout profile, and checks `pam_unix`/`pam_nologin` account policy.
It excludes `pam_faillock account`, `authsucc` and `authfail` from eligibility.
Preauth alone is insufficient: upstream can accept some failed tally opens and
can normalize file metadata. The fixture checks tally bytes and metadata around
PAM, rechecks local identity/shadow and the exact policy/configuration inputs,
rejects conversation requests, and supplies no candidate to this route. Unknown,
unreadable, changed or noncanonical state disables its simulated gate.

This fixture selects a policy direction, not a production worker API. It does
not verify a PIN, deliver an authorization grant, establish confinement, support
yescrypt or solve enrolled UID reuse. A real malformed-account hash case remains
untested because the packaged account tool refused its setup; pure C checks
exercise the strict parser separately. The private nologin-file test does not
establish complete desktop/access-policy coverage. Fresh checks around PAM do
not resolve account/policy changes after an authorization is delivered.

## Consequences and required tests

The candidate API is feasible for this Linux-PAM/`pam_unix` version and can guide
M2/M7 interfaces. It does not authorize deployment. A separate explicit password
conversation or refusal remains required if a supported downstream module cannot
reuse the candidate. No full password may be normalized, validated as a PIN, or
logged.

The production eligibility implementation remains a release blocker. The guarded
fixture supplies concrete lock/aging/nologin/failure-lockout evidence for its two
reviewed profiles. Production must validate supported hash formats, complete
nologin/access restrictions, every activated authselect graph and required
substack check, enrolled identity lifecycle, account-change races, worker
confinement and authenticated grant binding. Test real PIN success and password
success/failure while inspecting original counters; the fixture's permissive
sentinel and simulated gate do not satisfy that production validation.

The original stack may delay password fallback independently. Mock timeout
results demonstrate mapping only; elapsed deadline guarantees need blocked-native
worker tests and end-to-end measurements. Existing fingerprint/smartcard services
and unrelated PAM services remain outside the LocalPIN activation target.

## M6.1 implementation note — 2026-10-17

The M1 evidence and limitations above are historical. Production password-free
eligibility is now implemented only for the explicit Fedora 44 x86_64 Btrfs
appliance domain in [ADR 0012](0012-immutable-appliance-account-authority.md).
It validates the exact reviewed PAM/authselect graph and native binaries,
files-only NSS, supported local identity, strict SHA512-crypt/default yescrypt
formats, lock/aging/forced-change state and applicable nologin/faillock policy.
Unknown restrictions, unreadable or noncanonical state and requested PAM
conversations make PIN unavailable. The worker receives no password and must
leave tally contents and metadata unchanged; own-user enrollment cannot repair
missing state. Native checks run in a bounded supervised child and retain the
original request deadline, with time reserved to deliver unavailable.

The [M6.1 report](../development/m6.1-account-authorities.md) records actual
production-authority component flows and the remaining acceptance evidence.
This supersedes the M1 fixture's SHA512-only implementation limit solely within
the measured domain. It does not validate every Fedora policy or broaden account
support. M7 still owns the stock KDE PIN/fallback matrix; M8 owns installed
worker confinement and packaging; M9 owns independent human/specialist review
and physical hardware validation. None is established by the earlier fixture.
