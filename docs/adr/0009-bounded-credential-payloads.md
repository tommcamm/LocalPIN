# ADR 0009: bounded backend payloads and one-operation native contexts

- Date: 2026-10-17.
- Status: accepted development contract; TPM construction still requires independent review.
- Requirements: specification sections 8–12; M4/M5/M9.

## Decision

Keep the M2 `LPC1` envelope and M3 generation pointer unchanged. Backend payloads
are interpreted only after reading the active protected envelope under its UID
lock. A backend consumes a `VerificationJob` whose reservation, account
incarnation, generation, backend and exact charged KDF parameters match that
record. A backend match is not an authorization: the core completion still
requires durable success and the current generation/account fence.

Software payloads are canonical ASCII PHC strings, bounded to 98 bytes. Accept
only `$argon2id$v=19$m=<memory>,t=<passes>,p=1$<salt>$<output>`, with unsigned
canonical decimal fields, 65536–262144 KiB, 3–6 passes, a 16-byte salt and 32-byte
output encoded as unpadded canonical Base64. Reject duplicate, additional,
reordered, unknown and noncanonical fields rather than delegating arbitrary
work factors to a generic PHC verifier. Enrollment always uses 65536 KiB and
three passes. RustCrypto supplies Argon2 and constant-time comparison. The
shared KDF accepts an already charged lease; explicit work memory and output
use zeroizing owners. An exclusive derivation guard prevents shared references
from admitting simultaneous KDF allocations against one lease, and remains held
through erasure. Native enrollment/trial require a unique mutable lease borrow
for the entire operation. This primitive also derives TPM authorization without
constructing a software verifier.

TPM payloads use `LPT1`, schema version 1, Argon2 version 0x13, algorithm ID 1,
then the duplicated envelope account/generation, bounded KDF fields, 16-byte
salt, canonical marshaled parent public area and its 34-byte Name, canonical
object public area and its 34-byte Name, and opaque private blob. Integer
fields are big-endian; each variable blob has a two-byte length. Public areas
are capped at 1024 bytes each, private data at the pinned TPM type limit, and
trailing bytes are forbidden. Account/generation duplication detects envelope
rebinding. Recomputed Names, exact templates and native loaded identities must
all agree. No plaintext PIN, derived authorization, unsealed data or independent
comparison hash is persisted. The protected record is the authority; these
checks do not authenticate an attacker-controlled transport or replace storage
trust.

Use ADR 0002's exact RSA parent and keyed-hash object templates. Check the owner
hierarchy's `ownerAuthSet` property before attempting empty-owner authorization;
unsupported nonempty hierarchy authorization is unavailable. Use fresh salted
HMAC sessions with AES-128-CFB, protect create input/output and unseal output,
and inspect the shared DA budget immediately before candidate authorization.
Read dynamic properties through uncached bounded capability queries; the
wrapper's convenience property getter retains stale values for a context.
Unknown, inconsistent, locked or insufficient budget refuses the operation.
Other clients can race this observation; it is not a hardware reservation.

`NativeOperation` selects an explicit `/dev/tpmrm0` transport, or an explicitly
opted-in localhost simulator transport, and creates a new context only within
one operation. A verifier consumes that token even on failure. Successful native
work explicitly flushes its own object/session/parent handles and checks the
results; context Drop is only fallback cleanup. Unsealed output must be exactly
32 bytes and is dropped immediately. Never reuse contexts, sessions or matches
as caches, and never globally flush other clients' handles.

## Boundaries and compatibility

The new backend formats do not make M2's development account schema permanent.
Unmanaged accounts still fail closed. Synthetic M3 credentials remain valid
storage fixtures but are rejected by actual backend parsers. Tests cover strict
round trips, malformed records, invocation bindings and durable finalization.
Unknown schema/algorithm/version and unsupported values fail unavailable; there
is no automatic migration or backend downgrade.

Native functions can block, including during cleanup. These are worker
primitives, not a broker-facing executor. ADR 0004 and M5 must provide supervised
process deadlines, bounded process slots, late-result rejection and retention
of jobs/leases until workers are reaped. One-operation ownership bounds context
reuse; it does not establish a wall-clock deadline. Actual resource-manager,
suspend/hardware and independent specialist review remain explicit gates.
