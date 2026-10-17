# M4 credential backend implementation

- Date: 2026-10-17.
- Scope: local backend implementation and isolated tests; no production activation.
- Code: `localpin-credentials`, `localpin-tpm`, and real-backend M3 tests.
- Separate review: [M4 review and corrections](m4-review.md).
- Decisions: [ADR 0002](../adr/0002-tpm-construction.md),
  [ADR 0004](../adr/0004-native-worker-deadlines.md),
  [ADR 0009](../adr/0009-bounded-credential-payloads.md).

## Delivered behavior

The software backend creates Argon2id-v19 PHC credentials with 64 MiB, three
passes, one lane, 16-byte OS-random salt and 32-byte output. It validates the
whole canonical PHC algorithm/version, cost fields, salt/output and length
before work admission or derivation. Accepted version-1 costs remain bounded
by M2's 64–256 MiB, 3–6 passes and one lane. Enrollment aborts on entropy errors,
including partial-fill failure. A maintained constant-time equality operation
compares the derived verifier.

The shared derivation requires an existing exact charged work lease. Enrollment,
verification and TPM PIN derivation all use the same `ResourceBudget`; a full
256 MiB budget or already occupied UID refuses immediately. Argon2's explicit
work-memory API avoids a hidden uncharged allocation. Exclusive derivation
guards reject concurrent allocations against one shared lease, and native
enrollment/trial hold a unique lease borrow through context cleanup.
The work vector, output,
PHC construction scratch and parsed verifier have zeroizing owners. The public
derived-key owner redacts Debug and exposes bytes only explicitly. Caller-owned
inputs, compiler moves, native copies, swap and dumps are outside this erasure
claim.

The TPM backend uses `tss-esapi 7.7.0` with matching TPM2-TSS 4.x libraries.
It recreates ADR 0002's transient owner RSA-2048 primary, validates its template
and public identity, and creates/loads a PIN-authorized keyed-hash sealed-data
object with exact attributes `0x52` and no policy digest. Parent attributes are
exactly `0x30072`. Names are recomputed over canonical TPM public areas and
compared with the protected generation record and native ReadPublic response.
Nonempty owner hierarchy authorization is explicitly unsupported and detected
before trying empty authorization. No persistent handles or NV indexes are used.

Each native operation uses a fresh context and salted unbound HMAC session with
SHA-256 and AES-128-CFB. Create protects both parameters; Unseal protects the
response without requesting nonexistent command-parameter decryption. Unseal
must return exactly 32 bytes, which are dropped immediately. No unsealed data,
authorization verifier, comparison hash or successful session is cached or
persisted. Only the exact TPM auth-failure response is a mismatch; transport,
policy, lockout, metadata and other errors are unavailable. Successful paths
explicitly flush their own handles and check cleanup errors.

The shared DA counter, maximum and permanent flags are read immediately before
candidate authorization through uncached, bounded capability queries. Unknown,
inconsistent or locked state refuses, and the
observed remaining count must exceed a reserve of at least two. Other clients
can change that count between observation and command; this remains a shared
hardware race. Ordinary backend code never resets counters, changes DA policy,
changes hierarchy authorization or clears a TPM.

Both verifiers consume M2's owned `VerificationJob`, validate the exact protected
account incarnation/generation/backend/parameters, and retain its reservation
and work lease through the operation. Their completion grants no response until
M3 durably commits it while checking the current account and generation. Backend
selection remains pinned; errors cannot select software automatically.

## Reproduction and evidence

Use the pinned compiler and lockfile. Native builds need `pkg-config` and
TPM2-TSS 4.x development packages; the simulator suites additionally need
`swtpm` and `tpm2-tools`:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-features --locked
cargo build --workspace --all-features --release --locked
python3 crates/localpin-tpm/tests/run_simulator.py
cargo test -p localpin-storage --features tpm-simulator-tests --locked -- --ignored
cargo run -p localpin-credentials --example benchmark --release --locked -- 20
cargo deny --locked check advisories bans licenses sources
```

Ordinary tests do not open any TPM transport. Explicit ignored suites start
owned localhost simulators with private temporary state and watchdogs. Fixture
commands use their generated TCTI and may configure only those simulators.
No real TPM, host account, PAM configuration or production credential was used.
The syscall sandbox may refuse socket creation; approved execution outside that
sandbox still uses only disposable simulator endpoints.

Local validation passed with the final code:

| Check | Observed result |
| --- | --- |
| Formatting, diff whitespace and all-target/all-feature Clippy | Passed, warnings denied |
| Workspace tests | 141 unit/integration tests and 4 compile-fail doctests passed |
| Native backend simulator suite | Two tests passed; salted-session wire checks, failure cases and dynamic capability-cache regression; 12.40 s |
| Native backend with real M3 storage | Passed; bounded parent/child fixture, 9.81 s |
| Locked all-feature release build | Passed |
| Advisory, license, duplicate and source policy | Passed |

The ordinary workspace run skips the two explicit native suites and the storage
subprocess entry point (which other storage tests invoke as needed). Those skips
are not counted as passed native tests. The native suites were run separately.

Software vectors were independently generated with libargon2 20190702 through
its Argon2id-v19 C API, including a leading-zero PIN and a second salt/PIN. Strict
parser tests cover malformed/unknown/duplicate/reordered costs, noncanonical
numbers/Base64, wrong salt/output sizes, version/algorithm changes and excess
work. Binding, entropy-error, resource-admission and diagnostics tests complement
the KDF vectors.

Actual M3 software tests cover persisted staged trial verification, mismatch and
success, reservation-write failure preventing verifier invocation, successful
KDF followed by completion-write failure refusing authorization, failed trial
preserving the previous generation, and real matching completions rejected
after rotation or disable. Synthetic lifecycle authority is used throughout.
The optional native storage test covers staged enrollment, success/mismatch,
reservation/completion directory-sync failures and the disable fence with
actual protected TPM Unseal results. Failed trial and rotation have real software
coverage; the native storage scenario does not repeat those cases.

Local release timing on an AMD Ryzen 9 7945HX, Fedora 44 x86_64, Rust 1.99.1,
20 serial synthetic derivations (including allocation and erasure): minimum
85.52 ms, median 88.63 ms, p95 91.37 ms, maximum 91.44 ms. This host is faster than
the specification's illustrative 100–500 ms target. The fixed enrollment policy
was preserved; supported-hardware and end-to-end locker measurements are still
required before changing a versioned cryptographic policy.

The [dependency review](dependencies.md#m4-credential-backend-dependencies)
records exact native inputs, graph/license exceptions and the passing RustSec,
license, source and duplicate policy checks. Hosted CI is configured to compile
native dependencies and run both isolated simulator suites; a hosted successful
run has not been claimed.

## Remaining gates

These are native worker primitives. One-operation ownership bounds context
reuse and flushes owned resources; it does not impose a wall-clock deadline on
TPM2-TSS or its cleanup. M5 must run them in supervised short-lived processes,
limit process slots, reject late results, and keep job/UID/KDF capacity charged
until actual reaping, even after returning unavailable. No production broker
exists, so these blocking functions have not been exposed to authentication.

The maintained Rust wrapper owns zeroizing `Auth`/`SensitiveData` buffers, but
its create path also copies into C stack structures and its unseal path copies
from an ESAPI allocation. Erasure of every native copy is not established.
M5's worker exit, dump restrictions and process hardening plus native dependency
review remain necessary. Memory locking has not yet been implemented; its
process-level policy and limits belong to that worker boundary.

The physical `/dev/tpmrm0` connection, permitted hardware hierarchy, firmware,
transport trust, real resource manager, suspend/resume, abrupt power loss and
hardware performance/coexistence remain unverified. Fresh-context simulator
operations demonstrate reconstruction, not real suspend certification. Independent
TPM-focused review is still required before treating the construction as fixed
for release. M4's physical resource-manager evidence item therefore remains open.
Permanent accounts remain blocked on ADR 0006's enforcing lifecycle authority.
There is no PAM adapter, enrollment CLI, installable package or supported release.
