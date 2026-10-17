# Separate M4 code review

Date: 2026-10-17. Scope: the complete uncommitted M4 change, including new
sources, storage integration tests, native simulator harnesses, manifests,
lockfile, dependency policy, CI and documentation.

Three fresh-context review agents examined native TPM behavior, software/core
cryptography and resource contracts, and storage/CI/dependency integration.
None authored the implementation. The implementing agent also reviewed the
findings and made the corrections. This is separate AI-assisted development
review, not the independent human/TPM specialist review required for release.
No host authentication state or physical TPM was used.

## Findings and corrections

### Cached dynamic TPM properties (P2)

The pinned wrapper's `Context::get_tpm_property` caches the requested property
and neighboring values for the context's lifetime. Parent bootstrap first read
`Permanent`; final DA preflight then reused the cached lockout flag. A lockout
that cleared during bootstrap could therefore still be reported as active,
refusing an otherwise usable PIN and consuming its already reserved software
attempt. Counter/maximum values were fresh on the production path, so review
found no PIN bypass or demonstrated reserve violation from this issue.

Correction: read each exact dynamic property using direct bounded
`GetCapability(TpmProperties, tag, 1)`, without the wrapper cache. Validate the
response type/count and exact tag; missing or malformed data fails closed.
Both hierarchy preflight and final DA inspection use the fresh-read helper.
The shared-budget observation remains non-atomic with respect to other clients.

An owned-simulator regression primes the wrapper caches, changes maximum
failures, increments the counter, reaches lockout and then clears lockout on
that simulator. It checks that the same contexts observe fresh maximum,
counter and lockout/recovery values. The original reviewer re-read the fix and
regression and found the P2 resolved.

### Watchdog cleanup and coverage wording

The outer simulator runner had an unbounded wait for its direct Cargo child
after SIGKILL. That wait now has its own two-second bound. Termination can still
be delayed by kernel I/O; the fixture does not establish production worker
reaping or retention of occupied slots. Documentation distinguishes bounded
waiting for the direct child from comprehensive descendant-reaping guarantees.

The native storage coverage description now lists its actual enrollment,
success/mismatch, directory-sync-failure and disable cases. Failed trial and
rotation have real software coverage; the native storage scenario does not
repeat them.

## Review outcome and limits

The software/core reviewer found no actionable defect and independently passed
all 11 credential tests. Review included canonical PHC parsing, bounded Argon2
work memory, equal-length constant-time comparison, entropy failure, record/job
binding, zeroizing owners and retention of the derivation guard through erasure.

The integration reviewer found no actionable P1/P2 defect and independently
passed the four real software/storage tests. Default storage dependencies remain
free of native TPM libraries; all-feature duplicate versions match the narrow
policy exception. Durable reservation/finalization and revocation fences remain
composed with actual backend results.

After correction, the native reviewer found no remaining actionable defect in
its assigned scope. Session construction, public Names/templates, exact auth
failure classification, record bounds and explicit owned-handle cleanup were
checked against the pinned wrapper's source. Native response-HMAC corruption
and explicit cleanup-failure injection are not exercised; these are additional
native/security validation work, not claimed by the passing success-path tests.

The [M4 evidence report](m4-credential-backends.md) records final validation.
Physical resource-manager/hardware use, real suspend behavior, M5 supervised
worker deadlines and native-copy erasure remain open. This review does not
certify production readiness or replace specialist review.
