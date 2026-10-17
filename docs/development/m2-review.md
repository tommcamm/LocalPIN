# Separate M2 code review

Date: 2026-10-17. Scope: the entire M2 change, including previously untracked
sources, tests, manifests, lockfile, specification amendments and ADRs.

Three fresh-context review agents examined core state machines, protocol and
composition, and foundation/resource/secret/record contracts. They had not
authored the initial implementation. The implementing agent also inspected the
findings and coordinated corrections. This is separate AI-assisted development
review, not the independent human/specialist security review required by M9.
No actual platform authentication or host configuration was used for review.

## Findings

### Reusable backend invocation capabilities

The initial `CredentialVerifier::verify` accepted shared references to a durable
reservation and work permit. A public-API reproduction submitted ten different
synthetic PIN candidates under one reserved attempt and one memory charge, then
completed only once. The same work permit could also be shared across concurrent
calls. The existing protocol did not do this, but the model API failed to encode
its claimed one-invocation contract and could let a future adapter bypass guess
and memory limits.

Correction: transfer the reservation, work permit, PIN and validated backend/KDF
binding into an owned, non-cloneable verification job. The verifier consumes the
job and returns an opaque completion. Its result retains the charged work lease
until it is consumed after actual work/cleanup. Compile-fail ownership examples
and runtime admission/completion regressions cover the boundary. A real backend
still must perform exactly that job and a native supervisor must retain capacity
until worker exit/reaping; M2 implements no native supervisor.

### Shortened cooldown accepted after recovery

The initial throttle codec could validate a deadline against the fifth attempt
while recent timestamps existed. After reboot recovery or same-boot pruning
cleared those timestamps, validation only bounded the maximum remaining duration.
A reproduction flipped one encoded deadline bit after reboot recovery, changing
300000 ms to 37856 ms; decoding/loading accepted it and allowed a guess early.

Correction: retain the cooldown's start as well as its deadline. Validate the
exact checked 300000 ms interval even when no recent timestamps remain, and
preserve the origin during same-boot recovery. A new boot creates a new origin.
Canonical encoding rejects inconsistent optional fields, future origins and
shortened/extended intervals. Regression tests mutate recovered/pruned records
and exercise ordinary expiry, overflow and repeated recovery.
The development version 1 throttle envelope is now a fixed 150 bytes. No
production records exist; earlier 141-byte model envelopes are rejected by the
exact-size parser.

This is structural validation, not authenticated storage or protection from a
privileged attacker coherently replacing an entire record. M3 still owns trusted
filesystem access, atomic durable replacement and corruption/fault recovery.

## Follow-up verification

A reviewer who authored neither correction re-read both fixes and found no
remaining actionable defects. All four compile-fail examples were separately
compiled and rejected for the intended ownership errors (`E0382`/`E0507`), rather
than missing imports or invalid APIs. A public-API unwind reproduction also
retained the consumed pending reservation. This does not demonstrate cleanup of
a real native worker, which remains an adapter obligation.

Final validation passed: 81 runtime tests, 4 ownership compile-fail doctests,
formatting, Clippy with warnings denied, locked release build, dependency
advisory/license/source/ban checks with refreshed data, and whitespace checks.
Commands and counts are in the [M2 evidence report](m2-policy-contracts.md).
The protocol review found no additional actionable defects. The complete change
remains a pure model/parser milestone; actual filesystem, kernel-peer,
lifecycle, PAM/TPM and release-security gates remain open.
