# Separate M5 code review

Date: 2026-10-17. Scope: the complete uncommitted M5 broker, worker, Linux
transport/client and session adapter, tests, manifests, deployment contracts,
dependency policy and documentation.

Three fresh-context review agents examined broker authorization/persistence,
worker supervision, and transport/platform identity. None authored the initial
implementation. The implementing agent reviewed their findings and corrected
the broker integration; reviewers added regressions and the shared clock fix.
This is separate AI-assisted development review, not the independent human or
platform/security specialist review required before release. No host
authentication or physical TPM state was changed.

## Findings and corrections

### Request deadlines renewed after live checks (P2)

The broker created an ordinary request deadline before reading a frame and
checking eligibility, then renewed its two/five-second budget before invoking
the engine. A delayed session check therefore extended the absolute request
budget. The reviewer reproduced the issue with a delayed trusted checker and
a socket regression: the deadline supplied to verification was later than the
one supplied to the same request's eligibility check.

Correction: retain the original ordinary deadline, derive the TPM extension
from it and cap both by the existing connection lifetime. Select the protected
credential backend before creating the engine's eligibility adapter, so software
checks cannot inherit the TPM extension. The engine passes its selected absolute
deadline through the response callback, and socket delivery enforces that bound.
Cancellation during the later part of a TPM attempt uses its remaining TPM
budget to parse the queued cancel, without renewing either operation.

The initial regression failed before the correction. Four broker regressions
now cover the unchanged eligibility/verification deadline, connection-lifetime
cap, refusal of an expired delivery callback and late TPM cancellation. The
broker reviewer re-read the final code and passed all 15 broker tests.

### Suspend paused transport and backend budgets (P2)

The new IPC/supervisor code used `std::time::Instant`. On Linux that clock
excludes suspend, so a request could retain its remaining timeout after a long
suspend. Core `BootClock` separately prevented stale verification grants, but
the client fallback and server/resource deadlines did not meet the agreed
suspend-inclusive contract. A relative socket poll timeout would have retained
the same problem even after changing the elapsed-time comparisons.

Correction: share `BootInstant`, backed by `CLOCK_BOOTTIME`, across Linux
transport, broker connection/request lifetimes, worker supervision and session
queries. Socket waits poll an absolute `CLOCK_BOOTTIME` timerfd alongside the
socket, so a silent peer cannot keep the client waiting for the pre-suspend
remaining awake-time interval after resume. Timer/deadline expiry wins over
simultaneous socket readiness. New descriptors are close-on-exec and have scoped
ownership. No wall-clock time or new dependency was introduced.

Deterministic clock-adapter regressions advance only boot time and exercise the
250-ms, two-second, five-second and 15-second limits, exact expiry, overflow and
clock-scope cleanup. A native silent-socket test confirms timerfd wakeup. The
transport reviewer passed all 23 transport/time tests and strict protocol
Clippy. Actual machine suspend was not performed.

### Namespace artifact selection

The implementing agent also found that the opt-in runner hardcoded
`target/debug/localpin-worker`, while Cargo permits target/target-directory
overrides. This could select an older default-tree helper or fail despite a
successful overridden build. Both test and helper paths now come from Cargo's
structured artifact messages. The protected namespace suite is rerun with an
explicit `CARGO_BUILD_TARGET` override to exercise this selection.

## Review outcome and limits

No remaining actionable defect was found in the reviewed UID targeting,
connection/challenge binding, socket trust/activation, ancillary rejection,
peer-pidfd identity, logind routing, durable reservation/completion, revocation
serialization, root-only recovery or worker outcome/capacity paths.

The worker reviewer independently passed all ten native worker tests and both
actual-helper tests. It checked secret ownership, bounded private IPC, exact
outcome correlation, successful-exit requirements, SIGKILL before reaping the
PID-pinned leader, and retention of UID/memory/process leases through group
cleanup. Process-group escape prevention, installed cgroup/SELinux confinement,
physical TPM/native memory review and production account adapters retain their
documented later gates. Native filesystem and D-Bus connection/authentication
stalls remain occupied, fail-closed work; the client independently bounds fallback.

Final validation passed 205 workspace tests, the separate protected namespace
suite with a Cargo target override (8.13 seconds), formatting, all-target/
all-feature Clippy with warnings denied, a locked release build and the
dependency audit. Six explicit opt-in/helper entries remain ignored in the
ordinary workspace run. The final cancellation deadline clamp passed all 15
broker regressions. Further details are in the [M5 report](m5-bounded-broker.md). This
review does not certify production readiness or substitute for specialist review.
