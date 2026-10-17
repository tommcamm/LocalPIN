# M1 feasibility report

Date: 2026-10-16. Branch: `codex/m1-feasibility`.

**Status: enforcing-VM feasibility experiments delivered; M1 exit gate remains
open for two real desktops of one UID and actual second-seat coverage.** The maintainer supplied a disposable
Fedora 44 KDE VM with an ordinary test account and a clean snapshot. Actual
lock-screen, real-account and confined-worker results are now available. The
everyday host's authentication configuration and real TPM were not changed.

## Delivered evidence and its limits

| Area | Evidence | Remaining gate |
| --- | --- | --- |
| PAM | 30 private assertions; five namespace-private `pam_unix` assertions; twelve default-profile and sixteen `with-faillock` real-account cases; six/nine password-free experimental eligibility cases under enforcing SELinux | Complete explicit password-free eligibility, required-check preservation, supported-profile and account-change race implementation |
| Packaged locker | Matching Fedora source/build inspection identifies `kde` and auth-only behavior; actual stock KDE one-entry six-digit/ordinary password, wrong-then-correct, missing-adapter, reachable-broker and DAC-denied-broker fallback passed | Production PIN-success path, account restrictions and complete failure/latency matrix |
| TPM | Disposable swtpm object authorization, exact template/Name checks, protected sessions, parent recreation, rejection on another TPM, DA budget/races and stopped-transport timeout | Production tss-esapi/resource-manager integration, real-hardware lifecycle and specialist review |
| Platform | Complete guest PAM graph; actual user-manager locker identity; corrected user-unit discovery; 20 synthetic regressions; five real logind metadata cases; two genuine different-UID KDE desktops on seat0; enforcing broker/client MAC/DAC controls | Two real desktops for one UID, an actual second seat, and complete production caller/eligibility contract |
| Native worker | Six deadline/capacity tests; eight enforcing real-password/helper/account cases in a separate own-UID worker; no direct shadow-read or password-update SELinux grant | Production privileged grant binding, supported profiles, durable storage and IPC |
| CI | Fedora container job runs isolated suites plus safe VM-source compilation and guard tests | Hosted execution result; guest mutations never run in CI |

Detailed commands, versions, source digests and outcomes belong in the
[PAM report](m1-pam.md), [TPM report](m1-tpm.md), and
[platform report](m1-platform.md), with separate [real-account](m1-vm-pam.md),
[KDE UI](m1-vm-kde.md), [actual broker contact](m1-vm-kde-contact.md),
[password-free eligibility](m1-vm-eligibility.md), [sessions](m1-vm-sessions.md),
and [SELinux/worker](m1-vm-selinux.md) reports. Reviewed
JSON is in [VM results](../../experiments/m1/vm/results/README.md). Run the tools using
[experiments/m1/README.md](../../experiments/m1/README.md).

The PAM permit baseline fails inside Codex's restricted syscall sandbox, as
anticipated in specification section 18. A scoped run of the private harness
outside that sandbox passes its baselines and assertions. The simulator also
requires Unix sockets unavailable inside that sandbox. These environmental
failures are recorded separately from test assertions.

## Architecture consequences

- [ADR 0001](../adr/0001-pam-candidate-and-account-policy.md): preserve candidate
  bytes through Linux-PAM's token API, acquire a new candidate for every
  authentication, and add explicit account eligibility before PIN success.
  Real-account tests demonstrate that password locks and active faillock can be
  bypassed by naive fixture success. Account management alone is insufficient
  and can reset failure counters; it is not the selected eligibility shortcut.
  The bounded root-private preflight preserves required checks and explicit
  preauth without that resetting account hook; production implementation still
  requires broader hash/policy support and confinement.
- [ADR 0002](../adr/0002-tpm-construction.md): select the tested sealed-object
  construction as the candidate for M4, with exact public identity/metadata
  checks, protected sessions and the shared-DA reserve limitation. Another TPM
  client's activity can invalidate a budget observation.
- [ADR 0003](../adr/0003-session-and-worker-boundaries.md): use kernel peer
  identity plus logind discovery, refuse ambiguous unsupported cases, and retain
  the documented same-UID impersonation limit. UID reuse still requires a
  demonstrable lifecycle mechanism; ordinary account fields are insufficient.
- [ADR 0004](../adr/0004-native-worker-deadlines.md): isolate native calls in
  bounded processes, fence expired results, preserve reservations and keep
  occupied capacity charged until cleanup actually completes.

Specification 1.1 makes the candidate-shape accounting in ADR 0001 explicit:
six-digit account passwords can consume a PIN attempt before fallback, and
wrong PIN candidates can affect the original password failure counters. No
counter bypass is introduced. The exact fifth-attempt boundary remains M2 work.
The experimental eligibility route left active faillock bytes/metadata unchanged
and a separate correct-password attempt was still denied; fixture cleanup reset counters afterward, separately.

No product requirement is waived by these experiments. Production support for
UID reuse, reboot throttling, revocation races, failure accounting and activation
authority must be made explicit in M2/M3/M5/M6 as assigned by the roadmap and
ADRs. Actual Fedora same-entry fallback and the bounded enforcing password worker
now have positive evidence. Those results do not certify the complete desktop
design or waive the remaining account/session and production integration gates.

## Local repository checks

Rust formatting, Clippy with warnings denied, locked offline tests/release build,
and cached dependency advisory/license/source/bans checks pass. The Rust library
still contains no authentication behavior and no third-party dependencies.
Workflow YAML and shell blocks parse, and action pins/read-only permissions are
retained. Final local runs pass 30 synthetic PAM assertions, five packaged
`pam_unix` assertions, 20 platform tests, six worker tests, and the full TPM
simulator suite. The final simulator results match the sanitized reference
assertions, with native timeout cleanup measured at 0.501 seconds.
New local source checks additionally pass 13 SELinux fixture tests, five
positive-worker tests, five contact-hold tests, six session-fixture tests and
four eligibility guard tests, plus strict C compilation and pure hash-format
checks. Seven fixed-contact namespace cases passed, including the stalled
reply deadline. No successful GitHub-hosted M1 run is claimed.

## Remaining M1 gate

The bounded session/contact/eligibility experiments are complete. Two genuine
KDE/Wayland desktops for different UIDs ran together on seat0, and the inactive
locked test desktop remained its UID's sole candidate while the foreign active
management desktop was excluded. The actual greeter again had no direct session
and matched its user-manager UID.

Two real KDE desktops for the same UID and an actual second independent seat
remain untested. The [multiple-seat gap report](m1-multiseat-gap.md) records the
current one-GPU/SPICE limitation and exact packaged login-manager source findings;
it does not claim a second-seat runtime failure was reproduced. Another display
head or root-declared metadata does not close these gates. A dedicated routed
second-seat VM configuration and genuine desktop/locker interactions remain
required. M1 is not marked complete and these requirements are not waived.

Production eligibility, complete required-policy preservation, UID lifecycle,
peer/process races, grant binding and the full integration/fault matrix retain
their M2–M8 implementation/release gates. The SHA512-only administrative-domain
eligibility fixture is evidence for a direction, not a deployable worker.

## Next work: M2 foundations

Sequencing reviewed on 2026-10-17: the completed feasibility evidence supports
starting pure M2 policy models, reservation/generation/clock state machines,
resource bounds and bounded protocol tests using simulated dependencies. M1
remains open and platform-facing contracts remain provisional. M2 must resolve
the fifth-attempt boundary, reboot throttling, revocation fences and account
lifecycle before the relevant contracts and persistent records are stabilized.
UID/name/home equality does not solve account reuse. The
[roadmap](../implementation-plan.md) records this overlap; no further VM input
is needed from the maintainer for that initial M2 work.

## Recovery completed

The [final cleanup record](../../experiments/m1/vm/results/2026-10-16-cleanup.json)
confirms exact account restoration in the account/UI reports, original PAM graph
and authselect profile verification, removal of fixture modules/units/paths,
explicit temporary guest-key removal, and whole-VM clean-snapshot restoration.
The VM restarted and its guest agent responded; the local temporary key pair was
deleted. SELinux was checked Enforcing before rollback; its post-restore mode was
not independently queried. Per-run reports keep their historical pre-snapshot
flags and are interpreted alongside this separate final record. The everyday
host's authentication setup and real TPM were not changed.
