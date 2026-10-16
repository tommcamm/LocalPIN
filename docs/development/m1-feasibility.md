# M1 feasibility report

Date: 2026-10-16. Branch: `codex/m1-feasibility`.

**Status: isolated experiments implemented; M1 exit gate remains open.** No
disposable Fedora KDE VM with SELinux enforcing is available yet. The maintainer
confirmed this and requested [VM setup steps](m1-vm-setup.md). The current host's
authentication configuration and real TPM were not changed.

## Delivered evidence and its limits

| Area | Evidence | Remaining gate |
| --- | --- | --- |
| PAM | 30 private `pam_start_confdir` assertions with known permit/deny baselines; five optional real `pam_unix` assertions with correct/wrong baselines and namespace-private synthetic accounts; candidate bytes, six-digit fallback and repeated handles | Real KDE conversation and the complete supported Fedora password/account/failure-counter policy in an enforcing VM |
| Packaged locker | Matching Fedora source RPM and installed-binary metadata inspection identify `kde` and authentication/credential-refresh calls without account management | Runtime tests of the actual installed VM build, supported authselect profiles and account restrictions |
| TPM | Disposable swtpm object authorization, exact template/Name checks, protected sessions, parent recreation, rejection on another TPM, DA budget/races and stopped-transport timeout | Production tss-esapi/resource-manager integration, real-hardware lifecycle and specialist review |
| Platform | Read-only PAM graph with digests and sanitized versions/session metadata; synthetic graph/session discovery regression tests | Actual multiple graphical sessions/seats, user-manager locker identity and enforcing SELinux broker/password-worker policy |
| Native worker | Six tests of blocked native calls, deadline/result fencing, reserve-before-spawn marker, reaping and bounded capacity | Production asynchronous cleanup, durable storage, privileges/sandbox and IPC |
| CI | Fedora container job runs the isolated suites | Hosted execution result; containers do not establish desktop or enforcing-SELinux compatibility |

Detailed commands, versions, source digests and outcomes belong in the
[PAM report](m1-pam.md), [TPM report](m1-tpm.md), and
[platform report](m1-platform.md). Run the tools using
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
  Synthetic modules cannot prove Fedora account/failure-counter behavior.
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

No product requirement is waived by these experiments. Production support for
UID reuse, reboot throttling, revocation races, failure accounting and activation
authority must be made explicit in M2/M3/M5/M6 as assigned by the roadmap and
ADRs. In particular, actual Fedora same-entry fallback and enforcing password
worker checks remain prerequisites for treating the desktop design as proven.

## Local repository checks

Rust formatting, Clippy with warnings denied, locked offline tests/release build,
and cached dependency advisory/license/source/bans checks pass. The Rust library
still contains no authentication behavior and no third-party dependencies.
Workflow YAML and shell blocks parse, and action pins/read-only permissions are
retained. Final local runs pass 30 synthetic PAM assertions, five packaged
`pam_unix` assertions, 18 platform tests, six worker tests, and the full TPM
simulator suite. The final simulator results match the sanitized reference
assertions, with native timeout cleanup measured at 0.501 seconds. No successful
GitHub-hosted M1 run is claimed.

## Next required action

Prepare the [Fedora KDE test VM](m1-vm-setup.md), verify SELinux says `Enforcing`,
and report its VM name and available console/SSH access. No password needs to be
sent. Then complete the real password, account/failure-counter, sessions/seats,
SELinux contact/worker and recovery matrix, record observations, and update the
ADRs before closing M1. Keep the everyday `pam_pinlock` setup separate until a
later tested migration milestone.
