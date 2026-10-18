# Flexible credential validation

Date: 2026-10-18. Contract: [ADR 0021](../adr/0021-flexible-credentials.md),
[specification 1.8](../product-specification.md).

## Change and evidence boundary

The source change supports TPM numeric PINs of 4–16 digits, software numeric
PINs of 8–16 digits and optional 8–64 printable-ASCII passcodes. It adds shared
terminal preparation, explicit credential profiles, envelope 2, IPC 2, status
schema 2 and profile/generation fencing. Legacy six-digit software credentials
remain usable and supported upgrades preserve their serialized bytes.

This is a current source-validation record. Historical
[M8.1](m8.1-desktop-compatibility.md), [M8.2](m8.2-installed-acceptance.md) and
[M8.3](m8.3-accounting-maintenance.md) installed observations retain their exact
build scope; they do not validate flexible credentials. No physical-hardware or
independent-review completion is claimed. Hosted CI is separate from local
checks and is reported only with a run for the tested candidate.

## Local source validation

| Check | Result and scope |
| --- | --- |
| `cargo test -p localpin-core --locked` | Passed: 66 unit tests, 8 integration tests and 4 compile-fail doctests. Includes length/type/backend boundaries, exact ASCII/space preservation, advisory warnings, v1/v2 record canonicalization and allocation limits. |
| `cargo test -p localpin-credentials --locked` | Passed: 12 tests, including software enrollment/reopened-envelope-2 verification of 8/16-digit PINs, exact spaced ASCII, and 64-character/64-digit passcodes. Changed-last-byte and trimmed-space candidates fail real KDF verification. |
| TPM simulator flexible-credential test | Passed: `cargo test -p localpin-tpm --features simulator --locked flexible_credentials_authorize_exact_bytes_with_version_two_metadata -- --ignored` ran one owned simulator test covering TPM PINs at 4/16 digits, spaced ASCII and 64-character passcodes, exact v2 metadata, successful verification and two real mismatches. |
| `cargo clippy -p localpin-core -p localpin-credentials -p localpin-tpm --all-targets --all-features --locked -- -D warnings` | Passed using an isolated temporary SDK extracted from matching TPM2-TSS development RPMs. No host package installation. |
| Formatting, links and whitespace | `cargo fmt --all -- --check`, `git diff --check` and a check of 233 relative links across 17 changed Markdown files passed. |
| `cargo test --workspace --all-features --locked` | Passed: 393 tests across 34 suites; 11 opt-in/fixture entries ignored by the ordinary run. Native and simulator runs below are separate. |
| `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings` | Passed using the isolated SDK. |
| Native production PAM namespace harness | Passed with the real release module and Linux-PAM: exact-byte fallback, flexible profiles, spaces, numeric-looking passcodes, mixed versions, enrolled-but-unreadable status without a verification attempt, native `pam_unix`/`pam_faillock`, and unchanged counters on LocalPIN success. Headers came from the matching Fedora development RPM extracted under `/tmp`. |
| Protected broker namespace | Passed: actual socket, protected storage, workers and durable revocation in an isolated mapped-UID namespace. |
| Enrollment broker namespace | Passed: full lifecycle, legacy software use, compliant rotation, passcodes, profile/generation fencing, unchanged attempts on profile rejection, and corrupt-record status. |
| Complete TPM simulator runner | Passed: three simulator tests, including the new flexible-credential test. Expected mismatch/transport-error diagnostics occurred in negative cases. |
| Storage simulator opt-in run | Passed: durable native TPM backend/revocation scenario and its subprocess fixture entry. |
| Python tools/setup/packaging | Passed: 141 tools tests, 21 M8 fixture tests, 14 M8.2 fixture tests, 16 M8.3 fixture tests and 86 Fedora packaging/release tests. |
| Fuzz support | Locked metadata, all-target compilation/Clippy/formatting and seed generation passed; seven record, 41 stream and two PHC seeds generated under `/tmp`. This is not a coverage-guided fuzz campaign. |
| `cargo build --workspace --all-features --release --locked -j 2` | Passed using the temporary native SDK. |
| Production release/RPM build | Passed without host installation. Candidate `localpin-0.1.0-0.1.alpha1.vm84.1.fc44.x86_64.rpm`; SHA256 `4f3294de165d516661a2b9e5ac61ebf17757be1468f6fb3273893f3755214268`. Includes ADR 0021. |

The simulator test initially could not bind localhost inside the sandbox. An
explicitly authorized run outside that restriction used only its owned temporary
simulator. Its first run then reached the default simulator safety reserve after
a deliberate mismatch; the fixture was corrected to configure eight attempts
and 24-hour recovery on that disposable simulator before enrollment. The rerun
passed and retained two mismatches in its shared counter. This changes no host
or production TPM policy and does not reset a test counter to advance a run.

The ordinary host lacks TPM/PAM development headers. Matching Fedora development
RPMs were downloaded and unpacked into a temporary SDK; the installed native
runtime libraries supplied execution. No development package was installed on
the host. Initial sandbox IPC/process restrictions were resolved by explicitly
approved runs of synthetic tests outside that restriction. `cargo-deny` is not
installed, so a fresh dependency-advisory run is unavailable; this change adds no
dependency or lockfile changes.

Additional code review caught two regressions before delivery: the offline
checker could create a missing integration lock, and corrupt credential state
could make status encoding fail instead of reporting enrolled-but-unavailable.
Both have targeted regression coverage; the checker uses existing-only locks,
and only unavailable status permits a known backend with an unknown profile.
One enrollment namespace run reached the unchanged two-second software deadline
while the release build and full suite were running concurrently. Its serialized
rerun passed in 41.11 seconds; no production deadline was relaxed.
This assisted review does not satisfy M9's independent human/specialist gate.

All fixtures use synthetic credentials. Native tests use isolated policies or
owned disposable TPM simulators, never the everyday machine's PAM configuration,
credential state or physical TPM failure allowance.

## Required installed and release follow-up

Use disposable Fedora KDE 44 x86_64 with SELinux enforcing and private TPM
emulators. Record the exact source/RPM digest, guest environment, commands,
observations and retained failures for each case:

- Fresh numeric/passcode enrollment for each backend, changing type and both
  migration directions, including exact spaces and maximum-length input.
- Stock lock-screen Enter submission, matching-profile and other account-password
  fallback, real wrong candidates, cooldowns, native lockout/counters and TPM
  safety reserves. No counter resets to advance a test.
- Legacy envelope-1 software and TPM verification, byte-preserving compatible
  RPM update, replacement advice and compliant replacement. Refused downgrade,
  mixed component versions, malformed records and package-resume refusal keep
  the gate closed and preserve password recovery.
- Cancellation, deadline/terminal restoration, interrupted commit/restart,
  generation/profile races, unavailable TPM/broker, console recovery, activation
  and reboot behavior with the final enrollment.

Installed acceptance remains outstanding until corresponding evidence is
recorded. Physical TPM/sensor validation and M9 independent human/specialist
review remain open even after source and VM checks pass.
