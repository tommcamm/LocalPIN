# Flexible credential validation

Date: 2026-10-18. Contract: [ADR 0021](../adr/0021-flexible-credentials.md),
[specification 1.8](../product-specification.md).

## Change and evidence boundary

The source change supports TPM numeric PINs of 4–16 digits, software numeric
PINs of 8–16 digits and optional 8–64 printable-ASCII passcodes. It adds shared
terminal preparation, explicit credential profiles, envelope 2, IPC 2, status
schema 2 and profile/generation fencing. Legacy six-digit software credentials
remain usable and supported upgrades preserve their serialized bytes.

This records current source validation and links the installed candidate's
separate evidence. Historical
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
| Formatting, links and whitespace | `cargo fmt --all -- --check`, `git diff --check`, workflow actionlint and relative Markdown link checks passed. |
| `cargo test --workspace --all-features --locked` | Passed: 393 tests across 34 suites; 11 opt-in/fixture entries ignored by the ordinary run. Native and simulator runs below are separate. |
| `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings` | Passed using the isolated SDK. |
| Native production PAM namespace harness | Passed with the real release module and Linux-PAM: exact-byte fallback, flexible profiles, spaces, numeric-looking passcodes, mixed versions, enrolled-but-unreadable status without a verification attempt, native `pam_unix`/`pam_faillock`, and unchanged counters on LocalPIN success. Headers came from the matching Fedora development RPM extracted under `/tmp`. |
| Protected broker namespace | Passed: actual socket, protected storage, workers and durable revocation in an isolated mapped-UID namespace. |
| Enrollment broker namespace | Passed: full lifecycle, legacy software use, compliant rotation, passcodes, profile/generation fencing, unchanged attempts on profile rejection, and corrupt-record status. |
| Complete TPM simulator runner | Passed: three simulator tests, including the new flexible-credential test. Expected mismatch/transport-error diagnostics occurred in negative cases. |
| Storage simulator opt-in run | Passed: durable native TPM backend/revocation scenario and its subprocess fixture entry. |
| Python tools/setup/packaging | Passed: 141 tools tests, 21 M8 fixture tests, 14 M8.2 fixture tests, 16 M8.3 fixture tests and 86 Fedora packaging/release tests. |
| Flexible installed-fixture source checks | Passed: eleven pure tests for exact printable-ASCII key mapping, bounded input, predictable-candidate generation, strict public-result sanitization, pending-cooldown reporting and direct-use guest guards; Python compilation passed. These checks do not operate a VM. |
| Existing M6.1/M7 fixtures | Python compilation and synthetic schema/flow checks passed. Fresh software inputs use 8–16 digits; wrong candidates and password-overlap cases follow the enrolled profile. Historical result files are unchanged; this is not a new M6.1/M7 VM run. |
| Fuzz support | Locked metadata, all-target compilation/Clippy/formatting and seed generation passed; seven record, 41 stream and two PHC seeds generated under `/tmp`. This is not a coverage-guided fuzz campaign. |
| `cargo build --workspace --all-features --release --locked -j 2` | Passed using the temporary native SDK. |
| Production release/RPM build | Passed without host installation. Candidate `localpin-0.1.0-0.1.alpha1.vm84.1.fc44.x86_64.rpm`; SHA256 `4f3294de165d516661a2b9e5ac61ebf17757be1468f6fb3273893f3755214268`. Includes ADR 0021. Its 118 runtime/build inputs match the committed implementation sources. |

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

## Hosted source CI

[CI run 39106909022](https://github.com/tommcamm/LocalPIN/actions/runs/39106909022)
passed for PR head `91e5011e2518cc5f3d0cb6ff0b6b47f521e96fa8`:
Ubuntu lint/build, dependency policy, isolated Fedora experiments and the Fedora
44 workspace/native/simulator/RPM job. PR workflows test GitHub's merge candidate;
fixture and evidence follow-ups have their own PR checks. The installed RPM was
built locally and has its separately recorded digest.

## Targeted installed acceptance

The [installed report and guarded fixtures](../../experiments/flexible/README.md)
record the exact RPM above in an independent Fedora KDE 44 x86_64 VM with
SELinux enforcing and a private managed TPM emulator. Its original clean VM
remains off; no physical TPM or host PAM policy is used.

Completed observations include:

- A real prior-RPM six-digit software enrollment, stock KDE PIN/password trial,
  and compatible update preserving credential, pointer, throttle and native
  failure bytes/security metadata. The new broker verifies the legacy credential
  and status reports policy zero with replacement advice.
- Actual Konsole menu/change input of a leading-zero ten-digit software PIN,
  observed masking and preparation before one hidden account-password prompt.
  Controlled installed-CLI PTYs also cover software numeric boundaries 8/16.
- Stock KDE Enter-required unlocking with software numeric 8/10, spaced passcode
  16, explicitly selected all-digit passcode 12 and maximum-length passcode 64;
  TPM numeric 4/16 and spaced passcode 16. Exact leading/trailing spaces survive.
  LocalPIN successes preserve native counters and full-password fallback works.
- A matching-profile account password consumes one LocalPIN attempt and still
  unlocks through password fallback. Four subsequent broker-only mismatches
  reach cooldown; another request is refused, and actual KDE password fallback
  works during cooldown. Explicit TPM migration preserves that cooldown and
  verification succeeds after natural expiry, without resetting counters.
- Both explicit backend-migration directions. A real reboot preserves the v2
  TPM credential, registry, pointer, throttle and native failure bytes/security
  metadata before verification. The old boot-bound trial closes; an explicit
  broker start and fresh trial then verify the same credential and actual KDE
  PIN/password paths. This is prepared/trial evidence, not active-boot acceptance.
- Own-user disable and fresh v2 software enrollment, with actual KDE password
  continuity while disabled and Enter-required unlocking with the new PIN.
- A missing-module fault with actual KDE password fallback, followed by real
  text-console login and sudo administrator recovery. Recovery restores the six
  original policies, revokes authority, disables the gate/broker and preserves
  native bytes/security metadata from the post-login checkpoint. The existing
  locked desktop then accepts the full password while the module remains absent.
  Native lockout initially
  refuses console login; the single retry succeeds after natural expiry with
  the original password and policy.
- Exact-candidate RPM removal after repairing the saved module, followed by
  stock KDE password unlocking. Native counter bytes/ownership/mode/xattrs and
  persistent accounting policy remain intact; no module, broker, boot socket
  or live LocalPIN authority remains.

The installed report retains fixture/environment failures separately from
successful product observations. It records the independent clone and temporary
access cleanup separately; source tests do not establish installed outcomes.

## Remaining release scope

This targeted feature matrix does not rerun the entire release matrix. Legacy
TPM-credential upgrades, all mixed-version/malformed-state/package-resume refusal
combinations, every cancellation/crash/race/fault case and active-boot acceptance
still need candidate-specific installed evidence where required. Source/native
tests above cover the changed parsers, fences, cancellation and deadlines;
historical reports keep their original scope. Physical TPM/sensor validation,
coverage-guided campaigns and M9 independent human/specialist review remain open.
