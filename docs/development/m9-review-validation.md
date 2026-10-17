# M9 development review and component validation

Date: 2026-10-17. Candidate source:
`dddbce91b84beb7cf763945897bd3448df2a3678` (current `main` at start).
Operator/reviewers: Codex coordinating implementation agent and two fresh
focused review agents. **This is AI-assisted development review, not the
independent human/specialist review required by section 20. M9 remains open;
these results do not establish readiness to replace everyday authentication.**

The [sanitized machine-readable evidence](../../experiments/m9/results/2026-10-17-candidate-components.json)
records commands, actual exit codes, runner/log/corpus identities, inventory,
failure dispositions and unavailable observations. Raw logs and generated
synthetic corpora remain local under `/tmp/localpin-m9-current`; no authentication
logs, real credentials, VM state or physical TPM data are published.

## Candidate and environment

Source and component checks ran on Fedora KDE 44 x86_64, Linux
`7.2.10-200.fc44.x86_64`, Rust/Cargo 1.99.1, GCC 16.2.1, PAM 1.7.2,
TPM2-TSS 4.1.3, swtpm/libtpms 0.10.2 and systemd 259.9. Build-only headers came
from extracted matching PAM/TPM2-TSS development RPMs. No host package install,
PAM/account change or physical TPM operation was performed. The host reports
SELinux **Disabled**: these local results establish no enforcing installation
or confinement behavior.

The actual [candidate hosted CI run](https://github.com/tommcamm/LocalPIN/actions/runs/39049852941)
completed successfully in all four jobs: Ubuntu lint/build, dependency policy,
Fedora workspace/native/simulator/RPM checks and isolated Fedora feasibility.
Its downloaded testing bundle passed all recorded SHA256 checks and identified:

- NEVRA: `localpin-0.1.0-0.1.alpha1.ci.15.1.fc44.x86_64`.
- RPM SHA256: `92d53a506dad3b7056c7437adef77ba0db0f84ee8755c01aa0b65060a0b06192`.
- This is an **unsigned CI testing RPM**, queried without installation. No new
  installed test or package-signature acceptance is claimed for it.

These package identities do not imply the locally tested release binaries were
extracted from that RPM. Local source checks, hosted CI and installed acceptance
are separate evidence.

## Source and isolated native results

| Check | Observed result and scope |
| --- | --- |
| Formatting, Clippy and locked release build | Passed on the production toolchain. |
| Full workspace, all features | 324 passed, 10 opt-in tests ignored; the separate native runners below cover applicable opt-ins. Zero-test harnesses are not counted as test cases. |
| Deterministic M9 models/campaigns | Workspace tests include all 38,416 verification traces, record mutations and stream partition/canonicalization checks. These remain separate from coverage-guided fuzzing. |
| cargo-deny 0.20.2 | Advisories, licenses, bans and sources passed after advisory refresh for both the production graph and the separately reviewed fuzz graph. The test runtime's NCSA/LLVM exception is isolated in fuzz/deny.toml. |
| Synthetic administration/release/VM guards | 72 integration, 50 release-policy and 21 topology-guard tests passed. Packaging assertions and SELinux policy compilation passed without installation or policy loading. |
| Native PAM ABI | Fedora layouts, exports and null-handle rejection passed; no host authentication handle was created. |
| Isolated production PAM adapter | Passed candidate-byte preservation, repeated handles, callback errors, fallback, unavailable broker cases, real synthetic pam_unix/faillock accounting, locked and expired accounts. |
| Isolated password worker and KDE accounting | Both runners and the separate read-only/writable tally-access test passed with synthetic account/policy/tally files; no real sensor or KDE greeter was exercised. |
| Protected verification and enrollment broker | Both mapped-UID namespace runners passed, including durable storage/worker/delivery and authorization fences. |
| Real private PTY job control | Proper Cargo entry point passed on the pinned compiler. |
| Native TPM storage | Dedicated simulator-backed storage/revocation test passed. |
| Native TPM authorization/identity/DA/lifetime | **Intermittent result:** initial run failed one assertion after the foreign simulator refused transport; failed case alone and two complete unchanged reruns passed. Cause remains unconfirmed. |

The original simulator failure expected `Record` and observed `Unavailable` at
`crates/localpin-tpm/src/simulator_tests.rs:704`. A failed transport correctly
cannot authorize. The record does not prove why that fixture stopped listening;
later successful runs do not erase the failure. No assertion or security policy
was weakened. Improve fixture diagnostics and resolve the intermittent failure
before describing the candidate simulator campaign as uniformly reliable.

An extra direct invocation of `terminal_job_control.py` without its required
Rust executable timed out waiting for a private prompt. That was a coordinating
agent invocation error. The workspace had already run the correct entry; a
separate `cargo test -p localpinctl --test job_control --locked` also passed.
The failed command remains recorded with that disposition.

## Parser and memory instrumentation

The new [separate fuzz workspace](../../fuzz/README.md) pins cargo-fuzz 0.13.2
and libfuzzer-sys 0.4.13. The shared production dependencies in its lockfile
match the production lockfile. Nightly instrumentation used Rust
`1.101.0-nightly (5d8fec066 2026-10-16)` / LLVM 23.1.4; production builds remain
pinned to Rust 1.99.1.

Three bounded 60-second campaigns used canonical public seeds, libFuzzer
coverage feedback, AddressSanitizer, debug/overflow assertions, seed 9,
per-input timeouts, input-size and 2 GiB RSS caps. Results and complete corpus
manifest digests are in the evidence record. The final campaigns executed
10,337,848 record inputs, 510,902 stream inputs and 12,546,052 PHC inputs
(23,394,802 total). No panic, sanitizer finding or
failure artifact was observed in the executed campaigns. These durations are a
bounded sample, not an exhaustive search or a code-coverage percentage.

The targets exercise configuration/credential/throttle canonicalization,
request/response streaming and decoder poisoning, and strict PHC policy parsing.
PHC fuzzing never invokes Argon2. They do not cover PAM arguments, native account
or TPM record formats, installer configuration or all enrollment/session traces.
Those remaining targets and longer campaigns retain their M9 gate.

Miri passed 22 selected pure tests: two secret-buffer/input tests, 18 enrollment
tests and two verification state/lifetime tests. Native PAM/TPM, transport,
installed policy, the whole workspace and all allocator/native copies were not
run under Miri. Applicable native ASan/UBSan scope and retained setup failures
are recorded separately in the machine-readable evidence.

Native instrumentation passed the ABI smoke, four adapter and five worker FFI
unit tests, and both full synthetic PAM suites. Selected Rust crates/dependencies
and std used ASan; the project C ABI/harness/password fixtures used ASan/UBSan
with one shared LLVM ASan runtime. Fedora libpam/modules, glibc/libcrypt, Python
and TPM libraries were uninstrumented; no TPM code or Rust UBSan coverage is
claimed. Leak detection was disabled because an attempted LeakSanitizer run
could not use its required ptrace mechanism in the namespace/non-dumpable
environment. No kernel policy was changed and no leak pass is claimed.

Earlier native attempts retained missing-runtime, restricted subordinate-ID
mapping, synthetic password-baseline and private runtime mount/access failures.
After extracting an uninstalled matching UBSan RPM and correcting private
fixture setup, the complete suites passed without memory-access/UB diagnostics.
The exact executed helper is retained. Subsequent source-attribution and
evidence/preflight-only hardening received focused checks; the recorded native
suite result is bound to the earlier helper hash, not silently reassigned.

A 100-sample software KDF microbenchmark on an AMD Ryzen 9 7945HX used the
reviewed 64 MiB / three-pass / one-lane Argon2id policy: minimum 86.29 ms,
median 89.09 ms, p95 91.77 ms, maximum 93.69 ms, including allocation and erasure.
Other checks were active; this is a component measurement, not KDE or TPM latency
and not proof of the end-to-end warm-PIN p95 requirement. It also falls below
section 10's 100–500 ms typical target on this CPU; no KDF parameters were changed
without a versioned policy/review.

## Development review and open requirements

One review covered the PAM exports/conversation ownership, fresh candidate and
target binding, native factor/account/tally validation, shared account locks,
privileged marker publication, installer journals/backups, update and recovery.
The other covered TPM templates/Names/parents/salted sessions/DA reserve,
software KDF/entropy/secret ownership, live peers/logind, worker resource charging,
durable reservation/success commits, throttle and generation revocation.
Neither bounded source review confirmed an authentication bypass or other
security-critical finding. This is a description of review scope, not assurance
that no vulnerability exists.

Three low-severity, previously unclosed product requirements remain visible:

| Requirement | Observed gap and required work |
| --- | --- |
| Specification section 10: best-effort memory locking and limits | Owned buffers are zeroized and core dumps suppressed, but secret-bearing process paths do not attempt memory locking. Define bounded policy and honest native-copy/swap limits, then validate installed confinement. |
| Section 16: structured operational events and success-logging policy | Current startup and rate-limited authority diagnostics do not supply the required enrollment/backend/cooldown event stream or configurable success logging. Implement sanitized bounded events and privacy tests. |
| Section 9: configurable TPM safety reserve | Production `TPM_DA_RESERVE` is fixed at two. The bounded `ConfigRecord` codec has no production policy loader. Preserve the conservative floor when adding reviewed root policy. |

These are requirement gaps, not demonstrated exploits. The independent reviewer
must assess the final implementations and any resulting boundary changes.

## Remaining work before everyday use

The old M8/M8.1 disposable test clone and its temporary access have been disposed
of. Read-only inventory found the original VM shut off and no current guarded
clone. No new installed KDE, enforcing SELinux, AccountsService GUI, old-credential
migration, disk-full/read-only/reset/crash fallback or console-recovery acceptance
ran in this pass. Historical results retain their exact original builds.

Resolve the recorded implementation gaps and simulator reliability, extend the
remaining parser/native instrumentation scope, select the resulting candidate,
and rebuild an independent enforcing Fedora KDE test clone for the complete
failure/recovery and RPM/migration matrix. Then obtain independent human/specialist
signoff and run the noncritical physical keyboard/dock/display/suspend/session,
TPM-coexistence, latency and console-recovery matrix. Bind those results to the
exact signed candidate before everyday rollout. No everyday PAM replacement or
third-party module migration was performed or authorized by this report.
