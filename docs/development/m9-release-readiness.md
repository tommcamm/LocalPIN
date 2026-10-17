# M9 release readiness and validation runbook

Date: 2026-10-17. **M9 is in progress; production completion is blocked on
independent review and the remaining installed and physical evidence below.**
This checklist maps [specification section 18](../product-specification.md#18-verification-and-acceptance-matrix)
and [section 20](../product-specification.md#20-production-completion-gates) to
reviewable evidence. A manually published experimental GitHub prerelease does
not complete these gates.

The target is Fedora KDE 44 x86_64, ordinary local non-root files accounts,
SELinux enforcing, the documented local authselect graphs and persistent native
faillock accounting. Stock `files systemd` NSS, including the supported group
merge clause, is covered by the current contract. Custom required factors,
network identities, systemd-homed, immutable Fedora variants, other desktops and
architectures remain unsupported. Refusing an unknown PIN route while retaining
the existing password/fingerprint route is expected behavior. Support for
ordinary desktops is a bounded compatibility contract, not a claim that every
Fedora configuration has been tested.

The current contract is [ADR 0017](../adr/0017-shadow-record-account-authority.md)
and [ADR 0018](../adr/0018-kde-native-update-compatibility.md). The
[M8.1 report](m8.1-desktop-compatibility.md) records targeted installed acceptance
in a disposable enforcing Fedora KDE VM with Btrfs and its own emulated TPM.
Earlier M6.1–M8 installed evidence describes the superseded immutable appliance.
Keep each case's recorded build scope: earlier results and final RPM provenance
do not imply that every historical scenario ran against the final RPM.

## Evidence rules

- **Recorded component evidence** establishes the linked model, parser, native
  boundary or isolated process behavior in its stated environment.
- **Recorded installed evidence** establishes only the actual VM/build/cases
  in that record. Synthetic biometric responses are not sensor acceptance;
  emulated TPM results are not physical TPM acceptance.
- **Open** means a release gate still needs a result bound to the candidate.
  A missing check, unsupported tool or infrastructure failure is not a pass.
- AI/implementation-agent review and maintainer attestations are development
  feedback. They do not satisfy section 20's review by someone independent of
  the implementation author.
- A CI configuration, local success and hosted workflow success are separate
  evidence. Link actual hosted run URLs and source commits before claiming a
  candidate's CI passed. The historical M8.1 source record explicitly describes
  local execution.

Each new result must identify source commit, RPM NEVRA and SHA256, test-runner
hash, date, operator/reviewer, environment inventory, preconditions, expected and
observed behavior, failure/recovery outcome, and sanitized evidence path. Mark
unavailable observations explicitly. Keep raw authentication logs, account
records, tally bytes, credential blobs, TPM secrets, VM images and debug dumps
private; public records should contain sanitized assertions and public artifact
identities. Follow [SECURITY.md](../../SECURITY.md) for suspected vulnerabilities.

## Section 18 acceptance checklist

Every row remains open for final-candidate reconciliation. Links describe
existing evidence; the final column identifies what must be added or verified
before a supported release.

| Acceptance area | Recorded evidence and reusable checks | Remaining release evidence |
| --- | --- | --- |
| PIN behavior | [PAM contract and M7 evidence](m7-pam-integration.md), [adapter tests](../../crates/localpin-pam/tests/isolated_pam.py), [M8.1 desktop record](../../experiments/m81/results/installed-desktop-and-continuity.json). Component checks cover candidate parsing and same-entry password fallback; actual KDE PIN and full-password UI passed in the VM. | Bind correct/wrong/empty input, leading zeroes, malformed and Unicode digits, six-digit account-password fallback and explicit Enter/no auto-submit to the candidate. Repeat input cases on physical top-row/numpad keyboards. |
| Password fallback | [M5 broker evidence](m5-bounded-broker.md), [isolated adapter](../../crates/localpin-pam/tests/isolated_pam.py), [M8.1 desktop/recovery](../../experiments/m81/results/installed-desktop-and-continuity.json). The VM demonstrated missing-module same-greeter password recovery. | Reconcile every required failure against the candidate: PIN mismatch/cooldown; stopped/crashed broker; module load error; unavailable/reset TPM; malformed state; read-only/full disk. Observe actual KDE password recovery and elapsed fallback time. Inject reset, disk and crash faults only in disposable environments. |
| PAM/account policy | [Current account contract](../adr/0017-shadow-record-account-authority.md), [native account tools](../../experiments/m81/results/account-tools.json), [KDE accounting harness](../../crates/localpin-auth/tests/kde_accounting.py), [installed policy regressions](../../experiments/m81/results/installed-policy-types.json), [disabled-fingerprint profile](../../experiments/m81/results/without-fingerprint-profile.json). | Candidate evidence for locked/expired users, wrong target/service, required-factor preservation, native counters, deletion/recreation and concurrent mutation. Exercise actual AccountsService GUI/DBus account administration; source dispatch inspection does not close it. Test real fingerprint success/rejection when claiming sensor compatibility. |
| Throttling | [M2 independent rolling-window model](m2-policy-contracts.md), [M3 durability/fault evidence](m3-protected-storage.md), [broker tests](../../crates/localpind/src/broker/tests.rs), [M8.1 reboot and upgrade continuity](../../experiments/m81/results/installed-desktop-and-continuity.json). | Reconcile concurrent clients/processes, reservation crash, success-write failure, broker restart, suspend, clock changes, reboot, missing/corrupt state and no unreserved verification. Preserve both LocalPIN and native password/biometric accounting. Repeat affected invariants after review fixes. |
| Storage | [M3 protected storage](m3-protected-storage.md), [storage tests](../../crates/localpin-storage/src/tests.rs), [finalization tests](../../crates/localpin-storage/src/tests/finalization.rs), [legacy-flag probe](../../experiments/m81/results/legacy-flags.json). | Candidate reconciliation for link/type/permission attacks, oversize records, rename/fsync interruption, generation rollback, UID reuse and migration failure. Demonstrate the complete old-TPM-credential migration with deliberate revocation and fresh enrollment; legacy flag probes alone do not establish it. Alternate accepted filesystems need their own installed durability evidence before broadening claims. |
| IPC | [M5 bounded broker](m5-bounded-broker.md), [protocol tests](../../crates/localpin-protocol/src/tests.rs), [transport tests](../../crates/localpin-protocol/src/transport/tests.rs), [protected broker harness](../../crates/localpind/tests/run_protected_broker.py). | Candidate results for cross-UID rejection, spoofed target/service, replay, partial/dropped/oversize frames, timeout/cancellation, queue/memory exhaustion and late-result rejection. Keep native live-peer identity and session-routing constraints explicit. |
| TPM simulator | [M1 TPM report](m1-tpm.md), [M4 backend report](m4-credential-backends.md), [native simulator runner](../../crates/localpin-tpm/tests/run_simulator.py), [real-storage TPM test](../../crates/localpin-storage/src/tests/tpm_backend.rs). | Re-run exact object attributes/Names, alternate-authorization rejection, wrong-PIN DA effect, exhausted/shared budget, transfer to a different TPM, reset/replacement, stale contexts and transport failures. Record simulator/library versions and failures. Physical hierarchy/firmware/resource-manager/coexistence behavior remains separate. |
| Software mode | [M4 backend/vector and benchmark evidence](m4-credential-backends.md), [software tests](../../crates/localpin-credentials/src/software/tests.rs), [real-storage software tests](../../crates/localpin-storage/src/tests/backends.rs). | Candidate fixed vectors, strict bounded PHC/KDF validation, random-source failure, explicit enrollment/migration and no silent TPM-to-software fallback. Run explicit software enrollment through the installed candidate and measure target-hardware latency. |
| Desktop hardware | [Historical M1 topology feasibility](m1-vm-topology.md), [M8.1 targeted desktop VM evidence](m8.1-desktop-compatibility.md). These are development/VM results. | Complete the physical matrix below: external screen/keyboard, closed lid, dock reconnect, Num Lock, suspend/resume, themes and multiple sessions/seats. Historical topology feasibility does not certify the final installed product. |
| Packaging | [M8.1 package/reboot evidence](../../experiments/m81/results/installed-desktop-and-continuity.json), [kernel boot](../../experiments/m81/results/kernel-boot.json), [actual DNF update](../../experiments/m81/results/dnf-upgrade.json), [native runtime reinstall](../../experiments/m81/results/native-pam-reinstall.json), [packaging checks](../../packaging/fedora/test_packaging.py), [administration tests](../../tools/tests/test_integration.py). | Candidate clean install, explicit enable/disable, upgrade/downgrade refusal, changed PAM file, protected backup/restore, missing-module recovery and uninstall with SELinux enforcing. Capture actual kernel/Plasma/PAM/authselect transactions rather than treating a no-op upgrade as replacement evidence. Verify published package signatures and recovery with that exact RPM. |
| Privacy | [M4 secret/native-copy limits](m4-credential-backends.md), [M5 process boundary](m5-bounded-broker.md), [process-secret checks](../../crates/localpind/tests/process_secrets.rs), [CLI terminal/job-control checks](../../crates/localpinctl/tests/terminal_job_control.py). | Candidate review of journals, process arguments/environment, core settings, secret-buffer ownership and allocator/native-copy limits. Any support-bundle feature must have explicit redaction/export review. Do not claim erasure of copies, swap or backups that has not been established. |

## Section 20 completion gates

| Gate | Current evidence | Required disposition |
| --- | --- | --- |
| 1. TPM and explicit software backends | [M4](m4-credential-backends.md), [ADR 0002](../adr/0002-tpm-construction.md), bounded backend records and no-downgrade tests. | Independent TPM/cryptography review, final-candidate reruns and physical TPM evidence remain open. |
| 2. Bounded broker/PAM/enrollment/CLI | [M5](m5-bounded-broker.md), [M6](m6-enrollment-cli.md), [M7](m7-pam-integration.md), current [account](../adr/0017-shadow-record-account-authority.md) and [KDE](../adr/0018-kde-native-update-compatibility.md) contracts. | Review current privilege/FFI boundaries and confirm candidate live-session and resource-limit evidence. |
| 3. Durable race-safe throttling/transactions | [M2 models](m2-policy-contracts.md), [M3 storage](m3-protected-storage.md), M8.1 continuity records. | Reconcile the entire fault/concurrency matrix, current identity publication and recovery crash points, and findings against the candidate. |
| 4. Real KDE unlock and entire password-failure matrix | M8.1 actual KDE PIN/password, missing-module recovery, update/reboot continuity and strict-policy regressions. | The entire section 18 fallback matrix and physical desktop behavior are not certified by those targeted cases. |
| 5. RPM/SELinux/systemd/upgrade/recovery | [Packaging contract](../../packaging/fedora/README.md), [installation/recovery runbook](../integration-administration.md), targeted enforcing VM evidence. | Final release RPM install/update/remove/recovery, controlled signing, hosted release run and physical console recovery remain open. |
| 6. Threat model/contracts/operations/dependencies | [Specification](../product-specification.md), [ADRs](../adr/), [account administration](../account-administration.md), [integration administration](../integration-administration.md), [dependency inventory](dependencies.md). | Review completeness, freeze record/protocol formats for the release, attach release SBOM and native/build inventory, publish actual limitations and maintenance/recovery instructions. |
| 7. Review independent of implementation author | Existing milestone review documents are useful development feedback. | **Open.** Obtain independent human/specialist review of TPM authorization, PAM/FFI, privilege separation, cryptography use and installer/recovery. AI review does not close this gate. |
| 8. Staged hardware rollout with verified recovery | Simulator and disposable VM stages have recorded targeted evidence. | **Open.** Complete noncritical physical hardware/test-account acceptance and recovery before any everyday deployment. |

## Independent review procedure

1. Select a candidate commit and RPM digest after the implementation is stable.
   Give the reviewer this checklist, the specification, ADRs, sources, locked
   dependency/native inventory, build instructions, sanitized evidence and known
   limitations. Record the reviewer's scope and independence from implementation.
   An AI-generated checklist is not a completed audit.
2. Review the TPM object template, Name/parent/generation binding, authorization
   paths, salted-session/parameter protection, hierarchy assumptions, global DA
   reserve/race limits, transport trust and absence of silent software downgrade.
   Include TPM2-TSS/tss-esapi ownership and native secret-copy limitations.
3. Review every project-owned unsafe/FFI boundary: PAM conversation/token
   lifetime, null/length/ownership checks, panic containment, C allocation/free
   contracts, library loading and native lock calls. Check that account expiry,
   failure accounting and unknown native factors cannot be bypassed by PIN.
4. Review peer/server identity, live logind routing, same-UID threat limits,
   privilege separation, worker deadlines, resource charging until reaping,
   response-delivery fences, SELinux domains and systemd/device restrictions.
   Review current shadow-marker continuity and native-lock retention through
   enrollment and authorization delivery, including deletion/recreation races.
5. Review cryptography use, entropy/error handling, KDF policy bounds, secret
   lifetimes, durable reservations/commits, rollback assumptions, and release
   installation/upgrade/uninstall/recovery trust boundaries. Inspect source and
   installed permit/deny evidence; advisory scans and compile-only policy checks
   cannot replace this work.
6. Record findings with severity, affected commit, requirement, reproduction,
   remediation and regression evidence. Keep exploitable details in the private
   reporting route. Have the reviewer confirm closure of blocking findings on
   the resulting candidate. Material boundary changes require renewed review of
   the affected scope and installed acceptance; do not silently carry old signoff.

Release approval must link the independent report and its exact reviewed scope,
with no unresolved security-critical findings. Establish a maintained private
security-reporting route and truthful supported-version/security-support policy
before describing any release as production-ready; the current
[security policy](../../SECURITY.md) promises neither a production release nor a
support window.

## Fuzzing, models and native-boundary tooling

The [M2 report](m2-policy-contracts.md) records 32,768 seeded steps checked against
an independent rolling-window model and bounded parser mutations. Additional
M9 core/protocol adversarial and state tests are deterministic checks as well;
their actual results belong in the change's validation record. They do not
establish coverage-guided fuzzing. No executed coverage-guided fuzz campaign or
applicable Miri/sanitizer result is linked by this initial checklist.

The initial M9 automation change adds
[record canonicalization campaigns](../../crates/localpin-core/tests/m9_records.rs),
[response/stream campaigns](../../crates/localpin-protocol/tests/m9_streams.rs)
and an [exhaustive verification model](../../crates/localpin-protocol/tests/m9_verification_model.rs).
The latter checks all 38,416 four-event traces; the stream campaign includes
30,720 single-byte response mutations. They run in normal workspace Cargo tests
without native authentication or physical TPM access. Passing them does not
certify unrelated PAM/FFI, native library or installed recovery behavior.

Before closing M9, record the exact toolchain, targets, seeds/corpus digests,
duration/iterations, results and any minimized regressions for:

- IPC frame/session decoders and PAM argument parsing;
- configuration, credential/account/state records and bounded PHC validation;
- throttle/generation/enrollment models, including cancellation, rotation,
  disable, failed reservation and failed success commit;
- project-owned FFI and native harnesses under applicable Miri/sanitizer tools.

Run pure parser/model targets without native system authentication or TPM
access. Run native instrumentation only in disposable synthetic environments.
Explain exact unsupported syscalls/native-library constraints when a target
cannot run under Miri or a sanitizer, retain the failed/tool-unavailable result,
and name the alternate review/test evidence. Do not report an uninstrumented
library or a target skipped by a filter as covered.

## Installed candidate and hardware procedure

First reproduce the affected installed VM matrix using the
[M8.1 instructions](../../experiments/m81/README.md) and
[M8 topology guards](../../experiments/m8/README.md). Keep original VMs off, disks
independent, no host shares or physical TPM passthrough, and private simulator
state. The guards and emulated-TPM fault runners are VM-only: do not relax them
to operate on physical hardware. Use [CONTRIBUTING.md](../../CONTRIBUTING.md#validation)
for source/native checks and keep hosted run results separate.

For physical acceptance, use a noncritical test machine with recoverable storage
and a dedicated local test account, independent of the everyday desktop. Before
installing, record Fedora edition/release/architecture, kernel, Plasma and
kscreenlocker versions, PAM/authselect/SELinux/systemd/glibc/TPM2-TSS RPM EVRs,
filesystem, authselect features, NSS shape, SELinux enforcement, hardware model,
TPM manufacturer/firmware/interface, keyboards/dock/displays and session/seat
layout. Redact serial numbers and account identifiers from public records. State
whether observed TPM state permits the documented hierarchy contract; mere
device presence does not prove suitability.

1. Verify full-password graphical unlock and real text-console administrator
   access first. Record the actual console-switch and return shortcuts; a root
   SSH command while the greeter is locked does not prove a usable local VT.
   Keep the administrator console available throughout trials.
2. Verify the candidate's package identity/signature, install without activation,
   and confirm no enrollment, KDE rewrite or started broker. Follow the existing
   [accounting/preparation runbook](../integration-administration.md); preserve
   existing native counters. Do not improvise live tally migration or reset
   counters to make acceptance pass.
3. Exercise explicit software mode and, where supported, `tpm2-required` through
   the normal interactive CLI. Test each backend in its own recorded enrollment;
   backend migration must be explicit and password-authorized. Never use real
   secrets in command arguments, environment, logs or evidence.
4. Use timed trials and perform the matrix below. For each row observe actual
   lock-screen PIN with Enter, the full-password route, correct account/session,
   counter behavior and elapsed time. Stop on an unexpected authentication grant,
   lost password recovery, stale identity acceptance or unexplained state change.
5. Exercise `sudo /usr/libexec/localpin/localpin-integration disable` from the
   local text console while the graphical screen remains locked. Verify the
   original password UI works without reboot and that native tallies survive.
   Recovery revokes enrollment; prepare/enroll and repeat final tests before
   recording an attestation and explicitly activating.
6. Check reboot, supported distribution updates and a compatible LocalPIN RPM
   update using the same enrollment, then disable/uninstall and verify the
   original graphical password route. Capture before/after public package
   inventory and sanitized state-preservation assertions. Perform crash,
   full-disk, TPM reset/replacement, global DA exhaustion, rollback and power-cut
   fault injection in isolated disposable VM/simulator environments instead.

Do not clear or change a physical TPM, reset its DA counter, consume its failure
budget for negative tests, disable another authenticator, weaken SELinux, or
touch unrelated TPM objects. Physical acceptance can verify correct PIN use,
availability, latency, suspend/reboot and coexistence without destructive DA
experiments. Use synthetic inputs and simulations for exhaustive wrong-PIN and
failure-budget coverage.

| Physical case | Observation required |
| --- | --- |
| Laptop open, built-in input | PIN/password, leading zeroes and explicit Enter; no auto-submit at six characters. |
| Lid closed, external display and USB keyboard | Lock/unlock remains usable without built-in display, fingerprint, network or another token. |
| USB/dock keyboard and display reconnect | Disconnect/reconnect while locked; confirm fresh input goes to the correct locker and password recovery remains usable. |
| Top-row/numpad and Num Lock on/off | Document expected key mapping, leading zeroes, no silent character conversion or unintended submission. |
| Suspend/resume | Open/closed lid and docked/undocked cases; no stale authorization, unintended cooldown reset or stuck unavailable worker. |
| Reboot/update | Same enrolled PIN and committed counters survive compatible transitions; incompatible policy retains password recovery and refuses PIN. |
| Sessions/seats | Single session, multiple local sessions, user-manager ambiguity and independent seat where available; reject wrong/ambiguous session delivery while preserving passwords. Mark unavailable topology untested. |
| Supported lock-screen themes | Stock supported theme and any additional theme actually claimed; input visibility, cancellation, Enter and password recovery behave correctly. |
| Fingerprint present/absent/disabled | No manufactured failure for unavailable/disabled devices; genuine rejection/success obey native accounting on an actual supported sensor. Never disable the user's factor to hide incompatibility. |
| TPM and explicit software mode | Correct backend remains pinned; availability/coexistence, resource-manager use and password fallback match the contract. |

Record latency distributions on each supported hardware class: warm PIN p50/p95
and maximum, sample count, backend, CPU/memory usage, disk-sync behavior,
availability/deadline outcomes and total password-fallback delay. The
[M4 software KDF microbenchmark](m4-credential-backends.md) is neither an
end-to-end KDE benchmark nor physical TPM evidence. Section 19 targets warm PIN
p95 below one second and bounded unavailability; distinguish LocalPIN's timeout
from delay in the remaining native password stack.

## Candidate publication and supported-release decision

Before publishing a candidate, bind its version/tag, commit and RPM digest to
the changelog, build/dependency/SBOM inputs, checksums, actual workflow run and
known limitations. Review release contents for privacy and verify the installed
RPM rather than assuming a successful build implies installed acceptance. The
[release runbook](../releasing.md) defines manual experimental prerelease
publication, mandatory verified OpenPGP signing and generated SPDX dependency
inventory. The [packaging guide](../../packaging/fedora/README.md) covers downloads
and installed testing. Workflow source and generated metadata do not establish
that a release was dispatched or that a maintainer signing key has been configured.

Specification section 15 and the M9 plan require **signed RPMs for a supported
release**. Checksums detect changes and provenance identifies build inputs;
neither supplies the package's RPM signature. Keep signing authority separate
from pull-request CI, document who controls the key and its public fingerprint,
provide trusted key distribution and rotation/revocation instructions, and
verify the exact distributed RPM with that trust established. Experimental
GitHub prereleases also require verified RPM and checksum signatures before
publication; ordinary CI testing artifacts remain unsigned. Every prerelease
retains all open production gates. Signing itself does not establish independent
review or desktop safety.

Only describe a release as supported/production-ready after every section 18
area and all eight completion gates have candidate-bound evidence, blocking
findings are resolved and independently confirmed, and staged hardware recovery
has passed. The final decision must name the supported Fedora KDE 44 profile,
tested hardware/backends and limitations. Everyday-system rollout comes after
those gates and separately verified recovery; this document authorizes no edits
to the everyday machine's PAM, account state or TPM.
