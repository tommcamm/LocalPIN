# LocalPIN implementation plan

- Date: 2026-10-17
- Status: Accepted roadmap; M0 implemented locally; M1 feasibility complete; M2 policy/protocol contracts, M3 protected storage, M4 credential primitives, M5 bounded broker and M6 enrollment worker/CLI implemented locally. M6.1 production account lifecycle and eligibility is the next implementation milestone and a prerequisite for M7's real-account completion gate. Installed password policy/sandbox, physical resource-manager and later review gates remain open. Hosted CI execution remains unverified. Permanent account records remain gated on production lifecycle support.
- Source of requirements: [product-specification.md](product-specification.md), version 1.2. M1 clarifies password/PIN accounting; M2 settles time boundaries and narrows lifecycle support explicitly.

This plan turns the specification into independently reviewable changes and evidence gates. The specification remains authoritative. An unresolved design question below must be resolved in an architecture decision record (ADR), with a specification amendment if necessary, rather than silently changing the requirements.

## Scope and intended outcome

Build an independent Rust project for six-digit PIN unlocking of an existing Fedora KDE graphical session, initially on x86_64 with local, non-root accounts. Deliver the broker, small PAM adapter, password enrollment worker, CLI, TPM and explicit software backends, durable throttling, Fedora RPMs, SELinux policy, recovery tooling, and public maintenance documentation.

Normal passwords and their existing policies remain the recovery route. Login, sudo, SSH, polkit, disk encryption, other distributions/desktops, a custom lock-screen theme, and PCR-based measured-boot policies are outside the initial supported scope. Public source can be useful before production readiness; an experimental source release does not satisfy the production completion gates.

The improvement to pursue is a narrower supported integration, protected authoritative state, hardware-bound credentials where usable, explicit backend selection, and demonstrated recovery behavior. Rust alone does not establish an improvement in security.

Use `pam_pinlock` as migration context. Its documented features already include Argon2id, throttling, a CLI, and password fallback. Avoid claiming those as novel, or claiming a source audit has been completed. Start with original Rust code; any upstream code or documentation reused must retain the applicable attribution and license notices. See the [upstream project](https://github.com/saltnpepper97/pam_pinlock).

## Planning baseline

- At planning time, the workspace contained the original `specs.md`; no application implementation or initialized Git history was found. M0 moves that specification to `docs/product-specification.md` and establishes the repository.
- The machine details in the specification are an initial deployment record, not a supported-platform certification.
- Read-only inspection during planning found the temporary `pam_pinlock` block in the KDE service. No installation, password-fallback test, TPM provisioning, or PAM change was performed as part of this plan.
- Dependency versions, Fedora package inputs, actual TPM suitability, and the supported PAM layout must be established and recorded during implementation.

## Delivery strategy

Begin with repository foundations and small feasibility experiments. Then implement the policy and persistence foundations before adding real credential verification. Probe the TPM design early, even though the complete TPM backend comes later. This changes the discovery order in specification section 21 without weakening its implementation or release requirements.

The principal dependency chain is:

```text
M0 repository foundation
  -> M1 PAM/TPM/platform feasibility and decisions
  -> M2 policy models and contracts
  -> M3 durable storage and throttling
  -> M4 credential backends
  -> M5 bounded broker
  -> M6 enrollment worker and CLI
  -> M6.1 production account lifecycle and eligibility
  -> M7 production PAM integration
  -> M8 Fedora packaging and recovery
  -> M9 independent review and staged release
```

Documentation, SELinux policy experiments, and test infrastructure progress alongside their corresponding implementation. Work that changes a shared protocol or state format stays sequential until its contract is settled. Software and TPM backend implementation can proceed independently once M2/M3 contracts are stable.

### M0 — Establish the repository and contribution workflow

Deliverables:

- Initialize Git with `main`. Preserve the supplied specification in the first commit, then commit the proposed roadmap separately so its review history is clear.
- Add an honest development-status README, build/contribution instructions, changelog, security-reporting policy, and issue/PR templates. Use `MIT OR Apache-2.0` for original code, the default adopted during M0; preserve applicable third-party notices.
- Add a scoped `.gitignore` for Rust outputs, local test state, VM images, sockets, generated packages, and local secrets. Commit `Cargo.lock` once the workspace exists. Keep sanitized fixtures distinct from real machine state.
- Pin an exact stable Rust toolchain, use edition 2024, declare the MSRV, and record why the selected dependencies/native libraries are suitable. Do not guess versions from the specification's machine inventory.
- Bootstrap only the crates needed for the first change; grow into the workspace layout in specification section 17. Avoid empty abstractions for all components on day one.
- Establish formatting, Clippy, locked builds/tests, dependency advisory/license checks, and a Fedora build job. Add simulator/desktop jobs when their harnesses exist. Pin external CI actions and give ordinary CI jobs read-only permissions.

Exit gate: a clean checkout builds the initial workspace with the pinned toolchain; the specification and roadmap have separate commits; CI runs without access to host authentication files or production credentials. The project repository is [tommcamm/LocalPIN](https://github.com/tommcamm/LocalPIN).

M0's local delivery and validation are recorded in the [foundation report](development/m0-foundation.md). The initial hosted workflow run must be verified separately; configuration validation and local builds are not presented as a successful GitHub run.

### M1 — Prove the risky platform assumptions

Use a disposable Fedora KDE VM, with SELinux enforcing and a dedicated test account. Record exact OS/package versions, relevant PAM files and digests, and results in a compatibility report. Use simulator state for TPM experiments. No experiment activates a prototype on the everyday host.

PAM/platform experiment:

- Inspect the Fedora-packaged KDE authentication implementation and the complete screen-lock PAM include/substack graph. Confirm the actual service name instead of assuming `kde`.
- Build an isolated PAM harness with known permit/deny baselines and a scripted conversation. Treat baseline failure as a harness/infrastructure problem, not a failed LocalPIN assertion.
- Prove one-entry candidate handling with ordinary passwords and a six-digit account password, preserving arbitrary PAM-supported password bytes. Establish whether downstream modules reuse `PAM_AUTHTOK`; do not assume setting it guarantees reuse.
- Determine which account lock/expiry checks KDE actually performs. Design an explicit eligibility check if the locker only calls authentication. Verify that a PIN short circuit preserves required account restrictions and existing failure accounting.
- Check session resolution for a locker under the systemd user manager, multiple sessions/seats, and local-session eligibility. Document same-UID caller impersonation as a threat-model limit.
- Exercise a minimal broker-contact/worker sandbox policy under enforcing SELinux before treating the privilege design as settled.

TPM experiment:

- With `swtpm`, prove parent recreation, PIN-derived object authorization, required object attributes, dictionary-attack behavior, salted/protected sessions, and inability to use copied blobs on another simulated TPM.
- Demonstrate that no alternate authorization path unseals the object without the PIN. Define object identity/metadata validation; do not treat arbitrary successful unseal output as sufficient evidence by itself.
- Establish how the global dictionary-attack budget can be inspected without consuming guesses, and what happens when unavailable. Simulate the two-attempt safety reserve and races with other clients.
- Test timeout behavior of the native TPM stack. Decide how blocked calls are isolated, bounded, and cleaned up while preserving already-reserved attempts.
- Inventory real TPM capabilities read-only only when needed. Do not run wrong-PIN budgets, clear operations, or global-policy changes on production hardware.

Exit gate: checked-in experiment results and ADRs resolve the early platform/design questions below and assign explicit tests to decisions completed in later milestones. If same-entry fallback or a secure TPM construction cannot be demonstrated, revise the design/specification visibly before building the full product around it. Experimental test adapters are not installable release artifacts.

The [M1 evidence report](development/m1-feasibility.md) records the isolated PAM,
TPM, platform and native-worker experiments. It now includes actual stock KDE fallback, real-account restrictions/failure
counters, user-manager discovery, root-declared logind registrations and separate
enforcing broker/worker boundaries. The [genuine topology tests](development/m1-vm-topology.md)
also passed same-UID ambiguity/password fallback and independent second-seat
desktop/locker checks, followed by complete clone disposal. This closes M1's
feasibility gate; production integration remains assigned to later milestones. Follow the
[VM setup instructions](development/m1-vm-setup.md) to reproduce the tests.

### M2 — Implement policy models and stable contracts

Implement `localpin-core` and `localpin-protocol`, with narrow interfaces for storage, clocks, randomness, session eligibility, and credential verification.

Sequencing review, 2026-10-17: M1's same-UID desktop and second-seat feasibility
tests have now passed, with recovery completed. Proceed with M2's pure
policy/model and bounded-parser work using simulated eligibility, storage and
backend inputs. Platform-facing contracts remain provisional until M2's own
decisions and tests settle them; M1 does not authorize production activation.
Resolve fifth-attempt behavior, conservative reboot throttling, revocation fences
and the UID-reuse lifecycle during M2. Do not stabilize a persisted account-identity
schema around UID/name/home equality. M3/M4 work may follow once its relevant M2
contracts are tested and settled; unresolved identity requirements still block
permanent credential/account records. No VM interaction is needed for this initial
M2 work. M2's delivered pure contracts, local checks and remaining adapter gates
are recorded in the [M2 report](development/m2-policy-contracts.md).

- Define bounded UID/account identity, backend selection, credential generations, PIN format, typed outcomes, enrollment transactions, and versioned records.
- Model the attempt lifecycle: eligible -> durably reserved -> backend outcome -> durably completed -> response. Represent unavailable, mismatch, cooldown, and success separately.
- Specify five submitted PIN-format guesses per rolling minute and a five-minute cooldown, including exact boundary behavior, reservation recovery, success reset, reboot handling, and time anomalies.
- Specify the versioned length-prefixed protocol, operation/state transition rules, expiry/connection binding, and sanitized error/status vocabulary. Reject oversized frames before allocating their claimed length.
- Fix limits from the specification: 4 KiB request frames, 64 KiB credential/config records, 16 KiB throttle records, one verification per UID, 32 connections, and a 256 MiB aggregate KDF-work budget. Budget enrollment and TPM PIN derivation as well as ordinary software verification.
- Keep secrets out of serializable status, `Debug`, panic output, and ordinary errors. Define zeroizing ownership and cleanup boundaries early.

Exit gate: deterministic/property tests cover state transitions and time boundaries; protocol parsers reject unknown/oversized inputs; no real PIN backend or host privilege is needed to test the contracts.

### M3 — Build protected storage and authoritative throttling

Implement `localpin-storage` and wire it to the policy state machine before any real verifier is exposed.

- Use descriptor-relative trusted paths, numeric UIDs, no-follow/beneath restrictions, file type/link/ownership/mode checks, bounded records, and stable lock inodes.
- Enforce one broker instance and cross-process serialization, in addition to per-UID locking. Keep unrelated UIDs responsive when one operation stalls.
- Durably reserve every attempt before invoking a backend. Durably complete success before returning authorization. Missing/corrupt required state makes the PIN unavailable.
- Implement staged credential generations, verification before commit, atomic pointer replacement, synchronization, and deterministic crash recovery. A previous generation is recovery material only, never a second accepted PIN after commit.
- Serialize rotation, disable, recovery, and in-flight verification so a stale generation cannot authorize after revocation is committed. Document that a PAM transaction already authorized before that boundary can still finish; revocation cannot retract a delivered success.
- Persist boot/time/cooldown/reservation metadata with the conservative reboot policy chosen in M1/M2. An ordinary reboot must not become a cheap attempt-budget reset.

Exit gate: fault injection at each write/fsync/rename boundary, multi-process contention, restart/reboot/time changes, missing state, disk-full/read-only errors, and filesystem attack fixtures cannot yield an unreserved verification or an authorization whose success was not committed.

The [M3 report](development/m3-protected-storage.md) records the local filesystem,
process and fault-injection evidence and its limits. Storage uses synthetic
lifecycle authorities and backend callbacks; ADR 0006 still blocks permanent
production account records. Disk-full/read-only errors are injected, and physical
power-loss behavior is not claimed by the local tests.

### M4 — Implement both credential backends

Software backend:

- Use maintained RustCrypto Argon2id v19 with the specification's enrollment parameters: 64 MiB, three passes, one lane, 16-byte salt, 32-byte output.
- Validate PHC algorithm/version/sizes and supported parameter bounds before verification. A stored record cannot request arbitrary memory/work. Reserve aggregate KDF capacity before allocating it.
- Abort enrollment on OS randomness failure; handle secret ownership and erasure explicitly. Benchmark rather than assuming the latency target is met.

TPM backend:

- Use `tss-esapi` with pinned TPM2-TSS requirements and the object/session/parent design proven in M1.
- Persist only protected blobs and required nonsecret metadata. Store no independent PIN or derived-authorization verifier for a TPM credential.
- Enforce the software reservation and hardware safety reserve before a TPM attempt. Handle exhausted/shared budgets, transport failures, parent mismatch, reset/replacement, and stale contexts after suspend.
- Erase unsealed data immediately and retain no successful authorization cache. Bound worker/context lifetimes and resource consumption.

Pin the enrolled backend. `auto` prefers a demonstrated usable TPM and requires explicit software acceptance when unavailable. TPM errors never create or select a software credential automatically.

Exit gate: software test vectors and bounded-parameter tests pass; simulator tests demonstrate the intended authorization path, hardware binding, DA reserve and failure handling; record inspection finds no shadow verifier; both backends obey identical durable reservation rules. The TPM design gets specialist review before being treated as fixed for release.

The [M4 report](development/m4-credential-backends.md) records implemented software
and native TPM worker primitives, backend/storage tests, simulator evidence,
dependency review and measured KDF latency. [ADR 0009](adr/0009-bounded-credential-payloads.md)
defines the new bounded backend payloads without changing the M2 envelope.
Physical resource-manager use remains unverified; M5 still owns supervised
native deadlines and process capacity, and M9 owns independent TPM/hardware review.

### M5 — Implement the bounded broker and session checks

Implement `localpind`, socket activation, and protocol clients.

- Authenticate client credentials with kernel peer information; verify the privileged server identity/socket trust before transmitting secrets. Test the exact socket-activation credential behavior rather than assuming peer PID always identifies the accepting broker. Client-supplied identity/service fields never grant authority.
- Limit normal operations to the peer's own eligible local non-root account/session. Define separate administrator-only operations rather than a user-controlled override flag.
- Reject ancillary capabilities, malformed/replayed/out-of-order messages, target spoofing, expired challenges, and cross-UID operations.
- Enforce connection/queue/worker/memory bounds, cancellation, deadlines, and sanitized rate-limited diagnostics. Abandoned reserved attempts remain consumed.
- Implement status and diagnostics without secret disclosure. Deadline tests cover a stalled native worker and unrelated UID responsiveness, not just a cooperative mock backend.
- Document broker and password-worker privileges independently. No general shell execution, network listener, or desktop-unlock command exists.

Exit gate: Unix-socket integration tests prove peer isolation, live session checks, resource limits, cancellation/replay resistance, server identity verification, and the 250 ms connection / two-second unavailable / five-second genuine TPM-attempt targets under their defined conditions.

The [M5 report](development/m5-bounded-broker.md) and
[ADR 0010](adr/0010-bounded-broker-and-live-peers.md) record the broker, protocol
client, native logind routing, process identity and bounded worker implementation.
Local tests cover actual Unix IPC and native stalls; account lifecycle/policy
defaults remain unavailable. Installed unit/SELinux and full production account
flows are not established by these tests. M6.1 owns production account lifecycle
and policy adapters; M6/M8/M9 retain their enrollment integration, packaging and
independent hardware/security gates.

### M6 — Add trusted enrollment and the usable CLI

Implement `localpin-auth` and `localpinctl`.

- Use a short-lived privileged worker with a dedicated, reviewed password-only PAM service. It must not include LocalPIN, the old PIN module, fingerprint shortcuts, or cached client authorization.
- Relay the supported PAM conversation privately. The worker/broker owns the result and binds the grant to UID, action, proposed generation, and the maximum 60-second commit interval.
- Implement doctor/status/JSON output, enrollment, PIN change, own-user disable, explicit backend migration, and root-authorized recovery. Establish how system-level integration commands obtain administrative authority without a setuid CLI.
- Require secure interactive input, confirmation and fresh password verification. Reject `--pin`, environment secrets, plaintext stdin enrollment, and release-build simulator injection.
- Prove that wrong/stale password, cancellation, reconnect, replay, account changes, and worker crash cannot authorize a commit. Pre-commit checks validate the new credential and password recovery without weakening lockout accounting.

Exit gate: complete enrollment/change/disable/recovery flows work against a test broker; an unlocked user process or old PIN cannot reset credentials; cancellation preserves committed state; installed/enrolled/tested/active are distinct statuses.

The [M6 report](development/m6-enrollment-cli.md) and
[ADR 0011](adr/0011-trusted-enrollment-and-cli.md) describe the password-only
worker, terminal CLI and staged credential transactions. Complete broker flows
use isolated synthetic account authorities; ADR 0006 still refuses unmanaged
production accounts. Installed password-policy/confinement evidence remains an
explicit M8 gate, and enrollment does not activate desktop integration.

### M6.1 — Implement production account lifecycle and eligibility

Status: planned; required next before M7's real-account integration and acceptance
work. M6 completed its test-broker gate using synthetic authorities. The installed
broker still uses `UnmanagedUnixAccounts`, and `SystemEligibility` returns
unavailable after live-session routing. This milestone owns both missing
production adapters; session metadata or successful enrollment-password PAM
authentication cannot stand in for either authority.

Design and implementation:

- Choose and document an enforceable local-account lifecycle mechanism in a new
  ADR that satisfies [ADR 0006](adr/0006-account-incarnation-support.md). Define
  the supported account domain, trusted source, administration paths, privilege
  boundary, lock order and durable revocation point before freezing a permanent
  identity schema. Enumerate creation, deletion, UID changes, rename, recovery
  and any supported GUI/AccountsService, shadow-utils or other mutation paths.
- Implement the production `LifecycleAuthority`: opaque account incarnations,
  durable revocation before deletion/reuse, and serialization with enrollment
  publication and PIN authorization. Preserve continuity on rename only when
  proved. UID/name/home equality, a random identifier stored only in the
  credential, polling and asynchronous file-change notifications cannot by
  themselves establish the required guarantee. Refuse unmanaged or out-of-band
  changes whenever continuity cannot be proved.
- Provide the privileged lifecycle provisioning path for a protected disabled
  account baseline, with explicit authority and crash recovery. Missing or
  corrupt required state must never be repaired by an own-user enrollment
  request, even after fresh-password authentication. Fence old credentials,
  staged generations, fresh-password grants and in-flight results when an
  incarnation is revoked or replaced.
  Define versioned compatibility/re-enrollment behavior without adopting
  synthetic development identities as production continuity evidence.
- Implement password-free `EligibilityAuthority` checks for the exact supported
  Fedora account/PAM policy, following
  [ADR 0001](adr/0001-pam-candidate-and-account-policy.md) and
  [ADR 0003](adr/0003-session-and-worker-boundaries.md). Cover locked/empty or
  unusable passwords, supported password-hash formats, account/password expiry,
  forced password change, nologin/access restrictions and applicable faillock
  state. Review the real policy graph; `pam_acct_mgmt` alone or a fixture-only
  SHA512 profile is not proof of complete supported policy. Unknown policy,
  format, account source or unreadable authoritative state makes PIN unavailable.
- Wire both adapters into `SystemAuthorities` only for the demonstrated domain.
  Preserve kernel peer/account binding and stable logind session checks, and
  repeat lifecycle/policy checks at existing enrollment/verification publication
  and delivery fences. Account checks must never prompt for a password, invoke
  an alternate authentication factor, reset/add password failure counters or
  bypass the original password route. Preserve resource/deadline/cancellation
  guarantees and supervise blocking native policy work as required.
- Extend doctor/status with actionable supported/unsupported/unavailable account
  diagnostics, keeping identities and secret account material out of public
  output. Record the architecture, actual evidence and remaining limitations in
  `docs/development/m6.1-account-authorities.md`; update affected decisions and
  specification text only after their guarantees have evidence. Obtain separate
  development review, fix findings and commit the implementation and evidence.

Required evidence:

- Delete and recreate an account with identical UID/name/home; rename and other
  supported identity mutations; every supported administrative path and attempts
  to bypass it; revocation concurrent with backend success, enrollment staging,
  pointer publication and response delivery. A reused account cannot inherit a
  PIN or a previously issued password grant.
- Missing/corrupt authority state, authority restart, crash at each durable
  revocation/provisioning boundary, reboot and interrupted account mutation.
  Required state failures refuse authorization; they cannot invent continuity,
  revive a revoked incarnation or turn missing state into a new enrollment.
- Real allowed, locked, expired, forced-change, restricted and policy-unknown
  accounts, plus relevant faillock states and supported hash formats. Prove
  policy checks are password-free and leave password accounting unchanged;
  preserve bounded failure behavior and unrelated-UID responsiveness.
- Complete enroll/change/disable/recover and broker PIN-verification flows with
  the actual production authorities and dedicated test accounts in a disposable
  Fedora KDE VM with SELinux enforcing. Include the existing password-only
  enrollment service and prove password recovery; synthetic-only authorities do
  not pass this gate. Keep the everyday host's PAM, accounts, enrolled state and
  TPM guess budget untouched.

Exit gate: at least one explicitly defined real local-account domain has an
enforcing lifecycle authority and complete supported eligibility policy, with
the deletion/reuse, crash, concurrency and real-account evidence above. Permanent
records are permitted only inside that proven domain; other accounts remain
unavailable. If the lifecycle guarantee cannot be enforced, record the blocker
and resolve it through a reviewed design or specification amendment; do not mark
M6.1 complete or weaken the existing default to proceed to M7.

M6.1 supplies the account authorities; M7 owns the unlock PAM adapter and actual
stock KDE success/fallback matrix. M8 retains installed password-worker/systemd
confinement, full SELinux/RPM lifecycle and activation/recovery validation.
Component-level VM setup needed to test M6.1 does not satisfy those M7/M8 gates
or authorize everyday-system activation.

### M7 — Complete the small PAM adapter and KDE integration contract

Implement `localpin-pam` using the behavior proven in M1.
Complete M6.1 before this milestone's real-account integration/acceptance work;
isolated ABI/parser development may proceed independently, but cannot substitute
for the production authorities or pass the M7 gate.

- Keep the C ABI and unsafe surface small, documented and reviewed. Validate ABI inputs within the PAM contract, match allocator ownership, contain Rust panics, and clean up sensitive buffers without unwinding across FFI.
- Enforce the supported screen-lock service, target identity and real/effective UID rules. Do not expose this module as an alternative for sudo, SSH, login, or another account.
- Accept only six ASCII digits for the PIN route; require Enter. Preserve other candidate bytes and the proven authentication-token lifetime for password fallback.
- Return success only on authoritative, durable broker success. Map all other outcomes to the tested control-rule behavior that preserves the original password route.
- Cover six-digit account passwords, failed PIN followed by full password, cooldown, empty/Unicode input, stopped/crashed broker, missing module, TPM faults and corrupt state. Test original failure counters, locked/expired account behavior, and repeated authentication calls on KDE's reused PAM handle without stale tokens or cached success.

Exit gate: isolated PAM tests and real stock-theme KDE tests pass in the disposable enforcing VM, including account eligibility and password fallback under failures. Successful mock PAM authentication alone does not pass this gate.

### M8 — Package, activate, migrate and recover on Fedora

- Ship systemd units, reviewed sandbox settings, SELinux policy and RPM packaging. Determine native dependency sourcing and the distinction between project-distributed RPMs and future Fedora repository inclusion.
- Installation makes no enrollment or PAM activation change. Activation recognizes only verified layouts and has a dry-run diff, protected original backup, digests and transactional edits.
- Preserve the complete existing password stack and other PAM sections. Never rewrite authselect-generated files or unrelated services. Unknown layouts refuse activation with useful diagnostics.
- Implement changed-file handling, owned-block removal, upgrade/state migration, downgrade behavior, disable, uninstall ordering and backup restoration. Test package transaction failure paths.
- Make administrative recovery a short documented text-console procedure. Prove it restores a failed graphical unlock without reboot/reinstallation in the test environment.
- Exercise clean install -> enroll -> test -> activate -> upgrade -> disable -> uninstall, including changed PAM files, SELinux denials and missing components.

Migration from the temporary installation is a separate explicit operation:

1. Inventory and back up the KDE service and identify the old owned block.
2. Verify the existing full-password recovery route and prepare console recovery.
3. Enroll LocalPIN freshly and test it with the isolated harness; import no old verifier.
4. Remove only the old KDE PIN block and verify the password-only route.
5. Activate the tested LocalPIN block; never stack the two PIN modules.
6. Test PIN and password in the actual locker and demonstrate restoration from backup.

Exit gate: Fedora RPM lifecycle and recovery matrix passes with SELinux enforcing; activation is opt-in and layout checked; migration and rollback have executable evidence. Changes to an everyday machine occur only as a later, deliberate rollout.

### M9 — Review, hardware validation and versioned release

- Build a requirement-to-evidence checklist covering every acceptance category in specification section 18 and every completion gate in section 20. Link tests, VM reports, hardware observations, benchmarks and review findings.
- Run parser fuzzing, state-machine property/model tests, and applicable FFI Miri/sanitizer checks. Explain where native library or platform constraints limit those tools.
- Complete the physical matrix: laptop closed, external monitor, USB/dock keyboard, top-row/numpad/leading zeroes, reconnect, suspend/resume, multiple sessions/seats, and supported theme variations.
- Obtain independent review of TPM authorization, PAM/FFI, privilege separation, cryptography use and installation/recovery. Another implementation agent's review is useful development feedback and is not a substitute for the specified independent review.
- Resolve blocking findings, freeze record/protocol formats for the release, produce a dependency inventory/SBOM and signed RPMs, record performance and limitations, and publish recovery/maintenance documentation.
- Roll out from simulator -> disposable VM -> noncritical hardware/test account -> the everyday system. Verify recovery before depending on PIN unlocking.

Exit gate: all specification completion gates have evidence and no unresolved security-critical findings. Publish a tagged supported release only with truthful support and review status.

## Design questions to resolve explicitly

| Decision | Resolution required | When |
|---|---|---|
| PAM token reuse and UI | Does the actual Fedora stack consume the candidate without a second password prompt? If not, prove an explicit password-selection conversation or refuse activation. | M1, before M7 |
| Account eligibility | M1 supplies feasibility evidence; M6.1 must implement and demonstrate password-free production lock/expiry/restriction checks before M7's real-account gate. No permissive substitute for failed checks. | M1 feasibility; M6.1 implementation, before M7 |
| Failure accounting | A six-digit account password is indistinguishable from a PIN candidate until tested. Document potential PIN-budget consumption, wrong-PIN effects on password lockout counters, supported authselect features, and the exact fifth-attempt boundary. Reconcile ambiguous wording in specification section 11 without bypassing existing lockout policy. | M1/M2 |
| TPM authorization and parent | Fix the reviewed object template, parent recreation, object identity checks, salted sessions, DA-budget inspection and behavior under unavailable hierarchy authorization. | M1/M4 |
| Blocking backends | Prove how hard LocalPIN deadlines survive a blocked native call, discard late authorization, and clean up workers/handles/reservations without unbounded spawning. Measure total fallback latency separately, including delays in the original password stack. | M1/M5 |
| Reboot throttling | Define conservative behavior for recent attempts even if no cooldown was active; a boot-ID change must not allow reboot-assisted unlimited guesses. | M2/M3 |
| UID reuse | ADR 0006 restricts support; M6.1 must choose and demonstrate an enforcing lifecycle/identity mechanism for a defined real-account domain. Ordinary UID/name/home equality cannot establish continuity. | M1/M2 restriction; M6.1 implementation, before M7 |
| Local-session identity | Define eligible logind sessions/seats and the user-manager lookup policy; do not equate a claimed service name with a genuine locker. | M1/M5 |
| Integration authority | Decide the narrow root/admin path for PAM changes and recovery, separate from fresh own-user password enrollment. | M1/M6 |
| Revocation races | Define the durable commit point for disable/rotation versus a verification already in flight; fence later results by generation while acknowledging that previously delivered authorization can finish. | M2/M3 |
| Project publication | Confirm license, repository owner/name, vulnerability-reporting channel and release-signing ownership before public publication. | M0/M9 |

These are engineering decisions to investigate, not unanswered user-preference questions that prevent starting M0.

## Git and GitHub workflow

Use one repository and a simple `main` plus short-lived branches workflow. A long-lived `develop` branch adds no value for this personal project.

1. Start with `git init -b main`. Commit only the reviewed specification as the baseline, then the roadmap, then repository/toolchain foundations in distinct commits. Use the maintainer's existing Git identity; do not invent one or change global settings.
2. Use one branch per coherent change, for example `chore/repository-foundation`, `spike/fedora-pam-fallback`, `feat/durable-throttle`, or `feat/tpm-backend`. A milestone can require several small branches/PRs.
3. Make focused commits that include the relevant tests and documentation. Example subjects: `feat(storage): reserve attempts durably` and `test(pam): cover six-digit password fallback`. Record what was actually tested, including environment limitations.
4. Review diffs before staging; stage explicit paths. Keep real credentials, state directories, PAM backups, private keys, core files, simulator secrets and machine-identifying debug logs out of history. Test fixtures must be synthetic and clearly labeled.
5. After the GitHub repository is deliberately created, add the confirmed remote, open PRs into `main`, and require available CI checks. Review the full diff even as a solo maintainer; obtain specialist review for the sensitive boundaries. Prefer squash merge for exploratory branches and a clear final PR description.
6. Rebase only unpublished personal work as appropriate; do not rewrite shared `main` or published release tags. Fix published mistakes through corrective commits and follow the documented credential-response process if a secret ever enters history.
7. Use annotated version tags, changelog entries, signed release packages, checksums, dependency/SBOM records and a release checklist. Keep release secrets out of pull-request CI and use a separately controlled signing/release step.

Publication can begin with clearly marked experimental source once licensing, privacy review and useful build instructions are ready. Suggested development tag: `v0.1.0-alpha.1`. Public availability does not imply recommendation for daily authentication. Reserve a production-ready claim for M9 and the specification's full gates.

For each branch/PR, include the problem, resulting behavior, specification requirement(s), validation evidence, and any migration/security implications. Shared protocol/record changes need an ADR and compatibility tests, not only an implementation diff.

## Validation and progress tracking

Each milestone records three things: delivered changes, evidence actually collected, and unresolved issues. A dependency that has not passed its gate remains visibly incomplete. Do not count generated code, a passing mock test, or a successful package build as a completed desktop-security requirement.

Use deterministic unit/property tests for policy; fault-injected filesystem tests for persistence; socket tests for IPC; simulator tests for TPM; permit/deny-baselined PAM harnesses for the adapter; enforcing Fedora VMs for packaging/desktop flows; and physical hardware for the final usability/performance matrix. Add regression tests when a discovered failure threatens authentication, persistence or recovery.

M1's isolated harnesses, guarded enforcing-VM tests and ADRs are delivered, and
its feasibility exit gate is complete. The evidence report distinguishes actual
same-UID/second-seat KDE fallback and account/helper checks from root-declared
metadata and synthetic controls. Production caller, lifecycle, persistence and
integration requirements retain their later milestone gates. The everyday
authentication setup remains separate throughout development. M2 contracts are
tested in the pure Rust suites and documented in ADRs 0005–0007; actual
persistence and platform lifecycle evidence remain later gates.

No calendar estimate is committed before the feasibility work. Subsequent estimates should use measured test infrastructure effort and availability of independent review/hardware, with review and recovery work included in the schedule.

## Primary references for the feasibility work

- [KDE screen-locker PAM contract](https://github.com/KDE/kscreenlocker/blob/master/README.pam): documents the default service and auth-only use; verify against the exact Fedora-packaged version.
- [KDE 6.7.5 authentication source](https://raw.githubusercontent.com/KDE/kscreenlocker/v6.7.5/greeter/pamauthenticator.cpp): source inspection shows authentication and credential refresh without an account-management call; this is not a behavior test of Fedora's installed build.
- [Linux-PAM project and documentation](https://github.com/linux-pam/linux-pam): authoritative API/control-stack behavior; test the exact distro policy rather than copying a generic example.
- [Linux-PAM 1.7.2 token handling](https://raw.githubusercontent.com/linux-pam/linux-pam/v1.7.2/libpam/pam_get_authtok.c): supports the inference that a preexisting authentication token can be reused; the full Fedora stack and repeated calls still need empirical tests.
- [Rust TPM ESAPI bindings](https://github.com/parallaxsecond/rust-tss-esapi): native bindings, supported APIs and dependency requirements.
- [RustCrypto Argon2 API](https://docs.rs/argon2/latest/argon2/): review the selected version and distinguish PHC verification from key derivation; stored PHC parameters require application validation.
- [Current temporary pam_pinlock project](https://github.com/saltnpepper97/pam_pinlock): migration behavior and attribution context, not evidence of LocalPIN security.

These are reference entry points, not pinned release inputs. M1 reports and later ADRs must record exact versions/commits and reproducible observations.
