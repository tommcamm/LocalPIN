# LocalPIN product specification

**Specification version:** 1.3

**Date:** 2026-10-17

**Status:** Implementation specification; M2–M6 code implemented locally and M6.1 component gate complete only for the restricted domain below. M7 has not started; unlock integration, M8 packaging/confinement and M9 release review/hardware gates remain open.
**Initial deployment:** Fedora Linux, KDE Plasma, local user accounts.  
**Working component names:** `pam_localpin.so`, `localpind`, `localpinctl`.

## 1. Product objective

Provide a convenient, six-digit PIN for unlocking an already running local graphical session. The primary user operates a laptop with its lid closed, an external monitor, and an ordinary external keyboard. The workflow must require no fingerprint reader, camera, phone, network connection, or additional security token.

The production product must preserve the existing full-password route and normal desktop locking behavior. Initial graphical login, virtual-terminal login, SSH, sudo, polkit, disk encryption, and password managers must retain their existing authentication requirements. Installation must not replace an account password or repurpose the disk-encryption passphrase.

Rust is an implementation choice that helps limit memory-safety problems; it does not establish a security guarantee. Security claims must describe the implemented backend, threat model, tests, and review status. A newly written module must not be advertised as safer than an existing product without supporting evidence.

This document defines the complete intended product, including installation, integration, recovery, maintenance, and release requirements. Development milestones are implementation steps toward that product, not permission to ship an incomplete authentication prototype.

## 2. Deployment baseline and support policy

The inspected machine reported Fedora 44 KDE, Plasma/kscreenlocker 6.7.5, Rust 1.95.0, and a TPM 2.0 entry in sysfs. TPM device access and suitability were not established. SELinux was disabled on this particular machine; the product must nevertheless support Fedora with SELinux enforcing.

The initial supported platform is Fedora KDE with local, non-root users and a verified screen-lock PAM service. Target x86_64 initially; aarch64 support requires equivalent CI, packages, and hardware integration testing. Network identities, systemd-homed accounts, non-KDE desktops, immutable Fedora variants, and other distributions must be reported as unsupported until adapters and tests exist. Unsupported configurations must not receive guessed PAM edits.

Account support additionally requires an enforcing, tested lifecycle authority
that distinguishes account incarnations and revokes enrollment before UID reuse.
Ordinary unmanaged Unix accounts remain unsupported for production activation.
UID/name/home equality is insufficient. See
[ADR 0006](adr/0006-account-incarnation-support.md).

Implementation note, 2026-10-17: M6.1 supplies production authorities only for
the explicitly provisioned Fedora 44 x86_64 Btrfs appliance domain in
[ADR 0012](adr/0012-immutable-appliance-account-authority.md). It requires local
files-only NSS, the exact reviewed PAM graph/binaries and supported local-account
and password-hash forms. Kernel immutable inputs and a writer-drain barrier
protect active incarnations. Administrative account, password and policy changes
must durably revoke the whole domain first; every reseal provisions fresh
disabled incarnations and requires enrollment again. Own-user enrollment cannot
establish or repair continuity. Missing authoritative state, including a lost
volatile faillock tally after reboot, makes PIN unavailable. This restriction
does not describe general-purpose Fedora account support or authorize deployment.
M6.1's component gate is complete for this domain. See the
[component evidence](development/m6.1-account-authorities.md),
[sanitized results](../experiments/m61/results/2026-10-17-account-authorities.json) and
[administration contract](account-administration.md); the separate M7/M8/M9
integration, confinement and release gates still apply.

The current Linux broker requires `openat2`, procfs and Linux 6.5+
`SO_PEERPIDFD` support, with a system bus and logind for live session routing.
Unsupported or denied identity operations leave the PIN route unavailable;
there is no numeric-PID identity fallback. See
[ADR 0010](adr/0010-bounded-broker-and-live-peers.md).

Use a pinned stable Rust toolchain, Rust 2024 edition, a declared minimum supported Rust version, and a committed Cargo.lock. Select maintained stable dependencies at implementation time. Record exact versions, licenses, advisories, and native-library requirements; do not follow moving `latest` versions in release builds.

## 3. Required user experience

1. A user installs the Fedora package without changing authentication automatically.
2. `localpinctl doctor` explains whether TPM protection is usable and checks the desktop integration, state permissions, service availability, and recovery route.
3. Enrollment requires fresh verification of the existing account password through a trusted password-only PAM policy. Merely knowing an old PIN, controlling an unlocked user process, or having a cached client-side success flag must not authorize enrollment, reset, or backend downgrade.
4. The user chooses and confirms a six-digit PIN privately. Leading zeroes are valid. The PIN must not be provided through command-line arguments, environment variables, shell history, or normal logs.
5. A pre-activation check verifies the selected PIN and the existing full-password route. Only then can the KDE integration be enabled.
6. At the lock screen the user types the PIN and presses Enter. Do not auto-submit after the sixth character: explicit submission avoids accidental attempts and preserves the password route.
7. Full-password fallback must remain available after a wrong PIN, during PIN cooldown, when the broker is stopped, and after backend or state failures.
8. The user can inspect status, change the PIN, disable PIN unlocking, and restore the previous PAM configuration.

The stock KDE password field may continue to say “Password.” Explain this honestly rather than claiming a native KDE PIN control exists. Default integration must not patch distribution QML files. A future upstream UI integration may add a PIN/password selector, but it must use the same backend and preserve the tested stock-theme path.

Keyboard acceptance includes top-row digits, numpad with Num Lock enabled, leading zeroes, USB keyboards, dock-attached keyboards, and normal keyboard layouts. Only ASCII digits 0–9 constitute a PIN. Unicode digit lookalikes must not be accepted as equivalent digits. Password input must remain arbitrary bytes according to PAM's supported conversation representation and must not be normalized as a PIN.

## 4. Security scope and limitations

### Protected situations

- An opportunistic person with physical access to a locked desktop tries to guess its PIN.
- A different unprivileged local UID tries to query, reset, tamper with, or exhaust another user's PIN allowance.
- Requests arrive concurrently or are interrupted while state is being updated.
- The broker, client, PAM consumer, storage, or TPM becomes unavailable during authentication.
- In TPM mode, credential files are copied and the attacker tries to verify guesses without the enrolled TPM.

### Explicit limits

- Root, a compromised kernel/firmware, or a compromised desktop compositor can bypass local screen authentication. The product does not repair those trust boundaries.
- Malware already executing as the logged-in user can capture future input or interact with that user's session. UID checks and a claimed PAM service name do not prove that the caller is a genuine lock-screen window.
- A six-digit PIN has only one million possible values. Hashing does not turn it into a strong offline secret.
- Software mode provides online throttling and protected system storage, but copied verifier material remains susceptible to offline guessing. Full-disk encryption remains a separate defense.
- Hardware protection depends on the TPM implementation and platform security. Do not claim immunity to physical hardware attacks, malicious firmware, or all forms of rollback.
- Password fallback depends on the existing password authentication system. A broken global PAM stack or an expired account may also prevent password unlocking; LocalPIN must not bypass those policies.

## 5. Architecture and trust boundaries

```text
KDE screen locker, running as the session user
  -> small Rust PAM adapter: pam_localpin.so
  -> authenticated local Unix socket
  -> system broker: localpind
       -> durable per-user throttle and credential state
       -> TPM 2.0 backend OR explicitly selected software backend

localpinctl -> broker enrollment transaction
           -> isolated privileged password-PAM worker
           -> credential creation/change only after fresh password verification

Any unsuccessful PIN route -> existing KDE password PAM stack
```

The PAM adapter handles the conversation, target identity validation, bounded IPC, and return-code mapping. It must not contain TPM provisioning logic, parse arbitrary credential files, or own persistent attempt counters.

The broker owns the authoritative state, serializes attempts, enforces policy, and invokes the selected backend. It must not call `loginctl unlock-session` or issue an independent desktop-unlock command. Its successful response only permits the requesting PAM transaction to return success; KDE remains responsible for unlocking its session.

The initial broker is a tightly sandboxed system service with the privileges required for its private state and TPM access. Password verification runs in a separate short-lived privileged PAM worker, so ordinary PIN-verification handling does not load the password stack. The privilege split, service credentials, filesystem access, and capability sets must be documented and integration-tested. A refactoring into separate service users is acceptable only if it preserves these boundaries and passes the same release gates.

No setuid general-purpose CLI, shell evaluation, network listener, or arbitrary TPM-command passthrough is allowed. TPM commands use a Rust library, not shell commands carrying PINs as arguments.

## 6. Identity and IPC protocol

Use a filesystem Unix stream socket under a root-controlled runtime directory. Version 1 uses a bounded, length-prefixed binary message format with explicit message types and rejected unknown fields/versions. A request frame must be at most 4 KiB; credential/config parsing has separate limits. Do not accept file descriptors or other ancillary capabilities from clients.

The broker obtains peer UID/GID/PID through kernel-provided credentials such as `SO_PEERCRED`. A supplied username, UID, PID, executable path, or session name is never authoritative. Normal verification is permitted only for the peer's own non-root UID and an eligible local graphical session associated with that UID. Resolve session properties through logind and handle Plasma processes launched under a user manager correctly. Test multiple seats and multiple sessions; do not assume the locker always has a direct session cgroup.

Client-supplied PAM service names are defense-in-depth policy inputs, not caller attestation. A same-UID process may reproduce them. The PAM adapter additionally requires the configured screen-lock service, checks that its real/effective identity agrees with the target, and refuses use as sudo, SSH, login, or another user's authentication module.

Each connection has a fresh random request identifier and each authentication challenge a short expiry, bound to that connection and UID. Responses cannot become reusable bearer tokens. No reusable “PIN already verified” file or global session-unlocked flag is permitted.

Required message operations are `Status`, `BeginVerify`, `Verify`, `Cancel`, `BeginEnroll`, `EnrollConversation`, `CommitEnrollment`, `Disable`, and administrator-only recovery operations. Enrollment authorization is stored only in the broker/worker transaction and bound to the UID, action, proposed generation, and a maximum 60-second commit interval after password authentication. A client cannot send a Boolean claiming authentication succeeded.

Set bounded connection, read, write, queue, and backend deadlines. Initial target: connect within 250 ms and return PIN-unavailable within 2 seconds when the broker cannot serve the request. Allow up to 5 seconds for a genuine TPM attempt before falling back. Cancelling must release resources; an attempt already durably reserved remains consumed.

## 7. PAM integration and password fallback

The package ships a documented Fedora KDE adapter. Activation modifies only the verified screen-lock service, normally `/etc/pam.d/kde`. It must preserve existing account, password, and session sections and the order of the original password authentication stack. It must not edit authselect-generated `system-auth` or `password-auth`, SDDM, plasmalogin, sudo, SSH, or polkit services.

The adapter runs before the existing password stack with a control rule that short-circuits only on positive PIN success and otherwise continues to the original stack. Existing required checks that precede it must not be skipped. The installer must reject unfamiliar layouts that cannot preserve required account/authorization restrictions. KDE's actual use of PAM account management must be established per supported version; where KDE only calls authentication, the adapter must explicitly preserve supported lock/expiry eligibility checks rather than assuming a later account phase occurs.

Return behavior:

| Condition | Adapter result | Whole authentication outcome |
|---|---|---|
| Valid PIN, eligible account/session, durable throttle success | `PAM_SUCCESS` | May unlock through the configured sufficient rule |
| Wrong PIN | PIN failure/ignore according to the adapter contract | Continue to password; never treat as success |
| Empty input or non-PIN input | Skip PIN | Continue to password |
| PIN cooldown, not enrolled, disabled | `PAM_IGNORE` | Continue to password |
| Broker/TPM unavailable, timeout, corrupt state, I/O failure | `PAM_IGNORE` plus sanitized diagnostic | Continue to password |
| Target identity mismatch or unsupported service | Non-success | No PIN authorization; original service policy remains authoritative |

The implementation must distinguish “the PIN route fails closed” from “the entire PAM transaction denies password fallback.” Backend errors must never grant access and must not make an otherwise functioning password route unusable.

For the intended stock-KDE experience, the adapter captures one candidate through PAM. It tries PIN verification only for six ASCII digits. On non-success it places the candidate in PAM's authentication token using the supported PAM API, with lifetime/cleanup rules documented, so the existing password module can consume that same candidate. This avoids demanding the full password twice and permits a six-digit account password to work through the password stack even when it is not the PIN. The exact Fedora stack must be tested for token reuse; if unsupported, activation must either select a verified explicit password-selection conversation or refuse. Do not silently deploy a broken single-entry promise.

All C ABI entrypoints validate pointers/arguments, contain Rust panics, and never unwind into PAM. Use a small reviewed FFI boundary with allocator ownership matched to PAM. Sensitive data must not appear in `Debug`, panic, tracing, or error output. A process-aborting panic strategy that could kill the locker is not a substitute for containment.

## 8. Backend selection and downgrade rules

Configuration supports `auto`, `tpm2-required`, and `software` for enrollment. `auto` probes hardware safely and prefers TPM protection when the required properties are verified. If TPM is unsuitable, the CLI explains the reason and requires explicit acceptance before enrolling software mode. A package installation or first unlock must never silently make that acceptance on the user's behalf.

The enrolled backend is pinned in the credential record. After TPM enrollment, a missing, busy, reset, or replaced TPM results in password fallback, not automatic software verification. No shadow software PIN hash may be created alongside a TPM credential.

Moving between backends requires fresh password authentication, a new enrollment transaction, and a visible status change. Status must distinguish “TPM device detected,” “TPM backend usable,” and “this credential is TPM protected.” TPM hardware presence alone establishes none of the latter two facts.

## 9. TPM 2.0 backend

Use `tss-esapi` over the distribution's TPM2-TSS ESAPI libraries, with `/dev/tpmrm0` or the supported equivalent resource manager. Probe the actual TPM algorithms, authorization requirements, resource-manager access, dictionary-attack properties, and existing platform constraints. Read-only probing must not consume failed-PIN attempts.

### Credential construction

- Create a random 32-byte secret and seal it in a TPM object whose authorization depends on the PIN.
- Derive a 32-byte object authorization value from the PIN using Argon2id v19 and a random per-enrollment salt. Store salt and bounded KDF parameters, never the derived authorization value.
- Store only the TPM-protected object blobs and required nonsecret metadata. Do not store a standalone hash/verifier of the PIN or derived authorization value that permits offline guessing without the TPM.
- Use a sealed-data object and an explicitly checked attribute template. Require `fixedTPM` and `fixedParent`; ensure dictionary-attack protection is enabled (`noDA` must be clear). Validate the intended authorization path and avoid any alternative empty-auth or PCR-only bypass of the PIN.
- Use authenticated, salted sessions and parameter protection where supported to avoid exposing authorization material or unsealed data on the TPM transport. Session setup must bind to validated TPM object identities and use maintained library constructions.
- PIN success requires successful authorization/unseal of the enrolled object, validated against its recorded metadata and generation. Erase the unsealed secret immediately; never return it to the PAM adapter or CLI.

The cryptographic template, parent provisioning, authorization sessions, and attribute verification require an independent TPM-focused review before release. Record exact algorithms and templates in the implementation documentation and automated fixtures. This is not permission to invent a new cryptographic protocol.

### Provisioning and coexistence

Prefer transient objects and TPM-protected blobs so enrollment does not allocate arbitrary persistent handles or NV indexes. Use a documented reproducible parent strategy under an existing permitted hierarchy. If hierarchy authorization or platform ownership prevents provisioning, stop with an actionable explanation. Never assume permission to clear the TPM or replace somebody else's persistent object.

Do not clear the TPM, change hierarchy passwords, reset global dictionary-attack counters, or change dictionary-attack thresholds during ordinary installation, enrollment, unlock, or uninstall. TPM dictionary-attack state is shared and can affect disk-unlock or other credentials. Before real-hardware failure testing, inspect the platform's current policy and use the simulator for exhaustive negative tests.

The broker's software throttle sits in front of TPM attempts. Additionally, inspect the global dictionary-attack budget before submission and preserve a configurable safety reserve, initially two remaining failures. If the available budget is unknown, too small, or globally locked, fall back to the password instead of consuming the last attempts. Other TPM clients can race this check; document that limitation and never promise complete prevention of shared TPM lockout.

### Boot state and lifecycle

Baseline mode is machine-bound plus PIN authorization; it does not claim measured-boot enforcement. PCR binding is a separate explicit policy requiring a supported signed-update/recovery design. A changing firmware or boot measurement must not unexpectedly require disabling Secure Boot or clearing the TPM to recover the desktop.

TPM reset, motherboard replacement, parent mismatch, firmware failure, or invalidated objects makes the enrolled PIN unavailable. Recovery is full-password login and fresh enrollment. Such events never trigger an automatic backend downgrade. Suspend/resume must discard stale handles and recreate contexts safely. Do not retain unsealed secrets or authenticated TPM sessions across sleeps or successful unlocks merely to accelerate later unlocks.

## 10. Software backend and cryptographic policy

Software mode is an explicitly labeled convenience/security tradeoff. Store an Argon2id v19 verifier in the broker's protected system storage, not in a user-writable home directory. Use RustCrypto's maintained implementation; do not implement a KDF or constant-time comparison manually.

Initial enrollment parameters are 64 MiB memory, three passes, one lane, a random 16-byte salt, and a 32-byte output. Benchmark on supported hardware; parameter changes require a versioned policy and review, not unbounded user tuning. Target a typical verification cost between 100 and 500 ms without compromising the hard memory budget.

Parse PHC strings strictly before running a KDF. Version 1 accepts only the reviewed Argon2id algorithm/version, output/salt sizes, and bounded parameters; accepted memory must be 64–256 MiB, passes 3–6, and parallelism one. Oversized, unknown, or conflicting parameters disable the PIN route. Root policy may raise requirements within supported limits. Migration must not silently accept weaker parameters or allocate attacker-chosen memory amounts.

OS randomness failures abort enrollment. Secrets use zeroizing buffers, bounded copies, no plaintext persistence, and no core dumps. Attempt memory locking only as defense in depth and report its limits; do not imply it prevents every copy or swap exposure. Native TPM/PAM libraries may have their own allocations, which must be assessed separately.

## 11. Authoritative throttling and crash consistency

The same broker-managed throttle applies to both backends. The default is five submitted valid-format guesses per rolling 60-second window, followed by a five-minute PIN cooldown. Candidates outside six ASCII digits do not invoke or consume LocalPIN verification attempts. A six-digit account password is also a PIN-format candidate and may consume a LocalPIN attempt before succeeding through password fallback. The fallback remains governed by the existing password stack, including any failure accounting when a wrong PIN is forwarded as the same candidate. LocalPIN must not suppress or reset those password counters. This accounting clarification is recorded in [ADR 0001](adr/0001-pam-candidate-and-account-policy.md).

The window is open at its lower boundary: an attempt exactly 60 seconds old no
longer counts. The fifth reservation is allowed and immediately installs a full
five-minute cooldown; its successful durable completion clears that cooldown.
Mismatch, technical error, cancellation or crash retains the reservation and
cooldown. Subsequent candidates cannot invoke a backend before cooldown expiry;
a request exactly at expiry is permitted. [ADR 0005](adr/0005-policy-time-and-revocation.md)
defines the tested M2 boundaries.

For each UID and credential generation:

1. Acquire the authoritative per-user lock before deciding whether an attempt is allowed.
2. Check account/session eligibility, cooldown, backend readiness, and any TPM safety reserve.
3. Reserve and durably record an attempt before invoking the verifier or TPM. A crash after reservation therefore consumes an attempt.
4. Perform verification while preserving serialization for that UID. Other UIDs must not be blocked by a stalled request.
5. On success, durably record the success/reset before returning PIN success. An inability to persist authoritative state makes the PIN unavailable and falls back to the password.
6. On mismatch, retain the consumed attempt and persist cooldown transitions. Technical errors must not be misclassified as proof of a wrong PIN; an already reserved attempt may conservatively remain consumed.

Use a fixed, bounded on-disk state representation with atomic replacement, file and directory synchronization, and lock files whose inode is never replaced during use. Limit one broker instance through the service/socket ownership and process locking; in-memory mutexes alone do not establish cross-process safety.

Persist the boot identifier, bounded recent-attempt timestamps, cooldown origin and deadline, generation, and state version. Validate the exact checked cooldown interval even after recent timestamps are pruned. Within a boot use a monotonic clock that includes suspend time. On boot-ID change discard incomparable timestamps and durably impose a fresh full cooldown whenever persisted recent attempts, an active cooldown or an unresolved reservation exist. This includes recent attempts below the fifth-attempt threshold and prevents cheap reboot resets. Recovery is committed once per new boot. Clock rollback, malformed timestamps, missing required throttle state, or corruption must not reset the budget to unlimited attempts. Deliberate root/disk-snapshot rollback remains outside software-mode guarantees; TPM mode retains its independent hardware defense.

Unauthenticated traffic must have global resource limits as well: at most one in-flight verification per UID, 32 concurrent connections, bounded queues, and an initial global KDF memory budget of 256 MiB. These limits may be raised only with measured deployment evidence. A caller cannot select expensive KDF work factors. Malformed frames must be rejected cheaply and must not charge another UID's budget.

## 12. Files, configuration, and transactions

Proposed layout:

| Path | Purpose and permissions |
|---|---|
| `/etc/localpin/config.toml` | Root-owned policy, mode 0644, no secrets |
| `/var/lib/localpin/` | Broker-owned privileged state, no desktop-user write access, mode 0700 |
| `/var/lib/localpin/users/<uid>/` | Credential generations, throttle, locks; directories 0700, files 0600 |
| `/run/localpin/` | Root-controlled runtime directory and socket |
| `/usr/lib64/security/pam_localpin.so` | Distribution-appropriate PAM module location |
| `/usr/bin/localpinctl` | Normal-user CLI; no setuid bit |
| `/usr/libexec/localpin/` | Broker and narrowly scoped privileged worker executables |
| `/var/lib/localpin/integration-backups/` | Original PAM files, digests, package/version metadata |

Use numeric UIDs for internal paths, never raw usernames. Detect UID reuse and require re-enrollment when the account identity no longer matches the recorded local-account identity. Renaming an account must not accidentally authorize a new account with an unrelated UID.

The identity must include an opaque incarnation from the supported trusted
lifecycle authority. Recheck it at enrollment and verification finalization;
unavailable/unsupported evidence refuses PIN. The M2 envelope is a development
contract, not a frozen permanent identity schema. Permanent account records and
production activation remain blocked until the authority's deletion/recreation,
crash and concurrency guarantees have evidence.

Implementation note, 2026-10-17: the M6.1 `LPACCT02` lifecycle registry records
the sealed-domain proof defined by ADR 0012. Earlier experimental registry state
is refused and privileged recovery creates fresh identities; it never adopts
development incarnations. Permanent records are limited to the domain covered
by the M6.1 evidence report. This does not lift the lifecycle requirement for
other accounts or the separate production activation gates.

Open relative to trusted directory descriptors using no-follow/beneath restrictions where available. Reject symlinks, unsafe ownership/modes, unexpected file types, and oversized records. Do not rely on an `lstat` followed by an unrestricted `open`. Credential records are bounded to 64 KiB; configuration to 64 KiB; throttle records to 16 KiB. Unknown versions fail the PIN route safely.

Enrollment and rotation create a staged generation, verify it, synchronize it, then atomically switch the authoritative generation pointer. There must never be a state where the old PIN is deleted before a valid new record is committed. A crash leaves either the previous committed generation or the new committed one, with deterministic cleanup. Keep no more than one recoverable previous generation for transaction recovery; it must not remain an alternative accepted PIN after commit.

The enrollment record includes schema version, UID/account identity, generation, backend, policy/KDF parameters, salt, TPM public/private blobs and validated attributes when applicable, and nonsecret creation metadata. No full password, plaintext PIN, derived TPM authorization, or unsealed secret is persisted.

## 13. CLI and operational behavior

Required commands:

```text
localpinctl doctor [--json]
localpinctl status [--json]
localpinctl enroll --backend auto|tpm2-required|software
localpinctl change
localpinctl disable
localpinctl integration enable|disable|status
localpinctl recover --user <account>       # administrator, password/recovery context
```

Own-user status is available without disclosing another user's enrollment details. JSON output is versioned and contains only nonsecret status. Status includes configured/enrolled backend, current availability, cooldown, integration state, and actionable failure reason. Public-facing messages should explain what the user can do; internal TPM codes belong only in sanitized diagnostics.

Changing, resetting, disabling, recovery, and backend migration require trusted authorization. Default own-user changes use fresh existing-password PAM verification. Administrators can perform explicitly identified recovery with system administrative authority; no old PIN is required and no PIN is revealed. A normal user cannot clear durable cooldown files or call an unauthenticated reset endpoint.

Interactive input requires a real terminal or an explicitly implemented protected desktop conversation. Reject insecure noninteractive PIN input. Offer no `--pin`, password environment variable, or general plaintext stdin enrollment option in release builds. Simulator/test secret injection is compiled only into test utilities.

Cancellation before commit leaves the existing enrollment/integration unchanged. CLI output must distinguish “installed,” “enrolled,” “tested,” and “active.” It must never say setup completed merely because files were copied.

## 14. Service hardening and SELinux

Ship systemd socket/service units, tmpfiles configuration if needed, and a Fedora SELinux policy. Enforcing-mode operation is a release requirement. Never recommend disabling SELinux or using broad allow-all policy generation to make authentication work.

The broker must have no IP networking; restrict address families to the required local mechanisms. Use a private temporary directory, strict system filesystem protection, explicit writable state/runtime paths, protected kernel/module/control-group interfaces, no core dumps, resource limits, and the smallest tested capability/device allowlist. Restrict TPM device access to the resource-manager interface where available. The PAM worker needs a separately reviewed sandbox that preserves legitimate password/account checks and failure accounting; blindly inheriting broker restrictions must not break PAM helpers.

The supported policy must allow KDE's unprivileged locker to contact the broker without granting it direct credential-file or TPM access. Test DAC and SELinux denial paths. Unexpected denials make PIN verification unavailable and preserve password fallback, while diagnostics identify the relevant failure without leaking secrets.

## 15. Packaging, installation, upgrade, rollback

Deliver signed Fedora RPM packages for the supported architectures. Installation starts no enrollment and performs no broad authentication rewrites. Explicit activation must inventory PAM files, verify hashes/layout, create a root-protected backup, test both routes, and apply the smallest known change atomically. Record the package version, original digest, installed block digest, and timestamp.

Do not stack `pam_localpin` and the temporary `pam_pinlock` installation. Migration requires fresh enrollment into LocalPIN, verified password fallback, disabling the old module's KDE line, and only then activating the new adapter. Do not import the old PIN hash into TPM mode or silently carry forward weaker software parameters.

Upgrades preserve committed enrollment and throttle state. State migrations are versioned, transactional, tested in both directions where supported, and run before enabling the new code. Unsupported downgrades must leave the password route usable and explain how to disable integration. Kernel, Plasma, PAM, and authselect upgrades are part of the compatibility matrix.

Uninstall/rollback must remove LocalPIN's integration before removing the module or broker. If the PAM file changed after activation, remove only the exact owned block or stop for an explicit reviewed merge; do not overwrite unrelated administrator/package updates. Preserve protected backups until verified restoration. A broken broker or missing module must not cause a blank-password path.

Provide a short, documented text-console recovery command. Test recovery from a failed graphical unlock without rebooting or reinstalling the OS. Keyboard shortcuts vary by system; document the verified console/return shortcuts for the supported Fedora configuration rather than asserting a universal function key.

Disabling the product revokes verification immediately. TPM objects created by the product are cleaned up without touching unrelated objects or global policy. Removing disk records cannot promise forensic erasure of SSD snapshots/backups, and a copied old TPM blob may remain usable on the original TPM by a privileged attacker; do not overstate revocation guarantees.

## 16. Observability and privacy

Use structured local journal events for enrollment changes, backend availability changes, cooldown transitions, integration changes, and sanitized failures. Rate-limit repeated diagnostics. Never log PINs, full passwords, KDF outputs, credential verifiers, TPM authorization values, raw IPC frames, unsealed data, or user-keystroke traces.

Success logging is configurable and defaults to minimal operational information. No telemetry or remote service is required. A support-bundle command, if added, must redact identifiers and secret-bearing records by construction and display the exact export contents before saving.

## 17. Rust workspace and dependency requirements

Suggested workspace boundaries:

```text
crates/localpin-core/       policy, bounded records, state machines, typed outcomes
crates/localpin-protocol/   bounded IPC messages and clients
crates/localpin-storage/    protected files, atomic commits, locking, recovery
crates/localpin-tpm/        reviewed tss-esapi adapter and object templates
crates/localpin-software/   RustCrypto Argon2id backend
crates/localpin-pam/        minimal cdylib and PAM conversation boundary
crates/localpind/           broker and worker supervision
crates/localpin-auth/       privileged enrollment password-PAM worker
crates/localpinctl/         CLI and interactive enrollment
tests/                     integration, simulator, fault injection, regression
packaging/fedora/          RPM, systemd, SELinux, integration management
docs/                      threat model, admin/recovery, formats, security claims
```

Prefer synchronous bounded processing where it keeps authentication easier to review. An async runtime, database, web UI, or general plugin system is not required. If introduced, each must justify its additional attack surface.

Use established crates for Argon2id, zeroization/secrets, OS randomness, serialization, system calls, and TPM access. Evaluate PAM bindings such as `pam-bindings` rather than assuming their safety or maintenance status. All project-owned `unsafe` code must be isolated, documented with invariants, and reviewed; native dependency boundaries remain part of the audit scope.

CI must run formatting, clippy with an agreed deny policy, tests, dependency advisory/license checks, and reproducible locked builds. Maintain an SBOM, dependency update process, security policy, private vulnerability reporting route, and release changelog. FFI wrappers and backend dependencies need review beyond an advisory scanner's result.

## 18. Verification and acceptance matrix

| Area | Required evidence before release |
|---|---|
| PIN behavior | Correct/wrong/empty input, leading zeroes, malformed/Unicode digits, six-digit account-password fallback, no auto-submit |
| Password fallback | Success after PIN mismatch, PIN cooldown, daemon stop/crash, module load error, TPM unavailable/reset, malformed state, read-only/full disk |
| PAM/account policy | Real KDE flow and isolated PAM tests; locked/expired users, wrong target, unsupported service, existing required checks and failure counters preserved |
| Throttling | Concurrent clients/processes, reservation crash, success-write failure, broker restart, suspend, clock changes, reboot, corrupted/missing state; no unreserved verification |
| Storage | Symlink/hardlink/type/permission attacks, oversized records, interrupted rename/fsync, generation rollback, UID reuse, migration failures |
| IPC | Cross-UID rejection, spoofed target/service fields, replayed responses, dropped/partial/oversized frames, timeout, cancellation, queue/memory exhaustion |
| TPM simulator | Correct object attributes, no alternate auth bypass, wrong-PIN DA effect, exhausted/shared budget, blob transfer to different TPM, reset/replacement, stale contexts, transport failures |
| Software mode | Fixed test vectors, bounded PHC/KDF parameters, random failure, explicit backend selection, no silent downgrade |
| Desktop hardware | External screen/keyboard, closed lid, dock reconnect, Num Lock, suspend/resume, theme variations, multiple sessions/seats |
| Packaging | Clean install/enable/disable/uninstall, upgrade/downgrade, changed PAM file, backup/restore, module removal, SELinux enforcing |
| Privacy | Logs/support bundles/process arguments/environment/core settings contain no secrets; zeroization/allocator boundaries reviewed |

Use `swtpm` or an equivalent TPM simulator for destructive/failure-budget tests; never run exhaustive bad-PIN tests against the user's production TPM. Fuzz IPC, config/state parsers, PHC validation, and PAM argument parsing. Use property tests/model checking for throttle and generation state machines. Run Miri/sanitizers where applicable, especially around project-owned FFI; they complement rather than replace integration tests.

Authentication tests must distinguish test-environment restrictions from product errors. In this session, Codex's syscall sandbox caused even PAM's permit-only baseline to return a system error; the same isolated-home test succeeded outside that sandbox. Every PAM integration harness therefore includes a known permit/deny baseline and reports infrastructure failures separately.

## 19. Performance and availability targets

Target warm PIN verification at p95 under one second on supported hardware, including software KDF or TPM authorization. No unavailable backend should hold the password route longer than its documented hard deadline. Enrollment may take longer and must show progress without exposing secrets.

The broker must not retain PINs, unsealed secrets, or successful authorization caches between attempts. Avoid optimistic availability shortcuts that bypass durable counters. Measure CPU, memory, disk synchronization, suspend/resume behavior, and TPM latency on actual target hardware before setting release claims.

## 20. Production completion gates

The product is complete only when all of the following are delivered:

1. Both TPM and explicit software backends with pinned enrollment mode and correct downgrade behavior.
2. A bounded Rust broker, PAM adapter, enrollment worker, and usable CLI with the stated privilege boundaries.
3. Durable, race-safe throttling and transactional credential changes with fault-injection evidence.
4. Real Fedora KDE PIN unlocking and tested full-password fallback across the entire failure matrix.
5. RPM packaging, enforcing SELinux policy, systemd hardening, and upgrade/rollback/recovery tooling.
6. Documented threat model, security limitations, object templates, record formats, protocols, operational instructions, and dependency inventory.
7. Review of the TPM authorization design, PAM/FFI boundary, privilege separation, cryptography use, and installer by someone independent of the implementation author before describing the release as production-ready.
8. A staged hardware rollout with recovery verified before the user's everyday lock screen depends on it.

An implementation that only accepts a PIN in a demo PAM client, only works with SELinux disabled, resets its counter on restart, silently falls back from TPM to a hash, or lacks a tested password escape route does not satisfy this specification.

## 21. Delivery sequence

Implement the core policy/state machine and storage transaction model first; add simulator-backed TPM and software backends; integrate the bounded broker/protocol; add PAM/CLI/enrollment authorization; then complete Fedora packaging and the real desktop matrix. Perform independent review, address findings, and ship a versioned release with recovery documentation. All phases serve the same full-production requirements above.

The immediate convenience setup using third-party `pam_pinlock` is a separate temporary deployment. It is not the Rust product, is not TPM backed, and does not inherit the guarantees specified here. The future Rust project must migrate away from it through the controlled process in section 15.

## 22. Primary implementation references

These links identify API and platform references, not endorsements or evidence that the future project has been audited. Revalidate versions and behavior when implementation begins.

- [KDE screen-lock PAM architecture](https://github.com/KDE/kscreenlocker/blob/master/README.pam): service selection and the locker's PAM integration contract.
- [Linux-PAM authentication API](https://man7.org/linux/man-pages/man3/pam_authenticate.3.html): authentication calls and return behavior.
- [Linux Unix-domain sockets](https://man7.org/linux/man-pages/man7/unix.7.html): kernel-provided peer credentials and local transport semantics.
- [Rust TPM ESAPI bindings](https://github.com/parallaxsecond/rust-tss-esapi): Rust access to TPM2-TSS ESAPI.
- [TPM object creation](https://tpm2-tools.readthedocs.io/en/latest/man/tpm2_create.1/), [unseal](https://tpm2-tools.readthedocs.io/en/latest/man/tpm2_unseal.1/), and [dictionary-attack policy](https://tpm2-tools.readthedocs.io/en/latest/man/tpm2_dictionarylockout.1/): platform object/authorization behavior; production code uses library calls.
- [RustCrypto Argon2](https://docs.rs/argon2/latest/argon2/): maintained hashing/KDF APIs; verification may use parameters from stored PHC data, so application-level bounds are required.
- [Rust PAM bindings](https://docs.rs/pam-bindings/latest/pam/): a candidate adapter dependency requiring its own review.
- [Current temporary pam_pinlock source](https://github.com/saltnpepper97/pam_pinlock): migration context only; inspected commit `919f6892a48809616222b4d481775d30591fab0c`.
