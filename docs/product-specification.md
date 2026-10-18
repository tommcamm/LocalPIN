# LocalPIN product specification

**Specification version:** 1.8

**Date:** 2026-10-18

**Status:** Targeted desktop, guided-setup and setup-managed accounting cases passed on Fedora KDE 44 x86_64 with SELinux enforcing and a private TPM emulator; the [M8.1](development/m8.1-desktop-compatibility.md), [M8.2](development/m8.2-installed-acceptance.md) and [M8.3](development/m8.3-accounting-maintenance.md) reports identify each case's tested build and limits. Historical M6.1–M8 evidence retains its earlier appliance scope. GUI/DBus AccountsService, full old-TPM-credential migration and physical hardware remain unvalidated. M9 independent review and release gates remain open; hosted CI results are separate from local and installed evidence.
**Initial deployment:** Fedora Linux, KDE Plasma, local user accounts.  
**Working component names:** `pam_localpin.so`, `localpind`, `localpin` (CLI; `localpinctl` compatibility name).

## 1. Product objective

Provide a convenient numeric PIN or optional passcode for unlocking an already running local graphical session. The primary user operates a laptop with its lid closed, an external monitor, and an ordinary external keyboard. The workflow must require no fingerprint reader, camera, phone, network connection, or additional security token.

The production product must preserve the existing full-password route and normal desktop locking behavior. Initial graphical login, virtual-terminal login, SSH, sudo, polkit, disk encryption, and password managers must retain their existing authentication requirements. Installation must not replace an account password or repurpose the disk-encryption passphrase.

Rust is an implementation choice that helps limit memory-safety problems; it does not establish a security guarantee. Security claims must describe the implemented backend, threat model, tests, and review status. A newly written module must not be advertised as safer than an existing product without supporting evidence.

This document defines the complete intended product, including installation, integration, recovery, maintenance, and release requirements. Development milestones are implementation steps toward that product, not permission to ship an incomplete authentication prototype.

## 2. Deployment baseline and support policy

The inspected machine reported Fedora 44 KDE, Plasma/kscreenlocker 6.7.5, Rust 1.95.0, and a TPM 2.0 entry in sysfs. TPM device access and suitability were not established. SELinux was disabled on this particular machine; the product must nevertheless support Fedora with SELinux enforcing.

The initial supported platform is Fedora KDE with local, non-root users and a verified screen-lock PAM service. Target x86_64 initially; aarch64 support requires equivalent CI, packages, and hardware integration testing. Network identities, systemd-homed accounts, non-KDE desktops, immutable Fedora variants, and other distributions must be reported as unsupported until adapters and tests exist. Unsupported configurations must not receive guessed PAM edits.

Account support requires a trusted lifecycle authority that distinguishes
account incarnations and serializes account mutation with authorization delivery.
UID/name/home equality is insufficient; accounts without privileged provisioning
remain unavailable. [ADR 0017](adr/0017-shadow-record-account-authority.md)
implements the local-files contract with a random root-owned marker in each
managed shadow record, an independent random 128-bit incarnation, and a retained
shared OFD lock on the native `/etc/.pwd.lock`. Ordinary account tools use the
conflicting exclusive lock. Deletion/recreation removes the marker, while normal
password updates and unrelated service-account creation can preserve it.
Direct root editing outside native locking, copying markers into recreated
accounts and restoring authority snapshots are deliberate trusted-administrator
changes requiring prior revocation and fresh provisioning.

M8.1 targets ordinary Fedora KDE 44 x86_64 with SELinux enforcing and stock
local `files systemd` NSS layouts. It sets no new immutable flags, pins no
filesystem type or individual PAM build hashes, and loads distribution-owned
Linux-PAM through its stable SONAME. PAM account restrictions, trusted native
metadata and unchanged operation inputs remain fail-closed checks. The reviewed
[KDE adapter](adr/0018-kde-native-update-compatibility.md) owns separate password
and fingerprint authentication substacks while preserving the other verified
service sections and native accounting. Unknown graphs remain unsupported.

The installed route requires reviewed persistent `/var/lib/faillock` accounting;
its offline transition preserves native counters. Eligibility never recreates
missing persistent state or repairs account authority. `LPACCT01`/`LPACCT02`
migration durably revokes before fresh provisioning/enrollment. It removes
legacy immutable flags only with valid captured old-registry proof; unknown
administrator hardening remains intact and unavailable.
[Account administration](account-administration.md) and
[integration administration](integration-administration.md) define these steps.
[ADR 0006](adr/0006-account-incarnation-support.md)'s lifecycle security intent
continues under ADR 0017's explicit local-tool trust contract.

The earlier [M6.1](development/m6.1-account-authorities.md),
[M7](development/m7-pam-integration.md) and
[M8](development/m8-packaging-recovery.md) acceptance applies to their historical
immutable appliance. The [M8.1 report](development/m8.1-desktop-compatibility.md)
records targeted account-tool, KDE/fingerprint, SELinux, RPM, reboot and actual
[DNF upgrade](../experiments/m81/results/dnf-upgrade.json) cases that passed.
Native PAM/authselect runtime replacement was exercised by
[real reinstallation](../experiments/m81/results/native-pam-reinstall.json).
Final source checks and the compatible `.5` → `.6` installed RPM upgrade also
passed; earlier cases retain their individual recorded build scope.
GUI/DBus AccountsService and full old-TPM-credential migration were not exercised;
physical sensors/TPMs, alternate filesystems and the full hardware matrix retain
separate gates. Source/model checks and operator attestations are not substitutes
for those missing observations or independent M9 review.

The current Linux broker requires `openat2`, procfs and Linux 6.5+
`SO_PEERPIDFD` support, with a system bus and logind for live session routing.
Unsupported or denied identity operations leave the PIN route unavailable;
there is no numeric-PID identity fallback. See
[ADR 0010](adr/0010-bounded-broker-and-live-peers.md).

Use a pinned stable Rust toolchain, Rust 2024 edition, a declared minimum supported Rust version, and a committed Cargo.lock. Select maintained stable dependencies at implementation time. Record exact versions, licenses, advisories, and native-library requirements; do not follow moving `latest` versions in release builds.

## 3. Required user experience

1. A user verifies and installs the Fedora RPM without changing authentication automatically, then runs `localpin setup` as their normal user in a foreground KDE terminal. The guide checks prerequisites, previews confirmed preparation, guides enrollment and trial/recovery tests, and requests explicit activation. A supported fresh installation can explicitly approve setup-managed offline accounting maintenance, including session termination and automatic setup resumption after password login. Unknown or interrupted state requires administrator recovery; setup never copies live tallies or resets counters.
2. `localpin` prints a concise command overview and exits without interaction; `localpin menu` explicitly opens the compact numbered menu. `localpin doctor` reports known backend/service availability and the desktop gate, and explains required recovery checks. Passive status does not perform desktop or password recovery tests or establish unprobed TPM usability.
3. Enrollment requires fresh verification of the existing account password through a trusted password-only PAM policy. Merely knowing an old PIN, controlling an unlocked user process, or having a cached client-side success flag must not authorize enrollment, reset, or backend downgrade.
4. The user chooses Numeric PIN or Passcode, then enters and confirms any permitted length under the policy below. Leading zeroes and passcode spaces are preserved. Secrets must not be provided through command-line arguments, environment variables, shell history, or normal logs.
5. Root preparation leaves the desktop gate closed. A bounded current-boot trial permits actual PIN, full-password and console-recovery tests. The administrator explicitly attests those tests before final activation; enrollment alone never opens the gate.
6. At the lock screen the user types the credential and presses Enter. Never auto-submit at an expected length: explicit submission avoids accidental attempts and preserves the password route.
7. Full-password fallback must remain available after a wrong PIN, during PIN cooldown, when the broker is stopped, and after backend or state failures.
8. The user can inspect status, change the PIN, disable PIN unlocking, and restore the previous PAM configuration.

The credential policy is:

| Credential | TPM protection | Software protection | Recommendation |
| --- | --- | --- | --- |
| Numeric PIN | 4–16 ASCII digits | 8–16 ASCII digits | 6 with TPM; 10 with software |
| Optional passcode | 8–64 printable ASCII characters | 8–64 printable ASCII characters | Suggest 12+ characters |

Recommendations never prefill or generate a secret. Numeric PINs accept only
`0`–`9`; passcodes accept bytes `0x20`–`0x7e`, including leading, trailing and
repeated spaces, without trimming, normalization or case folding. An explicitly
selected passcode may contain only digits. No uppercase/symbol composition rule
is required. Existing version-1 six-digit software credentials keep working;
status and management recommend replacement. Every new enrollment, change or
backend migration must satisfy the current policy for its target backend.

Setup, enrollment, change and migration share one terminal form: show protection,
select type, show limits and recommendation, collect and confirm a new secret,
resolve local errors and advisory warnings, obtain mutation confirmation, then
open a fresh connection for account-password verification and commit immediately
after success. Enrollment defaults to Numeric PIN; changes and migration default
to the existing type. There is no length picker. Show one `*` per new-credential
character and keep account-password entry fully hidden. Preserve editing,
cancellation, terminal restoration and plain `NO_COLOR`/`TERM=dumb` output.
Preparation, including retries, expires after five minutes; the existing
password deadline and strictly less-than-60-second authorization grant remain.
Erase prepared secrets on completion, cancellation or failure; authentication
retries require new preparation.

Predictable-choice detection is advisory, local to the terminal, and requires
an explicit **Use anyway** override that defaults to re-entry. Warn for repeated
characters, complete repeated blocks of one through four characters,
ascending/descending digit sequences wrapping modulo ten, and exact
ASCII-case-insensitive matches in the bundled list: `password`, `password1`,
`password123`, `qwerty123`, `qwertyuiop`, `letmein123`, `welcome1`, `iloveyou`,
`changeme`, `localpin`. Never print the entered value or an entropy score. The
broker independently enforces format and length without accepting a client
claim that validation succeeded. [ADR 0021](adr/0021-flexible-credentials.md)
records this contract and its compatibility limits.

Disabling only an own-user PIN leaves system integration active. Guided setup
must offer fresh enrollment in that state without repeating system preparation
or activation. Integration and direct native account administration share one
transaction lock before account-registry/native-password/storage locks, so a
concurrent account provisioner cannot invalidate setup's single-account scope
check before a mutation.

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
- Short numeric PINs have limited entropy: a six-digit PIN has only one million possible values. Predictable passcodes may also be weak. Hashing does not turn them into strong offline secrets.
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

localpin (localpinctl) -> broker enrollment transaction
           -> isolated privileged password-PAM worker
           -> credential creation/change only after fresh password verification

Any unsuccessful PIN route -> existing KDE password PAM stack
```

The PAM adapter handles the conversation, target identity validation, bounded IPC, and return-code mapping. It must not contain TPM provisioning logic, parse arbitrary credential files, or own persistent attempt counters.

The broker owns the authoritative state, serializes attempts, enforces policy, and invokes the selected backend. It must not call `loginctl unlock-session` or issue an independent desktop-unlock command. Its successful response only permits the requesting PAM transaction to return success; KDE remains responsible for unlocking its session.

The initial broker is a tightly sandboxed system service with the privileges required for its private state and TPM access. Password verification runs in a separate short-lived privileged PAM worker, so ordinary PIN-verification handling does not load the password stack. The privilege split, service credentials, filesystem access, and capability sets must be documented and integration-tested. A refactoring into separate service users is acceptable only if it preserves these boundaries and passes the same release gates.

No setuid general-purpose CLI, shell evaluation, network listener, or arbitrary TPM-command passthrough is allowed. TPM commands use a Rust library, not shell commands carrying PINs as arguments.

## 6. Identity and IPC protocol

Use a filesystem Unix stream socket under a root-controlled runtime directory. Version 2 uses a bounded, length-prefixed binary message format with explicit message types and rejected unknown fields/versions. A request frame must be at most 4 KiB; credential/config parsing has separate limits. Do not accept file descriptors or other ancillary capabilities from clients.

The broker obtains peer UID/GID/PID through kernel-provided credentials such as `SO_PEERCRED`. A supplied username, UID, PID, executable path, or session name is never authoritative. Normal verification is permitted only for the peer's own non-root UID and an eligible local graphical session associated with that UID. Resolve session properties through logind and handle Plasma processes launched under a user manager correctly. Test multiple seats and multiple sessions; do not assume the locker always has a direct session cgroup.

Client-supplied PAM service names are defense-in-depth policy inputs, not caller attestation. A same-UID process may reproduce them. The PAM adapter additionally requires the configured screen-lock service, checks that its real/effective identity agrees with the target, and refuses use as sudo, SSH, login, or another user's authentication module.

Each connection has a fresh random request identifier and each authentication challenge a short expiry, bound to that connection, account incarnation, committed generation, backend and credential profile. Before reserving an attempt, recheck these bindings under the user lock; any intervening credential change invalidates the challenge. Responses cannot become reusable bearer tokens. No reusable “PIN already verified” file or global session-unlocked flag is permitted.

Required message operations are `Status`, `BeginVerify`, `Verify`, `Cancel`, `BeginEnroll`, `EnrollConversation`, `CommitEnrollment`, `Disable`, and administrator-only recovery operations. Enrollment authorization is stored only in the broker/worker transaction and bound to the UID, action, proposed generation, and a maximum 60-second commit interval after password authentication. A client cannot send a Boolean claiming authentication succeeded.

Public and private worker protocols version variable-length credential inputs, capped at 64 bytes. Reject mixed protocol versions before sending secrets; the PAM adapter continues through password fallback and the CLI explains that components must be updated. Preserve the separate password-conversation limits.

Set bounded connection, read, write, queue, and backend deadlines. Initial target: connect within 250 ms and return PIN-unavailable within 2 seconds when the broker cannot serve the request. Allow up to 5 seconds for a genuine TPM attempt before falling back. Cancelling must release resources; an attempt already durably reserved remains consumed.

## 7. PAM integration and password fallback

The package ships a documented Fedora KDE adapter. Activation modifies only the verified KDE screen-lock services and their LocalPIN-owned authentication substacks. It must preserve existing account, password, and session sections. Replacing the original authentication substack requires an explicit reviewed compatibility decision that preserves its required factor/accounting behavior, protected backups, and installed acceptance for the password and fingerprint routes. It must not edit authselect-generated `system-auth` or `password-auth`, SDDM, plasmalogin, sudo, SSH, or polkit services.

The adapter runs before the reviewed password substack with a control rule that short-circuits only on positive PIN success and otherwise continues to password authentication. Existing required checks that precede it must not be skipped. The installer must reject unfamiliar layouts that cannot preserve required account/authorization restrictions. KDE's actual use of PAM account management must be established per supported version; where KDE only calls authentication, the adapter must explicitly preserve supported lock/expiry eligibility checks rather than assuming a later account phase occurs.

Return behavior:

| Condition | Adapter result | Whole authentication outcome |
|---|---|---|
| Valid PIN, eligible account/session, durable throttle success | `PAM_SUCCESS` | May unlock through the configured sufficient rule |
| Wrong PIN | PIN failure/ignore according to the adapter contract | Continue to password; never treat as success |
| Empty input or input outside the enrolled profile | Skip LocalPIN | Continue to password |
| PIN cooldown, not enrolled, disabled | `PAM_IGNORE` | Continue to password |
| Broker/TPM unavailable, timeout, corrupt state, I/O failure | `PAM_IGNORE` plus sanitized diagnostic | Continue to password |
| Target identity mismatch or unsupported service | Non-success | No PIN authorization; original service policy remains authoritative |

The implementation must distinguish “the PIN route fails closed” from “the entire PAM transaction denies password fallback.” Backend errors must never grant access and must not make an otherwise functioning password route unusable.

For the intended stock-KDE experience, the adapter captures one candidate through PAM. It obtains the enrolled public profile in its verification challenge and tries LocalPIN only when the candidate has that exact length and format. On non-success it places the candidate in PAM's authentication token using the supported PAM API, with lifetime/cleanup rules documented, so the existing password module can consume that same candidate. Preserve the original candidate byte-for-byte for fallback. This avoids demanding the full password twice and permits an account password matching the credential profile to work through the password stack even when it is not the LocalPIN credential. The exact Fedora stack must be tested for token reuse; if unsupported, activation must either select a verified explicit password-selection conversation or refuse. Do not silently deploy a broken single-entry promise.

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

The same broker-managed throttle applies to both backends. The default is five submitted valid-format guesses per rolling 60-second window, followed by a five-minute PIN cooldown. Candidates outside the enrolled exact length/format do not invoke or consume LocalPIN verification attempts. An account password matching the enrolled profile may consume a LocalPIN attempt before succeeding through password fallback; TPM-protected matches can also consume the shared TPM dictionary-attack allowance. Setup must explain this overlap. The fallback remains governed by the existing password stack, including any failure accounting when a wrong PIN is forwarded as the same candidate. LocalPIN must not suppress or reset those password counters. This accounting clarification is recorded in [ADR 0001](adr/0001-pam-candidate-and-account-policy.md).

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
| `/usr/bin/localpin` / `/usr/bin/localpinctl` | Primary CLI alias / shared normal-user executable; no setuid bit |
| `/usr/libexec/localpin/` | Broker and narrowly scoped privileged worker executables |
| `/var/lib/localpin-integration/control/` | Installed M8 root-only original PAM files, manifests and package/version metadata, mode 0700 |
| `/var/lib/localpin-integration/gate` | Root-written public desktop gate, mode 0644 beneath a mode-0755 directory |
| `/var/lib/localpin-accounts/` | Root-only versioned lifecycle registry and permanent serialization lock, mode 0700 |

Use numeric UIDs for internal paths, never raw usernames. Detect UID reuse and require re-enrollment when the account identity no longer matches the recorded local-account identity. Renaming an account must not accidentally authorize a new account with an unrelated UID.

The identity must include an opaque incarnation from the supported trusted
lifecycle authority. Recheck it at enrollment and verification finalization;
unavailable/unsupported evidence refuses PIN. The M2 envelope is a development
contract, not a frozen permanent identity schema. Permanent account records and
production activation remain blocked until the authority's deletion/recreation,
crash and concurrency guarantees have evidence.

Implementation note, 2026-10-17: current `LPACCT03` binds UID/login and a
root shadow-record marker to an independent random incarnation. Native locking
is retained through actual authorization delivery. The earlier `LPACCT01` and
`LPACCT02` formats are refused; privileged recovery rotates both identities and
quarantines old credential/throttle state. New publication requires durable
shadow and disabled baselines before the active registry. Recorded
[M8.1 account evidence](../experiments/m81/results/account-tools.json) and
[installed-helper flag tests](../experiments/m81/results/legacy-flags.json)
validate the targeted lifecycle cases; the report preserves untested paths and
independent review limits. They do not authorize a production claim.

Open relative to trusted directory descriptors using no-follow/beneath restrictions where available. Reject symlinks, unsafe ownership/modes, unexpected file types, and oversized records. Do not rely on an `lstat` followed by an unrestricted `open`. Credential records are bounded to 64 KiB; configuration to 64 KiB; throttle records to 16 KiB. Unknown versions fail the PIN route safely.

Enrollment and rotation create a staged generation, verify it, synchronize it, then atomically switch the authoritative generation pointer. There must never be a state where the old PIN is deleted before a valid new record is committed. A crash leaves either the previous committed generation or the new committed one, with deterministic cleanup. Keep no more than one recoverable previous generation for transaction recovery; it must not remain an alternative accepted PIN after commit.

Credential envelope version 2 adds explicit kind, exact length and credential-policy version to the existing UID/account identity, generation, backend and opaque backend payload. Decode version 1 as legacy six-digit numeric metadata and preserve its original bytes; all new mutations write version 2. Unknown envelope/policy versions fail closed. Configuration, active-pointer and throttle formats remain unchanged. Backend payloads retain reviewed KDF parameters, salt and TPM public/private blobs/attributes where applicable. No full password, plaintext PIN, derived TPM authorization, or unsealed secret is persisted.

## 13. CLI and operational behavior

Required commands (`localpinctl` remains compatible):

```text
localpin                                      # concise help; no interaction or broker access
localpin menu                                 # explicit interactive menu
localpin setup
localpin doctor [--json]
localpin status [--json]
localpin enroll --backend auto|tpm2-required|software
localpin change
localpin disable
localpin migrate --backend tpm2-required|software
localpin integration enable|disable|status
localpin recover --user <account>             # already-root recovery context
localpin help [command [subcommand]]
localpin completions bash|zsh|fish
localpin --help | -h
localpin --version | -V
```

Guided setup follows [ADR 0019](adr/0019-guided-setup-orchestration.md). It runs
as the current owner, with no setuid mode. It invokes only a closed set of fixed
packaged integration operations through absolute sudo with closed arguments,
a controlled environment and no shell. Sudo owns its administrator-password
prompt; credential secrets stay in the existing broker/private-input flow.
The helper's read-only, versioned `setup-status --uid N` report supplies bounded
nonsecret readiness/resume state. Wizard mutations carry `--setup-uid N` and
validate single-account integration and registry scope inside the root
transaction. Test attestation and activation also carry `--setup-trial` with the
opaque equality reference for the trial covered by the operator's confirmations.
The root transaction rechecks a live trial, current enrollment and exact trial
reference; the reference is not authorization. Multiuser, incomplete, suspended,
legacy or corrupt state requires manual administration.

Setup derives resume decisions from authoritative state, preserves healthy
active installations, and never automatically repeats preparation. It reuses
only a still-valid current-boot trial; an expired or enrollment-changed trial
requires repeated tests. Console recovery remains an actual administrator
console rehearsal and revokes enrollment; rerunning setup requires preparation,
enrollment and final trial tests before explicit attestation and activation.
No user-owned progress checkpoint can establish readiness or completed tests.
The fixed accounting-maintenance operation in
[ADR 0020](adr/0020-setup-accounting-maintenance.md) can prepare a supported fresh
installation offline after explicit sign-out approval. Its protected transaction
and all-account counter-preservation rules are separate from enrollment. The
post-login launcher supplies only a nonsecret UI hint; setup rechecks privileged
state and requires fresh account-password authorization.
Verified maintenance aborts must also reopen setup with an incomplete-preparation
explanation and the failed operation when known. Partial authentication masking
must not initiate desktop isolation. Migration outcome and observed login
restoration are distinct; pending restoration blocks preparation and enrollment.
Any retry requires new explicit service-interruption approval.
Before trial and activation, the broker must establish current account/session
readiness and an available enrollment; protected pointer inspection alone does
not prove native account continuity.
[ADR 0022](adr/0022-command-first-terminal-presentation.md) defines command-first
presentation. No-argument help, command help and completions require no terminal
or broker. `help COMMAND` and `COMMAND --help`/`-h` provide focused guidance.
Global `--color auto|always|never` and `--color=VALUE` control human styling;
auto honors the actual output destination, `NO_COLOR`, `TERM=dumb` and redirection.
JSON is always plain. Global `--no-input` refuses interactive commands, including
recovery, before terminal/account/broker access; it never bypasses confirmation.

A shared dependency-free semantic renderer supplies inline stage labels, aligned
status, width-aware paragraphs, warnings and next actions. Required sign-out,
software-protection and recovery acknowledgements remain adjacent to the action;
`doctor` and command help carry detail. Menus use bounded visible input and
preparation offers the complete sanitized policy diff before a separate apply
confirmation; skipping its display grants no authority. All
secrets remain on the private terminal path. Sanitized external text cannot
supply terminal styling. Static Bash, Zsh and Fish completions and a manual page
ship for both executable names without dynamic account or credential queries.
Exit codes are 0 for success, 1 for operational failure, 2 for invalid arguments
and 130 for cancellation; a closed output pipe exits quietly with status 0.

Own-user status is available without disclosing another user's enrollment details. JSON output is versioned and contains only nonsecret status. Status schema 2 includes configured/enrolled backend, own-user credential kind, exact length and policy version, legacy software upgrade advice, current availability, cooldown, integration state, and actionable failure reason. Public-facing messages should explain what the user can do; internal TPM codes belong only in sanitized diagnostics.

Changing, resetting, disabling, recovery, and backend migration require trusted authorization. Default own-user changes use fresh existing-password PAM verification. Administrators can perform explicitly identified recovery with system administrative authority; no old PIN is required and no PIN is revealed. A normal user cannot clear durable cooldown files or call an unauthenticated reset endpoint.

Interactive input requires a real terminal or an explicitly implemented protected desktop conversation. Reject insecure noninteractive PIN input. Offer no `--pin`, password environment variable, or general plaintext stdin enrollment option in release builds. Simulator/test secret injection is compiled only into test utilities.

Cancellation before a credential commit leaves that credential unchanged. Setup preserves already completed stages and reports a still-open trial when cancelled. Uncertain mutation results require authoritative inspection before retry. CLI output must distinguish “installed,” “enrolled,” “tested,” and “active.” It must never say setup completed merely because files were copied.

Schema-2 status distinguishes `integration: "trial"` from `"active"`; a trial
does not set `active: true`. `tested: "operator-attested"` requires agreement
between the readable root active gate and the broker's active status; otherwise
the test value remains `"not-recorded"`. Operator attestation is not automatic
desktop evidence. `integration status` reads the sanitized local gate without
a broker. `integration enable` and `disable` print the fixed root tool commands
for `activate` and `disable`; these compatibility commands do not invoke privilege escalation. Guided `setup` is the explicit fixed-operation exception defined above.

## 14. Service hardening and SELinux

Ship systemd socket/service units, tmpfiles configuration if needed, and a Fedora SELinux policy. Enforcing-mode operation is a release requirement. Never recommend disabling SELinux or using broad allow-all policy generation to make authentication work.

The broker must have no IP networking; restrict address families to the required local mechanisms. Use a private temporary directory, strict system filesystem protection, explicit writable state/runtime paths, protected kernel/module/control-group interfaces, no core dumps, resource limits, and the smallest tested capability/device allowlist. Restrict TPM device access to the resource-manager interface where available. The PAM worker needs a separately reviewed sandbox that preserves legitimate password/account checks and failure accounting; blindly inheriting broker restrictions must not break PAM helpers.

The supported policy must allow KDE's unprivileged locker to contact the broker without granting it direct credential-file or TPM access. Test DAC and SELinux denial paths. Unexpected denials make PIN verification unavailable and preserve password fallback, while diagnostics identify the relevant failure without leaking secrets.

M8 packages the systemd and SELinux confinement definitions. Its recorded
installed positive, causal SELinux denial and recovery cases passed with SELinux
enforcing in the restricted Fedora 44 x86_64 Btrfs appliance. See the
[M8 report](development/m8-packaging-recovery.md); a package build or synthetic
test alone does not establish that acceptance.

## 15. Packaging, installation, upgrade, rollback

Deliver signed Fedora RPM packages for the supported architectures. Installation starts no enrollment and performs no broad authentication rewrites. Explicit activation must inventory PAM files, verify hashes/layout, create a root-protected backup, test both routes, and apply the smallest known change atomically. Record the package version, original digest, installed block digest, and timestamp.

Do not stack `pam_localpin` and the temporary `pam_pinlock` installation. First
verify password/console recovery, durably back up the exact known legacy block,
revoke the old account domain and remove that block. Verify stock password
recovery before preparing, freshly enrolling, trial-testing and activating
LocalPIN. Migration explicitly revokes the old account bindings and provisions
fresh identities, so enrollment under the old graph cannot survive migration. Import no
old verifier or weaker software parameters. See the
[migration runbook](integration-administration.md#migrate-the-temporary-pin-block).

Upgrades preserve committed enrollment and throttle bytes, including legacy six-digit software credentials; they never automatically convert credentials. Before reopening a package-resume gate while the broker is stopped, the fixed root-only `localpin-account check-credentials` operation validates records using the shared Rust parsers, without writes, KDF work or TPM attempts. State migrations are versioned, transactional, tested in both directions where supported, and run before enabling the new code. Unsupported downgrades must leave the password route usable and explain how to disable integration. Kernel, Plasma, PAM, and authselect upgrades are part of the compatibility matrix.

M8.1 removes the immutable appliance/cache-window requirement. Routine Fedora
44 `dnf upgrade` must preserve native account markers, registry incarnations,
committed enrollment and durable throttles across Linux-PAM/authselect/Plasma
updates and unrelated service-account creation. An operation overlapping a
native replacement can become unavailable and use password recovery; later
operations may use the updated trusted native components without a build-hash
allowlist. Unknown PAM graphs still require an explicit compatibility decision.
No package hook may recreate a missing marker or silently accept a new identity.

LocalPIN RPM upgrades separately close the gate, quiesce the broker, validate
versioned registry/credential/throttle bindings and preserve compatible state.
Compatible schema-2 upgrades validate bound policy/state and can retain prior
activation; disabled/trial installations remain unactivated. Unsupported
transitions and downgrades refuse safely. Initial
installation starts no socket and changes no KDE/authselect/faillock policy.
The historical M8 matrix demonstrated the earlier restricted cache-window
upgrade. The [M8.1 installed evidence](development/m8.1-desktop-compatibility.md)
records actual DNF updates, native runtime reinstallation, compatible schema-2
RPM upgrades through `.1` → `.3` → `.4`, ordinary reboot and interrupted-upgrade
reboot/resume while preserving enrollment. Final source checks and the installed
`.5` → `.6` upgrade passed with exact enrollment, registry, throttle, native tally
and policy preservation and automatic restoration of prior activation. Earlier
cases retain their recorded build scope. These are targeted Fedora 44 cases, not a promise about
arbitrary future ABI/policy changes or physical hardware.

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
| Credential behavior | Every backend/type length boundary, leading zeroes, exact spaces/case, all-digit passcodes, malformed/Unicode/control input, legacy software verification/replacement, profile-overlapping password fallback, no auto-submit |
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
