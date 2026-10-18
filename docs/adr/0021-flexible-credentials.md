# ADR 0021: Flexible credentials and shared terminal preparation

Date: 2026-10-18. Status: development implementation; source and installed
evidence are recorded separately in the [validation report](../development/flexible-credentials.md).

## Context

A fixed six-digit PIN prevents owners from choosing longer credentials and gives
software protection a small offline search space. Longer input must preserve
password fallback, durable accounting, TPM dictionary-attack safety and existing
credentials. Credential entry after password authorization also spends the short
commit grant on choosing and confirming a new secret.

## Decision

Use an explicitly selected Numeric PIN or optional Passcode. Credential-policy
version 1 permits:

| Type | TPM protection | Software protection | Recommendation |
| --- | --- | --- | --- |
| Numeric PIN | 4–16 ASCII digits | 8–16 ASCII digits | 6 with TPM; 10 with software |
| Passcode | 8–64 printable ASCII characters | 8–64 printable ASCII characters | 12+ characters |

Keep leading zeroes and every passcode space/case byte exactly. Passcodes accept
`0x20`–`0x7e`, including an all-digit value when that type was selected. Reject
Unicode, control characters and overlong input without trimming, normalization
or truncation. Do not require uppercase/symbol combinations or invent entropy
scores. Recommendations do not prefill or generate values; users type any
permitted length without a length picker.

One inline terminal form serves setup, enrollment, change and migration. Show
protection, select type, display allowed range and recommendation, collect and
confirm the new value, resolve local errors/warnings, obtain mutation confirmation,
then open a fresh broker connection for account-password verification and commit
promptly afterward. Default enrollment to Numeric PIN and changes/migration to
the existing type. The backend's applicable policy is checked again before
sending and independently in the broker.

Display one `*` per new-credential character. Account-password entry remains
fully hidden. Support Backspace, Ctrl-U, bounded paste, cancellation and terminal
restoration; retain plain `NO_COLOR`/`TERM=dumb` output. Preparation, including
retries, has one five-minute deadline. Preserve the password deadline and the
existing strictly less-than-60-second authorization grant. Erase prepared input
when an operation ends; rejected password verification requires new preparation.
Cancellation before commit preserves the existing credential. An uncertain
commit requires authoritative status inspection before retry.

Warn locally for repeated characters, complete repeated blocks of one through
four characters, ascending/descending digit sequences wrapping modulo ten, and
exact ASCII-case-insensitive matches against: `password`, `password1`,
`password123`, `qwerty123`, `qwertyuiop`, `letmein123`, `welcome1`, `iloveyou`,
`changeme`, `localpin`. The warning defaults to re-entry; explicit **Use anyway**
accepts it. Never show the value. This advisory terminal guidance is separate
from mandatory broker validation and is not an IPC authorization flag.

## Records, protocol and authentication

Credential envelope 2 retains the `LPC1` magic and existing identity, generation
and backend fields, then adds three metadata bytes: policy, kind (`1` numeric,
`2` passcode) and exact length, before the opaque payload. Policy 1 is required
for new records. Decode envelope 1 as policy-0 six-digit numeric metadata and
preserve its original serialized bytes. Unknown versions/policies fail closed.
Configuration, active-pointer and throttle formats remain unchanged.

New enrollment, change and backend migration write envelope 2; broker worker
output and reopened staged records must agree with the requested profile before
commit. Existing envelope-1 software credentials remain usable with replacement
advice in status/management. Every replacement follows current target-backend
policy. No automatic conversion or backend downgrade is permitted. Retain
Argon2 parameters, TPM construction, hard deadlines and safety reserves.

Public IPC 2 and versioned private worker requests use bounded length-prefixed
credential secrets capped at 64 bytes, preserving separate password-conversation
limits. Reject mixed versions before sending secrets. PAM continues through
password fallback; CLI errors tell operators to update components together.
Own-user status/doctor JSON schema 2 adds credential kind, exact length, policy
version and legacy software replacement advice; expose no credential value.

KDE keeps its stock Password field and explicit Enter submission. Capture the
candidate once and preserve it byte-for-byte for password fallback. Obtain the
profile from the verification challenge and submit to LocalPIN only when exact
length and format match. Bind the challenge to account incarnation, committed
generation, backend and profile. Recheck all bindings under the user lock before
reserving an attempt; intervening credential mutation invalidates the challenge.

A matching-format account password can consume a LocalPIN attempt before
password fallback; TPM protection can also consume the shared dictionary-attack
allowance. Explain this during setup and test profile overlap in isolation.
Wrong candidates forwarded to password authentication can count as native
failures. Do not suppress/reset native counters or claim a PIN success resets
them. Account locks, expiry, cooldowns and TPM reserves remain authoritative.

## Updates and evidence

Supported package upgrades preserve credential and throttle bytes. Before
reopening a package-resume gate while the broker is stopped, invoke the fixed
root-only `localpin-account check-credentials` operation using shared Rust
parsers. It writes nothing and performs no KDF work or TPM attempts. Preserve
downgrade refusal and compatible-update activation semantics.

Validate boundary/format rules, legacy bytes, record/wire limits, mixed versions,
profile substitution, generation races, masked editing/deadlines/cancellation,
password overlap, native counters and both credential backends. Re-run affected
installed Fedora KDE/SELinux, package/legacy-upgrade and recovery cases in
disposable VMs with private simulators. Historical M8 evidence retains its
recorded build scope. Physical hardware and M9 independent review remain
separate gates; source tests and operator attestations cannot satisfy them.
