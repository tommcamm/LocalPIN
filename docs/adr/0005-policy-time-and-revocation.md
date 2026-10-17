# ADR 0005: Attempt boundaries, monotonic recovery, and revocation

Date: 2026-10-17. Status: accepted M2 model contract; durable filesystem and
platform adapters require M3/M5 evidence.

## Decision

Use suspend-inclusive elapsed milliseconds scoped by the kernel boot ID. Wall
time never replenishes a budget or extends an authorization. Within one boot,
backwards observations and arithmetic overflow make PIN unavailable.

The rolling window is `(now - 60 seconds, now]`: an attempt exactly 60 seconds
old leaves the window. All five submitted valid-format candidates may reach the
backend. Reserving the fifth installs a full 300-second cooldown immediately,
before backend invocation. A genuine mismatch on that attempt remains a mismatch;
later requests receive cooldown without invoking the backend. Cooldown expires
exactly at its deadline. A positive backend result clears recent attempts and
cooldown only through durable completion. Technical errors, cancellation and
abandoned reservations remain consumed; they are not evidence of a wrong PIN.
Persist the cooldown origin as well as its deadline and validate their exact
checked 300-second relationship, including after recent timestamps are pruned.

A reservation intent cannot invoke a verifier. Only an acknowledged durable
replacement yields a reserved-attempt capability. Backend invocation consumes
that capability together with its owned PIN and matching KDF work permit into a
single-use job; it cannot reuse shared references to submit additional guesses
or parallel work. Only durable completion yields an authorization response.
A failed/uncertain write poisons the in-memory machine
until authoritative reload; the store must compare the expected revision and
identity under the same per-UID lock as credential mutation. Dropping a reserved
operation requires recovery, preserving its consumed guess.

On boot change, any persisted recent attempt, active cooldown, or unresolved
reservation imposes a fresh full cooldown. Old boot timestamps are incomparable;
do not subtract wall time or assume old attempts expired. Persist recovery before
accepting work, so repeated reloads within the new boot do not extend or bypass
it. This intentionally can delay PIN after an otherwise innocent reboot. Clean
state after a durably completed success carries no attempt debt. Missing or
malformed required state is unavailable, never an invitation to initialize it.

Rotation, disable and administrative recovery advance a nonwrapping generation
and revision. In-flight results bind account incarnation and generation. Recheck
the current account, generation, session/account eligibility, connection and
deadline before committing/delivering success. Durable mutation is the revocation
boundary: results committed afterward cannot authorize the old generation.
Already delivered PAM authorization can still finish; no model can retract it.

Enrollment password authorization belongs to the trusted worker/broker, binds
connection, account, action, transaction and proposed generation, and expires at
60 seconds after password completion. Equality with the expiry is expired. New
boot, backwards time, cancellation, reconnect, changed lifecycle identity and a
different generation invalidate the transaction. New credential creation and
verification precede the conditional durable pointer commit. A previous record
is crash-recovery material, never an alternative accepted credential.

## Evidence and limits

The Rust policy tests exercise fake stores, clocks, lifecycle authorities,
password workers and backend outcomes, including failure acknowledgements and
revocation races. They establish the state-machine contract, not actual file
synchronization, password verification, TPM behavior or session validation.
M3 must fault-inject every persistence boundary; M5/M6 must enforce worker,
session, cancellation and deadline fences across real IPC.
