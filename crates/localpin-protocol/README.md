# LocalPIN protocol version 1

M2 defines the wire/state contract; M5 adds Linux transport and typed clients.
The broker composes
these transitions with `localpin-core`'s durable reservation/completion,
identity, enrollment and revocation fences. A `ConnectionAction::Verify` or
`CommitEnrollment` requests work; it does not authorize success by itself.

The transport is a private filesystem Unix stream socket. Before accepting a
request the adapter authenticates kernel peer credentials, rejects all ancillary
data/control truncation, and closes any received descriptors. Before sending
secrets the client authenticates the privileged server and socket path. A claimed
service name, identity or executable is never accepted as authority. M5 supplies
bounded socket/read/write/worker deadlines, per-UID and global admission control,
and worker cleanup. The Linux `transport` module implements root socket trust,
peer credentials, ancillary rejection, strict activation and typed clients.
`Client::connect` caps setup at 250 ms, `status` at two seconds and `verify` at
two seconds for software or five for TPM, closing after one terminal result.
Linux deadlines share suspend-inclusive `BootInstant`/`CLOCK_BOOTTIME` and
absolute timerfd socket waits; a suspend cannot renew a remaining budget.
See [ADR 0010](../../docs/adr/0010-bounded-broker-and-live-peers.md).

The broker creates a fresh unpredictable nonzero 128-bit connection identifier
from OS randomness and sends a `Hello`. Every following request and response
carries that identifier. Clients call `check_connection` on responses after the
hello and consume a final verification result only for their live PAM operation.
A response grants no reusable bearer capability. A connection supports repeated
idle `Status` requests and one authorizing operation, then terminates. Disconnect,
any parser/state error, or cancellation destroys its authorization. State is
ephemeral and must never be persisted or restored across restart/reboot; all
timestamps come from one trusted monotonic clock/boot. Backward time and checked
deadline overflow fail closed.

## Framing and primitive encodings

All multi-byte integers are unsigned big-endian. The four-byte prefix counts
body bytes only. The **entire frame**, including that prefix, is at most 4096
bytes; the body is therefore at most 4092 bytes and at least 18 bytes.

| Complete-frame offset | Bytes | Meaning |
| --- | --- | --- |
| 0 | 4 | Body length, `u32` |
| 4 | 1 | Version, exactly `1` |
| 5 | 1 | Explicit direction-specific operation code |
| 6 | 16 | Nonzero connection identifier |
| 22 | Defined by operation | Payload |

There is no padding, extensible field map, implicit terminator or ignored suffix.
Unknown versions, operations, enums, zero identifiers, invalid six-ASCII-digit
PINs, unknown fields and trailing bytes are errors. Request and response operation
spaces are separate; a client cannot send a server authentication-success message.

`id` means exactly 16 opaque nonzero bytes. `pin` means exactly six ASCII decimal
bytes, preserving leading zeroes. `blob` is a `u16` byte length followed by that
many bytes, at most 2048. Conversation responses preserve arbitrary bytes and
perform no text conversion or NUL truncation; the M6 PAM bridge must apply its
documented native representation constraints explicitly. `text` uses the same
`u16` length encoding but contains at most 1024 UTF-8 bytes and no NUL.

The incremental decoder owns one fixed 4096-byte buffer. It validates the length
as soon as the fourth prefix byte arrives, before reading payload or allocating
any claimed length. It consumes at most one frame per call and reports the exact
byte count so a caller can retain subsequent stream bytes. Errors poison the
decoder and require connection close. EOF during a partial frame erases the
buffer and fails. Frames and prompt/secret owners erase their owned storage on
drop, and frame buffers are erased after parsing. Input source owners must erase
their own buffers; this is not a promise to erase compiler temporaries, prior
moves, native copies, swap or dumps. Frames have no `Debug` or `Clone`; PINs,
password responses and prompt text have redacted `Debug` and no serialization.

## Requests

| Code | Operation | Exact payload |
| --- | --- | --- |
| `01` | Status | empty |
| `02` | BeginVerify | empty |
| `03` | Verify | challenge `id`, `pin` |
| `04` | Cancel | empty |
| `05` | BeginEnroll | action `u8`, proposed backend `u8` |
| `06` | EnrollConversation | transaction `id`, prompt `id`, response `blob` |
| `07` | CommitEnrollment | transaction `id`, new `pin` |
| `08` | Disable | transaction `id` |
| `09` | RecoverDisable | target UID `u32` |

Actions: enroll `1`, rotate `2`, explicit backend migration `3`, disable `4`.
Backends: absent `0`, TPM `1`, explicitly accepted software `2`. Only disable
requires absent backend; every other action requires an explicit backend. Core
policy independently checks current enrollment/backend and the correct action.
The broker **must call `resolve_enrollment_action` with the protected committed
backend before issuing enrollment IDs or starting a password worker**, and use
its resulting core action in `begin_own_user`. This pure conversion refuses
enrolling an existing credential, rotating with a different or missing backend,
migrating an absent credential or to the same backend, and disabling an absent
credential. Core deliberately derives a rotate backend from committed state;
this conversion checks that it agrees with the wire request. The issued
generation and every staged backend must agree with core's transaction binding.
No automatic fallback is represented. Every normal operation targets only the
kernel peer's own non-root UID, without a client target field. Only distinct
`RecoverDisable` names a target and requires a kernel-root peer; target UID zero
and the `u32::MAX` sentinel are rejected. Root cannot perform normal operations.

`BeginVerify` requires current trusted eligibility. The broker issues a fresh
random challenge valid for strictly less than five seconds from issuance.
`Verify` requires that challenge, connection and a fresh eligibility result; it
consumes the challenge and permits one bounded backend action. A separate
five-second backend deadline starts at accepted submission. A repeat, mismatched
challenge, out-of-order request, late backend result or cancellation can never
yield a success response. Core must reserve before calling the backend, durably
complete before success, and reject stale generation/identity/revocation results.
Abandoned reservations stay consumed. Eligibility is rechecked before success.

`BeginEnroll` binds broker-owned worker context to connection, UID, action,
proposed generation and fresh transaction ID. The password conversation has a
strict sixty-second deadline and at most sixteen sequential prompts. Each prompt
has a fresh random ID; repeated IDs, answers without an outstanding prompt,
cross-transaction answers and duplicate answers fail closed. Info/error messages
require an empty answer. Password responses are only relayed to the private
worker and confer no authority themselves.

Only the server API `password_authenticated` consumes a success from the trusted
password-only PAM worker with the identical context. It is never decoded from a
client field or Boolean. Authentication starts a commit interval of at most sixty
seconds. A matching `CommitEnrollment` or `Disable` can request its one bound
action only before that interval expires; equality with the deadline is expired.
Disconnect/reconnect, replay, another UID, action/generation/context change,
password failure, worker crash, or expiry cannot transfer that authorization.
Core/storage must validate the same context, current identity, staged credential,
generation fence and expiry before durable commit. `finish_mutation` only reports
that already committed result and then terminates the connection. Administrator
recovery uses its separate root path and a bounded five-second pending operation.

## Responses

| Code | Response | Exact payload |
| --- | --- | --- |
| `80` | Hello | empty |
| `81` | Status | preference `u8`, enrolled backend `u8`, availability `u8`, cooldown milliseconds `u32`, integration `u8`, detected `u8`, usable `u8`, reason `u8` |
| `82` | VerifyChallenge | challenge `id`, remaining milliseconds `u32` |
| `83` | EnrollmentStarted | transaction `id`, nonzero proposed generation `u64`, remaining milliseconds `u32` |
| `84` | ConversationPrompt | transaction `id`, prompt `id`, style `u8`, prompt `text` |
| `85` | EnrollmentReady | transaction `id`, remaining milliseconds `u32` |
| `86` | Verification | result `u8`, conditional data below |
| `87` | Completed | completion `u8`, conditional data below |
| `88` | Cancelled | empty |
| `89` | Error | error `u8` |

Challenge intervals are 1–5000 ms. Enrollment/conversation/commit intervals are
1–60000 ms. Configured preference distinguishes auto `0`, TPM `1`, software `2`;
enrolled backend uses absent/TPM/software `0/1/2`. Detection, usability and actual
enrolled TPM protection are independent status values. Booleans are exactly `0`
or `1`. Availability: available `0`, not enrolled `1`, disabled `2`, cooldown `3`,
ineligible `4`, unavailable `5`. Integration: inactive `0`, active `1`, needs
attention `2`. Reasons: none `0`, account `1`, session `2`, storage `3`, backend
`4`, policy `5`, busy `6`, protocol `7`. Prompt styles: echo-off `1`, echo-on `2`,
information `3`, error `4`.

Verification result: granted `1` and mismatch `2` have no suffix; cooldown `3`
has remaining milliseconds `u32`; unavailable `4` has reason `u8`. Completion:
enrolled `1` has actual backend `u8` (only TPM/software), disabled `2` and
administrator-recovery-disabled `3` have no suffix. Errors: protocol `1`, state
`2`, expired `3`, forbidden `4`, password rejected `5`, unavailable `6`. Native
errors, paths, account password results and secret data have no status encoding.

Deterministic tests cover every request/response split and nonempty truncation,
prefix and field boundaries, unknown/trailing values, arbitrary-byte mutations,
one-byte/coalesced stream reads, private-worker context and prompt replay,
cross-connection/UID inputs, expiry equality, clock anomalies, cancellation,
late authorization, root-only recovery and secret diagnostic redaction. These
are development parser/state tests; M5/M6 socket and worker tests remain required.
