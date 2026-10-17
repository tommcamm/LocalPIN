# ADR 0007: Fixed binary frames and connection-local authorization

Date: 2026-10-17. Status: accepted M2 development protocol contract; socket and
privileged-worker implementation require M5/M6 integration evidence.

## Decision

Version 1 uses a four-byte big-endian body length, explicit version and
direction-specific operation code, and a nonzero 128-bit connection identifier.
The 4 KiB limit includes the prefix, leaving at most 4092 body bytes. Validate
the prefix before accepting payload into a fixed buffer. Every operation has a
closed layout: reject unknown versions, operations, discriminants, appended
fields, partial EOF and any ancillary capabilities. Bounded password responses
preserve arbitrary bytes; the PAM bridge must explicitly enforce native string
constraints rather than silently convert or truncate them.

The privileged server issues a fresh random connection ID in its initial hello.
The client must authenticate the server/socket before sending secrets. Only
kernel peer credentials identify the account; normal requests carry no target
UID. Recovery is a distinct root-only operation. IDs correlate live operations,
not reusable bearer authorizations. A connection supports repeated idle status
requests and at most one authorizing operation; cancellation, disconnect, error
or terminal response destroys its state. No state survives broker restart/boot.

Verification challenges expire strictly before five seconds, with a separate
five-second genuine backend deadline after submission. Enrollment uses a bounded
60-second password conversation, at most 16 one-use prompts, and a separate
strict 60-second commit interval after trusted password authentication. All time
comes from one suspend-inclusive monotonic clock; backwards time and overflow
terminate the connection. M5 must also implement the specification's 250 ms
connect and two-second unavailable deadlines; these do not follow from a parser.

Protocol transitions produce pending work, not authorization. The broker must
resolve enrollment actions against the current pinned backend and combine
protocol order/binding with core lifecycle/eligibility, durable reservation,
staged verification, revocation and commit fences. Client messages cannot assert
password success. Only the private trusted worker interface supplies that event.
Wire success can be emitted only after authoritative core/storage completion.

Secret owners are non-cloneable, non-serializable and redacted in `Debug`.
PIN/password/frame/credential buffers and worker prompt text erase their owned
storage on drop through pinned RustCrypto `zeroize =1.9.1`. Borrow secret bytes
only at explicit private boundaries; source-buffer owners and native adapters
retain their own cleanup obligations. This cannot erase historical copies,
compiler moves, swap or dumps. Status/errors use closed nonsecret vocabularies.

## Evidence and consequences

The [wire contract](../../crates/localpin-protocol/README.md) specifies every
field and discriminant. Tests cover roundtrips, every stream split/truncation,
length boundaries, mutations, replay, expiry, cancellation, worker context,
root recovery and action conversion. Unknown extensions need a versioned design
change and compatibility tests. No production clients exist to migrate.
Sockets, credential acquisition, live account/session checks, actual password
workers and durable storage are explicitly outside this parser/model milestone.
