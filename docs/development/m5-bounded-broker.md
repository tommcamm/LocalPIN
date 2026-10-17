# M5 bounded broker and session checks

Date: 2026-10-17. Status: implemented locally; production account policy/lifecycle,
installed confinement and later hardware/release gates remain open.

## Delivered

`localpind` now serves the version-one protocol over authenticated filesystem
Unix sockets. Its installed entry point accepts only the expected socket
activation descriptor, fixed private state directory and fixed backend helper.
It has no command interpreter, IP listener, desktop-unlock operation, PAM-stack
loading or caller-selected worker/TPM transport. Enrollment operations return
unavailable until M6 supplies trusted fresh password authorization.

The transport validates root ownership, non-writable ancestors, no symlinks,
socket type and inode continuity before transmitting secrets. It checks kernel
server UID/GID; an accepting broker PID is not assumed for socket activation.
Requests reject ancillary descriptors/control truncation, oversized or partial
frames, forged bindings, replay, unknown/trailing fields and wrong order.
Typed clients validate the expected response operation, consume verification
once and cap connection setup at 250 ms, ordinary requests at two seconds and
TPM verification at five seconds.

The server admits 32 connections without an application queue, 32 requests per
connection and a finite 15-second connection lifetime. Each idle frame has one
two-second deadline that partial reads cannot renew. Per-client failures are
silent; the binary emits only a fixed startup error. Root has a distinct
recovery operation and cannot use normal verification/status. Normal requests
have no target UID field and are fenced to their actual kernel peer UID.

The [separate review](m5-review.md) fixed deadline renewal and suspend timing.
Transport, connection, worker and session deadlines now share `CLOCK_BOOTTIME`;
absolute boot-time timerfds wake silent socket waits after expiry during
suspend. Original request/connection bounds include session checks and response
delivery. Regressions emulate suspend without changing host power state.

`platform` captures `SO_PEERPIDFD` alongside `SO_PEERCRED`, then verifies process
liveness, start time and real/effective/saved/filesystem UID/GID. It requires
Linux 6.5+ and procfs; missing socket-bound identity fails closed. A single
documented FFI function acquires that descriptor, with no numeric-PID fallback.
Native D-Bus queries resolve direct sessions or a unique eligible own-user
manager session. Rechecks pin the bus incarnation, logind owner, exact session
and creation timestamp. A stable public-metadata digest identifies that session
across independent resolutions. Unknown, replaced, remote, ambiguous, closing,
seatless or unsupported sessions cannot authorize.

`ProtectedEngine` holds M3's stable UID lock through response delivery. It
validates the protected backend/parameters, charges the shared work budget,
durably reserves before spawning, then durably completes before a positive
response. Core account/generation/session fences and peer liveness are rechecked
after success persistence. It pins the credential backend: TPM errors cannot
select software. Root recovery commits a new disabled generation using the
separate core administrative authority. Unmanaged accounts still fail closed;
live session metadata does not establish password/account restrictions or
solve UID reuse.

The fixed one-operation backend helper receives a bounded credential envelope
and six-digit candidate only on private IPC. It receives no secret arguments
or inherited environment, emits one correlated fixed-size outcome and exits.
The broker owns authorization. Software work is limited to the ordinary
two-second budget; only a protected TPM credential permits five seconds.
Cancellation/disconnect, malformed/partial/extra output, crash and late results
cannot produce success. The four-slot supervisor and 256-MiB core work budget
retain each UID/memory/process lease until reaping. A bounded asynchronous
retired table handles killed native calls without blocking response deadlines
or permitting unlimited replacements. Already reserved attempts remain consumed.

The [decision record](../adr/0010-bounded-broker-and-live-peers.md) describes the
privileges, the narrow unsafe exception and timing conditions. Prototype socket
and service units live in `crates/localpind/systemd/`; the build never installs
or starts them. The future password-PAM worker has a separately reviewed M6
policy, because its helpers/account checks cannot inherit guessed restrictions.

## Evidence collected locally

- Unix transport tests use actual sockets and kernel credentials, including
  passed descriptors in frame headers/bodies, trust failures, inode replacement,
  response binding, fragmentation, timeout poisoning and stalled greetings.
  An inherited-listener subprocess establishes that the client's observed peer
  PID remains the listener creator rather than the accepting child.
- Broker socket tests exercise UID targeting, spoofed fields, replay, one-use
  challenges/results, fresh session checks, exact challenge expiry with an
  injected clock, cancellation before/during work and all 32 admission slots.
  Their engine/eligibility fixtures are explicitly synthetic. Separate root
  branches also passed inside an unprivileged disposable root user namespace.
- Platform tests cover routing, property types, unknown/ambiguous inventories,
  process metadata and session replacement. Real child/socket tests prove that
  the retained peer reference rejects exited peers, including exit before first
  observation. A read-only host probe resolved the actual logind session twice,
  checked equal references and revalidated it in 66 ms. This is a local routing
  observation, not supported-platform or account-policy certification.
- Native worker tests stall in an actual FIFO-open syscall, then assert an
  accelerated response deadline, delayed reaping with retained UID/memory/slot,
  and an unrelated UID's response within remaining capacity. They also cover
  exhaustion, cancellation, late/buffered/partial/malformed/crashed outcomes and
  native cleanup. A forked descendant retaining IPC is killed before its exited
  leader is reaped; group/UID/memory capacity remains charged until cleanup.
  Preventing process-group escapes remains part of planned confinement.
  The deadlines are shortened test budgets for the same code;
  these fixtures do not open a physical TPM.
- The actual built helper is spawned with an empty environment and synthetic
  software credentials. Correct/wrong candidates return only fixed sanitized
  match/mismatch results. Oversized/truncated/trailing input and unexpected
  arguments fail silently. M3/M4 tests separately retain their real filesystem,
  failure injection, native backend, generation/revocation and persistence checks.
- The opt-in multi-UID namespace suite also passed in 8.38 seconds. Public
  root-owned `Storage::open`, the actual fixed worker, typed client and broker
  sockets run together with namespace-root broker and a distinct UID-1000
  client. It proves foreign/root verification refusal, persisted mismatch debt,
  durable success reset, a vanished final session refusing a correct PIN,
  completion-write refusal retaining a consumed pending guess, and root recovery
  committing generation 3 with no credential. Only lifecycle/password/session
  authorities are synthetic. All host mounts are read-only; writable state and
  socket paths exist only on disposable tmpfs. No production trust bypass or
  test mode was added to either installed executable.

Run with the pinned Rust toolchain and native TPM2-TSS 4.x/libdbus development
inputs:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-features --locked
cargo build --workspace --all-features --release --locked
cargo deny --locked check advisories bans licenses sources
```

The protected pipeline suite is intentionally opt-in. As an ordinary host user
with configured subordinate UIDs/GIDs and `unshare`, `newuidmap`, `newgidmap`
and `bwrap`, run:

```sh
python3 crates/localpind/tests/run_protected_broker.py
```

The runner refuses host root, requires separate mapped ordinary UIDs and places
the fixture in private user/mount/PID/network namespaces. Missing prerequisites
are errors, not claimed test passes. Ordinary `cargo test` reports its two
namespace entry points as ignored, alongside the existing opt-in TPM tests.

The local tool sandbox denies local IPC and socket-pidfd syscalls. Native socket
tests were executed with those restrictions lifted, using temporary synthetic
fixtures. The tests do not treat a sandbox `EPERM` as successful negative
evidence. No host PAM files, account passwords, enrolled state, TPM devices or
TPM guess budgets were modified.

The refreshed dependency audit passed advisories, bans, licenses and sources
with cargo-deny 0.20.2 and RustSec commit
`64f92cdc64401fab47baa10e2e11fe382aa57155`. The new Windows-only `dbus` ABI
duplicate has one exact-version exception; there are no advisory/source
exceptions. See the [dependency review](dependencies.md).

Formatting, all-target/all-feature Clippy with warnings denied, workspace tests
and the locked all-feature release build passed locally. The workspace run
passed 205 tests with six explicit opt-in/helper entries ignored after separate
review; the protected namespace suite passed separately, including an explicit
Cargo target override. The final cancellation-bound adjustment also passed all
15 broker regressions. Simulator-only TPM
tests remain opt-in and were not rerun for this broker change; the M4 report
retains their prior evidence.

`systemd-analyze verify` reached only the expected missing installed executable
diagnostic for the development service path. This does not establish installed
unit operation. GitHub CI is updated for libdbus headers but has not been run
or claimed successful here.

## Remaining gates

Ordinary account lifecycle and supported lock/expiry/password-policy checks
still lack an enforcing adapter. The production authority deliberately returns
unavailable. M6 owns fresh password enrollment; M7 owns the actual PAM/KDE flow;
M8 owns RPMs, enforcing SELinux and installed systemd confinement; M9 owns
physical TPM, hardware performance and independent security review.

Synchronous filesystem I/O and libdbus connection/authentication can stall in
native code. Their occupied connection slots stay charged and late grants are
refused, while the client enforces its own fallback deadline. The supervised
backend's response path does not wait indefinitely for a killed kernel call.
This distinction is part of the timing claim: responsive local storage/bus and
bounded scheduler delays are assumed for server response measurements. End-to-end
KDE password fallback latency, including the original PAM stack, is still M7.
