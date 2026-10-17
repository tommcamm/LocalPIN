# ADR 0010: Bounded broker, socket peers and native workers

Date: 2026-10-17. Status: accepted implementation contract; installed sandbox,
account lifecycle and production authentication evidence remain gated.

## Decision

`localpind` composes the version-one connection machine, M3 stable per-UID lock,
durable reservation/completion and M4 backends. It admits at most 32 connections,
32 requests per connection and a 15-second connection lifetime. Idle frame I/O
has one two-second absolute deadline, including partial reads. There is no
application work queue. The socket backlog is 32. Errors close a connection;
per-client diagnostics are silent, avoiding secret-bearing or floodable logs.

All ephemeral deadlines use the same suspend-inclusive `CLOCK_BOOTTIME` source
as core policy. Socket waits use absolute boot-time timerfds, rather than
relative poll timeouts that pause during suspend. Eligibility, backend work and
delivery retain the original request deadline; only a protected TPM credential
permits the three-second extension, capped by the connection lifetime.

Client path checks walk from a trusted root descriptor with `openat2`, refuse
symlinks and writable/untrusted ancestors, pin the socket inode across connect,
and require kernel server UID/GID zero before reading Hello or sending secrets.
The 250-ms connect budget includes greeting. Socket activation uses `Accept=no`:
the listener creator can remain the kernel peer PID observed by clients. Root
identity and protected socket ownership are authoritative here, not a claimed
accepting PID. Strict activation metadata validation precedes `listenfd`'s safe
ownership transfer, before threads start; the inherited listener must have the
expected Unix stream/listening address and close-on-exec flag.

All public protocol reads use `recvmsg` with no ancillary capacity. Linux
discards capabilities that cannot fit, closes passed descriptors, and reports
control truncation; any such flag rejects the entire frame. Cancellation and
pending unexpected data invalidate a worker response before authorization.
Connections and challenges use OS randomness. Challenges, responses and results
are bound to a live connection, with no durable token or success cache.

The broker additionally captures a socket-bound `SO_PEERPIDFD` reference. Opening
a pidfd by numeric PID after `SO_PEERCRED` could attach to a replacement process;
there is no such fallback. This raises the Linux runtime requirement to 6.5 with
support for this socket option; missing support fails closed. M5's local
unsafe function is `platform::socket_peer_pidfd`: one `getsockopt` and ownership
transfer of its fresh descriptor, with output length and descriptor validation.
`localpind` uses `deny(unsafe_code)` with a function-scoped exception; the other
crates retain `forbid`, and the worker independently forbids unsafe code. The
libc, rustix, listenfd, D-Bus and TPM libraries remain native/unsafe review inputs.

M6.1 adds the separately reviewed, function-scoped integer `fcntl` ABI for the
kernel writer-drain lease in [ADR 0012](0012-immutable-appliance-account-authority.md).
It is required during privileged sealing; it runs no account policy in the broker.

Live session routing uses native logind D-Bus calls at the fixed system-bus
address, never a shell or inherited bus-address environment. A direct session
failure cannot fall back to another session. User-manager routing requires a
verified own-UID manager and exactly one eligible session, including inactive
live sessions. Unknown own-UID properties, ambiguous inventory, remote/closing,
seatless, non-user, non-KDE and non-graphical sessions refuse the PIN route.
Process exit/credentials/start-time checks surround routing. The bus incarnation,
unique logind owner, session identity and creation timestamp fence replacement.
Session references are stable for that exact identity. Account restrictions and
UID reuse remain distinct requirements: `SystemAuthorities` still refuses
ordinary unmanaged accounts. Session metadata cannot authorize an account.

Every backend executes in a fresh fixed installed helper with private bounded
IPC, an empty environment, no secret arguments and no caller-selected program,
path, transport or TPM command. Software work has at most two seconds; TPM work
has at most five. One supervisor shares four process slots and the core's
256-MiB KDF budget. The parent reserves durably before starting it. A worker can
return only one correlated backend outcome; it cannot commit or authorize.
Timeout, cancellation, partial/malformed output, crash and late results return
unavailable. A killed worker and its UID/memory/process lease stay in a bounded
retired table until a single asynchronous reaper confirms exit. Uninterruptible
I/O cannot cause unbounded replacement spawning or an unbounded response wait.
No worker persists TPM handles or a successful PIN.

The successful response is written while retaining the same stable UID lock
used for revocation. Durable completion, live account/generation/session and
connection expiry/cancellation checks precede it. Abandoned attempts remain
consumed. Distinct kernel-root recovery uses the core's administrative path.
Enrollment/password operations explicitly return unavailable until M6 supplies
the fresh password worker; no client assertion can stand in for that worker.

## Privileges and limits of the evidence

The broker and TPM worker prototype run as root with an empty capability set,
private state, AF_UNIX only, device access restricted to `/dev/tpmrm0`, finite
memory/process/fd limits and cgroup-wide cleanup. The worker inherits these
restrictions. The password-PAM worker is a separate M6 executable and policy:
it must retain legitimate PAM helpers and failure accounting; the broker's
sandbox must not be copied to it without tests. No password PAM stack is loaded
by this broker or backend worker.

The checked-in units express the deployment contract and are not installed by
the build. M8 owns RPM/SELinux and enforcing installed-unit validation. Ordinary
filesystem I/O and libdbus connection/authentication can block in native code.
Such a connection retains its admission slot, and all late grants are refused.
The client must retain its own absolute unavailable deadline, so a blocked
broker cannot extend PAM fallback. Server-side response latency is measured for
responsive local storage/bus and the supervised blocked backend conditions;
this is not a claim that an arbitrary kernel or system-bus hang is cancellable.
