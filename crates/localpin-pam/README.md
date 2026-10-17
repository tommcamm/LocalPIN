# LocalPIN PAM adapter

`localpin-pam` builds `liblocalpin_pam.so`; the reviewed installed module name is
`/usr/lib64/security/pam_localpin.so`. This crate does not install or activate
it. It supports only Linux-PAM's `kde` service, without module arguments, for an
existing unique local account whose nonzero UID equals both the process's real
and effective UIDs. Target binding reads a bounded root-owned regular
`/etc/passwd` directly, avoiding NSS callbacks. The broker independently
enforces ADR 0012's narrower supported account and session domain.
The regular-file size/allocation bounds and `O_NONBLOCK` reject oversized input
and special files; they do not impose a deadline on kernel filesystem I/O.

Every authentication call clears any previous `PAM_AUTHTOK`, requests exactly
one fresh `PAM_PROMPT_ECHO_OFF` conversation with `Password: `, and copies the
response from a successful callback with `pam_set_item(PAM_AUTHTOK)` before
erasing and freeing its transferred C allocation. It never uses
`pam_get_authtok` or reuses a previous response. All
native NUL-terminated candidate bytes, including empty, whitespace and non-UTF-8
passwords, pass unchanged into PAM's owned token. Embedded NUL is outside the
native PAM string representation. Only exactly six ASCII digits contact the
broker; Enter remains controlled by KDE's ordinary submitted conversation.

The fixed endpoint is `/run/localpin/broker.sock`. The production protocol
client authenticates the root-controlled socket path and root kernel peer,
reads a fresh connection greeting and checks every response binding. The
adapter requests own-user status, requires an available enrolled credential,
obtains a fresh valid challenge and submits one PIN. Only the terminal
`VerificationOutcome::Granted` returns `PAM_SUCCESS`. Every other result,
conversation failure, unsupported invocation, malformed exchange, timeout or
contained Rust panic returns `PAM_IGNORE`, preserving the reviewed original
password route under `[success=done default=ignore]`.

Connect (itself capped at 250 ms), status, challenge and software verification
share one absolute suspend-inclusive two-second deadline. Only a submitted TPM
verification selected by authenticated enrolled-backend status receives a
five-second total deadline, measured from the same broker-contact start. The
generic client's separate per-operation `status()` and
`verify()` helpers are deliberately unused. Closing the connection discards the
one-use exchange; no PIN, token pointer, prior-success flag or PAM module data
is cached.

`pam_sm_setcred` performs no conversation or broker operation. It returns a
successful no-op for the supported own-user KDE context and `PAM_IGNORE` for an
unsupported invocation. Linux-PAM's credential dispatch reuses the selected auth
path; this permits the original `[success=done]` branch to complete credential
refresh after a PIN grant without caching that grant. Both exported entry
points contain Rust unwinding panics and return `PAM_IGNORE` on panic. Abort,
invalid native pointers and a nonconforming application conversation are outside
Rust's unwind containment.

The only unsafe-code exception is `src/pam.rs`: public Linux-PAM layouts and
constants, the runtime `libpam.so.0` SONAME, borrowed item pointers, the
conversation call and libc allocator ownership. A successful PAM callback must
transfer distinct C allocations for the single response and its NUL-terminated
string. On callback failure, the application must release its own resources;
the module never inspects or frees the unowned output pointer, which may already
be dangling. Application failure-path leaks cannot be repaired safely by the
adapter. Cleanup of successfully transferred responses includes the terminator and uses the pinned RustCrypto
`zeroize` before `libc::free`. PAM owns its token copy; this module never frees
or retains it. The remaining Rust code denies unsafe code. Zeroization cannot
erase historical copies, compiler moves, native PAM copies, swap or dumps.

Run `cargo test -p localpin-pam` for policy, broker-order/deadline and panic
boundary tests. Isolated tests under `tests/` exercise the built module through
real Linux-PAM in a disposable namespace. These checks do not establish the
stock-theme KDE/enforcing-VM M7 acceptance matrix or authorize host activation;
those require the milestone's separate recorded evidence.
