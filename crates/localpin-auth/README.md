# localpin-auth

The broker binds a `PasswordSupervisor` to its authenticated private conversation
and suspend-inclusive trusted `Clock`, then passes that adapter to the core
enrollment state machine. Each operation gets a fresh non-setuid privileged
`localpin-auth-worker`, private socketpair and random correlation token. The
child receives the UID/account/connection/transaction/action/generation/time
binding; the broker retains the full opaque core binding and owns the result.
There is no client-supplied success flag, reusable grant, password argument,
password environment variable, alternate service selector or general shell.

The entire operation, including the hidden input prompt, is limited to 60 seconds
on `CLOCK_BOOTTIME`; the core's separate authorization lifetime starts only after
the trusted completion timestamp. Successful response requires the exact token,
one fresh hidden password answer, expected message ordering, successful child
exit and complete private IPC closure before the deadline. Cancellation, late
results, malformed/replayed conversation, process failure, unavailable policy or
account restrictions never authorize a transaction. The supervisor admits at
most four groups and one per UID. A retired group keeps its slot until actual
reaping and group disappearance; a single reaper polls without a blocking wait.

The trusted relay must enforce the absolute prompt deadline while awaiting its
client. Rust callback code cannot be preempted by the supervisor; it remains
inside the charged operation and its result is rechecked before acceptance.
PAM informational/error text is bounded and suppressed. Echo-on, multiple
password prompts and success without a fresh prompt are unsupported. The fixed
prompt is typed and sanitized; raw module text is never sent to a terminal.

`policy/localpin-enroll.disabled` is the fail-closed packaging sample. The worker
accepts only the exact normalized stack in
`policy/localpin-enroll.review-required`, at `/etc/pam.d/localpin-enroll`, owned
by root with protected non-symlink parents. It explicitly invokes `pam_unix` and
`pam_faillock`, and calls both authentication and account management. It refuses
includes, PIN modules, fingerprint, timestamp/cached success and null-password
options. This narrow local-Unix policy cannot stand in for an unknown site's
SSSD, authselect, remote-account or additional restriction policy. An installer
must review that site's supported account and failure-accounting requirements
before enabling it; these files do not install or modify anything.

The worker sandbox is a separate deployment boundary from the broker sandbox.
It needs legitimate password/shadow helper, PAM module, SELinux, audit and
faillock access. Core dumps and dumpability are disabled in the worker. The
deployment must bound memory/PIDs and prevent descendants escaping the process
group; blindly applying a broker filesystem/capability sandbox can break PAM.
M8's recorded installed matrix passed systemd/SELinux and native password-worker
checks on the restricted Fedora 44 x86_64 Btrfs appliance with SELinux enforcing.
See the [M8 report](../../docs/development/m8-packaging-recovery.md) for its exact
policy and artifact boundary; M9 review and physical TPM validation remain open.
No host PAM/account modifications are test prerequisites.

The project-owned native ABI is isolated in `src/pam.rs`, using fixed Linux-PAM
symbols loaded from `/usr/lib64/libpam.so.0` so development headers/linker symlinks are not
required. No installed PAM wrapper was available; existing pinned libc supplies
the allocator and dynamic loader. Its unsafe invariants cover native pointer
validity, repr(C) layouts, exact function signatures, callback panic containment,
and libc ownership of successful response arrays/strings. Rust-owned secret
copies are erased. PAM owns its successful C copies until its normal cleanup;
short-lived workers avoid retaining handles/tokens between authentications.

M6.1 additionally supplies a separate `localpin-eligibility-worker` and shared
`EligibilitySupervisor`. Its fixed password-free service never accepts a
candidate or a conversation. It validates the supported Fedora KDE graph and
safe root-owned native modules through the stable Linux-PAM SONAME, alongside
local identity, locks, aging, default yescrypt/SHA512 hashes,
nologin and canonical faillock state, and refuses unknown policy. It checks
unchanged accounting around preauth/account PAM without authfail/authsucc or
the resetting faillock account hook. Missing tallies are unavailable; this
worker cannot create them. Its four-slot process pool retains cancelled groups
until reaping and obeys the caller's original absolute deadline. See
[ADR 0012](../../docs/adr/0012-immutable-appliance-account-authority.md) and the
[M6.1 report](../../docs/development/m6.1-account-authorities.md) for the enforced
account domain and actual VM evidence. That historical component evidence is
separate from M8's installed confinement matrix linked above.

Validation:

```sh
cargo test -p localpin-auth
python3 crates/localpin-auth/tests/isolated_pam.py
python3 crates/localpin-auth/tests/kde_accounting.py
```

The second command builds with `--locked` and discovers the Cargo executable,
or accepts an explicit executable path as its only argument. It requires
unprivileged Linux user/mount/PID/network namespaces, bubblewrap and the system's
`pam_unix`/`pam_faillock`. It refuses host root, mounts only private synthetic
`/etc`, gives PAM a private failure tally directory, and mounts `/usr` read-only.
It checks actual correct/wrong password, recovery and counter reset under normal
successful PAM behavior, three-failure lockout, locked/expired password/account,
and unsupported policy rejection. A generic execution sandbox that rejects audit
socket creation with EPERM causes system PAM to fail closed; run this isolated
harness outside that extra socket restriction. Native audit behavior under a
production SELinux/systemd policy is not established by a private namespace test.

ABI and policy references: [Linux-PAM public types](https://github.com/linux-pam/linux-pam/blob/v1.7.0/libpam/include/security/_pam_types.h),
[conversation contract](https://github.com/linux-pam/linux-pam/blob/v1.7.0/doc/man/pam_conv.3.xml),
[authentication](https://github.com/linux-pam/linux-pam/blob/v1.7.0/doc/man/pam_authenticate.3.xml),
[account checks](https://github.com/linux-pam/linux-pam/blob/v1.7.0/doc/man/pam_acct_mgmt.3.xml),
[failure accounting](https://github.com/linux-pam/linux-pam/blob/v1.7.0/modules/pam_faillock/pam_faillock.c).

The KDE-specific password and fingerprint substacks implement native success
accounting during authentication, since KDE omits the PAM account phase. Missing
fingerprint devices/services deny without recording a false failure; genuine
fingerprint rejection still counts. PIN success preserves all native history.
The native KDE regression uses a real unavailable fprintd module and synthetic
biometric return codes in private namespaces. See [ADR 0018](../../docs/adr/0018-kde-native-update-compatibility.md).

An explicit noninteractive `pam_localpin.so policy` selector checks the live
authselect graph before each corrected native authentication. Unknown additional
factors or a missing selector module use the original native stack; they cannot
fall through to direct password verification. The selector never grants a PIN or
authenticates a user on its own.
