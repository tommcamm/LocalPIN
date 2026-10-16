# M1 isolated PAM experiments

These are test executables and a synthetic C module, not an installable LocalPIN
adapter. They never modify `/etc/pam.d` or authenticate a real host account.
C keeps this feasibility probe close to the Linux-PAM API without choosing the
production Rust FFI boundary or adding a native dependency to the Rust workspace.

On a Fedora test system with `gcc`, `pam`, and `pam-devel`:

```sh
experiments/m1/pam/run.sh
```

For development headers extracted from the matching Fedora RPM without installing
it, set `LOCALPIN_PAM_INCLUDE=/absolute/path/to/usr/include`. Other overrides are
`CC`, `PAM_LIBRARY`, and `PAM_MODULE_DIR`; the default library/module paths target
Fedora x86_64. Compiled files and service configurations live in a private
`mktemp` directory and are removed on exit. Both baselines load distribution
`pam_permit.so`/`pam_deny.so` through absolute paths. All later services name the
absolute experiment module path and include no host services.

Exit 0 means assertions passed, exit 1 means an assertion failed, and exit 77 means
PAM baselines or other required runtime infrastructure were unavailable. A compiler
failure is a build failure. A failing permit baseline must be investigated before
interpreting any authentication assertion.

The synthetic suite checks 30 conditions, including candidate reuse, every
non-NUL byte value, a 511-byte candidate, six-digit passwords, repeated handles,
cancellation, control rules, and auth/account phase separation. Mock outcomes for
broker/timeout/corruption are return-code fixtures; they exercise no IPC, actual
crash, deadline, storage, identity lookup, or account database.

For the optional real `pam_unix.so` test, install `bubblewrap`, `python3`, and
`libxcrypt` in the test environment and run:

```sh
LOCALPIN_PAM_UNIX=1 experiments/m1/pam/run.sh
```

This uses unprivileged user, mount, PID and network namespaces. It exposes the
system `/usr` read-only and a generated synthetic `/etc`; host `/etc`, home,
`/run`, and `/var` are absent. The namespace's UID 0 has no host-root authority.
Public fixed fixtures are hashed into temporary synthetic shadow records. It
checks known correct/wrong `pam_unix` baselines and five candidate/lifetime
assertions using `nodelay try_first_pass`. It does not exercise Fedora's complete
PAM include graph, `pam_faillock`, SELinux, or KDE. Namespace unavailability exits
77 and does not establish a test pass.

`LOCALPIN_PAM_SANITIZE=1` enables GCC AddressSanitizer and UndefinedBehaviorSanitizer
when their development/runtime libraries are available. See the
[experiment report](../../../docs/development/m1-pam.md) and
[decision](../../../docs/adr/0001-pam-candidate-and-account-policy.md) for results
and remaining deployment gates.
