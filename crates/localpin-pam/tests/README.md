# Isolated production PAM module tests

Run as an ordinary host user with Linux user namespaces, subordinate UID/GID
maps, `unshare`, `bubblewrap`, `newuidmap`, `newgidmap`, a C compiler, PAM
development headers, and the native `pam_permit`, `pam_deny`, `pam_unix` and
`pam_faillock` modules:

```sh
python3 crates/localpin-pam/tests/isolated_pam.py
```

If PAM headers are extracted locally instead of installed, set the build-only
`LOCALPIN_PAM_INCLUDE` to their `usr/include` directory. This changes only the
test C compiler include path. The runner builds `cargo build --locked --release
-p localpin-pam` and obtains the exact cdylib from Cargo's JSON output, including
target-directory overrides. There are no feature, socket, adapter-path or
production-environment test selectors.

The test runs a fake wire broker as UID 0 in a private user namespace and a real
Linux-PAM application as UID 1000 in that same namespace. Namespace root maps
to the ordinary invoking host user; other UIDs use subordinate mappings. The
application loads the exact release module and connects through its production
`/run/localpin/broker.sock` endpoint. The fake broker sends normal public wire
frames and checks connection/challenge binding, operation order, bounded credential
encoding and exact agreement with the issued profile. Numeric candidates retain
leading zeroes; passcodes retain spaces and case. Profile mismatches never emit
a verification request. Candidate values remain in
test process memory and are not printed or saved.

The private filesystem contains read-only `/usr`, read-only test artifacts, and
tmpfs `/etc`, `/run` and `/tmp`. Host `/etc`, `/run`, homes, accounts, credential
stores, TPM devices and PAM policies are absent. The runner refuses host root.
Its synthetic shadow hashes are public fixtures and deliberately readable in
the private namespace so the non-root native password baseline does not depend
on a host setuid helper. No package, daemon, account or PAM rule is installed.

Known native permit/deny and correct/wrong `pam_unix` baselines precede adapter
checks. A test-only downstream PAM module compares the original candidate
byte-for-byte and records normal password calls/failures. Cases cover all 255
non-NUL byte values, empty/Unicode/long values, six-digit account passwords,
flexible numeric and space-preserving passcode profiles, mixed-version greeting
refusal and profile-mismatch routing without a submitted attempt,
leading zeros, no second prompt, repeated authentication on one handle,
cancellation and malformed/error-return conversation responses, target/service changes during the callback, identity restrictions,
missing module, preceding required/requisite failure, explicit account-phase
denial, and unavailable/malformed/disconnected/cooldown broker outcomes. Actual
`pam_unix`/`pam_faillock` cases cover fallback, ordinary failure accounting,
unchanged counters on PIN success, password recovery, existing lockout, locked
password and expired-account management.

The error-return conversation regression frees its own response allocations
and deliberately leaves a non-NULL dangling output pointer. Under `pam_conv(3)`
only success transfers ownership; the module must inspect the return status
before reading that pointer. A deny-only downstream suffix prevents unrelated
PAM helpers from making another conversation call. A later fresh PIN call on
the same handle must recover.
Success with a nonzero response code or a NULL response string remains a
separate malformed-success test, where the module owns cleanup.

This isolates ABI/token/control-stack behavior and authenticated transport. The
fake broker does not prove production account eligibility, durable credential
storage, TPM operation, the installed Fedora policy, SELinux confinement, or
stock-theme KDE behavior. Those require the production-broker and disposable
enforcing-VM acceptance evidence; this harness alone does not pass M7's exit
gate.
