# M9 component validation

The [development validation report](../../docs/development/m9-review-validation.md)
records the tested candidate, successful checks, retained failures, review scope
and open release requirements. These are component/development results; the
[M9 runbook](../../docs/development/m9-release-readiness.md) owns installed,
independent-review and physical acceptance gates.

For the normal source, dependency and packaging checks, follow
[CONTRIBUTING.md](../../CONTRIBUTING.md#validation). On Fedora with extracted
development RPMs, `LOCALPIN_PAM_INCLUDE` may point to the extracted `usr/include`
and `PKG_CONFIG_PATH` to the extracted TPM2-TSS `usr/lib64/pkgconfig`. Those are
build inputs, never alternate production authentication paths.

Run the native suites as an ordinary user; they create isolated namespaces or
owned simulator processes and use synthetic inputs:

```sh
python3 crates/localpin-tpm/tests/run_simulator.py
cargo test -p localpin-storage --features tpm-simulator-tests --locked -- --ignored
python3 crates/localpin-pam/tests/isolated_pam.py
python3 crates/localpin-auth/tests/isolated_pam.py
python3 crates/localpin-auth/tests/kde_accounting.py
python3 crates/localpind/tests/run_protected_broker.py
python3 crates/localpind/tests/run_enrollment_broker.py
cargo test -p localpinctl --test job_control --locked
```

The terminal Python helper is invoked by the Rust `job_control` executable and
requires that executable as an argument; it is not a standalone test command.
Namespace permissions, subordinate UID/GID mappings, PAM development headers,
Fedora PAM modules, bubblewrap and simulator inputs are prerequisites. An
infrastructure or baseline failure is not a passing check.

For coverage-guided parser campaigns, use [fuzz/README.md](../../fuzz/README.md).
For the selected pure Miri checks, install an isolated nightly with `miri` and
`rust-src`, then run:

```sh
cargo +nightly-2026-10-17 miri test -p localpin-core --locked --lib secret::tests
cargo +nightly-2026-10-17 miri test -p localpin-core --locked --lib enrollment::tests
cargo +nightly-2026-10-17 miri test -p localpin-protocol --locked --lib tests::late_cancelled_or_ineligible_backend_results_cannot_authorize
cargo +nightly-2026-10-17 miri test -p localpin-protocol --locked --lib tests::verification_is_bound_one_use_eligible_and_strictly_expiring
```

Use a separate `CARGO_TARGET_DIR` for nightly instrumentation. These filters
exercise 22 pure tests; they do not run native FFI under Miri or cover the whole
workspace.

`native_instrumentation.py` reuses the existing synthetic PAM fixtures. It
rebuilds selected Rust dependencies and std with AddressSanitizer and compiles
project-owned C fixtures with ASan/UBSan. Follow its `--help` for a new output
directory, toolchain, build-only PAM includes and optional extracted UBSan
runtime. No package is installed. Fedora libpam/modules, glibc and TPM libraries
remain uninstrumented; leak detection is excluded. Preserve failure logs and
check the exact recorded instrumented stages before claiming coverage.

Do not run installed VM fault fixtures on physical hardware or the everyday
desktop. Follow the guarded procedures in the M9 runbook for those separate
stages.
