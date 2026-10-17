# Contributing to LocalPIN

LocalPIN has completed isolated and guarded enforcing-VM M1 feasibility experiments
and locally implements M2 pure policy/protocol models, M3 protected Linux
storage, M4 credential primitives, the M5 bounded broker, M6 trusted enrollment
worker/CLI. M6.1's account-authority component gate is complete for the restricted
Fedora appliance domain in [ADR 0012](docs/adr/0012-immutable-appliance-account-authority.md).
The [M6.1 report](docs/development/m6.1-account-authorities.md) and
[sanitized results](experiments/m61/results/2026-10-17-account-authorities.json)
record the real-account evidence. Ordinary unmanaged accounts remain unsupported.
M7's production PAM adapter, isolated native tests and required enforcing-KDE
acceptance cases passed for this domain. Its
[report](docs/development/m7-pam-integration.md) records evidence and native
accounting/TPM recovery limits.
M8 installed sandbox/packaging and
M9 human/specialist review and hardware validation remain open. Read the
[product specification](docs/product-specification.md) and
[implementation plan](docs/implementation-plan.md) before proposing implementation
changes. Authentication behavior needs evidence appropriate to its risk, including
failure and recovery paths.

## Workflow

- Keep `main` reviewable. Use a short-lived branch such as `feat/policy-models`,
  `fix/frame-limit`, or `docs/recovery` for each focused change.
- Make small commits with a clear purpose. Include relevant documentation and
  meaningful tests in the same change.
- Explain the problem, resulting behavior, and validation in a pull request.
  Link the milestone or requirement it addresses and identify remaining limits.
- Resolve design questions in an architecture decision record and amend the
  specification when requirements change. Do not silently weaken release gates.
- Keep unrelated refactoring and generated artifacts out of a change.

Use [tommcamm/LocalPIN](https://github.com/tommcamm/LocalPIN) for issues and pull
requests, targeting `main`. Distinguish local validation from GitHub CI results
and link the relevant workflow run when reporting hosted checks.

## Local checks

Use the toolchain pinned in `rust-toolchain.toml`; the workspace declares its MSRV
in `Cargo.toml`. Commit `Cargo.lock` when dependencies change and review its diff.

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-features --locked
cargo build --workspace --all-features --release --locked
cargo deny --locked check advisories bans licenses sources
```

Install the `cargo-deny` version pinned by CI before the last command. Advisory
checks need access to the configured advisory database. Report unavailable checks
honestly, including environmental failures. These workspace checks include
`localpin-storage`, which requires Linux and kernel support for `openat2` and
fails closed when unavailable. Policy/protocol tests use simulated authorities,
stores and workers. Storage tests use synthetic lifecycle identities and
credentials with actual temporary-file and process I/O to exercise persistence,
recovery and locking. They do not establish production lifecycle enforcement or
platform authentication. Read the [M3 storage report](docs/development/m3-protected-storage.md)
and [ADR 0008](docs/adr/0008-protected-storage-and-recovery.md) when changing these
contracts. Run the separate
[M1 harnesses](experiments/m1/README.md) when changing feasibility code; do not
report their container results as real KDE or SELinux evidence.

New dependencies need a documented purpose, maintenance and advisory review,
license review, MSRV compatibility, and any native-library requirements. Keep the
dependency set small and pin reproducible release inputs.

Native builds require TPM2-TSS 4.x and libdbus development libraries and pkg-config.
Run `python3 crates/localpin-tpm/tests/run_simulator.py` with
`swtpm` and `tpm2-tools` for the explicit disposable simulator suite. Ordinary
workspace tests never open a TPM device. Read the
[M4 report](docs/development/m4-credential-backends.md) before changing cryptographic
payloads or session templates; the native primitives run through M5's supervised
worker boundary in the broker. Read the
[M5 report](docs/development/m5-bounded-broker.md) and
[ADR 0010](docs/adr/0010-bounded-broker-and-live-peers.md) when changing sockets,
peer identity, deadlines or authorization delivery. Local socket and
`SO_PEERPIDFD` tests require Linux 6.5+ and permission to use local IPC; denied
syscalls are infrastructure failures, not passing negative assertions.
Ordinary tests never install units or change host authentication.

Read the [M6 report](docs/development/m6-enrollment-cli.md) and
[ADR 0011](docs/adr/0011-trusted-enrollment-and-cli.md) before changing enrollment,
password-worker policy, terminal input or credential publication. Run the
isolated enrollment and password-PAM suites when modifying those boundaries:

```sh
python3 crates/localpind/tests/run_enrollment_broker.py
python3 crates/localpin-auth/tests/isolated_pam.py
```

Changes to production account support also require
[ADR 0012](docs/adr/0012-immutable-appliance-account-authority.md), the
[account administration contract](docs/account-administration.md) and the
[M6.1 evidence report](docs/development/m6.1-account-authorities.md). The supported
domain uses immutable account/policy inputs plus a kernel writer-drain barrier;
root administration durably revokes all incarnations before changing them.
Do not substitute UID/name/home equality, a synthetic authority or successful
password authentication for this proof. Own-user operations must not create or
repair required state. Repeat the guarded real-account matrix in an independent
disposable Fedora KDE VM with SELinux enforcing; ordinary workspace tests cannot
establish those guarantees. Lifecycle provisioning changes global VM account
administration and is never a host-side test setup step.

## Authentication experiments

Use disposable Fedora KDE VMs and simulated TPMs for early integration and
negative tests. Do not use an everyday machine's PAM configuration, real password
database, credential state, or TPM failure budget as a test fixture. Read-only
host observations do not establish supported-platform compatibility.

Never commit passwords, PINs, derived authorization values, real credential
records, private keys, system authentication files, VM images, or unsanitized
logs. Use clearly synthetic, sanitized fixtures and document their purpose.

Report suspected vulnerabilities according to [SECURITY.md](SECURITY.md).

## Licensing

By submitting original contributions for inclusion in LocalPIN, you agree that
they may be distributed under `MIT OR Apache-2.0`, unless explicitly stated
otherwise. Retain applicable attribution and license notices for any reused
material, and identify it in the change. Do not copy upstream code or
documentation without checking its terms.
