# Contributing to LocalPIN

LocalPIN has completed isolated and guarded enforcing-VM M1 feasibility experiments
and locally implements M2 pure policy/protocol models, M3 protected Linux
storage and M4 credential backend primitives. Production worker integration,
PAM integration and account lifecycle gates remain
open. Read the
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
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
cargo build --workspace --locked
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

Native backend builds require TPM2-TSS 4.x development libraries and pkg-config.
Run `python3 crates/localpin-tpm/tests/run_simulator.py` with
`swtpm` and `tpm2-tools` for the explicit disposable simulator suite. Ordinary
workspace tests never open a TPM device. Read the
[M4 report](docs/development/m4-credential-backends.md) before changing cryptographic
payloads or session templates; the native primitives require M5's supervised
worker boundary before they can be exposed by a broker.

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
