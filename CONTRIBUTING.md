# Contributing to LocalPIN

LocalPIN has isolated and guarded enforcing-VM M1 feasibility experiments.
Same-UID desktop, second-seat and production integration gates remain open. Read the
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
honestly, including environmental failures. The initial core library has no
dependencies or authentication behavior, so passing the Rust checks establishes
only the repository foundation. Run the separate
[M1 harnesses](experiments/m1/README.md) when changing feasibility code; do not
report their container results as real KDE or SELinux evidence.

New dependencies need a documented purpose, maintenance and advisory review,
license review, MSRV compatibility, and any native-library requirements. Keep the
dependency set small and pin reproducible release inputs.

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
