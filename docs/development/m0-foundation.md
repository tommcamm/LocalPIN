# M0 foundation report

Date: 2026-10-16.

The LocalPIN repository foundation is implemented and validated locally. At the
time of the local checks below, hosted CI had not run. M1 feasibility work has
not started. The project repository is
[tommcamm/LocalPIN](https://github.com/tommcamm/LocalPIN).

## Delivered

- Git initialized with `main`; the original specification and roadmap have
  separate baseline commits. M0 changes are on `chore/repository-foundation`.
- The original `specs.md` moved to
  [`docs/product-specification.md`](../product-specification.md), with a clearer
  title. Its requirements are unchanged; Git records the rename.
- Project name LocalPIN and `MIT OR Apache-2.0` licensing for original material.
- A small Rust 2024 workspace with one dependency-free `localpin-core` library,
  committed `Cargo.lock`, and Rust 1.99.1 pinned in `rust-toolchain.toml`.
- An initial MSRV of 1.99.1, matching the toolchain actually tested. This is a
  conservative support choice, not a claim that edition 2024 requires 1.99.1.
- Formatting and lint policy, local-artifact ignore rules, README, contribution
  guide, security policy, changelog, and issue/PR templates.
- Read-only GitHub CI configuration for Rust quality, dependency policy, and
  Fedora 44 x86_64 build/tests; external actions pinned to full commit hashes.
- A [build-input inventory](dependencies.md) recording tool versions, source
  references, dependency policy and reproducibility limits.

No verifier, broker, PAM module, enrollment worker, CLI, installer, or RPM exists
yet. The library contains only foundation documentation. No runtime/native
dependencies or speculative component scaffolding have been added.

## Validation performed

The implementation revision `31d66ef` was cloned into a temporary directory with
`git clone --no-local`, so ignored tool caches and existing build outputs were
not copied. The following checks passed on Fedora 44 x86_64 using Rust 1.99.1:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features --locked --offline -- -D warnings
cargo test --workspace --all-features --locked --offline --target x86_64-unknown-linux-gnu
cargo build --workspace --all-features --release --locked --offline --target x86_64-unknown-linux-gnu
cargo doc --workspace --no-deps --locked --offline
cargo deny --frozen check advisories bans licenses sources
```

The clone remained clean after these checks. `cargo-deny` 0.20.2 was built from
its published locked dependencies and invoked from an ignored local tools
directory. An online policy check also passed before the clean-clone check;
the clone used the same local advisory cache with network access disabled.

There are zero unit tests and zero doctests at M0. Passing the test command
establishes that the test harness builds; it provides no authentication evidence.
The dependency graph contains no third-party crates, so the policy check is a
configuration baseline rather than a dependency security assessment.

Additional checks passed:

- TOML and GitHub workflow/issue-template YAML parsing.
- `bash -n` for every workflow shell block.
- Workflow read-only permissions, expected triggers, full action commit hashes,
  and disabled checkout credential persistence.
- Local Markdown links, pinned-toolchain/MSRV consistency, ignore behavior,
  license texts, and Git whitespace checks for the new foundation files.
- A separate agent review of documentation and configuration, with no material
  findings. This is development review, not the independent security review
  required before production readiness.

## Remaining evidence and publication work

The GitHub-hosted workflow and its Fedora container provisioning had not run at
the time of this report's local checks. The local Fedora build is not a substitute
for those execution results. Verify the initial hosted run and resolve any
runner-specific failures.

Before accepting external security reports, enable GitHub private vulnerability
reporting or establish a maintained private contact. Branch protection and
release signing remain publication/release tasks.

No authentication or TPM operation was tested, and no system PAM configuration
was changed during M0. The next implementation work is the isolated feasibility
experiments and design decisions in M1.
