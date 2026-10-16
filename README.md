# LocalPIN

LocalPIN is a personal project to build six-digit PIN unlocking for an existing
Fedora KDE graphical session, with the account password as the recovery route.
It is intended to become useful, reviewable open-source software.

Repository: [tommcamm/LocalPIN](https://github.com/tommcamm/LocalPIN).

**Development status: repository foundation (M0).** This repository contains the
specification, implementation roadmap, and an initial Rust workspace. It does not
yet provide a PIN verifier, broker, PAM module, CLI, or installable package. There
is no supported production release.

## Intended scope

The first target is Fedora KDE on x86_64, for local, non-root accounts. The planned
design uses a small PAM adapter, a local broker with durable attempt limits, and
either a TPM 2.0 credential or an explicitly selected software backend. Password
fallback, opt-in activation, enforcing SELinux support, and tested recovery are
release requirements; they have not yet been demonstrated.

Initial login, sudo, SSH, polkit, and disk encryption are outside the initial
scope. Six-digit PINs have limited entropy. The
[product specification](docs/product-specification.md) defines the threat model,
backend limitations, and acceptance requirements. Rust alone does not establish
a security guarantee.

## Build the foundation

Install Rust through rustup, then run these commands from the repository root.
`rust-toolchain.toml` selects the pinned toolchain; `Cargo.toml` declares the minimum
supported Rust version. The initial `localpin-core` library has no dependencies
or authentication functionality.

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
cargo build --workspace --locked
```

These checks validate the workspace foundation. They do not validate PAM, TPM,
password fallback, or desktop integration. There are no installation or activation
commands at this stage.

## Development

Read the [implementation plan](docs/implementation-plan.md) for milestones and
evidence gates, [CONTRIBUTING.md](CONTRIBUTING.md) for the Git and validation
workflow, and [SECURITY.md](SECURITY.md) for private security reporting guidance.
The [build-input inventory](docs/development/dependencies.md) records the initial
toolchain and dependency policy, and the [M0 report](docs/development/m0-foundation.md)
records validation actually performed. Changes are tracked in [CHANGELOG.md](CHANGELOG.md).

The existing [pam_pinlock project](https://github.com/saltnpepper97/pam_pinlock)
provides migration context. LocalPIN begins as an independent implementation;
no compatibility, migration tooling, or security improvement over that project
has been demonstrated.

## AI disclosure

LocalPIN is developed using OpenAI Codex and other large language models (LLMs),
with human code review and maintainer oversight. AI assistance does not replace
testing or the independent security review required before a production release.

## License

Copyright 2026 LocalPIN contributors.

Original project material is licensed under either the [MIT license](LICENSE-MIT)
or the [Apache License, Version 2.0](LICENSE-APACHE), at your option
(`MIT OR Apache-2.0`). Any future third-party material retains its own notices
and license terms.
