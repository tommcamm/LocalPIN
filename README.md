# LocalPIN

LocalPIN is a personal project to build six-digit PIN unlocking for an existing
Fedora KDE graphical session, with the account password as the recovery route.
It is intended to become useful, reviewable open-source software.

Repository: [tommcamm/LocalPIN](https://github.com/tommcamm/LocalPIN).

**Development status: M5 bounded broker, M4 credential primitives, M3 storage and M2 policy/protocol models implemented locally.**
This repository contains the specification, implementation roadmap, pure Rust
state machines, bounded IPC parsers, protected Linux filesystem storage,
isolated PAM/TPM/platform experiments and guarded Fedora KDE VM tests under
enforcing SELinux. Actual password fallback, account restrictions and a confined
worker have evidence, including real same-UID desktops, ambiguous locker fallback and
independently routed KDE seats. See the [M1 report](docs/development/m1-feasibility.md).
It includes bounded RustCrypto software credentials and a native TPM backend
for use inside supervised workers. See the [M4 report](docs/development/m4-credential-backends.md)
for simulator evidence and remaining hardware and worker gates.
The broker now composes protected throttling, one-operation backend processes,
authenticated Unix sockets and live logind session routing. Its production
account authority still refuses unmanaged accounts. See the
[M5 report](docs/development/m5-bounded-broker.md) for evidence and limits.
It does not yet provide a PAM module, enrollment CLI, or installable package.
There is no supported production release.

## Intended scope

The first target is Fedora KDE on x86_64, for local, non-root accounts. The planned
design uses a small PAM adapter, a local broker with durable attempt limits, and
either a TPM 2.0 credential or an explicitly selected software backend. Password
fallback, opt-in activation, enforcing SELinux support, and tested recovery are
release requirements; they have not yet been demonstrated end to end.

Initial login, sudo, SSH, polkit, and disk encryption are outside the initial
scope. Six-digit PINs have limited entropy. The
[product specification](docs/product-specification.md) defines the threat model,
backend limitations, and acceptance requirements. Rust alone does not establish
a security guarantee.

## Build and test

Install Rust through rustup, then run these commands from the repository root.
`rust-toolchain.toml` selects the pinned toolchain; `Cargo.toml` declares the minimum
supported Rust version. `localpin-core` models enrollment, eligibility,
revocation, resource budgets and durable throttling; `localpin-protocol` models
bounded messages and connection ordering. `localpin-storage` implements
descriptor-relative protected files, stable process locks, durable throttle
updates and atomic credential generations. Its Linux `openat2` dependency is
required at runtime; unsupported kernels fail closed. `localpin-credentials`
implements strict Argon2id PHC records and shared PIN derivation;
`localpin-tpm` implements the pinned TPM construction using `tss-esapi`.
Native builds require `pkg-config` and TPM2-TSS 4.x development libraries
(`tpm2-tss-devel` on Fedora; `libtss2-dev` on Ubuntu), plus libdbus development
libraries (`dbus-devel` / `libdbus-1-dev`). The broker requires Linux 6.5 or later
with `SO_PEERPIDFD`, procfs, and a system bus/logind. Dependencies are reviewed in the
[build-input inventory](docs/development/dependencies.md).

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
cargo build --workspace --locked
```

These workspace checks cover policy, protocol, storage, backends and broker.
Policy/protocol tests use simulated authorities and workers; storage tests use
synthetic account identities and credentials with actual filesystem and process
I/O, including persistence faults and contention. See the
[M3 storage report](docs/development/m3-protected-storage.md)
and [storage/recovery decision](docs/adr/0008-protected-storage-and-recovery.md)
for evidence and limits. Simulator, benchmark and protected-broker checks are
explicit opt-in commands using synthetic inputs and disposable state:

```sh
python3 crates/localpin-tpm/tests/run_simulator.py
cargo run -p localpin-credentials --example benchmark --release --locked
python3 crates/localpind/tests/run_protected_broker.py
```

The simulator test requires `swtpm` and `tpm2-tools`. The protected broker suite
requires bubblewrap, user namespaces and subordinate UID/GID mappings; it uses
only disposable state and synthetic account authorities. The benchmark uses synthetic
input and reports local KDF latency. These checks do not validate production PAM, physical TPMs,
password fallback, or desktop integration. There are no installation or
activation commands at this stage.

See the [M2 report](docs/development/m2-policy-contracts.md) for exact time and
failure boundaries. Production account support requires a tested lifecycle
authority that detects UID reuse; no production authority exists yet. The
current models and storage adapter deliberately refuse unsupported lifecycle
evidence. Account lifecycle and account-policy enforcement remain required
before permanent account enrollment. Broker systemd units are development
contracts; installed SELinux/sandbox validation remains part of packaging.

## Development

Read the [implementation plan](docs/implementation-plan.md) for milestones and
evidence gates, [CONTRIBUTING.md](CONTRIBUTING.md) for the Git and validation
workflow, and [SECURITY.md](SECURITY.md) for private security reporting guidance.
The [build-input inventory](docs/development/dependencies.md) records the initial
toolchain and dependency policy, and the [M0 report](docs/development/m0-foundation.md)
records foundation validation. The [M1 evidence report](docs/development/m1-feasibility.md)
links the runnable experiments and architecture decisions, with
[VM setup steps](docs/development/m1-vm-setup.md) for reproducing the desktop tests
and their remaining gates.
Changes are tracked in [CHANGELOG.md](CHANGELOG.md).

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
