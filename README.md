# LocalPIN

**Six-digit PIN unlocking for your existing Fedora KDE session, with your account
password as the recovery route.**

[![CI](https://github.com/tommcamm/LocalPIN/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/tommcamm/LocalPIN/actions/workflows/ci.yml)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue)](#license)

[Build from source](#build-from-source) ·
[Download a testing RPM](packaging/fedora/README.md#download-a-ci-testing-rpm) ·
[Installation and recovery](docs/integration-administration.md) ·
[Contribute](CONTRIBUTING.md) ·
[Report a security issue](SECURITY.md)

LocalPIN adds an opt-in PIN path to the KDE lock screen. It combines a small PAM
adapter, a local Rust broker, durable attempt limits, and a choice of TPM 2.0 or
explicitly selected software credentials. Your normal account password remains
available for unlocking and recovery.

> [!WARNING]
> LocalPIN is experimental. There is no supported production release. Independent
> security review and physical hardware validation remain open. Start in a
> disposable Fedora KDE VM and verify password fallback and console recovery
> before relying on any installation.

## What works today

The implementation includes enrollment and PIN changes, account lifecycle checks,
protected credential storage, software and TPM backends, KDE PAM integration,
Fedora RPM packaging, SELinux confinement, and administrator recovery tools.

The current M8.1 milestone has recorded source checks and targeted installed-RPM
acceptance on Fedora KDE 44 x86_64 with SELinux enforcing and a private TPM
emulator. The tested cases include KDE PIN/password unlocking, missing-component
fallback, console recovery, native account tools, ordinary DNF maintenance,
compatible LocalPIN upgrades, and reboot continuity. The
[M8.1 report](docs/development/m8.1-desktop-compatibility.md) records the exact
builds, evidence, and coverage limits.

Physical TPMs and fingerprint devices, alternate filesystems, AccountsService
GUI/DBus administration, and the full hardware matrix still need validation.
[M9](docs/implementation-plan.md#m9--review-hardware-validation-and-versioned-release)
covers independent review and the remaining release gates.

Hosted CI checks Rust lint/build quality on Ubuntu and runs the full workspace
tests, native PAM/TPM checks, and RPM build on Fedora 44. Successful Fedora jobs
provide an unsigned testing RPM with build metadata and checksums. See
[GitHub Actions](https://github.com/tommcamm/LocalPIN/actions/workflows/ci.yml)
for results; CI is separate from installed desktop and hardware evidence.

## Scope and security model

| Area | Current target |
| --- | --- |
| Platform | Fedora KDE 44, x86_64, SELinux enforcing; installed evidence uses Btrfs |
| Accounts | Local, non-root accounts with the documented native account authority |
| Authentication | Unlocking an existing local graphical session |
| Credentials | TPM 2.0 backend or an explicitly selected Argon2id software backend |
| Policy | Reviewed local authselect/PAM layouts and persistent native faillock accounting |
| Recovery | Account password and a separate administrator console recovery tool |

Initial login, sudo, SSH, polkit, and disk encryption are outside the initial
scope. Network accounts, systemd-homed, and custom authentication policies require
separate compatibility work. Unsupported or ambiguous policy/state refuses PIN
use; see the [account](docs/account-administration.md) and
[integration](docs/integration-administration.md) contracts for exact boundaries.

A six-digit PIN has limited entropy. Backend choice, protected state, and durable
attempt limits are part of the design; a PIN is not a general replacement for a
strong password. The [product specification](docs/product-specification.md)
defines the threat model and backend limitations. Implementation language and
passing tests alone do not establish a security guarantee.

## Build from source

Use a Fedora development environment with Rust installed through rustup. The
repository selects its toolchain in [rust-toolchain.toml](rust-toolchain.toml)
and declares its minimum Rust version in [Cargo.toml](Cargo.toml).

Native builds need a C compiler, `pkg-config`, TPM2-TSS 4.x development libraries,
and libdbus development libraries. On Fedora, install the build inputs with:

```sh
sudo dnf install gcc pkgconf-pkg-config tpm2-tss-devel dbus-devel
```

Python 3 is used by the test and packaging tools. Broker operation requires
Linux 6.5 or later with `SO_PEERPIDFD`, procfs, and a system bus/logind; protected
storage also requires `openat2` support.

```sh
git clone https://github.com/tommcamm/LocalPIN.git
cd LocalPIN
cargo build --workspace --all-features --release --locked
cargo run -p localpinctl -- --help
```

Building does not install or activate LocalPIN. The CLI's `doctor` and `status`
commands provide read-only diagnostics; enrollment needs a separately prepared
broker, supported account authority, and fresh interactive password verification.
See the [CLI reference](crates/localpinctl/README.md).

For a first source check:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-features --locked
```

[CONTRIBUTING.md](CONTRIBUTING.md#validation) covers the full local checks,
dependency policy, and separate simulator/PAM/VM suites. Workspace tests do not
establish installed desktop or physical hardware compatibility.

## Experimental installation

Download an experimental, unsigned RPM from a successful Fedora CI job or build
one yourself using the [Fedora packaging guide](packaging/fedora/README.md).
CI artifacts are retained for 14 days and identify the tested commit.
Installation starts no services and leaves PIN integration disabled.
Preparation, enrollment, a timed trial, password/recovery tests, and explicit
activation are separate steps in the
[installation and recovery runbook](docs/integration-administration.md).

Use a disposable enforcing Fedora KDE VM first. The runbook includes the required
persistent native accounting setup, supported policy layouts, compatible-update
behavior, and recovery from a text console. Building or installing an RPM does
not complete those checks.

## Inside the project

| Component | Responsibility |
| --- | --- |
| [`localpin-pam`](crates/localpin-pam) | Small PAM adapter for the KDE unlock path |
| [`localpind`](crates/localpind) | Broker, account authority, and supervised backend workers |
| [`localpinctl`](crates/localpinctl) | Interactive enrollment, credential changes, and diagnostics |
| [`localpin-auth`](crates/localpin-auth) | Private password-only PAM and eligibility workers |
| [`localpin-core`](crates/localpin-core) / [`localpin-protocol`](crates/localpin-protocol) | Policy, bounded messages, and operation contracts |
| [`localpin-storage`](crates/localpin-storage) | Protected files, credential generations, and durable throttling |
| [`localpin-credentials`](crates/localpin-credentials) / [`localpin-tpm`](crates/localpin-tpm) | Software credentials, PIN derivation, and TPM operations |
| [`packaging/fedora`](packaging/fedora) / [`tools`](tools) | RPM/confinement definitions and activation/recovery tooling |

Start with the [implementation plan](docs/implementation-plan.md) for the roadmap,
the [architecture decisions](docs/adr) for design rationale, and the
[changelog](CHANGELOG.md) for delivered changes. Historical milestone reports
retain their original scope; M8.1 supersedes the earlier immutable-appliance
account model.

## Contributing

Bug reports, documentation improvements, tests, and focused implementation work
are welcome. Read [CONTRIBUTING.md](CONTRIBUTING.md) before starting. Every change,
including documentation, uses its own branch and a pull request targeting `main`
for maintainer review.

Use [issues](https://github.com/tommcamm/LocalPIN/issues) for non-sensitive bugs
and feature proposals. Follow [SECURITY.md](SECURITY.md) for suspected
vulnerabilities; never put authentication secrets or private exploit details in
public issues.

## Project background and AI assistance

LocalPIN is an independent personal project. The existing
[pam_pinlock project](https://github.com/saltnpepper97/pam_pinlock) provides
migration context. LocalPIN's exact-block migration requires fresh provisioning
and enrollment and does not import old verifiers. Broader compatibility or a
security improvement over that project has not been demonstrated.

Development uses OpenAI Codex and other large language models, with maintainer
oversight. Contributors remain responsible for understanding and validating
their changes. AI assistance does not replace human review or the independent
security review required before a production release.

## License

Copyright 2026 LocalPIN contributors.

Original project material is dual-licensed under [MIT](LICENSE-MIT) or
[Apache-2.0](LICENSE-APACHE), at your option (`MIT OR Apache-2.0`). Third-party
material retains its own notices and license terms.
