# LocalPIN

LocalPIN is a personal project to build six-digit PIN unlocking for an existing
Fedora KDE graphical session, with the account password as the recovery route.
It is intended to become useful, reviewable open-source software.

Repository: [tommcamm/LocalPIN](https://github.com/tommcamm/LocalPIN).

**Development status: M8.1 final source checks and targeted installed RPM acceptance passed on Fedora KDE 44; M9 independent review, hardware and release gates remain open.**

The current target is a normal Fedora KDE 44 x86_64 system with local accounts,
SELinux enforcing, and routine `dnf upgrade`. M8.1 replaces the frozen appliance
account model with root-owned shadow-record markers and native account locks.
It supports existing stock `files systemd` NSS layouts, follows Linux-PAM's
stable SONAME, and separates KDE password and fingerprint substacks. See
[ADR 0017](docs/adr/0017-shadow-record-account-authority.md), the
[account runbook](docs/account-administration.md), and the
[integration runbook](docs/integration-administration.md). The
[M8.1 report](docs/development/m8.1-desktop-compatibility.md) records actual KDE
PIN/password/recovery, fingerprint-plus-faillock, reboot and compatible RPM
acceptance with SELinux enforcing and a private TPM emulator. The
[ordinary DNF transaction](experiments/m81/results/dnf-upgrade.json) updated 26
packages and installed five new kernel RPMs; [native reinstallation](experiments/m81/results/native-pam-reinstall.json)
replaced seven PAM/authselect runtime inodes without re-enrollment. Final source
checks and the compatible `.5` → `.6` RPM upgrade passed, preserving enrollment,
counters and policies and restoring prior activation. Each earlier installed
case retains its recorded build scope. There is no supported production release.

Earlier milestones provide the core policy/state machines, protected storage,
software and TPM credentials, bounded broker/IPC, trusted enrollment CLI and
PAM adapter. The [M1](docs/development/m1-feasibility.md),
[M4](docs/development/m4-credential-backends.md),
[M5](docs/development/m5-bounded-broker.md) and
[M6](docs/development/m6-enrollment-cli.md) reports record their evidence and
limits. [M6.1](docs/development/m6.1-account-authorities.md),
[M7](docs/development/m7-pam-integration.md) and
[M8](docs/development/m8-packaging-recovery.md) passed their recorded real-account,
KDE, confinement and RPM matrices on the earlier restricted Fedora 44 x86_64
Btrfs appliance with SELinux enforcing and a private TPM emulator. That
historical acceptance does not certify the changed M8.1 architecture. M9 retains
independent human/specialist review and physical TPM/hardware validation; hosted
CI execution remains unverified.

## Intended scope

The first target is Fedora KDE on x86_64, for local, non-root accounts. The planned
design uses a small PAM adapter, a local broker with durable attempt limits, and
either a TPM 2.0 credential or an explicitly selected software backend. Password
fallback, opt-in activation, enforcing SELinux support, and tested recovery are
release requirements. PAM unlock and fallback have disposable-VM evidence;
the [targeted M8.1 matrix](docs/development/m8.1-desktop-compatibility.md) passed
on a disposable enforcing Fedora KDE 44 x86_64 guest for the recorded builds.
GUI/DBus AccountsService administration and full old-TPM-credential migration
were not exercised. Physical fingerprint devices, TPMs, alternate filesystems
and the full hardware matrix remain unvalidated; historical appliance credentials
require explicit fresh provisioning/enrollment. Hosted CI and independent review
remain open.

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
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-features --locked
cargo build --workspace --all-features --release --locked
cargo deny --locked check advisories bans licenses sources
python3 -m unittest discover -s tools/tests
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
python3 crates/localpind/tests/run_enrollment_broker.py
```

The simulator test requires `swtpm` and `tpm2-tools`. The protected broker suite
requires bubblewrap, user namespaces and subordinate UID/GID mappings; it uses
only disposable state and synthetic account authorities. The benchmark uses synthetic
input and reports local KDF latency. These checks do not validate production PAM, physical TPMs,
password fallback, or desktop integration. Experimental RPM and fixed-path root
administration commands are documented in the
[installation and recovery runbook](docs/integration-administration.md); their
installed acceptance is separate from these checks.

The CLI command grammar is available with `cargo run -p localpinctl -- --help`.
Status and doctor are read-only. Enrollment requires a trusted supported account
baseline, fresh password-only PAM authentication and a foreground terminal;
accounts without privileged marker provisioning remain unavailable. The isolated password-PAM
test uses namespace-private accounts and policy:

```sh
python3 crates/localpin-auth/tests/isolated_pam.py
```

See the [M2 report](docs/development/m2-policy-contracts.md) for exact time and
failure boundaries. Production identity must prevent a deleted account's old
PIN from surviving UID reuse. The current
[account authority](docs/adr/0017-shadow-record-account-authority.md) binds a
random incarnation to the account's root-owned shadow marker and retains native
account locks through response delivery. Ordinary password changes,
service-account additions and package updates can preserve that marker.
Deletion/recreation, lost authority and explicit recovery require fresh
provisioning/enrollment. A changed current login/UID cannot use the old binding;
using that new identity requires fresh provisioning. Reversing an edit on the
same surviving marked record can match its original binding again. No immutable flags are set on new state;
privileged migration durably revokes recognized old appliance state before
removing its flags; unknown/custom immutable hardening is preserved and refused. Own-user enrollment never repairs lifecycle or accounting authority.

Installed activation retains persistent `/var/lib/faillock` accounting;
existing native counters must be preserved. Unknown PAM graphs, ambiguous
identity and missing/corrupt persistent state refuse PIN use. The
[checked M8.1 evidence](experiments/m81/results/updates-summary.json) records
those actual compatible maintenance cases; repeat affected KDE/RPM/DNF checks
for changes to this contract. Development never edits the everyday machine's
authentication setup.

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
provides migration context. LocalPIN is an independent implementation. M8's
explicit migration removes one exact measured legacy KDE block before fresh
provisioning/enrollment; it imports no old verifier. Broader compatibility or a
security improvement over that project has not been demonstrated.

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
