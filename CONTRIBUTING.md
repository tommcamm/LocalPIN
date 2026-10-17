# Contributing to LocalPIN

LocalPIN implements the core policy, storage, credentials, bounded broker,
trusted enrollment CLI, PAM adapter and Fedora packaging. Earlier M6.1–M8
acceptance passed for the historical immutable Fedora 44 x86_64 Btrfs appliance;
see the [M8 report](docs/development/m8-packaging-recovery.md). M8.1 changes the
account authority, KDE fingerprint/password composition and distribution-update
contract for an ordinary Fedora KDE 44 x86_64 desktop. Its recorded
[targeted installed cases](docs/development/m8.1-desktop-compatibility.md) passed
with SELinux enforcing and a private TPM emulator, including actual
[KDE/RPM/reboot continuity](experiments/m81/results/installed-desktop-and-continuity.json)
and [DNF updates](experiments/m81/results/dnf-upgrade.json). Final source checks
and the compatible `.5` → `.6` RPM upgrade passed with exact protected-state
preservation and automatic restoration of prior activation. The report keeps
each earlier installed case's build scope explicit. GUI/DBus
AccountsService, full old-TPM-credential migration, physical devices and the full
hardware matrix remain unvalidated. M9 independent human/specialist review and
release gates remain open; hosted CI execution remains unverified.

Read the [product specification](docs/product-specification.md) and
[implementation plan](docs/implementation-plan.md) before implementation changes.
Authentication behavior needs evidence appropriate to its risk, including
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
python3 -m unittest discover -s tools/tests
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

Changes to production account support require
[ADR 0017](docs/adr/0017-shadow-record-account-authority.md) and the
[account administration contract](docs/account-administration.md). Managed
identity uses a random root-owned marker in the native shadow record, a separate
random 128-bit incarnation and retained native account locks through delivery.
Test delete/recreate with identical UID/name/home/imported hash, retained home,
normal passwd/chage/usermod and AccountsService, systemd-sysusers additions,
concurrent mutation, restart, migration and crash recovery. Refuse legacy
registries; never infer continuity from UID/name/home or successful password
verification. Own-user operations cannot create/repair required state. Use
isolated native account-tool harnesses and disposable enforcing Fedora guests;
ordinary workspace tests cannot establish the full installed guarantee.

Activation/package changes also require the
[integration administration contract](docs/integration-administration.md),
[persistent accounting decision](docs/adr/0014-persistent-faillock.md), and
current M8.1 compatibility ADRs. Keep historical ADRs/reports distinguishable
from current implementation. The new authority sets no immutable flags and
requires no package-cache window. Prove native marker/incarnation/enrollment and
throttle preservation through real `dnf upgrade`, including package replacements
and service-account creation. Verify KDE password/fingerprint behavior with
persistent counters and no device, wrong/right factor, broker outage and normal
password success. Never reset existing counters or disable a factor to conceal
an incompatible graph. Unknown graphs remain refused.

Synthetic tests, root operator attestations and package builds do not complete
the installed enforcing KDE/RPM/reboot/console matrix. The
[M8.1 report](docs/development/m8.1-desktop-compatibility.md) links the targeted
cases that passed, including final source and targeted final RPM validation. Repeat
affected installed cases when changing these boundaries; do not extend that
result to unseen policies, untested account administration paths or physical
devices. M9 independent review and hardware/release gates remain separate.

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
