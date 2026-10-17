# Contributing to LocalPIN

Thanks for helping make LocalPIN easier to use, understand, and review.
Documentation fixes, reproducible bug reports, test improvements, and code
contributions are welcome.

LocalPIN is experimental authentication software with no supported production
release. The current target is an existing Fedora KDE 44 x86_64 session. Targeted
M8.1 desktop and package tests passed in a disposable guest with SELinux enforcing
and a private TPM emulator; independent review, physical hardware validation,
and release gates remain open. See the [README](README.md) for an overview and
the [M8.1 report](docs/development/m8.1-desktop-compatibility.md) for the exact
evidence and its limits.

## Choose a contribution

- **Report a bug:** use the [bug report form](https://github.com/tommcamm/LocalPIN/issues/new?template=bug_report.yml).
  Include the affected commit or package version, environment, expected and
  actual behavior, and steps to reproduce with synthetic data.
- **Suggest a feature:** use the [feature request form](https://github.com/tommcamm/LocalPIN/issues/new?template=feature_request.yml).
  Describe the problem and intended use. Discuss substantial architecture or
  scope changes before implementation.
- **Improve the project:** choose an existing issue or open a focused pull
  request for a small fix. Documentation and test contributions are useful
  starting points.
- **Report a vulnerability:** follow [SECURITY.md](SECURITY.md). Keep exploit
  details and sensitive authentication data out of public issues and PRs.

Keep discussions considerate and specific. Explain your assumptions, ask for
context when needed, and give feedback about the work and its behavior.

## Get started

Fork [tommcamm/LocalPIN](https://github.com/tommcamm/LocalPIN) if you do not have
write access, then clone your fork. With a local checkout:

```sh
git switch main
git pull --ff-only
git switch -c docs/clearer-recovery-guide
```

Choose a branch name that describes your change; `fix/`, `feat/`, `test/`, and
`docs/` are useful prefixes. Install the native build prerequisites described in
the [README](README.md#build-from-source). `rust-toolchain.toml` selects the pinned
Rust toolchain; `Cargo.toml` declares the minimum supported Rust version.

Before changing behavior, read the [product specification](docs/product-specification.md)
and the relevant part of the [implementation plan](docs/implementation-plan.md).
The specification defines the requirements; development reports describe the
evidence gathered so far. Resolve changes to a design contract in an
[architecture decision record](docs/adr/) and update the specification when
requirements change.

## Branches and pull requests

Every focused change, including documentation, gets its own short-lived branch
and pull request targeting `main`. Do not commit or push changes directly to
`main`.

1. Start a branch from current `main` and keep unrelated work out of it.
2. Make clear, focused commits. Include relevant documentation and meaningful
   tests with behavior changes; avoid generated build outputs and local state.
3. Run checks appropriate to the change and record their actual results.
4. Open a PR against `main` using the repository template. Explain the problem,
   resulting behavior, relevant issue or requirement, and remaining limits.
5. Leave the PR open for maintainer review and approval. Address feedback on the
   same branch; do not merge it automatically or before that review is complete.

## Validation

The [CI workflow](.github/workflows/ci.yml) is the source of truth for automated
checks. Its general workspace checks are:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-features --locked
python3 -m unittest discover -s tools/tests -p 'test_*.py' -v
python3 -m unittest discover -s experiments/m8 -p 'test_*.py' -v
cargo build --workspace --all-features --release --locked
```

For dependency policy checks, install the checker version pinned by CI:

```sh
cargo install cargo-deny --version 0.20.2 --locked
cargo deny --locked check advisories licenses bans sources
```

Use Fedora 44 x86_64 for native validation, matching the current target. At
baseline commit `a066099`, [hosted CI run 39042452799](https://github.com/tommcamm/LocalPIN/actions/runs/39042452799)
failed in Ubuntu PAM loading and the Fedora package-input check. The commands
above describe the configured checks; report their actual results in your
environment.

Advisory checks need access to the configured advisory database. Workspace
storage tests require Linux with `openat2`; local socket and `SO_PEERPIDFD`
tests require Linux 6.5+ and permission to use local IPC. Report unavailable tools,
denied syscalls, and other infrastructure failures explicitly. An unavailable
check is not a passing check. Distinguish local results from
[hosted CI results](https://github.com/tommcamm/LocalPIN/actions/workflows/ci.yml);
link a workflow run when claiming GitHub checks passed.

Match validation to the change. For documentation-only work, check accuracy,
links, commands, and formatting; explain why runtime tests are unnecessary.
Behavior changes need relevant tests, including failure paths. CI also defines
Fedora builds, disposable simulator tests, PAM ABI checks, packaging checks, and
isolated feasibility harnesses; use the relevant component's instructions for
additional validation.

Dependency changes must explain their purpose, maintenance status, license,
enabled features, MSRV compatibility, and native-library requirements. Review
and commit the resulting `Cargo.lock` diff. See the
[dependency policy and inventory](docs/development/dependencies.md).

## Work safely on authentication boundaries

Use disposable Fedora KDE VMs and simulated TPMs for integration and negative
tests. Never use an everyday machine's PAM configuration, password database,
credential state, or TPM failure budget as a test fixture. Ordinary workspace
tests do not install units, modify host authentication, or open a TPM device.

Use the relevant design and validation references when changing these boundaries:

| Change | Start here |
| --- | --- |
| Protected storage, recovery, or credential formats | [Storage and recovery](docs/adr/0008-protected-storage-and-recovery.md), [credential backends](docs/development/m4-credential-backends.md) |
| Sockets, peer identity, worker deadlines, or authorization delivery | [Broker contract](docs/adr/0010-bounded-broker-and-live-peers.md), [broker evidence](docs/development/m5-bounded-broker.md) |
| Enrollment, terminal input, or password verification | [Enrollment contract](docs/adr/0011-trusted-enrollment-and-cli.md), [enrollment evidence](docs/development/m6-enrollment-cli.md) |
| Account identity, lifecycle, or provisioning | [Current account authority](docs/adr/0017-shadow-record-account-authority.md), [account administration](docs/account-administration.md) |
| PAM, fingerprint/password composition, activation, or packaging | [Desktop compatibility contract](docs/adr/0018-kde-native-update-compatibility.md), [persistent accounting](docs/adr/0014-persistent-faillock.md), [integration and recovery](docs/integration-administration.md) |

Preserve password fallback, persistent failure counters, and fail-closed handling
of unknown policy or missing authority. Never infer account continuity from
UID/name/home or password success; own-user operations cannot repair privileged
account or accounting state. Do not reset counters or disable a factor to hide
an incompatible authentication graph.

Changes to these boundaries need evidence appropriate to their risk, including
failure and recovery paths. Repeat affected installed desktop, RPM, and update
cases using the [M8.1 instructions and evidence](docs/development/m8.1-desktop-compatibility.md).
Synthetic tests, container runs, package builds, and operator attestations do not
establish installed KDE behavior, enforcing SELinux compatibility, or physical
hardware support. Keep historical appliance results separate from the current
desktop contract; do not extend a recorded result beyond its tested build and
environment. Independent review and release gates remain separate requirements.

Never commit passwords, PINs, derived authorization values, real credential
records, private keys, system authentication files, VM images, or unsanitized
logs. Use clearly synthetic, sanitized fixtures and document their purpose.

## AI assistance and licensing

AI-assisted contributions are welcome. Contributors remain responsible for
understanding the submitted work, checking its correctness and provenance, and
providing appropriate validation. Explain substantial generated changes when
relevant to review. AI output and automated checks do not replace maintainer or
independent security review.

By submitting original contributions for inclusion in LocalPIN, you agree that
they may be distributed under `MIT OR Apache-2.0`, unless explicitly stated
otherwise. Retain applicable attribution and license notices for reused material
and identify it in the PR. Check the terms before copying upstream code or
documentation.
