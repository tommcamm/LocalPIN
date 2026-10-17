# Contributing to LocalPIN

Thanks for helping make LocalPIN easier to use, understand, and review.
Documentation fixes, reproducible bug reports, test improvements, and code
contributions are welcome.

LocalPIN is experimental authentication software with no supported production
release. The current target is an existing Fedora KDE 44 x86_64 session. Targeted
M8.1 desktop/package and M8.2 guided-setup cases passed in disposable guests with
SELinux enforcing and private TPM emulators; independent review, physical
hardware validation and release gates remain open. See the [README](README.md)
for an overview and the [M8.1](docs/development/m8.1-desktop-compatibility.md) and
[M8.2 reports](docs/development/m8.2-installed-acceptance.md) for the exact
evidence and scope limits.

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
`docs/` are useful prefixes. Follow [Build from source](#build-from-source) for
the native prerequisites and first build.

Before changing behavior, read the [product specification](docs/product-specification.md)
and the relevant part of the [implementation plan](docs/implementation-plan.md).
The specification defines the requirements; development reports describe the
evidence gathered so far. Resolve changes to a design contract in an
[architecture decision record](docs/adr/) and update the specification when
requirements change.

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

If you already cloned a fork, run the Cargo commands from that checkout.
Building does not install or activate LocalPIN. The CLI's `doctor` and `status`
commands provide read-only diagnostics; enrollment needs a separately prepared
broker, supported account authority, and fresh interactive password verification.
See the [CLI reference](crates/localpinctl/README.md) and the
[installation and recovery runbook](docs/integration-administration.md).

The [validation commands](#validation) below include the first source checks
(`cargo fmt`, Clippy, and workspace tests), dependency policy, and separate
simulator/PAM/VM suites. Workspace tests do not establish installed desktop or
physical hardware compatibility. For an RPM build, follow the
[Fedora packaging guide](packaging/fedora/README.md#build-without-installing).

## Branches and pull requests

Every focused development change, including documentation, gets its own
short-lived branch and pull request targeting `main`. Do not commit or push
development changes directly to `main`.

1. Start a branch from current `main` and keep unrelated work out of it.
2. Make clear, focused commits. Include relevant documentation and meaningful
   tests with behavior changes; avoid generated build outputs and local state.
3. Run checks appropriate to the change and record their actual results.
4. Open a PR against `main` using the repository template. Explain the problem,
   resulting behavior, relevant issue or requirement, and remaining limits.
5. Leave the PR open for maintainer review and approval. Address feedback on the
   same branch; do not merge it automatically or before that review is complete.

The manually dispatched experimental release workflow has a narrow exception:
it may create a generated version-only commit on a release branch and publish
its tag without merging that commit. This direct child of reviewed `main` may
change only matching manifests, lockfiles, package metadata and changelog. A retry
may reuse only the exact candidate, which must pass release checks before
publication. The workflow never pushes to `main`, force-pushes or replaces tags.
The exception does not cover ordinary development, changes to release automation
or automatic PR merges. See the [release policy](docs/releasing.md).

## Validation

The [CI workflow](.github/workflows/ci.yml) is the source of truth for automated
checks. Ubuntu runs Rust formatting, Clippy, Python checks, and the release build;
Fedora 44 runs the full workspace tests and doctests with native PAM inputs,
simulator checks, and packaging checks. The corresponding local commands are:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-features --locked
python3 -m unittest discover -s tools/tests -p 'test_*.py' -v
python3 -m unittest discover -s experiments/m8 -p 'test_*.py' -v
python3 -m unittest discover -s experiments/m82 -p 'test_*.py' -v
cargo build --workspace --all-features --release --locked
```

For dependency policy checks, install the checker version pinned by CI:

```sh
cargo install cargo-deny --version 0.20.2 --locked
cargo deny --locked check advisories licenses bans sources
```

Use Fedora 44 x86_64 for native validation, matching the current target. Some
native PAM tests load Fedora's `libpam.so.0` path; a passing build on another
distribution does not establish native test compatibility. The commands above
describe the configured checks; report their actual results in your environment.

Successful Fedora jobs publish an unsigned testing RPM, build provenance, and
SHA256 checksums for 14 days. Follow the
[artifact download and testing instructions](packaging/fedora/README.md#download-a-ci-testing-rpm)
and link the workflow run and tested commit in testing reports. Pull-request
builds test GitHub's merge commit; the bundle records the PR head separately.

Versioned experimental releases use the separate
[manual release workflow](docs/releasing.md). If the committed version has already
been tagged, it commits the next version to a release branch, then reruns CI and
publishes from that exact commit in the same run. Record changes under
`Unreleased` in `CHANGELOG.md` so release preparation can carry them forward.
Its release helper tests run with:

```sh
python3 -m unittest discover -s packaging/fedora -p 'test_release*.py' -v
```

Track remaining candidate, review and hardware evidence in the
[M9 checklist](docs/development/m9-release-readiness.md). Reproducible core/protocol
adversarial campaigns run in normal Cargo tests; they do not substitute for
coverage-guided fuzzing, applicable native tooling or independent review.

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

## Project background

LocalPIN is an independent personal project. The existing
[pam_pinlock project](https://github.com/saltnpepper97/pam_pinlock) provides
migration context. LocalPIN's exact-block migration requires fresh provisioning
and enrollment and does not import old verifiers. Broader compatibility or a
security improvement over that project has not been demonstrated.

Use the [documentation index](docs/README.md) for component references, design
contracts, development evidence, and the current implementation plan.

## AI assistance and licensing

Development uses OpenAI Codex and other large language models, with maintainer
oversight. AI assistance does not replace human review or the independent
security review required before a production release.

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
