# Build inputs and dependency policy

M2 has two workspace members, `localpin-core` and `localpin-protocol`, and one
third-party Rust dependency, `zeroize`. There are no native PAM, TPM2-TSS,
systemd, or KDF requirements in the production Rust graph yet. Select those
inputs when their milestones introduce them; the specification's machine
inventory is not a dependency pin. The isolated M1 experiments remain separate.

## Current inputs

| Input | Selection | Purpose |
| --- | --- | --- |
| Rust compiler, Cargo, rustfmt, Clippy, standard library | Exact release in [`rust-toolchain.toml`](../../rust-toolchain.toml) | One reviewed toolchain for local development and CI |
| Rust edition and minimum supported Rust version | Workspace package metadata in [`Cargo.toml`](../../Cargo.toml) | Edition 2024; the initial minimum is the tested toolchain version |
| Third-party Rust crates | `zeroize =1.9.1`, `default-features=false`, `alloc` only; [`Cargo.lock`](../../Cargo.lock) is committed | Erase owned PIN/password/record and framing buffers on drop |
| C compiler and system C library | Developer distribution; `gcc` and `glibc` from Fedora 44 in CI | Link Rust executables and test binaries |
| cargo-deny | `0.20.2`, installed with `--locked` | Advisory, license, duplicate/wildcard, and source checks |
| GitHub checkout action | `v7.0.1` at `3d3c42e5aac5ba805825da76410c181273ba90b1` | Fetch the source without retaining checkout credentials |
| Linux CI environments | GitHub `ubuntu-24.04`; official `fedora:44` container on x86_64 | General quality checks and a separate Fedora build/test job |

Toolchain and dependency versions belong in their authoritative files. Keep the
toolchain's `channel` an exact release, and update the workspace minimum version
when changing the supported compiler contract. CI reads the toolchain file rather
than keeping a second Rust version in workflow YAML.

The [checkout release](https://github.com/actions/checkout/releases/tag/v7.0.1)
links to the [pinned commit](https://github.com/actions/checkout/commit/3d3c42e5aac5ba805825da76410c181273ba90b1).
The [cargo-deny release](https://github.com/EmbarkStudios/cargo-deny/releases/tag/0.20.2)
and [release manifest](https://github.com/EmbarkStudios/cargo-deny/blob/0.20.2/Cargo.toml)
record the selected checker and its Rust requirement. Fedora supplies
[`rustup-init` through its rustup package](https://packages.fedoraproject.org/pkgs/rustup/rustup/fedora-44.html);
the container uses it to install LocalPIN's pinned compiler, independently of
Fedora's packaged Rust version.

## Adding or updating dependencies

Every dependency change should explain its purpose, maintained upstream, selected
version and enabled features, license, transitive graph, native requirements, and
effect on the minimum Rust version. Keep unnecessary default features disabled
when the selected crate permits it. Review build scripts and bundled native code.
Commit the resulting `Cargo.lock` update with the code and this inventory.

[`deny.toml`](../../deny.toml) checks every enabled feature without pruning target
platforms. Vulnerability and unsoundness advisories, unmaintained crates, yanked
versions, duplicate versions, wildcard requirements, unapproved licenses, and
unapproved registry/Git sources fail the configured checks. There are no ignored
advisories or policy exceptions at M0. Any future exception needs a specific
reason and a reviewable scope; adding a dependency is not a reason to weaken the
whole policy. The initial allowed license set is MIT and Apache-2.0 and can be
expanded after reviewing an actual dependency's terms.

Run the same dependency check locally with the pinned Rust toolchain:

```sh
cargo install cargo-deny --version 0.20.2 --locked
cargo deny --locked check advisories licenses bans sources
```

`cargo install --locked` uses the checker's published lockfile. The checker is a
development tool; its implementation dependencies are not LocalPIN runtime
dependencies and are outside LocalPIN's `Cargo.lock`.

## M2 Rust dependency review

`zeroize` is maintained by RustCrypto and licensed `Apache-2.0 OR MIT`, within
the existing license policy. Its published manifest declares edition 2024 and
Rust 1.85, below this workspace's pinned 1.99.1. With only `alloc` enabled it has
no transitive dependencies, native libraries or build script. Derive and serde
support remain disabled. The exact release and registry checksum are locked.
The reviewed published source and [published upstream changelog](https://docs.rs/crate/zeroize/1.9.1/source/CHANGELOG.md)
record 1.9.1's fix for a potential uninitialized-memory read in the previous
optimization-barrier fallback; M2 selects the fixed patch. The
[published manifest/source](https://docs.rs/crate/zeroize/1.9.1/source/Cargo.toml)
and [API](https://docs.rs/zeroize/1.9.1/zeroize/) are the primary references.

Project code forbids unsafe code; zeroize's implementation contains its own
reviewed memory-clearing boundary, still within the dependency audit scope.
Zeroizing ownership does not erase prior compiler moves, caller-owned inputs,
native copies, swap, or core dumps. M5/M7 must establish the process/FFI cleanup
and core-dump settings. No custom KDF or constant-time comparison is introduced.
The M2 evidence report records the actual advisory/license/source check result.

## M1 experiment inputs

The isolated experiments add no Rust dependencies and are not release artifacts.
Their original C/Python source remains `MIT OR Apache-2.0`; system tools and
libraries retain their distribution licensing. No third-party headers, native
binaries, upstream KDE source or simulator state are checked in. Runtime crate
and native production dependency selection remains M4/M7 work.

| Input | Observed Fedora package | Use |
| --- | --- | --- |
| Linux-PAM runtime and development headers | `1.7.2-2.fc44` | Isolated PAM C API, known baseline modules and optional packaged `pam_unix` |
| GCC | `16.2.1-2.fc44` | Compile the experimental module/harness with warnings denied |
| Python | `3.14.8-1.fc44` | Standard-library test orchestration, metadata collector and native-call probe |
| bubblewrap (optional) | `0.12.0-1.fc44` | User/mount/PID/network namespaces with synthetic passwd/shadow files |
| swtpm / libtpms | `0.10.2-1.fc44` / `0.10.2-3.fc44` | Disposable TPM instances only |
| tpm2-tools / TPM2-TSS | `5.7-5.fc44` / `4.1.3-9.fc44` | Exercise the TPM construction and blocking native transport |
| libargon2 | `20190702-10.fc44` | Test-only ctypes Argon2id derivation; production uses reviewed RustCrypto code |
| libsystemd | systemd `259.9-1.fc44` | Read-only direct-session versus user-manager ownership observations |

The PAM report records the matching extracted pam-devel RPM SHA-256 and the
kscreenlocker source RPM/installed binary digests. Headers were extracted under
ignored `.local/` without installing packages on the development host. The TPM
report records actual simulator/native versions and exact public-object template.
Distribution license tags include BSD for PAM/TPM tools and LGPL for bubblewrap;
review actual component terms when packaging rather than treating Cargo's
MIT/Apache license allowlist as a native-tool license inventory.

The Fedora M1 CI container installs distribution tools and runs isolated suites
without host credentials, a real TPM, privileged mode or a desktop session. It
does not enable the optional bubblewrap suite, because unprivileged namespaces
depend on the runner's container restrictions. Local optional-suite results and
enforcing-VM results must be recorded separately. M1 CI execution has not yet
been verified on GitHub.

## Guarded M1 VM fixtures

Real-account, KDE, logind and enforcing SELinux fixtures add guest-only test
inputs: `selinux-policy-devel`, `make`, `policycoreutils`, `setools-console`,
`shadow-utils` and `libxcrypt`, alongside the PAM/compiler/Python inputs above.
These are not production Rust dependencies. The actual guest's PAM/authselect,
kscreenlocker, systemd and SELinux versions are recorded in the
[VM evidence reports](m1-feasibility.md) and sanitized JSON. Exact supported
policy digests are fixture allowlists, not automatic product-activation rules.

The guarded runners require a dedicated ordinary account, a UUID-bound
root-owned VM marker, SELinux Enforcing and explicit snapshot confirmation.
They must never be run on an everyday host. CI invokes only their pure tests and
compile-only branches; it does not install policy, open a PAM transaction, change
an account, register sessions or edit the KDE service. The independent isolated
PAM/TPM suites retain their earlier container-only scope. Temporary VM access and
all test state were removed through the recorded final snapshot restoration.

## CI limits

CI runs formatting, Clippy with warnings denied, tests and doctests, and release
builds with the committed lockfile. The Fedora job also runs tests in a disposable
Fedora 44 x86_64 container and records its compiler and native package versions.
It provides initial build evidence, not evidence of KDE, PAM, TPM, SELinux, RPM,
or recovery behavior. Add those jobs when their isolated harnesses exist.

Jobs have read-only repository permissions, use `pull_request` rather than
`pull_request_target`, and do not use self-hosted runners, privileged containers,
host authentication paths, production credentials, or release-signing secrets.
Each external GitHub action is pinned to a full commit SHA. Review and update
action pins and the cargo-deny pin deliberately.

Network access is required to install Rust and cargo-deny, fetch any future
locked crates, install Fedora packages, and refresh the RustSec advisory database
and registry data. Advisory data is intentionally current rather than pinned.
The runner images, Fedora container tag, and distribution package repositories
also receive updates. Exact toolchains and lockfiles constrain the Rust inputs;
M0 does not claim hermetic or bit-for-bit reproducible builds. Release engineering
will need stronger image/package provenance and an explicit reproducibility
check before making either claim.
