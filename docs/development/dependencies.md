# Build inputs and dependency policy

## Guided setup JSON dependencies

The onboarding CLI adds exact direct `serde 1.0.229` (already in the workspace
lockfile, with `derive` and standard-library support) and `serde_json 1.0.150`
with its default `std` feature. The maintained serde-rs implementation parses
the fixed administrator helper's bounded nonsecret report; closed derived
types reject unknown/duplicate fields and incompatible schema versions. It is
not used to serialize passwords, PINs, or broker authorization messages. Public
status/doctor schema-1 output remains unchanged. No terminal UI framework is
added, and the helper adds no Python dependencies.

The lockfile adds `serde_json 1.0.150`, `itoa 1.0.18` and `zmij 1.0.23`;
`memchr`, serde core and derive dependencies were already locked. Serde and
serde_json/itoa use MIT OR Apache-2.0; zmij uses MIT. Their declared Rust minimums
are 1.56 (serde), 1.71 (serde_json and zmij), and 1.68 (itoa), below the pinned
1.99.1 toolchain. These crates add no native-library requirements. Serde_json's
build script selects target arithmetic configuration without downloading or
building native code. Optional arbitrary precision, unbounded-depth parsing,
raw values and order-preserving maps are not enabled.

The CLI bounds helper stdout at 64 KiB and uses a small closed setup report.
Mutation output is also bounded and parsed only for the preparation preview;
it never substitutes for a fresh authoritative report. The local locked
`cargo-deny 0.20.2` check passed advisories, licenses, bans and sources after
refresh on 2026-10-17, with no policy exception. This is dependency-policy
evidence, not independent review of the new orchestration boundary.

The PR review follow-up adds no dependencies. The native account tool's
integration-lock adapter has a narrowly scoped `fcntl` FFI boundary to validate
and duplicate an inherited numeric descriptor, set close-on-exec, and transfer
only the newly allocated descriptor into a Rust `File`. Invalid descriptors
produce an error without creating a borrowed Rust descriptor from an unchecked
integer. Canonical root-owned directories, lock metadata and inode identity are
checked around nonblocking lock acquisition. The duplicate retains the parent's
open-file description and is closed on drop without explicitly unlocking it.
This boundary remains an input to independent human/native review.

The current workspace has nine crates covering policy, IPC, protected storage,
software and TPM credentials, the broker, password/eligibility workers, CLI, and
PAM adapter. Native builds require TPM2-TSS 4.x and libdbus development libraries,
`pkg-config`, and a C compiler. Native PAM integration and installed packaging
have additional runtime and validation inputs; see the
[contribution guide](../../CONTRIBUTING.md#validation) and
[Fedora packaging guide](../../packaging/fedora/README.md).

The exact Rust graph is committed in `Cargo.lock`. This inventory keeps the
milestone-specific dependency reviews below as historical evidence; their crate
counts, measurements, and version observations describe the recorded baseline.
The specification's machine inventory is not a dependency pin. Isolated M1
experiment inputs remain separate from production dependencies.

## Shared build inputs

| Input | Selection | Purpose |
| --- | --- | --- |
| Rust compiler, Cargo, rustfmt, Clippy, standard library | Exact release in [`rust-toolchain.toml`](../../rust-toolchain.toml) | One reviewed toolchain for local development and CI |
| Rust edition and minimum supported Rust version | Workspace package metadata in [`Cargo.toml`](../../Cargo.toml) | Edition 2024; the initial minimum is the tested toolchain version |
| Secret-buffer dependency | `zeroize =1.9.1`, `default-features=false`, `alloc` only | Erase owned PIN/password/record, storage, and framing buffers on drop |
| Filesystem dependency | `rustix =1.1.5`, `default-features=false`, `std` and `fs` only; [`Cargo.lock`](../../Cargo.lock) is committed | Safe descriptor-relative Linux filesystem operations and file locking for protected durable storage |
| C compiler and system C library | Developer distribution; `gcc` and `glibc` from Fedora 44 in CI | Link Rust executables and test binaries |
| cargo-deny | `0.20.2`, installed with `--locked` | Advisory, license, duplicate/wildcard, and source checks |
| GitHub checkout action | `v7.0.1` at `3d3c42e5aac5ba805825da76410c181273ba90b1` | Fetch the source without retaining checkout credentials |
| GitHub artifact upload action | `v7.0.2` at `cf430e030ddbb5b0abf93d22962f4752f3646cd9` | Publish unsigned Fedora testing RPMs, build metadata, and checksums with 14-day retention |
| Linux CI environments | GitHub `ubuntu-24.04`; official `fedora:44` container on x86_64 | General quality checks and a separate Fedora build/test job |
| Release tools | Fedora 44 `rpm-sign`, `gnupg2`, `gh` and Python standard library | Separate manual experimental publication; required OpenPGP signing and verification use protected environment secrets and temporary keyrings |

Toolchain and dependency versions belong in their authoritative files. Keep the
toolchain's `channel` an exact release, and update the workspace minimum version
when changing the supported compiler contract. CI reads the toolchain file rather
than keeping a second Rust version in workflow YAML.

The [manual prerelease workflow](../releasing.md) reuses the pinned checkout and
upload actions above, reruns CI, and tests default features before building the
shipping RPM. It adds no Rust dependency. Its generated SPDX inventory records
the locked target Cargo graph and actual installed Fedora builder RPM versions;
native tools and the `fedora:44` image are resolved at build time rather than
presented as immutable or reproducible inputs. Release signing/publication tools
run separately from the compiler and PR CI.

The [checkout release](https://github.com/actions/checkout/releases/tag/v7.0.1)
links to the [pinned commit](https://github.com/actions/checkout/commit/3d3c42e5aac5ba805825da76410c181273ba90b1).
The [artifact upload release](https://github.com/actions/upload-artifact/releases/tag/v7.0.2)
links to its [pinned commit](https://github.com/actions/upload-artifact/commit/cf430e030ddbb5b0abf93d22962f4752f3646cd9).
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

## M3 filesystem dependency review

`rustix` is a [Bytecode Alliance project](https://github.com/bytecodealliance/rustix).
The reviewed [1.1.5 published manifest](https://docs.rs/crate/rustix/1.1.5/source/Cargo.toml)
declares Rust 1.65 and `Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT`.
Its bundled copyright and license files permit choosing Apache-2.0 or MIT, so
the existing license allowlist needs no exception. Only `std` and `fs` are
requested; `std` also enables `alloc` and `bitflags/std`. Networking, process,
randomness, io_uring, and other optional API groups remain disabled.

The following versions and registry checksums are committed in `Cargo.lock`.
Published manifests, license files, and upstream repository links were reviewed
from the downloaded registry sources. Maintainers are identified by those
upstream repositories; this inventory does not claim these are the latest
available releases.

| Transitive crate | Upstream and purpose | Declared minimum Rust | License |
| --- | --- | --- | --- |
| [`bitflags 2.13.2`](https://docs.rs/crate/bitflags/2.13.2/source/Cargo.toml) | [bitflags project](https://github.com/bitflags/bitflags); typed syscall flag values | 1.56.0 | `MIT OR Apache-2.0` |
| [`linux-raw-sys 0.12.1`](https://docs.rs/crate/linux-raw-sys/0.12.1/source/Cargo.toml) | [sunfishcode/linux-raw-sys](https://github.com/sunfishcode/linux-raw-sys); generated Linux UAPI definitions | 1.63 | `Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT` |
| [`errno 0.3.14`](https://docs.rs/crate/errno/0.3.14/source/Cargo.toml) | [lambda-fairy/rust-errno](https://github.com/lambda-fairy/rust-errno); error access for libc/Windows backends | 1.56 | `MIT OR Apache-2.0` |
| [`libc 0.2.191`](https://docs.rs/crate/libc/0.2.191/source/Cargo.toml) | [rust-lang/libc](https://github.com/rust-lang/libc); platform C ABI declarations for fallback targets | 1.65 | `MIT OR Apache-2.0` |
| [`windows-sys 0.61.2`](https://docs.rs/crate/windows-sys/0.61.2/source/Cargo.toml) | [Microsoft windows-rs](https://github.com/microsoft/windows-rs); Windows API declarations for target-specific rustix/errno support | 1.71 | `MIT OR Apache-2.0` |
| [`windows-link 0.2.1`](https://docs.rs/crate/windows-link/0.2.1/source/Cargo.toml) | [Microsoft windows-rs](https://github.com/microsoft/windows-rs); imports used by windows-sys | 1.71 | `MIT OR Apache-2.0` |

All declared minimums are below the workspace's pinned Rust 1.99.1; the
supported compiler contract is unchanged. The x86_64 Linux feature tree contains
only `bitflags` and `linux-raw-sys` below rustix. The libc/errno and Windows
branches are nevertheless retained in the lockfile and checked by cargo-deny,
which does not prune targets. Their presence does not add Windows support to
`localpin-storage`.

Rustix's reviewed [build script](https://docs.rs/crate/rustix/1.1.5/source/build.rs)
selects its syscall backend and probes compiler capabilities with Rust metadata
compilations. Libc has a Rust build script for compiler/target configuration,
used only when its backend is selected; the other added crates have no build
scripts. None of the selected crates has build dependencies, downloads native
artifacts, runs bindgen at build time, or compiles bundled C libraries. On the
tested Linux x86_64 target, rustix uses its Rust/assembly Linux syscall backend;
the normal Rust executable linker and system libc requirements remain.

Project code still forbids unsafe code. Rustix and its platform bindings contain
the reviewed unsafe syscall/ABI boundary, just as zeroize owns the memory-clearing
boundary. Safe wrappers do not establish path ownership, permissions, absence of
symlinks or hard links, lock lifetime, or crash durability on their own. The
storage adapter and its tests enforce those requirements. Filesystem and
hardware synchronization guarantees remain part of deployment validation.

For M3, `cargo-deny 0.20.2 --locked check advisories bans licenses sources`
passed all four checks with the unchanged policy. The sandbox's default Cargo
home was read-only and its network could not resolve GitHub; the successful run
used a writable copy under ignored `.local/m3-dependency-audit/cargo-home` and
approved network access to refresh RustSec. The checked advisory database commit
was `64f92cdc64401fab47baa10e2e11fe382aa57155` (17 October 2026). This is review
evidence, not a pin: CI must refresh and run the check again.

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
enforcing-VM results must be recorded separately. Consult the
[hosted workflow runs](https://github.com/tommcamm/LocalPIN/actions/workflows/ci.yml)
for current M1 CI execution results.

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

Ubuntu CI runs formatting, Clippy with warnings denied, Python checks, and release
builds with the committed lockfile. Full workspace tests and doctests run in the
disposable Fedora 44 x86_64 job with native PAM inputs. That job also records
compiler and native package versions, tests the PAM ABI and disposable TPM
simulators, compiles SELinux policy, and builds an RPM without installing it.
The Fedora build explicitly installs `systemd` and `selinux-policy-targeted`
alongside development tools so the package-input manifest can query them.

Successful Fedora jobs publish an unsigned RPM, its original `BUILD-INPUTS.json`,
a `CI-BUILD.json` recording the tested commit/run/release, and SHA256 checksums.
The [packaging guide](../../packaging/fedora/README.md#download-a-ci-testing-rpm)
describes downloads, provenance, CI upgrade sequencing, and the 14-day retention.
These checks and artifacts provide scoped container evidence; they do not
establish installed KDE, enforcing SELinux, RPM lifecycle/recovery, or physical
hardware behavior.

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

## M4 credential backend dependencies

The exact direct versions are `argon2 0.6.0`, `base64ct 1.8.3`, `ctutils 0.4.3`,
`getrandom 0.4.3`, `sha2 0.11.1`, `tss-esapi 7.7.0` and build-only
`pkg-config 0.3.34`. They use the existing `zeroize 1.9.1`. The complete
[locked inventory](m4-dependency-inventory.md) records registry versions,
manifest-declared Rust minimums and license expressions, including target-only
entries. All declared minimums fit Rust 1.99.1; undeclared minimums are covered
only by actual builds. Checksums are committed in `Cargo.lock`.

RustCrypto's [Argon2 0.6.0](https://docs.rs/argon2/0.6.0/argon2/) implements
Argon2id v19 and provides the explicit mutable work-memory API. Defaults are
disabled; only `zeroize` is enabled, allowing LocalPIN to clear its owned
`Vec<Block>` and the crate's internal intermediate buffers. No generic PHC
verifier or library allocation/default work policy is used. The same maintained
RustCrypto dependency family supplies [Base64](https://docs.rs/base64ct/1.8.3/base64ct/),
[constant-time equality](https://docs.rs/ctutils/0.4.3/ctutils/) and
[SHA-256](https://docs.rs/sha2/0.11.1/sha2/). SHA-256 processes only public TPM
Names. `ctutils` was selected from the existing Argon2 dependency graph rather
than adding another comparison implementation. LocalPIN implements format
validation, not a new KDF or comparison algorithm.

[`getrandom::fill`](https://docs.rs/getrandom/0.4.3/getrandom/fn.fill.html)
provides OS cryptographic entropy, with errors propagated and partial secret
buffers zeroized. No predictable entropy fallback is permitted. Randomness
injection is a trusted testing boundary, not an IPC option. On the tested Linux
build the dependency uses the native OS interface through libc. Target-only
`r-efi` remains in the lockfile but is not part of Linux runtime code.

[`tss-esapi 7.7.0`](https://docs.rs/tss-esapi/7.7.0/tss_esapi/) is the maintained
Parsec Rust wrapper, Apache-2.0, with declared Rust minimum 1.85. Its default
features are disabled. The transitive `tss-esapi-sys 0.6.0` uses published
x86_64 Linux bindings; `generate-bindings` and bindgen are not enabled. The
wrapper brings ASN.1/serde, enum/bitfield/procedural-macro and regex support even
though this backend uses only its low-level TPM operations. The inventory
retains them rather than describing the native boundary as dependency-free.
The dependency's `Auth`, `SensitiveData` and `Private` buffer wrappers own
zeroizing heap storage. FFI conversions and TPM2-TSS have additional native
allocations; Rust wrappers do not prove erasure of every native copy. This
remains in the independent native/security review scope. `Context::drop` logs
cleanup failures, so LocalPIN explicitly flushes its own handles and checks
success before accepting a native match.

LocalPIN's build script requires matching versions of `tss2-sys`, `tss2-esys`,
`tss2-tctildr` and `tss2-mu` in the pinned ABI range **>=4.0.0,<5.0.0**. Upstream's
sys crate accepts >=2.4.6; LocalPIN deliberately supports a narrower family.
The local test used Fedora `tpm2-tss-4.1.3-9.fc44.x86_64`. Its matching development
RPM was downloaded and extracted under ignored `.local/m4/native/`, without
installing host packages. SHA-256:
`eeed3d8b4a6553645acbaf03e42b50299e9e75dc89590e964d2d6dff8c49b436`.
The local pkg-config metadata points at those extracted development linker
names and the already installed matching runtime. CI installs the distro
development package normally in disposable runners. This is a tested build
input, not a claim that every 4.x firmware/native combination is certified.

Build scripts in this graph configure target/compiler capabilities, generate
Rust metadata or discover native libraries through pkg-config. In particular,
`tss-esapi-sys` does not download or compile a bundled TPM stack. Normal build
scripts and procedural macros execute trusted dependency code during the
build; all remain in the audit scope. Project code still forbids unsafe code;
the TPM wrapper/sys/native stack, OS entropy/libc and selected cryptography
own their respective unsafe/FFI boundaries. RustCrypto CPU feature detection
selects supported optimizations, not a different PIN policy.

`deny.toml` preserves the default MIT/Apache license allowlist and adds only two
exact-version exceptions after reviewing their bundled terms:
`target-lexicon 0.12.16` uses Apache-2.0 WITH LLVM-exception, and
`unicode-ident 1.0.27` additionally requires Unicode-3.0. Both permit
redistribution with applicable notices; packaging must retain those notices.
One exact duplicate exception permits `syn 2.0.119`, required by upstream derive
macros alongside `syn 3.0.9`. No duplicate cryptography family exception was
needed after selecting SHA-256 0.11.1. There are no advisory or source exceptions.

The M4 dependency policy check passed advisories, bans, licenses and sources
with `cargo-deny 0.20.2`, using refreshed RustSec commit
`64f92cdc64401fab47baa10e2e11fe382aa57155` on 2026-10-17. The audit used the
workspace-local writable Cargo cache and approved network access for refresh.
CI must refresh and check again; this result is not a specialist cryptographic
or native-library audit.

## M5 Linux broker and transport dependencies

M5 adds exact direct versions [`dbus 0.9.9`](https://docs.rs/dbus/0.9.9/dbus/)
and [`listenfd 1.0.2`](https://docs.rs/listenfd/1.0.2/listenfd/), and promotes
the already locked `libc 0.2.191` and `sha2 0.11.1` to direct broker dependencies.
The existing `rustix 1.1.5` is enabled for Unix sockets, polling, process handling
and suspend-inclusive time. Existing OS entropy and zeroizing owners remain in
use. Registry checksums and the complete target-inclusive graph are committed
in `Cargo.lock`; no Git/path replacement of an upstream dependency is used.

The dbus-rs wrapper and its exact transitive `libdbus-sys 0.2.7` use
`Apache-2.0/MIT`; `listenfd` uses Apache-2.0; `libc` and `sha2` offer MIT OR
Apache-2.0. The reviewed published manifests declare Rust 1.65 for `libc` and
1.88 for `sha2`; `dbus`, `libdbus-sys` and `listenfd` declare no Rust minimum.
An absent declaration is not a compatibility guarantee: the build check uses
the project's pinned Rust 1.99.1. The added Windows/UUID/WebAssembly entries
remain in the lockfile for target completeness; Linux does not compile them
as part of listener adoption or D-Bus queries. License notices must still be
retained for every component distributed in a binary/package.

`libdbus-sys` discovers system `dbus-1 >=1.6` with the already reviewed
`pkg-config` build dependency. Its `vendored` feature is disabled; no bundled C
stack is built or downloaded. The observed development/runtime input is Fedora
`dbus-devel`/`dbus-libs 1.16.2-1.fc44`, with `pkg-config --modversion dbus-1`
reporting 1.16.2. This is the tested native version, not an extra enforced
minimum or certification of every version accepted by upstream's build script.
Fedora's aggregate package license expression includes both AFL/GPL alternative
terms and GPL-only tools. The linked libdbus library's
[upstream licensing terms](https://dbus.freedesktop.org/doc/dbus-faq.html)
offer the AFL alternative; native-library notices and component selection need
packaging review separately from Cargo's Rust license allowlist. LocalPIN does
not redistribute the D-Bus daemon or claim the entire Fedora package is under
the Rust wrapper's license.

Source review covered dbus-rs's blocking call timeout conversion and channel
creation/registration, the sys crate's pkg-config-only build path, and the
listener crate's Unix descriptor ownership and environment parsing. The broker
opens the fixed `/run/dbus/system_bus_socket`, ignoring inherited
`DBUS_SYSTEM_BUS_ADDRESS`. It calls logind through its unique bus owner, pins
the D-Bus bus ID and session creation timestamp, and repeats checks before a
success can be delivered. A domain-separated, length-delimited SHA-256 digest
of authoritative identity yields the stable opaque session reference. It
processes public routing metadata; the reference is not a bearer authorization.
Method calls share an absolute deadline and have no per-property renewal.
libdbus's native connection/authentication/registration phase has no cancellation
interface in this wrapper: stalled work retains its broker admission slot and
late results cannot authorize, but that phase is not claimed to have a hard
native-call wall-clock bound.

`listenfd` intentionally supports development extensions that accept missing or
empty `LISTEN_PID` and alternate first descriptor numbers. LocalPIN's startup
wrapper rejects those extensions before invoking it: the exact current PID,
exactly one descriptor and the normal descriptor-3 base are required; an
optional descriptor name must be `localpin`. The adopted descriptor is then
independently checked as a listening Unix stream socket at the trusted installed
path. The crate marks it close-on-exec and consumes ownership. Its parser clears
`LISTEN_PID` and `LISTEN_FDS`; adoption occurs before application threads start,
because its environment mutation is not safe to introduce into an already
concurrent process. No systemfd development behavior is part of the broker's
authorization contract.

The core, protocol, storage and credential crates retain the workspace's local
unsafe-code prohibition. Only `localpind` narrows its crate lint to `deny`, with
one function-level exception for `getsockopt(SO_PEERPIDFD)` and immediate
`OwnedFd::from_raw_fd` ownership transfer. `rustix 1.1.5` has no safe wrapper
for this option. The reviewed function supplies correctly sized writable output
buffers, checks the result and returned length, and closes the owned descriptor
on all validation failures. Linux 6.5 or later is required for this operation;
an unsupported option, denied syscall, exited peer or unreadable/mismatching
procfs data fails closed. There is no numeric `pidfd_open` fallback, which could
bind to a recycled PID before the initial process observation. Native liveness
tests exercise both a live child and refusal after that same socket peer exits.
This exception does not permit new unsafe blocks elsewhere or substitute for
an independent FFI/security review.

The refreshed M5 `cargo deny --locked check advisories bans licenses sources`
passed all four categories with cargo-deny 0.20.2 and RustSec commit
`64f92cdc64401fab47baa10e2e11fe382aa57155` on 2026-10-17. An exact duplicate
exception permits Windows-only `windows-sys 0.59.0` required by dbus alongside
rustix's 0.61.2; Linux does not compile that ABI. No advisory or source
exception was introduced. Live logind routing also does not establish supported
account restrictions or an immutable account incarnation, so the default broker
keeps ordinary-account PIN authorization unavailable.

## M6 password worker and terminal dependencies

M6 adds two original workspace crates without introducing a new external crate
version: `localpin-auth` and `localpinctl`. They reuse exact locked `libc 0.2.191`,
`rustix 1.1.5`, `getrandom 0.4.3` and `zeroize 1.9.1`. The CLI enables rustix's
safe terminal/poll APIs and test-only PTY APIs. Native PAM is loaded from the
fixed `libpam.so.0` runtime ABI inside the disposable helper, so compiling does
not require PAM development headers. Runtime password use requires Linux-PAM,
`pam_unix`, `pam_faillock` and the explicitly reviewed service profile.

Two narrowly scoped unsafe boundaries are new review inputs. `localpin-auth`
isolates dynamic symbol loading, native PAM callback/allocator ownership and
NSS UID lookup in `pam.rs`; callbacks catch Rust panics before the C boundary.
The CLI isolates signal-mask calls in its terminal guard, restoring the terminal
before pending termination/suspend signals are unblocked on the same thread.
Both crates deny unsafe code outside their documented exceptions. Native PAM
copies and arbitrary NSS/PAM calls are bounded by disposable worker exit and
supervision, not a claim that zeroize erases upstream allocations.

The helper authenticates only the fixed password service and requires a fresh
hidden password conversation plus account checks. Review of its exact profile
does not certify the distribution's complete policy or installed privileges.
See [ADR 0011](../adr/0011-trusted-enrollment-and-cli.md) and the
[M6 report](m6-enrollment-cli.md) for validation and remaining gates.

The final M6 locked audit passed all four policy categories with cargo-deny
0.20.2. No dependency-policy exception or external crate version was added.

## M6.1 authority review inputs

M6.1 adds no external crate versions. `localpin-auth` reuses the already locked
RustCrypto `sha2 0.11.1` without default features for policy/native-binary input
digests. Credential KDFs and the lockfile's external version graph are unchanged.
The locked cargo-deny 0.20.2 audit passes advisories, bans, licenses and sources.

The lifecycle manager uses rustix's safe immutable-inode, descriptor-relative,
POSIX lock and unnamed temporary-file APIs. A new function-scoped unsafe
`fcntl(F_SETLEASE/F_GETLEASE)` exception accepts only a live borrowed read-only
file and fixed integer commands. It supplies the kernel writer-drain proof;
there are no pointer arguments or caller-selected operations. Its descriptor
ownership, kernel lease semantics and publication lifetime received separate
review and real Btrfs VM tests. Test-only writable-mapping fixtures isolate their
own documented mmap/munmap ABI. See [ADR 0012](../adr/0012-immutable-appliance-account-authority.md).

The password-free worker retains PAM's narrow ABI and pins the measured Fedora
PAM library/modules by SHA256. Policy or native-module updates outside that exact
set become unavailable and require new compatibility evidence. M8 confinement
and M9 specialist/native dependency review remain separate release gates.
