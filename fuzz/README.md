# Bounded parser fuzzing

This separate Cargo workspace uses `cargo-fuzz =0.13.2`,
`libfuzzer-sys =0.4.13` and the committed `Cargo.lock`. It adds no production
dependency or installed behavior. Its synthetic inputs never open PAM, a
socket, account state or a TPM, and never run Argon2. Keep generated corpora,
artifacts and logs private until reviewed under [SECURITY.md](../SECURITY.md).

Install the test tools in an isolated writable directory:

```sh
cargo install cargo-fuzz --version 0.13.2 --locked --root /tmp/localpin-fuzz-tools
rustup toolchain install nightly-2026-10-17 --profile minimal --component rust-src,miri
export PATH="/tmp/localpin-fuzz-tools/bin:$PATH"
python3 fuzz/run.py --output /tmp/localpin-fuzz-evidence --seconds-per-target 60
```

Use a new output directory for each run. A separate `RUSTUP_HOME` may be used
for the nightly tools. `--toolchain nightly` selects an already installed
nightly; the runner records the actual compiler and tool versions. The
production compiler stays pinned by the repository's `rust-toolchain.toml`.

The runner generates canonical public seeds, then runs three coverage-guided
campaigns with AddressSanitizer, debug assertions, overflow checks, a fixed
initial seed, input/RSS/time limits and a watchdog. `summary.json` binds the
source commit, harness/lockfile hashes, starting and resulting corpus hashes,
commands, elapsed time, executed inputs, logs and failure artifacts. Time bounds
make a campaign repeatable in method, not identical in iteration count or
coverage. Do not treat coverage counters as a coverage percentage.

- `records` checks canonical configuration, credential and throttle decoding.
- `streams` checks request and response frames with whole and split input,
  canonical re-encoding, progress bounds, EOF rejection and permanent poisoning.
- `phc` checks strict software-record parsing and allowed KDF work parameters.
  It deliberately stops before derivation or verification.

The existing [verification model](../crates/localpin-protocol/tests/m9_verification_model.rs)
and [core policy tests](../crates/localpin-core/tests/policy_flow.rs) remain
separate normal Cargo checks. These targets do not cover PAM argument parsing,
native account/TPM record formats, installer configuration, all session/enrollment
transitions, native FFI, installed KDE, or physical hardware. More targets and
longer campaigns remain part of M9; this bounded sample is not a completed audit.

## Development dependency review

The production graph is unchanged. The separate lockfile adds the following
test/build inputs, reviewed from their published manifests and source notices:

| Input | Upstream namespace / purpose | Declared MSRV | Published license |
| --- | --- | --- | --- |
| libfuzzer-sys 0.4.13 | rust-fuzz/libfuzzer; LLVM coverage-guided runtime wrapper | Not declared; built with pinned Rust 1.99.1 and the recorded nightly | `(MIT OR Apache-2.0) AND NCSA` |
| arbitrary 1.5.0 | rust-fuzz/arbitrary; fuzz input support | 1.71 | `MIT OR Apache-2.0` |
| cc 1.8.0 | rust-lang/cc-rs; compile bundled C++ runtime | 1.65 | `MIT OR Apache-2.0` |
| find-msvc-tools 0.1.14 | rust-lang/cc-rs; compiler discovery | 1.65 | `MIT OR Apache-2.0` |
| jobserver 0.1.35 | rust-lang/jobserver-rs; bounded parallel native build | 1.85 | `MIT OR Apache-2.0` |
| shlex 2.0.1 | comex/rust-shlex; native compiler argument parsing | 1.46 | `MIT OR Apache-2.0` |

libfuzzer-sys uses its default `link_libfuzzer` feature and enables cc's parallel
build support. No arbitrary derive feature is requested. A C++17 compiler and
its standard library build the bundled runtime; no new PAM/TPM library is
required. Shared production dependencies have identical locked versions.

These are upstream testing tools, not LocalPIN-maintained production components.
The executed advisory scan and the pinned release contents establish this
review's maintenance snapshot; future upstream releases still require review.
The crate metadata and bundled LLVM headers use different license expressions;
retain all upstream notices when distributing test binaries. The version-scoped
NCSA/LLVM exception is confined to [fuzz/deny.toml](deny.toml); production policy
is unchanged. Run the pinned checker against this separate graph with:

```sh
cargo deny --manifest-path fuzz/Cargo.toml --config fuzz/deny.toml --locked check advisories licenses bans sources
```
