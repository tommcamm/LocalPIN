# M4 locked Rust dependency inventory

Date: 2026-10-17. Extracted from the committed lockfile and reviewed downloaded
registry manifests. Registry checksums remain in `Cargo.lock`. This inventories
all targets; non-Linux entries do not expand supported platforms. The main
[dependency report](dependencies.md#m4-credential-backend-dependencies) explains
selection, native requirements, exceptions and audit results.

| Crate | Version | Declared Rust minimum | License expression |
| --- | --- | --- | --- |
| [aho-corasick](https://docs.rs/crate/aho-corasick/1.1.5) | 1.1.5 | 1.60.0 | `Unlicense OR MIT` |
| [argon2](https://docs.rs/crate/argon2/0.6.0) | 0.6.0 | 1.85 | `MIT OR Apache-2.0` |
| [autocfg](https://docs.rs/crate/autocfg/1.5.1) | 1.5.1 | 1.0 | `Apache-2.0 OR MIT` |
| [base64](https://docs.rs/crate/base64/0.23.1) | 0.23.1 | 1.71.0 | `MIT OR Apache-2.0` |
| [base64ct](https://docs.rs/crate/base64ct/1.8.3) | 1.8.3 | 1.85 | `Apache-2.0 OR MIT` |
| [bitfield](https://docs.rs/crate/bitfield/0.19.5) | 0.19.5 | not declared | `MIT OR Apache-2.0` |
| [bitfield-macros](https://docs.rs/crate/bitfield-macros/0.19.5) | 0.19.5 | not declared | `MIT OR Apache-2.0` |
| [bitflags](https://docs.rs/crate/bitflags/2.13.2) | 2.13.2 | 1.56.0 | `MIT OR Apache-2.0` |
| [blake2](https://docs.rs/crate/blake2/0.11.0) | 0.11.0 | 1.85 | `MIT OR Apache-2.0` |
| [block-buffer](https://docs.rs/crate/block-buffer/0.12.1) | 0.12.1 | 1.85 | `MIT OR Apache-2.0` |
| [cfg-if](https://docs.rs/crate/cfg-if/1.0.5) | 1.0.5 | 1.32 | `MIT OR Apache-2.0` |
| [cmov](https://docs.rs/crate/cmov/0.5.4) | 0.5.4 | 1.85 | `Apache-2.0 OR MIT` |
| [cpufeatures](https://docs.rs/crate/cpufeatures/0.3.1) | 0.3.1 | 1.85 | `MIT OR Apache-2.0` |
| [crypto-common](https://docs.rs/crate/crypto-common/0.2.2) | 0.2.2 | 1.85 | `MIT OR Apache-2.0` |
| [ctutils](https://docs.rs/crate/ctutils/0.4.3) | 0.4.3 | 1.87 | `Apache-2.0 OR MIT` |
| [digest](https://docs.rs/crate/digest/0.11.3) | 0.11.3 | 1.85 | `MIT OR Apache-2.0` |
| [enumflags2](https://docs.rs/crate/enumflags2/0.7.12) | 0.7.12 | 1.56 | `MIT OR Apache-2.0` |
| [enumflags2_derive](https://docs.rs/crate/enumflags2_derive/0.7.12) | 0.7.12 | 1.56 | `MIT OR Apache-2.0` |
| [errno](https://docs.rs/crate/errno/0.3.14) | 0.3.14 | 1.56 | `MIT OR Apache-2.0` |
| [getrandom](https://docs.rs/crate/getrandom/0.4.3) | 0.4.3 | 1.85 | `MIT OR Apache-2.0` |
| [hostname-validator](https://docs.rs/crate/hostname-validator/1.1.1) | 1.1.1 | not declared | `MIT` |
| [hybrid-array](https://docs.rs/crate/hybrid-array/0.4.15) | 0.4.15 | 1.85 | `MIT OR Apache-2.0` |
| [libc](https://docs.rs/crate/libc/0.2.191) | 0.2.191 | 1.65 | `MIT OR Apache-2.0` |
| [linux-raw-sys](https://docs.rs/crate/linux-raw-sys/0.12.1) | 0.12.1 | 1.63 | `Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT` |
| [log](https://docs.rs/crate/log/0.4.34) | 0.4.34 | 1.71.0 | `MIT OR Apache-2.0` |
| [mbox](https://docs.rs/crate/mbox/0.7.1) | 0.7.1 | 1.36.0 | `MIT` |
| [memchr](https://docs.rs/crate/memchr/2.8.3) | 2.8.3 | 1.61 | `Unlicense OR MIT` |
| [num-derive](https://docs.rs/crate/num-derive/0.4.2) | 0.4.2 | 1.56.0 | `MIT OR Apache-2.0` |
| [num-traits](https://docs.rs/crate/num-traits/0.2.19) | 0.2.19 | 1.60 | `MIT OR Apache-2.0` |
| [oid](https://docs.rs/crate/oid/0.2.1) | 0.2.1 | not declared | `MIT OR Apache-2.0` |
| [picky-asn1](https://docs.rs/crate/picky-asn1/0.10.1) | 0.10.1 | 1.61 | `MIT OR Apache-2.0` |
| [picky-asn1-der](https://docs.rs/crate/picky-asn1-der/0.5.7) | 0.5.7 | 1.85 | `MIT OR Apache-2.0` |
| [picky-asn1-x509](https://docs.rs/crate/picky-asn1-x509/0.15.5) | 0.15.5 | 1.85 | `MIT OR Apache-2.0` |
| [pkg-config](https://docs.rs/crate/pkg-config/0.3.34) | 0.3.34 | 1.63 | `MIT OR Apache-2.0` |
| [proc-macro2](https://docs.rs/crate/proc-macro2/1.0.107) | 1.0.107 | 1.71 | `MIT OR Apache-2.0` |
| [quote](https://docs.rs/crate/quote/1.0.47) | 1.0.47 | 1.71 | `MIT OR Apache-2.0` |
| [r-efi](https://docs.rs/crate/r-efi/6.0.0) | 6.0.0 | 1.68 | `MIT OR Apache-2.0 OR LGPL-2.1-or-later` |
| [regex](https://docs.rs/crate/regex/1.13.1) | 1.13.1 | 1.65 | `MIT OR Apache-2.0` |
| [regex-automata](https://docs.rs/crate/regex-automata/0.4.18) | 0.4.18 | 1.65 | `MIT OR Apache-2.0` |
| [regex-syntax](https://docs.rs/crate/regex-syntax/0.8.11) | 0.8.11 | 1.65 | `MIT OR Apache-2.0` |
| [rustix](https://docs.rs/crate/rustix/1.1.5) | 1.1.5 | 1.65 | `Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT` |
| [serde](https://docs.rs/crate/serde/1.0.229) | 1.0.229 | 1.56 | `MIT OR Apache-2.0` |
| [serde_bytes](https://docs.rs/crate/serde_bytes/0.11.19) | 0.11.19 | 1.68 | `MIT OR Apache-2.0` |
| [serde_core](https://docs.rs/crate/serde_core/1.0.229) | 1.0.229 | 1.56 | `MIT OR Apache-2.0` |
| [serde_derive](https://docs.rs/crate/serde_derive/1.0.229) | 1.0.229 | 1.71 | `MIT OR Apache-2.0` |
| [sha2](https://docs.rs/crate/sha2/0.11.1) | 0.11.1 | 1.88 | `MIT OR Apache-2.0` |
| [stable_deref_trait](https://docs.rs/crate/stable_deref_trait/1.2.1) | 1.2.1 | not declared | `MIT OR Apache-2.0` |
| [syn](https://docs.rs/crate/syn/2.0.119) | 2.0.119 | 1.71 | `MIT OR Apache-2.0` |
| [syn](https://docs.rs/crate/syn/3.0.9) | 3.0.9 | 1.71 | `MIT OR Apache-2.0` |
| [target-lexicon](https://docs.rs/crate/target-lexicon/0.12.16) | 0.12.16 | not declared | `Apache-2.0 WITH LLVM-exception` |
| [tss-esapi](https://docs.rs/crate/tss-esapi/7.7.0) | 7.7.0 | 1.85.0 | `Apache-2.0` |
| [tss-esapi-sys](https://docs.rs/crate/tss-esapi-sys/0.6.0) | 0.6.0 | 1.85.0 | `Apache-2.0` |
| [typenum](https://docs.rs/crate/typenum/1.20.1) | 1.20.1 | 1.41.0 | `MIT OR Apache-2.0` |
| [unicode-ident](https://docs.rs/crate/unicode-ident/1.0.27) | 1.0.27 | 1.71 | `(MIT OR Apache-2.0) AND Unicode-3.0` |
| [windows-link](https://docs.rs/crate/windows-link/0.2.1) | 0.2.1 | 1.71 | `MIT OR Apache-2.0` |
| [windows-sys](https://docs.rs/crate/windows-sys/0.61.2) | 0.61.2 | 1.71 | `MIT OR Apache-2.0` |
| [zeroize](https://docs.rs/crate/zeroize/1.9.1) | 1.9.1 | 1.85 | `Apache-2.0 OR MIT` |
| [zeroize_derive](https://docs.rs/crate/zeroize_derive/1.5.0) | 1.5.0 | 1.85 | `Apache-2.0 OR MIT` |
