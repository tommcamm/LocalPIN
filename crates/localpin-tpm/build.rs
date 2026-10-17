//! Pin the reviewed native ABI family in addition to the exact Rust wrapper.
fn main() {
    let mut native_version = None;
    for library in ["tss2-sys", "tss2-esys", "tss2-tctildr", "tss2-mu"] {
        let dependency = pkg_config::Config::new()
            .range_version("4.0.0".."5.0.0")
            .probe(library)
            .expect("LocalPIN M4 requires TPM2-TSS >=4.0.0,<5.0.0 development libraries");
        if let Some(expected) = &native_version {
            assert_eq!(
                &dependency.version, expected,
                "TPM2-TSS libraries must have matching versions"
            );
        } else {
            native_version = Some(dependency.version);
        }
    }
}
