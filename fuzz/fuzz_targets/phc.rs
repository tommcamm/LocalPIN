#![no_main]

use libfuzzer_sys::fuzz_target;
use localpin_core::{
    records::CredentialRecord,
    types::{AccountId, Backend, Generation, Incarnation, Uid},
};
use localpin_credentials::SoftwareVerifier;

fuzz_target!(|bytes: &[u8]| {
    // Only parse the PHC policy. Never run a KDF or submit authentication.
    let account = AccountId {
        uid: Uid::new(1000).unwrap(),
        incarnation: Incarnation::new([7; 16]).unwrap(),
    };
    if let Ok(record) = CredentialRecord::new(
        account,
        Generation::new(1).unwrap(),
        Backend::Software,
        bytes,
    ) && let Ok(verifier) = SoftwareVerifier::new(&record)
    {
        let parameters = verifier.parameters();
        assert!((65536..=262144).contains(&parameters.memory_kib()));
        assert!((3..=6).contains(&parameters.passes()));
    }
});
