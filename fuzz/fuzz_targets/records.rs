#![no_main]

use libfuzzer_sys::fuzz_target;
use localpin_core::{
    records::{ConfigRecord, CredentialRecord},
    throttle::ThrottleRecord,
};

fuzz_target!(|bytes: &[u8]| {
    if let Ok(record) = ConfigRecord::decode(bytes) {
        assert_eq!(record.encode().unwrap(), bytes);
        assert!((65536..=262144).contains(&record.kdf.memory_kib()));
        assert!((3..=6).contains(&record.kdf.passes()));
        assert!(record.tpm_safety_reserve >= 2);
    }
    if let Ok(record) = CredentialRecord::decode(bytes) {
        assert_eq!(record.encode().unwrap().expose(), bytes);
        assert!(!record.payload().is_empty());
        assert!(record.profile().validate(record.backend()).is_ok());
    }
    if let Ok(record) = ThrottleRecord::decode(bytes) {
        assert_eq!(record.encode().unwrap(), bytes);
    }
});
