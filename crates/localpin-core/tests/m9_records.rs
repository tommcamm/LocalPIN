//! Bounded, reproducible adversarial record campaigns over synthetic bytes.
//!
//! These are canonicalization properties, not coverage-guided fuzzing or proof
//! of cryptographic payload validity. No credential backend or host state is used.

use localpin_core::{
    limits::{KdfParameters, MAX_RECORD_BYTES, MAX_THROTTLE_BYTES},
    records::{ConfigRecord, CredentialRecord},
    throttle::ThrottleRecord,
    types::{
        AccountId, Backend, BackendSelection, BootId, Generation, Incarnation, TimePoint, Uid,
    },
};

struct Generator(u64);

impl Generator {
    fn next(&mut self) -> usize {
        // Fixed seed and wrapping arithmetic make failures replayable everywhere.
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        (self.0 >> 32) as usize
    }

    fn fill(&mut self, bytes: &mut [u8]) {
        for byte in bytes {
            *byte = self.next() as u8;
        }
    }
}

fn account() -> AccountId {
    AccountId {
        uid: Uid::new(1000).unwrap(),
        incarnation: Incarnation::new([0x71; 16]).unwrap(),
    }
}

fn check_config(bytes: &[u8]) -> bool {
    if let Ok(record) = ConfigRecord::decode(bytes) {
        assert_eq!(record.encode().unwrap(), bytes);
        assert!((64 * 1024..=256 * 1024).contains(&record.kdf.memory_kib()));
        assert!((3..=6).contains(&record.kdf.passes()));
        assert!(record.tpm_safety_reserve >= 2);
        true
    } else {
        false
    }
}

fn check_credential(bytes: &[u8]) -> bool {
    if let Ok(record) = CredentialRecord::decode(bytes) {
        assert_eq!(record.encode().unwrap().expose(), bytes);
        assert!(!record.payload().is_empty());
        assert_ne!(record.account().uid.get(), 0);
        assert_ne!(record.account().uid.get(), u32::MAX);
        assert_ne!(record.generation().get(), 0);
        true
    } else {
        false
    }
}

fn check_throttle(bytes: &[u8]) -> bool {
    if let Ok(record) = ThrottleRecord::decode(bytes) {
        assert_eq!(record.encode().unwrap(), bytes);
        true
    } else {
        false
    }
}

#[test]
fn seeded_record_mutations_are_canonical_and_enforce_work_bounds() {
    let config = ConfigRecord {
        selection: BackendSelection::Auto,
        kdf: KdfParameters::ENROLLMENT,
        tpm_safety_reserve: 2,
    }
    .encode()
    .unwrap();
    let credential = CredentialRecord::new(
        account(),
        Generation::new(1).unwrap(),
        Backend::Software,
        b"synthetic opaque payload; no verifier material",
    )
    .unwrap()
    .encode()
    .unwrap();
    let throttle = ThrottleRecord::initial(
        account(),
        Generation::new(1).unwrap(),
        TimePoint {
            boot: BootId::new([0x42; 16]).unwrap(),
            millis: 1,
        },
    )
    .encode()
    .unwrap();
    let mut generator = Generator(0x4d39_7265_636f_7264);
    for (original, check) in [
        (config.as_slice(), check_config as fn(&[u8]) -> bool),
        (credential.expose(), check_credential),
        (throttle.as_slice(), check_throttle),
    ] {
        assert!(check(original));
        let mut accepted = 0;
        let mut rejected = 0;
        // Every byte receives each possible byte value, including unknown tags,
        // zero identifiers, length changes, and arithmetic-boundary mutations.
        for offset in 0..original.len() {
            for value in 0..=u8::MAX {
                let mut bytes = original.to_vec();
                bytes[offset] = value;
                if check(&bytes) {
                    accepted += 1;
                } else {
                    rejected += 1;
                }
            }
        }
        for _ in 0..2048 {
            let mut bytes = original.to_vec();
            for _ in 0..1 + generator.next() % 8 {
                let offset = generator.next() % bytes.len();
                bytes[offset] = generator.next() as u8;
            }
            let _ = check(&bytes);
        }
        assert!(accepted > 0);
        assert!(rejected > 0);
    }
}

#[test]
fn unstructured_record_inputs_cover_exact_limits_and_short_headers() {
    let mut generator = Generator(0x4d39_7369_7a65_7365);
    let mut lengths: Vec<_> = (0..=256).collect();
    lengths.extend([
        MAX_THROTTLE_BYTES - 1,
        MAX_THROTTLE_BYTES,
        MAX_THROTTLE_BYTES + 1,
        MAX_RECORD_BYTES - 1,
        MAX_RECORD_BYTES,
        MAX_RECORD_BYTES + 1,
    ]);
    for len in lengths {
        let mut bytes = vec![0; len];
        generator.fill(&mut bytes);
        // All three parsers must reject arbitrary data without a valid magic.
        bytes.iter_mut().take(4).for_each(|byte| *byte = 0);
        assert!(!check_config(&bytes));
        assert!(!check_credential(&bytes));
        assert!(!check_throttle(&bytes));
    }
    // An otherwise valid credential must still obey the complete-envelope cap.
    let record = CredentialRecord::new(
        account(),
        Generation::new(1).unwrap(),
        Backend::Tpm2,
        &vec![0x5a; MAX_RECORD_BYTES - 35],
    )
    .unwrap();
    let encoded = record.encode().unwrap();
    assert_eq!(encoded.expose().len(), MAX_RECORD_BYTES);
    assert!(check_credential(encoded.expose()));
    let mut oversized = encoded.expose().to_vec();
    oversized.push(0);
    assert!(!check_credential(&oversized));
}
