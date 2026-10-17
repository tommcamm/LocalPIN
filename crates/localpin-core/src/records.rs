//! Versioned bounded model envelopes. No filesystem or cryptographic validation.
//!
//! These are development contracts, not a production account-lifecycle schema.
//! M3 must establish trusted storage and lifecycle support before persisting them;
//! M4 must validate the selected backend's payload before use.

use crate::{
    limits::{KdfParameters, MAX_RECORD_BYTES},
    secret::SecretBytes,
    types::{AccountId, Backend, BackendSelection, Generation, Incarnation, Uid},
};

/// Current envelope/config model version. Unknown versions are unavailable.
pub const RECORD_VERSION: u16 = 1;
const HEADER_BYTES: usize = 4 + 2 + 4 + 16 + 8 + 1;

/// Sanitized structural record error, without credential bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecordError;

/// Credential envelope; exactly one pinned backend payload, never a shadow hash.
#[derive(Debug)]
pub struct CredentialRecord {
    account: AccountId,
    generation: Generation,
    backend: Backend,
    payload: SecretBytes,
}

impl CredentialRecord {
    /// Account incarnation from a trusted lifecycle authority.
    pub const fn account(&self) -> AccountId {
        self.account
    }

    /// Committed generation; recovery copies are not accepted as alternatives.
    pub const fn generation(&self) -> Generation {
        self.generation
    }

    /// Immutable pinned backend; runtime availability never changes it.
    pub const fn backend(&self) -> Backend {
        self.backend
    }

    /// Bound an opaque backend payload. This does not validate cryptography.
    pub fn new(
        account: AccountId,
        generation: Generation,
        backend: Backend,
        payload: &[u8],
    ) -> Result<Self, RecordError> {
        if payload.is_empty() {
            return Err(RecordError);
        }
        let payload = SecretBytes::from_slice(payload, MAX_RECORD_BYTES - HEADER_BYTES)
            .map_err(|_| RecordError)?;
        Ok(Self {
            account,
            generation,
            backend,
            payload,
        })
    }

    /// Private backend parsing boundary. Never expose this in status or errors.
    pub fn payload(&self) -> &[u8] {
        self.payload.expose()
    }

    /// Parse the whole bounded envelope; trailing bytes are the backend payload.
    pub fn decode(bytes: &[u8]) -> Result<Self, RecordError> {
        if bytes.len() <= HEADER_BYTES || bytes.len() > MAX_RECORD_BYTES {
            return Err(RecordError);
        }
        if &bytes[..4] != b"LPC1"
            || u16::from_be_bytes(bytes[4..6].try_into().map_err(|_| RecordError)?)
                != RECORD_VERSION
        {
            return Err(RecordError);
        }
        let uid = Uid::new(u32::from_be_bytes(
            bytes[6..10].try_into().map_err(|_| RecordError)?,
        ))
        .map_err(|_| RecordError)?;
        let incarnation = Incarnation::new(bytes[10..26].try_into().map_err(|_| RecordError)?)
            .map_err(|_| RecordError)?;
        let generation = Generation::new(u64::from_be_bytes(
            bytes[26..34].try_into().map_err(|_| RecordError)?,
        ))
        .map_err(|_| RecordError)?;
        let backend = match bytes[34] {
            1 => Backend::Tpm2,
            2 => Backend::Software,
            _ => return Err(RecordError),
        };
        Self::new(
            AccountId { uid, incarnation },
            generation,
            backend,
            &bytes[HEADER_BYTES..],
        )
    }

    /// Encode into secret-owning memory; the storage adapter must avoid copies.
    pub fn encode(&self) -> Result<SecretBytes, RecordError> {
        let mut bytes =
            zeroize::Zeroizing::new(Vec::with_capacity(HEADER_BYTES + self.payload().len()));
        bytes.extend_from_slice(b"LPC1");
        bytes.extend_from_slice(&RECORD_VERSION.to_be_bytes());
        bytes.extend_from_slice(&self.account.uid.get().to_be_bytes());
        bytes.extend_from_slice(&self.account.incarnation.get());
        bytes.extend_from_slice(&self.generation.get().to_be_bytes());
        bytes.push(match self.backend {
            Backend::Tpm2 => 1,
            Backend::Software => 2,
        });
        bytes.extend_from_slice(self.payload());
        SecretBytes::from_slice(&bytes, MAX_RECORD_BYTES).map_err(|_| RecordError)
    }
}

/// Fixed development policy config; unknown fields/versions are rejected.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConfigRecord {
    /// Enrollment selection; committed credentials remain pinned independently.
    pub selection: BackendSelection,
    /// Bounded Argon2id v19 parameters, one lane, 16-byte salt, 32-byte output.
    pub kdf: KdfParameters,
    /// TPM failures reserved for other users; at least two.
    pub tpm_safety_reserve: u32,
}

impl ConfigRecord {
    /// Exactly 19 bytes: magic, version, selection, memory, passes, safety reserve.
    pub fn decode(bytes: &[u8]) -> Result<Self, RecordError> {
        if bytes.len() != 19
            || &bytes[..4] != b"LPF1"
            || bytes[4..6] != RECORD_VERSION.to_be_bytes()
        {
            return Err(RecordError);
        }
        let selection = match bytes[6] {
            0 => BackendSelection::Auto,
            1 => BackendSelection::Tpm2Required,
            2 => BackendSelection::Software,
            _ => return Err(RecordError),
        };
        let read = |range: std::ops::Range<usize>| -> Result<u32, RecordError> {
            Ok(u32::from_be_bytes(
                bytes[range].try_into().map_err(|_| RecordError)?,
            ))
        };
        let kdf = KdfParameters::new(read(7..11)?, read(11..15)?, 1).map_err(|_| RecordError)?;
        let tpm_safety_reserve = read(15..19)?;
        if tpm_safety_reserve < 2 {
            return Err(RecordError);
        }
        Ok(Self {
            selection,
            kdf,
            tpm_safety_reserve,
        })
    }

    /// Encode only reviewed policy values; invalid reserve is refused.
    pub fn encode(self) -> Result<[u8; 19], RecordError> {
        if self.tpm_safety_reserve < 2 {
            return Err(RecordError);
        }
        let mut bytes = [0; 19];
        bytes[..4].copy_from_slice(b"LPF1");
        bytes[4..6].copy_from_slice(&RECORD_VERSION.to_be_bytes());
        bytes[6] = match self.selection {
            BackendSelection::Auto => 0,
            BackendSelection::Tpm2Required => 1,
            BackendSelection::Software => 2,
        };
        bytes[7..11].copy_from_slice(&self.kdf.memory_kib().to_be_bytes());
        bytes[11..15].copy_from_slice(&self.kdf.passes().to_be_bytes());
        bytes[15..19].copy_from_slice(&self.tpm_safety_reserve.to_be_bytes());
        Ok(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record() -> CredentialRecord {
        CredentialRecord::new(
            AccountId {
                uid: Uid::new(1000).unwrap(),
                incarnation: Incarnation::new([7; 16]).unwrap(),
            },
            Generation::new(1).unwrap(),
            Backend::Tpm2,
            b"synthetic protected blob",
        )
        .unwrap()
    }

    #[test]
    fn bounded_versioned_envelope() {
        let record = record();
        let encoded = record.encode().unwrap();
        let parsed = CredentialRecord::decode(encoded.expose()).unwrap();
        assert_eq!(parsed.account, record.account);
        assert_eq!(parsed.backend, Backend::Tpm2);
        assert_eq!(parsed.payload(), record.payload());
        for len in 0..=HEADER_BYTES {
            assert!(CredentialRecord::decode(&encoded.expose()[..len]).is_err());
        }
        let mut corrupted = encoded.expose().to_vec();
        corrupted[5] = 2;
        assert!(CredentialRecord::decode(&corrupted).is_err());
        corrupted[5] = 1;
        corrupted[34] = 3;
        assert!(CredentialRecord::decode(&corrupted).is_err());
        assert!(CredentialRecord::decode(&vec![0; MAX_RECORD_BYTES + 1]).is_err());
        assert!(!format!("{record:?}").contains("synthetic"));
    }

    #[test]
    fn fixed_config_rejects_extensions_and_work_inflation() {
        let config = ConfigRecord {
            selection: BackendSelection::Auto,
            kdf: KdfParameters::ENROLLMENT,
            tpm_safety_reserve: 2,
        };
        let encoded = config.encode().unwrap();
        assert_eq!(ConfigRecord::decode(&encoded), Ok(config));
        for len in 0..19 {
            assert!(ConfigRecord::decode(&encoded[..len]).is_err());
        }
        let mut bad = encoded;
        bad[7..11].copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(ConfigRecord::decode(&bad).is_err());
        assert!(ConfigRecord::decode(&[encoded.as_slice(), &[0]].concat()).is_err());
    }
}
