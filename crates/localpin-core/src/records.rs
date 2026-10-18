//! Versioned bounded model envelopes. No filesystem or cryptographic validation.
//!
//! These are development contracts, not a production account-lifecycle schema.
//! `localpin-storage` exercises these with synthetic lifecycle identities.
//! Permanent use still requires demonstrated lifecycle support; M4 must validate
//! the selected backend's payload before use.

use crate::{
    limits::{KdfParameters, MAX_RECORD_BYTES},
    secret::{CURRENT_POLICY, CredentialKind, CredentialProfile, SecretBytes},
    types::{AccountId, Backend, BackendSelection, Generation, Incarnation, Uid},
};

/// Current credential envelope version. Unknown versions are unavailable.
pub const CREDENTIAL_VERSION: u16 = 2;
/// Configuration version, independent of credential format evolution.
pub const CONFIG_VERSION: u16 = 1;
/// Legacy envelope/config version, retained for source compatibility.
pub const RECORD_VERSION: u16 = 1;
const HEADER_BYTES: usize = 4 + 2 + 4 + 16 + 8 + 1;
const PROFILE_BYTES: usize = 3;

/// Sanitized structural record error, without credential bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecordError;

/// Credential envelope; exactly one pinned backend payload, never a shadow hash.
#[derive(Debug)]
pub struct CredentialRecord {
    account: AccountId,
    generation: Generation,
    backend: Backend,
    version: u16,
    profile: CredentialProfile,
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

    /// Public credential type and exact length, including legacy-policy metadata.
    pub const fn profile(&self) -> CredentialProfile {
        self.profile
    }

    /// Construct a legacy envelope, for compatibility fixtures and backend output.
    /// New enrollment must attach its validated profile with `with_profile`.
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
            version: RECORD_VERSION,
            profile: CredentialProfile::legacy(),
            payload,
        })
    }

    /// Bound a new credential's backend payload and validated current profile.
    /// This validates metadata, not the opaque backend's cryptography.
    pub fn new_with_profile(
        account: AccountId,
        generation: Generation,
        backend: Backend,
        profile: CredentialProfile,
        payload: &[u8],
    ) -> Result<Self, RecordError> {
        Self::new(account, generation, backend, payload)?.with_profile(profile)
    }

    /// Attach an enrollment profile to a newly created backend result.
    /// Legacy policy cannot be written into a version-2 envelope.
    pub fn with_profile(mut self, profile: CredentialProfile) -> Result<Self, RecordError> {
        if profile.policy != CURRENT_POLICY
            || profile.validate(self.backend).is_err()
            || self.payload().len() > MAX_RECORD_BYTES - HEADER_BYTES - PROFILE_BYTES
        {
            return Err(RecordError);
        }
        self.version = CREDENTIAL_VERSION;
        self.profile = profile;
        Ok(self)
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
        if &bytes[..4] != b"LPC1" {
            return Err(RecordError);
        }
        let version = u16::from_be_bytes(bytes[4..6].try_into().map_err(|_| RecordError)?);
        if version != RECORD_VERSION && version != CREDENTIAL_VERSION {
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
        let (profile, payload_offset) = if version == CREDENTIAL_VERSION {
            if bytes.len() <= HEADER_BYTES + PROFILE_BYTES {
                return Err(RecordError);
            }
            let profile = CredentialProfile {
                policy: bytes[35],
                kind: match bytes[36] {
                    1 => CredentialKind::NumericPin,
                    2 => CredentialKind::Passcode,
                    _ => return Err(RecordError),
                },
                length: bytes[37],
            };
            if profile.policy != CURRENT_POLICY || profile.validate(backend).is_err() {
                return Err(RecordError);
            }
            (profile, HEADER_BYTES + PROFILE_BYTES)
        } else {
            (CredentialProfile::legacy(), HEADER_BYTES)
        };
        let mut record = Self::new(
            AccountId { uid, incarnation },
            generation,
            backend,
            &bytes[payload_offset..],
        )?;
        record.version = version;
        record.profile = profile;
        Ok(record)
    }

    /// Encode into secret-owning memory; the storage adapter must avoid copies.
    pub fn encode(&self) -> Result<SecretBytes, RecordError> {
        let mut bytes = zeroize::Zeroizing::new(Vec::with_capacity(
            HEADER_BYTES + PROFILE_BYTES + self.payload().len(),
        ));
        bytes.extend_from_slice(b"LPC1");
        bytes.extend_from_slice(&self.version.to_be_bytes());
        bytes.extend_from_slice(&self.account.uid.get().to_be_bytes());
        bytes.extend_from_slice(&self.account.incarnation.get());
        bytes.extend_from_slice(&self.generation.get().to_be_bytes());
        bytes.push(match self.backend {
            Backend::Tpm2 => 1,
            Backend::Software => 2,
        });
        if self.version == CREDENTIAL_VERSION {
            bytes.push(self.profile.policy);
            bytes.push(match self.profile.kind {
                CredentialKind::NumericPin => 1,
                CredentialKind::Passcode => 2,
            });
            bytes.push(self.profile.length);
        }
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
            || bytes[4..6] != CONFIG_VERSION.to_be_bytes()
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
        bytes[4..6].copy_from_slice(&CONFIG_VERSION.to_be_bytes());
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
        corrupted[5] = 3;
        assert!(CredentialRecord::decode(&corrupted).is_err());
        corrupted[5] = 1;
        corrupted[34] = 3;
        assert!(CredentialRecord::decode(&corrupted).is_err());
        assert!(CredentialRecord::decode(&vec![0; MAX_RECORD_BYTES + 1]).is_err());
        assert!(!format!("{record:?}").contains("synthetic"));
    }

    #[test]
    fn legacy_envelope_is_preserved_byte_for_byte() {
        let record = record();
        let encoded = record.encode().unwrap();
        assert_eq!(encoded.expose()[4..6], [0, 1]);
        let parsed = CredentialRecord::decode(encoded.expose()).unwrap();
        assert_eq!(parsed.profile(), CredentialProfile::legacy());
        assert_eq!(parsed.encode().unwrap().expose(), encoded.expose());
        assert!(record.with_profile(CredentialProfile::legacy()).is_err());
        let software = CredentialRecord::new(
            parsed.account(),
            parsed.generation(),
            Backend::Software,
            parsed.payload(),
        )
        .unwrap();
        assert_eq!(
            CredentialRecord::decode(software.encode().unwrap().expose())
                .unwrap()
                .profile(),
            CredentialProfile::legacy()
        );
    }

    #[test]
    fn new_envelopes_bind_and_validate_current_profile() {
        for (backend, kind, length) in [
            (Backend::Tpm2, CredentialKind::NumericPin, 4),
            (Backend::Software, CredentialKind::NumericPin, 8),
            (Backend::Software, CredentialKind::Passcode, 64),
        ] {
            let original = record();
            let profile = CredentialProfile {
                policy: CURRENT_POLICY,
                kind,
                length,
            };
            let new = CredentialRecord::new_with_profile(
                original.account(),
                original.generation(),
                backend,
                profile,
                original.payload(),
            )
            .unwrap();
            let encoded = new.encode().unwrap();
            assert_eq!(encoded.expose()[4..6], [0, 2]);
            let decoded = CredentialRecord::decode(encoded.expose()).unwrap();
            assert_eq!(decoded.profile(), profile);
            assert_eq!(decoded.encode().unwrap().expose(), encoded.expose());
            for len in 0..=HEADER_BYTES + PROFILE_BYTES {
                assert!(CredentialRecord::decode(&encoded.expose()[..len]).is_err());
            }
            for (offset, bad) in [(35, 0), (35, 2), (36, 0), (36, 3), (37, 0), (37, 65)] {
                let mut corrupt = encoded.expose().to_vec();
                corrupt[offset] = bad;
                assert!(CredentialRecord::decode(&corrupt).is_err());
            }
        }
        let invalid_software = CredentialProfile {
            policy: CURRENT_POLICY,
            kind: CredentialKind::NumericPin,
            length: 6,
        };
        let original = record();
        assert!(
            CredentialRecord::new_with_profile(
                original.account(),
                original.generation(),
                Backend::Software,
                invalid_software,
                original.payload(),
            )
            .is_err()
        );
    }

    #[test]
    fn version_two_accounts_for_its_larger_header_in_allocation_cap() {
        let profile = CredentialProfile {
            policy: CURRENT_POLICY,
            kind: CredentialKind::Passcode,
            length: 12,
        };
        let original = record();
        let largest = CredentialRecord::new_with_profile(
            original.account(),
            original.generation(),
            Backend::Tpm2,
            profile,
            &vec![0x5a; MAX_RECORD_BYTES - HEADER_BYTES - PROFILE_BYTES],
        )
        .unwrap();
        assert_eq!(largest.encode().unwrap().expose().len(), MAX_RECORD_BYTES);
        assert!(CredentialRecord::decode(largest.encode().unwrap().expose()).is_ok());
        assert!(
            CredentialRecord::new_with_profile(
                original.account(),
                original.generation(),
                Backend::Tpm2,
                profile,
                &vec![0x5a; MAX_RECORD_BYTES - HEADER_BYTES - PROFILE_BYTES + 1],
            )
            .is_err()
        );
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
