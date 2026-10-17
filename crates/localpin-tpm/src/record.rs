use localpin_core::{
    limits::{KdfParameters, MAX_RECORD_BYTES},
    records::CredentialRecord,
    types::{AccountId, Backend, Generation, Incarnation, Uid},
};
use sha2::{Digest as _, Sha256};
use tss_esapi::{
    structures::{Private, Public},
    traits::{Marshall, UnMarshall},
};
use zeroize::Zeroizing;

use crate::{Error, native};

const MAGIC: &[u8; 4] = b"LPT1";
const VERSION: u16 = 1;
const MAX_PUBLIC: usize = 1024;

/// Strict versioned protected TPM payload. It has no PIN/auth verifier, unsealed
/// data, secret comparison hash, PHC string or backend fallback material.
/// Public identities must remain protected alongside the opaque private blob.
/// Deliberately implements neither Debug, Clone nor general serialization.
pub struct TpmRecord {
    pub(crate) account: AccountId,
    pub(crate) generation: Generation,
    pub(crate) parameters: KdfParameters,
    pub(crate) salt: [u8; 16],
    pub(crate) parent: Public,
    pub(crate) parent_name: [u8; 34],
    pub(crate) object: Public,
    pub(crate) object_name: [u8; 34],
    pub(crate) private: Private,
}

impl TpmRecord {
    /// Validate the complete pinned envelope and its canonical TPM identities.
    pub fn from_credential(credential: &CredentialRecord) -> Result<Self, Error> {
        if credential.backend() != Backend::Tpm2 {
            return Err(Error::Record);
        }
        let mut reader = Reader(credential.payload());
        if reader.take(4)? != MAGIC
            || reader.u16()? != VERSION
            || reader.u16()? != 0x13
            || reader.u8()? != 1
        {
            return Err(Error::Record);
        }
        let account = AccountId {
            uid: Uid::new(reader.u32()?).map_err(|_| Error::Record)?,
            incarnation: Incarnation::new(reader.take(16)?.try_into().map_err(|_| Error::Record)?)
                .map_err(|_| Error::Record)?,
        };
        let generation = Generation::new(reader.u64()?).map_err(|_| Error::Record)?;
        if account != credential.account() || generation != credential.generation() {
            return Err(Error::Record);
        }
        let parameters = KdfParameters::new(reader.u32()?, reader.u32()?, reader.u32()?)
            .map_err(|_| Error::Record)?;
        let salt = reader.take(16)?.try_into().map_err(|_| Error::Record)?;
        let parent = canonical_public(reader.blob(MAX_PUBLIC)?)?;
        let parent_name = reader.take(34)?.try_into().map_err(|_| Error::Record)?;
        let object = canonical_public(reader.blob(MAX_PUBLIC)?)?;
        let object_name = reader.take(34)?.try_into().map_err(|_| Error::Record)?;
        let private_bytes = reader.blob(Private::MAX_SIZE)?;
        if private_bytes.is_empty() || !reader.0.is_empty() {
            return Err(Error::Record);
        }
        let private = Private::try_from(private_bytes).map_err(|_| Error::Record)?;
        let record = Self {
            account,
            generation,
            parameters,
            salt,
            parent,
            parent_name,
            object,
            object_name,
            private,
        };
        record.validate()?;
        Ok(record)
    }

    pub(crate) fn validate(&self) -> Result<(), Error> {
        native::validate_parent(&self.parent)?;
        native::validate_object(&self.object)?;
        if name(&self.parent)? != self.parent_name || name(&self.object)? != self.object_name {
            return Err(Error::Record);
        }
        Ok(())
    }

    /// Reviewed bounded Argon2id-v19 policy encoded by this payload.
    pub const fn parameters(&self) -> KdfParameters {
        self.parameters
    }

    /// Nonsecret Argon2 salt; no independent derived-output verifier is stored.
    pub const fn salt(&self) -> &[u8; 16] {
        &self.salt
    }

    pub(crate) fn into_credential(self) -> Result<CredentialRecord, Error> {
        self.validate()?;
        let mut output = Zeroizing::new(Vec::with_capacity(1024));
        output.extend_from_slice(MAGIC);
        output.extend_from_slice(&VERSION.to_be_bytes());
        output.extend_from_slice(&0x13u16.to_be_bytes());
        output.push(1); // Argon2id, not an algorithm negotiation field.
        output.extend_from_slice(&self.account.uid.get().to_be_bytes());
        output.extend_from_slice(&self.account.incarnation.get());
        output.extend_from_slice(&self.generation.get().to_be_bytes());
        for word in [self.parameters.memory_kib(), self.parameters.passes(), 1] {
            output.extend_from_slice(&word.to_be_bytes());
        }
        output.extend_from_slice(&self.salt);
        put_blob(
            &mut output,
            &self.parent.marshall().map_err(|_| Error::Record)?,
        )?;
        output.extend_from_slice(&self.parent_name);
        put_blob(
            &mut output,
            &self.object.marshall().map_err(|_| Error::Record)?,
        )?;
        output.extend_from_slice(&self.object_name);
        put_blob(&mut output, self.private.value())?;
        CredentialRecord::new(self.account, self.generation, Backend::Tpm2, &output)
            .map_err(|_| Error::Record)
    }
}

pub(crate) fn name(public: &Public) -> Result<[u8; 34], Error> {
    let bytes = public.marshall().map_err(|_| Error::Record)?;
    let mut result = [0; 34];
    result[..2].copy_from_slice(&0x000bu16.to_be_bytes());
    result[2..].copy_from_slice(&Sha256::digest(bytes));
    Ok(result)
}

fn canonical_public(bytes: &[u8]) -> Result<Public, Error> {
    let public = Public::unmarshall(bytes).map_err(|_| Error::Record)?;
    if public.marshall().map_err(|_| Error::Record)? != bytes {
        return Err(Error::Record);
    }
    Ok(public)
}

fn put_blob(output: &mut Vec<u8>, bytes: &[u8]) -> Result<(), Error> {
    let length = u16::try_from(bytes.len()).map_err(|_| Error::Record)?;
    if output
        .len()
        .checked_add(bytes.len() + 2)
        .is_none_or(|length| length > MAX_RECORD_BYTES)
    {
        return Err(Error::Record);
    }
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(bytes);
    Ok(())
}

struct Reader<'a>(&'a [u8]);
impl<'a> Reader<'a> {
    fn take(&mut self, length: usize) -> Result<&'a [u8], Error> {
        let (first, rest) = self.0.split_at_checked(length).ok_or(Error::Record)?;
        self.0 = rest;
        Ok(first)
    }
    fn u8(&mut self) -> Result<u8, Error> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16, Error> {
        Ok(u16::from_be_bytes(
            self.take(2)?.try_into().map_err(|_| Error::Record)?,
        ))
    }
    fn u32(&mut self) -> Result<u32, Error> {
        Ok(u32::from_be_bytes(
            self.take(4)?.try_into().map_err(|_| Error::Record)?,
        ))
    }
    fn u64(&mut self) -> Result<u64, Error> {
        Ok(u64::from_be_bytes(
            self.take(8)?.try_into().map_err(|_| Error::Record)?,
        ))
    }
    fn blob(&mut self, maximum: usize) -> Result<&'a [u8], Error> {
        let length = usize::from(self.u16()?);
        if length == 0 || length > maximum {
            return Err(Error::Record);
        }
        self.take(length)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tss_esapi::structures::{Digest, PublicKeyRsa};

    fn fixture() -> CredentialRecord {
        // Fake opaque blob for parser tests only; never called a TPM credential.
        let mut parent = native::parent_template().unwrap();
        let mut object = native::object_template().unwrap();
        if let Public::Rsa { unique, .. } = &mut parent {
            *unique = PublicKeyRsa::try_from(vec![1; 256]).unwrap();
        }
        if let Public::KeyedHash { unique, .. } = &mut object {
            *unique = Digest::try_from(vec![2; 32]).unwrap();
        }
        TpmRecord {
            account: AccountId {
                uid: Uid::new(1000).unwrap(),
                incarnation: Incarnation::new([1; 16]).unwrap(),
            },
            generation: Generation::new(1).unwrap(),
            parameters: KdfParameters::ENROLLMENT,
            salt: [3; 16],
            parent_name: name(&parent).unwrap(),
            object_name: name(&object).unwrap(),
            parent,
            object,
            private: Private::try_from(vec![4; 64]).unwrap(),
        }
        .into_credential()
        .unwrap()
    }

    #[test]
    fn canonical_record_round_trip_and_every_truncation_are_bounded() {
        let credential = fixture();
        let record = TpmRecord::from_credential(&credential).unwrap();
        let round_trip = record.into_credential().unwrap();
        assert_eq!(round_trip.payload(), credential.payload());
        for length in 1..credential.payload().len() {
            let short = CredentialRecord::new(
                credential.account(),
                credential.generation(),
                Backend::Tpm2,
                &credential.payload()[..length],
            )
            .unwrap();
            assert!(TpmRecord::from_credential(&short).is_err());
        }
        let mut trailing = credential.payload().to_vec();
        trailing.push(0);
        assert!(
            TpmRecord::from_credential(
                &CredentialRecord::new(
                    credential.account(),
                    credential.generation(),
                    Backend::Tpm2,
                    &trailing
                )
                .unwrap()
            )
            .is_err()
        );
        let wrong_backend = CredentialRecord::new(
            credential.account(),
            credential.generation(),
            Backend::Software,
            credential.payload(),
        )
        .unwrap();
        assert!(TpmRecord::from_credential(&wrong_backend).is_err());
        let wrong_generation = CredentialRecord::new(
            credential.account(),
            credential.generation().next().unwrap(),
            Backend::Tpm2,
            credential.payload(),
        )
        .unwrap();
        assert!(TpmRecord::from_credential(&wrong_generation).is_err());
    }
}
