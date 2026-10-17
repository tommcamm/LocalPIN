//! Fixed authoritative pointer; no previous-generation fallback.

use crate::{Error, Result};
use localpin_core::{
    enrollment::CommittedState,
    types::{AccountId, Backend, Generation, Incarnation, Uid},
};

pub(crate) const ENCODED_LEN: usize = 35;
pub(crate) struct Pointer(pub CommittedState);

impl Pointer {
    pub(crate) fn encode(&self) -> [u8; ENCODED_LEN] {
        let mut bytes = [0; ENCODED_LEN];
        bytes[..6].copy_from_slice(b"LPA3\0\x01");
        bytes[6..10].copy_from_slice(&self.0.account().uid.get().to_be_bytes());
        bytes[10..26].copy_from_slice(&self.0.account().incarnation.get());
        bytes[26..34].copy_from_slice(&self.0.generation().get().to_be_bytes());
        bytes[34] = match self.0.backend() {
            None => 0,
            Some(Backend::Tpm2) => 1,
            Some(Backend::Software) => 2,
        };
        bytes
    }

    pub(crate) fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != ENCODED_LEN || &bytes[..6] != b"LPA3\0\x01" {
            return Err(Error::Corrupt);
        }
        let uid = Uid::new(u32::from_be_bytes(
            bytes[6..10].try_into().map_err(|_| Error::Corrupt)?,
        ))
        .map_err(|_| Error::Corrupt)?;
        let incarnation = Incarnation::new(bytes[10..26].try_into().map_err(|_| Error::Corrupt)?)
            .map_err(|_| Error::Corrupt)?;
        let generation = Generation::new(u64::from_be_bytes(
            bytes[26..34].try_into().map_err(|_| Error::Corrupt)?,
        ))
        .map_err(|_| Error::Corrupt)?;
        let backend = match bytes[34] {
            0 => None,
            1 => Some(Backend::Tpm2),
            2 => Some(Backend::Software),
            _ => return Err(Error::Corrupt),
        };
        Ok(Self(CommittedState::new(
            AccountId { uid, incarnation },
            generation,
            backend,
        )))
    }
}
