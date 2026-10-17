//! Bounded credential cryptography. This crate grants no authentication response.
//!
//! Software verification consumes the core's durable reservation and keeps its
//! memory lease until the KDF has ended. The shared derivation also supports TPM
//! authorization, without creating a software verifier for a TPM credential.
//! Host integration must supervise backend deadlines and protect process memory.

pub mod software;

use argon2::{Algorithm, Argon2, Block, Params, Version};
use localpin_core::{
    limits::{KdfParameters, WorkKind, WorkPermit},
    secret::Pin,
    types::{Randomness, Unavailable},
};
use std::fmt;
use zeroize::Zeroizing;

pub use software::{SoftwareVerifier, enroll, enroll_with_random, validate_enrollment};

/// Fixed size of every LocalPIN Argon2id salt.
pub const SALT_BYTES: usize = 16;
/// Fixed size of software verifier output and TPM object authorization.
pub const OUTPUT_BYTES: usize = 32;

/// Non-cloneable derived authorization or verifier output, erased on drop.
///
/// No display, serialization, implicit byte borrow or general equality is
/// provided. Borrow only at the narrow cryptographic boundary with
/// [`Self::expose`]; diagnostics redact the value.
pub struct DerivedKey(Zeroizing<[u8; OUTPUT_BYTES]>);

impl DerivedKey {
    /// Explicitly borrow this secret for the shortest required boundary.
    pub fn expose(&self) -> &[u8; OUTPUT_BYTES] {
        &self.0
    }
}

impl fmt::Debug for DerivedKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DerivedKey([REDACTED])")
    }
}

/// Sanitized failure class; no native messages or credential material are kept.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// Credential payload is malformed, noncanonical or outside reviewed bounds.
    InvalidRecord,
    /// Record or work admission does not match the exact invocation.
    Binding,
    /// Aggregate memory or the UID's work slot is already occupied.
    Capacity,
    /// The operating system's cryptographic entropy source failed.
    Entropy,
    /// The reviewed memory allocation could not be acquired.
    Allocation,
    /// The maintained KDF implementation refused the derivation.
    Derivation,
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidRecord => "invalid credential record",
            Self::Binding => "credential binding mismatch",
            Self::Capacity => "credential work capacity unavailable",
            Self::Entropy => "operating system entropy unavailable",
            Self::Allocation => "credential memory unavailable",
            Self::Derivation => "credential derivation unavailable",
        })
    }
}

impl std::error::Error for Error {}

/// Operating-system cryptographic randomness with no predictable fallback.
#[derive(Default)]
pub struct OsRandom;

impl Randomness for OsRandom {
    fn fill(&mut self, destination: &mut [u8]) -> Result<(), Unavailable> {
        getrandom::fill(destination).map_err(|_| Unavailable)
    }
}

/// Derive Argon2id v19 using an already charged, exact work permit.
///
/// Every caller must keep the permit alive until derivation returns. The caller
/// binds its UID and operation with [`WorkPermit::covers`] before calling; this
/// shared primitive accepts the three reviewed PIN-derived work classes. There
/// is no default parameter path. Output and explicit Argon2 memory erase on drop,
/// including a returned KDF error. Caller inputs remain the caller's property.
/// A live derivation guard excludes concurrent or reentrant KDF allocations
/// using this same permit until this call's memory has been erased.
pub fn derive(
    pin: &Pin,
    salt: &[u8; SALT_BYTES],
    parameters: KdfParameters,
    permit: &WorkPermit,
) -> Result<DerivedKey, Error> {
    if permit.parameters() != parameters {
        return Err(Error::Binding);
    }
    match permit.kind() {
        WorkKind::Verification | WorkKind::Enrollment | WorkKind::TpmPinDerivation => {}
    }
    let _derivation = permit.try_derivation().map_err(|_| Error::Capacity)?;
    let parameters = Params::new(
        parameters.memory_kib(),
        parameters.passes(),
        1,
        Some(OUTPUT_BYTES),
    )
    .map_err(|_| Error::Derivation)?;
    let mut memory = Zeroizing::new(Vec::new());
    memory
        .try_reserve_exact(parameters.block_count())
        .map_err(|_| Error::Allocation)?;
    memory.resize(parameters.block_count(), Block::default());
    let mut output = Zeroizing::new([0; OUTPUT_BYTES]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, parameters)
        .hash_password_into_with_memory(pin.expose(), salt, output.as_mut(), memory.as_mut_slice())
        .map_err(|_| Error::Derivation)?;
    Ok(DerivedKey(output))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derived_key_diagnostics_redact_secret_bytes() {
        let key = DerivedKey(Zeroizing::new(*b"synthetic derived secret bytes!!"));
        assert_eq!(format!("{key:?}"), "DerivedKey([REDACTED])");
        assert_eq!(key.expose(), b"synthetic derived secret bytes!!");
    }
}
