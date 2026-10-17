//! Canonical bounded PHC software credentials, explicitly selected at enrollment.

use crate::{Error, OUTPUT_BYTES, OsRandom, SALT_BYTES, derive};
use base64ct::{Base64Unpadded, Encoding};
use ctutils::CtEq;
use localpin_core::{
    limits::{KdfParameters, ResourceBudget, WorkKind},
    records::CredentialRecord,
    secret::Pin,
    throttle::{BackendFailure, BackendOutcome},
    types::{
        AccountId, Backend, CredentialVerifier, Generation, Randomness, VerificationCompletion,
        VerificationJob,
    },
};
use std::fmt::Write;
use zeroize::Zeroizing;

/// Longest accepted canonical PHC payload (six-digit memory cost).
pub const MAX_PHC_BYTES: usize = 98;
const SALT_ENCODED_BYTES: usize = 22;
const OUTPUT_ENCODED_BYTES: usize = 43;

struct Parsed {
    parameters: KdfParameters,
    salt: [u8; SALT_BYTES],
    output: Zeroizing<[u8; OUTPUT_BYTES]>,
}

impl Parsed {
    fn parse(payload: &[u8]) -> Result<Self, Error> {
        // Bound the input before UTF-8 parsing, splitting or output allocation.
        if payload.len() > MAX_PHC_BYTES {
            return Err(Error::InvalidRecord);
        }
        let payload = std::str::from_utf8(payload).map_err(|_| Error::InvalidRecord)?;
        let mut fields = payload.split('$');
        if fields.next() != Some("")
            || fields.next() != Some("argon2id")
            || fields.next() != Some("v=19")
        {
            return Err(Error::InvalidRecord);
        }
        let costs = fields.next().ok_or(Error::InvalidRecord)?;
        let mut costs = costs.split(',');
        let memory = decimal(costs.next(), "m=")?;
        let passes = decimal(costs.next(), "t=")?;
        let lanes = decimal(costs.next(), "p=")?;
        if costs.next().is_some() {
            return Err(Error::InvalidRecord);
        }
        let parameters =
            KdfParameters::new(memory, passes, lanes).map_err(|_| Error::InvalidRecord)?;
        let salt = fields.next().ok_or(Error::InvalidRecord)?;
        let output = fields.next().ok_or(Error::InvalidRecord)?;
        if fields.next().is_some()
            || salt.len() != SALT_ENCODED_BYTES
            || output.len() != OUTPUT_ENCODED_BYTES
        {
            return Err(Error::InvalidRecord);
        }
        let mut parsed = Self {
            parameters,
            salt: [0; SALT_BYTES],
            output: Zeroizing::new([0; OUTPUT_BYTES]),
        };
        Base64Unpadded::decode(salt, &mut parsed.salt).map_err(|_| Error::InvalidRecord)?;
        Base64Unpadded::decode(output, parsed.output.as_mut()).map_err(|_| Error::InvalidRecord)?;
        // Re-encoding additionally refuses alternate nonzero trailing bits.
        let mut canonical_salt = [0; SALT_ENCODED_BYTES];
        let mut canonical_output = Zeroizing::new([0; OUTPUT_ENCODED_BYTES]);
        if Base64Unpadded::encode(&parsed.salt, &mut canonical_salt)
            .map_err(|_| Error::InvalidRecord)?
            != salt
            || Base64Unpadded::encode(parsed.output.as_ref(), canonical_output.as_mut())
                .map_err(|_| Error::InvalidRecord)?
                != output
        {
            return Err(Error::InvalidRecord);
        }
        Ok(parsed)
    }
}

fn decimal(field: Option<&str>, prefix: &str) -> Result<u32, Error> {
    let digits = field
        .and_then(|value| value.strip_prefix(prefix))
        .ok_or(Error::InvalidRecord)?;
    if digits.is_empty()
        || digits.len() > 6
        || digits.starts_with('0')
        || !digits.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(Error::InvalidRecord);
    }
    digits.parse().map_err(|_| Error::InvalidRecord)
}

fn parse_record(record: &CredentialRecord) -> Result<Parsed, Error> {
    if record.backend() != Backend::Software {
        return Err(Error::Binding);
    }
    Parsed::parse(record.payload())
}

/// Create a software record with reviewed defaults and OS-generated salt.
///
/// The caller must already hold fresh enrollment authorization. This operation
/// creates a candidate record; protected storage must durably commit and trial
/// verify it before activating the new generation.
pub fn enroll(
    account: AccountId,
    generation: Generation,
    pin: &Pin,
    budget: &ResourceBudget,
) -> Result<CredentialRecord, Error> {
    enroll_with_random(account, generation, pin, budget, &mut OsRandom)
}

/// Enrollment with an injected trusted entropy adapter; failures abort creation.
///
/// Production adapters must supply cryptographic OS entropy. Injection supports
/// reproducible vectors and partial-fill failure tests without a host RNG fault.
pub fn enroll_with_random<R: Randomness + ?Sized>(
    account: AccountId,
    generation: Generation,
    pin: &Pin,
    budget: &ResourceBudget,
    random: &mut R,
) -> Result<CredentialRecord, Error> {
    let parameters = KdfParameters::ENROLLMENT;
    let work = budget
        .try_work(account.uid, parameters, WorkKind::Enrollment)
        .map_err(|_| Error::Capacity)?;
    let mut salt = Zeroizing::new([0; SALT_BYTES]);
    random.fill(salt.as_mut()).map_err(|_| Error::Entropy)?;
    let output = derive(pin, &salt, parameters, &work)?;
    let mut salt_b64 = [0; SALT_ENCODED_BYTES];
    let mut output_b64 = Zeroizing::new([0; OUTPUT_ENCODED_BYTES]);
    let salt =
        Base64Unpadded::encode(salt.as_ref(), &mut salt_b64).map_err(|_| Error::Derivation)?;
    let output = Base64Unpadded::encode(output.expose(), output_b64.as_mut())
        .map_err(|_| Error::Derivation)?;
    let mut payload = Zeroizing::new(String::with_capacity(MAX_PHC_BYTES));
    write!(payload, "$argon2id$v=19$m=65536,t=3,p=1${salt}${output}")
        .map_err(|_| Error::Derivation)?;
    CredentialRecord::new(account, generation, Backend::Software, payload.as_bytes())
        .map_err(|_| Error::InvalidRecord)
}

/// Trial-check a proposed protected enrollment record under the enrollment cap.
///
/// This returns no authentication capability. It is only for the storage
/// transaction's trial callback; ordinary authentication must use
/// [`SoftwareVerifier`] and a durably reserved [`VerificationJob`].
pub fn validate_enrollment(
    record: &CredentialRecord,
    pin: &Pin,
    budget: &ResourceBudget,
) -> Result<bool, Error> {
    let parsed = parse_record(record)?;
    let work = budget
        .try_work(
            record.account().uid,
            parsed.parameters,
            WorkKind::Enrollment,
        )
        .map_err(|_| Error::Capacity)?;
    let derived = derive(pin, &parsed.salt, parsed.parameters, &work)?;
    Ok(bool::from(
        derived.expose().as_slice().ct_eq(parsed.output.as_ref()),
    ))
}

/// One authoritative software record prepared for a durably reserved invocation.
///
/// This retains verifier material, never a successful PIN or derived candidate.
/// Its record must come from protected storage under the account lock. Completion
/// still requires the core's live account/generation fence and durable commit.
pub struct SoftwareVerifier<'record> {
    record: &'record CredentialRecord,
    parsed: Parsed,
}

impl<'record> SoftwareVerifier<'record> {
    /// Strictly validate the pinned backend, PHC and work bounds before any KDF.
    pub fn new(record: &'record CredentialRecord) -> Result<Self, Error> {
        Ok(Self {
            record,
            parsed: parse_record(record)?,
        })
    }

    /// Exact reviewed parameters to charge when constructing a verification job.
    pub const fn parameters(&self) -> KdfParameters {
        self.parsed.parameters
    }

    fn outcome(&self, job: &VerificationJob<'_>) -> Result<BackendOutcome, Error> {
        if job.backend() != Backend::Software
            || job.account() != self.record.account()
            || job.generation() != self.record.generation()
            || job.parameters() != self.parsed.parameters
            || !job.work().covers(
                job.account().uid,
                self.parsed.parameters,
                WorkKind::Verification,
            )
        {
            return Err(Error::Binding);
        }
        let derived = derive(
            job.pin(),
            &self.parsed.salt,
            self.parsed.parameters,
            job.work(),
        )?;
        Ok(
            if bool::from(
                derived
                    .expose()
                    .as_slice()
                    .ct_eq(self.parsed.output.as_ref()),
            ) {
                BackendOutcome::Match
            } else {
                BackendOutcome::Mismatch
            },
        )
    }
}

impl CredentialVerifier for SoftwareVerifier<'_> {
    fn verify<'a>(&mut self, job: VerificationJob<'a>) -> VerificationCompletion<'a> {
        let outcome = self
            .outcome(&job)
            .unwrap_or(BackendOutcome::Unavailable(BackendFailure::Technical));
        job.finish(outcome)
    }
}

#[cfg(test)]
mod tests;
