//! One-operation TPM2 credential worker primitives for ADR 0002.
//!
//! Native calls, including cleanup, may block. Run each [`NativeOperation`] in a
//! short-lived supervised process, retaining its job/permit until it is reaped.
//! M5 owns deadlines, result-channel cancellation and bounded process slots. These
//! functions provide no deadline or thread-cancellation substitute. Each operation
//! creates one ESAPI context and releases only that context's own handles; no
//! persistent handles, NV indices, hierarchy changes or global flushes are used.
//! The active protected record and durable reservation come from M3. A match is
//! only a backend result: its durable completion and generation fence must precede
//! any authorization response. There is no software fallback or success cache.

mod native;
mod record;

use localpin_core::{
    limits::{KdfParameters, WorkKind, WorkPermit},
    records::CredentialRecord,
    secret::Pin,
    throttle::{BackendFailure, BackendOutcome},
    types::{
        AccountId, Backend, CredentialVerifier, Generation, Randomness, VerificationCompletion,
        VerificationJob,
    },
};
use tss_esapi::tcti_ldr::TctiNameConf;

pub use record::TpmRecord;

/// Sanitized failure; never contains candidate, derived auth or TPM output.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// Protected metadata was invalid, unsupported or did not match the job.
    Record,
    /// Native TPM/transport/hierarchy/cleanup or OS randomness was unavailable.
    Unavailable,
    /// Shared dictionary-attack state was unknown, locked or inside the reserve.
    Budget,
    /// TPM positively rejected the submitted object's authValue.
    Mismatch,
}

/// Observed shared TPM dictionary-attack state. This is not an atomic reservation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TpmDaBudget {
    counter: u32,
    maximum: u32,
    in_lockout: bool,
}

impl TpmDaBudget {
    /// Unknown properties and inconsistent state fail closed.
    pub fn from_properties(
        counter: Option<u32>,
        maximum: Option<u32>,
        permanent: Option<u32>,
    ) -> Result<Self, Error> {
        let (counter, maximum, permanent) = (
            counter.ok_or(Error::Budget)?,
            maximum.ok_or(Error::Budget)?,
            permanent.ok_or(Error::Budget)?,
        );
        // TPMA_PERMANENT only defines bits 0..2 and 8..10 in the reviewed ABI.
        if maximum == 0 || counter > maximum || permanent & !0x707 != 0 {
            return Err(Error::Budget);
        }
        Ok(Self {
            counter,
            maximum,
            in_lockout: permanent & (1 << 9) != 0,
        })
    }

    /// Submit only when a possible mismatch still leaves at least `reserve`.
    /// Other TPM clients may change shared state after this observation.
    pub fn permits(self, reserve: u32) -> bool {
        reserve >= 2
            && !self.in_lockout
            && self
                .maximum
                .checked_sub(self.counter)
                .is_some_and(|remaining| remaining > reserve)
    }

    /// Counter observed without submitting an authorization.
    pub const fn counter(self) -> u32 {
        self.counter
    }
    /// Maximum observed without changing global policy.
    pub const fn maximum(self) -> u32 {
        self.maximum
    }
}

/// Explicit single native operation. Construction does not open a TPM.
///
/// Consume it in a supervised short-lived worker process. Verification consumes
/// the token even when metadata is rejected; it cannot reuse sessions or context.
#[must_use = "consume within a supervised native worker"]
pub struct NativeOperation {
    endpoint: TctiNameConf,
}

impl NativeOperation {
    /// Connect only to the Linux resource manager. No environment/default TCTI.
    /// The deployment must establish trusted local device access/hierarchy use.
    pub fn resource_manager() -> Result<Self, Error> {
        use std::str::FromStr;
        let endpoint =
            TctiNameConf::from_str("device:/dev/tpmrm0").map_err(|_| Error::Unavailable)?;
        Ok(Self { endpoint })
    }

    /// Disposable simulator transport for opt-in synthetic tests only.
    /// The caller starts and owns the localhost simulator and its state.
    #[cfg(feature = "simulator")]
    pub fn simulator(port: u16) -> Result<Self, Error> {
        use std::str::FromStr;
        if port == 0 || port == u16::MAX {
            return Err(Error::Unavailable);
        }
        let endpoint = TctiNameConf::from_str(&format!("swtpm:host=127.0.0.1,port={port}"))
            .map_err(|_| Error::Unavailable)?;
        Ok(Self { endpoint })
    }

    /// Enroll fixed Argon2id-v19 parameters under one charged TPM work lease.
    /// Returns only protected blobs and necessary nonsecret identity metadata.
    /// The M3 staging callback must trial verify its reopened exact record.
    pub fn enroll(
        self,
        account: AccountId,
        generation: Generation,
        pin: &Pin,
        permit: &mut WorkPermit,
        random: &mut impl Randomness,
    ) -> Result<CredentialRecord, Error> {
        if !permit.covers(
            account.uid,
            KdfParameters::ENROLLMENT,
            WorkKind::TpmPinDerivation,
        ) {
            return Err(Error::Record);
        }
        let mut salt = [0; 16];
        let mut secret = zeroize::Zeroizing::new([0; 32]);
        random.fill(&mut salt).map_err(|_| Error::Unavailable)?;
        random
            .fill(secret.as_mut())
            .map_err(|_| Error::Unavailable)?;
        let auth = localpin_credentials::derive(pin, &salt, KdfParameters::ENROLLMENT, permit)
            .map_err(|_| Error::Unavailable)?;
        let record = native::enroll(
            self.endpoint,
            account,
            generation,
            salt,
            auth.expose(),
            &secret,
        )?;
        record.into_credential()
    }

    /// Trial verify the exact record reopened by M3 during staged enrollment.
    /// This is trusted enrollment code, never a broker/client verification path.
    pub fn trial_verify(
        self,
        credential: &CredentialRecord,
        pin: &Pin,
        permit: &mut WorkPermit,
        reserve: u32,
    ) -> Result<(), Error> {
        let record = TpmRecord::from_credential(credential)?;
        if !permit.covers(
            credential.account().uid,
            record.parameters(),
            WorkKind::TpmPinDerivation,
        ) {
            return Err(Error::Record);
        }
        let auth = localpin_credentials::derive(pin, record.salt(), record.parameters(), permit)
            .map_err(|_| Error::Unavailable)?;
        native::verify(self.endpoint, &record, auth.expose().as_slice(), reserve)
    }

    /// Bind one active protected credential to one forthcoming reserved job.
    /// Errors still consume the operation token; the job's reservation persists.
    pub fn verifier(self, credential: &CredentialRecord, reserve: u32) -> TpmVerifier<'_> {
        TpmVerifier {
            operation: Some(self),
            credential,
            reserve,
        }
    }
}

/// A one-shot adapter. It contains configuration/record references, no context,
/// derived authorization, unsealed data or cached success.
pub struct TpmVerifier<'r> {
    operation: Option<NativeOperation>,
    credential: &'r CredentialRecord,
    reserve: u32,
}

impl CredentialVerifier for TpmVerifier<'_> {
    fn verify<'a>(&mut self, job: VerificationJob<'a>) -> VerificationCompletion<'a> {
        let result = (|| {
            let operation = self.operation.take().ok_or(Error::Unavailable)?;
            if job.backend() != Backend::Tpm2
                || self.credential.account() != job.account()
                || self.credential.generation() != job.generation()
            {
                return Err(Error::Record);
            }
            let record = TpmRecord::from_credential(self.credential)?;
            if record.parameters() != job.parameters()
                || !job.work().covers(
                    job.account().uid,
                    record.parameters(),
                    WorkKind::TpmPinDerivation,
                )
            {
                return Err(Error::Record);
            }
            let auth = localpin_credentials::derive(
                job.pin(),
                record.salt(),
                record.parameters(),
                job.work(),
            )
            .map_err(|_| Error::Unavailable)?;
            native::verify(
                operation.endpoint,
                &record,
                auth.expose().as_slice(),
                self.reserve,
            )
        })();
        let outcome = match result {
            Ok(()) => BackendOutcome::Match,
            Err(Error::Mismatch) => BackendOutcome::Mismatch,
            Err(_) => BackendOutcome::Unavailable(BackendFailure::Unavailable),
        };
        // All context cleanup and auth erasure have completed before finish.
        job.finish(outcome)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn da_budget_checked_reserve_and_invalid_state() {
        for bad in [
            (None, Some(8), Some(0)),
            (Some(1), None, Some(0)),
            (Some(1), Some(8), None),
            (Some(9), Some(8), Some(0)),
            (Some(0), Some(0), Some(0)),
            (Some(0), Some(8), Some(1 << 31)),
        ] {
            assert!(TpmDaBudget::from_properties(bad.0, bad.1, bad.2).is_err());
        }
        for count in 0..=8 {
            assert_eq!(
                TpmDaBudget::from_properties(Some(count), Some(8), Some(0))
                    .unwrap()
                    .permits(2),
                count < 6
            );
        }
        assert!(
            !TpmDaBudget::from_properties(Some(0), Some(u32::MAX), Some(1 << 9))
                .unwrap()
                .permits(2)
        );
        assert!(
            !TpmDaBudget::from_properties(Some(0), Some(8), Some(0))
                .unwrap()
                .permits(1)
        );
    }
}

#[cfg(all(test, feature = "simulator"))]
mod simulator_tests;
