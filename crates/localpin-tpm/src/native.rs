use crate::{Error, TpmDaBudget, TpmRecord, record::name};
use localpin_core::{
    limits::KdfParameters,
    types::{AccountId, Generation},
};
use tss_esapi::{
    Context,
    attributes::{ObjectAttributes, SessionAttributesBuilder},
    constants::response_code::{FormatOneResponseCode, Tss2ResponseCode},
    constants::{CapabilityType, PropertyTag, SessionType},
    handles::{KeyHandle, SessionHandle},
    interface_types::{
        algorithm::{HashingAlgorithm, PublicAlgorithm},
        key_bits::RsaKeyBits,
        resource_handles::Hierarchy,
        session_handles::AuthSession,
    },
    structures::{
        Auth, CapabilityData, Digest, KeyedHashScheme, Public, PublicBuilder, PublicKeyRsa,
        PublicKeyedHashParameters, PublicRsaParametersBuilder, RsaExponent, SensitiveData,
        SymmetricDefinition, SymmetricDefinitionObject,
    },
    tcti_ldr::TctiNameConf,
};

pub(crate) fn parent_template() -> Result<Public, Error> {
    PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::Rsa)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(ObjectAttributes::from(0x30072u32))
        .with_auth_policy(Digest::default())
        .with_rsa_parameters(
            PublicRsaParametersBuilder::new_restricted_decryption_key(
                SymmetricDefinitionObject::AES_128_CFB,
                RsaKeyBits::Rsa2048,
                RsaExponent::ZERO_EXPONENT,
            )
            .build()
            .map_err(|_| Error::Record)?,
        )
        .with_rsa_unique_identifier(PublicKeyRsa::default())
        .build()
        .map_err(|_| Error::Record)
}

pub(crate) fn object_template() -> Result<Public, Error> {
    PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::KeyedHash)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(ObjectAttributes::from(0x52u32))
        .with_auth_policy(Digest::default())
        .with_keyed_hash_parameters(PublicKeyedHashParameters::new(KeyedHashScheme::Null))
        .with_keyed_hash_unique_identifier(Digest::default())
        .build()
        .map_err(|_| Error::Record)
}

pub(crate) fn validate_parent(public: &Public) -> Result<(), Error> {
    match public {
        Public::Rsa { unique, .. } if unique.value().len() == 256 => {
            let mut expected = parent_template()?;
            if let Public::Rsa {
                unique: expected_unique,
                ..
            } = &mut expected
            {
                *expected_unique = unique.clone();
            }
            if expected == *public {
                return Ok(());
            }
            Err(Error::Record)
        }
        _ => Err(Error::Record),
    }
}

pub(crate) fn validate_object(public: &Public) -> Result<(), Error> {
    match public {
        Public::KeyedHash { unique, .. } if unique.value().len() == 32 => {
            let mut expected = object_template()?;
            if let Public::KeyedHash {
                unique: expected_unique,
                ..
            } = &mut expected
            {
                *expected_unique = unique.clone();
            }
            if expected == *public {
                return Ok(());
            }
            Err(Error::Record)
        }
        _ => Err(Error::Record),
    }
}

fn create_parent(
    ctx: &mut Context,
    enrolled: Option<&TpmRecord>,
) -> Result<(KeyHandle, Public, [u8; 34]), Error> {
    // Empty owner auth is supported only when the TPM advertises it unset.
    // Refuse provisioned hierarchy auth without submitting any guessed auth.
    let permanent = fresh_property(ctx, PropertyTag::Permanent)?.ok_or(Error::Unavailable)?;
    if permanent & !0x707 != 0 || permanent & 1 != 0 {
        return Err(Error::Unavailable);
    }
    // Only empty owner/primary auth is used in bootstrap. Never guess/change it.
    let created = ctx
        .execute_with_nullauth_session(|ctx| {
            ctx.create_primary(
                Hierarchy::Owner,
                parent_template().map_err(|_| {
                    tss_esapi::Error::WrapperError(tss_esapi::WrapperErrorKind::InvalidParam)
                })?,
                None,
                None,
                None,
                None,
            )
        })
        .map_err(|_| Error::Unavailable)?;
    validate_parent(&created.out_public)?;
    let (public, returned_name, _) = ctx
        .read_public(created.key_handle)
        .map_err(|_| Error::Unavailable)?;
    validate_parent(&public)?;
    let computed = name(&public)?;
    if public != created.out_public
        || returned_name.value() != computed
        || enrolled.is_some_and(|record| record.parent != public || record.parent_name != computed)
    {
        return Err(Error::Record);
    }
    Ok((created.key_handle, public, computed))
}

fn salted_session(
    ctx: &mut Context,
    parent: KeyHandle,
    decrypt: bool,
) -> Result<AuthSession, Error> {
    let session = ctx
        .start_auth_session(
            Some(parent),
            None,
            None,
            SessionType::Hmac,
            SymmetricDefinition::AES_128_CFB,
            HashingAlgorithm::Sha256,
        )
        .map_err(|_| Error::Unavailable)?
        .ok_or(Error::Unavailable)?;
    let (attributes, mask) = SessionAttributesBuilder::new()
        .with_continue_session(true)
        .with_decrypt(decrypt)
        .with_encrypt(true)
        .build();
    ctx.tr_sess_set_attributes(session, attributes, mask)
        .map_err(|_| Error::Unavailable)?;
    Ok(session)
}

fn fresh_property(ctx: &mut Context, property: PropertyTag) -> Result<Option<u32>, Error> {
    // get_tpm_property caches dynamic values for the context's whole lifetime.
    // Query exactly one property directly so bootstrap and preflight observations
    // cannot reuse stale owner authorization, lockout or shared-budget state.
    let (capability, _) = ctx
        .execute_without_session(|ctx| {
            ctx.get_capability(CapabilityType::TpmProperties, property.into(), 1)
        })
        .map_err(|_| Error::Unavailable)?;
    match capability {
        CapabilityData::TpmProperties(properties) if properties.len() <= 1 => {
            Ok(properties.find(property).map(|value| value.value()))
        }
        _ => Err(Error::Unavailable),
    }
}

pub(crate) fn budget(ctx: &mut Context) -> Result<TpmDaBudget, Error> {
    let counter = fresh_property(ctx, PropertyTag::LockoutCounter)?;
    let maximum = fresh_property(ctx, PropertyTag::MaxAuthFail)?;
    let permanent = fresh_property(ctx, PropertyTag::Permanent)?;
    TpmDaBudget::from_properties(counter, maximum, permanent)
}

pub(crate) fn enroll(
    endpoint: TctiNameConf,
    account: AccountId,
    generation: Generation,
    salt: [u8; 16],
    auth: &[u8; 32],
    secret: &[u8; 32],
) -> Result<TpmRecord, Error> {
    let mut ctx = Context::new(endpoint).map_err(|_| Error::Unavailable)?;
    let (parent_handle, parent, parent_name) = create_parent(&mut ctx, None)?;
    let session = salted_session(&mut ctx, parent_handle, true)?;
    let created = ctx
        .execute_with_session(Some(session), |ctx| {
            ctx.create(
                parent_handle,
                object_template().map_err(|_| {
                    tss_esapi::Error::WrapperError(tss_esapi::WrapperErrorKind::InvalidParam)
                })?,
                Some(Auth::try_from(auth.as_slice())?),
                Some(SensitiveData::try_from(secret.as_slice())?),
                None,
                None,
            )
        })
        .map_err(|_| Error::Unavailable)?;
    validate_object(&created.out_public)?;
    let object_name = name(&created.out_public)?;
    let record = TpmRecord {
        account,
        generation,
        parameters: KdfParameters::ENROLLMENT,
        salt,
        parent,
        parent_name,
        object: created.out_public,
        object_name,
        private: created.out_private,
    };
    record.validate()?;
    ctx.clear_sessions();
    ctx.flush_context(SessionHandle::from(session).into())
        .map_err(|_| Error::Unavailable)?;
    ctx.flush_context(parent_handle.into())
        .map_err(|_| Error::Unavailable)?;
    // Context drop remains fallback cleanup on every early failure.
    Ok(record)
}

pub(crate) fn verify(
    endpoint: TctiNameConf,
    record: &TpmRecord,
    auth: &[u8],
    reserve: u32,
) -> Result<(), Error> {
    record.validate()?;
    if reserve < 2 {
        return Err(Error::Budget);
    }
    let mut ctx = Context::new(endpoint).map_err(|_| Error::Unavailable)?;
    let (parent_handle, _, _) = create_parent(&mut ctx, Some(record))?;
    let object_handle = ctx
        .execute_with_nullauth_session(|ctx| {
            ctx.load(parent_handle, record.private.clone(), record.object.clone())
        })
        .map_err(|_| Error::Unavailable)?;
    let (public, object_name, _) = ctx
        .read_public(object_handle)
        .map_err(|_| Error::Unavailable)?;
    validate_object(&public)?;
    if public != record.object
        || name(&public)? != record.object_name
        || object_name.value() != record.object_name
    {
        return Err(Error::Record);
    }
    let session = salted_session(&mut ctx, parent_handle, false)?;
    ctx.tr_set_auth(
        object_handle.into(),
        Auth::try_from(auth).map_err(|_| Error::Record)?,
    )
    .map_err(|_| Error::Unavailable)?;
    // This inspection happens immediately before the candidate authorization.
    if !budget(&mut ctx)?.permits(reserve) {
        return Err(Error::Budget);
    }
    let unsealed = ctx
        .execute_with_session(Some(session), |ctx| ctx.unseal(object_handle.into()))
        .map_err(classify_unseal)?;
    let valid_length = unsealed.value().len() == 32;
    // SensitiveData is a zeroizing owner in the pinned tss-esapi release. Never
    // hash/compare/cache the returned bytes; the authenticated response is proof.
    drop(unsealed);
    if !valid_length {
        return Err(Error::Unavailable);
    }
    ctx.clear_sessions();
    ctx.flush_context(object_handle.into())
        .map_err(|_| Error::Unavailable)?;
    ctx.flush_context(SessionHandle::from(session).into())
        .map_err(|_| Error::Unavailable)?;
    ctx.flush_context(parent_handle.into())
        .map_err(|_| Error::Unavailable)?;
    Ok(())
}

fn classify_unseal(error: tss_esapi::Error) -> Error {
    // Exact TPM_RC_AUTH_FAIL for the first authorization session. Do not map a
    // transport-layer code sharing low bits, policy failure or lockout to PIN bad.
    match error {
        tss_esapi::Error::Tss2Error(Tss2ResponseCode::FormatOne(FormatOneResponseCode(0x98e))) => {
            Error::Mismatch
        }
        _ => Error::Unavailable,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tss_esapi::traits::Marshall;

    #[test]
    fn templates_are_exact_and_reject_every_attribute_change() {
        let mut parent = parent_template().unwrap();
        let mut child = object_template().unwrap();
        if let Public::Rsa { unique, .. } = &mut parent {
            *unique = PublicKeyRsa::try_from(vec![0x31; 256]).unwrap();
        }
        if let Public::KeyedHash { unique, .. } = &mut child {
            *unique = Digest::try_from(vec![0x32; 32]).unwrap();
        }
        assert_eq!(validate_parent(&parent), Ok(()));
        assert_eq!(validate_object(&child), Ok(()));
        assert_eq!(
            &parent.marshall().unwrap()[..10],
            &[0, 1, 0, 11, 0, 3, 0, 0x72, 0, 0]
        );
        assert_eq!(
            &child.marshall().unwrap()[..14],
            &[0, 8, 0, 11, 0, 0, 0, 0x52, 0, 0, 0, 16, 0, 32]
        );
        for bit in 0..32 {
            let mut changed = parent.clone();
            if let Public::Rsa {
                object_attributes, ..
            } = &mut changed
            {
                *object_attributes = ObjectAttributes::from(0x30072u32 ^ (1 << bit));
            }
            assert_eq!(validate_parent(&changed), Err(Error::Record));
            let mut changed = child.clone();
            if let Public::KeyedHash {
                object_attributes, ..
            } = &mut changed
            {
                *object_attributes = ObjectAttributes::from(0x52u32 ^ (1 << bit));
            }
            assert_eq!(validate_object(&changed), Err(Error::Record));
        }
        let mut changed = child.clone();
        if let Public::KeyedHash { auth_policy, .. } = &mut changed {
            *auth_policy = Digest::try_from(vec![1; 32]).unwrap();
        }
        assert_eq!(validate_object(&changed), Err(Error::Record));
        let mut changed = child.clone();
        if let Public::KeyedHash {
            name_hashing_algorithm,
            ..
        } = &mut changed
        {
            *name_hashing_algorithm = HashingAlgorithm::Sha1;
        }
        assert_eq!(validate_object(&changed), Err(Error::Record));
        assert_eq!(validate_object(&parent), Err(Error::Record));
        assert_eq!(validate_parent(&child), Err(Error::Record));
    }

    #[test]
    fn only_exact_tpm_auth_fail_is_a_candidate_mismatch() {
        assert_eq!(
            classify_unseal(tss_esapi::Error::Tss2Error(Tss2ResponseCode::FormatOne(
                FormatOneResponseCode(0x98e)
            ))),
            Error::Mismatch
        );
        for code in [0x18e, 0xa098e, 0x99d, 0x1df] {
            assert_eq!(
                classify_unseal(tss_esapi::Error::Tss2Error(Tss2ResponseCode::FormatOne(
                    FormatOneResponseCode(code)
                ))),
                Error::Unavailable
            );
        }
        assert_eq!(
            classify_unseal(tss_esapi::Error::WrapperError(
                tss_esapi::WrapperErrorKind::WrongValueFromTpm
            )),
            Error::Unavailable
        );
    }
}
