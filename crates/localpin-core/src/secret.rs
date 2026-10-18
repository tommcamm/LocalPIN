//! Explicitly borrowed, non-cloneable secret ownership; no serialization traits.
//!
//! Input owners must erase their own source buffers. Drop clears owned storage,
//! not prior moves, compiler temporaries, native-library copies, swap or dumps.

use std::fmt;
use zeroize::Zeroizing;

use crate::types::Backend;

/// Absolute allocation cap for a secret-bearing record or buffer.
pub const MAX_SECRET_BYTES: usize = 64 * 1024;

/// Maximum credential input, before its enrolled kind and backend are known.
pub const MAX_CREDENTIAL_BYTES: usize = 64;

/// Policy written by all newly enrolled credentials.
pub const CURRENT_POLICY: u8 = 1;

/// The explicitly selected credential format, never inferred from its contents.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum CredentialKind {
    /// ASCII decimal digits, preserving leading zeroes.
    NumericPin = 1,
    /// Printable ASCII, preserving every space and the original case.
    Passcode = 2,
}

/// Public format metadata; the secret itself remains in separately erased memory.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CredentialProfile {
    /// Enrollment policy version; zero represents only a legacy v1 record.
    pub policy: u8,
    /// Explicitly selected format, including all-digit passcodes.
    pub kind: CredentialKind,
    /// Exact enrolled byte/character length. All accepted characters are ASCII.
    pub length: u8,
}

impl CredentialProfile {
    /// Metadata for a version-1 record, including existing software credentials.
    pub const fn legacy() -> Self {
        Self {
            policy: 0,
            kind: CredentialKind::NumericPin,
            length: 6,
        }
    }

    /// Validate the selected type against the actual protection backend.
    pub fn for_enrollment(
        backend: Backend,
        kind: CredentialKind,
        secret: &Pin,
    ) -> Result<Self, SecretError> {
        let profile = Self {
            policy: CURRENT_POLICY,
            kind,
            length: u8::try_from(secret.expose().len()).map_err(|_| SecretError)?,
        };
        profile.validate(backend)?;
        if !profile.matches(secret) {
            return Err(SecretError);
        }
        Ok(profile)
    }

    /// Reject unknown policies and impossible backend/type/length combinations.
    pub fn validate(self, backend: Backend) -> Result<(), SecretError> {
        if self.policy == 0 {
            return if self == Self::legacy() {
                Ok(())
            } else {
                Err(SecretError)
            };
        }
        if self.policy != CURRENT_POLICY {
            return Err(SecretError);
        }
        let minimum = match (self.kind, backend) {
            (CredentialKind::NumericPin, Backend::Tpm2) => 4,
            (CredentialKind::NumericPin, Backend::Software) | (CredentialKind::Passcode, _) => 8,
        };
        let maximum = match self.kind {
            CredentialKind::NumericPin => 16,
            CredentialKind::Passcode => MAX_CREDENTIAL_BYTES as u8,
        };
        if !(minimum..=maximum).contains(&self.length) {
            return Err(SecretError);
        }
        Ok(())
    }

    /// Match only the exact public profile before reserving a backend attempt.
    pub fn matches(self, secret: &Pin) -> bool {
        let bytes = secret.expose();
        if usize::from(self.length) != bytes.len()
            || (self.policy != CURRENT_POLICY && self != Self::legacy())
        {
            return false;
        }
        match self.kind {
            CredentialKind::NumericPin => {
                (4..=16).contains(&bytes.len()) && bytes.iter().all(u8::is_ascii_digit)
            }
            CredentialKind::Passcode => {
                (8..=MAX_CREDENTIAL_BYTES).contains(&bytes.len())
                    && bytes.iter().all(|byte| (b' '..=b'~').contains(byte))
            }
        }
    }
}

/// Sanitized invalid-format or excessive-length error; never includes input.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SecretError;

/// Bounded heap storage erased on drop; intentionally neither Clone nor Display.
pub struct SecretBytes(Zeroizing<Vec<u8>>);

impl SecretBytes {
    /// Copy only after validating both the caller's cap and the absolute cap.
    pub fn from_slice(bytes: &[u8], max: usize) -> Result<Self, SecretError> {
        if max > MAX_SECRET_BYTES || bytes.len() > max {
            return Err(SecretError);
        }
        Ok(Self(Zeroizing::new(bytes.to_vec())))
    }

    /// Explicit secret exposure. Borrow only for the shortest required boundary.
    pub fn expose(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretBytes([REDACTED])")
    }
}

/// Bounded candidate, awaiting validation against an explicit enrolled profile.
///
/// The compatibility name remains `Pin`; it also owns passcode candidates.
pub struct Pin(SecretBytes);

/// Secret-owning credential candidate, including numeric PINs and passcodes.
pub type CredentialSecret = Pin;

impl Pin {
    /// Accept plausible numeric or printable-ASCII credential candidates.
    /// Backend-specific enrollment policy must be checked separately.
    pub fn parse(bytes: &[u8]) -> Result<Self, SecretError> {
        let numeric = (4..=MAX_CREDENTIAL_BYTES).contains(&bytes.len())
            && bytes.iter().all(u8::is_ascii_digit);
        let passcode = (8..=MAX_CREDENTIAL_BYTES).contains(&bytes.len())
            && bytes.iter().all(|byte| (b' '..=b'~').contains(byte));
        if !numeric && !passcode {
            return Err(SecretError);
        }
        SecretBytes::from_slice(bytes, MAX_CREDENTIAL_BYTES).map(Self)
    }

    /// Explicit borrowing for the KDF or bounded private IPC encoder.
    pub fn expose(&self) -> &[u8] {
        self.0.expose()
    }
}

/// Advisory predictable-choice warning; this never changes acceptance policy.
/// The caller must obtain an explicit local override before using a warned input.
pub fn is_predictable(secret: &Pin) -> bool {
    let bytes = secret.expose();
    let repeated = (1..=4).any(|period| {
        bytes.len() >= 2 * period
            && bytes.len().is_multiple_of(period)
            && bytes
                .iter()
                .enumerate()
                .all(|(index, byte)| *byte == bytes[index % period])
    });
    let sequence = bytes.iter().all(u8::is_ascii_digit)
        && [1, 9].iter().any(|step| {
            bytes
                .windows(2)
                .all(|pair| (pair[0] - b'0' + step) % 10 == pair[1] - b'0')
        });
    const COMMON: [&[u8]; 10] = [
        b"password",
        b"password1",
        b"password123",
        b"qwerty123",
        b"qwertyuiop",
        b"letmein123",
        b"welcome1",
        b"iloveyou",
        b"changeme",
        b"localpin",
    ];
    repeated || sequence || COMMON.iter().any(|word| bytes.eq_ignore_ascii_case(word))
}

impl fmt::Debug for Pin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Pin([REDACTED])")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ascii_only_and_leading_zeroes() {
        assert_eq!(Pin::parse(b"000001").unwrap().expose(), b"000001");
        for invalid in [
            b"".as_slice(),
            b"123",
            b"12345 ",
            b"+12345",
            b"pass\nword",
            b"pass\tword",
            b"pass\0word",
            b"pass\x7fword",
            "１２３４５６".as_bytes(),
            "١٢٣٤٥٦".as_bytes(),
            "synthetic café".as_bytes(),
        ] {
            assert!(Pin::parse(invalid).is_err());
        }
        for byte in 0..=255u8 {
            let mut candidate = *b"012345";
            candidate[2] = byte;
            assert_eq!(Pin::parse(&candidate).is_ok(), byte.is_ascii_digit());
        }
        assert_eq!(
            Pin::parse(b"  Mixed ASCII  ").unwrap().expose(),
            b"  Mixed ASCII  "
        );
        for byte in 0..=255u8 {
            let mut candidate = *b"passcode";
            candidate[2] = byte;
            assert_eq!(
                Pin::parse(&candidate).is_ok(),
                (b' '..=b'~').contains(&byte)
            );
        }
    }

    #[test]
    fn enrollment_boundaries_are_backend_and_type_specific() {
        for len in 0..=65 {
            let digits = vec![b'0'; len];
            let characters = vec![b'A'; len];
            for backend in [Backend::Tpm2, Backend::Software] {
                let numeric_minimum = if backend == Backend::Tpm2 { 4 } else { 8 };
                let numeric = Pin::parse(&digits).and_then(|secret| {
                    CredentialProfile::for_enrollment(backend, CredentialKind::NumericPin, &secret)
                });
                assert_eq!(numeric.is_ok(), (numeric_minimum..=16).contains(&len));
                for candidate in [&digits, &characters] {
                    let passcode = Pin::parse(candidate).and_then(|secret| {
                        CredentialProfile::for_enrollment(
                            backend,
                            CredentialKind::Passcode,
                            &secret,
                        )
                    });
                    assert_eq!(passcode.is_ok(), (8..=64).contains(&len));
                }
            }
        }
        let text = Pin::parse(b"eight AB").unwrap();
        assert!(
            CredentialProfile::for_enrollment(Backend::Tpm2, CredentialKind::NumericPin, &text)
                .is_err()
        );
    }

    #[test]
    fn profile_matching_preserves_exact_format_and_length() {
        let numeric = CredentialProfile::for_enrollment(
            Backend::Tpm2,
            CredentialKind::NumericPin,
            &Pin::parse(b"000001").unwrap(),
        )
        .unwrap();
        assert_eq!(numeric.length, 6);
        assert_eq!(numeric.policy, CURRENT_POLICY);
        assert!(numeric.matches(&Pin::parse(b"654321").unwrap()));
        assert!(!numeric.matches(&Pin::parse(b"0654321").unwrap()));
        let passcode = CredentialProfile::for_enrollment(
            Backend::Software,
            CredentialKind::Passcode,
            &Pin::parse(b" passcode ").unwrap(),
        )
        .unwrap();
        assert_eq!(passcode.length, 10);
        assert!(passcode.matches(&Pin::parse(b"0123456789").unwrap()));
        assert!(!passcode.matches(&Pin::parse(b" passcode").unwrap()));
        assert!(CredentialProfile::legacy().matches(&Pin::parse(b"123456").unwrap()));
        assert_eq!(
            CredentialProfile::legacy().validate(Backend::Software),
            Ok(())
        );
        for profile in [
            CredentialProfile {
                policy: 2,
                ..numeric
            },
            CredentialProfile {
                policy: 0,
                length: 8,
                ..numeric
            },
            CredentialProfile {
                kind: CredentialKind::Passcode,
                ..CredentialProfile::legacy()
            },
        ] {
            assert!(profile.validate(Backend::Tpm2).is_err());
            assert!(!profile.matches(&Pin::parse(b"123456").unwrap()));
        }
    }

    #[test]
    fn predictable_choices_are_advisory_and_case_insensitive() {
        for predictable in [
            b"0000".as_slice(),
            b"AAAAAAAA",
            b"        ",
            b"12121212",
            b"abcabcabc",
            b"aB4$aB4$",
            b"78901234",
            b"21098765",
            b"PASSWORD",
            b"password1",
            b"Password123",
            b"qwerty123",
            b"qwertyuiop",
            b"letmein123",
            b"welcome1",
            b"iloveyou",
            b"changeme",
            b"localpin",
        ] {
            assert!(is_predictable(&Pin::parse(predictable).unwrap()));
        }
        for other in [
            b"739426".as_slice(),
            b" password",
            b"aB4$aB4%",
            b"synthetic phrase",
        ] {
            assert!(!is_predictable(&Pin::parse(other).unwrap()));
        }
    }

    #[test]
    fn diagnostics_never_include_secret() {
        assert_eq!(
            format!("{:?}", Pin::parse(b"012345").unwrap()),
            "Pin([REDACTED])"
        );
        assert_eq!(
            format!(
                "{:?}",
                SecretBytes::from_slice(b"synthetic password", 100).unwrap()
            ),
            "SecretBytes([REDACTED])"
        );
        assert!(SecretBytes::from_slice(&[], MAX_SECRET_BYTES + 1).is_err());
        assert!(SecretBytes::from_slice(b"12", 1).is_err());
    }
}
