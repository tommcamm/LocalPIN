//! Explicitly borrowed, non-cloneable secret ownership; no serialization traits.
//!
//! Input owners must erase their own source buffers. Drop clears owned storage,
//! not prior moves, compiler temporaries, native-library copies, swap or dumps.

use std::fmt;
use zeroize::Zeroizing;

/// Absolute allocation cap for a secret-bearing record or buffer.
pub const MAX_SECRET_BYTES: usize = 64 * 1024;

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

/// Exactly six ASCII decimal digits, including leading zeroes.
pub struct Pin(SecretBytes);

impl Pin {
    /// Reject empty, Unicode digits, signs, whitespace and all other lengths.
    pub fn parse(bytes: &[u8]) -> Result<Self, SecretError> {
        if bytes.len() != 6 || !bytes.iter().all(u8::is_ascii_digit) {
            return Err(SecretError);
        }
        SecretBytes::from_slice(bytes, 6).map(Self)
    }

    /// Explicit borrowing for the KDF or bounded private IPC encoder.
    pub fn expose(&self) -> &[u8] {
        self.0.expose()
    }
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
            b"12345",
            b"1234567",
            b"12345 ",
            b"+12345",
            "１２３４５６".as_bytes(),
            "١٢٣٤٥٦".as_bytes(),
        ] {
            assert!(Pin::parse(invalid).is_err());
        }
        for byte in 0..=255u8 {
            let mut candidate = *b"012345";
            candidate[2] = byte;
            assert_eq!(Pin::parse(&candidate).is_ok(), byte.is_ascii_digit());
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
