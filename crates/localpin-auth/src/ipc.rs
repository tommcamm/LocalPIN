//! Private bounded framing: not part of the client protocol or a bearer grant.
#![forbid(unsafe_code)]

use localpin_core::{
    enrollment::{EnrollmentAction, PasswordWorkerRequest},
    secret::SecretBytes,
    types::Backend,
};
use std::io::{self, Read, Write};
use zeroize::Zeroizing;

pub(crate) const PROMPT: u8 = 1;
pub(crate) const ANSWER: u8 = 2;
pub(crate) const RESULT: u8 = 3;
pub(crate) const HEADER: usize = 23;
pub(crate) const REQUEST_BYTES: usize = 105;

pub(crate) struct Request {
    pub(crate) token: [u8; 16],
    pub(crate) uid: u32,
}

impl Request {
    pub(crate) fn encode(request: PasswordWorkerRequest, token: [u8; 16]) -> [u8; REQUEST_BYTES] {
        let binding = request.binding();
        let action = match binding.action() {
            EnrollmentAction::Enroll(Backend::Tpm2) => 1,
            EnrollmentAction::Enroll(Backend::Software) => 2,
            EnrollmentAction::Rotate => 3,
            EnrollmentAction::MigrateBackend(Backend::Tpm2) => 4,
            EnrollmentAction::MigrateBackend(Backend::Software) => 5,
            EnrollmentAction::Disable => 6,
            EnrollmentAction::AdministrativeRecovery => 7,
        };
        let mut out = [0; REQUEST_BYTES];
        let fields: &[&[u8]] = &[
            b"LPA1",
            &token,
            &binding.account().uid.get().to_be_bytes(),
            &binding.account().incarnation.get(),
            &binding.connection().get(),
            &binding.transaction().get(),
            &[action],
            &binding.proposed_generation().get().to_be_bytes(),
            &request.started_at().boot.get(),
            &request.started_at().millis.to_be_bytes(),
        ];
        let mut offset = 0;
        for field in fields {
            out[offset..offset + field.len()].copy_from_slice(field);
            offset += field.len();
        }
        out
    }

    pub(crate) fn read(reader: &mut impl Read) -> io::Result<Self> {
        let mut bytes = [0; REQUEST_BYTES];
        reader.read_exact(&mut bytes)?;
        let uid = u32::from_be_bytes(bytes[20..24].try_into().map_err(|_| invalid())?);
        if bytes[..4] != *b"LPA1"
            || bytes[4..20] == [0; 16]
            || uid == 0
            || uid == u32::MAX
            || !(1..=6).contains(&bytes[72])
            || bytes[73..81] == [0; 8]
            || [24..40, 40..56, 56..72, 81..97]
                .iter()
                .any(|range| bytes[range.clone()] == [0; 16])
        {
            return Err(invalid());
        }
        Ok(Self {
            token: bytes[4..20].try_into().map_err(|_| invalid())?,
            uid,
        })
    }
}

pub(crate) struct Frame {
    pub(crate) kind: u8,
    pub(crate) token: [u8; 16],
    pub(crate) sequence: u32,
    pub(crate) payload: SecretBytes,
}

pub(crate) fn write_frame(
    writer: &mut impl Write,
    kind: u8,
    token: &[u8; 16],
    sequence: u32,
    bytes: &[u8],
) -> io::Result<()> {
    if bytes.len() > crate::MAX_PASSWORD_BYTES {
        return Err(invalid());
    }
    let mut buffer = Zeroizing::new(Vec::with_capacity(HEADER + bytes.len()));
    buffer.push(kind);
    buffer.extend_from_slice(token);
    buffer.extend_from_slice(&sequence.to_be_bytes());
    buffer.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
    buffer.extend_from_slice(bytes);
    writer.write_all(&buffer)?;
    writer.flush()
}

pub(crate) fn decode(bytes: &[u8]) -> io::Result<Option<(Frame, usize)>> {
    if bytes.len() < HEADER {
        return Ok(None);
    }
    let length = u16::from_be_bytes([bytes[21], bytes[22]]) as usize;
    if length > crate::MAX_PASSWORD_BYTES || !(PROMPT..=RESULT).contains(&bytes[0]) {
        return Err(invalid());
    }
    if bytes.len() < HEADER + length {
        return Ok(None);
    }
    Ok(Some((
        Frame {
            kind: bytes[0],
            token: bytes[1..17].try_into().map_err(|_| invalid())?,
            sequence: u32::from_be_bytes(bytes[17..21].try_into().map_err(|_| invalid())?),
            payload: SecretBytes::from_slice(
                &bytes[HEADER..HEADER + length],
                crate::MAX_PASSWORD_BYTES,
            )
            .map_err(|_| invalid())?,
        },
        HEADER + length,
    )))
}

pub(crate) fn read_frame(reader: &mut impl Read) -> io::Result<Frame> {
    let mut header = [0; HEADER];
    reader.read_exact(&mut header)?;
    let length = u16::from_be_bytes([header[21], header[22]]) as usize;
    if length > crate::MAX_PASSWORD_BYTES {
        return Err(invalid());
    }
    let mut bytes = Zeroizing::new(Vec::with_capacity(HEADER + length));
    bytes.extend_from_slice(&header);
    bytes.resize(HEADER + length, 0);
    reader.read_exact(&mut bytes[HEADER..])?;
    decode(&bytes)?.map(|(frame, _)| frame).ok_or_else(invalid)
}

pub(crate) fn invalid() -> io::Error {
    io::Error::other("invalid private password worker frame")
}
