#![no_main]

use libfuzzer_sys::fuzz_target;
use localpin_protocol::{
    EncodedFrame, ProtocolError, RequestDecoder, ResponseDecoder, encode_request, encode_response,
};

trait Decoder: Default {
    fn push(&mut self, bytes: &[u8]) -> Result<(usize, Option<EncodedFrame>), ProtocolError>;
    fn finish(&mut self) -> Result<(), ProtocolError>;
}

impl Decoder for RequestDecoder {
    fn push(&mut self, bytes: &[u8]) -> Result<(usize, Option<EncodedFrame>), ProtocolError> {
        let (consumed, request) = RequestDecoder::push(self, bytes)?;
        Ok((consumed, request.as_ref().map(encode_request).transpose()?))
    }

    fn finish(&mut self) -> Result<(), ProtocolError> {
        RequestDecoder::finish(self)
    }
}

impl Decoder for ResponseDecoder {
    fn push(&mut self, bytes: &[u8]) -> Result<(usize, Option<EncodedFrame>), ProtocolError> {
        let (consumed, response) = ResponseDecoder::push(self, bytes)?;
        Ok((
            consumed,
            response.as_ref().map(encode_response).transpose()?,
        ))
    }

    fn finish(&mut self) -> Result<(), ProtocolError> {
        ResponseDecoder::finish(self)
    }
}

fn poisoned(decoder: &mut impl Decoder) {
    assert!(matches!(decoder.push(&[]), Err(ProtocolError::OutOfOrder)));
    assert!(matches!(
        decoder.push(&[0; 22]),
        Err(ProtocolError::OutOfOrder)
    ));
    assert_eq!(decoder.finish(), Err(ProtocolError::OutOfOrder));
}

fn inspect<D: Decoder>(bytes: &[u8], chunk: usize) {
    let mut decoder = D::default();
    let mut offset = 0;
    let mut frame_start = 0;
    while offset < bytes.len() {
        let end = bytes.len().min(offset + chunk);
        match decoder.push(&bytes[offset..end]) {
            Ok((consumed, frame)) => {
                assert!((1..=end - offset).contains(&consumed));
                offset += consumed;
                if let Some(frame) = frame {
                    assert_eq!(frame.as_bytes(), &bytes[frame_start..offset]);
                    frame_start = offset;
                }
            }
            Err(_) => {
                poisoned(&mut decoder);
                return;
            }
        }
    }
    if decoder.finish().is_err() {
        poisoned(&mut decoder);
    } else {
        assert_eq!(frame_start, bytes.len());
    }
}

fuzz_target!(|bytes: &[u8]| {
    // Check identical bytes at both whole-stream and data-dependent boundaries.
    let chunk = 1 + usize::from(bytes.first().copied().unwrap_or(0));
    inspect::<RequestDecoder>(bytes, chunk);
    inspect::<ResponseDecoder>(bytes, chunk);
    inspect::<RequestDecoder>(bytes, bytes.len().max(1));
    inspect::<ResponseDecoder>(bytes, bytes.len().max(1));
});
