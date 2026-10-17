//! Pure version-one LocalPIN IPC contracts, bounded parsing and connection policy.
//!
//! This crate opens no sockets and grants no authority by itself. The broker must
//! authenticate kernel peer credentials, establish eligibility, obtain fresh OS
//! randomness and complete durable policy/storage work before sending success.

mod codec;
mod session;
mod wire;

pub use codec::{EncodedFrame, RequestDecoder, ResponseDecoder, encode_request, encode_response};
pub use session::*;
pub use wire::*;

#[cfg(test)]
mod tests;
