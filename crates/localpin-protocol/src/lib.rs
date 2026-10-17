//! Version-one LocalPIN IPC contracts, bounded parsing and Linux Unix transport.
//!
//! The Linux transport authenticates kernel peer credentials and protects socket
//! paths. The broker must separately establish live eligibility, obtain fresh OS
//! randomness and complete durable policy/storage work before sending success.

mod codec;
mod session;
mod wire;

#[cfg(target_os = "linux")]
pub mod transport;

pub use codec::{EncodedFrame, RequestDecoder, ResponseDecoder, encode_request, encode_response};
pub use session::*;
pub use wire::*;

#[cfg(test)]
mod tests;
