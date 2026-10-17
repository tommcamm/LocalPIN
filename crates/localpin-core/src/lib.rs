//! Pure LocalPIN policy contracts. No host authentication or credential backend.
//!
//! Platform adapters are trusted boundaries: a simulated durable store, lifecycle
//! authority, or password worker is not evidence of a production implementation.

pub mod eligibility;
pub mod enrollment;
pub mod limits;
pub mod records;
pub mod secret;
pub mod throttle;
pub mod types;
