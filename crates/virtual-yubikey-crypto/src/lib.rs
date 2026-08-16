//! Protocol-neutral software signing and verification.
//!
//! Protocol layers retain responsibility for identifiers, public-key
//! containers, signature encodings, policy, persistence, and error mapping.

pub mod post_quantum;
pub mod rsa_signing;
pub mod software_signing;
