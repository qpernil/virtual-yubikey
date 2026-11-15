//! Wire framing is independent of applet command semantics.
//! Each applet owns its request/response envelope definitions in its own module.
//! TLV contents, authorization and state transitions belong to the implementations.
mod spec;
mod wire;
pub use spec::{ApduSpec, Length, Parameter, SpecError, Value, find};
pub use wire::{ApduError, CommandApdu, ResponseApdu};
pub mod fido;
pub mod hsmauth;
pub mod iso7816;
pub mod management;
pub mod oath;
pub mod openpgp;
pub mod piv;
pub mod scp;
pub mod security_domain;
#[cfg(test)]
mod tests;
