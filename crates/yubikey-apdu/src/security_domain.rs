use crate::{ApduSpec as S, Length as L, Parameter as P, Value as V};
pub const AID: [u8; 8] = [0xa0, 0, 0, 1, 0x51, 0, 0, 0];
pub const GET_DATA: S = S::new(
    "GET DATA (value)",
    0,
    0xca,
    P::new("object tag high byte", V::Any),
    P::new("object tag low byte", V::Any),
    L::ANY,
    L::ANY,
);
pub const GET_DATA_TLV: S = S::new(
    "GET DATA (TLV)",
    0x80,
    0xca,
    P::new("object tag high byte", V::Any),
    P::new("object tag low byte", V::Any),
    L::ANY,
    L::ANY,
);
pub const GENERATE: S = S::new(
    "GENERATE KEY",
    0x80,
    0xf1,
    P::new("replaced key version", V::Any),
    P::new("key identifier", V::Any),
    L::ANY,
    L::ANY,
);
pub const PUT_KEY: S = S::new(
    "PUT KEY",
    0x80,
    0xd8,
    P::new("replaced key version", V::Any),
    P::new("key identifier / multiple keys", V::Any),
    L::ANY,
    L::range(1, 10),
);
pub const STORE_DATA: S = S::new(
    "STORE DATA",
    0,
    0xe2,
    P::fixed("last block, BER-TLV", 0x90),
    P::ZERO,
    L::ANY,
    L::EMPTY,
);
pub const DELETE: S = S::new(
    "DELETE KEY",
    0x80,
    0xe4,
    P::ZERO,
    P::new("delete last key permission", V::Range(0, 1)),
    L::ANY,
    L::EMPTY,
);
pub const COMMANDS: &[S] = &[
    GET_DATA,
    GET_DATA_TLV,
    GENERATE,
    PUT_KEY,
    STORE_DATA,
    DELETE,
];
