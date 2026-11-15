use crate::{ApduSpec as S, Length as L, Parameter as P, Value as V};
pub const AID: [u8; 8] = [0xa0, 0, 0, 5, 0x27, 0x21, 7, 1];
pub const PUT: S = S::new("PUT credential", 0, 1, P::ZERO, P::ZERO, L::ANY, L::EMPTY);
pub const DELETE: S = S::new(
    "DELETE credential",
    0,
    2,
    P::ZERO,
    P::ZERO,
    L::ANY,
    L::EMPTY,
);
pub const CALCULATE: S = S::new(
    "CALCULATE session keys",
    0,
    3,
    P::ZERO,
    P::ZERO,
    L::ANY,
    L::exact(48),
);
pub const CHALLENGE: S = S::new("GET CHALLENGE", 0, 4, P::ZERO, P::ZERO, L::ANY, L::ANY);
pub const LIST: S = S::new("LIST credentials", 0, 5, P::ZERO, P::ZERO, L::EMPTY, L::ANY);
pub const RESET: S = S::new(
    "RESET",
    0,
    6,
    P::fixed("reset selector", 0xde),
    P::fixed("reset selector", 0xad),
    L::EMPTY,
    L::EMPTY,
);
pub const VERSION: S = S::new("GET VERSION", 0, 7, P::ZERO, P::ZERO, L::EMPTY, L::exact(3));
pub const SET_MANAGEMENT_KEY: S = S::new(
    "PUT MANAGEMENT KEY",
    0,
    8,
    P::ZERO,
    P::ZERO,
    L::ANY,
    L::EMPTY,
);
pub const RETRIES: S = S::new(
    "GET MANAGEMENT KEY RETRIES",
    0,
    9,
    P::ZERO,
    P::ZERO,
    L::EMPTY,
    L::exact(1),
);
pub const PUBLIC_KEY: S = S::new(
    "GET PUBLIC KEY",
    0,
    0x0a,
    P::ZERO,
    P::ZERO,
    L::ANY,
    L::exact(65),
);
pub const CHANGE_PASSWORD: S = S::new(
    "CHANGE CREDENTIAL PASSWORD",
    0,
    0x0b,
    P::new("generation mode", V::Range(0, 1)),
    P::ZERO,
    L::ANY,
    L::ANY,
);
pub const COMMANDS: &[S] = &[
    PUT,
    DELETE,
    CALCULATE,
    CHALLENGE,
    LIST,
    RESET,
    VERSION,
    SET_MANAGEMENT_KEY,
    RETRIES,
    PUBLIC_KEY,
    CHANGE_PASSWORD,
];
