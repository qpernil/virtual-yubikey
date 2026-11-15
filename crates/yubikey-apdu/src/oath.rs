use crate::{ApduSpec as S, Length as L, Parameter as P, Value as V};
pub const AID: [u8; 7] = [0xa0, 0, 0, 5, 0x27, 0x21, 1];
pub const SEND_REMAINING: S = S::new(
    "SEND REMAINING",
    0,
    0xa5,
    P::ZERO,
    P::ZERO,
    L::EMPTY,
    L::ANY,
);
pub const PUT: S = S::new("PUT", 0, 1, P::ZERO, P::ZERO, L::ANY, L::EMPTY).with_continuation(0xa5);
pub const DELETE: S =
    S::new("DELETE", 0, 2, P::ZERO, P::ZERO, L::ANY, L::EMPTY).with_continuation(0xa5);
pub const SET_CODE: S =
    S::new("SET CODE", 0, 3, P::ZERO, P::ZERO, L::ANY, L::EMPTY).with_continuation(0xa5);
pub const RESET: S = S::new(
    "RESET",
    0,
    4,
    P::fixed("reset selector", 0xde),
    P::fixed("reset selector", 0xad),
    L::EMPTY,
    L::EMPTY,
)
.with_continuation(0xa5);
pub const RENAME: S =
    S::new("RENAME", 0, 5, P::ZERO, P::ZERO, L::ANY, L::EMPTY).with_continuation(0xa5);
pub const LIST: S =
    S::new("LIST", 0, 0xa1, P::ZERO, P::ZERO, L::EMPTY, L::ANY).with_continuation(0xa5);
pub const CALCULATE: S = S::new(
    "CALCULATE",
    0,
    0xa2,
    P::ZERO,
    P::new("truncation mode", V::Range(0, 1)),
    L::ANY,
    L::ANY,
)
.with_continuation(0xa5);
pub const VALIDATE: S =
    S::new("VALIDATE", 0, 0xa3, P::ZERO, P::ZERO, L::ANY, L::ANY).with_continuation(0xa5);
pub const CALCULATE_ALL: S = S::new(
    "CALCULATE ALL",
    0,
    0xa4,
    P::ZERO,
    P::new("truncation mode", V::Range(0, 1)),
    L::ANY,
    L::ANY,
)
.with_continuation(0xa5);
pub const COMMANDS: &[S] = &[
    PUT,
    DELETE,
    SET_CODE,
    RESET,
    RENAME,
    LIST,
    CALCULATE,
    VALIDATE,
    CALCULATE_ALL,
    SEND_REMAINING,
];
