use crate::{ApduSpec as S, Length as L, Parameter as P};
pub const SELECT: S = S::new(
    "SELECT application",
    0,
    0xa4,
    P::fixed("select by AID", 4),
    P::ZERO,
    L::range(1, 16),
    L::ANY,
);
pub const GET_RESPONSE: S = S::new("GET RESPONSE", 0, 0xc0, P::ZERO, P::ZERO, L::EMPTY, L::ANY);
pub const COMMANDS: &[S] = &[SELECT, GET_RESPONSE];
