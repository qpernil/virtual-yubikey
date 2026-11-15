use crate::{ApduSpec as S, Length as L, Parameter as P, Value as V};
pub const AID: [u8; 8] = [0xa0, 0, 0, 5, 0x27, 0x47, 0x11, 0x17];
pub const READ_INFO: S = S::new(
    "READ DEVICE INFO",
    0,
    0x1d,
    P::new("page", V::Any),
    P::ZERO,
    L::EMPTY,
    L::ANY,
);
pub const WRITE_CONFIG: S = S::new("WRITE CONFIG", 0, 0x1c, P::ZERO, P::ZERO, L::ANY, L::EMPTY);
pub const COMMANDS: &[S] = &[READ_INFO, WRITE_CONFIG];
