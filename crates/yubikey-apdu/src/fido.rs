use crate::{ApduSpec as S, Length as L, Parameter as P, Value as V};
pub const AID: [u8; 8] = [0xa0, 0, 0, 6, 0x47, 0x2f, 0, 1];
pub const KEEPALIVE_STATUS: u16 = 0x9100;
pub const MESSAGE: S = S::new(
    "NFCCTAP_MSG",
    0x80,
    0x10,
    P::new("keepalive polling support", V::OneOf(&[0, 0x80])),
    P::ZERO,
    L::range(1, 65535),
    L::ANY,
)
.with_protected_status(KEEPALIVE_STATUS);
pub const POLL: S = S::new(
    "NFCCTAP_GETRESPONSE",
    0x80,
    0x11,
    P::ZERO,
    P::ZERO,
    L::EMPTY,
    L::ANY,
)
.with_protected_status(KEEPALIVE_STATUS);
pub const U2F_REGISTER: S = S::new(
    "U2F REGISTER",
    0,
    1,
    P::new("registration mode", V::OneOf(&[0, 3])),
    P::ZERO,
    L::exact(64),
    L::ANY,
);
pub const U2F_AUTHENTICATE: S = S::new(
    "U2F AUTHENTICATE",
    0,
    2,
    P::new("presence mode", V::OneOf(&[3, 7, 8])),
    P::ZERO,
    L::range(65, 320),
    L::ANY,
);
pub const U2F_VERSION: S = S::new("U2F VERSION", 0, 3, P::ZERO, P::ZERO, L::EMPTY, L::exact(6));
pub const COMMANDS: &[S] = &[MESSAGE, POLL, U2F_REGISTER, U2F_AUTHENTICATE, U2F_VERSION];
