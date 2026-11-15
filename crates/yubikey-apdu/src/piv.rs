use crate::{ApduSpec as S, Length as L, Parameter as P, Value as V};
pub const AID: [u8; 11] = [0xa0, 0, 0, 3, 8, 0, 0, 0x10, 0, 1, 0];
pub const VERIFY: S = S::new(
    "VERIFY PIN",
    0,
    0x20,
    P::ZERO,
    P::fixed("PIN reference", 0x80),
    L::ANY,
    L::EMPTY,
);
pub const DEAUTHENTICATE: S = S::new(
    "deauthenticate PIN",
    0,
    0x20,
    P::fixed("deauthenticate", 0xff),
    P::fixed("PIN reference", 0x80),
    L::EMPTY,
    L::EMPTY,
);
pub const CHANGE_REFERENCE: S = S::new(
    "CHANGE REFERENCE DATA",
    0,
    0x24,
    P::ZERO,
    P::new("PIN/PUK reference", V::OneOf(&[0x80, 0x81])),
    L::ANY,
    L::EMPTY,
);
pub const RESET_RETRY: S = S::new(
    "RESET RETRY COUNTER",
    0,
    0x2c,
    P::ZERO,
    P::fixed("PIN reference", 0x80),
    L::ANY,
    L::EMPTY,
);
pub const GENERATE: S = S::new(
    "GENERATE ASYMMETRIC KEY PAIR",
    0,
    0x47,
    P::ZERO,
    P::new("key reference", V::Any),
    L::ANY,
    L::ANY,
);
pub const AUTHENTICATE: S = S::new(
    "GENERAL AUTHENTICATE",
    0,
    0x87,
    P::new("algorithm", V::Any),
    P::new("key reference", V::Any),
    L::ANY,
    L::ANY,
);
pub const GET_DATA: S = S::new(
    "GET DATA",
    0,
    0xcb,
    P::fixed("object selector", 0x3f),
    P::fixed("object selector", 0xff),
    L::ANY,
    L::ANY,
);
pub const PUT_DATA: S = S::new(
    "PUT DATA",
    0,
    0xdb,
    P::fixed("object selector", 0x3f),
    P::fixed("object selector", 0xff),
    L::ANY,
    L::EMPTY,
);
pub const MOVE_KEY: S = S::new(
    "MOVE/DELETE KEY",
    0,
    0xf6,
    P::new("destination or delete", V::Any),
    P::new("source key", V::Any),
    L::EMPTY,
    L::EMPTY,
);
pub const VERSION: S = S::new(
    "GET VERSION",
    0,
    0xfd,
    P::ZERO,
    P::ZERO,
    L::EMPTY,
    L::exact(3),
);
pub const SERIAL: S = S::new(
    "GET SERIAL",
    0,
    0xf8,
    P::ZERO,
    P::ZERO,
    L::EMPTY,
    L::exact(4),
);
pub const METADATA: S = S::new(
    "GET METADATA",
    0,
    0xf7,
    P::ZERO,
    P::new("reference", V::Any),
    L::EMPTY,
    L::ANY,
);
pub const ATTEST: S = S::new(
    "ATTEST",
    0,
    0xf9,
    P::new("key reference", V::Any),
    P::ZERO,
    L::EMPTY,
    L::ANY,
);
pub const IMPORT_KEY: S = S::new(
    "IMPORT KEY",
    0,
    0xfe,
    P::new("algorithm", V::Any),
    P::new("key reference", V::Any),
    L::ANY,
    L::EMPTY,
);
pub const SET_RETRIES: S = S::new(
    "SET RETRIES",
    0,
    0xfa,
    P::new("PIN retries", V::Any),
    P::new("PUK retries", V::Any),
    L::EMPTY,
    L::EMPTY,
);
pub const RESET: S = S::new("RESET", 0, 0xfb, P::ZERO, P::ZERO, L::EMPTY, L::EMPTY);
pub const SET_MANAGEMENT_KEY: S = S::new(
    "SET MANAGEMENT KEY",
    0,
    0xff,
    P::fixed("management key selector", 0xff),
    P::new("touch policy", V::Any),
    L::ANY,
    L::EMPTY,
);
pub const COMMANDS: &[S] = &[
    VERIFY,
    DEAUTHENTICATE,
    CHANGE_REFERENCE,
    RESET_RETRY,
    GENERATE,
    AUTHENTICATE,
    GET_DATA,
    PUT_DATA,
    MOVE_KEY,
    VERSION,
    SERIAL,
    METADATA,
    ATTEST,
    IMPORT_KEY,
    SET_RETRIES,
    RESET,
    SET_MANAGEMENT_KEY,
];
