use crate::{ApduSpec as S, Length as L, Parameter as P, Value as V};
pub const AID: [u8; 6] = [0xd2, 0x76, 0, 1, 0x24, 1];
pub const VERIFY: S = S::new(
    "VERIFY",
    0,
    0x20,
    P::ZERO,
    P::new("password reference", V::Any),
    L::ANY,
    L::EMPTY,
);
pub const DEAUTHENTICATE: S = S::new(
    "deauthenticate password",
    0,
    0x20,
    P::fixed("deauthenticate", 0xff),
    P::new("password reference", V::Any),
    L::EMPTY,
    L::EMPTY,
);
pub const CHANGE_REFERENCE: S = S::new(
    "CHANGE REFERENCE DATA",
    0,
    0x24,
    P::ZERO,
    P::new("password reference", V::OneOf(&[0x81, 0x83])),
    L::ANY,
    L::EMPTY,
);
pub const RESET_RETRY: S = S::new(
    "RESET RETRY COUNTER",
    0,
    0x2c,
    P::new("reset mode", V::OneOf(&[0, 2])),
    P::fixed("PW1 reference", 0x81),
    L::ANY,
    L::EMPTY,
);
pub const GENERATE: S = S::new(
    "GENERATE ASYMMETRIC KEY PAIR",
    0,
    0x47,
    P::new("generate/read", V::OneOf(&[0x80, 0x81])),
    P::ZERO,
    L::ANY,
    L::ANY,
);
pub const SIGN: S = S::new(
    "PSO COMPUTE DIGITAL SIGNATURE",
    0,
    0x2a,
    P::fixed("signature result", 0x9e),
    P::fixed("signature input", 0x9a),
    L::ANY,
    L::ANY,
);
pub const DECIPHER: S = S::new(
    "PSO DECIPHER",
    0,
    0x2a,
    P::fixed("plaintext result", 0x80),
    P::fixed("ciphertext input", 0x86),
    L::ANY,
    L::ANY,
);
pub const ENCIPHER: S = S::new(
    "PSO ENCIPHER",
    0,
    0x2a,
    P::fixed("ciphertext result", 0x86),
    P::fixed("plaintext input", 0x80),
    L::ANY,
    L::ANY,
);
pub const AUTHENTICATE: S = S::new(
    "INTERNAL AUTHENTICATE",
    0,
    0x88,
    P::ZERO,
    P::ZERO,
    L::ANY,
    L::ANY,
);
pub const GET_DATA: S = S::new(
    "GET DATA",
    0,
    0xca,
    P::new("object tag high byte", V::Any),
    P::new("object tag low byte", V::Any),
    L::EMPTY,
    L::ANY,
);
pub const GET_DATA_ODD: S = S::new(
    "GET DATA ODD",
    0,
    0xcb,
    P::new("object selector", V::Any),
    P::new("object selector", V::Any),
    L::ANY,
    L::ANY,
);
pub const GET_NEXT_DATA: S = S::new(
    "GET NEXT DATA",
    0,
    0xcc,
    P::fixed("certificate tag", 0x7f),
    P::fixed("certificate tag", 0x21),
    L::EMPTY,
    L::ANY,
);
pub const SELECT_DATA: S = S::new(
    "SELECT DATA",
    0,
    0xa5,
    P::new("certificate occurrence", V::Range(0, 2)),
    P::fixed("selection control", 4),
    L::ANY,
    L::EMPTY,
);
pub const PUT_DATA: S = S::new(
    "PUT DATA",
    0,
    0xda,
    P::new("object tag high byte", V::Any),
    P::new("object tag low byte", V::Any),
    L::ANY,
    L::EMPTY,
);
pub const IMPORT_KEY: S = S::new(
    "PUT DATA ODD / IMPORT KEY",
    0,
    0xdb,
    P::fixed("key template selector", 0x3f),
    P::fixed("key template selector", 0xff),
    L::ANY,
    L::EMPTY,
);
pub const MANAGE_SECURITY_ENVIRONMENT: S = S::new(
    "MANAGE SECURITY ENVIRONMENT",
    0,
    0x22,
    P::fixed("set environment", 0x41),
    P::new("operation", V::OneOf(&[0xa4, 0xb8])),
    L::ANY,
    L::EMPTY,
);
pub const CHALLENGE: S = S::new("GET CHALLENGE", 0, 0x84, P::ZERO, P::ZERO, L::EMPTY, L::ANY);
pub const VERSION: S = S::new(
    "GET VERSION",
    0,
    0xf1,
    P::ZERO,
    P::ZERO,
    L::EMPTY,
    L::exact(3),
);
pub const TERMINATE: S = S::new(
    "TERMINATE DF",
    0,
    0xe6,
    P::ZERO,
    P::ZERO,
    L::EMPTY,
    L::EMPTY,
);
pub const ACTIVATE: S = S::new(
    "ACTIVATE FILE",
    0,
    0x44,
    P::ZERO,
    P::ZERO,
    L::EMPTY,
    L::EMPTY,
);
pub const SET_PIN_RETRIES: S = S::new(
    "SET PIN RETRIES",
    0,
    0xf2,
    P::ZERO,
    P::ZERO,
    L::ANY,
    L::EMPTY,
);
pub const ATTEST: S = S::new(
    "GET ATTESTATION",
    0x80,
    0xfb,
    P::new("key reference", V::Any),
    P::ZERO,
    L::EMPTY,
    L::ANY,
);
pub const COMMANDS: &[S] = &[
    VERIFY,
    DEAUTHENTICATE,
    CHANGE_REFERENCE,
    RESET_RETRY,
    GENERATE,
    SIGN,
    DECIPHER,
    ENCIPHER,
    AUTHENTICATE,
    GET_DATA,
    GET_DATA_ODD,
    GET_NEXT_DATA,
    SELECT_DATA,
    PUT_DATA,
    IMPORT_KEY,
    MANAGE_SECURITY_ENVIRONMENT,
    CHALLENGE,
    VERSION,
    TERMINATE,
    ACTIVATE,
    SET_PIN_RETRIES,
    ATTEST,
];
