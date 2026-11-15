use crate::{ApduSpec as S, Length as L, Parameter as P, Value as V};
pub const INITIALIZE_UPDATE: S = S::new(
    "SCP03 INITIALIZE UPDATE",
    0x80,
    0x50,
    P::new("key version", V::Any),
    P::new("key identifier", V::Any),
    L::exact(8),
    L::ANY,
);
pub const EXTERNAL_AUTHENTICATE: S = S::new(
    "SCP03 EXTERNAL AUTHENTICATE",
    0x84,
    0x82,
    P::new("security level", V::Any),
    P::ZERO,
    L::exact(16),
    L::EMPTY,
);
pub const INTERNAL_AUTHENTICATE: S = S::new(
    "SCP11b INTERNAL AUTHENTICATE",
    0x80,
    0x88,
    P::new("key version", V::Any),
    P::fixed("SCP11b key identifier", 0x13),
    L::ANY,
    L::ANY,
);
pub const SCP11_AUTHENTICATE: S = S::new(
    "SCP11a/c EXTERNAL AUTHENTICATE",
    0x80,
    0x82,
    P::new("key version", V::Any),
    P::new("SCP11 key identifier", V::OneOf(&[0x11, 0x15])),
    L::ANY,
    L::ANY,
);
pub const UPLOAD_CERTIFICATE: S = S::new(
    "SCP11 PSO certificate upload",
    0x80,
    0x2a,
    P::new("host CA key version", V::Any),
    P::new("host CA key identifier / more certificates", V::Any),
    L::ANY,
    L::EMPTY,
);
pub const COMMANDS: &[S] = &[
    INITIALIZE_UPDATE,
    EXTERNAL_AUTHENTICATE,
    INTERNAL_AUTHENTICATE,
    SCP11_AUTHENTICATE,
    UPLOAD_CERTIFICATE,
];
