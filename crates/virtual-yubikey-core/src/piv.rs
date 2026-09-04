use crate::{
    CommandApdu, PIV_TOUCH_CACHE_DURATION, PresenceAuthorization, ResponseApdu, UserPresencePolicy,
    crypto::{AES_BLOCK_SIZE, Direction, TDES_BLOCK_SIZE, aes_ecb_block, tdes_ecb_block},
    presence::PresenceClient,
};
use software_key_core::{
    software_key_agreement::{MontgomeryCurve, SoftwareMontgomeryKey, derive_with_signing_key},
    software_private_key::SoftwarePrivateKey,
    software_signing::{
        EcCurve, EdwardsCurve, KeyKind, SignatureScheme, SoftwarePublicKey, SoftwareSigningKey,
    },
};
use std::{collections::BTreeMap, fmt};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

pub const PIV_AID: [u8; 11] = [
    0xa0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10, 0x00, 0x01, 0x00,
];

const PIV_SELECT_RESPONSE: [u8; 19] = [
    0x61, 0x11, 0x4f, 0x06, 0x00, 0x00, 0x10, 0x00, 0x01, 0x00, 0x79, 0x07, 0x4f, 0x05, 0xa0, 0x00,
    0x00, 0x03, 0x08,
];
const DISCOVERY_OBJECT: [u8; 20] = [
    0x7e, 0x12, 0x4f, 0x0b, 0xa0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10, 0x00, 0x01, 0x00, 0x5f,
    0x2f, 0x02, 0x40, 0x00,
];

const INS_VERIFY: u8 = 0x20;
const INS_CHANGE_REFERENCE: u8 = 0x24;
const INS_RESET_RETRY: u8 = 0x2c;
const INS_GENERATE_ASYMMETRIC: u8 = 0x47;
const INS_AUTHENTICATE: u8 = 0x87;
const INS_GET_DATA: u8 = 0xcb;
const INS_PUT_DATA: u8 = 0xdb;
const INS_MOVE_KEY: u8 = 0xf6;
const INS_GET_VERSION: u8 = 0xfd;
const INS_GET_SERIAL: u8 = 0xf8;
const INS_GET_METADATA: u8 = 0xf7;
const INS_IMPORT_KEY: u8 = 0xfe;
const INS_SET_RETRIES: u8 = 0xfa;
const INS_RESET: u8 = 0xfb;
const INS_SET_MANAGEMENT_KEY: u8 = 0xff;

const REFERENCE_PIN: u8 = 0x80;
const REFERENCE_PUK: u8 = 0x81;
const REFERENCE_MANAGEMENT_KEY: u8 = 0x9b;
const ALGORITHM_PIN_OR_PUK: u8 = 0xff;
const FACTORY_RETRIES: u8 = 3;
const FACTORY_PIN: [u8; 8] = [b'1', b'2', b'3', b'4', b'5', b'6', 0xff, 0xff];
const FACTORY_PUK: [u8; 8] = *b"12345678";
const FACTORY_MANAGEMENT_KEY: [u8; 24] = [
    1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8,
];

const STATUS_WRONG_LENGTH: u16 = 0x6700;
const STATUS_SECURITY_NOT_SATISFIED: u16 = 0x6982;
const STATUS_AUTHENTICATION_BLOCKED: u16 = 0x6983;
const STATUS_CONDITIONS_NOT_SATISFIED: u16 = 0x6985;
const STATUS_INCORRECT_DATA: u16 = 0x6a80;
const STATUS_NOT_FOUND: u16 = 0x6a82;
const STATUS_INCORRECT_PARAMETERS: u16 = 0x6a86;
const STATUS_REFERENCE_NOT_FOUND: u16 = 0x6a88;
const STATUS_INSTRUCTION_NOT_SUPPORTED: u16 = 0x6d00;
const STATUS_CLASS_NOT_SUPPORTED: u16 = 0x6e00;
const STATUS_INTERNAL_ERROR: u16 = 0x6f00;
const ORIGIN_GENERATED: u8 = 1;
const ORIGIN_IMPORTED: u8 = 2;
const PIN_POLICY_NEVER: u8 = 1;
const PIN_POLICY_ONCE: u8 = 2;
const PIN_POLICY_ALWAYS: u8 = 3;
const TOUCH_POLICY_NEVER: u8 = 1;
const TOUCH_POLICY_ALWAYS: u8 = 2;
const TOUCH_POLICY_CACHED: u8 = 3;

pub(crate) enum PivExchange {
    Complete(ResponseApdu),
    PresenceRequired(UserPresencePolicy),
}

impl From<ResponseApdu> for PivExchange {
    fn from(response: ResponseApdu) -> Self {
        Self::Complete(response)
    }
}

pub(crate) fn select_response() -> Vec<u8> {
    PIV_SELECT_RESPONSE.to_vec()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
enum ManagementAlgorithm {
    TripleDes = 0x03,
    Aes128 = 0x08,
    Aes192 = 0x0a,
    Aes256 = 0x0c,
}

impl ManagementAlgorithm {
    fn from_id(id: u8) -> Option<Self> {
        match id {
            0x03 => Some(Self::TripleDes),
            0x08 => Some(Self::Aes128),
            0x0a => Some(Self::Aes192),
            0x0c => Some(Self::Aes256),
            _ => None,
        }
    }

    const fn key_length(self) -> usize {
        match self {
            Self::TripleDes | Self::Aes192 => 24,
            Self::Aes128 => 16,
            Self::Aes256 => 32,
        }
    }

    const fn block_size(self) -> usize {
        match self {
            Self::TripleDes => TDES_BLOCK_SIZE,
            Self::Aes128 | Self::Aes192 | Self::Aes256 => AES_BLOCK_SIZE,
        }
    }

    fn crypt_block(self, key: &[u8], block: &[u8], direction: Direction) -> Result<Vec<u8>, ()> {
        match self {
            Self::TripleDes => tdes_ecb_block(key, block, direction),
            Self::Aes128 | Self::Aes192 | Self::Aes256 => aes_ecb_block(key, block, direction),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
enum PivAlgorithm {
    Rsa3072 = 0x05,
    Rsa1024 = 0x06,
    Rsa2048 = 0x07,
    EccP256 = 0x11,
    EccP384 = 0x14,
    Rsa4096 = 0x16,
    Ed25519 = 0xe0,
    X25519 = 0xe1,
}

impl PivAlgorithm {
    fn from_id(id: u8) -> Option<Self> {
        match id {
            0x05 => Some(Self::Rsa3072),
            0x06 => Some(Self::Rsa1024),
            0x07 => Some(Self::Rsa2048),
            0x11 => Some(Self::EccP256),
            0x14 => Some(Self::EccP384),
            0x16 => Some(Self::Rsa4096),
            0xe0 => Some(Self::Ed25519),
            0xe1 => Some(Self::X25519),
            _ => None,
        }
    }

    const fn signing_algorithm(self) -> Option<SignatureScheme> {
        match self {
            Self::Rsa1024 | Self::Rsa2048 | Self::Rsa3072 | Self::Rsa4096 => {
                Some(SignatureScheme::RsaPkcs1Sha256)
            }
            Self::EccP256 => Some(SignatureScheme::EcdsaP256Sha256),
            Self::EccP384 => Some(SignatureScheme::EcdsaP384Sha384),
            Self::Ed25519 => Some(SignatureScheme::Ed25519),
            Self::X25519 => None,
        }
    }

    const fn key_kind(self) -> Option<KeyKind> {
        match self {
            Self::Rsa1024 => Some(KeyKind::Rsa { modulus_bits: 1024 }),
            Self::Rsa2048 => Some(KeyKind::Rsa { modulus_bits: 2048 }),
            Self::Rsa3072 => Some(KeyKind::Rsa { modulus_bits: 3072 }),
            Self::Rsa4096 => Some(KeyKind::Rsa { modulus_bits: 4096 }),
            Self::EccP256 => Some(KeyKind::Ec(EcCurve::P256)),
            Self::EccP384 => Some(KeyKind::Ec(EcCurve::P384)),
            Self::Ed25519 => Some(KeyKind::Edwards(EdwardsCurve::Ed25519)),
            Self::X25519 => None,
        }
    }

    const fn curve(self) -> Option<EcCurve> {
        match self {
            Self::Rsa1024 | Self::Rsa2048 | Self::Rsa3072 | Self::Rsa4096 => None,
            Self::EccP256 => Some(EcCurve::P256),
            Self::EccP384 => Some(EcCurve::P384),
            Self::Ed25519 | Self::X25519 => None,
        }
    }

    const fn rsa_bits(self) -> Option<usize> {
        match self {
            Self::Rsa1024 => Some(1_024),
            Self::Rsa2048 => Some(2_048),
            Self::Rsa3072 => Some(3_072),
            Self::Rsa4096 => Some(4_096),
            Self::EccP256 | Self::EccP384 | Self::Ed25519 | Self::X25519 => None,
        }
    }

    const fn input_length(self) -> usize {
        match self {
            Self::Rsa1024 => 128,
            Self::Rsa2048 => 256,
            Self::Rsa3072 => 384,
            Self::Rsa4096 => 512,
            Self::EccP256 => 32,
            Self::EccP384 => 48,
            Self::Ed25519 | Self::X25519 => 32,
        }
    }

    const fn import_tag(self) -> Option<u32> {
        match self {
            Self::Rsa1024 | Self::Rsa2048 | Self::Rsa3072 | Self::Rsa4096 => None,
            Self::EccP256 | Self::EccP384 => Some(0x06),
            Self::Ed25519 => Some(0x07),
            Self::X25519 => Some(0x08),
        }
    }
}

fn generate_private_key(algorithm: PivAlgorithm) -> Result<SoftwarePrivateKey, ()> {
    if let Some(key_kind) = algorithm.key_kind() {
        SoftwareSigningKey::generate_for_kind(key_kind)
            .map(SoftwarePrivateKey::Signing)
            .map_err(|_| ())
    } else if algorithm == PivAlgorithm::X25519 {
        SoftwareMontgomeryKey::generate(MontgomeryCurve::X25519)
            .map(SoftwarePrivateKey::Montgomery)
            .map_err(|_| ())
    } else {
        Err(())
    }
}

fn private_key_from_serialized(
    algorithm: PivAlgorithm,
    serialized: &[u8],
) -> Result<SoftwarePrivateKey, ()> {
    if let Some(key_kind) = algorithm.key_kind() {
        SoftwareSigningKey::from_serialized_for_kind(key_kind, serialized)
            .map(SoftwarePrivateKey::Signing)
            .map_err(|_| ())
    } else if algorithm == PivAlgorithm::X25519 {
        SoftwareMontgomeryKey::from_serialized(MontgomeryCurve::X25519, serialized)
            .map(SoftwarePrivateKey::Montgomery)
            .map_err(|_| ())
    } else {
        Err(())
    }
}

fn serialized_private_key(key: &SoftwarePrivateKey) -> Result<Zeroizing<Vec<u8>>, ()> {
    match key {
        SoftwarePrivateKey::Signing(key) => key.serialized().map_err(|_| ()),
        SoftwarePrivateKey::Montgomery(key) => Ok(key.serialized()),
        SoftwarePrivateKey::MlKem(_) => Err(()),
    }
}

#[derive(Clone)]
struct PivKey {
    algorithm: PivAlgorithm,
    pin_policy: u8,
    touch_policy: u8,
    origin: u8,
    private_key: SoftwarePrivateKey,
}

impl fmt::Debug for PivKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PivKey")
            .field("algorithm", &self.algorithm)
            .field("pin_policy", &self.pin_policy)
            .field("touch_policy", &self.touch_policy)
            .field("origin", &self.origin)
            .finish_non_exhaustive()
    }
}

impl PivKey {
    fn public_template(&self) -> Result<Vec<u8>, ()> {
        match &self.private_key {
            SoftwarePrivateKey::Signing(key) => match key.public_key() {
                SoftwarePublicKey::Ec {
                    curve,
                    uncompressed,
                } if Some(curve) == self.algorithm.curve() => Ok(encode_tlv(0x86, &uncompressed)),
                SoftwarePublicKey::Edwards {
                    curve: EdwardsCurve::Ed25519,
                    public_key,
                } if self.algorithm == PivAlgorithm::Ed25519 => Ok(encode_tlv(0x86, &public_key)),
                SoftwarePublicKey::Rsa { modulus, exponent }
                    if self.algorithm.rsa_bits() == Some(modulus.len() * 8) =>
                {
                    Ok([encode_tlv(0x81, &modulus), encode_tlv(0x82, &exponent)].concat())
                }
                _ => Err(()),
            },
            SoftwarePrivateKey::Montgomery(key)
                if self.algorithm == PivAlgorithm::X25519
                    && key.curve() == MontgomeryCurve::X25519 =>
            {
                Ok(encode_tlv(0x86, &key.public_key()))
            }
            SoftwarePrivateKey::Montgomery(_) | SoftwarePrivateKey::MlKem(_) => Err(()),
        }
    }
}

struct PinReference {
    value: Zeroizing<[u8; 8]>,
    retries: u8,
    maximum_retries: u8,
}

impl PinReference {
    fn new(value: [u8; 8]) -> Self {
        Self {
            value: Zeroizing::new(value),
            retries: FACTORY_RETRIES,
            maximum_retries: FACTORY_RETRIES,
        }
    }

    fn retry_status(&self) -> u16 {
        if self.retries == 0 {
            STATUS_AUTHENTICATION_BLOCKED
        } else {
            0x63c0 | u16::from(self.retries.min(15))
        }
    }

    fn verify(&mut self, supplied: &[u8]) -> Result<(), u16> {
        if self.retries == 0 {
            return Err(STATUS_AUTHENTICATION_BLOCKED);
        }
        if supplied.len() != self.value.len() {
            return Err(STATUS_WRONG_LENGTH);
        }
        if bool::from(self.value.as_slice().ct_eq(supplied)) {
            self.retries = self.maximum_retries;
            Ok(())
        } else {
            self.retries = self.retries.saturating_sub(1);
            Err(self.retry_status())
        }
    }

    fn replace(&mut self, value: [u8; 8]) {
        self.value.zeroize();
        self.value = Zeroizing::new(value);
        self.retries = self.maximum_retries;
    }
}

pub(crate) struct PivApplet {
    serial: u32,
    firmware: [u8; 3],
    pin: PinReference,
    puk: PinReference,
    pin_verified: bool,
    management_algorithm: ManagementAlgorithm,
    management_key: Zeroizing<Vec<u8>>,
    management_touch_policy: u8,
    management_challenge: Option<Zeroizing<Vec<u8>>>,
    management_authenticated: bool,
    presence: PresenceClient,
    objects: BTreeMap<u32, Vec<u8>>,
    keys: BTreeMap<u8, PivKey>,
    persistent_change: bool,
}

impl fmt::Debug for PivApplet {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PivApplet")
            .field("serial", &self.serial)
            .field("firmware", &self.firmware)
            .field("pin_retries", &self.pin.retries)
            .field("puk_retries", &self.puk.retries)
            .field("pin_verified", &self.pin_verified)
            .field("management_algorithm", &self.management_algorithm)
            .field("management_touch_policy", &self.management_touch_policy)
            .field("management_authenticated", &self.management_authenticated)
            .field("object_count", &self.objects.len())
            .field("key_count", &self.keys.len())
            .field("persistent_change", &self.persistent_change)
            .finish_non_exhaustive()
    }
}

impl PivApplet {
    pub(crate) fn new(serial: u32, firmware: [u8; 3]) -> Self {
        Self {
            serial,
            firmware,
            pin: PinReference::new(FACTORY_PIN),
            puk: PinReference::new(FACTORY_PUK),
            pin_verified: false,
            management_algorithm: ManagementAlgorithm::Aes192,
            management_key: Zeroizing::new(FACTORY_MANAGEMENT_KEY.to_vec()),
            management_touch_policy: TOUCH_POLICY_NEVER,
            management_challenge: None,
            management_authenticated: false,
            presence: PresenceClient::default(),
            objects: BTreeMap::new(),
            keys: BTreeMap::new(),
            persistent_change: false,
        }
    }

    pub(crate) fn reset_connection(&mut self) {
        self.pin_verified = false;
        self.management_authenticated = false;
        self.management_challenge = None;
    }

    pub(crate) fn from_persistent_state(
        serial: u32,
        firmware: [u8; 3],
        encoded: &[u8],
    ) -> Result<Self, &'static str> {
        let mut decoder = minicbor::Decoder::new(encoded);
        let fields = decoder
            .map()
            .map_err(|_| "persistent PIV state is not a CBOR map")?
            .ok_or("indefinite persistent PIV state is unsupported")?;
        let mut version = None;
        let mut stored_serial = None;
        let mut pin = None;
        let mut pin_retries = None;
        let mut pin_maximum = None;
        let mut puk = None;
        let mut puk_retries = None;
        let mut puk_maximum = None;
        let mut management_algorithm = None;
        let mut management_key = None;
        let mut management_touch_policy = None;
        let mut objects = None;
        let mut keys = None;
        for _ in 0..fields {
            match decoder
                .u8()
                .map_err(|_| "persistent PIV state has an invalid field")?
            {
                1 if version.is_none() => {
                    version = Some(
                        decoder
                            .u8()
                            .map_err(|_| "persistent PIV state has an invalid version")?,
                    );
                }
                2 if stored_serial.is_none() => {
                    stored_serial = Some(
                        decoder
                            .u32()
                            .map_err(|_| "persistent PIV state has an invalid serial")?,
                    );
                }
                3 if pin.is_none() => {
                    pin = Some(decode_persistent_pin(&mut decoder, "PIN")?);
                }
                4 if pin_retries.is_none() => {
                    pin_retries = Some(
                        decoder
                            .u8()
                            .map_err(|_| "persistent PIV state has invalid PIN retries")?,
                    );
                }
                5 if pin_maximum.is_none() => {
                    pin_maximum = Some(
                        decoder
                            .u8()
                            .map_err(|_| "persistent PIV state has invalid PIN retry maximum")?,
                    );
                }
                6 if puk.is_none() => {
                    puk = Some(decode_persistent_pin(&mut decoder, "PUK")?);
                }
                7 if puk_retries.is_none() => {
                    puk_retries = Some(
                        decoder
                            .u8()
                            .map_err(|_| "persistent PIV state has invalid PUK retries")?,
                    );
                }
                8 if puk_maximum.is_none() => {
                    puk_maximum = Some(
                        decoder
                            .u8()
                            .map_err(|_| "persistent PIV state has invalid PUK retry maximum")?,
                    );
                }
                9 if management_algorithm.is_none() => {
                    management_algorithm =
                        Some(decoder.u8().map_err(
                            |_| "persistent PIV state has an invalid management algorithm",
                        )?);
                }
                10 if management_key.is_none() => {
                    management_key = Some(Zeroizing::new(
                        decoder
                            .bytes()
                            .map_err(|_| "persistent PIV state has an invalid management key")?
                            .to_vec(),
                    ));
                }
                11 if objects.is_none() => {
                    objects = Some(decode_persistent_objects(&mut decoder)?);
                }
                12 if keys.is_none() => {
                    keys = Some(decode_persistent_keys(&mut decoder)?);
                }
                13 if management_touch_policy.is_none() => {
                    management_touch_policy =
                        Some(decoder.u8().map_err(
                            |_| "persistent PIV state has invalid management touch policy",
                        )?);
                }
                _ => decoder
                    .skip()
                    .map_err(|_| "persistent PIV state contains invalid data")?,
            }
        }
        if decoder.position() != encoded.len() {
            return Err("persistent PIV state has trailing data");
        }
        if version != Some(3) {
            return Err("unsupported persistent PIV state version");
        }
        if stored_serial != Some(serial) {
            return Err("persistent PIV state belongs to another device serial");
        }
        let pin_maximum = pin_maximum.ok_or("persistent PIV state has no PIN retry maximum")?;
        let pin_retries = pin_retries.ok_or("persistent PIV state has no PIN retries")?;
        let puk_maximum = puk_maximum.ok_or("persistent PIV state has no PUK retry maximum")?;
        let puk_retries = puk_retries.ok_or("persistent PIV state has no PUK retries")?;
        if pin_maximum == 0
            || pin_maximum > 15
            || pin_retries > pin_maximum
            || puk_maximum == 0
            || puk_maximum > 15
            || puk_retries > puk_maximum
        {
            return Err("persistent PIV state has invalid retry counters");
        }
        let management_algorithm = ManagementAlgorithm::from_id(
            management_algorithm.ok_or("persistent PIV state has no management algorithm")?,
        )
        .ok_or("persistent PIV state management algorithm is unsupported")?;
        let management_key = management_key.ok_or("persistent PIV state has no management key")?;
        if management_key.len() != management_algorithm.key_length() {
            return Err("persistent PIV state management key has the wrong length");
        }
        let management_touch_policy = management_touch_policy
            .filter(|policy| valid_management_touch_policy(*policy))
            .ok_or("persistent PIV state has no valid management touch policy")?;
        Ok(Self {
            serial,
            firmware,
            pin: PinReference {
                value: Zeroizing::new(pin.ok_or("persistent PIV state has no PIN")?),
                retries: pin_retries,
                maximum_retries: pin_maximum,
            },
            puk: PinReference {
                value: Zeroizing::new(puk.ok_or("persistent PIV state has no PUK")?),
                retries: puk_retries,
                maximum_retries: puk_maximum,
            },
            pin_verified: false,
            management_algorithm,
            management_key,
            management_touch_policy,
            management_challenge: None,
            management_authenticated: false,
            presence: PresenceClient::default(),
            objects: objects.ok_or("persistent PIV state has no object store")?,
            keys: keys.ok_or("persistent PIV state has no key store")?,
            persistent_change: false,
        })
    }

    pub(crate) fn persistent_state(&self) -> Result<Vec<u8>, &'static str> {
        let mut encoder = minicbor::Encoder::new(Vec::new());
        encoder
            .map(13)
            .map_err(|_| "cannot encode persistent PIV state")?
            .u8(1)
            .map_err(|_| "cannot encode persistent PIV state")?
            .u8(3)
            .map_err(|_| "cannot encode persistent PIV state")?
            .u8(2)
            .map_err(|_| "cannot encode persistent PIV state")?
            .u32(self.serial)
            .map_err(|_| "cannot encode persistent PIV state")?
            .u8(3)
            .map_err(|_| "cannot encode persistent PIV state")?
            .bytes(self.pin.value.as_slice())
            .map_err(|_| "cannot encode persistent PIV state")?
            .u8(4)
            .map_err(|_| "cannot encode persistent PIV state")?
            .u8(self.pin.retries)
            .map_err(|_| "cannot encode persistent PIV state")?
            .u8(5)
            .map_err(|_| "cannot encode persistent PIV state")?
            .u8(self.pin.maximum_retries)
            .map_err(|_| "cannot encode persistent PIV state")?
            .u8(6)
            .map_err(|_| "cannot encode persistent PIV state")?
            .bytes(self.puk.value.as_slice())
            .map_err(|_| "cannot encode persistent PIV state")?
            .u8(7)
            .map_err(|_| "cannot encode persistent PIV state")?
            .u8(self.puk.retries)
            .map_err(|_| "cannot encode persistent PIV state")?
            .u8(8)
            .map_err(|_| "cannot encode persistent PIV state")?
            .u8(self.puk.maximum_retries)
            .map_err(|_| "cannot encode persistent PIV state")?
            .u8(9)
            .map_err(|_| "cannot encode persistent PIV state")?
            .u8(self.management_algorithm as u8)
            .map_err(|_| "cannot encode persistent PIV state")?
            .u8(10)
            .map_err(|_| "cannot encode persistent PIV state")?
            .bytes(&self.management_key)
            .map_err(|_| "cannot encode persistent PIV state")?
            .u8(11)
            .map_err(|_| "cannot encode persistent PIV state")?
            .array(
                u64::try_from(self.objects.len()).map_err(|_| "too many PIV objects to persist")?,
            )
            .map_err(|_| "cannot encode persistent PIV state")?;
        for (object_id, value) in &self.objects {
            encoder
                .array(2)
                .map_err(|_| "cannot encode persistent PIV object")?
                .u32(*object_id)
                .map_err(|_| "cannot encode persistent PIV object")?
                .bytes(value)
                .map_err(|_| "cannot encode persistent PIV object")?;
        }
        encoder
            .u8(12)
            .map_err(|_| "cannot encode persistent PIV state")?
            .array(u64::try_from(self.keys.len()).map_err(|_| "too many PIV keys to persist")?)
            .map_err(|_| "cannot encode persistent PIV state")?;
        for (slot, key) in &self.keys {
            let private_key = serialized_private_key(&key.private_key)
                .map_err(|_| "cannot serialize persistent PIV key")?;
            encoder
                .array(6)
                .map_err(|_| "cannot encode persistent PIV key")?
                .u8(*slot)
                .map_err(|_| "cannot encode persistent PIV key")?
                .u8(key.algorithm as u8)
                .map_err(|_| "cannot encode persistent PIV key")?
                .u8(key.pin_policy)
                .map_err(|_| "cannot encode persistent PIV key")?
                .u8(key.touch_policy)
                .map_err(|_| "cannot encode persistent PIV key")?
                .u8(key.origin)
                .map_err(|_| "cannot encode persistent PIV key")?
                .bytes(&private_key)
                .map_err(|_| "cannot encode persistent PIV key")?;
        }
        encoder
            .u8(13)
            .map_err(|_| "cannot encode persistent PIV state")?
            .u8(self.management_touch_policy)
            .map_err(|_| "cannot encode persistent PIV state")?;
        Ok(encoder.into_writer())
    }

    pub(crate) fn take_persistent_change(&mut self) -> bool {
        std::mem::take(&mut self.persistent_change)
    }

    #[cfg(test)]
    pub(crate) fn transmit(&mut self, command: &CommandApdu<'_>) -> ResponseApdu {
        match self.exchange(command, PresenceAuthorization::Absent) {
            PivExchange::Complete(response) => response,
            PivExchange::PresenceRequired(_) => {
                ResponseApdu::status(STATUS_CONDITIONS_NOT_SATISFIED)
            }
        }
    }

    pub(crate) fn exchange(
        &mut self,
        command: &CommandApdu<'_>,
        presence: PresenceAuthorization,
    ) -> PivExchange {
        if command.cla != 0 {
            return ResponseApdu::status(STATUS_CLASS_NOT_SUPPORTED).into();
        }
        let response = match command.ins {
            INS_GET_VERSION if empty_command(command, 0, 0) => {
                ResponseApdu::success(self.firmware.to_vec())
            }
            INS_GET_SERIAL if empty_command(command, 0, 0) => {
                ResponseApdu::success(self.serial.to_be_bytes().to_vec())
            }
            INS_GET_METADATA if command.p1 == 0 && command.data.is_empty() => {
                self.get_metadata(command.p2)
            }
            INS_GENERATE_ASYMMETRIC if command.p1 == 0 => {
                self.generate_asymmetric(command.p2, command.data)
            }
            INS_GET_DATA if command.p1 == 0x3f && command.p2 == 0xff => self.get_data(command.data),
            INS_PUT_DATA if command.p1 == 0x3f && command.p2 == 0xff => self.put_data(command.data),
            INS_MOVE_KEY if command.data.is_empty() => self.move_or_delete_key(command),
            INS_VERIFY if command.p1 == 0 && command.p2 == REFERENCE_PIN => {
                self.verify_pin(command.data)
            }
            INS_VERIFY
                if command.p1 == 0xff && command.p2 == REFERENCE_PIN && command.data.is_empty() =>
            {
                self.pin_verified = false;
                ResponseApdu::success(Vec::new())
            }
            INS_CHANGE_REFERENCE if command.p1 == 0 => {
                self.change_reference(command.p2, command.data)
            }
            INS_RESET_RETRY if command.p1 == 0 && command.p2 == REFERENCE_PIN => {
                self.reset_retry(command.data)
            }
            INS_AUTHENTICATE if command.p2 == REFERENCE_MANAGEMENT_KEY => {
                return self.authenticate_management(command, presence);
            }
            INS_AUTHENTICATE => return self.general_authenticate(command, presence),
            INS_IMPORT_KEY => self.import_key(command),
            INS_SET_RETRIES if command.data.is_empty() => self.set_retries(command.p1, command.p2),
            INS_RESET if empty_command(command, 0, 0) => self.reset(),
            INS_SET_MANAGEMENT_KEY => self.set_management_key(command),
            INS_GET_VERSION
            | INS_GET_SERIAL
            | INS_GET_METADATA
            | INS_GENERATE_ASYMMETRIC
            | INS_GET_DATA
            | INS_PUT_DATA
            | INS_MOVE_KEY
            | INS_VERIFY
            | INS_CHANGE_REFERENCE
            | INS_RESET_RETRY
            | INS_SET_RETRIES
            | INS_RESET => ResponseApdu::status(STATUS_INCORRECT_PARAMETERS),
            _ => ResponseApdu::status(STATUS_INSTRUCTION_NOT_SUPPORTED),
        };
        response.into()
    }

    fn get_metadata(&self, reference: u8) -> ResponseApdu {
        let mut data = Vec::new();
        match reference {
            REFERENCE_PIN => self.push_reference_metadata(&mut data, &self.pin),
            REFERENCE_PUK => self.push_reference_metadata(&mut data, &self.puk),
            REFERENCE_MANAGEMENT_KEY => {
                push_tlv(&mut data, 0x01, &[self.management_algorithm as u8]);
                push_tlv(&mut data, 0x02, &[0, self.management_touch_policy]);
                let is_default = self.management_algorithm == ManagementAlgorithm::Aes192
                    && self.management_key.as_slice() == FACTORY_MANAGEMENT_KEY;
                push_tlv(&mut data, 0x05, &[u8::from(is_default)]);
            }
            slot if valid_key_slot(slot) => {
                let Some(key) = self.keys.get(&slot) else {
                    return ResponseApdu::status(STATUS_REFERENCE_NOT_FOUND);
                };
                push_tlv(&mut data, 0x01, &[key.algorithm as u8]);
                push_tlv(&mut data, 0x02, &[key.pin_policy, key.touch_policy]);
                push_tlv(&mut data, 0x03, &[key.origin]);
                let Ok(public) = key.public_template() else {
                    return ResponseApdu::status(STATUS_INTERNAL_ERROR);
                };
                push_tlv(&mut data, 0x04, &public);
            }
            _ => return ResponseApdu::status(STATUS_REFERENCE_NOT_FOUND),
        }
        ResponseApdu::success(data)
    }

    fn push_reference_metadata(&self, data: &mut Vec<u8>, reference: &PinReference) {
        push_tlv(data, 0x01, &[ALGORITHM_PIN_OR_PUK]);
        push_tlv(data, 0x05, &[1]);
        push_tlv(data, 0x06, &[reference.maximum_retries, reference.retries]);
    }

    fn get_data(&self, request: &[u8]) -> ResponseApdu {
        let Some(object_id) = decode_object_id(request) else {
            return ResponseApdu::status(STATUS_INCORRECT_PARAMETERS);
        };
        let mut response = Vec::new();
        if object_id == 0x7e {
            push_tlv(&mut response, 0x53, &DISCOVERY_OBJECT);
        } else if let Some(value) = self.objects.get(&object_id) {
            push_tlv(&mut response, 0x53, value);
        } else {
            return ResponseApdu::status(STATUS_NOT_FOUND);
        }
        ResponseApdu::success(response)
    }

    fn put_data(&mut self, request: &[u8]) -> ResponseApdu {
        if !self.management_authenticated {
            return ResponseApdu::status(STATUS_SECURITY_NOT_SATISFIED);
        }
        let Some((object_id, value)) = decode_data_object_request(request) else {
            return ResponseApdu::status(STATUS_INCORRECT_DATA);
        };
        if !writable_object_id(object_id) {
            return ResponseApdu::status(STATUS_INCORRECT_DATA);
        }
        if value.is_empty() {
            self.objects.remove(&object_id);
        } else {
            self.objects.insert(object_id, value.to_vec());
        }
        self.persistent_change = true;
        ResponseApdu::success(Vec::new())
    }

    fn generate_asymmetric(&mut self, slot: u8, request: &[u8]) -> ResponseApdu {
        if !self.management_authenticated {
            return ResponseApdu::status(STATUS_SECURITY_NOT_SATISFIED);
        }
        if !valid_key_slot(slot) {
            return ResponseApdu::status(STATUS_INCORRECT_PARAMETERS);
        }
        let Some(template) = decode_exact_tlv(request, 0xac) else {
            return ResponseApdu::status(STATUS_INCORRECT_DATA);
        };
        let Some(fields) = decode_tlvs(template) else {
            return ResponseApdu::status(STATUS_INCORRECT_DATA);
        };
        if fields.is_empty()
            || fields.len() > 3
            || fields
                .iter()
                .any(|(tag, _)| !matches!(*tag, 0x80 | 0xaa | 0xab))
        {
            return ResponseApdu::status(STATUS_INCORRECT_DATA);
        }
        let Some(algorithm) = unique_byte_field(&fields, 0x80).and_then(PivAlgorithm::from_id)
        else {
            return ResponseApdu::status(STATUS_INCORRECT_DATA);
        };
        let Some(pin_policy) = optional_policy(&fields, 0xaa, default_pin_policy(slot)) else {
            return ResponseApdu::status(STATUS_INCORRECT_DATA);
        };
        let Some(touch_policy) = optional_policy(&fields, 0xab, TOUCH_POLICY_NEVER) else {
            return ResponseApdu::status(STATUS_INCORRECT_DATA);
        };
        let Ok(private_key) = generate_private_key(algorithm) else {
            return ResponseApdu::status(STATUS_INTERNAL_ERROR);
        };
        let key = PivKey {
            algorithm,
            pin_policy,
            touch_policy,
            origin: ORIGIN_GENERATED,
            private_key,
        };
        let Ok(public) = key.public_template() else {
            return ResponseApdu::status(STATUS_INTERNAL_ERROR);
        };
        self.keys.insert(slot, key);
        self.persistent_change = true;
        ResponseApdu::success(encode_tlv(0x7f49, &public))
    }

    fn import_key(&mut self, command: &CommandApdu<'_>) -> ResponseApdu {
        if !self.management_authenticated {
            return ResponseApdu::status(STATUS_SECURITY_NOT_SATISFIED);
        }
        if !valid_key_slot(command.p2) {
            return ResponseApdu::status(STATUS_INCORRECT_PARAMETERS);
        }
        let Some(algorithm) = PivAlgorithm::from_id(command.p1) else {
            return ResponseApdu::status(STATUS_INCORRECT_PARAMETERS);
        };
        let Some(fields) = decode_tlvs(command.data) else {
            return ResponseApdu::status(STATUS_INCORRECT_DATA);
        };
        let Some(pin_policy) = optional_policy(&fields, 0xaa, default_pin_policy(command.p2))
        else {
            return ResponseApdu::status(STATUS_INCORRECT_DATA);
        };
        let Some(touch_policy) = optional_policy(&fields, 0xab, TOUCH_POLICY_NEVER) else {
            return ResponseApdu::status(STATUS_INCORRECT_DATA);
        };
        let private_key = if algorithm.rsa_bits().is_some() {
            if fields.len() < 5
                || fields.len() > 7
                || fields
                    .iter()
                    .any(|(tag, _)| !matches!(*tag, 0x01..=0x05 | 0xaa | 0xab))
            {
                return ResponseApdu::status(STATUS_INCORRECT_DATA);
            }
            let component_length = algorithm.input_length() / 2;
            let mut components = Vec::with_capacity(5);
            for tag in 0x01..=0x05 {
                let Some(component) = unique_field(&fields, tag) else {
                    return ResponseApdu::status(STATUS_INCORRECT_DATA);
                };
                if component.is_empty() || component.len() > component_length {
                    return ResponseApdu::status(STATUS_INCORRECT_DATA);
                }
                components.push(component);
            }
            SoftwareSigningKey::from_rsa_primes(components[0], components[1], &[1, 0, 1])
                .and_then(|key| {
                    let computed = key.rsa_crt_components()?;
                    if components
                        .iter()
                        .zip(computed.iter())
                        .all(|(supplied, expected)| unsigned_integer_equal(supplied, expected))
                    {
                        Ok(key)
                    } else {
                        Err(software_key_core::software_signing::SoftwareSigningError::InvalidPrivateKey)
                    }
                })
                .map(SoftwarePrivateKey::Signing)
                .map_err(|_| ())
        } else {
            let Some(import_tag) = algorithm.import_tag() else {
                return ResponseApdu::status(STATUS_INCORRECT_DATA);
            };
            if fields.is_empty()
                || fields.len() > 3
                || fields
                    .iter()
                    .any(|(tag, _)| !matches!(*tag, 0x06..=0x08 | 0xaa | 0xab))
            {
                return ResponseApdu::status(STATUS_INCORRECT_DATA);
            }
            let Some(serialized) = unique_field(&fields, import_tag) else {
                return ResponseApdu::status(STATUS_INCORRECT_DATA);
            };
            if fields
                .iter()
                .any(|(tag, _)| matches!(*tag, 0x06..=0x08) && *tag != import_tag)
            {
                return ResponseApdu::status(STATUS_INCORRECT_DATA);
            }
            private_key_from_serialized(algorithm, serialized)
        };
        let Ok(private_key) = private_key else {
            return ResponseApdu::status(STATUS_INCORRECT_DATA);
        };
        let key = PivKey {
            algorithm,
            pin_policy,
            touch_policy,
            origin: ORIGIN_IMPORTED,
            private_key,
        };
        if key.public_template().is_err() {
            return ResponseApdu::status(STATUS_INCORRECT_DATA);
        }
        self.keys.insert(command.p2, key);
        self.persistent_change = true;
        ResponseApdu::success(Vec::new())
    }

    fn move_or_delete_key(&mut self, command: &CommandApdu<'_>) -> ResponseApdu {
        if !self.management_authenticated {
            return ResponseApdu::status(STATUS_SECURITY_NOT_SATISFIED);
        }
        if !valid_key_slot(command.p2) {
            return ResponseApdu::status(STATUS_INCORRECT_PARAMETERS);
        }
        if command.p1 != 0xff && !valid_key_slot(command.p1) {
            return ResponseApdu::status(STATUS_INCORRECT_PARAMETERS);
        }
        let Some(key) = self.keys.remove(&command.p2) else {
            return ResponseApdu::status(STATUS_REFERENCE_NOT_FOUND);
        };
        if command.p1 != 0xff {
            self.keys.insert(command.p1, key);
        }
        self.persistent_change = true;
        ResponseApdu::success(Vec::new())
    }

    fn set_retries(&mut self, pin_retries: u8, puk_retries: u8) -> ResponseApdu {
        if !self.management_authenticated || !self.pin_verified {
            return ResponseApdu::status(STATUS_SECURITY_NOT_SATISFIED);
        }
        if pin_retries == 0 || puk_retries == 0 {
            return ResponseApdu::status(STATUS_INCORRECT_PARAMETERS);
        }
        self.pin = PinReference::new(FACTORY_PIN);
        self.pin.retries = pin_retries;
        self.pin.maximum_retries = pin_retries;
        self.puk = PinReference::new(FACTORY_PUK);
        self.puk.retries = puk_retries;
        self.puk.maximum_retries = puk_retries;
        self.pin_verified = false;
        self.persistent_change = true;
        ResponseApdu::success(Vec::new())
    }

    fn reset(&mut self) -> ResponseApdu {
        if self.pin.retries != 0 || self.puk.retries != 0 {
            return ResponseApdu::status(STATUS_CONDITIONS_NOT_SATISFIED);
        }
        let mut reset = Self::new(self.serial, self.firmware);
        reset.persistent_change = true;
        *self = reset;
        ResponseApdu::success(Vec::new())
    }

    fn verify_pin(&mut self, supplied: &[u8]) -> ResponseApdu {
        if supplied.is_empty() {
            return if self.pin_verified {
                ResponseApdu::success(Vec::new())
            } else {
                ResponseApdu::status(self.pin.retry_status())
            };
        }
        match self.pin.verify(supplied) {
            Ok(()) => {
                self.pin_verified = true;
                self.persistent_change = true;
                ResponseApdu::success(Vec::new())
            }
            Err(status) => {
                self.pin_verified = false;
                if supplied.len() == 8 {
                    self.persistent_change = true;
                }
                ResponseApdu::status(status)
            }
        }
    }

    fn change_reference(&mut self, reference: u8, request: &[u8]) -> ResponseApdu {
        let Some((old_value, new_value)) = split_reference_change(request) else {
            return ResponseApdu::status(STATUS_WRONG_LENGTH);
        };
        let Some(new_value) = validate_pin_value(new_value) else {
            return ResponseApdu::status(STATUS_INCORRECT_DATA);
        };
        let target = match reference {
            REFERENCE_PIN => &mut self.pin,
            REFERENCE_PUK => &mut self.puk,
            _ => return ResponseApdu::status(STATUS_INCORRECT_PARAMETERS),
        };
        match target.verify(old_value) {
            Ok(()) => {
                target.replace(new_value);
                self.persistent_change = true;
                ResponseApdu::success(Vec::new())
            }
            Err(status) => {
                self.persistent_change = true;
                ResponseApdu::status(status)
            }
        }
    }

    fn reset_retry(&mut self, request: &[u8]) -> ResponseApdu {
        let Some((puk, new_pin)) = split_reference_change(request) else {
            return ResponseApdu::status(STATUS_WRONG_LENGTH);
        };
        let Some(new_pin) = validate_pin_value(new_pin) else {
            return ResponseApdu::status(STATUS_INCORRECT_DATA);
        };
        match self.puk.verify(puk) {
            Ok(()) => {
                self.pin.replace(new_pin);
                self.pin_verified = false;
                self.persistent_change = true;
                ResponseApdu::success(Vec::new())
            }
            Err(status) => {
                self.persistent_change = true;
                ResponseApdu::status(status)
            }
        }
    }

    fn authenticate_management(
        &mut self,
        command: &CommandApdu<'_>,
        presence: PresenceAuthorization,
    ) -> PivExchange {
        if command.p2 != REFERENCE_MANAGEMENT_KEY || command.p1 != self.management_algorithm as u8 {
            return ResponseApdu::status(STATUS_INCORRECT_PARAMETERS).into();
        }
        let Some(dynamic) = decode_exact_tlv(command.data, 0x7c) else {
            return ResponseApdu::status(STATUS_INCORRECT_DATA).into();
        };
        let Some(fields) = decode_tlvs(dynamic) else {
            return ResponseApdu::status(STATUS_INCORRECT_DATA).into();
        };

        if fields.as_slice() == [(0x80, &[][..])] {
            let presence_policy = match self.management_touch_policy {
                TOUCH_POLICY_NEVER => None,
                TOUCH_POLICY_ALWAYS => Some(UserPresencePolicy::Always),
                _ => return ResponseApdu::status(STATUS_CONDITIONS_NOT_SATISFIED).into(),
            };
            if let Some(policy) = presence_policy
                && !self.presence.authorize(policy, presence)
            {
                return PivExchange::PresenceRequired(policy);
            }
            let mut challenge = Zeroizing::new(vec![0_u8; self.management_algorithm.block_size()]);
            if getrandom::fill(challenge.as_mut()).is_err() {
                return ResponseApdu::status(STATUS_INTERNAL_ERROR).into();
            }
            let Ok(cryptogram) = self.management_algorithm.crypt_block(
                &self.management_key,
                &challenge,
                Direction::Encrypt,
            ) else {
                return ResponseApdu::status(STATUS_INTERNAL_ERROR).into();
            };
            self.management_challenge = Some(challenge);
            return ResponseApdu::success(encode_tlv(0x7c, &encode_tlv(0x80, &cryptogram))).into();
        }

        if fields.as_slice() == [(0x81, &[][..])] {
            let mut challenge = Zeroizing::new(vec![0_u8; self.management_algorithm.block_size()]);
            if getrandom::fill(challenge.as_mut()).is_err() {
                return ResponseApdu::status(STATUS_INTERNAL_ERROR).into();
            }
            let response = encode_tlv(0x7c, &encode_tlv(0x81, challenge.as_slice()));
            self.management_challenge = Some(challenge);
            self.management_authenticated = false;
            return ResponseApdu::success(response).into();
        }

        if let [(0x82, host_response)] = fields.as_slice() {
            let block_size = self.management_algorithm.block_size();
            if host_response.len() != block_size {
                return ResponseApdu::status(STATUS_WRONG_LENGTH).into();
            }
            let Some(challenge) = self.management_challenge.take() else {
                return ResponseApdu::status(STATUS_CONDITIONS_NOT_SATISFIED).into();
            };
            let Ok(expected) = self.management_algorithm.crypt_block(
                &self.management_key,
                &challenge,
                Direction::Encrypt,
            ) else {
                return ResponseApdu::status(STATUS_INTERNAL_ERROR).into();
            };
            if !bool::from(expected.as_slice().ct_eq(*host_response)) {
                self.management_authenticated = false;
                return ResponseApdu::status(STATUS_SECURITY_NOT_SATISFIED).into();
            }
            self.management_authenticated = true;
            return ResponseApdu::success(Vec::new()).into();
        }

        let Some(card_response) = unique_field(&fields, 0x80) else {
            return ResponseApdu::status(STATUS_INCORRECT_DATA).into();
        };
        let Some(host_challenge) = unique_field(&fields, 0x81) else {
            return ResponseApdu::status(STATUS_INCORRECT_DATA).into();
        };
        let block_size = self.management_algorithm.block_size();
        if card_response.len() != block_size || host_challenge.len() != block_size {
            return ResponseApdu::status(STATUS_WRONG_LENGTH).into();
        }
        let Some(expected) = self.management_challenge.take() else {
            return ResponseApdu::status(STATUS_CONDITIONS_NOT_SATISFIED).into();
        };
        if !bool::from(expected.as_slice().ct_eq(card_response)) {
            self.management_authenticated = false;
            return ResponseApdu::status(STATUS_SECURITY_NOT_SATISFIED).into();
        }
        let Ok(cryptogram) = self.management_algorithm.crypt_block(
            &self.management_key,
            host_challenge,
            Direction::Encrypt,
        ) else {
            return ResponseApdu::status(STATUS_INTERNAL_ERROR).into();
        };
        self.management_authenticated = true;
        ResponseApdu::success(encode_tlv(0x7c, &encode_tlv(0x82, &cryptogram))).into()
    }

    fn general_authenticate(
        &mut self,
        command: &CommandApdu<'_>,
        presence: PresenceAuthorization,
    ) -> PivExchange {
        let Some(key) = self.keys.get(&command.p2) else {
            return ResponseApdu::status(STATUS_REFERENCE_NOT_FOUND).into();
        };
        if command.p1 != key.algorithm as u8 {
            return ResponseApdu::status(STATUS_INCORRECT_PARAMETERS).into();
        }
        if key.pin_policy >= 4 {
            return ResponseApdu::status(STATUS_CONDITIONS_NOT_SATISFIED).into();
        }
        if key.pin_policy != PIN_POLICY_NEVER && !self.pin_verified {
            return ResponseApdu::status(STATUS_SECURITY_NOT_SATISFIED).into();
        }
        let Some(dynamic) = decode_exact_tlv(command.data, 0x7c) else {
            return ResponseApdu::status(STATUS_INCORRECT_DATA).into();
        };
        let Some(fields) = decode_tlvs(dynamic) else {
            return ResponseApdu::status(STATUS_INCORRECT_DATA).into();
        };
        if fields.len() != 2
            || unique_field(&fields, 0x82) != Some(&[][..])
            || fields
                .iter()
                .any(|(tag, _)| !matches!(*tag, 0x81 | 0x82 | 0x85))
        {
            return ResponseApdu::status(STATUS_INCORRECT_DATA).into();
        }
        let presence_policy = match key.touch_policy {
            TOUCH_POLICY_NEVER => None,
            TOUCH_POLICY_ALWAYS => Some(UserPresencePolicy::Always),
            TOUCH_POLICY_CACHED => Some(UserPresencePolicy::Cached(PIV_TOUCH_CACHE_DURATION)),
            _ => return ResponseApdu::status(STATUS_CONDITIONS_NOT_SATISFIED).into(),
        };
        if let Some(policy) = presence_policy
            && !self.presence.authorize(policy, presence)
        {
            return PivExchange::PresenceRequired(policy);
        }
        let result = if let Some(digest) = unique_field(&fields, 0x81) {
            let invalid_length = match key.algorithm {
                PivAlgorithm::Rsa1024
                | PivAlgorithm::Rsa2048
                | PivAlgorithm::Rsa3072
                | PivAlgorithm::Rsa4096 => digest.len() != key.algorithm.input_length(),
                PivAlgorithm::EccP256 | PivAlgorithm::EccP384 => {
                    digest.is_empty() || digest.len() > key.algorithm.input_length()
                }
                PivAlgorithm::Ed25519 => false,
                PivAlgorithm::X25519 => {
                    return ResponseApdu::status(STATUS_INCORRECT_DATA).into();
                }
            };
            if invalid_length {
                return ResponseApdu::status(STATUS_WRONG_LENGTH).into();
            }
            let SoftwarePrivateKey::Signing(private_key) = &key.private_key else {
                return ResponseApdu::status(STATUS_INCORRECT_DATA).into();
            };
            let signature = if key.algorithm.rsa_bits().is_some() {
                private_key
                    .sign_rsa_raw(digest)
                    .map(|signature| signature.into_bytes())
            } else if key.algorithm == PivAlgorithm::Ed25519 {
                private_key
                    .sign_message(SignatureScheme::Ed25519, digest)
                    .map(|signature| signature.into_bytes())
            } else {
                let Some(algorithm) = key.algorithm.signing_algorithm() else {
                    return ResponseApdu::status(STATUS_INCORRECT_DATA).into();
                };
                private_key
                    .sign_prehash(algorithm, digest)
                    .map(|signature| signature.into_bytes())
            };
            let Ok(signature) = signature else {
                return ResponseApdu::status(STATUS_INTERNAL_ERROR).into();
            };
            if key.algorithm.rsa_bits().is_some() || key.algorithm == PivAlgorithm::Ed25519 {
                signature
            } else {
                let Some(signature) = encode_ecdsa_der(&signature) else {
                    return ResponseApdu::status(STATUS_INTERNAL_ERROR).into();
                };
                signature
            }
        } else if let Some(peer_public_key) = unique_field(&fields, 0x85) {
            let expected_length = if key.algorithm == PivAlgorithm::X25519 {
                32
            } else {
                key.algorithm.input_length() * 2 + 1
            };
            if key.algorithm.rsa_bits().is_some()
                || key.algorithm == PivAlgorithm::Ed25519
                || peer_public_key.len() != expected_length
            {
                return ResponseApdu::status(STATUS_WRONG_LENGTH).into();
            }
            let shared_secret = match &key.private_key {
                SoftwarePrivateKey::Signing(private_key) => {
                    derive_with_signing_key(private_key, peer_public_key).map_err(|_| ())
                }
                SoftwarePrivateKey::Montgomery(private_key) => {
                    private_key.derive(peer_public_key).map_err(|_| ())
                }
                SoftwarePrivateKey::MlKem(_) => Err(()),
            };
            let Ok(shared_secret) = shared_secret else {
                return ResponseApdu::status(STATUS_INCORRECT_DATA).into();
            };
            shared_secret.to_vec()
        } else {
            return ResponseApdu::status(STATUS_INCORRECT_DATA).into();
        };
        if key.pin_policy == PIN_POLICY_ALWAYS {
            self.pin_verified = false;
        }
        ResponseApdu::success(encode_tlv(0x7c, &encode_tlv(0x82, &result))).into()
    }

    fn set_management_key(&mut self, command: &CommandApdu<'_>) -> ResponseApdu {
        if command.p1 != 0xff {
            return ResponseApdu::status(STATUS_INCORRECT_PARAMETERS);
        }
        if !matches!(command.p2, 0xfe | 0xff) {
            return ResponseApdu::status(STATUS_INCORRECT_DATA);
        }
        if !self.management_authenticated {
            return ResponseApdu::status(STATUS_SECURITY_NOT_SATISFIED);
        }
        let Some((&algorithm, request)) = command.data.split_first() else {
            return ResponseApdu::status(STATUS_INCORRECT_DATA);
        };
        let Some((&reference, request)) = request.split_first() else {
            return ResponseApdu::status(STATUS_INCORRECT_DATA);
        };
        let Some((&length, key)) = request.split_first() else {
            return ResponseApdu::status(STATUS_INCORRECT_DATA);
        };
        let Some(algorithm) = ManagementAlgorithm::from_id(algorithm) else {
            return ResponseApdu::status(STATUS_INCORRECT_DATA);
        };
        if reference != REFERENCE_MANAGEMENT_KEY
            || usize::from(length) != key.len()
            || key.len() != algorithm.key_length()
        {
            return ResponseApdu::status(STATUS_INCORRECT_DATA);
        }
        self.management_key.zeroize();
        self.management_key = Zeroizing::new(key.to_vec());
        self.management_algorithm = algorithm;
        self.management_touch_policy = match command.p2 {
            0xff => TOUCH_POLICY_NEVER,
            0xfe => TOUCH_POLICY_ALWAYS,
            _ => unreachable!(),
        };
        self.management_challenge = None;
        self.persistent_change = true;
        ResponseApdu::success(Vec::new())
    }
}

fn empty_command(command: &CommandApdu<'_>, p1: u8, p2: u8) -> bool {
    command.p1 == p1 && command.p2 == p2 && command.data.is_empty()
}

fn split_reference_change(request: &[u8]) -> Option<(&[u8], &[u8])> {
    (request.len() == 16).then(|| request.split_at(8))
}

fn validate_pin_value(value: &[u8]) -> Option<[u8; 8]> {
    let bytes = value.try_into().ok()?;
    let length = value.iter().position(|byte| *byte == 0xff).unwrap_or(8);
    if !(6..=8).contains(&length) || !value[length..].iter().all(|byte| *byte == 0xff) {
        return None;
    }
    Some(bytes)
}

fn decode_persistent_pin(
    decoder: &mut minicbor::Decoder<'_>,
    name: &'static str,
) -> Result<[u8; 8], &'static str> {
    let value = decoder.bytes().map_err(|_| match name {
        "PIN" => "persistent PIV state has an invalid PIN",
        _ => "persistent PIV state has an invalid PUK",
    })?;
    validate_pin_value(value).ok_or(match name {
        "PIN" => "persistent PIV state has an invalid PIN",
        _ => "persistent PIV state has an invalid PUK",
    })
}

fn decode_persistent_objects(
    decoder: &mut minicbor::Decoder<'_>,
) -> Result<BTreeMap<u32, Vec<u8>>, &'static str> {
    let count = decoder
        .array()
        .map_err(|_| "persistent PIV object store is not an array")?
        .ok_or("indefinite persistent PIV object store is unsupported")?;
    let mut objects = BTreeMap::new();
    for _ in 0..count {
        if decoder
            .array()
            .map_err(|_| "persistent PIV object is not an array")?
            != Some(2)
        {
            return Err("persistent PIV object has an invalid shape");
        }
        let object_id = decoder
            .u32()
            .map_err(|_| "persistent PIV object has an invalid identifier")?;
        if !writable_object_id(object_id) {
            return Err("persistent PIV object identifier is unsupported");
        }
        let value = decoder
            .bytes()
            .map_err(|_| "persistent PIV object has an invalid value")?
            .to_vec();
        if objects.insert(object_id, value).is_some() {
            return Err("persistent PIV state contains duplicate objects");
        }
    }
    Ok(objects)
}

fn decode_persistent_keys(
    decoder: &mut minicbor::Decoder<'_>,
) -> Result<BTreeMap<u8, PivKey>, &'static str> {
    let count = decoder
        .array()
        .map_err(|_| "persistent PIV key store is not an array")?
        .ok_or("indefinite persistent PIV key store is unsupported")?;
    let mut keys = BTreeMap::new();
    for _ in 0..count {
        if decoder
            .array()
            .map_err(|_| "persistent PIV key is not an array")?
            != Some(6)
        {
            return Err("persistent PIV key has an invalid shape");
        }
        let slot = decoder
            .u8()
            .map_err(|_| "persistent PIV key has an invalid slot")?;
        if !valid_key_slot(slot) {
            return Err("persistent PIV key slot is unsupported");
        }
        let algorithm = PivAlgorithm::from_id(
            decoder
                .u8()
                .map_err(|_| "persistent PIV key has an invalid algorithm")?,
        )
        .ok_or("persistent PIV key algorithm is unsupported")?;
        let pin_policy = decoder
            .u8()
            .map_err(|_| "persistent PIV key has an invalid PIN policy")?;
        let touch_policy = decoder
            .u8()
            .map_err(|_| "persistent PIV key has an invalid touch policy")?;
        let origin = decoder
            .u8()
            .map_err(|_| "persistent PIV key has an invalid origin")?;
        if !valid_pin_policy(pin_policy)
            || !valid_touch_policy(touch_policy)
            || !matches!(origin, ORIGIN_GENERATED | ORIGIN_IMPORTED)
        {
            return Err("persistent PIV key has unsupported metadata");
        }
        let serialized = decoder
            .bytes()
            .map_err(|_| "persistent PIV key has invalid private material")?;
        let private_key = private_key_from_serialized(algorithm, serialized)
            .map_err(|_| "persistent PIV key has invalid private material")?;
        let key = PivKey {
            algorithm,
            pin_policy,
            touch_policy,
            origin,
            private_key,
        };
        if key.public_template().is_err() {
            return Err("persistent PIV key does not match its algorithm");
        }
        if keys.insert(slot, key).is_some() {
            return Err("persistent PIV state contains duplicate keys");
        }
    }
    Ok(keys)
}

fn valid_key_slot(slot: u8) -> bool {
    matches!(slot, 0x9a | 0x9c | 0x9d | 0x9e | 0x82..=0x95)
}

fn default_pin_policy(slot: u8) -> u8 {
    match slot {
        0x9e => PIN_POLICY_NEVER,
        0x9c => PIN_POLICY_ALWAYS,
        _ => PIN_POLICY_ONCE,
    }
}

fn valid_pin_policy(policy: u8) -> bool {
    matches!(policy, 1..=5)
}

fn valid_touch_policy(policy: u8) -> bool {
    matches!(policy, 1..=3)
}

fn valid_management_touch_policy(policy: u8) -> bool {
    matches!(policy, TOUCH_POLICY_NEVER | TOUCH_POLICY_ALWAYS)
}

fn unique_byte_field(fields: &[(u32, &[u8])], tag: u32) -> Option<u8> {
    let [value] = unique_field(fields, tag)? else {
        return None;
    };
    Some(*value)
}

fn optional_policy(fields: &[(u32, &[u8])], tag: u32, default: u8) -> Option<u8> {
    match fields.iter().filter(|(field, _)| *field == tag).count() {
        0 => Some(default),
        1 => match unique_byte_field(fields, tag)? {
            policy
                if (tag == 0xaa && valid_pin_policy(policy))
                    || (tag == 0xab && valid_touch_policy(policy)) =>
            {
                Some(policy)
            }
            _ => None,
        },
        _ => None,
    }
}

fn encode_ecdsa_der(signature: &[u8]) -> Option<Vec<u8>> {
    if signature.is_empty() || !signature.len().is_multiple_of(2) {
        return None;
    }
    let (r, s) = signature.split_at(signature.len() / 2);
    let r = encode_der_integer(r);
    let s = encode_der_integer(s);
    let content_length = r.len().checked_add(s.len())?;
    let length = u8::try_from(content_length).ok()?;
    let mut output = Vec::with_capacity(content_length + 2);
    output.extend_from_slice(&[0x30, length]);
    output.extend_from_slice(&r);
    output.extend_from_slice(&s);
    Some(output)
}

fn encode_der_integer(integer: &[u8]) -> Vec<u8> {
    let integer = integer
        .iter()
        .position(|byte| *byte != 0)
        .map_or(&integer[integer.len().saturating_sub(1)..], |first| {
            &integer[first..]
        });
    let needs_zero = integer.first().is_some_and(|byte| byte & 0x80 != 0);
    let mut encoded = Vec::with_capacity(integer.len() + 3);
    encoded.extend_from_slice(&[0x02, (integer.len() + usize::from(needs_zero)) as u8]);
    if needs_zero {
        encoded.push(0);
    }
    encoded.extend_from_slice(integer);
    encoded
}

fn writable_object_id(object_id: u32) -> bool {
    object_id <= 0x00ff_ffff && object_id != 0x7e
}

fn unsigned_integer_equal(left: &[u8], right: &[u8]) -> bool {
    let left = left
        .iter()
        .position(|byte| *byte != 0)
        .map_or(&[][..], |first| &left[first..]);
    let right = right
        .iter()
        .position(|byte| *byte != 0)
        .map_or(&[][..], |first| &right[first..]);
    left == right
}

fn decode_object_id(request: &[u8]) -> Option<u32> {
    let value = decode_exact_tlv(request, 0x5c)?;
    decode_object_id_value(value)
}

fn decode_object_id_value(value: &[u8]) -> Option<u32> {
    if !(1..=3).contains(&value.len()) {
        return None;
    }
    Some(
        value
            .iter()
            .fold(0_u32, |object, byte| (object << 8) | u32::from(*byte)),
    )
}

fn decode_data_object_request(request: &[u8]) -> Option<(u32, &[u8])> {
    let fields = decode_tlvs(request)?;
    if fields.len() != 2 || fields[0].0 != 0x5c || fields[1].0 != 0x53 {
        return None;
    }
    Some((decode_object_id_value(fields[0].1)?, fields[1].1))
}

fn decode_exact_tlv(input: &[u8], expected_tag: u32) -> Option<&[u8]> {
    let (tag, value, remaining) = decode_tlv(input)?;
    (tag == expected_tag && remaining.is_empty()).then_some(value)
}

fn decode_tlvs(mut input: &[u8]) -> Option<Vec<(u32, &[u8])>> {
    let mut fields = Vec::new();
    while !input.is_empty() {
        let (tag, value, remaining) = decode_tlv(input)?;
        fields.push((tag, value));
        input = remaining;
    }
    Some(fields)
}

fn decode_tlv(input: &[u8]) -> Option<(u32, &[u8], &[u8])> {
    let (&first_tag, mut input) = input.split_first()?;
    let mut tag = u32::from(first_tag);
    if first_tag & 0x1f == 0x1f {
        loop {
            let (&next, remaining) = input.split_first()?;
            tag = tag.checked_shl(8)? | u32::from(next);
            input = remaining;
            if next & 0x80 == 0 {
                break;
            }
        }
    }
    let (&first_length, input) = input.split_first()?;
    let (length, input) = match first_length {
        value @ 0..=0x7f => (usize::from(value), input),
        0x81 => {
            let (&length, input) = input.split_first()?;
            (usize::from(length), input)
        }
        0x82 => {
            let (&high, input) = input.split_first()?;
            let (&low, input) = input.split_first()?;
            ((usize::from(high) << 8) | usize::from(low), input)
        }
        _ => return None,
    };
    let (value, remaining) = input.split_at_checked(length)?;
    Some((tag, value, remaining))
}

fn unique_field<'a>(fields: &[(u32, &'a [u8])], wanted: u32) -> Option<&'a [u8]> {
    let mut matching = fields
        .iter()
        .filter(|(tag, _)| *tag == wanted)
        .map(|(_, value)| *value);
    let value = matching.next()?;
    matching.next().is_none().then_some(value)
}

fn encode_tlv(tag: u32, value: &[u8]) -> Vec<u8> {
    let mut output = Vec::new();
    match tag {
        0..=0xff => output.push(tag as u8),
        0x100..=0xffff => output.extend_from_slice(&(tag as u16).to_be_bytes()),
        _ => output.extend_from_slice(&tag.to_be_bytes()[1..]),
    }
    match value.len() {
        length @ 0..=0x7f => output.push(length as u8),
        length @ 0x80..=0xff => output.extend_from_slice(&[0x81, length as u8]),
        length => {
            output.push(0x82);
            output.extend_from_slice(&(length as u16).to_be_bytes());
        }
    }
    output.extend_from_slice(value);
    output
}

fn push_tlv(output: &mut Vec<u8>, tag: u32, value: &[u8]) {
    output.extend_from_slice(&encode_tlv(tag, value));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn command(ins: u8, p1: u8, p2: u8, data: &[u8]) -> CommandApdu<'_> {
        CommandApdu {
            cla: 0,
            ins,
            p1,
            p2,
            data,
            le: Some(256),
        }
    }

    fn authenticate_management(piv: &mut PivApplet, algorithm: ManagementAlgorithm, key: &[u8]) {
        let request = encode_tlv(0x7c, &encode_tlv(0x80, &[]));
        let response = piv.transmit(&command(
            INS_AUTHENTICATE,
            algorithm as u8,
            REFERENCE_MANAGEMENT_KEY,
            &request,
        ));
        assert_eq!(response.status, 0x9000);
        let dynamic = decode_exact_tlv(&response.data, 0x7c).unwrap();
        let encrypted_challenge = decode_exact_tlv(dynamic, 0x80).unwrap();
        let challenge = algorithm
            .crypt_block(key, encrypted_challenge, Direction::Decrypt)
            .unwrap();

        let host_challenge = vec![0x5a; algorithm.block_size()];
        let mut dynamic = encode_tlv(0x80, &challenge);
        dynamic.extend_from_slice(&encode_tlv(0x81, &host_challenge));
        let response = piv.transmit(&command(
            INS_AUTHENTICATE,
            algorithm as u8,
            REFERENCE_MANAGEMENT_KEY,
            &encode_tlv(0x7c, &dynamic),
        ));
        assert_eq!(response.status, 0x9000);
        let dynamic = decode_exact_tlv(&response.data, 0x7c).unwrap();
        let cryptogram = decode_exact_tlv(dynamic, 0x82).unwrap();
        assert_eq!(
            algorithm
                .crypt_block(key, cryptogram, Direction::Decrypt)
                .unwrap(),
            host_challenge
        );
    }

    fn complete(exchange: PivExchange) -> ResponseApdu {
        match exchange {
            PivExchange::Complete(response) => response,
            PivExchange::PresenceRequired(policy) => {
                panic!("unexpected presence request: {policy:?}")
            }
        }
    }

    fn generate_touch_key(piv: &mut PivApplet, slot: u8, touch_policy: u8) {
        let template = [
            encode_tlv(0x80, &[PivAlgorithm::EccP256 as u8]),
            encode_tlv(0xaa, &[PIN_POLICY_NEVER]),
            encode_tlv(0xab, &[touch_policy]),
        ]
        .concat();
        assert_eq!(
            piv.transmit(&command(
                INS_GENERATE_ASYMMETRIC,
                0,
                slot,
                &encode_tlv(0xac, &template),
            ))
            .status,
            0x9000
        );
    }

    fn signing_request(digest: &[u8]) -> Vec<u8> {
        encode_tlv(
            0x7c,
            &[encode_tlv(0x82, &[]), encode_tlv(0x81, digest)].concat(),
        )
    }

    #[test]
    fn private_key_operations_surface_always_and_cached_touch_policies() {
        let mut piv = PivApplet::new(20, [5, 8, 0]);
        authenticate_management(
            &mut piv,
            ManagementAlgorithm::Aes192,
            &FACTORY_MANAGEMENT_KEY,
        );
        generate_touch_key(&mut piv, 0x9a, TOUCH_POLICY_ALWAYS);
        generate_touch_key(&mut piv, 0x9d, TOUCH_POLICY_CACHED);

        let cached_request = signing_request(&[0x22; 32]);
        let cached = command(
            INS_AUTHENTICATE,
            PivAlgorithm::EccP256 as u8,
            0x9d,
            &cached_request,
        );
        assert!(matches!(
            piv.exchange(&cached, PresenceAuthorization::Absent),
            PivExchange::PresenceRequired(UserPresencePolicy::Cached(duration))
                if duration == PIV_TOUCH_CACHE_DURATION
        ));
        assert_eq!(
            complete(piv.exchange(&cached, PresenceAuthorization::Granted)).status,
            0x9000
        );
        assert_eq!(
            complete(piv.exchange(&cached, PresenceAuthorization::Absent)).status,
            0x9000
        );

        let always_request = signing_request(&[0x11; 32]);
        let always = command(
            INS_AUTHENTICATE,
            PivAlgorithm::EccP256 as u8,
            0x9a,
            &always_request,
        );
        assert!(matches!(
            piv.exchange(&always, PresenceAuthorization::Absent),
            PivExchange::PresenceRequired(UserPresencePolicy::Always)
        ));
        assert_eq!(
            complete(piv.exchange(&always, PresenceAuthorization::Granted)).status,
            0x9000
        );
        assert!(matches!(
            piv.exchange(&always, PresenceAuthorization::Absent),
            PivExchange::PresenceRequired(UserPresencePolicy::Always)
        ));
    }

    fn decode_ecdsa_der(signature: &[u8], coordinate_length: usize) -> Vec<u8> {
        let sequence = decode_exact_tlv(signature, 0x30).unwrap();
        let fields = decode_tlvs(sequence).unwrap();
        assert_eq!(fields.len(), 2);
        assert_eq!(fields[0].0, 0x02);
        assert_eq!(fields[1].0, 0x02);
        let mut raw = Vec::with_capacity(coordinate_length * 2);
        for (_, integer) in fields {
            let integer = integer.strip_prefix(&[0]).unwrap_or(integer);
            assert!(integer.len() <= coordinate_length);
            raw.resize(raw.len() + coordinate_length - integer.len(), 0);
            raw.extend_from_slice(integer);
        }
        raw
    }

    #[test]
    fn reports_factory_identity_and_reference_metadata() {
        let mut piv = PivApplet::new(0x01020304, [5, 8, 0]);
        assert_eq!(
            piv.transmit(&command(INS_GET_VERSION, 0, 0, &[])),
            ResponseApdu::success(vec![5, 8, 0])
        );
        assert_eq!(
            piv.transmit(&command(INS_GET_SERIAL, 0, 0, &[])),
            ResponseApdu::success(vec![1, 2, 3, 4])
        );
        assert_eq!(
            piv.transmit(&command(INS_GET_METADATA, 0, REFERENCE_PIN, &[])),
            ResponseApdu::success(vec![
                0x01, 0x01, 0xff, 0x05, 0x01, 0x01, 0x06, 0x02, 0x03, 0x03
            ])
        );
        assert_eq!(
            piv.transmit(&command(INS_GET_METADATA, 0, REFERENCE_MANAGEMENT_KEY, &[])),
            ResponseApdu::success(vec![
                0x01, 0x01, 0x0a, 0x02, 0x02, 0x00, 0x01, 0x05, 0x01, 0x01
            ])
        );
        assert_eq!(
            piv.transmit(&command(INS_GET_METADATA, 0, 0x9a, &[]))
                .status,
            STATUS_REFERENCE_NOT_FOUND
        );
    }

    #[test]
    fn returns_the_factory_discovery_object() {
        let mut piv = PivApplet::new(1, [5, 8, 0]);
        let response = piv.transmit(&command(INS_GET_DATA, 0x3f, 0xff, &[0x5c, 1, 0x7e]));
        assert_eq!(response.status, 0x9000);
        assert_eq!(&response.data[..2], &[0x53, DISCOVERY_OBJECT.len() as u8]);
        assert_eq!(&response.data[2..], DISCOVERY_OBJECT);
        assert_eq!(
            piv.transmit(&command(
                INS_GET_DATA,
                0x3f,
                0xff,
                &[0x5c, 3, 0x5f, 0xc1, 0x05]
            ))
            .status,
            STATUS_NOT_FOUND
        );
    }

    #[test]
    fn stores_deletes_and_persists_management_authorized_data_objects() {
        let mut piv = PivApplet::new(9, [5, 8, 0]);
        let object_id = [0x5f, 0xc1, 0x05];
        let value = [0x70, 0x02, 0x30, 0x00];
        let request = [encode_tlv(0x5c, &object_id), encode_tlv(0x53, &value)].concat();
        assert_eq!(
            piv.transmit(&command(INS_PUT_DATA, 0x3f, 0xff, &request))
                .status,
            STATUS_SECURITY_NOT_SATISFIED
        );
        authenticate_management(
            &mut piv,
            ManagementAlgorithm::Aes192,
            &FACTORY_MANAGEMENT_KEY,
        );
        assert_eq!(
            piv.transmit(&command(INS_PUT_DATA, 0x3f, 0xff, &request))
                .status,
            0x9000
        );
        assert_eq!(
            piv.transmit(&command(
                INS_GET_DATA,
                0x3f,
                0xff,
                &encode_tlv(0x5c, &object_id),
            )),
            ResponseApdu::success(encode_tlv(0x53, &value))
        );

        let encoded = piv.persistent_state().unwrap();
        let mut restored = PivApplet::from_persistent_state(9, [5, 8, 0], &encoded).unwrap();
        assert_eq!(
            restored.transmit(&command(
                INS_GET_DATA,
                0x3f,
                0xff,
                &encode_tlv(0x5c, &object_id),
            )),
            ResponseApdu::success(encode_tlv(0x53, &value))
        );

        authenticate_management(
            &mut restored,
            ManagementAlgorithm::Aes192,
            &FACTORY_MANAGEMENT_KEY,
        );
        let delete = [encode_tlv(0x5c, &object_id), encode_tlv(0x53, &[])].concat();
        assert_eq!(
            restored
                .transmit(&command(INS_PUT_DATA, 0x3f, 0xff, &delete))
                .status,
            0x9000
        );
        assert_eq!(
            restored
                .transmit(&command(
                    INS_GET_DATA,
                    0x3f,
                    0xff,
                    &encode_tlv(0x5c, &object_id),
                ))
                .status,
            STATUS_NOT_FOUND
        );
    }

    #[test]
    fn generates_reports_and_persists_ecc_keys() {
        let mut piv = PivApplet::new(11, [5, 8, 0]);
        let p256_request = encode_tlv(
            0xac,
            &[
                encode_tlv(0x80, &[PivAlgorithm::EccP256 as u8]),
                encode_tlv(0xaa, &[PIN_POLICY_ALWAYS]),
                encode_tlv(0xab, &[2]),
            ]
            .concat(),
        );
        assert_eq!(
            piv.transmit(&command(INS_GENERATE_ASYMMETRIC, 0, 0x9c, &p256_request,))
                .status,
            STATUS_SECURITY_NOT_SATISFIED
        );
        authenticate_management(
            &mut piv,
            ManagementAlgorithm::Aes192,
            &FACTORY_MANAGEMENT_KEY,
        );

        let response = piv.transmit(&command(INS_GENERATE_ASYMMETRIC, 0, 0x9c, &p256_request));
        assert_eq!(response.status, 0x9000);
        let p256_public = decode_exact_tlv(&response.data, 0x7f49).unwrap();
        let p256_point = decode_exact_tlv(p256_public, 0x86).unwrap();
        assert_eq!(p256_point.len(), 65);
        assert_eq!(p256_point[0], 4);

        let p384_request = encode_tlv(0xac, &encode_tlv(0x80, &[PivAlgorithm::EccP384 as u8]));
        let response = piv.transmit(&command(INS_GENERATE_ASYMMETRIC, 0, 0x9a, &p384_request));
        assert_eq!(response.status, 0x9000);
        let p384_public = decode_exact_tlv(&response.data, 0x7f49).unwrap();
        let p384_point = decode_exact_tlv(p384_public, 0x86).unwrap();
        assert_eq!(p384_point.len(), 97);
        assert_eq!(p384_point[0], 4);

        let metadata = piv.transmit(&command(INS_GET_METADATA, 0, 0x9c, &[])).data;
        let fields = decode_tlvs(&metadata).unwrap();
        assert_eq!(unique_field(&fields, 0x01), Some(&[0x11][..]));
        assert_eq!(unique_field(&fields, 0x02), Some(&[3, 2][..]));
        assert_eq!(unique_field(&fields, 0x03), Some(&[1][..]));
        assert_eq!(
            decode_exact_tlv(unique_field(&fields, 0x04).unwrap(), 0x86),
            Some(p256_point)
        );

        let encoded = piv.persistent_state().unwrap();
        let mut restored = PivApplet::from_persistent_state(11, [5, 8, 1], &encoded).unwrap();
        assert_eq!(
            restored.transmit(&command(INS_GET_METADATA, 0, 0x9c, &[])),
            ResponseApdu::success(metadata)
        );
        let restored_p384 = restored.transmit(&command(INS_GET_METADATA, 0, 0x9a, &[]));
        assert_eq!(restored_p384.status, 0x9000);
        let fields = decode_tlvs(&restored_p384.data).unwrap();
        assert_eq!(unique_field(&fields, 0x01), Some(&[0x14][..]));
        assert_eq!(unique_field(&fields, 0x02), Some(&[2, 1][..]));
        assert_eq!(
            decode_exact_tlv(unique_field(&fields, 0x04).unwrap(), 0x86),
            Some(p384_point)
        );
    }

    #[test]
    fn omitted_policy_tlvs_use_slot_defaults_and_explicit_policy_zero_is_invalid() {
        let mut piv = PivApplet::new(22, [5, 8, 0]);
        authenticate_management(
            &mut piv,
            ManagementAlgorithm::Aes192,
            &FACTORY_MANAGEMENT_KEY,
        );
        let request = encode_tlv(0xac, &encode_tlv(0x80, &[PivAlgorithm::EccP256 as u8]));
        for (slot, expected_pin) in [
            (0x9a, PIN_POLICY_ONCE),
            (0x9c, PIN_POLICY_ALWAYS),
            (0x9d, PIN_POLICY_ONCE),
            (0x9e, PIN_POLICY_NEVER),
            (0x82, PIN_POLICY_ONCE),
        ] {
            assert_eq!(
                piv.transmit(&command(INS_GENERATE_ASYMMETRIC, 0, slot, &request))
                    .status,
                0x9000
            );
            assert_eq!(piv.keys[&slot].pin_policy, expected_pin);
            assert_eq!(piv.keys[&slot].touch_policy, TOUCH_POLICY_NEVER);
        }

        for (slot, policy_tag) in [(0x83, 0xaa), (0x84, 0xab)] {
            let explicit_default = encode_tlv(
                0xac,
                &[
                    encode_tlv(0x80, &[PivAlgorithm::EccP256 as u8]),
                    encode_tlv(policy_tag, &[0]),
                ]
                .concat(),
            );
            assert_eq!(
                piv.transmit(&command(
                    INS_GENERATE_ASYMMETRIC,
                    0,
                    slot,
                    &explicit_default,
                ))
                .status,
                STATUS_INCORRECT_DATA
            );
            assert!(!piv.keys.contains_key(&slot));
        }
    }

    #[test]
    fn rejects_unsupported_key_generation_parameters() {
        let mut piv = PivApplet::new(12, [5, 8, 0]);
        authenticate_management(
            &mut piv,
            ManagementAlgorithm::Aes192,
            &FACTORY_MANAGEMENT_KEY,
        );
        assert_eq!(
            piv.transmit(&command(
                INS_GENERATE_ASYMMETRIC,
                0,
                0xf9,
                &encode_tlv(0xac, &encode_tlv(0x80, &[0x11])),
            ))
            .status,
            STATUS_INCORRECT_PARAMETERS
        );
        assert_eq!(
            piv.transmit(&command(
                INS_GENERATE_ASYMMETRIC,
                0,
                0x9a,
                &encode_tlv(0xac, &encode_tlv(0x80, &[0x08])),
            ))
            .status,
            STATUS_INCORRECT_DATA
        );
        assert_eq!(
            piv.transmit(&command(INS_GET_METADATA, 0, 0x9a, &[]))
                .status,
            STATUS_REFERENCE_NOT_FOUND
        );
    }

    #[test]
    fn signs_ecc_digests_and_enforces_the_always_pin_policy() {
        let mut piv = PivApplet::new(13, [5, 8, 0]);
        authenticate_management(
            &mut piv,
            ManagementAlgorithm::Aes192,
            &FACTORY_MANAGEMENT_KEY,
        );
        let generate = encode_tlv(0xac, &encode_tlv(0x80, &[PivAlgorithm::EccP256 as u8]));
        assert_eq!(
            piv.transmit(&command(INS_GENERATE_ASYMMETRIC, 0, 0x9c, &generate))
                .status,
            0x9000
        );
        let SoftwarePrivateKey::Signing(private_key) = &piv.keys.get(&0x9c).unwrap().private_key
        else {
            unreachable!();
        };
        let public_key = private_key.public_key();
        let digest = [0x42; 32];
        let request = encode_tlv(
            0x7c,
            &[encode_tlv(0x82, &[]), encode_tlv(0x81, &digest)].concat(),
        );
        assert_eq!(
            piv.transmit(&command(
                INS_AUTHENTICATE,
                PivAlgorithm::EccP256 as u8,
                0x9c,
                &request,
            ))
            .status,
            STATUS_SECURITY_NOT_SATISFIED
        );
        assert_eq!(
            piv.transmit(&command(INS_VERIFY, 0, REFERENCE_PIN, &FACTORY_PIN))
                .status,
            0x9000
        );
        let response = piv.transmit(&command(
            INS_AUTHENTICATE,
            PivAlgorithm::EccP256 as u8,
            0x9c,
            &request,
        ));
        assert_eq!(response.status, 0x9000);
        let dynamic = decode_exact_tlv(&response.data, 0x7c).unwrap();
        let signature = decode_exact_tlv(dynamic, 0x82).unwrap();
        public_key
            .verify_prehash(
                SignatureScheme::EcdsaP256Sha256,
                &digest,
                &decode_ecdsa_der(signature, 32),
            )
            .unwrap();
        assert_eq!(
            piv.transmit(&command(
                INS_AUTHENTICATE,
                PivAlgorithm::EccP256 as u8,
                0x9c,
                &request,
            ))
            .status,
            STATUS_SECURITY_NOT_SATISFIED
        );
    }

    #[test]
    fn imports_moves_uses_and_deletes_an_ecc_key() {
        let imported = SoftwareSigningKey::generate_for_kind(KeyKind::Ec(EcCurve::P256)).unwrap();
        let public_key = imported.public_key();
        let private_key = imported.serialized().unwrap();
        let request = [
            encode_tlv(0x06, &private_key),
            encode_tlv(0xaa, &[PIN_POLICY_NEVER]),
            encode_tlv(0xab, &[TOUCH_POLICY_NEVER]),
        ]
        .concat();
        let mut piv = PivApplet::new(14, [5, 8, 0]);
        assert_eq!(
            piv.transmit(&command(
                INS_IMPORT_KEY,
                PivAlgorithm::EccP256 as u8,
                0x9a,
                &request,
            ))
            .status,
            STATUS_SECURITY_NOT_SATISFIED
        );
        authenticate_management(
            &mut piv,
            ManagementAlgorithm::Aes192,
            &FACTORY_MANAGEMENT_KEY,
        );
        assert_eq!(
            piv.transmit(&command(
                INS_IMPORT_KEY,
                PivAlgorithm::EccP256 as u8,
                0x9a,
                &request,
            ))
            .status,
            0x9000
        );
        let metadata = piv.transmit(&command(INS_GET_METADATA, 0, 0x9a, &[]));
        let fields = decode_tlvs(&metadata.data).unwrap();
        assert_eq!(unique_field(&fields, 0x03), Some(&[ORIGIN_IMPORTED][..]));

        let digest = [0x33; 32];
        let request = encode_tlv(
            0x7c,
            &[encode_tlv(0x82, &[]), encode_tlv(0x81, &digest)].concat(),
        );
        let response = piv.transmit(&command(
            INS_AUTHENTICATE,
            PivAlgorithm::EccP256 as u8,
            0x9a,
            &request,
        ));
        let signature =
            decode_exact_tlv(decode_exact_tlv(&response.data, 0x7c).unwrap(), 0x82).unwrap();
        public_key
            .verify_prehash(
                SignatureScheme::EcdsaP256Sha256,
                &digest,
                &decode_ecdsa_der(signature, 32),
            )
            .unwrap();

        assert_eq!(
            piv.transmit(&command(INS_MOVE_KEY, 0x82, 0x9a, &[])).status,
            0x9000
        );
        assert_eq!(
            piv.transmit(&command(INS_GET_METADATA, 0, 0x9a, &[]))
                .status,
            STATUS_REFERENCE_NOT_FOUND
        );
        assert_eq!(
            piv.transmit(&command(INS_GET_METADATA, 0, 0x82, &[])),
            metadata
        );
        let encoded = piv.persistent_state().unwrap();
        let mut restored = PivApplet::from_persistent_state(14, [5, 8, 0], &encoded).unwrap();
        authenticate_management(
            &mut restored,
            ManagementAlgorithm::Aes192,
            &FACTORY_MANAGEMENT_KEY,
        );
        assert_eq!(
            restored
                .transmit(&command(INS_MOVE_KEY, 0xff, 0x82, &[]))
                .status,
            0x9000
        );
        assert_eq!(
            restored
                .transmit(&command(INS_GET_METADATA, 0, 0x82, &[]))
                .status,
            STATUS_REFERENCE_NOT_FOUND
        );
    }

    #[test]
    fn generates_persists_and_uses_a_raw_rsa_key() {
        let mut piv = PivApplet::new(15, [5, 8, 0]);
        authenticate_management(
            &mut piv,
            ManagementAlgorithm::Aes192,
            &FACTORY_MANAGEMENT_KEY,
        );
        let generate = encode_tlv(0xac, &encode_tlv(0x80, &[PivAlgorithm::Rsa1024 as u8]));
        let response = piv.transmit(&command(INS_GENERATE_ASYMMETRIC, 0, 0x9e, &generate));
        assert_eq!(response.status, 0x9000);
        let public = decode_exact_tlv(&response.data, 0x7f49).unwrap();
        let fields = decode_tlvs(public).unwrap();
        assert_eq!(unique_field(&fields, 0x81).unwrap().len(), 128);
        assert_eq!(unique_field(&fields, 0x82), Some(&[1, 0, 1][..]));
        let SoftwarePrivateKey::Signing(private_key) = &piv.keys.get(&0x9e).unwrap().private_key
        else {
            unreachable!();
        };
        let public_key = private_key.public_key();

        let mut encoded_input = vec![0; 128];
        encoded_input[1] = 1;
        encoded_input[127] = 0x55;
        let request = encode_tlv(
            0x7c,
            &[encode_tlv(0x82, &[]), encode_tlv(0x81, &encoded_input)].concat(),
        );
        let response = piv.transmit(&command(
            INS_AUTHENTICATE,
            PivAlgorithm::Rsa1024 as u8,
            0x9e,
            &request,
        ));
        assert_eq!(response.status, 0x9000);
        let signature =
            decode_exact_tlv(decode_exact_tlv(&response.data, 0x7c).unwrap(), 0x82).unwrap();
        assert_eq!(signature.len(), 128);
        public_key
            .verify_rsa_raw(&encoded_input, signature)
            .unwrap();

        let encoded = piv.persistent_state().unwrap();
        let mut restored = PivApplet::from_persistent_state(15, [5, 8, 1], &encoded).unwrap();
        let response = restored.transmit(&command(
            INS_AUTHENTICATE,
            PivAlgorithm::Rsa1024 as u8,
            0x9e,
            &request,
        ));
        assert_eq!(response.status, 0x9000);
    }

    #[test]
    fn imports_and_validates_rsa_crt_components() {
        let imported = SoftwareSigningKey::generate_for_kind(KeyKind::Rsa {
            modulus_bits: 1_024,
        })
        .unwrap();
        let components = imported.rsa_crt_components().unwrap();
        let mut request = Vec::new();
        for (index, component) in components.iter().enumerate() {
            push_tlv(&mut request, index as u32 + 1, component);
        }
        push_tlv(&mut request, 0xaa, &[PIN_POLICY_NEVER]);
        let mut piv = PivApplet::new(16, [5, 8, 0]);
        authenticate_management(
            &mut piv,
            ManagementAlgorithm::Aes192,
            &FACTORY_MANAGEMENT_KEY,
        );
        assert_eq!(
            piv.transmit(&command(
                INS_IMPORT_KEY,
                PivAlgorithm::Rsa1024 as u8,
                0x9a,
                &request,
            ))
            .status,
            0x9000
        );
        let metadata = piv.transmit(&command(INS_GET_METADATA, 0, 0x9a, &[]));
        let fields = decode_tlvs(&metadata.data).unwrap();
        assert_eq!(unique_field(&fields, 0x01), Some(&[0x06][..]));
        assert_eq!(unique_field(&fields, 0x03), Some(&[ORIGIN_IMPORTED][..]));

        let mut corrupted = Vec::new();
        for (tag, value) in decode_tlvs(&request).unwrap() {
            let mut value = value.to_vec();
            if tag == 0x05 {
                *value.last_mut().unwrap() ^= 1;
            }
            push_tlv(&mut corrupted, tag, &value);
        }
        assert_eq!(
            piv.transmit(&command(
                INS_IMPORT_KEY,
                PivAlgorithm::Rsa1024 as u8,
                0x82,
                &corrupted,
            ))
            .status,
            STATUS_INCORRECT_DATA
        );
    }

    #[test]
    fn derives_matching_piv_ecdh_shared_secrets() {
        let mut piv = PivApplet::new(19, [5, 8, 0]);
        authenticate_management(
            &mut piv,
            ManagementAlgorithm::Aes192,
            &FACTORY_MANAGEMENT_KEY,
        );
        let generate = encode_tlv(
            0xac,
            &[
                encode_tlv(0x80, &[PivAlgorithm::EccP256 as u8]),
                encode_tlv(0xaa, &[PIN_POLICY_NEVER]),
            ]
            .concat(),
        );
        for slot in [0x9d, 0x82] {
            assert_eq!(
                piv.transmit(&command(INS_GENERATE_ASYMMETRIC, 0, slot, &generate))
                    .status,
                0x9000
            );
        }
        let SoftwarePublicKey::Ec {
            uncompressed: first_public,
            ..
        } = (match &piv.keys.get(&0x9d).unwrap().private_key {
            SoftwarePrivateKey::Signing(key) => key.public_key(),
            SoftwarePrivateKey::Montgomery(_) | SoftwarePrivateKey::MlKem(_) => unreachable!(),
        })
        else {
            unreachable!();
        };
        let SoftwarePublicKey::Ec {
            uncompressed: second_public,
            ..
        } = (match &piv.keys.get(&0x82).unwrap().private_key {
            SoftwarePrivateKey::Signing(key) => key.public_key(),
            SoftwarePrivateKey::Montgomery(_) | SoftwarePrivateKey::MlKem(_) => unreachable!(),
        })
        else {
            unreachable!();
        };
        let SoftwarePrivateKey::Signing(private_key) = &piv.keys.get(&0x82).unwrap().private_key
        else {
            unreachable!();
        };
        let expected = derive_with_signing_key(private_key, &first_public).unwrap();
        let request = encode_tlv(
            0x7c,
            &[encode_tlv(0x82, &[]), encode_tlv(0x85, &second_public)].concat(),
        );
        let response = piv.transmit(&command(
            INS_AUTHENTICATE,
            PivAlgorithm::EccP256 as u8,
            0x9d,
            &request,
        ));
        assert_eq!(response.status, 0x9000);
        assert_eq!(
            decode_exact_tlv(decode_exact_tlv(&response.data, 0x7c).unwrap(), 0x82,).unwrap(),
            expected.as_slice()
        );
    }

    #[test]
    fn generates_imports_persists_and_signs_with_ed25519() {
        let mut piv = PivApplet::new(20, [5, 8, 0]);
        authenticate_management(
            &mut piv,
            ManagementAlgorithm::Aes192,
            &FACTORY_MANAGEMENT_KEY,
        );
        let generate = encode_tlv(
            0xac,
            &[
                encode_tlv(0x80, &[PivAlgorithm::Ed25519 as u8]),
                encode_tlv(0xaa, &[PIN_POLICY_NEVER]),
            ]
            .concat(),
        );
        let response = piv.transmit(&command(INS_GENERATE_ASYMMETRIC, 0, 0x9e, &generate));
        assert_eq!(response.status, 0x9000);
        let public = decode_exact_tlv(decode_exact_tlv(&response.data, 0x7f49).unwrap(), 0x86)
            .unwrap()
            .to_vec();
        assert_eq!(public.len(), 32);

        let message = b"Ed25519 signs the complete PIV message rather than a caller-sized digest";
        let request = encode_tlv(
            0x7c,
            &[encode_tlv(0x82, &[]), encode_tlv(0x81, message)].concat(),
        );
        let response = piv.transmit(&command(
            INS_AUTHENTICATE,
            PivAlgorithm::Ed25519 as u8,
            0x9e,
            &request,
        ));
        assert_eq!(response.status, 0x9000);
        let signature =
            decode_exact_tlv(decode_exact_tlv(&response.data, 0x7c).unwrap(), 0x82).unwrap();
        let verifying_key =
            ed25519_dalek::VerifyingKey::from_bytes(public.as_slice().try_into().unwrap()).unwrap();
        let signature = ed25519_dalek::Signature::from_slice(signature).unwrap();
        verifying_key.verify_strict(message, &signature).unwrap();

        let encoded = piv.persistent_state().unwrap();
        let mut restored = PivApplet::from_persistent_state(20, [5, 8, 1], &encoded).unwrap();
        let metadata = restored.transmit(&command(INS_GET_METADATA, 0, 0x9e, &[]));
        assert_eq!(metadata.status, 0x9000);
        let fields = decode_tlvs(&metadata.data).unwrap();
        assert_eq!(unique_field(&fields, 0x01), Some(&[0xe0][..]));
        assert_eq!(unique_field(&fields, 0x03), Some(&[ORIGIN_GENERATED][..]));
        assert_eq!(
            decode_exact_tlv(unique_field(&fields, 0x04).unwrap(), 0x86),
            Some(public.as_slice())
        );

        authenticate_management(
            &mut restored,
            ManagementAlgorithm::Aes192,
            &FACTORY_MANAGEMENT_KEY,
        );
        let seed = [0x5a; 32];
        let import = [
            encode_tlv(0x07, &seed),
            encode_tlv(0xaa, &[PIN_POLICY_NEVER]),
        ]
        .concat();
        assert_eq!(
            restored
                .transmit(&command(
                    INS_IMPORT_KEY,
                    PivAlgorithm::Ed25519 as u8,
                    0x82,
                    &import,
                ))
                .status,
            0x9000
        );
        let imported = SoftwareSigningKey::from_serialized_for_kind(
            KeyKind::Edwards(EdwardsCurve::Ed25519),
            &seed,
        )
        .unwrap();
        let SoftwarePublicKey::Edwards {
            curve: EdwardsCurve::Ed25519,
            public_key: expected_public,
        } = imported.public_key()
        else {
            unreachable!();
        };
        let metadata = restored.transmit(&command(INS_GET_METADATA, 0, 0x82, &[]));
        let fields = decode_tlvs(&metadata.data).unwrap();
        assert_eq!(unique_field(&fields, 0x03), Some(&[ORIGIN_IMPORTED][..]));
        assert_eq!(
            decode_exact_tlv(unique_field(&fields, 0x04).unwrap(), 0x86),
            Some(expected_public.as_slice())
        );
    }

    #[test]
    fn generates_imports_persists_and_agrees_with_x25519() {
        let mut piv = PivApplet::new(21, [5, 8, 0]);
        authenticate_management(
            &mut piv,
            ManagementAlgorithm::Aes192,
            &FACTORY_MANAGEMENT_KEY,
        );
        let generate = encode_tlv(
            0xac,
            &[
                encode_tlv(0x80, &[PivAlgorithm::X25519 as u8]),
                encode_tlv(0xaa, &[PIN_POLICY_NEVER]),
            ]
            .concat(),
        );
        let response = piv.transmit(&command(INS_GENERATE_ASYMMETRIC, 0, 0x9d, &generate));
        assert_eq!(response.status, 0x9000);
        let public = decode_exact_tlv(decode_exact_tlv(&response.data, 0x7f49).unwrap(), 0x86)
            .unwrap()
            .to_vec();
        assert_eq!(public.len(), 32);

        let peer = SoftwareMontgomeryKey::generate(MontgomeryCurve::X25519).unwrap();
        let peer_public = peer.public_key();
        let expected = peer.derive(&public).unwrap();
        let request = encode_tlv(
            0x7c,
            &[encode_tlv(0x82, &[]), encode_tlv(0x85, &peer_public)].concat(),
        );
        let response = piv.transmit(&command(
            INS_AUTHENTICATE,
            PivAlgorithm::X25519 as u8,
            0x9d,
            &request,
        ));
        assert_eq!(response.status, 0x9000);
        let actual =
            decode_exact_tlv(decode_exact_tlv(&response.data, 0x7c).unwrap(), 0x82).unwrap();
        assert_eq!(actual, expected.as_slice());

        let encoded = piv.persistent_state().unwrap();
        let mut restored = PivApplet::from_persistent_state(21, [5, 8, 1], &encoded).unwrap();
        let response = restored.transmit(&command(
            INS_AUTHENTICATE,
            PivAlgorithm::X25519 as u8,
            0x9d,
            &request,
        ));
        assert_eq!(response.status, 0x9000);
        assert_eq!(
            decode_exact_tlv(decode_exact_tlv(&response.data, 0x7c).unwrap(), 0x82,),
            Some(expected.as_slice())
        );

        authenticate_management(
            &mut restored,
            ManagementAlgorithm::Aes192,
            &FACTORY_MANAGEMENT_KEY,
        );
        let seed = [0xa5; 32];
        let import = [
            encode_tlv(0x08, &seed),
            encode_tlv(0xaa, &[PIN_POLICY_NEVER]),
        ]
        .concat();
        assert_eq!(
            restored
                .transmit(&command(
                    INS_IMPORT_KEY,
                    PivAlgorithm::X25519 as u8,
                    0x82,
                    &import,
                ))
                .status,
            0x9000
        );
        let imported =
            SoftwareMontgomeryKey::from_serialized(MontgomeryCurve::X25519, &seed).unwrap();
        let expected_public = imported.public_key();
        let metadata = restored.transmit(&command(INS_GET_METADATA, 0, 0x82, &[]));
        let fields = decode_tlvs(&metadata.data).unwrap();
        assert_eq!(unique_field(&fields, 0x01), Some(&[0xe1][..]));
        assert_eq!(unique_field(&fields, 0x03), Some(&[ORIGIN_IMPORTED][..]));
        assert_eq!(
            decode_exact_tlv(unique_field(&fields, 0x04).unwrap(), 0x86),
            Some(expected_public.as_slice())
        );

        let noncontributory = encode_tlv(
            0x7c,
            &[encode_tlv(0x82, &[]), encode_tlv(0x85, &[0; 32])].concat(),
        );
        assert_eq!(
            restored
                .transmit(&command(
                    INS_AUTHENTICATE,
                    PivAlgorithm::X25519 as u8,
                    0x82,
                    &noncontributory,
                ))
                .status,
            STATUS_INCORRECT_DATA
        );
    }

    #[test]
    fn verifies_changes_and_unblocks_pin_references() {
        let mut piv = PivApplet::new(1, [5, 8, 0]);
        assert_eq!(
            piv.transmit(&command(INS_VERIFY, 0, REFERENCE_PIN, &[]))
                .status,
            0x63c3
        );
        assert_eq!(
            piv.transmit(&command(INS_VERIFY, 0, REFERENCE_PIN, &[0; 8]))
                .status,
            0x63c2
        );
        assert!(piv.take_persistent_change());
        assert_eq!(
            piv.transmit(&command(INS_VERIFY, 0, REFERENCE_PIN, &FACTORY_PIN))
                .status,
            0x9000
        );
        assert_eq!(
            piv.transmit(&command(INS_VERIFY, 0, REFERENCE_PIN, &[]))
                .status,
            0x9000
        );

        let new_pin = [b'A', b'B', b'C', b'D', b'E', b'F', 0xff, 0xff];
        let change = [FACTORY_PIN.as_slice(), new_pin.as_slice()].concat();
        assert_eq!(
            piv.transmit(&command(INS_CHANGE_REFERENCE, 0, REFERENCE_PIN, &change))
                .status,
            0x9000
        );
        piv.reset_connection();
        assert_eq!(
            piv.transmit(&command(INS_VERIFY, 0, REFERENCE_PIN, &new_pin))
                .status,
            0x9000
        );

        let new_puk = *b"ABCDEFGH";
        let change_puk = [FACTORY_PUK.as_slice(), new_puk.as_slice()].concat();
        assert_eq!(
            piv.transmit(&command(
                INS_CHANGE_REFERENCE,
                0,
                REFERENCE_PUK,
                &change_puk,
            ))
            .status,
            0x9000
        );

        let restored = [new_puk.as_slice(), FACTORY_PIN.as_slice()].concat();
        assert_eq!(
            piv.transmit(&command(INS_RESET_RETRY, 0, REFERENCE_PIN, &restored))
                .status,
            0x9000
        );
        assert_eq!(
            piv.transmit(&command(INS_VERIFY, 0, REFERENCE_PIN, &FACTORY_PIN))
                .status,
            0x9000
        );
    }

    #[test]
    fn pin_deauthentication_clears_pin_once_but_not_management_authentication() {
        let mut piv = PivApplet::new(21, [5, 8, 0]);
        authenticate_management(
            &mut piv,
            ManagementAlgorithm::Aes192,
            &FACTORY_MANAGEMENT_KEY,
        );
        let generate = encode_tlv(0xac, &encode_tlv(0x80, &[PivAlgorithm::EccP256 as u8]));
        assert_eq!(
            piv.transmit(&command(INS_GENERATE_ASYMMETRIC, 0, 0x82, &generate))
                .status,
            0x9000
        );
        assert_eq!(piv.keys[&0x82].pin_policy, PIN_POLICY_ONCE);
        assert_eq!(
            piv.transmit(&command(INS_VERIFY, 0, REFERENCE_PIN, &FACTORY_PIN))
                .status,
            0x9000
        );

        let request = signing_request(&[0x31; 32]);
        let sign = command(
            INS_AUTHENTICATE,
            PivAlgorithm::EccP256 as u8,
            0x82,
            &request,
        );
        assert_eq!(piv.transmit(&sign).status, 0x9000);
        assert_eq!(piv.transmit(&sign).status, 0x9000);
        assert!(piv.pin_verified);
        assert!(piv.management_authenticated);

        assert_eq!(
            piv.transmit(&command(INS_VERIFY, 0xff, REFERENCE_PIN, &[]))
                .status,
            0x9000
        );
        assert!(!piv.pin_verified);
        assert!(piv.management_authenticated);
        assert_eq!(piv.transmit(&sign).status, STATUS_SECURITY_NOT_SATISFIED);

        assert_eq!(
            piv.transmit(&command(INS_VERIFY, 0, REFERENCE_PIN, &FACTORY_PIN))
                .status,
            0x9000
        );
        assert_eq!(piv.transmit(&sign).status, 0x9000);
        assert_eq!(piv.transmit(&sign).status, 0x9000);
    }

    #[test]
    fn sets_retry_limits_only_after_both_required_authentications() {
        let mut piv = PivApplet::new(17, [5, 8, 0]);
        assert_eq!(
            piv.transmit(&command(INS_SET_RETRIES, 20, 2, &[])).status,
            STATUS_SECURITY_NOT_SATISFIED
        );
        authenticate_management(
            &mut piv,
            ManagementAlgorithm::Aes192,
            &FACTORY_MANAGEMENT_KEY,
        );
        assert_eq!(
            piv.transmit(&command(INS_SET_RETRIES, 20, 2, &[])).status,
            STATUS_SECURITY_NOT_SATISFIED
        );
        assert_eq!(
            piv.transmit(&command(INS_VERIFY, 0, REFERENCE_PIN, &FACTORY_PIN))
                .status,
            0x9000
        );
        assert_eq!(
            piv.transmit(&command(INS_SET_RETRIES, 20, 2, &[])).status,
            0x9000
        );
        assert_eq!(
            piv.transmit(&command(INS_VERIFY, 0, REFERENCE_PIN, &[]))
                .status,
            0x63cf
        );
        let metadata = piv.transmit(&command(INS_GET_METADATA, 0, REFERENCE_PIN, &[]));
        assert_eq!(
            decode_tlvs(&metadata.data)
                .unwrap()
                .into_iter()
                .find(|(tag, _)| *tag == 0x06)
                .unwrap()
                .1,
            &[20, 20]
        );
        assert_eq!(
            piv.transmit(&command(INS_GET_METADATA, 0, REFERENCE_PUK, &[]))
                .data
                .last(),
            Some(&2)
        );
    }

    #[test]
    fn resets_the_piv_application_only_after_pin_and_puk_are_blocked() {
        let mut piv = PivApplet::new(18, [5, 8, 0]);
        assert_eq!(
            piv.transmit(&command(INS_RESET, 0, 0, &[])).status,
            STATUS_CONDITIONS_NOT_SATISFIED
        );
        for expected in [0x63c2, 0x63c1, STATUS_AUTHENTICATION_BLOCKED] {
            assert_eq!(
                piv.transmit(&command(INS_VERIFY, 0, REFERENCE_PIN, &[0; 8]))
                    .status,
                expected
            );
        }
        let wrong_puk = [[0_u8; 8].as_slice(), FACTORY_PIN.as_slice()].concat();
        for expected in [0x63c2, 0x63c1, STATUS_AUTHENTICATION_BLOCKED] {
            assert_eq!(
                piv.transmit(&command(INS_CHANGE_REFERENCE, 0, REFERENCE_PUK, &wrong_puk,))
                    .status,
                expected
            );
        }
        piv.objects.insert(0x5f_ff10, vec![1, 2, 3]);
        assert_eq!(piv.transmit(&command(INS_RESET, 0, 0, &[])).status, 0x9000);
        assert!(piv.objects.is_empty());
        assert!(piv.keys.is_empty());
        assert_eq!(piv.pin.maximum_retries, FACTORY_RETRIES);
        assert_eq!(piv.puk.maximum_retries, FACTORY_RETRIES);
        assert_eq!(piv.management_key.as_slice(), FACTORY_MANAGEMENT_KEY);
        assert!(piv.take_persistent_change());
        assert_eq!(
            piv.transmit(&command(INS_VERIFY, 0, REFERENCE_PIN, &FACTORY_PIN))
                .status,
            0x9000
        );
    }

    #[test]
    fn mutually_authenticates_and_rotates_the_management_key() {
        let mut piv = PivApplet::new(1, [5, 8, 0]);
        authenticate_management(
            &mut piv,
            ManagementAlgorithm::Aes192,
            &FACTORY_MANAGEMENT_KEY,
        );

        let new_key = [0x22; 16];
        let mut set_key = vec![
            ManagementAlgorithm::Aes128 as u8,
            REFERENCE_MANAGEMENT_KEY,
            16,
        ];
        set_key.extend_from_slice(&new_key);
        assert_eq!(
            piv.transmit(&command(INS_SET_MANAGEMENT_KEY, 0xff, 0xfd, &set_key))
                .status,
            STATUS_INCORRECT_DATA
        );
        assert_eq!(
            piv.transmit(&command(INS_SET_MANAGEMENT_KEY, 0xff, 0xfe, &set_key))
                .status,
            0x9000
        );
        assert!(piv.take_persistent_change());
        let metadata = piv.transmit(&command(INS_GET_METADATA, 0, REFERENCE_MANAGEMENT_KEY, &[]));
        let metadata = decode_tlvs(&metadata.data).unwrap();
        assert_eq!(
            unique_field(&metadata, 0x01),
            Some(&[ManagementAlgorithm::Aes128 as u8][..])
        );
        assert_eq!(
            unique_field(&metadata, 0x02),
            Some(&[0, TOUCH_POLICY_ALWAYS][..])
        );
        assert_eq!(unique_field(&metadata, 0x05), Some(&[0][..]));

        piv.reset_connection();
        let witness = encode_tlv(0x7c, &encode_tlv(0x80, &[]));
        let authenticate = command(
            INS_AUTHENTICATE,
            ManagementAlgorithm::Aes128 as u8,
            REFERENCE_MANAGEMENT_KEY,
            &witness,
        );
        assert!(matches!(
            piv.exchange(&authenticate, PresenceAuthorization::Absent),
            PivExchange::PresenceRequired(UserPresencePolicy::Always)
        ));
        assert_eq!(
            complete(piv.exchange(&authenticate, PresenceAuthorization::Granted)).status,
            0x9000
        );

        let encoded = piv.persistent_state().unwrap();
        let mut restored = PivApplet::from_persistent_state(1, [5, 8, 0], &encoded).unwrap();
        let metadata =
            restored.transmit(&command(INS_GET_METADATA, 0, REFERENCE_MANAGEMENT_KEY, &[]));
        assert_eq!(
            unique_field(&decode_tlvs(&metadata.data).unwrap(), 0x02),
            Some(&[0, TOUCH_POLICY_ALWAYS][..])
        );
        assert_eq!(
            unique_field(&decode_tlvs(&metadata.data).unwrap(), 0x05),
            Some(&[0][..])
        );
    }

    #[test]
    fn mutually_authenticates_and_persists_a_triple_des_management_key() {
        let mut piv = PivApplet::new(1, [5, 8, 0]);
        authenticate_management(
            &mut piv,
            ManagementAlgorithm::Aes192,
            &FACTORY_MANAGEMENT_KEY,
        );

        let new_key = [0x22; 24];
        let mut set_key = vec![
            ManagementAlgorithm::TripleDes as u8,
            REFERENCE_MANAGEMENT_KEY,
            new_key.len() as u8,
        ];
        set_key.extend_from_slice(&new_key);
        assert_eq!(
            piv.transmit(&command(INS_SET_MANAGEMENT_KEY, 0xff, 0xff, &set_key))
                .status,
            0x9000
        );

        let metadata = piv.transmit(&command(INS_GET_METADATA, 0, REFERENCE_MANAGEMENT_KEY, &[]));
        assert_eq!(
            unique_field(&decode_tlvs(&metadata.data).unwrap(), 0x01),
            Some(&[ManagementAlgorithm::TripleDes as u8][..])
        );

        let encoded = piv.persistent_state().unwrap();
        let mut restored = PivApplet::from_persistent_state(1, [5, 8, 0], &encoded).unwrap();
        authenticate_management(&mut restored, ManagementAlgorithm::TripleDes, &new_key);

        restored.reset_connection();
        let request = encode_tlv(0x7c, &encode_tlv(0x81, &[]));
        let challenge = restored.transmit(&command(
            INS_AUTHENTICATE,
            ManagementAlgorithm::TripleDes as u8,
            REFERENCE_MANAGEMENT_KEY,
            &request,
        ));
        assert_eq!(challenge.status, 0x9000);
        let dynamic = decode_exact_tlv(&challenge.data, 0x7c).unwrap();
        let challenge = decode_exact_tlv(dynamic, 0x81).unwrap();
        let response = ManagementAlgorithm::TripleDes
            .crypt_block(&new_key, challenge, Direction::Encrypt)
            .unwrap();
        let request = encode_tlv(0x7c, &encode_tlv(0x82, &response));
        assert_eq!(
            restored
                .transmit(&command(
                    INS_AUTHENTICATE,
                    ManagementAlgorithm::TripleDes as u8,
                    REFERENCE_MANAGEMENT_KEY,
                    &request,
                ))
                .status,
            0x9000
        );
        assert!(restored.management_authenticated);
    }

    #[test]
    fn persistent_state_restores_secrets_and_retry_counters_without_session_auth() {
        let mut piv = PivApplet::new(7, [5, 8, 0]);
        assert_eq!(
            piv.transmit(&command(INS_VERIFY, 0, REFERENCE_PIN, &[0; 8]))
                .status,
            0x63c2
        );
        let new_puk = *b"87654321";
        let change_puk = [FACTORY_PUK.as_slice(), new_puk.as_slice()].concat();
        assert_eq!(
            piv.transmit(&command(
                INS_CHANGE_REFERENCE,
                0,
                REFERENCE_PUK,
                &change_puk,
            ))
            .status,
            0x9000
        );
        authenticate_management(
            &mut piv,
            ManagementAlgorithm::Aes192,
            &FACTORY_MANAGEMENT_KEY,
        );
        let new_management_key = [0x22; 16];
        let mut set_key = vec![
            ManagementAlgorithm::Aes128 as u8,
            REFERENCE_MANAGEMENT_KEY,
            new_management_key.len() as u8,
        ];
        set_key.extend_from_slice(&new_management_key);
        assert_eq!(
            piv.transmit(&command(INS_SET_MANAGEMENT_KEY, 0xff, 0xff, &set_key))
                .status,
            0x9000
        );

        let encoded = piv.persistent_state().unwrap();
        assert_eq!(
            PivApplet::from_persistent_state(8, [5, 8, 0], &encoded).unwrap_err(),
            "persistent PIV state belongs to another device serial"
        );
        let mut restored = PivApplet::from_persistent_state(7, [5, 8, 1], &encoded).unwrap();
        assert!(!restored.take_persistent_change());
        assert_eq!(
            restored
                .transmit(&command(INS_VERIFY, 0, REFERENCE_PIN, &[]))
                .status,
            0x63c2
        );
        assert_eq!(
            restored
                .transmit(&command(INS_SET_MANAGEMENT_KEY, 0xff, 0xff, &set_key))
                .status,
            STATUS_SECURITY_NOT_SATISFIED
        );
        authenticate_management(
            &mut restored,
            ManagementAlgorithm::Aes128,
            &new_management_key,
        );

        let unblock = [new_puk.as_slice(), FACTORY_PIN.as_slice()].concat();
        assert_eq!(
            restored
                .transmit(&command(INS_RESET_RETRY, 0, REFERENCE_PIN, &unblock))
                .status,
            0x9000
        );
        assert_eq!(
            restored
                .transmit(&command(INS_VERIFY, 0, REFERENCE_PIN, &FACTORY_PIN))
                .status,
            0x9000
        );
    }
}
