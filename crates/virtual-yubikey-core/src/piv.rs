use crate::{
    crypto::{aes_ecb_block, Direction, AES_BLOCK_SIZE},
    CommandApdu, ResponseApdu,
};
use std::fmt;
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
const INS_AUTHENTICATE: u8 = 0x87;
const INS_GET_DATA: u8 = 0xcb;
const INS_GET_VERSION: u8 = 0xfd;
const INS_GET_SERIAL: u8 = 0xf8;
const INS_GET_METADATA: u8 = 0xf7;
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

pub(crate) fn select_response() -> Vec<u8> {
    PIV_SELECT_RESPONSE.to_vec()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
enum ManagementAlgorithm {
    Aes128 = 0x08,
    Aes192 = 0x0a,
    Aes256 = 0x0c,
}

impl ManagementAlgorithm {
    fn from_id(id: u8) -> Option<Self> {
        match id {
            0x08 => Some(Self::Aes128),
            0x0a => Some(Self::Aes192),
            0x0c => Some(Self::Aes256),
            _ => None,
        }
    }

    const fn key_length(self) -> usize {
        match self {
            Self::Aes128 => 16,
            Self::Aes192 => 24,
            Self::Aes256 => 32,
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
            0x63c0 | u16::from(self.retries)
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
    management_challenge: Option<Zeroizing<Vec<u8>>>,
    management_authenticated: bool,
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
            .field("management_authenticated", &self.management_authenticated)
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
            management_challenge: None,
            management_authenticated: false,
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
                        Some(decoder.u8().map_err(|_| {
                            "persistent PIV state has an invalid management algorithm"
                        })?);
                }
                10 if management_key.is_none() => {
                    management_key = Some(Zeroizing::new(
                        decoder
                            .bytes()
                            .map_err(|_| "persistent PIV state has an invalid management key")?
                            .to_vec(),
                    ));
                }
                _ => decoder
                    .skip()
                    .map_err(|_| "persistent PIV state contains invalid data")?,
            }
        }
        if decoder.position() != encoded.len() {
            return Err("persistent PIV state has trailing data");
        }
        if version != Some(1) {
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
            management_challenge: None,
            management_authenticated: false,
            persistent_change: false,
        })
    }

    pub(crate) fn persistent_state(&self) -> Result<Vec<u8>, &'static str> {
        let mut encoder = minicbor::Encoder::new(Vec::new());
        encoder
            .map(10)
            .map_err(|_| "cannot encode persistent PIV state")?
            .u8(1)
            .map_err(|_| "cannot encode persistent PIV state")?
            .u8(1)
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
            .map_err(|_| "cannot encode persistent PIV state")?;
        Ok(encoder.into_writer())
    }

    pub(crate) fn take_persistent_change(&mut self) -> bool {
        std::mem::take(&mut self.persistent_change)
    }

    pub(crate) fn transmit(&mut self, command: &CommandApdu<'_>) -> ResponseApdu {
        if command.cla != 0 {
            return ResponseApdu::status(STATUS_CLASS_NOT_SUPPORTED);
        }
        match command.ins {
            INS_GET_VERSION if empty_command(command, 0, 0) => {
                ResponseApdu::success(self.firmware.to_vec())
            }
            INS_GET_SERIAL if empty_command(command, 0, 0) => {
                ResponseApdu::success(self.serial.to_be_bytes().to_vec())
            }
            INS_GET_METADATA if command.p1 == 0 && command.data.is_empty() => {
                self.get_metadata(command.p2)
            }
            INS_GET_DATA if command.p1 == 0x3f && command.p2 == 0xff => self.get_data(command.data),
            INS_VERIFY if command.p1 == 0 && command.p2 == REFERENCE_PIN => {
                self.verify_pin(command.data)
            }
            INS_CHANGE_REFERENCE if command.p1 == 0 => {
                self.change_reference(command.p2, command.data)
            }
            INS_RESET_RETRY if command.p1 == 0 && command.p2 == REFERENCE_PIN => {
                self.reset_retry(command.data)
            }
            INS_AUTHENTICATE => self.authenticate_management(command),
            INS_SET_MANAGEMENT_KEY => self.set_management_key(command),
            INS_GET_VERSION | INS_GET_SERIAL | INS_GET_METADATA | INS_GET_DATA | INS_VERIFY
            | INS_CHANGE_REFERENCE | INS_RESET_RETRY => {
                ResponseApdu::status(STATUS_INCORRECT_PARAMETERS)
            }
            _ => ResponseApdu::status(STATUS_INSTRUCTION_NOT_SUPPORTED),
        }
    }

    fn get_metadata(&self, reference: u8) -> ResponseApdu {
        let mut data = Vec::new();
        match reference {
            REFERENCE_PIN => self.push_reference_metadata(&mut data, &self.pin),
            REFERENCE_PUK => self.push_reference_metadata(&mut data, &self.puk),
            REFERENCE_MANAGEMENT_KEY => {
                push_tlv(&mut data, 0x01, &[self.management_algorithm as u8]);
                push_tlv(&mut data, 0x02, &[0, 1]);
                push_tlv(&mut data, 0x05, &[1]);
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
        if object_id != 0x7e {
            return ResponseApdu::status(STATUS_NOT_FOUND);
        }
        let mut response = Vec::new();
        push_tlv(&mut response, 0x53, &DISCOVERY_OBJECT);
        ResponseApdu::success(response)
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

    fn authenticate_management(&mut self, command: &CommandApdu<'_>) -> ResponseApdu {
        if command.p2 != REFERENCE_MANAGEMENT_KEY || command.p1 != self.management_algorithm as u8 {
            return ResponseApdu::status(STATUS_INCORRECT_PARAMETERS);
        }
        let Some(dynamic) = decode_exact_tlv(command.data, 0x7c) else {
            return ResponseApdu::status(STATUS_INCORRECT_DATA);
        };
        let Some(fields) = decode_tlvs(dynamic) else {
            return ResponseApdu::status(STATUS_INCORRECT_DATA);
        };

        if fields.as_slice() == [(0x80, &[][..])] {
            let mut challenge = Zeroizing::new(vec![0_u8; AES_BLOCK_SIZE]);
            if getrandom::fill(challenge.as_mut()).is_err() {
                return ResponseApdu::status(STATUS_INTERNAL_ERROR);
            }
            let Ok(cryptogram) =
                aes_ecb_block(&self.management_key, &challenge, Direction::Encrypt)
            else {
                return ResponseApdu::status(STATUS_INTERNAL_ERROR);
            };
            self.management_challenge = Some(challenge);
            return ResponseApdu::success(encode_tlv(0x7c, &encode_tlv(0x80, &cryptogram)));
        }

        let Some(card_response) = unique_field(&fields, 0x80) else {
            return ResponseApdu::status(STATUS_INCORRECT_DATA);
        };
        let Some(host_challenge) = unique_field(&fields, 0x81) else {
            return ResponseApdu::status(STATUS_INCORRECT_DATA);
        };
        if card_response.len() != AES_BLOCK_SIZE || host_challenge.len() != AES_BLOCK_SIZE {
            return ResponseApdu::status(STATUS_WRONG_LENGTH);
        }
        let Some(expected) = self.management_challenge.take() else {
            return ResponseApdu::status(STATUS_CONDITIONS_NOT_SATISFIED);
        };
        if !bool::from(expected.as_slice().ct_eq(card_response)) {
            self.management_authenticated = false;
            return ResponseApdu::status(STATUS_SECURITY_NOT_SATISFIED);
        }
        let Ok(cryptogram) =
            aes_ecb_block(&self.management_key, host_challenge, Direction::Encrypt)
        else {
            return ResponseApdu::status(STATUS_INTERNAL_ERROR);
        };
        self.management_authenticated = true;
        ResponseApdu::success(encode_tlv(0x7c, &encode_tlv(0x82, &cryptogram)))
    }

    fn set_management_key(&mut self, command: &CommandApdu<'_>) -> ResponseApdu {
        if command.p1 != 0xff || !matches!(command.p2, 0xfe | 0xff) {
            return ResponseApdu::status(STATUS_INCORRECT_PARAMETERS);
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
    if !(6..=8).contains(&length)
        || !value[..length].iter().all(u8::is_ascii_digit)
        || !value[length..].iter().all(|byte| *byte == 0xff)
    {
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

fn decode_object_id(request: &[u8]) -> Option<u32> {
    let value = decode_exact_tlv(request, 0x5c)?;
    if !(1..=3).contains(&value.len()) {
        return None;
    }
    Some(
        value
            .iter()
            .fold(0_u32, |object, byte| (object << 8) | u32::from(*byte)),
    )
}

fn decode_exact_tlv(input: &[u8], expected_tag: u8) -> Option<&[u8]> {
    let (tag, value, remaining) = decode_tlv(input)?;
    (tag == expected_tag && remaining.is_empty()).then_some(value)
}

fn decode_tlvs(mut input: &[u8]) -> Option<Vec<(u8, &[u8])>> {
    let mut fields = Vec::new();
    while !input.is_empty() {
        let (tag, value, remaining) = decode_tlv(input)?;
        fields.push((tag, value));
        input = remaining;
    }
    Some(fields)
}

fn decode_tlv(input: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (&tag, input) = input.split_first()?;
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

fn unique_field<'a>(fields: &[(u8, &'a [u8])], wanted: u8) -> Option<&'a [u8]> {
    let mut matching = fields
        .iter()
        .filter(|(tag, _)| *tag == wanted)
        .map(|(_, value)| *value);
    let value = matching.next()?;
    matching.next().is_none().then_some(value)
}

fn encode_tlv(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut output = Vec::new();
    output.push(tag);
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

fn push_tlv(output: &mut Vec<u8>, tag: u8, value: &[u8]) {
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
        let challenge = aes_ecb_block(key, encrypted_challenge, Direction::Decrypt).unwrap();

        let host_challenge = [0x5a; AES_BLOCK_SIZE];
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
            aes_ecb_block(key, cryptogram, Direction::Decrypt).unwrap(),
            host_challenge
        );
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

        let new_pin = [b'6', b'5', b'4', b'3', b'2', b'1', 0xff, 0xff];
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

        let restored = [FACTORY_PUK.as_slice(), FACTORY_PIN.as_slice()].concat();
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
            piv.transmit(&command(INS_SET_MANAGEMENT_KEY, 0xff, 0xff, &set_key))
                .status,
            0x9000
        );
        assert!(piv.take_persistent_change());
        assert_eq!(
            piv.transmit(&command(INS_GET_METADATA, 0, REFERENCE_MANAGEMENT_KEY, &[]))
                .data[2],
            ManagementAlgorithm::Aes128 as u8
        );
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
