//! Transport-neutral YubiHSM Auth smart-card applet.

use crate::{
    CommandApdu, PresenceAuthorization, ResponseApdu, UserPresencePolicy, presence::PresenceClient,
};
use software_key_core::{
    secure_channel::{scp03_cryptogram, scp03_key, x963_kdf_sha256},
    software_key_agreement::derive_with_signing_key,
    software_signing::{EcCurve, KeyKind, SoftwarePublicKey, SoftwareSigningKey},
    software_symmetric::aes_cmac,
};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

pub const HSMAUTH_AID: [u8; 8] = [0xa0, 0x00, 0x00, 0x05, 0x27, 0x21, 0x07, 0x01];

const TAG_LABEL: u8 = 0x71;
const TAG_LABEL_LIST: u8 = 0x72;
const TAG_CREDENTIAL_PASSWORD: u8 = 0x73;
const TAG_ALGORITHM: u8 = 0x74;
const TAG_KEY_ENC: u8 = 0x75;
const TAG_KEY_MAC: u8 = 0x76;
const TAG_CONTEXT: u8 = 0x77;
const TAG_RESPONSE: u8 = 0x78;
const TAG_VERSION: u8 = 0x79;
const TAG_TOUCH: u8 = 0x7a;
const TAG_MANAGEMENT_KEY: u8 = 0x7b;
const TAG_PUBLIC_KEY: u8 = 0x7c;
const TAG_PRIVATE_KEY: u8 = 0x7d;

const INS_PUT: u8 = 0x01;
const INS_DELETE: u8 = 0x02;
const INS_CALCULATE: u8 = 0x03;
const INS_GET_CHALLENGE: u8 = 0x04;
const INS_LIST: u8 = 0x05;
const INS_RESET: u8 = 0x06;
const INS_GET_VERSION: u8 = 0x07;
const INS_PUT_MANAGEMENT_KEY: u8 = 0x08;
const INS_GET_MANAGEMENT_KEY_RETRIES: u8 = 0x09;
const INS_GET_PUBLIC_KEY: u8 = 0x0a;
const INS_CHANGE_CREDENTIAL_PASSWORD: u8 = 0x0b;

const STATUS_VERIFY_FAILED: u16 = 0x63c0;
const STATUS_AUTHENTICATION_BLOCKED: u16 = 0x6983;
const STATUS_CONDITIONS_NOT_SATISFIED: u16 = 0x6985;
const STATUS_DUPLICATE_CREDENTIAL: u16 = 0x6983;
const STATUS_DATA_INVALID: u16 = 0x6984;
const STATUS_WRONG_DATA: u16 = 0x6a80;
const STATUS_NOT_ENOUGH_MEMORY: u16 = 0x6a84;
const STATUS_INCORRECT_PARAMETERS: u16 = 0x6a86;
const STATUS_NOT_FOUND: u16 = 0x6a88;
const STATUS_INSTRUCTION_NOT_SUPPORTED: u16 = 0x6d00;
const STATUS_CLASS_NOT_SUPPORTED: u16 = 0x6e00;
const STATUS_EXECUTION_ERROR: u16 = 0x6f00;

const MANAGEMENT_KEY_LENGTH: usize = 16;
const CREDENTIAL_PASSWORD_LENGTH: usize = 16;
const P256_PUBLIC_KEY_LENGTH: usize = 65;
const MAX_CREDENTIALS: usize = 30;
const MAX_RETRIES: u8 = 8;
const SCP11_SHARED_INFO: [u8; 3] = [0x3c, 0x88, 0x10];
const FACTORY_MANAGEMENT_KEY: [u8; MANAGEMENT_KEY_LENGTH] = [0; MANAGEMENT_KEY_LENGTH];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
enum Algorithm {
    Aes128YubicoAuthentication = 38,
    EcP256YubicoAuthentication = 39,
}

impl Algorithm {
    fn from_id(id: u8) -> Option<Self> {
        match id {
            38 => Some(Self::Aes128YubicoAuthentication),
            39 => Some(Self::EcP256YubicoAuthentication),
            _ => None,
        }
    }
}

enum CredentialSecret {
    Symmetric {
        enc: Zeroizing<[u8; 16]>,
        mac: Zeroizing<[u8; 16]>,
    },
    Asymmetric(SoftwareSigningKey),
}

impl CredentialSecret {
    fn algorithm(&self) -> Algorithm {
        match self {
            Self::Symmetric { .. } => Algorithm::Aes128YubicoAuthentication,
            Self::Asymmetric(_) => Algorithm::EcP256YubicoAuthentication,
        }
    }

    fn serialized(&self) -> Result<Zeroizing<Vec<u8>>, &'static str> {
        match self {
            Self::Symmetric { enc, mac } => {
                let mut encoded = Zeroizing::new(Vec::with_capacity(32));
                encoded.extend_from_slice(enc.as_slice());
                encoded.extend_from_slice(mac.as_slice());
                Ok(encoded)
            }
            Self::Asymmetric(key) => key
                .serialized()
                .map_err(|_| "cannot serialize YubiHSM Auth private key"),
        }
    }

    fn from_serialized(algorithm: Algorithm, encoded: &[u8]) -> Result<Self, &'static str> {
        match algorithm {
            Algorithm::Aes128YubicoAuthentication => {
                if encoded.len() != 32 {
                    return Err("persistent YubiHSM Auth AES key has the wrong length");
                }
                Ok(Self::Symmetric {
                    enc: Zeroizing::new(encoded[..16].try_into().unwrap()),
                    mac: Zeroizing::new(encoded[16..].try_into().unwrap()),
                })
            }
            Algorithm::EcP256YubicoAuthentication => {
                SoftwareSigningKey::from_serialized_for_kind(KeyKind::Ec(EcCurve::P256), encoded)
                    .map(Self::Asymmetric)
                    .map_err(|_| "persistent YubiHSM Auth P-256 key is invalid")
            }
        }
    }
}

struct Credential {
    label: String,
    secret: CredentialSecret,
    password: Zeroizing<[u8; CREDENTIAL_PASSWORD_LENGTH]>,
    touch_required: bool,
    retries: u8,
}

impl core::fmt::Debug for Credential {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("Credential")
            .field("label", &self.label)
            .field("algorithm", &self.secret.algorithm())
            .field("touch_required", &self.touch_required)
            .field("retries", &self.retries)
            .finish_non_exhaustive()
    }
}

enum Challenge {
    Asymmetric {
        label: String,
        ephemeral: Box<SoftwareSigningKey>,
        public: [u8; P256_PUBLIC_KEY_LENGTH],
    },
}

pub(crate) enum HsmAuthExchange {
    Complete(ResponseApdu),
    PresenceRequired(UserPresencePolicy),
}

impl From<ResponseApdu> for HsmAuthExchange {
    fn from(response: ResponseApdu) -> Self {
        Self::Complete(response)
    }
}

pub(crate) struct HsmAuthApplet {
    serial: u32,
    firmware: [u8; 3],
    management_key: Zeroizing<[u8; MANAGEMENT_KEY_LENGTH]>,
    management_retries: u8,
    credentials: Vec<Credential>,
    challenge: Option<Challenge>,
    presence: PresenceClient,
    persistent_change: bool,
}

impl core::fmt::Debug for HsmAuthApplet {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("HsmAuthApplet")
            .field("serial", &self.serial)
            .field("firmware", &self.firmware)
            .field("management_retries", &self.management_retries)
            .field("credential_count", &self.credentials.len())
            .field("challenge_pending", &self.challenge.is_some())
            .field("persistent_change", &self.persistent_change)
            .finish_non_exhaustive()
    }
}

impl HsmAuthApplet {
    pub(crate) fn new(serial: u32, firmware: [u8; 3]) -> Self {
        Self {
            serial,
            firmware,
            management_key: Zeroizing::new(FACTORY_MANAGEMENT_KEY),
            management_retries: MAX_RETRIES,
            credentials: Vec::new(),
            challenge: None,
            presence: PresenceClient::default(),
            persistent_change: false,
        }
    }

    pub(crate) fn select_response(&self) -> Vec<u8> {
        encode_tlv(TAG_VERSION, &self.firmware).expect("version TLV always fits")
    }

    pub(crate) fn reset_connection(&mut self) {
        self.challenge = None;
    }

    pub(crate) fn take_persistent_change(&mut self) -> bool {
        core::mem::take(&mut self.persistent_change)
    }

    pub(crate) fn exchange(
        &mut self,
        command: &CommandApdu<'_>,
        presence: PresenceAuthorization,
    ) -> HsmAuthExchange {
        if command.cla != 0 {
            return ResponseApdu::status(STATUS_CLASS_NOT_SUPPORTED).into();
        }
        if command.p2 != 0 && !(command.ins == INS_RESET && command.p2 == 0xad) {
            return ResponseApdu::status(STATUS_INCORRECT_PARAMETERS).into();
        }
        match command.ins {
            INS_PUT if command.p1 == 0 => self.put_credential(command.data).into(),
            INS_DELETE if command.p1 == 0 => self.delete_credential(command.data).into(),
            INS_CALCULATE if command.p1 == 0 => self.calculate(command.data, presence),
            INS_GET_CHALLENGE if command.p1 == 0 => self.get_challenge(command.data).into(),
            INS_LIST if command.p1 == 0 && command.data.is_empty() => {
                ResponseApdu::success(self.list_credentials()).into()
            }
            INS_RESET if command.p1 == 0xde && command.p2 == 0xad && command.data.is_empty() => {
                self.factory_reset().into()
            }
            INS_GET_VERSION if command.p1 == 0 && command.data.is_empty() => {
                ResponseApdu::success(self.firmware.to_vec()).into()
            }
            INS_PUT_MANAGEMENT_KEY if command.p1 == 0 => {
                self.change_management_key(command.data).into()
            }
            INS_GET_MANAGEMENT_KEY_RETRIES if command.p1 == 0 && command.data.is_empty() => {
                ResponseApdu::success(vec![self.management_retries]).into()
            }
            INS_GET_PUBLIC_KEY if command.p1 == 0 => self.get_public_key(command.data).into(),
            INS_CHANGE_CREDENTIAL_PASSWORD if command.p1 <= 1 => self
                .change_credential_password(command.p1, command.data)
                .into(),
            INS_PUT
            | INS_DELETE
            | INS_CALCULATE
            | INS_GET_CHALLENGE
            | INS_LIST
            | INS_RESET
            | INS_GET_VERSION
            | INS_PUT_MANAGEMENT_KEY
            | INS_GET_MANAGEMENT_KEY_RETRIES
            | INS_GET_PUBLIC_KEY
            | INS_CHANGE_CREDENTIAL_PASSWORD => {
                ResponseApdu::status(STATUS_INCORRECT_PARAMETERS).into()
            }
            _ => ResponseApdu::status(STATUS_INSTRUCTION_NOT_SUPPORTED).into(),
        }
    }

    fn put_credential(&mut self, encoded: &[u8]) -> ResponseApdu {
        let Ok(tlvs) = parse_tlvs(encoded) else {
            return ResponseApdu::status(STATUS_WRONG_DATA);
        };
        if tlvs.len() < 6
            || tlvs[0].tag != TAG_MANAGEMENT_KEY
            || tlvs[1].tag != TAG_LABEL
            || tlvs[2].tag != TAG_ALGORITHM
        {
            return ResponseApdu::status(STATUS_WRONG_DATA);
        }
        if let Err(status) = self.verify_management_key(tlvs[0].value) {
            return ResponseApdu::status(status);
        }
        let Some(label) = parse_label(tlvs[1].value) else {
            return ResponseApdu::status(STATUS_WRONG_DATA);
        };
        if self
            .credentials
            .iter()
            .any(|credential| credential.label == label)
        {
            return ResponseApdu::status(STATUS_DUPLICATE_CREDENTIAL);
        }
        if self.credentials.len() >= MAX_CREDENTIALS {
            return ResponseApdu::status(STATUS_NOT_ENOUGH_MEMORY);
        }
        let Some(algorithm) = single_byte(tlvs[2].value).and_then(Algorithm::from_id) else {
            return ResponseApdu::status(STATUS_WRONG_DATA);
        };
        let (secret, password_index) = match algorithm {
            Algorithm::Aes128YubicoAuthentication
                if tlvs.len() == 7
                    && tlvs[3].tag == TAG_KEY_ENC
                    && tlvs[4].tag == TAG_KEY_MAC
                    && tlvs[3].value.len() == 16
                    && tlvs[4].value.len() == 16 =>
            {
                (
                    CredentialSecret::Symmetric {
                        enc: Zeroizing::new(tlvs[3].value.try_into().unwrap()),
                        mac: Zeroizing::new(tlvs[4].value.try_into().unwrap()),
                    },
                    5,
                )
            }
            Algorithm::EcP256YubicoAuthentication
                if tlvs.len() == 6 && tlvs[3].tag == TAG_PRIVATE_KEY =>
            {
                let key = if tlvs[3].value.is_empty() {
                    SoftwareSigningKey::generate_for_kind(KeyKind::Ec(EcCurve::P256))
                } else {
                    SoftwareSigningKey::from_serialized_for_kind(
                        KeyKind::Ec(EcCurve::P256),
                        tlvs[3].value,
                    )
                };
                let Ok(key) = key else {
                    return ResponseApdu::status(STATUS_WRONG_DATA);
                };
                (CredentialSecret::Asymmetric(key), 4)
            }
            _ => return ResponseApdu::status(STATUS_WRONG_DATA),
        };
        if tlvs[password_index].tag != TAG_CREDENTIAL_PASSWORD
            || tlvs[password_index].value.len() != CREDENTIAL_PASSWORD_LENGTH
            || tlvs[password_index + 1].tag != TAG_TOUCH
        {
            return ResponseApdu::status(STATUS_WRONG_DATA);
        }
        let Some(touch_required) = parse_bool(tlvs[password_index + 1].value) else {
            return ResponseApdu::status(STATUS_WRONG_DATA);
        };
        self.credentials.push(Credential {
            label,
            secret,
            password: Zeroizing::new(tlvs[password_index].value.try_into().unwrap()),
            touch_required,
            retries: MAX_RETRIES,
        });
        self.persistent_change = true;
        ResponseApdu::success(Vec::new())
    }

    fn delete_credential(&mut self, encoded: &[u8]) -> ResponseApdu {
        let Ok(tlvs) = parse_tlvs(encoded) else {
            return ResponseApdu::status(STATUS_WRONG_DATA);
        };
        if !tags_equal(&tlvs, &[TAG_MANAGEMENT_KEY, TAG_LABEL]) {
            return ResponseApdu::status(STATUS_WRONG_DATA);
        }
        if let Err(status) = self.verify_management_key(tlvs[0].value) {
            return ResponseApdu::status(status);
        }
        let Some(label) = parse_label(tlvs[1].value) else {
            return ResponseApdu::status(STATUS_WRONG_DATA);
        };
        let Some(index) = self.credential_index(&label) else {
            return ResponseApdu::status(STATUS_NOT_FOUND);
        };
        self.credentials.remove(index);
        self.clear_challenge_for(&label);
        self.persistent_change = true;
        ResponseApdu::success(Vec::new())
    }

    fn list_credentials(&self) -> Vec<u8> {
        let mut encoded = Vec::new();
        for credential in &self.credentials {
            let mut value = Vec::with_capacity(credential.label.len() + 3);
            value.push(credential.secret.algorithm() as u8);
            value.push(u8::from(credential.touch_required));
            value.extend_from_slice(credential.label.as_bytes());
            value.push(credential.retries);
            encoded.extend(encode_tlv(TAG_LABEL_LIST, &value).unwrap());
        }
        encoded
    }

    fn get_public_key(&self, encoded: &[u8]) -> ResponseApdu {
        let Ok(tlvs) = parse_tlvs(encoded) else {
            return ResponseApdu::status(STATUS_WRONG_DATA);
        };
        if !tags_equal(&tlvs, &[TAG_LABEL]) {
            return ResponseApdu::status(STATUS_WRONG_DATA);
        }
        let Some(label) = parse_label(tlvs[0].value) else {
            return ResponseApdu::status(STATUS_WRONG_DATA);
        };
        let Some(credential) = self
            .credentials
            .iter()
            .find(|credential| credential.label == label)
        else {
            return ResponseApdu::status(STATUS_NOT_FOUND);
        };
        let CredentialSecret::Asymmetric(key) = &credential.secret else {
            return ResponseApdu::status(STATUS_WRONG_DATA);
        };
        p256_public_key(key)
            .map(|public| ResponseApdu::success(public.to_vec()))
            .unwrap_or_else(|_| ResponseApdu::status(STATUS_EXECUTION_ERROR))
    }

    fn get_challenge(&mut self, encoded: &[u8]) -> ResponseApdu {
        let Ok(tlvs) = parse_tlvs(encoded) else {
            return ResponseApdu::status(STATUS_WRONG_DATA);
        };
        if tlvs.is_empty() || tlvs.len() > 2 || tlvs[0].tag != TAG_LABEL {
            return ResponseApdu::status(STATUS_WRONG_DATA);
        }
        let Some(label) = parse_label(tlvs[0].value) else {
            return ResponseApdu::status(STATUS_WRONG_DATA);
        };
        let Some(index) = self.credential_index(&label) else {
            return ResponseApdu::status(STATUS_NOT_FOUND);
        };
        match self.credentials[index].secret.algorithm() {
            Algorithm::Aes128YubicoAuthentication if tlvs.len() == 1 => {
                let mut host = [0; 8];
                if getrandom::fill(&mut host).is_err() {
                    return ResponseApdu::status(STATUS_EXECUTION_ERROR);
                }
                ResponseApdu::success(host.to_vec())
            }
            Algorithm::EcP256YubicoAuthentication
                if tlvs.len() == 2
                    && tlvs[1].tag == TAG_CREDENTIAL_PASSWORD
                    && tlvs[1].value.len() == CREDENTIAL_PASSWORD_LENGTH =>
            {
                if let Err(status) = self.verify_credential_password(index, tlvs[1].value) {
                    return ResponseApdu::status(status);
                }
                let Ok(ephemeral) =
                    SoftwareSigningKey::generate_for_kind(KeyKind::Ec(EcCurve::P256))
                else {
                    return ResponseApdu::status(STATUS_EXECUTION_ERROR);
                };
                let Ok(public) = p256_public_key(&ephemeral) else {
                    return ResponseApdu::status(STATUS_EXECUTION_ERROR);
                };
                self.challenge = Some(Challenge::Asymmetric {
                    label,
                    ephemeral: Box::new(ephemeral),
                    public,
                });
                ResponseApdu::success(public.to_vec())
            }
            _ => ResponseApdu::status(STATUS_WRONG_DATA),
        }
    }

    fn calculate(&mut self, encoded: &[u8], presence: PresenceAuthorization) -> HsmAuthExchange {
        let Ok(tlvs) = parse_tlvs(encoded) else {
            return ResponseApdu::status(STATUS_WRONG_DATA).into();
        };
        if tlvs.len() < 3
            || tlvs[0].tag != TAG_LABEL
            || tlvs[1].tag != TAG_CONTEXT
            || tlvs.last().map(|tlv| tlv.tag) != Some(TAG_CREDENTIAL_PASSWORD)
            || tlvs.last().map(|tlv| tlv.value.len()) != Some(CREDENTIAL_PASSWORD_LENGTH)
        {
            return ResponseApdu::status(STATUS_WRONG_DATA).into();
        }
        let Some(label) = parse_label(tlvs[0].value) else {
            return ResponseApdu::status(STATUS_WRONG_DATA).into();
        };
        let Some(index) = self.credential_index(&label) else {
            return ResponseApdu::status(STATUS_NOT_FOUND).into();
        };
        if let Err(status) = self.verify_credential_password(index, tlvs.last().unwrap().value) {
            return ResponseApdu::status(status).into();
        }
        if self.credentials[index].touch_required
            && !self
                .presence
                .authorize(UserPresencePolicy::Always, presence)
        {
            return HsmAuthExchange::PresenceRequired(UserPresencePolicy::Always);
        }
        match self.credentials[index].secret.algorithm() {
            Algorithm::Aes128YubicoAuthentication
                if tags_equal(
                    &tlvs,
                    &[
                        TAG_LABEL,
                        TAG_CONTEXT,
                        TAG_RESPONSE,
                        TAG_CREDENTIAL_PASSWORD,
                    ],
                ) =>
            {
                self.calculate_symmetric(index, tlvs[1].value, tlvs[2].value)
                    .into()
            }
            Algorithm::EcP256YubicoAuthentication
                if tags_equal(
                    &tlvs,
                    &[
                        TAG_LABEL,
                        TAG_CONTEXT,
                        TAG_PUBLIC_KEY,
                        TAG_RESPONSE,
                        TAG_CREDENTIAL_PASSWORD,
                    ],
                ) =>
            {
                self.calculate_asymmetric(
                    index,
                    &label,
                    tlvs[1].value,
                    tlvs[2].value,
                    tlvs[3].value,
                )
                .into()
            }
            _ => ResponseApdu::status(STATUS_WRONG_DATA).into(),
        }
    }

    fn calculate_symmetric(
        &mut self,
        index: usize,
        context: &[u8],
        card_cryptogram: &[u8],
    ) -> ResponseApdu {
        if context.len() != 16 || card_cryptogram.len() != 8 {
            return ResponseApdu::status(STATUS_WRONG_DATA);
        }
        let CredentialSecret::Symmetric { enc, mac } = &self.credentials[index].secret else {
            return ResponseApdu::status(STATUS_WRONG_DATA);
        };
        let (Ok(s_enc), Ok(s_mac), Ok(s_rmac)) = (
            scp03_key(enc.as_slice(), 0x04, context),
            scp03_key(mac.as_slice(), 0x06, context),
            scp03_key(mac.as_slice(), 0x07, context),
        ) else {
            return ResponseApdu::status(STATUS_EXECUTION_ERROR);
        };
        let Ok(expected) = scp03_cryptogram(&s_mac, 0x00, context) else {
            return ResponseApdu::status(STATUS_EXECUTION_ERROR);
        };
        if !bool::from(expected.ct_eq(card_cryptogram)) {
            return ResponseApdu::status(STATUS_DATA_INVALID);
        }
        let mut session_keys = Zeroizing::new(Vec::with_capacity(48));
        session_keys.extend_from_slice(&s_enc);
        session_keys.extend_from_slice(&s_mac);
        session_keys.extend_from_slice(&s_rmac);
        ResponseApdu::success(session_keys.to_vec())
    }

    fn calculate_asymmetric(
        &mut self,
        index: usize,
        label: &str,
        context: &[u8],
        device_static_public: &[u8],
        receipt: &[u8],
    ) -> ResponseApdu {
        if context.len() != P256_PUBLIC_KEY_LENGTH * 2
            || device_static_public.len() != P256_PUBLIC_KEY_LENGTH
            || receipt.len() != 16
        {
            return ResponseApdu::status(STATUS_WRONG_DATA);
        }
        let Some(Challenge::Asymmetric {
            label: pending_label,
            ephemeral,
            public: host_ephemeral_public,
        }) = self.challenge.take()
        else {
            return ResponseApdu::status(STATUS_CONDITIONS_NOT_SATISFIED);
        };
        if pending_label != label
            || !bool::from(host_ephemeral_public.ct_eq(&context[..P256_PUBLIC_KEY_LENGTH]))
        {
            return ResponseApdu::status(STATUS_DATA_INVALID);
        }
        let device_ephemeral_public = &context[P256_PUBLIC_KEY_LENGTH..];
        let CredentialSecret::Asymmetric(static_key) = &self.credentials[index].secret else {
            return ResponseApdu::status(STATUS_WRONG_DATA);
        };
        let (Ok(ephemeral_secret), Ok(static_secret)) = (
            derive_with_signing_key(&ephemeral, device_ephemeral_public),
            derive_with_signing_key(static_key, device_static_public),
        ) else {
            return ResponseApdu::status(STATUS_DATA_INVALID);
        };
        let mut combined = Zeroizing::new(Vec::with_capacity(64));
        combined.extend_from_slice(&ephemeral_secret);
        combined.extend_from_slice(&static_secret);
        let Ok(session_keys) = x963_kdf_sha256(&combined, &SCP11_SHARED_INFO, 64) else {
            return ResponseApdu::status(STATUS_EXECUTION_ERROR);
        };
        let mut receipt_input = Vec::with_capacity(P256_PUBLIC_KEY_LENGTH * 2);
        receipt_input.extend_from_slice(device_ephemeral_public);
        receipt_input.extend_from_slice(&host_ephemeral_public);
        let Ok(expected_receipt) = aes_cmac(&session_keys[..16], &receipt_input) else {
            return ResponseApdu::status(STATUS_EXECUTION_ERROR);
        };
        if !bool::from(expected_receipt.ct_eq(receipt)) {
            return ResponseApdu::status(STATUS_DATA_INVALID);
        }
        ResponseApdu::success(session_keys[16..].to_vec())
    }

    fn change_management_key(&mut self, encoded: &[u8]) -> ResponseApdu {
        let Ok(tlvs) = parse_tlvs(encoded) else {
            return ResponseApdu::status(STATUS_WRONG_DATA);
        };
        if !tags_equal(&tlvs, &[TAG_MANAGEMENT_KEY, TAG_MANAGEMENT_KEY])
            || tlvs[1].value.len() != MANAGEMENT_KEY_LENGTH
        {
            return ResponseApdu::status(STATUS_WRONG_DATA);
        }
        if let Err(status) = self.verify_management_key(tlvs[0].value) {
            return ResponseApdu::status(status);
        }
        self.management_key.zeroize();
        self.management_key.copy_from_slice(tlvs[1].value);
        self.management_retries = MAX_RETRIES;
        self.persistent_change = true;
        ResponseApdu::success(Vec::new())
    }

    fn change_credential_password(&mut self, mode: u8, encoded: &[u8]) -> ResponseApdu {
        let Ok(tlvs) = parse_tlvs(encoded) else {
            return ResponseApdu::status(STATUS_WRONG_DATA);
        };
        let expected = if mode == 0 {
            [TAG_LABEL, TAG_CREDENTIAL_PASSWORD, TAG_CREDENTIAL_PASSWORD]
        } else {
            [TAG_LABEL, TAG_MANAGEMENT_KEY, TAG_CREDENTIAL_PASSWORD]
        };
        if !tags_equal(&tlvs, &expected) || tlvs[2].value.len() != CREDENTIAL_PASSWORD_LENGTH {
            return ResponseApdu::status(STATUS_WRONG_DATA);
        }
        let Some(label) = parse_label(tlvs[0].value) else {
            return ResponseApdu::status(STATUS_WRONG_DATA);
        };
        let Some(index) = self.credential_index(&label) else {
            return ResponseApdu::status(STATUS_NOT_FOUND);
        };
        let verified = if mode == 0 {
            self.verify_credential_password(index, tlvs[1].value)
        } else {
            self.verify_management_key(tlvs[1].value)
        };
        if let Err(status) = verified {
            return ResponseApdu::status(status);
        }
        let Some(index) = self.credential_index(&label) else {
            return ResponseApdu::status(STATUS_NOT_FOUND);
        };
        self.credentials[index].password.zeroize();
        self.credentials[index]
            .password
            .copy_from_slice(tlvs[2].value);
        self.credentials[index].retries = MAX_RETRIES;
        self.clear_challenge_for(&label);
        self.persistent_change = true;
        ResponseApdu::success(Vec::new())
    }

    fn factory_reset(&mut self) -> ResponseApdu {
        self.management_key.zeroize();
        self.management_key = Zeroizing::new(FACTORY_MANAGEMENT_KEY);
        self.management_retries = MAX_RETRIES;
        self.credentials.clear();
        self.reset_connection();
        self.persistent_change = true;
        ResponseApdu::success(Vec::new())
    }

    fn verify_management_key(&mut self, supplied: &[u8]) -> Result<(), u16> {
        if supplied.len() != MANAGEMENT_KEY_LENGTH {
            return Err(STATUS_WRONG_DATA);
        }
        if self.management_retries == 0 {
            return Err(STATUS_AUTHENTICATION_BLOCKED);
        }
        if bool::from(self.management_key.as_slice().ct_eq(supplied)) {
            if self.management_retries != MAX_RETRIES {
                self.management_retries = MAX_RETRIES;
                self.persistent_change = true;
            }
            Ok(())
        } else {
            self.management_retries = self.management_retries.saturating_sub(1);
            self.persistent_change = true;
            Err(STATUS_VERIFY_FAILED | u16::from(self.management_retries))
        }
    }

    fn verify_credential_password(&mut self, index: usize, supplied: &[u8]) -> Result<(), u16> {
        if supplied.len() != CREDENTIAL_PASSWORD_LENGTH {
            return Err(STATUS_WRONG_DATA);
        }
        if bool::from(self.credentials[index].password.as_slice().ct_eq(supplied)) {
            if self.credentials[index].retries != MAX_RETRIES {
                self.credentials[index].retries = MAX_RETRIES;
                self.persistent_change = true;
            }
            return Ok(());
        }
        let label = self.credentials[index].label.clone();
        let retries = self.credentials[index].retries.saturating_sub(1);
        self.credentials[index].retries = retries;
        self.persistent_change = true;
        if retries == 0 {
            self.credentials.remove(index);
            self.clear_challenge_for(&label);
        }
        Err(STATUS_VERIFY_FAILED | u16::from(retries))
    }

    fn credential_index(&self, label: &str) -> Option<usize> {
        self.credentials
            .iter()
            .position(|credential| credential.label == label)
    }

    fn clear_challenge_for(&mut self, label: &str) {
        if matches!(
            &self.challenge,
            Some(Challenge::Asymmetric { label: pending, .. }) if pending == label
        ) {
            self.challenge = None;
        }
    }

    pub(crate) fn persistent_state(&self) -> Result<Vec<u8>, &'static str> {
        let mut encoder = minicbor::Encoder::new(Vec::new());
        encoder
            .map(5)
            .map_err(|_| "cannot encode persistent YubiHSM Auth state")?
            .u8(1)
            .map_err(|_| "cannot encode persistent YubiHSM Auth state")?
            .u8(1)
            .map_err(|_| "cannot encode persistent YubiHSM Auth state")?
            .u8(2)
            .map_err(|_| "cannot encode persistent YubiHSM Auth state")?
            .u32(self.serial)
            .map_err(|_| "cannot encode persistent YubiHSM Auth state")?
            .u8(3)
            .map_err(|_| "cannot encode persistent YubiHSM Auth state")?
            .bytes(self.management_key.as_slice())
            .map_err(|_| "cannot encode persistent YubiHSM Auth state")?
            .u8(4)
            .map_err(|_| "cannot encode persistent YubiHSM Auth state")?
            .u8(self.management_retries)
            .map_err(|_| "cannot encode persistent YubiHSM Auth state")?
            .u8(5)
            .map_err(|_| "cannot encode persistent YubiHSM Auth state")?
            .array(self.credentials.len() as u64)
            .map_err(|_| "cannot encode persistent YubiHSM Auth state")?;
        for credential in &self.credentials {
            let secret = credential.secret.serialized()?;
            encoder
                .array(6)
                .map_err(|_| "cannot encode persistent YubiHSM Auth credential")?
                .str(&credential.label)
                .map_err(|_| "cannot encode persistent YubiHSM Auth credential")?
                .u8(credential.secret.algorithm() as u8)
                .map_err(|_| "cannot encode persistent YubiHSM Auth credential")?
                .bytes(&secret)
                .map_err(|_| "cannot encode persistent YubiHSM Auth credential")?
                .bytes(credential.password.as_slice())
                .map_err(|_| "cannot encode persistent YubiHSM Auth credential")?
                .bool(credential.touch_required)
                .map_err(|_| "cannot encode persistent YubiHSM Auth credential")?
                .u8(credential.retries)
                .map_err(|_| "cannot encode persistent YubiHSM Auth credential")?;
        }
        Ok(encoder.into_writer())
    }

    pub(crate) fn from_persistent_state(
        serial: u32,
        firmware: [u8; 3],
        encoded: &[u8],
    ) -> Result<Self, &'static str> {
        let mut decoder = minicbor::Decoder::new(encoded);
        let fields = decoder
            .map()
            .map_err(|_| "persistent YubiHSM Auth state is not a CBOR map")?
            .ok_or("indefinite persistent YubiHSM Auth state is unsupported")?;
        let mut version = None;
        let mut stored_serial = None;
        let mut management_key = None;
        let mut management_retries = None;
        let mut credentials = None;
        for _ in 0..fields {
            match decoder
                .u8()
                .map_err(|_| "persistent YubiHSM Auth state has an invalid field")?
            {
                1 if version.is_none() => {
                    version = Some(
                        decoder
                            .u8()
                            .map_err(|_| "invalid YubiHSM Auth state version")?,
                    )
                }
                2 if stored_serial.is_none() => {
                    stored_serial = Some(
                        decoder
                            .u32()
                            .map_err(|_| "invalid YubiHSM Auth state serial")?,
                    )
                }
                3 if management_key.is_none() => {
                    management_key = Some(Zeroizing::new(
                        decoder
                            .bytes()
                            .map_err(|_| "invalid YubiHSM Auth management key")?
                            .to_vec(),
                    ))
                }
                4 if management_retries.is_none() => {
                    management_retries = Some(
                        decoder
                            .u8()
                            .map_err(|_| "invalid YubiHSM Auth management retries")?,
                    )
                }
                5 if credentials.is_none() => credentials = Some(decode_credentials(&mut decoder)?),
                _ => decoder
                    .skip()
                    .map_err(|_| "invalid YubiHSM Auth state data")?,
            }
        }
        if decoder.position() != encoded.len() {
            return Err("persistent YubiHSM Auth state has trailing data");
        }
        if version != Some(1) {
            return Err("unsupported persistent YubiHSM Auth state version");
        }
        if stored_serial != Some(serial) {
            return Err("persistent YubiHSM Auth state belongs to another serial");
        }
        let management_key: [u8; MANAGEMENT_KEY_LENGTH] = management_key
            .ok_or("persistent YubiHSM Auth state has no management key")?
            .as_slice()
            .try_into()
            .map_err(|_| "persistent YubiHSM Auth management key has the wrong length")?;
        let management_retries = management_retries
            .filter(|retries| *retries <= MAX_RETRIES)
            .ok_or("persistent YubiHSM Auth management retries are invalid")?;
        Ok(Self {
            serial,
            firmware,
            management_key: Zeroizing::new(management_key),
            management_retries,
            credentials: credentials.ok_or("persistent YubiHSM Auth state has no credentials")?,
            challenge: None,
            presence: PresenceClient::default(),
            persistent_change: false,
        })
    }
}

fn decode_credentials(
    decoder: &mut minicbor::Decoder<'_>,
) -> Result<Vec<Credential>, &'static str> {
    let count = decoder
        .array()
        .map_err(|_| "persistent YubiHSM Auth credentials are not an array")?
        .ok_or("indefinite persistent YubiHSM Auth credentials are unsupported")?;
    if count > MAX_CREDENTIALS as u64 {
        return Err("persistent YubiHSM Auth state exceeds credential capacity");
    }
    let mut credentials = Vec::with_capacity(count as usize);
    for _ in 0..count {
        if decoder
            .array()
            .map_err(|_| "invalid persistent YubiHSM Auth credential")?
            != Some(6)
        {
            return Err("persistent YubiHSM Auth credential has the wrong shape");
        }
        let label = decoder
            .str()
            .map_err(|_| "invalid persistent YubiHSM Auth label")?
            .to_owned();
        if parse_label(label.as_bytes()).is_none()
            || credentials
                .iter()
                .any(|credential: &Credential| credential.label == label)
        {
            return Err("persistent YubiHSM Auth label is invalid or duplicated");
        }
        let algorithm = Algorithm::from_id(
            decoder
                .u8()
                .map_err(|_| "invalid persistent YubiHSM Auth algorithm")?,
        )
        .ok_or("unsupported persistent YubiHSM Auth algorithm")?;
        let secret = CredentialSecret::from_serialized(
            algorithm,
            decoder
                .bytes()
                .map_err(|_| "invalid persistent YubiHSM Auth key")?,
        )?;
        let password = decoder
            .bytes()
            .map_err(|_| "invalid persistent YubiHSM Auth password")?
            .try_into()
            .map_err(|_| "persistent YubiHSM Auth password has the wrong length")?;
        let touch_required = decoder
            .bool()
            .map_err(|_| "invalid persistent YubiHSM Auth touch policy")?;
        let retries = decoder
            .u8()
            .map_err(|_| "invalid persistent YubiHSM Auth retries")?;
        if retries == 0 || retries > MAX_RETRIES {
            return Err("persistent YubiHSM Auth retry counter is invalid");
        }
        credentials.push(Credential {
            label,
            secret,
            password: Zeroizing::new(password),
            touch_required,
            retries,
        });
    }
    Ok(credentials)
}

fn p256_public_key(key: &SoftwareSigningKey) -> Result<[u8; P256_PUBLIC_KEY_LENGTH], ()> {
    let SoftwarePublicKey::Ec {
        curve: EcCurve::P256,
        uncompressed,
    } = key.public_key()
    else {
        return Err(());
    };
    uncompressed.try_into().map_err(|_| ())
}

fn parse_bool(value: &[u8]) -> Option<bool> {
    match value {
        [0] => Some(false),
        [1] => Some(true),
        _ => None,
    }
}

fn single_byte(value: &[u8]) -> Option<u8> {
    (value.len() == 1).then(|| value[0])
}

fn parse_label(value: &[u8]) -> Option<String> {
    if !(1..=64).contains(&value.len()) {
        return None;
    }
    core::str::from_utf8(value).ok().map(str::to_owned)
}

fn tags_equal(tlvs: &[Tlv<'_>], expected: &[u8]) -> bool {
    tlvs.len() == expected.len() && tlvs.iter().zip(expected).all(|(tlv, tag)| tlv.tag == *tag)
}

fn encode_tlv(tag: u8, value: &[u8]) -> Result<Vec<u8>, ()> {
    let mut encoded = Vec::with_capacity(value.len() + 4);
    encoded.push(tag);
    match value.len() {
        0..=0x7f => encoded.push(value.len() as u8),
        0x80..=0xff => encoded.extend([0x81, value.len() as u8]),
        0x100..=0xffff => {
            encoded.push(0x82);
            encoded.extend_from_slice(&(value.len() as u16).to_be_bytes());
        }
        _ => return Err(()),
    }
    encoded.extend_from_slice(value);
    Ok(encoded)
}

struct Tlv<'a> {
    tag: u8,
    value: &'a [u8],
}

fn parse_tlvs(mut encoded: &[u8]) -> Result<Vec<Tlv<'_>>, ()> {
    let mut tlvs = Vec::new();
    while !encoded.is_empty() {
        let tag = *encoded.first().ok_or(())?;
        encoded = &encoded[1..];
        let (length, length_length) = parse_length(encoded)?;
        encoded = &encoded[length_length..];
        let value = encoded.get(..length).ok_or(())?;
        tlvs.push(Tlv { tag, value });
        encoded = &encoded[length..];
    }
    Ok(tlvs)
}

fn parse_length(encoded: &[u8]) -> Result<(usize, usize), ()> {
    match *encoded.first().ok_or(())? {
        length @ 0..=0x7f => Ok((length as usize, 1)),
        0x81 => {
            let length = *encoded.get(1).ok_or(())? as usize;
            (length >= 0x80).then_some((length, 2)).ok_or(())
        }
        0x82 => {
            let value = encoded.get(1..3).ok_or(())?;
            let length = u16::from_be_bytes([value[0], value[1]]) as usize;
            (length > 0xff).then_some((length, 3)).ok_or(())
        }
        _ => Err(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PASSWORD: [u8; CREDENTIAL_PASSWORD_LENGTH] = [0x33; CREDENTIAL_PASSWORD_LENGTH];

    fn execute(
        applet: &mut HsmAuthApplet,
        ins: u8,
        p1: u8,
        p2: u8,
        data: &[u8],
        presence: PresenceAuthorization,
    ) -> HsmAuthExchange {
        applet.exchange(
            &CommandApdu {
                cla: 0,
                ins,
                p1,
                p2,
                data,
                le: None,
            },
            presence,
        )
    }

    fn complete(exchange: HsmAuthExchange) -> ResponseApdu {
        match exchange {
            HsmAuthExchange::Complete(response) => response,
            HsmAuthExchange::PresenceRequired(policy) => {
                panic!("unexpected presence request: {policy:?}")
            }
        }
    }

    fn append_tlv(encoded: &mut Vec<u8>, tag: u8, value: &[u8]) {
        encoded.extend(encode_tlv(tag, value).unwrap());
    }

    fn symmetric_put_data(
        management_key: &[u8],
        label: &str,
        enc: &[u8; 16],
        mac: &[u8; 16],
        password: &[u8; 16],
        touch_required: bool,
    ) -> Vec<u8> {
        let mut data = Vec::new();
        append_tlv(&mut data, TAG_MANAGEMENT_KEY, management_key);
        append_tlv(&mut data, TAG_LABEL, label.as_bytes());
        append_tlv(
            &mut data,
            TAG_ALGORITHM,
            &[Algorithm::Aes128YubicoAuthentication as u8],
        );
        append_tlv(&mut data, TAG_KEY_ENC, enc);
        append_tlv(&mut data, TAG_KEY_MAC, mac);
        append_tlv(&mut data, TAG_CREDENTIAL_PASSWORD, password);
        append_tlv(&mut data, TAG_TOUCH, &[u8::from(touch_required)]);
        data
    }

    fn put_symmetric(
        applet: &mut HsmAuthApplet,
        label: &str,
        enc: &[u8; 16],
        mac: &[u8; 16],
        touch_required: bool,
    ) -> ResponseApdu {
        let data = symmetric_put_data(
            &FACTORY_MANAGEMENT_KEY,
            label,
            enc,
            mac,
            &PASSWORD,
            touch_required,
        );
        complete(execute(
            applet,
            INS_PUT,
            0,
            0,
            &data,
            PresenceAuthorization::Absent,
        ))
    }

    fn put_asymmetric(
        applet: &mut HsmAuthApplet,
        label: &str,
        private_key: &[u8],
        touch_required: bool,
    ) -> ResponseApdu {
        let mut data = Vec::new();
        append_tlv(&mut data, TAG_MANAGEMENT_KEY, &FACTORY_MANAGEMENT_KEY);
        append_tlv(&mut data, TAG_LABEL, label.as_bytes());
        append_tlv(
            &mut data,
            TAG_ALGORITHM,
            &[Algorithm::EcP256YubicoAuthentication as u8],
        );
        append_tlv(&mut data, TAG_PRIVATE_KEY, private_key);
        append_tlv(&mut data, TAG_CREDENTIAL_PASSWORD, &PASSWORD);
        append_tlv(&mut data, TAG_TOUCH, &[u8::from(touch_required)]);
        complete(execute(
            applet,
            INS_PUT,
            0,
            0,
            &data,
            PresenceAuthorization::Absent,
        ))
    }

    #[test]
    fn selection_version_and_empty_discovery_match_the_applet_protocol() {
        let mut applet = HsmAuthApplet::new(12_345_678, [5, 8, 0]);
        assert_eq!(applet.select_response(), [TAG_VERSION, 3, 5, 8, 0]);
        assert_eq!(
            complete(execute(
                &mut applet,
                INS_GET_VERSION,
                0,
                0,
                &[],
                PresenceAuthorization::Absent,
            )),
            ResponseApdu::success(vec![5, 8, 0])
        );
        assert_eq!(
            complete(execute(
                &mut applet,
                INS_GET_MANAGEMENT_KEY_RETRIES,
                0,
                0,
                &[],
                PresenceAuthorization::Absent,
            )),
            ResponseApdu::success(vec![MAX_RETRIES])
        );
        assert_eq!(
            complete(execute(
                &mut applet,
                INS_LIST,
                0,
                0,
                &[],
                PresenceAuthorization::Absent,
            )),
            ResponseApdu::success(Vec::new())
        );
    }

    #[test]
    fn symmetric_get_challenge_returns_random_bytes_without_pending_state() {
        let mut applet = HsmAuthApplet::new(1, [5, 8, 0]);
        assert_eq!(
            put_symmetric(&mut applet, "symmetric", &[0x11; 16], &[0x22; 16], false).status,
            0x9000
        );

        let mut challenge_data = Vec::new();
        append_tlv(&mut challenge_data, TAG_LABEL, b"symmetric");
        let challenge = complete(execute(
            &mut applet,
            INS_GET_CHALLENGE,
            0,
            0,
            &challenge_data,
            PresenceAuthorization::Absent,
        ));

        assert_eq!(challenge.status, 0x9000);
        assert_eq!(challenge.data.len(), 8);
        assert!(applet.challenge.is_none());
    }

    #[test]
    fn symmetric_credential_accepts_host_context_derives_session_keys_and_requires_touch() {
        let enc = [0x11; 16];
        let mac = [0x22; 16];
        let mut applet = HsmAuthApplet::new(1, [5, 8, 0]);
        assert_eq!(
            put_symmetric(&mut applet, "touch key", &enc, &mac, true).status,
            0x9000
        );

        // Symmetric HSM Auth is stateless: callers may generate the host
        // challenge themselves and calculate directly from the complete
        // host-plus-card context without first issuing GET CHALLENGE.
        let mut context = vec![0x33; 8];
        context.extend_from_slice(&[0x44; 8]);
        let s_enc = scp03_key(&enc, 0x04, &context).unwrap();
        let s_mac = scp03_key(&mac, 0x06, &context).unwrap();
        let s_rmac = scp03_key(&mac, 0x07, &context).unwrap();
        let cryptogram = scp03_cryptogram(&s_mac, 0x00, &context).unwrap();

        let mut calculate_data = Vec::new();
        append_tlv(&mut calculate_data, TAG_LABEL, b"touch key");
        append_tlv(&mut calculate_data, TAG_CONTEXT, &context);
        append_tlv(&mut calculate_data, TAG_RESPONSE, &cryptogram);
        append_tlv(&mut calculate_data, TAG_CREDENTIAL_PASSWORD, &PASSWORD);
        assert!(matches!(
            execute(
                &mut applet,
                INS_CALCULATE,
                0,
                0,
                &calculate_data,
                PresenceAuthorization::Absent,
            ),
            HsmAuthExchange::PresenceRequired(UserPresencePolicy::Always)
        ));
        let response = complete(execute(
            &mut applet,
            INS_CALCULATE,
            0,
            0,
            &calculate_data,
            PresenceAuthorization::Granted,
        ));
        assert_eq!(response.status, 0x9000);
        assert_eq!(
            response.data,
            [s_enc.as_slice(), s_mac.as_slice(), s_rmac.as_slice()].concat()
        );
    }

    #[test]
    fn asymmetric_credential_performs_both_ecdh_operations_and_validates_the_receipt() {
        let mut private = [0_u8; 32];
        private[31] = 7;
        let credential_key =
            SoftwareSigningKey::from_serialized_for_kind(KeyKind::Ec(EcCurve::P256), &private)
                .unwrap();
        let credential_public = p256_public_key(&credential_key).unwrap();
        let mut applet = HsmAuthApplet::new(2, [5, 8, 0]);
        assert_eq!(
            put_asymmetric(&mut applet, "asymmetric", &private, false).status,
            0x9000
        );

        let mut label_data = Vec::new();
        append_tlv(&mut label_data, TAG_LABEL, b"asymmetric");
        let public = complete(execute(
            &mut applet,
            INS_GET_PUBLIC_KEY,
            0,
            0,
            &label_data,
            PresenceAuthorization::Absent,
        ));
        assert_eq!(public, ResponseApdu::success(credential_public.to_vec()));

        append_tlv(&mut label_data, TAG_CREDENTIAL_PASSWORD, &PASSWORD);
        let host_ephemeral_public = complete(execute(
            &mut applet,
            INS_GET_CHALLENGE,
            0,
            0,
            &label_data,
            PresenceAuthorization::Absent,
        ));
        assert_eq!(host_ephemeral_public.status, 0x9000);

        let device_static =
            SoftwareSigningKey::generate_for_kind(KeyKind::Ec(EcCurve::P256)).unwrap();
        let device_ephemeral =
            SoftwareSigningKey::generate_for_kind(KeyKind::Ec(EcCurve::P256)).unwrap();
        let device_static_public = p256_public_key(&device_static).unwrap();
        let device_ephemeral_public = p256_public_key(&device_ephemeral).unwrap();
        let ephemeral_secret =
            derive_with_signing_key(&device_ephemeral, &host_ephemeral_public.data).unwrap();
        let static_secret = derive_with_signing_key(&device_static, &credential_public).unwrap();
        let mut combined = Zeroizing::new(Vec::with_capacity(64));
        combined.extend_from_slice(&ephemeral_secret);
        combined.extend_from_slice(&static_secret);
        let session_keys = x963_kdf_sha256(&combined, &SCP11_SHARED_INFO, 64).unwrap();
        let receipt_input = [
            device_ephemeral_public.as_slice(),
            host_ephemeral_public.data.as_slice(),
        ]
        .concat();
        let receipt = aes_cmac(&session_keys[..16], &receipt_input).unwrap();
        let context = [
            host_ephemeral_public.data.as_slice(),
            device_ephemeral_public.as_slice(),
        ]
        .concat();

        let mut calculate_data = Vec::new();
        append_tlv(&mut calculate_data, TAG_LABEL, b"asymmetric");
        append_tlv(&mut calculate_data, TAG_CONTEXT, &context);
        append_tlv(&mut calculate_data, TAG_PUBLIC_KEY, &device_static_public);
        append_tlv(&mut calculate_data, TAG_RESPONSE, &receipt);
        append_tlv(&mut calculate_data, TAG_CREDENTIAL_PASSWORD, &PASSWORD);
        let response = complete(execute(
            &mut applet,
            INS_CALCULATE,
            0,
            0,
            &calculate_data,
            PresenceAuthorization::Absent,
        ));
        assert_eq!(response, ResponseApdu::success(session_keys[16..].to_vec()));
    }

    #[test]
    fn retry_counters_reset_on_success_and_exhaust_as_documented() {
        let enc = [1; 16];
        let mac = [2; 16];
        let mut applet = HsmAuthApplet::new(3, [5, 8, 0]);
        assert_eq!(
            put_symmetric(&mut applet, "credential", &enc, &mac, false).status,
            0x9000
        );

        for remaining in (0..MAX_RETRIES).rev() {
            assert_eq!(
                applet.verify_credential_password(0, &[0xff; 16]),
                Err(STATUS_VERIFY_FAILED | u16::from(remaining))
            );
        }
        assert!(applet.credentials.is_empty());

        let wrong_management_key = [0xff; 16];
        for remaining in (0..MAX_RETRIES).rev() {
            assert_eq!(
                applet.verify_management_key(&wrong_management_key),
                Err(STATUS_VERIFY_FAILED | u16::from(remaining))
            );
        }
        assert_eq!(
            applet.verify_management_key(&FACTORY_MANAGEMENT_KEY),
            Err(STATUS_AUTHENTICATION_BLOCKED)
        );
        assert_eq!(
            complete(execute(
                &mut applet,
                INS_RESET,
                0xde,
                0xad,
                &[],
                PresenceAuthorization::Absent,
            )),
            ResponseApdu::success(Vec::new())
        );
        assert_eq!(
            applet.verify_management_key(&FACTORY_MANAGEMENT_KEY),
            Ok(())
        );
    }

    #[test]
    fn credential_password_can_be_changed_by_the_credential_or_management_key() {
        let mut applet = HsmAuthApplet::new(4, [5, 8, 0]);
        assert_eq!(
            put_symmetric(&mut applet, "credential", &[1; 16], &[2; 16], false).status,
            0x9000
        );
        let second_password = [0x44; 16];
        let third_password = [0x55; 16];

        let mut data = Vec::new();
        append_tlv(&mut data, TAG_LABEL, b"credential");
        append_tlv(&mut data, TAG_CREDENTIAL_PASSWORD, &PASSWORD);
        append_tlv(&mut data, TAG_CREDENTIAL_PASSWORD, &second_password);
        assert_eq!(
            complete(execute(
                &mut applet,
                INS_CHANGE_CREDENTIAL_PASSWORD,
                0,
                0,
                &data,
                PresenceAuthorization::Absent,
            ))
            .status,
            0x9000
        );
        assert_eq!(
            applet.verify_credential_password(0, &second_password),
            Ok(())
        );

        data.clear();
        append_tlv(&mut data, TAG_LABEL, b"credential");
        append_tlv(&mut data, TAG_MANAGEMENT_KEY, &FACTORY_MANAGEMENT_KEY);
        append_tlv(&mut data, TAG_CREDENTIAL_PASSWORD, &third_password);
        assert_eq!(
            complete(execute(
                &mut applet,
                INS_CHANGE_CREDENTIAL_PASSWORD,
                1,
                0,
                &data,
                PresenceAuthorization::Absent,
            ))
            .status,
            0x9000
        );
        assert_eq!(
            applet.verify_credential_password(0, &third_password),
            Ok(())
        );
    }

    #[test]
    fn persistence_restores_credentials_and_retries_but_not_pending_challenges() {
        let mut applet = HsmAuthApplet::new(5, [5, 8, 0]);
        assert_eq!(
            put_symmetric(&mut applet, "persistent", &[1; 16], &[2; 16], true).status,
            0x9000
        );
        assert_eq!(
            applet.verify_management_key(&[0xff; 16]),
            Err(STATUS_VERIFY_FAILED | 7)
        );
        assert_eq!(
            applet.verify_credential_password(0, &[0xff; 16]),
            Err(STATUS_VERIFY_FAILED | 7)
        );
        let ephemeral = SoftwareSigningKey::generate_for_kind(KeyKind::Ec(EcCurve::P256)).unwrap();
        let public = p256_public_key(&ephemeral).unwrap();
        applet.challenge = Some(Challenge::Asymmetric {
            label: "persistent".to_owned(),
            ephemeral: Box::new(ephemeral),
            public,
        });

        let encoded = applet.persistent_state().unwrap();
        let restored = HsmAuthApplet::from_persistent_state(5, [5, 8, 1], &encoded).unwrap();
        assert_eq!(restored.management_retries, 7);
        assert_eq!(restored.credentials.len(), 1);
        assert_eq!(restored.credentials[0].retries, 7);
        assert!(restored.credentials[0].touch_required);
        assert!(restored.challenge.is_none());
        assert!(!restored.persistent_change);
        assert_eq!(
            HsmAuthApplet::from_persistent_state(6, [5, 8, 0], &encoded).unwrap_err(),
            "persistent YubiHSM Auth state belongs to another serial"
        );
    }
}
