//! Transport-neutral logical YubiKey emulator.
//!
//! This crate owns device identity, ISO 7816 routing, applet state, and APDU
//! behavior. It deliberately contains no USB, CCID, PC/SC, PKCS #11, or
//! operating-system integration.

mod crypto;
mod fido;
pub mod post_quantum;
mod preview_sign;
pub mod software_signing;

pub const MANAGEMENT_AID: [u8; 8] = [0xa0, 0x00, 0x00, 0x05, 0x27, 0x47, 0x11, 0x17];
pub const FIDO2_AID: [u8; 8] = [0xa0, 0x00, 0x00, 0x06, 0x47, 0x2f, 0x00, 0x01];
pub const MAX_DISCOVERABLE_CREDENTIALS: usize = fido::MAX_RESIDENT_CREDENTIALS;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FidoCredentialAlgorithm {
    Es256,
    Esp256,
    Ed25519,
    Esp384,
    Esp512,
    Es256K,
    MlDsa44,
    MlDsa65,
    MlDsa87,
}

impl FidoCredentialAlgorithm {
    pub const fn cose_identifier(self) -> i64 {
        match self {
            Self::Es256 => -7,
            Self::Esp256 => -9,
            Self::Ed25519 => -19,
            Self::Esp384 => -51,
            Self::Esp512 => -52,
            Self::Es256K => -47,
            Self::MlDsa44 => -48,
            Self::MlDsa65 => -49,
            Self::MlDsa87 => -50,
        }
    }

    pub const fn name(self) -> &'static str {
        match self {
            Self::Es256 => "es256",
            Self::Esp256 => "esp256",
            Self::Ed25519 => "ed25519",
            Self::Esp384 => "esp384",
            Self::Esp512 => "esp512",
            Self::Es256K => "es256k",
            Self::MlDsa44 => "ml-dsa-44",
            Self::MlDsa65 => "ml-dsa-65",
            Self::MlDsa87 => "ml-dsa-87",
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "es256" => Some(Self::Es256),
            "esp256" => Some(Self::Esp256),
            "ed25519" => Some(Self::Ed25519),
            "esp384" => Some(Self::Esp384),
            "esp512" => Some(Self::Esp512),
            "es256k" => Some(Self::Es256K),
            "ml-dsa-44" => Some(Self::MlDsa44),
            "ml-dsa-65" => Some(Self::MlDsa65),
            "ml-dsa-87" => Some(Self::MlDsa87),
            _ => None,
        }
    }

    pub fn from_cose_identifier(identifier: i64) -> Option<Self> {
        match identifier {
            -7 => Some(Self::Es256),
            -9 => Some(Self::Esp256),
            -19 => Some(Self::Ed25519),
            -51 => Some(Self::Esp384),
            -52 => Some(Self::Esp512),
            -47 => Some(Self::Es256K),
            -48 => Some(Self::MlDsa44),
            -49 => Some(Self::MlDsa65),
            -50 => Some(Self::MlDsa87),
            _ => None,
        }
    }

    pub const fn ml_dsa_parameter_set(self) -> Option<post_quantum::MlDsaParameterSet> {
        match self {
            Self::Es256
            | Self::Esp256
            | Self::Ed25519
            | Self::Esp384
            | Self::Esp512
            | Self::Es256K => None,
            Self::MlDsa44 => Some(post_quantum::MlDsaParameterSet::MlDsa44),
            Self::MlDsa65 => Some(post_quantum::MlDsaParameterSet::MlDsa65),
            Self::MlDsa87 => Some(post_quantum::MlDsaParameterSet::MlDsa87),
        }
    }

    pub const fn software_signing_algorithm(self) -> software_signing::SoftwareSigningAlgorithm {
        match self {
            Self::Es256 | Self::Esp256 => {
                software_signing::SoftwareSigningAlgorithm::EcdsaP256Sha256
            }
            Self::Ed25519 => software_signing::SoftwareSigningAlgorithm::Ed25519,
            Self::Esp384 => software_signing::SoftwareSigningAlgorithm::EcdsaP384Sha384,
            Self::Esp512 => software_signing::SoftwareSigningAlgorithm::EcdsaP521Sha512,
            Self::Es256K => software_signing::SoftwareSigningAlgorithm::EcdsaSecp256k1Sha256,
            Self::MlDsa44 => software_signing::SoftwareSigningAlgorithm::MlDsa(
                post_quantum::MlDsaParameterSet::MlDsa44,
            ),
            Self::MlDsa65 => software_signing::SoftwareSigningAlgorithm::MlDsa(
                post_quantum::MlDsaParameterSet::MlDsa65,
            ),
            Self::MlDsa87 => software_signing::SoftwareSigningAlgorithm::MlDsa(
                post_quantum::MlDsaParameterSet::MlDsa87,
            ),
        }
    }

    pub const fn from_ml_dsa_parameter_set(
        parameter_set: post_quantum::MlDsaParameterSet,
    ) -> Option<Self> {
        match parameter_set {
            post_quantum::MlDsaParameterSet::MlDsa44 => Some(Self::MlDsa44),
            post_quantum::MlDsaParameterSet::MlDsa65 => Some(Self::MlDsa65),
            post_quantum::MlDsaParameterSet::MlDsa87 => Some(Self::MlDsa87),
        }
    }
}

pub const ATR: [u8; 23] = [
    0x3b, 0xfd, 0x13, 0x00, 0x00, 0x81, 0x31, 0xfe, 0x15, 0x80, 0x73, 0xc0, 0x21, 0xc0, 0x57, 0x59,
    0x75, 0x62, 0x69, 0x4b, 0x65, 0x79, 0x40,
];

const INS_SELECT: u8 = 0xa4;
const INS_GET_RESPONSE: u8 = 0xc0;
const INS_READ_DEVICE_INFO: u8 = 0x1d;
const INS_CTAP_CBOR: u8 = 0x10;
const ISO7816_SUCCESS: u16 = 0x9000;
const MANAGEMENT_SELECT_PREFIX: &[u8] = b"Virtual mgr - FW version ";
const CAPABILITY_CCID: u16 = 0x0004;
const CAPABILITY_FIDO2: u16 = 0x0200;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Applet {
    Management,
    Fido2,
}

impl Applet {
    pub const fn name(self) -> &'static str {
        match self {
            Self::Management => "management",
            Self::Fido2 => "fido2",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AppletConfiguration {
    pub management: bool,
    pub fido2: bool,
}

impl AppletConfiguration {
    pub const fn yubikey_5_8_preview_sign() -> Self {
        Self {
            management: true,
            fido2: true,
        }
    }

    pub const fn contains(self, applet: Applet) -> bool {
        match applet {
            Applet::Management => self.management,
            Applet::Fido2 => self.fido2,
        }
    }

    pub const fn usb_capabilities(self) -> u16 {
        let ccid = if self.management || self.fido2 {
            CAPABILITY_CCID
        } else {
            0
        };
        let fido2 = if self.fido2 { CAPABILITY_FIDO2 } else { 0 };
        ccid | fido2
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeviceProfile {
    pub serial: u32,
    pub firmware: [u8; 3],
    pub form_factor: u8,
    pub applets: AppletConfiguration,
}

/// Configurable FIDO applet behavior used by transports and test fixtures.
///
/// The default models the FIDO behavior of the virtual YubiKey 5.8 profile:
/// PIN `123456`, PIN/UV auth protocols 2 and 1, and permissioned tokens.
pub struct FidoConfiguration {
    pub(crate) initial_pin: Option<Vec<u8>>,
    pub(crate) pin_uv_auth_protocols: Vec<u8>,
    pub(crate) permissioned_pin_uv_auth_tokens: bool,
    pub(crate) credential_algorithms: Vec<FidoCredentialAlgorithm>,
}

impl FidoConfiguration {
    pub fn yubikey_5_8_preview_sign() -> Self {
        Self {
            initial_pin: Some(b"123456".to_vec()),
            pin_uv_auth_protocols: vec![2, 1],
            permissioned_pin_uv_auth_tokens: true,
            credential_algorithms: vec![
                FidoCredentialAlgorithm::Es256,
                FidoCredentialAlgorithm::Esp256,
                FidoCredentialAlgorithm::Ed25519,
                FidoCredentialAlgorithm::Esp384,
                FidoCredentialAlgorithm::Esp512,
                FidoCredentialAlgorithm::Es256K,
                FidoCredentialAlgorithm::MlDsa44,
                FidoCredentialAlgorithm::MlDsa65,
                FidoCredentialAlgorithm::MlDsa87,
            ],
        }
    }

    pub fn with_pin(mut self, pin: impl Into<Vec<u8>>) -> Self {
        self.initial_pin = Some(pin.into());
        self
    }

    pub fn without_pin(mut self) -> Self {
        self.initial_pin = None;
        self
    }

    pub fn with_pin_uv_auth_protocols(mut self, protocols: impl Into<Vec<u8>>) -> Self {
        self.pin_uv_auth_protocols = protocols.into();
        self
    }

    pub fn with_permissioned_pin_uv_auth_tokens(mut self, supported: bool) -> Self {
        self.permissioned_pin_uv_auth_tokens = supported;
        self
    }

    pub fn with_credential_algorithms(
        mut self,
        algorithms: impl Into<Vec<FidoCredentialAlgorithm>>,
    ) -> Self {
        self.credential_algorithms = algorithms.into();
        self
    }
}

impl Default for FidoConfiguration {
    fn default() -> Self {
        Self::yubikey_5_8_preview_sign()
    }
}

impl DeviceProfile {
    pub const fn yubikey_5_8_ccid(serial: u32) -> Self {
        Self {
            serial,
            firmware: [5, 8, 0],
            form_factor: 0x01,
            applets: AppletConfiguration::yubikey_5_8_preview_sign(),
        }
    }

    pub const fn usb_supported_capabilities(&self) -> u16 {
        self.applets.usb_capabilities()
    }

    pub const fn usb_enabled_capabilities(&self) -> u16 {
        self.applets.usb_capabilities()
    }

    pub fn management_device_info(&self, page: u8) -> Option<Vec<u8>> {
        if page != 0 {
            return None;
        }
        let mut body = Vec::new();
        push_tlv(
            &mut body,
            0x01,
            &self.usb_supported_capabilities().to_be_bytes(),
        );
        push_tlv(&mut body, 0x02, &self.serial.to_be_bytes());
        push_tlv(
            &mut body,
            0x03,
            &self.usb_enabled_capabilities().to_be_bytes(),
        );
        push_tlv(&mut body, 0x04, &[self.form_factor]);
        push_tlv(&mut body, 0x05, &self.firmware);
        push_tlv(&mut body, 0x08, &[0]);

        let mut response = Vec::with_capacity(body.len() + 1);
        response.push(body.len() as u8);
        response.extend_from_slice(&body);
        Some(response)
    }
}

#[derive(Debug)]
pub struct FidoAuthenticator {
    state: fido::FidoState,
}

impl FidoAuthenticator {
    pub fn new() -> Self {
        Self::for_serial(12_345_678)
    }

    pub fn for_serial(serial: u32) -> Self {
        Self::with_configuration(serial, FidoConfiguration::default())
    }

    pub fn with_configuration(serial: u32, configuration: FidoConfiguration) -> Self {
        let device_identifier = device_identifier(serial);
        Self {
            state: fido::FidoState::new(device_identifier, configuration),
        }
    }

    pub fn from_persistent_state(
        serial: u32,
        configuration: FidoConfiguration,
        encoded: &[u8],
    ) -> Result<Self, &'static str> {
        Ok(Self {
            state: fido::FidoState::decode_persistent(
                encoded,
                device_identifier(serial),
                configuration,
            )?,
        })
    }

    pub fn persistent_state(&self) -> Result<Vec<u8>, &'static str> {
        self.state.encode_persistent()
    }

    pub fn take_persistent_change(&mut self) -> bool {
        self.state.take_persistent_change()
    }

    pub fn exchange(&mut self, request: &[u8]) -> Vec<u8> {
        fido::exchange(&mut self.state, request)
    }

    pub fn selected_make_credential_algorithm(
        &self,
        request: &[u8],
    ) -> Option<FidoCredentialAlgorithm> {
        self.state.selected_make_credential_algorithm(request)
    }

    /// Return the ordered public-key algorithms offered by a CTAP2
    /// authenticatorMakeCredential request without exposing request secrets.
    pub fn make_credential_algorithms(request: &[u8]) -> Option<Vec<i64>> {
        fido::make_credential_algorithms(request)
    }

    pub fn reset_connection(&mut self) {
        self.state.reset_connection();
    }
}

fn device_identifier(serial: u32) -> [u8; 16] {
    let mut identifier = *b"virtual-\0\0\0\0fido";
    identifier[8..12].copy_from_slice(&serial.to_be_bytes());
    identifier
}

impl Default for FidoAuthenticator {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug)]
pub struct VirtualYubiKey {
    profile: DeviceProfile,
    selected: Option<Applet>,
    chained_command: Vec<u8>,
    pending_response: Vec<u8>,
    fido: FidoAuthenticator,
}

impl VirtualYubiKey {
    pub fn new(profile: DeviceProfile) -> Self {
        Self::with_fido_configuration(profile, FidoConfiguration::default())
    }

    pub fn with_fido_configuration(
        profile: DeviceProfile,
        configuration: FidoConfiguration,
    ) -> Self {
        let fido = FidoAuthenticator::with_configuration(profile.serial, configuration);
        Self {
            profile,
            selected: None,
            chained_command: Vec::new(),
            pending_response: Vec::new(),
            fido,
        }
    }

    pub fn profile(&self) -> &DeviceProfile {
        &self.profile
    }

    pub fn selected_applet(&self) -> Option<Applet> {
        self.selected
    }

    pub fn power_on(&mut self) {
        self.reset();
    }

    pub fn power_off(&mut self) {
        self.reset();
    }

    pub fn reset(&mut self) {
        self.selected = None;
        self.chained_command.clear();
        self.pending_response.clear();
        self.fido.reset_connection();
    }

    pub fn transmit(&mut self, raw: &[u8]) -> Vec<u8> {
        let command = match CommandApdu::decode(raw) {
            Ok(command) => command,
            Err(_) => return ResponseApdu::status(0x6700).encode(),
        };

        if command.cla == 0 && command.ins == INS_GET_RESPONSE {
            return self.take_response(command.le).encode();
        }

        if command.ins == INS_SELECT && command.p1 == 0x04 {
            return self.select(command.data).encode();
        }

        match self.selected {
            Some(Applet::Management) => self.management(&command).encode(),
            Some(Applet::Fido2) => self.fido2(&command).encode(),
            None => ResponseApdu::status(0x6999).encode(),
        }
    }

    fn select(&mut self, aid: &[u8]) -> ResponseApdu {
        self.chained_command.clear();
        self.pending_response.clear();
        if aid == MANAGEMENT_AID && self.profile.applets.contains(Applet::Management) {
            self.selected = Some(Applet::Management);
            let mut data = MANAGEMENT_SELECT_PREFIX.to_vec();
            let [major, minor, patch] = self.profile.firmware;
            data.extend_from_slice(format!("{major}.{minor}.{patch}").as_bytes());
            ResponseApdu::success(data)
        } else if aid == FIDO2_AID && self.profile.applets.contains(Applet::Fido2) {
            self.selected = Some(Applet::Fido2);
            ResponseApdu::success(b"U2F_V2".to_vec())
        } else {
            self.selected = None;
            ResponseApdu::status(0x6a82)
        }
    }

    fn management(&self, command: &CommandApdu<'_>) -> ResponseApdu {
        if command.cla != 0 || command.ins != INS_READ_DEVICE_INFO || command.p2 != 0 {
            return ResponseApdu::status(0x6d00);
        }
        self.profile
            .management_device_info(command.p1)
            .map(ResponseApdu::success)
            .unwrap_or_else(|| ResponseApdu::status(0x6a86))
    }

    fn fido2(&mut self, command: &CommandApdu<'_>) -> ResponseApdu {
        if command.ins != INS_CTAP_CBOR || command.p2 != 0 {
            return ResponseApdu::status(0x6d00);
        }

        self.chained_command.extend_from_slice(command.data);
        if command.cla & 0x10 != 0 {
            return ResponseApdu::status(ISO7816_SUCCESS);
        }

        let request = std::mem::take(&mut self.chained_command);
        let response = self.fido.exchange(&request);
        self.pending_response = response;
        self.take_response(command.le)
    }

    fn take_response(&mut self, le: Option<u32>) -> ResponseApdu {
        let requested = le.unwrap_or(256).min(256) as usize;
        let count = requested.min(self.pending_response.len());
        let remaining = self.pending_response.split_off(count);
        let data = std::mem::replace(&mut self.pending_response, remaining);
        let status = if self.pending_response.is_empty() {
            ISO7816_SUCCESS
        } else {
            0x6100 | u16::try_from(self.pending_response.len().min(256)).unwrap_or(0)
        };
        ResponseApdu { data, status }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CommandApdu<'a> {
    pub cla: u8,
    pub ins: u8,
    pub p1: u8,
    pub p2: u8,
    pub data: &'a [u8],
    pub le: Option<u32>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApduDecodeError {
    TooShort,
    InvalidLength,
}

impl<'a> CommandApdu<'a> {
    pub fn decode(raw: &'a [u8]) -> Result<Self, ApduDecodeError> {
        if raw.len() < 4 {
            return Err(ApduDecodeError::TooShort);
        }
        let (data, le) = match raw.len() {
            4 => (&raw[4..4], None),
            5 => (&raw[4..4], Some(short_le(raw[4]))),
            _ if raw[4] != 0 => {
                let length = usize::from(raw[4]);
                let end = 5 + length;
                if raw.len() == end {
                    (&raw[5..end], None)
                } else if raw.len() == end + 1 {
                    (&raw[5..end], Some(short_le(raw[end])))
                } else {
                    return Err(ApduDecodeError::InvalidLength);
                }
            }
            7 => (
                &raw[7..7],
                Some(extended_le(u16::from_be_bytes([raw[5], raw[6]]))),
            ),
            _ => {
                if raw.len() < 7 {
                    return Err(ApduDecodeError::InvalidLength);
                }
                let length = usize::from(u16::from_be_bytes([raw[5], raw[6]]));
                if length == 0 {
                    return Err(ApduDecodeError::InvalidLength);
                }
                let end = 7 + length;
                if raw.len() == end {
                    (&raw[7..end], None)
                } else if raw.len() == end + 2 {
                    (
                        &raw[7..end],
                        Some(extended_le(u16::from_be_bytes([raw[end], raw[end + 1]]))),
                    )
                } else {
                    return Err(ApduDecodeError::InvalidLength);
                }
            }
        };
        Ok(Self {
            cla: raw[0],
            ins: raw[1],
            p1: raw[2],
            p2: raw[3],
            data,
            le,
        })
    }
}

fn short_le(value: u8) -> u32 {
    if value == 0 {
        256
    } else {
        u32::from(value)
    }
}

fn extended_le(value: u16) -> u32 {
    if value == 0 {
        65_536
    } else {
        u32::from(value)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResponseApdu {
    pub data: Vec<u8>,
    pub status: u16,
}

impl ResponseApdu {
    pub fn success(data: Vec<u8>) -> Self {
        Self {
            data,
            status: ISO7816_SUCCESS,
        }
    }

    pub fn status(status: u16) -> Self {
        Self {
            data: Vec::new(),
            status,
        }
    }

    pub fn encode(mut self) -> Vec<u8> {
        self.data.extend_from_slice(&self.status.to_be_bytes());
        self.data
    }
}

fn push_tlv(output: &mut Vec<u8>, tag: u8, value: &[u8]) {
    output.push(tag);
    output.push(value.len() as u8);
    output.extend_from_slice(value);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn select(aid: &[u8]) -> Vec<u8> {
        [
            vec![0, INS_SELECT, 0x04, 0, aid.len() as u8],
            aid.to_vec(),
            vec![0],
        ]
        .concat()
    }

    #[test]
    fn management_identity_is_derived_from_profile() {
        let mut device = VirtualYubiKey::new(DeviceProfile::yubikey_5_8_ccid(0x01020304));
        assert_eq!(
            device.transmit(&select(&MANAGEMENT_AID)),
            [b"Virtual mgr - FW version 5.8.0".as_slice(), &[0x90, 0]].concat()
        );
        let response = device.transmit(&[0, INS_READ_DEVICE_INFO, 0, 0, 0]);
        assert!(response.windows(6).any(|value| value == [2, 4, 1, 2, 3, 4]));
        assert!(response.windows(4).any(|value| value == [1, 2, 2, 4]));
        assert!(response.windows(4).any(|value| value == [3, 2, 2, 4]));
        assert!(response.windows(5).any(|value| value == [5, 3, 5, 8, 0]));
        assert_eq!(&response[response.len() - 2..], &[0x90, 0]);
    }

    #[test]
    fn reset_clears_selected_applet() {
        let mut device = VirtualYubiKey::new(DeviceProfile::yubikey_5_8_ccid(1));
        device.transmit(&select(&FIDO2_AID));
        assert_eq!(device.selected_applet(), Some(Applet::Fido2));
        device.reset();
        assert_eq!(device.selected_applet(), None);
        assert_eq!(
            device.transmit(&[0x80, INS_CTAP_CBOR, 0, 0, 1, 4]),
            [0x69, 0x99]
        );
    }

    #[test]
    fn fido_command_chaining_and_get_response_are_transport_neutral() {
        let mut device = VirtualYubiKey::new(DeviceProfile::yubikey_5_8_ccid(1));
        device.transmit(&select(&FIDO2_AID));
        assert_eq!(
            device.transmit(&[0x90, INS_CTAP_CBOR, 0, 0, 1, 0xff]),
            [0x90, 0]
        );
        assert_eq!(
            device.transmit(&[0x80, INS_CTAP_CBOR, 0, 0, 1, 0xaa]),
            [0x01, 0x90, 0]
        );

        let first = device.transmit(&[0x80, INS_CTAP_CBOR, 0, 0, 1, 4, 1]);
        assert_eq!(first[0], 0);
        assert_eq!(first[1], 0x61);
        let mut remainder = device.transmit(&[0, INS_GET_RESPONSE, 0, 0, 0]);
        while remainder[remainder.len() - 2] == 0x61 {
            remainder = device.transmit(&[0, INS_GET_RESPONSE, 0, 0, 0]);
        }
        assert_eq!(&remainder[remainder.len() - 2..], &[0x90, 0]);
    }

    #[test]
    fn parses_short_and_extended_apdu_cases() {
        assert_eq!(CommandApdu::decode(&[0, 1, 2, 3]).unwrap().le, None);
        assert_eq!(CommandApdu::decode(&[0, 1, 2, 3, 0]).unwrap().le, Some(256));
        let extended = CommandApdu::decode(&[0, 1, 2, 3, 0, 0, 1, 0xaa, 0, 0]).unwrap();
        assert_eq!(extended.data, &[0xaa]);
        assert_eq!(extended.le, Some(65_536));
    }
}
