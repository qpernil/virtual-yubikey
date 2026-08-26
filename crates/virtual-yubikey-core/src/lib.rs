//! Transport-neutral logical YubiKey emulator.
//!
//! This crate owns device identity, ISO 7816 routing, applet state, and APDU
//! behavior. It deliberately contains no USB, CCID, PC/SC, PKCS #11, or
//! operating-system integration.

mod crypto;
mod fido;
mod hsmauth;
mod openpgp;
mod piv;
mod presence;
mod preview_sign;
use software_key_core::{
    post_quantum::MlDsaParameterSet, software_signing::SoftwareSigningAlgorithm,
};
use std::time::Duration;

pub const MANAGEMENT_AID: [u8; 8] = [0xa0, 0x00, 0x00, 0x05, 0x27, 0x47, 0x11, 0x17];
pub const FIDO2_AID: [u8; 8] = [0xa0, 0x00, 0x00, 0x06, 0x47, 0x2f, 0x00, 0x01];
pub use hsmauth::HSMAUTH_AID;
pub use openpgp::OPENPGP_AID;
pub use piv::PIV_AID;
pub const MAX_DISCOVERABLE_CREDENTIALS: usize = fido::MAX_RESIDENT_CREDENTIALS;
pub const PIV_TOUCH_CACHE_DURATION: Duration = Duration::from_secs(15);

/// Physical-presence policy requested by an applet operation.
///
/// Transports decide how a touch is collected. Keeping this result in the
/// logical core lets USB, PC/SC, and future in-process frontends share the same
/// applet policy without coupling the core to buttons or IPC.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UserPresencePolicy {
    Always,
    Cached(Duration),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PresenceAuthorization {
    Absent,
    Granted,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ApduExchange {
    Complete(Vec<u8>),
    PresenceRequired(UserPresencePolicy),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FidoCredentialAlgorithm {
    Es256,
    Esp256,
    Ed25519,
    Esp384,
    Esp512,
    Es256K,
    Ps256,
    Ps384,
    Ps512,
    Rs256,
    Rs384,
    Rs512,
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
            Self::Ps256 => -37,
            Self::Ps384 => -38,
            Self::Ps512 => -39,
            Self::Rs256 => -257,
            Self::Rs384 => -258,
            Self::Rs512 => -259,
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
            Self::Ps256 => "ps256",
            Self::Ps384 => "ps384",
            Self::Ps512 => "ps512",
            Self::Rs256 => "rs256",
            Self::Rs384 => "rs384",
            Self::Rs512 => "rs512",
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
            "ps256" => Some(Self::Ps256),
            "ps384" => Some(Self::Ps384),
            "ps512" => Some(Self::Ps512),
            "rs256" => Some(Self::Rs256),
            "rs384" => Some(Self::Rs384),
            "rs512" => Some(Self::Rs512),
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
            -37 => Some(Self::Ps256),
            -38 => Some(Self::Ps384),
            -39 => Some(Self::Ps512),
            -257 => Some(Self::Rs256),
            -258 => Some(Self::Rs384),
            -259 => Some(Self::Rs512),
            -48 => Some(Self::MlDsa44),
            -49 => Some(Self::MlDsa65),
            -50 => Some(Self::MlDsa87),
            _ => None,
        }
    }

    pub const fn ml_dsa_parameter_set(self) -> Option<MlDsaParameterSet> {
        match self {
            Self::Es256
            | Self::Esp256
            | Self::Ed25519
            | Self::Esp384
            | Self::Esp512
            | Self::Es256K
            | Self::Ps256
            | Self::Ps384
            | Self::Ps512
            | Self::Rs256
            | Self::Rs384
            | Self::Rs512 => None,
            Self::MlDsa44 => Some(MlDsaParameterSet::MlDsa44),
            Self::MlDsa65 => Some(MlDsaParameterSet::MlDsa65),
            Self::MlDsa87 => Some(MlDsaParameterSet::MlDsa87),
        }
    }

    pub const fn software_signing_algorithm(self) -> SoftwareSigningAlgorithm {
        match self {
            Self::Es256 | Self::Esp256 => SoftwareSigningAlgorithm::EcdsaP256Sha256,
            Self::Ed25519 => SoftwareSigningAlgorithm::Ed25519,
            Self::Esp384 => SoftwareSigningAlgorithm::EcdsaP384Sha384,
            Self::Esp512 => SoftwareSigningAlgorithm::EcdsaP521Sha512,
            Self::Es256K => SoftwareSigningAlgorithm::EcdsaSecp256k1Sha256,
            Self::Ps256 => SoftwareSigningAlgorithm::RsaPssSha256,
            Self::Ps384 => SoftwareSigningAlgorithm::RsaPssSha384,
            Self::Ps512 => SoftwareSigningAlgorithm::RsaPssSha512,
            Self::Rs256 => SoftwareSigningAlgorithm::RsaPkcs1Sha256,
            Self::Rs384 => SoftwareSigningAlgorithm::RsaPkcs1Sha384,
            Self::Rs512 => SoftwareSigningAlgorithm::RsaPkcs1Sha512,
            Self::MlDsa44 => SoftwareSigningAlgorithm::MlDsa(MlDsaParameterSet::MlDsa44),
            Self::MlDsa65 => SoftwareSigningAlgorithm::MlDsa(MlDsaParameterSet::MlDsa65),
            Self::MlDsa87 => SoftwareSigningAlgorithm::MlDsa(MlDsaParameterSet::MlDsa87),
        }
    }

    pub const fn from_ml_dsa_parameter_set(parameter_set: MlDsaParameterSet) -> Option<Self> {
        match parameter_set {
            MlDsaParameterSet::MlDsa44 => Some(Self::MlDsa44),
            MlDsaParameterSet::MlDsa65 => Some(Self::MlDsa65),
            MlDsaParameterSet::MlDsa87 => Some(Self::MlDsa87),
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
const CAPABILITY_OPENPGP: u16 = 0x0008;
const CAPABILITY_PIV: u16 = 0x0010;
const CAPABILITY_HSMAUTH: u16 = 0x0100;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Applet {
    Management,
    HsmAuth,
    OpenPgp,
    Piv,
    Fido2,
}

impl Applet {
    pub const fn name(self) -> &'static str {
        match self {
            Self::Management => "management",
            Self::HsmAuth => "hsmauth",
            Self::OpenPgp => "openpgp",
            Self::Piv => "piv",
            Self::Fido2 => "fido2",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AppletConfiguration {
    pub management: bool,
    pub hsmauth: bool,
    pub openpgp: bool,
    pub piv: bool,
    pub fido2: bool,
}

impl AppletConfiguration {
    pub const fn yubikey_5_8_preview_sign() -> Self {
        Self {
            management: true,
            hsmauth: true,
            // The OpenPGP implementation is currently only a transport test
            // fixture. Do not advertise or select it on the real USB profile.
            openpgp: false,
            piv: true,
            fido2: true,
        }
    }

    pub const fn contains(self, applet: Applet) -> bool {
        match applet {
            Applet::Management => self.management,
            Applet::HsmAuth => self.hsmauth,
            Applet::OpenPgp => self.openpgp,
            Applet::Piv => self.piv,
            Applet::Fido2 => self.fido2,
        }
    }

    pub const fn usb_capabilities(self) -> u16 {
        let ccid = if self.management || self.hsmauth || self.openpgp || self.piv || self.fido2 {
            CAPABILITY_CCID
        } else {
            0
        };
        let openpgp = if self.openpgp { CAPABILITY_OPENPGP } else { 0 };
        let piv = if self.piv { CAPABILITY_PIV } else { 0 };
        let hsmauth = if self.hsmauth { CAPABILITY_HSMAUTH } else { 0 };
        let fido2 = if self.fido2 { CAPABILITY_FIDO2 } else { 0 };
        ccid | openpgp | piv | hsmauth | fido2
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
                FidoCredentialAlgorithm::Ps256,
                FidoCredentialAlgorithm::Ps384,
                FidoCredentialAlgorithm::Ps512,
                FidoCredentialAlgorithm::Rs256,
                FidoCredentialAlgorithm::Rs384,
                FidoCredentialAlgorithm::Rs512,
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

#[derive(Clone, Debug)]
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
    chained_command: Option<ChainedCommand>,
    presence_command: Option<PresenceCommand>,
    pending_response: Vec<u8>,
    piv: piv::PivApplet,
    hsmauth: hsmauth::HsmAuthApplet,
    fido: FidoAuthenticator,
}

#[derive(Debug)]
struct OwnedCommandApdu {
    cla: u8,
    ins: u8,
    p1: u8,
    p2: u8,
    data: Vec<u8>,
    le: Option<u32>,
}

impl OwnedCommandApdu {
    fn borrowed(&self) -> CommandApdu<'_> {
        CommandApdu {
            cla: self.cla,
            ins: self.ins,
            p1: self.p1,
            p2: self.p2,
            data: &self.data,
            le: self.le,
        }
    }

    fn matches(&self, command: &CommandApdu<'_>) -> bool {
        self.cla == command.cla
            && self.ins == command.ins
            && self.p1 == command.p1
            && self.p2 == command.p2
            && self.data == command.data
            && self.le == command.le
    }
}

#[derive(Debug)]
struct ChainedCommand {
    selected: Option<Applet>,
    command: OwnedCommandApdu,
}

#[derive(Debug)]
struct PresenceCommand {
    selected: Option<Applet>,
    command: OwnedCommandApdu,
    final_fragment: OwnedCommandApdu,
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
        let piv = piv::PivApplet::new(profile.serial, profile.firmware);
        let hsmauth = hsmauth::HsmAuthApplet::new(profile.serial, profile.firmware);
        Self::with_applets(profile, piv, hsmauth, fido)
    }

    pub fn from_persistent_states(
        profile: DeviceProfile,
        piv_encoded: &[u8],
        hsmauth_encoded: &[u8],
    ) -> Result<Self, &'static str> {
        let fido = FidoAuthenticator::for_serial(profile.serial);
        let piv =
            piv::PivApplet::from_persistent_state(profile.serial, profile.firmware, piv_encoded)?;
        let hsmauth = hsmauth::HsmAuthApplet::from_persistent_state(
            profile.serial,
            profile.firmware,
            hsmauth_encoded,
        )?;
        Ok(Self::with_applets(profile, piv, hsmauth, fido))
    }

    fn with_applets(
        profile: DeviceProfile,
        piv: piv::PivApplet,
        hsmauth: hsmauth::HsmAuthApplet,
        fido: FidoAuthenticator,
    ) -> Self {
        Self {
            profile,
            selected: None,
            chained_command: None,
            presence_command: None,
            pending_response: Vec::new(),
            piv,
            hsmauth,
            fido,
        }
    }

    pub fn piv_persistent_state(&self) -> Result<Vec<u8>, &'static str> {
        self.piv.persistent_state()
    }

    pub fn hsmauth_persistent_state(&self) -> Result<Vec<u8>, &'static str> {
        self.hsmauth.persistent_state()
    }

    pub fn take_piv_persistent_change(&mut self) -> bool {
        self.piv.take_persistent_change()
    }

    pub fn take_hsmauth_persistent_change(&mut self) -> bool {
        self.hsmauth.take_persistent_change()
    }

    pub fn profile(&self) -> &DeviceProfile {
        &self.profile
    }

    pub fn selected_applet(&self) -> Option<Applet> {
        self.selected
    }

    pub fn applet_for_aid(&self, aid: &[u8]) -> Option<Applet> {
        if aid.is_empty() {
            return None;
        }
        let candidates: [(Applet, &[u8]); 5] = [
            (Applet::Management, &MANAGEMENT_AID),
            (Applet::HsmAuth, &HSMAUTH_AID),
            (Applet::OpenPgp, &OPENPGP_AID),
            (Applet::Piv, &PIV_AID),
            (Applet::Fido2, &FIDO2_AID),
        ];
        let mut matching = candidates.into_iter().filter(|(applet, candidate)| {
            self.profile.applets.contains(*applet) && candidate.starts_with(aid)
        });
        let (applet, _) = matching.next()?;
        matching.next().is_none().then_some(applet)
    }

    pub fn power_on(&mut self) {
        self.reset();
    }

    pub fn power_off(&mut self) {
        self.reset();
    }

    pub fn reset(&mut self) {
        self.selected = None;
        self.chained_command = None;
        self.presence_command = None;
        self.pending_response.clear();
        self.piv.reset_connection();
        self.hsmauth.reset_connection();
        self.fido.reset_connection();
    }

    pub fn transmit(&mut self, raw: &[u8]) -> Vec<u8> {
        match self.exchange_apdu(raw, PresenceAuthorization::Absent) {
            ApduExchange::Complete(response) => response,
            ApduExchange::PresenceRequired(_) => ResponseApdu::status(0x6985).encode(),
        }
    }

    pub fn exchange_apdu(&mut self, raw: &[u8], presence: PresenceAuthorization) -> ApduExchange {
        let command = match CommandApdu::decode(raw) {
            Ok(command) => command,
            Err(_) => return ApduExchange::Complete(ResponseApdu::status(0x6700).encode()),
        };

        if presence == PresenceAuthorization::Granted {
            let Some(pending) = self.presence_command.take() else {
                return ApduExchange::Complete(ResponseApdu::status(0x6985).encode());
            };
            if pending.selected != self.selected || !pending.final_fragment.matches(&command) {
                return ApduExchange::Complete(ResponseApdu::status(0x6985).encode());
            }
            return self.dispatch_apdu(&pending.command.borrowed(), presence);
        }
        self.presence_command = None;

        if command.cla == 0 && command.ins == INS_GET_RESPONSE {
            return ApduExchange::Complete(self.take_response(command.le).encode());
        }
        self.pending_response.clear();

        if command.ins == INS_SELECT && command.p1 == 0x04 {
            return ApduExchange::Complete(self.select(command.data).encode());
        }

        let final_fragment = OwnedCommandApdu {
            cla: command.cla,
            ins: command.ins,
            p1: command.p1,
            p2: command.p2,
            data: command.data.to_vec(),
            le: command.le,
        };
        let command = match self.reassemble_command(command) {
            Ok(Some(command)) => command,
            Ok(None) => {
                return ApduExchange::Complete(ResponseApdu::status(ISO7816_SUCCESS).encode());
            }
            Err(status) => return ApduExchange::Complete(ResponseApdu::status(status).encode()),
        };
        let result = self.dispatch_apdu(&command.borrowed(), presence);
        if matches!(result, ApduExchange::PresenceRequired(_)) {
            self.presence_command = Some(PresenceCommand {
                selected: self.selected,
                command,
                final_fragment,
            });
        }
        result
    }

    fn dispatch_apdu(
        &mut self,
        command: &CommandApdu<'_>,
        presence: PresenceAuthorization,
    ) -> ApduExchange {
        let response = match self.selected {
            Some(Applet::Management) => self.management(command),
            Some(Applet::HsmAuth) => match self.hsmauth.exchange(command, presence) {
                hsmauth::HsmAuthExchange::Complete(response) => response,
                hsmauth::HsmAuthExchange::PresenceRequired(policy) => {
                    return ApduExchange::PresenceRequired(policy);
                }
            },
            Some(Applet::OpenPgp) => openpgp::transmit(command),
            Some(Applet::Piv) => match self.piv.exchange(command, presence) {
                piv::PivExchange::Complete(response) => response,
                piv::PivExchange::PresenceRequired(policy) => {
                    return ApduExchange::PresenceRequired(policy);
                }
            },
            Some(Applet::Fido2) => self.fido2(command),
            None => ResponseApdu::status(0x6999),
        };
        ApduExchange::Complete(self.prepare_response(command.le, response).encode())
    }

    fn reassemble_command(
        &mut self,
        command: CommandApdu<'_>,
    ) -> Result<Option<OwnedCommandApdu>, u16> {
        let chaining = command.cla & 0x10 != 0;
        let base_cla = command.cla & !0x10;
        if chaining {
            let pending = self.chained_command.get_or_insert_with(|| ChainedCommand {
                selected: self.selected,
                command: OwnedCommandApdu {
                    cla: base_cla,
                    ins: command.ins,
                    p1: command.p1,
                    p2: command.p2,
                    data: Vec::new(),
                    le: None,
                },
            });
            if pending.selected != self.selected
                || pending.command.cla != base_cla
                || pending.command.ins != command.ins
                || pending.command.p1 != command.p1
                || pending.command.p2 != command.p2
                || command.le.is_some()
            {
                self.chained_command = None;
                return Err(0x6883);
            }
            if pending
                .command
                .data
                .len()
                .saturating_add(command.data.len())
                > 65_535
            {
                self.chained_command = None;
                return Err(0x6700);
            }
            pending.command.data.extend_from_slice(command.data);
            return Ok(None);
        }

        if let Some(mut pending) = self.chained_command.take() {
            if pending.selected != self.selected
                || pending.command.cla != command.cla
                || pending.command.ins != command.ins
                || pending.command.p1 != command.p1
                || pending.command.p2 != command.p2
            {
                return Err(0x6883);
            }
            if pending
                .command
                .data
                .len()
                .saturating_add(command.data.len())
                > 65_535
            {
                return Err(0x6700);
            }
            pending.command.data.extend_from_slice(command.data);
            pending.command.le = command.le;
            Ok(Some(pending.command))
        } else {
            Ok(Some(OwnedCommandApdu {
                cla: command.cla,
                ins: command.ins,
                p1: command.p1,
                p2: command.p2,
                data: command.data.to_vec(),
                le: command.le,
            }))
        }
    }

    fn select(&mut self, aid: &[u8]) -> ResponseApdu {
        self.chained_command = None;
        self.presence_command = None;
        self.pending_response.clear();
        let Some(applet) = self.applet_for_aid(aid) else {
            self.selected = None;
            return ResponseApdu::status(0x6a82);
        };
        self.selected = Some(applet);
        match applet {
            Applet::Management => {
                let mut data = MANAGEMENT_SELECT_PREFIX.to_vec();
                let [major, minor, patch] = self.profile.firmware;
                data.extend_from_slice(format!("{major}.{minor}.{patch}").as_bytes());
                ResponseApdu::success(data)
            }
            Applet::HsmAuth => ResponseApdu::success(self.hsmauth.select_response()),
            Applet::OpenPgp => ResponseApdu::success(Vec::new()),
            Applet::Piv => ResponseApdu::success(piv::select_response()),
            Applet::Fido2 => ResponseApdu::success(b"U2F_V2".to_vec()),
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

        let response = self.fido.exchange(command.data);
        ResponseApdu::success(response)
    }

    fn prepare_response(&mut self, le: Option<u32>, response: ResponseApdu) -> ResponseApdu {
        let requested = le.unwrap_or(256).min(65_536) as usize;
        if response.status != ISO7816_SUCCESS || response.data.len() <= requested {
            return response;
        }
        self.pending_response = response.data;
        self.take_response_count(requested)
    }

    fn take_response(&mut self, le: Option<u32>) -> ResponseApdu {
        let requested = le.unwrap_or(256).min(256) as usize;
        self.take_response_count(requested)
    }

    fn take_response_count(&mut self, requested: usize) -> ResponseApdu {
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

    fn openpgp_test_profile(serial: u32) -> DeviceProfile {
        let mut profile = DeviceProfile::yubikey_5_8_ccid(serial);
        profile.applets.openpgp = true;
        profile
    }

    fn select(aid: &[u8]) -> Vec<u8> {
        [
            vec![0, INS_SELECT, 0x04, 0, aid.len() as u8],
            aid.to_vec(),
            vec![0],
        ]
        .concat()
    }

    fn test_tlv(tag: u8, value: &[u8]) -> Vec<u8> {
        let mut encoded = vec![tag];
        match value.len() {
            0..=0x7f => encoded.push(value.len() as u8),
            0x80..=0xff => encoded.extend([0x81, value.len() as u8]),
            _ => panic!("test TLV is too large"),
        }
        encoded.extend_from_slice(value);
        encoded
    }

    fn short_apdu(cla: u8, ins: u8, p1: u8, p2: u8, data: &[u8], le: Option<u8>) -> Vec<u8> {
        assert!(data.len() <= 255);
        let mut encoded = vec![cla, ins, p1, p2];
        if data.is_empty() {
            if let Some(le) = le {
                encoded.push(le);
            }
            return encoded;
        }
        encoded.push(data.len() as u8);
        encoded.extend_from_slice(data);
        if let Some(le) = le {
            encoded.push(le);
        }
        encoded
    }

    fn hsmauth_symmetric_put(label: &str, touch_required: bool) -> Vec<u8> {
        [
            test_tlv(0x7b, &[0; 16]),
            test_tlv(0x71, label.as_bytes()),
            test_tlv(0x74, &[38]),
            test_tlv(0x75, &[0x11; 16]),
            test_tlv(0x76, &[0x22; 16]),
            test_tlv(0x73, &[0x33; 16]),
            test_tlv(0x7a, &[u8::from(touch_required)]),
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
        assert!(response.windows(4).any(|value| value == [1, 2, 3, 20]));
        assert!(response.windows(4).any(|value| value == [3, 2, 3, 20]));
        assert!(response.windows(5).any(|value| value == [5, 3, 5, 8, 0]));
        assert_eq!(&response[response.len() - 2..], &[0x90, 0]);
    }

    #[test]
    fn selects_any_nonempty_unique_aid_prefix() {
        let mut device = VirtualYubiKey::new(DeviceProfile::yubikey_5_8_ccid(1));
        assert_eq!(
            device.applet_for_aid(&[0xa0, 0x00, 0x00, 0x03]),
            Some(Applet::Piv)
        );
        assert_eq!(
            device.applet_for_aid(&[0xa0, 0x00, 0x00, 0x05, 0x27, 0x47]),
            Some(Applet::Management)
        );
        assert_eq!(
            device.applet_for_aid(&[0xa0, 0x00, 0x00, 0x05, 0x27, 0x21]),
            Some(Applet::HsmAuth)
        );
        assert_eq!(device.applet_for_aid(&[0xa0, 0x00, 0x00, 0x05]), None);
        assert_eq!(
            device.applet_for_aid(&[0xa0, 0x00, 0x00, 0x06]),
            Some(Applet::Fido2)
        );
        assert_eq!(device.applet_for_aid(&OPENPGP_AID), None);
        assert_eq!(device.applet_for_aid(&[0xa0, 0x00, 0x00]), None);
        assert_eq!(device.applet_for_aid(&[]), None);
        assert_eq!(
            &device.transmit(&select(&[0xa0, 0x00, 0x00, 0x03]))[..2],
            &[0x61, 0x11]
        );
        assert_eq!(device.selected_applet(), Some(Applet::Piv));
        assert_eq!(device.transmit(&select(&[0xa0, 0x00, 0x00])), [0x6a, 0x82]);
        assert_eq!(device.selected_applet(), None);
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
    fn openpgp_get_challenge_honors_extended_le_up_to_its_buffer() {
        let mut device = VirtualYubiKey::new(openpgp_test_profile(1));
        assert_eq!(device.transmit(&select(&OPENPGP_AID)), [0x90, 0x00]);
        assert_eq!(device.selected_applet(), Some(Applet::OpenPgp));

        let response = device.transmit(&[0x00, 0x84, 0x00, 0x00, 0x00, 0x0c, 0x00]);
        assert_eq!(response.len(), 3_072 + 2);
        assert_eq!(&response[response.len() - 2..], &[0x90, 0x00]);

        let capped = device.transmit(&[0x00, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00]);
        assert_eq!(capped.len(), openpgp::MAX_RANDOM_RESPONSE_LENGTH + 2);
        assert_eq!(&capped[capped.len() - 2..], &[0x90, 0x00]);
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
    fn hsmauth_list_uses_generic_response_chaining() {
        let mut device = VirtualYubiKey::new(DeviceProfile::yubikey_5_8_ccid(1));
        assert_eq!(
            device.transmit(&select(&HSMAUTH_AID)),
            [0x79, 3, 5, 8, 0, 0x90, 0]
        );
        for suffix in 0..5 {
            let label = format!("{suffix}{}", "x".repeat(63));
            let data = hsmauth_symmetric_put(&label, false);
            assert_eq!(
                device.transmit(&short_apdu(0, 0x01, 0, 0, &data, None)),
                [0x90, 0]
            );
        }

        let first = device.transmit(&[0, 0x05, 0, 0, 10]);
        assert_eq!(first.len(), 12);
        assert_eq!(first[first.len() - 2], 0x61);
        let mut data = first[..first.len() - 2].to_vec();
        let mut status = u16::from_be_bytes(first[first.len() - 2..].try_into().unwrap());
        while status & 0xff00 == 0x6100 {
            let next = device.transmit(&[0, INS_GET_RESPONSE, 0, 0, 0]);
            data.extend_from_slice(&next[..next.len() - 2]);
            status = u16::from_be_bytes(next[next.len() - 2..].try_into().unwrap());
        }
        assert_eq!(status, 0x9000);
        assert_eq!(data.len(), 5 * 69);
    }

    #[test]
    fn hsmauth_chained_touch_command_is_preserved_until_presence_is_granted() {
        use software_key_core::secure_channel::{scp03_cryptogram, scp03_key};

        let mut device = VirtualYubiKey::new(DeviceProfile::yubikey_5_8_ccid(2));
        device.transmit(&select(&HSMAUTH_AID));
        let put = hsmauth_symmetric_put("touch key", true);
        assert_eq!(
            device.transmit(&short_apdu(0, 0x01, 0, 0, &put, None)),
            [0x90, 0]
        );

        let challenge_data = test_tlv(0x71, b"touch key");
        let challenge = device.transmit(&short_apdu(0, 0x04, 0, 0, &challenge_data, None));
        assert_eq!(&challenge[challenge.len() - 2..], &[0x90, 0]);
        let mut context = challenge[..challenge.len() - 2].to_vec();
        context.extend_from_slice(&[0x44; 8]);
        let s_enc = scp03_key(&[0x11; 16], 0x04, &context).unwrap();
        let s_mac = scp03_key(&[0x22; 16], 0x06, &context).unwrap();
        let s_rmac = scp03_key(&[0x22; 16], 0x07, &context).unwrap();
        let cryptogram = scp03_cryptogram(&s_mac, 0, &context).unwrap();
        let calculate = [
            test_tlv(0x71, b"touch key"),
            test_tlv(0x77, &context),
            test_tlv(0x78, &cryptogram),
            test_tlv(0x73, &[0x33; 16]),
        ]
        .concat();
        let split = calculate.len() / 2;
        assert_eq!(
            device.transmit(&short_apdu(0x10, 0x03, 0, 0, &calculate[..split], None)),
            [0x90, 0]
        );
        let final_fragment = short_apdu(0, 0x03, 0, 0, &calculate[split..], None);
        assert_eq!(
            device.exchange_apdu(&final_fragment, PresenceAuthorization::Absent),
            ApduExchange::PresenceRequired(UserPresencePolicy::Always)
        );
        assert_eq!(
            device.exchange_apdu(&final_fragment, PresenceAuthorization::Granted),
            ApduExchange::Complete(
                [
                    s_enc.as_slice(),
                    s_mac.as_slice(),
                    s_rmac.as_slice(),
                    &[0x90, 0]
                ]
                .concat()
            )
        );
    }

    #[test]
    fn piv_and_hsmauth_persistence_are_independent() {
        let profile = DeviceProfile::yubikey_5_8_ccid(0x01020304);
        let mut device = VirtualYubiKey::new(profile.clone());
        device.transmit(&select(&HSMAUTH_AID));
        let put = hsmauth_symmetric_put("persistent", false);
        assert_eq!(
            device.transmit(&short_apdu(0, 0x01, 0, 0, &put, None)),
            [0x90, 0]
        );
        assert!(!device.take_piv_persistent_change());
        assert!(device.take_hsmauth_persistent_change());
        assert!(!device.take_hsmauth_persistent_change());

        let piv_encoded = device.piv_persistent_state().unwrap();
        let hsmauth_encoded = device.hsmauth_persistent_state().unwrap();
        let mut restored =
            VirtualYubiKey::from_persistent_states(profile, &piv_encoded, &hsmauth_encoded)
                .unwrap();
        assert_eq!(restored.selected_applet(), None);
        assert!(!restored.take_piv_persistent_change());
        assert!(!restored.take_hsmauth_persistent_change());
        restored.transmit(&select(&HSMAUTH_AID));
        let list = restored.transmit(&[0, 0x05, 0, 0, 0]);
        assert!(list
            .windows(b"persistent".len())
            .any(|value| value == b"persistent"));
        assert_eq!(&list[list.len() - 2..], &[0x90, 0]);

        assert_eq!(
            VirtualYubiKey::from_persistent_states(
                DeviceProfile::yubikey_5_8_ccid(7),
                &piv_encoded,
                &hsmauth_encoded,
            )
            .unwrap_err(),
            "persistent PIV state belongs to another device serial"
        );
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
