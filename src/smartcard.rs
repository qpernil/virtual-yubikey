//! Diagnostic adapter from CCID to the transport-neutral logical device.

use crate::diagnostics::{self, Level};
use std::io;
use virtual_yubikey_core::{
    ApduExchange, Applet, CommandApdu, DeviceProfile, PresenceAuthorization, VirtualYubiKey,
};
#[cfg(test)]
use virtual_yubikey_core::{FIDO2_AID, PIV_AID};

pub(crate) use virtual_yubikey_core::ATR;
#[cfg(test)]
pub(crate) use virtual_yubikey_core::{MANAGEMENT_AID, OPENPGP_AID};

pub(crate) struct Card {
    device: VirtualYubiKey,
}

impl Card {
    pub(crate) fn new(serial: u32) -> Self {
        Self {
            device: VirtualYubiKey::new(DeviceProfile::yubikey_5_8_ccid(serial)),
        }
    }

    #[cfg(test)]
    pub(crate) fn with_profile(profile: DeviceProfile) -> Self {
        Self {
            device: VirtualYubiKey::new(profile),
        }
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn from_persistent_states(
        serial: u32,
        piv_encoded: &[u8],
        hsmauth_encoded: &[u8],
        security_domain_encoded: &[u8],
    ) -> Result<Self, &'static str> {
        Ok(Self {
            device: VirtualYubiKey::from_persistent_states(
                DeviceProfile::yubikey_5_8_ccid(serial),
                piv_encoded,
                hsmauth_encoded,
                security_domain_encoded,
            )?,
        })
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn piv_persistent_state(&self) -> Result<Vec<u8>, &'static str> {
        self.device.piv_persistent_state()
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn hsmauth_persistent_state(&self) -> Result<Vec<u8>, &'static str> {
        self.device.hsmauth_persistent_state()
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn security_domain_persistent_state(&self) -> Result<Vec<u8>, &'static str> {
        self.device.security_domain_persistent_state()
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn take_piv_persistent_change(&mut self) -> bool {
        self.device.take_piv_persistent_change()
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn take_hsmauth_persistent_change(&mut self) -> bool {
        self.device.take_hsmauth_persistent_change()
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn take_security_domain_persistent_change(&mut self) -> bool {
        self.device.take_security_domain_persistent_change()
    }

    pub(crate) fn reset(&mut self) {
        self.device.reset();
        diagnostics::log(
            Level::Debug,
            "smartcard",
            "reset",
            format_args!("selected=none"),
        );
    }

    pub(crate) fn transmit(&mut self, raw: &[u8]) -> Vec<u8> {
        self.transmit_inner(raw, || Ok(false))
            .expect("the direct smart-card transport has an infallible presence policy")
    }

    pub(crate) fn transmit_with_presence(
        &mut self,
        raw: &[u8],
        authorize: impl FnMut() -> io::Result<bool>,
    ) -> io::Result<Vec<u8>> {
        self.transmit_inner(raw, authorize)
    }

    fn transmit_inner(
        &mut self,
        raw: &[u8],
        mut authorize: impl FnMut() -> io::Result<bool>,
    ) -> io::Result<Vec<u8>> {
        if diagnostics::enabled(Level::Trace) {
            diagnostics::log(
                Level::Trace,
                "apdu",
                "request_payload",
                format_args!("hex={}", diagnostics::hex(raw)),
            );
        }

        let command = CommandApdu::decode(raw);
        match command.as_ref() {
            Ok(command) => diagnostics::log(
                Level::Debug,
                "apdu",
                "request",
                format_args!(
                    "cla={:02x} ins={:02x} p1={:02x} p2={:02x} data_length={} selected={}",
                    command.cla,
                    command.ins,
                    command.p1,
                    command.p2,
                    command.data.len(),
                    self.device.selected_applet().map_or("none", Applet::name)
                ),
            ),
            Err(reason) => diagnostics::log(
                Level::Info,
                "apdu",
                "parse_failed",
                format_args!("reason={reason:?} length={}", raw.len()),
            ),
        }

        let response = if command.as_ref().is_ok_and(|command| {
            command.ins == 0xa4
                && command.p1 == 0x04
                && self.device.applet_for_aid(command.data) == Some(Applet::Fido2)
        }) {
            self.device.reset();
            diagnostics::log(
                Level::Info,
                "fido2",
                "ccid_transport_unavailable",
                format_args!("use=fido_hid"),
            );
            vec![0x6a, 0x82]
        } else {
            match self
                .device
                .exchange_apdu(raw, PresenceAuthorization::Absent)
            {
                ApduExchange::Complete(response) => response,
                ApduExchange::PresenceRequired(_) if authorize()? => {
                    match self
                        .device
                        .exchange_apdu(raw, PresenceAuthorization::Granted)
                    {
                        ApduExchange::Complete(response) => response,
                        ApduExchange::PresenceRequired(_) => {
                            return Err(io::Error::other(
                                "smart-card operation requested presence after it was granted",
                            ));
                        }
                    }
                }
                ApduExchange::PresenceRequired(_) => vec![0x69, 0x85],
            }
        };
        if let Ok(command) = command {
            self.log_outcome(&command, &response);
        }
        self.log_response(&response);
        Ok(response)
    }

    fn log_outcome(&self, command: &CommandApdu<'_>, response: &[u8]) {
        let status = response_status(response);
        if command.ins == 0xa4 && command.p1 == 0x04 {
            diagnostics::log(
                Level::Info,
                "apdu",
                "select",
                format_args!(
                    "aid={} result={} sw={status:04x}",
                    diagnostics::hex(command.data),
                    self.device
                        .selected_applet()
                        .map_or("not_found", Applet::name)
                ),
            );
            return;
        }

        match self.device.selected_applet() {
            Some(Applet::Management) if command.cla == 0 && command.ins == 0x1d => {
                let profile = self.device.profile();
                let [major, minor, patch] = profile.firmware;
                diagnostics::log(
                    Level::Info,
                    "management",
                    if status == 0x9000 {
                        "device_info"
                    } else {
                        "device_info_failed"
                    },
                    format_args!(
                        "serial={} version={major}.{minor}.{patch} usb_capabilities=0x{:04x} page={} sw={status:04x}",
                        profile.serial,
                        profile.usb_enabled_capabilities(),
                        command.p1
                    ),
                );
            }
            Some(Applet::Piv) => {
                let state_changing =
                    matches!(command.ins, 0x20 | 0x24 | 0x2c | 0xff) && !command.data.is_empty();
                diagnostics::log(
                    if state_changing || status != 0x9000 {
                        Level::Info
                    } else {
                        Level::Debug
                    },
                    "piv",
                    piv_instruction_name(command.ins),
                    format_args!(
                        "ins={:02x} p1={:02x} p2={:02x} data_length={} sw={status:04x}",
                        command.ins,
                        command.p1,
                        command.p2,
                        command.data.len()
                    ),
                );
            }
            Some(Applet::HsmAuth) => {
                let state_changing = matches!(command.ins, 0x01 | 0x02 | 0x06 | 0x08 | 0x0b);
                diagnostics::log(
                    if state_changing || status != 0x9000 {
                        Level::Info
                    } else {
                        Level::Debug
                    },
                    "hsmauth",
                    hsmauth_instruction_name(command.ins),
                    format_args!(
                        "ins={:02x} p1={:02x} p2={:02x} data_length={} sw={status:04x}",
                        command.ins,
                        command.p1,
                        command.p2,
                        command.data.len()
                    ),
                );
            }
            _ => {}
        }
    }

    fn log_response(&self, response: &[u8]) {
        let status = response_status(response);
        diagnostics::log(
            Level::Debug,
            "apdu",
            "response",
            format_args!(
                "data_length={} sw={status:04x}",
                response.len().saturating_sub(2)
            ),
        );
        if diagnostics::enabled(Level::Trace) {
            diagnostics::log(
                Level::Trace,
                "apdu",
                "response_payload",
                format_args!("hex={}", diagnostics::hex(response)),
            );
        }
    }
}

fn hsmauth_instruction_name(instruction: u8) -> &'static str {
    match instruction {
        0x01 => "put_credential",
        0x02 => "delete_credential",
        0x03 => "calculate_session_keys",
        0x04 => "get_challenge",
        0x05 => "list_credentials",
        0x06 => "reset",
        0x07 => "get_version",
        0x08 => "put_management_key",
        0x09 => "get_management_key_retries",
        0x0a => "get_public_key",
        0x0b => "change_credential_password",
        _ => "unknown_instruction",
    }
}

fn piv_instruction_name(instruction: u8) -> &'static str {
    match instruction {
        0x20 => "verify_pin",
        0x24 => "change_reference",
        0x2c => "reset_retry",
        0x47 => "generate_key",
        0x87 => "authenticate",
        0xcb => "get_data",
        0xdb => "put_data",
        0xf6 => "move_key",
        0xf7 => "get_metadata",
        0xf8 => "get_serial",
        0xf9 => "attest",
        0xfd => "get_version",
        0xfe => "import_key",
        0xff => "set_management_key",
        _ => "unknown_instruction",
    }
}

fn response_status(response: &[u8]) -> u16 {
    response
        .get(response.len().saturating_sub(2)..)
        .and_then(|bytes| bytes.try_into().ok())
        .map(u16::from_be_bytes)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn select(aid: &[u8]) -> Vec<u8> {
        [
            vec![0, 0xa4, 0x04, 0, aid.len() as u8],
            aid.to_vec(),
            vec![0],
        ]
        .concat()
    }

    #[test]
    fn routes_management_through_the_shared_core() {
        let mut card = Card::new(0x01020304);
        assert_eq!(
            card.transmit(&select(&MANAGEMENT_AID)),
            [b"Virtual mgr - FW version 5.8.0".as_slice(), &[0x90, 0]].concat()
        );
        let response = card.transmit(&[0, 0x1d, 0, 0, 0]);
        assert!(response.windows(6).any(|value| value == [2, 4, 1, 2, 3, 4]));
        assert_eq!(&response[response.len() - 2..], &[0x90, 0]);
    }

    #[test]
    fn routes_piv_through_the_shared_core() {
        let mut card = Card::new(0x01020304);
        assert_eq!(&card.transmit(&select(&PIV_AID))[..2], &[0x61, 0x11]);
        assert_eq!(card.transmit(&[0, 0xfd, 0, 0, 0]), [5, 8, 0, 0x90, 0]);
        assert_eq!(card.transmit(&[0, 0xf8, 0, 0, 0]), [1, 2, 3, 4, 0x90, 0]);
        card.reset();
        assert_eq!(
            &card.transmit(&[
                0x00, 0xa4, 0x04, 0x00, 0x05, 0xa0, 0x00, 0x00, 0x03, 0x08, 0x00,
            ])[..2],
            &[0x61, 0x11]
        );
    }

    #[test]
    fn directs_usb_fido_clients_to_hid() {
        let mut card = Card::new(1);
        assert_eq!(card.transmit(&select(&FIDO2_AID)), [0x6a, 0x82]);
        assert_eq!(
            card.transmit(&select(&[0xa0, 0x00, 0x00, 0x06])),
            [0x6a, 0x82]
        );
        assert_eq!(card.transmit(&[0x80, 0x10, 0, 0, 1, 0x04, 0]), [0x69, 0x99]);
    }

    #[test]
    fn production_profile_does_not_expose_the_openpgp_fixture() {
        let mut card = Card::new(1);
        assert_eq!(card.transmit(&select(&OPENPGP_AID)), [0x6a, 0x82]);
    }

    #[test]
    fn unknown_aids_are_not_found() {
        let mut card = Card::new(1);
        assert_eq!(card.transmit(&select(&[1, 2, 3])), [0x6a, 0x82]);
    }
}
