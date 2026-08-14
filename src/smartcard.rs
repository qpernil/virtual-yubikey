//! Diagnostic adapter from CCID to the transport-neutral logical device.

use crate::diagnostics::{self, Level};
use virtual_yubikey_core::{Applet, CommandApdu, DeviceProfile, VirtualYubiKey};

pub(crate) use virtual_yubikey_core::ATR;
#[cfg(test)]
pub(crate) use virtual_yubikey_core::{FIDO2_AID, MANAGEMENT_AID};

pub(crate) struct Card {
    device: VirtualYubiKey,
}

impl Card {
    pub(crate) fn new(serial: u32) -> Self {
        Self {
            device: VirtualYubiKey::new(DeviceProfile::yubikey_5_8_ccid(serial)),
        }
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

        let response = self.device.transmit(raw);
        if let Ok(command) = command {
            self.log_outcome(&command, &response);
        }
        self.log_response(&response);
        response
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
                        profile.serial, profile.usb_enabled_capabilities(), command.p1
                    ),
                );
            }
            Some(Applet::Fido2) if command.ins == 0x10 => {
                let ctap_command = command.data.first().copied();
                diagnostics::log(
                    Level::Info,
                    "fido2",
                    if ctap_command == Some(0x04) {
                        "get_info"
                    } else {
                        "ctap_exchange"
                    },
                    format_args!(
                        "command={} payload_length={} sw={status:04x}",
                        ctap_command
                            .map_or_else(|| "none".to_owned(), |value| format!("{value:02x}")),
                        command.data.len().saturating_sub(1)
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
    fn routes_fido_through_the_shared_core() {
        let mut card = Card::new(1);
        assert_eq!(
            card.transmit(&select(&FIDO2_AID)),
            [b"U2F_V2".as_slice(), &[0x90, 0]].concat()
        );
        let response = card.transmit(&[0x80, 0x10, 0, 0, 1, 0x04, 0]);
        assert_eq!(response[0], 0);
        assert_eq!(&response[response.len() - 2..], &[0x90, 0]);
    }

    #[test]
    fn unknown_aids_are_not_found() {
        let mut card = Card::new(1);
        assert_eq!(card.transmit(&select(&[1, 2, 3])), [0x6a, 0x82]);
    }
}
