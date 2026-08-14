//! Read-only YubiKey Management and FIDO2 smart-card applet mock.

use crate::diagnostics::{self, Level};

pub(crate) const MANAGEMENT_AID: [u8; 8] = [0xa0, 0x00, 0x00, 0x05, 0x27, 0x47, 0x11, 0x17];
pub(crate) const FIDO2_AID: [u8; 8] = [0xa0, 0x00, 0x00, 0x06, 0x47, 0x2f, 0x00, 0x01];

pub(crate) const ATR: [u8; 23] = [
    0x3b, 0xfd, 0x13, 0x00, 0x00, 0x81, 0x31, 0xfe, 0x15, 0x80, 0x73, 0xc0, 0x21, 0xc0, 0x57, 0x59,
    0x75, 0x62, 0x69, 0x4b, 0x65, 0x79, 0x40,
];

const INS_SELECT: u8 = 0xa4;
const INS_READ_DEVICE_INFO: u8 = 0x1d;
const INS_CTAP_CBOR: u8 = 0x10;
const CTAP_GET_INFO: u8 = 0x04;
const FIRMWARE_VERSION: [u8; 3] = [5, 8, 0];
const MANAGEMENT_SELECT_RESPONSE: &[u8] = b"Virtual mgr - FW version 5.8.0";
// Management-over-CCID and the general CCID marker.
const CCID_ONLY_CAPABILITIES: [u8; 2] = [0x04, 0x04];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Applet {
    Management,
    Fido2,
}

impl Applet {
    fn name(self) -> &'static str {
        match self {
            Self::Management => "management",
            Self::Fido2 => "fido2",
        }
    }
}

pub(crate) struct Card {
    serial: u32,
    selected: Option<Applet>,
}

impl Card {
    pub(crate) fn new(serial: u32) -> Self {
        Self {
            serial,
            selected: None,
        }
    }

    pub(crate) fn reset(&mut self) {
        self.selected = None;
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

        let command = match CommandApdu::parse(raw) {
            Ok(command) => command,
            Err(reason) => {
                diagnostics::log(
                    Level::Info,
                    "apdu",
                    "parse_failed",
                    format_args!("reason={reason:?} length={}", raw.len()),
                );
                return status(0x67, 0x00);
            }
        };

        diagnostics::log(
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
                self.selected.map_or("none", Applet::name)
            ),
        );

        let response = if command.ins == INS_SELECT && command.p1 == 0x04 {
            self.select(&command)
        } else {
            match self.selected {
                Some(Applet::Management) => self.management(&command),
                Some(Applet::Fido2) => self.fido2(&command),
                None => {
                    diagnostics::log(
                        Level::Info,
                        "apdu",
                        "rejected",
                        format_args!(
                            "reason=no_applet_selected cla={:02x} ins={:02x} sw=6999",
                            command.cla, command.ins
                        ),
                    );
                    status(0x69, 0x99)
                }
            }
        };

        let sw = response
            .get(response.len().saturating_sub(2)..)
            .unwrap_or_default();
        diagnostics::log(
            Level::Debug,
            "apdu",
            "response",
            format_args!(
                "data_length={} sw={}",
                response.len().saturating_sub(2),
                diagnostics::hex(sw)
            ),
        );
        if diagnostics::enabled(Level::Trace) {
            diagnostics::log(
                Level::Trace,
                "apdu",
                "response_payload",
                format_args!("hex={}", diagnostics::hex(&response)),
            );
        }
        response
    }

    fn select(&mut self, command: &CommandApdu<'_>) -> Vec<u8> {
        let (applet, response) = if command.data == MANAGEMENT_AID {
            (
                Some(Applet::Management),
                with_status(MANAGEMENT_SELECT_RESPONSE, 0x90, 0x00),
            )
        } else if command.data == FIDO2_AID {
            (Some(Applet::Fido2), with_status(b"FIDO_2_0", 0x90, 0x00))
        } else {
            (None, status(0x6a, 0x82))
        };
        self.selected = applet;
        diagnostics::log(
            Level::Info,
            "apdu",
            "select",
            format_args!(
                "aid={} result={} sw={}",
                diagnostics::hex(command.data),
                applet.map_or("not_found", Applet::name),
                diagnostics::hex(&response[response.len() - 2..])
            ),
        );
        response
    }

    fn management(&self, command: &CommandApdu<'_>) -> Vec<u8> {
        if command.cla == 0 && command.ins == INS_READ_DEVICE_INFO && command.p2 == 0 {
            if command.p1 != 0 {
                diagnostics::log(
                    Level::Info,
                    "management",
                    "unsupported_page",
                    format_args!("page={} sw=6a86", command.p1),
                );
                return status(0x6a, 0x86);
            }
            let body = self.device_info();
            let mut response = Vec::with_capacity(body.len() + 3);
            response.push(body.len() as u8);
            response.extend_from_slice(&body);
            response.extend_from_slice(&[0x90, 0x00]);
            diagnostics::log(
                Level::Info,
                "management",
                "device_info",
                format_args!(
                    "serial={} version=5.8.0 usb_capabilities=0x0404",
                    self.serial
                ),
            );
            response
        } else {
            diagnostics::log(
                Level::Info,
                "management",
                "unsupported_command",
                format_args!(
                    "cla={:02x} ins={:02x} p1={:02x} p2={:02x} sw=6d00",
                    command.cla, command.ins, command.p1, command.p2
                ),
            );
            status(0x6d, 0x00)
        }
    }

    fn device_info(&self) -> Vec<u8> {
        let mut body = Vec::new();
        // General CCID and Management-over-CCID bits. FIDO2 over this CCID
        // prototype is intentionally not advertised as a FIDO HID interface.
        push_tlv(&mut body, 0x01, &CCID_ONLY_CAPABILITIES);
        push_tlv(&mut body, 0x02, &self.serial.to_be_bytes());
        push_tlv(&mut body, 0x03, &CCID_ONLY_CAPABILITIES);
        push_tlv(&mut body, 0x04, &[0x01]); // USB-A keychain form factor
        push_tlv(&mut body, 0x05, &FIRMWARE_VERSION);
        push_tlv(&mut body, 0x08, &[0]);
        body
    }

    fn fido2(&self, command: &CommandApdu<'_>) -> Vec<u8> {
        if command.cla == 0x80 && command.ins == INS_CTAP_CBOR {
            let Some((&ctap_command, payload)) = command.data.split_first() else {
                return with_status(&[0x12], 0x90, 0x00);
            };
            if ctap_command == CTAP_GET_INFO && payload.is_empty() {
                diagnostics::log(
                    Level::Info,
                    "fido2",
                    "get_info",
                    format_args!("versions=FIDO_2_0 extensions=none"),
                );
                let mut response = vec![0x00];
                response.extend_from_slice(&get_info_cbor());
                response.extend_from_slice(&[0x90, 0x00]);
                return response;
            }
            diagnostics::log(
                Level::Info,
                "fido2",
                "unsupported_ctap_command",
                format_args!(
                    "command={ctap_command:02x} payload_length={}",
                    payload.len()
                ),
            );
            return with_status(&[0x01], 0x90, 0x00);
        }

        diagnostics::log(
            Level::Info,
            "fido2",
            "unsupported_apdu",
            format_args!(
                "cla={:02x} ins={:02x} p1={:02x} p2={:02x} sw=6d00",
                command.cla, command.ins, command.p1, command.p2
            ),
        );
        status(0x6d, 0x00)
    }
}

fn get_info_cbor() -> Vec<u8> {
    // {1: ["FIDO_2_0"], 3: 16-byte AAGUID, 4: options,
    //  5: maxMsgSize, 9: ["usb"]}
    let mut output = vec![
        0xa5, 0x01, 0x81, 0x68, b'F', b'I', b'D', b'O', b'_', b'2', b'_', b'0', 0x03, 0x50,
    ];
    output.extend_from_slice(&[0; 16]);
    output.extend_from_slice(&[
        0x04, 0xa3, 0x62, b'r', b'k', 0xf4, 0x62, b'u', b'p', 0xf5, 0x69, b'c', b'l', b'i', b'e',
        b'n', b't', b'P', b'i', b'n', 0xf4, 0x05, 0x19, 0x10, 0x00, 0x09, 0x81, 0x63, b'u', b's',
        b'b',
    ]);
    output
}

fn push_tlv(output: &mut Vec<u8>, tag: u8, value: &[u8]) {
    output.push(tag);
    output.push(value.len() as u8);
    output.extend_from_slice(value);
}

fn with_status(data: &[u8], sw1: u8, sw2: u8) -> Vec<u8> {
    let mut output = Vec::with_capacity(data.len() + 2);
    output.extend_from_slice(data);
    output.extend_from_slice(&[sw1, sw2]);
    output
}

fn status(sw1: u8, sw2: u8) -> Vec<u8> {
    vec![sw1, sw2]
}

struct CommandApdu<'a> {
    cla: u8,
    ins: u8,
    p1: u8,
    p2: u8,
    data: &'a [u8],
}

#[derive(Debug)]
enum ApduParseError {
    TooShort,
    InvalidLength,
}

impl<'a> CommandApdu<'a> {
    fn parse(raw: &'a [u8]) -> Result<Self, ApduParseError> {
        if raw.len() < 4 {
            return Err(ApduParseError::TooShort);
        }
        let data = match raw.len() {
            4 | 5 => &raw[4..4],
            _ if raw[4] != 0 => {
                let length = usize::from(raw[4]);
                let end = 5 + length;
                if raw.len() != end && raw.len() != end + 1 {
                    return Err(ApduParseError::InvalidLength);
                }
                &raw[5..end]
            }
            _ => {
                if raw.len() < 7 {
                    return Err(ApduParseError::InvalidLength);
                }
                let length = u16::from_be_bytes([raw[5], raw[6]]) as usize;
                if length == 0 {
                    &raw[7..7]
                } else {
                    let end = 7 + length;
                    if raw.len() != end && raw.len() != end + 2 {
                        return Err(ApduParseError::InvalidLength);
                    }
                    &raw[7..end]
                }
            }
        };
        Ok(Self {
            cla: raw[0],
            ins: raw[1],
            p1: raw[2],
            p2: raw[3],
            data,
        })
    }
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
    fn management_reports_real_ccid_identity_and_serial() {
        let mut card = Card::new(0x01020304);
        assert_eq!(
            card.transmit(&select(&MANAGEMENT_AID)),
            [MANAGEMENT_SELECT_RESPONSE, &[0x90, 0]].concat()
        );
        let response = card.transmit(&[0, 0x1d, 0, 0, 0]);
        assert_eq!(&response[response.len() - 2..], &[0x90, 0]);
        assert!(response
            .windows(6)
            .any(|value| value == [0x02, 4, 1, 2, 3, 4]));
        assert!(response.windows(4).any(|value| value == [0x03, 2, 4, 4]));
        assert!(!response.windows(4).any(|value| value == b"MOCK"));
    }

    #[test]
    fn fido_select_and_get_info_report_only_implemented_features() {
        let mut card = Card::new(1);
        assert_eq!(
            card.transmit(&select(&FIDO2_AID)),
            [b"FIDO_2_0".as_slice(), &[0x90, 0]].concat()
        );
        let response = card.transmit(&[0x80, 0x10, 0, 0, 1, CTAP_GET_INFO, 0]);
        assert_eq!(response[0], 0);
        assert_eq!(&response[response.len() - 2..], &[0x90, 0]);
        assert!(!response.windows(11).any(|value| value == b"previewSign"));
    }

    #[test]
    fn logs_unknown_aids_as_not_found() {
        let mut card = Card::new(1);
        assert_eq!(card.transmit(&select(&[1, 2, 3])), [0x6a, 0x82]);
    }
}
