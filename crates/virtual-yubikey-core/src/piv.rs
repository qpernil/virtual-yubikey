use crate::{CommandApdu, ResponseApdu};

pub const PIV_AID: [u8; 11] = [
    0xa0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10, 0x00, 0x01, 0x00,
];

const PIV_SELECT_AID: [u8; 9] = [0xa0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10, 0x00];
const PIV_SELECT_RESPONSE: [u8; 19] = [
    0x61, 0x11, 0x4f, 0x06, 0x00, 0x00, 0x10, 0x00, 0x01, 0x00, 0x79, 0x07, 0x4f, 0x05, 0xa0, 0x00,
    0x00, 0x03, 0x08,
];
const DISCOVERY_OBJECT: [u8; 20] = [
    0x7e, 0x12, 0x4f, 0x0b, 0xa0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10, 0x00, 0x01, 0x00, 0x5f,
    0x2f, 0x02, 0x40, 0x00,
];

const INS_VERIFY: u8 = 0x20;
const INS_GET_DATA: u8 = 0xcb;
const INS_GET_VERSION: u8 = 0xfd;
const INS_GET_SERIAL: u8 = 0xf8;
const INS_GET_METADATA: u8 = 0xf7;

const REFERENCE_PIN: u8 = 0x80;
const REFERENCE_PUK: u8 = 0x81;
const REFERENCE_MANAGEMENT_KEY: u8 = 0x9b;
const ALGORITHM_PIN_OR_PUK: u8 = 0xff;
const ALGORITHM_AES192: u8 = 0x0a;
const FACTORY_RETRIES: u8 = 3;

const STATUS_INCORRECT_PARAMETERS: u16 = 0x6a86;
const STATUS_NOT_FOUND: u16 = 0x6a82;
const STATUS_REFERENCE_NOT_FOUND: u16 = 0x6a88;
const STATUS_INSTRUCTION_NOT_SUPPORTED: u16 = 0x6d00;
const STATUS_CLASS_NOT_SUPPORTED: u16 = 0x6e00;

pub(crate) fn matches_aid(aid: &[u8]) -> bool {
    aid == PIV_AID || aid == PIV_SELECT_AID
}

pub(crate) fn select_response() -> Vec<u8> {
    PIV_SELECT_RESPONSE.to_vec()
}

#[derive(Debug)]
pub(crate) struct PivApplet {
    serial: u32,
    firmware: [u8; 3],
}

impl PivApplet {
    pub(crate) fn new(serial: u32, firmware: [u8; 3]) -> Self {
        Self { serial, firmware }
    }

    pub(crate) fn reset_connection(&mut self) {}

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
            INS_VERIFY
                if command.p1 == 0 && command.p2 == REFERENCE_PIN && command.data.is_empty() =>
            {
                ResponseApdu::status(0x63c0 | u16::from(FACTORY_RETRIES))
            }
            INS_GET_VERSION | INS_GET_SERIAL | INS_GET_METADATA | INS_GET_DATA | INS_VERIFY => {
                ResponseApdu::status(STATUS_INCORRECT_PARAMETERS)
            }
            _ => ResponseApdu::status(STATUS_INSTRUCTION_NOT_SUPPORTED),
        }
    }

    fn get_metadata(&self, reference: u8) -> ResponseApdu {
        let mut data = Vec::new();
        match reference {
            REFERENCE_PIN | REFERENCE_PUK => {
                push_tlv(&mut data, 0x01, &[ALGORITHM_PIN_OR_PUK]);
                push_tlv(&mut data, 0x05, &[1]);
                push_tlv(&mut data, 0x06, &[FACTORY_RETRIES, FACTORY_RETRIES]);
            }
            REFERENCE_MANAGEMENT_KEY => {
                push_tlv(&mut data, 0x01, &[ALGORITHM_AES192]);
                push_tlv(&mut data, 0x02, &[0, 1]);
                push_tlv(&mut data, 0x05, &[1]);
            }
            _ => return ResponseApdu::status(STATUS_REFERENCE_NOT_FOUND),
        }
        ResponseApdu::success(data)
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
}

fn empty_command(command: &CommandApdu<'_>, p1: u8, p2: u8) -> bool {
    command.p1 == p1 && command.p2 == p2 && command.data.is_empty()
}

fn decode_object_id(request: &[u8]) -> Option<u32> {
    let (&tag, rest) = request.split_first()?;
    if tag != 0x5c {
        return None;
    }
    let (&length, value) = rest.split_first()?;
    if !(1..=3).contains(&length) || value.len() != usize::from(length) {
        return None;
    }
    Some(
        value
            .iter()
            .fold(0_u32, |object, byte| (object << 8) | u32::from(*byte)),
    )
}

fn push_tlv(output: &mut Vec<u8>, tag: u8, value: &[u8]) {
    output.push(tag);
    output.push(value.len() as u8);
    output.extend_from_slice(value);
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
                0x01, 0x01, 0xff, 0x05, 0x01, 0x01, 0x06, 0x02, 0x03, 0x03,
            ])
        );
        assert_eq!(
            piv.transmit(&command(INS_GET_METADATA, 0, REFERENCE_MANAGEMENT_KEY, &[],)),
            ResponseApdu::success(vec![
                0x01, 0x01, 0x0a, 0x02, 0x02, 0x00, 0x01, 0x05, 0x01, 0x01,
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
                &[0x5c, 3, 0x5f, 0xc1, 0x05],
            ))
            .status,
            STATUS_NOT_FOUND
        );
    }
}
