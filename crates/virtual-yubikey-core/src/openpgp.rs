use crate::{CommandApdu, ResponseApdu};

/// The application identifier used to select the OpenPGP card application.
pub const OPENPGP_AID: [u8; 6] = [0xd2, 0x76, 0x00, 0x01, 0x24, 0x01];

const INS_GET_CHALLENGE: u8 = 0x84;

/// Model the maximum response buffer available to the OpenPGP applet firmware.
pub const MAX_RANDOM_RESPONSE_LENGTH: usize = 4_096;

pub(crate) fn transmit(command: &CommandApdu<'_>) -> ResponseApdu {
    if command.cla != 0 {
        return ResponseApdu::status(0x6e00);
    }
    if command.ins != INS_GET_CHALLENGE {
        return ResponseApdu::status(0x6d00);
    }
    if command.p1 != 0 || command.p2 != 0 {
        return ResponseApdu::status(0x6a86);
    }
    if !command.data.is_empty() {
        return ResponseApdu::status(0x6700);
    }

    let Some(requested) = command.le else {
        return ResponseApdu::status(0x6700);
    };
    let length = requested.min(MAX_RANDOM_RESPONSE_LENGTH as u32) as usize;
    let mut random = vec![0; length];
    if getrandom::fill(&mut random).is_err() {
        return ResponseApdu::status(0x6f00);
    }
    ResponseApdu::success(random)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode(raw: &[u8]) -> CommandApdu<'_> {
        CommandApdu::decode(raw).unwrap()
    }

    #[test]
    fn get_challenge_uses_short_le() {
        let response = transmit(&decode(&[0x00, INS_GET_CHALLENGE, 0x00, 0x00, 0x20]));
        assert_eq!(response.data.len(), 32);
        assert_eq!(response.status, 0x9000);
    }

    #[test]
    fn get_challenge_uses_extended_le_and_caps_it_at_firmware_buffer() {
        let response = transmit(&decode(&[
            0x00,
            INS_GET_CHALLENGE,
            0x00,
            0x00,
            0x00,
            0x0f,
            0xff,
        ]));
        assert_eq!(response.data.len(), 4_095);
        assert_eq!(response.status, 0x9000);

        let response = transmit(&decode(&[
            0x00,
            INS_GET_CHALLENGE,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
        ]));
        assert_eq!(response.data.len(), MAX_RANDOM_RESPONSE_LENGTH);
        assert_eq!(response.status, 0x9000);
    }

    #[test]
    fn only_get_challenge_is_supported() {
        assert_eq!(transmit(&decode(&[0, 0xca, 0, 0])).status, 0x6d00);
        assert_eq!(
            transmit(&decode(&[0, INS_GET_CHALLENGE, 1, 0, 1])).status,
            0x6a86
        );
        assert_eq!(
            transmit(&decode(&[0, INS_GET_CHALLENGE, 0, 0])).status,
            0x6700
        );
    }
}
