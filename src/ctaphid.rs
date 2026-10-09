//! CTAPHID packet framing for the FIDO HID gadget transport.

use std::collections::HashSet;
use virtual_yubikey_core::{DeviceProfile, Management};

pub(crate) const REPORT_SIZE: usize = 64;
const INIT_DATA_SIZE: usize = 57;
const CONT_DATA_SIZE: usize = 59;
const MAX_MESSAGE_SIZE: usize = INIT_DATA_SIZE + 128 * CONT_DATA_SIZE;

const BROADCAST_CHANNEL: u32 = u32::MAX;
const CMD_PING: u8 = 0x01;
const CMD_MSG: u8 = 0x03;
const CMD_INIT: u8 = 0x06;
const CMD_CBOR: u8 = 0x10;
const CMD_CANCEL: u8 = 0x11;
const CMD_KEEPALIVE: u8 = 0x3b;
const CMD_ERROR: u8 = 0x3f;
const CMD_YUBIKEY_READ_CONFIG: u8 = 0x42;
const CMD_YUBIKEY_WRITE_CONFIG: u8 = 0x43;

const ERR_INVALID_CMD: u8 = 0x01;
const ERR_INVALID_PAR: u8 = 0x02;
const ERR_INVALID_LEN: u8 = 0x03;
const ERR_INVALID_SEQ: u8 = 0x04;
const ERR_CHANNEL_BUSY: u8 = 0x06;
const ERR_INVALID_CHANNEL: u8 = 0x0b;

const CAPABILITY_CBOR: u8 = 0x04;
const CAPABILITY_NMSG: u8 = 0x08;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum KeepaliveStatus {
    Processing = 0x01,
    UserPresenceNeeded = 0x02,
}

#[derive(Debug)]
struct Transaction {
    channel: u32,
    command: u8,
    length: usize,
    next_sequence: u8,
    payload: Vec<u8>,
}

#[derive(Debug)]
pub(crate) struct Device {
    profile: DeviceProfile,
    management: Management,
    management_changed: bool,
    next_channel: u32,
    channels: HashSet<u32>,
    transaction: Option<Transaction>,
}

impl Device {
    #[cfg(test)]
    pub(crate) fn new(profile: DeviceProfile) -> Self {
        let management = Management::new(profile.clone());
        Self::with_management(profile, management)
    }
    pub(crate) fn with_management(profile: DeviceProfile, management: Management) -> Self {
        Self {
            profile,
            management,
            management_changed: false,
            next_channel: 1,
            channels: HashSet::new(),
            transaction: None,
        }
    }

    pub(crate) fn take_management_change(&mut self) -> bool {
        std::mem::take(&mut self.management_changed)
    }

    pub(crate) fn receive<F>(
        &mut self,
        report: &[u8; REPORT_SIZE],
        mut exchange_fido: F,
    ) -> Vec<[u8; REPORT_SIZE]>
    where
        F: FnMut(virtual_yubikey_core::FidoProtocol, &[u8]) -> Vec<u8>,
    {
        let channel = u32::from_be_bytes(report[0..4].try_into().unwrap());
        if report[4] & 0x80 != 0 {
            return self.receive_initial(channel, report, exchange_fido);
        }

        let Some(transaction) = self.transaction.as_mut() else {
            return encode_message(channel, CMD_ERROR, &[ERR_INVALID_SEQ]);
        };
        if transaction.channel != channel || report[4] != transaction.next_sequence {
            self.transaction = None;
            return encode_message(channel, CMD_ERROR, &[ERR_INVALID_SEQ]);
        }

        transaction.next_sequence = transaction.next_sequence.wrapping_add(1);
        let remaining = transaction.length.saturating_sub(transaction.payload.len());
        transaction
            .payload
            .extend_from_slice(&report[5..5 + remaining.min(CONT_DATA_SIZE)]);
        if transaction.payload.len() < transaction.length {
            return Vec::new();
        }

        let complete = self.transaction.take().unwrap();
        self.execute(
            complete.channel,
            complete.command,
            &complete.payload,
            &mut exchange_fido,
        )
    }

    fn receive_initial<F>(
        &mut self,
        channel: u32,
        report: &[u8; REPORT_SIZE],
        mut exchange_fido: F,
    ) -> Vec<[u8; REPORT_SIZE]>
    where
        F: FnMut(virtual_yubikey_core::FidoProtocol, &[u8]) -> Vec<u8>,
    {
        let command = report[4] & 0x7f;
        let length = usize::from(u16::from_be_bytes([report[5], report[6]]));
        if length > MAX_MESSAGE_SIZE {
            return encode_message(channel, CMD_ERROR, &[ERR_INVALID_LEN]);
        }
        if let Some(active) = &self.transaction
            && active.channel != channel
        {
            return encode_message(channel, CMD_ERROR, &[ERR_CHANNEL_BUSY]);
        }
        self.transaction = None;

        let mut payload = Vec::with_capacity(length);
        payload.extend_from_slice(&report[7..7 + length.min(INIT_DATA_SIZE)]);
        if payload.len() == length {
            return self.execute(channel, command, &payload, &mut exchange_fido);
        }

        self.transaction = Some(Transaction {
            channel,
            command,
            length,
            next_sequence: 0,
            payload,
        });
        Vec::new()
    }

    fn execute<F>(
        &mut self,
        channel: u32,
        command: u8,
        payload: &[u8],
        exchange_fido: &mut F,
    ) -> Vec<[u8; REPORT_SIZE]>
    where
        F: FnMut(virtual_yubikey_core::FidoProtocol, &[u8]) -> Vec<u8>,
    {
        if command == CMD_INIT {
            if payload.len() != 8 {
                return encode_message(channel, CMD_ERROR, &[ERR_INVALID_LEN]);
            }
            let assigned = if channel == BROADCAST_CHANNEL {
                self.allocate_channel()
            } else if self.channels.contains(&channel) {
                channel
            } else {
                return encode_message(channel, CMD_ERROR, &[ERR_INVALID_CHANNEL]);
            };
            let mut response = Vec::with_capacity(17);
            response.extend_from_slice(payload);
            response.extend_from_slice(&assigned.to_be_bytes());
            response.push(2); // CTAPHID protocol version
            response.extend_from_slice(&self.profile.firmware);
            response.push(
                if self.management.fido2_enabled() {
                    CAPABILITY_CBOR
                } else {
                    0
                } | if self.management.u2f_enabled() {
                    0
                } else {
                    CAPABILITY_NMSG
                },
            );
            return encode_message(channel, CMD_INIT, &response);
        }

        if channel == BROADCAST_CHANNEL || !self.channels.contains(&channel) {
            return encode_message(channel, CMD_ERROR, &[ERR_INVALID_CHANNEL]);
        }

        match command {
            CMD_PING => encode_message(channel, CMD_PING, payload),
            CMD_CBOR if !self.management.fido2_enabled() => {
                encode_message(channel, CMD_ERROR, &[ERR_INVALID_CMD])
            }
            CMD_MSG if !self.management.u2f_enabled() => {
                encode_message(channel, CMD_ERROR, &[ERR_INVALID_CMD])
            }
            CMD_CBOR => encode_message(
                channel,
                CMD_CBOR,
                &exchange_fido(virtual_yubikey_core::FidoProtocol::Ctap2, payload),
            ),
            CMD_MSG => encode_message(
                channel,
                CMD_MSG,
                &exchange_fido(virtual_yubikey_core::FidoProtocol::U2f, payload),
            ),
            CMD_YUBIKEY_READ_CONFIG if payload.len() == 1 => {
                match self.management.read_config(payload[0]) {
                    Ok(config) => encode_message(channel, CMD_YUBIKEY_READ_CONFIG, &config),
                    Err(_) => encode_message(channel, CMD_ERROR, &[ERR_INVALID_PAR]),
                }
            }
            CMD_YUBIKEY_READ_CONFIG => encode_message(channel, CMD_ERROR, &[ERR_INVALID_LEN]),
            CMD_YUBIKEY_WRITE_CONFIG => match self.management.write_config(payload) {
                Ok(()) => {
                    self.management_changed = true;
                    encode_message(channel, CMD_YUBIKEY_WRITE_CONFIG, &[])
                }
                Err(0x6982) => encode_message(channel, CMD_ERROR, &[0x27]),
                Err(0x6f00) => encode_message(channel, CMD_ERROR, &[0x7f]),
                Err(_) => encode_message(channel, CMD_ERROR, &[ERR_INVALID_PAR]),
            },
            CMD_CANCEL if payload.is_empty() => Vec::new(),
            CMD_CANCEL => encode_message(channel, CMD_ERROR, &[ERR_INVALID_LEN]),
            _ => encode_message(channel, CMD_ERROR, &[ERR_INVALID_CMD]),
        }
    }

    fn allocate_channel(&mut self) -> u32 {
        loop {
            let candidate = self.next_channel;
            self.next_channel = self.next_channel.wrapping_add(1);
            if self.next_channel == 0 || self.next_channel == BROADCAST_CHANNEL {
                self.next_channel = 1;
            }
            if candidate != 0 && candidate != BROADCAST_CHANNEL && self.channels.insert(candidate) {
                return candidate;
            }
        }
    }
}

fn encode_message(channel: u32, command: u8, payload: &[u8]) -> Vec<[u8; REPORT_SIZE]> {
    let length = u16::try_from(payload.len()).expect("CTAPHID response exceeds 65535 bytes");
    let mut reports = Vec::new();
    let mut initial = [0_u8; REPORT_SIZE];
    initial[0..4].copy_from_slice(&channel.to_be_bytes());
    initial[4] = command | 0x80;
    initial[5..7].copy_from_slice(&length.to_be_bytes());
    let first = payload.len().min(INIT_DATA_SIZE);
    initial[7..7 + first].copy_from_slice(&payload[..first]);
    reports.push(initial);

    let mut offset = first;
    let mut sequence = 0_u8;
    while offset < payload.len() {
        let mut continuation = [0_u8; REPORT_SIZE];
        continuation[0..4].copy_from_slice(&channel.to_be_bytes());
        continuation[4] = sequence;
        let count = (payload.len() - offset).min(CONT_DATA_SIZE);
        continuation[5..5 + count].copy_from_slice(&payload[offset..offset + count]);
        reports.push(continuation);
        offset += count;
        sequence = sequence.wrapping_add(1);
    }
    reports
}

pub(crate) fn keepalive(channel: u32, status: KeepaliveStatus) -> [u8; REPORT_SIZE] {
    encode_message(channel, CMD_KEEPALIVE, &[status as u8])[0]
}

pub(crate) fn is_cancel(report: &[u8; REPORT_SIZE], channel: u32) -> bool {
    u32::from_be_bytes(report[0..4].try_into().unwrap()) == channel
        && report[4] == (CMD_CANCEL | 0x80)
        && report[5..7] == [0, 0]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn initial(channel: u32, command: u8, payload: &[u8]) -> [u8; REPORT_SIZE] {
        encode_message(channel, command, payload)[0]
    }

    fn assigned_channel(response: &[[u8; REPORT_SIZE]]) -> u32 {
        u32::from_be_bytes(response[0][15..19].try_into().unwrap())
    }

    fn device() -> Device {
        Device::new(DeviceProfile::yubikey_5_8_ccid(12_345_678))
    }

    #[test]
    fn initializes_channel_with_firmware_and_cbor_capability() {
        let nonce = *b"12345678";
        let mut device = device();
        let response = device.receive(
            &initial(BROADCAST_CHANNEL, CMD_INIT, &nonce),
            |_, _| unreachable!(),
        );
        assert_eq!(response.len(), 1);
        assert_eq!(&response[0][0..7], &[0xff, 0xff, 0xff, 0xff, 0x86, 0, 17]);
        assert_eq!(&response[0][7..15], &nonce);
        assert_eq!(&response[0][19..24], &[2, 5, 8, 0, 0x04]);
        assert_ne!(assigned_channel(&response), 0);
    }

    #[test]
    fn routes_cbor_and_fragments_long_response() {
        let mut device = device();
        let init = device.receive(
            &initial(BROADCAST_CHANNEL, CMD_INIT, b"abcdefgh"),
            |_, _| unreachable!(),
        );
        let channel = assigned_channel(&init);
        let response = device.receive(&initial(channel, CMD_CBOR, &[4]), |_, request| {
            assert_eq!(request, &[4]);
            vec![0x55; 120]
        });
        assert_eq!(response.len(), 3);
        assert_eq!(response[0][4], 0x90);
        assert_eq!(&response[0][5..7], &[0, 120]);
        assert_eq!(response[1][4], 0);
        assert_eq!(response[2][4], 1);
    }

    #[test]
    fn fragments_an_ml_dsa_87_sized_cbor_response_without_loss() {
        let mut device = device();
        let init = device.receive(
            &initial(BROADCAST_CHANNEL, CMD_INIT, b"abcdefgh"),
            |_, _| unreachable!(),
        );
        let channel = assigned_channel(&init);
        let payload: Vec<u8> = (0..4_700).map(|index| index as u8).collect();
        let response = device.receive(&initial(channel, CMD_CBOR, &[2]), |_, _| payload.clone());

        assert_eq!(response.len(), 80);
        assert_eq!(&response[0][0..7], &[0, 0, 0, 1, 0x90, 0x12, 0x5c]);
        for (sequence, report) in response[1..].iter().enumerate() {
            assert_eq!(report[0..4], channel.to_be_bytes());
            assert_eq!(report[4], sequence as u8);
        }
        assert_eq!(response.last().unwrap()[4], 78);

        let mut reconstructed = response[0][7..].to_vec();
        for report in &response[1..] {
            reconstructed.extend_from_slice(&report[5..]);
        }
        reconstructed.truncate(payload.len());
        assert_eq!(reconstructed, payload);
    }

    #[test]
    fn reassembles_multi_report_cbor_request() {
        let mut device = device();
        let init = device.receive(
            &initial(BROADCAST_CHANNEL, CMD_INIT, b"abcdefgh"),
            |_, _| unreachable!(),
        );
        let channel = assigned_channel(&init);
        let request = vec![0x42; 100];
        let reports = encode_message(channel, CMD_CBOR, &request);
        assert!(
            device
                .receive(&reports[0], |_, _| unreachable!())
                .is_empty()
        );
        let response = device.receive(&reports[1], |_, payload| {
            assert_eq!(payload, request);
            vec![0]
        });
        assert_eq!(response[0][4], 0x90);
        assert_eq!(response[0][7], 0);
    }

    #[test]
    fn rejects_commands_on_unallocated_channels() {
        let mut device = device();
        let response = device.receive(&initial(7, CMD_CBOR, &[4]), |_, _| unreachable!());
        assert_eq!(response[0][4], 0xbf);
        assert_eq!(response[0][7], ERR_INVALID_CHANNEL);
    }

    #[test]
    fn returns_profile_device_info_over_yubico_vendor_command() {
        let mut device = device();
        let init = device.receive(
            &initial(BROADCAST_CHANNEL, CMD_INIT, b"abcdefgh"),
            |_, _| unreachable!(),
        );
        let channel = assigned_channel(&init);
        let response = device.receive(
            &initial(channel, CMD_YUBIKEY_READ_CONFIG, &[0]),
            |_, _| unreachable!(),
        );
        assert_eq!(response[0][4], 0xc2);
        assert_eq!(response[0][7], 35);
        assert!(
            response[0]
                .windows(6)
                .any(|value| value == [2, 4, 0, 188, 97, 78])
        );
        assert!(response[0].windows(5).any(|value| value == [5, 3, 5, 8, 0]));
    }

    #[test]
    fn encodes_keepalive_statuses_and_recognizes_cancel() {
        let channel = 0x0102_0304;
        let processing = keepalive(channel, KeepaliveStatus::Processing);
        assert_eq!(&processing[..8], &[1, 2, 3, 4, 0xbb, 0, 1, 1]);
        let presence = keepalive(channel, KeepaliveStatus::UserPresenceNeeded);
        assert_eq!(&presence[..8], &[1, 2, 3, 4, 0xbb, 0, 1, 2]);

        let cancel = initial(channel, CMD_CANCEL, &[]);
        assert!(is_cancel(&cancel, channel));
        assert!(!is_cancel(&cancel, channel + 1));
    }

    #[test]
    fn cancellation_status_belongs_to_the_original_cbor_response() {
        let mut device = device();
        let init = device.receive(
            &initial(BROADCAST_CHANNEL, CMD_INIT, b"abcdefgh"),
            |_, _| unreachable!(),
        );
        let channel = assigned_channel(&init);

        let cancelled = device.receive(&initial(channel, CMD_CBOR, &[4]), |_, _| vec![0x2d]);
        assert_eq!(&cancelled[0][..8], &[0, 0, 0, 1, 0x90, 0, 1, 0x2d]);

        let cancel_command =
            device.receive(&initial(channel, CMD_CANCEL, &[]), |_, _| unreachable!());
        assert!(cancel_command.is_empty());
    }
    fn payload(reports: &[[u8; REPORT_SIZE]]) -> Vec<u8> {
        let length = usize::from(u16::from_be_bytes([reports[0][5], reports[0][6]]));
        let mut data = reports[0][7..].to_vec();
        for report in &reports[1..] {
            data.extend_from_slice(&report[5..]);
        }
        data.truncate(length);
        data
    }

    fn u2f_request(ins: u8, p1: u8, data: &[u8]) -> Vec<u8> {
        let mut raw = vec![0, ins, p1, 0, 0];
        if !data.is_empty() {
            raw.extend_from_slice(&(data.len() as u16).to_be_bytes());
            raw.extend_from_slice(data);
        }
        raw.extend_from_slice(&[0, 0]);
        raw
    }

    fn exchange_runtime(
        fido: &mut virtual_yubikey_core::FidoAuthenticator,
        protocol: virtual_yubikey_core::FidoProtocol,
        request: &[u8],
        granted: bool,
    ) -> Vec<u8> {
        use virtual_yubikey_core::{ApduExchange, FidoProtocol, PresenceAuthorization};
        match protocol {
            FidoProtocol::Ctap2 => fido.exchange_with_presence(
                request,
                if granted {
                    PresenceAuthorization::Granted
                } else {
                    PresenceAuthorization::Absent
                },
            ),
            FidoProtocol::U2f => match fido.exchange_u2f(
                request,
                if granted {
                    PresenceAuthorization::Granted
                } else {
                    PresenceAuthorization::Absent
                },
            ) {
                ApduExchange::Complete(response) => response,
                ApduExchange::PresenceRequired(_) => vec![0x69, 0x85],
            },
        }
    }

    fn hid_call(
        device: &mut Device,
        channel: u32,
        command: u8,
        request: &[u8],
        fido: &mut virtual_yubikey_core::FidoAuthenticator,
        granted: bool,
    ) -> Vec<u8> {
        let reports = encode_message(channel, command, request);
        let mut replies = Vec::new();
        for report in &reports {
            let result = device.receive(report, |protocol, request| {
                exchange_runtime(fido, protocol, request, granted)
            });
            if !result.is_empty() {
                replies = result;
            }
        }
        assert_eq!(replies[0][4], command | 0x80);
        payload(&replies)
    }

    #[test]
    fn u2f_hid_and_ccid_share_handles_identity_and_counter() {
        use virtual_yubikey_core::{FIDO2_AID, FidoAuthenticator};
        let mut device = device();
        let init = device.receive(
            &initial(BROADCAST_CHANNEL, CMD_INIT, b"abcdefgh"),
            |_, _| unreachable!(),
        );
        assert_eq!(init[0][23] & 8, 0); // MSG is supported.
        let channel = assigned_channel(&init);
        let mut fido = FidoAuthenticator::new();
        assert_eq!(
            hid_call(
                &mut device,
                channel,
                CMD_MSG,
                &[0, 3, 0, 0, 0, 0, 0],
                &mut fido,
                false
            ),
            b"U2F_V2\x90\x00"
        );
        let registration_data = [0x51; 64];
        let register = u2f_request(1, 0, &registration_data);
        assert_eq!(
            hid_call(&mut device, channel, CMD_MSG, &register, &mut fido, false),
            [0x69, 0x85]
        );
        let registration = hid_call(&mut device, channel, CMD_MSG, &register, &mut fido, true);
        assert_eq!(&registration[registration.len() - 2..], &[0x90, 0]);
        assert_eq!(registration[66], 64);
        let handle = &registration[67..131];
        let auth_data = [registration_data.as_slice(), &[64], handle].concat();
        let auth = u2f_request(2, 3, &auth_data);
        let hid_auth = hid_call(&mut device, channel, CMD_MSG, &auth, &mut fido, true);
        assert_eq!(&hid_auth[..5], &[1, 0, 0, 0, 1]);

        let mut card = crate::smartcard::Card::new(1);
        let select = [vec![0, 0xa4, 4, 0, 8], FIDO2_AID.to_vec()].concat();
        assert_eq!(card.transmit(&select), b"U2F_V2\x90\x00");
        let ccid_auth = card
            .transmit_with_presence_and_fido(&auth, || Ok(false), &mut |protocol, request| {
                exchange_runtime(&mut fido, protocol, request, true)
            })
            .unwrap();
        assert_eq!(&ccid_auth[..5], &[1, 0, 0, 0, 2]);
        assert_eq!(&ccid_auth[ccid_auth.len() - 2..], &[0x90, 0]);
        let verify = p256::ecdsa::VerifyingKey::from_sec1_bytes(&registration[1..66]).unwrap();
        for response in [hid_auth, ccid_auth] {
            let message = [
                &registration_data[32..],
                &response[..5],
                &registration_data[..32],
            ]
            .concat();
            use signature::Verifier;
            verify
                .verify(
                    &message,
                    &p256::ecdsa::Signature::from_der(&response[5..response.len() - 2]).unwrap(),
                )
                .unwrap();
        }
        let info = hid_call(&mut device, channel, CMD_CBOR, &[4], &mut fido, false);
        assert_eq!(info[0], 0);
        assert!(info.windows(6).any(|bytes| bytes == b"U2F_V2"));
        let check = u2f_request(2, 7, &auth_data);
        assert_eq!(
            hid_call(&mut device, channel, CMD_MSG, &check, &mut fido, false),
            [0x69, 0x85]
        );
        let malformed = hid_call(&mut device, channel, CMD_MSG, &[0, 1, 0], &mut fido, true);
        assert_eq!(malformed, [0x67, 0]);
    }

    #[test]
    fn embedded_ccid_u2f_obtains_fresh_presence_and_chains_short_registration_response() {
        let mut card = crate::smartcard::Card::new(1);
        let select = [
            vec![0, 0xa4, 4, 0, 8],
            virtual_yubikey_core::FIDO2_AID.to_vec(),
        ]
        .concat();
        card.transmit(&select);
        assert_eq!(
            card.transmit(&[0, 3, 0, 0, 0, 0, 0, 0, 0]),
            b"U2F_V2\x90\x00"
        );
        let mut register = vec![0, 1, 0, 0, 64];
        register.extend_from_slice(&[0x35; 64]);
        register.push(32); // Exercise ISO response chaining on a short APDU.
        assert_eq!(card.transmit(&register), [0x69, 0x85]);
        let first = card.transmit_with_presence(&register, || Ok(true)).unwrap();
        assert_eq!(first.len(), 34);
        assert_eq!(first[first.len() - 2], 0x61);
        let mut all = first[..first.len() - 2].to_vec();
        loop {
            let next = card.transmit(&[0, 0xc0, 0, 0, 0]);
            all.extend_from_slice(&next[..next.len() - 2]);
            if next[next.len() - 2..] == [0x90, 0] {
                break;
            }
        }
        assert_eq!(all[0], 5);
        assert_eq!(all[66], 64);
        let auth_data = [vec![0x35; 64], vec![64], all[67..131].to_vec()].concat();
        let auth = u2f_request(2, 3, &auth_data);
        assert_eq!(card.transmit(&auth), [0x69, 0x85]);
        let signed = card.transmit_with_presence(&auth, || Ok(true)).unwrap();
        assert_eq!(&signed[..5], [1, 0, 0, 0, 1]);
        let reset = [0x80, 0x10, 0, 0, 1, 7, 0];
        assert_eq!(card.transmit(&reset), [0x69, 0x85]);
        assert_eq!(
            card.transmit_with_presence(&reset, || Ok(true)).unwrap(),
            [0, 0x90, 0]
        );
        assert_eq!(card.transmit(&u2f_request(2, 7, &auth_data)), [0x6a, 0x80]);
    }
    #[test]
    fn management_writes_gate_both_transports_and_update_init_capabilities() {
        use virtual_yubikey_core::{FIDO2_AID, MANAGEMENT_AID, VirtualYubiKey};
        let profile = DeviceProfile::yubikey_5_8_ccid(42);
        let device = VirtualYubiKey::new(profile.clone());
        let management = device.management();
        let supported = management.usb_supported_capabilities();
        let (mut card, mut fido) = device.separate_fido();
        let mut hid = Device::with_management(profile, management.clone());
        let init = hid.receive(
            &initial(BROADCAST_CHANNEL, CMD_INIT, b"abcdefgh"),
            |_, _| unreachable!(),
        );
        let channel = assigned_channel(&init);
        for (u2f, fido2) in [(true, false), (false, true), (false, false), (true, true)] {
            let mask = supported & !(0x0002 | 0x0200)
                | if u2f { 2 } else { 0 }
                | if fido2 { 0x200 } else { 0 };
            assert_eq!(
                hid_call(
                    &mut hid,
                    channel,
                    CMD_YUBIKEY_WRITE_CONFIG,
                    &[6, 3, 2, (mask >> 8) as u8, mask as u8, 12, 0],
                    &mut fido,
                    false
                ),
                Vec::<u8>::new()
            );
            assert!(hid.take_management_change());
            assert!(!hid.take_management_change());
            let init = hid.receive(
                &initial(channel, CMD_INIT, b"abcdefgh"),
                |_, _| unreachable!(),
            );
            assert_eq!(
                init[0][23],
                if fido2 { 4 } else { 0 } | if u2f { 0 } else { 8 }
            );
            let reports = hid.receive(
                &initial(channel, CMD_MSG, &u2f_request(3, 0, &[])),
                |protocol, request| exchange_runtime(&mut fido, protocol, request, false),
            );
            assert_eq!(
                reports[0][4],
                if u2f {
                    CMD_MSG | 0x80
                } else {
                    CMD_ERROR | 0x80
                }
            );
            assert_eq!(
                payload(&reports),
                if u2f {
                    [b"U2F_V2".as_slice(), &[0x90, 0]].concat()
                } else {
                    vec![ERR_INVALID_CMD]
                }
            );
            let mut called = false;
            let reports = hid.receive(&initial(channel, CMD_CBOR, &[4]), |protocol, request| {
                called = true;
                exchange_runtime(&mut fido, protocol, request, false)
            });
            assert_eq!(called, fido2);
            assert_eq!(reports[0][4], if fido2 { 0x90 } else { 0xbf });
            let select = [
                vec![0, 0xa4, 4, 0, MANAGEMENT_AID.len() as u8],
                MANAGEMENT_AID.to_vec(),
                vec![0],
            ]
            .concat();
            assert!(card.transmit(&select).ends_with(&[0x90, 0]));
            let ccid_info = card.transmit(&[0, 0x1d, 0, 0, 0]);
            let hid_info = hid_call(
                &mut hid,
                channel,
                CMD_YUBIKEY_READ_CONFIG,
                &[0],
                &mut fido,
                false,
            );
            assert_eq!(&ccid_info[..ccid_info.len() - 2], hid_info);
            let select = [
                vec![0, 0xa4, 4, 0, FIDO2_AID.len() as u8],
                FIDO2_AID.to_vec(),
                vec![0],
            ]
            .concat();
            assert_eq!(card.transmit(&select).ends_with(&[0x90, 0]), u2f || fido2);
        }
        // A CCID configuration write updates the existing HID device's live settings.
        card.transmit(
            &[
                vec![0, 0xa4, 4, 0, MANAGEMENT_AID.len() as u8],
                MANAGEMENT_AID.to_vec(),
                vec![0],
            ]
            .concat(),
        );
        let mask = supported & !2;
        assert_eq!(
            card.transmit(&[0, 0x1c, 0, 0, 5, 4, 3, 2, (mask >> 8) as u8, mask as u8]),
            [0x90, 0]
        );
        let reports = hid.receive(
            &initial(channel, CMD_MSG, &u2f_request(3, 0, &[])),
            |_, _| unreachable!(),
        );
        assert_eq!(reports[0][4], 0xbf);
        assert_eq!(reports[0][7], ERR_INVALID_CMD);
    }
    #[test]
    fn failed_vendor_management_write_does_not_schedule_or_change_configuration() {
        let mut hid = device();
        let init = hid.receive(
            &initial(BROADCAST_CHANNEL, CMD_INIT, b"abcdefgh"),
            |_, _| unreachable!(),
        );
        let channel = assigned_channel(&init);
        let before = hid.management.persistent_state().unwrap();
        let response = hid.receive(
            &initial(channel, CMD_YUBIKEY_WRITE_CONFIG, &[4, 3, 2, 0]),
            |_, _| unreachable!(),
        );
        assert_eq!(response[0][4], 0xbf);
        assert_eq!(response[0][7], ERR_INVALID_PAR);
        assert!(!hid.take_management_change());
        assert_eq!(hid.management.persistent_state().unwrap(), before);
        let lock = [vec![18, 10, 16], vec![0x31; 16]].concat();
        hid.receive(
            &initial(channel, CMD_YUBIKEY_WRITE_CONFIG, &lock),
            |_, _| unreachable!(),
        );
        assert!(hid.take_management_change());
        let response = hid.receive(
            &initial(channel, CMD_YUBIKEY_WRITE_CONFIG, &[4, 3, 2, 0, 2]),
            |_, _| unreachable!(),
        );
        assert_eq!(response[0][7], 0x27);
        assert!(!hid.take_management_change());
    }
}
