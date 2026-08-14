//! CTAPHID packet framing for the FIDO HID gadget transport.

use std::collections::HashSet;

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
const CMD_ERROR: u8 = 0x3f;

const ERR_INVALID_CMD: u8 = 0x01;
const ERR_INVALID_LEN: u8 = 0x03;
const ERR_INVALID_SEQ: u8 = 0x04;
const ERR_CHANNEL_BUSY: u8 = 0x06;
const ERR_INVALID_CHANNEL: u8 = 0x0b;

const CAPABILITY_CBOR: u8 = 0x04;
const CAPABILITY_NMSG: u8 = 0x08;

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
    firmware: [u8; 3],
    next_channel: u32,
    channels: HashSet<u32>,
    transaction: Option<Transaction>,
}

impl Device {
    pub(crate) fn new(firmware: [u8; 3]) -> Self {
        Self {
            firmware,
            next_channel: 1,
            channels: HashSet::new(),
            transaction: None,
        }
    }

    pub(crate) fn receive<F>(
        &mut self,
        report: &[u8; REPORT_SIZE],
        mut exchange_cbor: F,
    ) -> Vec<[u8; REPORT_SIZE]>
    where
        F: FnMut(&[u8]) -> Vec<u8>,
    {
        let channel = u32::from_be_bytes(report[0..4].try_into().unwrap());
        if report[4] & 0x80 != 0 {
            return self.receive_initial(channel, report, exchange_cbor);
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
            &mut exchange_cbor,
        )
    }

    fn receive_initial<F>(
        &mut self,
        channel: u32,
        report: &[u8; REPORT_SIZE],
        mut exchange_cbor: F,
    ) -> Vec<[u8; REPORT_SIZE]>
    where
        F: FnMut(&[u8]) -> Vec<u8>,
    {
        let command = report[4] & 0x7f;
        let length = usize::from(u16::from_be_bytes([report[5], report[6]]));
        if length > MAX_MESSAGE_SIZE {
            return encode_message(channel, CMD_ERROR, &[ERR_INVALID_LEN]);
        }
        if let Some(active) = &self.transaction {
            if active.channel != channel {
                return encode_message(channel, CMD_ERROR, &[ERR_CHANNEL_BUSY]);
            }
        }
        self.transaction = None;

        let mut payload = Vec::with_capacity(length);
        payload.extend_from_slice(&report[7..7 + length.min(INIT_DATA_SIZE)]);
        if payload.len() == length {
            return self.execute(channel, command, &payload, &mut exchange_cbor);
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
        exchange_cbor: &mut F,
    ) -> Vec<[u8; REPORT_SIZE]>
    where
        F: FnMut(&[u8]) -> Vec<u8>,
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
            response.extend_from_slice(&self.firmware);
            response.push(CAPABILITY_CBOR | CAPABILITY_NMSG);
            return encode_message(channel, CMD_INIT, &response);
        }

        if channel == BROADCAST_CHANNEL || !self.channels.contains(&channel) {
            return encode_message(channel, CMD_ERROR, &[ERR_INVALID_CHANNEL]);
        }

        match command {
            CMD_PING => encode_message(channel, CMD_PING, payload),
            CMD_CBOR => encode_message(channel, CMD_CBOR, &exchange_cbor(payload)),
            CMD_CANCEL if payload.is_empty() => Vec::new(),
            CMD_CANCEL => encode_message(channel, CMD_ERROR, &[ERR_INVALID_LEN]),
            CMD_MSG => encode_message(channel, CMD_ERROR, &[ERR_INVALID_CMD]),
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

#[cfg(test)]
mod tests {
    use super::*;

    fn initial(channel: u32, command: u8, payload: &[u8]) -> [u8; REPORT_SIZE] {
        encode_message(channel, command, payload)[0]
    }

    fn assigned_channel(response: &[[u8; REPORT_SIZE]]) -> u32 {
        u32::from_be_bytes(response[0][15..19].try_into().unwrap())
    }

    #[test]
    fn initializes_channel_with_firmware_and_cbor_capability() {
        let nonce = *b"12345678";
        let mut device = Device::new([5, 8, 0]);
        let response = device.receive(
            &initial(BROADCAST_CHANNEL, CMD_INIT, &nonce),
            |_| unreachable!(),
        );
        assert_eq!(response.len(), 1);
        assert_eq!(&response[0][0..7], &[0xff, 0xff, 0xff, 0xff, 0x86, 0, 17]);
        assert_eq!(&response[0][7..15], &nonce);
        assert_eq!(&response[0][19..24], &[2, 5, 8, 0, 0x0c]);
        assert_ne!(assigned_channel(&response), 0);
    }

    #[test]
    fn routes_cbor_and_fragments_long_response() {
        let mut device = Device::new([5, 8, 0]);
        let init = device.receive(
            &initial(BROADCAST_CHANNEL, CMD_INIT, b"abcdefgh"),
            |_| unreachable!(),
        );
        let channel = assigned_channel(&init);
        let response = device.receive(&initial(channel, CMD_CBOR, &[4]), |request| {
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
    fn reassembles_multi_report_cbor_request() {
        let mut device = Device::new([5, 8, 0]);
        let init = device.receive(
            &initial(BROADCAST_CHANNEL, CMD_INIT, b"abcdefgh"),
            |_| unreachable!(),
        );
        let channel = assigned_channel(&init);
        let request = vec![0x42; 100];
        let reports = encode_message(channel, CMD_CBOR, &request);
        assert!(device.receive(&reports[0], |_| unreachable!()).is_empty());
        let response = device.receive(&reports[1], |payload| {
            assert_eq!(payload, request);
            vec![0]
        });
        assert_eq!(response[0][4], 0x90);
        assert_eq!(response[0][7], 0);
    }

    #[test]
    fn rejects_commands_on_unallocated_channels() {
        let mut device = Device::new([5, 8, 0]);
        let response = device.receive(&initial(7, CMD_CBOR, &[4]), |_| unreachable!());
        assert_eq!(response[0][4], 0xbf);
        assert_eq!(response[0][7], ERR_INVALID_CHANNEL);
    }
}
