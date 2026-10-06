//! USB CCID message framing and the permanently inserted mock smart card.

use crate::diagnostics::{self, Level};
use crate::keepalive;
use crate::smartcard::{ATR, Card};
use std::io;
use std::sync::mpsc::{self, RecvTimeoutError};
use std::thread;
use std::time::{Duration, Instant};

const PC_TO_RDR_SET_PARAMETERS: u8 = 0x61;
const PC_TO_RDR_ICC_POWER_ON: u8 = 0x62;
const PC_TO_RDR_ICC_POWER_OFF: u8 = 0x63;
const PC_TO_RDR_GET_SLOT_STATUS: u8 = 0x65;
const PC_TO_RDR_ESCAPE: u8 = 0x6b;
const PC_TO_RDR_GET_PARAMETERS: u8 = 0x6c;
const PC_TO_RDR_RESET_PARAMETERS: u8 = 0x6d;
const PC_TO_RDR_XFR_BLOCK: u8 = 0x6f;
const PC_TO_RDR_SET_DATA_RATE_AND_CLOCK: u8 = 0x73;

const RDR_TO_PC_DATA_BLOCK: u8 = 0x80;
const RDR_TO_PC_SLOT_STATUS: u8 = 0x81;
const RDR_TO_PC_PARAMETERS: u8 = 0x82;
const RDR_TO_PC_ESCAPE: u8 = 0x83;
const RDR_TO_PC_DATA_RATE_AND_CLOCK: u8 = 0x84;

const STATUS_COMMAND_FAILED: u8 = 0x40;
const STATUS_COMMAND_TIME_EXTENSION: u8 = 0x80;
const STATUS_ICC_ACTIVE: u8 = 0x00;
const STATUS_ICC_INACTIVE: u8 = 0x01;
const ERROR_COMMAND_NOT_SUPPORTED: u8 = 0x00;
const ERROR_BAD_LENGTH: u8 = 0x01;
const ERROR_SLOT_NOT_EXIST: u8 = 0x05;
const ERROR_BAD_LEVEL_PARAMETER: u8 = 0x08;

const CCID_HEADER_LENGTH: usize = 10;
pub(crate) const MAX_CCID_MESSAGE_LENGTH: usize = 3072;
const MAX_CCID_PAYLOAD: usize = MAX_CCID_MESSAGE_LENGTH - CCID_HEADER_LENGTH;
// Leave a host read of dwMaxCCIDMessageLength incomplete until the final
// short packet (or ZLP) is consumed, including during response chaining.
const MAX_CCID_RESPONSE_PAYLOAD: usize = MAX_CCID_PAYLOAD - 1;
const MAX_EXTENDED_APDU_LENGTH: usize = 65_544;
const T1_PARAMETERS: [u8; 7] = [0x11, 0x10, 0x00, 0x4d, 0x00, 0xfe, 0x00];
const TIME_EXTENSION_DELAY: Duration = Duration::from_millis(500);
const TIME_EXTENSION_INTERVAL: Duration = Duration::from_millis(500);
const COMMAND_POLL_INTERVAL: Duration = Duration::from_millis(5);

type FidoHandler<'a> = dyn FnMut(&[u8]) -> Vec<u8> + Send + 'a;

pub(crate) struct Device {
    active: bool,
    card: Card,
    buffered: Vec<u8>,
    chained_command: Vec<u8>,
    pending_response: Vec<u8>,
}

impl Device {
    #[cfg(test)]
    pub(crate) fn new(serial: u32) -> Self {
        Self::with_card(Card::new(serial))
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn from_device(device: virtual_yubikey_core::VirtualYubiKey) -> Self {
        Self::with_card(Card::from_device(device))
    }

    fn with_card(card: Card) -> Self {
        Self {
            active: false,
            card,
            buffered: Vec::new(),
            chained_command: Vec::new(),
            pending_response: Vec::new(),
        }
    }

    #[cfg(test)]
    fn with_profile(profile: virtual_yubikey_core::DeviceProfile) -> Self {
        Self::with_card(Card::with_profile(profile))
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn persistent_applet(
        &self,
        applet: virtual_yubikey_core::storage::PersistentApplet,
    ) -> io::Result<Vec<u8>> {
        self.card.persistent_applet(applet)
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn take_persistent_applets(
        &mut self,
    ) -> Vec<virtual_yubikey_core::storage::PersistentApplet> {
        self.card.take_persistent_applets()
    }

    /// Read a header packet first, then the exact remaining CCID frame bytes.
    /// A bounded initial read also tolerates fragmented or coalesced headers.
    pub(crate) fn next_read_length(&self) -> usize {
        if self.buffered.len() < CCID_HEADER_LENGTH {
            return crate::usb_identity::CCID_BULK_PACKET_SIZE as usize;
        }
        let payload = u32::from_le_bytes(self.buffered[1..5].try_into().unwrap()) as usize;
        // receive_inner rejects oversized frames and consumes complete frames.
        debug_assert!(payload <= MAX_CCID_PAYLOAD);
        CCID_HEADER_LENGTH + payload - self.buffered.len()
    }

    #[cfg(test)]
    pub(crate) fn receive(&mut self, bytes: &[u8]) -> Vec<Vec<u8>> {
        self.receive_inner(bytes, None, &mut || Ok(false), &mut None, &mut |_| Ok(()))
            .expect("direct CCID receive has an infallible time-extension sink")
    }

    #[cfg(test)]
    fn receive_with_fido(&mut self, bytes: &[u8], fido: &mut FidoHandler<'_>) -> Vec<Vec<u8>> {
        self.receive_inner(bytes, None, &mut || Ok(false), &mut Some(fido), &mut |_| {
            Ok(())
        })
        .expect("test CCID receive has infallible service callbacks")
    }

    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub(crate) fn receive_with_keepalives(
        &mut self,
        bytes: &[u8],
        clock: &keepalive::Handle,
        mut authorize: impl FnMut() -> io::Result<bool> + Send,
        fido: &mut FidoHandler<'_>,
        mut send: impl FnMut(&[u8]) -> io::Result<()>,
    ) -> io::Result<Vec<Vec<u8>>> {
        self.receive_inner(
            bytes,
            Some(clock),
            &mut authorize,
            &mut Some(fido),
            &mut send,
        )
    }

    fn receive_inner(
        &mut self,
        bytes: &[u8],
        clock: Option<&keepalive::Handle>,
        authorize: &mut (impl FnMut() -> io::Result<bool> + Send),
        fido: &mut Option<&mut FidoHandler<'_>>,
        send: &mut impl FnMut(&[u8]) -> io::Result<()>,
    ) -> io::Result<Vec<Vec<u8>>> {
        self.buffered.extend_from_slice(bytes);
        let mut responses = Vec::new();
        loop {
            if self.buffered.len() < 10 {
                break;
            }
            let length = u32::from_le_bytes(self.buffered[1..5].try_into().unwrap()) as usize;
            if length > MAX_CCID_PAYLOAD {
                let message_type = self.buffered[0];
                let slot = self.buffered[5];
                let sequence = self.buffered[6];
                diagnostics::log(
                    Level::Info,
                    "ccid",
                    "message_rejected",
                    format_args!(
                        "reason=payload_too_large length={length} slot={slot} seq={sequence}"
                    ),
                );
                self.buffered.clear();
                responses.push(response(
                    response_type(message_type),
                    slot,
                    sequence,
                    STATUS_COMMAND_FAILED | self.icc_status(),
                    ERROR_BAD_LENGTH,
                    0,
                    &[],
                ));
                break;
            }
            let total = 10 + length;
            if self.buffered.len() < total {
                break;
            }
            let message = self.buffered.drain(..total).collect::<Vec<_>>();
            responses.push(self.handle(&message, clock, authorize, fido, send)?);
        }
        Ok(responses)
    }

    fn handle(
        &mut self,
        message: &[u8],
        clock: Option<&keepalive::Handle>,
        authorize: &mut (impl FnMut() -> io::Result<bool> + Send),
        fido: &mut Option<&mut FidoHandler<'_>>,
        send: &mut impl FnMut(&[u8]) -> io::Result<()>,
    ) -> io::Result<Vec<u8>> {
        let message_type = message[0];
        let slot = message[5];
        let sequence = message[6];
        let data = &message[10..];
        diagnostics::log(
            Level::Debug,
            "ccid",
            "request",
            format_args!(
                "type={message_type:02x} name={} slot={slot} seq={sequence} data_length={}",
                request_name(message_type),
                data.len()
            ),
        );

        if slot != 0 {
            return Ok(self.failed(
                response_type(message_type),
                slot,
                sequence,
                ERROR_SLOT_NOT_EXIST,
                "slot_not_present",
            ));
        }

        let reply = match message_type {
            PC_TO_RDR_ICC_POWER_ON => {
                self.active = true;
                self.card.reset();
                self.chained_command.clear();
                self.pending_response.clear();
                diagnostics::log(
                    Level::Info,
                    "ccid",
                    "card_powered_on",
                    format_args!("slot=0 atr={}", diagnostics::hex(&ATR)),
                );
                response(
                    RDR_TO_PC_DATA_BLOCK,
                    slot,
                    sequence,
                    STATUS_ICC_ACTIVE,
                    0,
                    0,
                    &ATR,
                )
            }
            PC_TO_RDR_ICC_POWER_OFF => {
                self.active = false;
                self.card.reset();
                self.chained_command.clear();
                self.pending_response.clear();
                diagnostics::log(
                    Level::Info,
                    "ccid",
                    "card_powered_off",
                    format_args!("slot=0"),
                );
                response(
                    RDR_TO_PC_SLOT_STATUS,
                    slot,
                    sequence,
                    STATUS_ICC_INACTIVE,
                    0,
                    0,
                    &[],
                )
            }
            PC_TO_RDR_GET_SLOT_STATUS => response(
                RDR_TO_PC_SLOT_STATUS,
                slot,
                sequence,
                self.icc_status(),
                0,
                0,
                &[],
            ),
            PC_TO_RDR_GET_PARAMETERS | PC_TO_RDR_RESET_PARAMETERS => response(
                RDR_TO_PC_PARAMETERS,
                slot,
                sequence,
                self.icc_status(),
                0,
                1,
                &T1_PARAMETERS,
            ),
            PC_TO_RDR_SET_PARAMETERS => {
                if data.len() != T1_PARAMETERS.len() {
                    self.failed(
                        RDR_TO_PC_PARAMETERS,
                        slot,
                        sequence,
                        ERROR_BAD_LENGTH,
                        "invalid_t1_parameters",
                    )
                } else {
                    response(
                        RDR_TO_PC_PARAMETERS,
                        slot,
                        sequence,
                        self.icc_status(),
                        0,
                        1,
                        data,
                    )
                }
            }
            PC_TO_RDR_XFR_BLOCK => {
                if !self.active {
                    diagnostics::log(
                        Level::Info,
                        "ccid",
                        "message_rejected",
                        format_args!("reason=card_inactive type=6f slot=0 seq={sequence}"),
                    );
                    return Ok(response(
                        RDR_TO_PC_DATA_BLOCK,
                        slot,
                        sequence,
                        STATUS_COMMAND_FAILED | STATUS_ICC_INACTIVE,
                        0xfe,
                        0,
                        &[],
                    ));
                }
                let level_parameter = u16::from_le_bytes([message[8], message[9]]);
                if level_parameter == 0x0010 {
                    return Ok(self.next_response_block(slot, sequence, data));
                }

                let command = match level_parameter {
                    0x0000 => {
                        self.chained_command.clear();
                        self.pending_response.clear();
                        data.to_vec()
                    }
                    0x0001 => {
                        self.pending_response.clear();
                        self.chained_command.clear();
                        self.chained_command.extend_from_slice(data);
                        return Ok(response(
                            RDR_TO_PC_DATA_BLOCK,
                            slot,
                            sequence,
                            STATUS_ICC_ACTIVE,
                            0,
                            0x10,
                            &[],
                        ));
                    }
                    0x0002 | 0x0003 if !self.chained_command.is_empty() => {
                        if self.chained_command.len() + data.len() > MAX_EXTENDED_APDU_LENGTH {
                            self.chained_command.clear();
                            return Ok(self.failed(
                                RDR_TO_PC_DATA_BLOCK,
                                slot,
                                sequence,
                                ERROR_BAD_LENGTH,
                                "chained_apdu_too_large",
                            ));
                        }
                        self.chained_command.extend_from_slice(data);
                        if level_parameter == 0x0003 {
                            return Ok(response(
                                RDR_TO_PC_DATA_BLOCK,
                                slot,
                                sequence,
                                STATUS_ICC_ACTIVE,
                                0,
                                0x10,
                                &[],
                            ));
                        }
                        std::mem::take(&mut self.chained_command)
                    }
                    _ => {
                        self.chained_command.clear();
                        return Ok(self.failed(
                            RDR_TO_PC_DATA_BLOCK,
                            slot,
                            sequence,
                            ERROR_BAD_LEVEL_PARAMETER,
                            "invalid_level_parameter",
                        ));
                    }
                };
                let apdu_response = if let Some(clock) = clock {
                    transmit_with_keepalives(
                        &mut self.card,
                        &command,
                        (slot, sequence),
                        clock,
                        authorize,
                        fido,
                        send,
                    )?
                } else if let Some(handler) = fido {
                    self.card.transmit_with_presence_and_fido(
                        &command,
                        &mut *authorize,
                        &mut **handler,
                    )?
                } else {
                    self.card.transmit(&command)
                };
                self.first_response_block(slot, sequence, apdu_response)
            }
            PC_TO_RDR_SET_DATA_RATE_AND_CLOCK => {
                if data.len() != 8 {
                    self.failed(
                        RDR_TO_PC_DATA_RATE_AND_CLOCK,
                        slot,
                        sequence,
                        ERROR_BAD_LENGTH,
                        "invalid_clock_data_rate",
                    )
                } else {
                    response(
                        RDR_TO_PC_DATA_RATE_AND_CLOCK,
                        slot,
                        sequence,
                        self.icc_status(),
                        0,
                        0,
                        data,
                    )
                }
            }
            PC_TO_RDR_ESCAPE => self.failed(
                RDR_TO_PC_ESCAPE,
                slot,
                sequence,
                ERROR_COMMAND_NOT_SUPPORTED,
                "escape_not_supported",
            ),
            _ => self.failed(
                response_type(message_type),
                slot,
                sequence,
                ERROR_COMMAND_NOT_SUPPORTED,
                "command_not_supported",
            ),
        };
        Ok(reply)
    }

    fn failed(
        &self,
        response_type: u8,
        slot: u8,
        sequence: u8,
        error: u8,
        reason: &str,
    ) -> Vec<u8> {
        diagnostics::log(
            Level::Info,
            "ccid",
            "message_rejected",
            format_args!("reason={reason} slot={slot} seq={sequence} error={error:02x}"),
        );
        response(
            response_type,
            slot,
            sequence,
            STATUS_COMMAND_FAILED | self.icc_status(),
            error,
            0,
            &[],
        )
    }

    fn first_response_block(&mut self, slot: u8, sequence: u8, mut data: Vec<u8>) -> Vec<u8> {
        self.pending_response.clear();
        let chain_parameter = if data.len() > MAX_CCID_RESPONSE_PAYLOAD {
            self.pending_response = data.split_off(MAX_CCID_RESPONSE_PAYLOAD);
            0x01
        } else {
            0x00
        };
        response(
            RDR_TO_PC_DATA_BLOCK,
            slot,
            sequence,
            STATUS_ICC_ACTIVE,
            0,
            chain_parameter,
            &data,
        )
    }

    fn next_response_block(&mut self, slot: u8, sequence: u8, data: &[u8]) -> Vec<u8> {
        if !data.is_empty() || self.pending_response.is_empty() || !self.chained_command.is_empty()
        {
            return self.failed(
                RDR_TO_PC_DATA_BLOCK,
                slot,
                sequence,
                ERROR_BAD_LEVEL_PARAMETER,
                "unexpected_response_continuation",
            );
        }

        let count = self.pending_response.len().min(MAX_CCID_RESPONSE_PAYLOAD);
        let remaining = self.pending_response.split_off(count);
        let block = std::mem::replace(&mut self.pending_response, remaining);
        let chain_parameter = if self.pending_response.is_empty() {
            0x02
        } else {
            0x03
        };
        response(
            RDR_TO_PC_DATA_BLOCK,
            slot,
            sequence,
            STATUS_ICC_ACTIVE,
            0,
            chain_parameter,
            &block,
        )
    }

    fn icc_status(&self) -> u8 {
        if self.active {
            STATUS_ICC_ACTIVE
        } else {
            STATUS_ICC_INACTIVE
        }
    }
}

fn transmit_with_keepalives(
    card: &mut Card,
    data: &[u8],
    address: (u8, u8),
    clock: &keepalive::Handle,
    authorize: &mut (impl FnMut() -> io::Result<bool> + Send),
    fido: &mut Option<&mut FidoHandler<'_>>,
    send: &mut impl FnMut(&[u8]) -> io::Result<()>,
) -> io::Result<Vec<u8>> {
    let (slot, sequence) = address;
    run_with_keepalives(
        || {
            if let Some(handler) = fido {
                card.transmit_with_presence_and_fido(data, authorize, &mut **handler)
            } else {
                card.transmit_with_presence(data, authorize)
            }
        },
        slot,
        sequence,
        clock,
        TIME_EXTENSION_DELAY,
        TIME_EXTENSION_INTERVAL,
        send,
    )?
}

fn run_with_keepalives<T: Send>(
    operation: impl FnOnce() -> T + Send,
    slot: u8,
    sequence: u8,
    clock: &keepalive::Handle,
    initial_delay: Duration,
    interval: Duration,
    send: &mut impl FnMut(&[u8]) -> io::Result<()>,
) -> io::Result<T> {
    let ticks = clock.subscribe(initial_delay, interval)?;
    let started = Instant::now();
    let mut extensions = 0_u64;
    thread::scope(|scope| {
        let (result_tx, result_rx) = mpsc::sync_channel(1);
        let command = scope.spawn(move || {
            let response = operation();
            let _ = result_tx.send(response);
        });
        loop {
            match result_rx.recv_timeout(COMMAND_POLL_INTERVAL) {
                Ok(response) => {
                    command.join().expect("CCID command thread panicked");
                    if extensions != 0 {
                        diagnostics::log(
                            Level::Info,
                            "ccid",
                            "time_extension_complete",
                            format_args!(
                                "slot={slot} seq={sequence} extensions={extensions} elapsed_ms={}",
                                started.elapsed().as_millis()
                            ),
                        );
                    }
                    return Ok(response);
                }
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => {
                    command.join().expect("CCID command thread panicked");
                    return Err(io::Error::other("CCID command thread returned no response"));
                }
            }
            if ticks.tick_due() {
                if extensions == 0 {
                    diagnostics::log(
                        Level::Info,
                        "ccid",
                        "time_extension_started",
                        format_args!("slot={slot} seq={sequence}"),
                    );
                }
                send(&time_extension(slot, sequence))?;
                extensions += 1;
            }
        }
    })
}

fn time_extension(slot: u8, sequence: u8) -> Vec<u8> {
    response(
        RDR_TO_PC_DATA_BLOCK,
        slot,
        sequence,
        STATUS_COMMAND_TIME_EXTENSION | STATUS_ICC_ACTIVE,
        1,
        0,
        &[],
    )
}

fn response(
    message_type: u8,
    slot: u8,
    sequence: u8,
    status: u8,
    error: u8,
    specific: u8,
    data: &[u8],
) -> Vec<u8> {
    let mut output = Vec::with_capacity(10 + data.len());
    output.push(message_type);
    output.extend_from_slice(&(data.len() as u32).to_le_bytes());
    output.extend_from_slice(&[slot, sequence, status, error, specific]);
    output.extend_from_slice(data);
    diagnostics::log(
        Level::Debug,
        "ccid",
        "response",
        format_args!(
            "type={message_type:02x} slot={slot} seq={sequence} status={status:02x} error={error:02x} data_length={}",
            data.len()
        ),
    );
    output
}

fn response_type(request: u8) -> u8 {
    match request {
        PC_TO_RDR_SET_PARAMETERS | PC_TO_RDR_GET_PARAMETERS | PC_TO_RDR_RESET_PARAMETERS => {
            RDR_TO_PC_PARAMETERS
        }
        PC_TO_RDR_ICC_POWER_ON | PC_TO_RDR_XFR_BLOCK => RDR_TO_PC_DATA_BLOCK,
        PC_TO_RDR_ESCAPE => RDR_TO_PC_ESCAPE,
        PC_TO_RDR_SET_DATA_RATE_AND_CLOCK => RDR_TO_PC_DATA_RATE_AND_CLOCK,
        _ => RDR_TO_PC_SLOT_STATUS,
    }
}

fn request_name(message_type: u8) -> &'static str {
    match message_type {
        PC_TO_RDR_SET_PARAMETERS => "set_parameters",
        PC_TO_RDR_ICC_POWER_ON => "icc_power_on",
        PC_TO_RDR_ICC_POWER_OFF => "icc_power_off",
        PC_TO_RDR_GET_SLOT_STATUS => "get_slot_status",
        PC_TO_RDR_ESCAPE => "escape",
        PC_TO_RDR_GET_PARAMETERS => "get_parameters",
        PC_TO_RDR_RESET_PARAMETERS => "reset_parameters",
        PC_TO_RDR_XFR_BLOCK => "xfr_block",
        PC_TO_RDR_SET_DATA_RATE_AND_CLOCK => "set_data_rate_and_clock",
        _ => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::smartcard::{MANAGEMENT_AID, OPENPGP_AID};
    use virtual_yubikey_core::{FIDO2_AID, HSMAUTH_AID};

    fn openpgp_device(serial: u32) -> Device {
        let mut profile = virtual_yubikey_core::DeviceProfile::yubikey_5_8_ccid(serial);
        profile.applets.openpgp = true;
        Device::with_profile(profile)
    }

    fn request(message_type: u8, sequence: u8, specific: [u8; 3], data: &[u8]) -> Vec<u8> {
        let mut output = vec![message_type];
        output.extend_from_slice(&(data.len() as u32).to_le_bytes());
        output.extend_from_slice(&[0, sequence]);
        output.extend_from_slice(&specific);
        output.extend_from_slice(data);
        output
    }

    fn tlv(tag: u8, value: &[u8]) -> Vec<u8> {
        assert!(value.len() < 0x80);
        [vec![tag, value.len() as u8], value.to_vec()].concat()
    }

    fn short_apdu(ins: u8, data: &[u8]) -> Vec<u8> {
        assert!(data.len() <= u8::MAX as usize);
        [vec![0, ins, 0, 0, data.len() as u8], data.to_vec()].concat()
    }

    fn hsmauth_touch_calculation() -> (Card, Vec<u8>) {
        let mut card = Card::new(1);
        let select = [
            vec![0, 0xa4, 4, 0, HSMAUTH_AID.len() as u8],
            HSMAUTH_AID.to_vec(),
            vec![0],
        ]
        .concat();
        assert_eq!(&card.transmit(&select)[5..], &[0x90, 0]);

        let label = b"touch";
        let password = [0x33; 16];
        let put = [
            tlv(0x7b, &[0; 16]),
            tlv(0x71, label),
            tlv(0x74, &[38]),
            tlv(0x75, &[0x11; 16]),
            tlv(0x76, &[0x22; 16]),
            tlv(0x73, &password),
            tlv(0x7a, &[1]),
        ]
        .concat();
        assert_eq!(card.transmit(&short_apdu(0x01, &put)), [0x90, 0]);

        let challenge = card.transmit(&short_apdu(0x04, &tlv(0x71, label)));
        assert_eq!(&challenge[challenge.len() - 2..], &[0x90, 0]);
        let mut context = challenge[..challenge.len() - 2].to_vec();
        context.extend_from_slice(&[0x44; 8]);
        let calculate = [
            tlv(0x71, label),
            tlv(0x77, &context),
            tlv(0x78, &[0; 8]),
            tlv(0x73, &password),
        ]
        .concat();
        (card, short_apdu(0x03, &calculate))
    }

    #[test]
    fn usb_ccid_openpgp_discovers_provisions_and_signs_using_the_shared_core() {
        use signature::hazmat::PrehashVerifier;
        let mut device = Device::new(12345678);
        device.receive(&request(PC_TO_RDR_ICC_POWER_ON, 0, [0, 0, 0], &[]));
        let mut exchange = |apdu: &[u8]| {
            let responses = device.receive(&request(PC_TO_RDR_XFR_BLOCK, 1, [0, 0, 0], apdu));
            assert_eq!(responses.len(), 1);
            responses[0][10..].to_vec()
        };
        let mut select = vec![0, 0xa4, 4, 0, 6];
        select.extend(OPENPGP_AID);
        assert_eq!(exchange(&select), [0x90, 0]);
        let info = exchange(&[0, 0xca, 0, 0x6e, 0]);
        assert!(info.windows(6).any(|w| w == OPENPGP_AID));
        assert!(info.ends_with(&[0x90, 0]));
        assert_eq!(
            exchange(&[
                0, 0x20, 0, 0x83, 8, b'1', b'2', b'3', b'4', b'5', b'6', b'7', b'8'
            ]),
            [0x90, 0]
        );
        assert_eq!(
            exchange(&[
                0, 0xda, 0, 0xc1, 9, 0x13, 0x2a, 0x86, 0x48, 0xce, 0x3d, 3, 1, 7
            ]),
            [0x90, 0]
        );
        let public = exchange(&[0, 0x47, 0x80, 0, 2, 0xb6, 0]);
        assert!(public.ends_with(&[0x90, 0]));
        // 7F49 43 86 41 followed by the uncompressed P-256 point.
        assert_eq!(&public[..5], &[0x7f, 0x49, 0x43, 0x86, 0x41]);
        let verifier = p256::ecdsa::VerifyingKey::from_sec1_bytes(&public[5..70]).unwrap();
        let digest = software_key_core::digest::HashAlgorithm::Sha256.digest(b"USB OpenPGP");
        let mut sign = vec![0, 0x2a, 0x9e, 0x9a, 32];
        sign.extend(&digest);
        assert_eq!(exchange(&sign), [0x69, 0x82]);
        assert_eq!(
            exchange(&[0, 0x20, 0, 0x81, 6, b'1', b'2', b'3', b'4', b'5', b'6']),
            [0x90, 0]
        );
        let result = exchange(&sign);
        assert!(result.ends_with(&[0x90, 0]));
        verifier
            .verify_prehash(
                &digest,
                &p256::ecdsa::Signature::from_slice(&result[..64]).unwrap(),
            )
            .unwrap();
        assert_eq!(exchange(&sign), [0x69, 0x82]);
    }

    #[test]
    fn powers_on_with_yubikey_atr() {
        let mut device = Device::new(1);
        let responses = device.receive(&request(PC_TO_RDR_ICC_POWER_ON, 7, [0, 0, 0], &[]));
        assert_eq!(responses.len(), 1);
        assert_eq!(responses[0][0], RDR_TO_PC_DATA_BLOCK);
        assert_eq!(responses[0][6], 7);
        assert_eq!(&responses[0][10..], &ATR);
    }

    #[test]
    fn buffers_partial_messages_and_routes_management_apdus() {
        let mut device = Device::new(0x01020304);
        device.receive(&request(PC_TO_RDR_ICC_POWER_ON, 0, [0, 0, 0], &[]));
        let select = [
            vec![0, 0xa4, 4, 0, MANAGEMENT_AID.len() as u8],
            MANAGEMENT_AID.to_vec(),
            vec![0],
        ]
        .concat();
        let message = request(PC_TO_RDR_XFR_BLOCK, 1, [0, 0, 0], &select);
        assert!(device.receive(&message[..5]).is_empty());
        let responses = device.receive(&message[5..]);
        assert_eq!(
            &responses[0][10..],
            [b"Virtual mgr - FW version 5.8.0".as_slice(), &[0x90, 0]].concat()
        );
    }

    #[test]
    fn packet_sized_reads_complete_ccid_frames_without_a_short_packet_or_zlp() {
        let packet_size = crate::usb_identity::CCID_BULK_PACKET_SIZE as usize;
        for frame_len in [63, 64, 65, 127, 128, 129, 319, 320, 321, 512, 1024, 3072] {
            let mut device = Device::new(1);
            device.receive(&request(PC_TO_RDR_ICC_POWER_ON, 0, [0, 0, 0], &[]));
            let aid = virtual_yubikey_core::PIV_AID;
            let select = [vec![0, 0xa4, 4, 0, aid.len() as u8], aid.to_vec()].concat();
            device.receive(&request(PC_TO_RDR_XFR_BLOCK, 1, [0, 0, 0], &select));
            // An invalid read-only GET DATA returns 6a86 after the complete
            // APDU arrives, without requiring management authentication.
            let data_len = frame_len - 10 - 9;
            let mut apdu = vec![0, 0xcb, 0x3f, 0xff, 0];
            apdu.extend_from_slice(&(data_len as u16).to_be_bytes());
            apdu.resize(7 + data_len, 0);
            apdu.extend_from_slice(&[0, 0]);
            let message = request(PC_TO_RDR_XFR_BLOCK, 2, [0, 0, 0], &apdu);
            assert_eq!(message.len(), frame_len);
            let packets = message.chunks(packet_size);
            let packet_count = packets.len();
            for (index, packet) in packets.enumerate() {
                let replies = device.receive(packet);
                if index + 1 == packet_count {
                    assert_eq!(replies.len(), 1, "frame length {frame_len}");
                    assert_eq!(replies[0][6], 2);
                    assert_eq!(&replies[0][10..], &[0x6a, 0x86]);
                } else {
                    assert!(replies.is_empty(), "frame length {frame_len}");
                }
            }
        }
    }

    #[test]
    fn read_lengths_follow_the_header_then_the_remaining_frame() {
        for frame_len in [63, 64, 65, 319, 320, 321, 512, 1024, 3072] {
            let mut device = Device::new(1);
            device.receive(&request(PC_TO_RDR_ICC_POWER_ON, 0, [0, 0, 0], &[]));
            let aid = virtual_yubikey_core::PIV_AID;
            let select = [vec![0, 0xa4, 4, 0, aid.len() as u8], aid.to_vec()].concat();
            device.receive(&request(PC_TO_RDR_XFR_BLOCK, 1, [0, 0, 0], &select));
            let data_len = frame_len - CCID_HEADER_LENGTH - 9;
            let mut apdu = vec![0, 0xcb, 0x3f, 0xff, 0];
            apdu.extend_from_slice(&(data_len as u16).to_be_bytes());
            apdu.resize(7 + data_len, 0);
            apdu.extend_from_slice(&[0, 0]);
            let message = request(PC_TO_RDR_XFR_BLOCK, 2, [0, 0, 0], &apdu);
            assert_eq!(device.next_read_length(), 64);
            let initial = frame_len.min(device.next_read_length());
            let replies = device.receive(&message[..initial]);
            if initial < frame_len {
                assert!(replies.is_empty());
                assert_eq!(device.next_read_length(), frame_len - initial);
                let replies = device.receive(&message[initial..]);
                assert_eq!(replies.len(), 1);
                assert_eq!(&replies[0][10..], &[0x6a, 0x86]);
            } else {
                assert_eq!(replies.len(), 1);
            }
            assert_eq!(device.next_read_length(), 64);
            // A trailing USB ZLP contributes no CCID bytes. The following
            // command must retain its own sequence number and framing.
            assert!(device.receive(&[]).is_empty());
            let next = request(PC_TO_RDR_GET_SLOT_STATUS, 3, [0, 0, 0], &[]);
            let replies = device.receive(&next);
            assert_eq!(replies.len(), 1);
            assert_eq!(replies[0][6], 3);
            assert_eq!(device.next_read_length(), 64);
        }
        let mut device = Device::new(1);
        let frame = request(PC_TO_RDR_GET_SLOT_STATUS, 7, [0, 0, 0], &[]);
        assert!(device.receive(&frame[..4]).is_empty());
        assert_eq!(device.next_read_length(), 64);
        assert_eq!(device.receive(&frame[4..]).len(), 1);
        assert_eq!(device.next_read_length(), 64);
    }

    #[test]
    fn routes_fido_apdus_through_the_runtime_authenticator() {
        let mut device = Device::new(1);
        device.receive(&request(PC_TO_RDR_ICC_POWER_ON, 0, [0, 0, 0], &[]));
        let select = [
            vec![0, 0xa4, 4, 0, FIDO2_AID.len() as u8],
            FIDO2_AID.to_vec(),
        ]
        .concat();
        let mut requests = Vec::new();
        let mut handler = |request: &[u8]| {
            requests.push(request.to_vec());
            vec![0x2e]
        };
        let selected = device.receive_with_fido(
            &request(PC_TO_RDR_XFR_BLOCK, 1, [0, 0, 0], &select),
            &mut handler,
        );
        assert_eq!(&selected[0][CCID_HEADER_LENGTH..], b"U2F_V2\x90\0");

        let cbor = [0x80, 0x10, 0, 0, 2, 0xaa, 0xbb];
        let response = device.receive_with_fido(
            &request(PC_TO_RDR_XFR_BLOCK, 2, [0, 0, 0], &cbor),
            &mut handler,
        );
        assert_eq!(requests, [vec![0xaa, 0xbb]]);
        assert_eq!(&response[0][CCID_HEADER_LENGTH..], &[0x2e, 0x90, 0x00]);
    }

    #[test]
    fn openpgp_large_extended_le_uses_descriptor_bounded_response_chaining() {
        let mut device = openpgp_device(1);
        device.receive(&request(PC_TO_RDR_ICC_POWER_ON, 0, [0, 0, 0], &[]));

        let select = [
            vec![0, 0xa4, 4, 0, OPENPGP_AID.len() as u8],
            OPENPGP_AID.to_vec(),
            vec![0],
        ]
        .concat();
        let selected = device.receive(&request(PC_TO_RDR_XFR_BLOCK, 1, [0, 0, 0], &select));
        assert_eq!(&selected[0][10..], &[0x90, 0x00]);

        // Extended Le=0000 requests 65,536 bytes. The modeled firmware buffer
        // caps this to 4,096 bytes, while CCID splits the APDU response into
        // messages no larger than the descriptor's 3,072-byte maximum.
        let get_challenge = [0x00, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00];
        let first = device.receive(&request(PC_TO_RDR_XFR_BLOCK, 2, [0, 0, 0], &get_challenge));
        assert_eq!(first[0].len(), MAX_CCID_MESSAGE_LENGTH - 1);
        assert_eq!(
            u32::from_le_bytes(first[0][1..5].try_into().unwrap()),
            MAX_CCID_RESPONSE_PAYLOAD as u32
        );
        assert_eq!(first[0][9], 0x01);

        let last = device.receive(&request(PC_TO_RDR_XFR_BLOCK, 3, [0, 0x10, 0], &[]));
        assert_eq!(last[0].len(), CCID_HEADER_LENGTH + 1_037);
        assert_eq!(last[0][9], 0x02);
        assert_eq!(&last[0][last[0].len() - 2..], &[0x90, 0x00]);

        let mut apdu_response = first[0][CCID_HEADER_LENGTH..].to_vec();
        apdu_response.extend_from_slice(&last[0][CCID_HEADER_LENGTH..]);
        assert_eq!(apdu_response.len(), 4_096 + 2);
        assert_eq!(&apdu_response[apdu_response.len() - 2..], &[0x90, 0x00]);
        assert!(first[0].len() < MAX_CCID_MESSAGE_LENGTH);
        assert!(last[0].len() < MAX_CCID_MESSAGE_LENGTH);
    }

    #[test]
    fn ccid_response_boundary_accounts_for_header_and_status_word() {
        let mut device = openpgp_device(1);
        device.receive(&request(PC_TO_RDR_ICC_POWER_ON, 0, [0, 0, 0], &[]));
        let select = [
            vec![0, 0xa4, 4, 0, OPENPGP_AID.len() as u8],
            OPENPGP_AID.to_vec(),
            vec![0],
        ]
        .concat();
        device.receive(&request(PC_TO_RDR_XFR_BLOCK, 1, [0, 0, 0], &select));

        let fits = [0x00, 0x84, 0x00, 0x00, 0x00, 0x0b, 0xf3];
        let response = device.receive(&request(PC_TO_RDR_XFR_BLOCK, 2, [0, 0, 0], &fits));
        assert_eq!(response[0].len(), MAX_CCID_MESSAGE_LENGTH - 1);
        assert_eq!(response[0][9], 0x00);
        assert_eq!(&response[0][response[0].len() - 2..], &[0x90, 0x00]);

        let needs_chain = [0x00, 0x84, 0x00, 0x00, 0x00, 0x0b, 0xf4];
        let first = device.receive(&request(PC_TO_RDR_XFR_BLOCK, 3, [0, 0, 0], &needs_chain));
        assert_eq!(first[0].len(), MAX_CCID_MESSAGE_LENGTH - 1);
        assert_eq!(first[0][9], 0x01);
        let last = device.receive(&request(PC_TO_RDR_XFR_BLOCK, 4, [0, 0x10, 0], &[]));
        assert_eq!(last[0].len(), CCID_HEADER_LENGTH + 1);
        assert_eq!(last[0][9], 0x02);

        let mut complete = first[0][CCID_HEADER_LENGTH..].to_vec();
        complete.extend_from_slice(&last[0][CCID_HEADER_LENGTH..]);
        assert_eq!(complete.len(), 3_060 + 2);
        assert_eq!(&complete[complete.len() - 2..], &[0x90, 0x00]);
    }

    #[test]
    fn reassembles_descriptor_bounded_command_blocks() {
        let mut device = openpgp_device(1);
        device.receive(&request(PC_TO_RDR_ICC_POWER_ON, 0, [0, 0, 0], &[]));
        let select = [
            vec![0, 0xa4, 4, 0, OPENPGP_AID.len() as u8],
            OPENPGP_AID.to_vec(),
            vec![0],
        ]
        .concat();

        let first = device.receive(&request(PC_TO_RDR_XFR_BLOCK, 1, [0, 1, 0], &select[..6]));
        assert!(first[0][CCID_HEADER_LENGTH..].is_empty());
        assert_eq!(first[0][9], 0x10);
        let last = device.receive(&request(PC_TO_RDR_XFR_BLOCK, 2, [0, 2, 0], &select[6..]));
        assert_eq!(&last[0][CCID_HEADER_LENGTH..], &[0x90, 0x00]);

        let challenge = [0x00, 0x84, 0x00, 0x00, 0x20];
        let response = device.receive(&request(PC_TO_RDR_XFR_BLOCK, 3, [0, 0, 0], &challenge));
        assert_eq!(response[0].len(), CCID_HEADER_LENGTH + 32 + 2);
        assert_eq!(&response[0][response[0].len() - 2..], &[0x90, 0x00]);
    }

    #[test]
    fn rejects_unknown_commands_with_diagnostics_response() {
        let mut device = Device::new(1);
        let response = device.receive(&request(0x72, 9, [0, 0, 0], &[]));
        assert_eq!(response[0][0], RDR_TO_PC_SLOT_STATUS);
        assert_eq!(
            response[0][7] & STATUS_COMMAND_FAILED,
            STATUS_COMMAND_FAILED
        );
    }

    #[test]
    fn rejects_incoming_messages_larger_than_the_descriptor_limit() {
        let mut device = Device::new(1);
        let oversized = request(
            PC_TO_RDR_XFR_BLOCK,
            9,
            [0, 0, 0],
            &vec![0; MAX_CCID_PAYLOAD + 1],
        );
        let response = device.receive(&oversized);
        assert_eq!(response.len(), 1);
        assert_eq!(response[0][0], RDR_TO_PC_DATA_BLOCK);
        assert_eq!(
            response[0][7] & STATUS_COMMAND_FAILED,
            STATUS_COMMAND_FAILED
        );
        assert_eq!(response[0][8], ERROR_BAD_LENGTH);
        assert!(response[0].len() <= MAX_CCID_MESSAGE_LENGTH);
    }

    #[test]
    fn time_extension_has_the_original_slot_and_sequence() {
        assert_eq!(
            time_extension(2, 9),
            [RDR_TO_PC_DATA_BLOCK, 0, 0, 0, 0, 2, 9, 0x80, 1, 0]
        );
    }

    #[test]
    fn slow_work_emits_extensions_only_until_its_result_is_ready() {
        let scheduler = keepalive::Scheduler::start().unwrap();
        let clock = scheduler.handle();
        let mut extensions = Vec::new();
        let result = run_with_keepalives(
            || {
                thread::sleep(Duration::from_millis(35));
                42
            },
            0,
            7,
            &clock,
            Duration::from_millis(5),
            Duration::from_millis(5),
            &mut |frame| {
                extensions.push(frame.to_vec());
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(result, 42);
        assert!(!extensions.is_empty());
        assert!(
            extensions
                .iter()
                .all(|frame| frame == &time_extension(0, 7))
        );

        let count = extensions.len();
        thread::sleep(Duration::from_millis(20));
        assert_eq!(extensions.len(), count);
    }

    #[test]
    fn hsmauth_touch_wait_emits_ccid_time_extensions() {
        let (mut card, calculate) = hsmauth_touch_calculation();
        let scheduler = keepalive::Scheduler::start().unwrap();
        let clock = scheduler.handle();
        let mut extensions = Vec::new();
        let response = run_with_keepalives(
            || {
                card.transmit_with_presence(&calculate, || {
                    thread::sleep(Duration::from_millis(35));
                    Ok(true)
                })
            },
            0,
            11,
            &clock,
            Duration::from_millis(5),
            Duration::from_millis(5),
            &mut |frame| {
                extensions.push(frame.to_vec());
                Ok(())
            },
        )
        .unwrap()
        .unwrap();

        assert_eq!(response, [0x69, 0x84]);
        assert!(!extensions.is_empty());
        assert!(
            extensions
                .iter()
                .all(|frame| frame == &time_extension(0, 11))
        );
    }

    #[test]
    fn hsmauth_touch_timeout_stops_extensions_and_fails_the_apdu() {
        let (mut card, calculate) = hsmauth_touch_calculation();
        let scheduler = keepalive::Scheduler::start().unwrap();
        let clock = scheduler.handle();
        let mut extensions = Vec::new();
        let response = run_with_keepalives(
            || {
                card.transmit_with_presence(&calculate, || {
                    thread::sleep(Duration::from_millis(35));
                    Ok(false)
                })
            },
            0,
            12,
            &clock,
            Duration::from_millis(5),
            Duration::from_millis(5),
            &mut |frame| {
                extensions.push(frame.to_vec());
                Ok(())
            },
        )
        .unwrap()
        .unwrap();

        assert_eq!(response, [0x69, 0x85]);
        assert!(!extensions.is_empty());
        assert!(
            extensions
                .iter()
                .all(|frame| frame == &time_extension(0, 12))
        );
        let count = extensions.len();
        thread::sleep(Duration::from_millis(20));
        assert_eq!(extensions.len(), count);
    }
}
