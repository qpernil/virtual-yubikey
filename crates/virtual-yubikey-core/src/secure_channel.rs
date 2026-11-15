use crate::{CommandApdu, OwnedCommandApdu, ResponseApdu};
use software_key_core::{
    secure_channel::{pad_iso7816, scp03_cryptogram, scp03_kdf, unpad_iso7816, x963_kdf_sha256},
    software_key_agreement::derive_with_signing_key,
    software_signing::{EcCurve, KeyKind, SoftwarePublicKey, SoftwareSigningKey},
    software_symmetric::{aes_cmac, decrypt_aes_cbc, encrypt_aes_block, encrypt_aes_cbc},
};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

const MAC_LENGTH: usize = 8;
const AES_BLOCK_SIZE: usize = 16;
const SCP03_KEY_ID: u8 = 0x00;
const SECURITY_C_MAC: u8 = 0x01;
const SECURITY_C_ENCRYPTION: u8 = 0x02;
const SECURITY_R_MAC: u8 = 0x10;
const SECURITY_R_ENCRYPTION: u8 = 0x20;
const SCP11_SECURITY_LEVEL: u8 = 0x33;
const SCP11_SHARED_INFO: [u8; 3] = [0x3c, 0x88, 0x10];

pub(crate) enum ChannelOutcome {
    Handled(ResponseApdu),
    Command(OwnedCommandApdu, bool),
}

#[derive(Default)]
pub(crate) struct SecureChannel {
    pending_scp03: Option<PendingScp03>,
    host_certificates: Option<HostCertificates>,
    session: Option<Session>,
}

impl std::fmt::Debug for SecureChannel {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SecureChannel")
            .field("pending_scp03", &self.pending_scp03.is_some())
            .field("active", &self.session.is_some())
            .finish()
    }
}

struct HostCertificates {
    reference: (u8, u8),
    certificates: Vec<Vec<u8>>,
    complete: bool,
}

struct PendingScp03 {
    reference: (u8, u8),
    host_cryptogram: [u8; 8],
    s_enc: Zeroizing<Vec<u8>>,
    s_mac: Zeroizing<Vec<u8>>,
    s_rmac: Zeroizing<Vec<u8>>,
    dek: Zeroizing<Vec<u8>>,
}

struct Session {
    dek: Zeroizing<Vec<u8>>,
    oce_authenticated: bool,
    s_enc: Zeroizing<Vec<u8>>,
    s_mac: Zeroizing<Vec<u8>>,
    s_rmac: Zeroizing<Vec<u8>>,
    mac_chaining_value: [u8; AES_BLOCK_SIZE],
    encryption_counter: u128,
    security_level: u8,
}

const INITIALIZE_UPDATE: u8 = yubikey_apdu::scp::INITIALIZE_UPDATE.ins;
const EXTERNAL_AUTHENTICATE: u8 = yubikey_apdu::scp::EXTERNAL_AUTHENTICATE.ins;
const INTERNAL_AUTHENTICATE: u8 = yubikey_apdu::scp::INTERNAL_AUTHENTICATE.ins;
const UPLOAD_CERTIFICATE: u8 = yubikey_apdu::scp::UPLOAD_CERTIFICATE.ins;

impl SecureChannel {
    pub(crate) fn pending_authentication_reference(&self) -> Option<(u8, u8)> {
        self.pending_scp03.as_ref().map(|pending| pending.reference)
    }

    pub(crate) fn begins_establishment(command: &CommandApdu<'_>) -> bool {
        command.cla == 0x80
            && matches!(
                command.ins,
                INITIALIZE_UPDATE | INTERNAL_AUTHENTICATE | EXTERNAL_AUTHENTICATE
            )
    }

    /// Whether a successful protocol step completes an authentication attempt.
    pub(crate) fn completes_authentication(command: &CommandApdu<'_>) -> bool {
        command.ins != INITIALIZE_UPDATE
            && (command.ins != UPLOAD_CERTIFICATE || command.p2 & 0x80 == 0)
    }

    pub(crate) fn reset(&mut self) {
        self.pending_scp03 = None;
        self.host_certificates = None;
        self.session = None;
    }

    pub(crate) fn process(
        &mut self,
        command: &CommandApdu<'_>,
        security_domain: &crate::security_domain::SecurityDomain,
    ) -> ChannelOutcome {
        if Self::begins_establishment(command) && command.ins == INITIALIZE_UPDATE {
            return ChannelOutcome::Handled(self.initialize_update(command, security_domain));
        }
        if command.cla == 0x84 && command.ins == EXTERNAL_AUTHENTICATE {
            return ChannelOutcome::Handled(self.external_authenticate(command));
        }
        if Self::begins_establishment(command) {
            return ChannelOutcome::Handled(self.scp11_authenticate(command, security_domain));
        }

        if command.cla == 0x80 && command.ins == UPLOAD_CERTIFICATE {
            return ChannelOutcome::Handled(self.upload_host_certificate(command, security_domain));
        }
        let protected = command.cla & 0x04 != 0;
        if !protected {
            return ChannelOutcome::Command(OwnedCommandApdu::from_command(command), false);
        }
        match self.unprotect(command) {
            Ok(command) => ChannelOutcome::Command(command, true),
            Err(status) => {
                self.reset();
                ChannelOutcome::Handled(ResponseApdu::status(status))
            }
        }
    }

    /// Only expose administration authority while dispatching a command whose
    /// C-MAC has verified. For SCP11a/c this is also proof of host key possession;
    /// merely uploading a valid certificate never authorizes a write.
    pub(crate) fn administration_dek(&self, protected: bool) -> Option<&[u8]> {
        let session = self.session.as_ref()?;
        (protected && session.oce_authenticated).then_some(session.dek.as_slice())
    }

    pub(crate) fn protect_response(&self, response: ResponseApdu) -> ResponseApdu {
        let Some(session) = self.session.as_ref() else {
            return response;
        };
        if response.status != 0x9000
            && response.status & 0xff00 != 0x6200
            && response.status & 0xff00 != 0x6300
        {
            return ResponseApdu::status(response.status);
        }
        let mut data = response.data;
        if session.security_level & SECURITY_R_ENCRYPTION != 0 && !data.is_empty() {
            let Ok(iv) = session.command_iv(true) else {
                return ResponseApdu::status(0x6f00);
            };
            let Ok(encrypted) = encrypt_aes_cbc(&session.s_enc, &iv, &pad_iso7816(&data)) else {
                return ResponseApdu::status(0x6f00);
            };
            data = encrypted;
        }
        if session.security_level & SECURITY_R_MAC != 0 {
            let mut input = Vec::with_capacity(16 + data.len() + 2);
            input.extend_from_slice(&session.mac_chaining_value);
            input.extend_from_slice(&data);
            input.extend_from_slice(&response.status.to_be_bytes());
            let Ok(mac) = aes_cmac(&session.s_rmac, &input) else {
                return ResponseApdu::status(0x6f00);
            };
            data.extend_from_slice(&mac[..MAC_LENGTH]);
        }
        ResponseApdu {
            data,
            status: response.status,
        }
    }

    fn initialize_update(
        &mut self,
        command: &CommandApdu<'_>,
        domain: &crate::security_domain::SecurityDomain,
    ) -> ResponseApdu {
        self.reset();
        if yubikey_apdu::scp::INITIALIZE_UPDATE
            .validate(command)
            .is_err()
            || command.p2 != SCP03_KEY_ID
        {
            return ResponseApdu::status(0x6a88);
        }
        let mut card_challenge = [0_u8; 8];
        if getrandom::fill(&mut card_challenge).is_err() {
            return ResponseApdu::status(0x6f00);
        }
        let mut context = [0_u8; 16];
        context[..8].copy_from_slice(command.data);
        context[8..].copy_from_slice(&card_challenge);
        let Some((key_version, static_keys)) = domain.scp03_keys(command.p1) else {
            return ResponseApdu::status(0x6a88);
        };
        let Ok(s_enc) = scp03_kdf(&static_keys[..16], 0x04, &context, 128) else {
            return ResponseApdu::status(0x6f00);
        };
        let Ok(s_mac) = scp03_kdf(&static_keys[16..32], 0x06, &context, 128) else {
            return ResponseApdu::status(0x6f00);
        };
        let Ok(s_rmac) = scp03_kdf(&static_keys[16..32], 0x07, &context, 128) else {
            return ResponseApdu::status(0x6f00);
        };
        let Ok(card_cryptogram) = scp03_cryptogram(&s_mac, 0x00, &context) else {
            return ResponseApdu::status(0x6f00);
        };
        let Ok(host_cryptogram) = scp03_cryptogram(&s_mac, 0x01, &context) else {
            return ResponseApdu::status(0x6f00);
        };
        self.pending_scp03 = Some(PendingScp03 {
            reference: (0, key_version),
            host_cryptogram,
            s_enc: Zeroizing::new(s_enc),
            s_mac: Zeroizing::new(s_mac),
            s_rmac: Zeroizing::new(s_rmac),
            dek: Zeroizing::new(static_keys[32..48].to_vec()),
        });
        let mut data = vec![0; 10];
        data.extend([key_version, 0x03, 0x60]);
        data.extend_from_slice(&card_challenge);
        data.extend_from_slice(&card_cryptogram);
        ResponseApdu::success(data)
    }

    fn external_authenticate(&mut self, command: &CommandApdu<'_>) -> ResponseApdu {
        let Some(pending) = self.pending_scp03.take() else {
            return ResponseApdu::status(0x6985);
        };
        let security_level = command.p1;
        if yubikey_apdu::scp::EXTERNAL_AUTHENTICATE
            .validate(command)
            .is_err()
            || security_level & !0x33 != 0
            || security_level & SECURITY_C_MAC == 0
            || !bool::from(pending.host_cryptogram.ct_eq(&command.data[..8]))
        {
            return ResponseApdu::status(0x6982);
        }
        let mut input = vec![0; AES_BLOCK_SIZE];
        let Ok(header) = encode_header_and_data(command, command.data.len(), &command.data[..8])
        else {
            return ResponseApdu::status(0x6700);
        };
        input.extend_from_slice(&header);
        let Ok(mac) = aes_cmac(&pending.s_mac, &input) else {
            return ResponseApdu::status(0x6f00);
        };
        if !bool::from(mac[..MAC_LENGTH].ct_eq(&command.data[8..])) {
            return ResponseApdu::status(0x6982);
        }
        self.session = Some(Session {
            dek: pending.dek,
            oce_authenticated: true,
            s_enc: pending.s_enc,
            s_mac: pending.s_mac,
            s_rmac: pending.s_rmac,
            mac_chaining_value: mac,
            encryption_counter: 0,
            security_level,
        });
        ResponseApdu::success(Vec::new())
    }

    fn scp11_authenticate(
        &mut self,
        command: &CommandApdu<'_>,
        security_domain: &crate::security_domain::SecurityDomain,
    ) -> ResponseApdu {
        // Consume uploaded credentials on every attempt, successful or otherwise.
        let host_certificates = self.host_certificates.take();
        self.reset();
        if let Err(error) = yubikey_apdu::find(yubikey_apdu::scp::COMMANDS, command) {
            return ResponseApdu::status(error.status());
        }
        let parameter = match (command.ins, command.p2) {
            (INTERNAL_AUTHENTICATE, 0x13) => 0,
            (EXTERNAL_AUTHENTICATE, 0x11) => 1,
            (EXTERNAL_AUTHENTICATE, 0x15) => 3,
            _ => return ResponseApdu::status(0x6a86),
        };
        let Some(card_static) = security_domain.scp11_key(command.p2, command.p1) else {
            return ResponseApdu::status(0x6a88);
        };
        let Some(host_ephemeral) = parse_scp11_request(command.data, parameter) else {
            return ResponseApdu::status(0x6a80);
        };
        let host_static = if parameter == 0 {
            None
        } else {
            let Some(upload) = host_certificates.filter(|upload| upload.complete) else {
                return ResponseApdu::status(0x6985);
            };
            let Some(point) = security_domain.validate_host(
                Some((command.p2, command.p1)),
                upload.reference,
                &upload.certificates,
            ) else {
                return ResponseApdu::status(0x6982);
            };
            Some(point)
        };
        let card_ephemeral = if parameter == 3 {
            None
        } else {
            let Ok(key) = SoftwareSigningKey::generate_for_kind(KeyKind::Ec(EcCurve::P256)) else {
                return ResponseApdu::status(0x6f00);
            };
            Some(key)
        };
        let Ok(ka1) = derive_with_signing_key(
            card_ephemeral.as_ref().unwrap_or(card_static),
            host_ephemeral,
        ) else {
            return ResponseApdu::status(0x6a80);
        };
        let Ok(ka2) = derive_with_signing_key(
            card_static,
            host_static.as_deref().unwrap_or(host_ephemeral),
        ) else {
            return ResponseApdu::status(0x6a80);
        };
        let mut agreement = Zeroizing::new(Vec::with_capacity(64));
        agreement.extend_from_slice(&ka1);
        agreement.extend_from_slice(&ka2);
        let Ok(keys) = x963_kdf_sha256(&agreement, &SCP11_SHARED_INFO, 80) else {
            return ResponseApdu::status(0x6f00);
        };
        let card_ephemeral_tlv = match card_ephemeral {
            Some(key) => {
                let SoftwarePublicKey::Ec {
                    curve: EcCurve::P256,
                    uncompressed: point,
                } = key.public_key()
                else {
                    return ResponseApdu::status(0x6f00);
                };
                encode_tlv(&[0x5f, 0x49], &point)
            }
            None => Vec::new(),
        };
        let mut receipt_input = Vec::with_capacity(command.data.len() + card_ephemeral_tlv.len());
        receipt_input.extend_from_slice(command.data);
        receipt_input.extend_from_slice(&card_ephemeral_tlv);
        let Ok(receipt) = aes_cmac(&keys[..16], &receipt_input) else {
            return ResponseApdu::status(0x6f00);
        };
        self.session = Some(Session {
            dek: Zeroizing::new(keys[64..80].to_vec()),
            oce_authenticated: parameter != 0,
            s_enc: Zeroizing::new(keys[16..32].to_vec()),
            s_mac: Zeroizing::new(keys[32..48].to_vec()),
            s_rmac: Zeroizing::new(keys[48..64].to_vec()),
            mac_chaining_value: receipt,
            encryption_counter: 0,
            security_level: SCP11_SECURITY_LEVEL,
        });
        let mut response = card_ephemeral_tlv;
        response.extend(encode_tlv(&[0x86], &receipt));
        ResponseApdu::success(response)
    }

    /// Called only after ISO command chaining has assembled one PSO certificate.
    pub(crate) fn upload_host_certificate(
        &mut self,
        command: &CommandApdu<'_>,
        security_domain: &crate::security_domain::SecurityDomain,
    ) -> ResponseApdu {
        if let Err(error) = yubikey_apdu::scp::UPLOAD_CERTIFICATE.validate(command) {
            self.reset();
            return ResponseApdu::status(error.status());
        }
        let reference = (command.p2 & 0x7f, command.p1);
        if self
            .host_certificates
            .as_ref()
            .is_none_or(|upload| upload.complete)
        {
            self.reset();
            self.host_certificates = Some(HostCertificates {
                reference,
                certificates: Vec::new(),
                complete: false,
            });
        }
        let upload = self.host_certificates.as_mut().unwrap();
        if upload.reference != reference
            || command.data.len() > 8192
            || upload.certificates.len() >= 8
            || software_key_core::certificate_chain::ParsedCertificate::parse(command.data).is_err()
        {
            self.reset();
            return ResponseApdu::status(0x6a80);
        }
        upload.certificates.push(command.data.to_vec());
        if command.p2 & 0x80 == 0 {
            if security_domain
                .validate_host(None, reference, &upload.certificates)
                .is_none()
            {
                self.reset();
                return ResponseApdu::status(0x6982);
            }
            upload.complete = true;
        }
        ResponseApdu::success(Vec::new())
    }

    fn unprotect(&mut self, command: &CommandApdu<'_>) -> Result<OwnedCommandApdu, u16> {
        let session = self.session.as_mut().ok_or(0x6982_u16)?;
        session.encryption_counter = session
            .encryption_counter
            .checked_add(1)
            .ok_or(0x6f00_u16)?;
        let mut data = command.data.to_vec();
        if session.security_level & SECURITY_C_MAC != 0 {
            if data.len() < MAC_LENGTH {
                return Err(0x6982);
            }
            let received = data.split_off(data.len() - MAC_LENGTH);
            let mut input = Vec::with_capacity(16 + 7 + data.len());
            input.extend_from_slice(&session.mac_chaining_value);
            input.extend_from_slice(&encode_header_and_data(command, command.data.len(), &data)?);
            let mac = aes_cmac(&session.s_mac, &input).map_err(|_| 0x6f00_u16)?;
            if !bool::from(mac[..MAC_LENGTH].ct_eq(&received)) {
                return Err(0x6982);
            }
            session.mac_chaining_value = mac;
        }
        if session.security_level & SECURITY_C_ENCRYPTION != 0 && !data.is_empty() {
            if !data.len().is_multiple_of(AES_BLOCK_SIZE) {
                return Err(0x6982);
            }
            let iv = session.command_iv(false).map_err(|_| 0x6f00_u16)?;
            data =
                unpad_iso7816(decrypt_aes_cbc(&session.s_enc, &iv, &data).map_err(|_| 0x6982_u16)?)
                    .map_err(|_| 0x6982_u16)?;
        }
        Ok(OwnedCommandApdu {
            cla: command.cla & !0x0c,
            ins: command.ins,
            p1: command.p1,
            p2: command.p2,
            data,
            le: command.le,
            extended: command.extended,
        })
    }
}

impl Session {
    fn command_iv(&self, response: bool) -> Result<[u8; AES_BLOCK_SIZE], ()> {
        let mut counter = self.encryption_counter.to_be_bytes();
        if response {
            counter[0] |= 0x80;
        }
        encrypt_aes_block(&self.s_enc, &counter).map_err(|_| ())
    }
}

fn encode_header_and_data(
    command: &CommandApdu<'_>,
    encoded_length: usize,
    data: &[u8],
) -> Result<Vec<u8>, u16> {
    CommandApdu { data, ..*command }
        .encode_header_and_data(encoded_length)
        .map_err(|_| 0x6700)
}

fn parse_scp11_request(data: &[u8], parameter: u8) -> Option<&[u8]> {
    let parameters = &[
        0xa6, 0x0d, 0x90, 0x02, 0x11, parameter, 0x95, 0x01, 0x3c, 0x80, 0x01, 0x88, 0x81, 0x01,
        0x10,
    ];
    let remaining = data.strip_prefix(parameters)?;
    let remaining = remaining.strip_prefix(&[0x5f, 0x49, 0x41])?;
    if remaining.len() == 65 && remaining.first() == Some(&0x04) {
        Some(remaining)
    } else {
        None
    }
}

fn encode_tlv(tag: &[u8], value: &[u8]) -> Vec<u8> {
    debug_assert!(value.len() < 0x80);
    let mut output = Vec::with_capacity(tag.len() + 1 + value.len());
    output.extend_from_slice(tag);
    output.push(value.len() as u8);
    output.extend_from_slice(value);
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        Applet, DeviceProfile, FIDO2_AID, HSMAUTH_AID, ISSUER_SECURITY_DOMAIN_AID, MANAGEMENT_AID,
        OATH_AID, OPENPGP_AID, PIV_AID, VirtualYubiKey,
    };

    struct HostSession {
        s_enc: Vec<u8>,
        s_mac: Vec<u8>,
        s_rmac: Vec<u8>,
        chain: [u8; 16],
        counter: u128,
    }

    struct HostCommand<'a> {
        cla: u8,
        ins: u8,
        p1: u8,
        p2: u8,
        data: &'a [u8],
        le: Option<u8>,
    }

    impl<'a> HostCommand<'a> {
        fn short(ins: u8, p2: u8, data: &'a [u8], le: u8) -> Self {
            Self {
                cla: 0,
                ins,
                p1: 0,
                p2,
                data,
                le: Some(le),
            }
        }
    }

    type SecureMessagingCase = (&'static [u8], Applet, HostCommand<'static>);

    impl HostSession {
        fn exchange(
            &mut self,
            device: &mut VirtualYubiKey,
            command: &HostCommand<'_>,
        ) -> ResponseApdu {
            let raw = self.protect_command(command);
            let response = send(device, &raw);
            self.unprotect_response(collect_response(device, response))
        }

        fn protect_command(&mut self, command: &HostCommand<'_>) -> Vec<u8> {
            self.counter += 1;
            let protected_cla = (command.cla & !0x0c) | 0x04;
            let mut data = if command.data.is_empty() {
                Vec::new()
            } else {
                let iv = self.command_iv(false);
                encrypt_aes_cbc(&self.s_enc, &iv, &pad_iso7816(command.data)).unwrap()
            };
            let header = CommandApdu {
                cla: protected_cla,
                ins: command.ins,
                p1: command.p1,
                p2: command.p2,
                data: &data,
                le: command
                    .le
                    .map(|value| if value == 0 { 256 } else { u32::from(value) }),
                extended: false,
            };
            let mut mac_input = self.chain.to_vec();
            mac_input
                .extend(encode_header_and_data(&header, data.len() + MAC_LENGTH, &data).unwrap());
            let mac = aes_cmac(&self.s_mac, &mac_input).unwrap();
            self.chain = mac;
            data.extend_from_slice(&mac[..MAC_LENGTH]);
            let mut raw = vec![
                protected_cla,
                command.ins,
                command.p1,
                command.p2,
                data.len() as u8,
            ];
            raw.extend_from_slice(&data);
            if let Some(le) = command.le {
                raw.push(le);
            }
            raw
        }

        fn unprotect_response(&self, response: ResponseApdu) -> ResponseApdu {
            assert!(matches!(response.status, 0x9000 | 0x6200..=0x63ff));
            assert!(response.data.len() >= MAC_LENGTH);
            let mut protected_data = response.data;
            let received_mac = protected_data.split_off(protected_data.len() - MAC_LENGTH);
            let mut mac_input = self.chain.to_vec();
            mac_input.extend_from_slice(&protected_data);
            mac_input.extend_from_slice(&response.status.to_be_bytes());
            let expected_mac = aes_cmac(&self.s_rmac, &mac_input).unwrap();
            assert!(bool::from(expected_mac[..MAC_LENGTH].ct_eq(&received_mac)));
            let data = if protected_data.is_empty() {
                Vec::new()
            } else {
                let iv = self.command_iv(true);
                unpad_iso7816(decrypt_aes_cbc(&self.s_enc, &iv, &protected_data).unwrap()).unwrap()
            };
            ResponseApdu {
                data,
                status: response.status,
            }
        }

        fn command_iv(&self, response: bool) -> [u8; 16] {
            let mut counter = self.counter.to_be_bytes();
            if response {
                counter[0] |= 0x80;
            }
            encrypt_aes_block(&self.s_enc, &counter).unwrap()
        }
    }

    fn establish_scp03(device: &mut VirtualYubiKey) -> HostSession {
        establish_scp03_with_format(device, false)
    }

    fn establish_scp03_with_format(device: &mut VirtualYubiKey, extended: bool) -> HostSession {
        let host_challenge = [0x11; 8];
        let mut initialize = vec![0x80, 0x50, 0xff, 0x00, 0x08];
        initialize.extend_from_slice(&host_challenge);
        initialize.push(0);
        let response = send(device, &initialize);
        assert_eq!(response.status, 0x9000);
        assert_eq!(response.data.len(), 29);
        assert_eq!(&response.data[10..13], &[0xff, 0x03, 0x60]);
        let mut context = [0_u8; 16];
        context[..8].copy_from_slice(&host_challenge);
        context[8..].copy_from_slice(&response.data[13..21]);
        let key = crate::security_domain::factory_scp03_key();
        let s_enc = scp03_kdf(key, 0x04, &context, 128).unwrap();
        let s_mac = scp03_kdf(key, 0x06, &context, 128).unwrap();
        let s_rmac = scp03_kdf(key, 0x07, &context, 128).unwrap();
        assert_eq!(
            scp03_cryptogram(&s_mac, 0x00, &context).unwrap(),
            response.data[21..29]
        );
        let host_cryptogram = scp03_cryptogram(&s_mac, 0x01, &context).unwrap();
        let mut authenticate = vec![0x84, 0x82, 0x33, 0];
        if extended {
            authenticate.extend([0, 0, 0x10]);
        } else {
            authenticate.push(0x10);
        }
        let mut mac_input = vec![0; 16];
        mac_input.extend_from_slice(&authenticate);
        mac_input.extend_from_slice(&host_cryptogram);
        let mac = aes_cmac(&s_mac, &mac_input).unwrap();
        authenticate.extend_from_slice(&host_cryptogram);
        authenticate.extend_from_slice(&mac[..8]);
        assert_eq!(send(device, &authenticate).status, 0x9000);
        HostSession {
            s_enc,
            s_mac,
            s_rmac,
            chain: mac,
            counter: 0,
        }
    }

    fn establish_scp11b(device: &mut VirtualYubiKey) -> HostSession {
        let card_static = device.scp11b_public_key();
        let host = SoftwareSigningKey::generate_for_kind(KeyKind::Ec(EcCurve::P256)).unwrap();
        let SoftwarePublicKey::Ec {
            uncompressed: host_point,
            ..
        } = host.public_key()
        else {
            unreachable!()
        };
        let mut request = vec![
            0xa6, 0x0d, 0x90, 0x02, 0x11, 0x00, 0x95, 0x01, 0x3c, 0x80, 0x01, 0x88, 0x81, 0x01,
            0x10, 0x5f, 0x49, 0x41,
        ];
        request.extend_from_slice(&host_point);
        let mut raw = vec![0x80, 0x88, 0x01, 0x13, request.len() as u8];
        raw.extend_from_slice(&request);
        raw.push(0);
        let response = send(device, &raw);
        assert_eq!(response.status, 0x9000);
        assert_eq!(&response.data[..3], &[0x5f, 0x49, 0x41]);
        let card_ephemeral = &response.data[3..68];
        assert_eq!(&response.data[68..70], &[0x86, 0x10]);
        let ka1 = derive_with_signing_key(&host, card_ephemeral).unwrap();
        let ka2 = derive_with_signing_key(&host, &card_static).unwrap();
        let mut agreement = Zeroizing::new(Vec::with_capacity(64));
        agreement.extend_from_slice(&ka1);
        agreement.extend_from_slice(&ka2);
        let keys = x963_kdf_sha256(&agreement, &SCP11_SHARED_INFO, 80).unwrap();
        let mut receipt_input = request;
        receipt_input.extend_from_slice(&response.data[..68]);
        let receipt = aes_cmac(&keys[..16], &receipt_input).unwrap();
        assert_eq!(receipt, response.data[70..86]);
        HostSession {
            s_enc: keys[16..32].to_vec(),
            s_mac: keys[32..48].to_vec(),
            s_rmac: keys[48..64].to_vec(),
            chain: receipt,
            counter: 0,
        }
    }

    #[test]
    fn scp03_external_authenticate_supports_short_and_extended_apdus() {
        for extended in [false, true] {
            let mut device = VirtualYubiKey::new(DeviceProfile::yubikey_5_8_ccid(12345678));
            let mut select = vec![0, 0xa4, 4, 0, ISSUER_SECURITY_DOMAIN_AID.len() as u8];
            select.extend_from_slice(&ISSUER_SECURITY_DOMAIN_AID);
            assert_eq!(send(&mut device, &select).status, 0x9000);
            let expected = send(&mut device, &[0, 0xca, 0, 0xe0, 0]).data;
            let mut host = establish_scp03_with_format(&mut device, extended);
            for _ in 0..3 {
                let response = host.exchange(&mut device, &HostCommand::short(0xca, 0xe0, &[], 0));
                assert_eq!(response.status, 0x9000);
                assert_eq!(response.data, expected);
            }
        }
    }

    #[test]
    fn protected_security_domain_commands_use_iso_chaining() {
        let mut device = VirtualYubiKey::new(DeviceProfile::yubikey_5_8_ccid(42));
        assert_eq!(
            send(&mut device, &select(&ISSUER_SECURITY_DOMAIN_AID)).status,
            0x9000
        );
        let mut host = establish_scp03(&mut device);
        let ca = SoftwareSigningKey::generate_for_kind(KeyKind::Ec(EcCurve::P256)).unwrap();
        let SoftwarePublicKey::Ec { uncompressed, .. } = ca.public_key() else {
            unreachable!()
        };
        let mut data = vec![1, 0xb0, 65];
        data.extend_from_slice(&uncompressed);
        data.extend_from_slice(&[0xf0, 1, 0, 0]);
        let put = HostCommand {
            cla: 0x80,
            ins: 0xd8,
            p1: 0,
            p2: 0x20,
            data: &data,
            le: Some(0),
        };
        let delete = HostCommand {
            cla: 0x80,
            ins: 0xe4,
            p1: 0,
            p2: 0,
            data: &[0xd0, 1, 0x20, 0xd2, 1, 1],
            le: Some(0),
        };
        for (command, expected) in [(put, vec![1]), (delete, vec![])] {
            let raw = host.protect_command(&command);
            let protected = CommandApdu::decode(&raw).unwrap();
            let split = protected.data.len() / 2;
            let mut first = vec![
                protected.cla | 0x10,
                protected.ins,
                protected.p1,
                protected.p2,
                split as u8,
            ];
            first.extend_from_slice(&protected.data[..split]);
            let ack = send(&mut device, &first);
            assert_eq!(ack, ResponseApdu::success(vec![]));
            let mut last = vec![
                protected.cla,
                protected.ins,
                protected.p1,
                protected.p2,
                (protected.data.len() - split) as u8,
            ];
            last.extend_from_slice(&protected.data[split..]);
            last.push(0);
            let response = send(&mut device, &last);
            assert_eq!(host.unprotect_response(response).data, expected);
        }
    }

    #[test]
    fn applet_p1_parameters_are_preserved_without_an_exception_list() {
        let cases: &[(&[u8], HostCommand<'_>)] = &[
            // RESET has a high P1 selector in both applets.
            (
                &OATH_AID,
                HostCommand {
                    cla: 0,
                    ins: 4,
                    p1: 0xde,
                    p2: 0xad,
                    data: &[],
                    le: Some(0),
                },
            ),
            (
                &HSMAUTH_AID,
                HostCommand {
                    cla: 0,
                    ins: 6,
                    p1: 0xde,
                    p2: 0xad,
                    data: &[],
                    le: Some(0),
                },
            ),
        ];
        for scp11 in [false, true] {
            for (aid, command) in cases {
                let mut device = VirtualYubiKey::new(DeviceProfile::yubikey_5_8_ccid(42));
                assert_eq!(send(&mut device, &select(aid)).status, 0x9000);
                let mut host = if scp11 {
                    establish_scp11b(&mut device)
                } else {
                    establish_scp03(&mut device)
                };
                assert_eq!(host.exchange(&mut device, command).status, 0x9000);
                // The reset executed and the protected channel remains synchronized.
                let version =
                    HostCommand::short(if *aid == OATH_AID { 0xa1 } else { 7 }, 0, &[], 0);
                assert_eq!(host.exchange(&mut device, &version).status, 0x9000);
            }
        }
    }

    #[test]
    fn select_requires_its_full_unprotected_header() {
        let mut device = VirtualYubiKey::new(DeviceProfile::yubikey_5_8_ccid(42));
        assert_eq!(send(&mut device, &select(&OPENPGP_AID)).status, 0x9000);
        establish_scp03(&mut device);
        let mut invalid = select(&PIV_AID);
        invalid[3] = 1;
        assert_eq!(send(&mut device, &invalid).status, 0x6a86);
        assert_eq!(device.selected_applet(), Some(Applet::OpenPgp));
        // An applet-specific CLA does not become an unprotected SELECT.
        invalid[0] = 0x80;
        invalid[3] = 0;
        assert_eq!(send(&mut device, &invalid).status, 0x6e00);
        assert_eq!(device.selected_applet(), Some(Applet::OpenPgp));
        // A protected header must go through C-MAC verification.
        invalid[0] = 4;
        assert_eq!(send(&mut device, &invalid).status, 0x6982);
        assert_eq!(device.selected_applet(), Some(Applet::OpenPgp));
        assert!(device.secure_channel.session.is_none());
        let mut host = establish_scp03(&mut device);
        assert_eq!(
            host.exchange(&mut device, &HostCommand::short(0x84, 0, &[], 8))
                .data
                .len(),
            8
        );
    }

    #[test]
    fn protected_openpgp_commands_preserve_p1_parameters() {
        for scp11 in [false, true] {
            let mut device = VirtualYubiKey::new(DeviceProfile::yubikey_5_8_ccid(42));
            assert_eq!(send(&mut device, &select(&OPENPGP_AID)).status, 0x9000);
            let mut channel = if scp11 {
                establish_scp11b(&mut device)
            } else {
                establish_scp03(&mut device)
            };
            let admin = HostCommand::short(0x20, 0x83, b"12345678", 0);
            assert_eq!(channel.exchange(&mut device, &admin).status, 0x9000);
            let generate = HostCommand {
                cla: 0,
                ins: 0x47,
                p1: 0x80,
                p2: 0,
                data: &[0xb6, 0],
                le: Some(0),
            };
            let public = channel.exchange(&mut device, &generate);
            assert_eq!(public.status, 0x9000);
            assert_eq!(&public.data[..2], &[0x7f, 0x49]);
            let read = HostCommand {
                p1: 0x81,
                ..generate
            };
            assert_eq!(channel.exchange(&mut device, &read).data, public.data);
            let user = HostCommand::short(0x20, 0x81, b"123456", 0);
            assert_eq!(channel.exchange(&mut device, &user).status, 0x9000);
            let sign = HostCommand {
                cla: 0,
                ins: 0x2a,
                p1: 0x9e,
                p2: 0x9a,
                data: b"protected OpenPGP payload",
                le: Some(0),
            };
            let signature = channel.exchange(&mut device, &sign);
            assert_eq!(signature.status, 0x9000);
            assert_eq!(signature.data.len(), 256);
            let query = HostCommand::short(0x20, 0x83, &[], 0);
            assert_eq!(channel.exchange(&mut device, &query).status, 0x9000);
            let revoke = HostCommand { p1: 0xff, ..query };
            assert_eq!(channel.exchange(&mut device, &revoke).status, 0x9000);
            assert_eq!(channel.exchange(&mut device, &query).status, 0x63c3);
        }
    }

    #[test]
    fn scp03_secure_messaging_is_shared_by_every_selectable_applet() {
        let mut profile = DeviceProfile::yubikey_5_8_ccid(0x0102_0304);
        profile.applets.openpgp = true;
        let mut device = VirtualYubiKey::new(profile);
        let cases: &[SecureMessagingCase] = &[
            (
                &MANAGEMENT_AID,
                Applet::Management,
                HostCommand::short(0x1d, 0, &[], 0),
            ),
            (
                &HSMAUTH_AID,
                Applet::HsmAuth,
                HostCommand::short(0x07, 0, &[], 0),
            ),
            (
                &OPENPGP_AID,
                Applet::OpenPgp,
                HostCommand::short(0x84, 0, &[], 8),
            ),
            (&OATH_AID, Applet::Oath, HostCommand::short(0xa1, 0, &[], 0)),
            (&PIV_AID, Applet::Piv, HostCommand::short(0xfd, 0, &[], 0)),
            (
                &FIDO2_AID,
                Applet::Fido2,
                HostCommand::short(0x03, 0, &[], 0),
            ),
            (
                &FIDO2_AID,
                Applet::Fido2,
                HostCommand {
                    cla: 0x80,
                    ins: 0x10,
                    p1: 0x80,
                    p2: 0,
                    data: &[0x04],
                    le: Some(0),
                },
            ),
            (
                &ISSUER_SECURITY_DOMAIN_AID,
                Applet::IssuerSecurityDomain,
                HostCommand::short(0xca, 0xe0, &[], 0),
            ),
        ];
        for (aid, applet, command) in cases {
            assert_eq!(send(&mut device, &select(aid)).status, 0x9000);
            assert_eq!(device.selected_applet(), Some(*applet));
            let mut channel = establish_scp03(&mut device);
            let response = channel.exchange(&mut device, command);
            assert_eq!(response.status, 0x9000, "{applet:?}");
            if *applet == Applet::Oath {
                assert!(response.data.is_empty(), "factory OATH inventory is empty");
            } else {
                assert!(!response.data.is_empty(), "{applet:?}");
            }
        }
    }

    #[test]
    fn scp03_management_configuration_respects_lock_and_preserves_fido_state() {
        let mut device = VirtualYubiKey::new(DeviceProfile::yubikey_5_8_ccid(42));
        let management = device.management();
        let supported = management.usb_supported_capabilities();
        let code = [0x31; 16];
        let lock = [vec![18, 10, 16], code.to_vec()].concat();
        management.write_config(&lock).unwrap();
        let fido_before = device.fido_persistent_state().unwrap();
        assert_eq!(send(&mut device, &select(&MANAGEMENT_AID)).status, 0x9000);
        let mut channel = establish_scp03(&mut device);
        let mask = supported & !0x0002;
        let config = [4, 3, 2, (mask >> 8) as u8, mask as u8];
        assert_eq!(management.write_config(&config), Err(0x6982));
        assert_eq!(management.usb_enabled_capabilities().unwrap(), supported);
        let authorized = [
            vec![22, 3, 2, (mask >> 8) as u8, mask as u8, 11, 16],
            code.to_vec(),
        ]
        .concat();
        assert_eq!(
            channel
                .exchange(&mut device, &HostCommand::short(0x1c, 0, &authorized, 0))
                .status,
            0x9000
        );
        assert_eq!(management.usb_enabled_capabilities().unwrap(), mask);
        assert_eq!(device.fido_persistent_state().unwrap(), fido_before);
    }

    #[test]
    fn factory_scp11b_identity_persists_and_establishes_a_piv_channel() {
        let profile = DeviceProfile::yubikey_5_8_ccid(42);
        let device = VirtualYubiKey::new(profile.clone());
        let public = device.scp11b_public_key();
        let sd_state = device.security_domain_persistent_state().unwrap();
        let piv_state = device.piv_persistent_state().unwrap();
        let hsmauth_state = device.hsmauth_persistent_state().unwrap();
        let mut restored =
            VirtualYubiKey::from_persistent_states(profile, &piv_state, &hsmauth_state, &sd_state)
                .unwrap();
        assert_eq!(restored.scp11b_public_key(), public);
        assert_eq!(send(&mut restored, &select(&PIV_AID)).status, 0x9000);
        assert_eq!(
            send(
                &mut restored,
                &[
                    0, 0x20, 0, 0x80, 8, b'1', b'2', b'3', b'4', b'5', b'6', 0xff, 0xff
                ],
            )
            .status,
            0x9000
        );
        let mut channel = establish_scp11b(&mut restored);
        assert_eq!(restored.selected_applet(), Some(Applet::Piv));
        assert_eq!(send(&mut restored, &[0, 0x20, 0, 0x80, 0]).status, 0x63c3);
        assert_eq!(
            channel.exchange(&mut restored, &HostCommand::short(0xfd, 0, &[], 0),),
            ResponseApdu::success(vec![5, 8, 0])
        );
    }

    fn select(aid: &[u8]) -> Vec<u8> {
        let mut raw = vec![0, 0xa4, 0x04, 0, aid.len() as u8];
        raw.extend_from_slice(aid);
        raw.push(0);
        raw
    }

    fn send(device: &mut VirtualYubiKey, raw: &[u8]) -> ResponseApdu {
        let mut encoded = device.transmit(raw);
        let status = u16::from_be_bytes(encoded.split_off(encoded.len() - 2).try_into().unwrap());
        ResponseApdu {
            data: encoded,
            status,
        }
    }

    fn collect_response(device: &mut VirtualYubiKey, mut response: ResponseApdu) -> ResponseApdu {
        let mut data = Vec::new();
        while response.status & 0xff00 == 0x6100 {
            data.extend(response.data);
            let expected = response.status as u8;
            response = send(device, &[0, 0xc0, 0, 0, expected]);
        }
        data.extend(response.data);
        ResponseApdu {
            data,
            status: response.status,
        }
    }
}
