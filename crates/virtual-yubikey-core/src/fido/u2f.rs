//! CTAP1/U2F commands. Credentials live in authenticated wrapped handles, not a store.

use super::{Error, FidoState, sha256};
use crate::{CommandApdu, PresenceAuthorization, ResponseApdu, UserPresencePolicy};
use software_key_core::{
    software_signing::{EcCurve, KeyKind, SoftwareSigningKey},
    software_symmetric::{CcmOperation, ccm_with, encrypt_aes_cbc, encrypt_aes_ecb},
};
use zeroize::Zeroizing;

const HANDLE_PREFIX: [u8; 4] = *b"U2F\x01";
const HANDLE_LENGTH: usize = 64;
const NONCE_LENGTH: usize = 12;

fn ccm(
    master: &[u8],
    app: &[u8],
    nonce: &[u8],
    data: &[u8],
    encrypt: bool,
) -> Result<Vec<u8>, Error> {
    let mut aad = b"virtual-yubikey.u2f.v1".to_vec();
    aad.extend_from_slice(&HANDLE_PREFIX);
    aad.extend_from_slice(app);
    ccm_with(
        32,
        nonce,
        &aad,
        16,
        data,
        encrypt,
        |operation, blocks| match operation {
            CcmOperation::EncryptBlocks => encrypt_aes_ecb(master, blocks),
            CcmOperation::CbcMac => {
                let mac = Zeroizing::new(encrypt_aes_cbc(master, &[0; 16], blocks)?);
                Ok(mac[mac.len() - 16..].to_vec())
            }
        },
    )
    .map_err(|_| Error)
}

pub(super) fn unwrap(state: &FidoState, handle: &[u8], app: &[u8]) -> Option<SoftwareSigningKey> {
    if app.len() != 32 || handle.len() != HANDLE_LENGTH || handle[..4] != HANDLE_PREFIX {
        return None;
    }
    let master = state.u2f_wrapping_key.as_ref()?;
    let private = Zeroizing::new(ccm(master, app, &handle[4..16], &handle[16..], false).ok()?);
    SoftwareSigningKey::from_serialized_for_kind(KeyKind::Ec(EcCurve::P256), &private).ok()
}

fn wrap(state: &mut FidoState, key: &SoftwareSigningKey, app: &[u8]) -> Result<Vec<u8>, Error> {
    if state.u2f_wrapping_key.is_none() {
        let mut master = Zeroizing::new(vec![0; 32]);
        getrandom::fill(&mut master).map_err(|_| Error)?;
        state.u2f_wrapping_key = Some(master);
        state.persistent_change = true;
    }
    let mut nonce = [0; NONCE_LENGTH];
    getrandom::fill(&mut nonce).map_err(|_| Error)?;
    let private = key.serialized().map_err(|_| Error)?;
    let wrapped = ccm(
        state.u2f_wrapping_key.as_ref().ok_or(Error)?,
        app,
        &nonce,
        &private,
        true,
    )?;
    let mut handle = HANDLE_PREFIX.to_vec();
    handle.extend_from_slice(&nonce);
    handle.extend_from_slice(&wrapped);
    Ok(handle)
}

pub(super) fn sign(key: &SoftwareSigningKey, message: &[u8]) -> Result<Vec<u8>, Error> {
    key.sign_message(EcCurve::P256.signature_scheme(), message)
        .map_err(|_| Error)?
        .to_ecdsa_der(EcCurve::P256)
        .map_err(|_| Error)
}

pub(super) fn next_counter(state: &mut FidoState) -> Result<u32, Error> {
    // Fail closed at exhaustion instead of emitting a repeated or wrapped counter.
    state.u2f_counter = state.u2f_counter.checked_add(1).ok_or(Error)?;
    state.persistent_change = true;
    Ok(state.u2f_counter)
}

/// python-fido2 encodes an empty Lc followed by extended Le, even for VERSION.
/// Accept that legacy CTAP1 form only in FIDO paths; ordinary ISO parsing stays strict.
pub(crate) fn decode(raw: &[u8]) -> Result<CommandApdu<'_>, crate::ApduDecodeError> {
    if raw.len() == 9 && raw[4..7] == [0; 3] {
        let le = u16::from_be_bytes([raw[7], raw[8]]);
        return Ok(CommandApdu {
            cla: raw[0],
            ins: raw[1],
            p1: raw[2],
            p2: raw[3],
            data: &raw[7..7],
            le: Some(if le == 0 { 65_536 } else { u32::from(le) }),
            extended: true,
        });
    }
    CommandApdu::decode(raw)
}

pub(crate) fn exchange(
    state: &mut FidoState,
    command: &CommandApdu<'_>,
    presence: PresenceAuthorization,
) -> Result<ResponseApdu, UserPresencePolicy> {
    match exchange_inner(state, command, presence) {
        Ok(response) => response,
        Err(_) => Ok(ResponseApdu::status(0x6f00)),
    }
}

fn exchange_inner(
    state: &mut FidoState,
    command: &CommandApdu<'_>,
    presence: PresenceAuthorization,
) -> Result<Result<ResponseApdu, UserPresencePolicy>, Error> {
    let status = |sw| Ok(Ok(ResponseApdu::status(sw)));
    if command.cla != 0 {
        return status(0x6e00);
    }
    if !matches!(command.ins, 1..=3) {
        return status(0x6d00);
    }
    if command.p2 != 0
        || (command.ins != 2 && command.p1 != 0)
        || (command.ins == 2 && !matches!(command.p1, 0x03 | 0x07 | 0x08))
    {
        return status(0x6a86);
    }
    if command.ins == 3 {
        return if command.data.is_empty() {
            Ok(Ok(ResponseApdu::success(b"U2F_V2".to_vec())))
        } else {
            status(0x6700)
        };
    }
    if (command.ins == 1 && command.data.len() != 64)
        || (command.ins == 2
            && (command.data.len() < 65
                || command.data.len() != 65 + usize::from(command.data[64])))
    {
        return status(0x6700);
    }
    let challenge = &command.data[..32];
    let app = &command.data[32..64];
    if command.ins == 1 {
        if presence != PresenceAuthorization::Granted {
            return Ok(Err(UserPresencePolicy::Always));
        }
        let key =
            SoftwareSigningKey::generate(EcCurve::P256.signature_scheme()).map_err(|_| Error)?;
        let public = match key.public_key() {
            software_key_core::software_signing::SoftwarePublicKey::Ec { uncompressed, .. } => {
                uncompressed
            }
            _ => return Err(Error),
        };
        let handle = wrap(state, &key, app)?;
        if state.attestation.is_none() {
            state.attestation = Some(crate::fido_attestation::Identity::generate()?);
            state.persistent_change = true;
        }
        let identity = state.attestation.as_ref().ok_or(Error)?;
        let mut signed = vec![0];
        signed.extend_from_slice(app);
        signed.extend_from_slice(challenge);
        signed.extend_from_slice(&handle);
        signed.extend_from_slice(&public);
        let signature = identity.sign(&signed)?;
        let mut response = vec![5];
        response.extend_from_slice(&public);
        response.push(HANDLE_LENGTH as u8);
        response.extend_from_slice(&handle);
        response.extend_from_slice(identity.certificate());
        response.extend_from_slice(&signature);
        return Ok(Ok(ResponseApdu::success(response)));
    }
    let Some(key) = unwrap(state, &command.data[65..], app) else {
        return status(0x6a80);
    };
    if command.p1 == 7 {
        return status(0x6985);
    }
    if command.p1 == 3 && presence != PresenceAuthorization::Granted {
        return Ok(Err(UserPresencePolicy::Always));
    }
    let mut response = vec![u8::from(presence == PresenceAuthorization::Granted)];
    response.extend_from_slice(&next_counter(state)?.to_be_bytes());
    let mut message = app.to_vec();
    message.extend_from_slice(&response);
    message.extend_from_slice(challenge);
    response.extend_from_slice(&sign(&key, &message)?);
    Ok(Ok(ResponseApdu::success(response)))
}

/// Encode an unwrapped/reassembled card command for the shared runtime handler.
pub(crate) fn encode(command: &CommandApdu<'_>) -> Vec<u8> {
    let mut raw = vec![command.cla, command.ins, command.p1, command.p2, 0];
    if !command.data.is_empty() {
        raw.extend_from_slice(&(command.data.len() as u16).to_be_bytes());
        raw.extend_from_slice(command.data);
    }
    raw.extend_from_slice(&[0, 0]);
    raw
}

pub(super) fn assertion(
    state: &mut FidoState,
    handle: &[u8],
    rp_id: &str,
    challenge: &[u8],
    verified: bool,
) -> Result<Option<Vec<u8>>, Error> {
    let app = sha256(rp_id.as_bytes());
    let Some(key) = unwrap(state, handle, &app) else {
        return Ok(None);
    };
    let mut auth_data = app;
    auth_data.push(if verified { 5 } else { 1 });
    auth_data.extend_from_slice(&next_counter(state)?.to_be_bytes());
    let mut signed = auth_data.clone();
    signed.extend_from_slice(challenge);
    let signature = sign(&key, &signed)?;
    let mut result = vec![0];
    minicbor::Encoder::new(&mut result)
        .map(3)
        .map_err(|_| Error)?
        .u8(1)
        .map_err(|_| Error)?
        .map(2)
        .map_err(|_| Error)?
        .str("id")
        .map_err(|_| Error)?
        .bytes(handle)
        .map_err(|_| Error)?
        .str("type")
        .map_err(|_| Error)?
        .str("public-key")
        .map_err(|_| Error)?
        .u8(2)
        .map_err(|_| Error)?
        .bytes(&auth_data)
        .map_err(|_| Error)?
        .u8(3)
        .map_err(|_| Error)?
        .bytes(&signature)
        .map_err(|_| Error)?;
    state.reset_connection();
    Ok(Some(result))
}

#[cfg(test)]
mod tests;
