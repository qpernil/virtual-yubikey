//! CTAP 2.1 applet state and commands, including the previewSign extension.

use crate::crypto::{aes_cbc, Direction, AES_BLOCK_SIZE};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use minicbor::Encoder;
use p256::ecdsa::{DerSignature, SigningKey};
use p256::{ecdh::diffie_hellman, elliptic_curve::sec1::ToSec1Point, PublicKey, SecretKey};
use sha2::{Digest, Sha256};
use signature::Signer;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

const AUTHENTICATOR_MAKE_CREDENTIAL: u8 = 0x01;
const AUTHENTICATOR_GET_ASSERTION: u8 = 0x02;
const AUTHENTICATOR_GET_INFO: u8 = 0x04;
const AUTHENTICATOR_CLIENT_PIN: u8 = 0x06;
const AUTHENTICATOR_CREDENTIAL_MANAGEMENT: u8 = 0x0a;
const CTAP2_OK: u8 = 0;
const CTAP1_ERR_INVALID_COMMAND: u8 = 0x01;
const CTAP2_ERR_INVALID_CBOR: u8 = 0x12;
const CTAP2_ERR_MISSING_PARAMETER: u8 = 0x14;
const CTAP2_ERR_NO_CREDENTIALS: u8 = 0x2e;
const CTAP2_ERR_PIN_INVALID: u8 = 0x31;
const CTAP2_ERR_PIN_NOT_SET: u8 = 0x35;
const CTAP2_ERR_PIN_POLICY_VIOLATION: u8 = 0x37;
const CTAP2_ERR_OTHER: u8 = 0x7f;
const PIN_RETRIES: u8 = 8;

const CKR_ARGUMENTS_BAD: u64 = 1;
const CKR_DEVICE_ERROR: u64 = 2;

#[derive(Clone, Copy, Debug)]
struct Error;

impl From<u64> for Error {
    fn from(_: u64) -> Self {
        Self
    }
}

impl From<()> for Error {
    fn from(_: ()) -> Self {
        Self
    }
}

#[derive(Debug)]
pub(crate) struct FidoState {
    device_identifier: [u8; 16],
    pin: Option<Zeroizing<Vec<u8>>>,
    key_agreement: Option<SecretKey>,
    pin_uv_auth_token: Zeroizing<Vec<u8>>,
    pin_uv_auth_protocols: Vec<u8>,
    permissioned_pin_uv_auth_tokens: bool,
    resident_credential: ResidentCredential,
    preview_credential: Option<PreviewCredential>,
}

#[derive(Debug)]
struct ResidentCredential {
    rp_id: String,
    rp_name: String,
    user_id: Vec<u8>,
    user_name: String,
    user_display_name: String,
    credential_id: Vec<u8>,
    private_key: SecretKey,
    public_key_cose: Vec<u8>,
    counter: u32,
}

#[derive(Debug)]
struct PreviewCredential {
    rp_id: String,
    credential_id: Vec<u8>,
    signing_key_handle: Vec<u8>,
}

impl FidoState {
    pub(crate) fn new(device_identifier: [u8; 16]) -> Self {
        let private_key = SecretKey::from_slice(&[0x11; 32])
            .expect("fixed resident credential key must be valid");
        let public_key = private_key.public_key().to_sec1_point(false);
        let resident_credential = ResidentCredential {
            rp_id: "example.com".to_owned(),
            rp_name: "virtual-yubikey relying party".to_owned(),
            user_id: b"virtual-yubikey-user".to_vec(),
            user_name: "virtual-user".to_owned(),
            user_display_name: "Virtual YubiKey user".to_owned(),
            credential_id: vec![0x22; 32],
            private_key,
            public_key_cose: encode_ec2(public_key.as_bytes())
                .expect("fixed resident credential public key must encode"),
            counter: 0,
        };
        Self {
            device_identifier,
            pin: Some(Zeroizing::new(b"123456".to_vec())),
            key_agreement: None,
            pin_uv_auth_token: Zeroizing::new(vec![0x5a; 32]),
            pin_uv_auth_protocols: vec![2, 1],
            permissioned_pin_uv_auth_tokens: true,
            resident_credential,
            preview_credential: None,
        }
    }
}

pub(crate) fn exchange(state: &mut FidoState, request: &[u8]) -> Vec<u8> {
    exchange_inner(state, request).unwrap_or_else(|_| vec![CTAP2_ERR_OTHER])
}

fn exchange_inner(state: &mut FidoState, request: &[u8]) -> Result<Vec<u8>, Error> {
    let (&command, payload) = request.split_first().ok_or(CKR_ARGUMENTS_BAD)?;
    match command {
        AUTHENTICATOR_GET_INFO if payload.is_empty() => authenticator_get_info(state),
        AUTHENTICATOR_CLIENT_PIN => authenticator_client_pin(state, payload),
        AUTHENTICATOR_MAKE_CREDENTIAL => authenticator_make_credential(state, payload),
        AUTHENTICATOR_GET_ASSERTION => authenticator_get_assertion(state, payload),
        AUTHENTICATOR_CREDENTIAL_MANAGEMENT => authenticator_credential_management(state, payload),
        _ => Ok(vec![CTAP1_ERR_INVALID_COMMAND]),
    }
}

#[derive(Default)]
struct PreviewRequest {
    rp_id: Option<String>,
    client_data_hash: Option<Vec<u8>>,
    credential_id: Option<Vec<u8>>,
    signing_key_handle: Option<Vec<u8>>,
    to_be_signed: Option<Vec<u8>>,
    additional_args: Option<Vec<u8>>,
    pin_uv_auth: Option<Vec<u8>>,
    protocol: Option<u8>,
}

fn decode_text_id_map(decoder: &mut minicbor::Decoder<'_>) -> Result<String, u8> {
    let count = decoder
        .map()
        .map_err(|_| CTAP2_ERR_INVALID_CBOR)?
        .ok_or(CTAP2_ERR_INVALID_CBOR)?;
    let mut id = None;
    for _ in 0..count {
        match decoder.str().map_err(|_| CTAP2_ERR_INVALID_CBOR)? {
            "id" if id.is_none() => {
                id = Some(
                    decoder
                        .str()
                        .map_err(|_| CTAP2_ERR_INVALID_CBOR)?
                        .to_owned(),
                )
            }
            _ => decoder.skip().map_err(|_| CTAP2_ERR_INVALID_CBOR)?,
        }
    }
    id.ok_or(CTAP2_ERR_MISSING_PARAMETER)
}

fn decode_allow_list(decoder: &mut minicbor::Decoder<'_>) -> Result<Vec<u8>, u8> {
    if decoder
        .array()
        .map_err(|_| CTAP2_ERR_INVALID_CBOR)?
        .ok_or(CTAP2_ERR_INVALID_CBOR)?
        != 1
    {
        return Err(CTAP2_ERR_INVALID_CBOR);
    }
    let count = decoder
        .map()
        .map_err(|_| CTAP2_ERR_INVALID_CBOR)?
        .ok_or(CTAP2_ERR_INVALID_CBOR)?;
    let mut id = None;
    for _ in 0..count {
        match decoder.str().map_err(|_| CTAP2_ERR_INVALID_CBOR)? {
            "id" if id.is_none() => {
                id = Some(
                    decoder
                        .bytes()
                        .map_err(|_| CTAP2_ERR_INVALID_CBOR)?
                        .to_vec(),
                )
            }
            _ => decoder.skip().map_err(|_| CTAP2_ERR_INVALID_CBOR)?,
        }
    }
    id.ok_or(CTAP2_ERR_MISSING_PARAMETER)
}

fn decode_preview_extension(
    decoder: &mut minicbor::Decoder<'_>,
    request: &mut PreviewRequest,
) -> Result<(), u8> {
    let count = decoder
        .map()
        .map_err(|_| CTAP2_ERR_INVALID_CBOR)?
        .ok_or(CTAP2_ERR_INVALID_CBOR)?;
    for _ in 0..count {
        let name = decoder.str().map_err(|_| CTAP2_ERR_INVALID_CBOR)?;
        if name != "previewSign" {
            decoder.skip().map_err(|_| CTAP2_ERR_INVALID_CBOR)?;
            continue;
        }
        let count = decoder
            .map()
            .map_err(|_| CTAP2_ERR_INVALID_CBOR)?
            .ok_or(CTAP2_ERR_INVALID_CBOR)?;
        for _ in 0..count {
            match decoder.u8().map_err(|_| CTAP2_ERR_INVALID_CBOR)? {
                2 if request.signing_key_handle.is_none() => {
                    request.signing_key_handle = Some(
                        decoder
                            .bytes()
                            .map_err(|_| CTAP2_ERR_INVALID_CBOR)?
                            .to_vec(),
                    )
                }
                6 if request.to_be_signed.is_none() => {
                    request.to_be_signed = Some(
                        decoder
                            .bytes()
                            .map_err(|_| CTAP2_ERR_INVALID_CBOR)?
                            .to_vec(),
                    )
                }
                7 if request.additional_args.is_none() => {
                    request.additional_args = Some(
                        decoder
                            .bytes()
                            .map_err(|_| CTAP2_ERR_INVALID_CBOR)?
                            .to_vec(),
                    )
                }
                _ => decoder.skip().map_err(|_| CTAP2_ERR_INVALID_CBOR)?,
            }
        }
    }
    Ok(())
}

fn decode_preview_request(payload: &[u8], assertion: bool) -> Result<PreviewRequest, u8> {
    let mut decoder = minicbor::Decoder::new(payload);
    let count = decoder
        .map()
        .map_err(|_| CTAP2_ERR_INVALID_CBOR)?
        .ok_or(CTAP2_ERR_INVALID_CBOR)?;
    let mut request = PreviewRequest::default();
    for _ in 0..count {
        match decoder.u8().map_err(|_| CTAP2_ERR_INVALID_CBOR)? {
            1 if assertion && request.rp_id.is_none() => {
                request.rp_id = Some(
                    decoder
                        .str()
                        .map_err(|_| CTAP2_ERR_INVALID_CBOR)?
                        .to_owned(),
                )
            }
            1 if !assertion && request.client_data_hash.is_none() => {
                request.client_data_hash = Some(
                    decoder
                        .bytes()
                        .map_err(|_| CTAP2_ERR_INVALID_CBOR)?
                        .to_vec(),
                )
            }
            2 if assertion && request.client_data_hash.is_none() => {
                request.client_data_hash = Some(
                    decoder
                        .bytes()
                        .map_err(|_| CTAP2_ERR_INVALID_CBOR)?
                        .to_vec(),
                )
            }
            2 if !assertion && request.rp_id.is_none() => {
                request.rp_id = Some(decode_text_id_map(&mut decoder)?)
            }
            3 if assertion && request.credential_id.is_none() => {
                request.credential_id = Some(decode_allow_list(&mut decoder)?)
            }
            4 if assertion => decode_preview_extension(&mut decoder, &mut request)?,
            6 if !assertion => decode_preview_extension(&mut decoder, &mut request)?,
            6 if assertion && request.pin_uv_auth.is_none() => {
                request.pin_uv_auth = Some(
                    decoder
                        .bytes()
                        .map_err(|_| CTAP2_ERR_INVALID_CBOR)?
                        .to_vec(),
                )
            }
            7 if assertion && request.protocol.is_none() => {
                request.protocol = Some(decoder.u8().map_err(|_| CTAP2_ERR_INVALID_CBOR)?)
            }
            8 if !assertion && request.pin_uv_auth.is_none() => {
                request.pin_uv_auth = Some(
                    decoder
                        .bytes()
                        .map_err(|_| CTAP2_ERR_INVALID_CBOR)?
                        .to_vec(),
                )
            }
            9 if !assertion && request.protocol.is_none() => {
                request.protocol = Some(decoder.u8().map_err(|_| CTAP2_ERR_INVALID_CBOR)?)
            }
            _ => decoder.skip().map_err(|_| CTAP2_ERR_INVALID_CBOR)?,
        }
    }
    if decoder.position() != payload.len() {
        return Err(CTAP2_ERR_INVALID_CBOR);
    }
    Ok(request)
}

struct CredentialManagementRequest {
    subcommand: u8,
    parameters: Option<Vec<u8>>,
    protocol: Option<u8>,
    auth: Option<Vec<u8>>,
}

fn decode_credential_management_request(payload: &[u8]) -> Result<CredentialManagementRequest, u8> {
    let mut decoder = minicbor::Decoder::new(payload);
    let count = decoder
        .map()
        .map_err(|_| CTAP2_ERR_INVALID_CBOR)?
        .ok_or(CTAP2_ERR_INVALID_CBOR)?;
    let mut subcommand = None;
    let mut parameters = None;
    let mut protocol = None;
    let mut auth = None;
    for _ in 0..count {
        match decoder.u8().map_err(|_| CTAP2_ERR_INVALID_CBOR)? {
            1 if subcommand.is_none() => {
                subcommand = Some(decoder.u8().map_err(|_| CTAP2_ERR_INVALID_CBOR)?)
            }
            2 if parameters.is_none() => {
                let start = decoder.position();
                decoder.skip().map_err(|_| CTAP2_ERR_INVALID_CBOR)?;
                parameters = Some(payload[start..decoder.position()].to_vec());
            }
            3 if protocol.is_none() => {
                protocol = Some(decoder.u8().map_err(|_| CTAP2_ERR_INVALID_CBOR)?)
            }
            4 if auth.is_none() => {
                auth = Some(
                    decoder
                        .bytes()
                        .map_err(|_| CTAP2_ERR_INVALID_CBOR)?
                        .to_vec(),
                )
            }
            _ => decoder.skip().map_err(|_| CTAP2_ERR_INVALID_CBOR)?,
        }
    }
    if decoder.position() != payload.len() {
        return Err(CTAP2_ERR_INVALID_CBOR);
    }
    Ok(CredentialManagementRequest {
        subcommand: subcommand.ok_or(CTAP2_ERR_MISSING_PARAMETER)?,
        parameters,
        protocol,
        auth,
    })
}

fn decode_management_rp_id_hash(parameters: &[u8]) -> Result<[u8; 32], u8> {
    let mut decoder = minicbor::Decoder::new(parameters);
    if decoder
        .map()
        .map_err(|_| CTAP2_ERR_INVALID_CBOR)?
        .ok_or(CTAP2_ERR_INVALID_CBOR)?
        != 1
        || decoder.u8().map_err(|_| CTAP2_ERR_INVALID_CBOR)? != 1
    {
        return Err(CTAP2_ERR_INVALID_CBOR);
    }
    let value = decoder
        .bytes()
        .map_err(|_| CTAP2_ERR_INVALID_CBOR)?
        .try_into()
        .map_err(|_| CTAP2_ERR_INVALID_CBOR)?;
    if decoder.position() != parameters.len() {
        return Err(CTAP2_ERR_INVALID_CBOR);
    }
    Ok(value)
}

fn credential_management_rp_response(credential: &ResidentCredential) -> Result<Vec<u8>, Error> {
    let mut response = vec![CTAP2_OK];
    Encoder::new(&mut response)
        .map(3)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .u8(3)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .map(2)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .str("id")
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .str(&credential.rp_id)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .str("name")
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .str(&credential.rp_name)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .u8(4)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .bytes(&Sha256::digest(credential.rp_id.as_bytes()))
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .u8(5)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .u8(1)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?;
    Ok(response)
}

fn credential_management_metadata_response() -> Result<Vec<u8>, Error> {
    let mut response = vec![CTAP2_OK];
    Encoder::new(&mut response)
        .map(2)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .u8(1)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .u8(1)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .u8(2)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .u8(24)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?;
    Ok(response)
}

fn credential_management_credential_response(
    credential: &ResidentCredential,
) -> Result<Vec<u8>, Error> {
    let mut response = vec![CTAP2_OK];
    let mut encoder = Encoder::new(&mut response);
    encoder
        .map(6)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .u8(6)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .map(3)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .str("id")
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .bytes(&credential.user_id)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .str("name")
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .str(&credential.user_name)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .str("displayName")
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .str(&credential.user_display_name)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .u8(7)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .map(2)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .str("id")
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .bytes(&credential.credential_id)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .str("type")
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .str("public-key")
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .u8(8)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?;
    encoder
        .writer_mut()
        .extend_from_slice(&credential.public_key_cose);
    encoder
        .u8(9)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .u8(1)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .u8(10)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .u8(3)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .u8(12)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .bool(false)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?;
    Ok(response)
}

fn authenticator_credential_management(
    state: &FidoState,
    payload: &[u8],
) -> Result<Vec<u8>, Error> {
    let request = match decode_credential_management_request(payload) {
        Ok(request) => request,
        Err(status) => return Ok(vec![status]),
    };
    match request.subcommand {
        1 | 2 | 4 | 6 | 7 => {
            let Some(protocol) = request.protocol else {
                return Ok(vec![CTAP2_ERR_MISSING_PARAMETER]);
            };
            if !state.pin_uv_auth_protocols.contains(&protocol) {
                return Ok(vec![CTAP2_ERR_MISSING_PARAMETER]);
            }
            let mut authenticated = vec![request.subcommand];
            if let Some(parameters) = request.parameters.as_deref() {
                authenticated.extend_from_slice(parameters);
            }
            if !authenticate(
                protocol,
                state.pin_uv_auth_token.as_ref(),
                &authenticated,
                request.auth.as_deref(),
            ) {
                return Ok(vec![CTAP2_ERR_PIN_INVALID]);
            }
        }
        _ => {}
    }
    match request.subcommand {
        1 => credential_management_metadata_response(),
        2 => credential_management_rp_response(&state.resident_credential),
        3 | 5 => Ok(vec![CTAP2_ERR_NO_CREDENTIALS]),
        4 => {
            let Some(parameters) = request.parameters.as_deref() else {
                return Ok(vec![CTAP2_ERR_MISSING_PARAMETER]);
            };
            let rp_id_hash = match decode_management_rp_id_hash(parameters) {
                Ok(value) => value,
                Err(status) => return Ok(vec![status]),
            };
            if rp_id_hash != Sha256::digest(state.resident_credential.rp_id.as_bytes()).as_slice() {
                return Ok(vec![CTAP2_ERR_NO_CREDENTIALS]);
            }
            credential_management_credential_response(&state.resident_credential)
        }
        _ => Ok(vec![CTAP1_ERR_INVALID_COMMAND]),
    }
}

fn encode_ec2(public: &[u8]) -> Result<Vec<u8>, Error> {
    if public.len() != 65 || public[0] != 4 {
        return Err(CKR_DEVICE_ERROR.into());
    }
    let mut encoded = Vec::new();
    Encoder::new(&mut encoded)
        .map(5)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .u8(1)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .u8(2)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .u8(3)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .i8(-7)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .i8(-1)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .u8(1)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .i8(-2)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .bytes(&public[1..33])
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .i8(-3)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .bytes(&public[33..])
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?;
    Ok(encoded)
}

fn authenticator_data(
    rp_id: &str,
    credential_id: &[u8],
    public_key_cose: &[u8],
    extension_output: &[u8],
    counter: u32,
) -> Result<Vec<u8>, Error> {
    let mut data = Sha256::digest(rp_id.as_bytes()).to_vec();
    data.push(0xc5);
    data.extend_from_slice(&counter.to_be_bytes());
    data.extend_from_slice(&[0x50; 16]);
    data.extend_from_slice(
        &u16::try_from(credential_id.len())
            .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
            .to_be_bytes(),
    );
    data.extend_from_slice(credential_id);
    data.extend_from_slice(public_key_cose);
    let mut extensions = Vec::new();
    let mut encoder = Encoder::new(&mut extensions);
    encoder
        .map(1)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .str("previewSign")
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?;
    encoder.writer_mut().extend_from_slice(extension_output);
    data.extend_from_slice(&extensions);
    Ok(data)
}

fn authenticator_make_credential(state: &mut FidoState, payload: &[u8]) -> Result<Vec<u8>, Error> {
    let request = match decode_preview_request(payload, false) {
        Ok(request) => request,
        Err(status) => return Ok(vec![status]),
    };
    let client_data_hash = request
        .client_data_hash
        .as_deref()
        .ok_or(CKR_DEVICE_ERROR)?;
    let Some(protocol) = request.protocol else {
        return Ok(vec![CTAP2_ERR_MISSING_PARAMETER]);
    };
    if !state.pin_uv_auth_protocols.contains(&protocol) {
        return Ok(vec![CTAP2_ERR_MISSING_PARAMETER]);
    }
    if !authenticate(
        protocol,
        state.pin_uv_auth_token.as_ref(),
        client_data_hash,
        request.pin_uv_auth.as_deref(),
    ) {
        return Ok(vec![CTAP2_ERR_PIN_INVALID]);
    }
    let rp_id = request.rp_id.ok_or(CKR_DEVICE_ERROR)?;
    let credential_id = vec![0xa5; 32];
    let signing_key_handle = vec![0x5a; 48];
    let parent_secret = random_secret()?;
    let parent_public = parent_secret.public_key().to_sec1_point(false);
    let parent_cose = encode_ec2(parent_public.as_bytes())?;
    let mut algorithm_output = Vec::new();
    Encoder::new(&mut algorithm_output)
        .map(1)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .u8(3)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .i64(-65_539)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?;
    let outer_auth_data =
        authenticator_data(&rp_id, &credential_id, &parent_cose, &algorithm_output, 0)?;

    let seed = crate::preview_sign::seed_cose().map_err(|_| Error::from(CKR_DEVICE_ERROR))?;
    let mut policy_output = Vec::new();
    Encoder::new(&mut policy_output)
        .map(1)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .u8(4)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .u8(1)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?;
    let inner_auth_data =
        authenticator_data(&rp_id, &signing_key_handle, &seed, &policy_output, 0)?;
    let mut attestation = Vec::new();
    Encoder::new(&mut attestation)
        .map(3)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .u8(1)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .str("none")
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .u8(2)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .bytes(&inner_auth_data)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .u8(3)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .map(0)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?;
    let mut response = vec![CTAP2_OK];
    Encoder::new(&mut response)
        .map(4)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .u8(1)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .str("none")
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .u8(2)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .bytes(&outer_auth_data)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .u8(3)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .map(0)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .u8(6)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .map(1)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .str("previewSign")
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .map(1)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .u8(7)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .bytes(&attestation)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?;
    state.preview_credential = Some(PreviewCredential {
        rp_id,
        credential_id,
        signing_key_handle,
    });
    Ok(response)
}

fn authenticator_get_assertion(state: &mut FidoState, payload: &[u8]) -> Result<Vec<u8>, Error> {
    let request = match decode_preview_request(payload, true) {
        Ok(request) => request,
        Err(status) => return Ok(vec![status]),
    };
    let client_data_hash = request
        .client_data_hash
        .as_deref()
        .ok_or(CKR_DEVICE_ERROR)?;
    let Some(protocol) = request.protocol else {
        return Ok(vec![CTAP2_ERR_MISSING_PARAMETER]);
    };
    if !state.pin_uv_auth_protocols.contains(&protocol) {
        return Ok(vec![CTAP2_ERR_MISSING_PARAMETER]);
    }
    if !authenticate(
        protocol,
        state.pin_uv_auth_token.as_ref(),
        client_data_hash,
        request.pin_uv_auth.as_deref(),
    ) {
        return Ok(vec![CTAP2_ERR_PIN_INVALID]);
    }
    if request.signing_key_handle.is_none() {
        let credential = &mut state.resident_credential;
        if request.rp_id.as_deref() != Some(credential.rp_id.as_str())
            || request.credential_id.as_deref() != Some(credential.credential_id.as_slice())
        {
            return Ok(vec![CTAP2_ERR_NO_CREDENTIALS]);
        }
        credential.counter = credential.counter.saturating_add(1);
        let mut auth_data = Sha256::digest(credential.rp_id.as_bytes()).to_vec();
        auth_data.push(0x05);
        auth_data.extend_from_slice(&credential.counter.to_be_bytes());
        let mut signed = Vec::with_capacity(auth_data.len() + client_data_hash.len());
        signed.extend_from_slice(&auth_data);
        signed.extend_from_slice(client_data_hash);
        let signing_key = SigningKey::from(credential.private_key.clone());
        let signature: DerSignature = signing_key.sign(&signed);
        let mut response = vec![CTAP2_OK];
        Encoder::new(&mut response)
            .map(3)
            .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
            .u8(1)
            .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
            .map(2)
            .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
            .str("id")
            .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
            .bytes(&credential.credential_id)
            .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
            .str("type")
            .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
            .str("public-key")
            .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
            .u8(2)
            .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
            .bytes(&auth_data)
            .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
            .u8(3)
            .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
            .bytes(signature.as_bytes())
            .map_err(|_| Error::from(CKR_DEVICE_ERROR))?;
        return Ok(response);
    }
    let credential = state.preview_credential.as_ref().ok_or(CKR_DEVICE_ERROR)?;
    if request.rp_id.as_deref() != Some(credential.rp_id.as_str())
        || request.credential_id.as_deref() != Some(credential.credential_id.as_slice())
        || request.signing_key_handle.as_deref() != Some(credential.signing_key_handle.as_slice())
    {
        return Ok(vec![CTAP2_ERR_NO_CREDENTIALS]);
    }
    let signature = crate::preview_sign::sign(
        request.additional_args.as_deref().ok_or(CKR_DEVICE_ERROR)?,
        request.to_be_signed.as_deref().ok_or(CKR_DEVICE_ERROR)?,
    )
    .map_err(|_| Error::from(CKR_DEVICE_ERROR))?;
    let mut extensions = Vec::new();
    Encoder::new(&mut extensions)
        .map(1)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .str("previewSign")
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .map(1)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .u8(6)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .bytes(&signature)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?;
    let mut auth_data = Sha256::digest(credential.rp_id.as_bytes()).to_vec();
    auth_data.push(0x85);
    auth_data.extend_from_slice(&1_u32.to_be_bytes());
    auth_data.extend_from_slice(&extensions);
    let mut response = vec![CTAP2_OK];
    Encoder::new(&mut response)
        .map(3)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .u8(1)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .map(2)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .str("id")
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .bytes(&credential.credential_id)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .str("type")
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .str("public-key")
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .u8(2)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .bytes(&auth_data)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .u8(3)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .bytes(&[0; 64])
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?;
    Ok(response)
}

fn authenticator_get_info(state: &FidoState) -> Result<Vec<u8>, Error> {
    let encrypted_identifier = encrypted_device_identifier(state)?;
    let mut response = vec![CTAP2_OK];
    let mut encoder = Encoder::new(&mut response);
    encoder
        .map(9)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .u8(1)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .array(2)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .str("FIDO_2_0")
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .str("FIDO_2_1")
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .u8(2)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .array(1)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .str("previewSign")
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .u8(3)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .bytes(&[0x50; 16])
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .u8(4)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .map(6)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .str("rk")
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .bool(true)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .str("plat")
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .bool(false)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .str("credMgmt")
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .bool(true)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .str("clientPin")
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .bool(state.pin.is_some())
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .str("perCredMgmtRO")
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .bool(true)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .str("pinUvAuthToken")
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .bool(state.permissioned_pin_uv_auth_tokens)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .u8(5)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .u16(1200)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .u8(6)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .array(
            u64::try_from(state.pin_uv_auth_protocols.len())
                .map_err(|_| Error::from(CKR_DEVICE_ERROR))?,
        )
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?;
    for protocol in &state.pin_uv_auth_protocols {
        encoder
            .u8(*protocol)
            .map_err(|_| Error::from(CKR_DEVICE_ERROR))?;
    }
    encoder
        .u8(9)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .array(1)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .str("usb")
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .u8(13)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .u8(4)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .u8(25)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .bytes(&encrypted_identifier)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?;
    Ok(response)
}

fn encrypted_device_identifier(state: &FidoState) -> Result<Vec<u8>, Error> {
    let hkdf = Hkdf::<Sha256>::new(Some(&[0u8; 32]), state.pin_uv_auth_token.as_ref());
    let mut key = Zeroizing::new([0u8; 16]);
    hkdf.expand(b"encIdentifier", key.as_mut())
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?;
    let mut iv = [0u8; AES_BLOCK_SIZE];
    getrandom::fill(&mut iv).map_err(|_| Error::from(CKR_DEVICE_ERROR))?;
    let ciphertext = aes_cbc(
        key.as_ref(),
        &iv,
        &state.device_identifier,
        Direction::Encrypt,
    )?;
    let mut encrypted = iv.to_vec();
    encrypted.extend_from_slice(&ciphertext);
    Ok(encrypted)
}

#[derive(Default)]
struct ClientPinRequest {
    protocol: Option<u8>,
    subcommand: Option<u8>,
    peer: Option<PublicKey>,
    auth: Option<Vec<u8>>,
    new_pin: Option<Vec<u8>>,
    pin_hash: Option<Vec<u8>>,
}

fn authenticator_client_pin(state: &mut FidoState, payload: &[u8]) -> Result<Vec<u8>, Error> {
    let request = match decode_client_pin(payload) {
        Ok(request) => request,
        Err(status) => return Ok(vec![status]),
    };
    let Some(protocol) = request.protocol else {
        return Ok(vec![CTAP2_ERR_MISSING_PARAMETER]);
    };
    if !state.pin_uv_auth_protocols.contains(&protocol) {
        return Ok(vec![CTAP2_ERR_MISSING_PARAMETER]);
    }
    match request.subcommand {
        Some(1) => pin_retries_response(),
        Some(2) => key_agreement_response(state),
        Some(3) => set_pin(state, request),
        Some(4) => change_pin(state, request),
        Some(5 | 9) => pin_token(state, request),
        _ => Ok(vec![CTAP1_ERR_INVALID_COMMAND]),
    }
}

fn pin_retries_response() -> Result<Vec<u8>, Error> {
    let mut response = vec![CTAP2_OK];
    Encoder::new(&mut response)
        .map(2)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .u8(3)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .u8(PIN_RETRIES)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .u8(4)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .bool(false)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?;
    Ok(response)
}

fn decode_client_pin(payload: &[u8]) -> Result<ClientPinRequest, u8> {
    let mut decoder = minicbor::Decoder::new(payload);
    let count = decoder
        .map()
        .map_err(|_| CTAP2_ERR_INVALID_CBOR)?
        .ok_or(CTAP2_ERR_INVALID_CBOR)?;
    let mut request = ClientPinRequest::default();
    for _ in 0..count {
        match decoder.u8().map_err(|_| CTAP2_ERR_INVALID_CBOR)? {
            1 if request.protocol.is_none() => {
                request.protocol = Some(decoder.u8().map_err(|_| CTAP2_ERR_INVALID_CBOR)?)
            }
            2 if request.subcommand.is_none() => {
                request.subcommand = Some(decoder.u8().map_err(|_| CTAP2_ERR_INVALID_CBOR)?)
            }
            3 if request.peer.is_none() => request.peer = Some(decode_cose_key(&mut decoder)?),
            4 if request.auth.is_none() => {
                request.auth = Some(
                    decoder
                        .bytes()
                        .map_err(|_| CTAP2_ERR_INVALID_CBOR)?
                        .to_vec(),
                )
            }
            5 if request.new_pin.is_none() => {
                request.new_pin = Some(
                    decoder
                        .bytes()
                        .map_err(|_| CTAP2_ERR_INVALID_CBOR)?
                        .to_vec(),
                )
            }
            6 if request.pin_hash.is_none() => {
                request.pin_hash = Some(
                    decoder
                        .bytes()
                        .map_err(|_| CTAP2_ERR_INVALID_CBOR)?
                        .to_vec(),
                )
            }
            _ => decoder.skip().map_err(|_| CTAP2_ERR_INVALID_CBOR)?,
        }
    }
    if decoder.position() != payload.len() {
        return Err(CTAP2_ERR_INVALID_CBOR);
    }
    Ok(request)
}

fn decode_cose_key(decoder: &mut minicbor::Decoder<'_>) -> Result<PublicKey, u8> {
    let count = decoder
        .map()
        .map_err(|_| CTAP2_ERR_INVALID_CBOR)?
        .ok_or(CTAP2_ERR_INVALID_CBOR)?;
    let mut x = None;
    let mut y = None;
    for _ in 0..count {
        match decoder.i64().map_err(|_| CTAP2_ERR_INVALID_CBOR)? {
            -2 if x.is_none() => {
                x = Some(
                    decoder
                        .bytes()
                        .map_err(|_| CTAP2_ERR_INVALID_CBOR)?
                        .to_vec(),
                )
            }
            -3 if y.is_none() => {
                y = Some(
                    decoder
                        .bytes()
                        .map_err(|_| CTAP2_ERR_INVALID_CBOR)?
                        .to_vec(),
                )
            }
            _ => decoder.skip().map_err(|_| CTAP2_ERR_INVALID_CBOR)?,
        }
    }
    let (x, y) = (
        x.ok_or(CTAP2_ERR_MISSING_PARAMETER)?,
        y.ok_or(CTAP2_ERR_MISSING_PARAMETER)?,
    );
    if x.len() != 32 || y.len() != 32 {
        return Err(CTAP2_ERR_INVALID_CBOR);
    }
    let mut point = Vec::with_capacity(65);
    point.push(4);
    point.extend_from_slice(&x);
    point.extend_from_slice(&y);
    PublicKey::from_sec1_bytes(&point).map_err(|_| CTAP2_ERR_INVALID_CBOR)
}

fn key_agreement_response(state: &mut FidoState) -> Result<Vec<u8>, Error> {
    let secret = random_secret()?;
    let public = secret.public_key().to_sec1_point(false);
    let public = public.as_bytes();
    let mut response = vec![CTAP2_OK];
    let mut encoder = Encoder::new(&mut response);
    encoder
        .map(1)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .u8(1)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?;
    encode_cose_key(&mut encoder, &public[1..33], &public[33..])?;
    state.key_agreement = Some(secret);
    Ok(response)
}

fn set_pin(state: &mut FidoState, request: ClientPinRequest) -> Result<Vec<u8>, Error> {
    if state.pin.is_some() {
        return Ok(vec![CTAP2_ERR_PIN_POLICY_VIOLATION]);
    }
    let protocol = request.protocol.ok_or(CKR_DEVICE_ERROR)?;
    let shared = match shared_secret(state, request.peer.as_ref(), protocol) {
        Ok(shared) => shared,
        Err(status) => return Ok(vec![status]),
    };
    let encrypted = match request.new_pin {
        Some(value) => value,
        None => return Ok(vec![CTAP2_ERR_MISSING_PARAMETER]),
    };
    if !authenticate(protocol, &shared[..32], &encrypted, request.auth.as_deref()) {
        return Ok(vec![CTAP2_ERR_PIN_INVALID]);
    }
    let plaintext = match decrypt(protocol, &shared, &encrypted) {
        Ok(value) => value,
        Err(status) => return Ok(vec![status]),
    };
    let Some(pin) = padded_pin(&plaintext) else {
        return Ok(vec![CTAP2_ERR_PIN_POLICY_VIOLATION]);
    };
    state.pin = Some(Zeroizing::new(pin));
    state.key_agreement = None;
    Ok(vec![CTAP2_OK])
}

fn change_pin(state: &mut FidoState, request: ClientPinRequest) -> Result<Vec<u8>, Error> {
    let Some(current) = state.pin.as_ref() else {
        return Ok(vec![CTAP2_ERR_PIN_NOT_SET]);
    };
    let protocol = request.protocol.ok_or(CKR_DEVICE_ERROR)?;
    let shared = match shared_secret(state, request.peer.as_ref(), protocol) {
        Ok(shared) => shared,
        Err(status) => return Ok(vec![status]),
    };
    let (new_pin, old_hash) = match (request.new_pin, request.pin_hash) {
        (Some(new_pin), Some(old_hash)) => (new_pin, old_hash),
        _ => return Ok(vec![CTAP2_ERR_MISSING_PARAMETER]),
    };
    let mut authenticated = new_pin.clone();
    authenticated.extend_from_slice(&old_hash);
    if !authenticate(
        protocol,
        &shared[..32],
        &authenticated,
        request.auth.as_deref(),
    ) || !pin_hash_matches(protocol, &shared, &old_hash, current)
    {
        return Ok(vec![CTAP2_ERR_PIN_INVALID]);
    }
    let plaintext = match decrypt(protocol, &shared, &new_pin) {
        Ok(value) => value,
        Err(status) => return Ok(vec![status]),
    };
    let Some(pin) = padded_pin(&plaintext) else {
        return Ok(vec![CTAP2_ERR_PIN_POLICY_VIOLATION]);
    };
    state.pin = Some(Zeroizing::new(pin));
    state.key_agreement = None;
    Ok(vec![CTAP2_OK])
}

fn pin_token(state: &mut FidoState, request: ClientPinRequest) -> Result<Vec<u8>, Error> {
    let Some(pin) = state.pin.as_ref() else {
        return Ok(vec![CTAP2_ERR_PIN_NOT_SET]);
    };
    let protocol = request.protocol.ok_or(CKR_DEVICE_ERROR)?;
    let shared = match shared_secret(state, request.peer.as_ref(), protocol) {
        Ok(shared) => shared,
        Err(status) => return Ok(vec![status]),
    };
    let Some(hash) = request.pin_hash else {
        return Ok(vec![CTAP2_ERR_MISSING_PARAMETER]);
    };
    if !pin_hash_matches(protocol, &shared, &hash, pin) {
        return Ok(vec![CTAP2_ERR_PIN_INVALID]);
    }
    let encrypted = encrypt(protocol, &shared, state.pin_uv_auth_token.as_ref())?;
    let mut response = vec![CTAP2_OK];
    Encoder::new(&mut response)
        .map(1)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .u8(2)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .bytes(&encrypted)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?;
    state.key_agreement = None;
    Ok(response)
}

fn random_secret() -> Result<SecretKey, Error> {
    loop {
        let mut bytes = Zeroizing::new([0u8; 32]);
        getrandom::fill(bytes.as_mut()).map_err(|_| Error::from(CKR_DEVICE_ERROR))?;
        if let Ok(secret) = SecretKey::from_slice(bytes.as_ref()) {
            return Ok(secret);
        }
    }
}

fn shared_secret(
    state: &FidoState,
    peer: Option<&PublicKey>,
    protocol: u8,
) -> Result<Zeroizing<Vec<u8>>, u8> {
    let secret = state
        .key_agreement
        .as_ref()
        .ok_or(CTAP2_ERR_MISSING_PARAMETER)?;
    let peer = peer.ok_or(CTAP2_ERR_MISSING_PARAMETER)?;
    let z = diffie_hellman(secret.to_nonzero_scalar(), peer.as_affine());
    match protocol {
        1 => Ok(Zeroizing::new(
            Sha256::digest(z.raw_secret_bytes()).to_vec(),
        )),
        2 => {
            let hkdf = Hkdf::<Sha256>::new(Some(&[0u8; 32]), z.raw_secret_bytes().as_ref());
            let mut output = Zeroizing::new(vec![0u8; 64]);
            hkdf.expand(b"CTAP2 HMAC key", &mut output[..32])
                .map_err(|_| CTAP2_ERR_PIN_INVALID)?;
            hkdf.expand(b"CTAP2 AES key", &mut output[32..])
                .map_err(|_| CTAP2_ERR_PIN_INVALID)?;
            Ok(output)
        }
        _ => Err(CTAP2_ERR_MISSING_PARAMETER),
    }
}

fn encode_cose_key(encoder: &mut Encoder<&mut Vec<u8>>, x: &[u8], y: &[u8]) -> Result<(), Error> {
    encoder
        .map(5)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .u8(1)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .u8(2)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .u8(3)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .i8(-25)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .i8(-1)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .u8(1)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .i8(-2)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .bytes(x)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .i8(-3)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .bytes(y)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?;
    Ok(())
}

fn decrypt(protocol: u8, key: &[u8], ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>, u8> {
    let result = match protocol {
        1 if key.len() == 32
            && !ciphertext.is_empty()
            && ciphertext.len().is_multiple_of(AES_BLOCK_SIZE) =>
        {
            aes_cbc(key, &[0u8; AES_BLOCK_SIZE], ciphertext, Direction::Decrypt)
        }
        2 if key.len() == 64
            && ciphertext.len() >= AES_BLOCK_SIZE * 2
            && ciphertext.len().is_multiple_of(AES_BLOCK_SIZE) =>
        {
            aes_cbc(
                &key[32..],
                &ciphertext[..AES_BLOCK_SIZE],
                &ciphertext[AES_BLOCK_SIZE..],
                Direction::Decrypt,
            )
        }
        _ => return Err(CTAP2_ERR_INVALID_CBOR),
    };
    result
        .map(Zeroizing::new)
        .map_err(|_| CTAP2_ERR_PIN_INVALID)
}

fn encrypt(protocol: u8, key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, Error> {
    if !plaintext.len().is_multiple_of(AES_BLOCK_SIZE) {
        return Err(CKR_DEVICE_ERROR.into());
    }
    match protocol {
        1 if key.len() == 32 => Ok(aes_cbc(
            key,
            &[0u8; AES_BLOCK_SIZE],
            plaintext,
            Direction::Encrypt,
        )?),
        2 if key.len() == 64 => {
            let mut iv = [0u8; AES_BLOCK_SIZE];
            getrandom::fill(&mut iv).map_err(|_| Error::from(CKR_DEVICE_ERROR))?;
            let ciphertext = aes_cbc(&key[32..], &iv, plaintext, Direction::Encrypt)?;
            let mut output = iv.to_vec();
            output.extend_from_slice(&ciphertext);
            Ok(output)
        }
        _ => Err(CKR_DEVICE_ERROR.into()),
    }
}

fn authenticate(protocol: u8, key: &[u8], message: &[u8], supplied: Option<&[u8]>) -> bool {
    let Some(supplied) = supplied else {
        return false;
    };
    let Ok(mut mac) = <Hmac<Sha256> as hmac::digest::KeyInit>::new_from_slice(key) else {
        return false;
    };
    mac.update(message);
    let output = mac.finalize().into_bytes();
    let expected = match protocol {
        1 => &output[..16],
        2 => output.as_slice(),
        _ => return false,
    };
    bool::from(expected.ct_eq(supplied))
}

fn padded_pin(plaintext: &[u8]) -> Option<Vec<u8>> {
    let end = plaintext
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(plaintext.len());
    let pin = plaintext.get(..end)?;
    let text = std::str::from_utf8(pin).ok()?;
    if pin.len() > 63 || !(4..=63).contains(&text.chars().count()) {
        return None;
    }
    Some(pin.to_vec())
}

fn pin_hash_matches(protocol: u8, shared: &[u8], encrypted: &[u8], pin: &[u8]) -> bool {
    let Ok(mut supplied) = decrypt(protocol, shared, encrypted) else {
        return false;
    };
    let expected = Sha256::digest(pin);
    let matches = supplied.len() == 16 && bool::from(supplied.as_slice().ct_eq(&expected[..16]));
    supplied.zeroize();
    matches
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::{Signature, VerifyingKey};
    use signature::hazmat::PrehashVerifier;

    const CONTEXT: &[u8] = b"ARKG-P256.test vectors";
    const EXPECTED_PUBLIC_KEY: &str = "04572a111ce5cfd2a67d56a0f7c684184b16ccd212490dc9c5b579df749647d107dac2a1b197cc10d2376559ad6df6bc107318d5cfb90def9f4a1f5347e086c2cd";
    const EXPECTED_TICKET: &str = "27987995f184a44cfa548d104b0a461d0487fc739dbcdabc293ac5469221da91b220e04c681074ec4692a76ffacb9043dec2847ea9060fd42da267f66852e63589f0c00dc88f290d660c65a65a50c86361";

    #[test]
    fn ppuat_decrypts_a_stable_device_identifier() {
        let identifier = *b"virtual-test-id!";
        let state = FidoState::new(identifier);
        let encrypted = encrypted_device_identifier(&state).unwrap();
        assert_eq!(encrypted.len(), AES_BLOCK_SIZE * 2);

        let hkdf = Hkdf::<Sha256>::new(Some(&[0u8; 32]), state.pin_uv_auth_token.as_ref());
        let mut key = [0u8; 16];
        hkdf.expand(b"encIdentifier", &mut key).unwrap();
        let decrypted = aes_cbc(
            &key,
            &encrypted[..AES_BLOCK_SIZE],
            &encrypted[AES_BLOCK_SIZE..],
            Direction::Decrypt,
        )
        .unwrap();
        assert_eq!(decrypted, identifier);
    }

    #[test]
    fn client_pin_reports_retries_for_management_clients() {
        let mut state = FidoState::new(*b"virtual-test-id!");
        let mut request = vec![AUTHENTICATOR_CLIENT_PIN];
        Encoder::new(&mut request)
            .map(2)
            .unwrap()
            .u8(1)
            .unwrap()
            .u8(2)
            .unwrap()
            .u8(2)
            .unwrap()
            .u8(1)
            .unwrap();

        let response = exchange(&mut state, &request);
        assert_eq!(response[0], CTAP2_OK);
        let mut decoder = minicbor::Decoder::new(&response[1..]);
        assert_eq!(decoder.map().unwrap(), Some(2));
        assert_eq!(decoder.u8().unwrap(), 3);
        assert_eq!(decoder.u8().unwrap(), PIN_RETRIES);
        assert_eq!(decoder.u8().unwrap(), 4);
        assert!(!decoder.bool().unwrap());
    }

    #[test]
    fn get_info_uses_canonical_option_key_order() {
        let mut state = FidoState::new(*b"virtual-test-id!");
        let response = exchange(&mut state, &[AUTHENTICATOR_GET_INFO]);
        assert_eq!(response[0], CTAP2_OK);

        let mut decoder = minicbor::Decoder::new(&response[1..]);
        let fields = decoder.map().unwrap().unwrap();
        let mut versions = Vec::new();
        let mut options = Vec::new();
        let mut encrypted_identifier = None;
        for _ in 0..fields {
            match decoder.u8().unwrap() {
                1 => {
                    let count = decoder.array().unwrap().unwrap();
                    for _ in 0..count {
                        versions.push(decoder.str().unwrap().to_owned());
                    }
                }
                4 => {
                    let count = decoder.map().unwrap().unwrap();
                    for _ in 0..count {
                        options.push(decoder.str().unwrap().to_owned());
                        decoder.bool().unwrap();
                    }
                }
                25 => encrypted_identifier = Some(decoder.bytes().unwrap().to_vec()),
                _ => decoder.skip().unwrap(),
            }
        }

        assert_eq!(versions, ["FIDO_2_0", "FIDO_2_1"]);
        assert_eq!(
            options,
            [
                "rk",
                "plat",
                "credMgmt",
                "clientPin",
                "perCredMgmtRO",
                "pinUvAuthToken",
            ]
        );
        assert_eq!(encrypted_identifier.unwrap().len(), AES_BLOCK_SIZE * 2);
    }

    #[test]
    fn credential_management_reports_resident_credential_metadata() {
        let mut state = FidoState::new(*b"virtual-test-id!");
        let mut request = vec![AUTHENTICATOR_CREDENTIAL_MANAGEMENT];
        Encoder::new(&mut request)
            .map(3)
            .unwrap()
            .u8(1)
            .unwrap()
            .u8(1)
            .unwrap()
            .u8(3)
            .unwrap()
            .u8(2)
            .unwrap()
            .u8(4)
            .unwrap()
            .bytes(&pin_auth(&[1]))
            .unwrap();

        let response = exchange(&mut state, &request);
        assert_eq!(response[0], CTAP2_OK);
        let mut decoder = minicbor::Decoder::new(&response[1..]);
        assert_eq!(decoder.map().unwrap(), Some(2));
        assert_eq!(decoder.u8().unwrap(), 1);
        assert_eq!(decoder.u8().unwrap(), 1);
        assert_eq!(decoder.u8().unwrap(), 2);
        assert_eq!(decoder.u8().unwrap(), 24);
    }

    #[test]
    fn preview_sign_registration_and_assertion_complete_a_verified_cycle() {
        let mut state = FidoState::new(*b"virtual-test-id!");
        let client_data_hash = [0x33; 32];
        let pin_auth = pin_auth(&client_data_hash);

        let mut registration = vec![AUTHENTICATOR_MAKE_CREDENTIAL];
        Encoder::new(&mut registration)
            .map(5)
            .unwrap()
            .u8(1)
            .unwrap()
            .bytes(&client_data_hash)
            .unwrap()
            .u8(2)
            .unwrap()
            .map(1)
            .unwrap()
            .str("id")
            .unwrap()
            .str("example.com")
            .unwrap()
            .u8(6)
            .unwrap()
            .map(1)
            .unwrap()
            .str("previewSign")
            .unwrap()
            .map(0)
            .unwrap()
            .u8(8)
            .unwrap()
            .bytes(&pin_auth)
            .unwrap()
            .u8(9)
            .unwrap()
            .u8(2)
            .unwrap();
        let registration_response = exchange(&mut state, &registration);
        assert_eq!(registration_response[0], CTAP2_OK);
        let seed = crate::preview_sign::seed_cose().unwrap();
        assert!(registration_response
            .windows(seed.len())
            .any(|window| window == seed));

        let ticket = decode_hex(EXPECTED_TICKET);
        assert_eq!(ticket.len(), 81);
        let mut signing_arguments = Vec::new();
        Encoder::new(&mut signing_arguments)
            .map(3)
            .unwrap()
            .u8(3)
            .unwrap()
            .i64(crate::preview_sign::ARKG_P256_ESP256_ALGORITHM)
            .unwrap()
            .i8(-1)
            .unwrap()
            .bytes(&ticket)
            .unwrap()
            .i8(-2)
            .unwrap()
            .bytes(CONTEXT)
            .unwrap();

        let digest: [u8; 32] = Sha256::digest(b"virtual-yubikey previewSign").into();
        let mut assertion = vec![AUTHENTICATOR_GET_ASSERTION];
        Encoder::new(&mut assertion)
            .map(6)
            .unwrap()
            .u8(1)
            .unwrap()
            .str("example.com")
            .unwrap()
            .u8(2)
            .unwrap()
            .bytes(&client_data_hash)
            .unwrap()
            .u8(3)
            .unwrap()
            .array(1)
            .unwrap()
            .map(2)
            .unwrap()
            .str("type")
            .unwrap()
            .str("public-key")
            .unwrap()
            .str("id")
            .unwrap()
            .bytes(&[0xa5; 32])
            .unwrap()
            .u8(4)
            .unwrap()
            .map(1)
            .unwrap()
            .str("previewSign")
            .unwrap()
            .map(3)
            .unwrap()
            .u8(2)
            .unwrap()
            .bytes(&[0x5a; 48])
            .unwrap()
            .u8(6)
            .unwrap()
            .bytes(&digest)
            .unwrap()
            .u8(7)
            .unwrap()
            .bytes(&signing_arguments)
            .unwrap()
            .u8(6)
            .unwrap()
            .bytes(&pin_auth)
            .unwrap()
            .u8(7)
            .unwrap()
            .u8(2)
            .unwrap();

        let assertion_response = exchange(&mut state, &assertion);
        assert_eq!(assertion_response[0], CTAP2_OK);
        let authenticator_data = assertion_authenticator_data(&assertion_response[1..]);
        let signature = preview_signature(&authenticator_data);

        let verifying_key =
            VerifyingKey::from_sec1_bytes(&decode_hex(EXPECTED_PUBLIC_KEY)).unwrap();
        let signature = Signature::from_slice(&signature).unwrap();
        verifying_key.verify_prehash(&digest, &signature).unwrap();
    }

    fn pin_auth(message: &[u8]) -> Vec<u8> {
        let mut mac = <Hmac<Sha256> as hmac::digest::KeyInit>::new_from_slice(&[0x5a; 32]).unwrap();
        mac.update(message);
        mac.finalize().into_bytes().to_vec()
    }

    fn assertion_authenticator_data(response: &[u8]) -> Vec<u8> {
        let mut decoder = minicbor::Decoder::new(response);
        let count = decoder.map().unwrap().unwrap();
        for _ in 0..count {
            match decoder.u8().unwrap() {
                2 => return decoder.bytes().unwrap().to_vec(),
                _ => decoder.skip().unwrap(),
            }
        }
        panic!("assertion response did not contain authenticator data");
    }

    fn preview_signature(authenticator_data: &[u8]) -> Vec<u8> {
        let mut decoder = minicbor::Decoder::new(&authenticator_data[37..]);
        assert_eq!(decoder.map().unwrap(), Some(1));
        assert_eq!(decoder.str().unwrap(), "previewSign");
        assert_eq!(decoder.map().unwrap(), Some(1));
        assert_eq!(decoder.u8().unwrap(), 6);
        decoder.bytes().unwrap().to_vec()
    }

    fn decode_hex(input: &str) -> Vec<u8> {
        input
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| {
                let high = (pair[0] as char).to_digit(16).unwrap();
                let low = (pair[1] as char).to_digit(16).unwrap();
                ((high << 4) | low) as u8
            })
            .collect()
    }
}
