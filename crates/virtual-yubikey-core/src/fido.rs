//! CTAP 2.1 applet state and commands, including the previewSign extension.

use crate::{
    crypto::{aes_cbc, Direction, AES_BLOCK_SIZE},
    FidoConfiguration, FidoCredentialAlgorithm,
};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use minicbor::Encoder;
use p256::{ecdh::diffie_hellman, elliptic_curve::sec1::ToSec1Point, PublicKey, SecretKey};
use sha2::{Digest, Sha256};
#[cfg(test)]
use software_key_core::post_quantum;
use software_key_core::software_signing::{
    EcCurve, SoftwarePublicKey, SoftwareSigningAlgorithm, SoftwareSigningKey,
};
use std::fmt;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

const AUTHENTICATOR_MAKE_CREDENTIAL: u8 = 0x01;
const AUTHENTICATOR_GET_ASSERTION: u8 = 0x02;
const AUTHENTICATOR_GET_INFO: u8 = 0x04;
const AUTHENTICATOR_CLIENT_PIN: u8 = 0x06;
const AUTHENTICATOR_GET_NEXT_ASSERTION: u8 = 0x08;
const AUTHENTICATOR_CREDENTIAL_MANAGEMENT: u8 = 0x0a;
const AUTHENTICATOR_SELECTION: u8 = 0x0b;
const CTAP2_OK: u8 = 0;
const CTAP1_ERR_INVALID_COMMAND: u8 = 0x01;
const CTAP2_ERR_INVALID_CBOR: u8 = 0x12;
const CTAP2_ERR_MISSING_PARAMETER: u8 = 0x14;
const CTAP2_ERR_CREDENTIAL_EXCLUDED: u8 = 0x19;
const CTAP2_ERR_UNSUPPORTED_ALGORITHM: u8 = 0x26;
const CTAP2_ERR_KEY_STORE_FULL: u8 = 0x28;
const CTAP2_ERR_NO_CREDENTIALS: u8 = 0x2e;
const CTAP2_ERR_PIN_INVALID: u8 = 0x31;
const CTAP2_ERR_PIN_NOT_SET: u8 = 0x35;
const CTAP2_ERR_PIN_POLICY_VIOLATION: u8 = 0x37;
const CTAP2_ERR_OTHER: u8 = 0x7f;
const PIN_RETRIES: u8 = 8;
pub(crate) const MAX_RESIDENT_CREDENTIALS: usize = 100;
const MAX_CTAP_MESSAGE_SIZE: u16 = 7609;
const PERSISTENT_STATE_VERSION: u8 = 2;

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

#[derive(Clone, Debug)]
pub(crate) struct FidoState {
    device_identifier: [u8; 16],
    pin: Option<Zeroizing<Vec<u8>>>,
    key_agreement: Option<SecretKey>,
    pin_uv_auth_token: Zeroizing<Vec<u8>>,
    pin_uv_auth_protocols: Vec<u8>,
    permissioned_pin_uv_auth_tokens: bool,
    credential_algorithms: Vec<FidoCredentialAlgorithm>,
    credentials: Vec<ResidentCredential>,
    rp_enumeration: Vec<String>,
    rp_enumeration_offset: usize,
    credential_enumeration: Vec<usize>,
    credential_enumeration_offset: usize,
    assertion_enumeration: Vec<usize>,
    assertion_enumeration_offset: usize,
    assertion_client_data_hash: Vec<u8>,
    assertion_user_verified: bool,
    persistent_change: bool,
}

#[derive(Clone, Debug)]
struct ResidentCredential {
    rp_id: String,
    rp_name: String,
    user_id: Vec<u8>,
    user_name: String,
    user_display_name: String,
    credential_id: Vec<u8>,
    private_key: CredentialPrivateKey,
    public_key_cose: Vec<u8>,
    counter: u32,
    discoverable: bool,
    preview: Option<PreviewCredential>,
}

#[derive(Clone)]
struct CredentialPrivateKey {
    algorithm: FidoCredentialAlgorithm,
    key: SoftwareSigningKey,
}

impl fmt::Debug for CredentialPrivateKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CredentialPrivateKey")
            .field("algorithm", &self.algorithm())
            .finish_non_exhaustive()
    }
}

impl CredentialPrivateKey {
    fn generate(algorithm: FidoCredentialAlgorithm) -> Result<Self, Error> {
        let key = SoftwareSigningKey::generate(algorithm.software_signing_algorithm())
            .map_err(|_| Error::from(CKR_DEVICE_ERROR))?;
        Ok(Self { algorithm, key })
    }

    fn from_serialized(
        algorithm: FidoCredentialAlgorithm,
        serialized: &[u8],
    ) -> Result<Self, &'static str> {
        let key =
            SoftwareSigningKey::from_serialized(algorithm.software_signing_algorithm(), serialized)
                .map_err(|_| "persistent credential private key is invalid")?;
        Ok(Self { algorithm, key })
    }

    fn algorithm(&self) -> FidoCredentialAlgorithm {
        self.algorithm
    }

    fn serialized(&self) -> Result<Zeroizing<Vec<u8>>, Error> {
        self.key
            .serialized()
            .map_err(|_| Error::from(CKR_DEVICE_ERROR))
    }

    fn public_key_cose(&self) -> Result<Vec<u8>, Error> {
        match self.key.public_key() {
            SoftwarePublicKey::Ec {
                curve,
                uncompressed,
            } => encode_ec2(
                self.algorithm.cose_identifier(),
                match curve {
                    EcCurve::P256 => 1,
                    EcCurve::P384 => 2,
                    EcCurve::P521 => 3,
                    EcCurve::Secp256k1 => 8,
                },
                &uncompressed,
            ),
            SoftwarePublicKey::Ed25519(public) => {
                encode_okp(self.algorithm.cose_identifier(), 6, &public)
            }
            SoftwarePublicKey::MlDsa { public_key, .. } => {
                encode_akp(self.algorithm.cose_identifier(), &public_key)
            }
            SoftwarePublicKey::Rsa { modulus, exponent } => {
                encode_rsa(self.algorithm.cose_identifier(), &modulus, &exponent)
            }
        }
    }

    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
        let signature = self
            .key
            .sign_message(self.algorithm.software_signing_algorithm(), message)
            .map_err(|_| Error::from(CKR_DEVICE_ERROR))?;
        match self.algorithm.software_signing_algorithm() {
            SoftwareSigningAlgorithm::EcdsaP256Sha256 => {
                p256::ecdsa::Signature::from_slice(signature.as_bytes())
                    .map(|signature| signature.to_der().as_bytes().to_vec())
                    .map_err(|_| Error::from(CKR_DEVICE_ERROR))
            }
            SoftwareSigningAlgorithm::EcdsaP384Sha384 => {
                p384::ecdsa::Signature::from_slice(signature.as_bytes())
                    .map(|signature| signature.to_der().as_bytes().to_vec())
                    .map_err(|_| Error::from(CKR_DEVICE_ERROR))
            }
            SoftwareSigningAlgorithm::EcdsaP521Sha512 => {
                p521::ecdsa::Signature::from_slice(signature.as_bytes())
                    .map(|signature| signature.to_der().as_bytes().to_vec())
                    .map_err(|_| Error::from(CKR_DEVICE_ERROR))
            }
            SoftwareSigningAlgorithm::EcdsaSecp256k1Sha256 => {
                k256::ecdsa::Signature::from_slice(signature.as_bytes())
                    .map(|signature| signature.to_der().as_bytes().to_vec())
                    .map_err(|_| Error::from(CKR_DEVICE_ERROR))
            }
            SoftwareSigningAlgorithm::Ed25519 | SoftwareSigningAlgorithm::MlDsa(_) => {
                Ok(signature.into_bytes())
            }
            SoftwareSigningAlgorithm::RsaPssSha256
            | SoftwareSigningAlgorithm::RsaPssSha384
            | SoftwareSigningAlgorithm::RsaPssSha512
            | SoftwareSigningAlgorithm::RsaPkcs1Sha256
            | SoftwareSigningAlgorithm::RsaPkcs1Sha384
            | SoftwareSigningAlgorithm::RsaPkcs1Sha512 => Ok(signature.into_bytes()),
        }
    }
}

#[derive(Clone, Debug)]
struct PreviewCredential {
    signing_key_handle: Vec<u8>,
}

impl FidoState {
    pub(crate) fn new(device_identifier: [u8; 16], configuration: FidoConfiguration) -> Self {
        let pin_uv_auth_token_length = if configuration.pin_uv_auth_protocols.contains(&2) {
            32
        } else {
            16
        };
        Self {
            device_identifier,
            pin: configuration.initial_pin.map(Zeroizing::new),
            key_agreement: None,
            pin_uv_auth_token: Zeroizing::new(vec![0x5a; pin_uv_auth_token_length]),
            pin_uv_auth_protocols: configuration.pin_uv_auth_protocols,
            permissioned_pin_uv_auth_tokens: configuration.permissioned_pin_uv_auth_tokens,
            credential_algorithms: configuration.credential_algorithms,
            credentials: Vec::new(),
            rp_enumeration: Vec::new(),
            rp_enumeration_offset: 0,
            credential_enumeration: Vec::new(),
            credential_enumeration_offset: 0,
            assertion_enumeration: Vec::new(),
            assertion_enumeration_offset: 0,
            assertion_client_data_hash: Vec::new(),
            assertion_user_verified: false,
            persistent_change: false,
        }
    }

    pub(crate) fn reset_connection(&mut self) {
        self.key_agreement = None;
        self.rp_enumeration.clear();
        self.credential_enumeration.clear();
        self.assertion_enumeration.clear();
        self.assertion_client_data_hash.clear();
    }

    pub(crate) fn take_persistent_change(&mut self) -> bool {
        std::mem::take(&mut self.persistent_change)
    }

    pub(crate) fn encode_persistent(&self) -> Result<Vec<u8>, &'static str> {
        let mut output = Vec::new();
        let mut encoder = Encoder::new(&mut output);
        encoder
            .map(4)
            .map_err(|_| "cannot encode persistent FIDO state")?
            .u8(1)
            .map_err(|_| "cannot encode persistent FIDO state")?
            .u8(PERSISTENT_STATE_VERSION)
            .map_err(|_| "cannot encode persistent FIDO state")?
            .u8(2)
            .map_err(|_| "cannot encode persistent FIDO state")?
            .bytes(&self.device_identifier)
            .map_err(|_| "cannot encode persistent FIDO state")?
            .u8(3)
            .map_err(|_| "cannot encode persistent FIDO state")?
            .bytes(
                self.pin
                    .as_ref()
                    .map(|pin| pin.as_slice())
                    .unwrap_or_default(),
            )
            .map_err(|_| "cannot encode persistent FIDO state")?
            .u8(4)
            .map_err(|_| "cannot encode persistent FIDO state")?
            .array(
                u64::try_from(self.credentials.len())
                    .map_err(|_| "too many credentials to persist")?,
            )
            .map_err(|_| "cannot encode persistent FIDO state")?;
        for credential in &self.credentials {
            let private_key = credential
                .private_key
                .serialized()
                .map_err(|_| "cannot serialize persistent credential key")?;
            encoder
                .map(11)
                .map_err(|_| "cannot encode persistent credential")?
                .u8(1)
                .map_err(|_| "cannot encode persistent credential")?
                .str(&credential.rp_id)
                .map_err(|_| "cannot encode persistent credential")?
                .u8(2)
                .map_err(|_| "cannot encode persistent credential")?
                .str(&credential.rp_name)
                .map_err(|_| "cannot encode persistent credential")?
                .u8(3)
                .map_err(|_| "cannot encode persistent credential")?
                .bytes(&credential.user_id)
                .map_err(|_| "cannot encode persistent credential")?
                .u8(4)
                .map_err(|_| "cannot encode persistent credential")?
                .str(&credential.user_name)
                .map_err(|_| "cannot encode persistent credential")?
                .u8(5)
                .map_err(|_| "cannot encode persistent credential")?
                .str(&credential.user_display_name)
                .map_err(|_| "cannot encode persistent credential")?
                .u8(6)
                .map_err(|_| "cannot encode persistent credential")?
                .bytes(&credential.credential_id)
                .map_err(|_| "cannot encode persistent credential")?
                .u8(7)
                .map_err(|_| "cannot encode persistent credential")?
                .bytes(private_key.as_slice())
                .map_err(|_| "cannot encode persistent credential")?
                .u8(8)
                .map_err(|_| "cannot encode persistent credential")?
                .u32(credential.counter)
                .map_err(|_| "cannot encode persistent credential")?
                .u8(9)
                .map_err(|_| "cannot encode persistent credential")?
                .bool(credential.discoverable)
                .map_err(|_| "cannot encode persistent credential")?
                .u8(10)
                .map_err(|_| "cannot encode persistent credential")?
                .bytes(
                    credential
                        .preview
                        .as_ref()
                        .map(|preview| preview.signing_key_handle.as_slice())
                        .unwrap_or_default(),
                )
                .map_err(|_| "cannot encode persistent credential")?
                .u8(11)
                .map_err(|_| "cannot encode persistent credential")?
                .i64(credential.private_key.algorithm().cose_identifier())
                .map_err(|_| "cannot encode persistent credential")?;
        }
        Ok(output)
    }

    pub(crate) fn decode_persistent(
        encoded: &[u8],
        expected_identifier: [u8; 16],
        configuration: FidoConfiguration,
    ) -> Result<Self, &'static str> {
        let mut decoder = minicbor::Decoder::new(encoded);
        let fields = decoder
            .map()
            .map_err(|_| "persistent FIDO state is not a CBOR map")?
            .ok_or("indefinite persistent FIDO state is unsupported")?;
        let mut version = None;
        let mut identifier = None;
        let mut pin = None;
        let mut credentials = None;
        for _ in 0..fields {
            match decoder
                .u8()
                .map_err(|_| "persistent FIDO state has an invalid field")?
            {
                1 if version.is_none() => {
                    version = Some(
                        decoder
                            .u8()
                            .map_err(|_| "persistent FIDO state has an invalid version")?,
                    )
                }
                2 if identifier.is_none() => {
                    identifier = Some(
                        decoder
                            .bytes()
                            .map_err(|_| "persistent FIDO state has an invalid identifier")?
                            .to_vec(),
                    )
                }
                3 if pin.is_none() => {
                    pin = Some(
                        decoder
                            .bytes()
                            .map_err(|_| "persistent FIDO state has an invalid PIN")?
                            .to_vec(),
                    )
                }
                4 if credentials.is_none() => {
                    let count = decoder
                        .array()
                        .map_err(|_| "persistent credentials are not an array")?
                        .ok_or("indefinite persistent credentials are unsupported")?;
                    let mut decoded = Vec::new();
                    for _ in 0..count {
                        decoded.push(decode_persistent_credential(&mut decoder)?);
                    }
                    credentials = Some(decoded);
                }
                _ => decoder
                    .skip()
                    .map_err(|_| "persistent FIDO state contains invalid data")?,
            }
        }
        if decoder.position() != encoded.len() {
            return Err("persistent FIDO state has trailing data");
        }
        if version != Some(PERSISTENT_STATE_VERSION) {
            return Err("unsupported persistent FIDO state version");
        }
        if identifier.as_deref() != Some(expected_identifier.as_slice()) {
            return Err("persistent FIDO state belongs to another device serial");
        }
        let credentials = credentials.ok_or("persistent FIDO state has no credential array")?;
        if credentials
            .iter()
            .filter(|credential| credential.discoverable)
            .count()
            > MAX_RESIDENT_CREDENTIALS
        {
            return Err("persistent FIDO state exceeds resident credential capacity");
        }
        for (index, credential) in credentials.iter().enumerate() {
            if credentials[..index]
                .iter()
                .any(|other| other.credential_id == credential.credential_id)
            {
                return Err("persistent FIDO state contains duplicate credential IDs");
            }
        }
        let mut state = Self::new(expected_identifier, configuration);
        let pin = pin.ok_or("persistent FIDO state has no PIN field")?;
        state.pin = (!pin.is_empty()).then(|| Zeroizing::new(pin));
        state.credentials = credentials;
        Ok(state)
    }
}

fn decode_persistent_credential(
    decoder: &mut minicbor::Decoder<'_>,
) -> Result<ResidentCredential, &'static str> {
    let fields = decoder
        .map()
        .map_err(|_| "persistent credential is not a CBOR map")?
        .ok_or("indefinite persistent credential is unsupported")?;
    let mut rp_id = None;
    let mut rp_name = None;
    let mut user_id = None;
    let mut user_name = None;
    let mut user_display_name = None;
    let mut credential_id = None;
    let mut private_key = None;
    let mut counter = None;
    let mut discoverable = None;
    let mut preview_handle = None;
    let mut algorithm = None;
    for _ in 0..fields {
        match decoder
            .u8()
            .map_err(|_| "persistent credential has an invalid field")?
        {
            1 if rp_id.is_none() => {
                rp_id = Some(
                    decoder
                        .str()
                        .map_err(|_| "persistent credential has an invalid RP ID")?
                        .to_owned(),
                )
            }
            2 if rp_name.is_none() => {
                rp_name = Some(
                    decoder
                        .str()
                        .map_err(|_| "persistent credential has an invalid RP name")?
                        .to_owned(),
                )
            }
            3 if user_id.is_none() => {
                user_id = Some(
                    decoder
                        .bytes()
                        .map_err(|_| "persistent credential has an invalid user ID")?
                        .to_vec(),
                )
            }
            4 if user_name.is_none() => {
                user_name = Some(
                    decoder
                        .str()
                        .map_err(|_| "persistent credential has an invalid user name")?
                        .to_owned(),
                )
            }
            5 if user_display_name.is_none() => {
                user_display_name = Some(
                    decoder
                        .str()
                        .map_err(|_| "persistent credential has an invalid display name")?
                        .to_owned(),
                )
            }
            6 if credential_id.is_none() => {
                credential_id = Some(
                    decoder
                        .bytes()
                        .map_err(|_| "persistent credential has an invalid credential ID")?
                        .to_vec(),
                )
            }
            7 if private_key.is_none() => {
                private_key = Some(
                    decoder
                        .bytes()
                        .map_err(|_| "persistent credential has an invalid private key")?
                        .to_vec(),
                )
            }
            8 if counter.is_none() => {
                counter = Some(
                    decoder
                        .u32()
                        .map_err(|_| "persistent credential has an invalid counter")?,
                )
            }
            9 if discoverable.is_none() => {
                discoverable = Some(
                    decoder
                        .bool()
                        .map_err(|_| "persistent credential has an invalid discoverable flag")?,
                )
            }
            10 if preview_handle.is_none() => {
                preview_handle = Some(
                    decoder
                        .bytes()
                        .map_err(|_| "persistent credential has an invalid preview handle")?
                        .to_vec(),
                )
            }
            11 if algorithm.is_none() => {
                algorithm = Some(
                    decoder
                        .i64()
                        .map_err(|_| "persistent credential has an invalid algorithm")?,
                )
            }
            _ => decoder
                .skip()
                .map_err(|_| "persistent credential contains invalid data")?,
        }
    }
    let algorithm = FidoCredentialAlgorithm::from_cose_identifier(
        algorithm.ok_or("persistent credential has no algorithm")?,
    )
    .ok_or("persistent credential algorithm is unsupported")?;
    let private_key = CredentialPrivateKey::from_serialized(
        algorithm,
        &private_key.ok_or("persistent credential has no private key")?,
    )?;
    let public_key_cose = private_key
        .public_key_cose()
        .map_err(|_| "persistent credential public key cannot be encoded")?;
    let preview_handle = preview_handle.ok_or("persistent credential has no preview field")?;
    Ok(ResidentCredential {
        rp_id: rp_id.ok_or("persistent credential has no RP ID")?,
        rp_name: rp_name.ok_or("persistent credential has no RP name")?,
        user_id: user_id.ok_or("persistent credential has no user ID")?,
        user_name: user_name.ok_or("persistent credential has no user name")?,
        user_display_name: user_display_name.ok_or("persistent credential has no display name")?,
        credential_id: credential_id.ok_or("persistent credential has no credential ID")?,
        private_key,
        public_key_cose,
        counter: counter.ok_or("persistent credential has no counter")?,
        discoverable: discoverable.ok_or("persistent credential has no discoverable flag")?,
        preview: (!preview_handle.is_empty()).then_some(PreviewCredential {
            signing_key_handle: preview_handle,
        }),
    })
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
        AUTHENTICATOR_GET_NEXT_ASSERTION if payload.is_empty() => {
            authenticator_get_next_assertion(state)
        }
        AUTHENTICATOR_CREDENTIAL_MANAGEMENT => authenticator_credential_management(state, payload),
        AUTHENTICATOR_SELECTION if payload.is_empty() => Ok(vec![CTAP2_OK]),
        _ => Ok(vec![CTAP1_ERR_INVALID_COMMAND]),
    }
}

#[derive(Default)]
struct PreviewRequest {
    rp_id: Option<String>,
    rp_name: Option<String>,
    user_id: Option<Vec<u8>>,
    user_name: Option<String>,
    user_display_name: Option<String>,
    client_data_hash: Option<Vec<u8>>,
    credential_ids: Vec<Vec<u8>>,
    algorithms: Vec<i64>,
    resident_key: bool,
    preview_requested: bool,
    signing_key_handle: Option<Vec<u8>>,
    to_be_signed: Option<Vec<u8>>,
    additional_args: Option<Vec<u8>>,
    pin_uv_auth: Option<Vec<u8>>,
    protocol: Option<u8>,
}

fn decode_rp(decoder: &mut minicbor::Decoder<'_>, request: &mut PreviewRequest) -> Result<(), u8> {
    let count = decoder
        .map()
        .map_err(|_| CTAP2_ERR_INVALID_CBOR)?
        .ok_or(CTAP2_ERR_INVALID_CBOR)?;
    for _ in 0..count {
        match decoder.str().map_err(|_| CTAP2_ERR_INVALID_CBOR)? {
            "id" if request.rp_id.is_none() => {
                request.rp_id = Some(
                    decoder
                        .str()
                        .map_err(|_| CTAP2_ERR_INVALID_CBOR)?
                        .to_owned(),
                )
            }
            "name" if request.rp_name.is_none() => {
                request.rp_name = Some(
                    decoder
                        .str()
                        .map_err(|_| CTAP2_ERR_INVALID_CBOR)?
                        .to_owned(),
                )
            }
            _ => decoder.skip().map_err(|_| CTAP2_ERR_INVALID_CBOR)?,
        }
    }
    request.rp_id.as_ref().ok_or(CTAP2_ERR_MISSING_PARAMETER)?;
    Ok(())
}

fn decode_user(
    decoder: &mut minicbor::Decoder<'_>,
    request: &mut PreviewRequest,
) -> Result<(), u8> {
    let count = decoder
        .map()
        .map_err(|_| CTAP2_ERR_INVALID_CBOR)?
        .ok_or(CTAP2_ERR_INVALID_CBOR)?;
    for _ in 0..count {
        match decoder.str().map_err(|_| CTAP2_ERR_INVALID_CBOR)? {
            "id" if request.user_id.is_none() => {
                request.user_id = Some(
                    decoder
                        .bytes()
                        .map_err(|_| CTAP2_ERR_INVALID_CBOR)?
                        .to_vec(),
                )
            }
            "name" if request.user_name.is_none() => {
                request.user_name = Some(
                    decoder
                        .str()
                        .map_err(|_| CTAP2_ERR_INVALID_CBOR)?
                        .to_owned(),
                )
            }
            "displayName" if request.user_display_name.is_none() => {
                request.user_display_name = Some(
                    decoder
                        .str()
                        .map_err(|_| CTAP2_ERR_INVALID_CBOR)?
                        .to_owned(),
                )
            }
            _ => decoder.skip().map_err(|_| CTAP2_ERR_INVALID_CBOR)?,
        }
    }
    request
        .user_id
        .as_ref()
        .ok_or(CTAP2_ERR_MISSING_PARAMETER)?;
    Ok(())
}

fn decode_allow_list(decoder: &mut minicbor::Decoder<'_>) -> Result<Vec<Vec<u8>>, u8> {
    let count = decoder
        .array()
        .map_err(|_| CTAP2_ERR_INVALID_CBOR)?
        .ok_or(CTAP2_ERR_INVALID_CBOR)?;
    let mut ids = Vec::new();
    for _ in 0..count {
        ids.push(decode_credential_descriptor(decoder)?);
    }
    Ok(ids)
}

fn decode_credential_descriptor(decoder: &mut minicbor::Decoder<'_>) -> Result<Vec<u8>, u8> {
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

fn decode_algorithms(
    decoder: &mut minicbor::Decoder<'_>,
    request: &mut PreviewRequest,
) -> Result<(), u8> {
    let count = decoder
        .array()
        .map_err(|_| CTAP2_ERR_INVALID_CBOR)?
        .ok_or(CTAP2_ERR_INVALID_CBOR)?;
    for _ in 0..count {
        let fields = decoder
            .map()
            .map_err(|_| CTAP2_ERR_INVALID_CBOR)?
            .ok_or(CTAP2_ERR_INVALID_CBOR)?;
        let mut algorithm = None;
        let mut public_key = false;
        for _ in 0..fields {
            match decoder.str().map_err(|_| CTAP2_ERR_INVALID_CBOR)? {
                "alg" => algorithm = Some(decoder.i64().map_err(|_| CTAP2_ERR_INVALID_CBOR)?),
                "type" => {
                    public_key = decoder.str().map_err(|_| CTAP2_ERR_INVALID_CBOR)? == "public-key"
                }
                _ => decoder.skip().map_err(|_| CTAP2_ERR_INVALID_CBOR)?,
            }
        }
        if public_key {
            if let Some(algorithm) = algorithm {
                request.algorithms.push(algorithm);
            }
        }
    }
    Ok(())
}

pub(crate) fn make_credential_algorithms(request: &[u8]) -> Option<Vec<i64>> {
    let (&command, payload) = request.split_first()?;
    if command != AUTHENTICATOR_MAKE_CREDENTIAL {
        return None;
    }
    decode_preview_request(payload, false)
        .ok()
        .map(|request| request.algorithms)
}

impl FidoState {
    fn select_credential_algorithm(&self, offered: &[i64]) -> Option<FidoCredentialAlgorithm> {
        for preferred in [
            FidoCredentialAlgorithm::MlDsa87,
            FidoCredentialAlgorithm::MlDsa65,
            FidoCredentialAlgorithm::MlDsa44,
        ] {
            if self.credential_algorithms.contains(&preferred)
                && offered.contains(&preferred.cose_identifier())
            {
                return Some(preferred);
            }
        }
        offered
            .iter()
            .filter_map(|identifier| FidoCredentialAlgorithm::from_cose_identifier(*identifier))
            .find(|algorithm| self.credential_algorithms.contains(algorithm))
    }

    pub(crate) fn selected_make_credential_algorithm(
        &self,
        request: &[u8],
    ) -> Option<FidoCredentialAlgorithm> {
        let (&command, payload) = request.split_first()?;
        if command != AUTHENTICATOR_MAKE_CREDENTIAL {
            return None;
        }
        let request = decode_preview_request(payload, false).ok()?;
        self.select_credential_algorithm(&request.algorithms)
    }
}

fn decode_options(
    decoder: &mut minicbor::Decoder<'_>,
    request: &mut PreviewRequest,
) -> Result<(), u8> {
    let count = decoder
        .map()
        .map_err(|_| CTAP2_ERR_INVALID_CBOR)?
        .ok_or(CTAP2_ERR_INVALID_CBOR)?;
    for _ in 0..count {
        let name = decoder.str().map_err(|_| CTAP2_ERR_INVALID_CBOR)?;
        if name == "rk" {
            request.resident_key = decoder.bool().map_err(|_| CTAP2_ERR_INVALID_CBOR)?;
        } else {
            decoder.skip().map_err(|_| CTAP2_ERR_INVALID_CBOR)?;
        }
    }
    Ok(())
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
        request.preview_requested = true;
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
            2 if !assertion && request.rp_id.is_none() => decode_rp(&mut decoder, &mut request)?,
            3 if !assertion && request.user_id.is_none() => {
                decode_user(&mut decoder, &mut request)?
            }
            3 if assertion && request.credential_ids.is_empty() => {
                request.credential_ids = decode_allow_list(&mut decoder)?
            }
            4 if !assertion => decode_algorithms(&mut decoder, &mut request)?,
            5 if !assertion => request.credential_ids = decode_allow_list(&mut decoder)?,
            4 if assertion => decode_preview_extension(&mut decoder, &mut request)?,
            6 if !assertion => decode_preview_extension(&mut decoder, &mut request)?,
            5 if assertion => decode_options(&mut decoder, &mut request)?,
            7 if !assertion => decode_options(&mut decoder, &mut request)?,
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

fn decode_management_credential_id(parameters: &[u8]) -> Result<Vec<u8>, u8> {
    let mut decoder = minicbor::Decoder::new(parameters);
    let count = decoder
        .map()
        .map_err(|_| CTAP2_ERR_INVALID_CBOR)?
        .ok_or(CTAP2_ERR_INVALID_CBOR)?;
    let mut credential_id = None;
    for _ in 0..count {
        match decoder.u8().map_err(|_| CTAP2_ERR_INVALID_CBOR)? {
            2 if credential_id.is_none() => {
                let fields = decoder
                    .map()
                    .map_err(|_| CTAP2_ERR_INVALID_CBOR)?
                    .ok_or(CTAP2_ERR_INVALID_CBOR)?;
                let mut id = None;
                let mut type_is_public_key = false;
                for _ in 0..fields {
                    match decoder.str().map_err(|_| CTAP2_ERR_INVALID_CBOR)? {
                        "id" if id.is_none() => {
                            id = Some(
                                decoder
                                    .bytes()
                                    .map_err(|_| CTAP2_ERR_INVALID_CBOR)?
                                    .to_vec(),
                            );
                        }
                        "type" => {
                            type_is_public_key =
                                decoder.str().map_err(|_| CTAP2_ERR_INVALID_CBOR)? == "public-key";
                        }
                        _ => decoder.skip().map_err(|_| CTAP2_ERR_INVALID_CBOR)?,
                    }
                }
                if !type_is_public_key {
                    return Err(CTAP2_ERR_INVALID_CBOR);
                }
                credential_id = id;
            }
            _ => decoder.skip().map_err(|_| CTAP2_ERR_INVALID_CBOR)?,
        }
    }
    if decoder.position() != parameters.len() {
        return Err(CTAP2_ERR_INVALID_CBOR);
    }
    credential_id.ok_or(CTAP2_ERR_MISSING_PARAMETER)
}

fn credential_management_rp_response(
    credential: &ResidentCredential,
    total: Option<usize>,
) -> Result<Vec<u8>, Error> {
    let mut response = vec![CTAP2_OK];
    Encoder::new(&mut response)
        .map(if total.is_some() { 3 } else { 2 })
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
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?;
    if let Some(total) = total {
        Encoder::new(&mut response)
            .u8(5)
            .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
            .u64(u64::try_from(total).map_err(|_| Error::from(CKR_DEVICE_ERROR))?)
            .map_err(|_| Error::from(CKR_DEVICE_ERROR))?;
    }
    Ok(response)
}

fn credential_management_metadata_response(state: &FidoState) -> Result<Vec<u8>, Error> {
    let used = state
        .credentials
        .iter()
        .filter(|credential| credential.discoverable)
        .count();
    let mut response = vec![CTAP2_OK];
    Encoder::new(&mut response)
        .map(2)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .u8(1)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .u64(u64::try_from(used).map_err(|_| Error::from(CKR_DEVICE_ERROR))?)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .u8(2)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .u64(
            u64::try_from(MAX_RESIDENT_CREDENTIALS.saturating_sub(used))
                .map_err(|_| Error::from(CKR_DEVICE_ERROR))?,
        )
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?;
    Ok(response)
}

fn credential_management_credential_response(
    credential: &ResidentCredential,
    total: Option<usize>,
) -> Result<Vec<u8>, Error> {
    let mut response = vec![CTAP2_OK];
    let mut encoder = Encoder::new(&mut response);
    encoder
        .map(if total.is_some() { 6 } else { 5 })
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
    if let Some(total) = total {
        encoder
            .u8(9)
            .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
            .u64(u64::try_from(total).map_err(|_| Error::from(CKR_DEVICE_ERROR))?)
            .map_err(|_| Error::from(CKR_DEVICE_ERROR))?;
    }
    encoder
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

fn decode_management_update_user(
    parameters: &[u8],
) -> Result<(Vec<u8>, Vec<u8>, String, String), u8> {
    let mut decoder = minicbor::Decoder::new(parameters);
    let count = decoder
        .map()
        .map_err(|_| CTAP2_ERR_INVALID_CBOR)?
        .ok_or(CTAP2_ERR_INVALID_CBOR)?;
    let mut credential_id = None;
    let mut request = PreviewRequest::default();
    for _ in 0..count {
        match decoder.u8().map_err(|_| CTAP2_ERR_INVALID_CBOR)? {
            2 if credential_id.is_none() => {
                credential_id = Some(decode_credential_descriptor(&mut decoder)?)
            }
            3 if request.user_id.is_none() => decode_user(&mut decoder, &mut request)?,
            _ => decoder.skip().map_err(|_| CTAP2_ERR_INVALID_CBOR)?,
        }
    }
    if decoder.position() != parameters.len() {
        return Err(CTAP2_ERR_INVALID_CBOR);
    }
    Ok((
        credential_id.ok_or(CTAP2_ERR_MISSING_PARAMETER)?,
        request.user_id.ok_or(CTAP2_ERR_MISSING_PARAMETER)?,
        request.user_name.unwrap_or_default(),
        request.user_display_name.unwrap_or_default(),
    ))
}

fn authenticator_credential_management(
    state: &mut FidoState,
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
        1 => credential_management_metadata_response(state),
        2 => {
            let mut rps = Vec::new();
            for credential in state
                .credentials
                .iter()
                .filter(|credential| credential.discoverable)
            {
                if !rps.contains(&credential.rp_id) {
                    rps.push(credential.rp_id.clone());
                }
            }
            let Some(first_rp) = rps.first() else {
                return Ok(vec![CTAP2_ERR_NO_CREDENTIALS]);
            };
            let credential = state
                .credentials
                .iter()
                .find(|credential| credential.discoverable && credential.rp_id == *first_rp)
                .cloned()
                .ok_or(CKR_DEVICE_ERROR)?;
            let total = rps.len();
            state.rp_enumeration = rps;
            state.rp_enumeration_offset = 1;
            credential_management_rp_response(&credential, Some(total))
        }
        3 => {
            let Some(rp_id) = state
                .rp_enumeration
                .get(state.rp_enumeration_offset)
                .cloned()
            else {
                return Ok(vec![CTAP2_ERR_NO_CREDENTIALS]);
            };
            state.rp_enumeration_offset += 1;
            let credential = state
                .credentials
                .iter()
                .find(|credential| credential.discoverable && credential.rp_id == rp_id)
                .ok_or(CKR_DEVICE_ERROR)?;
            credential_management_rp_response(credential, None)
        }
        4 => {
            let Some(parameters) = request.parameters.as_deref() else {
                return Ok(vec![CTAP2_ERR_MISSING_PARAMETER]);
            };
            let rp_id_hash = match decode_management_rp_id_hash(parameters) {
                Ok(value) => value,
                Err(status) => return Ok(vec![status]),
            };
            let indices: Vec<usize> = state
                .credentials
                .iter()
                .enumerate()
                .filter(|(_, credential)| {
                    credential.discoverable
                        && rp_id_hash == Sha256::digest(credential.rp_id.as_bytes()).as_slice()
                })
                .map(|(index, _)| index)
                .collect();
            let Some(&first) = indices.first() else {
                return Ok(vec![CTAP2_ERR_NO_CREDENTIALS]);
            };
            let total = indices.len();
            state.credential_enumeration = indices;
            state.credential_enumeration_offset = 1;
            credential_management_credential_response(&state.credentials[first], Some(total))
        }
        5 => {
            let Some(&index) = state
                .credential_enumeration
                .get(state.credential_enumeration_offset)
            else {
                return Ok(vec![CTAP2_ERR_NO_CREDENTIALS]);
            };
            state.credential_enumeration_offset += 1;
            credential_management_credential_response(&state.credentials[index], None)
        }
        6 => {
            let Some(parameters) = request.parameters.as_deref() else {
                return Ok(vec![CTAP2_ERR_MISSING_PARAMETER]);
            };
            let credential_id = match decode_management_credential_id(parameters) {
                Ok(value) => value,
                Err(status) => return Ok(vec![status]),
            };
            if let Some(index) = state
                .credentials
                .iter()
                .position(|credential| credential.credential_id == credential_id)
            {
                state.credentials.remove(index);
                state.persistent_change = true;
                Ok(vec![CTAP2_OK])
            } else {
                Ok(vec![CTAP2_ERR_NO_CREDENTIALS])
            }
        }
        7 => {
            let Some(parameters) = request.parameters.as_deref() else {
                return Ok(vec![CTAP2_ERR_MISSING_PARAMETER]);
            };
            let (credential_id, user_id, user_name, user_display_name) =
                match decode_management_update_user(parameters) {
                    Ok(value) => value,
                    Err(status) => return Ok(vec![status]),
                };
            let Some(credential) = state
                .credentials
                .iter_mut()
                .find(|credential| credential.credential_id == credential_id)
            else {
                return Ok(vec![CTAP2_ERR_NO_CREDENTIALS]);
            };
            credential.user_id = user_id;
            credential.user_name = user_name;
            credential.user_display_name = user_display_name;
            state.persistent_change = true;
            Ok(vec![CTAP2_OK])
        }
        _ => Ok(vec![CTAP1_ERR_INVALID_COMMAND]),
    }
}

fn encode_ec2(algorithm: i64, curve: u8, public: &[u8]) -> Result<Vec<u8>, Error> {
    if public.len() < 3 || public[0] != 4 || (public.len() - 1) % 2 != 0 {
        return Err(CKR_DEVICE_ERROR.into());
    }
    let coordinate_length = (public.len() - 1) / 2;
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
        .i64(algorithm)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .i8(-1)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .u8(curve)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .i8(-2)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .bytes(&public[1..1 + coordinate_length])
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .i8(-3)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .bytes(&public[1 + coordinate_length..])
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?;
    Ok(encoded)
}

fn encode_akp(algorithm: i64, public: &[u8]) -> Result<Vec<u8>, Error> {
    let mut encoded = Vec::new();
    Encoder::new(&mut encoded)
        .map(3)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .u8(1)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .u8(7)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .u8(3)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .i64(algorithm)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .i8(-1)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .bytes(public)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?;
    Ok(encoded)
}

fn encode_okp(algorithm: i64, curve: u8, public: &[u8]) -> Result<Vec<u8>, Error> {
    let mut encoded = Vec::new();
    Encoder::new(&mut encoded)
        .map(4)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .u8(1)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .u8(1)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .u8(3)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .i64(algorithm)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .i8(-1)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .u8(curve)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .i8(-2)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .bytes(public)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?;
    Ok(encoded)
}

fn encode_rsa(algorithm: i64, modulus: &[u8], exponent: &[u8]) -> Result<Vec<u8>, Error> {
    let mut encoded = Vec::new();
    Encoder::new(&mut encoded)
        .map(4)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .u8(1)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .u8(3)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .u8(3)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .i64(algorithm)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .i8(-1)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .bytes(modulus)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .i8(-2)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .bytes(exponent)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?;
    Ok(encoded)
}

fn authenticator_data(
    rp_id: &str,
    credential_id: &[u8],
    public_key_cose: &[u8],
    extension_output: Option<&[u8]>,
    counter: u32,
    user_verified: bool,
) -> Result<Vec<u8>, Error> {
    let mut data = Sha256::digest(rp_id.as_bytes()).to_vec();
    let mut flags = 0x41;
    if user_verified {
        flags |= 0x04;
    }
    if extension_output.is_some() {
        flags |= 0x80;
    }
    data.push(flags);
    data.extend_from_slice(&counter.to_be_bytes());
    data.extend_from_slice(&[0x50; 16]);
    data.extend_from_slice(
        &u16::try_from(credential_id.len())
            .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
            .to_be_bytes(),
    );
    data.extend_from_slice(credential_id);
    data.extend_from_slice(public_key_cose);
    if let Some(extension_output) = extension_output {
        let mut extensions = Vec::new();
        let mut encoder = Encoder::new(&mut extensions);
        encoder
            .map(1)
            .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
            .str("previewSign")
            .map_err(|_| Error::from(CKR_DEVICE_ERROR))?;
        encoder.writer_mut().extend_from_slice(extension_output);
        data.extend_from_slice(&extensions);
    }
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
    if client_data_hash.len() != 32 {
        return Ok(vec![CTAP2_ERR_INVALID_CBOR]);
    }
    let user_verified = match (request.protocol, request.pin_uv_auth.as_deref()) {
        (Some(protocol), Some(auth)) => {
            if !state.pin_uv_auth_protocols.contains(&protocol)
                || !authenticate(
                    protocol,
                    state.pin_uv_auth_token.as_ref(),
                    client_data_hash,
                    Some(auth),
                )
            {
                return Ok(vec![CTAP2_ERR_PIN_INVALID]);
            }
            true
        }
        (None, None) => false,
        _ => return Ok(vec![CTAP2_ERR_MISSING_PARAMETER]),
    };
    let Some(algorithm) = state.select_credential_algorithm(&request.algorithms) else {
        return Ok(vec![CTAP2_ERR_UNSUPPORTED_ALGORITHM]);
    };
    let rp_id = request.rp_id.ok_or(CKR_DEVICE_ERROR)?;
    if request.credential_ids.iter().any(|credential_id| {
        state.credentials.iter().any(|credential| {
            credential.credential_id == *credential_id && credential.rp_id == rp_id
        })
    }) {
        return Ok(vec![CTAP2_ERR_CREDENTIAL_EXCLUDED]);
    }
    let discoverable = request.resident_key || request.preview_requested;
    if discoverable
        && state
            .credentials
            .iter()
            .filter(|credential| credential.discoverable)
            .count()
            >= MAX_RESIDENT_CREDENTIALS
    {
        return Ok(vec![CTAP2_ERR_KEY_STORE_FULL]);
    }
    let credential_id = loop {
        let mut candidate = vec![0_u8; 32];
        getrandom::fill(&mut candidate).map_err(|_| Error::from(CKR_DEVICE_ERROR))?;
        if !state
            .credentials
            .iter()
            .any(|credential| credential.credential_id == candidate)
        {
            break candidate;
        }
    };
    let parent_secret = CredentialPrivateKey::generate(algorithm)?;
    let parent_cose = parent_secret.public_key_cose()?;
    let (extension_output, unsigned_extension, preview) = if request.preview_requested {
        let mut algorithm_output = Vec::new();
        Encoder::new(&mut algorithm_output)
            .map(1)
            .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
            .u8(3)
            .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
            .i64(-65_539)
            .map_err(|_| Error::from(CKR_DEVICE_ERROR))?;
        let mut signing_key_handle = vec![0_u8; 48];
        getrandom::fill(&mut signing_key_handle).map_err(|_| Error::from(CKR_DEVICE_ERROR))?;
        let seed = crate::preview_sign::seed_cose().map_err(|_| Error::from(CKR_DEVICE_ERROR))?;
        let mut policy_output = Vec::new();
        Encoder::new(&mut policy_output)
            .map(1)
            .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
            .u8(4)
            .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
            .u8(1)
            .map_err(|_| Error::from(CKR_DEVICE_ERROR))?;
        let inner_auth_data = authenticator_data(
            &rp_id,
            &signing_key_handle,
            &seed,
            Some(&policy_output),
            0,
            user_verified,
        )?;
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
        (
            Some(algorithm_output),
            Some(attestation),
            Some(PreviewCredential { signing_key_handle }),
        )
    } else {
        (None, None, None)
    };
    let outer_auth_data = authenticator_data(
        &rp_id,
        &credential_id,
        &parent_cose,
        extension_output.as_deref(),
        0,
        user_verified,
    )?;
    let mut response = vec![CTAP2_OK];
    let mut encoder = Encoder::new(&mut response);
    encoder
        .map(if unsigned_extension.is_some() { 4 } else { 3 })
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
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?;
    if let Some(attestation) = unsigned_extension {
        encoder
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
    }
    state.credentials.push(ResidentCredential {
        rp_id,
        rp_name: request.rp_name.unwrap_or_default(),
        user_id: request.user_id.unwrap_or_default(),
        user_name: request.user_name.unwrap_or_default(),
        user_display_name: request.user_display_name.unwrap_or_default(),
        credential_id,
        private_key: parent_secret,
        public_key_cose: parent_cose,
        counter: 0,
        discoverable,
        preview,
    });
    state.persistent_change = true;
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
    if client_data_hash.len() != 32 {
        return Ok(vec![CTAP2_ERR_INVALID_CBOR]);
    }
    let user_verified = match (request.protocol, request.pin_uv_auth.as_deref()) {
        (Some(protocol), Some(auth)) => {
            if !state.pin_uv_auth_protocols.contains(&protocol)
                || !authenticate(
                    protocol,
                    state.pin_uv_auth_token.as_ref(),
                    client_data_hash,
                    Some(auth),
                )
            {
                return Ok(vec![CTAP2_ERR_PIN_INVALID]);
            }
            true
        }
        (None, None) => false,
        _ => return Ok(vec![CTAP2_ERR_MISSING_PARAMETER]),
    };
    let rp_id = request.rp_id.as_deref().ok_or(CKR_DEVICE_ERROR)?;
    let candidates: Vec<usize> = state
        .credentials
        .iter()
        .enumerate()
        .filter(|(_, credential)| {
            credential.rp_id == rp_id
                && if request.credential_ids.is_empty() {
                    credential.discoverable
                } else {
                    request.credential_ids.contains(&credential.credential_id)
                }
        })
        .map(|(index, _)| index)
        .collect();
    let Some(&index) = candidates.first() else {
        return Ok(vec![CTAP2_ERR_NO_CREDENTIALS]);
    };
    if request.preview_requested || request.signing_key_handle.is_some() {
        let credential = &state.credentials[index];
        let Some(preview) = credential.preview.as_ref() else {
            return Ok(vec![CTAP2_ERR_NO_CREDENTIALS]);
        };
        if request.signing_key_handle.as_deref() != Some(preview.signing_key_handle.as_slice()) {
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
        return Ok(response);
    }

    let total = if request.credential_ids.is_empty() && candidates.len() > 1 {
        Some(candidates.len())
    } else {
        None
    };
    state.assertion_enumeration = candidates;
    state.assertion_enumeration_offset = 1;
    state.assertion_client_data_hash = client_data_hash.to_vec();
    state.assertion_user_verified = user_verified;
    standard_assertion_response(state, index, client_data_hash, total)
}

fn authenticator_get_next_assertion(state: &mut FidoState) -> Result<Vec<u8>, Error> {
    let Some(&index) = state
        .assertion_enumeration
        .get(state.assertion_enumeration_offset)
    else {
        return Ok(vec![CTAP2_ERR_NO_CREDENTIALS]);
    };
    state.assertion_enumeration_offset += 1;
    let client_data_hash = state.assertion_client_data_hash.clone();
    standard_assertion_response(state, index, &client_data_hash, None)
}

fn standard_assertion_response(
    state: &mut FidoState,
    index: usize,
    client_data_hash: &[u8],
    total: Option<usize>,
) -> Result<Vec<u8>, Error> {
    let credential = state.credentials.get_mut(index).ok_or(CKR_DEVICE_ERROR)?;
    let include_user = credential.discoverable;
    let user_fields = if state.assertion_user_verified { 3 } else { 1 };
    credential.counter = credential.counter.saturating_add(1);
    let mut auth_data = Sha256::digest(credential.rp_id.as_bytes()).to_vec();
    auth_data.push(if state.assertion_user_verified {
        0x05
    } else {
        0x01
    });
    auth_data.extend_from_slice(&credential.counter.to_be_bytes());
    let mut signed = Vec::with_capacity(auth_data.len() + client_data_hash.len());
    signed.extend_from_slice(&auth_data);
    signed.extend_from_slice(client_data_hash);
    let signature = credential.private_key.sign(&signed)?;
    let mut response = vec![CTAP2_OK];
    let mut encoder = Encoder::new(&mut response);
    encoder
        .map(3 + u64::from(include_user) + u64::from(total.is_some()))
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
        .bytes(&signature)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?;
    if include_user {
        encoder
            .u8(4)
            .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
            .map(user_fields)
            .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
            .str("id")
            .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
            .bytes(&credential.user_id)
            .map_err(|_| Error::from(CKR_DEVICE_ERROR))?;
        if state.assertion_user_verified {
            encoder
                .str("name")
                .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
                .str(&credential.user_name)
                .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
                .str("displayName")
                .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
                .str(&credential.user_display_name)
                .map_err(|_| Error::from(CKR_DEVICE_ERROR))?;
        }
    }
    if let Some(total) = total {
        encoder
            .u8(5)
            .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
            .u64(u64::try_from(total).map_err(|_| Error::from(CKR_DEVICE_ERROR))?)
            .map_err(|_| Error::from(CKR_DEVICE_ERROR))?;
    }
    state.persistent_change = true;
    Ok(response)
}

fn authenticator_get_info(state: &FidoState) -> Result<Vec<u8>, Error> {
    let encrypted_identifier = encrypted_device_identifier(state)?;
    let mut response = vec![CTAP2_OK];
    let mut encoder = Encoder::new(&mut response);
    encoder
        .map(10)
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
        .u16(MAX_CTAP_MESSAGE_SIZE)
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
        .u8(10)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
        .array(
            u64::try_from(state.credential_algorithms.len())
                .map_err(|_| Error::from(CKR_DEVICE_ERROR))?,
        )
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?;
    for algorithm in &state.credential_algorithms {
        encoder
            .map(2)
            .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
            .str("alg")
            .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
            .i64(algorithm.cose_identifier())
            .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
            .str("type")
            .map_err(|_| Error::from(CKR_DEVICE_ERROR))?
            .str("public-key")
            .map_err(|_| Error::from(CKR_DEVICE_ERROR))?;
    }
    encoder
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
    state.persistent_change = true;
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
    state.persistent_change = true;
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
            && ciphertext.len() % AES_BLOCK_SIZE == 0 =>
        {
            aes_cbc(key, &[0u8; AES_BLOCK_SIZE], ciphertext, Direction::Decrypt)
        }
        2 if key.len() == 64
            && ciphertext.len() >= AES_BLOCK_SIZE * 2
            && ciphertext.len() % AES_BLOCK_SIZE == 0 =>
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
    if plaintext.len() % AES_BLOCK_SIZE != 0 {
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

    #[test]
    fn selection_accepts_an_empty_request_for_transport_gated_touch() {
        let mut state = FidoState::new([0x11; 16], FidoConfiguration::default());
        assert_eq!(exchange(&mut state, &[AUTHENTICATOR_SELECTION]), [CTAP2_OK]);
        assert_eq!(
            exchange(&mut state, &[AUTHENTICATOR_SELECTION, 0xa0]),
            [CTAP1_ERR_INVALID_COMMAND]
        );
    }

    #[test]
    fn assertion_user_entity_respects_discoverability_and_verification() {
        let mut state = FidoState::new(*b"virtual-test-id!", FidoConfiguration::default());
        state
            .credentials
            .push(test_credential(vec![0x22; 32], "privacy.example", None));

        let response = standard_assertion_response(&mut state, 0, &[0x33; 32], None).unwrap();
        assert_eq!(assertion_user_field_count(&response[1..]), Some(1));

        state.assertion_user_verified = true;
        let response = standard_assertion_response(&mut state, 0, &[0x44; 32], None).unwrap();
        assert_eq!(assertion_user_field_count(&response[1..]), Some(3));

        state.credentials[0].discoverable = false;
        let response = standard_assertion_response(&mut state, 0, &[0x55; 32], None).unwrap();
        assert_eq!(assertion_user_field_count(&response[1..]), None);
    }
    use p256::ecdsa::{DerSignature, Signature, VerifyingKey};
    use signature::{hazmat::PrehashVerifier, Verifier};

    const CONTEXT: &[u8] = b"ARKG-P256.test vectors";
    const EXPECTED_PUBLIC_KEY: &str = "04572a111ce5cfd2a67d56a0f7c684184b16ccd212490dc9c5b579df749647d107dac2a1b197cc10d2376559ad6df6bc107318d5cfb90def9f4a1f5347e086c2cd";
    const EXPECTED_TICKET: &str = "27987995f184a44cfa548d104b0a461d0487fc739dbcdabc293ac5469221da91b220e04c681074ec4692a76ffacb9043dec2847ea9060fd42da267f66852e63589f0c00dc88f290d660c65a65a50c86361";

    #[test]
    fn ppuat_decrypts_a_stable_device_identifier() {
        let identifier = *b"virtual-test-id!";
        let state = FidoState::new(identifier, FidoConfiguration::default());
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
        let mut state = FidoState::new(*b"virtual-test-id!", FidoConfiguration::default());
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
        let mut state = FidoState::new(*b"virtual-test-id!", FidoConfiguration::default());
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
                        options.push((decoder.str().unwrap().to_owned(), decoder.bool().unwrap()));
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
                ("rk".to_owned(), true),
                ("plat".to_owned(), false),
                ("credMgmt".to_owned(), true),
                ("clientPin".to_owned(), true),
                ("perCredMgmtRO".to_owned(), true),
                ("pinUvAuthToken".to_owned(), true),
            ]
        );
        assert_eq!(encrypted_identifier.unwrap().len(), AES_BLOCK_SIZE * 2);
    }

    #[test]
    fn credential_management_reports_resident_credential_metadata() {
        let mut state = FidoState::new(*b"virtual-test-id!", FidoConfiguration::default());
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
        assert_eq!(decoder.u8().unwrap(), 0);
        assert_eq!(decoder.u8().unwrap(), 2);
        assert_eq!(decoder.u8().unwrap(), 100);
    }

    #[test]
    fn credential_management_deletes_the_preview_sign_parent_credential() {
        let mut state = FidoState::new(*b"virtual-test-id!", FidoConfiguration::default());
        let credential_id = vec![0xa5; 32];
        state.credentials.push(test_credential(
            credential_id.clone(),
            "preview-sign.pkcs11rs.invalid",
            Some(vec![0x5a; 48]),
        ));

        let mut parameters = Vec::new();
        Encoder::new(&mut parameters)
            .map(1)
            .unwrap()
            .u8(2)
            .unwrap()
            .map(2)
            .unwrap()
            .str("id")
            .unwrap()
            .bytes(&credential_id)
            .unwrap()
            .str("type")
            .unwrap()
            .str("public-key")
            .unwrap();
        let mut authenticated = vec![6];
        authenticated.extend_from_slice(&parameters);

        let mut request = vec![AUTHENTICATOR_CREDENTIAL_MANAGEMENT];
        let mut encoder = Encoder::new(&mut request);
        encoder
            .map(4)
            .unwrap()
            .u8(1)
            .unwrap()
            .u8(6)
            .unwrap()
            .u8(2)
            .unwrap();
        encoder.writer_mut().extend_from_slice(&parameters);
        encoder
            .u8(3)
            .unwrap()
            .u8(2)
            .unwrap()
            .u8(4)
            .unwrap()
            .bytes(&pin_auth(&authenticated))
            .unwrap();

        assert_eq!(exchange(&mut state, &request), [CTAP2_OK]);
        assert!(state.credentials.is_empty());
        assert_eq!(exchange(&mut state, &request), [CTAP2_ERR_NO_CREDENTIALS]);
    }

    #[test]
    fn standard_credentials_start_empty_persist_and_use_the_100_slot_capacity() {
        let identifier = *b"virtual-test-id!";
        let mut state = FidoState::new(identifier, FidoConfiguration::default());
        assert!(state.credentials.is_empty());

        assert_eq!(
            create_standard_credential(&mut state, "one.example", 1)[0],
            CTAP2_OK
        );
        assert_eq!(
            create_standard_credential(&mut state, "two.example", 2)[0],
            CTAP2_OK
        );
        assert_eq!(state.credentials.len(), 2);
        assert_ne!(
            state.credentials[0].credential_id,
            state.credentials[1].credential_id
        );

        let encoded = state.encode_persistent().unwrap();
        let mut restored =
            FidoState::decode_persistent(&encoded, identifier, FidoConfiguration::default())
                .unwrap();
        assert_eq!(restored.credentials.len(), 2);
        assert_eq!(restored.credentials[0].rp_id, "one.example");
        assert_eq!(restored.credentials[1].user_id, [2; 16]);
        assert_eq!(
            restored.credentials[0]
                .private_key
                .serialized()
                .unwrap()
                .as_slice(),
            state.credentials[0]
                .private_key
                .serialized()
                .unwrap()
                .as_slice()
        );

        let client_data_hash = [0x44; 32];
        let credential_id = restored.credentials[0].credential_id.clone();
        let CredentialPrivateKey {
            algorithm: FidoCredentialAlgorithm::Es256,
            key: SoftwareSigningKey::P256(private_key),
        } = &restored.credentials[0].private_key
        else {
            panic!("standard test credential should use ES256");
        };
        let verifying_key = VerifyingKey::from(private_key.public_key());
        let mut assertion = vec![AUTHENTICATOR_GET_ASSERTION];
        Encoder::new(&mut assertion)
            .map(5)
            .unwrap()
            .u8(1)
            .unwrap()
            .str("one.example")
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
            .str("id")
            .unwrap()
            .bytes(&credential_id)
            .unwrap()
            .str("type")
            .unwrap()
            .str("public-key")
            .unwrap()
            .u8(6)
            .unwrap()
            .bytes(&pin_auth(&client_data_hash))
            .unwrap()
            .u8(7)
            .unwrap()
            .u8(2)
            .unwrap();
        let assertion = exchange(&mut restored, &assertion);
        assert_eq!(assertion[0], CTAP2_OK);
        let auth_data = assertion_authenticator_data(&assertion[1..]);
        let signature = assertion_signature(&assertion[1..]);
        let mut signed = auth_data;
        signed.extend_from_slice(&client_data_hash);
        verifying_key.verify(&signed, &signature).unwrap();

        let mut full = FidoState::new(identifier, FidoConfiguration::default());
        for index in 0..MAX_RESIDENT_CREDENTIALS {
            full.credentials.push(test_credential(
                vec![u8::try_from(index).unwrap(); 32],
                "capacity.example",
                None,
            ));
        }
        assert_eq!(
            create_standard_credential(&mut full, "full.example", 0)[0],
            CTAP2_ERR_KEY_STORE_FULL
        );
    }

    #[test]
    fn credential_management_enumerates_multiple_relying_parties_and_credentials() {
        let mut state = FidoState::new(*b"virtual-test-id!", FidoConfiguration::default());
        assert_eq!(
            create_standard_credential(&mut state, "one.example", 1)[0],
            CTAP2_OK
        );
        assert_eq!(
            create_standard_credential(&mut state, "one.example", 2)[0],
            CTAP2_OK
        );
        assert_eq!(
            create_standard_credential(&mut state, "two.example", 3)[0],
            CTAP2_OK
        );

        assert_eq!(
            exchange(&mut state, &management_request(2, None))[0],
            CTAP2_OK
        );
        let next_rp = management_request(3, None);
        assert_eq!(exchange(&mut state, &next_rp)[0], CTAP2_OK);
        assert_eq!(exchange(&mut state, &next_rp), [CTAP2_ERR_NO_CREDENTIALS]);

        let mut parameters = Vec::new();
        Encoder::new(&mut parameters)
            .map(1)
            .unwrap()
            .u8(1)
            .unwrap()
            .bytes(&Sha256::digest(b"one.example"))
            .unwrap();
        assert_eq!(
            exchange(&mut state, &management_request(4, Some(&parameters)))[0],
            CTAP2_OK
        );
        let next_credential = management_request(5, None);
        assert_eq!(exchange(&mut state, &next_credential)[0], CTAP2_OK);
        assert_eq!(
            exchange(&mut state, &next_credential),
            [CTAP2_ERR_NO_CREDENTIALS]
        );
    }

    #[test]
    fn preview_sign_registration_and_assertion_complete_a_verified_cycle() {
        let mut state = FidoState::new(*b"virtual-test-id!", FidoConfiguration::default());
        let client_data_hash = [0x33; 32];
        let pin_auth = pin_auth(&client_data_hash);

        let mut registration = vec![AUTHENTICATOR_MAKE_CREDENTIAL];
        Encoder::new(&mut registration)
            .map(8)
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
            .u8(3)
            .unwrap()
            .map(3)
            .unwrap()
            .str("id")
            .unwrap()
            .bytes(b"preview-user")
            .unwrap()
            .str("name")
            .unwrap()
            .str("preview")
            .unwrap()
            .str("displayName")
            .unwrap()
            .str("Preview User")
            .unwrap()
            .u8(4)
            .unwrap()
            .array(1)
            .unwrap()
            .map(2)
            .unwrap()
            .str("alg")
            .unwrap()
            .i8(-7)
            .unwrap()
            .str("type")
            .unwrap()
            .str("public-key")
            .unwrap()
            .u8(6)
            .unwrap()
            .map(1)
            .unwrap()
            .str("previewSign")
            .unwrap()
            .map(0)
            .unwrap()
            .u8(7)
            .unwrap()
            .map(1)
            .unwrap()
            .str("rk")
            .unwrap()
            .bool(true)
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
        let credential_id = state.credentials[0].credential_id.clone();
        let signing_key_handle = state.credentials[0]
            .preview
            .as_ref()
            .unwrap()
            .signing_key_handle
            .clone();

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
            .bytes(&credential_id)
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
            .bytes(&signing_key_handle)
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

    fn create_standard_credential(state: &mut FidoState, rp_id: &str, marker: u8) -> Vec<u8> {
        let request = make_credential_request(rp_id, marker, &[-7]);
        exchange(state, &request)
    }

    fn make_credential_request(rp_id: &str, marker: u8, algorithms: &[i64]) -> Vec<u8> {
        let client_data_hash = [marker; 32];
        let mut request = vec![AUTHENTICATOR_MAKE_CREDENTIAL];
        let mut encoder = Encoder::new(&mut request);
        encoder
            .map(7)
            .unwrap()
            .u8(1)
            .unwrap()
            .bytes(&client_data_hash)
            .unwrap()
            .u8(2)
            .unwrap()
            .map(2)
            .unwrap()
            .str("id")
            .unwrap()
            .str(rp_id)
            .unwrap()
            .str("name")
            .unwrap()
            .str(rp_id)
            .unwrap()
            .u8(3)
            .unwrap()
            .map(3)
            .unwrap()
            .str("id")
            .unwrap()
            .bytes(&[marker; 16])
            .unwrap()
            .str("name")
            .unwrap()
            .str("test-user")
            .unwrap()
            .str("displayName")
            .unwrap()
            .str("Test User")
            .unwrap()
            .u8(4)
            .unwrap()
            .array(u64::try_from(algorithms.len()).unwrap())
            .unwrap();
        for algorithm in algorithms {
            encoder
                .map(2)
                .unwrap()
                .str("alg")
                .unwrap()
                .i64(*algorithm)
                .unwrap()
                .str("type")
                .unwrap()
                .str("public-key")
                .unwrap();
        }
        encoder
            .u8(7)
            .unwrap()
            .map(1)
            .unwrap()
            .str("rk")
            .unwrap()
            .bool(true)
            .unwrap()
            .u8(8)
            .unwrap()
            .bytes(&pin_auth(&client_data_hash))
            .unwrap()
            .u8(9)
            .unwrap()
            .u8(2)
            .unwrap();
        request
    }

    #[test]
    fn inspects_ordered_make_credential_algorithms() {
        let mut request = vec![AUTHENTICATOR_MAKE_CREDENTIAL];
        let mut encoder = Encoder::new(&mut request);
        encoder
            .map(4)
            .unwrap()
            .u8(1)
            .unwrap()
            .bytes(&[0x55; 32])
            .unwrap()
            .u8(2)
            .unwrap()
            .map(1)
            .unwrap()
            .str("id")
            .unwrap()
            .str("example.com")
            .unwrap()
            .u8(3)
            .unwrap()
            .map(1)
            .unwrap()
            .str("id")
            .unwrap()
            .bytes(b"test-user")
            .unwrap()
            .u8(4)
            .unwrap()
            .array(4)
            .unwrap();
        for (algorithm, key_type) in [
            (-48, "public-key"),
            (-7, "public-key"),
            (-49, "public-key"),
            (-50, "not-public-key"),
        ] {
            encoder
                .map(2)
                .unwrap()
                .str("alg")
                .unwrap()
                .i64(algorithm)
                .unwrap()
                .str("type")
                .unwrap()
                .str(key_type)
                .unwrap();
        }

        assert_eq!(
            make_credential_algorithms(&request),
            Some(vec![-48, -7, -49])
        );
    }

    #[test]
    fn selects_strongest_offered_ml_dsa_before_classical_algorithms() {
        let state = FidoState::new(*b"virtual-test-id!", FidoConfiguration::default());
        let request = make_credential_request("preference.example", 0x61, &[-7, -48, -49, -50]);
        assert_eq!(
            state.selected_make_credential_algorithm(&request),
            Some(FidoCredentialAlgorithm::MlDsa87)
        );

        let request = make_credential_request("fallback.example", 0x62, &[-999, -7]);
        assert_eq!(
            state.selected_make_credential_algorithm(&request),
            Some(FidoCredentialAlgorithm::Es256)
        );
    }

    #[test]
    fn esp256_credentials_persist_and_complete_verified_assertions() {
        let algorithm = FidoCredentialAlgorithm::Esp256;
        let identifier = *b"virtual-test-id!";
        let configuration =
            FidoConfiguration::default().with_credential_algorithms(vec![algorithm]);
        let mut state = FidoState::new(identifier, configuration);
        let request =
            make_credential_request("esp256.example", 0x09, &[algorithm.cose_identifier()]);
        assert_eq!(exchange(&mut state, &request)[0], CTAP2_OK);
        assert_eq!(state.credentials[0].private_key.algorithm(), algorithm);
        assert_ec2_public_key(&state.credentials[0].public_key_cose, algorithm, 1, 32);

        let encoded = state.encode_persistent().unwrap();
        let configuration =
            FidoConfiguration::default().with_credential_algorithms(vec![algorithm]);
        let mut restored =
            FidoState::decode_persistent(&encoded, identifier, configuration).unwrap();
        let CredentialPrivateKey {
            algorithm: FidoCredentialAlgorithm::Esp256,
            key: SoftwareSigningKey::P256(key),
        } = &restored.credentials[0].private_key
        else {
            panic!("ESP256 credential did not restore its P-256 key");
        };
        let verifying_key = VerifyingKey::from(key.public_key());
        let client_data_hash = [0x79; 32];
        let assertion_request = get_assertion_request(
            "esp256.example",
            &restored.credentials[0].credential_id,
            &client_data_hash,
        );
        let assertion = exchange(&mut restored, &assertion_request);
        assert_eq!(assertion[0], CTAP2_OK);
        let mut signed = assertion_authenticator_data(&assertion[1..]);
        signed.extend_from_slice(&client_data_hash);
        verifying_key
            .verify(&signed, &assertion_signature(&assertion[1..]))
            .unwrap();
    }

    #[test]
    fn ed25519_credentials_persist_and_complete_verified_assertions() {
        let algorithm = FidoCredentialAlgorithm::Ed25519;
        let identifier = *b"virtual-test-id!";
        let configuration =
            FidoConfiguration::default().with_credential_algorithms(vec![algorithm]);
        let mut state = FidoState::new(identifier, configuration);
        let request =
            make_credential_request("ed25519.example", 0x19, &[algorithm.cose_identifier()]);
        assert_eq!(exchange(&mut state, &request)[0], CTAP2_OK);
        assert_okp_public_key(&state.credentials[0].public_key_cose, algorithm, 6, 32);

        let encoded = state.encode_persistent().unwrap();
        let configuration =
            FidoConfiguration::default().with_credential_algorithms(vec![algorithm]);
        let mut restored =
            FidoState::decode_persistent(&encoded, identifier, configuration).unwrap();
        let CredentialPrivateKey {
            algorithm: FidoCredentialAlgorithm::Ed25519,
            key: SoftwareSigningKey::Ed25519(key),
        } = &restored.credentials[0].private_key
        else {
            panic!("Ed25519 credential did not restore its signing key");
        };
        let verifying_key = key.verifying_key();
        let client_data_hash = [0x78; 32];
        let assertion_request = get_assertion_request(
            "ed25519.example",
            &restored.credentials[0].credential_id,
            &client_data_hash,
        );
        let assertion = exchange(&mut restored, &assertion_request);
        assert_eq!(assertion[0], CTAP2_OK);
        let mut signed = assertion_authenticator_data(&assertion[1..]);
        signed.extend_from_slice(&client_data_hash);
        let signature = ed25519_dalek::Signature::try_from(
            assertion_signature_bytes(&assertion[1..]).as_slice(),
        )
        .unwrap();
        verifying_key.verify(&signed, &signature).unwrap();
    }

    #[test]
    fn esp384_credentials_persist_and_complete_verified_assertions() {
        let algorithm = FidoCredentialAlgorithm::Esp384;
        let identifier = *b"virtual-test-id!";
        let configuration =
            FidoConfiguration::default().with_credential_algorithms(vec![algorithm]);
        let mut state = FidoState::new(identifier, configuration);
        let request =
            make_credential_request("esp384.example", 0x51, &[algorithm.cose_identifier()]);
        assert_eq!(exchange(&mut state, &request)[0], CTAP2_OK);
        assert_ec2_public_key(&state.credentials[0].public_key_cose, algorithm, 2, 48);

        let encoded = state.encode_persistent().unwrap();
        let configuration =
            FidoConfiguration::default().with_credential_algorithms(vec![algorithm]);
        let mut restored =
            FidoState::decode_persistent(&encoded, identifier, configuration).unwrap();
        let CredentialPrivateKey {
            algorithm: FidoCredentialAlgorithm::Esp384,
            key: SoftwareSigningKey::P384(key),
        } = &restored.credentials[0].private_key
        else {
            panic!("ESP384 credential did not restore its P-384 key");
        };
        let verifying_key = p384::ecdsa::VerifyingKey::from(key.public_key());
        let client_data_hash = [0x77; 32];
        let assertion_request = get_assertion_request(
            "esp384.example",
            &restored.credentials[0].credential_id,
            &client_data_hash,
        );
        let assertion = exchange(&mut restored, &assertion_request);
        assert_eq!(assertion[0], CTAP2_OK);
        let mut signed = assertion_authenticator_data(&assertion[1..]);
        signed.extend_from_slice(&client_data_hash);
        let signature =
            p384::ecdsa::DerSignature::from_bytes(&assertion_signature_bytes(&assertion[1..]))
                .unwrap();
        verifying_key.verify(&signed, &signature).unwrap();
    }

    #[test]
    fn esp512_credentials_persist_and_complete_verified_assertions() {
        let algorithm = FidoCredentialAlgorithm::Esp512;
        let identifier = *b"virtual-test-id!";
        let configuration =
            FidoConfiguration::default().with_credential_algorithms(vec![algorithm]);
        let mut state = FidoState::new(identifier, configuration);
        let request =
            make_credential_request("esp512.example", 0x52, &[algorithm.cose_identifier()]);
        assert_eq!(exchange(&mut state, &request)[0], CTAP2_OK);
        assert_ec2_public_key(&state.credentials[0].public_key_cose, algorithm, 3, 66);

        let encoded = state.encode_persistent().unwrap();
        let configuration =
            FidoConfiguration::default().with_credential_algorithms(vec![algorithm]);
        let mut restored =
            FidoState::decode_persistent(&encoded, identifier, configuration).unwrap();
        let CredentialPrivateKey {
            algorithm: FidoCredentialAlgorithm::Esp512,
            key: SoftwareSigningKey::P521(key),
        } = &restored.credentials[0].private_key
        else {
            panic!("ESP512 credential did not restore its P-521 key");
        };
        let verifying_key = p521::ecdsa::VerifyingKey::from(key.public_key());
        let client_data_hash = [0x76; 32];
        let assertion_request = get_assertion_request(
            "esp512.example",
            &restored.credentials[0].credential_id,
            &client_data_hash,
        );
        let assertion = exchange(&mut restored, &assertion_request);
        assert_eq!(assertion[0], CTAP2_OK);
        let mut signed = assertion_authenticator_data(&assertion[1..]);
        signed.extend_from_slice(&client_data_hash);
        let signature =
            p521::ecdsa::DerSignature::from_bytes(&assertion_signature_bytes(&assertion[1..]))
                .unwrap();
        verifying_key.verify(&signed, &signature).unwrap();
    }

    #[test]
    fn es256k_credentials_persist_and_complete_verified_assertions() {
        let algorithm = FidoCredentialAlgorithm::Es256K;
        let identifier = *b"virtual-test-id!";
        let configuration =
            FidoConfiguration::default().with_credential_algorithms(vec![algorithm]);
        let mut state = FidoState::new(identifier, configuration);
        let request =
            make_credential_request("es256k.example", 0x47, &[algorithm.cose_identifier()]);
        assert_eq!(exchange(&mut state, &request)[0], CTAP2_OK);
        assert_ec2_public_key(&state.credentials[0].public_key_cose, algorithm, 8, 32);

        let encoded = state.encode_persistent().unwrap();
        let configuration =
            FidoConfiguration::default().with_credential_algorithms(vec![algorithm]);
        let mut restored =
            FidoState::decode_persistent(&encoded, identifier, configuration).unwrap();
        let CredentialPrivateKey {
            algorithm: FidoCredentialAlgorithm::Es256K,
            key: SoftwareSigningKey::K256(key),
        } = &restored.credentials[0].private_key
        else {
            panic!("ES256K credential did not restore its secp256k1 key");
        };
        let verifying_key = k256::ecdsa::VerifyingKey::from(key.public_key());
        let client_data_hash = [0x75; 32];
        let assertion_request = get_assertion_request(
            "es256k.example",
            &restored.credentials[0].credential_id,
            &client_data_hash,
        );
        let assertion = exchange(&mut restored, &assertion_request);
        assert_eq!(assertion[0], CTAP2_OK);
        let mut signed = assertion_authenticator_data(&assertion[1..]);
        signed.extend_from_slice(&client_data_hash);
        let signature =
            k256::ecdsa::DerSignature::from_bytes(&assertion_signature_bytes(&assertion[1..]))
                .unwrap();
        verifying_key.verify(&signed, &signature).unwrap();
    }

    #[test]
    fn ps256_credentials_persist_and_complete_verified_assertions() {
        assert_rsa_cycle(FidoCredentialAlgorithm::Ps256, "ps256.example", 0x37);
    }

    #[test]
    fn ps384_credentials_persist_and_complete_verified_assertions() {
        assert_rsa_cycle(FidoCredentialAlgorithm::Ps384, "ps384.example", 0x38);
    }

    #[test]
    fn ps512_credentials_persist_and_complete_verified_assertions() {
        assert_rsa_cycle(FidoCredentialAlgorithm::Ps512, "ps512.example", 0x39);
    }

    #[test]
    fn rs256_credentials_persist_and_complete_verified_assertions() {
        assert_rsa_cycle(FidoCredentialAlgorithm::Rs256, "rs256.example", 0x61);
    }

    #[test]
    fn rs384_credentials_persist_and_complete_verified_assertions() {
        assert_rsa_cycle(FidoCredentialAlgorithm::Rs384, "rs384.example", 0x62);
    }

    #[test]
    fn rs512_credentials_persist_and_complete_verified_assertions() {
        assert_rsa_cycle(FidoCredentialAlgorithm::Rs512, "rs512.example", 0x63);
    }

    fn assert_rsa_cycle(algorithm: FidoCredentialAlgorithm, rp_id: &str, request_marker: u8) {
        let identifier = *b"virtual-test-id!";
        let configuration =
            FidoConfiguration::default().with_credential_algorithms(vec![algorithm]);
        let mut state = FidoState::new(identifier, configuration);
        let request =
            make_credential_request(rp_id, request_marker, &[algorithm.cose_identifier()]);
        assert_eq!(exchange(&mut state, &request)[0], CTAP2_OK);
        assert_rsa_public_key(&state.credentials[0].public_key_cose, algorithm, 256);

        let encoded = state.encode_persistent().unwrap();
        let configuration =
            FidoConfiguration::default().with_credential_algorithms(vec![algorithm]);
        let mut restored =
            FidoState::decode_persistent(&encoded, identifier, configuration).unwrap();
        let public_key = restored.credentials[0].private_key.key.public_key();
        let client_data_hash = [request_marker; 32];
        let assertion_request = get_assertion_request(
            rp_id,
            &restored.credentials[0].credential_id,
            &client_data_hash,
        );
        let assertion = exchange(&mut restored, &assertion_request);
        assert_eq!(assertion[0], CTAP2_OK);
        let mut signed = assertion_authenticator_data(&assertion[1..]);
        signed.extend_from_slice(&client_data_hash);
        public_key
            .verify_message(
                algorithm.software_signing_algorithm(),
                &signed,
                &assertion_signature_bytes(&assertion[1..]),
            )
            .unwrap();
    }

    #[test]
    fn ml_dsa_credentials_persist_and_complete_verified_assertions() {
        assert_ml_dsa_cycle(FidoCredentialAlgorithm::MlDsa44, 1312, 2420);
        assert_ml_dsa_cycle(FidoCredentialAlgorithm::MlDsa65, 1952, 3309);
        assert_ml_dsa_cycle(FidoCredentialAlgorithm::MlDsa87, 2592, 4627);
    }

    fn assert_ml_dsa_cycle(
        algorithm: FidoCredentialAlgorithm,
        public_key_size: usize,
        signature_size: usize,
    ) {
        let identifier = *b"virtual-test-id!";
        let configuration =
            FidoConfiguration::default().with_credential_algorithms(vec![algorithm]);
        let mut state = FidoState::new(identifier, configuration);
        let request = make_credential_request(
            "ml-dsa.example",
            u8::try_from(-algorithm.cose_identifier()).unwrap(),
            &[algorithm.cose_identifier()],
        );
        let registration = exchange(&mut state, &request);
        assert_eq!(registration[0], CTAP2_OK);
        assert_eq!(state.credentials.len(), 1);
        assert_eq!(state.credentials[0].private_key.algorithm(), algorithm);
        assert_akp_public_key(
            &state.credentials[0].public_key_cose,
            algorithm,
            public_key_size,
        );

        let encoded = state.encode_persistent().unwrap();
        let configuration =
            FidoConfiguration::default().with_credential_algorithms(vec![algorithm]);
        let mut restored =
            FidoState::decode_persistent(&encoded, identifier, configuration).unwrap();
        assert_eq!(restored.credentials[0].private_key.algorithm(), algorithm);
        assert_eq!(
            restored.credentials[0]
                .private_key
                .serialized()
                .unwrap()
                .as_slice(),
            state.credentials[0]
                .private_key
                .serialized()
                .unwrap()
                .as_slice()
        );

        let client_data_hash = [0x7a; 32];
        let credential_id = restored.credentials[0].credential_id.clone();
        let assertion_request =
            get_assertion_request("ml-dsa.example", &credential_id, &client_data_hash);
        let assertion = exchange(&mut restored, &assertion_request);
        assert_eq!(assertion[0], CTAP2_OK);
        let auth_data = assertion_authenticator_data(&assertion[1..]);
        let signature = assertion_signature_bytes(&assertion[1..]);
        assert_eq!(signature.len(), signature_size);
        assert!(assertion.len() < usize::from(MAX_CTAP_MESSAGE_SIZE));
        let mut signed = auth_data;
        signed.extend_from_slice(&client_data_hash);

        let CredentialPrivateKey {
            key: SoftwareSigningKey::MlDsa(key),
            ..
        } = &restored.credentials[0].private_key
        else {
            panic!("ML-DSA test credential has a classical private key");
        };
        post_quantum::verify_ml_dsa(
            key.parameter_set(),
            &key.public_key(),
            &signed,
            &[],
            &signature,
        )
        .unwrap();
    }

    fn assert_akp_public_key(
        encoded: &[u8],
        algorithm: FidoCredentialAlgorithm,
        public_key_size: usize,
    ) {
        let mut decoder = minicbor::Decoder::new(encoded);
        assert_eq!(decoder.map().unwrap(), Some(3));
        assert_eq!(decoder.u8().unwrap(), 1);
        assert_eq!(decoder.u8().unwrap(), 7);
        assert_eq!(decoder.u8().unwrap(), 3);
        assert_eq!(decoder.i64().unwrap(), algorithm.cose_identifier());
        assert_eq!(decoder.i8().unwrap(), -1);
        assert_eq!(decoder.bytes().unwrap().len(), public_key_size);
        assert_eq!(decoder.position(), encoded.len());
    }

    fn assert_ec2_public_key(
        encoded: &[u8],
        algorithm: FidoCredentialAlgorithm,
        curve: u8,
        coordinate_length: usize,
    ) {
        let mut decoder = minicbor::Decoder::new(encoded);
        assert_eq!(decoder.map().unwrap(), Some(5));
        assert_eq!(decoder.u8().unwrap(), 1);
        assert_eq!(decoder.u8().unwrap(), 2);
        assert_eq!(decoder.u8().unwrap(), 3);
        assert_eq!(decoder.i64().unwrap(), algorithm.cose_identifier());
        assert_eq!(decoder.i8().unwrap(), -1);
        assert_eq!(decoder.u8().unwrap(), curve);
        assert_eq!(decoder.i8().unwrap(), -2);
        assert_eq!(decoder.bytes().unwrap().len(), coordinate_length);
        assert_eq!(decoder.i8().unwrap(), -3);
        assert_eq!(decoder.bytes().unwrap().len(), coordinate_length);
        assert_eq!(decoder.position(), encoded.len());
    }

    fn assert_okp_public_key(
        encoded: &[u8],
        algorithm: FidoCredentialAlgorithm,
        curve: u8,
        public_key_length: usize,
    ) {
        let mut decoder = minicbor::Decoder::new(encoded);
        assert_eq!(decoder.map().unwrap(), Some(4));
        assert_eq!(decoder.u8().unwrap(), 1);
        assert_eq!(decoder.u8().unwrap(), 1);
        assert_eq!(decoder.u8().unwrap(), 3);
        assert_eq!(decoder.i64().unwrap(), algorithm.cose_identifier());
        assert_eq!(decoder.i8().unwrap(), -1);
        assert_eq!(decoder.u8().unwrap(), curve);
        assert_eq!(decoder.i8().unwrap(), -2);
        assert_eq!(decoder.bytes().unwrap().len(), public_key_length);
        assert_eq!(decoder.position(), encoded.len());
    }

    fn assert_rsa_public_key(
        encoded: &[u8],
        algorithm: FidoCredentialAlgorithm,
        modulus_length: usize,
    ) {
        let mut decoder = minicbor::Decoder::new(encoded);
        assert_eq!(decoder.map().unwrap(), Some(4));
        assert_eq!(decoder.u8().unwrap(), 1);
        assert_eq!(decoder.u8().unwrap(), 3);
        assert_eq!(decoder.u8().unwrap(), 3);
        assert_eq!(decoder.i64().unwrap(), algorithm.cose_identifier());
        assert_eq!(decoder.i8().unwrap(), -1);
        assert_eq!(decoder.bytes().unwrap().len(), modulus_length);
        assert_eq!(decoder.i8().unwrap(), -2);
        assert_eq!(decoder.bytes().unwrap(), &[1, 0, 1]);
        assert_eq!(decoder.position(), encoded.len());
    }

    fn get_assertion_request(
        rp_id: &str,
        credential_id: &[u8],
        client_data_hash: &[u8; 32],
    ) -> Vec<u8> {
        let mut request = vec![AUTHENTICATOR_GET_ASSERTION];
        Encoder::new(&mut request)
            .map(5)
            .unwrap()
            .u8(1)
            .unwrap()
            .str(rp_id)
            .unwrap()
            .u8(2)
            .unwrap()
            .bytes(client_data_hash)
            .unwrap()
            .u8(3)
            .unwrap()
            .array(1)
            .unwrap()
            .map(2)
            .unwrap()
            .str("id")
            .unwrap()
            .bytes(credential_id)
            .unwrap()
            .str("type")
            .unwrap()
            .str("public-key")
            .unwrap()
            .u8(6)
            .unwrap()
            .bytes(&pin_auth(client_data_hash))
            .unwrap()
            .u8(7)
            .unwrap()
            .u8(2)
            .unwrap();
        request
    }

    fn management_request(subcommand: u8, parameters: Option<&[u8]>) -> Vec<u8> {
        let authenticated = if matches!(subcommand, 1 | 2 | 4 | 6 | 7) {
            let mut authenticated = vec![subcommand];
            if let Some(parameters) = parameters {
                authenticated.extend_from_slice(parameters);
            }
            Some(pin_auth(&authenticated))
        } else {
            None
        };
        let mut request = vec![AUTHENTICATOR_CREDENTIAL_MANAGEMENT];
        let mut encoder = Encoder::new(&mut request);
        encoder
            .map(1 + u64::from(parameters.is_some()) + 2 * u64::from(authenticated.is_some()))
            .unwrap()
            .u8(1)
            .unwrap()
            .u8(subcommand)
            .unwrap();
        if let Some(parameters) = parameters {
            encoder.u8(2).unwrap();
            encoder.writer_mut().extend_from_slice(parameters);
        }
        if let Some(authenticated) = authenticated {
            encoder
                .u8(3)
                .unwrap()
                .u8(2)
                .unwrap()
                .u8(4)
                .unwrap()
                .bytes(&authenticated)
                .unwrap();
        }
        request
    }

    fn test_credential(
        credential_id: Vec<u8>,
        rp_id: &str,
        preview_handle: Option<Vec<u8>>,
    ) -> ResidentCredential {
        let private_key = SecretKey::from_slice(&[0x11; 32]).unwrap();
        let public_key = private_key.public_key().to_sec1_point(false);
        ResidentCredential {
            rp_id: rp_id.to_owned(),
            rp_name: format!("{rp_id} test RP"),
            user_id: b"test-user-id".to_vec(),
            user_name: "test-user".to_owned(),
            user_display_name: "Test User".to_owned(),
            credential_id,
            private_key: CredentialPrivateKey {
                algorithm: FidoCredentialAlgorithm::Es256,
                key: SoftwareSigningKey::P256(private_key),
            },
            public_key_cose: encode_ec2(
                FidoCredentialAlgorithm::Es256.cose_identifier(),
                1,
                public_key.as_bytes(),
            )
            .unwrap(),
            counter: 0,
            discoverable: true,
            preview: preview_handle
                .map(|signing_key_handle| PreviewCredential { signing_key_handle }),
        }
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

    fn assertion_signature_bytes(response: &[u8]) -> Vec<u8> {
        let mut decoder = minicbor::Decoder::new(response);
        let count = decoder.map().unwrap().unwrap();
        for _ in 0..count {
            match decoder.u8().unwrap() {
                3 => return decoder.bytes().unwrap().to_vec(),
                _ => decoder.skip().unwrap(),
            }
        }
        panic!("assertion response did not contain a signature");
    }

    fn assertion_signature(response: &[u8]) -> DerSignature {
        DerSignature::from_bytes(&assertion_signature_bytes(response)).unwrap()
    }

    fn assertion_user_field_count(response: &[u8]) -> Option<u64> {
        let mut decoder = minicbor::Decoder::new(response);
        let count = decoder.map().unwrap().unwrap();
        for _ in 0..count {
            match decoder.u8().unwrap() {
                4 => return decoder.map().unwrap(),
                _ => decoder.skip().unwrap(),
            }
        }
        None
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
