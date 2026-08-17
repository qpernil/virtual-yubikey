//! Protocol-neutral software signing keys.
//!
//! This module owns key generation, compact private-key serialization, public
//! projection, message and prehash signing, verification, and algorithm-specific
//! controls such as RSA-PSS salt length. Callers retain responsibility for
//! protocol identifiers, public-key containers, signature formatting, policy,
//! and error mapping.

use crate::{
    post_quantum::{verify_ml_dsa, MlDsaParameterSet, MlDsaPrivateKey},
    rsa_signing::{
        rsa_sign_pkcs1v15_digest, rsa_sign_pss_digest, rsa_sign_raw, rsa_verify_pkcs1v15_digest,
        rsa_verify_pss_digest, rsa_verify_raw, RsaHashAlgorithm, RsaPssParameters,
        RsaSignatureError,
    },
};
use ed25519_dalek::SigningKey as Ed25519SigningKey;
use k256::ecdsa::SigningKey as K256SigningKey;
use k256::SecretKey as K256SecretKey;
use p256::ecdsa::SigningKey as P256SigningKey;
use p256::elliptic_curve::sec1::ToSec1Point;
use p256::SecretKey as P256SecretKey;
use p384::ecdsa::SigningKey as P384SigningKey;
use p384::SecretKey as P384SecretKey;
use p521::ecdsa::SigningKey as P521SigningKey;
use p521::SecretKey as P521SecretKey;
use rsa::pkcs8::{DecodePrivateKey, EncodePrivateKey};
use rsa::traits::{PrivateKeyParts, PublicKeyParts};
use rsa::{RsaPrivateKey, RsaPublicKey};
use signature::hazmat::{PrehashSigner, PrehashVerifier};
use signature::{Signer, Verifier};
use std::fmt;
use zeroize::Zeroizing;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SoftwareSigningAlgorithm {
    EcdsaP256Sha256,
    Ed25519,
    EcdsaP384Sha384,
    EcdsaP521Sha512,
    EcdsaSecp256k1Sha256,
    RsaPssSha256,
    RsaPssSha384,
    RsaPssSha512,
    RsaPkcs1Sha256,
    RsaPkcs1Sha384,
    RsaPkcs1Sha512,
    MlDsa(MlDsaParameterSet),
}

impl SoftwareSigningAlgorithm {
    const fn is_rsa(self) -> bool {
        matches!(
            self,
            Self::RsaPssSha256
                | Self::RsaPssSha384
                | Self::RsaPssSha512
                | Self::RsaPkcs1Sha256
                | Self::RsaPkcs1Sha384
                | Self::RsaPkcs1Sha512
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SoftwareSigningError {
    AlgorithmMismatch,
    InvalidPublicKey,
    InvalidPrivateKey,
    InvalidSignature,
    RandomnessUnavailable,
    SigningFailed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EcCurve {
    P256,
    P384,
    P521,
    Secp256k1,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SoftwarePublicKey {
    Ec {
        curve: EcCurve,
        uncompressed: Vec<u8>,
    },
    Ed25519([u8; 32]),
    MlDsa {
        parameter_set: MlDsaParameterSet,
        public_key: Vec<u8>,
    },
    Rsa {
        modulus: Vec<u8>,
        exponent: Vec<u8>,
    },
}

macro_rules! verify_ecdsa {
    ($ec:ident, $public:expr, $message:expr, $signature:expr) => {{
        let key = $ec::ecdsa::VerifyingKey::from_sec1_bytes($public)
            .map_err(|_| SoftwareSigningError::InvalidPublicKey)?;
        let signature = $ec::ecdsa::Signature::from_slice($signature)
            .map_err(|_| SoftwareSigningError::InvalidSignature)?;
        key.verify($message, &signature)
            .map_err(|_| SoftwareSigningError::InvalidSignature)
    }};
}

macro_rules! verify_ecdsa_prehash {
    ($ec:ident, $public:expr, $prehash:expr, $signature:expr) => {{
        let key = $ec::ecdsa::VerifyingKey::from_sec1_bytes($public)
            .map_err(|_| SoftwareSigningError::InvalidPublicKey)?;
        let signature = $ec::ecdsa::Signature::from_slice($signature)
            .map_err(|_| SoftwareSigningError::InvalidSignature)?;
        key.verify_prehash($prehash, &signature)
            .map_err(|_| SoftwareSigningError::InvalidSignature)
    }};
}

impl SoftwarePublicKey {
    /// Verify a raw RSA private-key operation against the caller-supplied
    /// modulus-width encoded input.
    pub fn verify_rsa_raw(
        &self,
        input: &[u8],
        signature: &[u8],
    ) -> Result<(), SoftwareSigningError> {
        let Self::Rsa { modulus, exponent } = self else {
            return Err(SoftwareSigningError::AlgorithmMismatch);
        };
        let key = rsa_public_key(modulus, exponent)?;
        rsa_verify_raw(&key, input, signature).map_err(map_rsa_verification_error)
    }

    /// Verify a signature over an unhashed message.
    ///
    /// ECDSA signatures use fixed-width `r || s`; Ed25519 and ML-DSA use their
    /// standard raw encodings. Protocol layers remain responsible for
    /// converting formats such as WebAuthn's DER-encoded ECDSA signatures.
    pub fn verify_message(
        &self,
        algorithm: SoftwareSigningAlgorithm,
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), SoftwareSigningError> {
        match (algorithm, self) {
            (
                SoftwareSigningAlgorithm::EcdsaP256Sha256,
                Self::Ec {
                    curve: EcCurve::P256,
                    uncompressed,
                },
            ) => verify_ecdsa!(p256, uncompressed, message, signature),
            (
                SoftwareSigningAlgorithm::EcdsaP384Sha384,
                Self::Ec {
                    curve: EcCurve::P384,
                    uncompressed,
                },
            ) => verify_ecdsa!(p384, uncompressed, message, signature),
            (
                SoftwareSigningAlgorithm::EcdsaP521Sha512,
                Self::Ec {
                    curve: EcCurve::P521,
                    uncompressed,
                },
            ) => verify_ecdsa!(p521, uncompressed, message, signature),
            (
                SoftwareSigningAlgorithm::EcdsaSecp256k1Sha256,
                Self::Ec {
                    curve: EcCurve::Secp256k1,
                    uncompressed,
                },
            ) => verify_ecdsa!(k256, uncompressed, message, signature),
            (SoftwareSigningAlgorithm::Ed25519, Self::Ed25519(public)) => {
                let key = ed25519_dalek::VerifyingKey::from_bytes(public)
                    .map_err(|_| SoftwareSigningError::InvalidPublicKey)?;
                let signature = ed25519_dalek::Signature::try_from(signature)
                    .map_err(|_| SoftwareSigningError::InvalidSignature)?;
                key.verify(message, &signature)
                    .map_err(|_| SoftwareSigningError::InvalidSignature)
            }
            (
                SoftwareSigningAlgorithm::MlDsa(expected),
                Self::MlDsa {
                    parameter_set,
                    public_key,
                },
            ) if expected == *parameter_set => {
                verify_ml_dsa(*parameter_set, public_key, message, &[], signature)
                    .map_err(|_| SoftwareSigningError::InvalidSignature)
            }
            (
                algorithm @ (SoftwareSigningAlgorithm::RsaPssSha256
                | SoftwareSigningAlgorithm::RsaPssSha384
                | SoftwareSigningAlgorithm::RsaPssSha512
                | SoftwareSigningAlgorithm::RsaPkcs1Sha256
                | SoftwareSigningAlgorithm::RsaPkcs1Sha384
                | SoftwareSigningAlgorithm::RsaPkcs1Sha512),
                Self::Rsa { modulus, exponent },
            ) => {
                let key = RsaPublicKey::new(
                    rsa::BigUint::from_bytes_be(modulus),
                    rsa::BigUint::from_bytes_be(exponent),
                )
                .map_err(|_| SoftwareSigningError::InvalidPublicKey)?;
                verify_rsa_message(algorithm, &key, message, signature)
            }
            _ => Err(SoftwareSigningError::AlgorithmMismatch),
        }
    }

    /// Verify a signature over a digest supplied by the caller.
    ///
    /// This is available for ECDSA and RSA. Ed25519 and ML-DSA define their
    /// own message processing and therefore use [`Self::verify_message`].
    pub fn verify_prehash(
        &self,
        algorithm: SoftwareSigningAlgorithm,
        prehash: &[u8],
        signature: &[u8],
    ) -> Result<(), SoftwareSigningError> {
        match (algorithm, self) {
            (
                SoftwareSigningAlgorithm::EcdsaP256Sha256,
                Self::Ec {
                    curve: EcCurve::P256,
                    uncompressed,
                },
            ) => verify_ecdsa_prehash!(p256, uncompressed, prehash, signature),
            (
                SoftwareSigningAlgorithm::EcdsaP384Sha384,
                Self::Ec {
                    curve: EcCurve::P384,
                    uncompressed,
                },
            ) => verify_ecdsa_prehash!(p384, uncompressed, prehash, signature),
            (
                SoftwareSigningAlgorithm::EcdsaP521Sha512,
                Self::Ec {
                    curve: EcCurve::P521,
                    uncompressed,
                },
            ) => verify_ecdsa_prehash!(p521, uncompressed, prehash, signature),
            (
                SoftwareSigningAlgorithm::EcdsaSecp256k1Sha256,
                Self::Ec {
                    curve: EcCurve::Secp256k1,
                    uncompressed,
                },
            ) => verify_ecdsa_prehash!(k256, uncompressed, prehash, signature),
            (
                algorithm @ (SoftwareSigningAlgorithm::RsaPssSha256
                | SoftwareSigningAlgorithm::RsaPssSha384
                | SoftwareSigningAlgorithm::RsaPssSha512
                | SoftwareSigningAlgorithm::RsaPkcs1Sha256
                | SoftwareSigningAlgorithm::RsaPkcs1Sha384
                | SoftwareSigningAlgorithm::RsaPkcs1Sha512),
                Self::Rsa { modulus, exponent },
            ) => {
                let key = rsa_public_key(modulus, exponent)?;
                verify_rsa_prehash(algorithm, &key, prehash, signature, None)
            }
            _ => Err(SoftwareSigningError::AlgorithmMismatch),
        }
    }

    /// Verify an RSA-PSS signature over a digest with an explicit salt length.
    pub fn verify_rsa_pss_prehash(
        &self,
        algorithm: SoftwareSigningAlgorithm,
        prehash: &[u8],
        salt_length: usize,
        signature: &[u8],
    ) -> Result<(), SoftwareSigningError> {
        let Self::Rsa { modulus, exponent } = self else {
            return Err(SoftwareSigningError::AlgorithmMismatch);
        };
        let key = rsa_public_key(modulus, exponent)?;
        verify_rsa_prehash(algorithm, &key, prehash, signature, Some(salt_length))
    }
}

fn rsa_public_key(modulus: &[u8], exponent: &[u8]) -> Result<RsaPublicKey, SoftwareSigningError> {
    RsaPublicKey::new(
        rsa::BigUint::from_bytes_be(modulus),
        rsa::BigUint::from_bytes_be(exponent),
    )
    .map_err(|_| SoftwareSigningError::InvalidPublicKey)
}

fn rsa_profile(algorithm: SoftwareSigningAlgorithm) -> Option<(RsaHashAlgorithm, bool)> {
    match algorithm {
        SoftwareSigningAlgorithm::RsaPssSha256 => Some((RsaHashAlgorithm::Sha256, true)),
        SoftwareSigningAlgorithm::RsaPssSha384 => Some((RsaHashAlgorithm::Sha384, true)),
        SoftwareSigningAlgorithm::RsaPssSha512 => Some((RsaHashAlgorithm::Sha512, true)),
        SoftwareSigningAlgorithm::RsaPkcs1Sha256 => Some((RsaHashAlgorithm::Sha256, false)),
        SoftwareSigningAlgorithm::RsaPkcs1Sha384 => Some((RsaHashAlgorithm::Sha384, false)),
        SoftwareSigningAlgorithm::RsaPkcs1Sha512 => Some((RsaHashAlgorithm::Sha512, false)),
        _ => None,
    }
}

fn verify_rsa_message(
    algorithm: SoftwareSigningAlgorithm,
    key: &RsaPublicKey,
    message: &[u8],
    signature: &[u8],
) -> Result<(), SoftwareSigningError> {
    let (hash, _) = rsa_profile(algorithm).ok_or(SoftwareSigningError::AlgorithmMismatch)?;
    verify_rsa_prehash(algorithm, key, &hash.digest(message), signature, None)
}

fn verify_rsa_prehash(
    algorithm: SoftwareSigningAlgorithm,
    key: &RsaPublicKey,
    prehash: &[u8],
    signature: &[u8],
    pss_salt_length: Option<usize>,
) -> Result<(), SoftwareSigningError> {
    let (hash, pss) = rsa_profile(algorithm).ok_or(SoftwareSigningError::AlgorithmMismatch)?;
    let result = if pss {
        rsa_verify_pss_digest(
            key,
            RsaPssParameters {
                hash,
                mgf_hash: hash,
                salt_length: pss_salt_length.unwrap_or_else(|| hash.output_length()),
            },
            prehash,
            signature,
        )
    } else {
        rsa_verify_pkcs1v15_digest(key, hash, prehash, signature)
    };
    result.map_err(map_rsa_verification_error)
}

fn map_rsa_verification_error(error: RsaSignatureError) -> SoftwareSigningError {
    match error {
        RsaSignatureError::InvalidKey => SoftwareSigningError::InvalidPublicKey,
        RsaSignatureError::InputTooLong
        | RsaSignatureError::InputOutOfRange
        | RsaSignatureError::InvalidDigestLength
        | RsaSignatureError::InvalidSignature
        | RsaSignatureError::RandomnessUnavailable
        | RsaSignatureError::OperationFailed => SoftwareSigningError::InvalidSignature,
    }
}

/// A signature in the algorithm's fixed-width native representation.
///
/// ECDSA values are the concatenated, fixed-width `r || s` form. Ed25519 and
/// ML-DSA values are their standard raw signature encodings.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SoftwareSignature(Vec<u8>);

impl SoftwareSignature {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

#[derive(Clone)]
pub enum SoftwareSigningKey {
    P256(P256SecretKey),
    Ed25519(Ed25519SigningKey),
    P384(P384SecretKey),
    P521(P521SecretKey),
    K256(K256SecretKey),
    Rsa(Box<RsaPrivateKey>),
    MlDsa(MlDsaPrivateKey),
}

impl fmt::Debug for SoftwareSigningKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SoftwareSigningKey")
            .field("kind", &self.kind_name())
            .finish_non_exhaustive()
    }
}

impl SoftwareSigningKey {
    pub fn generate(algorithm: SoftwareSigningAlgorithm) -> Result<Self, SoftwareSigningError> {
        match algorithm {
            SoftwareSigningAlgorithm::EcdsaP256Sha256 => random_p256_secret().map(Self::P256),
            SoftwareSigningAlgorithm::Ed25519 => {
                let mut seed = Zeroizing::new([0_u8; 32]);
                getrandom::fill(seed.as_mut())
                    .map_err(|_| SoftwareSigningError::RandomnessUnavailable)?;
                Ok(Self::Ed25519(Ed25519SigningKey::from_bytes(&seed)))
            }
            SoftwareSigningAlgorithm::EcdsaP384Sha384 => random_p384_secret().map(Self::P384),
            SoftwareSigningAlgorithm::EcdsaP521Sha512 => random_p521_secret().map(Self::P521),
            SoftwareSigningAlgorithm::EcdsaSecp256k1Sha256 => random_k256_secret().map(Self::K256),
            SoftwareSigningAlgorithm::RsaPssSha256
            | SoftwareSigningAlgorithm::RsaPssSha384
            | SoftwareSigningAlgorithm::RsaPssSha512
            | SoftwareSigningAlgorithm::RsaPkcs1Sha256
            | SoftwareSigningAlgorithm::RsaPkcs1Sha384
            | SoftwareSigningAlgorithm::RsaPkcs1Sha512 => {
                let mut key = RsaPrivateKey::new(&mut rsa::rand_core::OsRng, 2_048)
                    .map_err(|_| SoftwareSigningError::RandomnessUnavailable)?;
                key.precompute()
                    .map_err(|_| SoftwareSigningError::InvalidPrivateKey)?;
                Ok(Self::Rsa(Box::new(key)))
            }
            SoftwareSigningAlgorithm::MlDsa(parameter_set) => {
                MlDsaPrivateKey::generate(parameter_set)
                    .map(Self::MlDsa)
                    .map_err(|_| SoftwareSigningError::RandomnessUnavailable)
            }
        }
    }

    /// Generate an RSA key with an explicit modulus size.
    pub fn generate_rsa(modulus_bits: usize) -> Result<Self, SoftwareSigningError> {
        let mut key = RsaPrivateKey::new(&mut rsa::rand_core::OsRng, modulus_bits)
            .map_err(|_| SoftwareSigningError::RandomnessUnavailable)?;
        key.precompute()
            .map_err(|_| SoftwareSigningError::InvalidPrivateKey)?;
        Ok(Self::Rsa(Box::new(key)))
    }

    /// Reconstruct an RSA private key from its two primes and public exponent.
    pub fn from_rsa_primes(
        p: &[u8],
        q: &[u8],
        public_exponent: &[u8],
    ) -> Result<Self, SoftwareSigningError> {
        let mut key = RsaPrivateKey::from_p_q(
            rsa::BigUint::from_bytes_be(p),
            rsa::BigUint::from_bytes_be(q),
            rsa::BigUint::from_bytes_be(public_exponent),
        )
        .map_err(|_| SoftwareSigningError::InvalidPrivateKey)?;
        key.precompute()
            .map_err(|_| SoftwareSigningError::InvalidPrivateKey)?;
        Ok(Self::Rsa(Box::new(key)))
    }

    pub fn from_serialized(
        algorithm: SoftwareSigningAlgorithm,
        serialized: &[u8],
    ) -> Result<Self, SoftwareSigningError> {
        match algorithm {
            SoftwareSigningAlgorithm::EcdsaP256Sha256 => P256SecretKey::from_slice(serialized)
                .map(Self::P256)
                .map_err(|_| SoftwareSigningError::InvalidPrivateKey),
            SoftwareSigningAlgorithm::Ed25519 => {
                let seed = serialized
                    .try_into()
                    .map_err(|_| SoftwareSigningError::InvalidPrivateKey)?;
                Ok(Self::Ed25519(Ed25519SigningKey::from_bytes(seed)))
            }
            SoftwareSigningAlgorithm::EcdsaP384Sha384 => P384SecretKey::from_slice(serialized)
                .map(Self::P384)
                .map_err(|_| SoftwareSigningError::InvalidPrivateKey),
            SoftwareSigningAlgorithm::EcdsaP521Sha512 => P521SecretKey::from_slice(serialized)
                .map(Self::P521)
                .map_err(|_| SoftwareSigningError::InvalidPrivateKey),
            SoftwareSigningAlgorithm::EcdsaSecp256k1Sha256 => K256SecretKey::from_slice(serialized)
                .map(Self::K256)
                .map_err(|_| SoftwareSigningError::InvalidPrivateKey),
            SoftwareSigningAlgorithm::RsaPssSha256
            | SoftwareSigningAlgorithm::RsaPssSha384
            | SoftwareSigningAlgorithm::RsaPssSha512
            | SoftwareSigningAlgorithm::RsaPkcs1Sha256
            | SoftwareSigningAlgorithm::RsaPkcs1Sha384
            | SoftwareSigningAlgorithm::RsaPkcs1Sha512 => {
                let mut key = RsaPrivateKey::from_pkcs8_der(serialized)
                    .map_err(|_| SoftwareSigningError::InvalidPrivateKey)?;
                key.precompute()
                    .map_err(|_| SoftwareSigningError::InvalidPrivateKey)?;
                Ok(Self::Rsa(Box::new(key)))
            }
            SoftwareSigningAlgorithm::MlDsa(parameter_set) => {
                MlDsaPrivateKey::from_seed_slice(parameter_set, serialized)
                    .map(Self::MlDsa)
                    .map_err(|_| SoftwareSigningError::InvalidPrivateKey)
            }
        }
    }

    const fn kind_name(&self) -> &'static str {
        match self {
            Self::P256(_) => "P-256",
            Self::Ed25519(_) => "Ed25519",
            Self::P384(_) => "P-384",
            Self::P521(_) => "P-521",
            Self::K256(_) => "secp256k1",
            Self::Rsa(_) => "RSA",
            Self::MlDsa(_) => "ML-DSA",
        }
    }

    pub fn serialized(&self) -> Result<Zeroizing<Vec<u8>>, SoftwareSigningError> {
        let serialized = match self {
            Self::P256(key) => key.to_bytes().to_vec(),
            Self::Ed25519(key) => key.to_bytes().to_vec(),
            Self::P384(key) => key.to_bytes().to_vec(),
            Self::P521(key) => key.to_bytes().to_vec(),
            Self::K256(key) => key.to_bytes().to_vec(),
            Self::Rsa(key) => key
                .to_pkcs8_der()
                .map_err(|_| SoftwareSigningError::InvalidPrivateKey)?
                .as_bytes()
                .to_vec(),
            Self::MlDsa(key) => key.seed().to_vec(),
        };
        Ok(Zeroizing::new(serialized))
    }

    pub fn public_key(&self) -> SoftwarePublicKey {
        match self {
            Self::P256(key) => SoftwarePublicKey::Ec {
                curve: EcCurve::P256,
                uncompressed: key.public_key().to_sec1_point(false).as_bytes().to_vec(),
            },
            Self::Ed25519(key) => SoftwarePublicKey::Ed25519(key.verifying_key().to_bytes()),
            Self::P384(key) => SoftwarePublicKey::Ec {
                curve: EcCurve::P384,
                uncompressed: key.public_key().to_sec1_point(false).as_bytes().to_vec(),
            },
            Self::P521(key) => SoftwarePublicKey::Ec {
                curve: EcCurve::P521,
                uncompressed: key.public_key().to_sec1_point(false).as_bytes().to_vec(),
            },
            Self::K256(key) => SoftwarePublicKey::Ec {
                curve: EcCurve::Secp256k1,
                uncompressed: key.public_key().to_sec1_point(false).as_bytes().to_vec(),
            },
            Self::Rsa(key) => SoftwarePublicKey::Rsa {
                modulus: key.n().to_bytes_be(),
                exponent: key.e().to_bytes_be(),
            },
            Self::MlDsa(key) => SoftwarePublicKey::MlDsa {
                parameter_set: key.parameter_set(),
                public_key: key.public_key(),
            },
        }
    }

    pub fn sign_message(
        &self,
        algorithm: SoftwareSigningAlgorithm,
        message: &[u8],
    ) -> Result<SoftwareSignature, SoftwareSigningError> {
        let signature = match (algorithm, self) {
            (SoftwareSigningAlgorithm::EcdsaP256Sha256, Self::P256(key)) => {
                let signature: p256::ecdsa::Signature =
                    P256SigningKey::from(key.clone()).sign(message);
                signature.to_bytes().to_vec()
            }
            (SoftwareSigningAlgorithm::Ed25519, Self::Ed25519(key)) => {
                key.sign(message).to_bytes().to_vec()
            }
            (SoftwareSigningAlgorithm::EcdsaP384Sha384, Self::P384(key)) => {
                let signature: p384::ecdsa::Signature =
                    P384SigningKey::from(key.clone()).sign(message);
                signature.to_bytes().to_vec()
            }
            (SoftwareSigningAlgorithm::EcdsaP521Sha512, Self::P521(key)) => {
                let signature: p521::ecdsa::Signature =
                    P521SigningKey::from(key.clone()).sign(message);
                signature.to_bytes().to_vec()
            }
            (SoftwareSigningAlgorithm::EcdsaSecp256k1Sha256, Self::K256(key)) => {
                let signature: k256::ecdsa::Signature =
                    K256SigningKey::from(key.clone()).sign(message);
                signature.to_bytes().to_vec()
            }
            (algorithm, Self::Rsa(key)) if algorithm.is_rsa() => {
                rsa_sign_message(algorithm, key, message)?
            }
            (SoftwareSigningAlgorithm::MlDsa(parameter_set), Self::MlDsa(key))
                if parameter_set == key.parameter_set() =>
            {
                key.sign_hedged(message, &[])
                    .map_err(|_| SoftwareSigningError::SigningFailed)?
            }
            _ => return Err(SoftwareSigningError::AlgorithmMismatch),
        };
        Ok(SoftwareSignature(signature))
    }

    /// Sign a digest supplied by the caller.
    ///
    /// This is available for ECDSA and RSA. Ed25519 and ML-DSA define their
    /// own message processing and therefore use [`Self::sign_message`].
    pub fn sign_prehash(
        &self,
        algorithm: SoftwareSigningAlgorithm,
        prehash: &[u8],
    ) -> Result<SoftwareSignature, SoftwareSigningError> {
        macro_rules! sign_ecdsa_prehash {
            ($key:expr, $signing_key:ty, $signature:ty) => {{
                let key = <$signing_key>::from($key.clone());
                let signature: $signature = key
                    .sign_prehash(prehash)
                    .map_err(|_| SoftwareSigningError::SigningFailed)?;
                signature.to_bytes().to_vec()
            }};
        }
        let signature = match (algorithm, self) {
            (SoftwareSigningAlgorithm::EcdsaP256Sha256, Self::P256(key)) => {
                sign_ecdsa_prehash!(key, P256SigningKey, p256::ecdsa::Signature)
            }
            (SoftwareSigningAlgorithm::EcdsaP384Sha384, Self::P384(key)) => {
                sign_ecdsa_prehash!(key, P384SigningKey, p384::ecdsa::Signature)
            }
            (SoftwareSigningAlgorithm::EcdsaP521Sha512, Self::P521(key)) => {
                sign_ecdsa_prehash!(key, P521SigningKey, p521::ecdsa::Signature)
            }
            (SoftwareSigningAlgorithm::EcdsaSecp256k1Sha256, Self::K256(key)) => {
                sign_ecdsa_prehash!(key, K256SigningKey, k256::ecdsa::Signature)
            }
            (algorithm, Self::Rsa(key)) if algorithm.is_rsa() => {
                rsa_sign_prehash(algorithm, key, prehash, None)?
            }
            _ => return Err(SoftwareSigningError::AlgorithmMismatch),
        };
        Ok(SoftwareSignature(signature))
    }

    /// Sign a digest with RSA-PSS and a caller-selected salt length.
    pub fn sign_rsa_pss_prehash(
        &self,
        algorithm: SoftwareSigningAlgorithm,
        prehash: &[u8],
        salt_length: usize,
    ) -> Result<SoftwareSignature, SoftwareSigningError> {
        let Self::Rsa(key) = self else {
            return Err(SoftwareSigningError::AlgorithmMismatch);
        };
        rsa_sign_prehash(algorithm, key, prehash, Some(salt_length)).map(SoftwareSignature)
    }

    /// Perform the raw RSA private-key operation used by protocols that supply
    /// their own modulus-width encoding.
    pub fn sign_rsa_raw(&self, input: &[u8]) -> Result<SoftwareSignature, SoftwareSigningError> {
        let Self::Rsa(key) = self else {
            return Err(SoftwareSigningError::AlgorithmMismatch);
        };
        rsa_sign_raw(key, input)
            .map(SoftwareSignature)
            .map_err(map_rsa_signing_error)
    }

    /// Export the two primes and precomputed CRT values as unsigned big-endian
    /// integers in P, Q, dP, dQ, QInv order.
    pub fn rsa_crt_components(&self) -> Result<[Zeroizing<Vec<u8>>; 5], SoftwareSigningError> {
        let Self::Rsa(key) = self else {
            return Err(SoftwareSigningError::AlgorithmMismatch);
        };
        let [p, q] = key.primes() else {
            return Err(SoftwareSigningError::InvalidPrivateKey);
        };
        let dp = key.dp().ok_or(SoftwareSigningError::InvalidPrivateKey)?;
        let dq = key.dq().ok_or(SoftwareSigningError::InvalidPrivateKey)?;
        let qinv = key
            .qinv()
            .and_then(|value| value.to_biguint())
            .ok_or(SoftwareSigningError::InvalidPrivateKey)?;
        Ok([
            Zeroizing::new(p.to_bytes_be()),
            Zeroizing::new(q.to_bytes_be()),
            Zeroizing::new(dp.to_bytes_be()),
            Zeroizing::new(dq.to_bytes_be()),
            Zeroizing::new(qinv.to_bytes_be()),
        ])
    }
}

fn rsa_sign_message(
    algorithm: SoftwareSigningAlgorithm,
    key: &RsaPrivateKey,
    message: &[u8],
) -> Result<Vec<u8>, SoftwareSigningError> {
    let (hash, _) = rsa_profile(algorithm).ok_or(SoftwareSigningError::AlgorithmMismatch)?;
    rsa_sign_prehash(algorithm, key, &hash.digest(message), None)
}

fn rsa_sign_prehash(
    algorithm: SoftwareSigningAlgorithm,
    key: &RsaPrivateKey,
    prehash: &[u8],
    pss_salt_length: Option<usize>,
) -> Result<Vec<u8>, SoftwareSigningError> {
    let (hash, pss) = rsa_profile(algorithm).ok_or(SoftwareSigningError::AlgorithmMismatch)?;
    let result = if pss {
        rsa_sign_pss_digest(
            key,
            RsaPssParameters {
                hash,
                mgf_hash: hash,
                salt_length: pss_salt_length.unwrap_or_else(|| hash.output_length()),
            },
            prehash,
        )
    } else {
        rsa_sign_pkcs1v15_digest(key, hash, prehash)
    };
    result.map_err(map_rsa_signing_error)
}

fn map_rsa_signing_error(error: RsaSignatureError) -> SoftwareSigningError {
    match error {
        RsaSignatureError::InvalidKey => SoftwareSigningError::InvalidPrivateKey,
        RsaSignatureError::RandomnessUnavailable => SoftwareSigningError::RandomnessUnavailable,
        RsaSignatureError::InputTooLong
        | RsaSignatureError::InputOutOfRange
        | RsaSignatureError::InvalidDigestLength
        | RsaSignatureError::InvalidSignature
        | RsaSignatureError::OperationFailed => SoftwareSigningError::SigningFailed,
    }
}

fn random_p256_secret() -> Result<P256SecretKey, SoftwareSigningError> {
    loop {
        let mut bytes = Zeroizing::new([0_u8; 32]);
        getrandom::fill(bytes.as_mut()).map_err(|_| SoftwareSigningError::RandomnessUnavailable)?;
        if let Ok(secret) = P256SecretKey::from_slice(bytes.as_ref()) {
            return Ok(secret);
        }
    }
}

fn random_p384_secret() -> Result<P384SecretKey, SoftwareSigningError> {
    loop {
        let mut bytes = Zeroizing::new([0_u8; 48]);
        getrandom::fill(bytes.as_mut()).map_err(|_| SoftwareSigningError::RandomnessUnavailable)?;
        if let Ok(secret) = P384SecretKey::from_slice(bytes.as_ref()) {
            return Ok(secret);
        }
    }
}

fn random_p521_secret() -> Result<P521SecretKey, SoftwareSigningError> {
    loop {
        let mut bytes = Zeroizing::new([0_u8; 66]);
        getrandom::fill(bytes.as_mut()).map_err(|_| SoftwareSigningError::RandomnessUnavailable)?;
        if let Ok(secret) = P521SecretKey::from_slice(bytes.as_ref()) {
            return Ok(secret);
        }
    }
}

fn random_k256_secret() -> Result<K256SecretKey, SoftwareSigningError> {
    loop {
        let mut bytes = Zeroizing::new([0_u8; 32]);
        getrandom::fill(bytes.as_mut()).map_err(|_| SoftwareSigningError::RandomnessUnavailable)?;
        if let Ok(secret) = K256SecretKey::from_slice(bytes.as_ref()) {
            return Ok(secret);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256, Sha384, Sha512};

    #[test]
    fn every_key_kind_round_trips_compact_private_material() {
        for algorithm in [
            SoftwareSigningAlgorithm::EcdsaP256Sha256,
            SoftwareSigningAlgorithm::Ed25519,
            SoftwareSigningAlgorithm::EcdsaP384Sha384,
            SoftwareSigningAlgorithm::EcdsaP521Sha512,
            SoftwareSigningAlgorithm::EcdsaSecp256k1Sha256,
            SoftwareSigningAlgorithm::RsaPssSha256,
            SoftwareSigningAlgorithm::MlDsa(MlDsaParameterSet::MlDsa44),
            SoftwareSigningAlgorithm::MlDsa(MlDsaParameterSet::MlDsa65),
            SoftwareSigningAlgorithm::MlDsa(MlDsaParameterSet::MlDsa87),
        ] {
            let key = SoftwareSigningKey::generate(algorithm).unwrap();
            let serialized = key.serialized().unwrap();
            let restored = SoftwareSigningKey::from_serialized(algorithm, &serialized).unwrap();
            let public_key = key.public_key();
            assert_eq!(restored.public_key(), public_key);
            let signature = restored
                .sign_message(algorithm, b"shared signing test")
                .unwrap();
            public_key
                .verify_message(algorithm, b"shared signing test", signature.as_bytes())
                .unwrap();
            assert_eq!(
                public_key.verify_message(algorithm, b"changed", signature.as_bytes()),
                Err(SoftwareSigningError::InvalidSignature)
            );
        }
    }

    #[test]
    fn ecdsa_keys_sign_and_verify_caller_supplied_digests() {
        for (algorithm, prehash) in [
            (
                SoftwareSigningAlgorithm::EcdsaP256Sha256,
                Sha256::digest(b"prehashed signing test").to_vec(),
            ),
            (
                SoftwareSigningAlgorithm::EcdsaP384Sha384,
                Sha384::digest(b"prehashed signing test").to_vec(),
            ),
            (
                SoftwareSigningAlgorithm::EcdsaP521Sha512,
                Sha512::digest(b"prehashed signing test").to_vec(),
            ),
            (
                SoftwareSigningAlgorithm::EcdsaSecp256k1Sha256,
                Sha256::digest(b"prehashed signing test").to_vec(),
            ),
        ] {
            let key = SoftwareSigningKey::generate(algorithm).unwrap();
            let public_key = key.public_key();
            let signature = key.sign_prehash(algorithm, &prehash).unwrap();
            public_key
                .verify_prehash(algorithm, &prehash, signature.as_bytes())
                .unwrap();
            let mut changed = prehash;
            changed[0] ^= 1;
            assert_eq!(
                public_key.verify_prehash(algorithm, &changed, signature.as_bytes()),
                Err(SoftwareSigningError::InvalidSignature)
            );
        }
    }

    #[test]
    fn rsa_keys_sign_and_verify_caller_supplied_digests() {
        let original = SoftwareSigningKey::generate(SoftwareSigningAlgorithm::RsaPssSha256)
            .unwrap()
            .serialized()
            .unwrap();
        for (algorithm, digest_length) in [
            (SoftwareSigningAlgorithm::RsaPssSha256, 32),
            (SoftwareSigningAlgorithm::RsaPssSha384, 48),
            (SoftwareSigningAlgorithm::RsaPssSha512, 64),
            (SoftwareSigningAlgorithm::RsaPkcs1Sha256, 32),
            (SoftwareSigningAlgorithm::RsaPkcs1Sha384, 48),
            (SoftwareSigningAlgorithm::RsaPkcs1Sha512, 64),
        ] {
            let key = SoftwareSigningKey::from_serialized(algorithm, &original).unwrap();
            let public_key = key.public_key();
            let prehash = vec![0x5a; digest_length];
            let signature = key.sign_prehash(algorithm, &prehash).unwrap();
            public_key
                .verify_prehash(algorithm, &prehash, signature.as_bytes())
                .unwrap();
        }
    }

    #[test]
    fn rsa_pss_accepts_an_explicit_salt_length() {
        let algorithm = SoftwareSigningAlgorithm::RsaPssSha256;
        let key = SoftwareSigningKey::generate(algorithm).unwrap();
        let public_key = key.public_key();
        let prehash = [0x73; 32];
        let signature = key.sign_rsa_pss_prehash(algorithm, &prehash, 17).unwrap();
        public_key
            .verify_rsa_pss_prehash(algorithm, &prehash, 17, signature.as_bytes())
            .unwrap();
        assert_eq!(
            public_key.verify_rsa_pss_prehash(algorithm, &prehash, 16, signature.as_bytes()),
            Err(SoftwareSigningError::InvalidSignature)
        );
    }

    #[test]
    fn explicit_rsa_sizes_and_prime_import_support_raw_operations() {
        let key = SoftwareSigningKey::generate_rsa(1_024).unwrap();
        let public_key = key.public_key();
        let mut input = vec![0; 128];
        input[1] = 1;
        input[127] = 0x42;
        let signature = key.sign_rsa_raw(&input).unwrap();
        public_key
            .verify_rsa_raw(&input, signature.as_bytes())
            .unwrap();

        let SoftwareSigningKey::Rsa(key) = &key else {
            unreachable!();
        };
        let rebuilt = SoftwareSigningKey::from_rsa_primes(
            &key.primes()[0].to_bytes_be(),
            &key.primes()[1].to_bytes_be(),
            &[1, 0, 1],
        )
        .unwrap();
        assert_eq!(rebuilt.public_key(), public_key);
        let signature = rebuilt.sign_rsa_raw(&input).unwrap();
        public_key
            .verify_rsa_raw(&input, signature.as_bytes())
            .unwrap();
    }
}
