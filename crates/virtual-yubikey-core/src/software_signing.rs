//! Protocol-neutral software signing keys.
//!
//! This module owns key generation, compact private-key serialization, public
//! projection, and ordinary message signing. Callers retain responsibility for
//! protocol identifiers, public-key containers, signature formatting, policy,
//! and error mapping.

use crate::post_quantum::{MlDsaParameterSet, MlDsaPrivateKey};
use ed25519_dalek::SigningKey as Ed25519SigningKey;
use p256::ecdsa::SigningKey as P256SigningKey;
use p256::elliptic_curve::sec1::ToSec1Point;
use p256::SecretKey as P256SecretKey;
use p384::ecdsa::SigningKey as P384SigningKey;
use p384::SecretKey as P384SecretKey;
use signature::Signer;
use std::fmt;
use zeroize::Zeroizing;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SoftwareSigningAlgorithm {
    EcdsaP256Sha256,
    Ed25519,
    EcdsaP384Sha384,
    MlDsa(MlDsaParameterSet),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SoftwareSigningError {
    InvalidPrivateKey,
    RandomnessUnavailable,
    SigningFailed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EcCurve {
    P256,
    P384,
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
    MlDsa(MlDsaPrivateKey),
}

impl fmt::Debug for SoftwareSigningKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SoftwareSigningKey")
            .field("algorithm", &self.algorithm())
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
            SoftwareSigningAlgorithm::MlDsa(parameter_set) => {
                MlDsaPrivateKey::generate(parameter_set)
                    .map(Self::MlDsa)
                    .map_err(|_| SoftwareSigningError::RandomnessUnavailable)
            }
        }
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
            SoftwareSigningAlgorithm::MlDsa(parameter_set) => {
                MlDsaPrivateKey::from_seed_slice(parameter_set, serialized)
                    .map(Self::MlDsa)
                    .map_err(|_| SoftwareSigningError::InvalidPrivateKey)
            }
        }
    }

    pub const fn algorithm(&self) -> SoftwareSigningAlgorithm {
        match self {
            Self::P256(_) => SoftwareSigningAlgorithm::EcdsaP256Sha256,
            Self::Ed25519(_) => SoftwareSigningAlgorithm::Ed25519,
            Self::P384(_) => SoftwareSigningAlgorithm::EcdsaP384Sha384,
            Self::MlDsa(key) => SoftwareSigningAlgorithm::MlDsa(key.parameter_set()),
        }
    }

    pub fn serialized(&self) -> Zeroizing<Vec<u8>> {
        match self {
            Self::P256(key) => Zeroizing::new(key.to_bytes().to_vec()),
            Self::Ed25519(key) => Zeroizing::new(key.to_bytes().to_vec()),
            Self::P384(key) => Zeroizing::new(key.to_bytes().to_vec()),
            Self::MlDsa(key) => Zeroizing::new(key.seed().to_vec()),
        }
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
            Self::MlDsa(key) => SoftwarePublicKey::MlDsa {
                parameter_set: key.parameter_set(),
                public_key: key.public_key(),
            },
        }
    }

    pub fn sign_message(&self, message: &[u8]) -> Result<SoftwareSignature, SoftwareSigningError> {
        let signature = match self {
            Self::P256(key) => {
                let signature: p256::ecdsa::Signature =
                    P256SigningKey::from(key.clone()).sign(message);
                signature.to_bytes().to_vec()
            }
            Self::Ed25519(key) => key.sign(message).to_bytes().to_vec(),
            Self::P384(key) => {
                let signature: p384::ecdsa::Signature =
                    P384SigningKey::from(key.clone()).sign(message);
                signature.to_bytes().to_vec()
            }
            Self::MlDsa(key) => key
                .sign_hedged(message, &[])
                .map_err(|_| SoftwareSigningError::SigningFailed)?,
        };
        Ok(SoftwareSignature(signature))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_key_kind_round_trips_compact_private_material() {
        for algorithm in [
            SoftwareSigningAlgorithm::EcdsaP256Sha256,
            SoftwareSigningAlgorithm::Ed25519,
            SoftwareSigningAlgorithm::EcdsaP384Sha384,
            SoftwareSigningAlgorithm::MlDsa(MlDsaParameterSet::MlDsa44),
            SoftwareSigningAlgorithm::MlDsa(MlDsaParameterSet::MlDsa65),
            SoftwareSigningAlgorithm::MlDsa(MlDsaParameterSet::MlDsa87),
        ] {
            let key = SoftwareSigningKey::generate(algorithm).unwrap();
            let restored =
                SoftwareSigningKey::from_serialized(algorithm, &key.serialized()).unwrap();
            assert_eq!(restored.algorithm(), algorithm);
            assert_eq!(restored.public_key(), key.public_key());
            assert!(!restored
                .sign_message(b"shared signing test")
                .unwrap()
                .as_bytes()
                .is_empty());
        }
    }
}
