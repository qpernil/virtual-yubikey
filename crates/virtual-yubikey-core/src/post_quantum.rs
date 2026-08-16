//! Role-neutral post-quantum key operations shared by virtual applets.
//!
//! Protocol-specific identifiers, encodings, policy, and error mapping belong
//! in their callers. This module deliberately operates on raw FIPS 204 keys,
//! messages, contexts, and signatures so it can also be reused by `pkcs11rs`.

use ::ml_dsa::{EncodedVerifyingKey, MlDsa44, MlDsa65, MlDsa87, Seed, Signature, SigningKey};
use signature::Keypair;
use std::fmt;
use zeroize::Zeroizing;

/// One of the three FIPS 204 ML-DSA parameter sets.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MlDsaParameterSet {
    MlDsa44,
    MlDsa65,
    MlDsa87,
}

impl MlDsaParameterSet {
    pub const fn public_key_length(self) -> usize {
        match self {
            Self::MlDsa44 => 1_312,
            Self::MlDsa65 => 1_952,
            Self::MlDsa87 => 2_592,
        }
    }

    pub const fn signature_length(self) -> usize {
        match self {
            Self::MlDsa44 => 2_420,
            Self::MlDsa65 => 3_309,
            Self::MlDsa87 => 4_627,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MlDsaError {
    InvalidSeedLength,
    InvalidContext,
    InvalidPublicKey,
    InvalidSignature,
    RandomnessUnavailable,
    SigningFailed,
}

/// How an ML-DSA signature obtains its per-signature randomizer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MlDsaRandomization {
    /// Use the deterministic FIPS 204 variant.
    Deterministic,
    /// Require fresh operating-system randomness and fail if it is unavailable.
    Randomized,
    /// Prefer fresh randomness but fall back to the permitted deterministic variant.
    HedgePreferred,
}

/// An ML-DSA private key with its expanded form cached by RustCrypto.
#[derive(Clone)]
pub enum MlDsaPrivateKey {
    MlDsa44(SigningKey<MlDsa44>),
    MlDsa65(SigningKey<MlDsa65>),
    MlDsa87(SigningKey<MlDsa87>),
}

impl fmt::Debug for MlDsaPrivateKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MlDsaPrivateKey")
            .field("parameter_set", &self.parameter_set())
            .finish_non_exhaustive()
    }
}

impl MlDsaPrivateKey {
    pub fn generate(parameter_set: MlDsaParameterSet) -> Result<Self, MlDsaError> {
        let mut seed = Zeroizing::new([0_u8; 32]);
        getrandom::fill(seed.as_mut()).map_err(|_| MlDsaError::RandomnessUnavailable)?;
        Ok(Self::from_seed(parameter_set, *seed))
    }

    pub fn from_seed(parameter_set: MlDsaParameterSet, seed: [u8; 32]) -> Self {
        let seed = Seed::from(seed);
        match parameter_set {
            MlDsaParameterSet::MlDsa44 => Self::MlDsa44(SigningKey::from_seed(&seed)),
            MlDsaParameterSet::MlDsa65 => Self::MlDsa65(SigningKey::from_seed(&seed)),
            MlDsaParameterSet::MlDsa87 => Self::MlDsa87(SigningKey::from_seed(&seed)),
        }
    }

    pub fn from_seed_slice(
        parameter_set: MlDsaParameterSet,
        seed: &[u8],
    ) -> Result<Self, MlDsaError> {
        let seed = seed.try_into().map_err(|_| MlDsaError::InvalidSeedLength)?;
        Ok(Self::from_seed(parameter_set, seed))
    }

    pub const fn parameter_set(&self) -> MlDsaParameterSet {
        match self {
            Self::MlDsa44(_) => MlDsaParameterSet::MlDsa44,
            Self::MlDsa65(_) => MlDsaParameterSet::MlDsa65,
            Self::MlDsa87(_) => MlDsaParameterSet::MlDsa87,
        }
    }

    pub fn seed(&self) -> Zeroizing<[u8; 32]> {
        let bytes = match self {
            Self::MlDsa44(key) => key.as_seed(),
            Self::MlDsa65(key) => key.as_seed(),
            Self::MlDsa87(key) => key.as_seed(),
        };
        Zeroizing::new((*bytes).into())
    }

    pub fn public_key(&self) -> Vec<u8> {
        match self {
            Self::MlDsa44(key) => key.verifying_key().encode().to_vec(),
            Self::MlDsa65(key) => key.verifying_key().encode().to_vec(),
            Self::MlDsa87(key) => key.verifying_key().encode().to_vec(),
        }
    }

    pub fn sign(
        &self,
        message: &[u8],
        context: &[u8],
        randomization: MlDsaRandomization,
    ) -> Result<Vec<u8>, MlDsaError> {
        if context.len() > 255 {
            return Err(MlDsaError::InvalidContext);
        }
        macro_rules! sign {
            ($key:expr) => {{
                let expanded = $key.expanded_key();
                let signature = match randomization {
                    MlDsaRandomization::Deterministic => expanded
                        .sign_deterministic(message, context)
                        .map_err(|_| MlDsaError::SigningFailed)?,
                    MlDsaRandomization::Randomized => expanded
                        .sign_randomized(message, context, &mut getrandom::SysRng)
                        .map_err(|_| MlDsaError::RandomnessUnavailable)?,
                    MlDsaRandomization::HedgePreferred => expanded
                        .sign_randomized(message, context, &mut getrandom::SysRng)
                        .or_else(|_| expanded.sign_deterministic(message, context))
                        .map_err(|_| MlDsaError::SigningFailed)?,
                };
                Ok(signature.encode().to_vec())
            }};
        }
        match self {
            Self::MlDsa44(key) => sign!(key),
            Self::MlDsa65(key) => sign!(key),
            Self::MlDsa87(key) => sign!(key),
        }
    }

    /// Produce a randomized FIPS 204 signature, falling back to the permitted
    /// deterministic variant if the operating-system RNG is unavailable.
    pub fn sign_hedged(&self, message: &[u8], context: &[u8]) -> Result<Vec<u8>, MlDsaError> {
        self.sign(message, context, MlDsaRandomization::HedgePreferred)
    }

    pub fn sign_deterministic(
        &self,
        message: &[u8],
        context: &[u8],
    ) -> Result<Vec<u8>, MlDsaError> {
        self.sign(message, context, MlDsaRandomization::Deterministic)
    }
}

pub fn verify_ml_dsa(
    parameter_set: MlDsaParameterSet,
    public_key: &[u8],
    message: &[u8],
    context: &[u8],
    signature: &[u8],
) -> Result<(), MlDsaError> {
    if context.len() > 255 {
        return Err(MlDsaError::InvalidContext);
    }
    macro_rules! verify {
        ($params:ty) => {{
            let encoded = EncodedVerifyingKey::<$params>::try_from(public_key)
                .map_err(|_| MlDsaError::InvalidPublicKey)?;
            let key = ::ml_dsa::VerifyingKey::<$params>::decode(&encoded);
            let signature = Signature::<$params>::try_from(signature)
                .map_err(|_| MlDsaError::InvalidSignature)?;
            if key.verify_with_context(message, context, &signature) {
                Ok(())
            } else {
                Err(MlDsaError::InvalidSignature)
            }
        }};
    }
    match parameter_set {
        MlDsaParameterSet::MlDsa44 => verify!(MlDsa44),
        MlDsaParameterSet::MlDsa65 => verify!(MlDsa65),
        MlDsaParameterSet::MlDsa87 => verify!(MlDsa87),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    #[test]
    fn ml_dsa_44_key_generation_matches_nist_acvp_fips_204() {
        // NIST ACVP-Server, ML-DSA-keyGen-FIPS204, tgId 1 / tcId 1.
        let seed = [
            0x71, 0x94, 0xb1, 0x3c, 0x95, 0x23, 0x10, 0x10, 0xaf, 0xd2, 0xc9, 0x09, 0x99, 0x2b,
            0xd2, 0x00, 0x3b, 0xa6, 0xf4, 0x37, 0xc3, 0x88, 0x6b, 0xdb, 0xe3, 0xf6, 0xb8, 0x67,
            0xa1, 0x4b, 0xa1, 0x61,
        ];
        let key = MlDsaPrivateKey::from_seed(MlDsaParameterSet::MlDsa44, seed);
        assert_eq!(
            Sha256::digest(key.public_key()).as_slice(),
            &[
                0x83, 0x8b, 0x88, 0xb6, 0xac, 0x41, 0xe2, 0xc6, 0x06, 0x98, 0x17, 0x3e, 0x08, 0xca,
                0x17, 0x3d, 0x0b, 0x0d, 0x28, 0x39, 0x20, 0x58, 0x06, 0xe5, 0x6a, 0x8a, 0x3d, 0x53,
                0x19, 0x5f, 0x3a, 0x03,
            ]
        );
    }

    #[test]
    fn every_parameter_set_round_trips_seed_and_signatures() {
        for parameter_set in [
            MlDsaParameterSet::MlDsa44,
            MlDsaParameterSet::MlDsa65,
            MlDsaParameterSet::MlDsa87,
        ] {
            let key = MlDsaPrivateKey::from_seed(parameter_set, [7; 32]);
            assert_eq!(*key.seed(), [7; 32]);
            assert_eq!(key.public_key().len(), parameter_set.public_key_length());
            let signature = key.sign_deterministic(b"message", b"context").unwrap();
            assert_eq!(signature.len(), parameter_set.signature_length());
            verify_ml_dsa(
                parameter_set,
                &key.public_key(),
                b"message",
                b"context",
                &signature,
            )
            .unwrap();

            let randomized = key
                .sign(
                    b"randomized message",
                    b"context",
                    MlDsaRandomization::Randomized,
                )
                .unwrap();
            verify_ml_dsa(
                parameter_set,
                &key.public_key(),
                b"randomized message",
                b"context",
                &randomized,
            )
            .unwrap();
        }
    }

    #[test]
    fn rejects_contexts_larger_than_fips_204_allows() {
        let key = MlDsaPrivateKey::from_seed(MlDsaParameterSet::MlDsa44, [9; 32]);
        assert_eq!(
            key.sign(b"message", &[0; 256], MlDsaRandomization::HedgePreferred,),
            Err(MlDsaError::InvalidContext)
        );
    }
}
