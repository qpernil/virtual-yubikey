//! Protocol-neutral static software key agreement.
//!
//! This module owns raw ECDH and X25519 operations. Protocol layers retain
//! responsibility for algorithm identifiers, public-key containers, KDFs,
//! authorization policy, persistence, and error mapping.

use crate::software_signing::SoftwareSigningKey;
use p256::elliptic_curve::{
    sec1::{FromSec1Point, ModulusSize, ToSec1Point},
    AffinePoint, CurveArithmetic, FieldBytesSize, PublicKey, SecretKey,
};
use std::fmt;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519SecretKey};
use zeroize::Zeroizing;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SoftwareKeyAgreementError {
    AlgorithmMismatch,
    InvalidPrivateKey,
    InvalidPublicKey,
    NonContributoryPublicKey,
    RandomnessUnavailable,
}

/// A persistent X25519 private key.
#[derive(Clone)]
pub struct SoftwareX25519Key(X25519SecretKey);

impl fmt::Debug for SoftwareX25519Key {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SoftwareX25519Key")
            .finish_non_exhaustive()
    }
}

impl SoftwareX25519Key {
    pub fn generate() -> Result<Self, SoftwareKeyAgreementError> {
        let mut seed = Zeroizing::new([0_u8; 32]);
        getrandom::fill(seed.as_mut())
            .map_err(|_| SoftwareKeyAgreementError::RandomnessUnavailable)?;
        Ok(Self(X25519SecretKey::from(*seed)))
    }

    pub fn from_serialized(serialized: &[u8]) -> Result<Self, SoftwareKeyAgreementError> {
        let seed: [u8; 32] = serialized
            .try_into()
            .map_err(|_| SoftwareKeyAgreementError::InvalidPrivateKey)?;
        Ok(Self(X25519SecretKey::from(seed)))
    }

    pub fn serialized(&self) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(self.0.to_bytes().to_vec())
    }

    pub fn public_key(&self) -> [u8; 32] {
        X25519PublicKey::from(&self.0).to_bytes()
    }

    pub fn derive(
        &self,
        peer_public_key: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, SoftwareKeyAgreementError> {
        derive_x25519(&self.0, peer_public_key)
    }
}

/// Perform raw X25519 with an existing software private key.
pub fn derive_x25519(
    private_key: &X25519SecretKey,
    peer_public_key: &[u8],
) -> Result<Zeroizing<Vec<u8>>, SoftwareKeyAgreementError> {
    let peer: [u8; 32] = peer_public_key
        .try_into()
        .map_err(|_| SoftwareKeyAgreementError::InvalidPublicKey)?;
    let shared = private_key.diffie_hellman(&X25519PublicKey::from(peer));
    if !shared.was_contributory() {
        return Err(SoftwareKeyAgreementError::NonContributoryPublicKey);
    }
    Ok(Zeroizing::new(shared.to_bytes().to_vec()))
}

/// Perform raw static ECDH for any RustCrypto short-Weierstrass curve.
///
/// The peer key may use any SEC1 encoding accepted by the curve. The returned
/// value is the fixed-width x-coordinate and is intentionally not passed
/// through a KDF.
pub fn derive_weierstrass<C>(
    private_key: &SecretKey<C>,
    peer_public_key: &[u8],
) -> Result<Zeroizing<Vec<u8>>, SoftwareKeyAgreementError>
where
    C: CurveArithmetic,
    FieldBytesSize<C>: ModulusSize,
    AffinePoint<C>: FromSec1Point<C> + ToSec1Point<C>,
{
    let peer = PublicKey::<C>::from_sec1_bytes(peer_public_key)
        .map_err(|_| SoftwareKeyAgreementError::InvalidPublicKey)?;
    let shared = p256::elliptic_curve::ecdh::diffie_hellman(
        private_key.to_nonzero_scalar(),
        peer.as_affine(),
    );
    Ok(Zeroizing::new(shared.raw_secret_bytes().to_vec()))
}

/// Perform ECDH with any Weierstrass key owned by the shared software signing
/// key container.
pub fn derive_with_signing_key(
    private_key: &SoftwareSigningKey,
    peer_public_key: &[u8],
) -> Result<Zeroizing<Vec<u8>>, SoftwareKeyAgreementError> {
    match private_key {
        SoftwareSigningKey::P256(key) => derive_weierstrass(key, peer_public_key),
        SoftwareSigningKey::P384(key) => derive_weierstrass(key, peer_public_key),
        SoftwareSigningKey::P521(key) => derive_weierstrass(key, peer_public_key),
        SoftwareSigningKey::K256(key) => derive_weierstrass(key, peer_public_key),
        SoftwareSigningKey::Ed25519(_)
        | SoftwareSigningKey::Rsa(_)
        | SoftwareSigningKey::MlDsa(_) => Err(SoftwareKeyAgreementError::AlgorithmMismatch),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::software_signing::{SoftwarePublicKey, SoftwareSigningAlgorithm};

    #[test]
    fn every_shared_weierstrass_curve_agrees() {
        for algorithm in [
            SoftwareSigningAlgorithm::EcdsaP256Sha256,
            SoftwareSigningAlgorithm::EcdsaP384Sha384,
            SoftwareSigningAlgorithm::EcdsaP521Sha512,
            SoftwareSigningAlgorithm::EcdsaSecp256k1Sha256,
        ] {
            let first = SoftwareSigningKey::generate(algorithm).unwrap();
            let second = SoftwareSigningKey::generate(algorithm).unwrap();
            let SoftwarePublicKey::Ec {
                uncompressed: first_public,
                ..
            } = first.public_key()
            else {
                unreachable!();
            };
            let SoftwarePublicKey::Ec {
                uncompressed: second_public,
                ..
            } = second.public_key()
            else {
                unreachable!();
            };
            assert_eq!(
                derive_with_signing_key(&first, &second_public).unwrap(),
                derive_with_signing_key(&second, &first_public).unwrap()
            );
        }
    }

    #[test]
    fn x25519_round_trips_and_agrees() {
        let alice = SoftwareX25519Key::generate().unwrap();
        let serialized = alice.serialized();
        let restored = SoftwareX25519Key::from_serialized(&serialized).unwrap();
        assert_eq!(restored.public_key(), alice.public_key());

        let bob = SoftwareX25519Key::generate().unwrap();
        assert_eq!(
            restored.derive(&bob.public_key()).unwrap(),
            bob.derive(&alice.public_key()).unwrap()
        );
    }

    #[test]
    fn x25519_rejects_bad_and_noncontributory_peers() {
        let key = SoftwareX25519Key::generate().unwrap();
        assert_eq!(
            key.derive(&[1; 31]),
            Err(SoftwareKeyAgreementError::InvalidPublicKey)
        );
        assert_eq!(
            key.derive(&[0; 32]),
            Err(SoftwareKeyAgreementError::NonContributoryPublicKey)
        );
    }
}
