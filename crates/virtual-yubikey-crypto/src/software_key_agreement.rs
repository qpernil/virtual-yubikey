//! Protocol-neutral static software key agreement.
//!
//! Protocol layers retain responsibility for algorithm identifiers, public-key
//! containers, authorization policy, persistence, and error mapping.

use std::fmt;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519SecretKey};
use zeroize::Zeroizing;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SoftwareKeyAgreementAlgorithm {
    X25519,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SoftwareKeyAgreementError {
    AlgorithmMismatch,
    InvalidPrivateKey,
    InvalidPublicKey,
    NonContributoryPublicKey,
    RandomnessUnavailable,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SoftwareKeyAgreementPublicKey {
    X25519([u8; 32]),
}

#[derive(Clone)]
pub enum SoftwareKeyAgreementKey {
    X25519(X25519SecretKey),
}

impl fmt::Debug for SoftwareKeyAgreementKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SoftwareKeyAgreementKey")
            .field("kind", &"X25519")
            .finish_non_exhaustive()
    }
}

impl SoftwareKeyAgreementKey {
    pub fn generate(
        algorithm: SoftwareKeyAgreementAlgorithm,
    ) -> Result<Self, SoftwareKeyAgreementError> {
        match algorithm {
            SoftwareKeyAgreementAlgorithm::X25519 => {
                let mut seed = Zeroizing::new([0_u8; 32]);
                getrandom::fill(seed.as_mut())
                    .map_err(|_| SoftwareKeyAgreementError::RandomnessUnavailable)?;
                Ok(Self::X25519(X25519SecretKey::from(*seed)))
            }
        }
    }

    pub fn from_serialized(
        algorithm: SoftwareKeyAgreementAlgorithm,
        serialized: &[u8],
    ) -> Result<Self, SoftwareKeyAgreementError> {
        match algorithm {
            SoftwareKeyAgreementAlgorithm::X25519 => {
                let seed: [u8; 32] = serialized
                    .try_into()
                    .map_err(|_| SoftwareKeyAgreementError::InvalidPrivateKey)?;
                Ok(Self::X25519(X25519SecretKey::from(seed)))
            }
        }
    }

    pub fn serialized(&self) -> Zeroizing<Vec<u8>> {
        match self {
            Self::X25519(key) => Zeroizing::new(key.to_bytes().to_vec()),
        }
    }

    pub fn public_key(&self) -> SoftwareKeyAgreementPublicKey {
        match self {
            Self::X25519(key) => {
                SoftwareKeyAgreementPublicKey::X25519(X25519PublicKey::from(key).to_bytes())
            }
        }
    }

    pub fn derive(
        &self,
        algorithm: SoftwareKeyAgreementAlgorithm,
        peer_public_key: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, SoftwareKeyAgreementError> {
        match (algorithm, self) {
            (SoftwareKeyAgreementAlgorithm::X25519, Self::X25519(key)) => {
                let peer: [u8; 32] = peer_public_key
                    .try_into()
                    .map_err(|_| SoftwareKeyAgreementError::InvalidPublicKey)?;
                let shared = key.diffie_hellman(&X25519PublicKey::from(peer));
                if !shared.was_contributory() {
                    return Err(SoftwareKeyAgreementError::NonContributoryPublicKey);
                }
                Ok(Zeroizing::new(shared.to_bytes().to_vec()))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn x25519_round_trips_and_agrees() {
        let algorithm = SoftwareKeyAgreementAlgorithm::X25519;
        let alice = SoftwareKeyAgreementKey::generate(algorithm).unwrap();
        let serialized = alice.serialized();
        let restored = SoftwareKeyAgreementKey::from_serialized(algorithm, &serialized).unwrap();
        assert_eq!(restored.public_key(), alice.public_key());

        let bob = SoftwareKeyAgreementKey::generate(algorithm).unwrap();
        let SoftwareKeyAgreementPublicKey::X25519(alice_public) = alice.public_key();
        let SoftwareKeyAgreementPublicKey::X25519(bob_public) = bob.public_key();
        assert_eq!(
            restored.derive(algorithm, &bob_public).unwrap(),
            bob.derive(algorithm, &alice_public).unwrap()
        );
    }

    #[test]
    fn x25519_rejects_bad_and_noncontributory_peers() {
        let algorithm = SoftwareKeyAgreementAlgorithm::X25519;
        let key = SoftwareKeyAgreementKey::generate(algorithm).unwrap();
        assert_eq!(
            key.derive(algorithm, &[1; 31]),
            Err(SoftwareKeyAgreementError::InvalidPublicKey)
        );
        assert_eq!(
            key.derive(algorithm, &[0; 32]),
            Err(SoftwareKeyAgreementError::NonContributoryPublicKey)
        );
    }
}
