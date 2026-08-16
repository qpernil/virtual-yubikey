//! Protocol-neutral RSA signature primitives.
//!
//! Callers choose the exact input form and encoding. This module owns the RSA
//! operations, PKCS #1 v1.5 signature padding and DigestInfo values, and
//! RSASSA-PSS encoding with independent message and MGF1 hash algorithms.

use rsa::{traits::PublicKeyParts, BigUint, RsaPrivateKey, RsaPublicKey};
use sha1::Sha1;
use sha2::{Digest, Sha224, Sha256, Sha384, Sha512};
use sha3::{Sha3_224, Sha3_256, Sha3_384, Sha3_512};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RsaHashAlgorithm {
    Sha1,
    Sha224,
    Sha256,
    Sha384,
    Sha512,
    Sha3_224,
    Sha3_256,
    Sha3_384,
    Sha3_512,
}

impl RsaHashAlgorithm {
    pub const fn output_length(self) -> usize {
        match self {
            Self::Sha1 => 20,
            Self::Sha224 | Self::Sha3_224 => 28,
            Self::Sha256 | Self::Sha3_256 => 32,
            Self::Sha384 | Self::Sha3_384 => 48,
            Self::Sha512 | Self::Sha3_512 => 64,
        }
    }

    pub fn digest(self, message: &[u8]) -> Vec<u8> {
        macro_rules! digest {
            ($digest:ty) => {
                <$digest>::digest(message).to_vec()
            };
        }
        match self {
            Self::Sha1 => digest!(Sha1),
            Self::Sha224 => digest!(Sha224),
            Self::Sha256 => digest!(Sha256),
            Self::Sha384 => digest!(Sha384),
            Self::Sha512 => digest!(Sha512),
            Self::Sha3_224 => digest!(Sha3_224),
            Self::Sha3_256 => digest!(Sha3_256),
            Self::Sha3_384 => digest!(Sha3_384),
            Self::Sha3_512 => digest!(Sha3_512),
        }
    }

    fn digest_info_prefix(self) -> &'static [u8] {
        match self {
            Self::Sha1 => &[
                0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00,
            ],
            Self::Sha224 => &[
                0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
                0x04, 0x05, 0x00,
            ],
            Self::Sha256 => &[
                0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
                0x01, 0x05, 0x00,
            ],
            Self::Sha384 => &[
                0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
                0x02, 0x05, 0x00,
            ],
            Self::Sha512 => &[
                0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
                0x03, 0x05, 0x00,
            ],
            Self::Sha3_224 => &[
                0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
                0x07, 0x05, 0x00,
            ],
            Self::Sha3_256 => &[
                0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
                0x08, 0x05, 0x00,
            ],
            Self::Sha3_384 => &[
                0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
                0x09, 0x05, 0x00,
            ],
            Self::Sha3_512 => &[
                0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
                0x0a, 0x05, 0x00,
            ],
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RsaPssParameters {
    pub hash: RsaHashAlgorithm,
    pub mgf_hash: RsaHashAlgorithm,
    pub salt_length: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RsaSignatureError {
    InputTooLong,
    InputOutOfRange,
    InvalidDigestLength,
    InvalidKey,
    InvalidSignature,
    RandomnessUnavailable,
    OperationFailed,
}

fn left_pad(value: Vec<u8>, length: usize) -> Result<Vec<u8>, RsaSignatureError> {
    if value.len() > length {
        return Err(RsaSignatureError::OperationFailed);
    }
    let mut output = vec![0; length];
    output[length - value.len()..].copy_from_slice(&value);
    Ok(output)
}

fn private_operation(key: &RsaPrivateKey, encoded: &[u8]) -> Result<Vec<u8>, RsaSignatureError> {
    if encoded.len() > key.size() {
        return Err(RsaSignatureError::InputTooLong);
    }
    let value = BigUint::from_bytes_be(encoded);
    if &value >= key.n() {
        return Err(RsaSignatureError::InputOutOfRange);
    }
    let value = rsa::hazmat::rsa_decrypt_and_check(key, Some(&mut rsa::rand_core::OsRng), &value)
        .map_err(|_| RsaSignatureError::OperationFailed)?;
    left_pad(value.to_bytes_be(), key.size())
}

fn public_operation(key: &RsaPublicKey, signature: &[u8]) -> Result<Vec<u8>, RsaSignatureError> {
    if signature.len() != key.size() {
        return Err(RsaSignatureError::InvalidSignature);
    }
    let value = BigUint::from_bytes_be(signature);
    if &value >= key.n() {
        return Err(RsaSignatureError::InvalidSignature);
    }
    let value =
        rsa::hazmat::rsa_encrypt(key, &value).map_err(|_| RsaSignatureError::InvalidSignature)?;
    left_pad(value.to_bytes_be(), key.size())
}

pub fn rsa_sign_raw(key: &RsaPrivateKey, input: &[u8]) -> Result<Vec<u8>, RsaSignatureError> {
    private_operation(key, input)
}

pub fn rsa_verify_raw(
    key: &RsaPublicKey,
    input: &[u8],
    signature: &[u8],
) -> Result<(), RsaSignatureError> {
    if input.len() > key.size() {
        return Err(RsaSignatureError::InputTooLong);
    }
    let mut expected = vec![0; key.size() - input.len()];
    expected.extend_from_slice(input);
    if public_operation(key, signature)? == expected {
        Ok(())
    } else {
        Err(RsaSignatureError::InvalidSignature)
    }
}

fn pkcs1v15_encoded_payload(
    modulus_size: usize,
    payload: &[u8],
) -> Result<Vec<u8>, RsaSignatureError> {
    if payload.len() > modulus_size.saturating_sub(11) {
        return Err(RsaSignatureError::InputTooLong);
    }
    let mut encoded = vec![0, 1];
    encoded.resize(modulus_size - payload.len() - 1, 0xff);
    encoded.push(0);
    encoded.extend_from_slice(payload);
    Ok(encoded)
}

pub fn rsa_sign_pkcs1v15_payload(
    key: &RsaPrivateKey,
    payload: &[u8],
) -> Result<Vec<u8>, RsaSignatureError> {
    private_operation(key, &pkcs1v15_encoded_payload(key.size(), payload)?)
}

pub fn rsa_verify_pkcs1v15_payload(
    key: &RsaPublicKey,
    payload: &[u8],
    signature: &[u8],
) -> Result<(), RsaSignatureError> {
    let expected = pkcs1v15_encoded_payload(key.size(), payload)?;
    if public_operation(key, signature)? == expected {
        Ok(())
    } else {
        Err(RsaSignatureError::InvalidSignature)
    }
}

fn digest_info(hash: RsaHashAlgorithm, digest: &[u8]) -> Result<Vec<u8>, RsaSignatureError> {
    if digest.len() != hash.output_length() {
        return Err(RsaSignatureError::InvalidDigestLength);
    }
    let mut result = hash.digest_info_prefix().to_vec();
    result.extend_from_slice(digest);
    Ok(result)
}

pub fn rsa_sign_pkcs1v15_digest(
    key: &RsaPrivateKey,
    hash: RsaHashAlgorithm,
    digest: &[u8],
) -> Result<Vec<u8>, RsaSignatureError> {
    rsa_sign_pkcs1v15_payload(key, &digest_info(hash, digest)?)
}

pub fn rsa_verify_pkcs1v15_digest(
    key: &RsaPublicKey,
    hash: RsaHashAlgorithm,
    digest: &[u8],
    signature: &[u8],
) -> Result<(), RsaSignatureError> {
    rsa_verify_pkcs1v15_payload(key, &digest_info(hash, digest)?, signature)
}

fn mgf1(seed: &[u8], length: usize, hash: RsaHashAlgorithm) -> Result<Vec<u8>, RsaSignatureError> {
    let mut output = Vec::with_capacity(length);
    let mut counter = 0_u32;
    while output.len() < length {
        let mut input = Vec::with_capacity(seed.len() + 4);
        input.extend_from_slice(seed);
        input.extend_from_slice(&counter.to_be_bytes());
        output.extend_from_slice(&hash.digest(&input));
        counter = counter
            .checked_add(1)
            .ok_or(RsaSignatureError::InputTooLong)?;
    }
    output.truncate(length);
    Ok(output)
}

fn pss_encoded_digest(
    modulus_bits: usize,
    parameters: RsaPssParameters,
    digest: &[u8],
) -> Result<Vec<u8>, RsaSignatureError> {
    if digest.len() != parameters.hash.output_length() {
        return Err(RsaSignatureError::InvalidDigestLength);
    }
    let em_bits = modulus_bits
        .checked_sub(1)
        .ok_or(RsaSignatureError::InvalidKey)?;
    let em_len = em_bits.div_ceil(8);
    let hash_length = parameters.hash.output_length();
    if em_len < hash_length + parameters.salt_length + 2 {
        return Err(RsaSignatureError::InputTooLong);
    }
    let mut salt = vec![0; parameters.salt_length];
    getrandom::fill(&mut salt).map_err(|_| RsaSignatureError::RandomnessUnavailable)?;
    let mut m_prime = vec![0; 8];
    m_prime.extend_from_slice(digest);
    m_prime.extend_from_slice(&salt);
    let h = parameters.hash.digest(&m_prime);
    let mut db = vec![0; em_len - parameters.salt_length - hash_length - 2];
    db.push(1);
    db.extend_from_slice(&salt);
    let mask = mgf1(&h, db.len(), parameters.mgf_hash)?;
    for (value, mask) in db.iter_mut().zip(mask) {
        *value ^= mask;
    }
    db[0] &= 0xff >> (8 * em_len - em_bits);
    db.extend_from_slice(&h);
    db.push(0xbc);
    Ok(db)
}

pub fn rsa_sign_pss_digest(
    key: &RsaPrivateKey,
    parameters: RsaPssParameters,
    digest: &[u8],
) -> Result<Vec<u8>, RsaSignatureError> {
    private_operation(
        key,
        &pss_encoded_digest(key.n().bits(), parameters, digest)?,
    )
}

pub fn rsa_verify_pss_digest(
    key: &RsaPublicKey,
    parameters: RsaPssParameters,
    digest: &[u8],
    signature: &[u8],
) -> Result<(), RsaSignatureError> {
    if digest.len() != parameters.hash.output_length() {
        return Err(RsaSignatureError::InvalidDigestLength);
    }
    let em_bits = key
        .n()
        .bits()
        .checked_sub(1)
        .ok_or(RsaSignatureError::InvalidKey)?;
    let em_len = em_bits.div_ceil(8);
    let recovered = public_operation(key, signature)?;
    let prefix_length = recovered
        .len()
        .checked_sub(em_len)
        .ok_or(RsaSignatureError::InvalidSignature)?;
    if recovered[..prefix_length].iter().any(|byte| *byte != 0) {
        return Err(RsaSignatureError::InvalidSignature);
    }
    let encoded = &recovered[prefix_length..];
    let hash_length = parameters.hash.output_length();
    if encoded.len() < hash_length + parameters.salt_length + 2 || encoded.last() != Some(&0xbc) {
        return Err(RsaSignatureError::InvalidSignature);
    }
    let h_offset = encoded.len() - hash_length - 1;
    let masked_db = &encoded[..h_offset];
    let h = &encoded[h_offset..h_offset + hash_length];
    let unused_bits = 8 * em_len - em_bits;
    if unused_bits != 0
        && masked_db
            .first()
            .is_some_and(|value| *value & (0xff << (8 - unused_bits)) != 0)
    {
        return Err(RsaSignatureError::InvalidSignature);
    }
    let mask = mgf1(h, masked_db.len(), parameters.mgf_hash)?;
    let mut db = masked_db.to_vec();
    for (value, mask) in db.iter_mut().zip(mask) {
        *value ^= mask;
    }
    db[0] &= 0xff >> unused_bits;
    let separator = db
        .len()
        .checked_sub(parameters.salt_length + 1)
        .ok_or(RsaSignatureError::InvalidSignature)?;
    if db.get(separator) != Some(&1) || db[..separator].iter().any(|value| *value != 0) {
        return Err(RsaSignatureError::InvalidSignature);
    }
    let mut m_prime = vec![0; 8];
    m_prime.extend_from_slice(digest);
    m_prime.extend_from_slice(&db[separator + 1..]);
    if parameters.hash.digest(&m_prime) == h {
        Ok(())
    } else {
        Err(RsaSignatureError::InvalidSignature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key_pair() -> (RsaPrivateKey, RsaPublicKey) {
        let private = RsaPrivateKey::new(&mut rsa::rand_core::OsRng, 2_048).unwrap();
        let public = RsaPublicKey::from(&private);
        (private, public)
    }

    #[test]
    fn raw_and_pkcs1_payload_signatures_round_trip() {
        let (private, public) = key_pair();
        for (sign, verify) in [
            (
                rsa_sign_raw as fn(&RsaPrivateKey, &[u8]) -> _,
                rsa_verify_raw as fn(&RsaPublicKey, &[u8], &[u8]) -> _,
            ),
            (rsa_sign_pkcs1v15_payload, rsa_verify_pkcs1v15_payload),
        ] {
            let signature = sign(&private, b"caller-controlled payload").unwrap();
            verify(&public, b"caller-controlled payload", &signature).unwrap();
            assert_eq!(
                verify(&public, b"changed", &signature),
                Err(RsaSignatureError::InvalidSignature)
            );
        }
    }

    #[test]
    fn every_digest_info_hash_round_trips() {
        let (private, public) = key_pair();
        for hash in [
            RsaHashAlgorithm::Sha1,
            RsaHashAlgorithm::Sha224,
            RsaHashAlgorithm::Sha256,
            RsaHashAlgorithm::Sha384,
            RsaHashAlgorithm::Sha512,
            RsaHashAlgorithm::Sha3_224,
            RsaHashAlgorithm::Sha3_256,
            RsaHashAlgorithm::Sha3_384,
            RsaHashAlgorithm::Sha3_512,
        ] {
            let digest = hash.digest(b"message");
            let signature = rsa_sign_pkcs1v15_digest(&private, hash, &digest).unwrap();
            rsa_verify_pkcs1v15_digest(&public, hash, &digest, &signature).unwrap();
        }
    }

    #[test]
    fn pss_supports_independent_hash_mgf_and_salt() {
        let (private, public) = key_pair();
        let parameters = RsaPssParameters {
            hash: RsaHashAlgorithm::Sha3_384,
            mgf_hash: RsaHashAlgorithm::Sha256,
            salt_length: 37,
        };
        let digest = parameters.hash.digest(b"message");
        let signature = rsa_sign_pss_digest(&private, parameters, &digest).unwrap();
        rsa_verify_pss_digest(&public, parameters, &digest, &signature).unwrap();
        let wrong = RsaPssParameters {
            salt_length: 36,
            ..parameters
        };
        assert_eq!(
            rsa_verify_pss_digest(&public, wrong, &digest, &signature),
            Err(RsaSignatureError::InvalidSignature)
        );
    }
}
