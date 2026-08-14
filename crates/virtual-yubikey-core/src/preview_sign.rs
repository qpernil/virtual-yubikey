//! Emulator-side ARKG-P256 operations for Yubico's experimental previewSign.
//!
//! The fixed private seeds are test-device firmware state. They are deliberately
//! deterministic so end-to-end tests can reproduce registrations and signatures.

use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use minicbor::{Decoder, Encoder};
use p256::{
    ecdsa::SigningKey,
    elliptic_curve::{group::ff::PrimeField, sec1::ToSec1Point, Field, Group},
    FieldBytes, ProjectivePoint, PublicKey, Scalar,
};
use sha2::{Digest, Sha256};
use signature::hazmat::PrehashSigner;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

pub(crate) const ARKG_P256_ESP256_ALGORITHM: i64 = -65_539;
const ARKG_PUBLIC_KEY_TYPE: i64 = -65_537;
const ARKG_P256_ALGORITHM: i64 = -65_700;
const ESP256_ALGORITHM: i64 = -9;
const COSE_EC2_KEY_TYPE: i64 = 2;
const COSE_P256_CURVE: i64 = 1;
const MAX_CONTEXT_LENGTH: usize = 64;
const P256_POINT_LENGTH: usize = 65;
const ARKG_TICKET_LENGTH: usize = 16 + P256_POINT_LENGTH;
const HASH_TO_SCALAR_LENGTH: usize = 48;

const DERIVE_KEY_KEM_LABEL: &[u8] = b"ARKG-Derive-Key-KEM.";
const DERIVE_KEY_BL_LABEL: &[u8] = b"ARKG-Derive-Key-BL.";
const ECDH_AUGMENTED_DST: &[u8] = b"ARKG-ECDH.ARKG-P256";
const KEM_MAC_LABEL: &[u8] = b"ARKG-KEM-HMAC-mac.";
const KEM_SHARED_LABEL: &[u8] = b"ARKG-KEM-HMAC-shared.";
const BLINDING_PRF_LABEL: &[u8] = b"ARKG-BL-EC.ARKG-P256";

const BLINDING_PRIVATE: [u8; 32] = [
    0xd9, 0x59, 0x50, 0x0a, 0x78, 0xcc, 0xf8, 0x50, 0xce, 0x46, 0xc8, 0x0a, 0x8c, 0x50, 0x43, 0xc9,
    0xa2, 0xe3, 0x38, 0x44, 0x23, 0x2b, 0x38, 0x29, 0xdf, 0x37, 0xd0, 0x5b, 0x30, 0x69, 0xf4, 0x55,
];
const KEM_PRIVATE: [u8; 32] = [
    0x74, 0xe0, 0xa4, 0xcd, 0x81, 0xca, 0x2d, 0x24, 0x24, 0x6f, 0xf7, 0x5b, 0xfd, 0x6d, 0x4f, 0xb7,
    0xf9, 0xdf, 0xc9, 0x38, 0x37, 0x26, 0x27, 0xfe, 0xb2, 0xc2, 0x34, 0x8f, 0x8b, 0x14, 0x93, 0xb5,
];

pub(crate) fn seed_cose() -> Result<Vec<u8>, &'static str> {
    let blinding = public_point(BLINDING_PRIVATE)?;
    let kem = public_point(KEM_PRIVATE)?;
    let blinding = encode_ec2(&blinding)?;
    let kem = encode_ec2(&kem)?;

    let mut encoded = Vec::new();
    let mut encoder = Encoder::new(&mut encoded);
    encoder
        .map(5)
        .and_then(|encoder| encoder.u8(1))
        .and_then(|encoder| encoder.i64(ARKG_PUBLIC_KEY_TYPE))
        .and_then(|encoder| encoder.u8(3))
        .and_then(|encoder| encoder.i64(ARKG_P256_ALGORITHM))
        .and_then(|encoder| encoder.i8(-1))
        .map_err(|_| "failed to encode ARKG seed")?;
    encoder.writer_mut().extend_from_slice(&blinding);
    encoder.i8(-2).map_err(|_| "failed to encode ARKG seed")?;
    encoder.writer_mut().extend_from_slice(&kem);
    encoder
        .i8(-3)
        .and_then(|encoder| encoder.i64(ESP256_ALGORITHM))
        .map_err(|_| "failed to encode ARKG seed")?;
    Ok(encoded)
}

pub(crate) fn sign(signing_arguments_cbor: &[u8], digest: &[u8]) -> Result<Vec<u8>, &'static str> {
    let digest: &[u8; 32] = digest
        .try_into()
        .map_err(|_| "previewSign requires a 32-byte digest")?;
    let (ticket, context) = decode_signing_arguments(signing_arguments_cbor)?;
    let ephemeral =
        PublicKey::from_sec1_bytes(&ticket[16..]).map_err(|_| "invalid ticket point")?;
    let kem_private = private_scalar(KEM_PRIVATE)?;
    let shared = projective_to_uncompressed(ephemeral.to_projective() * kem_private)?;
    let shared_secret =
        Zeroizing::new(<[u8; 32]>::try_from(&shared[1..33]).map_err(|_| "invalid shared secret")?);

    let mut context_prime = Vec::with_capacity(context.len() + 1);
    context_prime.push(u8::try_from(context.len()).map_err(|_| "context length")?);
    context_prime.extend_from_slice(&context);
    let context_kem = concatenate(&[DERIVE_KEY_KEM_LABEL, &context_prime]);
    let mac_info = concatenate(&[KEM_MAC_LABEL, ECDH_AUGMENTED_DST, &context_kem]);
    let mac_key = hkdf_sha256(&shared_secret[..], &mac_info)?;
    let mut mac = <Hmac<Sha256> as hmac::digest::KeyInit>::new_from_slice(&mac_key[..])
        .map_err(|_| "invalid HMAC key")?;
    mac.update(&ticket[16..]);
    if !bool::from(ticket[..16].ct_eq(&mac.finalize().into_bytes()[..16])) {
        return Err("ticket authentication failed");
    }

    let shared_info = concatenate(&[KEM_SHARED_LABEL, ECDH_AUGMENTED_DST, &context_kem]);
    let blinding_input = hkdf_sha256(&shared_secret[..], &shared_info)?;
    let context_bl = concatenate(&[DERIVE_KEY_BL_LABEL, &context_prime]);
    let blinding_dst = concatenate(&[BLINDING_PRF_LABEL, &context_bl]);
    let tau = hash_to_scalar(&blinding_input[..], &blinding_dst)?;
    let private = private_scalar(BLINDING_PRIVATE)? + tau;
    if bool::from(private.is_zero()) {
        return Err("derived private key is zero");
    }
    let signing_key =
        SigningKey::from_bytes(&private.to_bytes()).map_err(|_| "invalid signing key")?;
    let signature: p256::ecdsa::Signature = signing_key
        .sign_prehash(digest)
        .map_err(|_| "signing failed")?;
    Ok(signature.to_bytes().to_vec())
}

fn decode_signing_arguments(
    encoded: &[u8],
) -> Result<([u8; ARKG_TICKET_LENGTH], Vec<u8>), &'static str> {
    let mut decoder = Decoder::new(encoded);
    let count = decoder
        .map()
        .map_err(|_| "invalid signing arguments")?
        .ok_or("indefinite signing arguments")?;
    let mut algorithm = None;
    let mut ticket = None;
    let mut context = None;
    for _ in 0..count {
        match decoder.i64().map_err(|_| "invalid signing argument key")? {
            3 if algorithm.is_none() => {
                algorithm = Some(decoder.i64().map_err(|_| "invalid signing algorithm")?)
            }
            -1 if ticket.is_none() => {
                ticket = Some(
                    decoder
                        .bytes()
                        .map_err(|_| "invalid signing ticket")?
                        .try_into()
                        .map_err(|_| "invalid signing ticket length")?,
                )
            }
            -2 if context.is_none() => {
                context = Some(
                    decoder
                        .bytes()
                        .map_err(|_| "invalid signing context")?
                        .to_vec(),
                )
            }
            3 | -1 | -2 => return Err("duplicate signing argument"),
            _ => decoder.skip().map_err(|_| "invalid signing argument")?,
        }
    }
    if decoder.position() != encoded.len() || algorithm != Some(ARKG_P256_ESP256_ALGORITHM) {
        return Err("invalid signing arguments");
    }
    let context = context.ok_or("missing signing context")?;
    if context.len() > MAX_CONTEXT_LENGTH {
        return Err("context is too long");
    }
    Ok((ticket.ok_or("missing signing ticket")?, context))
}

fn public_point(private: [u8; 32]) -> Result<[u8; P256_POINT_LENGTH], &'static str> {
    projective_to_uncompressed(ProjectivePoint::GENERATOR * private_scalar(private)?)
}

fn private_scalar(bytes: [u8; 32]) -> Result<Scalar, &'static str> {
    Option::<Scalar>::from(Scalar::from_repr(bytes.into())).ok_or("invalid private scalar")
}

fn encode_ec2(point: &[u8; P256_POINT_LENGTH]) -> Result<Vec<u8>, &'static str> {
    let mut encoded = Vec::new();
    Encoder::new(&mut encoded)
        .map(5)
        .and_then(|encoder| encoder.u8(1))
        .and_then(|encoder| encoder.i64(COSE_EC2_KEY_TYPE))
        .and_then(|encoder| encoder.u8(3))
        .and_then(|encoder| encoder.i64(ESP256_ALGORITHM))
        .and_then(|encoder| encoder.i8(-1))
        .and_then(|encoder| encoder.i64(COSE_P256_CURVE))
        .and_then(|encoder| encoder.i8(-2))
        .and_then(|encoder| encoder.bytes(&point[1..33]))
        .and_then(|encoder| encoder.i8(-3))
        .and_then(|encoder| encoder.bytes(&point[33..]))
        .map_err(|_| "failed to encode EC2 key")?;
    Ok(encoded)
}

fn hkdf_sha256(
    input_keying_material: &[u8],
    info: &[u8],
) -> Result<Zeroizing<[u8; 32]>, &'static str> {
    let hkdf = Hkdf::<Sha256>::new(None, input_keying_material);
    let mut output = Zeroizing::new([0_u8; 32]);
    hkdf.expand(info, &mut *output)
        .map_err(|_| "invalid HKDF output length")?;
    Ok(output)
}

fn hash_to_scalar(message: &[u8], domain: &[u8]) -> Result<Scalar, &'static str> {
    if domain.len() > u8::MAX as usize {
        return Err("hash-to-scalar domain is too long");
    }
    let mut domain_prime = domain.to_vec();
    domain_prime.push(u8::try_from(domain.len()).map_err(|_| "domain length")?);

    let mut b0_hasher = Sha256::new();
    b0_hasher.update([0_u8; 64]);
    b0_hasher.update(message);
    b0_hasher.update([0, HASH_TO_SCALAR_LENGTH as u8]);
    b0_hasher.update([0]);
    b0_hasher.update(&domain_prime);
    let b0 = b0_hasher.finalize();

    let mut b1_hasher = Sha256::new();
    b1_hasher.update(b0);
    b1_hasher.update([1]);
    b1_hasher.update(&domain_prime);
    let b1 = b1_hasher.finalize();

    let mut xored = [0_u8; 32];
    for (output, (left, right)) in xored.iter_mut().zip(b0.iter().zip(b1.iter())) {
        *output = left ^ right;
    }
    let mut b2_hasher = Sha256::new();
    b2_hasher.update(xored);
    b2_hasher.update([2]);
    b2_hasher.update(&domain_prime);
    let b2 = b2_hasher.finalize();

    let mut uniform = [0_u8; HASH_TO_SCALAR_LENGTH];
    uniform[..32].copy_from_slice(&b1);
    uniform[32..].copy_from_slice(&b2[..16]);
    reduce_48_bytes(&uniform)
}

fn reduce_48_bytes(uniform: &[u8; HASH_TO_SCALAR_LENGTH]) -> Result<Scalar, &'static str> {
    let high = scalar_from_24_bytes(&uniform[..24])?;
    let low = scalar_from_24_bytes(&uniform[24..])?;
    let mut two_to_192_bytes = FieldBytes::default();
    two_to_192_bytes[7] = 1;
    let two_to_192 = Option::<Scalar>::from(Scalar::from_repr(two_to_192_bytes))
        .ok_or("invalid scalar reduction constant")?;
    Ok(high * two_to_192 + low)
}

fn scalar_from_24_bytes(input: &[u8]) -> Result<Scalar, &'static str> {
    if input.len() != 24 {
        return Err("invalid scalar input length");
    }
    let mut bytes = FieldBytes::default();
    bytes[8..].copy_from_slice(input);
    Option::<Scalar>::from(Scalar::from_repr(bytes)).ok_or("scalar input is out of range")
}

fn projective_to_uncompressed(
    point: ProjectivePoint,
) -> Result<[u8; P256_POINT_LENGTH], &'static str> {
    if bool::from(point.is_identity()) {
        return Err("identity point");
    }
    let encoded = point.to_affine().to_sec1_point(false);
    let bytes = encoded.as_bytes();
    let mut output = [0_u8; P256_POINT_LENGTH];
    if bytes.len() != output.len() {
        return Err("invalid point length");
    }
    output.copy_from_slice(bytes);
    Ok(output)
}

fn concatenate(parts: &[&[u8]]) -> Vec<u8> {
    let mut output = Vec::with_capacity(parts.iter().map(|part| part.len()).sum());
    for part in parts {
        output.extend_from_slice(part);
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seed_is_a_canonical_arkg_cose_key() {
        let seed = seed_cose().unwrap();
        let mut decoder = Decoder::new(&seed);
        assert_eq!(decoder.map().unwrap(), Some(5));
        assert_eq!(decoder.u8().unwrap(), 1);
        assert_eq!(decoder.i64().unwrap(), ARKG_PUBLIC_KEY_TYPE);
    }
}
