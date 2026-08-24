//! Emulator-side ARKG-P256 operations for Yubico's experimental previewSign.
//!
//! The fixed private seeds are test-device firmware state. They are deliberately
//! deterministic so end-to-end tests can reproduce registrations and signatures.

use minicbor::{Decoder, Encoder};
use software_key_core::{
    arkg::{
        arkg_p256_derive_private, arkg_p256_public_point,
        ARKG_P256_MAX_CONTEXT_LENGTH as MAX_CONTEXT_LENGTH,
        ARKG_P256_POINT_LENGTH as P256_POINT_LENGTH, ARKG_P256_TICKET_LENGTH as ARKG_TICKET_LENGTH,
    },
    software_signing::{SoftwareSigningAlgorithm, SoftwareSigningKey},
};

pub(crate) const ARKG_P256_ESP256_ALGORITHM: i64 = -65_539;
const ARKG_PUBLIC_KEY_TYPE: i64 = -65_537;
const ARKG_P256_ALGORITHM: i64 = -65_700;
const ESP256_ALGORITHM: i64 = -9;
const COSE_EC2_KEY_TYPE: i64 = 2;
const COSE_P256_CURVE: i64 = 1;

const BLINDING_PRIVATE: [u8; 32] = [
    0xd9, 0x59, 0x50, 0x0a, 0x78, 0xcc, 0xf8, 0x50, 0xce, 0x46, 0xc8, 0x0a, 0x8c, 0x50, 0x43, 0xc9,
    0xa2, 0xe3, 0x38, 0x44, 0x23, 0x2b, 0x38, 0x29, 0xdf, 0x37, 0xd0, 0x5b, 0x30, 0x69, 0xf4, 0x55,
];
const KEM_PRIVATE: [u8; 32] = [
    0x74, 0xe0, 0xa4, 0xcd, 0x81, 0xca, 0x2d, 0x24, 0x24, 0x6f, 0xf7, 0x5b, 0xfd, 0x6d, 0x4f, 0xb7,
    0xf9, 0xdf, 0xc9, 0x38, 0x37, 0x26, 0x27, 0xfe, 0xb2, 0xc2, 0x34, 0x8f, 0x8b, 0x14, 0x93, 0xb5,
];

pub(crate) fn seed_cose() -> Result<Vec<u8>, &'static str> {
    let blinding = arkg_p256_public_point(&BLINDING_PRIVATE).map_err(|_| "invalid seed")?;
    let kem = arkg_p256_public_point(&KEM_PRIVATE).map_err(|_| "invalid seed")?;
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
    let private = arkg_p256_derive_private(&BLINDING_PRIVATE, &KEM_PRIVATE, &ticket, &context)
        .map_err(|error| match error {
            software_key_core::arkg::ArkgP256Error::TicketAuthenticationFailed => {
                "ticket authentication failed"
            }
            _ => "private derivation failed",
        })?;
    let algorithm = SoftwareSigningAlgorithm::EcdsaP256Sha256;
    SoftwareSigningKey::from_serialized(algorithm, &private[..])
        .and_then(|key| key.sign_prehash(algorithm, digest))
        .map(|signature| signature.into_bytes())
        .map_err(|_| "signing failed")
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
