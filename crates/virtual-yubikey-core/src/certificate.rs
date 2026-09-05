//! Certificate construction shared by applets that expose device identities.

use const_oid::ObjectIdentifier;
use der::{
    Decode, Encode,
    asn1::{Any, BitString},
};
use rsa::{BigUint, RsaPublicKey, pkcs8::EncodePublicKey as EncodeRsaPublicKey};
use signature::{Keypair, Signer};
use software_key_core::software_signing::{
    EcCurve, EdwardsCurve, SignatureScheme, SoftwarePublicKey, SoftwareSigningKey,
};
use spki::{
    AlgorithmIdentifierOwned, DynSignatureAlgorithmIdentifier, SignatureBitStringEncoding,
    SubjectPublicKeyInfoOwned,
};
use x509_cert::{
    builder::{Builder, CertificateBuilder, profile::BuilderProfile},
    serial_number::SerialNumber,
    time::Validity,
};

#[derive(Clone)]
pub(crate) struct CertificateVerifyingKey(SubjectPublicKeyInfoOwned);

impl spki::EncodePublicKey for CertificateVerifyingKey {
    fn to_public_key_der(&self) -> spki::Result<spki::Document> {
        spki::Document::try_from(self.0.to_der()?).map_err(Into::into)
    }
}

#[derive(Clone, Copy)]
enum CertificateSignatureScheme {
    RsaSha256,
    EcdsaP256Sha256,
    EcdsaP384Sha384,
    Ed25519,
}

pub(crate) struct CertificateSigner {
    key: SoftwareSigningKey,
    verifying_key: CertificateVerifyingKey,
    scheme: CertificateSignatureScheme,
}

impl CertificateSigner {
    pub(crate) fn from_key(key: &SoftwareSigningKey) -> Result<Self, ()> {
        let scheme = match key.public_key() {
            SoftwarePublicKey::Rsa { .. } => CertificateSignatureScheme::RsaSha256,
            SoftwarePublicKey::Ec {
                curve: EcCurve::P256,
                ..
            } => CertificateSignatureScheme::EcdsaP256Sha256,
            SoftwarePublicKey::Ec {
                curve: EcCurve::P384,
                ..
            } => CertificateSignatureScheme::EcdsaP384Sha384,
            SoftwarePublicKey::Edwards {
                curve: EdwardsCurve::Ed25519,
                ..
            } => CertificateSignatureScheme::Ed25519,
            _ => return Err(()),
        };
        Ok(Self {
            key: key.clone(),
            verifying_key: CertificateVerifyingKey(subject_public_key_info(key)?),
            scheme,
        })
    }
}

impl Keypair for CertificateSigner {
    type VerifyingKey = CertificateVerifyingKey;

    fn verifying_key(&self) -> Self::VerifyingKey {
        self.verifying_key.clone()
    }
}

impl DynSignatureAlgorithmIdentifier for CertificateSigner {
    fn signature_algorithm_identifier(&self) -> spki::Result<AlgorithmIdentifierOwned> {
        let (oid, parameters) = match self.scheme {
            CertificateSignatureScheme::RsaSha256 => (
                ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11"),
                Some(Any::null()),
            ),
            CertificateSignatureScheme::EcdsaP256Sha256 => {
                (ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2"), None)
            }
            CertificateSignatureScheme::EcdsaP384Sha384 => {
                (ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.3"), None)
            }
            CertificateSignatureScheme::Ed25519 => {
                (ObjectIdentifier::new_unwrap("1.3.101.112"), None)
            }
        };
        Ok(AlgorithmIdentifierOwned { oid, parameters })
    }
}

struct CertificateSignature(Vec<u8>);

impl SignatureBitStringEncoding for CertificateSignature {
    fn to_bitstring(&self) -> der::Result<BitString> {
        BitString::from_bytes(&self.0)
    }
}

impl Signer<CertificateSignature> for CertificateSigner {
    fn try_sign(
        &self,
        message: &[u8],
    ) -> core::result::Result<CertificateSignature, signature::Error> {
        let scheme = match self.scheme {
            CertificateSignatureScheme::RsaSha256 => SignatureScheme::RsaPkcs1Sha256,
            CertificateSignatureScheme::EcdsaP256Sha256 => SignatureScheme::EcdsaP256Sha256,
            CertificateSignatureScheme::EcdsaP384Sha384 => SignatureScheme::EcdsaP384Sha384,
            CertificateSignatureScheme::Ed25519 => SignatureScheme::Ed25519,
        };
        let signature = self
            .key
            .sign_message(scheme, message)
            .map_err(|_| signature::Error::new())?;
        let signature = match self.scheme {
            CertificateSignatureScheme::EcdsaP256Sha256 => signature
                .to_ecdsa_der(EcCurve::P256)
                .map_err(|_| signature::Error::new())?,
            CertificateSignatureScheme::EcdsaP384Sha384 => signature
                .to_ecdsa_der(EcCurve::P384)
                .map_err(|_| signature::Error::new())?,
            CertificateSignatureScheme::RsaSha256 | CertificateSignatureScheme::Ed25519 => {
                signature.into_bytes()
            }
        };
        Ok(CertificateSignature(signature))
    }
}

pub(crate) fn subject_public_key_info(
    key: &SoftwareSigningKey,
) -> Result<SubjectPublicKeyInfoOwned, ()> {
    match key.public_key() {
        SoftwarePublicKey::Ec {
            curve,
            uncompressed,
        } => ec_subject_public_key_info(curve, &uncompressed),
        SoftwarePublicKey::Edwards {
            curve: EdwardsCurve::Ed25519,
            public_key,
        } => Ok(SubjectPublicKeyInfoOwned {
            algorithm: AlgorithmIdentifierOwned {
                oid: ObjectIdentifier::new_unwrap("1.3.101.112"),
                parameters: None,
            },
            subject_public_key: BitString::from_bytes(&public_key).map_err(|_| ())?,
        }),
        SoftwarePublicKey::Rsa { modulus, exponent } => {
            let public = RsaPublicKey::new(
                BigUint::from_bytes_be(&modulus),
                BigUint::from_bytes_be(&exponent),
            )
            .map_err(|_| ())?;
            let encoded = public.to_public_key_der().map_err(|_| ())?;
            SubjectPublicKeyInfoOwned::from_der(encoded.as_bytes()).map_err(|_| ())
        }
        SoftwarePublicKey::Edwards { .. } | SoftwarePublicKey::MlDsa { .. } => Err(()),
    }
}

fn ec_subject_public_key_info(
    curve: EcCurve,
    uncompressed: &[u8],
) -> Result<SubjectPublicKeyInfoOwned, ()> {
    let curve_oid = match curve {
        EcCurve::P256 => ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7"),
        EcCurve::P384 => ObjectIdentifier::new_unwrap("1.3.132.0.34"),
        _ => return Err(()),
    };
    Ok(SubjectPublicKeyInfoOwned {
        algorithm: AlgorithmIdentifierOwned {
            oid: ObjectIdentifier::new_unwrap("1.2.840.10045.2.1"),
            parameters: Some(Any::encode_from(&curve_oid).map_err(|_| ())?),
        },
        subject_public_key: BitString::from_bytes(uncompressed).map_err(|_| ())?,
    })
}

pub(crate) fn build(
    profile: impl BuilderProfile,
    serial: &[u8],
    validity: Validity,
    subject_public_key: SubjectPublicKeyInfoOwned,
    signer: &CertificateSigner,
) -> Result<Vec<u8>, ()> {
    let certificate = CertificateBuilder::new(
        profile,
        SerialNumber::new(serial).map_err(|_| ())?,
        validity,
        subject_public_key,
    )
    .map_err(|_| ())?
    .build::<_, CertificateSignature>(signer)
    .map_err(|_| ())?;
    certificate.to_der().map_err(|_| ())
}
