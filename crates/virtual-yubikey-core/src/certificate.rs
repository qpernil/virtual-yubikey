//! Certificate construction shared by applets that expose device identities.

use der::Encode;
use software_key_core::certificate_signing::{CertificateSignature, CertificateSigner};
use spki::SubjectPublicKeyInfoOwned;
use x509_cert::{
    builder::{Builder, CertificateBuilder, profile::BuilderProfile},
    serial_number::SerialNumber,
    time::Validity,
};

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
