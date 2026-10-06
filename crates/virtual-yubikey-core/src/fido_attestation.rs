//! Per-device virtual FIDO identity. Trust requires explicitly pinning its certificate.
use der::{Decode, Encode};
use minicbor::Encoder;
use software_key_core::{
    certificate_signing::{CertificateSigner, subject_public_key_info},
    software_signing::{EcCurve, KeyKind, SoftwareSigningKey},
};
use spki::SubjectPublicKeyInfoRef;
use std::str::FromStr;
use x509_cert::{
    Certificate,
    builder::profile::BuilderProfile,
    certificate::TbsCertificate,
    ext::{
        Extension, ToExtension,
        pkix::{BasicConstraints, KeyUsage, KeyUsages},
    },
    name::Name,
    time::{Time, Validity},
};
use zeroize::Zeroizing;

#[derive(Clone)]
pub(crate) struct Identity {
    key: SoftwareSigningKey,
    certificate: Vec<u8>,
}

struct Profile(Name);
impl BuilderProfile for Profile {
    fn get_issuer(&self, _: &Name) -> Name {
        self.0.clone()
    }
    fn get_subject(&self) -> Name {
        self.0.clone()
    }
    fn build_extensions(
        &self,
        _: SubjectPublicKeyInfoRef<'_>,
        _: SubjectPublicKeyInfoRef<'_>,
        tbs: &TbsCertificate,
    ) -> x509_cert::builder::Result<Vec<Extension>> {
        let mut extensions = vec![
            BasicConstraints {
                ca: false,
                path_len_constraint: None,
            }
            .to_extension(tbs.subject(), &[])?,
        ];
        extensions.push(
            KeyUsage(KeyUsages::DigitalSignature.into())
                .to_extension(tbs.subject(), &extensions)?,
        );
        // The certificate's AAGUID must match authenticatorData; it is non-critical.
        extensions.push(Extension {
            extn_id: const_oid::ObjectIdentifier::new_unwrap("1.3.6.1.4.1.45724.1.1.4"),
            critical: false,
            extn_value: der::asn1::OctetString::new(
                der::asn1::OctetString::new([0x50; 16])?.to_der()?,
            )?,
        });
        Ok(extensions)
    }
}
impl Identity {
    pub(crate) fn generate() -> Result<Self, ()> {
        let key = SoftwareSigningKey::generate(EcCurve::P256.signature_scheme()).map_err(|_| ())?;
        let signer = CertificateSigner::from_key(&key).map_err(|_| ())?;
        let mut serial = [0u8; 16];
        getrandom::fill(&mut serial).map_err(|_| ())?;
        serial[0] = (serial[0] & 0x7f) | 1;
        let certificate = crate::certificate::build(
            Profile(Name::from_str("C=SE,O=Virtual YubiKey,OU=Authenticator Attestation,CN=Virtual FIDO Attestation").map_err(|_| ())?),
            &serial,
            Validity::new(Time::from_str("2026-01-01T00:00:00Z").map_err(|_| ())?, Time::from_str("2049-12-31T23:59:59Z").map_err(|_| ())?),
            subject_public_key_info(&key.public_key()).map_err(|_| ())?, &signer)?;
        Ok(Self { key, certificate })
    }
    pub(crate) fn serialized_key(&self) -> Result<Zeroizing<Vec<u8>>, ()> {
        self.key.serialized().map_err(|_| ())
    }
    pub(crate) fn certificate(&self) -> &[u8] {
        &self.certificate
    }
    pub(crate) fn restore(key: &[u8], certificate: &[u8]) -> Result<Self, &'static str> {
        let key = SoftwareSigningKey::from_serialized_for_kind(KeyKind::Ec(EcCurve::P256), key)
            .map_err(|_| "invalid FIDO attestation key")?;
        let parsed = Certificate::from_der(certificate)
            .map_err(|_| "invalid FIDO attestation certificate")?;
        if parsed.tbs_certificate().subject_public_key_info()
            != &subject_public_key_info(&key.public_key())
                .map_err(|_| "invalid FIDO attestation public key")?
        {
            return Err("FIDO attestation certificate does not match key");
        }
        Ok(Self {
            key,
            certificate: certificate.to_vec(),
        })
    }
    pub(crate) fn statement(&self, auth_data: &[u8], client_hash: &[u8]) -> Result<Vec<u8>, ()> {
        let mut message = auth_data.to_vec();
        message.extend_from_slice(client_hash);
        let signature = self
            .key
            .sign_message(EcCurve::P256.signature_scheme(), &message)
            .map_err(|_| ())?
            .to_ecdsa_der(EcCurve::P256)
            .map_err(|_| ())?;
        let mut result = Vec::new();
        Encoder::new(&mut result)
            .map(3)
            .map_err(|_| ())?
            .str("alg")
            .map_err(|_| ())?
            .i8(-7)
            .map_err(|_| ())?
            .str("sig")
            .map_err(|_| ())?
            .bytes(&signature)
            .map_err(|_| ())?
            .str("x5c")
            .map_err(|_| ())?
            .array(1)
            .map_err(|_| ())?
            .bytes(&self.certificate)
            .map_err(|_| ())?;
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use signature::Verifier;
    #[test]
    fn certificate_meets_packed_profile_and_restored_identity_matches_key() {
        let identity = Identity::generate().unwrap();
        let cert = Certificate::from_der(identity.certificate()).unwrap();
        let tbs = cert.tbs_certificate();
        let subject = tbs.subject().to_string();
        for field in [
            "C=SE",
            "O=Virtual YubiKey",
            "OU=Authenticator Attestation",
            "CN=Virtual FIDO Attestation",
        ] {
            assert!(subject.contains(field), "{subject}");
        }
        assert_eq!(tbs.subject(), tbs.issuer());
        let extensions = tbs.extensions().unwrap();
        let constraints = extensions
            .iter()
            .find(|e| e.extn_id == const_oid::ObjectIdentifier::new_unwrap("2.5.29.19"))
            .unwrap();
        assert!(
            !BasicConstraints::from_der(constraints.extn_value.as_bytes())
                .unwrap()
                .ca
        );
        let aaguid = extensions
            .iter()
            .find(|e| {
                e.extn_id == const_oid::ObjectIdentifier::new_unwrap("1.3.6.1.4.1.45724.1.1.4")
            })
            .unwrap();
        assert!(!aaguid.critical);
        assert_eq!(
            der::asn1::OctetString::from_der(aaguid.extn_value.as_bytes())
                .unwrap()
                .as_bytes(),
            [0x50; 16]
        );
        let public = tbs
            .subject_public_key_info()
            .subject_public_key
            .as_bytes()
            .unwrap();
        p256::ecdsa::VerifyingKey::from_sec1_bytes(public)
            .unwrap()
            .verify(
                &tbs.to_der().unwrap(),
                &p256::ecdsa::Signature::from_der(cert.signature().as_bytes().unwrap()).unwrap(),
            )
            .unwrap();
        let key = identity.serialized_key().unwrap();
        assert!(Identity::restore(&key, identity.certificate()).is_ok());
        let other = Identity::generate().unwrap();
        assert!(Identity::restore(&key, other.certificate()).is_err());
    }
}
