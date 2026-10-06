//! OpenPGP card 3.4.1: persistent credentials and keys, connection-scoped authorization.
use crate::{CommandApdu, PresenceAuthorization, ResponseApdu, UserPresencePolicy};
use software_key_core::{
    digest::HashAlgorithm,
    software_key_agreement::{MontgomeryCurve, SoftwareMontgomeryKey, derive_with_signing_key},
    software_signing::{EcCurve, EdwardsCurve, KeyKind, SoftwarePublicKey, SoftwareSigningKey},
};
use std::collections::BTreeMap;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;
pub const OPENPGP_AID: [u8; 6] = [0xd2, 0x76, 0x00, 0x01, 0x24, 0x01];
pub const MAX_RANDOM_RESPONSE_LENGTH: usize = 4096;
const MAX_OBJECT: usize = 4096;
type Result<T> = std::result::Result<T, u16>;

// Never keep submitted PINs; retain a salted verifier and the length needed by CHANGE.
struct Password {
    salt: [u8; 32],
    digest: Zeroizing<Vec<u8>>,
    length: usize,
    retries: u8,
    limit: u8,
}
impl std::fmt::Debug for Password {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Password")
            .field("retries", &self.retries)
            .finish_non_exhaustive()
    }
}
impl Password {
    fn new(value: &[u8], limit: u8) -> Self {
        let mut salt = [0; 32];
        getrandom::fill(&mut salt).expect("OpenPGP requires OS randomness");
        Self {
            salt,
            digest: Self::hash(&salt, value),
            length: value.len(),
            retries: limit,
            limit,
        }
    }
    fn hash(salt: &[u8], value: &[u8]) -> Zeroizing<Vec<u8>> {
        let mut input = Zeroizing::new(salt.to_vec());
        input.extend_from_slice(value);
        Zeroizing::new(HashAlgorithm::Sha256.digest(&input))
    }
    fn verify(&mut self, value: &[u8]) -> Result<()> {
        if self.retries == 0 {
            return Err(0x6983);
        }
        self.retries -= 1;
        if value.len() == self.length
            && bool::from(self.digest.ct_eq(&Self::hash(&self.salt, value)))
        {
            self.retries = self.limit;
            Ok(())
        } else {
            Err(if self.retries == 0 {
                0x6983
            } else {
                0x63c0 | u16::from(self.retries)
            })
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq)]
enum Algorithm {
    Rsa(usize),
    Ec(EcCurve),
    Ed25519,
    X25519,
}
fn algorithm(attributes: &[u8], index: usize) -> Result<Algorithm> {
    if attributes.first() == Some(&1) {
        if attributes.len() != 6 || attributes[3..] != [0, 32, 0] {
            return Err(0x6a80);
        }
        let bits = usize::from(u16::from_be_bytes([attributes[1], attributes[2]]));
        return if matches!(bits, 2048 | 3072 | 4096) {
            Ok(Algorithm::Rsa(bits))
        } else {
            Err(0x6a80)
        };
    }
    let (&id, oid) = attributes.split_first().ok_or(0x6a80u16)?;
    let oid = oid.strip_suffix(&[0xff]).unwrap_or(oid);
    if id == 0x16 && index != 1 && oid == [0x2b, 6, 1, 4, 1, 0xda, 0x47, 0xf, 1] {
        return Ok(Algorithm::Ed25519);
    }
    if id == 0x12 && index == 1 && oid == [0x2b, 6, 1, 4, 1, 0x97, 0x55, 1, 5, 1] {
        return Ok(Algorithm::X25519);
    }
    if id != if index == 1 { 0x12 } else { 0x13 } {
        return Err(0x6a80);
    }
    for (curve, expected) in curves() {
        if oid == expected {
            return Ok(Algorithm::Ec(curve));
        }
    }
    Err(0x6a80)
}
fn curves() -> [(EcCurve, &'static [u8]); 7] {
    [
        (EcCurve::P256, &[0x2a, 0x86, 0x48, 0xce, 0x3d, 3, 1, 7]),
        (EcCurve::P384, &[0x2b, 0x81, 4, 0, 0x22]),
        (EcCurve::P521, &[0x2b, 0x81, 4, 0, 0x23]),
        (EcCurve::Secp256k1, &[0x2b, 0x81, 4, 0, 0xa]),
        (EcCurve::BrainpoolP256, &[0x2b, 0x24, 3, 3, 2, 8, 1, 1, 7]),
        (EcCurve::BrainpoolP384, &[0x2b, 0x24, 3, 3, 2, 8, 1, 1, 0xb]),
        (EcCurve::BrainpoolP512, &[0x2b, 0x24, 3, 3, 2, 8, 1, 1, 0xd]),
    ]
}
#[derive(Debug)]
enum Key {
    Signing(SoftwareSigningKey),
    Montgomery(SoftwareMontgomeryKey),
}
impl Key {
    fn generate(alg: Algorithm) -> Result<Self> {
        match alg {
            Algorithm::X25519 => SoftwareMontgomeryKey::generate(MontgomeryCurve::X25519)
                .map(Self::Montgomery)
                .map_err(|_| 0x6f00),
            _ => SoftwareSigningKey::generate_for_kind(kind(alg)?)
                .map(Self::Signing)
                .map_err(|_| 0x6f00),
        }
    }
    fn restore(alg: Algorithm, bytes: &[u8]) -> Result<Self> {
        match alg {
            Algorithm::X25519 => {
                SoftwareMontgomeryKey::from_serialized(MontgomeryCurve::X25519, bytes)
                    .map(Self::Montgomery)
                    .map_err(|_| 0x6a80)
            }
            _ => SoftwareSigningKey::from_serialized_for_kind(kind(alg)?, bytes)
                .map(Self::Signing)
                .map_err(|_| 0x6a80),
        }
    }
    fn serialized(&self) -> Result<Zeroizing<Vec<u8>>> {
        match self {
            Self::Signing(key) => key.serialized().map_err(|_| 0x6f00),
            Self::Montgomery(key) => Ok(key.serialized()),
        }
    }
    fn public(&self) -> Vec<u8> {
        match self {
            Self::Signing(key) => match key.public_key() {
                SoftwarePublicKey::Rsa { modulus, exponent } => {
                    let mut data = tlv(0x81, &modulus);
                    data.extend(tlv(0x82, &exponent));
                    tlv(0x7f49, &data)
                }
                SoftwarePublicKey::Ec { uncompressed, .. } => {
                    tlv(0x7f49, &tlv(0x86, &uncompressed))
                }
                SoftwarePublicKey::Edwards { public_key, .. } => {
                    tlv(0x7f49, &tlv(0x86, &public_key))
                }
                _ => Vec::new(),
            },
            Self::Montgomery(key) => tlv(0x7f49, &tlv(0x86, &key.public_key())),
        }
    }
}
fn kind(alg: Algorithm) -> Result<KeyKind> {
    Ok(match alg {
        Algorithm::Rsa(bits) => KeyKind::Rsa { modulus_bits: bits },
        Algorithm::Ec(curve) => KeyKind::Ec(curve),
        Algorithm::Ed25519 => KeyKind::Edwards(EdwardsCurve::Ed25519),
        Algorithm::X25519 => return Err(0x6a80),
    })
}
#[derive(Debug)]
struct Slot {
    attributes: Vec<u8>,
    key: Option<Key>,
    status: u8,
    certificate: Vec<u8>,
    uif: u8,
}
impl Slot {
    fn new() -> Self {
        Self {
            attributes: vec![1, 8, 0, 0, 32, 0],
            key: None,
            status: 0,
            certificate: Vec::new(),
            uif: 0,
        }
    }
}
pub(crate) struct OpenPgp {
    serial: u32,
    firmware: [u8; 3],
    user: Password,
    admin: Password,
    reset_code: Option<Password>,
    authorized: [bool; 3],
    slots: [Slot; 3],
    objects: BTreeMap<u16, Vec<u8>>,
    counter: u32,
    multiple_signatures: bool,
    terminated: bool,
    occurrence: usize,
    auth_key: usize,
    decipher_key: usize,
    persistent_change: bool,
}
impl std::fmt::Debug for OpenPgp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OpenPgp")
            .field("serial", &self.serial)
            .field("terminated", &self.terminated)
            .finish_non_exhaustive()
    }
}
pub(crate) enum Exchange {
    Complete(ResponseApdu),
    PresenceRequired(UserPresencePolicy),
}
impl OpenPgp {
    pub(crate) fn new(serial: u32, firmware: [u8; 3]) -> Self {
        Self {
            serial,
            firmware,
            user: Password::new(b"123456", 3),
            admin: Password::new(b"12345678", 3),
            reset_code: None,
            authorized: [false; 3],
            slots: std::array::from_fn(|_| Slot::new()),
            objects: BTreeMap::new(),
            counter: 0,
            multiple_signatures: false,
            terminated: false,
            occurrence: 0,
            auth_key: 2,
            decipher_key: 1,
            persistent_change: false,
        }
    }
    pub(crate) fn reset_connection(&mut self) {
        self.authorized = [false; 3];
        self.occurrence = 0;
        self.auth_key = 2;
        self.decipher_key = 1;
    }
    pub(crate) fn take_persistent_change(&mut self) -> bool {
        std::mem::take(&mut self.persistent_change)
    }
    pub(crate) fn select_response(&self) -> ResponseApdu {
        ResponseApdu::status(if self.terminated { 0x6285 } else { 0x9000 })
    }
    fn aid(&self) -> Vec<u8> {
        let mut aid = OPENPGP_AID.to_vec();
        aid.extend([3, 4, 0xff, 0xff]);
        aid.extend(self.serial.to_be_bytes());
        aid.extend([0, 0]);
        aid
    }
    fn required(&self, index: usize) -> Result<()> {
        if self.authorized[index] {
            Ok(())
        } else {
            Err(0x6982)
        }
    }
    fn password_index(reference: u8) -> Result<usize> {
        match reference {
            0x81 => Ok(0),
            0x82 => Ok(1),
            0x83 => Ok(2),
            _ => Err(0x6a88),
        }
    }
    fn verify(&mut self, c: &CommandApdu<'_>) -> Result<Vec<u8>> {
        let i = Self::password_index(c.p2)?;
        if c.p1 == 0xff && c.data.is_empty() {
            self.authorized[i] = false;
            return Ok(vec![]);
        }
        if c.p1 != 0 {
            return Err(0x6a86);
        }
        let p = if i == 2 {
            &mut self.admin
        } else {
            &mut self.user
        };
        if c.data.is_empty() {
            return if p.retries == 0 {
                Err(0x6983)
            } else if self.authorized[i] {
                Ok(vec![])
            } else {
                Err(0x63c0 | u16::from(p.retries))
            };
        }
        self.persistent_change = true;
        if let Err(status) = p.verify(c.data) {
            if i == 2 {
                self.authorized[2] = false;
            } else {
                self.authorized[..2].fill(false);
            }
            return Err(status);
        }
        self.authorized[i] = true;
        Ok(vec![])
    }
    fn change(&mut self, c: &CommandApdu<'_>) -> Result<Vec<u8>> {
        if c.p1 != 0 || !matches!(c.p2, 0x81 | 0x83) {
            return Err(0x6a86);
        }
        let admin = c.p2 == 0x83;
        let p = if admin {
            &mut self.admin
        } else {
            &mut self.user
        };
        let length = p.length;
        if c.data.len() < length {
            return Err(0x6700);
        }
        let new = &c.data[length..];
        validate_password(new, if admin { 8 } else { 6 })?;
        self.persistent_change = true;
        let result = p.verify(&c.data[..length]);
        if admin {
            self.authorized[2] = false;
        } else {
            self.authorized[..2].fill(false);
        }
        result?;
        *p = Password::new(new, p.limit);
        Ok(vec![])
    }
    fn unblock(&mut self, c: &CommandApdu<'_>) -> Result<Vec<u8>> {
        if c.p2 != 0x81 {
            return Err(0x6a86);
        }
        let new = match c.p1 {
            2 => {
                self.required(2)?;
                c.data
            }
            0 => {
                let reset = self.reset_code.as_ref().ok_or(0x6982u16)?;
                if c.data.len() < reset.length {
                    return Err(0x6700);
                }
                &c.data[reset.length..]
            }
            _ => return Err(0x6a86),
        };
        validate_password(new, 6)?;
        if c.p1 == 0 {
            let reset = self.reset_code.as_mut().unwrap();
            self.persistent_change = true;
            reset.verify(&c.data[..reset.length])?;
        }
        self.user = Password::new(new, self.user.limit);
        self.authorized[..2].fill(false);
        self.persistent_change = true;
        Ok(vec![])
    }
    fn get(&mut self, tag: u16) -> Result<Vec<u8>> {
        match tag {
            0x4f => Ok(self.aid()),
            0x5f52 => Ok(vec![0, 0x31, 0xc5, 0x73, 0xc0, 1, 0x80, 5, 0x90, 0]),
            0x7f66 => Ok(tlv(2, &[0xff, 0xff])
                .into_iter()
                .chain(tlv(2, &[0xff, 0xff]))
                .collect()),
            0x7f74 => Ok(tlv(0x81, &[0x20])),
            0x65 => {
                let mut body = vec![];
                for tag in [0x5b, 0x5f2d, 0x5f35] {
                    body.extend(tlv(tag, &self.get(tag)?));
                }
                Ok(tlv(0x65, &body))
            }
            0x6e => {
                let mut body = tlv(0x4f, &self.aid());
                body.extend(tlv(0x5f52, &self.get(0x5f52)?));
                body.extend(tlv(0x7f66, &self.get(0x7f66)?));
                let mut discretionary = vec![];
                for tag in [
                    0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xcd, 0xde, 0xd6, 0xd7, 0xd8,
                ] {
                    discretionary.extend(tlv(tag, &self.get(tag)?));
                }
                body.extend(tlv(0x73, &discretionary));
                Ok(tlv(0x6e, &body))
            }
            // Proprietary SCP is handled by the shared channel; no OpenPGP-specific SM or KDF is advertised.
            0xc0 => Ok(vec![0x7c, 0, 0x10, 0, 0x10, 0, 0x10, 0, 0, 1]),
            0xc1..=0xc3 => Ok(self.slots[usize::from(tag - 0xc1)].attributes.clone()),
            0xc4 => Ok(vec![
                u8::from(self.multiple_signatures),
                127,
                127,
                127,
                self.user.retries,
                self.reset_code.as_ref().map_or(0, |p| p.retries),
                self.admin.retries,
            ]),
            0xc5 | 0xc6 | 0xcd => {
                let (first, len) = match tag {
                    0xc5 => (0xc7, 20),
                    0xc6 => (0xca, 20),
                    _ => (0xce, 4),
                };
                let mut data = vec![];
                for i in 0..3 {
                    data.extend(
                        self.objects
                            .get(&(first + i))
                            .cloned()
                            .unwrap_or(vec![0; len]),
                    );
                }
                Ok(data)
            }
            0xc7..=0xcc => Ok(self.objects.get(&tag).cloned().unwrap_or(vec![0; 20])),
            0xce..=0xd0 => Ok(self.objects.get(&tag).cloned().unwrap_or(vec![0; 4])),
            0xd6..=0xd8 => Ok(vec![self.slots[usize::from(tag - 0xd6)].uif, 0x20]),
            0xde => Ok((0..3)
                .flat_map(|i| [i as u8 + 1, self.slots[i].status])
                .collect()),
            0x93 => Ok(self.counter.to_be_bytes()[1..].to_vec()),
            0x7a => Ok(tlv(0x7a, &tlv(0x93, &self.get(0x93)?))),
            0x7f21 => Ok(self.slots[2 - self.occurrence].certificate.clone()),
            0xfa => {
                let mut data = vec![];
                for i in 0..3 {
                    for attr in supported_attributes(i) {
                        data.extend(tlv(0xc1 + i as u16, &attr));
                    }
                }
                Ok(tlv(0xfa, &data))
            }
            0x0103 => {
                self.required(1)?;
                Ok(self.objects.get(&tag).cloned().unwrap_or_default())
            }
            0x0104 => {
                self.required(2)?;
                Ok(self.objects.get(&tag).cloned().unwrap_or_default())
            }
            0x5f35 => Ok(self.objects.get(&tag).cloned().unwrap_or(vec![b'0'])),
            0x5b | 0x5e | 0x5f2d | 0x5f50 | 0x0101 | 0x0102 => {
                Ok(self.objects.get(&tag).cloned().unwrap_or_default())
            }
            _ => Err(0x6a88),
        }
    }
    fn put(&mut self, tag: u16, data: &[u8]) -> Result<Vec<u8>> {
        self.required(if matches!(tag, 0x0101 | 0x0103) { 1 } else { 2 })?;
        if data.len() > MAX_OBJECT {
            return Err(0x6700);
        }
        match tag {
            0xc1..=0xc3 => {
                let i = usize::from(tag - 0xc1);
                algorithm(data, i)?;
                if self.slots[i].attributes != data {
                    self.slots[i].key = None;
                    self.slots[i].status = 0;
                    self.slots[i].certificate.clear();
                    if i == 0 {
                        self.counter = 0;
                    }
                }
                self.slots[i].attributes = data.to_vec();
            }
            0xc4 => {
                if data.len() != 1 || data[0] > 1 {
                    return Err(0x6a80);
                }
                self.multiple_signatures = data[0] == 1;
            }
            0xd3 => {
                if !data.is_empty() {
                    validate_password(data, 8)?;
                }
                self.reset_code = (!data.is_empty()).then(|| Password::new(data, 3));
            }
            0xd6..=0xd8 => {
                let slot = &mut self.slots[usize::from(tag - 0xd6)];
                if data.len() != 2 || data[0] > 2 || data[1] != 0x20 {
                    return Err(0x6a80);
                }
                if slot.uif == 2 && data[0] != 2 {
                    return Err(0x6985);
                }
                slot.uif = data[0];
            }
            0x7f21 => self.slots[2 - self.occurrence].certificate = data.to_vec(),
            0xc7..=0xcc => {
                if data.len() != 20 {
                    return Err(0x6a80);
                }
                self.objects.insert(tag, data.to_vec());
            }
            0xce..=0xd0 => {
                if data.len() != 4 {
                    return Err(0x6a80);
                }
                self.objects.insert(tag, data.to_vec());
            }
            0x5b if data.len() <= 39 => {
                self.objects.insert(tag, data.to_vec());
            }
            0x5f2d if !data.is_empty() && data.len() <= 8 && data.len().is_multiple_of(2) => {
                self.objects.insert(tag, data.to_vec());
            }
            0x5f35 if data.len() == 1 && matches!(data[0], b'0' | b'1' | b'2' | b'9') => {
                self.objects.insert(tag, data.to_vec());
            }
            0x5e | 0x5f50 | 0x0101..=0x0104 => {
                self.objects.insert(tag, data.to_vec());
            }
            _ => return Err(0x6a80),
        }
        self.persistent_change = true;
        Ok(vec![])
    }
    fn generate(&mut self, c: &CommandApdu<'_>) -> Result<Vec<u8>> {
        if c.p2 != 0 || !matches!(c.p1, 0x80 | 0x81) {
            return Err(0x6a86);
        }
        let i = crt_index(c.data)?;
        if c.p1 == 0x80 {
            self.required(2)?;
            let key = Key::generate(algorithm(&self.slots[i].attributes, i)?)?;
            self.slots[i].key = Some(key);
            self.slots[i].status = 1;
            self.slots[i].certificate.clear();
            if i == 0 {
                self.counter = 0;
            }
            self.persistent_change = true;
        }
        Ok(self.slots[i].key.as_ref().ok_or(0x6a88u16)?.public())
    }
    fn import(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        self.required(2)?;
        let outer = parse_tlvs(data)?;
        if outer.len() != 1 || outer[0].0 != 0x4d {
            return Err(0x6a80);
        }
        let fields = parse_tlvs(outer[0].1)?;
        if fields.len() != 3 || fields[1].0 != 0x7f48 || fields[2].0 != 0x5f48 {
            return Err(0x6a80);
        }
        let i = crt_index(&tlv(fields[0].0, fields[0].1))?;
        let mut description = fields[1].1;
        let mut contents = fields[2].1;
        let mut parts = BTreeMap::new();
        while !description.is_empty() {
            let (tag, len) = header(&mut description)?;
            let part = contents.get(..len).ok_or(0x6a80u16)?;
            contents = &contents[len..];
            if parts.insert(tag, part).is_some() {
                return Err(0x6a80);
            }
        }
        if !contents.is_empty() {
            return Err(0x6a80);
        }
        let alg = algorithm(&self.slots[i].attributes, i)?;
        let key = if let Algorithm::Rsa(bits) = alg {
            if parts.len() != 3
                || parts.keys().copied().collect::<Vec<_>>() != [0x91, 0x92, 0x93]
                || parts[&0x91].len() != 4
                || parts[&0x92].len() != bits / 16
                || parts[&0x93].len() != bits / 16
            {
                return Err(0x6a80);
            }
            let key = SoftwareSigningKey::from_rsa_primes(parts[&0x92], parts[&0x93], parts[&0x91])
                .map_err(|_| 0x6a80u16)?;
            if key.key_kind() != (KeyKind::Rsa { modulus_bits: bits }) {
                return Err(0x6a80);
            }
            Key::Signing(key)
        } else {
            if parts.keys().any(|tag| !matches!(tag, 0x92 | 0x99)) {
                return Err(0x6a80);
            }
            let key = Key::restore(alg, parts.get(&0x92).ok_or(0x6a80u16)?)?;
            if let Some(public) = parts.get(&0x99) {
                let encoded = key.public();
                let fields = parse_tlvs(&encoded)?;
                let fields = parse_tlvs(fields[0].1)?;
                if fields[0].1 != *public {
                    return Err(0x6a80);
                }
            }
            key
        };
        self.slots[i].key = Some(key);
        self.slots[i].status = 2;
        self.slots[i].certificate.clear();
        if i == 0 {
            self.counter = 0;
        }
        self.persistent_change = true;
        Ok(vec![])
    }
    fn crypto(
        &mut self,
        c: &CommandApdu<'_>,
        presence: PresenceAuthorization,
    ) -> std::result::Result<Vec<u8>, CryptoError> {
        let (i, sign) = match (c.ins, c.p1, c.p2) {
            (0x2a, 0x9e, 0x9a) => (0, true),
            (0x88, 0, 0) => (self.auth_key, true),
            (0x2a, 0x80, 0x86) => (self.decipher_key, false),
            _ => return Err(CryptoError::Status(0x6a86)),
        };
        self.required(if i == 0 && sign { 0 } else { 1 })?;
        let slot = &self.slots[i];
        let key = slot.key.as_ref().ok_or(CryptoError::Status(0x6a88))?;
        if slot.uif != 0 && presence != PresenceAuthorization::Granted {
            return Err(CryptoError::Touch);
        }
        let alg = algorithm(&slot.attributes, i)?;
        let result = if sign {
            match (alg, key) {
                (Algorithm::Rsa(_), Key::Signing(key)) => key
                    .sign_rsa_pkcs1v15_payload(c.data)
                    .map(|s| s.into_bytes())
                    .map_err(|_| 0x6a80u16)?,
                (Algorithm::Ec(curve), Key::Signing(key)) => key
                    .sign_prehash(curve.signature_scheme(), c.data)
                    .map(|s| s.into_bytes())
                    .map_err(|_| 0x6a80u16)?,
                (Algorithm::Ed25519, Key::Signing(key)) => key
                    .sign_message(EdwardsCurve::Ed25519.signature_scheme(), c.data)
                    .map(|s| s.into_bytes())
                    .map_err(|_| 0x6a80u16)?,
                _ => return Err(CryptoError::Status(0x6a80)),
            }
        } else {
            match (alg, key) {
                (Algorithm::Rsa(_), Key::Signing(key)) => {
                    let input = c
                        .data
                        .strip_prefix(&[0])
                        .ok_or(CryptoError::Status(0x6a80))?;
                    key.decrypt_rsa_pkcs1v15(input)
                        .map_err(|_| 0x6a80u16)?
                        .to_vec()
                }
                (Algorithm::Ec(_), Key::Signing(key)) => {
                    derive_with_signing_key(key, ecdh_peer(c.data)?)
                        .map_err(|_| 0x6a80u16)?
                        .to_vec()
                }
                (Algorithm::X25519, Key::Montgomery(key)) => key
                    .derive(ecdh_peer(c.data)?)
                    .map_err(|_| 0x6a80u16)?
                    .to_vec(),
                _ => return Err(CryptoError::Status(0x6a80)),
            }
        };
        if c.ins == 0x2a && sign {
            self.counter = (self.counter + 1).min(0xffffff);
            self.persistent_change = true;
            if !self.multiple_signatures {
                self.authorized[0] = false;
            }
        }
        Ok(result)
    }
    fn command(&mut self, c: &CommandApdu<'_>) -> Result<Vec<u8>> {
        match c.ins {
            0x20 => self.verify(c),
            0x24 => self.change(c),
            0x2c => self.unblock(c),
            0xca if c.data.is_empty() => self.get(u16::from_be_bytes([c.p1, c.p2])),
            0xcb => {
                let fields = parse_tlvs(c.data)?;
                if fields.len() != 1 || fields[0].0 != 0x5c || fields[0].1.len() != 2 {
                    return Err(0x6a80);
                }
                self.get(u16::from_be_bytes(fields[0].1.try_into().unwrap()))
            }
            0xcc if [c.p1, c.p2] == [0x7f, 0x21] && c.data.is_empty() => {
                if self.occurrence >= 2 {
                    return Err(0x6a88);
                }
                self.occurrence += 1;
                self.get(0x7f21)
            }
            0xa5 => {
                if c.p1 > 2 || c.p2 != 4 || c.data != [0x60, 4, 0x5c, 2, 0x7f, 0x21] {
                    return Err(0x6a86);
                }
                self.occurrence = usize::from(c.p1);
                Ok(vec![])
            }
            0xda => self.put(u16::from_be_bytes([c.p1, c.p2]), c.data),
            0xdb if [c.p1, c.p2] == [0x3f, 0xff] => self.import(c.data),
            0x47 => self.generate(c),
            0x22 => {
                if c.p1 != 0x41
                    || !matches!(c.p2, 0xa4 | 0xb8)
                    || c.data.len() != 3
                    || c.data[..2] != [0x83, 1]
                    || !matches!(c.data[2], 2 | 3)
                {
                    return Err(0x6a86);
                }
                if c.p2 == 0xa4 {
                    self.auth_key = usize::from(c.data[2] - 1);
                } else {
                    self.decipher_key = usize::from(c.data[2] - 1);
                }
                Ok(vec![])
            }
            0x84 => challenge(c),
            0xf1 if c.p1 == 0 && c.p2 == 0 && c.data.is_empty() => Ok(self.firmware.to_vec()),
            0xe6 if c.p1 == 0 && c.p2 == 0 && c.data.is_empty() => {
                if !self.authorized[2] && self.admin.retries != 0 {
                    return Err(0x6982);
                }
                self.terminated = true;
                self.reset_connection();
                self.persistent_change = true;
                Ok(vec![])
            }
            0x44 if c.p1 == 0 && c.p2 == 0 && c.data.is_empty() => {
                if self.terminated {
                    *self = Self::new(self.serial, self.firmware);
                    self.persistent_change = true;
                }
                Ok(vec![])
            }
            _ => Err(0x6d00),
        }
    }
    pub(crate) fn exchange(
        &mut self,
        c: &CommandApdu<'_>,
        presence: PresenceAuthorization,
    ) -> Exchange {
        if c.cla != 0 {
            return Exchange::Complete(ResponseApdu::status(0x6e00));
        }
        if self.terminated && c.ins != 0x44 {
            return Exchange::Complete(ResponseApdu::status(0x6285));
        }
        let result = if matches!(c.ins, 0x2a | 0x88) {
            match self.crypto(c, presence) {
                Ok(data) => Ok(data),
                Err(CryptoError::Status(sw)) => Err(sw),
                Err(CryptoError::Touch) => {
                    return Exchange::PresenceRequired(UserPresencePolicy::Always);
                }
            }
        } else {
            self.command(c)
        };
        Exchange::Complete(match result {
            Ok(data) => ResponseApdu::success(data),
            Err(sw) => ResponseApdu::status(sw),
        })
    }
}
enum CryptoError {
    Status(u16),
    Touch,
}
impl From<u16> for CryptoError {
    fn from(value: u16) -> Self {
        Self::Status(value)
    }
}
fn validate_password(data: &[u8], min: usize) -> Result<()> {
    if (min..=127).contains(&data.len()) {
        Ok(())
    } else {
        Err(0x6700)
    }
}
fn supported_attributes(index: usize) -> Vec<Vec<u8>> {
    let mut attrs: Vec<_> = [2048u16, 3072, 4096]
        .into_iter()
        .map(|bits| {
            let [a, b] = bits.to_be_bytes();
            vec![1, a, b, 0, 32, 0]
        })
        .collect();
    for (_, oid) in curves() {
        let mut attr = vec![if index == 1 { 0x12 } else { 0x13 }];
        attr.extend(oid);
        attrs.push(attr);
    }
    let mut attr = vec![if index == 1 { 0x12 } else { 0x16 }];
    attr.extend(if index == 1 {
        &[0x2b, 6, 1, 4, 1, 0x97, 0x55, 1, 5, 1][..]
    } else {
        &[0x2b, 6, 1, 4, 1, 0xda, 0x47, 0xf, 1][..]
    });
    attrs.push(attr);
    attrs
}
fn crt_index(data: &[u8]) -> Result<usize> {
    let fields = parse_tlvs(data)?;
    if fields.len() != 1 {
        return Err(0x6a80);
    }
    let i = match fields[0].0 {
        0xb6 => 0,
        0xb8 => 1,
        0xa4 => 2,
        _ => return Err(0x6a80),
    };
    if !fields[0].1.is_empty() && fields[0].1 != [0x84, 1, i as u8 + 1] {
        return Err(0x6a80);
    }
    Ok(i)
}
fn ecdh_peer(data: &[u8]) -> Result<&[u8]> {
    let outer = parse_tlvs(data)?;
    if outer.len() != 1 || outer[0].0 != 0xa6 {
        return Err(0x6a80);
    }
    let middle = parse_tlvs(outer[0].1)?;
    if middle.len() != 1 || middle[0].0 != 0x7f49 {
        return Err(0x6a80);
    }
    let inner = parse_tlvs(middle[0].1)?;
    if inner.len() != 1 || inner[0].0 != 0x86 {
        return Err(0x6a80);
    }
    Ok(inner[0].1)
}
fn challenge(c: &CommandApdu<'_>) -> Result<Vec<u8>> {
    if c.p1 != 0 || c.p2 != 0 {
        return Err(0x6a86);
    }
    if !c.data.is_empty() {
        return Err(0x6700);
    }
    let size =
        c.le.ok_or(0x6700u16)?
            .min(MAX_RANDOM_RESPONSE_LENGTH as u32) as usize;
    let mut data = vec![0; size];
    getrandom::fill(&mut data).map_err(|_| 0x6f00u16)?;
    Ok(data)
}
fn tlv(tag: u16, value: &[u8]) -> Vec<u8> {
    let mut data = if tag > 255 {
        tag.to_be_bytes().to_vec()
    } else {
        vec![tag as u8]
    };
    let length = value.len();
    if length < 128 {
        data.push(length as u8);
    } else if length <= 255 {
        data.extend([0x81, length as u8]);
    } else {
        data.push(0x82);
        data.extend((length as u16).to_be_bytes());
    }
    data.extend(value);
    data
}
fn header(data: &mut &[u8]) -> Result<(u16, usize)> {
    let first = *data.first().ok_or(0x6a80u16)?;
    *data = &data[1..];
    let tag = if first & 0x1f == 0x1f {
        let second = *data.first().ok_or(0x6a80u16)?;
        *data = &data[1..];
        if second & 0x80 != 0 {
            return Err(0x6a80);
        }
        u16::from_be_bytes([first, second])
    } else {
        u16::from(first)
    };
    let first = *data.first().ok_or(0x6a80u16)?;
    *data = &data[1..];
    let len = match first {
        0..=127 => usize::from(first),
        0x81 => {
            let len = *data.first().ok_or(0x6a80u16)?;
            *data = &data[1..];
            usize::from(len)
        }
        0x82 => {
            let bytes = data.get(..2).ok_or(0x6a80u16)?;
            let len = usize::from(u16::from_be_bytes(bytes.try_into().unwrap()));
            *data = &data[2..];
            len
        }
        _ => return Err(0x6a80),
    };
    Ok((tag, len))
}
fn parse_tlvs(mut data: &[u8]) -> Result<Vec<(u16, &[u8])>> {
    let mut fields = vec![];
    while !data.is_empty() {
        let (tag, len) = header(&mut data)?;
        let value = data.get(..len).ok_or(0x6a80u16)?;
        data = &data[len..];
        fields.push((tag, value));
    }
    Ok(fields)
}
impl OpenPgp {
    pub(crate) fn persistent_state(&self) -> std::result::Result<Vec<u8>, &'static str> {
        let mut out = vec![];
        let mut e = minicbor::Encoder::new(&mut out);
        let result =
            (|| -> std::result::Result<(), minicbor::encode::Error<std::convert::Infallible>> {
                e.array(10)?.u8(1)?.u32(self.serial)?;
                encode_password(&mut e, &self.user)?;
                encode_password(&mut e, &self.admin)?;
                if let Some(p) = &self.reset_code {
                    encode_password(&mut e, p)?;
                } else {
                    e.null()?;
                }
                e.bool(self.multiple_signatures)?
                    .bool(self.terminated)?
                    .u32(self.counter)?
                    .array(3)?;
                for slot in &self.slots {
                    e.array(5)?
                        .bytes(&slot.attributes)?
                        .u8(slot.status)?
                        .bytes(&slot.certificate)?
                        .u8(slot.uif)?;
                    if let Some(key) = &slot.key {
                        let bytes = key.serialized().map_err(|_| {
                            minicbor::encode::Error::message("serialize OpenPGP key")
                        })?;
                        e.bytes(&bytes)?;
                    } else {
                        e.bytes(&[])?;
                    }
                }
                e.map(self.objects.len() as u64)?;
                for (tag, data) in &self.objects {
                    e.u16(*tag)?.bytes(data)?;
                }
                Ok(())
            })();
        result.map_err(|_| "encode OpenPGP state")?;
        Ok(out)
    }
    pub(crate) fn from_persistent_state(
        serial: u32,
        firmware: [u8; 3],
        encoded: &[u8],
    ) -> std::result::Result<Self, &'static str> {
        let mut d = minicbor::Decoder::new(encoded);
        if d.array().ok() != Some(Some(10))
            || d.u8().ok() != Some(1)
            || d.u32().ok() != Some(serial)
        {
            return Err("invalid OpenPGP state identity or version");
        }
        let mut state = Self::new(serial, firmware);
        state.user = decode_password(&mut d, 6)?;
        state.admin = decode_password(&mut d, 8)?;
        if d.datatype().map_err(|_| "invalid resetting code")? == minicbor::data::Type::Null {
            d.null().map_err(|_| "invalid resetting code")?;
        } else {
            state.reset_code = Some(decode_password(&mut d, 8)?);
        }
        state.multiple_signatures = d.bool().map_err(|_| "invalid OpenPGP PIN policy")?;
        state.terminated = d.bool().map_err(|_| "invalid OpenPGP lifecycle")?;
        state.counter = d.u32().map_err(|_| "invalid OpenPGP counter")?;
        if state.counter > 0xffffff || d.array().ok() != Some(Some(3)) {
            return Err("invalid OpenPGP slots or counter");
        }
        for (i, slot) in state.slots.iter_mut().enumerate() {
            if d.array().ok() != Some(Some(5)) {
                return Err("invalid OpenPGP slot");
            }
            slot.attributes = d.bytes().map_err(|_| "invalid OpenPGP algorithm")?.to_vec();
            let alg =
                algorithm(&slot.attributes, i).map_err(|_| "unsupported OpenPGP algorithm")?;
            slot.status = d.u8().map_err(|_| "invalid OpenPGP key status")?;
            slot.certificate = d
                .bytes()
                .map_err(|_| "invalid OpenPGP certificate")?
                .to_vec();
            slot.uif = d.u8().map_err(|_| "invalid OpenPGP UIF")?;
            let bytes = Zeroizing::new(d.bytes().map_err(|_| "invalid OpenPGP key")?.to_vec());
            if slot.status > 2
                || slot.uif > 2
                || slot.certificate.len() > MAX_OBJECT
                || (slot.status == 0) != bytes.is_empty()
            {
                return Err("invalid OpenPGP slot policy");
            }
            if !bytes.is_empty() {
                slot.key =
                    Some(Key::restore(alg, &bytes).map_err(|_| "invalid OpenPGP private key")?);
            }
        }
        let count = d
            .map()
            .map_err(|_| "invalid OpenPGP objects")?
            .ok_or("indefinite OpenPGP objects")?;
        if count > 32 {
            return Err("too many OpenPGP objects");
        }
        // Validate stored DOs through the same write policy, then remove synthetic authorization.
        state.authorized = [true; 3];
        for _ in 0..count {
            let tag = d.u16().map_err(|_| "invalid OpenPGP object tag")?;
            let data = d.bytes().map_err(|_| "invalid OpenPGP object data")?;
            if !matches!(tag,0x5b | 0x5e | 0x5f2d | 0x5f35 | 0x5f50 | 0xc7..=0xcc | 0xce..=0xd0 | 0x0101..=0x0104)
                || state.objects.contains_key(&tag)
            {
                return Err("invalid or duplicate OpenPGP object");
            }
            state
                .put(tag, data)
                .map_err(|_| "invalid persisted OpenPGP object")?;
        }
        if d.position() != encoded.len() {
            return Err("trailing OpenPGP state");
        }
        state.reset_connection();
        state.persistent_change = false;
        Ok(state)
    }
}
fn encode_password(
    e: &mut minicbor::Encoder<&mut Vec<u8>>,
    p: &Password,
) -> std::result::Result<(), minicbor::encode::Error<std::convert::Infallible>> {
    e.array(5)?
        .bytes(&p.salt)?
        .bytes(&p.digest)?
        .u8(p.length as u8)?
        .u8(p.retries)?
        .u8(p.limit)?;
    Ok(())
}
fn decode_password(
    d: &mut minicbor::Decoder<'_>,
    min: usize,
) -> std::result::Result<Password, &'static str> {
    if d.array().ok() != Some(Some(5)) {
        return Err("invalid OpenPGP password record");
    }
    let salt = d
        .bytes()
        .map_err(|_| "invalid OpenPGP password salt")?
        .try_into()
        .map_err(|_| "invalid OpenPGP password salt length")?;
    let digest = Zeroizing::new(
        d.bytes()
            .map_err(|_| "invalid OpenPGP password verifier")?
            .to_vec(),
    );
    let length = usize::from(d.u8().map_err(|_| "invalid OpenPGP password length")?);
    let retries = d.u8().map_err(|_| "invalid OpenPGP password retries")?;
    let limit = d.u8().map_err(|_| "invalid OpenPGP password retry limit")?;
    if !(min..=127).contains(&length)
        || digest.len() != 32
        || limit == 0
        || limit > 15
        || retries > limit
    {
        return Err("invalid OpenPGP password policy");
    }
    Ok(Password {
        salt,
        digest,
        length,
        retries,
        limit,
    })
}

#[cfg(test)]
fn transmit(c: &CommandApdu<'_>) -> ResponseApdu {
    match OpenPgp::new(12345678, [5, 8, 0]).exchange(c, PresenceAuthorization::Absent) {
        Exchange::Complete(r) => r,
        Exchange::PresenceRequired(_) => ResponseApdu::status(0x6985),
    }
}
#[cfg(test)]
mod tests {
    fn send(state: &mut OpenPgp, ins: u8, p1: u8, p2: u8, data: &[u8]) -> ResponseApdu {
        let c = CommandApdu {
            cla: 0,
            ins,
            p1,
            p2,
            data,
            le: None,
            extended: false,
        };
        match state.exchange(&c, PresenceAuthorization::Granted) {
            Exchange::Complete(r) => r,
            Exchange::PresenceRequired(_) => panic!("unexpected touch request"),
        }
    }
    fn admin(state: &mut OpenPgp) {
        assert_eq!(send(state, 0x20, 0, 0x83, b"12345678").status, 0x9000);
    }
    #[test]
    fn passwords_retries_unblock_and_lifecycle_survive_persistence_without_authorization() {
        let mut state = OpenPgp::new(12345678, [5, 8, 0]);
        assert_eq!(send(&mut state, 0x20, 0, 0x81, b"wrong").status, 0x63c2);
        let encoded = state.persistent_state().unwrap();
        assert!(!encoded.windows(8).any(|w| w == b"12345678"));
        state = OpenPgp::from_persistent_state(12345678, [5, 8, 0], &encoded).unwrap();
        assert_eq!(send(&mut state, 0x20, 0, 0x82, b"wrong").status, 0x63c1);
        assert_eq!(send(&mut state, 0x20, 0, 0x81, b"wrong").status, 0x6983);
        assert_eq!(send(&mut state, 0x20, 0, 0x82, b"123456").status, 0x6983);
        admin(&mut state);
        assert_eq!(
            send(&mut state, 0xda, 0, 0xd3, b"reset-code").status,
            0x9000
        );
        assert_eq!(
            send(&mut state, 0x2c, 0, 0x81, b"reset-codenewpin").status,
            0x9000
        );
        assert_eq!(send(&mut state, 0x20, 0, 0x82, b"newpin").status, 0x9000);
        assert!(!state.authorized[0]);
        let restored =
            OpenPgp::from_persistent_state(12345678, [5, 8, 0], &state.persistent_state().unwrap())
                .unwrap();
        assert_eq!(restored.authorized, [false; 3]);
        assert_eq!(
            send(&mut state, 0x24, 0, 0x81, b"newpinchanged").status,
            0x9000
        );
        assert_eq!(send(&mut state, 0x20, 0, 0x81, b"changed").status, 0x9000);
        assert_eq!(send(&mut state, 0xe6, 0, 0, &[]).status, 0x9000);
        assert_eq!(send(&mut state, 0xca, 0, 0x4f, &[]).status, 0x6285);
        assert_eq!(send(&mut state, 0x44, 0, 0, &[]).status, 0x9000);
        assert_eq!(send(&mut state, 0x20, 0, 0x81, b"123456").status, 0x9000);
    }
    #[test]
    fn every_ec_signing_algorithm_imports_generates_and_verifies_with_one_shot_pin() {
        let mut attrs: Vec<_> = supported_attributes(0)
            .into_iter()
            .filter(|a| a[0] != 1)
            .collect();
        // Import the first key; generate the remaining algorithms.
        for (n, attr) in attrs.drain(..).enumerate() {
            let mut state = OpenPgp::new(12345678, [5, 8, 0]);
            admin(&mut state);
            assert_eq!(send(&mut state, 0xda, 0, 0xc1, &attr).status, 0x9000);
            if n == 0 {
                let mut body = vec![0xb6, 0];
                body.extend(tlv(0x7f48, &[0x92, 32]));
                body.extend(tlv(0x5f48, &[0x11; 32]));
                assert_eq!(
                    send(&mut state, 0xdb, 0x3f, 0xff, &tlv(0x4d, &body)).status,
                    0x9000
                );
            } else {
                assert_eq!(send(&mut state, 0x47, 0x80, 0, &[0xb6, 0]).status, 0x9000);
            }
            let alg = algorithm(&attr, 0).unwrap();
            let (scheme, message) = match alg {
                Algorithm::Ec(curve) => (
                    curve.signature_scheme(),
                    HashAlgorithm::Sha512.digest(b"message"),
                ),
                Algorithm::Ed25519 => (
                    EdwardsCurve::Ed25519.signature_scheme(),
                    b"message".to_vec(),
                ),
                _ => unreachable!(),
            };
            assert_eq!(send(&mut state, 0x2a, 0x9e, 0x9a, &message).status, 0x6982);
            assert_eq!(send(&mut state, 0x20, 0, 0x81, b"123456").status, 0x9000);
            let sig = send(&mut state, 0x2a, 0x9e, 0x9a, &message);
            assert_eq!(sig.status, 0x9000);
            let Key::Signing(key) = state.slots[0].key.as_ref().unwrap() else {
                unreachable!()
            };
            if matches!(alg, Algorithm::Ed25519) {
                key.public_key()
                    .verify_message(scheme, &message, &sig.data)
                    .unwrap();
            } else {
                key.public_key()
                    .verify_prehash(scheme, &message, &sig.data)
                    .unwrap();
            }
            assert_eq!(state.counter, 1);
            assert_eq!(send(&mut state, 0x2a, 0x9e, 0x9a, &message).status, 0x6982);
            let mut restored = OpenPgp::from_persistent_state(
                12345678,
                [5, 8, 0],
                &state.persistent_state().unwrap(),
            )
            .unwrap();
            assert_eq!(
                send(&mut restored, 0x47, 0x81, 0, &[0xb6, 0]).data,
                state.slots[0].key.as_ref().unwrap().public()
            );
        }
    }
    #[test]
    fn decipher_ecdh_and_x25519_reject_noncontributory_peers_and_require_operations_pin() {
        for attr in supported_attributes(1).into_iter().filter(|a| a[0] != 1) {
            let mut state = OpenPgp::new(12345678, [5, 8, 0]);
            admin(&mut state);
            assert_eq!(send(&mut state, 0xda, 0, 0xc2, &attr).status, 0x9000);
            assert_eq!(send(&mut state, 0x47, 0x80, 0, &[0xb8, 0]).status, 0x9000);
            let peer = Key::generate(algorithm(&attr, 1).unwrap()).unwrap();
            let public = peer.public();
            let fields = parse_tlvs(&public).unwrap();
            let fields = parse_tlvs(fields[0].1).unwrap();
            let data = tlv(0xa6, &tlv(0x7f49, &tlv(0x86, fields[0].1)));
            assert_eq!(send(&mut state, 0x20, 0, 0x81, b"123456").status, 0x9000);
            assert_eq!(send(&mut state, 0x2a, 0x80, 0x86, &data).status, 0x6982);
            assert_eq!(send(&mut state, 0x20, 0, 0x82, b"123456").status, 0x9000);
            let response = send(&mut state, 0x2a, 0x80, 0x86, &data);
            assert_eq!(response.status, 0x9000);
            let public = state.slots[1].key.as_ref().unwrap().public();
            let fields = parse_tlvs(&public).unwrap();
            let fields = parse_tlvs(fields[0].1).unwrap();
            let expected = match peer {
                Key::Signing(key) => derive_with_signing_key(&key, fields[0].1).unwrap(),
                Key::Montgomery(key) => key.derive(fields[0].1).unwrap(),
            };
            assert_eq!(response.data, expected.as_slice());
            let bad = tlv(0xa6, &tlv(0x7f49, &tlv(0x86, &[0; 32])));
            assert_eq!(send(&mut state, 0x2a, 0x80, 0x86, &bad).status, 0x6a80);
        }
    }
    #[test]
    fn rsa_sign_decipher_and_import_match_public_key_operations() {
        let mut state = OpenPgp::new(12345678, [5, 8, 0]);
        admin(&mut state);
        assert_eq!(send(&mut state, 0x47, 0x80, 0, &[0xb6, 0]).status, 0x9000);
        let hash = HashAlgorithm::Sha256.digest(b"OpenPGP RSA");
        let mut digest_info = vec![
            0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
            0x01, 0x05, 0x00, 0x04, 0x20,
        ];
        digest_info.extend(hash);
        assert_eq!(send(&mut state, 0x20, 0, 0x81, b"123456").status, 0x9000);
        let sig = send(&mut state, 0x2a, 0x9e, 0x9a, &digest_info);
        assert_eq!(sig.status, 0x9000);
        let Key::Signing(key) = state.slots[0].key.as_ref().unwrap() else {
            unreachable!()
        };
        key.public_key()
            .verify_message(
                software_key_core::software_signing::SignatureScheme::RsaPkcs1Sha256,
                b"OpenPGP RSA",
                &sig.data,
            )
            .unwrap();
        let components = key.rsa_private_components().unwrap();
        let mut description = vec![0x91, 4, 0x92, 0x81, 128, 0x93, 0x81, 128];
        let mut private = Zeroizing::new(vec![0, 1, 0, 1]);
        for prime in [&components[1], &components[2]] {
            private.extend(vec![0; 128 - prime.len()]);
            private.extend(prime.as_slice());
        }
        let mut body = Zeroizing::new(vec![0xa4, 0]);
        body.extend(tlv(0x7f48, &description));
        body.extend(tlv(0x5f48, &private));
        let import = tlv(0x4d, &body);
        assert_eq!(send(&mut state, 0xdb, 0x3f, 0xff, &import).status, 0x9000);
        assert_eq!(state.slots[2].status, 2);
        assert_eq!(
            state.slots[2].key.as_ref().unwrap().public(),
            state.slots[0].key.as_ref().unwrap().public()
        );
        description[0] = 0x92;
        body = Zeroizing::new(vec![0xa4, 0]);
        body.extend(tlv(0x7f48, &description));
        body.extend(tlv(0x5f48, &private));
        assert_eq!(
            send(&mut state, 0xdb, 0x3f, 0xff, &tlv(0x4d, &body)).status,
            0x6a80
        );
        assert_eq!(send(&mut state, 0x47, 0x80, 0, &[0xb8, 0]).status, 0x9000);
        let Key::Signing(key) = state.slots[1].key.as_ref().unwrap() else {
            unreachable!()
        };
        let cipher = key.public_key().encrypt_rsa_pkcs1v15(b"secret").unwrap();
        let mut input = vec![0];
        input.extend(cipher);
        assert_eq!(send(&mut state, 0x20, 0, 0x82, b"123456").status, 0x9000);
        let plaintext = send(&mut state, 0x2a, 0x80, 0x86, &input);
        assert_eq!(plaintext.status, 0x9000);
        assert_eq!(plaintext.data, b"secret");
    }
    #[test]
    fn permanent_touch_certificates_private_objects_and_failed_import_are_isolated() {
        let mut state = OpenPgp::new(12345678, [5, 8, 0]);
        admin(&mut state);
        assert_eq!(
            send(&mut state, 0xda, 0, 0xc1, &supported_attributes(0)[3]).status,
            0x9000
        );
        assert_eq!(send(&mut state, 0x47, 0x80, 0, &[0xb6, 0]).status, 0x9000);
        let previous = state.slots[0].key.as_ref().unwrap().public();
        assert_eq!(
            send(&mut state, 0xdb, 0x3f, 0xff, &[0x4d, 0]).status,
            0x6a80
        );
        assert_eq!(state.slots[0].key.as_ref().unwrap().public(), previous);
        assert_eq!(send(&mut state, 0xda, 0, 0xd6, &[2, 0x20]).status, 0x9000);
        assert_eq!(send(&mut state, 0xda, 0, 0xd6, &[0, 0x20]).status, 0x6985);
        assert_eq!(send(&mut state, 0x20, 0, 0x81, b"123456").status, 0x9000);
        let digest = HashAlgorithm::Sha256.digest(b"touch");
        assert!(matches!(
            state.exchange(
                &CommandApdu {
                    cla: 0,
                    ins: 0x2a,
                    p1: 0x9e,
                    p2: 0x9a,
                    data: &digest,
                    le: None,
                    extended: false
                },
                PresenceAuthorization::Absent
            ),
            Exchange::PresenceRequired(_)
        ));
        assert_eq!(send(&mut state, 0x2a, 0x9e, 0x9a, &digest).status, 0x9000);
        for occurrence in 0..3 {
            assert_eq!(
                send(
                    &mut state,
                    0xa5,
                    occurrence,
                    4,
                    &[0x60, 4, 0x5c, 2, 0x7f, 0x21]
                )
                .status,
                0x9000
            );
            assert_eq!(
                send(&mut state, 0xda, 0x7f, 0x21, &[occurrence]).status,
                0x9000
            );
        }
        assert_eq!(
            send(&mut state, 0xa5, 0, 4, &[0x60, 4, 0x5c, 2, 0x7f, 0x21]).status,
            0x9000
        );
        assert_eq!(send(&mut state, 0xca, 0x7f, 0x21, &[]).data, [0]);
        assert_eq!(send(&mut state, 0xcc, 0x7f, 0x21, &[]).data, [1]);
        assert_eq!(send(&mut state, 0xda, 1, 4, b"private").status, 0x9000);
        state.reset_connection();
        assert_eq!(send(&mut state, 0xca, 1, 4, &[]).status, 0x6982);
    }

    use super::*;

    fn decode(raw: &[u8]) -> CommandApdu<'_> {
        CommandApdu::decode(raw).unwrap()
    }

    #[test]
    fn get_challenge_uses_short_le() {
        let response = transmit(&decode(&[0x00, 0x84, 0x00, 0x00, 0x20]));
        assert_eq!(response.data.len(), 32);
        assert_eq!(response.status, 0x9000);
    }

    #[test]
    fn get_challenge_uses_extended_le_and_caps_it_at_firmware_buffer() {
        let response = transmit(&decode(&[0x00, 0x84, 0x00, 0x00, 0x00, 0x0f, 0xff]));
        assert_eq!(response.data.len(), 4_095);
        assert_eq!(response.status, 0x9000);

        let response = transmit(&decode(&[0x00, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00]));
        assert_eq!(response.data.len(), MAX_RANDOM_RESPONSE_LENGTH);
        assert_eq!(response.status, 0x9000);
    }

    #[test]
    fn unsupported_command_is_rejected() {
        assert_eq!(transmit(&decode(&[0, 0xff, 0, 0])).status, 0x6d00);
        assert_eq!(transmit(&decode(&[0, 0x84, 1, 0, 1])).status, 0x6a86);
        assert_eq!(transmit(&decode(&[0, 0x84, 0, 0])).status, 0x6700);
    }
}
