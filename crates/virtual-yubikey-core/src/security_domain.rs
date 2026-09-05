use crate::{CommandApdu, ResponseApdu, certificate};
use software_key_core::{
    certificate_chain::{CertificateTrust, ParsedCertificate},
    software_signing::{EcCurve, KeyKind, SoftwarePublicKey, SoftwareSigningKey},
    software_symmetric::{decrypt_aes_cbc, encrypt_aes_block},
};
use spki::SubjectPublicKeyInfoRef;
use std::{collections::BTreeMap, str::FromStr};
use subtle::ConstantTimeEq;
use x509_cert::{
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

pub(crate) const SCP11B_KEY_ID: u8 = 0x13;
pub(crate) const SCP11B_KEY_VERSION: u8 = 1;
const FACTORY_SCP03_KEY: [u8; 16] = [
    0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f,
];
const VIRTUAL_ATTESTATION_ROOT_PRIVATE_KEY: [u8; 32] = [0x24; 32];
const MAX_KEYS: usize = 32;
type KeyRef = (u8, u8);
type StatusResult<T> = Result<T, u16>;

#[cfg(test)]
pub(crate) fn factory_scp03_key() -> &'static [u8; 16] {
    &FACTORY_SCP03_KEY
}

enum Material {
    Private(SoftwareSigningKey),
    Public(Vec<u8>),
    Scp03(Zeroizing<Vec<u8>>),
}

// Deliberately omit private and symmetric material from diagnostics.
impl std::fmt::Debug for Material {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Private(_) => "Private(P256)",
            Self::Public(_) => "Public(P256)",
            Self::Scp03(_) => "Scp03(AES128)",
        })
    }
}

#[derive(Debug)]
struct Entry {
    material: Material,
    certificates: Vec<Vec<u8>>,
    issuer: Vec<u8>,
    allowlist: Vec<Vec<u8>>,
}

impl Entry {
    fn new(material: Material) -> Self {
        Self {
            material,
            certificates: Vec::new(),
            issuer: Vec::new(),
            allowlist: Vec::new(),
        }
    }

    fn point(&self) -> Option<Vec<u8>> {
        match &self.material {
            Material::Public(point) => Some(point.clone()),
            Material::Private(key) => match key.public_key() {
                SoftwarePublicKey::Ec { uncompressed, .. } => Some(uncompressed),
                _ => None,
            },
            Material::Scp03(_) => None,
        }
    }
}

#[derive(Debug)]
pub(crate) struct SecurityDomain {
    serial: u32,
    keys: BTreeMap<KeyRef, Entry>,
    persistent_change: bool,
}

impl SecurityDomain {
    pub(crate) fn new(serial: u32, firmware: [u8; 3], form_factor: u8) -> Self {
        let key = SoftwareSigningKey::generate_for_kind(KeyKind::Ec(EcCurve::P256))
            .expect("OS randomness");
        let certificates =
            certificate_chain(serial, firmware, form_factor, &key).expect("virtual SD certificate");
        let mut entry = Entry::new(Material::Private(key));
        entry.certificates = certificates;
        let mut keys = BTreeMap::new();
        keys.insert(
            (0, 0xff),
            Entry::new(Material::Scp03(Zeroizing::new(FACTORY_SCP03_KEY.repeat(3)))),
        );
        keys.insert((SCP11B_KEY_ID, SCP11B_KEY_VERSION), entry);
        Self {
            serial,
            keys,
            persistent_change: false,
        }
    }

    pub(crate) fn persistent_state(&self) -> Result<Vec<u8>, &'static str> {
        let mut encoded = Vec::new();
        let mut e = minicbor::Encoder::new(&mut encoded);
        e.map(3)
            .and_then(|e| e.u8(1))
            .and_then(|e| e.u8(2))
            .and_then(|e| e.u8(2))
            .and_then(|e| e.u32(self.serial))
            .and_then(|e| e.u8(3))
            .and_then(|e| e.array(self.keys.len() as u64))
            .map_err(|_| "encode SD state")?;
        for (&(kid, kvn), entry) in &self.keys {
            let (kind, material) = match &entry.material {
                Material::Private(key) => (0xb1, key.serialized().map_err(|_| "serialize SD key")?),
                Material::Public(point) => (0xb0, Zeroizing::new(point.clone())),
                Material::Scp03(keys) => (0x88, keys.clone()),
            };
            e.array(7)
                .and_then(|e| e.u8(kid))
                .and_then(|e| e.u8(kvn))
                .and_then(|e| e.u8(kind))
                .and_then(|e| e.bytes(&material))
                .and_then(|e| e.array(entry.certificates.len() as u64))
                .map_err(|_| "encode SD entry")?;
            for cert in &entry.certificates {
                e.bytes(cert).map_err(|_| "encode SD certificate")?;
            }
            e.bytes(&entry.issuer)
                .and_then(|e| e.array(entry.allowlist.len() as u64))
                .map_err(|_| "encode SD policy")?;
            for serial in &entry.allowlist {
                e.bytes(serial).map_err(|_| "encode SD serial")?;
            }
        }
        Ok(encoded)
    }

    pub(crate) fn from_persistent_state(
        serial: u32,
        firmware: [u8; 3],
        form_factor: u8,
        encoded: &[u8],
    ) -> Result<Self, &'static str> {
        // Decode the exact map order emitted by persistent_state. Version 1 is
        // accepted by the separate decoder for existing factory identities.
        let mut d = minicbor::Decoder::new(encoded);
        let fields = d.map().map_err(|_| "invalid SD map")?;
        if d.u8().map_err(|_| "invalid SD field")? != 1 {
            return Err("invalid SD field");
        }
        let version = d.u8().map_err(|_| "invalid SD version")?;
        if version == 1 {
            return Self::load_v1(serial, firmware, form_factor, encoded);
        }
        if version != 2
            || fields != Some(3)
            || d.u8().ok() != Some(2)
            || d.u32().ok() != Some(serial)
            || d.u8().ok() != Some(3)
        {
            return Err("invalid SD identity or version");
        }
        let count = d
            .array()
            .map_err(|_| "invalid SD keys")?
            .ok_or("indefinite SD keys")?;
        if count > MAX_KEYS as u64 {
            return Err("too many SD keys");
        }
        let mut keys = BTreeMap::new();
        for _ in 0..count {
            if d.array().ok() != Some(Some(7)) {
                return Err("invalid SD entry");
            }
            let kid = d.u8().map_err(|_| "invalid SD KID")?;
            let kvn = d.u8().map_err(|_| "invalid SD KVN")?;
            let kind = d.u8().map_err(|_| "invalid SD key type")?;
            let bytes = d.bytes().map_err(|_| "invalid SD material")?;
            let material = match kind {
                0xb1 if is_card(kid) && valid_version(kvn) => Material::Private(
                    SoftwareSigningKey::from_serialized_for_kind(KeyKind::Ec(EcCurve::P256), bytes)
                        .map_err(|_| "invalid SD private key")?,
                ),
                0xb0 if is_ca(kid) && valid_version(kvn) => {
                    validate_point(bytes).map_err(|_| "invalid SD public key")?;
                    Material::Public(bytes.to_vec())
                }
                0x88 if kid == 0 && kvn != 0 && bytes.len() == 48 => {
                    Material::Scp03(Zeroizing::new(bytes.to_vec()))
                }
                _ => return Err("invalid SD key reference or material"),
            };
            let mut entry = Entry::new(material);
            entry.certificates = decode_blobs(&mut d, 8, 8192)?;
            for cert in &entry.certificates {
                ParsedCertificate::parse(cert).map_err(|_| "invalid SD certificate")?;
            }
            entry.issuer = d.bytes().map_err(|_| "invalid SD issuer")?.to_vec();
            if entry.issuer.len() > 64 {
                return Err("invalid SD issuer");
            }
            entry.allowlist = decode_blobs(&mut d, 64, 21)?;
            if entry
                .allowlist
                .iter()
                .any(|s| canonical_serial(s).as_deref() != Ok(s.as_slice()))
            {
                return Err("invalid SD allowlist");
            }
            if keys.insert((kid, kvn), entry).is_some() {
                return Err("duplicate SD key");
            }
        }
        if d.position() != encoded.len() {
            return Err("trailing SD state");
        }
        Ok(Self {
            serial,
            keys,
            persistent_change: false,
        })
    }

    fn load_v1(
        serial: u32,
        firmware: [u8; 3],
        form_factor: u8,
        encoded: &[u8],
    ) -> Result<Self, &'static str> {
        let mut d = minicbor::Decoder::new(encoded);
        let count = d
            .map()
            .map_err(|_| "invalid SD map")?
            .ok_or("invalid SD map")?;
        if !matches!(count, 3 | 4)
            || d.u8().ok() != Some(1)
            || d.u8().ok() != Some(1)
            || d.u8().ok() != Some(2)
            || d.u32().ok() != Some(serial)
            || d.u8().ok() != Some(3)
        {
            return Err("invalid SD identity");
        }
        let key = SoftwareSigningKey::from_serialized_for_kind(
            KeyKind::Ec(EcCurve::P256),
            d.bytes().map_err(|_| "missing SD key")?,
        )
        .map_err(|_| "invalid SD key")?;
        let certificates = certificate_chain(serial, firmware, form_factor, &key)
            .map_err(|_| "invalid SD certificate")?;
        let mut state = Self {
            serial,
            keys: BTreeMap::new(),
            persistent_change: false,
        };
        state.keys.insert(
            (0, 0xff),
            Entry::new(Material::Scp03(Zeroizing::new(FACTORY_SCP03_KEY.repeat(3)))),
        );
        let mut entry = Entry::new(Material::Private(key));
        entry.certificates = certificates;
        state.keys.insert((0x13, 1), entry);
        if count == 4 {
            if d.u8().ok() != Some(4) {
                return Err("invalid SD field");
            }
            let count = d
                .array()
                .map_err(|_| "invalid SD provisioning")?
                .ok_or("invalid SD provisioning")?;
            if count > 16 {
                return Err("too many SD keys");
            }
            for _ in 0..count {
                if d.array().ok() != Some(Some(6)) {
                    return Err("invalid SD entry");
                }
                let kid = d.u8().map_err(|_| "invalid KID")?;
                let kvn = d.u8().map_err(|_| "invalid KVN")?;
                let key = Zeroizing::new(d.bytes().map_err(|_| "invalid key")?.to_vec());
                let host_kid = d.u8().map_err(|_| "invalid CA KID")?;
                let host_kvn = d.u8().map_err(|_| "invalid CA KVN")?;
                let ca = decode_blobs(&mut d, 8, 8192)?;
                state.provision_scp11(kid, kvn, &key, host_kid, host_kvn, &ca)?;
            }
        }
        if d.position() != encoded.len() {
            return Err("trailing SD state");
        }
        state.persistent_change = false;
        Ok(state)
    }

    pub(crate) fn provision_scp11(
        &mut self,
        kid: u8,
        kvn: u8,
        private_key: &[u8],
        host_kid: u8,
        host_kvn: u8,
        host_ca: &[Vec<u8>],
    ) -> Result<(), &'static str> {
        if !matches!(kid, 0x11 | 0x15)
            || !valid_version(kvn)
            || !is_ca(host_kid)
            || !valid_version(host_kvn)
            || host_ca.len() > 8
            || host_ca.iter().any(|c| c.len() > 8192)
        {
            return Err("invalid SCP11 provisioning");
        }
        CertificateTrust::new(host_ca).map_err(|_| "invalid host trust")?;
        let root = host_ca
            .iter()
            .filter_map(|c| ParsedCertificate::parse(c).ok())
            .find(|c| c.is_self_issued())
            .ok_or("missing host root")?;
        let point = root
            .p256_public_point()
            .map_err(|_| "host CA must be P256")?;
        let key =
            SoftwareSigningKey::from_serialized_for_kind(KeyKind::Ec(EcCurve::P256), private_key)
                .map_err(|_| "invalid card key")?;
        let additional = usize::from(!self.keys.contains_key(&(kid, kvn)))
            + usize::from(!self.keys.contains_key(&(host_kid, host_kvn)));
        if self.keys.len() + additional > MAX_KEYS {
            return Err("too many SD keys");
        }
        let mut ca = Entry::new(Material::Public(point));
        ca.certificates = host_ca.to_vec();
        self.keys.insert((host_kid, host_kvn), ca);
        self.keys
            .insert((kid, kvn), Entry::new(Material::Private(key)));
        self.persistent_change = true;
        Ok(())
    }

    pub(crate) fn scp03_keys(&self, kvn: u8) -> Option<(u8, &[u8])> {
        self.keys.iter().find_map(|(&(kid, version), entry)| {
            if kid != 0 || (kvn != 0 && kvn != version) {
                return None;
            }
            match &entry.material {
                Material::Scp03(keys) => Some((version, keys.as_slice())),
                _ => None,
            }
        })
    }

    pub(crate) fn scp11_key(&self, kid: u8, kvn: u8) -> Option<&SoftwareSigningKey> {
        match &self.keys.get(&(kid, kvn))?.material {
            Material::Private(key) => Some(key),
            _ => None,
        }
    }

    pub(crate) fn validate_host(
        &self,
        card_ref: Option<KeyRef>,
        host_ref: KeyRef,
        certificates: &[Vec<u8>],
    ) -> Option<Vec<u8>> {
        let leaf = ParsedCertificate::parse(certificates.last()?).ok()?;
        let serial = canonical_serial(
            leaf.certificate()
                .tbs_certificate()
                .serial_number()
                .as_bytes(),
        )
        .ok()?;
        if let Some(reference) = card_ref {
            let card = self.keys.get(&reference)?;
            if !card.allowlist.is_empty() && !card.allowlist.contains(&serial) {
                return None;
            }
        }
        self.keys
            .iter()
            .filter(|(reference, entry)| {
                matches!(entry.material, Material::Public(_))
                    && (host_ref == (0, 0) || **reference == host_ref)
                    && (entry.allowlist.is_empty() || entry.allowlist.contains(&serial))
            })
            .find_map(|(_, entry)| {
                // Full configured CA certificates preserve their constraints. A CA
                // imported by PUT KEY is explicitly trusted as a bare public key.
                if !entry.certificates.is_empty() {
                    CertificateTrust::new(&entry.certificates)
                        .ok()?
                        .validate_p256_key_agreement_point(certificates)
                        .ok()
                } else {
                    CertificateTrust::validate_with_p256_ca_key(&entry.point()?, certificates).ok()
                }
            })
    }

    pub(crate) fn take_persistent_change(&mut self) -> bool {
        std::mem::take(&mut self.persistent_change)
    }
    pub(crate) fn scp11b_public_key(&self) -> Vec<u8> {
        self.keys
            .get(&(0x13, 1))
            .and_then(Entry::point)
            .unwrap_or_default()
    }

    pub(crate) fn exchange(
        &mut self,
        command: &CommandApdu<'_>,
        admin_dek: Option<&[u8]>,
    ) -> ResponseApdu {
        let result = if command.cla == 0 && command.ins == 0xca {
            self.get_data(command)
        } else if matches!(
            (command.cla, command.ins),
            (0x80, 0xf1 | 0xd8 | 0xe4) | (0, 0xe2)
        ) {
            match admin_dek {
                None => Err(0x6982),
                Some(dek) => self.administer(command, dek),
            }
        } else {
            Err(0x6d00)
        };
        match result {
            Ok(data) => ResponseApdu::success(data),
            Err(status) => ResponseApdu::status(status),
        }
    }

    fn get_data(&self, command: &CommandApdu<'_>) -> StatusResult<Vec<u8>> {
        let tag = u16::from_be_bytes([command.p1, command.p2]);
        let mut output = Vec::new();
        match tag {
            0xe0 if command.data.is_empty() => {
                for (&(kid, kvn), entry) in &self.keys {
                    match &entry.material {
                        Material::Scp03(_) => {
                            for id in 1..=3 {
                                push_tlv(&mut output, &[0xc0], &[id, kvn, 0x88, 16]);
                            }
                        }
                        Material::Private(_) => {
                            push_tlv(&mut output, &[0xc0], &[kid, kvn, 0xb1, 32, 0xf0, 0])
                        }
                        Material::Public(_) => {
                            push_tlv(&mut output, &[0xc0], &[kid, kvn, 0xb0, 65, 0xf0, 0])
                        }
                    }
                }
            }
            0xbf21 => {
                let mut data = command.data;
                let selector = take_tlv(&mut data, 0xa6)?;
                if !data.is_empty() {
                    return Err(0x6a80);
                }
                let reference = selector_ref(selector)?;
                let entry = self.keys.get(&reference).ok_or(0x6a88_u16)?;
                if entry.certificates.is_empty() {
                    return Err(0x6a88);
                }
                output = entry.certificates.concat();
            }
            0xff33 | 0xff34 if command.data.is_empty() => {
                for (&(kid, kvn), entry) in &self.keys {
                    if !entry.issuer.is_empty() && is_card(kid) == (tag == 0xff34) {
                        push_tlv(&mut output, &[0x42], &entry.issuer);
                        push_tlv(&mut output, &[0x83], &[kid, kvn]);
                    }
                }
                if output.is_empty() {
                    return Err(0x6a88);
                }
            }
            _ => return Err(0x6a88),
        }
        Ok(output)
    }

    fn replace(&mut self, reference: KeyRef, replace_kvn: u8, entry: Entry) -> StatusResult<()> {
        let previous = (reference.0, replace_kvn);
        if replace_kvn == 0 {
            if self.keys.contains_key(&reference) {
                return Err(0x6a80);
            }
        } else if !self.keys.contains_key(&previous) {
            return Err(0x6a88);
        }
        if reference != previous && self.keys.contains_key(&reference) {
            return Err(0x6a80);
        }
        if replace_kvn == 0 && self.keys.len() >= MAX_KEYS {
            return Err(0x6a84);
        }
        if reference.0 == 0 {
            let count = self
                .keys
                .keys()
                .filter(|&&(kid, kvn)| kid == 0 && kvn != 0xff && kvn != replace_kvn)
                .count();
            if count >= 3 {
                return Err(0x6a84);
            }
        }
        // Validate everything before removing or replacing any existing material.
        if replace_kvn != 0 {
            self.keys.remove(&previous);
        }
        if reference.0 == 0 {
            self.keys.remove(&(0, 0xff));
        }
        self.keys.insert(reference, entry);
        self.persistent_change = true;
        Ok(())
    }

    fn administer(&mut self, command: &CommandApdu<'_>, dek: &[u8]) -> StatusResult<Vec<u8>> {
        match command.ins {
            0xf1 => {
                let (&kvn, mut data) = command.data.split_first().ok_or(0x6a80_u16)?;
                if !is_card(command.p2)
                    || !valid_version(kvn)
                    || take_tlv(&mut data, 0xf0)? != [0]
                    || !data.is_empty()
                {
                    return Err(0x6a80);
                }
                let key = SoftwareSigningKey::generate_for_kind(KeyKind::Ec(EcCurve::P256))
                    .map_err(|_| 0x6f00_u16)?;
                let entry = Entry::new(Material::Private(key));
                let point = entry.point().ok_or(0x6f00_u16)?;
                self.replace((command.p2, kvn), command.p1, entry)?;
                let mut output = Vec::new();
                push_tlv(&mut output, &[0xb0], &point);
                Ok(output)
            }
            0xd8 => {
                let (&kvn, mut data) = command.data.split_first().ok_or(0x6a80_u16)?;
                if command.p2 == 0x81 {
                    if kvn == 0 || kvn == 0xff {
                        return Err(0x6a80);
                    }
                    let mut keys = Zeroizing::new(Vec::new());
                    let mut response = vec![kvn];
                    for _ in 0..3 {
                        let wrapped = take_tlv(&mut data, 0x88)?;
                        if wrapped.len() != 16 {
                            return Err(0x6a80);
                        }
                        let key = Zeroizing::new(
                            decrypt_aes_cbc(dek, &[0; 16], wrapped).map_err(|_| 0x6a80_u16)?,
                        );
                        let (&length, remaining) = data.split_first().ok_or(0x6a80_u16)?;
                        if length != 3 || remaining.len() < 3 {
                            return Err(0x6a80);
                        }
                        let kcv = encrypt_aes_block(&key, &[1; 16]).map_err(|_| 0x6a80_u16)?;
                        if !bool::from(kcv[..3].ct_eq(&remaining[..3])) {
                            return Err(0x6a80);
                        }
                        data = &remaining[3..];
                        response.extend_from_slice(&kcv[..3]);
                        keys.extend_from_slice(&key);
                    }
                    if !data.is_empty() {
                        return Err(0x6a80);
                    }
                    self.replace((0, kvn), command.p1, Entry::new(Material::Scp03(keys)))?;
                    return Ok(response);
                }
                if !valid_version(kvn) {
                    return Err(0x6a80);
                }
                let material = match data.first() {
                    Some(0xb1) if is_card(command.p2) => {
                        let wrapped = take_tlv(&mut data, 0xb1)?;
                        if wrapped.len() != 32 {
                            return Err(0x6a80);
                        }
                        let scalar = Zeroizing::new(
                            decrypt_aes_cbc(dek, &[0; 16], wrapped).map_err(|_| 0x6a80_u16)?,
                        );
                        Material::Private(
                            SoftwareSigningKey::from_serialized_for_kind(
                                KeyKind::Ec(EcCurve::P256),
                                &scalar,
                            )
                            .map_err(|_| 0x6a80_u16)?,
                        )
                    }
                    Some(0xb0) if is_ca(command.p2) => {
                        let point = take_tlv(&mut data, 0xb0)?;
                        validate_point(point)?;
                        Material::Public(point.to_vec())
                    }
                    _ => return Err(0x6a80),
                };
                if take_tlv(&mut data, 0xf0)? != [0] || data != [0] {
                    return Err(0x6a80);
                }
                self.replace((command.p2, kvn), command.p1, Entry::new(material))?;
                Ok(vec![kvn])
            }
            0xe2 => self.store_data(command),
            0xe4 => {
                if command.p1 != 0 || command.p2 > 1 {
                    return Err(0x6a86);
                }
                let mut data = command.data;
                let mut kid = None;
                let mut kvn = None;
                while !data.is_empty() {
                    match data.first() {
                        Some(0xd0) if kid.is_none() => {
                            kid = Some(single(take_tlv(&mut data, 0xd0)?)?)
                        }
                        Some(0xd2) if kvn.is_none() => {
                            kvn = Some(single(take_tlv(&mut data, 0xd2)?)?)
                        }
                        _ => return Err(0x6a80),
                    }
                }
                if kid.is_none() && kvn.is_none()
                    || kid == Some(0)
                    || kvn == Some(0)
                    || kid.is_some_and(|k| k <= 3)
                {
                    return Err(0x6a80);
                }
                let targets: Vec<_> = self
                    .keys
                    .keys()
                    .copied()
                    .filter(|&(k, v)| {
                        kid.is_none_or(|id| id == k) && kvn.is_none_or(|version| version == v)
                    })
                    .collect();
                if targets.is_empty() {
                    return Err(0x6a88);
                }
                if targets.len() == self.keys.len() && command.p2 == 0 {
                    return Err(0x6985);
                }
                for target in targets {
                    self.keys.remove(&target);
                }
                self.persistent_change = true;
                Ok(Vec::new())
            }
            _ => Err(0x6d00),
        }
    }

    fn store_data(&mut self, command: &CommandApdu<'_>) -> StatusResult<Vec<u8>> {
        if (command.p1, command.p2) != (0x90, 0) {
            return Err(0x6a86);
        }
        let mut data = command.data;
        let mut selector = take_tlv(&mut data, 0xa6)?;
        if selector.first() == Some(&0x80) {
            let klcc = single(take_tlv(&mut selector, 0x80)?)?;
            let issuer = take_tlv(&mut selector, 0x42)?.to_vec();
            let reference = selector_ref(selector)?;
            if !data.is_empty()
                || issuer.is_empty()
                || issuer.len() > 64
                || klcc > 1
                || is_card(reference.0) != (klcc == 1)
            {
                return Err(0x6a80);
            }
            self.keys.get_mut(&reference).ok_or(0x6a88_u16)?.issuer = issuer;
        } else {
            let reference = selector_ref(selector)?;
            let entry = self.keys.get_mut(&reference).ok_or(0x6a88_u16)?;
            match data.first() {
                Some(0xbf) if is_card(reference.0) => {
                    let mut bundle = take_tlv(&mut data, 0xbf21)?;
                    let mut certificates = Vec::new();
                    while !bundle.is_empty() {
                        let before = bundle;
                        take_tlv(&mut bundle, 0x30)?;
                        let cert = before[..before.len() - bundle.len()].to_vec();
                        if certificates.len() >= 8 || cert.len() > 8192 {
                            return Err(0x6a84);
                        }
                        ParsedCertificate::parse(&cert).map_err(|_| 0x6a80_u16)?;
                        certificates.push(cert);
                    }
                    if !data.is_empty() {
                        return Err(0x6a80);
                    }
                    // The stored chain is presentation material, not host trust.
                    // Ensure the leaf belongs to the selected card key.
                    let leaf = ParsedCertificate::parse(certificates.last().ok_or(0x6a80_u16)?)
                        .map_err(|_| 0x6a80_u16)?;
                    if Some(leaf.p256_public_point().map_err(|_| 0x6a80_u16)?) != entry.point() {
                        return Err(0x6a80);
                    }
                    entry.certificates = certificates;
                }
                Some(0x70) if matches!(reference.0, 0x11 | 0x15) || is_ca(reference.0) => {
                    let mut serials = take_tlv(&mut data, 0x70)?;
                    if !data.is_empty() {
                        return Err(0x6a80);
                    }
                    let mut allowlist = Vec::new();
                    while !serials.is_empty() {
                        if allowlist.len() >= 64 {
                            return Err(0x6a84);
                        }
                        let serial = take_tlv(&mut serials, 0x93)?;
                        let canonical = canonical_serial(serial)?;
                        if canonical != serial {
                            return Err(0x6a80);
                        }
                        if !allowlist.contains(&canonical) {
                            allowlist.push(canonical);
                        }
                    }
                    entry.allowlist = allowlist;
                }
                _ => return Err(0x6a80),
            }
        }
        self.persistent_change = true;
        Ok(Vec::new())
    }
}

fn is_card(kid: u8) -> bool {
    matches!(kid, 0x11 | 0x13 | 0x15)
}
fn is_ca(kid: u8) -> bool {
    matches!(kid, 0x10 | 0x20..=0x2f)
}
fn valid_version(kvn: u8) -> bool {
    (1..=127).contains(&kvn)
}
fn validate_point(point: &[u8]) -> StatusResult<()> {
    if point.len() != 65 || point[0] != 4 {
        return Err(0x6a80);
    }
    SoftwarePublicKey::Ec {
        curve: EcCurve::P256,
        uncompressed: point.to_vec(),
    }
    .validate()
    .map_err(|_| 0x6a80)
}
fn single(value: &[u8]) -> StatusResult<u8> {
    if value.len() != 1 {
        Err(0x6a80)
    } else {
        Ok(value[0])
    }
}
fn selector_ref(mut value: &[u8]) -> StatusResult<KeyRef> {
    let reference = take_tlv(&mut value, 0x83)?;
    if reference.len() != 2 || !value.is_empty() {
        return Err(0x6a80);
    }
    Ok((reference[0], reference[1]))
}
fn canonical_serial(value: &[u8]) -> StatusResult<Vec<u8>> {
    if value.is_empty() || value.len() > 21 {
        return Err(0x6a80);
    }
    let first = value
        .iter()
        .position(|&v| v != 0)
        .unwrap_or(value.len() - 1);
    let mut value = value[first..].to_vec();
    if value[0] & 0x80 != 0 {
        value.insert(0, 0);
    }
    Ok(value)
}
fn decode_blobs(
    d: &mut minicbor::Decoder<'_>,
    max_count: u64,
    max_len: usize,
) -> Result<Vec<Vec<u8>>, &'static str> {
    let count = d
        .array()
        .map_err(|_| "invalid SD array")?
        .ok_or("indefinite SD array")?;
    if count > max_count {
        return Err("SD array too large");
    }
    let mut result = Vec::new();
    for _ in 0..count {
        let value = d.bytes().map_err(|_| "invalid SD bytes")?;
        if value.len() > max_len {
            return Err("SD value too large");
        }
        result.push(value.to_vec());
    }
    Ok(result)
}

/// Strict definite, minimally encoded BER lengths for the SD wire protocol.
fn take_tlv<'a>(data: &mut &'a [u8], expected: u16) -> StatusResult<&'a [u8]> {
    let original = *data;
    let (&first, mut rest) = original.split_first().ok_or(0x6a80_u16)?;
    let tag = if first & 0x1f == 0x1f {
        let (&second, remaining) = rest.split_first().ok_or(0x6a80_u16)?;
        rest = remaining;
        u16::from_be_bytes([first, second])
    } else {
        first as u16
    };
    if tag != expected {
        return Err(0x6a80);
    }
    let (&length, remaining) = rest.split_first().ok_or(0x6a80_u16)?;
    rest = remaining;
    let length = match length {
        0..=127 => length as usize,
        0x81 => {
            let (&length, remaining) = rest.split_first().ok_or(0x6a80_u16)?;
            if length < 128 {
                return Err(0x6a80);
            }
            rest = remaining;
            length as usize
        }
        0x82 if rest.len() >= 2 => {
            let length = u16::from_be_bytes([rest[0], rest[1]]) as usize;
            if length < 256 {
                return Err(0x6a80);
            }
            rest = &rest[2..];
            length
        }
        _ => return Err(0x6a80),
    };
    if rest.len() < length {
        return Err(0x6a80);
    }
    let (value, remaining) = rest.split_at(length);
    *data = remaining;
    Ok(value)
}

struct CertificateProfile {
    subject: Name,
    issuer: Name,
    is_ca: bool,
    key_agreement: bool,
}

impl BuilderProfile for CertificateProfile {
    fn get_issuer(&self, _subject: &Name) -> Name {
        self.issuer.clone()
    }

    fn get_subject(&self) -> Name {
        self.subject.clone()
    }

    fn build_extensions(
        &self,
        _subject_key: SubjectPublicKeyInfoRef<'_>,
        _issuer_key: SubjectPublicKeyInfoRef<'_>,
        tbs: &TbsCertificate,
    ) -> x509_cert::builder::Result<Vec<Extension>> {
        let mut extensions = Vec::new();
        extensions.push(
            BasicConstraints {
                ca: self.is_ca,
                path_len_constraint: self.is_ca.then_some(0),
            }
            .to_extension(tbs.subject(), &extensions)?,
        );
        let mut usages = if self.is_ca {
            KeyUsages::KeyCertSign | KeyUsages::CRLSign
        } else {
            KeyUsages::DigitalSignature.into()
        };
        if self.key_agreement {
            usages |= KeyUsages::KeyAgreement;
        }
        extensions.push(KeyUsage(usages).to_extension(tbs.subject(), &extensions)?);
        Ok(extensions)
    }
}

fn certificate_chain(
    serial: u32,
    _firmware: [u8; 3],
    _form_factor: u8,
    scp11b_key: &SoftwareSigningKey,
) -> Result<Vec<Vec<u8>>, ()> {
    let root_key = SoftwareSigningKey::from_serialized_for_kind(
        KeyKind::Ec(EcCurve::P256),
        &VIRTUAL_ATTESTATION_ROOT_PRIVATE_KEY,
    )
    .map_err(|_| ())?;
    let root_signer = certificate::CertificateSigner::from_key(&root_key)?;
    let root_name = Name::from_str("CN=Virtual YubiKey Security Domain Root").map_err(|_| ())?;
    let validity = Validity::new(
        Time::from_str("2026-01-01T00:00:00Z").map_err(|_| ())?,
        Time::from_str("2049-12-31T23:59:59Z").map_err(|_| ())?,
    );
    let root = certificate::build(
        CertificateProfile {
            subject: root_name.clone(),
            issuer: root_name.clone(),
            is_ca: true,
            key_agreement: false,
        },
        &[0x56, 0x59, 0x4b, 0x53, 0x44, 0x01],
        validity,
        certificate::subject_public_key_info(&root_key)?,
        &root_signer,
    )?;
    let mut leaf_serial = [0_u8; 8];
    leaf_serial[..4].copy_from_slice(&serial.to_be_bytes());
    leaf_serial[4..].copy_from_slice(&[SCP11B_KEY_ID, SCP11B_KEY_VERSION, 0, 1]);
    let leaf_name =
        Name::from_str(&format!("CN=Virtual YubiKey SCP11b {serial}")).map_err(|_| ())?;
    let leaf = certificate::build(
        CertificateProfile {
            subject: leaf_name,
            issuer: root_name,
            is_ca: false,
            key_agreement: true,
        },
        &leaf_serial,
        validity,
        certificate::subject_public_key_info(scp11b_key)?,
        &root_signer,
    )?;
    // GlobalPlatform/YubiKey certificate stores are issuer-to-leaf. Both
    // libykpiv and pkcs11rs use the final certificate as the card key.
    Ok(vec![root, leaf])
}

fn push_tlv(output: &mut Vec<u8>, tag: &[u8], value: &[u8]) {
    output.extend_from_slice(tag);
    if value.len() < 0x80 {
        output.push(value.len() as u8);
    } else if value.len() <= u8::MAX as usize {
        output.extend([0x81, value.len() as u8]);
    } else {
        output.push(0x82);
        output.extend_from_slice(&(value.len() as u16).to_be_bytes());
    }
    output.extend_from_slice(value);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn execute(domain: &mut SecurityDomain, ins: u8, p1: u8, p2: u8, data: &[u8]) -> ResponseApdu {
        domain.exchange(
            &CommandApdu {
                cla: if ins == 0xe2 { 0 } else { 0x80 },
                ins,
                p1,
                p2,
                data,
                le: None,
                extended: false,
            },
            Some(&FACTORY_SCP03_KEY),
        )
    }

    #[test]
    fn replacement_and_failed_mutations_are_atomic() {
        let mut domain = SecurityDomain::new(42, [5, 8, 0], 1);
        assert_eq!(
            execute(&mut domain, 0xf1, 0, 0x11, &[2, 0xf0, 1, 0]).status,
            0x9000
        );
        let before = domain.persistent_state().unwrap();
        for data in [
            &[2, 0xf0, 1, 0][..],
            &[3, 0xf0, 1, 1],
            &[3, 0xf0, 0x81, 1, 0],
            &[3, 0xf0, 1, 0, 0],
        ] {
            assert_ne!(execute(&mut domain, 0xf1, 0, 0x11, data).status, 0x9000);
            assert_eq!(domain.persistent_state().unwrap(), before);
        }
        assert_eq!(
            execute(&mut domain, 0xf1, 2, 0x11, &[3, 0xf0, 1, 0]).status,
            0x9000
        );
        assert!(domain.scp11_key(0x11, 2).is_none());
        assert!(domain.scp11_key(0x11, 3).is_some());
        let state = domain.persistent_state().unwrap();
        let restored = SecurityDomain::from_persistent_state(42, [5, 8, 0], 1, &state).unwrap();
        assert_eq!(state, restored.persistent_state().unwrap());
        let mut trailing = state.clone();
        trailing.push(0);
        assert!(SecurityDomain::from_persistent_state(42, [5, 8, 0], 1, &trailing).is_err());
        assert!(SecurityDomain::from_persistent_state(43, [5, 8, 0], 1, &state).is_err());
    }

    #[test]
    fn deletion_requires_explicit_permission_for_the_final_key() {
        let mut domain = SecurityDomain::new(42, [5, 8, 0], 1);
        assert_eq!(
            execute(&mut domain, 0xe4, 0, 0, &[0xd2, 1, 0xff]).status,
            0x9000
        );
        assert!(domain.scp03_keys(0xff).is_none());
        let before = domain.persistent_state().unwrap();
        assert_eq!(
            execute(&mut domain, 0xe4, 0, 0, &[0xd0, 1, 0x13]).status,
            0x6985
        );
        assert_eq!(domain.persistent_state().unwrap(), before);
        assert_eq!(
            execute(&mut domain, 0xe4, 0, 1, &[0xd0, 1, 0x13]).status,
            0x9000
        );
        let state = domain.persistent_state().unwrap();
        let restored = SecurityDomain::from_persistent_state(42, [5, 8, 0], 1, &state).unwrap();
        assert!(restored.keys.is_empty());
    }

    #[test]
    fn factory_state_decoder_preserves_the_existing_identity() {
        let domain = SecurityDomain::new(42, [5, 8, 0], 1);
        let key = domain.scp11_key(0x13, 1).unwrap().serialized().unwrap();
        let mut encoded = Vec::new();
        minicbor::Encoder::new(&mut encoded)
            .map(3)
            .unwrap()
            .u8(1)
            .unwrap()
            .u8(1)
            .unwrap()
            .u8(2)
            .unwrap()
            .u32(42)
            .unwrap()
            .u8(3)
            .unwrap()
            .bytes(&key)
            .unwrap();
        let restored = SecurityDomain::from_persistent_state(42, [5, 8, 0], 1, &encoded).unwrap();
        assert_eq!(restored.scp11b_public_key(), domain.scp11b_public_key());
    }

    #[test]
    fn bare_ca_trust_checks_signatures_usage_time_and_intermediate_constraints() {
        let key = || SoftwareSigningKey::generate_for_kind(KeyKind::Ec(EcCurve::P256)).unwrap();
        let ca = key();
        let host = key();
        let other = key();
        let point = match ca.public_key() {
            SoftwarePublicKey::Ec { uncompressed, .. } => uncompressed,
            _ => unreachable!(),
        };
        let certificate = |subject: &str,
                           issuer: &str,
                           subject_key: &SoftwareSigningKey,
                           signer: &SoftwareSigningKey,
                           is_ca,
                           key_agreement,
                           expired| {
            let validity = if expired {
                ("2000-01-01T00:00:00Z", "2001-01-01T00:00:00Z")
            } else {
                ("2026-01-01T00:00:00Z", "2049-12-31T23:59:59Z")
            };
            certificate::build(
                CertificateProfile {
                    subject: Name::from_str(subject).unwrap(),
                    issuer: Name::from_str(issuer).unwrap(),
                    is_ca,
                    key_agreement,
                },
                &[2],
                Validity::new(
                    Time::from_str(validity.0).unwrap(),
                    Time::from_str(validity.1).unwrap(),
                ),
                certificate::subject_public_key_info(subject_key).unwrap(),
                &certificate::CertificateSigner::from_key(signer).unwrap(),
            )
            .unwrap()
        };
        let leaf = certificate("CN=Host", "CN=CA", &host, &ca, false, true, false);
        assert!(CertificateTrust::validate_with_p256_ca_key(&point, &[leaf]).is_ok());
        for (signer, is_ca, agreement, expired) in [
            (&other, false, true, false),
            (&ca, true, true, false),
            (&ca, false, false, false),
            (&ca, false, true, true),
        ] {
            let leaf = certificate("CN=Host", "CN=CA", &host, signer, is_ca, agreement, expired);
            assert!(CertificateTrust::validate_with_p256_ca_key(&point, &[leaf]).is_err());
        }
        let leaf = certificate(
            "CN=Host",
            "CN=Intermediate",
            &host,
            &other,
            false,
            true,
            false,
        );
        for is_ca in [false, true] {
            let intermediate =
                certificate("CN=Intermediate", "CN=CA", &other, &ca, is_ca, false, false);
            assert_eq!(
                CertificateTrust::validate_with_p256_ca_key(&point, &[intermediate, leaf.clone()])
                    .is_ok(),
                is_ca
            );
        }
    }
}
