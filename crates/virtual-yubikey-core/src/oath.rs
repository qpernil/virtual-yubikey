//! YKOATH credential storage and connection-scoped mutual authentication.
use crate::{CommandApdu, PresenceAuthorization, ResponseApdu, UserPresencePolicy};
use software_key_core::digest::{HashAlgorithm as MessageDigest, hmac};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

pub const OATH_AID: [u8; 7] = [0xa0, 0, 0, 5, 0x27, 0x21, 1];
const MAX_CREDENTIALS: usize = 64;
const WRONG_DATA: u16 = 0x6a80;
const NOT_FOUND: u16 = 0x6984;

struct Credential {
    name: Vec<u8>,
    kind: u8,
    digits: u8,
    secret: Zeroizing<Vec<u8>>,
    properties: u8,
    counter: u64,
    last_challenge: Option<u64>,
}
impl Credential {
    fn validate(&self) -> Result<(), u16> {
        if self.name.is_empty()
            || self.name.len() > 64
            || !matches!(self.kind & 0xf0, 0x10 | 0x20)
            || digest(self.kind & 15).is_none()
            || !(6..=8).contains(&self.digits)
            || !(14..=64).contains(&self.secret.len())
            || self.properties & !3 != 0
            || (self.kind & 0xf0 == 0x10 && self.properties & 1 != 0)
            || (self.properties & 1 == 0 && self.last_challenge.is_some())
        {
            return Err(WRONG_DATA);
        }
        Ok(())
    }
    fn result(&self, challenge: &[u8], truncate: bool) -> Result<Vec<u8>, u16> {
        let mac = Zeroizing::new(
            hmac(
                digest(self.kind & 15).ok_or(WRONG_DATA)?,
                &self.secret,
                challenge,
            )
            .map_err(|_| 0x6f00u16)?,
        );
        let mut result = vec![self.digits];
        if truncate {
            let offset = usize::from(mac[mac.len() - 1] & 15);
            result.extend_from_slice(&mac[offset..offset + 4]);
            result[1] &= 0x7f;
        } else {
            result.extend_from_slice(&mac);
        }
        Ok(result)
    }
    fn increasing_challenge(&self, challenge: &[u8]) -> Result<Option<u64>, u16> {
        if self.properties & 1 == 0 {
            return Ok(None);
        }
        let value = u64::from_be_bytes(challenge.try_into().map_err(|_| WRONG_DATA)?);
        if self.last_challenge.is_some_and(|last| value <= last) {
            return Err(0x6985);
        }
        Ok(Some(value))
    }
}

pub(crate) enum Exchange {
    Complete(ResponseApdu),
    PresenceRequired(UserPresencePolicy),
}

pub(crate) struct OathApplet {
    serial: u32,
    firmware: [u8; 3],
    salt: [u8; 8],
    access_key: Option<Zeroizing<Vec<u8>>>,
    challenge: Option<[u8; 8]>,
    authorized: bool,
    credentials: Vec<Credential>,
    dirty: bool,
}
impl core::fmt::Debug for OathApplet {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("OathApplet")
            .field("credential_count", &self.credentials.len())
            .field("protected", &self.access_key.is_some())
            .finish_non_exhaustive()
    }
}
impl OathApplet {
    pub(crate) fn new(serial: u32, firmware: [u8; 3]) -> Self {
        let mut salt = [0; 8];
        getrandom::fill(&mut salt).expect("OATH identity requires system randomness");
        Self {
            serial,
            firmware,
            salt,
            access_key: None,
            challenge: None,
            authorized: false,
            credentials: Vec::new(),
            dirty: false,
        }
    }
    pub(crate) fn reset_connection(&mut self) {
        self.authorized = false;
        self.challenge = None;
    }
    /// Channel establishment follows SELECT; its challenge must remain usable.
    pub(crate) fn clear_authorization(&mut self) {
        self.authorized = false;
    }
    pub(crate) fn take_persistent_change(&mut self) -> bool {
        core::mem::take(&mut self.dirty)
    }
    pub(crate) fn select_response(&mut self) -> ResponseApdu {
        self.reset_connection();
        let mut data = Vec::new();
        tlv(&mut data, 0x79, &self.firmware);
        tlv(&mut data, 0x71, &self.salt);
        if self.access_key.is_some() {
            let mut challenge = [0; 8];
            if getrandom::fill(&mut challenge).is_err() {
                return ResponseApdu::status(0x6f00);
            }
            self.challenge = Some(challenge);
            tlv(&mut data, 0x74, &challenge);
            tlv(&mut data, 0x7b, &[1]);
        }
        ResponseApdu::success(data)
    }
    pub(crate) fn exchange(
        &mut self,
        command: &CommandApdu<'_>,
        presence: PresenceAuthorization,
    ) -> Exchange {
        if command.cla != 0 {
            return Exchange::Complete(ResponseApdu::status(0x6e00));
        }
        let result = self.execute(command, presence);
        match result {
            Ok(Some(data)) => Exchange::Complete(ResponseApdu::success(data)),
            Ok(None) => Exchange::PresenceRequired(UserPresencePolicy::Always),
            Err(status) => Exchange::Complete(ResponseApdu::status(status)),
        }
    }
    fn execute(
        &mut self,
        c: &CommandApdu<'_>,
        presence: PresenceAuthorization,
    ) -> Result<Option<Vec<u8>>, u16> {
        if c.ins == 4 {
            if (c.p1, c.p2) != (0xde, 0xad) || !c.data.is_empty() {
                return Err(0x6a86);
            }
            let mut salt = [0; 8];
            getrandom::fill(&mut salt).map_err(|_| 0x6f00u16)?;
            self.credentials.clear();
            self.access_key = None;
            self.salt = salt;
            self.reset_connection();
            self.dirty = true;
            return Ok(Some(Vec::new()));
        }
        if c.p1 != 0 || c.p2 > 1 || (c.p2 != 0 && !matches!(c.ins, 0xa2 | 0xa4)) {
            return Err(0x6a86);
        }
        if !matches!(c.ins, 1..=3 | 5 | 0xa1..=0xa4) {
            return Err(0x6d00);
        }
        if c.ins != 0xa3 && self.access_key.is_some() && !self.authorized {
            return Err(0x6982);
        }
        let fields = match parse(c.data, c.ins == 1) {
            Ok(fields) => fields,
            Err(status) => {
                if c.ins == 0xa3 {
                    self.reset_connection();
                }
                return Err(status);
            }
        };
        let mut output = Vec::new();
        match c.ins {
            1 => {
                only(&fields, &[0x71, 0x73, 0x78, 0x7a])?;
                let name = required(&fields, 0x71)?;
                let key = required(&fields, 0x73)?;
                if key.len() < 2 {
                    return Err(WRONG_DATA);
                }
                let properties = field(&fields, 0x78).unwrap_or(&[0]);
                if properties.len() != 1 {
                    return Err(WRONG_DATA);
                }
                let counter = match field(&fields, 0x7a) {
                    Some(value) if key[0] & 0xf0 == 0x10 => u64::from(u32::from_be_bytes(
                        value.try_into().map_err(|_| WRONG_DATA)?,
                    )),
                    Some(_) => return Err(WRONG_DATA),
                    None => 0,
                };
                let credential = Credential {
                    name: name.to_vec(),
                    kind: key[0],
                    digits: key[1],
                    secret: Zeroizing::new(key[2..].to_vec()),
                    properties: properties[0],
                    counter,
                    last_challenge: None,
                };
                credential.validate()?;
                if let Some(index) = self.credentials.iter().position(|v| v.name == name) {
                    self.credentials[index] = credential;
                } else {
                    if self.credentials.len() >= MAX_CREDENTIALS {
                        return Err(0x6a84);
                    }
                    self.credentials.push(credential);
                }
                self.dirty = true;
            }
            2 => {
                only(&fields, &[0x71])?;
                let index = self.index(required(&fields, 0x71)?)?;
                self.credentials.remove(index);
                self.dirty = true;
            }
            3 => {
                only(&fields, &[0x73, 0x74, 0x75])?;
                let key = required(&fields, 0x73)?;
                if key.is_empty() {
                    if fields.len() != 1 {
                        return Err(WRONG_DATA);
                    }
                    self.access_key = None;
                } else {
                    if key.len() != 17 || key[0] != 0x21 {
                        return Err(WRONG_DATA);
                    }
                    let challenge = required(&fields, 0x74)?;
                    if challenge.len() != 8 {
                        return Err(WRONG_DATA);
                    }
                    let response = required(&fields, 0x75)?;
                    if !bool::from(response.ct_eq(&mac(&key[1..], challenge)?)) {
                        return Err(0x6984);
                    }
                    self.access_key = Some(Zeroizing::new(key[1..].to_vec()));
                }
                // SET CODE does not revoke the current native applet session.
                self.authorized = true;
                self.challenge = None;
                self.dirty = true;
            }
            5 => {
                if fields.len() != 2 || fields.iter().any(|(t, _)| *t != 0x71) {
                    return Err(WRONG_DATA);
                }
                let index = self.index(fields[0].1)?;
                let name = fields[1].1;
                if name.is_empty()
                    || name.len() > 64
                    || self.credentials.iter().any(|v| v.name == name)
                {
                    return Err(WRONG_DATA);
                }
                self.credentials[index].name = name.to_vec();
                self.dirty = true;
            }
            0xa1 => {
                if !fields.is_empty() {
                    return Err(WRONG_DATA);
                }
                for v in &self.credentials {
                    tlv(&mut output, 0x72, &[&[v.kind], v.name.as_slice()].concat());
                }
            }
            0xa2 => {
                only(&fields, &[0x71, 0x74])?;
                let index = self.index(required(&fields, 0x71)?)?;
                let v = &mut self.credentials[index];
                let host_challenge = required(&fields, 0x74)?;
                if host_challenge.len() > 64 || (v.kind & 0xf0 == 0x20 && host_challenge.is_empty())
                {
                    return Err(WRONG_DATA);
                }
                let increasing = v.increasing_challenge(host_challenge)?;
                if v.properties & 2 != 0 && presence != PresenceAuthorization::Granted {
                    return Ok(None);
                }
                let hotp = v.kind & 0xf0 == 0x10;
                let next = if hotp {
                    Some(v.counter.checked_add(1).ok_or(0x6985u16)?)
                } else {
                    None
                };
                let counter = v.counter.to_be_bytes();
                let challenge = if hotp {
                    counter.as_slice()
                } else {
                    host_challenge
                };
                tlv(
                    &mut output,
                    if c.p2 == 1 { 0x76 } else { 0x75 },
                    &v.result(challenge, c.p2 == 1)?,
                );
                if let Some(next) = next {
                    v.counter = next;
                    self.dirty = true;
                }
                if let Some(value) = increasing {
                    v.last_challenge = Some(value);
                    self.dirty = true;
                }
            }
            0xa3 => {
                // Every attempt consumes SELECT's challenge, including malformed authentication.
                self.authorized = false;
                let challenge = self.challenge.take().ok_or(0x6984u16)?;
                only(&fields, &[0x75, 0x74])?;
                let key = self.access_key.as_ref().ok_or(0x6984u16)?;
                let host = required(&fields, 0x74)?;
                if host.len() != 8 {
                    return Err(WRONG_DATA);
                }
                if !bool::from(required(&fields, 0x75)?.ct_eq(&mac(key, &challenge)?)) {
                    return Err(0x6a80);
                }
                tlv(&mut output, 0x75, &mac(key, host)?);
                self.authorized = true;
            }
            0xa4 => {
                only(&fields, &[0x74])?;
                let challenge = required(&fields, 0x74)?;
                if challenge.is_empty() || challenge.len() > 64 {
                    return Err(WRONG_DATA);
                }
                let mut updates = Vec::new();
                for (index, v) in self.credentials.iter().enumerate() {
                    tlv(&mut output, 0x71, &v.name);
                    if v.kind & 0xf0 == 0x10 {
                        tlv(&mut output, 0x77, &[v.digits]);
                    } else if v.properties & 2 != 0 {
                        tlv(&mut output, 0x7c, &[v.digits]);
                    } else {
                        let increasing = v.increasing_challenge(challenge)?;
                        tlv(
                            &mut output,
                            if c.p2 == 1 { 0x76 } else { 0x75 },
                            &v.result(challenge, c.p2 == 1)?,
                        );
                        if let Some(value) = increasing {
                            updates.push((index, value));
                        }
                    }
                }
                for (index, value) in updates {
                    self.credentials[index].last_challenge = Some(value);
                    self.dirty = true;
                }
            }
            _ => unreachable!(),
        }
        Ok(Some(output))
    }
    fn index(&self, name: &[u8]) -> Result<usize, u16> {
        self.credentials
            .iter()
            .position(|v| v.name == name)
            .ok_or(NOT_FOUND)
    }
    pub(crate) fn persistent_state(&self) -> Result<Vec<u8>, &'static str> {
        self.encode_persistent()
            .map_err(|_| "cannot encode OATH state")
    }
    fn encode_persistent(
        &self,
    ) -> Result<Vec<u8>, minicbor::encode::Error<core::convert::Infallible>> {
        let mut encoder = minicbor::Encoder::new(Vec::new());
        encoder
            .array(5)?
            .u8(1)?
            .u32(self.serial)?
            .bytes(&self.salt)?;
        if let Some(key) = &self.access_key {
            encoder.bytes(key)?;
        } else {
            encoder.null()?;
        }
        encoder.array(self.credentials.len() as u64)?;
        for credential in &self.credentials {
            encoder
                .array(8)?
                .bytes(&credential.name)?
                .u8(credential.kind)?
                .u8(credential.digits)?
                .bytes(&credential.secret)?
                .u8(credential.properties)?
                .u64(credential.counter)?;
            if let Some(last) = credential.last_challenge {
                encoder.u64(last)?;
            } else {
                encoder.null()?;
            }
            encoder.u8(1)?; // credential format version
        }
        Ok(encoder.into_writer())
    }
    pub(crate) fn from_persistent_state(
        serial: u32,
        firmware: [u8; 3],
        data: &[u8],
    ) -> Result<Self, &'static str> {
        Self::decode_persistent(serial, firmware, data).map_err(|_| "invalid persistent OATH state")
    }
    fn decode_persistent(
        serial: u32,
        firmware: [u8; 3],
        data: &[u8],
    ) -> Result<Self, minicbor::decode::Error> {
        let mut decoder = minicbor::Decoder::new(data);
        let invalid = || minicbor::decode::Error::message("invalid OATH state");
        if decoder.array()? != Some(5) || decoder.u8()? != 1 || decoder.u32()? != serial {
            return Err(invalid());
        }
        let salt = decoder.bytes()?.try_into().map_err(|_| invalid())?;
        let access_key = if decoder.datatype()? == minicbor::data::Type::Null {
            decoder.null()?;
            None
        } else {
            let key = decoder.bytes()?;
            if key.len() != 16 {
                return Err(invalid());
            }
            Some(Zeroizing::new(key.to_vec()))
        };
        let count = decoder.array()?.ok_or_else(invalid)?;
        if count > MAX_CREDENTIALS as u64 {
            return Err(invalid());
        }
        let mut credentials: Vec<Credential> = Vec::new();
        for _ in 0..count {
            if decoder.array()? != Some(8) {
                return Err(invalid());
            }
            let name = decoder.bytes()?.to_vec();
            let kind = decoder.u8()?;
            let digits = decoder.u8()?;
            let secret = Zeroizing::new(decoder.bytes()?.to_vec());
            let properties = decoder.u8()?;
            let counter = decoder.u64()?;
            let last_challenge = if decoder.datatype()? == minicbor::data::Type::Null {
                decoder.null()?;
                None
            } else {
                Some(decoder.u64()?)
            };
            if decoder.u8()? != 1 {
                return Err(invalid());
            }
            let v = Credential {
                name,
                kind,
                digits,
                secret,
                properties,
                counter,
                last_challenge,
            };
            v.validate().map_err(|_| invalid())?;
            if credentials.iter().any(|other| other.name == v.name) {
                return Err(invalid());
            }
            credentials.push(v);
        }
        if decoder.position() != data.len() {
            return Err(invalid());
        }
        Ok(OathApplet {
            serial,
            firmware,
            salt,
            access_key,
            credentials,
            challenge: None,
            authorized: false,
            dirty: false,
        })
    }
}
fn digest(id: u8) -> Option<MessageDigest> {
    match id {
        1 => Some(MessageDigest::Sha1),
        2 => Some(MessageDigest::Sha256),
        3 => Some(MessageDigest::Sha512),
        _ => None,
    }
}
fn mac(key: &[u8], challenge: &[u8]) -> Result<Zeroizing<Vec<u8>>, u16> {
    hmac(MessageDigest::Sha1, key, challenge)
        .map(Zeroizing::new)
        .map_err(|_| 0x6f00)
}
fn tlv(out: &mut Vec<u8>, tag: u8, value: &[u8]) {
    out.push(tag);
    if value.len() >= 128 {
        out.push(0x81);
    }
    out.push(value.len() as u8);
    out.extend_from_slice(value);
}
fn parse(mut data: &[u8], property: bool) -> Result<Vec<(u8, &[u8])>, u16> {
    let mut out = Vec::new();
    while !data.is_empty() {
        if data.len() < 2 {
            return Err(WRONG_DATA);
        }
        let tag = data[0];
        // YKOATH's property is a tag + byte, deliberately not a TLV.
        if tag == 0x78 && property {
            out.push((tag, &data[1..2]));
            data = &data[2..];
            continue;
        }
        let (len, offset) = match data[1] {
            0..=127 => (data[1] as usize, 2),
            0x81 if data.len() >= 3 => (data[2] as usize, 3),
            _ => return Err(WRONG_DATA),
        };
        let value = data.get(offset..offset + len).ok_or(WRONG_DATA)?;
        out.push((tag, value));
        data = &data[offset + len..];
    }
    Ok(out)
}
fn field<'a>(fields: &[(u8, &'a [u8])], tag: u8) -> Option<&'a [u8]> {
    fields.iter().find(|(t, _)| *t == tag).map(|(_, v)| *v)
}
fn required<'a>(fields: &[(u8, &'a [u8])], tag: u8) -> Result<&'a [u8], u16> {
    field(fields, tag).ok_or(WRONG_DATA)
}
fn only(fields: &[(u8, &[u8])], allowed: &[u8]) -> Result<(), u16> {
    for (index, (tag, _)) in fields.iter().enumerate() {
        if !allowed.contains(tag) || fields[..index].iter().any(|(t, _)| t == tag) {
            return Err(WRONG_DATA);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
