//! Shared Management capability configuration for every transport of one device.
use crate::{
    Applet, CAPABILITY_CCID, CAPABILITY_FIDO2, CAPABILITY_HSMAUTH, CAPABILITY_OPENPGP,
    CAPABILITY_PIV, CAPABILITY_U2F, DeviceProfile, push_tlv,
};
use std::sync::{Arc, Mutex, MutexGuard};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

#[derive(Clone)]
pub struct Management {
    profile: DeviceProfile,
    state: Arc<Mutex<State>>,
}
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct State {
    enabled: u16,
    lock_verifier: Option<[u8; 32]>,
    dirty: bool,
    revision: u64,
}
impl std::fmt::Debug for Management {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Management")
            .field("serial", &self.profile.serial)
            .finish_non_exhaustive()
    }
}
impl State {
    pub(crate) fn revision(&self) -> u64 {
        self.revision
    }
    pub(crate) fn u2f_enabled(&self) -> bool {
        self.enabled & CAPABILITY_U2F != 0
    }
    pub(crate) fn fido2_enabled(&self) -> bool {
        self.enabled & CAPABILITY_FIDO2 != 0
    }
}
impl Management {
    pub fn new(profile: DeviceProfile) -> Self {
        let enabled = profile.usb_supported_capabilities();
        Self {
            profile,
            state: Arc::new(Mutex::new(State {
                enabled,
                lock_verifier: None,
                dirty: false,
                revision: 0,
            })),
        }
    }
    pub(crate) fn lock(&self) -> Result<MutexGuard<'_, State>, u16> {
        self.state.lock().map_err(|_| 0x6f00)
    }
    pub(crate) fn revision(&self) -> Result<u64, u16> {
        Ok(self.lock()?.revision)
    }
    pub fn usb_supported_capabilities(&self) -> u16 {
        self.profile.usb_supported_capabilities()
    }
    pub fn usb_enabled_capabilities(&self) -> Result<u16, u16> {
        Ok(self.lock()?.enabled)
    }
    pub fn applet_enabled(&self, applet: Applet) -> bool {
        if !self.profile.applets.contains(applet) {
            return false;
        }
        let bit = match applet {
            Applet::Management | Applet::IssuerSecurityDomain => return true,
            Applet::Piv => CAPABILITY_PIV,
            Applet::OpenPgp => CAPABILITY_OPENPGP,
            Applet::HsmAuth => CAPABILITY_HSMAUTH,
            Applet::Fido2 => CAPABILITY_U2F | CAPABILITY_FIDO2,
        };
        self.usb_enabled_capabilities()
            .is_ok_and(|mask| mask & bit != 0)
    }
    pub fn u2f_enabled(&self) -> bool {
        self.lock().is_ok_and(|state| state.u2f_enabled())
    }
    pub fn fido2_enabled(&self) -> bool {
        self.lock().is_ok_and(|state| state.fido2_enabled())
    }
    pub fn read_config(&self, page: u8) -> Result<Vec<u8>, u16> {
        if page != 0 {
            return Err(0x6a86);
        }
        let state = self.lock()?;
        let mut body = Vec::new();
        push_tlv(
            &mut body,
            1,
            &self.usb_supported_capabilities().to_be_bytes(),
        );
        push_tlv(&mut body, 2, &self.profile.serial.to_be_bytes());
        push_tlv(&mut body, 3, &state.enabled.to_be_bytes());
        push_tlv(&mut body, 4, &[self.profile.form_factor]);
        push_tlv(&mut body, 5, &self.profile.firmware);
        push_tlv(&mut body, 6, &[0, 0]);
        push_tlv(&mut body, 7, &[15]);
        push_tlv(&mut body, 8, &[0]);
        push_tlv(&mut body, 10, &[u8::from(state.lock_verifier.is_some())]);
        let mut response = vec![body.len() as u8];
        response.extend_from_slice(&body);
        Ok(response)
    }
    fn verifier(&self, code: &[u8]) -> [u8; 32] {
        let mut input = Zeroizing::new(b"virtual-yubikey.management-lock.v1".to_vec());
        input.extend_from_slice(&self.profile.serial.to_be_bytes());
        input.extend_from_slice(code);
        software_key_core::digest::HashAlgorithm::Sha256
            .digest(&input)
            .try_into()
            .expect("SHA256 length")
    }
    /// Apply one complete Yubico length-prefixed TLV transaction. Unknown or
    /// unsupported settings fail atomically; configuration lock codes are never retained.
    pub fn write_config(&self, encoded: &[u8]) -> Result<(), u16> {
        let Some((&length, body)) = encoded.split_first() else {
            return Err(0x6a80);
        };
        if usize::from(length) != body.len() {
            return Err(0x6a80);
        }
        let mut seen = [false; 256];
        let mut position = 0;
        let mut reboot = false;
        let mut enabled = None;
        let mut new_lock = None;
        let mut unlock = None;
        while position < body.len() {
            let header = body.get(position..position + 2).ok_or(0x6a80u16)?;
            let tag = header[0];
            let size = usize::from(header[1]);
            position += 2;
            let value = body.get(position..position + size).ok_or(0x6a80u16)?;
            position += size;
            if std::mem::replace(&mut seen[usize::from(tag)], true) {
                return Err(0x6a80);
            }
            match (tag, value) {
                (3, [hi, lo]) => enabled = Some(u16::from_be_bytes([*hi, *lo])),
                (10, code) if code.len() == 16 => new_lock = Some(code),
                (11, code) if code.len() == 16 => unlock = Some(code),
                (12, []) => reboot = true, // Settings apply immediately; the published USB personality stays stable.
                (6, [0, 0]) | (7, [15]) | (8, [0]) => {} // Fixed defaults only; no unsupported behavior is promised.
                _ => return Err(0x6a80),
            }
        }
        let mut state = self.lock()?;
        if let Some(verifier) = state.lock_verifier {
            let code = unlock.ok_or(0x6982u16)?;
            if !bool::from(verifier.ct_eq(&self.verifier(code))) {
                return Err(0x6982);
            }
        }
        let mut updated = state.clone();
        if let Some(mask) = enabled {
            let supported = self.usb_supported_capabilities();
            // CCID is a physical capability, not a writable application bit.
            updated.enabled = (mask & supported & !CAPABILITY_CCID) | (supported & CAPABILITY_CCID);
        }
        if let Some(code) = new_lock {
            updated.lock_verifier = if code == [0; 16] {
                None
            } else {
                Some(self.verifier(code))
            };
        }
        if updated.enabled != state.enabled || reboot {
            updated.revision = state.revision.checked_add(1).ok_or(0x6f00u16)?;
        }
        if updated.enabled != state.enabled || updated.lock_verifier != state.lock_verifier {
            updated.dirty = true;
        }
        *state = updated;
        Ok(())
    }
    pub fn take_persistent_change(&self) -> bool {
        self.lock()
            .is_ok_and(|mut state| std::mem::take(&mut state.dirty))
    }
    pub fn persistent_state(&self) -> Result<Vec<u8>, &'static str> {
        let state = self.lock().map_err(|_| "Management state lock poisoned")?;
        let mut encoded = Vec::new();
        minicbor::Encoder::new(&mut encoded)
            .map(4)
            .and_then(|e| e.u8(1))
            .and_then(|e| e.u8(1))
            .and_then(|e| e.u8(2))
            .and_then(|e| e.u32(self.profile.serial))
            .and_then(|e| e.u8(3))
            .and_then(|e| e.u16(state.enabled))
            .and_then(|e| e.u8(4))
            .and_then(|e| e.bytes(state.lock_verifier.as_ref().map_or(&[], |v| v.as_slice())))
            .map_err(|_| "cannot encode Management state")?;
        Ok(encoded)
    }
    pub fn from_persistent_state(
        profile: DeviceProfile,
        encoded: &[u8],
    ) -> Result<Self, &'static str> {
        let mut decoder = minicbor::Decoder::new(encoded);
        let count = decoder
            .map()
            .map_err(|_| "invalid Management state")?
            .ok_or("indefinite Management state")?;
        let mut version = None;
        let mut serial = None;
        let mut enabled = None;
        let mut verifier = None;
        for _ in 0..count {
            match decoder.u8().map_err(|_| "invalid Management field")? {
                1 if version.is_none() => {
                    version = Some(decoder.u8().map_err(|_| "invalid Management version")?)
                }
                2 if serial.is_none() => {
                    serial = Some(decoder.u32().map_err(|_| "invalid Management serial")?)
                }
                3 if enabled.is_none() => {
                    enabled = Some(
                        decoder
                            .u16()
                            .map_err(|_| "invalid Management capabilities")?,
                    )
                }
                4 if verifier.is_none() => {
                    verifier = Some(
                        decoder
                            .bytes()
                            .map_err(|_| "invalid Management lock")?
                            .to_vec(),
                    )
                }
                _ => return Err("unknown or duplicate Management field"),
            }
        }
        if decoder.position() != encoded.len()
            || version != Some(1)
            || serial != Some(profile.serial)
        {
            return Err("invalid Management identity or version");
        }
        let mask = enabled.ok_or("missing Management capabilities")?;
        let verifier = match verifier.ok_or("missing Management lock")?.as_slice() {
            [] => None,
            value if value.len() == 32 => Some(value.try_into().unwrap()),
            _ => return Err("invalid Management lock length"),
        };
        let supported = profile.usb_supported_capabilities();
        Ok(Self {
            profile,
            state: Arc::new(Mutex::new(State {
                enabled: (mask & supported & !CAPABILITY_CCID) | (supported & CAPABILITY_CCID),
                lock_verifier: verifier,
                dirty: false,
                revision: 0,
            })),
        })
    }
}

#[cfg(test)]
mod tests;
