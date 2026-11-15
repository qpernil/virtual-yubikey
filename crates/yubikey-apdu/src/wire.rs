use std::fmt;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApduError {
    TooShort,
    InvalidLength,
}
impl fmt::Display for ApduError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid APDU: {self:?}")
    }
}
impl std::error::Error for ApduError {}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct CommandApdu<'a> {
    pub cla: u8,
    pub ins: u8,
    pub p1: u8,
    pub p2: u8,
    pub data: &'a [u8],
    pub le: Option<u32>,
    pub extended: bool,
}
impl fmt::Debug for CommandApdu<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CommandApdu")
            .field("cla", &self.cla)
            .field("ins", &self.ins)
            .field("p1", &self.p1)
            .field("p2", &self.p2)
            .field("data_length", &self.data.len())
            .field("le", &self.le)
            .field("extended", &self.extended)
            .finish()
    }
}
impl<'a> CommandApdu<'a> {
    pub fn decode(raw: &'a [u8]) -> Result<Self, ApduError> {
        if raw.len() < 4 {
            return Err(ApduError::TooShort);
        }
        let (data, le, extended) = match raw.len() {
            4 => (&raw[4..4], None, false),
            5 => (&raw[4..4], Some(short_le(raw[4])), false),
            _ if raw[4] != 0 => {
                let end = 5 + usize::from(raw[4]);
                if raw.len() == end {
                    (&raw[5..end], None, false)
                } else if raw.len() == end + 1 {
                    (&raw[5..end], Some(short_le(raw[end])), false)
                } else {
                    return Err(ApduError::InvalidLength);
                }
            }
            7 => (
                &raw[7..7],
                Some(extended_le(u16::from_be_bytes([raw[5], raw[6]]))),
                true,
            ),
            _ => {
                if raw.len() < 7 {
                    return Err(ApduError::InvalidLength);
                }
                let length = usize::from(u16::from_be_bytes([raw[5], raw[6]]));
                if length == 0 {
                    return Err(ApduError::InvalidLength);
                }
                let end = 7 + length;
                if raw.len() == end {
                    (&raw[7..end], None, true)
                } else if raw.len() == end + 2 {
                    (
                        &raw[7..end],
                        Some(extended_le(u16::from_be_bytes([raw[end], raw[end + 1]]))),
                        true,
                    )
                } else {
                    return Err(ApduError::InvalidLength);
                }
            }
        };
        Ok(Self {
            cla: raw[0],
            ins: raw[1],
            p1: raw[2],
            p2: raw[3],
            data,
            le,
            extended,
        })
    }
    pub fn uses_extended_length(&self, data_len: usize) -> Result<bool, ApduError> {
        if data_len > 65535 || self.le.is_some_and(|le| le == 0 || le > 65536) {
            return Err(ApduError::InvalidLength);
        }
        Ok(self.extended || data_len > 255 || self.le.is_some_and(|le| le > 256))
    }
    /// Encode a header/data prefix, reserving length for a MAC appended by the caller.
    /// No command parameters are interpreted or changed.
    pub fn encode_header_and_data(&self, encoded_data_len: usize) -> Result<Vec<u8>, ApduError> {
        if encoded_data_len < self.data.len() {
            return Err(ApduError::InvalidLength);
        }
        let extended = self.uses_extended_length(encoded_data_len)?;
        let mut raw = vec![self.cla, self.ins, self.p1, self.p2];
        if encoded_data_len != 0 {
            if extended {
                raw.push(0);
                raw.extend_from_slice(&(encoded_data_len as u16).to_be_bytes());
            } else {
                raw.push(encoded_data_len as u8);
            }
            raw.extend_from_slice(self.data);
        }
        Ok(raw)
    }
    pub fn encode(&self) -> Result<Vec<u8>, ApduError> {
        let extended = self.uses_extended_length(self.data.len())?;
        let mut raw = self.encode_header_and_data(self.data.len())?;
        if let Some(le) = self.le {
            if extended {
                if self.data.is_empty() {
                    raw.push(0);
                }
                raw.extend_from_slice(&(if le == 65536 { 0 } else { le as u16 }).to_be_bytes());
            } else {
                raw.push(if le == 256 { 0 } else { le as u8 });
            }
        }
        Ok(raw)
    }
}
fn short_le(value: u8) -> u32 {
    if value == 0 { 256 } else { u32::from(value) }
}
fn extended_le(value: u16) -> u32 {
    if value == 0 { 65536 } else { u32::from(value) }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct ResponseApdu<'a> {
    pub data: &'a [u8],
    pub status: u16,
}
impl fmt::Debug for ResponseApdu<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ResponseApdu")
            .field("data_length", &self.data.len())
            .field("status", &self.status)
            .finish()
    }
}
impl<'a> ResponseApdu<'a> {
    pub fn decode(raw: &'a [u8]) -> Result<Self, ApduError> {
        let end = raw.len().checked_sub(2).ok_or(ApduError::TooShort)?;
        Ok(Self {
            data: &raw[..end],
            status: u16::from_be_bytes([raw[end], raw[end + 1]]),
        })
    }
    pub fn encode(&self) -> Vec<u8> {
        Self::encode_owned(self.data.to_vec(), self.status)
    }
    /// Encode an owned payload without allocating a second payload buffer.
    pub fn encode_owned(mut data: Vec<u8>, status: u16) -> Vec<u8> {
        data.extend_from_slice(&status.to_be_bytes());
        data
    }
}
