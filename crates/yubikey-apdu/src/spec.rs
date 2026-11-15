use crate::{CommandApdu, ResponseApdu};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Value {
    Any,
    Exact(u8),
    Range(u8, u8),
    OneOf(&'static [u8]),
}
impl Value {
    pub fn accepts(self, value: u8) -> bool {
        match self {
            Self::Any => true,
            Self::Exact(v) => value == v,
            Self::Range(min, max) => (min..=max).contains(&value),
            Self::OneOf(v) => v.contains(&value),
        }
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Parameter {
    pub name: &'static str,
    pub values: Value,
}
impl Parameter {
    pub const fn new(name: &'static str, values: Value) -> Self {
        Self { name, values }
    }
    pub const fn fixed(name: &'static str, value: u8) -> Self {
        Self::new(name, Value::Exact(value))
    }
    pub const ZERO: Self = Self::fixed("reserved", 0);
    pub const ANY: Self = Self::new("command parameter", Value::Any);
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Length {
    pub min: usize,
    pub max: usize,
}
impl Length {
    pub const ANY: Self = Self::range(0, 65536);
    pub const EMPTY: Self = Self::exact(0);
    pub const fn exact(length: usize) -> Self {
        Self::range(length, length)
    }
    pub const fn range(min: usize, max: usize) -> Self {
        Self { min, max }
    }
    pub fn accepts(self, length: usize) -> bool {
        (self.min..=self.max).contains(&length)
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SpecError {
    Class,
    Instruction,
    Parameters,
    Data(u16),
    Response,
}
impl SpecError {
    pub const fn status(self) -> u16 {
        match self {
            Self::Class => 0x6e00,
            Self::Instruction => 0x6d00,
            Self::Parameters => 0x6a86,
            Self::Data(status) => status,
            Self::Response => 0x6f00,
        }
    }
}
impl std::fmt::Display for SpecError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "APDU specification mismatch: {self:?}")
    }
}
impl std::error::Error for SpecError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ApduSpec {
    pub name: &'static str,
    pub cla: u8,
    pub ins: u8,
    pub p1: Parameter,
    pub p2: Parameter,
    pub data: Length,
    pub response: Length,
    pub response_continuation: u8,
    pub protected_status: Option<u16>,
    pub data_error: u16,
}
impl ApduSpec {
    pub const fn new(
        name: &'static str,
        cla: u8,
        ins: u8,
        p1: Parameter,
        p2: Parameter,
        data: Length,
        response: Length,
    ) -> Self {
        Self {
            name,
            cla,
            ins,
            p1,
            p2,
            data,
            response,
            response_continuation: 0xc0,
            protected_status: None,
            data_error: if data.max == 0 { 0x6a86 } else { 0x6700 },
        }
    }
    pub const fn with_continuation(mut self, instruction: u8) -> Self {
        self.response_continuation = instruction;
        self
    }
    pub const fn with_protected_status(mut self, status: u16) -> Self {
        self.protected_status = Some(status);
        self
    }
    pub const fn with_data_error(mut self, status: u16) -> Self {
        self.data_error = status;
        self
    }
    pub fn validate(&self, command: &CommandApdu<'_>) -> Result<(), SpecError> {
        if command.cla != self.cla {
            return Err(SpecError::Class);
        }
        if command.ins != self.ins {
            return Err(SpecError::Instruction);
        }
        if !self.p1.values.accepts(command.p1) || !self.p2.values.accepts(command.p2) {
            return Err(SpecError::Parameters);
        }
        if !self.data.accepts(command.data.len()) {
            return Err(SpecError::Data(self.data_error));
        }
        if command.uses_extended_length(command.data.len()).is_err() {
            return Err(SpecError::Data(0x6700));
        }
        Ok(())
    }
    pub fn command<'a>(
        &self,
        p1: u8,
        p2: u8,
        data: &'a [u8],
        le: Option<u32>,
    ) -> Result<CommandApdu<'a>, SpecError> {
        let command = CommandApdu {
            cla: self.cla,
            ins: self.ins,
            p1,
            p2,
            data,
            le,
            extended: false,
        };
        self.validate(&command)?;
        Ok(command)
    }
    /// Response lengths describe success; applet status/authentication semantics remain local.
    pub fn validate_response(&self, response: &ResponseApdu<'_>) -> Result<(), SpecError> {
        if response.status == 0x9000 && !self.response.accepts(response.data.len()) {
            Err(SpecError::Response)
        } else {
            Ok(())
        }
    }
}
/// Resolve within the selected applet's command set, never by a global INS table.
pub fn find<'a>(
    specs: &'a [ApduSpec],
    command: &CommandApdu<'_>,
) -> Result<&'a ApduSpec, SpecError> {
    let mut class = false;
    let mut instruction = false;
    let mut data_error = None;
    for spec in specs {
        if spec.cla != command.cla {
            continue;
        }
        class = true;
        if spec.ins != command.ins {
            continue;
        }
        instruction = true;
        match spec.validate(command) {
            Ok(()) => return Ok(spec),
            Err(SpecError::Data(status)) => data_error = Some(status),
            _ => {}
        }
    }
    Err(if !class {
        SpecError::Class
    } else if !instruction {
        SpecError::Instruction
    } else if let Some(status) = data_error {
        SpecError::Data(status)
    } else {
        SpecError::Parameters
    })
}
