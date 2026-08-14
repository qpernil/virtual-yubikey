//! Small dependency-free diagnostic logger.

#[cfg(any(target_os = "linux", test))]
use std::fmt;
use std::sync::atomic::{AtomicU8, Ordering};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
#[repr(u8)]
pub(crate) enum Level {
    Off = 0,
    Info = 1,
    Debug = 2,
    Trace = 3,
}

impl Level {
    pub(crate) fn parse(value: &str) -> Option<Self> {
        match value {
            "off" => Some(Self::Off),
            "info" => Some(Self::Info),
            "debug" => Some(Self::Debug),
            "trace" => Some(Self::Trace),
            _ => None,
        }
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Info => "info",
            Self::Debug => "debug",
            Self::Trace => "trace",
        }
    }
}

static LEVEL: AtomicU8 = AtomicU8::new(Level::Info as u8);

pub(crate) fn set_level(level: Level) {
    LEVEL.store(level as u8, Ordering::Relaxed);
}

#[cfg(any(target_os = "linux", test))]
pub(crate) fn enabled(level: Level) -> bool {
    LEVEL.load(Ordering::Relaxed) >= level as u8
}

#[cfg(any(target_os = "linux", test))]
pub(crate) fn log(level: Level, component: &str, event: &str, details: fmt::Arguments<'_>) {
    if !enabled(level) {
        return;
    }
    let level = match level {
        Level::Off => return,
        Level::Info => "info",
        Level::Debug => "debug",
        Level::Trace => "trace",
    };
    if details.as_str() == Some("") {
        eprintln!("virtual-yubikey level={level} component={component} event={event}");
    } else {
        eprintln!("virtual-yubikey level={level} component={component} event={event} {details}");
    }
}

#[cfg(any(target_os = "linux", test))]
pub(crate) fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(output, "{byte:02x}").expect("writing to String cannot fail");
    }
    output
}
