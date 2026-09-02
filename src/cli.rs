use std::{io, time::Duration};
use usb_gadget_worker::PersistenceMode;

use crate::diagnostics::Level;
pub(crate) const DEFAULT_SERIAL: u32 = 12_345_678;

#[derive(Debug, PartialEq)]
pub(crate) struct Options {
    pub(crate) serial: u32,
    pub(crate) log_level: Level,
    pub(crate) display: DisplayKind,
    pub(crate) persistence: PersistenceMode,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DisplayKind {
    St7789Spi,
    Sh1106Spi,
    Sh1106I2c,
}

impl DisplayKind {
    #[cfg(target_os = "linux")]
    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::St7789Spi => "st7789-spi",
            Self::Sh1106Spi => "sh1106-spi",
            Self::Sh1106I2c => "sh1106-i2c",
        }
    }

    fn parse(value: &str) -> io::Result<Self> {
        match value {
            "st7789-spi" => Ok(Self::St7789Spi),
            "sh1106-spi" => Ok(Self::Sh1106Spi),
            "sh1106-i2c" => Ok(Self::Sh1106I2c),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid display {value:?}; use st7789-spi, sh1106-spi, or sh1106-i2c"),
            )),
        }
    }
}

pub(crate) fn parse<I>(arguments: I) -> io::Result<Options>
where
    I: IntoIterator<Item = String>,
{
    let mut serial = DEFAULT_SERIAL;
    let mut log_level = Level::Info;
    let mut display = DisplayKind::St7789Spi;
    let mut persistence = PersistenceMode::Batched(Duration::from_millis(500));
    let mut arguments = arguments.into_iter();

    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "--serial" => {
                let value = arguments.next().ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidInput, "--serial needs a value")
                })?;
                serial = value.parse().map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("invalid decimal serial number: {value}"),
                    )
                })?;
            }
            "--log-level" => {
                let value = arguments.next().ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidInput, "--log-level needs a value")
                })?;
                log_level = Level::parse(&value).ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("invalid log level {value:?}; use off, info, debug, or trace"),
                    )
                })?;
            }
            "--display" => {
                let value = arguments.next().ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidInput, "--display needs a value")
                })?;
                display = DisplayKind::parse(&value)?;
            }
            "--help" | "-h" => {
                println!(
                    "Usage: virtual-yubikey-worker [--serial DECIMAL] [--log-level LEVEL] [--display BACKEND] [--persistence MODE]\n\
                     \n\
                     This unprivileged binary is started by usb-gadget-supervisor. Its\n\
                     control socket is fixed at FD 3 and resource descriptors arrive through\n\
                     the versioned supervisor protocol. It refuses to run as root.\n\
                     BACKEND is st7789-spi (default), sh1106-spi, or sh1106-i2c.\n\
                     MODE is batched (default, 500 ms) or immediate.\n\
                     LEVEL is off, info (default), debug, or trace. Trace includes payloads\n\
                     and may expose secrets once stateful commands are implemented."
                );
                std::process::exit(0);
            }
            value if value.starts_with("--display=") => {
                display = DisplayKind::parse(&value["--display=".len()..])?;
            }
            "--persistence" => {
                let value = arguments.next().ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidInput, "--persistence needs a value")
                })?;
                persistence = parse_persistence(&value)?;
            }
            value if value.starts_with("--persistence=") => {
                persistence = parse_persistence(&value["--persistence=".len()..])?;
            }
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("unknown argument: {argument}"),
                ));
            }
        }
    }

    Ok(Options {
        serial,
        log_level,
        display,
        persistence,
    })
}

fn parse_persistence(value: &str) -> io::Result<PersistenceMode> {
    match value {
        "batched" => Ok(PersistenceMode::Batched(Duration::from_millis(500))),
        "immediate" => Ok(PersistenceMode::Immediate),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid persistence mode {value:?}; use batched or immediate"),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_to_the_virtual_yubikey_serial() {
        assert_eq!(parse(Vec::<String>::new()).unwrap().serial, DEFAULT_SERIAL);
    }

    #[test]
    fn parses_worker_options() {
        let options = parse(["--serial".to_owned(), "24681357".to_owned()]).unwrap();
        assert_eq!(
            options,
            Options {
                serial: 24_681_357,
                log_level: Level::Info,
                display: DisplayKind::St7789Spi,
                persistence: PersistenceMode::Batched(Duration::from_millis(500)),
            }
        );
    }

    #[test]
    fn parses_debug_log_level() {
        let options = parse(["--log-level".to_owned(), "debug".to_owned()]).unwrap();
        assert_eq!(options.log_level, Level::Debug);
    }

    #[test]
    fn parses_oled_display() {
        let options = parse(["--display=sh1106-spi".to_owned()]).unwrap();
        assert_eq!(options.display, DisplayKind::Sh1106Spi);

        let options = parse(["--display=sh1106-i2c".to_owned()]).unwrap();
        assert_eq!(options.display, DisplayKind::Sh1106I2c);
    }

    #[test]
    fn parses_immediate_persistence() {
        let options = parse(["--persistence=immediate".to_owned()]).unwrap();
        assert_eq!(options.persistence, PersistenceMode::Immediate);
    }
}
