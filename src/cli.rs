use std::io;

use crate::diagnostics::Level;
pub(crate) const DEFAULT_SERIAL: u32 = 12_345_678;

#[derive(Debug, PartialEq)]
pub(crate) struct Options {
    pub(crate) serial: u32,
    pub(crate) log_level: Level,
}

pub(crate) fn parse<I>(arguments: I) -> io::Result<Options>
where
    I: IntoIterator<Item = String>,
{
    let mut serial = DEFAULT_SERIAL;
    let mut log_level = Level::Info;
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
            "--help" | "-h" => {
                println!(
                    "Usage: virtual-yubikey-worker [--serial DECIMAL] [--log-level LEVEL]\n\
                     \n\
                     This unprivileged binary is started by usb-gadget-supervisor. Its\n\
                     control descriptor and USB resource paths are inherited through the\n\
                     versioned worker environment contract. It refuses to run as root.\n\
                     LEVEL is off, info (default), debug, or trace. Trace includes payloads\n\
                     and may expose secrets once stateful commands are implemented."
                );
                std::process::exit(0);
            }
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("unknown argument: {argument}"),
                ));
            }
        }
    }

    Ok(Options { serial, log_level })
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
            }
        );
    }

    #[test]
    fn parses_debug_log_level() {
        let options = parse(["--log-level".to_owned(), "debug".to_owned()]).unwrap();
        assert_eq!(options.log_level, Level::Debug);
    }
}
