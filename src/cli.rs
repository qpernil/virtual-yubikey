use std::io;

use crate::diagnostics::Level;
pub(crate) const DEFAULT_SERIAL: u32 = 12_345_678;

#[derive(Debug, PartialEq)]
pub(crate) struct Options {
    pub(crate) serial: u32,
    pub(crate) udc: Option<String>,
    pub(crate) run_as: Option<String>,
    pub(crate) worker_fd: Option<i32>,
    pub(crate) hid_fd: Option<i32>,
    pub(crate) log_level: Level,
}

pub(crate) fn parse<I>(arguments: I) -> io::Result<Options>
where
    I: IntoIterator<Item = String>,
{
    let mut serial = DEFAULT_SERIAL;
    let mut udc = None;
    let mut run_as = None;
    let mut worker_fd = None;
    let mut hid_fd = None;
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
            "--udc" => {
                let value = arguments.next().ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidInput, "--udc needs a value")
                })?;
                if value.is_empty()
                    || !value
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || b"_.:-".contains(&byte))
                {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("invalid UDC name: {value}"),
                    ));
                }
                udc = Some(value);
            }
            "--run-as" => {
                let value = arguments.next().ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidInput, "--run-as needs a user name")
                })?;
                if value.is_empty()
                    || !value
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || b"_.-".contains(&byte))
                {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("invalid worker user name: {value}"),
                    ));
                }
                run_as = Some(value);
            }
            "--worker-fd" => {
                let value = arguments.next().ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidInput, "--worker-fd needs a number")
                })?;
                let descriptor = value.parse::<i32>().map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("invalid worker readiness descriptor: {value}"),
                    )
                })?;
                if descriptor < 3 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "worker readiness descriptor must be at least 3",
                    ));
                }
                worker_fd = Some(descriptor);
            }
            "--hid-fd" => {
                let value = arguments.next().ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidInput, "--hid-fd needs a number")
                })?;
                let descriptor = value.parse::<i32>().map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("invalid HID descriptor: {value}"),
                    )
                })?;
                if descriptor < 3 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "HID descriptor must be at least 3",
                    ));
                }
                hid_fd = Some(descriptor);
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
                    "Usage: virtual-yubikey [--serial DECIMAL] [--udc NAME] [--run-as USER] [--log-level LEVEL]\n\
                     \n\
                     Run through sudo on Linux; the supervisor stays root while a fresh\n\
                     worker process opens FunctionFS and handles USB as USER. USER defaults\n\
                     to SUDO_USER when sudo supplied a non-root account.\n\
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

    if worker_fd.is_some() && (udc.is_some() || run_as.is_some()) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "--worker-fd cannot be combined with public runtime options",
        ));
    }
    if worker_fd.is_some() != hid_fd.is_some() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "--worker-fd and --hid-fd must be supplied together",
        ));
    }
    Ok(Options {
        serial,
        udc,
        run_as,
        worker_fd,
        hid_fd,
        log_level,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_to_the_virtual_yubikey_serial() {
        assert_eq!(parse(Vec::<String>::new()).unwrap().serial, DEFAULT_SERIAL);
    }

    #[test]
    fn parses_runtime_options() {
        let options = parse([
            "--serial".to_owned(),
            "24681357".to_owned(),
            "--udc".to_owned(),
            "fe980000.usb".to_owned(),
            "--run-as".to_owned(),
            "per".to_owned(),
        ])
        .unwrap();
        assert_eq!(
            options,
            Options {
                serial: 24_681_357,
                udc: Some("fe980000.usb".to_owned()),
                run_as: Some("per".to_owned()),
                worker_fd: None,
                hid_fd: None,
                log_level: Level::Info,
            }
        );
    }

    #[test]
    fn rejects_path_as_udc_name() {
        let error = parse(["--udc".to_owned(), "../../bad".to_owned()]).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn rejects_path_as_worker_user() {
        let error = parse(["--run-as".to_owned(), "../../root".to_owned()]).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn parses_debug_log_level() {
        let options = parse(["--log-level".to_owned(), "debug".to_owned()]).unwrap();
        assert_eq!(options.log_level, Level::Debug);
    }
}
