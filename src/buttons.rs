//! Event-driven controls from the display HAT joystick and keys.

use crate::diagnostics::{self, Level};
use crate::functionfs::USER_PRESENCE_TOUCH;
use std::fs::File;
use std::io::{self, Read};
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixDatagram;
use std::path::PathBuf;
use std::thread::{self, JoinHandle};

const GPIO_V2_LINE_EVENT_SIZE: usize = 48;
const GPIO_V2_LINE_EVENT_ID_OFFSET: usize = 8;
const GPIO_V2_LINE_EVENT_RISING_EDGE: u32 = 1;
const GPIO_V2_LINE_EVENT_FALLING_EDGE: u32 = 2;

pub(crate) struct Controller {
    shutdown: UnixDatagram,
    reconnect: UnixDatagram,
    thread: JoinHandle<io::Result<()>>,
}

impl Controller {
    pub(crate) fn start(
        touch_lines: File,
        reconnect_lines: File,
        touch_socket: PathBuf,
    ) -> io::Result<Self> {
        set_nonblocking(&touch_lines)?;
        set_nonblocking(&reconnect_lines)?;
        let (shutdown, receiver) = UnixDatagram::pair()?;
        let (reconnect_sender, reconnect) = UnixDatagram::pair()?;
        reconnect.set_nonblocking(true)?;
        reconnect_sender.set_nonblocking(true)?;
        let thread = thread::Builder::new()
            .name("yubikey-buttons".to_owned())
            .spawn(move || {
                button_loop(
                    touch_lines,
                    reconnect_lines,
                    receiver,
                    reconnect_sender,
                    touch_socket,
                )
            })?;
        Ok(Self {
            shutdown,
            reconnect,
            thread,
        })
    }

    pub(crate) fn reconnect_descriptor(&self) -> i32 {
        self.reconnect.as_raw_fd()
    }

    pub(crate) fn take_reconnect_transition(&self) -> io::Result<Option<bool>> {
        let mut byte = [0_u8; 1];
        loop {
            match self.reconnect.recv(&mut byte) {
                Ok(1) if byte[0] <= 1 => return Ok(Some(byte[0] != 0)),
                Ok(length) => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("invalid reconnect transition packet: length={length}"),
                    ));
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(None),
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error),
            }
        }
    }

    pub(crate) fn shutdown(self) -> io::Result<()> {
        let _ = self.shutdown.send(&[0]);
        self.thread
            .join()
            .map_err(|_| io::Error::other("YubiKey touch-button thread panicked"))?
    }
}

fn button_loop(
    mut touch_lines: File,
    mut reconnect_lines: File,
    shutdown: UnixDatagram,
    reconnect: UnixDatagram,
    touch_socket: PathBuf,
) -> io::Result<()> {
    diagnostics::log(
        Level::Info,
        "button",
        "ready",
        format_args!("touch=joystick-center gpio=13 reconnect=key3 gpio=16"),
    );
    let notifier = UnixDatagram::unbound()?;
    let mut poll_fds = [
        libc::pollfd {
            fd: touch_lines.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        },
        libc::pollfd {
            fd: reconnect_lines.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        },
        libc::pollfd {
            fd: shutdown.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        },
    ];

    loop {
        // SAFETY: poll_fds names two valid descriptors for the duration of the call.
        let result = unsafe { libc::poll(poll_fds.as_mut_ptr(), poll_fds.len() as _, -1) };
        if result < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }
        if poll_fds[2].revents & libc::POLLIN != 0 {
            return Ok(());
        }
        if poll_fds[0].revents & libc::POLLIN != 0 {
            drain_touch_events(&mut touch_lines, &notifier, &touch_socket)?;
        }
        if poll_fds[1].revents & libc::POLLIN != 0 {
            drain_reconnect_events(&mut reconnect_lines, &reconnect)?;
        }
        for (name, descriptor) in [
            ("touch-button", poll_fds[0]),
            ("reconnect-button", poll_fds[1]),
        ] {
            let unexpected = descriptor.revents & !libc::POLLIN;
            if unexpected != 0 {
                return Err(io::Error::other(format!(
                    "{name} descriptor reported poll events 0x{unexpected:x}"
                )));
            }
        }
    }
}

fn drain_touch_events(
    lines: &mut File,
    notifier: &UnixDatagram,
    touch_socket: &PathBuf,
) -> io::Result<()> {
    loop {
        let mut event = [0_u8; GPIO_V2_LINE_EVENT_SIZE];
        match lines.read(&mut event) {
            Ok(GPIO_V2_LINE_EVENT_SIZE) => {
                let id = u32::from_ne_bytes(
                    event[GPIO_V2_LINE_EVENT_ID_OFFSET..GPIO_V2_LINE_EVENT_ID_OFFSET + 4]
                        .try_into()
                        .unwrap(),
                );
                if id == GPIO_V2_LINE_EVENT_RISING_EDGE {
                    signal_touch(notifier, touch_socket);
                }
            }
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "touch-button descriptor closed",
                ))
            }
            Ok(length) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("partial GPIO edge event: {length} bytes"),
                ))
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(()),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        }
    }
}

fn drain_reconnect_events(lines: &mut File, notifier: &UnixDatagram) -> io::Result<()> {
    loop {
        let mut event = [0_u8; GPIO_V2_LINE_EVENT_SIZE];
        match lines.read(&mut event) {
            Ok(GPIO_V2_LINE_EVENT_SIZE) => {
                let id = u32::from_ne_bytes(
                    event[GPIO_V2_LINE_EVENT_ID_OFFSET..GPIO_V2_LINE_EVENT_ID_OFFSET + 4]
                        .try_into()
                        .unwrap(),
                );
                let state = match id {
                    GPIO_V2_LINE_EVENT_RISING_EDGE => Some(1),
                    GPIO_V2_LINE_EVENT_FALLING_EDGE => Some(0),
                    _ => None,
                };
                if let Some(state) = state {
                    match notifier.send(&[state]) {
                        Ok(1) => diagnostics::log(
                            Level::Info,
                            "button",
                            "reconnect_state",
                            format_args!("input=key3 pressed={}", state != 0),
                        ),
                        Ok(length) => diagnostics::log(
                            Level::Info,
                            "button",
                            "failed",
                            format_args!("operation=send-reconnect-state bytes={length}"),
                        ),
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                        Err(error) => diagnostics::log(
                            Level::Info,
                            "button",
                            "failed",
                            format_args!("operation=send-reconnect-state error={error:?}"),
                        ),
                    }
                }
            }
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "button descriptor closed",
                ))
            }
            Ok(length) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("partial GPIO edge event: {length} bytes"),
                ))
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(()),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        }
    }
}

fn signal_touch(notifier: &UnixDatagram, touch_socket: &PathBuf) {
    match notifier.send_to(&[USER_PRESENCE_TOUCH], touch_socket) {
        Ok(1) => diagnostics::log(
            Level::Info,
            "button",
            "touch",
            format_args!("input=joystick-center accepted=true"),
        ),
        Ok(length) => diagnostics::log(
            Level::Info,
            "button",
            "failed",
            format_args!("operation=send-touch bytes={length}"),
        ),
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused
            ) => {}
        Err(error) => diagnostics::log(
            Level::Info,
            "button",
            "failed",
            format_args!("operation=send-touch error={error:?}"),
        ),
    }
}

fn set_nonblocking(file: &File) -> io::Result<()> {
    // SAFETY: fcntl operates on a valid inherited descriptor and does not retain pointers.
    let flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFL) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the descriptor remains valid and F_SETFL accepts the retrieved flags.
    if unsafe { libc::fcntl(file.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn touch_never_lingers_into_a_later_wait() {
        let path =
            std::env::temp_dir().join(format!("virtual-yubikey-touch-test-{}", std::process::id()));
        let _ = fs::remove_file(&path);
        let notifier = UnixDatagram::unbound().unwrap();

        signal_touch(&notifier, &path);
        let current = UnixDatagram::bind(&path).unwrap();
        current.set_nonblocking(true).unwrap();
        assert_eq!(
            current.recv(&mut [0_u8; 1]).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );

        signal_touch(&notifier, &path);
        let mut command = [0_u8; 1];
        assert_eq!(current.recv(&mut command).unwrap(), 1);
        assert_eq!(command[0], USER_PRESENCE_TOUCH);

        drop(current);
        fs::remove_file(&path).unwrap();
        signal_touch(&notifier, &path);
        let later = UnixDatagram::bind(&path).unwrap();
        later.set_nonblocking(true).unwrap();
        assert_eq!(
            later.recv(&mut command).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        drop(later);
        fs::remove_file(path).unwrap();
    }
}
