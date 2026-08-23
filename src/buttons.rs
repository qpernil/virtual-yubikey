//! Event-driven physical-presence input from the display HAT joystick center.

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

pub(crate) struct Controller {
    shutdown: UnixDatagram,
    thread: JoinHandle<io::Result<()>>,
}

impl Controller {
    pub(crate) fn start(lines: File, touch_socket: PathBuf) -> io::Result<Self> {
        set_nonblocking(&lines)?;
        let (shutdown, receiver) = UnixDatagram::pair()?;
        let thread = thread::Builder::new()
            .name("yubikey-touch-button".to_owned())
            .spawn(move || button_loop(lines, receiver, touch_socket))?;
        Ok(Self { shutdown, thread })
    }

    pub(crate) fn shutdown(self) -> io::Result<()> {
        let _ = self.shutdown.send(&[0]);
        self.thread
            .join()
            .map_err(|_| io::Error::other("YubiKey touch-button thread panicked"))?
    }
}

fn button_loop(mut lines: File, shutdown: UnixDatagram, touch_socket: PathBuf) -> io::Result<()> {
    diagnostics::log(
        Level::Info,
        "button",
        "ready",
        format_args!("input=joystick-center gpio=13"),
    );
    let notifier = UnixDatagram::unbound()?;
    let mut poll_fds = [
        libc::pollfd {
            fd: lines.as_raw_fd(),
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
        if poll_fds[1].revents & libc::POLLIN != 0 {
            return Ok(());
        }
        if poll_fds[0].revents & libc::POLLIN != 0 {
            drain_button_events(&mut lines, &notifier, &touch_socket)?;
        }
        let unexpected = poll_fds[0].revents & !(libc::POLLIN);
        if unexpected != 0 {
            return Err(io::Error::other(format!(
                "touch-button descriptor reported poll events 0x{unexpected:x}"
            )));
        }
    }
}

fn drain_button_events(
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
