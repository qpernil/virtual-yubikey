//! Shared physical-presence service for every virtual YubiKey applet.

#[cfg(target_os = "linux")]
use crate::diagnostics::{self, Level};
#[cfg(target_os = "linux")]
use crate::display;
use std::fs;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixDatagram;
use std::path::{Path, PathBuf};
#[cfg(target_os = "linux")]
use std::sync::{Arc, Mutex, TryLockError};
#[cfg(target_os = "linux")]
use std::thread;
#[cfg(target_os = "linux")]
use std::time::Duration;

#[cfg(target_os = "linux")]
const POLL_INTERVAL: Duration = Duration::from_millis(5);
pub(crate) const USER_PRESENCE_TOUCH: u8 = b'T';

#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum UserPresenceCommand {
    Touch,
}

#[cfg(target_os = "linux")]
impl UserPresenceCommand {
    fn decode(value: u8) -> Option<Self> {
        match value {
            USER_PRESENCE_TOUCH => Some(Self::Touch),
            // Additional command bytes can represent simulated biometric
            // results without changing the IPC transport.
            _ => None,
        }
    }
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum WaitControl {
    Continue,
    Cancel,
}

#[cfg(target_os = "linux")]
#[derive(Clone)]
pub(crate) struct Service {
    inner: Arc<Inner>,
}

#[cfg(target_os = "linux")]
struct Inner {
    touch_socket: PathBuf,
    display_activity: display::Activity,
    sensor: Mutex<()>,
}

#[cfg(target_os = "linux")]
impl Service {
    pub(crate) fn new(touch_socket: PathBuf, display_activity: display::Activity) -> Self {
        Self {
            inner: Arc::new(Inner {
                touch_socket,
                display_activity,
                sensor: Mutex::new(()),
            }),
        }
    }

    pub(crate) fn wait(
        &self,
        mut poll: impl FnMut() -> io::Result<WaitControl>,
    ) -> io::Result<bool> {
        let _sensor = loop {
            match self.inner.sensor.try_lock() {
                Ok(sensor) => break sensor,
                Err(TryLockError::WouldBlock) => {
                    if poll()? == WaitControl::Cancel {
                        return Ok(false);
                    }
                    thread::sleep(POLL_INTERVAL);
                }
                Err(TryLockError::Poisoned(_)) => {
                    return Err(io::Error::other("presence sensor lock poisoned"));
                }
            }
        };

        let touch = TouchSocket::bind(&self.inner.touch_socket)?;
        diagnostics::log(
            Level::Info,
            "presence",
            "wait",
            format_args!("socket={}", self.inner.touch_socket.display()),
        );
        let _attention = self.inner.display_activity.wait_for_presence()?;
        let mut signal = [0_u8; 1];

        loop {
            match touch.socket.recv(&mut signal) {
                Ok(1)
                    if UserPresenceCommand::decode(signal[0])
                        == Some(UserPresenceCommand::Touch) =>
                {
                    diagnostics::log(Level::Info, "presence", "received", format_args!("touch"));
                    return Ok(true);
                }
                Ok(_) => {}
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => return Err(with_context(error, "receive touch notification")),
            }

            if poll()? == WaitControl::Cancel {
                diagnostics::log(
                    Level::Info,
                    "presence",
                    "cancelled",
                    format_args!("cancelled"),
                );
                return Ok(false);
            }
            thread::sleep(POLL_INTERVAL);
        }
    }
}

struct TouchSocket {
    socket: UnixDatagram,
    path: PathBuf,
}

impl TouchSocket {
    fn bind(path: &Path) -> io::Result<Self> {
        match fs::remove_file(path) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(with_context(error, "remove stale touch socket")),
        }
        let socket =
            UnixDatagram::bind(path).map_err(|error| with_context(error, "bind touch socket"))?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
        socket.set_nonblocking(true)?;
        Ok(Self {
            socket,
            path: path.to_owned(),
        })
    }
}

impl Drop for TouchSocket {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

fn with_context(error: io::Error, context: &str) -> io::Error {
    io::Error::new(error.kind(), format!("{context}: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn touch_never_lingers_into_a_later_wait() {
        let temporary = if cfg!(target_os = "macos") {
            PathBuf::from("/private/tmp")
        } else {
            std::env::temp_dir()
        };
        let path = temporary.join(format!("virtual-yubikey-touch-test-{}", std::process::id()));
        let _ = fs::remove_file(&path);
        let notifier = UnixDatagram::unbound().unwrap();

        assert!(notifier.send_to(&[USER_PRESENCE_TOUCH], &path).is_err());
        let current = TouchSocket::bind(&path).unwrap();
        assert_eq!(
            current.socket.recv(&mut [0_u8; 1]).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );

        assert_eq!(notifier.send_to(&[USER_PRESENCE_TOUCH], &path).unwrap(), 1);
        let mut command = [0_u8; 1];
        assert_eq!(current.socket.recv(&mut command).unwrap(), 1);
        assert_eq!(command[0], USER_PRESENCE_TOUCH);

        drop(current);
        assert!(notifier.send_to(&[USER_PRESENCE_TOUCH], &path).is_err());
        let later = TouchSocket::bind(&path).unwrap();
        assert_eq!(
            later.socket.recv(&mut command).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
    }
}
