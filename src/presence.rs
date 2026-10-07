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
use std::time::{Duration, Instant};

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
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum WaitOutcome {
    Granted,
    Cancelled,
    TimedOut,
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
    touch_pressed: Box<dyn Fn() -> io::Result<bool> + Send + Sync>,
}

#[cfg(target_os = "linux")]
impl Service {
    pub(crate) fn new(
        touch_socket: PathBuf,
        display_activity: display::Activity,
        touch_sensor: crate::buttons::TouchSensor,
    ) -> Self {
        Self::with_touch_reader(touch_socket, display_activity, move || {
            touch_sensor.is_pressed()
        })
    }

    fn with_touch_reader(
        touch_socket: PathBuf,
        display_activity: display::Activity,
        touch_pressed: impl Fn() -> io::Result<bool> + Send + Sync + 'static,
    ) -> Self {
        Self {
            inner: Arc::new(Inner {
                touch_socket,
                display_activity,
                sensor: Mutex::new(()),
                touch_pressed: Box::new(touch_pressed),
            }),
        }
    }

    /// Samples the physical button once; no touch event is cached between polls.
    pub(crate) fn poll_u2f_presence(&self) -> io::Result<bool> {
        let _sensor = match self.inner.sensor.try_lock() {
            Ok(sensor) => sensor,
            Err(TryLockError::WouldBlock) => return Ok(false),
            Err(TryLockError::Poisoned(_)) => {
                return Err(io::Error::other("presence sensor lock poisoned"));
            }
        };
        let pressed = (self.inner.touch_pressed)()?;
        if !pressed {
            self.inner.display_activity.poll_u2f_presence()?;
        }
        Ok(pressed)
    }

    pub(crate) fn complete_u2f_presence(&self) -> io::Result<()> {
        self.inner.display_activity.finish_u2f_presence()
    }

    pub(crate) fn wait_for(
        &self,
        timeout: Duration,
        poll: impl FnMut() -> io::Result<WaitControl>,
    ) -> io::Result<bool> {
        let deadline = Instant::now().checked_add(timeout).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "presence timeout overflow")
        })?;
        self.wait_until(Some(deadline), poll)
    }

    pub(crate) fn wait_for_outcome(
        &self,
        timeout: Duration,
        mut poll: impl FnMut() -> io::Result<WaitControl>,
    ) -> io::Result<WaitOutcome> {
        let mut cancelled = false;
        let granted = self.wait_for(timeout, || {
            let control = poll()?;
            cancelled |= control == WaitControl::Cancel;
            Ok(control)
        })?;
        Ok(if granted {
            WaitOutcome::Granted
        } else if cancelled {
            WaitOutcome::Cancelled
        } else {
            WaitOutcome::TimedOut
        })
    }

    fn wait_until(
        &self,
        deadline: Option<Instant>,
        mut poll: impl FnMut() -> io::Result<WaitControl>,
    ) -> io::Result<bool> {
        let started = Instant::now();
        let _sensor = loop {
            match self.inner.sensor.try_lock() {
                Ok(sensor) => break sensor,
                Err(TryLockError::WouldBlock) => {
                    if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
                        self.log_timeout(started);
                        return Ok(false);
                    }
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
            if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
                self.log_timeout(started);
                return Ok(false);
            }
            thread::sleep(POLL_INTERVAL);
        }
    }

    fn log_timeout(&self, started: Instant) {
        diagnostics::log(
            Level::Info,
            "presence",
            "timed_out",
            format_args!("elapsed_ms={}", started.elapsed().as_millis()),
        );
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

    #[cfg(target_os = "linux")]
    #[test]
    fn u2f_samples_once_per_poll_without_waiting_or_caching_touches() {
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
        let fixture = display::TestIndicator::new(|_| Ok(())).unwrap();
        let pressed = Arc::new(AtomicBool::new(false));
        let samples = Arc::new(AtomicUsize::new(0));
        let input = Arc::clone(&pressed);
        let count = Arc::clone(&samples);
        let service = Service::with_touch_reader(
            PathBuf::from("unused-u2f-touch.sock"),
            fixture.activity.clone(),
            move || {
                count.fetch_add(1, Ordering::Relaxed);
                Ok(input.load(Ordering::Acquire))
            },
        );
        let started = Instant::now();
        assert!(!service.poll_u2f_presence().unwrap());
        assert!(started.elapsed() < Duration::from_millis(100));
        pressed.store(true, Ordering::Release);
        assert!(service.poll_u2f_presence().unwrap());
        service.complete_u2f_presence().unwrap();
        pressed.store(false, Ordering::Release);
        assert!(!service.poll_u2f_presence().unwrap());
        // A complete press between calls must not authorize the next call.
        pressed.store(true, Ordering::Release);
        pressed.store(false, Ordering::Release);
        assert!(!service.poll_u2f_presence().unwrap());
        assert_eq!(samples.load(Ordering::Relaxed), 4);
        // A blocking applet owns the sensor; U2F returns immediately, without
        // stealing its input or starting a second touch wait.
        let _sensor = service.inner.sensor.lock().unwrap();
        let started = Instant::now();
        assert!(!service.poll_u2f_presence().unwrap());
        assert!(started.elapsed() < Duration::from_millis(100));
        assert_eq!(samples.load(Ordering::Relaxed), 4);
    }

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
