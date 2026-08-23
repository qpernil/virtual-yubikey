//! Physical ST7789 status display for the virtual YubiKey worker.

const FRAME_SIZE: usize = 240 * 240 * 2;
const IDLE_FRAME: &[u8; FRAME_SIZE] = include_bytes!("../assets/yubikey-idle.rgb565");
const ACTIVE_FRAME: &[u8; FRAME_SIZE] = include_bytes!("../assets/yubikey-active.rgb565");

#[cfg(target_os = "linux")]
use crate::diagnostics::{self, Level};
#[cfg(target_os = "linux")]
use display_backends::{Backend, Display};
#[cfg(target_os = "linux")]
use std::collections::BTreeMap;
#[cfg(target_os = "linux")]
use std::fs::File;
#[cfg(target_os = "linux")]
use std::io;
#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd;
#[cfg(target_os = "linux")]
use std::sync::atomic::{AtomicBool, Ordering};
#[cfg(target_os = "linux")]
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
#[cfg(target_os = "linux")]
use std::sync::Arc;
#[cfg(target_os = "linux")]
use std::thread::{self, JoinHandle};
#[cfg(target_os = "linux")]
use std::time::{Duration, Instant};

#[cfg(target_os = "linux")]
const ACTIVITY_HOLD: Duration = Duration::from_millis(90);
#[cfg(target_os = "linux")]
#[derive(Clone)]
pub(crate) struct Activity {
    sender: Sender<Command>,
    activity_pending: Arc<AtomicBool>,
}

#[cfg(target_os = "linux")]
impl Activity {
    pub(crate) fn pulse(&self) {
        if self.activity_pending.swap(true, Ordering::AcqRel) {
            return;
        }
        if self.sender.send(Command::Activity).is_err() {
            self.activity_pending.store(false, Ordering::Release);
        }
    }

    pub(crate) fn wait_for_presence(&self, half_period: Duration) -> io::Result<PresenceWait> {
        if half_period.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "presence blink half-period must be nonzero",
            ));
        }
        self.sender
            .send(Command::PresenceWaitStarted(half_period))
            .map_err(|_| display_stopped())?;
        Ok(PresenceWait {
            sender: self.sender.clone(),
            half_period,
        })
    }
}

#[cfg(target_os = "linux")]
pub(crate) struct PresenceWait {
    sender: Sender<Command>,
    half_period: Duration,
}

#[cfg(target_os = "linux")]
impl Drop for PresenceWait {
    fn drop(&mut self) {
        let _ = self
            .sender
            .send(Command::PresenceWaitEnded(self.half_period));
    }
}

#[cfg(target_os = "linux")]
pub(crate) struct Controller {
    sender: Sender<Command>,
    activity_pending: Arc<AtomicBool>,
    thread: JoinHandle<()>,
}

#[cfg(target_os = "linux")]
impl Controller {
    pub(crate) fn start(bus: File, control: File) -> io::Result<Self> {
        let (sender, receiver) = mpsc::channel();
        let activity_pending = Arc::new(AtomicBool::new(false));
        let display_activity_pending = activity_pending.clone();
        let thread = thread::Builder::new()
            .name("yubikey-display".to_owned())
            .spawn(move || display_loop(bus, control, receiver, display_activity_pending))?;
        Ok(Self {
            sender,
            activity_pending,
            thread,
        })
    }

    pub(crate) fn activity(&self) -> Activity {
        Activity {
            sender: self.sender.clone(),
            activity_pending: self.activity_pending.clone(),
        }
    }

    pub(crate) fn suspend(&self) -> io::Result<()> {
        send_command(&self.sender, Command::Suspend)
    }

    pub(crate) fn resume(&self) -> io::Result<()> {
        send_command(&self.sender, Command::Resume)
    }

    pub(crate) fn shutdown(self) -> io::Result<()> {
        let _ = self.sender.send(Command::Shutdown);
        self.thread
            .join()
            .map_err(|_| io::Error::other("YubiKey display thread panicked"))
    }
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy)]
enum Command {
    Activity,
    PresenceWaitStarted(Duration),
    PresenceWaitEnded(Duration),
    Suspend,
    Resume,
    Shutdown,
}

#[cfg(target_os = "linux")]
fn send_command(sender: &Sender<Command>, command: Command) -> io::Result<()> {
    sender.send(command).map_err(|_| display_stopped())
}

#[cfg(target_os = "linux")]
fn display_stopped() -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, "YubiKey display thread stopped")
}

#[cfg(target_os = "linux")]
fn display_loop(
    bus: File,
    control: File,
    receiver: Receiver<Command>,
    activity_pending: Arc<AtomicBool>,
) {
    let mut hardware = Hardware::new(bus, control);
    let mut suspended = false;
    let mut lit = false;
    let mut presence_waiters = BTreeMap::<Duration, u32>::new();
    let mut idle_at: Option<Instant> = None;
    hardware.render(false);

    loop {
        let received = match idle_at {
            Some(deadline) => receiver
                .recv_timeout(deadline.saturating_duration_since(Instant::now()))
                .map(Some),
            None => receiver
                .recv()
                .map(Some)
                .map_err(|_| RecvTimeoutError::Disconnected),
        };
        let command = match received {
            Ok(Some(command)) => command,
            Ok(None) => unreachable!(),
            Err(RecvTimeoutError::Timeout) => {
                if !suspended && !presence_waiters.is_empty() {
                    lit = !lit;
                    hardware.render(lit);
                    idle_at = presence_deadline(&presence_waiters);
                } else {
                    if !suspended && lit {
                        lit = false;
                        hardware.render(false);
                    }
                    idle_at = None;
                }
                continue;
            }
            Err(RecvTimeoutError::Disconnected) => Command::Shutdown,
        };
        match command {
            Command::Activity => {
                activity_pending.store(false, Ordering::Release);
                if suspended || !presence_waiters.is_empty() {
                    continue;
                }
                lit = !lit;
                hardware.render(lit);
                idle_at = Some(Instant::now() + ACTIVITY_HOLD);
            }
            Command::PresenceWaitStarted(half_period) => {
                let first = presence_waiters.is_empty();
                let count = presence_waiters.entry(half_period).or_default();
                *count = count.saturating_add(1);
                if !suspended {
                    if first {
                        lit = true;
                        hardware.render(true);
                    }
                    idle_at = presence_deadline(&presence_waiters);
                }
            }
            Command::PresenceWaitEnded(half_period) => {
                if let Some(count) = presence_waiters.get_mut(&half_period) {
                    *count = count.saturating_sub(1);
                    if *count == 0 {
                        presence_waiters.remove(&half_period);
                    }
                }
                if presence_waiters.is_empty() {
                    idle_at = None;
                    if !suspended && lit {
                        lit = false;
                        hardware.render(false);
                    }
                } else if !suspended {
                    idle_at = presence_deadline(&presence_waiters);
                }
            }
            Command::Suspend => {
                suspended = true;
                lit = false;
                idle_at = None;
                hardware.turn_off("USB suspend");
            }
            Command::Resume => {
                if suspended {
                    suspended = false;
                    lit = !presence_waiters.is_empty();
                    hardware.render(lit);
                    idle_at = presence_deadline(&presence_waiters);
                }
            }
            Command::Shutdown => {
                hardware.turn_off("worker shutdown");
                break;
            }
        }
    }
}

#[cfg(target_os = "linux")]
fn presence_deadline(waiters: &BTreeMap<Duration, u32>) -> Option<Instant> {
    waiters.keys().next().map(|period| Instant::now() + *period)
}

#[cfg(target_os = "linux")]
struct Hardware {
    bus: File,
    control: File,
    display: Option<Display>,
    error_reported: bool,
}

#[cfg(target_os = "linux")]
impl Hardware {
    fn new(bus: File, control: File) -> Self {
        Self {
            bus,
            control,
            display: None,
            error_reported: false,
        }
    }

    fn render(&mut self, active: bool) {
        let recovered = self.error_reported;
        if self.display.is_none() {
            match Display::from_raw_fds(
                Backend::St7789Spi,
                self.bus.as_raw_fd(),
                Some(self.control.as_raw_fd()),
            ) {
                Ok(display) => {
                    self.display = Some(display);
                    diagnostics::log(
                        Level::Info,
                        "display",
                        if recovered { "recovered" } else { "ready" },
                        format_args!("backend=st7789-spi"),
                    );
                    self.error_reported = false;
                }
                Err(error) => {
                    self.report_error("initialization", &error);
                    return;
                }
            }
        }
        let frame = if active { ACTIVE_FRAME } else { IDLE_FRAME };
        if let Err(error) = self.display.as_mut().unwrap().write_native_frame(frame) {
            self.report_error("frame_write", &error);
        }
    }

    fn turn_off(&mut self, reason: &str) {
        let Some(mut display) = self.display.take() else {
            return;
        };
        match display.shutdown() {
            Ok(()) => diagnostics::log(
                Level::Info,
                "display",
                "off",
                format_args!("backend=st7789-spi reason={reason:?}"),
            ),
            Err(error) => self.report_error("shutdown", &error),
        }
    }

    fn report_error(&mut self, operation: &str, error: &io::Error) {
        if !self.error_reported {
            diagnostics::log(
                Level::Info,
                "display",
                "failed",
                format_args!("backend=st7789-spi operation={operation} error={error:?}"),
            );
        }
        self.error_reported = true;
        self.display = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_frames_are_native_st7789_images() {
        assert_eq!(IDLE_FRAME.len(), FRAME_SIZE);
        assert_eq!(ACTIVE_FRAME.len(), FRAME_SIZE);
        assert_ne!(IDLE_FRAME, ACTIVE_FRAME);
        let mut changed = 0;
        for (index, (idle, active)) in IDLE_FRAME
            .chunks_exact(2)
            .zip(ACTIVE_FRAME.chunks_exact(2))
            .enumerate()
        {
            if idle == active {
                continue;
            }
            changed += 1;
            let x = index % 240;
            let y = index / 240;
            assert!((109..=131).contains(&x));
            assert!((84..=121).contains(&y));
        }
        assert!((100..1_000).contains(&changed));
    }
}
