//! Physical ST7789 status display for the virtual YubiKey worker.

const FRAME_SIZE: usize = 240 * 240 * 2;
const IDLE_FRAME: &[u8; FRAME_SIZE] = include_bytes!("../assets/yubikey-idle.rgb565");
const ACTIVE_FRAME: &[u8; FRAME_SIZE] = include_bytes!("../assets/yubikey-active.rgb565");

#[cfg(target_os = "linux")]
use crate::diagnostics::{self, Level};
#[cfg(target_os = "linux")]
use display_backends::{Backend, Display};
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
const PRESENCE_BLINK_HALF_PERIOD: Duration = Duration::from_millis(384);
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

    pub(crate) fn wait_for_presence(&self) -> io::Result<PresenceWait> {
        self.sender
            .send(Command::PresenceWaitStarted)
            .map_err(|_| display_stopped())?;
        Ok(PresenceWait {
            sender: self.sender.clone(),
        })
    }
}

#[cfg(target_os = "linux")]
pub(crate) struct PresenceWait {
    sender: Sender<Command>,
}

#[cfg(target_os = "linux")]
impl Drop for PresenceWait {
    fn drop(&mut self) {
        let _ = self.sender.send(Command::PresenceWaitEnded);
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

    pub(crate) fn bind(&self) -> io::Result<()> {
        send_command(&self.sender, Command::Bind)
    }

    pub(crate) fn unbind(&self) -> io::Result<()> {
        send_command(&self.sender, Command::Unbind)
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
    PresenceWaitStarted,
    PresenceWaitEnded,
    Bind,
    Unbind,
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
    let mut bound = false;
    let mut suspended = false;
    let mut lit = false;
    let mut presence_waiters = 0_u32;
    let mut idle_at: Option<Instant> = None;

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
                if bound && !suspended && presence_waiters != 0 {
                    lit = !lit;
                    hardware.render(lit);
                    idle_at = Some(Instant::now() + PRESENCE_BLINK_HALF_PERIOD);
                } else {
                    if bound && !suspended && lit {
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
                if !bound || suspended || presence_waiters != 0 {
                    continue;
                }
                lit = !lit;
                hardware.render(lit);
                idle_at = Some(Instant::now() + ACTIVITY_HOLD);
            }
            Command::PresenceWaitStarted => {
                presence_waiters = presence_waiters.saturating_add(1);
                if presence_waiters == 1 && bound && !suspended {
                    lit = true;
                    hardware.render(true);
                    idle_at = Some(Instant::now() + PRESENCE_BLINK_HALF_PERIOD);
                }
            }
            Command::PresenceWaitEnded => {
                presence_waiters = presence_waiters.saturating_sub(1);
                if presence_waiters == 0 {
                    idle_at = None;
                    if bound && !suspended && lit {
                        lit = false;
                        hardware.render(false);
                    }
                }
            }
            Command::Bind => {
                bound = true;
                suspended = false;
                lit = presence_waiters != 0;
                hardware.render(lit);
                idle_at =
                    (presence_waiters != 0).then(|| Instant::now() + PRESENCE_BLINK_HALF_PERIOD);
            }
            Command::Unbind => {
                bound = false;
                suspended = false;
                lit = false;
                idle_at = None;
                hardware.turn_off("USB unbind");
            }
            Command::Suspend => {
                suspended = true;
                lit = false;
                idle_at = None;
                if bound {
                    hardware.turn_off("USB suspend");
                }
            }
            Command::Resume => {
                if bound && suspended {
                    suspended = false;
                    lit = presence_waiters != 0;
                    hardware.render(lit);
                    idle_at = (presence_waiters != 0)
                        .then(|| Instant::now() + PRESENCE_BLINK_HALF_PERIOD);
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
