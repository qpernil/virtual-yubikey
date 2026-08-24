//! Physical status display for the virtual YubiKey worker.

const COLOR_FRAME_SIZE: usize = 240 * 240 * 2;
const OLED_FRAME_SIZE: usize = 128 * 64 / 8;
const IDLE_FRAME: &[u8; COLOR_FRAME_SIZE] = include_bytes!("../assets/yubikey-idle.rgb565");
const ACTIVE_FRAME: &[u8; COLOR_FRAME_SIZE] = include_bytes!("../assets/yubikey-active.rgb565");
const OLED_IDLE_FRAME: &[u8; OLED_FRAME_SIZE] = include_bytes!("../assets/yubikey-oled-idle.mono1");
const OLED_ACTIVE_FRAME: &[u8; OLED_FRAME_SIZE] =
    include_bytes!("../assets/yubikey-oled-active.mono1");

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
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
#[cfg(target_os = "linux")]
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
#[cfg(target_os = "linux")]
use std::sync::Arc;
#[cfg(target_os = "linux")]
use std::thread::{self, JoinHandle};
#[cfg(target_os = "linux")]
use std::time::{Duration, Instant};

#[cfg(target_os = "linux")]
const ACTIVITY_LED_ON_HOLD: Duration = Duration::from_millis(67);
#[cfg(target_os = "linux")]
const ACTIVITY_LED_OFF_HOLD: Duration = Duration::from_millis(33);
#[cfg(target_os = "linux")]
const ACTIVITY_LED_MIN_ON_HOLD: Duration = Duration::from_millis(8);
#[cfg(target_os = "linux")]
const ACTIVITY_LED_MIN_OFF_HOLD: Duration = Duration::from_millis(8);
#[cfg(target_os = "linux")]
const PRESENCE_BLINK_HALF_PERIOD: Duration = Duration::from_millis(384);
#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ActivityPhase {
    Idle,
    Active,
    Pending,
    Finalizing,
}

#[cfg(target_os = "linux")]
#[derive(Clone)]
pub(crate) struct Activity {
    state: Arc<ActivityState>,
}

#[cfg(target_os = "linux")]
struct ActivityState {
    sender: Sender<Command>,
    active_count: AtomicUsize,
    desired_lit: AtomicBool,
    activity_pending: AtomicBool,
    notification_pending: AtomicBool,
}

#[cfg(target_os = "linux")]
impl ActivityState {
    fn notify(&self) {
        if !self.notification_pending.swap(true, Ordering::AcqRel)
            && self.sender.send(Command::ActivityChanged).is_err()
        {
            self.notification_pending.store(false, Ordering::Release);
        }
    }
}

#[cfg(target_os = "linux")]
impl Activity {
    pub(crate) fn begin(&self) -> ActivityGuard {
        self.state.desired_lit.fetch_xor(true, Ordering::AcqRel);
        self.state.activity_pending.store(true, Ordering::Release);
        let _ =
            self.state
                .active_count
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                    Some(count.saturating_add(1))
                });
        self.state.notify();
        ActivityGuard {
            state: Arc::clone(&self.state),
        }
    }

    pub(crate) fn wait_for_presence(&self) -> io::Result<PresenceWait> {
        self.state
            .sender
            .send(Command::PresenceWaitStarted)
            .map_err(|_| display_stopped())?;
        Ok(PresenceWait {
            sender: self.state.sender.clone(),
        })
    }
}

#[cfg(target_os = "linux")]
pub(crate) struct ActivityGuard {
    state: Arc<ActivityState>,
}

#[cfg(target_os = "linux")]
impl Drop for ActivityGuard {
    fn drop(&mut self) {
        let previous = self
            .state
            .active_count
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                Some(count.saturating_sub(1))
            })
            .unwrap();
        if previous == 1 {
            self.state.notify();
        }
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
    activity_state: Arc<ActivityState>,
    thread: JoinHandle<()>,
}

#[cfg(target_os = "linux")]
impl Controller {
    pub(crate) fn start(
        bus: File,
        control: File,
        kind: crate::cli::DisplayKind,
    ) -> io::Result<Self> {
        let (sender, receiver) = mpsc::channel();
        let activity_state = Arc::new(ActivityState {
            sender: sender.clone(),
            active_count: AtomicUsize::new(0),
            desired_lit: AtomicBool::new(false),
            activity_pending: AtomicBool::new(false),
            notification_pending: AtomicBool::new(false),
        });
        let display_activity_state = Arc::clone(&activity_state);
        let thread = thread::Builder::new()
            .name("yubikey-display".to_owned())
            .spawn(move || display_loop(bus, control, kind, receiver, display_activity_state))?;
        Ok(Self {
            sender,
            activity_state,
            thread,
        })
    }

    pub(crate) fn activity(&self) -> Activity {
        Activity {
            state: Arc::clone(&self.activity_state),
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
    ActivityChanged,
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
    kind: crate::cli::DisplayKind,
    receiver: Receiver<Command>,
    activity_state: Arc<ActivityState>,
) {
    let mut hardware = Hardware::new(bus, control, kind);
    let mut bound = false;
    let mut suspended = false;
    let mut lit = false;
    let mut presence_waiters = 0_u32;
    let mut activity_count = 0_usize;
    let mut activity_phase = ActivityPhase::Idle;
    let mut visible_until = None;
    let mut busy_due = None;
    let mut transition_due: Option<Instant> = None;

    loop {
        let received = match transition_due {
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
                    toggle_led(&mut hardware, &mut lit);
                    activity_state.desired_lit.store(lit, Ordering::Release);
                    transition_due = Some(Instant::now() + PRESENCE_BLINK_HALF_PERIOD);
                } else if bound && !suspended {
                    match activity_phase {
                        ActivityPhase::Active => {
                            visible_until = Some(toggle_global_led_minimum(
                                &mut hardware,
                                &mut lit,
                                &activity_state.desired_lit,
                            ));
                            busy_due = Some(Instant::now() + activity_blink_delay(lit));
                            transition_due = busy_due;
                        }
                        ActivityPhase::Pending => {
                            let desired = activity_state.desired_lit.load(Ordering::Acquire);
                            if desired != lit {
                                lit = desired;
                                hardware.render(lit);
                                visible_until = Some(Instant::now() + minimum_led_hold(lit));
                            }
                            if activity_count != 0 {
                                activity_phase = ActivityPhase::Active;
                                busy_due = Some(Instant::now() + activity_blink_delay(lit));
                                transition_due = busy_due;
                            } else {
                                activity_phase = ActivityPhase::Finalizing;
                                let now = Instant::now();
                                transition_due = Some(visible_until.unwrap_or(now).max(now));
                            }
                        }
                        ActivityPhase::Finalizing => {
                            if activity_count != 0 {
                                activity_phase = ActivityPhase::Active;
                                transition_due = busy_due
                                    .or_else(|| Some(Instant::now() + activity_blink_delay(lit)));
                            } else if lit {
                                busy_due = None;
                                visible_until = Some(toggle_led_minimum(&mut hardware, &mut lit));
                                activity_state.desired_lit.store(false, Ordering::Release);
                                transition_due = visible_until;
                            } else {
                                busy_due = None;
                                activity_state.desired_lit.store(false, Ordering::Release);
                                visible_until = None;
                                activity_phase = ActivityPhase::Idle;
                                transition_due = None;
                            }
                        }
                        ActivityPhase::Idle => {
                            transition_due = None;
                        }
                    }
                } else {
                    transition_due = None;
                }
                continue;
            }
            Err(RecvTimeoutError::Disconnected) => Command::Shutdown,
        };
        match command {
            Command::ActivityChanged => {
                activity_state
                    .notification_pending
                    .store(false, Ordering::Release);
                let activity_happened = activity_state
                    .activity_pending
                    .swap(false, Ordering::AcqRel);
                let was_active = activity_count != 0;
                activity_count = activity_state.active_count.load(Ordering::Acquire);
                if !bound || suspended || presence_waiters != 0 {
                    activity_phase = ActivityPhase::Idle;
                    visible_until = None;
                    busy_due = None;
                    activity_state.desired_lit.store(
                        if presence_waiters != 0 { lit } else { false },
                        Ordering::Release,
                    );
                    continue;
                }

                let desired = activity_state.desired_lit.load(Ordering::Acquire);
                let now = Instant::now();
                let can_render = visible_until.is_none_or(|until| now >= until);
                if desired != lit && can_render {
                    lit = desired;
                    hardware.render(lit);
                    visible_until = Some(Instant::now() + minimum_led_hold(lit));
                    if activity_count != 0 {
                        busy_due = Some(Instant::now() + activity_blink_delay(lit));
                        activity_phase = ActivityPhase::Active;
                        transition_due = busy_due;
                    } else {
                        busy_due = None;
                        activity_phase = ActivityPhase::Finalizing;
                        transition_due = visible_until;
                    }
                } else if desired != lit {
                    activity_phase = ActivityPhase::Pending;
                    transition_due = visible_until;
                } else if was_active && activity_count == 0
                    || activity_happened && activity_count == 0
                {
                    busy_due = None;
                    activity_phase = ActivityPhase::Finalizing;
                    transition_due = Some(visible_until.unwrap_or(now).max(now));
                } else if activity_count != 0 {
                    activity_phase = ActivityPhase::Active;
                    busy_due = busy_due
                        .filter(|due| *due > now)
                        .or_else(|| Some(Instant::now() + activity_blink_delay(lit)));
                    transition_due = busy_due;
                }
            }
            Command::PresenceWaitStarted => {
                presence_waiters = presence_waiters.saturating_add(1);
                if presence_waiters == 1 && bound && !suspended {
                    activity_phase = ActivityPhase::Idle;
                    activity_state
                        .activity_pending
                        .store(false, Ordering::Release);
                    visible_until = None;
                    busy_due = None;
                    if !lit {
                        toggle_led(&mut hardware, &mut lit);
                    }
                    activity_state.desired_lit.store(true, Ordering::Release);
                    transition_due = Some(Instant::now() + PRESENCE_BLINK_HALF_PERIOD);
                }
            }
            Command::PresenceWaitEnded => {
                presence_waiters = presence_waiters.saturating_sub(1);
                if presence_waiters == 0 {
                    transition_due = None;
                    activity_phase = ActivityPhase::Idle;
                    visible_until = None;
                    busy_due = None;
                    activity_state
                        .activity_pending
                        .store(false, Ordering::Release);
                    activity_count = activity_state.active_count.load(Ordering::Acquire);
                    if bound && !suspended {
                        let activity_visible = activity_count != 0;
                        if lit != activity_visible {
                            lit = activity_visible;
                            hardware.render(lit);
                        }
                        activity_state.desired_lit.store(lit, Ordering::Release);
                        if activity_count != 0 {
                            activity_phase = ActivityPhase::Active;
                            visible_until = Some(Instant::now() + minimum_led_hold(lit));
                            busy_due = Some(Instant::now() + activity_blink_delay(lit));
                            transition_due = busy_due;
                        }
                    }
                }
            }
            Command::Bind => {
                bound = true;
                suspended = false;
                activity_phase = ActivityPhase::Idle;
                visible_until = None;
                busy_due = None;
                activity_state
                    .activity_pending
                    .store(false, Ordering::Release);
                activity_count = activity_state.active_count.load(Ordering::Acquire);
                lit = presence_waiters != 0 || activity_count != 0;
                hardware.render(lit);
                activity_state.desired_lit.store(lit, Ordering::Release);
                transition_due = if presence_waiters != 0 {
                    Some(Instant::now() + PRESENCE_BLINK_HALF_PERIOD)
                } else if activity_count != 0 {
                    activity_phase = ActivityPhase::Active;
                    visible_until = Some(Instant::now() + minimum_led_hold(lit));
                    busy_due = Some(Instant::now() + activity_blink_delay(lit));
                    busy_due
                } else {
                    None
                };
            }
            Command::Unbind => {
                bound = false;
                suspended = false;
                lit = false;
                activity_count = 0;
                activity_phase = ActivityPhase::Idle;
                visible_until = None;
                busy_due = None;
                activity_state
                    .activity_pending
                    .store(false, Ordering::Release);
                activity_state.desired_lit.store(false, Ordering::Release);
                transition_due = None;
                hardware.turn_off("USB unbind");
            }
            Command::Suspend => {
                suspended = true;
                lit = false;
                activity_phase = ActivityPhase::Idle;
                visible_until = None;
                busy_due = None;
                activity_state
                    .activity_pending
                    .store(false, Ordering::Release);
                activity_state.desired_lit.store(false, Ordering::Release);
                transition_due = None;
                if bound {
                    hardware.turn_off("USB suspend");
                }
            }
            Command::Resume => {
                if bound && suspended {
                    suspended = false;
                    activity_phase = ActivityPhase::Idle;
                    visible_until = None;
                    busy_due = None;
                    activity_state
                        .activity_pending
                        .store(false, Ordering::Release);
                    activity_count = activity_state.active_count.load(Ordering::Acquire);
                    lit = presence_waiters != 0 || activity_count != 0;
                    hardware.render(lit);
                    activity_state.desired_lit.store(lit, Ordering::Release);
                    transition_due = if presence_waiters != 0 {
                        Some(Instant::now() + PRESENCE_BLINK_HALF_PERIOD)
                    } else if activity_count != 0 {
                        activity_phase = ActivityPhase::Active;
                        visible_until = Some(Instant::now() + minimum_led_hold(lit));
                        busy_due = Some(Instant::now() + activity_blink_delay(lit));
                        busy_due
                    } else {
                        None
                    };
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
fn toggle_led(hardware: &mut Hardware, lit: &mut bool) {
    *lit = !*lit;
    hardware.render(*lit);
}

#[cfg(target_os = "linux")]
fn toggle_led_minimum(hardware: &mut Hardware, lit: &mut bool) -> Instant {
    toggle_led(hardware, lit);
    Instant::now() + minimum_led_hold(*lit)
}

#[cfg(target_os = "linux")]
fn toggle_global_led_minimum(
    hardware: &mut Hardware,
    lit: &mut bool,
    desired_lit: &AtomicBool,
) -> Instant {
    let target = !desired_lit.fetch_xor(true, Ordering::AcqRel);
    if *lit != target {
        *lit = target;
        hardware.render(target);
    }
    Instant::now() + minimum_led_hold(*lit)
}

#[cfg(target_os = "linux")]
fn minimum_led_hold(lit: bool) -> Duration {
    if lit {
        ACTIVITY_LED_MIN_ON_HOLD
    } else {
        ACTIVITY_LED_MIN_OFF_HOLD
    }
}

#[cfg(target_os = "linux")]
fn activity_blink_delay(lit: bool) -> Duration {
    if lit {
        ACTIVITY_LED_ON_HOLD
    } else {
        ACTIVITY_LED_OFF_HOLD
    }
}

#[cfg(target_os = "linux")]
struct Hardware {
    bus: File,
    control: File,
    kind: crate::cli::DisplayKind,
    display: Option<Display>,
    error_reported: bool,
}

#[cfg(target_os = "linux")]
impl Hardware {
    fn new(bus: File, control: File, kind: crate::cli::DisplayKind) -> Self {
        Self {
            bus,
            control,
            kind,
            display: None,
            error_reported: false,
        }
    }

    fn render(&mut self, active: bool) {
        let recovered = self.error_reported;
        if self.display.is_none() {
            let backend = match self.kind {
                crate::cli::DisplayKind::St7789Spi => Backend::St7789Spi,
                crate::cli::DisplayKind::Sh1106Spi => Backend::Sh1106Spi,
            };
            match Display::from_raw_fds(
                backend,
                self.bus.as_raw_fd(),
                Some(self.control.as_raw_fd()),
            ) {
                Ok(display) => {
                    self.display = Some(display);
                    diagnostics::log(
                        Level::Info,
                        "display",
                        if recovered { "recovered" } else { "ready" },
                        format_args!("backend={}", self.kind.name()),
                    );
                    self.error_reported = false;
                }
                Err(error) => {
                    self.report_error("initialization", &error);
                    return;
                }
            }
        }
        let frame: &[u8] = match (self.kind, active) {
            (crate::cli::DisplayKind::St7789Spi, false) => IDLE_FRAME,
            (crate::cli::DisplayKind::St7789Spi, true) => ACTIVE_FRAME,
            (crate::cli::DisplayKind::Sh1106Spi, false) => OLED_IDLE_FRAME,
            (crate::cli::DisplayKind::Sh1106Spi, true) => OLED_ACTIVE_FRAME,
        };
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
                format_args!("backend={} reason={reason:?}", self.kind.name()),
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
                format_args!(
                    "backend={} operation={operation} error={error:?}",
                    self.kind.name()
                ),
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
        assert_eq!(IDLE_FRAME.len(), COLOR_FRAME_SIZE);
        assert_eq!(ACTIVE_FRAME.len(), COLOR_FRAME_SIZE);
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

    #[test]
    fn oled_frames_are_native_monochrome_images() {
        assert_eq!(OLED_IDLE_FRAME.len(), OLED_FRAME_SIZE);
        assert_eq!(OLED_ACTIVE_FRAME.len(), OLED_FRAME_SIZE);
        assert_ne!(OLED_IDLE_FRAME, OLED_ACTIVE_FRAME);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn activity_guard_coalesces_wakes_to_parity_and_latches_activity() {
        let (sender, receiver) = mpsc::channel();
        let state = Arc::new(ActivityState {
            sender,
            active_count: AtomicUsize::new(0),
            desired_lit: AtomicBool::new(false),
            activity_pending: AtomicBool::new(false),
            notification_pending: AtomicBool::new(false),
        });
        let activity = Activity {
            state: Arc::clone(&state),
        };

        let first = activity.begin();
        let second = activity.begin();
        assert_eq!(state.active_count.load(Ordering::Acquire), 2);
        assert!(!state.desired_lit.load(Ordering::Acquire));
        assert!(state.activity_pending.load(Ordering::Acquire));
        assert!(matches!(receiver.recv().unwrap(), Command::ActivityChanged));
        assert!(receiver.try_recv().is_err());

        state.notification_pending.store(false, Ordering::Release);
        state.activity_pending.store(false, Ordering::Release);
        drop(first);
        assert_eq!(state.active_count.load(Ordering::Acquire), 1);
        assert!(receiver.try_recv().is_err());

        drop(second);
        assert_eq!(state.active_count.load(Ordering::Acquire), 0);
        assert!(matches!(receiver.recv().unwrap(), Command::ActivityChanged));

        state.notification_pending.store(false, Ordering::Release);
        for _ in 0..3 {
            drop(activity.begin());
        }
        assert_eq!(state.active_count.load(Ordering::Acquire), 0);
        assert!(state.desired_lit.load(Ordering::Acquire));
        assert!(state.activity_pending.load(Ordering::Acquire));
        assert!(matches!(receiver.recv().unwrap(), Command::ActivityChanged));
        assert!(receiver.try_recv().is_err());
        assert_eq!(ACTIVITY_LED_ON_HOLD, Duration::from_millis(67));
        assert_eq!(ACTIVITY_LED_OFF_HOLD, Duration::from_millis(33));
        assert_eq!(ACTIVITY_LED_MIN_ON_HOLD, Duration::from_millis(8));
        assert_eq!(ACTIVITY_LED_MIN_OFF_HOLD, Duration::from_millis(8));
        assert_eq!(
            ACTIVITY_LED_ON_HOLD + ACTIVITY_LED_OFF_HOLD,
            Duration::from_millis(100)
        );
    }
}
