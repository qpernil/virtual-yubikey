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
use display_backends::indicator::{
    AttentionGuard, Cadence, CommandGuard, Controller as IndicatorController, IdlePolicy,
    IndicatorRenderer, Policy,
};
#[cfg(target_os = "linux")]
use display_backends::{Backend, Display};
#[cfg(target_os = "linux")]
use std::fs::File;
#[cfg(target_os = "linux")]
use std::io;
#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd;
#[cfg(target_os = "linux")]
use std::sync::{Arc, Condvar, Mutex};
#[cfg(target_os = "linux")]
use std::thread::{self, JoinHandle};
#[cfg(target_os = "linux")]
use std::time::{Duration, Instant};

#[cfg(target_os = "linux")]
const BUSY_CADENCE: Cadence = Cadence::new(Duration::from_millis(67), Duration::from_millis(33));
#[cfg(target_os = "linux")]
const PRESENCE_CADENCE: Cadence =
    Cadence::new(Duration::from_millis(384), Duration::from_millis(384));
#[cfg(target_os = "linux")]
const MINIMUM_EDGE: Duration = Duration::from_millis(8);
#[cfg(target_os = "linux")]
const MINIMUM_ACTIVITY_OFF: Duration = Duration::from_millis(20);
#[cfg(target_os = "linux")]
const MINIMUM_ACTIVITY_ON: Duration = Duration::from_micros(33_500);

#[cfg(target_os = "linux")]
fn indicator_policy() -> Policy {
    Policy::new(BUSY_CADENCE, IdlePolicy::Off, MINIMUM_EDGE)
        .with_minimum_activity_off(MINIMUM_ACTIVITY_OFF)
        .with_minimum_activity_on(MINIMUM_ACTIVITY_ON)
}

#[cfg(target_os = "linux")]
#[derive(Clone)]
pub(crate) struct Activity {
    inner: display_backends::indicator::Activity,
    presence: Arc<PresenceIndication>,
}

#[cfg(target_os = "linux")]
impl Activity {
    pub(crate) fn begin(&self) -> Option<CommandGuard> {
        let state = self.presence.state.lock().ok()?;
        if state.waiting || state.u2f.is_some() {
            None
        } else {
            Some(self.inner.begin())
        }
    }

    pub(crate) fn poll_u2f_presence(&self) -> io::Result<()> {
        let mut state = self.presence.lock()?;
        if state.waiting || state.stopped {
            return Ok(());
        }
        let deadline = Instant::now() + PRESENCE_CADENCE.on + PRESENCE_CADENCE.off;
        if let Some(prompt) = &mut state.u2f {
            // Refresh expiry only; retaining the guard preserves the blink phase.
            prompt.deadline = deadline;
        } else {
            state.u2f = Some(U2fPrompt {
                deadline,
                _guard: self.inner.attention(PRESENCE_CADENCE)?,
            });
            diagnostics::log(
                Level::Info,
                "u2f",
                "indication",
                format_args!("active=true"),
            );
        }
        self.presence.changed.notify_one();
        Ok(())
    }

    pub(crate) fn finish_u2f_presence(&self) -> io::Result<()> {
        self.presence.lock()?.clear_u2f("completed");
        self.presence.changed.notify_one();
        Ok(())
    }

    pub(crate) fn wait_for_presence(&self) -> io::Result<PresenceGuard> {
        let mut state = self.presence.lock()?;
        state.clear_u2f("presence_wait");
        let guard = self.inner.attention(PRESENCE_CADENCE)?;
        state.waiting = true;
        self.presence.changed.notify_one();
        Ok(PresenceGuard {
            guard: Some(guard),
            presence: Arc::clone(&self.presence),
        })
    }
}

#[cfg(target_os = "linux")]
pub(crate) struct PresenceGuard {
    guard: Option<AttentionGuard>,
    presence: Arc<PresenceIndication>,
}

#[cfg(target_os = "linux")]
impl Drop for PresenceGuard {
    fn drop(&mut self) {
        if let Ok(mut state) = self.presence.lock() {
            self.guard.take();
            state.waiting = false;
        }
    }
}

#[cfg(target_os = "linux")]
struct U2fPrompt {
    deadline: Instant,
    _guard: AttentionGuard,
}

#[cfg(target_os = "linux")]
#[derive(Default)]
struct PresenceState {
    u2f: Option<U2fPrompt>,
    waiting: bool,
    stopped: bool,
}

#[cfg(target_os = "linux")]
impl PresenceState {
    fn clear_u2f(&mut self, reason: &str) {
        if self.u2f.take().is_some() {
            diagnostics::log(
                Level::Info,
                "u2f",
                "indication",
                format_args!("active=false reason={reason}"),
            );
        }
    }
}

#[cfg(target_os = "linux")]
#[derive(Default)]
struct PresenceIndication {
    state: Mutex<PresenceState>,
    changed: Condvar,
}

#[cfg(target_os = "linux")]
impl PresenceIndication {
    fn lock(&self) -> io::Result<std::sync::MutexGuard<'_, PresenceState>> {
        self.state
            .lock()
            .map_err(|_| io::Error::other("presence indication lock poisoned"))
    }
}

#[cfg(target_os = "linux")]
struct IndicationExpiry {
    presence: Arc<PresenceIndication>,
    thread: Option<JoinHandle<io::Result<()>>>,
}

#[cfg(target_os = "linux")]
impl IndicationExpiry {
    fn start(presence: Arc<PresenceIndication>) -> io::Result<Self> {
        let timer = Arc::clone(&presence);
        let thread = thread::Builder::new()
            .name("yubikey-u2f-indication".into())
            .spawn(move || {
                let mut state = timer.lock()?;
                while !state.stopped {
                    if let Some(prompt) = &state.u2f {
                        let remaining = prompt.deadline.saturating_duration_since(Instant::now());
                        if remaining.is_zero() {
                            state.clear_u2f("polling_ended");
                        } else {
                            state = timer
                                .changed
                                .wait_timeout(state, remaining)
                                .map_err(|_| io::Error::other("presence indication lock poisoned"))?
                                .0;
                        }
                    } else {
                        state = timer
                            .changed
                            .wait(state)
                            .map_err(|_| io::Error::other("presence indication lock poisoned"))?;
                    }
                }
                Ok(())
            })?;
        Ok(Self {
            presence,
            thread: Some(thread),
        })
    }

    fn finish(&mut self) -> io::Result<()> {
        let Some(thread) = self.thread.take() else {
            return Ok(());
        };
        {
            let mut state = self.presence.lock()?;
            state.clear_u2f("shutdown");
            state.stopped = true;
            self.presence.changed.notify_one();
        }
        thread
            .join()
            .map_err(|_| io::Error::other("U2F indication thread panicked"))?
    }
}

#[cfg(target_os = "linux")]
impl Drop for IndicationExpiry {
    fn drop(&mut self) {
        let _ = self.finish();
    }
}

#[cfg(target_os = "linux")]
pub(crate) struct Controller {
    expiry: IndicationExpiry,
    indicator: IndicatorController,
    hardware: Arc<Mutex<Hardware>>,
}

#[cfg(target_os = "linux")]
impl Controller {
    pub(crate) fn start(
        bus: File,
        control: File,
        kind: crate::cli::DisplayKind,
    ) -> io::Result<Self> {
        let hardware = Arc::new(Mutex::new(Hardware::new(bus, control, kind)));
        let indicator = IndicatorController::start(
            indicator_policy(),
            HardwareRenderer {
                hardware: Arc::clone(&hardware),
            },
            "yubikey-indicator",
        )?;
        let expiry = IndicationExpiry::start(Arc::new(PresenceIndication::default()))?;
        Ok(Self {
            expiry,
            indicator,
            hardware,
        })
    }

    pub(crate) fn activity(&self) -> Activity {
        Activity {
            inner: self.indicator.activity(),
            presence: Arc::clone(&self.expiry.presence),
        }
    }

    pub(crate) fn bind(&self) -> io::Result<()> {
        self.with_hardware(|hardware| hardware.render(false))?;
        self.indicator.enable()
    }

    pub(crate) fn unbind(&self) -> io::Result<()> {
        self.activity().finish_u2f_presence()?;
        let result = self.indicator.disable();
        self.with_hardware(|hardware| hardware.turn_off("USB unbind"))?;
        result
    }

    pub(crate) fn suspend(&self) -> io::Result<()> {
        self.activity().finish_u2f_presence()?;
        let result = self.indicator.disable();
        self.with_hardware(|hardware| hardware.turn_off("USB suspend"))?;
        result
    }

    pub(crate) fn resume(&self) -> io::Result<()> {
        self.with_hardware(|hardware| hardware.render(false))?;
        self.indicator.enable()
    }

    pub(crate) fn shutdown(self) -> io::Result<()> {
        let Self {
            mut expiry,
            indicator,
            hardware,
        } = self;
        expiry.finish()?;
        let result = indicator.shutdown();
        lock_hardware(&hardware)?.turn_off("worker shutdown");
        result
    }

    fn with_hardware(&self, operation: impl FnOnce(&mut Hardware)) -> io::Result<()> {
        let mut hardware = lock_hardware(&self.hardware)?;
        operation(&mut hardware);
        Ok(())
    }
}

#[cfg(target_os = "linux")]
fn lock_hardware(hardware: &Mutex<Hardware>) -> io::Result<std::sync::MutexGuard<'_, Hardware>> {
    hardware
        .lock()
        .map_err(|_| io::Error::other("YubiKey display lock poisoned"))
}

#[cfg(target_os = "linux")]
struct HardwareRenderer {
    hardware: Arc<Mutex<Hardware>>,
}

#[cfg(target_os = "linux")]
impl IndicatorRenderer for HardwareRenderer {
    fn set_indicator(&mut self, lit: bool) -> io::Result<()> {
        lock_hardware(&self.hardware)?.render(lit);
        Ok(())
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
                crate::cli::DisplayKind::Sh1106I2c => Backend::Sh1106I2c,
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
            (crate::cli::DisplayKind::Sh1106I2c, false) => OLED_IDLE_FRAME,
            (crate::cli::DisplayKind::Sh1106I2c, true) => OLED_ACTIVE_FRAME,
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

#[cfg(all(test, target_os = "linux"))]
pub(crate) struct TestIndicator {
    pub(crate) activity: Activity,
    _expiry: IndicationExpiry,
    _indicator: IndicatorController,
}

#[cfg(all(test, target_os = "linux"))]
impl TestIndicator {
    pub(crate) fn new(renderer: impl IndicatorRenderer) -> io::Result<Self> {
        let indicator =
            IndicatorController::start(indicator_policy(), renderer, "test-u2f-indicator")?;
        indicator.enable()?;
        let presence = Arc::new(PresenceIndication::default());
        let expiry = IndicationExpiry::start(Arc::clone(&presence))?;
        let activity = Activity {
            inner: indicator.activity(),
            presence,
        };
        Ok(Self {
            activity,
            _expiry: expiry,
            _indicator: indicator,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "linux")]
    #[test]
    fn u2f_polls_preserve_visible_blink_phase_and_expire_without_further_calls() {
        let (sender, edges) = std::sync::mpsc::channel();
        let fixture = TestIndicator::new(move |lit| {
            sender.send((Instant::now(), lit)).unwrap();
            Ok(())
        })
        .unwrap();
        fixture.activity.poll_u2f_presence().unwrap();
        let first = edges.recv_timeout(Duration::from_secs(1)).unwrap();
        assert!(first.1);
        // A client retrying faster than the blink must not restart its phase or
        // insert command-activity flashes. The renderer observes actual edges.
        for _ in 0..12 {
            thread::sleep(Duration::from_millis(100));
            assert!(fixture.activity.begin().is_none());
            fixture.activity.poll_u2f_presence().unwrap();
        }
        let last_poll = Instant::now();
        let mut transitions = vec![first];
        loop {
            if fixture.activity.presence.lock().unwrap().u2f.is_none() {
                break;
            }
            assert!(last_poll.elapsed() < Duration::from_secs(2));
            if let Ok(edge) = edges.recv_timeout(Duration::from_millis(50)) {
                transitions.push(edge);
            }
        }
        transitions.extend(edges.try_iter());
        assert!(last_poll.elapsed() >= Duration::from_millis(768));
        assert!(last_poll.elapsed() < Duration::from_millis(1000));
        assert!(transitions.len() >= 5);
        for pair in transitions[..4].windows(2) {
            assert_ne!(pair[0].1, pair[1].1);
            let half_period = pair[1].0.duration_since(pair[0].0);
            assert!(
                (Duration::from_millis(300)..Duration::from_millis(500)).contains(&half_period),
                "{half_period:?}"
            );
        }
        assert!(!transitions.last().unwrap().1);
        assert!(fixture.activity.begin().is_some());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn successful_u2f_presence_ends_the_indication_before_its_timeout() {
        let (sender, edges) = std::sync::mpsc::channel();
        let fixture = TestIndicator::new(move |lit| {
            sender.send(lit).unwrap();
            Ok(())
        })
        .unwrap();
        fixture.activity.poll_u2f_presence().unwrap();
        assert!(edges.recv_timeout(Duration::from_secs(1)).unwrap());
        fixture.activity.finish_u2f_presence().unwrap();
        assert!(!edges.recv_timeout(Duration::from_millis(200)).unwrap());
        assert!(fixture.activity.presence.lock().unwrap().u2f.is_none());
    }

    #[test]
    fn display_frames_are_native_st7789_images() {
        assert_eq!(IDLE_FRAME.len(), COLOR_FRAME_SIZE);
        assert_eq!(ACTIVE_FRAME.len(), COLOR_FRAME_SIZE);
        assert_ne!(IDLE_FRAME, ACTIVE_FRAME);
        let mut changed = 0;
        for (index, (idle, active)) in IDLE_FRAME
            .as_chunks::<2>()
            .0
            .iter()
            .zip(ACTIVE_FRAME.as_chunks::<2>().0.iter())
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
    fn indicator_policy_matches_measured_yubikey_cadences() {
        assert_eq!(BUSY_CADENCE.on, Duration::from_millis(67));
        assert_eq!(BUSY_CADENCE.off, Duration::from_millis(33));
        assert_eq!(PRESENCE_CADENCE.on, Duration::from_millis(384));
        assert_eq!(PRESENCE_CADENCE.off, Duration::from_millis(384));
        let policy = indicator_policy();
        assert_eq!(policy.idle, IdlePolicy::Off);
        assert_eq!(policy.minimum_edge, Duration::from_millis(8));
        assert_eq!(policy.minimum_activity_off, Duration::from_millis(20));
        assert_eq!(policy.minimum_activity_on, Duration::from_micros(33_500));
    }
}
