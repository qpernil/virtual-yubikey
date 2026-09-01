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
use std::sync::{Arc, Mutex};
#[cfg(target_os = "linux")]
use std::time::Duration;

#[cfg(target_os = "linux")]
const BUSY_CADENCE: Cadence = Cadence::new(Duration::from_millis(67), Duration::from_millis(33));
#[cfg(target_os = "linux")]
const PRESENCE_CADENCE: Cadence =
    Cadence::new(Duration::from_millis(384), Duration::from_millis(384));
#[cfg(target_os = "linux")]
const MINIMUM_EDGE: Duration = Duration::from_millis(8);

#[cfg(target_os = "linux")]
#[derive(Clone)]
pub(crate) struct Activity {
    inner: display_backends::indicator::Activity,
}

#[cfg(target_os = "linux")]
impl Activity {
    pub(crate) fn begin(&self) -> CommandGuard {
        self.inner.begin()
    }

    pub(crate) fn wait_for_presence(&self) -> io::Result<AttentionGuard> {
        self.inner.attention(PRESENCE_CADENCE)
    }
}

#[cfg(target_os = "linux")]
pub(crate) struct Controller {
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
            Policy::new(BUSY_CADENCE, IdlePolicy::Off, MINIMUM_EDGE),
            HardwareRenderer {
                hardware: Arc::clone(&hardware),
            },
            "yubikey-indicator",
        )?;
        Ok(Self {
            indicator,
            hardware,
        })
    }

    pub(crate) fn activity(&self) -> Activity {
        Activity {
            inner: self.indicator.activity(),
        }
    }

    pub(crate) fn bind(&self) -> io::Result<()> {
        self.with_hardware(|hardware| hardware.render(false))?;
        self.indicator.enable()
    }

    pub(crate) fn unbind(&self) -> io::Result<()> {
        let result = self.indicator.disable();
        self.with_hardware(|hardware| hardware.turn_off("USB unbind"))?;
        result
    }

    pub(crate) fn suspend(&self) -> io::Result<()> {
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
            indicator,
            hardware,
        } = self;
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
        assert_eq!(MINIMUM_EDGE, Duration::from_millis(8));
    }
}
