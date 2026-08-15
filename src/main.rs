//! A virtual YubiKey exposed through Linux USB gadget mode.
//!
//! In normal operation a root supervisor owns the Linux USB gadget lifecycle
//! and execs an unprivileged copy to own FunctionFS and handle protocol data.

#[cfg(any(target_os = "linux", test))]
mod ccid;
mod cli;
#[cfg(any(target_os = "linux", test))]
mod ctaphid;
mod diagnostics;
mod functionfs;
#[cfg(target_os = "linux")]
mod gadget;
#[cfg(any(target_os = "linux", test))]
mod smartcard;
#[cfg(any(target_os = "linux", test))]
mod usb_identity;

use std::env;
use std::io;
#[cfg(target_os = "linux")]
use std::path::Path;
#[cfg(target_os = "linux")]
use std::sync::atomic::{AtomicBool, Ordering};

#[cfg(target_os = "linux")]
pub(crate) static STOP_REQUESTED: AtomicBool = AtomicBool::new(false);

fn main() {
    if let Err(error) = run() {
        eprintln!("virtual-yubikey: {error}");
        std::process::exit(1);
    }
}

fn run() -> io::Result<()> {
    let options = cli::parse(env::args().skip(1))?;
    diagnostics::set_level(options.log_level);

    if let Some(_ready_fd) = options.worker_fd {
        #[cfg(target_os = "linux")]
        {
            install_signal_handlers()?;
            return functionfs::run_worker(
                options.serial,
                _ready_fd,
                Path::new(gadget::FUNCTIONFS),
                Path::new(gadget::HID_DEVICE),
            );
        }
        #[cfg(not(target_os = "linux"))]
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "the FunctionFS worker is Linux-only",
        ));
    }

    #[cfg(target_os = "linux")]
    {
        install_signal_handlers()?;
        let mut runtime = gadget::Runtime::setup(
            options.serial,
            options.udc.as_deref(),
            options.run_as.as_deref(),
            options.log_level,
        )?;
        let serve_result = runtime.serve();
        let cleanup_result = runtime.cleanup();
        serve_result.and(cleanup_result)
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = (options.udc, options.run_as);
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "USB gadget mode is Linux-only",
        ))
    }
}

#[cfg(target_os = "linux")]
fn install_signal_handlers() -> io::Result<()> {
    unsafe extern "C" fn stop(_signal: i32) {
        STOP_REQUESTED.store(true, Ordering::Relaxed);
    }

    unsafe extern "C" {
        fn signal(signal: i32, handler: unsafe extern "C" fn(i32)) -> usize;
    }

    const SIGINT: i32 = 2;
    const SIGTERM: i32 = 15;
    const SIG_ERR: usize = usize::MAX;

    // SAFETY: `stop` has the C signal-handler ABI and only stores to an atomic.
    if unsafe { signal(SIGINT, stop) } == SIG_ERR || unsafe { signal(SIGTERM, stop) } == SIG_ERR {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}
