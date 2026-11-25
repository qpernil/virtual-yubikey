//! Unprivileged YubiKey protocol worker for `usb-gadget-supervisor`.

#[cfg(unix)]
mod buttons;
#[cfg(any(unix, test))]
mod ccid;
mod cli;
#[cfg(any(unix, test))]
mod ctaphid;
mod diagnostics;
#[cfg(any(unix, test))]
mod display;
mod functionfs;
#[cfg(any(unix, test))]
mod keepalive;
#[cfg(any(unix, test))]
mod presence;
#[cfg(any(unix, test))]
mod smartcard;
#[cfg(any(unix, test))]
mod usb_identity;
#[cfg(any(unix, test))]
mod worker_protocol;

use std::env;
use std::io;
#[cfg(unix)]
use std::sync::atomic::{AtomicBool, Ordering};

#[cfg(unix)]
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

    #[cfg(unix)]
    {
        install_signal_handlers()?;
        functionfs::run_worker(options.serial, options.display, options.persistence)
    }

    #[cfg(not(unix))]
    {
        let _ = options;
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "the virtual YubiKey worker requires Unix handles",
        ))
    }
}

#[cfg(unix)]
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
