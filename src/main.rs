//! Unprivileged YubiKey protocol worker for `usb-gadget-supervisor`.

#[cfg(any(target_os = "linux", test))]
mod ccid;
mod cli;
#[cfg(any(target_os = "linux", test))]
mod ctaphid;
mod diagnostics;
mod functionfs;
#[cfg(any(target_os = "linux", test))]
mod keepalive;
#[cfg(any(target_os = "linux", test))]
mod smartcard;
#[cfg(test)]
mod usb_identity;
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
#[cfg(any(target_os = "linux", test))]
mod worker_protocol;

use std::env;
use std::io;
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

    #[cfg(target_os = "linux")]
    {
        install_signal_handlers()?;
        functionfs::run_worker(options.serial)
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = options;
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "the virtual YubiKey worker is Linux-only",
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
