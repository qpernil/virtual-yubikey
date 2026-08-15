//! Unprivileged FunctionFS transport for the virtual YubiKey CCID interface.

#[cfg(target_os = "linux")]
use crate::diagnostics::{self, Level};
#[cfg(target_os = "linux")]
use crate::STOP_REQUESTED;
#[cfg(target_os = "linux")]
use std::fs::{File, OpenOptions};
#[cfg(target_os = "linux")]
use std::io::{self, Read, Write};
#[cfg(target_os = "linux")]
use std::os::fd::FromRawFd;
#[cfg(target_os = "linux")]
use std::os::unix::fs::OpenOptionsExt;
#[cfg(target_os = "linux")]
use std::path::Path;
#[cfg(target_os = "linux")]
use std::sync::atomic::Ordering;
#[cfg(target_os = "linux")]
use std::sync::mpsc::{self, TryRecvError};
#[cfg(target_os = "linux")]
use std::{thread, time::Duration};
#[cfg(target_os = "linux")]
use virtual_yubikey_core::FidoAuthenticator;

#[cfg(target_os = "linux")]
const MAX_TRANSFER: usize = 16 * 1024;
#[cfg(target_os = "linux")]
const O_NONBLOCK_LINUX: i32 = 0x800;

#[cfg(target_os = "linux")]
pub(crate) fn run_worker(
    serial: u32,
    control_fd: i32,
    functionfs: &Path,
    hid_device: &Path,
) -> io::Result<()> {
    unsafe extern "C" {
        fn geteuid() -> u32;
    }
    // SAFETY: geteuid has no preconditions.
    if unsafe { geteuid() } == 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "refusing to run the protocol worker as root",
        ));
    }

    // SAFETY: the supervisor passes ownership of this descriptor to the worker.
    let mut control = unsafe { File::from_raw_fd(control_fd) };
    let endpoints = Endpoints::open(functionfs)?;
    control.write_all(b"R")?;
    let mut attached = [0_u8; 1];
    control.read_exact(&mut attached)?;
    if attached != *b"H" {
        return Err(io::Error::other(
            "supervisor sent an invalid HID-ready message",
        ));
    }
    drop(control);
    let hid = OpenOptions::new()
        .read(true)
        .write(true)
        .open(hid_device)
        .map_err(|error| with_context(error, "open FIDO HID gadget"))?;
    diagnostics::log(
        Level::Info,
        "worker",
        "ready",
        format_args!(
            "serial={serial} functionfs={} hid={}",
            functionfs.display(),
            hid_device.display()
        ),
    );
    endpoints.serve(serial, hid)
}

#[cfg(target_os = "linux")]
struct Endpoints {
    ep0: File,
    ccid_out: File,
    ccid_in: File,
    ccid_interrupt: File,
    ccid_notification_pending: bool,
}

#[cfg(target_os = "linux")]
impl Endpoints {
    fn open(functionfs: &Path) -> io::Result<Self> {
        let mut ep0 = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(O_NONBLOCK_LINUX)
            .open(functionfs.join("ep0"))?;
        ep0.write_all(&descriptors())
            .map_err(|error| with_context(error, "write FunctionFS descriptors"))?;
        ep0.write_all(&strings())
            .map_err(|error| with_context(error, "write FunctionFS strings"))?;

        Ok(Self {
            ep0,
            ccid_out: open_nonblocking(functionfs.join("ep1"), true, false)?,
            ccid_in: open_nonblocking(functionfs.join("ep2"), false, true)?,
            ccid_interrupt: open_nonblocking(functionfs.join("ep3"), false, true)?,
            ccid_notification_pending: false,
        })
    }

    fn serve(self, serial: u32, hid: File) -> io::Result<()> {
        let Self {
            mut ep0,
            ccid_out,
            ccid_in,
            mut ccid_interrupt,
            mut ccid_notification_pending,
        } = self;
        let (completion_tx, completion_rx) = mpsc::channel();

        // FunctionFS endpoint reads remain synchronous after enable even when
        // opened O_NONBLOCK, so keep the bulk OUT endpoint in its own thread.
        let ccid_completion = completion_tx.clone();
        thread::Builder::new()
            .name("ccid-usb".to_owned())
            .spawn(move || {
                let _ = ccid_completion.send(("CCID", serve_ccid(ccid_out, ccid_in, serial)));
            })?;

        thread::Builder::new()
            .name("fido-hid".to_owned())
            .spawn(move || {
                let fido = FidoAuthenticator::new();
                let _ = completion_tx.send(("FIDO HID", serve_hid(hid, fido)));
            })?;

        while !STOP_REQUESTED.load(Ordering::Relaxed) {
            drain_events(&mut ep0, &mut ccid_notification_pending)?;
            let mut progressed = false;

            if ccid_notification_pending {
                match ccid_interrupt.write(&[0x50, 0x03]) {
                    Ok(2) => {
                        progressed = true;
                        ccid_notification_pending = false;
                        diagnostics::log(
                            Level::Debug,
                            "ccid",
                            "slot_change_notification",
                            format_args!("slot=0 present=true changed=true"),
                        );
                    }
                    Ok(_) => {}
                    Err(error) if transient_endpoint_error(&error) => {}
                    Err(error) => return Err(error),
                }
            }

            match completion_rx.try_recv() {
                Ok((transport, Ok(()))) => {
                    return Err(io::Error::other(format!(
                        "{transport} endpoint worker exited unexpectedly"
                    )));
                }
                Ok((transport, Err(error))) => {
                    return Err(with_context(
                        error,
                        &format!("{transport} endpoint worker failed"),
                    ));
                }
                Err(TryRecvError::Empty) => {}
                Err(TryRecvError::Disconnected) => {
                    return Err(io::Error::other("CCID endpoint worker disconnected"));
                }
            }

            if !progressed {
                thread::sleep(Duration::from_millis(5));
            }
        }
        Ok(())
    }
}

#[cfg(target_os = "linux")]
fn serve_ccid(mut output: File, mut input: File, serial: u32) -> io::Result<()> {
    let mut request = [0_u8; MAX_TRANSFER];
    let mut ccid = crate::ccid::Device::new(serial);
    while !STOP_REQUESTED.load(Ordering::Relaxed) {
        match output.read(&mut request) {
            Ok(0) => {}
            Ok(length) => {
                for reply in ccid.receive(&request[..length]) {
                    write_nonblocking(&mut input, &reply)?;
                }
            }
            Err(error) if transient_endpoint_error(&error) => {
                thread::sleep(Duration::from_millis(5));
            }
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn serve_hid(mut hid: File, mut fido: FidoAuthenticator) -> io::Result<()> {
    let mut report = [0_u8; crate::ctaphid::REPORT_SIZE];
    let mut ctaphid = crate::ctaphid::Device::new([5, 8, 0]);
    while !STOP_REQUESTED.load(Ordering::Relaxed) {
        match hid.read(&mut report) {
            Ok(0) => {}
            Ok(length) if length != report.len() => {
                diagnostics::log(
                    Level::Info,
                    "ctaphid",
                    "report_rejected",
                    format_args!("reason=invalid_length length={length}"),
                );
            }
            Ok(_) => {
                diagnostics::log(
                    Level::Debug,
                    "ctaphid",
                    "report",
                    format_args!(
                        "channel={:08x} command={:02x}",
                        u32::from_be_bytes(report[0..4].try_into().unwrap()),
                        report[4]
                    ),
                );
                let replies = ctaphid.receive(&report, |request| fido.exchange(request));
                for reply in replies {
                    hid.write_all(&reply)?;
                }
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) if endpoint_is_gone(&error) => return Ok(()),
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn drain_events(ep0: &mut File, ccid_notification_pending: &mut bool) -> io::Result<()> {
    let mut events = [0_u8; 12 * 8];
    loop {
        match ep0.read(&mut events) {
            Ok(0) => return Ok(()),
            Ok(length) => {
                for event in events[..length].chunks_exact(12) {
                    let event_type = event[8];
                    diagnostics::log(
                        Level::Debug,
                        "functionfs",
                        "event",
                        format_args!("type={} name={}", event_type, event_name(event_type)),
                    );
                    match event_type {
                        2 => *ccid_notification_pending = true,
                        4 => log_setup_request(event),
                        _ => {}
                    }
                }
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(()),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) if endpoint_is_gone(&error) => return Ok(()),
            Err(error) => return Err(error),
        }
    }
}

#[cfg(target_os = "linux")]
fn log_setup_request(event: &[u8]) {
    let request_type = event[0];
    let request = event[1];
    let value = u16::from_le_bytes([event[2], event[3]]);
    let index = u16::from_le_bytes([event[4], event[5]]);
    let length = u16::from_le_bytes([event[6], event[7]]);
    diagnostics::log(
        Level::Info,
        "functionfs",
        "unhandled_setup_request",
        format_args!(
            "request_type={request_type:02x} request={request:02x} value={value:04x} index={index:04x} length={length}"
        ),
    );
}

#[cfg(target_os = "linux")]
fn event_name(event_type: u8) -> &'static str {
    match event_type {
        0 => "bind",
        1 => "unbind",
        2 => "enable",
        3 => "disable",
        4 => "setup",
        5 => "suspend",
        6 => "resume",
        _ => "unknown",
    }
}

#[cfg(target_os = "linux")]
fn open_nonblocking(path: impl AsRef<Path>, read: bool, write: bool) -> io::Result<File> {
    OpenOptions::new()
        .read(read)
        .write(write)
        .custom_flags(O_NONBLOCK_LINUX)
        .open(path)
}

#[cfg(target_os = "linux")]
fn write_nonblocking(file: &mut File, mut bytes: &[u8]) -> io::Result<()> {
    while !bytes.is_empty() && !STOP_REQUESTED.load(Ordering::Relaxed) {
        match file.write(bytes) {
            Ok(0) => thread::sleep(Duration::from_millis(5)),
            Ok(length) => bytes = &bytes[length..],
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(5));
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) if endpoint_is_gone(&error) => return Ok(()),
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn transient_endpoint_error(error: &io::Error) -> bool {
    error.kind() == io::ErrorKind::WouldBlock
        || error.kind() == io::ErrorKind::Interrupted
        || endpoint_is_gone(error)
}

#[cfg(target_os = "linux")]
fn endpoint_is_gone(error: &io::Error) -> bool {
    matches!(error.raw_os_error(), Some(19 | 32 | 108))
}

#[cfg(any(target_os = "linux", test))]
fn descriptors() -> Vec<u8> {
    const FUNCTIONFS_DESCRIPTORS_MAGIC_V2: u32 = 3;
    const FUNCTIONFS_HAS_FS_DESC: u32 = 1;
    const FUNCTIONFS_HAS_HS_DESC: u32 = 2;

    let fs = descriptor_set(64, 32);
    let hs = descriptor_set(512, 9);
    let length = 20 + fs.len() + hs.len();
    let mut descriptors = Vec::with_capacity(length);
    push_u32_le(&mut descriptors, FUNCTIONFS_DESCRIPTORS_MAGIC_V2);
    push_u32_le(&mut descriptors, length as u32);
    push_u32_le(
        &mut descriptors,
        FUNCTIONFS_HAS_FS_DESC | FUNCTIONFS_HAS_HS_DESC,
    );
    push_u32_le(&mut descriptors, 5);
    push_u32_le(&mut descriptors, 5);
    descriptors.extend_from_slice(&fs);
    descriptors.extend_from_slice(&hs);
    descriptors
}

#[cfg(any(target_os = "linux", test))]
fn descriptor_set(bulk_max_packet_size: u16, interrupt_interval: u8) -> Vec<u8> {
    let mut descriptors = vec![9, 4, 0, 0, 3, 0x0b, 0, 0, 0];
    descriptors.extend_from_slice(&ccid_functional_descriptor());
    descriptors.extend_from_slice(&[7, 5, 0x01, 2]); // bulk OUT
    descriptors.extend_from_slice(&bulk_max_packet_size.to_le_bytes());
    descriptors.extend_from_slice(&[0, 7, 5, 0x81, 2]); // bulk IN
    descriptors.extend_from_slice(&bulk_max_packet_size.to_le_bytes());
    descriptors.extend_from_slice(&[
        0,
        7,
        5,
        0x82,
        3,
        8,
        0,
        interrupt_interval, // interrupt IN
    ]);
    descriptors
}

#[cfg(any(target_os = "linux", test))]
fn ccid_functional_descriptor() -> Vec<u8> {
    let mut descriptor = vec![
        0x36, 0x21, // length and CCID descriptor type
        0x00, 0x01, // CCID 1.00, matching the allowlisted YubiKey identity
        0x00, // one slot
        0x07, // 5 V, 3 V, and 1.8 V
    ];
    descriptor.extend_from_slice(&2_u32.to_le_bytes()); // T=1
    descriptor.extend_from_slice(&4000_u32.to_le_bytes());
    descriptor.extend_from_slice(&4000_u32.to_le_bytes());
    descriptor.push(0);
    descriptor.extend_from_slice(&307_200_u32.to_le_bytes());
    descriptor.extend_from_slice(&307_200_u32.to_le_bytes());
    descriptor.push(0);
    descriptor.extend_from_slice(&3062_u32.to_le_bytes());
    descriptor.extend_from_slice(&0_u32.to_le_bytes());
    descriptor.extend_from_slice(&0_u32.to_le_bytes());
    descriptor.extend_from_slice(&0x0004_00fe_u32.to_le_bytes());
    descriptor.extend_from_slice(&3072_u32.to_le_bytes());
    descriptor.extend_from_slice(&[0xff, 0xff, 0, 0, 0, 1]);
    debug_assert_eq!(descriptor.len(), 0x36);
    descriptor
}

#[cfg(target_os = "linux")]
fn strings() -> Vec<u8> {
    const FUNCTIONFS_STRINGS_MAGIC: u32 = 2;
    let mut strings = Vec::with_capacity(16);
    push_u32_le(&mut strings, FUNCTIONFS_STRINGS_MAGIC);
    push_u32_le(&mut strings, 16);
    push_u32_le(&mut strings, 0);
    push_u32_le(&mut strings, 0);
    strings
}

#[cfg(any(target_os = "linux", test))]
fn push_u32_le(output: &mut Vec<u8>, value: u32) {
    output.extend_from_slice(&value.to_le_bytes());
}

#[cfg(target_os = "linux")]
fn with_context(error: io::Error, operation: &str) -> io::Error {
    io::Error::new(error.kind(), format!("{operation}: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn descriptors_have_matching_v2_length_and_counts() {
        let descriptors = descriptors();
        assert_eq!(descriptors.len(), 188);
        assert_eq!(
            u32::from_le_bytes(descriptors[4..8].try_into().unwrap()) as usize,
            descriptors.len()
        );
        assert_eq!(
            u32::from_le_bytes(descriptors[8..12].try_into().unwrap()),
            3
        );
        assert_eq!(
            u32::from_le_bytes(descriptors[12..16].try_into().unwrap()),
            5
        );
        assert_eq!(
            u32::from_le_bytes(descriptors[16..20].try_into().unwrap()),
            5
        );
    }

    #[test]
    fn descriptor_set_is_one_ccid_interface() {
        let descriptors = descriptor_set(64, 32);
        assert_eq!(&descriptors[..9], &[9, 4, 0, 0, 3, 0x0b, 0, 0, 0]);
        assert_eq!(descriptors.len(), 84);
        assert!(descriptors.windows(2).any(|value| value == [0x36, 0x21]));
        assert_eq!(
            descriptors
                .windows(2)
                .filter(|value| *value == [9, 4])
                .count(),
            1
        );
    }

    #[test]
    fn ccid_descriptor_has_specified_length() {
        assert_eq!(ccid_functional_descriptor().len(), 0x36);
    }

    #[test]
    fn ccid_endpoints_have_the_real_facing_shape() {
        let descriptors = descriptor_set(64, 32);
        assert!(descriptors
            .windows(7)
            .any(|value| value == [7, 5, 0x01, 2, 64, 0, 0]));
        assert!(descriptors
            .windows(7)
            .any(|value| value == [7, 5, 0x81, 2, 64, 0, 0]));
        assert!(descriptors
            .windows(7)
            .any(|value| value == [7, 5, 0x82, 3, 8, 0, 32]));
    }
}
