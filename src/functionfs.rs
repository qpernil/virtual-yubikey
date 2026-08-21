//! Unprivileged FunctionFS transport for the virtual YubiKey CCID interface.

#[cfg(target_os = "linux")]
use crate::diagnostics::{self, Level};
#[cfg(target_os = "linux")]
use crate::worker_protocol::{Channel, Message, RUNTIME_DIRECTORY_ENV, STATE_DIRECTORY_ENV};
#[cfg(target_os = "linux")]
use crate::STOP_REQUESTED;
#[cfg(target_os = "linux")]
use std::env;
#[cfg(target_os = "linux")]
use std::fs::{self, File, OpenOptions};
#[cfg(target_os = "linux")]
use std::io::{self, Read, Write};
#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd;
#[cfg(target_os = "linux")]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
#[cfg(target_os = "linux")]
use std::os::unix::net::UnixDatagram;
#[cfg(target_os = "linux")]
use std::path::{Path, PathBuf};
#[cfg(target_os = "linux")]
use std::sync::atomic::Ordering;
#[cfg(target_os = "linux")]
use std::sync::mpsc::{self, TryRecvError};
#[cfg(target_os = "linux")]
use std::{
    thread,
    time::{Duration, Instant},
};
#[cfg(target_os = "linux")]
use virtual_yubikey_core::FidoAuthenticator;

#[cfg(target_os = "linux")]
const MAX_TRANSFER: usize = 16 * 1024;
#[cfg(target_os = "linux")]
const HID_KEEPALIVE_INTERVAL: Duration = Duration::from_millis(100);
#[cfg(target_os = "linux")]
const HID_PROCESSING_KEEPALIVE_DELAY: Duration = Duration::from_millis(100);
#[cfg(target_os = "linux")]
const HID_COMMAND_POLL_INTERVAL: Duration = Duration::from_millis(5);
#[cfg(target_os = "linux")]
const IDLE_ENDPOINT_WAIT_MS: i32 = 250;

#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum UserPresenceCommand {
    Touch,
}

#[cfg(target_os = "linux")]
impl UserPresenceCommand {
    fn decode(value: u8) -> Option<Self> {
        match value {
            b'T' => Some(Self::Touch),
            // Additional command bytes can represent simulated
            // biometric results without changing the IPC transport.
            _ => None,
        }
    }
}

#[cfg(target_os = "linux")]
#[repr(C)]
struct PollFd {
    fd: i32,
    events: i16,
    revents: i16,
}

#[cfg(target_os = "linux")]
unsafe extern "C" {
    fn poll(fds: *mut PollFd, count: usize, timeout_ms: i32) -> i32;
}

#[cfg(target_os = "linux")]
const POLLIN: i16 = 0x0001;
#[cfg(target_os = "linux")]
const POLLOUT: i16 = 0x0004;

#[cfg(target_os = "linux")]
pub(crate) fn run_worker(serial: u32) -> io::Result<()> {
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

    let mut control = Channel::from_fixed_descriptor()?;
    let prebind = control.receive_files(Message::PrebindResources, 4)?;
    let state_directory = required_path(STATE_DIRECTORY_ENV)?;
    let runtime_directory = required_path(RUNTIME_DIRECTORY_ENV)?;
    let storage = WorkerStorage {
        fido_state: state_directory.join(format!("fido-{serial}.cbor")),
        piv_state: state_directory.join(format!("piv-{serial}.cbor")),
        touch_socket: runtime_directory.join("touch.sock"),
    };
    let fido = load_fido_state(serial, &storage.fido_state)?;
    let ccid = load_piv_state(serial, &storage.piv_state)?;
    let endpoints = Endpoints::from_files(prebind)?;
    control.send(Message::Prepared)?;
    let mut postbind = control.receive_files(Message::PostbindResources, 1)?;
    let hid = postbind
        .pop()
        .expect("protocol validated one HID descriptor");
    control.send(Message::Serving)?;
    diagnostics::log(
        Level::Info,
        "worker",
        "ready",
        format_args!("serial={serial} usb_descriptors=5"),
    );
    let mut lifecycle = control.try_clone()?;
    thread::Builder::new()
        .name("worker-control".to_owned())
        .spawn(move || {
            let _ = lifecycle.receive();
            STOP_REQUESTED.store(true, Ordering::Relaxed);
        })?;

    endpoints.serve(serial, hid, fido, ccid, &storage)
}

#[cfg(target_os = "linux")]
fn required_path(name: &str) -> io::Result<PathBuf> {
    let value = env::var_os(name).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("missing inherited resource path {name}"),
        )
    })?;
    let path = PathBuf::from(value);
    if !path.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("inherited resource path {name} must be absolute"),
        ));
    }
    Ok(path)
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
struct WorkerStorage {
    fido_state: PathBuf,
    piv_state: PathBuf,
    touch_socket: PathBuf,
}

#[cfg(target_os = "linux")]
impl Endpoints {
    fn from_files(files: Vec<File>) -> io::Result<Self> {
        let [ep0, ccid_out, ccid_in, ccid_interrupt]: [File; 4] =
            files.try_into().map_err(|files: Vec<File>| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "expected four pre-bind USB descriptors, got {}",
                        files.len()
                    ),
                )
            })?;
        Ok(Self {
            ep0,
            ccid_out,
            ccid_in,
            ccid_interrupt,
            ccid_notification_pending: false,
        })
    }

    fn serve(
        self,
        serial: u32,
        hid: File,
        fido: FidoAuthenticator,
        ccid: crate::ccid::Device,
        storage: &WorkerStorage,
    ) -> io::Result<()> {
        let Self {
            mut ep0,
            ccid_out,
            ccid_in,
            mut ccid_interrupt,
            mut ccid_notification_pending,
        } = self;
        let (completion_tx, completion_rx) = mpsc::channel();
        let keepalive = crate::keepalive::Scheduler::start()?;

        // FunctionFS endpoint reads remain synchronous after enable even when
        // opened O_NONBLOCK, so keep the bulk OUT endpoint in its own thread.
        let ccid_completion = completion_tx.clone();
        thread::Builder::new().name("ccid-usb".to_owned()).spawn({
            let state_path = storage.piv_state.clone();
            let clock = keepalive.handle();
            move || {
                let _ = ccid_completion.send((
                    "CCID",
                    serve_ccid(ccid_out, ccid_in, ccid, &state_path, clock),
                ));
            }
        })?;

        thread::Builder::new().name("fido-hid".to_owned()).spawn({
            let state_path = storage.fido_state.clone();
            let touch_socket = storage.touch_socket.clone();
            let clock = keepalive.handle();
            move || {
                let _ = completion_tx.send((
                    "FIDO HID",
                    serve_hid(hid, fido, serial, &state_path, &touch_socket, clock),
                ));
            }
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
                wait_for_main_activity(&ep0, &ccid_interrupt, ccid_notification_pending)?;
            }
        }
        Ok(())
    }
}

#[cfg(target_os = "linux")]
fn serve_ccid(
    mut output: File,
    mut input: File,
    mut ccid: crate::ccid::Device,
    state_path: &Path,
    clock: crate::keepalive::Handle,
) -> io::Result<()> {
    let mut request = [0_u8; MAX_TRANSFER];
    while !STOP_REQUESTED.load(Ordering::Relaxed) {
        match output.read(&mut request) {
            Ok(0) => wait_for_descriptor(&output, POLLIN, IDLE_ENDPOINT_WAIT_MS)?,
            Ok(length) => {
                let replies =
                    ccid.receive_with_keepalives(&request[..length], &clock, |keepalive| {
                        write_nonblocking(&mut input, keepalive)
                    })?;
                if ccid.take_piv_persistent_change() {
                    persist_piv_state(&ccid, state_path)?;
                }
                for reply in replies {
                    write_nonblocking(&mut input, &reply)?;
                }
            }
            Err(error) if transient_endpoint_error(&error) => {
                wait_for_descriptor(&output, POLLIN, IDLE_ENDPOINT_WAIT_MS)?;
            }
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn serve_hid(
    mut hid: File,
    mut fido: FidoAuthenticator,
    serial: u32,
    state_path: &Path,
    touch_socket: &Path,
    clock: crate::keepalive::Handle,
) -> io::Result<()> {
    let mut report = [0_u8; crate::ctaphid::REPORT_SIZE];
    let mut ctaphid = crate::ctaphid::Device::new(
        virtual_yubikey_core::DeviceProfile::yubikey_5_8_ccid(serial),
    );
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
                let mut persistence_error = None;
                let mut command_error = None;
                let channel = u32::from_be_bytes(report[0..4].try_into().unwrap());
                let replies = ctaphid.receive(&report, |request| {
                    let command = request.first().copied().unwrap_or_default();
                    diagnostics::log(
                        Level::Info,
                        "ctap2",
                        "request",
                        format_args!(
                            "command=0x{command:02x} name={} cbor_length={}",
                            if request.is_empty() {
                                "missing"
                            } else {
                                ctap_command_name(command)
                            },
                            request.len().saturating_sub(1)
                        ),
                    );
                    if let Some(algorithms) = FidoAuthenticator::make_credential_algorithms(request)
                    {
                        diagnostics::log(
                            Level::Info,
                            "ctap2",
                            "make_credential_algorithms",
                            format_args!("algorithms={algorithms:?}"),
                        );
                    }
                    if let Some(algorithm) = fido.selected_make_credential_algorithm(request) {
                        diagnostics::log(
                            Level::Info,
                            "ctap2",
                            "make_credential_algorithm_selected",
                            format_args!(
                                "algorithm={} cose={}",
                                algorithm.name(),
                                algorithm.cose_identifier()
                            ),
                        );
                    }
                    let response = if matches!(command, 0x01 | 0x02 | 0x0b) {
                        match wait_for_touch(&mut hid, channel, touch_socket, &clock) {
                            Ok(true) => match exchange_fido_with_keepalives(
                                &mut hid, &mut fido, request, channel, true, &clock,
                            ) {
                                Ok(response) => response,
                                Err(error) => {
                                    command_error = Some(error);
                                    vec![0x7f]
                                }
                            },
                            Ok(false) => vec![0x2d],
                            Err(error) => {
                                command_error = Some(error);
                                vec![0x7f]
                            }
                        }
                    } else {
                        match exchange_fido_with_keepalives(
                            &mut hid, &mut fido, request, channel, false, &clock,
                        ) {
                            Ok(response) => response,
                            Err(error) => {
                                command_error = Some(error);
                                vec![0x7f]
                            }
                        }
                    };
                    if fido.take_persistent_change() {
                        if let Err(error) = persist_fido_state(&fido, state_path) {
                            persistence_error = Some(error);
                        }
                    }
                    let status = response.first().copied().unwrap_or_default();
                    diagnostics::log(
                        Level::Info,
                        "ctap2",
                        "response",
                        format_args!(
                            "command=0x{command:02x} status=0x{status:02x} name={} cbor_length={}",
                            if response.is_empty() {
                                "missing"
                            } else {
                                ctap_status_name(status)
                            },
                            response.len().saturating_sub(1)
                        ),
                    );
                    response
                });
                if let Some(error) = persistence_error {
                    return Err(error);
                }
                if let Some(error) = command_error {
                    return Err(error);
                }
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
fn exchange_fido_with_keepalives(
    hid: &mut File,
    fido: &mut FidoAuthenticator,
    request: &[u8],
    channel: u32,
    follows_user_presence: bool,
    clock: &crate::keepalive::Handle,
) -> io::Result<Vec<u8>> {
    let initial_delay = if follows_user_presence {
        Duration::ZERO
    } else {
        HID_PROCESSING_KEEPALIVE_DELAY
    };
    let keepalives = clock.subscribe(initial_delay, HID_KEEPALIVE_INTERVAL)?;
    let started = Instant::now();
    let mut staged = fido.clone();
    let request = request.to_vec();
    let (result_tx, result_rx) = mpsc::sync_channel(1);
    thread::Builder::new()
        .name("fido-command".to_owned())
        .spawn(move || {
            let response = staged.exchange(&request);
            let _ = result_tx.send((staged, response));
        })?;

    let mut report = [0_u8; crate::ctaphid::REPORT_SIZE];
    let mut processing_keepalives = 0_u64;
    loop {
        match result_rx.try_recv() {
            Ok((completed, response)) => {
                *fido = completed;
                if processing_keepalives != 0 {
                    diagnostics::log(
                        Level::Info,
                        "ctaphid",
                        "processing_complete",
                        format_args!(
                            "channel={channel:08x} keepalives={processing_keepalives} elapsed_ms={}",
                            started.elapsed().as_millis()
                        ),
                    );
                }
                return Ok(response);
            }
            Err(TryRecvError::Empty) => {}
            Err(TryRecvError::Disconnected) => {
                return Err(io::Error::other("FIDO command thread returned no response"));
            }
        }

        if input_ready(hid)? {
            match hid.read(&mut report) {
                Ok(length) if length == report.len() => {
                    if crate::ctaphid::is_cancel(&report, channel) {
                        diagnostics::log(
                            Level::Info,
                            "ctaphid",
                            "processing_cancelled",
                            format_args!(
                                "channel={channel:08x} elapsed_ms={}",
                                started.elapsed().as_millis()
                            ),
                        );
                        return Ok(vec![0x2d]);
                    }
                    diagnostics::log(
                        Level::Debug,
                        "ctaphid",
                        "report_ignored_while_processing",
                        format_args!(
                            "channel={:08x} command={:02x}",
                            u32::from_be_bytes(report[0..4].try_into().unwrap()),
                            report[4]
                        ),
                    );
                }
                Ok(0) => return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "HID closed")),
                Ok(length) => diagnostics::log(
                    Level::Info,
                    "ctaphid",
                    "report_rejected",
                    format_args!("reason=invalid_length length={length}"),
                ),
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) if endpoint_is_gone(&error) => return Err(error),
                Err(error) => return Err(error),
            }
        }

        if keepalives.tick_due() {
            if processing_keepalives == 0 {
                diagnostics::log(
                    Level::Info,
                    "ctaphid",
                    "processing_started",
                    format_args!("channel={channel:08x}"),
                );
            }
            hid.write_all(&crate::ctaphid::keepalive(
                channel,
                crate::ctaphid::KeepaliveStatus::Processing,
            ))?;
            processing_keepalives += 1;
        }
        thread::sleep(HID_COMMAND_POLL_INTERVAL);
    }
}

#[cfg(target_os = "linux")]
struct TouchSocket {
    socket: UnixDatagram,
    path: PathBuf,
}

#[cfg(target_os = "linux")]
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

#[cfg(target_os = "linux")]
impl Drop for TouchSocket {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

#[cfg(target_os = "linux")]
fn wait_for_touch(
    hid: &mut File,
    channel: u32,
    touch_socket: &Path,
    clock: &crate::keepalive::Handle,
) -> io::Result<bool> {
    let touch = TouchSocket::bind(touch_socket)?;
    diagnostics::log(
        Level::Info,
        "fido",
        "user_presence_wait",
        format_args!("channel={channel:08x} socket={}", touch_socket.display()),
    );
    let keepalives = clock.subscribe(Duration::ZERO, HID_KEEPALIVE_INTERVAL)?;
    let mut signal = [0_u8; 1];
    let mut report = [0_u8; crate::ctaphid::REPORT_SIZE];

    while !STOP_REQUESTED.load(Ordering::Relaxed) {
        match touch.socket.recv(&mut signal) {
            Ok(1) if UserPresenceCommand::decode(signal[0]) == Some(UserPresenceCommand::Touch) => {
                diagnostics::log(
                    Level::Info,
                    "fido",
                    "user_presence_received",
                    format_args!("channel={channel:08x}"),
                );
                return Ok(true);
            }
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(with_context(error, "receive touch notification")),
        }

        if input_ready(hid)? {
            match hid.read(&mut report) {
                Ok(length) if length == report.len() => {
                    if crate::ctaphid::is_cancel(&report, channel) {
                        diagnostics::log(
                            Level::Info,
                            "fido",
                            "user_presence_cancelled",
                            format_args!("channel={channel:08x}"),
                        );
                        return Ok(false);
                    }
                    diagnostics::log(
                        Level::Debug,
                        "ctaphid",
                        "report_ignored_while_waiting",
                        format_args!(
                            "channel={:08x} command={:02x}",
                            u32::from_be_bytes(report[0..4].try_into().unwrap()),
                            report[4]
                        ),
                    );
                }
                Ok(0) => return Ok(false),
                Ok(length) => diagnostics::log(
                    Level::Info,
                    "ctaphid",
                    "report_rejected",
                    format_args!("reason=invalid_length length={length}"),
                ),
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) if endpoint_is_gone(&error) => return Ok(false),
                Err(error) => return Err(error),
            }
        }

        if keepalives.tick_due() {
            hid.write_all(&crate::ctaphid::keepalive(
                channel,
                crate::ctaphid::KeepaliveStatus::UserPresenceNeeded,
            ))?;
        }
        thread::sleep(Duration::from_millis(5));
    }
    Ok(false)
}

#[cfg(target_os = "linux")]
fn input_ready(file: &File) -> io::Result<bool> {
    let mut descriptor = PollFd {
        fd: file.as_raw_fd(),
        events: POLLIN,
        revents: 0,
    };
    // SAFETY: `descriptor` points to one valid pollfd for the duration of the call.
    let result = unsafe { poll(&mut descriptor, 1, 0) };
    if result < 0 {
        let error = io::Error::last_os_error();
        if error.kind() == io::ErrorKind::Interrupted {
            return Ok(false);
        }
        return Err(error);
    }
    Ok(result > 0 && descriptor.revents != 0)
}

#[cfg(target_os = "linux")]
fn wait_for_main_activity(
    ep0: &File,
    ccid_interrupt: &File,
    ccid_notification_pending: bool,
) -> io::Result<()> {
    let mut descriptors = [
        PollFd {
            fd: ep0.as_raw_fd(),
            events: POLLIN,
            revents: 0,
        },
        PollFd {
            fd: ccid_interrupt.as_raw_fd(),
            events: POLLOUT,
            revents: 0,
        },
    ];
    let count = if ccid_notification_pending { 2 } else { 1 };
    wait_for_poll(&mut descriptors, count, IDLE_ENDPOINT_WAIT_MS)
}

#[cfg(target_os = "linux")]
fn wait_for_descriptor(file: &File, events: i16, timeout_ms: i32) -> io::Result<()> {
    let mut descriptor = [PollFd {
        fd: file.as_raw_fd(),
        events,
        revents: 0,
    }];
    wait_for_poll(&mut descriptor, 1, timeout_ms)
}

#[cfg(target_os = "linux")]
fn wait_for_poll(descriptors: &mut [PollFd], count: usize, timeout_ms: i32) -> io::Result<()> {
    // SAFETY: `descriptors` contains at least `count` initialized pollfd values.
    let result = unsafe { poll(descriptors.as_mut_ptr(), count, timeout_ms) };
    if result >= 0 {
        return Ok(());
    }
    let error = io::Error::last_os_error();
    if error.kind() == io::ErrorKind::Interrupted {
        Ok(())
    } else {
        Err(error)
    }
}

#[cfg(target_os = "linux")]
fn load_fido_state(serial: u32, path: &Path) -> io::Result<FidoAuthenticator> {
    match fs::read(path) {
        Ok(encoded) => FidoAuthenticator::from_persistent_state(
            serial,
            virtual_yubikey_core::FidoConfiguration::default(),
            &encoded,
        )
        .map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("load persistent FIDO state {}: {error}", path.display()),
            )
        }),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            Ok(FidoAuthenticator::for_serial(serial))
        }
        Err(error) => Err(with_context(error, "read persistent FIDO state")),
    }
}

#[cfg(target_os = "linux")]
fn persist_fido_state(fido: &FidoAuthenticator, path: &Path) -> io::Result<()> {
    let encoded = fido
        .persistent_state()
        .map_err(|error| io::Error::other(format!("encode persistent FIDO state: {error}")))?;
    persist_state(&encoded, path, "FIDO")
}

#[cfg(target_os = "linux")]
fn load_piv_state(serial: u32, path: &Path) -> io::Result<crate::ccid::Device> {
    match fs::read(path) {
        Ok(encoded) => crate::ccid::Device::from_piv_persistent_state(serial, &encoded)
            .inspect(|_| {
                diagnostics::log(
                    Level::Info,
                    "piv",
                    "state_loaded",
                    format_args!("source=persistent bytes={}", encoded.len()),
                );
            })
            .map_err(|error| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("load persistent PIV state {}: {error}", path.display()),
                )
            }),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            diagnostics::log(
                Level::Info,
                "piv",
                "state_loaded",
                format_args!("source=factory"),
            );
            Ok(crate::ccid::Device::new(serial))
        }
        Err(error) => Err(with_context(error, "read persistent PIV state")),
    }
}

#[cfg(target_os = "linux")]
fn persist_piv_state(ccid: &crate::ccid::Device, path: &Path) -> io::Result<()> {
    let encoded = ccid
        .piv_persistent_state()
        .map_err(|error| io::Error::other(format!("encode persistent PIV state: {error}")))?;
    persist_state(&encoded, path, "PIV")?;
    diagnostics::log(
        Level::Info,
        "piv",
        "state_persisted",
        format_args!("bytes={}", encoded.len()),
    );
    Ok(())
}

#[cfg(target_os = "linux")]
fn persist_state(encoded: &[u8], path: &Path, application: &str) -> io::Result<()> {
    let temporary = path.with_extension(format!("tmp-{}", std::process::id()));
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&temporary)
        .map_err(|error| with_context(error, &format!("create temporary {application} state")))?;
    file.write_all(encoded)
        .map_err(|error| with_context(error, &format!("write temporary {application} state")))?;
    file.sync_all()
        .map_err(|error| with_context(error, &format!("sync temporary {application} state")))?;
    drop(file);
    fs::rename(&temporary, path)
        .map_err(|error| with_context(error, &format!("replace persistent {application} state")))?;
    let parent = path.parent().ok_or_else(|| {
        io::Error::other(format!(
            "persistent {application} state has no parent directory"
        ))
    })?;
    File::open(parent)?.sync_all().map_err(|error| {
        with_context(
            error,
            &format!("sync persistent {application} state directory"),
        )
    })
}

#[cfg(target_os = "linux")]
fn ctap_command_name(command: u8) -> &'static str {
    match command {
        0x01 => "make_credential",
        0x02 => "get_assertion",
        0x04 => "get_info",
        0x06 => "client_pin",
        0x07 => "reset",
        0x08 => "get_next_assertion",
        0x09 => "bio_enrollment",
        0x0a => "credential_management",
        0x0b => "selection",
        0x0c => "large_blobs",
        0x0d => "config",
        _ => "unknown",
    }
}

#[cfg(target_os = "linux")]
fn ctap_status_name(status: u8) -> &'static str {
    match status {
        0x00 => "ok",
        0x01 => "invalid_command",
        0x02 => "invalid_parameter",
        0x03 => "invalid_length",
        0x11 => "cbor_unexpected_type",
        0x12 => "invalid_cbor",
        0x14 => "missing_parameter",
        0x27 => "operation_denied",
        0x2d => "keepalive_cancel",
        0x2e => "no_credentials",
        0x31 => "pin_invalid",
        0x32 => "pin_blocked",
        0x33 => "pin_auth_invalid",
        0x35 => "pin_not_set",
        0x36 => "pin_required",
        0x37 => "pin_policy_violation",
        0x7f => "other",
        _ => "unknown",
    }
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

#[cfg(test)]
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

#[cfg(test)]
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

#[cfg(test)]
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
    descriptor.extend_from_slice(&(crate::ccid::MAX_CCID_MESSAGE_LENGTH as u32).to_le_bytes());
    descriptor.extend_from_slice(&[0xff, 0xff, 0, 0, 0, 1]);
    debug_assert_eq!(descriptor.len(), 0x36);
    descriptor
}

#[cfg(test)]
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
