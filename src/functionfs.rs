//! Unprivileged FunctionFS transport for the virtual YubiKey worker.

#[cfg(target_os = "linux")]
use crate::diagnostics::{self, Level};
#[cfg(target_os = "linux")]
use crate::worker_protocol::{
    validate_initial_resources, Channel, Kind, Record, RUNTIME_DIRECTORY_ENV, STATE_DIRECTORY_ENV,
};
#[cfg(target_os = "linux")]
use crate::STOP_REQUESTED;
#[cfg(target_os = "linux")]
use std::env;
#[cfg(target_os = "linux")]
use std::fs::{self, File, OpenOptions};
#[cfg(target_os = "linux")]
use std::io::{self, Read, Write};
#[cfg(target_os = "linux")]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
#[cfg(target_os = "linux")]
use std::os::unix::net::UnixDatagram;
#[cfg(target_os = "linux")]
use std::path::{Path, PathBuf};
#[cfg(target_os = "linux")]
use std::sync::atomic::Ordering;
#[cfg(target_os = "linux")]
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender, TryRecvError, TrySendError};
#[cfg(target_os = "linux")]
use std::{
    thread,
    time::{Duration, Instant},
};
#[cfg(target_os = "linux")]
use usb_gadget_worker::UsbBusEvent;
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
const ENDPOINT_RETRY_DELAY: Duration = Duration::from_millis(50);
#[cfg(target_os = "linux")]
const FIDO_PRESENCE_BLINK_HALF_PERIOD: Duration = Duration::from_millis(384);
#[cfg(target_os = "linux")]
pub(crate) const USER_PRESENCE_TOUCH: u8 = b'T';

#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum UserPresenceCommand {
    Touch,
}

#[cfg(target_os = "linux")]
impl UserPresenceCommand {
    fn decode(value: u8) -> Option<Self> {
        match value {
            USER_PRESENCE_TOUCH => Some(Self::Touch),
            // Additional command bytes can represent simulated
            // biometric results without changing the IPC transport.
            _ => None,
        }
    }
}

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

    STOP_REQUESTED.store(false, Ordering::Relaxed);
    let control = Channel::from_fixed_descriptor();
    let resources = InitialResources::parse(validate_initial_resources(control.receive()?)?)?;
    let display =
        crate::display::Controller::start(resources.display_spi, resources.display_control)?;
    let state_directory = required_path(STATE_DIRECTORY_ENV)?;
    let runtime_directory = required_path(RUNTIME_DIRECTORY_ENV)?;
    let storage = WorkerStorage {
        fido_state: state_directory.join(format!("fido-{serial}.cbor")),
        piv_state: state_directory.join(format!("piv-{serial}.cbor")),
        touch_socket: runtime_directory.join("touch.sock"),
    };
    let buttons =
        crate::buttons::Controller::start(resources.touch_button, storage.touch_socket.clone())?;
    let fido = load_fido_state(serial, &storage.fido_state)?;
    let ccid = load_piv_state(serial, &storage.piv_state)?;
    let configure_request = 1;
    control.send(&Record::new(
        Kind::Configure,
        0,
        configure_request,
        crate::usb_identity::personality().to_cbor()?,
    ))?;
    let endpoints_record = control.receive()?;
    if endpoints_record.kind == Kind::ConfigurationRejected {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "supervisor rejected USB personality: {}",
                String::from_utf8_lossy(&endpoints_record.body)
            ),
        ));
    }
    if endpoints_record.kind != Kind::UsbEndpoints
        || endpoints_record.generation == 0
        || endpoints_record.request_id != configure_request
    {
        return invalid("expected USB endpoints for the published personality");
    }
    let generation = endpoints_record.generation;
    let endpoints = Endpoints::from_record(endpoints_record)?;
    control.send(&Record::new(
        Kind::Serving,
        generation,
        configure_request,
        Vec::new(),
    ))?;
    diagnostics::log(
        Level::Info,
        "worker",
        "ready",
        format_args!("serial={serial} generation={generation} usb_endpoints=5"),
    );

    let keepalive = crate::keepalive::Scheduler::start()?;
    let activity = display.activity();
    let ccid_notifications =
        endpoints.start(serial, fido, ccid, &storage, &keepalive, &activity)?;
    let result = serve_control(control, generation, ccid_notifications, &display);
    drop(keepalive);
    let button_result = buttons.shutdown();
    let display_result = display.shutdown();
    result.and(button_result).and(display_result)
}

#[cfg(target_os = "linux")]
struct InitialResources {
    display_spi: File,
    display_control: File,
    touch_button: File,
}

#[cfg(target_os = "linux")]
impl InitialResources {
    fn parse(resources: Vec<(String, File)>) -> io::Result<Self> {
        let mut display_spi = None;
        let mut display_control = None;
        let mut touch_button = None;
        for (name, file) in resources {
            let target = match name.as_str() {
                "display-spi" => &mut display_spi,
                "display-control" => &mut display_control,
                "touch-button" => &mut touch_button,
                _ => return invalid(format!("unexpected initial resource {name}")),
            };
            if target.replace(file).is_some() {
                return invalid(format!("duplicate initial resource {name}"));
            }
        }
        Ok(Self {
            display_spi: display_spi.ok_or_else(|| data_error("missing display-spi resource"))?,
            display_control: display_control
                .ok_or_else(|| data_error("missing display-control resource"))?,
            touch_button: touch_button
                .ok_or_else(|| data_error("missing touch-button resource"))?,
        })
    }
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
    fido_out: File,
    fido_in: File,
    ccid_out: File,
    ccid_in: File,
    ccid_interrupt: File,
}

#[cfg(target_os = "linux")]
struct WorkerStorage {
    fido_state: PathBuf,
    piv_state: PathBuf,
    touch_socket: PathBuf,
}

#[cfg(target_os = "linux")]
struct HidRuntime {
    serial: u32,
    state_path: PathBuf,
    touch_socket: PathBuf,
    clock: crate::keepalive::Handle,
    display_activity: crate::display::Activity,
}

#[cfg(target_os = "linux")]
impl Endpoints {
    fn from_record(record: Record) -> io::Result<Self> {
        let count = record
            .body
            .get(..2)
            .ok_or_else(|| data_error("truncated USB endpoint map"))?;
        let count = u16::from_be_bytes(count.try_into().unwrap()) as usize;
        if record.body.len() != 2 + count * 4 || record.files.len() != count {
            return invalid("USB endpoint map and descriptors differ");
        }
        let mut fido_out = None;
        let mut fido_in = None;
        let mut ccid_out = None;
        let mut ccid_in = None;
        let mut ccid_interrupt = None;
        for (entry, file) in record.body[2..].chunks_exact(4).zip(record.files) {
            let address = entry[0];
            let transfer_type = entry[1];
            let packet_size = u16::from_be_bytes(entry[2..4].try_into().unwrap());
            let target = match address {
                crate::usb_identity::FIDO_OUT if transfer_type == 3 && packet_size == 64 => {
                    &mut fido_out
                }
                crate::usb_identity::FIDO_IN if transfer_type == 3 && packet_size == 64 => {
                    &mut fido_in
                }
                crate::usb_identity::CCID_OUT if transfer_type == 2 && packet_size == 64 => {
                    &mut ccid_out
                }
                crate::usb_identity::CCID_IN if transfer_type == 2 && packet_size == 64 => {
                    &mut ccid_in
                }
                crate::usb_identity::CCID_INTERRUPT_IN
                    if transfer_type == 3 && packet_size == 8 =>
                {
                    &mut ccid_interrupt
                }
                _ => {
                    return invalid(format!(
                        "unexpected USB endpoint {address:#04x} type={transfer_type} packet_size={packet_size}"
                    ));
                }
            };
            if target.replace(file).is_some() {
                return invalid(format!("duplicate USB endpoint {address:#04x}"));
            }
        }
        Ok(Self {
            fido_out: required_endpoint(fido_out, "FIDO OUT")?,
            fido_in: required_endpoint(fido_in, "FIDO IN")?,
            ccid_out: required_endpoint(ccid_out, "CCID OUT")?,
            ccid_in: required_endpoint(ccid_in, "CCID IN")?,
            ccid_interrupt: required_endpoint(ccid_interrupt, "CCID interrupt IN")?,
        })
    }

    fn start(
        self,
        serial: u32,
        fido: FidoAuthenticator,
        ccid: crate::ccid::Device,
        storage: &WorkerStorage,
        keepalive: &crate::keepalive::Scheduler,
        display_activity: &crate::display::Activity,
    ) -> io::Result<SyncSender<()>> {
        let Self {
            fido_out,
            fido_in,
            ccid_out,
            ccid_in,
            mut ccid_interrupt,
        } = self;
        let (notification_tx, notification_rx) = mpsc::sync_channel(1);

        thread::Builder::new()
            .name("ccid-notify".to_owned())
            .spawn(move || {
                while notification_rx.recv().is_ok() {
                    if let Err(error) = write_transfer(&mut ccid_interrupt, &[0x50, 0x03]) {
                        if !endpoint_is_gone(&error) {
                            diagnostics::log(
                                Level::Info,
                                "ccid",
                                "notification_failed",
                                format_args!("{error}"),
                            );
                            STOP_REQUESTED.store(true, Ordering::Relaxed);
                            break;
                        }
                    } else {
                        diagnostics::log(
                            Level::Debug,
                            "ccid",
                            "slot_change_notification",
                            format_args!("slot=0 present=true changed=true"),
                        );
                    }
                }
            })?;

        thread::Builder::new().name("ccid-usb".to_owned()).spawn({
            let state_path = storage.piv_state.clone();
            let clock = keepalive.handle();
            let display_activity = display_activity.clone();
            move || {
                if let Err(error) = serve_ccid(
                    ccid_out,
                    ccid_in,
                    ccid,
                    &state_path,
                    clock,
                    display_activity,
                ) {
                    diagnostics::log(
                        Level::Info,
                        "ccid",
                        "transport_failed",
                        format_args!("{error}"),
                    );
                    STOP_REQUESTED.store(true, Ordering::Relaxed);
                }
            }
        })?;

        thread::Builder::new().name("fido-hid".to_owned()).spawn({
            let runtime = HidRuntime {
                serial,
                state_path: storage.fido_state.clone(),
                touch_socket: storage.touch_socket.clone(),
                clock: keepalive.handle(),
                display_activity: display_activity.clone(),
            };
            move || {
                if let Err(error) = serve_hid(fido_out, fido_in, fido, runtime) {
                    diagnostics::log(
                        Level::Info,
                        "ctaphid",
                        "transport_failed",
                        format_args!("{error}"),
                    );
                    STOP_REQUESTED.store(true, Ordering::Relaxed);
                }
            }
        })?;
        Ok(notification_tx)
    }
}

#[cfg(target_os = "linux")]
fn required_endpoint(file: Option<File>, name: &str) -> io::Result<File> {
    file.ok_or_else(|| data_error(format!("missing {name} endpoint")))
}

#[cfg(target_os = "linux")]
fn serve_control(
    control: Channel<'static>,
    generation: u32,
    ccid_notifications: SyncSender<()>,
    display: &crate::display::Controller,
) -> io::Result<()> {
    loop {
        let record = match control.receive() {
            Ok(record) => record,
            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => {
                STOP_REQUESTED.store(true, Ordering::Relaxed);
                return Ok(());
            }
            Err(error) => return Err(error),
        };
        if record.generation != generation || !record.files.is_empty() {
            return invalid("supervisor sent a mismatched runtime record");
        }
        match record.kind {
            Kind::UsbBusEvent if record.request_id == 0 => {
                let (event, activation) = UsbBusEvent::decode(&record.body)?;
                diagnostics::log(
                    Level::Info,
                    "usb",
                    "bus_event",
                    format_args!("event={event:?} activation={activation}"),
                );
                if event == UsbBusEvent::Enable {
                    display.resume()?;
                    match ccid_notifications.try_send(()) {
                        Ok(()) | Err(TrySendError::Full(())) => {}
                        Err(TrySendError::Disconnected(())) => {
                            return Err(io::Error::other("CCID notification endpoint stopped"));
                        }
                    }
                } else if event == UsbBusEvent::Suspend {
                    display.suspend()?;
                } else if event == UsbBusEvent::Resume {
                    display.resume()?;
                }
            }
            Kind::UsbControlRequest if record.request_id != 0 => {
                let response = respond_to_control_request(&record.body)?;
                control.send(&Record::new(
                    Kind::UsbControlResponse,
                    generation,
                    record.request_id,
                    response,
                ))?;
            }
            Kind::Quiesce if record.body.is_empty() => {
                STOP_REQUESTED.store(true, Ordering::Relaxed);
                control.send(&Record::new(
                    Kind::Quiesced,
                    generation,
                    record.request_id,
                    Vec::new(),
                ))?;
                return Ok(());
            }
            Kind::ConfigurationRejected => {
                return invalid(format!(
                    "supervisor rejected USB personality: {}",
                    String::from_utf8_lossy(&record.body)
                ));
            }
            _ => return invalid(format!("unexpected runtime record {:?}", record.kind)),
        }
    }
}

#[cfg(target_os = "linux")]
fn respond_to_control_request(request: &[u8]) -> io::Result<Vec<u8>> {
    let setup: &[u8; 8] = request
        .get(..8)
        .ok_or_else(|| data_error("truncated USB control request"))?
        .try_into()
        .unwrap();
    let request_type = setup[0];
    let request_code = setup[1];
    let value = u16::from_le_bytes(setup[2..4].try_into().unwrap());
    let index = u16::from_le_bytes(setup[4..6].try_into().unwrap());
    let length = u16::from_le_bytes(setup[6..8].try_into().unwrap()) as usize;
    let output = &request[8..];
    if request_type & 0x80 == 0 {
        if output.len() != length {
            return invalid("USB control OUT data length differs from wLength");
        }
    } else if !output.is_empty() {
        return invalid("USB control IN request carries OUT data");
    }

    let answer: Option<Vec<u8>> = match (request_type, request_code, value, index) {
        (0x81, 0x06, 0x2200, interface)
            if interface == crate::usb_identity::FIDO_INTERFACE as u16 =>
        {
            Some(crate::usb_identity::FIDO_REPORT_DESCRIPTOR.to_vec())
        }
        (0x81, 0x06, 0x2100, interface)
            if interface == crate::usb_identity::FIDO_INTERFACE as u16 =>
        {
            Some(crate::usb_identity::FIDO_HID_DESCRIPTOR.to_vec())
        }
        (0xa1, 0x02, _, interface) if interface == crate::usb_identity::FIDO_INTERFACE as u16 => {
            Some(vec![0])
        }
        (0xa1, 0x03, _, interface) if interface == crate::usb_identity::FIDO_INTERFACE as u16 => {
            Some(vec![1])
        }
        (0x21, 0x0a | 0x0b, _, interface)
            if interface == crate::usb_identity::FIDO_INTERFACE as u16 && output.is_empty() =>
        {
            return Ok(vec![1]);
        }
        (0x21, 0x01, _, interface)
            if interface == crate::usb_identity::CCID_INTERFACE as u16 && output.is_empty() =>
        {
            return Ok(vec![1]);
        }
        (0xa1, 0x02, _, interface) if interface == crate::usb_identity::CCID_INTERFACE as u16 => {
            Some(4_000_u32.to_le_bytes().to_vec())
        }
        (0xa1, 0x03, _, interface) if interface == crate::usb_identity::CCID_INTERFACE as u16 => {
            Some(307_200_u32.to_le_bytes().to_vec())
        }
        _ => None,
    };
    match answer {
        Some(mut bytes) => {
            bytes.truncate(length);
            let mut response = Vec::with_capacity(1 + bytes.len());
            response.push(2);
            response.extend_from_slice(&bytes);
            Ok(response)
        }
        None => Ok(vec![0]),
    }
}

#[cfg(target_os = "linux")]
fn serve_ccid(
    mut output: File,
    mut input: File,
    mut ccid: crate::ccid::Device,
    state_path: &Path,
    clock: crate::keepalive::Handle,
    display_activity: crate::display::Activity,
) -> io::Result<()> {
    let mut request = [0_u8; MAX_TRANSFER];
    while !STOP_REQUESTED.load(Ordering::Relaxed) {
        match output.read(&mut request) {
            Ok(0) => {}
            Ok(length) => {
                display_activity.pulse();
                let replies =
                    ccid.receive_with_keepalives(&request[..length], &clock, |keepalive| {
                        write_transfer(&mut input, keepalive)
                    })?;
                if ccid.take_piv_persistent_change() {
                    persist_piv_state(&ccid, state_path)?;
                }
                for reply in replies {
                    write_transfer(&mut input, &reply)?;
                }
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) if endpoint_is_gone(&error) => thread::sleep(ENDPOINT_RETRY_DELAY),
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn serve_hid(
    output: File,
    mut input: File,
    mut fido: FidoAuthenticator,
    runtime: HidRuntime,
) -> io::Result<()> {
    let HidRuntime {
        serial,
        state_path,
        touch_socket,
        clock,
        display_activity,
    } = runtime;
    let reports = start_hid_reader(output)?;
    let mut ctaphid = crate::ctaphid::Device::new(
        virtual_yubikey_core::DeviceProfile::yubikey_5_8_ccid(serial),
    );
    while !STOP_REQUESTED.load(Ordering::Relaxed) {
        let report = match reports.recv_timeout(Duration::from_millis(250)) {
            Ok(Ok(report)) => report,
            Ok(Err(error)) => return Err(error),
            Err(RecvTimeoutError::Timeout) => continue,
            Err(RecvTimeoutError::Disconnected) if STOP_REQUESTED.load(Ordering::Relaxed) => {
                return Ok(())
            }
            Err(RecvTimeoutError::Disconnected) => {
                return Err(io::Error::other("FIDO OUT reader stopped"))
            }
        };
        if !report.is_empty() {
            display_activity.pulse();
        }
        match report.len() {
            0 => {}
            length if length != crate::ctaphid::REPORT_SIZE => {
                diagnostics::log(
                    Level::Info,
                    "ctaphid",
                    "report_rejected",
                    format_args!("reason=invalid_length length={length}"),
                );
            }
            _ => {
                let report: [u8; crate::ctaphid::REPORT_SIZE] = report.try_into().unwrap();
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
                        match wait_for_touch(
                            &mut input,
                            &reports,
                            channel,
                            &touch_socket,
                            &clock,
                            &display_activity,
                        ) {
                            Ok(true) => match exchange_fido_with_keepalives(
                                &mut input, &reports, &mut fido, request, channel, true, &clock,
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
                            &mut input, &reports, &mut fido, request, channel, false, &clock,
                        ) {
                            Ok(response) => response,
                            Err(error) => {
                                command_error = Some(error);
                                vec![0x7f]
                            }
                        }
                    };
                    if fido.take_persistent_change() {
                        if let Err(error) = persist_fido_state(&fido, &state_path) {
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
                    write_transfer(&mut input, &reply)?;
                }
            }
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn start_hid_reader(mut output: File) -> io::Result<Receiver<io::Result<Vec<u8>>>> {
    let (sender, receiver) = mpsc::sync_channel(1);
    thread::Builder::new()
        .name("fido-out".to_owned())
        .spawn(move || {
            let mut report = [0_u8; crate::ctaphid::REPORT_SIZE];
            while !STOP_REQUESTED.load(Ordering::Relaxed) {
                match output.read(&mut report) {
                    Ok(length) => {
                        if sender.send(Ok(report[..length].to_vec())).is_err() {
                            break;
                        }
                    }
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                    Err(error) if endpoint_is_gone(&error) => {
                        thread::sleep(ENDPOINT_RETRY_DELAY);
                    }
                    Err(error) => {
                        let _ = sender.send(Err(error));
                        break;
                    }
                }
            }
        })?;
    Ok(receiver)
}

#[cfg(target_os = "linux")]
fn exchange_fido_with_keepalives(
    input: &mut File,
    reports: &Receiver<io::Result<Vec<u8>>>,
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

        if let Some(report) = try_receive_hid_report(reports)? {
            match report.len() {
                crate::ctaphid::REPORT_SIZE => {
                    let report: &[u8; crate::ctaphid::REPORT_SIZE] =
                        report.as_slice().try_into().unwrap();
                    if crate::ctaphid::is_cancel(report, channel) {
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
                length => diagnostics::log(
                    Level::Info,
                    "ctaphid",
                    "report_rejected",
                    format_args!("reason=invalid_length length={length}"),
                ),
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
            write_transfer(
                &mut *input,
                &crate::ctaphid::keepalive(channel, crate::ctaphid::KeepaliveStatus::Processing),
            )?;
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
    input: &mut File,
    reports: &Receiver<io::Result<Vec<u8>>>,
    channel: u32,
    touch_socket: &Path,
    clock: &crate::keepalive::Handle,
    display_activity: &crate::display::Activity,
) -> io::Result<bool> {
    let touch = TouchSocket::bind(touch_socket)?;
    diagnostics::log(
        Level::Info,
        "fido",
        "user_presence_wait",
        format_args!("channel={channel:08x} socket={}", touch_socket.display()),
    );
    let keepalives = clock.subscribe(Duration::ZERO, HID_KEEPALIVE_INTERVAL)?;
    let _presence_wait = display_activity.wait_for_presence(FIDO_PRESENCE_BLINK_HALF_PERIOD)?;
    let mut signal = [0_u8; 1];

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

        if let Some(report) = try_receive_hid_report(reports)? {
            match report.len() {
                crate::ctaphid::REPORT_SIZE => {
                    let report: &[u8; crate::ctaphid::REPORT_SIZE] =
                        report.as_slice().try_into().unwrap();
                    if crate::ctaphid::is_cancel(report, channel) {
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
                length => diagnostics::log(
                    Level::Info,
                    "ctaphid",
                    "report_rejected",
                    format_args!("reason=invalid_length length={length}"),
                ),
            }
        }

        if keepalives.tick_due() {
            write_transfer(
                &mut *input,
                &crate::ctaphid::keepalive(
                    channel,
                    crate::ctaphid::KeepaliveStatus::UserPresenceNeeded,
                ),
            )?;
        }
        thread::sleep(Duration::from_millis(5));
    }
    Ok(false)
}

#[cfg(target_os = "linux")]
fn try_receive_hid_report(reports: &Receiver<io::Result<Vec<u8>>>) -> io::Result<Option<Vec<u8>>> {
    match reports.try_recv() {
        Ok(Ok(report)) => Ok(Some(report)),
        Ok(Err(error)) => Err(error),
        Err(TryRecvError::Empty) => Ok(None),
        Err(TryRecvError::Disconnected) if STOP_REQUESTED.load(Ordering::Relaxed) => Ok(None),
        Err(TryRecvError::Disconnected) => Err(io::Error::other("FIDO OUT reader stopped")),
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
fn write_transfer(file: &mut File, bytes: &[u8]) -> io::Result<()> {
    loop {
        match file.write(bytes) {
            Ok(length) if length == bytes.len() => return Ok(()),
            Ok(length) => {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    format!(
                        "FunctionFS accepted {length} of {} bytes in one transfer",
                        bytes.len()
                    ),
                ));
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) if endpoint_is_gone(&error) => return Ok(()),
            Err(error) => return Err(error),
        }
    }
}

#[cfg(target_os = "linux")]
fn endpoint_is_gone(error: &io::Error) -> bool {
    matches!(error.raw_os_error(), Some(19 | 32 | 108))
}

#[cfg(target_os = "linux")]
fn invalid<T>(message: impl Into<String>) -> io::Result<T> {
    Err(data_error(message))
}

#[cfg(target_os = "linux")]
fn data_error(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

#[cfg(target_os = "linux")]
fn with_context(error: io::Error, operation: &str) -> io::Error {
    io::Error::new(error.kind(), format!("{operation}: {error}"))
}
