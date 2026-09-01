//! Unprivileged FunctionFS transport for the virtual YubiKey worker.

#[cfg(target_os = "linux")]
use crate::STOP_REQUESTED;
#[cfg(target_os = "linux")]
use crate::diagnostics::{self, Level};
#[cfg(target_os = "linux")]
use crate::worker_protocol::{
    Channel, Kind, RUNTIME_DIRECTORY_ENV, Record, STATE_DIRECTORY_ENV, validate_initial_resources,
};
#[cfg(target_os = "linux")]
use std::env;
#[cfg(target_os = "linux")]
use std::fs::{self, File};
#[cfg(target_os = "linux")]
use std::io::{self, Read, Write};
#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd;
#[cfg(target_os = "linux")]
use std::path::{Path, PathBuf};
#[cfg(target_os = "linux")]
use std::sync::atomic::Ordering;
#[cfg(target_os = "linux")]
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender, TryRecvError, TrySendError};
#[cfg(target_os = "linux")]
use std::sync::{Arc, Mutex};
#[cfg(target_os = "linux")]
use std::{
    thread,
    time::{Duration, Instant},
};
#[cfg(target_os = "linux")]
use usb_gadget_worker::{
    EndpointLifecycle, MutationReceipt, PersistenceMode, StateLock, StatePersistence,
    StatePersistenceHandle, UsbBusEvent, replace_file_atomically,
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
const CCID_TOUCH_TIMEOUT: Duration = Duration::from_secs(15);
#[cfg(target_os = "linux")]
pub(crate) fn run_worker(
    serial: u32,
    display_kind: crate::cli::DisplayKind,
    persistence_mode: PersistenceMode,
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

    STOP_REQUESTED.store(false, Ordering::Relaxed);
    let control = Channel::from_fixed_descriptor();
    let resources = InitialResources::parse(validate_initial_resources(control.receive()?)?)?;
    let state_directory = required_path(STATE_DIRECTORY_ENV)?;
    let _state_lock = StateLock::acquire(state_directory.join(format!("yubikey-{serial}.lock")))?;
    let display = crate::display::Controller::start(
        resources.display_spi,
        resources.display_control,
        display_kind,
    )?;
    let runtime_directory = required_path(RUNTIME_DIRECTORY_ENV)?;
    let storage = WorkerStorage {
        fido_state: state_directory.join(format!("fido-{serial}.cbor")),
        piv_state: state_directory.join(format!("piv-{serial}.cbor")),
        hsmauth_state: state_directory.join(format!("hsmauth-{serial}.cbor")),
        touch_socket: runtime_directory.join("touch.sock"),
    };
    let fido_persistence = StatePersistence::start(
        load_fido_state(serial, &storage.fido_state)?,
        storage.fido_state.clone(),
        persistence_mode,
        encode_fido_state,
        || STOP_REQUESTED.store(true, Ordering::Relaxed),
    )?;
    let fido = fido_persistence.handle();
    let ccid_state = Arc::new(Mutex::new(load_ccid_state(
        serial,
        &storage.piv_state,
        &storage.hsmauth_state,
    )?));
    let piv_persistence = StatePersistence::start(
        SharedCcidState(Arc::clone(&ccid_state)),
        storage.piv_state.clone(),
        persistence_mode,
        encode_shared_piv_state,
        || STOP_REQUESTED.store(true, Ordering::Relaxed),
    )?;
    let hsmauth_persistence = StatePersistence::start(
        SharedCcidState(Arc::clone(&ccid_state)),
        storage.hsmauth_state.clone(),
        persistence_mode,
        encode_shared_hsmauth_state,
        || STOP_REQUESTED.store(true, Ordering::Relaxed),
    )?;
    let smartcard = CcidPersistenceHandle {
        state: ccid_state,
        piv: piv_persistence.handle(),
        hsmauth: hsmauth_persistence.handle(),
    };
    let buttons = crate::buttons::Controller::start(
        resources.touch_button,
        resources.reconnect_button,
        storage.touch_socket.clone(),
    )?;
    let personality = crate::usb_identity::personality().to_cbor()?;
    let mut configure_request = 1;
    if buttons.reconnect_pressed() {
        diagnostics::log(
            Level::Info,
            "usb",
            "absent_at_startup",
            format_args!("input=key3 pressed=true"),
        );
        control.send(&Record::new(
            Kind::Configure,
            0,
            configure_request,
            Vec::new(),
        ))?;
        if !wait_for_reinsert(&control, 0, &buttons, &personality, &mut configure_request)? {
            let button_result = buttons.shutdown();
            let display_result = display.shutdown();
            return button_result.and(display_result);
        }
    } else {
        control.send(&Record::new(
            Kind::Configure,
            0,
            configure_request,
            personality.clone(),
        ))?;
    }
    let keepalive = crate::keepalive::Scheduler::start()?;
    let activity = display.activity();
    let result = (|| loop {
        let endpoints_record = control.receive()?;
        if endpoints_record.kind == Kind::ConfigurationRejected {
            return invalid(format!(
                "supervisor rejected USB personality: {}",
                String::from_utf8_lossy(&endpoints_record.body)
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
        STOP_REQUESTED.store(false, Ordering::Relaxed);
        let lifecycle = Arc::new(EndpointLifecycle::new());
        let endpoint_runtime = endpoints.start(
            fido.clone(),
            smartcard.clone(),
            EndpointServices {
                serial,
                storage: &storage,
                keepalive: &keepalive,
                display_activity: &activity,
                lifecycle: Arc::clone(&lifecycle),
            },
        )?;
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

        let control_result = serve_control(
            &control,
            generation,
            endpoint_runtime.notifications(),
            &display,
            &buttons,
            &mut configure_request,
            &lifecycle,
        );
        lifecycle.stop();
        let runtime_result = endpoint_runtime.shutdown();
        let fido_flush_result = fido_persistence.flush();
        let piv_flush_result = piv_persistence.flush();
        let hsmauth_flush_result = hsmauth_persistence.flush();
        let outcome = control_result?;
        runtime_result?;
        fido_flush_result?;
        piv_flush_result?;
        hsmauth_flush_result?;
        match outcome {
            ControlOutcome::Quiesce {
                request_id,
                ejected,
            } => {
                control.send(&Record::new(
                    Kind::Quiesced,
                    generation,
                    request_id,
                    Vec::new(),
                ))?;
                if !ejected {
                    return Ok(());
                }
                if !wait_for_reinsert(
                    &control,
                    generation,
                    &buttons,
                    &personality,
                    &mut configure_request,
                )? {
                    return Ok(());
                }
                continue;
            }
            ControlOutcome::Exit => return Ok(()),
        }
    })();
    drop(keepalive);
    let fido_persistence_result = fido_persistence.shutdown();
    let piv_persistence_result = piv_persistence.shutdown();
    let hsmauth_persistence_result = hsmauth_persistence.shutdown();
    let button_result = buttons.shutdown();
    let display_result = display.shutdown();
    result
        .and(fido_persistence_result)
        .and(piv_persistence_result)
        .and(hsmauth_persistence_result)
        .and(button_result)
        .and(display_result)
}

#[cfg(target_os = "linux")]
struct InitialResources {
    display_spi: File,
    display_control: File,
    touch_button: File,
    reconnect_button: File,
}

#[cfg(target_os = "linux")]
impl InitialResources {
    fn parse(resources: Vec<(String, File)>) -> io::Result<Self> {
        let mut display_spi = None;
        let mut display_control = None;
        let mut touch_button = None;
        let mut reconnect_button = None;
        for (name, file) in resources {
            let target = match name.as_str() {
                "display-spi" => &mut display_spi,
                "display-control" => &mut display_control,
                "touch-button" => &mut touch_button,
                "reconnect-button" => &mut reconnect_button,
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
            reconnect_button: reconnect_button
                .ok_or_else(|| data_error("missing reconnect-button resource"))?,
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
    hsmauth_state: PathBuf,
    touch_socket: PathBuf,
}

#[cfg(target_os = "linux")]
#[derive(Clone)]
struct SharedCcidState(Arc<Mutex<crate::ccid::Device>>);

#[cfg(target_os = "linux")]
#[derive(Clone)]
struct CcidPersistenceHandle {
    state: Arc<Mutex<crate::ccid::Device>>,
    piv: StatePersistenceHandle<SharedCcidState>,
    hsmauth: StatePersistenceHandle<SharedCcidState>,
}

#[cfg(target_os = "linux")]
struct EndpointServices<'a> {
    serial: u32,
    storage: &'a WorkerStorage,
    keepalive: &'a crate::keepalive::Scheduler,
    display_activity: &'a crate::display::Activity,
    lifecycle: Arc<EndpointLifecycle>,
}

#[cfg(target_os = "linux")]
struct HidRuntime {
    serial: u32,
    presence: crate::presence::Service,
    clock: crate::keepalive::Handle,
    lifecycle: Arc<EndpointLifecycle>,
}

#[cfg(target_os = "linux")]
struct EndpointRuntime {
    notifications: Option<SyncSender<()>>,
    threads: Vec<thread::JoinHandle<()>>,
}

#[cfg(target_os = "linux")]
impl EndpointRuntime {
    fn notifications(&self) -> &SyncSender<()> {
        self.notifications.as_ref().unwrap()
    }

    fn shutdown(mut self) -> io::Result<()> {
        self.notifications.take();
        for thread in self.threads {
            thread
                .join()
                .map_err(|_| io::Error::other("USB endpoint thread panicked"))?;
        }
        Ok(())
    }
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
        for (entry, file) in record.body[2..].as_chunks::<4>().0.iter().zip(record.files) {
            set_nonblocking(&file)?;
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
        fido: StatePersistenceHandle<FidoAuthenticator>,
        ccid: CcidPersistenceHandle,
        services: EndpointServices<'_>,
    ) -> io::Result<EndpointRuntime> {
        let EndpointServices {
            serial,
            storage,
            keepalive,
            display_activity,
            lifecycle,
        } = services;
        let Self {
            fido_out,
            fido_in,
            ccid_out,
            ccid_in,
            mut ccid_interrupt,
        } = self;
        let (notification_tx, notification_rx) = mpsc::sync_channel(1);
        let presence =
            crate::presence::Service::new(storage.touch_socket.clone(), display_activity.clone());

        let notification_thread = thread::Builder::new()
            .name("ccid-notify".to_owned())
            .spawn(move || {
                while notification_rx.recv().is_ok() {
                    if let Err(error) = write_transfer(&mut ccid_interrupt, &[0x50, 0x03]) {
                        if !endpoint_is_unavailable(&error) {
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

        let ccid_thread = thread::Builder::new().name("ccid-usb".to_owned()).spawn({
            let clock = keepalive.handle();
            let display_activity = display_activity.clone();
            let presence = presence.clone();
            let lifecycle = Arc::clone(&lifecycle);
            move || {
                if let Err(error) = serve_ccid(
                    ccid_out,
                    ccid_in,
                    ccid,
                    presence,
                    clock,
                    display_activity,
                    lifecycle,
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

        let fido_thread = thread::Builder::new().name("fido-hid".to_owned()).spawn({
            let runtime = HidRuntime {
                serial,
                presence,
                clock: keepalive.handle(),
                lifecycle,
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
        Ok(EndpointRuntime {
            notifications: Some(notification_tx),
            threads: vec![notification_thread, ccid_thread, fido_thread],
        })
    }
}

#[cfg(target_os = "linux")]
fn required_endpoint(file: Option<File>, name: &str) -> io::Result<File> {
    file.ok_or_else(|| data_error(format!("missing {name} endpoint")))
}

#[cfg(target_os = "linux")]
enum ControlOutcome {
    Quiesce { request_id: u32, ejected: bool },
    Exit,
}

#[cfg(target_os = "linux")]
fn serve_control(
    control: &Channel<'static>,
    generation: u32,
    ccid_notifications: &SyncSender<()>,
    display: &crate::display::Controller,
    buttons: &crate::buttons::Controller,
    configure_request: &mut u32,
    lifecycle: &EndpointLifecycle,
) -> io::Result<ControlOutcome> {
    let mut unconfiguration_pending = false;
    loop {
        let mut poll_fds = [
            libc::pollfd {
                fd: control.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: buttons.reconnect_descriptor(),
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        // A timeout lets signal and endpoint failures terminate the generation.
        let ready = unsafe { libc::poll(poll_fds.as_mut_ptr(), poll_fds.len() as _, 250) };
        if ready < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }
        if STOP_REQUESTED.load(Ordering::Relaxed) {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "USB endpoint generation stopped",
            ));
        }
        if poll_fds[0].revents == 0 && poll_fds[1].revents == 0 {
            continue;
        }
        if poll_fds[0].revents & libc::POLLIN == 0 {
            let unexpected = poll_fds[0].revents;
            if unexpected != 0 {
                STOP_REQUESTED.store(true, Ordering::Relaxed);
                return if unexpected & libc::POLLHUP != 0 {
                    Ok(ControlOutcome::Exit)
                } else {
                    Err(io::Error::other(format!(
                        "worker-control descriptor reported poll events 0x{unexpected:x}"
                    )))
                };
            }
        } else {
            let record = match control.receive() {
                Ok(record) => record,
                Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => {
                    STOP_REQUESTED.store(true, Ordering::Relaxed);
                    return Ok(ControlOutcome::Exit);
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
                        lifecycle.activate(activation);
                    }
                    if event == UsbBusEvent::Bind {
                        display.bind()?;
                    } else if event == UsbBusEvent::Unbind {
                        display.unbind()?;
                    } else if event == UsbBusEvent::Enable {
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
                    lifecycle.stop();
                    display.unbind()?;
                    return if record.request_id == 0 {
                        Ok(ControlOutcome::Quiesce {
                            request_id: 0,
                            ejected: false,
                        })
                    } else if unconfiguration_pending && record.request_id == *configure_request {
                        Ok(ControlOutcome::Quiesce {
                            request_id: record.request_id,
                            ejected: true,
                        })
                    } else {
                        invalid("supervisor quiesced an unknown configuration request")
                    };
                }
                _ => return invalid(format!("unexpected runtime record {:?}", record.kind)),
            }
        }

        if poll_fds[1].revents & libc::POLLIN != 0
            && !unconfiguration_pending
            && buttons.take_reconnect_state()?
        {
            let request_id = configure_request
                .checked_add(1)
                .ok_or_else(|| io::Error::other("USB configuration request overflow"))?;
            control.send(&Record::new(
                Kind::Configure,
                generation,
                request_id,
                Vec::new(),
            ))?;
            *configure_request = request_id;
            unconfiguration_pending = true;
            diagnostics::log(
                Level::Info,
                "usb",
                "eject_requested",
                format_args!("generation={generation} request={request_id}"),
            );
        }
        let unexpected = poll_fds[1].revents & !libc::POLLIN;
        if unexpected != 0 {
            return Err(io::Error::other(format!(
                "reconnect notification descriptor reported poll events 0x{unexpected:x}"
            )));
        }
    }
}

#[cfg(target_os = "linux")]
fn wait_for_reinsert(
    control: &Channel<'static>,
    generation: u32,
    buttons: &crate::buttons::Controller,
    personality: &[u8],
    configure_request: &mut u32,
) -> io::Result<bool> {
    loop {
        let mut poll_fds = [
            libc::pollfd {
                fd: control.as_raw_fd(),
                events: libc::POLLIN | libc::POLLHUP | libc::POLLERR,
                revents: 0,
            },
            libc::pollfd {
                fd: buttons.reconnect_descriptor(),
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        let ready = unsafe { libc::poll(poll_fds.as_mut_ptr(), poll_fds.len() as _, -1) };
        if ready < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }
        if poll_fds[0].revents != 0 {
            return match control.receive() {
                Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => Ok(false),
                Err(error) => Err(error),
                Ok(record) => invalid(format!(
                    "unexpected supervisor message while USB is ejected: {:?}",
                    record.kind
                )),
            };
        }
        if poll_fds[1].revents & libc::POLLIN != 0 && !buttons.take_reconnect_state()? {
            let request_id = configure_request
                .checked_add(1)
                .ok_or_else(|| io::Error::other("USB configuration request overflow"))?;
            control.send(&Record::new(
                Kind::Configure,
                generation,
                request_id,
                personality.to_vec(),
            ))?;
            *configure_request = request_id;
            diagnostics::log(
                Level::Info,
                "usb",
                "insert_requested",
                format_args!("generation={generation} request={request_id}"),
            );
            return Ok(true);
        }
        let unexpected = poll_fds[1].revents & !libc::POLLIN;
        if unexpected != 0 {
            return Err(io::Error::other(format!(
                "reconnect notification descriptor reported poll events 0x{unexpected:x}"
            )));
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
    ccid: CcidPersistenceHandle,
    presence: crate::presence::Service,
    clock: crate::keepalive::Handle,
    display_activity: crate::display::Activity,
    lifecycle: Arc<EndpointLifecycle>,
) -> io::Result<()> {
    let mut request = [0_u8; MAX_TRANSFER];
    let mut activation = 0;
    while let Some(next_activation) = lifecycle.wait_for_activation_after(activation) {
        activation = next_activation;
        loop {
            if STOP_REQUESTED.load(Ordering::Relaxed) {
                return Ok(());
            }
            match output.read(&mut request) {
                Ok(0) => {}
                Ok(length) => {
                    let _activity = display_activity.begin();
                    let (replies, piv_mutation, hsmauth_mutation) = {
                        let mut state = ccid
                            .state
                            .lock()
                            .map_err(|_| io::Error::other("smart-card state lock poisoned"))?;
                        let replies = state.receive_with_keepalives(
                            &request[..length],
                            &clock,
                            || {
                                presence.wait_for(CCID_TOUCH_TIMEOUT, || {
                                    Ok(if STOP_REQUESTED.load(Ordering::Relaxed) {
                                        crate::presence::WaitControl::Cancel
                                    } else {
                                        crate::presence::WaitControl::Continue
                                    })
                                })
                            },
                            |keepalive| write_transfer(&mut input, keepalive),
                        )?;
                        let piv_mutation = state
                            .take_piv_persistent_change()
                            .then(|| ccid.piv.record_mutation())
                            .transpose()?;
                        let hsmauth_mutation = state
                            .take_hsmauth_persistent_change()
                            .then(|| ccid.hsmauth.record_mutation())
                            .transpose()?;
                        (replies, piv_mutation, hsmauth_mutation)
                    };
                    if let Some(mutation) = piv_mutation {
                        mutation.wait()?;
                    }
                    if let Some(mutation) = hsmauth_mutation {
                        mutation.wait()?;
                    }
                    for reply in replies {
                        write_transfer(&mut input, &reply)?;
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) if endpoint_is_unavailable(&error) => break,
                Err(error) => return Err(error),
            }
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn serve_hid(
    output: File,
    mut input: File,
    fido: StatePersistenceHandle<FidoAuthenticator>,
    runtime: HidRuntime,
) -> io::Result<()> {
    let HidRuntime {
        serial,
        presence,
        clock,
        lifecycle,
    } = runtime;
    let reports = HidReader::start(output, lifecycle)?;
    let result = (|| {
        let receiver = reports.receiver();
        let mut ctaphid = crate::ctaphid::Device::new(
            virtual_yubikey_core::DeviceProfile::yubikey_5_8_ccid(serial),
        );
        while !STOP_REQUESTED.load(Ordering::Relaxed) {
            let report = match receiver.recv_timeout(Duration::from_millis(250)) {
                Ok(Ok(report)) => report,
                Ok(Err(error)) => return Err(error),
                Err(RecvTimeoutError::Timeout) => continue,
                Err(RecvTimeoutError::Disconnected) if STOP_REQUESTED.load(Ordering::Relaxed) => {
                    return Ok(());
                }
                Err(RecvTimeoutError::Disconnected) => {
                    return Err(io::Error::other("FIDO OUT reader stopped"));
                }
            };
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
                    let mut mutation = None;
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
                        if let Some(algorithms) =
                            FidoAuthenticator::make_credential_algorithms(request)
                        {
                            diagnostics::log(
                                Level::Info,
                                "ctap2",
                                "make_credential_algorithms",
                                format_args!("algorithms={algorithms:?}"),
                            );
                        }
                        let selected_algorithm = match fido.state().lock() {
                            Ok(state) => state.selected_make_credential_algorithm(request),
                            Err(_) => {
                                command_error = Some(io::Error::other("FIDO state lock poisoned"));
                                return vec![0x7f];
                            }
                        };
                        if let Some(algorithm) = selected_algorithm {
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
                            match wait_for_touch(&mut input, receiver, channel, &presence, &clock) {
                                Ok(true) => match exchange_persistent_fido_with_keepalives(
                                    &fido, &mut input, receiver, request, channel, true, &clock,
                                ) {
                                    Ok((response, receipt)) => {
                                        mutation = receipt;
                                        response
                                    }
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
                            match exchange_persistent_fido_with_keepalives(
                                &fido, &mut input, receiver, request, channel, false, &clock,
                            ) {
                                Ok((response, receipt)) => {
                                    mutation = receipt;
                                    response
                                }
                                Err(error) => {
                                    command_error = Some(error);
                                    vec![0x7f]
                                }
                            }
                        };
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
                    if let Some(mutation) = mutation {
                        mutation.wait()?;
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
    })();
    let reader_result = reports.shutdown();
    result.and(reader_result)
}

#[cfg(target_os = "linux")]
struct HidReader {
    receiver: Receiver<io::Result<Vec<u8>>>,
    thread: thread::JoinHandle<()>,
}

#[cfg(target_os = "linux")]
impl HidReader {
    fn start(mut output: File, lifecycle: Arc<EndpointLifecycle>) -> io::Result<Self> {
        let (sender, receiver) = mpsc::sync_channel(1);
        let thread = thread::Builder::new()
            .name("fido-out".to_owned())
            .spawn(move || {
                let mut report = [0_u8; crate::ctaphid::REPORT_SIZE];
                let mut activation = 0;
                while let Some(next_activation) = lifecycle.wait_for_activation_after(activation) {
                    activation = next_activation;
                    loop {
                        if STOP_REQUESTED.load(Ordering::Relaxed) {
                            return;
                        }
                        match output.read(&mut report) {
                            Ok(length) => {
                                if sender.send(Ok(report[..length].to_vec())).is_err() {
                                    return;
                                }
                            }
                            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                            Err(error) if endpoint_is_unavailable(&error) => break,
                            Err(error) => {
                                let _ = sender.send(Err(error));
                                return;
                            }
                        }
                    }
                }
            })?;
        Ok(Self { receiver, thread })
    }

    fn receiver(&self) -> &Receiver<io::Result<Vec<u8>>> {
        &self.receiver
    }

    fn shutdown(self) -> io::Result<()> {
        drop(self.receiver);
        self.thread
            .join()
            .map_err(|_| io::Error::other("FIDO OUT reader thread panicked"))
    }
}

#[cfg(target_os = "linux")]
fn exchange_persistent_fido_with_keepalives(
    fido: &StatePersistenceHandle<FidoAuthenticator>,
    input: &mut File,
    reports: &Receiver<io::Result<Vec<u8>>>,
    request: &[u8],
    channel: u32,
    follows_user_presence: bool,
    clock: &crate::keepalive::Handle,
) -> io::Result<(Vec<u8>, Option<MutationReceipt>)> {
    let mut state = fido
        .state()
        .lock()
        .map_err(|_| io::Error::other("FIDO state lock poisoned"))?;
    let response = exchange_fido_with_keepalives(
        input,
        reports,
        &mut state,
        request,
        channel,
        follows_user_presence,
        clock,
    )?;
    let mutation = state
        .take_persistent_change()
        .then(|| fido.record_mutation())
        .transpose()?;
    Ok((response, mutation))
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
fn wait_for_touch(
    input: &mut File,
    reports: &Receiver<io::Result<Vec<u8>>>,
    channel: u32,
    presence: &crate::presence::Service,
    clock: &crate::keepalive::Handle,
) -> io::Result<bool> {
    let keepalives = clock.subscribe(Duration::ZERO, HID_KEEPALIVE_INTERVAL)?;
    presence.wait(|| {
        if STOP_REQUESTED.load(Ordering::Relaxed) {
            return Ok(crate::presence::WaitControl::Cancel);
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
                        return Ok(crate::presence::WaitControl::Cancel);
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
        Ok(crate::presence::WaitControl::Continue)
    })
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
            let fido = FidoAuthenticator::for_serial(serial);
            let encoded = encode_fido_state(&fido)?;
            replace_file_atomically(path, &encoded)
                .map_err(|error| with_context(error, "create initial persistent FIDO state"))?;
            Ok(fido)
        }
        Err(error) => Err(with_context(error, "read persistent FIDO state")),
    }
}

#[cfg(target_os = "linux")]
fn encode_fido_state(fido: &FidoAuthenticator) -> io::Result<Vec<u8>> {
    fido.persistent_state()
        .map_err(|error| io::Error::other(format!("encode persistent FIDO state: {error}")))
}

#[cfg(target_os = "linux")]
fn load_ccid_state(
    serial: u32,
    piv_path: &Path,
    hsmauth_path: &Path,
) -> io::Result<crate::ccid::Device> {
    let factory = crate::ccid::Device::new(serial);
    let piv_factory = encode_piv_state(&factory)?;
    let hsmauth_factory = encode_hsmauth_state(&factory)?;
    let piv = load_applet_state(piv_path, "piv", &piv_factory)?;
    let hsmauth = load_applet_state(hsmauth_path, "hsmauth", &hsmauth_factory)?;
    crate::ccid::Device::from_persistent_states(serial, &piv, &hsmauth).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("load persistent smart-card applet state: {error}"),
        )
    })
}

#[cfg(target_os = "linux")]
fn load_applet_state(path: &Path, applet: &str, factory: &[u8]) -> io::Result<Vec<u8>> {
    match fs::read(path) {
        Ok(encoded) => {
            diagnostics::log(
                Level::Info,
                "smartcard",
                "state_loaded",
                format_args!("applet={applet} source=persistent bytes={}", encoded.len()),
            );
            Ok(encoded)
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            diagnostics::log(
                Level::Info,
                "smartcard",
                "state_loaded",
                format_args!("applet={applet} source=factory"),
            );
            replace_file_atomically(path, factory).map_err(|error| {
                with_context(error, "create initial persistent smart-card applet state")
            })?;
            Ok(factory.to_vec())
        }
        Err(error) => Err(with_context(
            error,
            "read persistent smart-card applet state",
        )),
    }
}

#[cfg(target_os = "linux")]
fn encode_shared_piv_state(state: &SharedCcidState) -> io::Result<Vec<u8>> {
    let ccid = state
        .0
        .lock()
        .map_err(|_| io::Error::other("smart-card state lock poisoned"))?;
    encode_piv_state(&ccid)
}

#[cfg(target_os = "linux")]
fn encode_shared_hsmauth_state(state: &SharedCcidState) -> io::Result<Vec<u8>> {
    let ccid = state
        .0
        .lock()
        .map_err(|_| io::Error::other("smart-card state lock poisoned"))?;
    encode_hsmauth_state(&ccid)
}

#[cfg(target_os = "linux")]
fn encode_piv_state(ccid: &crate::ccid::Device) -> io::Result<Vec<u8>> {
    ccid.piv_persistent_state()
        .map_err(|error| io::Error::other(format!("encode persistent PIV state: {error}")))
}

#[cfg(target_os = "linux")]
fn encode_hsmauth_state(ccid: &crate::ccid::Device) -> io::Result<Vec<u8>> {
    ccid.hsmauth_persistent_state()
        .map_err(|error| io::Error::other(format!("encode persistent YubiHSM Auth state: {error}")))
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
            Err(error) if endpoint_is_unavailable(&error) => return Ok(()),
            Err(error) => return Err(error),
        }
    }
}

#[cfg(target_os = "linux")]
fn endpoint_is_unavailable(error: &io::Error) -> bool {
    matches!(error.raw_os_error(), Some(11 | 19 | 32 | 108))
}

#[cfg(target_os = "linux")]
fn set_nonblocking(file: &File) -> io::Result<()> {
    // FunctionFS continues to block for an enabled transfer. O_NONBLOCK only
    // prevents a new operation from sleeping while its endpoint is disabled.
    let flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFL) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    if unsafe { libc::fcntl(file.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
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
