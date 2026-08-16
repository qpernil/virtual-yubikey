//! Privileged Linux USB gadget lifecycle and worker supervision.

use crate::diagnostics::Level;
use crate::usb_identity::{UsbIdentity, USB_IDENTITY};
use crate::STOP_REQUESTED;
use std::env;
use std::ffi::{c_char, c_void, CString};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;
use std::os::raw::{c_int, c_ulong};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{chown, PermissionsExt};
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::Ordering;
use std::thread;
use std::time::Duration;

const CONFIGFS: &str = "/sys/kernel/config";
const GADGET: &str = "/sys/kernel/config/usb_gadget/virtual-yubikey";
pub(crate) const FUNCTIONFS: &str = "/dev/ffs-virtual-yubikey";
pub(crate) const HID_DEVICE: &str = "/dev/hidg0";
const LOCK_FILE: &str = "/run/lock/virtual-yubikey.lock";

const LOCK_EX: c_int = 2;
const LOCK_NB: c_int = 4;
const F_SETFD: c_int = 2;
const PR_SET_PDEATHSIG: c_int = 1;
const PR_SET_NO_NEW_PRIVS: c_int = 38;
const SIGTERM: c_int = 15;

unsafe extern "C" {
    fn geteuid() -> u32;
    fn getppid() -> c_int;
    fn flock(fd: c_int, operation: c_int) -> c_int;
    fn fcntl(fd: c_int, command: c_int, argument: c_int) -> c_int;
    fn kill(pid: c_int, signal: c_int) -> c_int;
    fn mount(
        source: *const c_char,
        target: *const c_char,
        filesystemtype: *const c_char,
        mountflags: c_ulong,
        data: *const c_void,
    ) -> c_int;
    fn prctl(
        option: c_int,
        argument2: c_ulong,
        argument3: c_ulong,
        argument4: c_ulong,
        argument5: c_ulong,
    ) -> c_int;
    fn setgroups(size: usize, groups: *const u32) -> c_int;
    fn setgid(gid: u32) -> c_int;
    fn setuid(uid: u32) -> c_int;
    fn umount2(target: *const c_char, flags: c_int) -> c_int;
}

struct WorkerIdentity {
    name: String,
    uid: u32,
    gid: u32,
}

pub(crate) struct Runtime {
    _lock: File,
    configfs_mounted_by_us: bool,
    owns_gadget: bool,
    mounted_functionfs: bool,
    worker: Option<Child>,
    cleaned: bool,
}

impl Runtime {
    pub(crate) fn setup(
        serial: u32,
        requested_udc: Option<&str>,
        requested_user: Option<&str>,
        log_level: Level,
    ) -> io::Result<Self> {
        // SAFETY: geteuid has no preconditions.
        if unsafe { geteuid() } != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "USB gadget setup needs root (configfs mount/write and UDC binding); run with sudo",
            ));
        }

        let identity = resolve_worker_identity(requested_user)?;
        let lock = acquire_lock()?;
        let configfs_mounted_by_us = ensure_configfs()?;
        let mut runtime = Self {
            _lock: lock,
            configfs_mounted_by_us,
            owns_gadget: false,
            mounted_functionfs: false,
            worker: None,
            cleaned: false,
        };

        runtime.cleanup_stale_state()?;
        fs::create_dir(GADGET)?;
        runtime.owns_gadget = true;
        runtime.populate_gadget()?;

        fs::create_dir_all(FUNCTIONFS)?;
        let mount_options = format!(
            "uid={},gid={},rmode=0500,fmode=0600",
            identity.uid, identity.gid
        );
        mount_filesystem(
            "virtual-yubikey",
            FUNCTIONFS,
            "functionfs",
            Some(&mount_options),
        )?;
        runtime.mounted_functionfs = true;
        let (worker, mut control) = spawn_worker(serial, &identity, log_level)?;
        runtime.worker = Some(worker);

        symlink(
            &format!("{GADGET}/functions/ffs.virtual-yubikey"),
            &format!("{GADGET}/configs/c.1/ffs.virtual-yubikey"),
        )?;
        symlink(
            &format!("{GADGET}/functions/hid.virtual-yubikey"),
            &format!("{GADGET}/configs/c.1/hid.virtual-yubikey"),
        )?;
        let udc = select_udc(requested_udc)?;
        write_attribute(&format!("{GADGET}/UDC"), &udc)?;
        prepare_hid_device(identity.uid, identity.gid)?;
        control.write_all(b"H")?;
        drop(control);
        println!(
            "Virtual YubiKey attached through UDC {udc} as {:04x}:{:04x} ({}); protocol worker is user {}; press Ctrl-C to stop",
            UsbIdentity::VENDOR_ID,
            USB_IDENTITY.product_id(),
            USB_IDENTITY.product(),
            identity.name,
        );
        Ok(runtime)
    }

    pub(crate) fn serve(&mut self) -> io::Result<()> {
        while !STOP_REQUESTED.load(Ordering::Relaxed) {
            let worker = self.worker.as_mut().expect("worker is present after setup");
            if let Some(status) = worker.try_wait()? {
                return Err(io::Error::other(format!(
                    "unprivileged protocol worker exited unexpectedly with {status}"
                )));
            }
            thread::sleep(Duration::from_millis(50));
        }
        Ok(())
    }

    pub(crate) fn cleanup(&mut self) -> io::Result<()> {
        if self.cleaned {
            return Ok(());
        }

        let mut first_error = None;
        if self.owns_gadget {
            record_error(&mut first_error, unbind_gadget());
        }

        record_error(&mut first_error, stop_worker(&mut self.worker));

        if self.mounted_functionfs {
            record_error(
                &mut first_error,
                unmount_filesystem(FUNCTIONFS, "functionfs").map(|_| ()),
            );
            self.mounted_functionfs = false;
        }

        if self.owns_gadget {
            record_error(&mut first_error, remove_gadget_tree());
            self.owns_gadget = false;
        }
        record_error(
            &mut first_error,
            remove_dir_if_exists(Path::new(FUNCTIONFS)),
        );

        if self.configfs_mounted_by_us {
            record_error(
                &mut first_error,
                unmount_filesystem(CONFIGFS, "configfs").map(|_| ()),
            );
            self.configfs_mounted_by_us = false;
        }

        self.cleaned = true;
        match first_error {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    fn cleanup_stale_state(&mut self) -> io::Result<()> {
        if Path::new(GADGET).exists() {
            unbind_gadget()?;
        }
        unmount_filesystem(FUNCTIONFS, "functionfs")?;
        if Path::new(GADGET).exists() {
            remove_gadget_tree()?;
        }
        remove_dir_if_exists(Path::new(FUNCTIONFS))
    }

    fn populate_gadget(&self) -> io::Result<()> {
        // A physical YubiKey enumerates as a USB full-speed device. Capping the
        // composite gadget also keeps endpoint descriptors and host behavior on
        // the same 12 Mbit/s path as the device being emulated.
        write_attribute(&format!("{GADGET}/max_speed"), "full-speed")?;
        write_attribute(
            &format!("{GADGET}/idVendor"),
            &format!("0x{:04x}", UsbIdentity::VENDOR_ID),
        )?;
        write_attribute(
            &format!("{GADGET}/idProduct"),
            &format!("0x{:04x}", USB_IDENTITY.product_id()),
        )?;
        write_attribute(&format!("{GADGET}/bcdUSB"), "0x0200")?;
        write_attribute(
            &format!("{GADGET}/bcdDevice"),
            &format!("0x{:04x}", USB_IDENTITY.bcd_device()),
        )?;
        write_attribute(&format!("{GADGET}/bDeviceClass"), "0x00")?;
        write_attribute(&format!("{GADGET}/bDeviceSubClass"), "0x00")?;
        write_attribute(&format!("{GADGET}/bDeviceProtocol"), "0x00")?;

        fs::create_dir(format!("{GADGET}/strings/0x409"))?;
        // Do not populate the USB iSerialNumber string. Real YubiKeys expose
        // their serial through Management commands rather than the USB device
        // descriptor. The serial passed to the worker remains the logical
        // Management serial.
        write_attribute(&format!("{GADGET}/strings/0x409/manufacturer"), "Yubico")?;
        write_attribute(
            &format!("{GADGET}/strings/0x409/product"),
            USB_IDENTITY.product(),
        )?;

        fs::create_dir(format!("{GADGET}/configs/c.1"))?;
        write_attribute(&format!("{GADGET}/configs/c.1/MaxPower"), "30")?;
        fs::create_dir(format!("{GADGET}/functions/ffs.virtual-yubikey"))?;
        let hid = format!("{GADGET}/functions/hid.virtual-yubikey");
        fs::create_dir(&hid)?;
        write_attribute(&format!("{hid}/protocol"), "0")?;
        write_attribute(&format!("{hid}/subclass"), "0")?;
        write_attribute(&format!("{hid}/report_length"), "64")?;
        fs::write(format!("{hid}/report_desc"), fido_report_descriptor()).map_err(|error| {
            io::Error::new(
                error.kind(),
                format!("write HID report descriptor: {error}"),
            )
        })
    }
}

impl Drop for Runtime {
    fn drop(&mut self) {
        if let Err(error) = self.cleanup() {
            eprintln!("virtual-yubikey: cleanup failed: {error}");
        }
    }
}

fn resolve_worker_identity(requested: Option<&str>) -> io::Result<WorkerIdentity> {
    let name = match requested {
        Some(name) => name.to_owned(),
        None => env::var("SUDO_USER")
            .ok()
            .filter(|name| name != "root" && valid_user_name(name))
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "no unprivileged worker account selected; use --run-as USER",
                )
            })?,
    };
    if !valid_user_name(&name) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid worker user name: {name}"),
        ));
    }

    let uid = query_account_id("-u", &name)?;
    let gid = query_account_id("-g", &name)?;
    if uid == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "the protocol worker account must not be root",
        ));
    }
    Ok(WorkerIdentity { name, uid, gid })
}

fn valid_user_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_.-".contains(&byte))
}

fn query_account_id(flag: &str, name: &str) -> io::Result<u32> {
    let output = Command::new("/usr/bin/id")
        .args([flag, "--", name])
        .output()?;
    if !output.status.success() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("cannot resolve worker account {name:?}"),
        ));
    }
    let value = std::str::from_utf8(&output.stdout)
        .map_err(|_| io::Error::other("id returned non-UTF-8 output"))?
        .trim();
    value
        .parse()
        .map_err(|_| io::Error::other(format!("id returned an invalid numeric ID for {name:?}")))
}

fn spawn_worker(
    serial: u32,
    identity: &WorkerIdentity,
    log_level: Level,
) -> io::Result<(Child, UnixStream)> {
    let executable = env::current_exe()?;
    let (mut supervisor_ready, worker_ready) = UnixStream::pair()?;
    supervisor_ready.set_read_timeout(Some(Duration::from_secs(10)))?;
    let ready_fd = worker_ready.as_raw_fd();
    let parent_pid = std::process::id() as c_int;
    let uid = identity.uid;
    let gid = identity.gid;

    let mut command = Command::new(executable);
    command
        .args([
            "--serial",
            &serial.to_string(),
            "--worker-fd",
            &ready_fd.to_string(),
            "--log-level",
            log_level.as_str(),
        ])
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());

    // SAFETY: this closure calls only libc operations suitable between fork and exec.
    // It clears inherited groups, permanently drops UID/GID, and retains only the
    // readiness descriptor across exec.
    unsafe {
        command.pre_exec(move || {
            if fcntl(ready_fd, F_SETFD, 0) != 0 {
                return Err(io::Error::last_os_error());
            }
            if setgroups(0, std::ptr::null()) != 0 {
                return Err(io::Error::last_os_error());
            }
            if setgid(gid) != 0 {
                return Err(io::Error::last_os_error());
            }
            if setuid(uid) != 0 {
                return Err(io::Error::last_os_error());
            }
            if prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
                return Err(io::Error::last_os_error());
            }
            // Credential changes clear an earlier parent-death signal, so set this last.
            if prctl(PR_SET_PDEATHSIG, SIGTERM as c_ulong, 0, 0, 0) != 0 {
                return Err(io::Error::last_os_error());
            }
            if getppid() != parent_pid {
                return Err(io::Error::from_raw_os_error(32));
            }
            Ok(())
        });
    }

    let mut child = command.spawn()?;
    drop(worker_ready);
    let mut marker = [0_u8; 1];
    if let Err(error) = supervisor_ready.read_exact(&mut marker) {
        let _ = terminate_child(&mut child);
        return Err(io::Error::new(
            error.kind(),
            format!("protocol worker did not become ready: {error}"),
        ));
    }
    if marker != *b"R" {
        let _ = terminate_child(&mut child);
        return Err(io::Error::other(
            "protocol worker sent an invalid readiness message",
        ));
    }
    Ok((child, supervisor_ready))
}

fn prepare_hid_device(uid: u32, gid: u32) -> io::Result<()> {
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        if Path::new(HID_DEVICE).exists() {
            chown(HID_DEVICE, Some(uid), Some(gid)).map_err(|error| {
                io::Error::new(error.kind(), format!("chown {HID_DEVICE}: {error}"))
            })?;
            fs::set_permissions(HID_DEVICE, fs::Permissions::from_mode(0o600)).map_err(
                |error| io::Error::new(error.kind(), format!("chmod {HID_DEVICE}: {error}")),
            )?;
            return Ok(());
        }
        if std::time::Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("{HID_DEVICE} did not appear after binding the gadget"),
            ));
        }
        thread::sleep(Duration::from_millis(10));
    }
}

fn fido_report_descriptor() -> &'static [u8] {
    &[
        0x06, 0xd0, 0xf1, // Usage Page (FIDO Alliance)
        0x09, 0x01, // Usage (Authenticator Device)
        0xa1, 0x01, // Collection (Application)
        0x09, 0x20, // Usage (Input Report Data)
        0x15, 0x00, // Logical Minimum (0)
        0x26, 0xff, 0x00, // Logical Maximum (255)
        0x75, 0x08, // Report Size (8)
        0x95, 0x40, // Report Count (64)
        0x81, 0x02, // Input (Data, Variable, Absolute)
        0x09, 0x21, // Usage (Output Report Data)
        0x15, 0x00, // Logical Minimum (0)
        0x26, 0xff, 0x00, // Logical Maximum (255)
        0x75, 0x08, // Report Size (8)
        0x95, 0x40, // Report Count (64)
        0x91, 0x02, // Output (Data, Variable, Absolute)
        0xc0, // End Collection
    ]
}

fn stop_worker(worker: &mut Option<Child>) -> io::Result<()> {
    match worker.take() {
        Some(mut child) => terminate_child(&mut child),
        None => Ok(()),
    }
}

fn terminate_child(child: &mut Child) -> io::Result<()> {
    if child.try_wait()?.is_none() {
        // SAFETY: this PID belongs to the still-running Child handle.
        if unsafe { kill(child.id() as c_int, SIGTERM) } != 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(3) {
                return Err(error);
            }
        }
    }
    child.wait().map(|_| ())
}

fn acquire_lock() -> io::Result<File> {
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(LOCK_FILE)?;
    // SAFETY: the descriptor remains open in Runtime and operation flags are valid.
    if unsafe { flock(lock.as_raw_fd(), LOCK_EX | LOCK_NB) } != 0 {
        let error = io::Error::last_os_error();
        if error.raw_os_error() == Some(11) {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "another virtual-yubikey instance holds the lifecycle lock",
            ));
        }
        return Err(error);
    }
    Ok(lock)
}

fn ensure_configfs() -> io::Result<bool> {
    fs::create_dir_all(CONFIGFS)?;
    let mut mounted_by_us = false;
    if !is_mounted_as(CONFIGFS, "configfs")? {
        mount_filesystem("none", CONFIGFS, "configfs", None)?;
        mounted_by_us = true;
    }

    let result = (|| {
        if !Path::new(&format!("{CONFIGFS}/usb_gadget")).is_dir() {
            let status = Command::new("modprobe").arg("libcomposite").status()?;
            if !status.success() {
                return Err(io::Error::other(format!(
                    "modprobe libcomposite exited with {status}"
                )));
            }
        }
        if !Path::new(&format!("{CONFIGFS}/usb_gadget")).is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "configfs USB gadget support is unavailable",
            ));
        }
        Ok(mounted_by_us)
    })();

    if result.is_err() && mounted_by_us {
        let _ = unmount_filesystem(CONFIGFS, "configfs");
    }
    result
}

fn select_udc(requested: Option<&str>) -> io::Result<String> {
    let mut available = fs::read_dir("/sys/class/udc")?
        .filter_map(Result::ok)
        .filter_map(|entry| entry.file_name().into_string().ok())
        .collect::<Vec<_>>();
    available.sort();

    if let Some(name) = requested {
        if available.iter().any(|candidate| candidate == name) {
            return Ok(name.to_owned());
        }
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!(
                "requested UDC {name:?} is unavailable; found: {}",
                available.join(", ")
            ),
        ));
    }

    available.into_iter().next().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            "no USB device controller found; enable dwc2 peripheral mode and reboot",
        )
    })
}

fn write_attribute(path: &str, value: &str) -> io::Result<()> {
    fs::write(path, value)
        .map_err(|error| io::Error::new(error.kind(), format!("write {path}: {error}")))
}

fn unbind_gadget() -> io::Result<()> {
    let path = format!("{GADGET}/UDC");
    match fs::write(&path, "\n") {
        Ok(()) => Ok(()),
        Err(error) if error.raw_os_error() == Some(19) => Ok(()),
        Err(error) => Err(io::Error::new(
            error.kind(),
            format!("write {path}: {error}"),
        )),
    }
}

fn remove_gadget_tree() -> io::Result<()> {
    remove_file_if_exists(Path::new(&format!(
        "{GADGET}/configs/c.1/hid.virtual-yubikey"
    )))?;
    remove_file_if_exists(Path::new(&format!(
        "{GADGET}/configs/c.1/ffs.virtual-yubikey"
    )))?;
    remove_dir_if_exists(Path::new(&format!(
        "{GADGET}/functions/ffs.virtual-yubikey"
    )))?;
    remove_dir_if_exists(Path::new(&format!(
        "{GADGET}/functions/hid.virtual-yubikey"
    )))?;
    remove_dir_if_exists(Path::new(&format!("{GADGET}/configs/c.1/strings/0x409")))?;
    remove_dir_if_exists(Path::new(&format!("{GADGET}/configs/c.1")))?;
    remove_dir_if_exists(Path::new(&format!("{GADGET}/strings/0x409")))?;
    remove_dir_if_exists(Path::new(GADGET))
}

fn remove_file_if_exists(path: &Path) -> io::Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

fn remove_dir_if_exists(path: &Path) -> io::Result<()> {
    match fs::remove_dir(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

fn is_mounted_as(target: &str, filesystem: &str) -> io::Result<bool> {
    let mounts = fs::read_to_string("/proc/self/mounts")?;
    Ok(mounts.lines().any(|line| {
        let mut fields = line.split_whitespace();
        let _source = fields.next();
        fields.next() == Some(target) && fields.next() == Some(filesystem)
    }))
}

fn mount_filesystem(
    source: &str,
    target: &str,
    filesystem: &str,
    options: Option<&str>,
) -> io::Result<()> {
    let source = CString::new(source)?;
    let target = CString::new(Path::new(target).as_os_str().as_bytes())?;
    let filesystem = CString::new(filesystem)?;
    let options = options.map(CString::new).transpose()?;
    let data = options
        .as_ref()
        .map_or(std::ptr::null(), |value| value.as_ptr().cast::<c_void>());
    // SAFETY: all C strings are NUL-terminated and pointers live for this call.
    if unsafe {
        mount(
            source.as_ptr(),
            target.as_ptr(),
            filesystem.as_ptr(),
            0,
            data,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn unmount_filesystem(target: &str, filesystem: &str) -> io::Result<bool> {
    if !is_mounted_as(target, filesystem)? {
        return Ok(false);
    }
    let target = CString::new(Path::new(target).as_os_str().as_bytes())?;
    // A regular unmount is intentional: EBUSY protects an active, uncooperative user.
    // SAFETY: target is a valid NUL-terminated mount-point path.
    if unsafe { umount2(target.as_ptr(), 0) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(true)
}

fn symlink(original: &str, link: &str) -> io::Result<()> {
    std::os::unix::fs::symlink(original, link)
}

fn record_error(first_error: &mut Option<io::Error>, result: io::Result<()>) {
    if let Err(error) = result {
        if first_error.is_none() {
            *first_error = Some(error);
        }
    }
}
