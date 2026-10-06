//! Shared per-applet storage for every virtual YubiKey runtime.
//!
//! A directory and serial identify one device. All runtimes use the same files,
//! exclusive lock and durable writer; transport/session state is never stored.
use crate::{DeviceProfile, FidoAuthenticator, FidoConfiguration, VirtualYubiKey};
use software_key_core::state_persistence::{
    MutationReceipt, PersistenceMode, StateLock, StatePersistence, StatePersistenceHandle,
    replace_file_atomically,
};
use std::{
    fs, io,
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicU8, Ordering},
    },
};

/// Default policy shared by embedded and USB hosts.
pub const DEFAULT_PERSISTENCE_MODE: PersistenceMode =
    PersistenceMode::Batched(std::time::Duration::from_millis(500));

/// Durable state components, independent of transport and selected applets.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum PersistentApplet {
    Fido,
    Piv,
    HsmAuth,
    SecurityDomain,
    OpenPgp,
}
impl PersistentApplet {
    pub const ALL: [Self; 5] = [
        Self::Fido,
        Self::Piv,
        Self::HsmAuth,
        Self::SecurityDomain,
        Self::OpenPgp,
    ];
    fn name(self) -> &'static str {
        match self {
            Self::Fido => "fido",
            Self::Piv => "piv",
            Self::HsmAuth => "hsmauth",
            Self::SecurityDomain => "security-domain",
            Self::OpenPgp => "openpgp",
        }
    }
    fn bit(self) -> u8 {
        1 << self as u8
    }
}

impl VirtualYubiKey {
    pub fn persistent_applet(&self, applet: PersistentApplet) -> io::Result<Vec<u8>> {
        match applet {
            PersistentApplet::Fido => self.fido_persistent_state(),
            PersistentApplet::Piv => self.piv_persistent_state(),
            PersistentApplet::HsmAuth => self.hsmauth_persistent_state(),
            PersistentApplet::SecurityDomain => self.security_domain_persistent_state(),
            PersistentApplet::OpenPgp => self.openpgp_persistent_state(),
        }
        .map_err(io::Error::other)
    }
    /// Consume dirty flags without conflating independently stored applets.
    pub fn take_persistent_applets(&mut self) -> Vec<PersistentApplet> {
        let changed = [
            self.take_fido_persistent_change(),
            self.take_piv_persistent_change(),
            self.take_hsmauth_persistent_change(),
            self.take_security_domain_persistent_change(),
            self.take_openpgp_persistent_change(),
        ];
        PersistentApplet::ALL
            .into_iter()
            .zip(changed)
            .filter_map(|(applet, dirty)| dirty.then_some(applet))
            .collect()
    }
    /// Separate the authenticator for runtimes serving FIDO concurrently with
    /// other applets. The returned authenticator is the authoritative FIDO state;
    /// CCID must route FIDO requests to it rather than to the placeholder.
    pub fn separate_fido(mut self) -> (Self, FidoAuthenticator) {
        let placeholder = FidoAuthenticator::for_serial(self.profile.serial);
        let fido = std::mem::replace(&mut self.fido, placeholder);
        (self, fido)
    }
}

/// Exclusively owned device directory, held until the writer finishes.
pub struct DeviceStorage {
    root: PathBuf,
    serial: u32,
    _lock: StateLock,
}
impl DeviceStorage {
    /// Load exactly the common per-applet layout. Missing applets start from
    /// factory state; invalid files fail startup without replacing any state.
    /// Whole-device `state.cbor` records are not imported.
    pub fn open(
        root: &Path,
        profile: DeviceProfile,
        configuration: FidoConfiguration,
    ) -> io::Result<(Self, VirtualYubiKey)> {
        fs::create_dir_all(root)?;
        let storage = Self {
            root: root.to_owned(),
            serial: profile.serial,
            _lock: StateLock::acquire(root.join(format!("yubikey-{}.lock", profile.serial)))?,
        };
        let mut records: [Option<Vec<u8>>; 5] = Default::default();
        for applet in PersistentApplet::ALL {
            records[applet as usize] = match fs::read(storage.path(applet)) {
                Ok(encoded) => Some(encoded),
                Err(error) if error.kind() == io::ErrorKind::NotFound => None,
                Err(error) => return Err(error),
            };
        }
        let missing = records.each_ref().map(Option::is_none);
        let fido = match records[0].as_deref() {
            Some(encoded) => {
                FidoAuthenticator::from_persistent_state(profile.serial, configuration, encoded)
                    .map_err(invalid_state)?
            }
            None => FidoAuthenticator::with_configuration(profile.serial, configuration),
        };
        if missing[0] {
            records[0] = Some(fido.persistent_state().map_err(invalid_state)?);
        }
        if missing[1..].contains(&true) {
            let factory = VirtualYubiKey::new(profile.clone());
            for applet in PersistentApplet::ALL.into_iter().skip(1) {
                if missing[applet as usize] {
                    records[applet as usize] = Some(factory.persistent_applet(applet)?);
                }
            }
        }
        let records = records.map(Option::unwrap);
        let mut device = VirtualYubiKey::from_persistent_states(
            profile.clone(),
            &records[1],
            &records[2],
            &records[3],
        )
        .map_err(invalid_state)?;
        device.fido = fido;
        device
            .restore_openpgp_persistent_state(&records[4])
            .map_err(invalid_state)?;
        // Validate every record before initializing anything on disk.
        for applet in PersistentApplet::ALL {
            if missing[applet as usize] {
                replace_file_atomically(&storage.path(applet), &records[applet as usize])?;
            }
        }
        Ok((storage, device))
    }
    pub fn path(&self, applet: PersistentApplet) -> PathBuf {
        self.root
            .join(format!("{}-{}.cbor", applet.name(), self.serial))
    }

    /// One writer for all applets. The snapshot callback locks only the requested
    /// applet's runtime state. Never wait for durability while holding that lock.
    pub fn start<S, F>(
        self,
        mode: PersistenceMode,
        snapshot: S,
        on_failure: F,
    ) -> io::Result<DevicePersistence>
    where
        S: Fn(PersistentApplet) -> io::Result<Vec<u8>> + Send + 'static,
        F: Fn() + Send + 'static,
    {
        let dirty = Arc::new(AtomicU8::new(0));
        let pending = Pending {
            dirty: dirty.clone(),
            snapshot: Box::new(snapshot),
        };
        let runtime = StatePersistence::start_with_writer(
            pending,
            mode,
            |pending| {
                let dirty = pending.dirty.swap(0, Ordering::AcqRel);
                let mut encoded = Vec::new();
                let mut encoder = minicbor::Encoder::new(&mut encoded);
                encoder
                    .map(dirty.count_ones().into())
                    .map_err(io::Error::other)?;
                for applet in PersistentApplet::ALL {
                    if dirty & applet.bit() != 0 {
                        encoder
                            .u8(applet as u8)
                            .map_err(io::Error::other)?
                            .bytes(&(pending.snapshot)(applet)?)
                            .map_err(io::Error::other)?;
                    }
                }
                Ok(encoded)
            },
            move |encoded| {
                let mut decoder = minicbor::Decoder::new(encoded);
                let count = decoder
                    .map()
                    .map_err(io::Error::other)?
                    .ok_or_else(|| io::Error::other("invalid applet write batch"))?;
                for _ in 0..count {
                    let index = decoder.u8().map_err(io::Error::other)? as usize;
                    let applet = PersistentApplet::ALL
                        .get(index)
                        .ok_or_else(|| io::Error::other("invalid applet write index"))?;
                    let record = decoder.bytes().map_err(io::Error::other)?;
                    replace_file_atomically(&self.path(*applet), record)?;
                }
                // Capture the storage guard, including its lock, for the entire writer lifetime.
                let _ = &self._lock;
                Ok(())
            },
            on_failure,
        )?;
        let handle = DevicePersistenceHandle {
            runtime: runtime.handle(),
            dirty,
        };
        Ok(DevicePersistence { runtime, handle })
    }
}
fn invalid_state(error: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error)
}
struct Pending {
    dirty: Arc<AtomicU8>,
    snapshot: Box<dyn Fn(PersistentApplet) -> io::Result<Vec<u8>> + Send>,
}

/// Single shared background writer, dropped only after runtime state is released.
pub struct DevicePersistence {
    runtime: StatePersistence<Pending>,
    handle: DevicePersistenceHandle,
}
impl DevicePersistence {
    pub fn handle(&self) -> DevicePersistenceHandle {
        self.handle.clone()
    }
    pub fn flush(&self) -> io::Result<()> {
        self.runtime.flush()
    }
    pub fn shutdown(self) -> io::Result<()> {
        self.runtime.shutdown()
    }
}
#[derive(Clone)]
pub struct DevicePersistenceHandle {
    runtime: StatePersistenceHandle<Pending>,
    dirty: Arc<AtomicU8>,
}
impl DevicePersistenceHandle {
    pub fn record_mutations(
        &self,
        applets: impl IntoIterator<Item = PersistentApplet>,
    ) -> io::Result<Option<MutationReceipt>> {
        let mask = applets
            .into_iter()
            .fold(0, |mask, applet| mask | applet.bit());
        if mask == 0 {
            return Ok(None);
        }
        // No runtime-state locks are acquired here, so this is safe inside an
        // applet mutation. The snapshot epoch is captured before dirty flags;
        // concurrent mutations are included here or scheduled for the next batch.
        self.dirty.fetch_or(mask, Ordering::Release);
        self.runtime.record_mutation().map(Some)
    }
    pub fn flush(&self) -> io::Result<()> {
        self.runtime.flush()
    }
    pub fn applet<T>(
        &self,
        applet: PersistentApplet,
        state: Arc<Mutex<T>>,
    ) -> AppletPersistenceHandle<T> {
        AppletPersistenceHandle {
            state,
            applet,
            device: self.clone(),
        }
    }
}
/// Runtime state access plus mutation scheduling for one applet.
pub struct AppletPersistenceHandle<T> {
    state: Arc<Mutex<T>>,
    applet: PersistentApplet,
    device: DevicePersistenceHandle,
}
impl<T> Clone for AppletPersistenceHandle<T> {
    fn clone(&self) -> Self {
        Self {
            state: self.state.clone(),
            applet: self.applet,
            device: self.device.clone(),
        }
    }
}
impl<T> AppletPersistenceHandle<T> {
    pub fn state(&self) -> &Arc<Mutex<T>> {
        &self.state
    }
    pub fn record_mutation(&self) -> io::Result<MutationReceipt> {
        Ok(self.device.record_mutations([self.applet])?.unwrap())
    }
    pub fn flush(&self) -> io::Result<()> {
        self.device.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        sync::{atomic::AtomicU64, mpsc},
        time::Duration,
    };
    static NEXT: AtomicU64 = AtomicU64::new(0);
    struct Directory(PathBuf);
    impl Directory {
        fn new() -> Self {
            let root = std::env::temp_dir().join(format!(
                "yubikey-shared-store-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&root).unwrap();
            Self(root)
        }
        fn open(&self) -> (DeviceStorage, VirtualYubiKey) {
            DeviceStorage::open(
                &self.0,
                DeviceProfile::yubikey_5_8_ccid(42),
                FidoConfiguration::default(),
            )
            .unwrap()
        }
    }
    impl Drop for Directory {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }
    fn select(device: &mut VirtualYubiKey, aid: &[u8]) {
        let mut command = vec![0, 0xa4, 4, 0, aid.len() as u8];
        command.extend_from_slice(aid);
        assert!(device.transmit(&command).ends_with(&[0x90, 0]));
    }
    fn retry(device: &mut VirtualYubiKey) {
        select(device, &crate::OPENPGP_AID);
        assert_eq!(
            device.transmit(&[0, 0x20, 0, 0x81, 6, b'0', b'0', b'0', b'0', b'0', b'0']),
            [0x63, 0xc2]
        );
    }
    #[test]
    fn embedded_and_split_runtime_reopen_identical_applet_files() {
        let directory = Directory::new();
        let (storage, device) = directory.open();
        let state = Arc::new(Mutex::new(device));
        let snapshot = state.clone();
        let runtime = storage
            .start(
                PersistenceMode::Immediate,
                move |applet| snapshot.lock().unwrap().persistent_applet(applet),
                || {},
            )
            .unwrap();
        let handle = runtime.handle();
        let receipt = {
            let mut device = state.lock().unwrap();
            retry(&mut device);
            handle
                .record_mutations(device.take_persistent_applets())
                .unwrap()
                .unwrap()
        };
        receipt.wait().unwrap();
        let expected = PersistentApplet::ALL
            .map(|applet| state.lock().unwrap().persistent_applet(applet).unwrap());
        runtime.shutdown().unwrap();
        let (storage, device) = directory.open();
        let (card, fido) = device.separate_fido();
        let card = Arc::new(Mutex::new(card));
        let fido = Arc::new(Mutex::new(fido));
        let snapshot_card = card.clone();
        let snapshot_fido = fido.clone();
        for applet in PersistentApplet::ALL {
            assert_eq!(
                fs::read(storage.path(applet)).unwrap(),
                expected[applet as usize]
            );
            let actual = if applet == PersistentApplet::Fido {
                fido.lock().unwrap().persistent_state().unwrap()
            } else {
                card.lock().unwrap().persistent_applet(applet).unwrap()
            };
            assert_eq!(actual, expected[applet as usize]);
        }
        let runtime = storage
            .start(
                PersistenceMode::Immediate,
                move |applet| {
                    if applet == PersistentApplet::Fido {
                        snapshot_fido
                            .lock()
                            .unwrap()
                            .persistent_state()
                            .map_err(io::Error::other)
                    } else {
                        snapshot_card.lock().unwrap().persistent_applet(applet)
                    }
                },
                || {},
            )
            .unwrap();
        let receipt = {
            let mut device = card.lock().unwrap();
            select(&mut device, &crate::OPENPGP_AID);
            assert_eq!(
                device.transmit(&[0, 0x20, 0, 0x81, 6, b'0', b'0', b'0', b'0', b'0', b'0']),
                [0x63, 0xc1]
            );
            runtime
                .handle()
                .record_mutations(device.take_persistent_applets())
                .unwrap()
                .unwrap()
        };
        receipt.wait().unwrap();
        runtime.shutdown().unwrap();
        let (_, mut device) = directory.open();
        select(&mut device, &crate::OPENPGP_AID);
        assert_eq!(device.transmit(&[0, 0x20, 0, 0x81]), [0x63, 0xc1]);
    }
    #[test]
    fn dirty_applets_are_batched_without_rewriting_others() {
        let directory = Directory::new();
        let (storage, device) = directory.open();
        let paths = PersistentApplet::ALL.map(|applet| storage.path(applet));
        let before = paths.each_ref().map(|path| fs::read(path).unwrap());
        let snapshots = Arc::new(Mutex::new(Vec::new()));
        let recorded = snapshots.clone();
        let state = Arc::new(Mutex::new(device));
        let snapshot = state.clone();
        let runtime = storage
            .start(
                PersistenceMode::Batched(Duration::from_secs(60)),
                move |applet| {
                    recorded.lock().unwrap().push(applet);
                    snapshot.lock().unwrap().persistent_applet(applet)
                },
                || {},
            )
            .unwrap();
        for _ in 0..100 {
            runtime
                .handle()
                .record_mutations([PersistentApplet::OpenPgp])
                .unwrap();
        }
        runtime.flush().unwrap();
        assert_eq!(*snapshots.lock().unwrap(), [PersistentApplet::OpenPgp]);
        assert_eq!(paths.each_ref().map(|path| fs::read(path).unwrap()), before);
        runtime.shutdown().unwrap();
    }
    #[test]
    fn one_lock_covers_all_runtimes_until_the_writer_stops() {
        let directory = Directory::new();
        let (storage, device) = directory.open();
        assert!(
            DeviceStorage::open(
                &directory.0,
                DeviceProfile::yubikey_5_8_ccid(42),
                FidoConfiguration::default()
            )
            .is_err()
        );
        let runtime = storage
            .start(
                PersistenceMode::Immediate,
                move |applet| device.persistent_applet(applet),
                || {},
            )
            .unwrap();
        assert!(
            DeviceStorage::open(
                &directory.0,
                DeviceProfile::yubikey_5_8_ccid(42),
                FidoConfiguration::default()
            )
            .is_err()
        );
        runtime.shutdown().unwrap();
        drop(directory.open());
    }
    #[test]
    fn corrupt_state_is_not_replaced_and_missing_applets_are_not_created() {
        let directory = Directory::new();
        let (storage, _) = directory.open();
        let corrupt = storage.path(PersistentApplet::OpenPgp);
        let missing = storage.path(PersistentApplet::HsmAuth);
        fs::write(&corrupt, b"corrupt").unwrap();
        fs::remove_file(&missing).unwrap();
        drop(storage);
        assert!(
            DeviceStorage::open(
                &directory.0,
                DeviceProfile::yubikey_5_8_ccid(42),
                FidoConfiguration::default()
            )
            .is_err()
        );
        assert_eq!(fs::read(corrupt).unwrap(), b"corrupt");
        assert!(!missing.exists());
    }
    #[test]
    fn concurrent_mutation_during_snapshot_survives_the_next_batch() {
        let directory = Directory::new();
        let (storage, device) = directory.open();
        let (started_tx, started_rx) = mpsc::channel();
        let (continue_tx, continue_rx) = mpsc::channel();
        let calls = Arc::new(AtomicU64::new(0));
        let called = calls.clone();
        let runtime = storage
            .start(
                PersistenceMode::Immediate,
                move |applet| {
                    if called.fetch_add(1, Ordering::Relaxed) == 0 {
                        started_tx.send(()).unwrap();
                        continue_rx.recv_timeout(Duration::from_secs(5)).unwrap();
                    }
                    device.persistent_applet(applet)
                },
                || {},
            )
            .unwrap();
        let handle = runtime.handle();
        let first = handle
            .record_mutations([PersistentApplet::Piv])
            .unwrap()
            .unwrap();
        started_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        let second = handle
            .record_mutations([PersistentApplet::OpenPgp])
            .unwrap()
            .unwrap();
        continue_tx.send(()).unwrap();
        first.wait().unwrap();
        second.wait().unwrap();
        assert_eq!(calls.load(Ordering::Relaxed), 2);
        runtime.shutdown().unwrap();
    }
    #[test]
    fn write_failure_fails_receipts_and_notifies_the_host() {
        let directory = Directory::new();
        let (storage, device) = directory.open();
        let path = storage.path(PersistentApplet::OpenPgp);
        fs::remove_file(&path).unwrap();
        fs::create_dir(&path).unwrap(); // atomic replacement cannot replace a directory
        let (tx, rx) = mpsc::channel();
        let runtime = storage
            .start(
                PersistenceMode::Immediate,
                move |applet| device.persistent_applet(applet),
                move || {
                    tx.send(()).unwrap();
                },
            )
            .unwrap();
        let handle = runtime.handle();
        assert!(
            handle
                .record_mutations([PersistentApplet::OpenPgp])
                .unwrap()
                .unwrap()
                .wait()
                .is_err()
        );
        rx.recv_timeout(Duration::from_secs(5)).unwrap();
        assert!(handle.record_mutations([PersistentApplet::Piv]).is_err());
        assert!(runtime.shutdown().is_err());
    }
}
