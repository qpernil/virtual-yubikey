# Shared virtual YubiKey storage

`virtual-yubikey-core::storage` owns the on-disk layout, loading, factory
initialization, exclusive ownership and persistence scheduling for embedded,
USB and future device hosts. Transports supply only their runtime state access
and durability policy. Storage is available on Unix-family targets; ephemeral
core emulation remains independent of it.

## Layout and identity

For serial `12345678`, every host uses these files in its selected directory:

| File | Durable state |
| --- | --- |
| `fido-12345678.cbor` | CTAP2 credentials, U2F wrapping key and global counter, PIN state, retry policy and attestation identity |
| `piv-12345678.cbor` | Keys, objects, PIN/PUK policy and attestation identity |
| `openpgp-12345678.cbor` | Keys, certificates, PIN verifiers, counters, metadata and lifecycle |
| `hsmauth-12345678.cbor` | HSM Auth credentials and management policy |
| `security-domain-12345678.cbor` | SCP keys, certificates, trust policy and attempt budgets |
| `management-12345678.cbor` | Enabled USB application mask and configuration-lock verifier |
| `yubikey-12345678.lock` | Exclusive process ownership; not applet state |

Each file uses its applet's versioned CBOR codec. Transport selection, applet
selection, login authorization, presence grants and secure-channel sessions
are transient. Installed applets and device profile remain host configuration;
USB application enablement is persistent Management state.
Disabled applets retain their stored state. To reuse the directory in another
host, stop its owner and configure the same serial and compatible profile in
the new host. The directory may be relocated without conversion.

Missing applet files are initialized from factory state only after every
existing record validates. Invalid records fail startup and are not replaced.
The loader does not import whole-device `state.cbor` files. Deployments replacing
that layout explicitly clear old virtual YubiKey state; there is no migration
or automatic destructive recovery.

## Runtime and locking

`DeviceStorage::open` acquires the serial's exclusive lock before reading any
records. `DeviceStorage::start` moves that lock into the writer, retaining it
until the writer has finished its final flush and stopped. Embedded and USB
cannot own the same directory and serial concurrently.

One background writer serves all applets in a device. Hosts record dirty applets
after mutations; the shared scheduler batches those notifications and snapshots
only dirty applets. Unchanged applet files are not rewritten. The default policy
batches for at most 500 ms after the first pending mutation. Immediate mode waits
for durable writes before acknowledging an operation. Each replacement uses a
mode-0600 temporary file, file sync, atomic rename and directory sync. Applet
files are independent: a batch is not an atomic transaction across applets.
A write failure fails outstanding receipts and notifies the host.

Embedded hosts protect the core device with a mutex. USB hosts keep separate
FIDO and CCID state locks and route HID and CCID FIDO requests to one shared
authenticator. The FIDO operation coordinator prevents overlapping transport
operations. These runtime ownership choices do not change the stored records.
The writer takes runtime locks only to encode requested applet snapshots.
Commands release runtime state locks before waiting for receipts or flushing,
including FIDO PIN operations routed through CCID. Long-running commands can
delay snapshots. FIDO signature counters, PIN changes/retries, reset, and U2F wrapping-key
mutations and Management configuration writes are flushed before their response;
embedded hosts conservatively flush all FIDO mutations. The USB writer snapshots
Management separately from FIDO and CCID runtime locks.

Hosts flush on quiesce/ejection and join the writer on shutdown. Storage contains
unencrypted virtual private keys and applet credential state; directory access
must be restricted to the device owner. Files do not supply hardware protection.

## Verification

Regression tests reopen identical files through whole-device and split FIDO/CCID
runtimes, preserve OpenPGP keys and retry state across embedded restarts, verify
that only dirty applets are encoded, reject concurrent ownership, and exercise
mutations arriving during a snapshot and writer failures. Corrupt records remain
unchanged, and startup validation does not create missing files when another
record is invalid.
