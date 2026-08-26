# USB gadget architecture

This guide explains how Raspberry Pi USB gadget mode presents Virtual YubiKey
to a host, and where the separate `usb-gadget-supervisor` fits. The central
design rule is that the supervisor owns privileged setup and lifecycle, while
ordinary USB payloads travel directly between Linux endpoint files and the
unprivileged worker.

A printable version is available as
[USB gadget architecture (PDF)](../output/pdf/usb-gadget-architecture.pdf).

## System architecture

Solid arrows below carry USB protocol data. Dashed arrows carry configuration
or lifecycle control.

```mermaid
flowchart TB
    subgraph Host["Host computer"]
        Apps["Browser / ykman / yubico-piv-tool"]
        HostUSB["Host USB stack"]
        Apps <--> HostUSB
    end

    HostUSB <== "USB HID and CCID transfers" ==> USBC

    subgraph Hardware["Raspberry Pi hardware"]
        USBC["USB-C connector"]
        DWC2["DWC2 USB device controller (UDC)"]
        USBC <--> DWC2
    end

    DWC2 <==> GadgetCore

    subgraph Kernel["Linux kernel gadget framework"]
        GadgetCore["Composite USB gadget"]
        ConfigFS["ConfigFS identity and composition"]
        FFS["FunctionFS composite function"]
        FFSEps["FunctionFS endpoint files"]

        ConfigFS -. "defines" .-> GadgetCore
        GadgetCore <--> FFS
        FFS <--> FFSEps
    end

    subgraph Userspace["Pi userspace"]
        Systemd["systemd"]
        Profile["Root-owned TOML profile"]
        Supervisor["usb-gadget-supervisor (root)"]
        Worker["virtual-yubikey-worker (unprivileged)"]
        Core["Virtual YubiKey core: FIDO, Management, PIV, YubiHSM Auth"]
        State["Persistent state: /var/lib/virtual-yubikey"]

        Systemd -. "starts and restarts" .-> Supervisor
        Profile -. "launch and resources" .-> Supervisor
        Worker -. "USB personality and control replies" .-> Supervisor
        Supervisor -. "lifecycle and endpoint FDs" .-> Worker
        FFSEps <== "FIDO and CCID packets" ==> Worker
        Worker <--> Core
        Core <--> State
    end

    Supervisor -. "creates and removes gadget" .-> ConfigFS
    Supervisor -. "mounts, publishes, and opens endpoints" .-> FFS
    Supervisor -. "binds and unbinds controller" .-> DWC2
    Supervisor -. "starts with reduced credentials" .-> Worker
```

## Component responsibilities

| Component | Responsibility |
| --- | --- |
| Host USB stack | Discovers the composite USB device and routes HID and CCID transfers to host applications. |
| DWC2 UDC | Implements the Raspberry Pi's USB 2.0 device-side controller on the USB-C connector. |
| ConfigFS | Defines the host-visible device identity, configuration, and ordered functions. |
| FunctionFS | Exposes one userspace composite function containing FIDO HID and CCID endpoints. |
| `usb-gadget-supervisor` | Validates the worker personality, owns ep0/ConfigFS/lifecycle, transfers data endpoints, binds the UDC, and cleans up. |
| `virtual-yubikey-worker` | Publishes its USB personality, answers forwarded setup requests, and implements FIDO and CCID over received endpoint files. |
| `virtual-yubikey-core` | Implements Management, PIV, YubiHSM Auth, FIDO2, credentials, policy, cryptography, and persistent logical state. |

## UDC, ConfigFS, and FunctionFS

These three names describe different layers. They cooperate, but they are not
interchangeable:

```text
UDC        = the physical USB device-side controller and its kernel driver
ConfigFS   = the control surface used to assemble a USB device
FunctionFS = the data/control endpoint surface used to implement a function in userspace
```

An analogy is useful:

- The **UDC is the USB engine and socket**. It sends and receives electrical USB
  packets and exposes hardware endpoints to the Linux gadget framework.
- **ConfigFS is the wiring and identity plan**. It tells the kernel which device
  to build: VID/PID, strings, configurations, functions, interface order, power
  declaration, and the UDC to which the completed gadget should attach.
- **FunctionFS is a service hatch into one function**. The worker declares the
  function's descriptors; the supervisor reformats and publishes them, retains
  ep0, and gives the worker the resulting data endpoint files.

### UDC: the device-side hardware

UDC means **USB Device Controller**. On Raspberry Pi 4 and Pi 5 gadget mode,
this is the DWC2 controller behind the USB-C connector. Its kernel driver deals
with registers, interrupts, FIFOs, DMA, endpoint availability, cable state, and
USB packet transfer. Higher layers do not need to know those hardware details.

Linux lists registered device controllers under `/sys/class/udc`. A controller
being listed means the kernel has a device-side controller available; it does
not mean a gadget is already attached to it.

Only one gadget driver can normally own a given UDC at a time. Writing a UDC
name into a gadget's ConfigFS `UDC` file performs the bind. Writing an empty
string performs the unbind, which appears to the host as a physical USB
disconnect.

### ConfigFS: assemble and activate the device

ConfigFS is a userspace-driven kernel configuration filesystem, normally
mounted at `/sys/kernel/config`. Its directories and attribute files are not
ordinary persistent files. Creating directories and writing attributes creates
and configures live kernel objects.

For a USB gadget, ConfigFS describes questions such as:

- What are the vendor ID, product ID, USB version, and device version?
- What manufacturer and product strings should the host receive?
- Which USB configurations exist?
- Which functions and interfaces belong to each configuration, and in what
  order?
- Which UDC should expose the finished gadget to the host?

A simplified Virtual YubiKey tree looks like this:

```text
/sys/kernel/config/usb_gadget/virtual-yubikey/
├── idVendor                         # 0x1050
├── idProduct                        # 0x0406
├── strings/0x409/manufacturer       # Virtual USB Gadget
├── strings/0x409/product            # Virtual Yubico YubiKey FIDO+CCID
├── functions/
│   ├── hid.fido                     # kernel HID gadget function
│   └── ffs.ccid                     # userspace FunctionFS function
├── configs/c.1/
│   ├── hid.fido -> ../../functions/hid.fido
│   └── ffs.ccid -> ../../functions/ffs.ccid
└── UDC                              # write 1000480000.usb to attach
```

The symbolic links compose the functions into a configuration. Nothing is
host-visible merely because this tree exists. The final write to `UDC` binds
the complete definition to physical device-side hardware and permits host
enumeration.

ConfigFS is therefore primarily a **configuration and lifecycle path**, not a
path through which normal FIDO or CCID packets flow.

The product string deliberately contains the contiguous words `Yubico
YubiKey`. Yubico's PC/SC discovery treats readers without that text as NFC
readers. Keeping it in the visibly virtual product name lets the CCID and HID
interfaces be recognized as transports of the same USB device rather than as
separate NFC and USB devices. Stock Yubico Authenticator computes its visible
model name from the compatibility identity and Management response rather than
from this product string, so it can still display `YubiKey 5A`. The profile is
therefore a local interoperability-test identity, not a claim of product
origin.

### FunctionFS: implement a USB function in userspace

Virtual YubiKey exposes both FIDO HID and CCID through one FunctionFS composite
function. This keeps the USB personality under worker control and gives both
applications the same direct endpoint model.

The supervisor mounts an instance such as:

```text
/dev/ffs-virtual-yubikey/
```

Initially that mount provides `ep0`. At startup the worker constructs a typed
`UsbPersonality` containing device, configuration, HID, CCID, endpoint, and
string descriptors and serializes it as CBOR over the control channel. The
supervisor validates and logs the personality, writes the corresponding
FunctionFS descriptor tables to `ep0`, and opens the generated endpoints:

```text
/dev/ffs-virtual-yubikey/
├── ep0    # setup requests, events, descriptors and control handling
├── ep1..  # FIDO interrupt OUT and IN
└── ep*    # CCID bulk OUT/IN and interrupt IN
```

The supervisor retains `ep0`, translates setup and lifecycle activity into the
versioned worker-control protocol, and transfers only the data endpoints with
`SCM_RIGHTS`. Each endpoint record includes the USB address, transfer type, and
maximum packet size, so the worker validates the semantic map instead of
depending on local `epN` filenames.

Once attached, a host CCID OUT transfer becomes readable bytes on a FunctionFS
endpoint file. A worker write to the corresponding IN endpoint becomes a USB
transfer back to the host. Closing all FunctionFS files disables that function.

### Why both ConfigFS and FunctionFS are necessary here

ConfigFS answers **"what USB device should Linux expose?"** FunctionFS answers
**"which userspace process implements this particular USB function, and how do
its endpoint bytes move?"**

For Virtual YubiKey both applications use the same mechanism:

| Interface | Device composition | Runtime protocol path |
| --- | --- | --- |
| FIDO HID | FunctionFS interface 0 | Interrupt OUT/IN files directly to the worker |
| CCID | FunctionFS interface 1 | Bulk OUT/IN and interrupt IN files directly to the worker |

The worker owns the descriptor contents and runtime behavior. The supervisor
validates and publishes the declaration, opens the USB paths, forwards ep0
requests and lifecycle events, and binds the UDC.

## Supervisor startup sequence

```mermaid
sequenceDiagram
    participant S as systemd
    participant G as Supervisor (root)
    participant K as Linux gadget framework
    participant W as Worker (unprivileged)
    participant H as Host computer

    S->>G: Start service
    G->>G: Validate launch profile and acquire UDC lock
    G->>W: Drop credentials and start worker
    G-->>W: InitialResources
    W-->>G: Configure + UsbPersonality CBOR
    G->>K: Create ConfigFS gadget; mount and publish FunctionFS
    G-->>W: UsbEndpoints + five FunctionFS FDs
    W-->>G: Serving
    G->>K: Link function and write UDC name
    K->>H: Connect and enumerate over USB
    G-->>W: UsbBusEvent and UsbControlRequest
    W-->>G: UsbControlResponse
    H<<->>W: HID and CCID traffic through kernel endpoints
```

The gadget remains unbound while it is incomplete. The host sees it only after
the supervisor has accepted and published the personality and the worker has
validated all five endpoint handles.

## What the supervisor does

The supervisor:

1. Loads and strictly validates the root-owned launch/resource profile.
2. Acquires the global UDC lifecycle lock.
3. Ensures ConfigFS and `libcomposite` are available.
4. Creates the private `AF_UNIX` `SOCK_SEQPACKET` control channel, starts the
   worker with reduced credentials, and sends named initial resources.
5. Receives, validates, and logs the worker's complete USB personality.
6. Creates the unbound ConfigFS gadget, mounts FunctionFS root-only, publishes
   the personality, and opens every generated endpoint.
7. Opens profile-approved local character devices and claims exact GPIO line
   groups.
8. Transfers the typed FunctionFS endpoint map and matching FDs, then waits for
   `Serving`.
9. Links the function and binds the selected UDC.
10. Owns ep0, forwarding USB control requests and lifecycle events while data
    endpoints flow directly between the kernel and worker.
11. On worker exit, unbinds first, cleans the incarnation, and constructs a
    fresh worker process; on service stop it performs final cleanup and exits.

It does not parse CTAP, CCID, APDU, PIN, credential, or private-key data. It is
not an application-level USB proxy.

## Direct USB data paths

FIDO HID and CCID traffic follow the same direct path:

```text
host application
  <-> host USB stack
  <-> USB-C / DWC2 UDC
  <-> Linux FunctionFS
  <-> FunctionFS endpoint files
  <-> virtual-yubikey-worker
```

Neither path crosses the supervisor process. This avoids an extra copy, keeps
latency predictable, and prevents the root process from handling untrusted USB
payloads or cryptographic secrets.

## What the host computer does

USB does not use client/server terminology at its lowest level. The host is the
bus controller and initiates transfers; the Pi is the USB device and responds.
At higher levels there may still be client libraries and server processes such
as `pcscd` or `yubihsm-connector`.

When the supervisor binds the gadget to the UDC, the host detects an attachment
and enumerates it:

1. The host resets the port, assigns a USB address, and reads the device,
   configuration, interface, endpoint, string, HID, and class-specific
   descriptors.
2. The operating system considers each interface independently and chooses an
   appropriate driver or userspace access mechanism.
3. An application talks through that interface's normal host API. It does not
   need to know that the device is implemented by Linux on a Raspberry Pi.
4. The host stack turns API operations into USB transfers. On the Pi, the UDC
   and gadget framework deliver those transfers to FunctionFS endpoint files.

The same composite device can therefore use several host paths at once:

```mermaid
flowchart LR
    subgraph Apps["Host applications"]
        Browser["Browser / WebAuthn / libfido2"]
        SmartcardApp["ykman / yubico-piv-tool"]
        TrezorApp["Trezor Suite / trezorctl"]
        HSMApp["PKCS #11 / yubihsm-shell / SDK"]
    end

    subgraph HostServices["Host APIs, services, and drivers"]
        HIDStack["OS HID/FIDO stack"]
        PCSC["PC/SC client API -> pcscd -> CCID driver"]
        TrezorChoice["WebUSB / native USB<br/>or Trezor Bridge"]
        HSMChoice["libyubihsm USB backend<br/>or yubihsm-connector"]
    end

    Browser --> HIDStack
    SmartcardApp --> PCSC
    TrezorApp --> TrezorChoice
    HSMApp --> HSMChoice

    HIDStack <== "interrupt reports" ==> HIDInterface["FIDO HID interface"]
    PCSC <== "bulk CCID messages" ==> CCIDInterface["CCID interface"]
    TrezorChoice <== "vendor/WebUSB messages" ==> TrezorInterface["Trezor main interface"]
    HSMChoice <== "vendor bulk commands" ==> HSMInterface["YubiHSM interface"]
```

### Case 1: HID, including FIDO/CTAP

The FIDO interface declares USB class `0x03` (HID) and a FIDO usage page in its
HID report descriptor. The operating system's HID machinery discovers it
without a product-specific kernel driver. FIDO software such as a browser,
platform WebAuthn implementation, or `libfido2` uses the operating system's
HID access API.

CTAPHID uses fixed-size reports, commonly 64 bytes for full-speed devices, over
an interrupt OUT endpoint and an interrupt IN endpoint. Larger CTAP messages
are split into an initial packet followed by continuation packets.

```text
browser or FIDO client
  -> WebAuthn / FIDO client stack
  -> host HID API and HID driver
  -> USB interrupt OUT reports
  -> Pi FunctionFS interrupt OUT endpoint
  -> virtual-yubikey-worker
  -> response returns through interrupt IN reports
```

The word "interrupt" does not mean the application is interrupting the device.
It is the USB transfer type: the host polls the endpoint on a bounded schedule.

### Case 2: CCID smart-card traffic

The CCID interface declares USB class `0x0b`. Applications normally do not open
the raw USB interface themselves. They use the cross-platform PC/SC API.

On Linux, `libpcsclite` is the application-side client library, `pcscd` is a
local server daemon, and the CCID driver owns the USB interface. The CCID driver
uses bulk OUT and bulk IN endpoints for commands and responses plus an optional
interrupt IN endpoint for slot-status notifications. Windows and macOS provide
equivalent smart-card middleware.

```text
ykman or yubico-piv-tool
  -> PC/SC API
  -> pcscd / system smart-card service
  -> CCID host driver
  -> USB bulk CCID message
  -> Pi FunctionFS endpoint
  -> virtual-yubikey-worker
  -> CCID framing -> APDU -> Management, PIV, or YubiHSM Auth applet
```

This middleware provides discovery, reader naming, card insertion state,
transactions, and multi-application arbitration. The Pi looks like a CCID
reader containing one permanently inserted smart card.

Each CCID command updates a shared command-active flag and increments a
monotonic activity epoch. The device-neutral indicator scheduler in
`display-backends` samples that state from its dedicated thread and invokes a
YubiKey renderer through a single `set_indicator(bool)` trait method. The
renderer selects between two complete, pre-encoded native frames. The scheduler
therefore has no knowledge of the artwork, backend, or physical display power.

The command epoch preserves one visible transition when a complete command fits
inside a synchronous frame write. Commands arriving while that pulse is visible
may retain one additional pulse; further commands coalesce instead of
accumulating delayed animations. Edges begin at least 8 ms apart, with renderer
time included in that interval rather than added to it; a slower backend
naturally limits the cadence. Sustained command processing uses a 67 ms on,
33 ms off cadence. On completion the YubiKey returns to off after the current
and, if present, single pending pulse. General FIDO HID traffic does not drive
this application-activity indicator.

A scoped physical-presence override blinks for as long as an application is
blocked waiting for touch. It uses the measured YubiKey 5 NFC cadence for every
application: a 384 ms half-period, approximately 1.30 blinks per second. PIV,
FIDO, and YubiHSM Auth use the same protocol-neutral presence service. OpenPGP
can reuse it when that applet is implemented, without teaching the scheduler
which protocol requested presence. USB suspend and worker exit independently
clear the display and turn off its backlight.

The ST7789 and buttons share a HAT but not an I/O path. Display frames use SPI;
GPIO25, GPIO27, and GPIO24 control data/command, reset, and backlight. Separate
active-low event handles expose joystick-center GPIO13 for presence and KEY3
GPIO16 for USB reconnect. A worker thread blocks in `poll` on those handles and
a private shutdown socket, so idle button handling consumes no CPU and never
enters `display-backends`.

Every GPIO edge is drained immediately. A logical rising edge sends the same
one-byte touch command as the local helper, but the destination datagram socket
exists only for the lifetime of the current applet presence wait. Closing a
wait destroys its socket and queued datagrams. Presses made while idle or while
a previous request was active can therefore never approve a later operation.

PIV reports `Always` or `Cached` requirements from the transport-neutral core.
Its applet-local presence client owns the monotonic 15-second cache. The CCID
command thread blocks in the shared physical-presence service while its endpoint
owner continues sending time extensions. FIDO and YubiHSM Auth presence cannot
populate the PIV cache. A touch-required YubiHSM Auth credential always requests
a new touch and uses the same CCID time-extension path.

KEY3 is represented by its sampled current logical level. GPIO edges merely
wake the main worker, and multiple wakes may coalesce without losing the final
pressed/released state. The worker publishes an empty personality with a new
request identifier; it does not
manipulate the display directly. The supervisor unbinds, asks the worker to
quiesce, and waits with no configured USB generation. Quiescing turns the
display off as part of that lifecycle transition. Release makes the worker
publish its complete personality; the supervisor creates and binds that
generation immediately, without imposing the 250 ms floor used by atomic
replacement. Endpoint threads are joined before the worker accepts the new
endpoint files. A canceled endpoint helper parks until a newer `Enable`
activation or quiescence, preventing it from retrying a disabled FunctionFS
endpoint during that join. `Serving` alone leaves the display dark; the idle image returns
on the new generation's `Bind` event. `Disable` leaves it on because the device
remains physically present. The host observes a detach for exactly the physical
hold interval while the worker, initial resource handles, and persistent
authenticator state survive.

### Case 3: Trezor vendor/WebUSB transport

Trezor Suite or `trezorctl` exchanges framed Trezor protocol messages with the
device's main USB interface. Modern host paths can access the vendor/WebUSB
interface directly through browser WebUSB or a native USB transport.

Trezor Bridge is an alternative host-side daemon. It owns access to the USB
device and exposes a local HTTP API to applications or webpages. It remains
useful where WebUSB is unavailable, for older HID-only firmware, or when one
process must coordinate USB ownership across browser domains.

```text
Trezor Suite / trezorctl
  -> direct WebUSB or native USB transport
     OR Trezor Bridge HTTP service
  -> Trezor vendor/WebUSB USB interface
  -> Pi FunctionFS OUT/IN endpoint files
  -> virtual-trezor worker
  -> Trezor message decoder and upstream legacy firmware
```

The proposed Pi worker uses a platform HAL rather than emulating an STM32 CPU.
Its main vendor/WebUSB endpoint traffic goes through FunctionFS. A selected
profile can additionally expose a debug interface or U2F HID interface.

USB carries commands and responses, but physical confirmation remains local to
the virtual appliance: upstream Trezor firmware draws its framebuffer, the Pi
HAL sends it to the attached OLED, and GPIO buttons provide No/Yes input. The
supervisor opens the I2C/SPI bus and claims two exact GPIO v2 line groups: one
output handle for display control and one pollable input/event handle for all
buttons. It closes the broad GPIO-chip descriptor before the worker starts and
passes only the line-request handles. The worker therefore knows semantic bit
positions, not GPIO paths or offsets, and cannot claim additional lines. It
blocks on button events while idle and takes immediate atomic value snapshots
only when firmware behavior needs them. The supervisor does not interpret
wallet screens, buttons, seeds, or signing requests.

### Case 4: vendor-specific bulk USB, such as YubiHSM 2

Bulk is a USB transfer type rather than a complete device class. A
vendor-specific device normally has no generic operating-system protocol stack,
so a userspace library claims its USB interface and talks through a raw USB API
such as `libusb` or WinUSB.

Yubico's direct `libyubihsm` USB backend finds the YubiHSM by VID/PID, claims
interface 0, and uses bulk endpoint `0x01` for OUT and `0x81` for IN. It exposes
this as the `yhusb://` connector URL. In that mode the application process has
direct, normally exclusive access to the USB interface:

```text
yubihsm-shell / yubihsm-pkcs11 / application
  -> libyubihsm with yhusb://
  -> libusb or platform raw-USB backend
  -> USB bulk OUT/IN
  -> virtual YubiHSM FunctionFS endpoints on the Pi
  -> virtual-yubihsm worker
```

Alternatively, `yubihsm-connector` owns the local USB interface and exposes an
HTTP service. Applications use the same `libyubihsm` API with an `http://` or
`https://` connector URL:

```text
local or remote application
  -> libyubihsm HTTP backend
  -> HTTP POST
  -> yubihsm-connector on the USB host
  -> libusb bulk OUT/IN
  -> virtual YubiHSM on the Pi
```

The connector is a server at the HTTP layer and a USB host-side client of the
device protocol. It is optional: direct USB and connector-mediated access are
two alternative host architectures.

A future `virtual-yubihsm-worker` would naturally publish its vendor-specific
personality and read/write its bulk FunctionFS endpoint files. The generic
supervisor would not need YubiHSM knowledge; only the launch profile and worker
would change.

### Host-side comparison

| Device interface | Host-visible class | Usual host access | USB transfers | Pi userspace endpoint |
| --- | --- | --- | --- | --- |
| FIDO HID | HID (`0x03`) | WebAuthn/FIDO stack through OS HID APIs | Interrupt OUT/IN reports | FunctionFS `ep*` |
| CCID | Smart card/CCID (`0x0b`) | PC/SC service and CCID driver | Bulk OUT/IN, optional interrupt IN | FunctionFS `ep*` |
| Trezor main transport | Vendor/WebUSB | WebUSB/native transport or Trezor Bridge | Primarily bulk OUT/IN | FunctionFS `ep*` |
| YubiHSM-style device | Vendor-specific | `libyubihsm`/`libusb`, directly or through a connector | Bulk OUT/IN | FunctionFS `ep*` |

Permissions and ownership also differ. HID and CCID are normally mediated by
operating-system subsystems. Direct vendor USB usually needs an OS rule granting
one account or group access to the raw USB device. If a connector service is
used, only that service account needs raw USB permission.

## The three virtual appliance profiles

The generic supervisor does not run all three identities simultaneously on one
Pi USB-C port. One UDC binds one selected profile and worker at a time:

```mermaid
flowchart TB
    Profile{"Selected root-owned profile"}
    Supervisor["usb-gadget-supervisor"]
    YK["virtual-yubikey-worker"]
    TR["virtual-trezor worker"]
    HSM["virtual-yubihsm worker"]

    Profile --> Supervisor
    Supervisor -->|"FIDO HID + CCID"| YK
    Supervisor -->|"vendor/WebUSB + optional debug/U2F"| TR
    Supervisor -->|"vendor-specific bulk"| HSM
```

| Virtual appliance | Host-facing applications | USB interfaces | Pi endpoint implementation | Device-specific worker responsibility |
| --- | --- | --- | --- | --- |
| Virtual YubiKey | Browser/WebAuthn, `ykman`, `yubico-piv-tool`, `pkcs11rs` | FIDO HID plus CCID | FunctionFS | USB personality, CTAPHID, CCID, Management, PIV, YubiHSM Auth, FIDO2, keys, state, and local activity display |
| Virtual Trezor | Trezor Suite, `trezorctl`, Trezor Connect | Main vendor/WebUSB, optional debug and U2F HID | Primarily FunctionFS; profile-selected HID where appropriate | Trezor framing, legacy firmware, OLED framebuffer, buttons, wallet state |
| Virtual YubiHSM | `yubihsm-shell`, PKCS #11 module, SDKs | Vendor-specific bulk OUT/IN | FunctionFS | YubiHSM sessions, commands, objects, capabilities, audit and state |

The common boundary remains unchanged:

```text
usb-gadget-supervisor
  = root-owned launch/resource profile, personality validation and publication,
    ep0, open data FDs, ConfigFS, UDC, credentials, lifecycle

selected device worker
  = USB personality, control replies, endpoint traffic, protocol, cryptography,
    policy, UI, state
```

The Virtual YubiKey and Virtual Trezor workers implement this resource boundary.
The Trezor host-facing behavior and the future YubiHSM worker must still be
validated against the real applications listed above before compatibility is
claimed.

## UDC discovery and binding

After the `dwc2` overlay is enabled, Linux registers each available USB Device
Controller under:

```text
/sys/class/udc
```

Typical controller names are:

| Board | Typical UDC name |
| --- | --- |
| Raspberry Pi 4 | `fe980000.usb` |
| Raspberry Pi 5 | `1000480000.usb` |

The supervisor reads every directory entry, sorts the names, and selects the
first one. If `--udc NAME` is supplied, it instead requires that exact entry.
It fails closed if no UDC is present. Binding consists of writing the selected
name to:

```text
/sys/kernel/config/usb_gadget/<gadget-name>/UDC
```

More than one UDC is unusual on a standard Pi. It can occur with virtual test
drivers such as `dummy_hcd`, custom carrier hardware, an additional device
controller, or a virtualized test environment. Use `--udc` when selection must
be deterministic in a multi-UDC system.

## Lifecycle and failure containment

The private version-1 `SOCK_SEQPACKET` channel carries 20-byte record headers,
typed bodies, and attached file descriptors via `SCM_RIGHTS`. It never carries
normal USB frames.

```mermaid
stateDiagram-v2
    [*] --> Preparing
    Preparing --> AwaitingPersonality: start worker; send InitialResources
    AwaitingPersonality --> AwaitingWorker: receive Configure; publish/open FunctionFS
    AwaitingWorker --> Binding: send UsbEndpoints; receive Serving
    Binding --> Running: bind UDC
    Running --> Cleaning: worker exit or EOF
    Cleaning --> Preparing: fresh worker incarnation
    Preparing --> FinalCleanup: service stop or setup failure
    AwaitingPersonality --> FinalCleanup: service stop or timeout
    AwaitingWorker --> FinalCleanup: service stop or timeout
    Binding --> FinalCleanup: service stop or bind failure
    Running --> FinalCleanup: service stop
    FinalCleanup --> [*]: UDC unbound and owned resources removed
```

If the worker exits or closes the channel while attached, the supervisor
immediately unbinds the UDC. It then removes that incarnation's resources and
starts a fresh process and USB generation while the supervisor service remains
running. A worker-requested personality change quiesces the current generation,
publishes replacement endpoints, and preserves the worker process; `SIGHUP`
intentionally performs the broader fresh-worker reload.

## Privilege boundary

The supervisor must run as root because ConfigFS creation, FunctionFS mounts,
descriptor publication, endpoint opening, UDC binding, and credential setup are privileged Linux
operations. The protocol worker does not need those privileges.

The worker receives only its validated resource contract: control socket FD 3,
state/runtime paths, already-open USB data endpoints, approved local-device
handles, and exact GPIO line-request handles. The supervisor rejects raw
GPIO-chip resources. Named initial handles and typed endpoint maps arrive over
the control protocol; there are no descriptor-number environment variables.
The worker receives no USB or GPIO paths and needs no device-node ownership
changes. Process exit
closes its descriptor table, releasing every line group and endpoint even after
a crash. Persistent credentials and private keys remain in the worker and its
state directory; they never belong to the supervisor.

This separation limits software privilege exposure. It does not turn a
general-purpose Raspberry Pi into tamper-resistant security hardware.

The underlying `SCM_RIGHTS` capability transfer also exists on macOS, but
macOS does not provide this design's Linux `AF_UNIX/SOCK_SEQPACKET` transport,
ConfigFS, FunctionFS, or UDC gadget mode. Cross-platform tests use a local
datagram socket to exercise descriptor transfer itself.

## Raspberry Pi 4 and Pi 5

The Linux gadget architecture is the same on both boards:

| Aspect | Raspberry Pi 4 | Raspberry Pi 5 |
| --- | --- | --- |
| Gadget connector | On-board USB-C | On-board USB-C |
| Gadget driver | DWC2 | DWC2 |
| Boot setting | `dtoverlay=dwc2,dr_mode=peripheral` | Same |
| Gadget framework | ConfigFS and FunctionFS | Same |
| Typical UDC name | `fe980000.usb` | `1000480000.usb` |

The Pi 5's RP1-connected ordinary USB ports are not the gadget path. The native
SoC DWC2 peripheral function is routed to USB-C. The principal Pi 5 differences
are operational: it needs a stronger power arrangement, and some direct
USB-C-to-USB-C host connections can encounter USB Power Delivery negotiation
problems. A known data-capable cable and an adequately powered connection are
important.

The Virtual YubiKey profile advertises full-speed USB, so Pi 4 and Pi 5 have no
protocol-level performance difference for this device.

## Pi preflight

This deployment is tested on both 64-bit Ubuntu and 64-bit Raspberry Pi OS.
For either system, the normal board-specific setup is simply to enable the
DWC2 controller in peripheral mode. The resulting UDC is the controller that
the supervisor composes through ConfigFS and serves through FunctionFS.

Enable peripheral mode in `/boot/firmware/config.txt`:

```ini
[all]
dtoverlay=dwc2,dr_mode=peripheral
```

Do not load a legacy single-function gadget such as `g_ether`, `g_hid`, or
`g_mass_storage` for the same controller. After rebooting, verify the UDC before
starting the service:

```sh
ls /sys/class/udc
sudo systemctl start usb-gadget-supervisor@virtual-yubikey.service
cat /sys/class/udc/*/state
```

With a working data connection and successful host enumeration, the UDC state
should become `configured`.

## Related documents

- [`usb-gadget-supervisor` architecture](../../usb-gadget-supervisor/docs/architecture.md)
- [`usb-gadget-supervisor` worker protocol](../../usb-gadget-supervisor/docs/worker-protocol.md)
- [Virtual YubiKey README](../README.md)

## Technical references

- [Linux USB gadget ConfigFS documentation](https://docs.kernel.org/usb/gadget_configfs.html)
- [Linux FunctionFS documentation](https://docs.kernel.org/usb/functionfs.html)
- [Linux USB Gadget API](https://docs.kernel.org/driver-api/usb/gadget.html)
- [Raspberry Pi OTG mode application note](https://pip-assets.raspberrypi.com/categories/685-app-notes-guides-whitepapers/documents/RP-009276-WP-1-Using%20OTG%20mode%20on%20Raspberry%20Pi%20SBCs)
- [FIDO Client to Authenticator Protocol specification](https://fidoalliance.org/specifications/)
- [PC/SC Lite architecture](https://pcsclite.apdu.fr/api/)
- [Trezor Bridge](https://github.com/trezor/trezord-go)
- [YubiHSM `libyubihsm` backends](https://docs.yubico.com/hardware/yubihsm-2/hsm-2-user-guide/hsm2-intro-libyubihsm-backend.html)
- [YubiHSM libusb backend source](https://github.com/Yubico/yubihsm-shell/blob/master/lib/yubihsm_libusb.c)
