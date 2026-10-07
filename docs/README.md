# Documentation

- [USB gadget architecture](usb-gadget-architecture.md) - how the host, Pi
  hardware, Linux gadget framework, privileged supervisor, and unprivileged
  Virtual YubiKey, Virtual Trezor, and Virtual YubiHSM profiles fit together.
- [USB application configuration](management.md) - independent U2F/FIDO2
  settings, shared Management bindings, configuration locks and persistence.
- [Applet scope and qualification](applet-roadmap.md) - implemented applets,
  protocol boundaries, remaining gaps and host qualification.
- [PKCS #11 reuse](pkcs11rs-reuse.md) - boundary between the reusable logical
  device, Linux USB transports, and configurable embedded CCID applets.
- [PIV standards and compatibility](piv-conformance.md) - current NIST
  baseline, YubiKey extensions, and explicit conformance gaps.
- [FIDO U2F](u2f.md) - CTAP1 over HID and CCID, wrapped credentials,
  presence, persistence and CTAP2 interoperability.
- [Browser FIDO test](fido-browser-test.md) - reusable WebAuthn fixture, independent
  U2F/FIDO2 runs, physical-touch checks and measured browser behavior.
- [OpenPGP card](openpgp.md) - commands, algorithms, PIN/recovery and touch
  policies, persistent keys, reset, and physical RSA qualification.
- [GlobalPlatform secure messaging](globalplatform-secure-messaging.md) - SCP03
  and SCP11 session behavior, compatibility, and security boundaries.
- [Shared storage](storage.md) - common per-applet format and persistence runtime for every device form.
- [Future storage model](future-storage-model.md) - proposed persistent-storage
  and cross-token key identity design.

The printable version of the USB gadget architecture guide is available as
[PDF](../output/pdf/usb-gadget-architecture.pdf).
