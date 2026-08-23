//! Worker-owned USB identity and descriptor bundle.

use usb_gadget_worker::{StringDescriptor, UsbPersonality, UsbSpeed};

pub(crate) const FIDO_INTERFACE: u8 = 0;
pub(crate) const CCID_INTERFACE: u8 = 1;
pub(crate) const FIDO_OUT: u8 = 0x03;
pub(crate) const FIDO_IN: u8 = 0x83;
pub(crate) const CCID_OUT: u8 = 0x01;
pub(crate) const CCID_IN: u8 = 0x81;
pub(crate) const CCID_INTERRUPT_IN: u8 = 0x82;

pub(crate) const FIDO_REPORT_DESCRIPTOR: [u8; 34] = [
    0x06, 0xd0, 0xf1, 0x09, 0x01, 0xa1, 0x01, 0x09, 0x20, 0x15, 0x00, 0x26, 0xff, 0x00, 0x75, 0x08,
    0x95, 0x40, 0x81, 0x02, 0x09, 0x21, 0x15, 0x00, 0x26, 0xff, 0x00, 0x75, 0x08, 0x95, 0x40, 0x91,
    0x02, 0xc0,
];

pub(crate) const FIDO_HID_DESCRIPTOR: [u8; 9] = [
    9,
    0x21,
    0x11,
    0x01, // HID 1.11
    0,
    1,
    0x22,
    FIDO_REPORT_DESCRIPTOR.len() as u8,
    0,
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct UsbInterfaces {
    otp: bool,
    fido: bool,
    ccid: bool,
}

impl UsbInterfaces {
    pub(crate) const fn fido_ccid() -> Self {
        Self {
            otp: false,
            fido: true,
            ccid: true,
        }
    }

    const fn mask(self) -> u16 {
        (self.otp as u16) | ((self.fido as u16) << 1) | ((self.ccid as u16) << 2)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct UsbIdentity {
    interfaces: UsbInterfaces,
    firmware: [u8; 3],
}

impl UsbIdentity {
    pub(crate) const VENDOR_ID: u16 = 0x1050;

    pub(crate) const fn yubikey_5_8(interfaces: UsbInterfaces) -> Self {
        Self {
            interfaces,
            firmware: [5, 8, 0],
        }
    }

    pub(crate) const fn product_id(self) -> u16 {
        0x0400 | self.interfaces.mask()
    }

    pub(crate) const fn bcd_device(self) -> u16 {
        ((self.firmware[0] as u16) << 8)
            | ((self.firmware[1] as u16) << 4)
            | self.firmware[2] as u16
    }

    pub(crate) const fn product(self) -> &'static str {
        match self.interfaces.mask() {
            0x01 => "Virtual Yubico YubiKey OTP",
            0x02 => "Virtual Yubico YubiKey FIDO",
            0x03 => "Virtual Yubico YubiKey OTP+FIDO",
            0x04 => "Virtual Yubico YubiKey CCID",
            0x05 => "Virtual Yubico YubiKey OTP+CCID",
            0x06 => "Virtual Yubico YubiKey FIDO+CCID",
            0x07 => "Virtual Yubico YubiKey OTP+FIDO+CCID",
            _ => "Virtual Yubico YubiKey",
        }
    }
}

pub(crate) const USB_IDENTITY: UsbIdentity = UsbIdentity::yubikey_5_8(UsbInterfaces::fido_ccid());

pub(crate) fn personality() -> UsbPersonality {
    let identity = USB_IDENTITY;
    let vendor = UsbIdentity::VENDOR_ID.to_le_bytes();
    let product = identity.product_id().to_le_bytes();
    let release = identity.bcd_device().to_le_bytes();
    let device = vec![
        18, 1, 0x00, 0x02, 0, 0, 0, 64, vendor[0], vendor[1], product[0], product[1], release[0],
        release[1], 1, 2, 0, 1,
    ];
    UsbPersonality::new(UsbSpeed::FullSpeed, device, configuration_descriptor())
        .with_string(StringDescriptor::new(0, 0, [4, 3, 0x09, 0x04]))
        .with_string(StringDescriptor::new(
            1,
            0x0409,
            string_descriptor("Virtual USB Gadget"),
        ))
        .with_string(StringDescriptor::new(
            2,
            0x0409,
            string_descriptor(identity.product()),
        ))
}

fn configuration_descriptor() -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&[9, 4, FIDO_INTERFACE, 0, 2, 0x03, 0, 0, 0]);
    body.extend_from_slice(&FIDO_HID_DESCRIPTOR);
    endpoint(&mut body, FIDO_IN, 0x03, 64, 5);
    endpoint(&mut body, FIDO_OUT, 0x03, 64, 5);

    body.extend_from_slice(&[9, 4, CCID_INTERFACE, 0, 3, 0x0b, 0, 0, 0]);
    body.extend_from_slice(&ccid_functional_descriptor());
    endpoint(&mut body, CCID_OUT, 0x02, 64, 0);
    endpoint(&mut body, CCID_IN, 0x02, 64, 0);
    endpoint(&mut body, CCID_INTERRUPT_IN, 0x03, 8, 32);

    let total_length = u16::try_from(9 + body.len()).expect("USB configuration is too large");
    let mut configuration = vec![
        9,
        2,
        total_length as u8,
        (total_length >> 8) as u8,
        2,
        1,
        0,
        0x80,
        15,
    ];
    configuration.extend_from_slice(&body);
    configuration
}

fn endpoint(output: &mut Vec<u8>, address: u8, attributes: u8, size: u16, interval: u8) {
    output.extend_from_slice(&[
        7,
        5,
        address,
        attributes,
        size as u8,
        (size >> 8) as u8,
        interval,
    ]);
}

fn ccid_functional_descriptor() -> Vec<u8> {
    let mut descriptor = vec![
        0x36, 0x21, 0x00, 0x01, // length, type, CCID 1.00
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

fn string_descriptor(value: &str) -> Vec<u8> {
    let words = value.encode_utf16().collect::<Vec<_>>();
    let length = 2 + words.len() * 2;
    let mut descriptor = Vec::with_capacity(length);
    descriptor.push(u8::try_from(length).expect("USB string is too long"));
    descriptor.push(3);
    for word in words {
        descriptor.extend_from_slice(&word.to_le_bytes());
    }
    descriptor
}

#[cfg(test)]
mod tests {
    use super::*;

    const PROFILE: &str = include_str!("../profiles/virtual-yubikey.toml");

    #[test]
    fn identity_is_derived_from_enabled_interfaces_and_firmware() {
        assert_eq!(UsbIdentity::VENDOR_ID, 0x1050);
        assert_eq!(USB_IDENTITY.product_id(), 0x0406);
        assert_eq!(USB_IDENTITY.product(), "Virtual Yubico YubiKey FIDO+CCID");
        assert_eq!(USB_IDENTITY.bcd_device(), 0x0580);
        let composite = UsbIdentity::yubikey_5_8(UsbInterfaces {
            otp: true,
            fido: true,
            ccid: true,
        });
        assert_eq!(composite.product_id(), 0x0407);
        assert_eq!(composite.product(), "Virtual Yubico YubiKey OTP+FIDO+CCID");
    }

    #[test]
    fn worker_publishes_the_complete_composite_personality() {
        let personality = personality();
        assert_eq!(personality.device_descriptor.len(), 18);
        assert_eq!(personality.configuration_descriptor.len(), 125);
        assert_eq!(personality.configuration_descriptor[4], 2);
        assert_eq!(personality.configuration_descriptor[8], 15);
        for address in [FIDO_IN, FIDO_OUT, CCID_OUT, CCID_IN, CCID_INTERRUPT_IN] {
            assert!(personality
                .configuration_descriptor
                .windows(3)
                .any(|bytes| bytes == [7, 5, address]));
        }
        assert!(personality.microsoft_os_1.is_none());
        assert!(personality.webusb.is_none());
    }

    #[test]
    fn installed_profile_contains_launch_display_and_touch_boundaries() {
        let profile: toml::Value = toml::from_str(PROFILE).unwrap();
        assert_eq!(profile.get("schema").unwrap().as_integer(), Some(1));
        assert_eq!(
            profile.get("functionfs_mount").unwrap().as_str(),
            Some("/dev/ffs-virtual-yubikey")
        );
        assert!(profile.get("usb").is_none());
        assert!(profile.get("functions").is_none());
        let resources = profile.get("resources").unwrap().as_array().unwrap();
        assert_eq!(resources.len(), 4);
        assert_eq!(
            resources[0].get("name").unwrap().as_str(),
            Some("display-spi")
        );
        assert_eq!(
            resources[1].get("name").unwrap().as_str(),
            Some("display-control")
        );
        assert_eq!(
            resources[2].get("name").unwrap().as_str(),
            Some("touch-button")
        );
        assert_eq!(
            resources[2].get("offsets").unwrap().as_array().unwrap()[0].as_integer(),
            Some(13)
        );
        assert_eq!(
            resources[2].get("direction").unwrap().as_str(),
            Some("input")
        );
        assert_eq!(
            resources[2].get("active_low").unwrap().as_bool(),
            Some(true)
        );
        assert_eq!(resources[2].get("bias").unwrap().as_str(), Some("pull-up"));
        assert_eq!(resources[2].get("edge").unwrap().as_str(), Some("both"));
        assert_eq!(
            resources[3].get("name").unwrap().as_str(),
            Some("reconnect-button")
        );
        assert_eq!(
            resources[3].get("offsets").unwrap().as_array().unwrap()[0].as_integer(),
            Some(16)
        );
        assert_eq!(
            resources[3].get("direction").unwrap().as_str(),
            Some("input")
        );
        assert_eq!(
            resources[3].get("active_low").unwrap().as_bool(),
            Some(true)
        );
        assert_eq!(resources[3].get("bias").unwrap().as_str(), Some("pull-up"));
        assert_eq!(resources[3].get("edge").unwrap().as_str(), Some("both"));
        assert_eq!(
            profile
                .get("worker")
                .unwrap()
                .get("command")
                .unwrap()
                .as_str(),
            Some("/absolute/path/to/virtual-yubikey-worker")
        );
    }
}
