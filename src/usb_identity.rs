//! USB identity derived from the set of physically exposed interfaces.

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
    fn installed_profile_preserves_the_worker_usb_contract() {
        let profile: toml::Value = toml::from_str(PROFILE).unwrap();
        let usb = profile.get("usb").unwrap();
        let worker = profile.get("worker").unwrap();
        assert_eq!(
            worker.get("command").unwrap().as_str(),
            Some("/home/per/virtual-yubikey/target/release/virtual-yubikey-worker")
        );
        assert_eq!(usb.get("vendor_id").unwrap().as_integer(), Some(0x1050));
        assert_eq!(
            usb.get("manufacturer").unwrap().as_str(),
            Some("Virtual USB Gadget")
        );
        assert_eq!(usb.get("bcd_usb").unwrap().as_integer(), Some(0x0200));
        assert_eq!(
            usb.get("product_id").unwrap().as_integer(),
            Some(USB_IDENTITY.product_id() as i64)
        );
        assert_eq!(
            usb.get("bcd_device").unwrap().as_integer(),
            Some(USB_IDENTITY.bcd_device() as i64)
        );
        assert_eq!(
            usb.get("product").unwrap().as_str(),
            Some(USB_IDENTITY.product())
        );
        assert_eq!(usb.get("max_speed").unwrap().as_str(), Some("full-speed"));
        assert_eq!(usb.get("device_class").unwrap().as_integer(), Some(0));
        assert_eq!(usb.get("device_subclass").unwrap().as_integer(), Some(0));
        assert_eq!(usb.get("device_protocol").unwrap().as_integer(), Some(0));
        assert_eq!(usb.get("max_power_ma").unwrap().as_integer(), Some(30));
        assert!(usb.get("serial").is_none());

        let functions = profile.get("functions").unwrap().as_array().unwrap();
        assert_eq!(functions.len(), 2);
        assert_eq!(functions[0].get("type").unwrap().as_str(), Some("hid"));
        assert_eq!(functions[0].get("name").unwrap().as_str(), Some("fido"));
        assert!(functions[0].get("report_descriptor").is_none());
        assert_eq!(
            functions[1].get("type").unwrap().as_str(),
            Some("functionfs")
        );
        assert_eq!(functions[1].get("name").unwrap().as_str(), Some("ccid"));

        let descriptor = functions[0]
            .get("report_descriptor_hex")
            .unwrap()
            .as_str()
            .unwrap()
            .split_whitespace()
            .map(|byte| u8::from_str_radix(byte, 16).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(
            descriptor,
            vec![
                0x06, 0xd0, 0xf1, 0x09, 0x01, 0xa1, 0x01, 0x09, 0x20, 0x15, 0x00, 0x26, 0xff, 0x00,
                0x75, 0x08, 0x95, 0x40, 0x81, 0x02, 0x09, 0x21, 0x15, 0x00, 0x26, 0xff, 0x00, 0x75,
                0x08, 0x95, 0x40, 0x91, 0x02, 0xc0,
            ]
        );
    }
}
