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
            0x01 => "YubiKey OTP",
            0x02 => "YubiKey FIDO",
            0x03 => "YubiKey OTP+FIDO",
            0x04 => "YubiKey CCID",
            0x05 => "YubiKey OTP+CCID",
            0x06 => "YubiKey FIDO+CCID",
            0x07 => "YubiKey OTP+FIDO+CCID",
            _ => "YubiKey",
        }
    }
}

pub(crate) const USB_IDENTITY: UsbIdentity = UsbIdentity::yubikey_5_8(UsbInterfaces::fido_ccid());

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_is_derived_from_enabled_interfaces_and_firmware() {
        assert_eq!(UsbIdentity::VENDOR_ID, 0x1050);
        assert_eq!(USB_IDENTITY.product_id(), 0x0406);
        assert_eq!(USB_IDENTITY.product(), "YubiKey FIDO+CCID");
        assert_eq!(USB_IDENTITY.bcd_device(), 0x0580);

        let composite = UsbIdentity::yubikey_5_8(UsbInterfaces {
            otp: true,
            fido: true,
            ccid: true,
        });
        assert_eq!(composite.product_id(), 0x0407);
        assert_eq!(composite.product(), "YubiKey OTP+FIDO+CCID");
    }
}
