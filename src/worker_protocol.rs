//! Fixed-size, C-friendly lifecycle protocol shared with the generic supervisor.

use std::env;
use std::ffi::c_void;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::net::UnixStream;

unsafe extern "C" {
    fn send(socket: i32, buffer: *const c_void, length: usize, flags: i32) -> isize;
    fn recv(socket: i32, buffer: *mut c_void, length: usize, flags: i32) -> isize;
}

pub(crate) const CONTROL_FD_ENV: &str = "USB_GADGET_CONTROL_FD";
pub(crate) const STATE_DIRECTORY_ENV: &str = "USB_GADGET_STATE_DIRECTORY";
pub(crate) const RUNTIME_DIRECTORY_ENV: &str = "USB_GADGET_RUNTIME_DIRECTORY";
pub(crate) const FUNCTIONFS_CCID_ENV: &str = "USB_GADGET_FUNCTIONFS_CCID";
pub(crate) const HID_FIDO_ENV: &str = "USB_GADGET_HID_FIDO";

const MAGIC: [u8; 4] = *b"UGSP";
const VERSION: u8 = 1;
const PACKET_LENGTH: usize = 8;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub(crate) enum Message {
    ResourcesReady = 0x01,
    UsbAttached = 0x02,
    UsbDetached = 0x03,
    Shutdown = 0x04,
    FunctionFsReady = 0x81,
    ReconnectRequest = 0x82,
    Stopped = 0x83,
    Fatal = 0x84,
}

pub(crate) struct Channel {
    socket: UnixStream,
}

impl Channel {
    pub(crate) fn from_environment() -> io::Result<Self> {
        let value = env::var(CONTROL_FD_ENV).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("missing inherited {CONTROL_FD_ENV}"),
            )
        })?;
        let descriptor = value.parse::<i32>().map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid inherited control descriptor {value:?}"),
            )
        })?;
        if descriptor < 3 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "the inherited control descriptor must be at least 3",
            ));
        }
        Ok(Self {
            // SAFETY: the supervisor transfers this descriptor to exactly one worker.
            socket: unsafe { UnixStream::from_raw_fd(descriptor) },
        })
    }

    pub(crate) fn try_clone(&self) -> io::Result<Self> {
        Ok(Self {
            socket: self.socket.try_clone()?,
        })
    }

    pub(crate) fn send(&mut self, message: Message) -> io::Result<()> {
        let packet = message.encode();
        let length = unsafe {
            send(
                self.socket.as_raw_fd(),
                packet.as_ptr().cast::<c_void>(),
                packet.len(),
                0,
            )
        };
        if length < 0 {
            return Err(io::Error::last_os_error());
        }
        if length as usize != packet.len() {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "worker-control packet was not sent atomically",
            ));
        }
        Ok(())
    }

    pub(crate) fn receive(&mut self) -> io::Result<Message> {
        let mut record = [0_u8; PACKET_LENGTH + 1];
        let length = unsafe {
            recv(
                self.socket.as_raw_fd(),
                record.as_mut_ptr().cast::<c_void>(),
                record.len(),
                0,
            )
        };
        if length < 0 {
            return Err(io::Error::last_os_error());
        }
        if length == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "worker-control channel closed",
            ));
        }
        if length as usize != PACKET_LENGTH {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("worker-control record has invalid length {length}"),
            ));
        }
        Message::decode(record[..PACKET_LENGTH].try_into().unwrap())
    }
}

impl Message {
    fn encode(self) -> [u8; PACKET_LENGTH] {
        [
            MAGIC[0], MAGIC[1], MAGIC[2], MAGIC[3], VERSION, self as u8, 0, 0,
        ]
    }

    fn decode(packet: [u8; PACKET_LENGTH]) -> io::Result<Self> {
        if packet[..4] != MAGIC || packet[4] != VERSION || packet[6..] != [0, 0] {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid worker-control packet header",
            ));
        }
        match packet[5] {
            0x01 => Ok(Self::ResourcesReady),
            0x02 => Ok(Self::UsbAttached),
            0x03 => Ok(Self::UsbDetached),
            0x04 => Ok(Self::Shutdown),
            0x81 => Ok(Self::FunctionFsReady),
            0x82 => Ok(Self::ReconnectRequest),
            0x83 => Ok(Self::Stopped),
            0x84 => Ok(Self::Fatal),
            kind => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unknown worker-control message 0x{kind:02x}"),
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_the_supervisor_wire_fixture() {
        assert_eq!(
            Message::FunctionFsReady.encode(),
            [b'U', b'G', b'S', b'P', 1, 0x81, 0, 0]
        );
        assert_eq!(
            Message::decode([b'U', b'G', b'S', b'P', 1, 0x02, 0, 0]).unwrap(),
            Message::UsbAttached
        );
    }
}
