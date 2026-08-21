//! Fixed-size lifecycle protocol and descriptor transfer from the supervisor.

use std::ffi::c_void;
use std::fs::File;
use std::io;
#[cfg(test)]
use std::os::fd::AsFd;
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
#[cfg(test)]
use std::os::unix::net::UnixStream;

pub(crate) const STATE_DIRECTORY_ENV: &str = "USB_GADGET_STATE_DIRECTORY";
pub(crate) const RUNTIME_DIRECTORY_ENV: &str = "USB_GADGET_RUNTIME_DIRECTORY";
const CONTROL_FD: i32 = 3;

const MAGIC: [u8; 4] = *b"UGSP";
const VERSION: u8 = 1;
const PACKET_LENGTH: usize = 8;
#[cfg(target_os = "linux")]
const RECEIVE_DESCRIPTOR_FLAGS: libc::c_int = libc::MSG_CMSG_CLOEXEC;
#[cfg(not(target_os = "linux"))]
const RECEIVE_DESCRIPTOR_FLAGS: libc::c_int = 0;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub(crate) enum Message {
    PrebindResources = 0x01,
    PostbindResources = 0x02,
    Prepared = 0x81,
    Serving = 0x82,
}

pub(crate) struct Channel<'descriptor> {
    descriptor: BorrowedFd<'descriptor>,
}

impl Channel<'static> {
    pub(crate) fn from_fixed_descriptor() -> Self {
        Self {
            // SAFETY: the supervisor installs FD 3 before exec, and the worker
            // deliberately retains that inherited descriptor until process exit.
            descriptor: unsafe { BorrowedFd::borrow_raw(CONTROL_FD) },
        }
    }
}

impl Channel<'_> {
    pub(crate) fn send(&mut self, message: Message) -> io::Result<()> {
        let packet = message.encode(0);
        let length = unsafe {
            libc::send(
                self.descriptor.as_raw_fd(),
                packet.as_ptr().cast::<c_void>(),
                packet.len(),
                libc::MSG_NOSIGNAL,
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

    pub(crate) fn receive_files(
        &mut self,
        expected_message: Message,
        expected_count: usize,
    ) -> io::Result<Vec<File>> {
        let control_length = if expected_count == 0 {
            0
        } else {
            unsafe {
                libc::CMSG_SPACE(
                    (expected_count * std::mem::size_of::<libc::c_int>()) as libc::c_uint,
                ) as usize
            }
        };
        let mut control = vec![0_u8; control_length];
        let mut record = [0_u8; PACKET_LENGTH + 1];
        let mut iovec = libc::iovec {
            iov_base: record.as_mut_ptr().cast::<c_void>(),
            iov_len: record.len(),
        };
        let mut header: libc::msghdr = unsafe { std::mem::zeroed() };
        header.msg_iov = &mut iovec;
        header.msg_iovlen = 1;
        if !control.is_empty() {
            header.msg_control = control.as_mut_ptr().cast::<c_void>();
            header.msg_controllen = control.len() as _;
        }
        let length = unsafe {
            libc::recvmsg(
                self.descriptor.as_raw_fd(),
                &mut header,
                RECEIVE_DESCRIPTOR_FLAGS,
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
        if length as usize != PACKET_LENGTH
            || header.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) != 0
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "truncated or incorrectly sized worker-control record",
            ));
        }
        let (message, declared_count) =
            Message::decode(record[..PACKET_LENGTH].try_into().unwrap())?;
        let mut descriptors = Vec::<OwnedFd>::new();
        unsafe {
            let mut ancillary = libc::CMSG_FIRSTHDR(&header);
            while !ancillary.is_null() {
                if (*ancillary).cmsg_level != libc::SOL_SOCKET
                    || (*ancillary).cmsg_type != libc::SCM_RIGHTS
                {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "unexpected ancillary worker-control data",
                    ));
                }
                let base = libc::CMSG_LEN(0) as usize;
                let ancillary_length = (*ancillary).cmsg_len as usize;
                if ancillary_length < base
                    || (ancillary_length - base) % std::mem::size_of::<libc::c_int>() != 0
                {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "malformed SCM_RIGHTS payload",
                    ));
                }
                let count = (ancillary_length - base) / std::mem::size_of::<libc::c_int>();
                let source = libc::CMSG_DATA(ancillary).cast::<libc::c_int>();
                for index in 0..count {
                    descriptors.push(OwnedFd::from_raw_fd(*source.add(index)));
                }
                ancillary = libc::CMSG_NXTHDR(&header, ancillary);
            }
        }
        if message != expected_message
            || declared_count as usize != expected_count
            || descriptors.len() != expected_count
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "expected {expected_message:?} with {expected_count} descriptors; received {message:?} declaring {declared_count} with {} descriptors",
                    descriptors.len()
                ),
            ));
        }
        #[cfg(not(target_os = "linux"))]
        {
            for descriptor in &descriptors {
                if unsafe { libc::fcntl(descriptor.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) }
                    != 0
                {
                    return Err(io::Error::last_os_error());
                }
            }
        }
        Ok(descriptors.into_iter().map(File::from).collect())
    }

    pub(crate) fn receive(&mut self) -> io::Result<(Message, u16)> {
        let mut record = [0_u8; PACKET_LENGTH + 1];
        let length = unsafe {
            libc::recv(
                self.descriptor.as_raw_fd(),
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
    fn encode(self, descriptor_count: u16) -> [u8; PACKET_LENGTH] {
        let count = descriptor_count.to_be_bytes();
        [
            MAGIC[0], MAGIC[1], MAGIC[2], MAGIC[3], VERSION, self as u8, count[0], count[1],
        ]
    }

    fn decode(packet: [u8; PACKET_LENGTH]) -> io::Result<(Self, u16)> {
        if packet[..4] != MAGIC || packet[4] != VERSION {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid worker-control packet header",
            ));
        }
        let message = match packet[5] {
            0x01 => Self::PrebindResources,
            0x02 => Self::PostbindResources,
            0x81 => Self::Prepared,
            0x82 => Self::Serving,
            kind => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("unknown worker-control message 0x{kind:02x}"),
                ));
            }
        };
        Ok((message, u16::from_be_bytes([packet[6], packet[7]])))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seqpacket_pair() -> (UnixStream, UnixStream) {
        let mut descriptors = [-1; 2];
        // Darwin supports SCM_RIGHTS but not AF_UNIX/SOCK_SEQPACKET. A local
        // datagram pair exercises the same ancillary-data semantics there.
        let socket_type = if cfg!(target_os = "linux") {
            libc::SOCK_SEQPACKET
        } else {
            libc::SOCK_DGRAM
        };
        assert_eq!(
            unsafe { libc::socketpair(libc::AF_UNIX, socket_type, 0, descriptors.as_mut_ptr(),) },
            0
        );
        unsafe {
            (
                UnixStream::from_raw_fd(descriptors[0]),
                UnixStream::from_raw_fd(descriptors[1]),
            )
        }
    }

    fn send_file(socket: &UnixStream, message: Message, file: &File) {
        let packet = message.encode(1);
        let mut iovec = libc::iovec {
            iov_base: packet.as_ptr().cast::<c_void>().cast_mut(),
            iov_len: packet.len(),
        };
        let mut control =
            vec![
                0_u8;
                unsafe { libc::CMSG_SPACE(std::mem::size_of::<libc::c_int>() as _) as usize }
            ];
        let mut header: libc::msghdr = unsafe { std::mem::zeroed() };
        header.msg_iov = &mut iovec;
        header.msg_iovlen = 1;
        header.msg_control = control.as_mut_ptr().cast::<c_void>();
        header.msg_controllen = control.len() as _;
        unsafe {
            let ancillary = libc::CMSG_FIRSTHDR(&header);
            (*ancillary).cmsg_level = libc::SOL_SOCKET;
            (*ancillary).cmsg_type = libc::SCM_RIGHTS;
            (*ancillary).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<libc::c_int>() as _) as _;
            *libc::CMSG_DATA(ancillary).cast::<libc::c_int>() = file.as_raw_fd();
        }
        assert_eq!(
            unsafe { libc::sendmsg(socket.as_raw_fd(), &header, 0) },
            PACKET_LENGTH as isize
        );
    }

    #[test]
    fn matches_the_supervisor_wire_fixture() {
        assert_eq!(
            Message::Prepared.encode(0),
            [b'U', b'G', b'S', b'P', 1, 0x81, 0, 0]
        );
        assert_eq!(
            Message::decode([b'U', b'G', b'S', b'P', 1, 0x02, 0, 1]).unwrap(),
            (Message::PostbindResources, 1)
        );
    }

    #[test]
    fn receives_a_real_scm_rights_descriptor_and_marks_it_close_on_exec() {
        let (sender, receiver) = seqpacket_pair();
        let source = File::open("/dev/null").unwrap();
        send_file(&sender, Message::PostbindResources, &source);

        let mut channel = Channel {
            descriptor: receiver.as_fd(),
        };
        let received = channel
            .receive_files(Message::PostbindResources, 1)
            .unwrap();
        assert_eq!(received.len(), 1);
        assert_ne!(received[0].as_raw_fd(), source.as_raw_fd());
        assert_ne!(
            unsafe { libc::fcntl(received[0].as_raw_fd(), libc::F_GETFD) } & libc::FD_CLOEXEC,
            0
        );
    }
}
