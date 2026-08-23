//! Versioned worker-control records and `SCM_RIGHTS` endpoint transfer.

use std::ffi::c_void;
use std::fs::File;
use std::io;
#[cfg(test)]
use std::os::fd::AsFd;
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
#[cfg(test)]
use std::os::unix::net::UnixStream;

pub(crate) const STATE_DIRECTORY_ENV: &str = "STATE_DIRECTORY";
pub(crate) const RUNTIME_DIRECTORY_ENV: &str = "RUNTIME_DIRECTORY";
const CONTROL_FD: i32 = 3;
const MAGIC: [u8; 4] = *b"UGSP";
const VERSION: u8 = 1;
const HEADER_LENGTH: usize = 20;
const MAX_BODY_LENGTH: usize = 1024 * 1024;
const MAX_DESCRIPTORS: usize = 32;

#[cfg(target_os = "linux")]
const RECEIVE_DESCRIPTOR_FLAGS: libc::c_int = libc::MSG_CMSG_CLOEXEC;
#[cfg(not(target_os = "linux"))]
const RECEIVE_DESCRIPTOR_FLAGS: libc::c_int = 0;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub(crate) enum Kind {
    InitialResources = 0x01,
    UsbEndpoints = 0x02,
    UsbBusEvent = 0x03,
    UsbControlRequest = 0x04,
    Quiesce = 0x11,
    ConfigurationRejected = 0x12,
    Configure = 0x80,
    UsbControlResponse = 0x81,
    Serving = 0x82,
    Quiesced = 0x84,
}

pub(crate) struct Record {
    pub(crate) kind: Kind,
    pub(crate) generation: u32,
    pub(crate) request_id: u32,
    pub(crate) body: Vec<u8>,
    pub(crate) files: Vec<File>,
}

impl Record {
    pub(crate) fn new(kind: Kind, generation: u32, request_id: u32, body: Vec<u8>) -> Self {
        Self {
            kind,
            generation,
            request_id,
            body,
            files: Vec::new(),
        }
    }
}

pub(crate) struct Channel<'descriptor> {
    descriptor: BorrowedFd<'descriptor>,
}

impl Channel<'static> {
    pub(crate) fn from_fixed_descriptor() -> Self {
        Self {
            // SAFETY: the supervisor installs FD 3 before exec and retains the
            // peer for the lifetime of this worker incarnation.
            descriptor: unsafe { BorrowedFd::borrow_raw(CONTROL_FD) },
        }
    }
}

impl Channel<'_> {
    pub(crate) fn send(&self, record: &Record) -> io::Result<()> {
        if !record.files.is_empty() {
            return invalid("workers cannot attach descriptors to this record");
        }
        let body_length = u32::try_from(record.body.len())
            .map_err(|_| data_error("worker-control body is too large"))?;
        if record.body.len() > MAX_BODY_LENGTH {
            return invalid("worker-control body is too large");
        }
        let mut packet = Vec::with_capacity(HEADER_LENGTH + record.body.len());
        packet.extend_from_slice(&MAGIC);
        packet.push(VERSION);
        packet.push(record.kind as u8);
        packet.extend_from_slice(&0_u16.to_be_bytes());
        packet.extend_from_slice(&record.generation.to_be_bytes());
        packet.extend_from_slice(&record.request_id.to_be_bytes());
        packet.extend_from_slice(&body_length.to_be_bytes());
        packet.extend_from_slice(&record.body);
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
                "worker-control record was not sent atomically",
            ));
        }
        Ok(())
    }

    pub(crate) fn receive(&self) -> io::Result<Record> {
        let mut packet = vec![0_u8; HEADER_LENGTH + MAX_BODY_LENGTH + 1];
        let mut control = vec![
            0_u8;
            unsafe {
                libc::CMSG_SPACE(
                    (MAX_DESCRIPTORS * std::mem::size_of::<libc::c_int>()) as libc::c_uint,
                ) as usize
            }
        ];
        let mut iovec = libc::iovec {
            iov_base: packet.as_mut_ptr().cast::<c_void>(),
            iov_len: packet.len(),
        };
        let mut header: libc::msghdr = unsafe { std::mem::zeroed() };
        header.msg_iov = &mut iovec;
        header.msg_iovlen = 1;
        header.msg_control = control.as_mut_ptr().cast::<c_void>();
        header.msg_controllen = control.len() as _;
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
        if header.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) != 0
            || (length as usize) < HEADER_LENGTH
        {
            return invalid("truncated worker-control record");
        }
        packet.truncate(length as usize);
        if packet[..4] != MAGIC || packet[4] != VERSION {
            return invalid("invalid worker-control header");
        }
        let kind = Kind::from_byte(packet[5])?;
        let declared_files = u16::from_be_bytes(packet[6..8].try_into().unwrap()) as usize;
        let generation = u32::from_be_bytes(packet[8..12].try_into().unwrap());
        let request_id = u32::from_be_bytes(packet[12..16].try_into().unwrap());
        let body_length = u32::from_be_bytes(packet[16..20].try_into().unwrap()) as usize;
        if body_length > MAX_BODY_LENGTH || packet.len() != HEADER_LENGTH + body_length {
            return invalid("worker-control body length does not match its record");
        }

        let mut descriptors = Vec::<OwnedFd>::new();
        unsafe {
            let mut ancillary = libc::CMSG_FIRSTHDR(&header);
            while !ancillary.is_null() {
                if (*ancillary).cmsg_level != libc::SOL_SOCKET
                    || (*ancillary).cmsg_type != libc::SCM_RIGHTS
                {
                    return invalid("unexpected ancillary worker-control data");
                }
                let base = libc::CMSG_LEN(0) as usize;
                let ancillary_length = (*ancillary).cmsg_len as usize;
                if ancillary_length < base
                    || (ancillary_length - base) % std::mem::size_of::<libc::c_int>() != 0
                {
                    return invalid("malformed SCM_RIGHTS payload");
                }
                let count = (ancillary_length - base) / std::mem::size_of::<libc::c_int>();
                let source = libc::CMSG_DATA(ancillary).cast::<libc::c_int>();
                for index in 0..count {
                    descriptors.push(OwnedFd::from_raw_fd(*source.add(index)));
                }
                ancillary = libc::CMSG_NXTHDR(&header, ancillary);
            }
        }
        if descriptors.len() != declared_files || descriptors.len() > MAX_DESCRIPTORS {
            return invalid("worker-control descriptor count does not match its record");
        }
        #[cfg(not(target_os = "linux"))]
        for descriptor in &descriptors {
            if unsafe { libc::fcntl(descriptor.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) } != 0
            {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(Record {
            kind,
            generation,
            request_id,
            body: packet.split_off(HEADER_LENGTH),
            files: descriptors.into_iter().map(File::from).collect(),
        })
    }
}

impl Kind {
    fn from_byte(value: u8) -> io::Result<Self> {
        match value {
            0x01 => Ok(Self::InitialResources),
            0x02 => Ok(Self::UsbEndpoints),
            0x03 => Ok(Self::UsbBusEvent),
            0x04 => Ok(Self::UsbControlRequest),
            0x11 => Ok(Self::Quiesce),
            0x12 => Ok(Self::ConfigurationRejected),
            0x80 => Ok(Self::Configure),
            0x81 => Ok(Self::UsbControlResponse),
            0x82 => Ok(Self::Serving),
            0x84 => Ok(Self::Quiesced),
            _ => invalid(format!("unknown worker-control kind 0x{value:02x}")),
        }
    }
}

pub(crate) fn validate_initial_resources(record: Record) -> io::Result<Vec<(String, File)>> {
    if record.kind != Kind::InitialResources || record.generation != 0 || record.request_id != 0 {
        return invalid("expected initial worker resources");
    }
    if record.body.len() < 2 {
        return invalid("invalid initial resource-name table");
    }
    let count = u16::from_be_bytes(record.body[..2].try_into().unwrap()) as usize;
    if count != record.files.len() {
        return invalid("initial resource names and descriptors differ");
    }
    let mut offset = 2;
    let mut names = Vec::with_capacity(count);
    for _ in 0..count {
        let length = record
            .body
            .get(offset..offset + 2)
            .ok_or_else(|| data_error("truncated initial resource name"))?;
        offset += 2;
        let length = u16::from_be_bytes(length.try_into().unwrap()) as usize;
        let bytes = record
            .body
            .get(offset..offset + length)
            .ok_or_else(|| data_error("truncated initial resource name"))?;
        offset += length;
        names.push(
            std::str::from_utf8(bytes)
                .map_err(|_| data_error("initial resource name is not UTF-8"))?
                .to_owned(),
        );
    }
    if offset != record.body.len() {
        return invalid("initial resource-name table has trailing data");
    }
    Ok(names.into_iter().zip(record.files).collect())
}

fn invalid<T>(message: impl Into<String>) -> io::Result<T> {
    Err(data_error(message))
}

fn data_error(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seqpacket_pair() -> (UnixStream, UnixStream) {
        let mut descriptors = [-1; 2];
        let socket_type = if cfg!(target_os = "linux") {
            libc::SOCK_SEQPACKET
        } else {
            libc::SOCK_DGRAM
        };
        assert_eq!(
            unsafe { libc::socketpair(libc::AF_UNIX, socket_type, 0, descriptors.as_mut_ptr()) },
            0
        );
        unsafe {
            (
                UnixStream::from_raw_fd(descriptors[0]),
                UnixStream::from_raw_fd(descriptors[1]),
            )
        }
    }

    fn send_file(socket: &UnixStream, record: &Record, file: &File) {
        let mut packet = Vec::new();
        packet.extend_from_slice(&MAGIC);
        packet.extend_from_slice(&[VERSION, record.kind as u8]);
        packet.extend_from_slice(&1_u16.to_be_bytes());
        packet.extend_from_slice(&record.generation.to_be_bytes());
        packet.extend_from_slice(&record.request_id.to_be_bytes());
        packet.extend_from_slice(&(record.body.len() as u32).to_be_bytes());
        packet.extend_from_slice(&record.body);
        let mut iovec = libc::iovec {
            iov_base: packet.as_mut_ptr().cast::<c_void>(),
            iov_len: packet.len(),
        };
        let mut control =
            vec![0_u8; unsafe { libc::CMSG_SPACE(std::mem::size_of::<i32>() as _) as usize }];
        let mut header: libc::msghdr = unsafe { std::mem::zeroed() };
        header.msg_iov = &mut iovec;
        header.msg_iovlen = 1;
        header.msg_control = control.as_mut_ptr().cast::<c_void>();
        header.msg_controllen = control.len() as _;
        unsafe {
            let ancillary = libc::CMSG_FIRSTHDR(&header);
            (*ancillary).cmsg_level = libc::SOL_SOCKET;
            (*ancillary).cmsg_type = libc::SCM_RIGHTS;
            (*ancillary).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<i32>() as _) as _;
            *libc::CMSG_DATA(ancillary).cast::<i32>() = file.as_raw_fd();
        }
        assert_eq!(
            unsafe { libc::sendmsg(socket.as_raw_fd(), &header, 0) },
            packet.len() as isize
        );
    }

    #[test]
    fn sends_the_current_twenty_byte_header() {
        let (sender, receiver) = seqpacket_pair();
        let channel = Channel {
            descriptor: sender.as_fd(),
        };
        channel
            .send(&Record::new(Kind::Serving, 7, 9, vec![1, 2]))
            .unwrap();
        let mut packet = [0_u8; 22];
        assert_eq!(
            unsafe { libc::recv(receiver.as_raw_fd(), packet.as_mut_ptr().cast(), 22, 0) },
            22
        );
        assert_eq!(&packet[..8], b"UGSP\x01\x82\0\0");
        assert_eq!(&packet[8..12], &7_u32.to_be_bytes());
        assert_eq!(&packet[12..16], &9_u32.to_be_bytes());
        assert_eq!(&packet[16..20], &2_u32.to_be_bytes());
        assert_eq!(&packet[20..], &[1, 2]);
    }

    #[test]
    fn receives_current_records_and_real_descriptors() {
        let (sender, receiver) = seqpacket_pair();
        let source = File::open("/dev/null").unwrap();
        let record = Record::new(Kind::UsbEndpoints, 4, 11, vec![0, 1, 3, 0, 64]);
        send_file(&sender, &record, &source);
        let channel = Channel {
            descriptor: receiver.as_fd(),
        };
        let received = channel.receive().unwrap();
        assert_eq!(received.kind, Kind::UsbEndpoints);
        assert_eq!(received.generation, 4);
        assert_eq!(received.request_id, 11);
        assert_eq!(received.files.len(), 1);
        assert_ne!(received.files[0].as_raw_fd(), source.as_raw_fd());
    }
}
