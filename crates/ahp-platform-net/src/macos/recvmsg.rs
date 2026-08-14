// Favonius — high-performance file transfer over UDP
// Copyright (c) 2025-2026 Vantino SàRL
// SPDX-License-Identifier: Apache-2.0

//! macOS receive backend: single-datagram `recvfrom` per call.
//!
//! macOS/XNU has no `recvmmsg`, so there is no batched-receive syscall to
//! amortize. Each `recv_batch` reads exactly one datagram. Callers that want
//! more throughput simply loop; the abstraction stays identical to Linux so
//! the daemon receive loop is the same shape on every platform.

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::os::unix::io::RawFd;

use crate::common::{PacketBatchReceiver, RecvCapabilities, RecvError};

pub struct RecvmsgReceiver {
    fd: RawFd,
    max_packet: usize,
    buf: Vec<u8>,
    len: usize,
    source: SocketAddr,
    last_n: usize,
}

impl RecvmsgReceiver {
    pub fn new(fd: RawFd, max_packet: usize) -> Self {
        Self {
            fd,
            max_packet,
            buf: vec![0u8; max_packet],
            len: 0,
            source: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)),
            last_n: 0,
        }
    }
}

impl PacketBatchReceiver for RecvmsgReceiver {
    fn recv_batch(&mut self) -> Result<usize, RecvError> {
        let mut ss: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
        let mut ss_len = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;

        // SAFETY: buf is a valid, writable region of `max_packet` bytes and
        // ss/ss_len are a valid sockaddr output pair.
        let ret = unsafe {
            libc::recvfrom(
                self.fd,
                self.buf.as_mut_ptr() as *mut libc::c_void,
                self.max_packet,
                0,
                &mut ss as *mut _ as *mut libc::sockaddr,
                &mut ss_len,
            )
        };

        if ret < 0 {
            let err = std::io::Error::last_os_error();
            self.last_n = 0;
            if err.kind() == std::io::ErrorKind::WouldBlock {
                return Err(RecvError::WouldBlock);
            }
            return Err(RecvError::Io(err));
        }

        self.len = ret as usize;
        self.source = if ss.ss_family as i32 == libc::AF_INET {
            // SAFETY: family is AF_INET → storage is a valid sockaddr_in.
            let sin = unsafe { &*(&ss as *const _ as *const libc::sockaddr_in) };
            SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr)),
                u16::from_be(sin.sin_port),
            ))
        } else {
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0))
        };
        self.last_n = 1;
        Ok(1)
    }

    fn packet(&self, i: usize) -> &[u8] {
        assert!(i < self.last_n, "packet index {i} out of range");
        &self.buf[..self.len]
    }

    fn packet_mut(&mut self, i: usize) -> &mut [u8] {
        assert!(i < self.last_n, "packet index {i} out of range");
        &mut self.buf[..self.len]
    }

    fn source(&self, i: usize) -> SocketAddr {
        assert!(i < self.last_n, "packet index {i} out of range");
        self.source
    }

    fn capabilities(&self) -> RecvCapabilities {
        RecvCapabilities {
            max_batch_size: 1,
            supports_batched_syscall: false,
            max_packet_size: self.max_packet,
        }
    }

    fn name(&self) -> &'static str {
        "macos/recvfrom"
    }
}
