// Favonius — high-performance file transfer over UDP
// Copyright (c) 2025-2026 Vantino SàRL
// SPDX-License-Identifier: Apache-2.0

//! Windows receive backend: single-datagram `recvfrom` per call.
//!
//! Windows has no `recvmmsg`. `WSARecvMsg` exists but only receives one
//! datagram per call anyway (its value is control-message access, not
//! batching), so a plain `recvfrom` is the simplest correct backend. Each
//! `recv_batch` reads exactly one datagram, keeping the receive-loop shape
//! identical to the Linux `recvmmsg` backend.
//!
//! One Winsock behaviour has to be normalised here. When a datagram is
//! larger than the supplied buffer, the BSD sockets API silently truncates
//! it and reports the bytes it kept; Winsock fills the buffer, discards the
//! excess, and *also* returns `SOCKET_ERROR` with `WSAEMSGSIZE`. Left
//! as-is that turns a routine oversized packet into a receive-loop error on
//! Windows only — and since any peer can send an oversized datagram to an
//! open port, that difference is reachable by anyone. This backend reports
//! the truncated datagram instead, so every platform hands the daemon the
//! same thing and the daemon's own length validation rejects it.

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::os::windows::io::RawSocket;

use windows_sys::Win32::Networking::WinSock::{
    recvfrom, WSAGetLastError, AF_INET, SOCKADDR, SOCKADDR_IN, SOCKET, SOCKET_ERROR,
    WSAEMSGSIZE, WSAEWOULDBLOCK,
};

use crate::common::{PacketBatchReceiver, RecvCapabilities, RecvError};

pub struct RecvfromReceiver {
    socket: SOCKET,
    max_packet: usize,
    buf: Vec<u8>,
    len: usize,
    source: SocketAddr,
    last_n: usize,
}

impl RecvfromReceiver {
    pub fn new(raw_socket: RawSocket, max_packet: usize) -> Self {
        Self {
            socket: raw_socket as SOCKET,
            max_packet,
            buf: vec![0u8; max_packet],
            len: 0,
            source: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)),
            last_n: 0,
        }
    }
}

impl PacketBatchReceiver for RecvfromReceiver {
    fn recv_batch(&mut self) -> Result<usize, RecvError> {
        let mut from: SOCKADDR_IN = unsafe { std::mem::zeroed() };
        let mut from_len = std::mem::size_of::<SOCKADDR_IN>() as i32;

        // SAFETY: buf is a valid writable region; from/from_len are a valid
        // sockaddr output pair sized for a SOCKADDR_IN.
        let ret = unsafe {
            recvfrom(
                self.socket,
                self.buf.as_mut_ptr(),
                self.max_packet as i32,
                0,
                &mut from as *mut _ as *mut SOCKADDR,
                &mut from_len,
            )
        };

        // Set below on every path that produces a datagram; `truncated`
        // records the WSAEMSGSIZE case, where the byte count has to be
        // inferred because Winsock does not return one.
        let received;

        if ret == SOCKET_ERROR {
            let err = unsafe { WSAGetLastError() };
            if err == WSAEWOULDBLOCK {
                self.last_n = 0;
                return Err(RecvError::WouldBlock);
            }
            if err == WSAEMSGSIZE {
                // A datagram arrived and did not fit. Winsock has already
                // written `max_packet` bytes into the buffer and dropped the
                // rest, so this is a truncated packet, not a failure — the
                // same state a BSD `recvfrom` reports without an error. The
                // source address is filled in as usual.
                //
                // Reporting it, rather than erroring, is what keeps a peer
                // from stopping the receive loop with one jumbo datagram.
                // It will fail the daemon's length check on arrival, which
                // is exactly what happens on Linux and macOS.
                received = self.max_packet;
            } else {
                self.last_n = 0;
                return Err(RecvError::Io(std::io::Error::from_raw_os_error(err)));
            }
        } else {
            received = ret as usize;
        }

        self.len = received;
        self.source = if from.sin_family == AF_INET {
            // windows-sys stores sin_addr as a big-endian u32 in S_addr.
            let addr = unsafe { from.sin_addr.S_un.S_addr };
            SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::from(u32::from_be(addr)),
                u16::from_be(from.sin_port),
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
        "windows/recvfrom"
    }
}
