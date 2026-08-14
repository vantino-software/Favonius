// Favonius — high-performance file transfer over UDP
// Copyright (c) 2025-2026 Vantino SàRL
// SPDX-License-Identifier: Apache-2.0

//! Windows USO (UDP Send Offload) batched UDP sender.
//!
//! USO is the Windows equivalent of Linux GSO. Available since Windows 10
//! version 2004 (Build 19041, May 2020). Submits one large buffer with a
//! `UDP_SEND_MSG_SIZE` control message; the kernel/NIC splits it into N
//! datagrams at segment boundaries.
//!
//! Throughput is comparable to Linux GSO when the NIC driver supports the
//! offload (most Intel/Realtek/Mellanox drivers do).
//!
//! Only the final segment of a USO buffer may be shorter than
//! segment_size: staging a short packet first flushes any full-size
//! segments already pending, and a pending short tail is flushed before
//! anything else is staged behind it. A short packet is therefore never
//! emitted as a mid-batch segment padded with stale bytes.

use std::net::SocketAddr;
use std::os::windows::io::RawSocket;

use windows_sys::Win32::Networking::WinSock::{
    sendto, WSAGetLastError, IPPROTO_UDP, SOCKADDR, SOCKADDR_IN, SOCKET, SOCKET_ERROR,
};

use crate::common::{Capabilities, PacketBatchSender, SendError};

/// `UDP_SEND_MSG_SIZE` socket option (from `mstcpip.h`).
const UDP_SEND_MSG_SIZE: i32 = 2;

// setsockopt wrapper for Windows (windows-sys 0.59 doesn't expose it directly).
extern "system" {
    fn setsockopt(
        s: SOCKET,
        level: i32,
        optname: i32,
        optval: *const u8,
        optlen: i32,
    ) -> i32;
}

pub struct UsoBatchSender {
    socket: SOCKET,
    buf: Vec<u8>,
    segment_size: usize,
    count: usize,
    tail_len: Option<usize>,
    batch_capacity: usize,
    dest: SOCKADDR_IN,
}

impl UsoBatchSender {
    /// Create a USO sender. Returns `None` if the `UDP_SEND_MSG_SIZE`
    /// setsockopt fails — without it the kernel would emit the whole
    /// multi-packet staging buffer as one garbage datagram, so the caller
    /// must fall back to another backend instead of using this one.
    pub fn new(raw_socket: RawSocket, remote: SocketAddr, batch_capacity: usize, segment_size: usize) -> Option<Self> {
        let socket = raw_socket as SOCKET;
        let dest = sockaddr_from(remote);

        // Enable USO via setsockopt(IPPROTO_UDP, UDP_SEND_MSG_SIZE).
        let seg = segment_size as u32;
        let ret = unsafe {
            setsockopt(
                socket,
                IPPROTO_UDP as i32,
                UDP_SEND_MSG_SIZE,
                &seg as *const _ as *const u8,
                std::mem::size_of::<u32>() as i32,
            )
        };
        if ret == SOCKET_ERROR {
            tracing::warn!(err = unsafe { WSAGetLastError() }, "USO setsockopt failed; USO backend unavailable");
            return None;
        }

        Some(Self {
            socket,
            buf: vec![0u8; batch_capacity * segment_size],
            segment_size,
            count: 0,
            tail_len: None,
            batch_capacity,
            dest,
        })
    }
}

impl PacketBatchSender for UsoBatchSender {
    fn stage(&mut self, packet: &[u8]) -> Result<usize, SendError> {
        if self.count >= self.batch_capacity {
            return Err(SendError::BatchFull);
        }
        // USO splits the flush buffer at fixed segment_size boundaries,
        // so only the final segment may be short. Flush the pending batch
        // when a short packet is staged behind full segments, or when
        // anything is staged behind a short tail — otherwise the short
        // packet would go on the wire padded to segment_size with stale
        // bytes from the previous batch.
        if self.count > 0 && (packet.len() < self.segment_size || self.tail_len.is_some()) {
            self.flush()?;
        }
        let offset = self.count * self.segment_size;
        self.buf[offset..offset + packet.len()].copy_from_slice(packet);
        if packet.len() < self.segment_size {
            self.tail_len = Some(packet.len());
        } else {
            self.tail_len = None;
        }
        self.count += 1;
        Ok(packet.len())
    }

    fn flush(&mut self) -> Result<usize, SendError> {
        if self.count == 0 {
            return Ok(0);
        }

        let total_len = if self.count > 1 {
            (self.count - 1) * self.segment_size + self.tail_len.unwrap_or(self.segment_size)
        } else {
            self.tail_len.unwrap_or(self.segment_size)
        };

        // Single sendto — Windows segments at segment_size boundaries via
        // USO. A lone short packet is below the segment size, so it goes
        // out unsegmented as a single datagram. On a non-blocking socket
        // WSAEWOULDBLOCK is ordinary backpressure: retry briefly with a
        // bounded budget before surfacing the error.
        let mut attempt = 0usize;
        loop {
            let n = unsafe {
                sendto(
                    self.socket,
                    self.buf.as_ptr(),
                    total_len as i32,
                    0,
                    &self.dest as *const _ as *const SOCKADDR,
                    std::mem::size_of::<SOCKADDR_IN>() as i32,
                )
            };

            if n == SOCKET_ERROR {
                let err = std::io::Error::from_raw_os_error(unsafe { WSAGetLastError() });
                if let Some(delay) = crate::common::would_block_retry(err.kind(), attempt) {
                    attempt += 1;
                    std::thread::sleep(delay);
                    continue;
                }
                self.count = 0;
                self.tail_len = None;
                return Err(SendError::Io(err));
            }

            let sent = self.count;
            self.count = 0;
            self.tail_len = None;
            return Ok(sent);
        }
    }

    fn is_full(&self) -> bool {
        self.count >= self.batch_capacity
    }

    fn pending(&self) -> usize {
        self.count
    }

    fn modify_last_packet(&mut self, f: &mut dyn FnMut(&mut [u8])) -> bool {
        if self.count == 0 {
            return false;
        }
        let off = (self.count - 1) * self.segment_size;
        // Last staged packet may be a short tail; otherwise it's a full segment.
        let len = self.tail_len.unwrap_or(self.segment_size);
        let slice = &mut self.buf[off..off + len];
        f(slice);
        true
    }

    fn supports_post_stage_mutation(&self) -> bool {
        true
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities {
            max_batch_size: self.batch_capacity,
            supports_segmentation_offload: true,
            supports_zero_copy: false,
            typical_throughput_mbps: 950,
        }
    }

    fn name(&self) -> &'static str {
        "windows/uso"
    }
}

/// Probe whether the running Windows kernel supports USO.
///
/// USO requires Windows 10 build ≥ 19041 (May 2020). Uses RtlGetVersion
/// from ntdll.dll to check the OS build number.
pub fn probe_uso() -> bool {
    use windows_sys::Win32::System::SystemInformation::OSVERSIONINFOW;
    use windows_sys::Wdk::System::SystemServices::RtlGetVersion;

    let mut info: OSVERSIONINFOW = unsafe { std::mem::zeroed() };
    info.dwOSVersionInfoSize = std::mem::size_of::<OSVERSIONINFOW>() as u32;
    let status = unsafe { RtlGetVersion(&mut info) };
    if status != 0 {
        return false;
    }

    // Windows 10 = major 10, USO needs build >= 19041 (Win10 2004).
    info.dwMajorVersion >= 10 && info.dwBuildNumber >= 19041
}

fn sockaddr_from(addr: SocketAddr) -> SOCKADDR_IN {
    use windows_sys::Win32::Networking::WinSock::{AF_INET, IN_ADDR, IN_ADDR_0};

    match addr {
        SocketAddr::V4(v4) => {
            let mut sa: SOCKADDR_IN = unsafe { std::mem::zeroed() };
            sa.sin_family = AF_INET;
            sa.sin_port = v4.port().to_be();
            sa.sin_addr = IN_ADDR {
                S_un: IN_ADDR_0 {
                    S_addr: u32::from(*v4.ip()).to_be(),
                },
            };
            sa
        }
        _ => panic!("IPv6 not yet supported"),
    }
}
