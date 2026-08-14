// Favonius — high-performance file transfer over UDP
// Copyright (c) 2025-2026 Vantino SàRL
// SPDX-License-Identifier: Apache-2.0

//! Linux GSO (Generic Segmentation Offload) batched UDP sender.
//!
//! Stages packets into a contiguous buffer at fixed segment_size offsets,
//! then flushes via a single `sendmsg(2)` call with a `UDP_SEGMENT` cmsg.
//! The kernel splits the buffer into N datagrams at segment boundaries.
//!
//! Only the final segment of a GSO buffer may be shorter than
//! segment_size: staging a short packet first flushes any full-size
//! segments already pending, and a pending short tail is flushed before
//! anything else is staged behind it. A short packet is therefore never
//! emitted as a mid-batch segment padded with stale bytes.

use std::io::IoSlice;
use std::net::SocketAddr;
use std::os::unix::io::RawFd;
use std::time::Duration;

use nix::sys::socket::{sendmsg, sendto, ControlMessage, MsgFlags, SockaddrStorage};

use crate::common::{Capabilities, PacketBatchSender, SendError};

pub struct GsoBatchSender {
    buf: Vec<u8>,
    segment_size: usize,
    count: usize,
    tail_len: Option<usize>,
    batch_capacity: usize,
    raw_fd: RawFd,
    dest: SockaddrStorage,
}

impl GsoBatchSender {
    pub fn new(fd: RawFd, remote: SocketAddr, batch_capacity: usize, segment_size: usize) -> Self {
                    // IPv6 works because `dest` is a `SockaddrStorage`, which
            // holds either family and implements the same `SockaddrLike`
            // the send calls take. This was `SockaddrIn` with a
            // `panic!("IPv6 not yet supported")` on the V6 arm — reachable
            // the moment anything upstream stopped rejecting v6 first.
            let dest = SockaddrStorage::from(remote);
        Self {
            buf: vec![0u8; batch_capacity * segment_size],
            segment_size,
            count: 0,
            tail_len: None,
            batch_capacity,
            raw_fd: fd,
            dest,
        }
    }
}

impl PacketBatchSender for GsoBatchSender {
    fn stage(&mut self, packet: &[u8]) -> Result<usize, SendError> {
        if self.count >= self.batch_capacity {
            return Err(SendError::BatchFull);
        }
        // UDP GSO splits the flush buffer at fixed segment_size boundaries,
        // so only the final segment may be short. Flush the pending batch
        // when a short packet is staged behind full segments, or when
        // anything is staged behind a short tail — otherwise the short
        // packet would go on the wire padded to segment_size with stale
        // bytes from the previous batch.
        if self.count > 0 && (packet.len() < self.segment_size || self.tail_len.is_some()) {
            self.flush()?;
        }
        let offset = self.count * self.segment_size;
        let dst = &mut self.buf[offset..offset + self.segment_size];
        dst[..packet.len()].copy_from_slice(packet);

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
            let full_count = self.count - 1;
            let tail = self.tail_len.unwrap_or(self.segment_size);
            full_count * self.segment_size + tail
        } else {
            self.tail_len.unwrap_or(self.segment_size)
        };

        let n = self.count;
        let segment_size_u16 = self.segment_size as u16;
        let iov = [IoSlice::new(&self.buf[..total_len])];
        let cmsg = ControlMessage::UdpGsoSegments(&segment_size_u16);
        // A lone short packet goes out as a plain datagram — the
        // UDP_SEGMENT cmsg is only needed when the kernel must split
        // full-size segments.
        let lone_short = n == 1 && self.tail_len.is_some();

        loop {
            let result = if lone_short {
                sendto(self.raw_fd, &self.buf[..total_len], &self.dest, MsgFlags::empty())
            } else {
                sendmsg(
                    self.raw_fd,
                    &iov,
                    &[cmsg],
                    MsgFlags::empty(),
                    Some(&self.dest),
                )
            };
            match result {
                Ok(_) => {
                    self.count = 0;
                    self.tail_len = None;
                    return Ok(n);
                }
                Err(nix::errno::Errno::EAGAIN) => {
                    std::thread::sleep(Duration::from_micros(100));
                }
                Err(e) => {
                    self.count = 0;
                    self.tail_len = None;
                    return Err(SendError::Io(std::io::Error::from_raw_os_error(e as i32)));
                }
            }
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
        // Last staged packet may be a short tail; otherwise it's a full
        // segment. This holds even when the batch is exactly full.
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
            typical_throughput_mbps: 1000,
        }
    }

    fn name(&self) -> &'static str {
        "linux/gso"
    }
}

/// Probe whether the kernel supports UDP GSO. Returns true on Linux 4.18+
/// where `UDP_SEGMENT` cmsg is accepted by `sendmsg`.
pub fn probe_gso(fd: RawFd) -> bool {
    let segment: u16 = 1200;
    let data = [0u8; 0];
    let iov = [IoSlice::new(&data)];
    let cmsg = ControlMessage::UdpGsoSegments(&segment);
    let dest = SockaddrStorage::from(std::net::SocketAddr::V4(
        std::net::SocketAddrV4::new(std::net::Ipv4Addr::LOCALHOST, 1),
    ));
    match sendmsg(fd, &iov, &[cmsg], MsgFlags::MSG_DONTWAIT, Some(&dest)) {
        Ok(_) => true,
        Err(nix::errno::Errno::EIO) => false,
        Err(nix::errno::Errno::EINVAL) => false,
        Err(nix::errno::Errno::ENOENT) => false,
        // Other errors mean the cmsg was accepted (e.g., ECONNREFUSED)
        _ => true,
    }
}
