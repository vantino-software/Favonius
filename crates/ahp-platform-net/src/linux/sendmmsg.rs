// Favonius — high-performance file transfer over UDP
// Copyright (c) 2025-2026 Vantino SàRL
// SPDX-License-Identifier: Apache-2.0

//! Linux sendmmsg fallback (used when GSO is unavailable).
//!
//! Submits N packets in one syscall via `sendmmsg(2)`. Slower than GSO
//! because each packet still gets its own skb, but ~5x faster than per-
//! packet sendto.

use std::io::IoSlice;
use std::net::SocketAddr;
use std::os::unix::io::RawFd;
use std::time::Duration;

use nix::sys::socket::{sendmmsg, MsgFlags, MultiHeaders, SockaddrStorage};

use crate::common::{Capabilities, PacketBatchSender, SendError};

pub struct SendmmsgBatchSender {
    buf: Vec<u8>,
    lengths: Vec<usize>,
    max_packet_size: usize,
    batch_capacity: usize,
    count: usize,
    raw_fd: RawFd,
    dest: SockaddrStorage,
}

impl SendmmsgBatchSender {
    pub fn new(fd: RawFd, remote: SocketAddr, batch_capacity: usize) -> Self {
        const MAX_PACKET: usize = 1500;
                    // IPv6 works because `dest` is a `SockaddrStorage`, which
            // holds either family and implements the same `SockaddrLike`
            // the send calls take. This was `SockaddrIn` with a
            // `panic!("IPv6 not yet supported")` on the V6 arm — reachable
            // the moment anything upstream stopped rejecting v6 first.
            let dest = SockaddrStorage::from(remote);
        Self {
            buf: vec![0u8; batch_capacity * MAX_PACKET],
            lengths: vec![0usize; batch_capacity],
            max_packet_size: MAX_PACKET,
            batch_capacity,
            count: 0,
            raw_fd: fd,
            dest,
        }
    }
}

impl PacketBatchSender for SendmmsgBatchSender {
    fn stage(&mut self, packet: &[u8]) -> Result<usize, SendError> {
        if self.count >= self.batch_capacity {
            return Err(SendError::BatchFull);
        }
        let offset = self.count * self.max_packet_size;
        self.buf[offset..offset + packet.len()].copy_from_slice(packet);
        self.lengths[self.count] = packet.len();
        self.count += 1;
        Ok(packet.len())
    }

    fn flush(&mut self) -> Result<usize, SendError> {
        if self.count == 0 {
            return Ok(0);
        }

        let mut total_sent = 0;
        let mut offset = 0;
        let count = self.count;

        while offset < count {
            let remaining = count - offset;
            let slices: Vec<[IoSlice<'_>; 1]> = (offset..count)
                .map(|i| {
                    let start = i * self.max_packet_size;
                    let len = self.lengths[i];
                    [IoSlice::new(&self.buf[start..start + len])]
                })
                .collect();

            let addrs: Vec<Option<SockaddrStorage>> = vec![Some(self.dest); remaining];
            let mut multi = MultiHeaders::<SockaddrStorage>::preallocate(remaining, None);
            let no_cmsgs: Vec<nix::sys::socket::ControlMessage<'_>> = vec![];

            match sendmmsg(self.raw_fd, &mut multi, &slices, &addrs, &no_cmsgs, MsgFlags::empty()) {
                Ok(result) => {
                    let sent = result.count();
                    total_sent += sent;
                    offset += sent;
                }
                Err(nix::errno::Errno::EAGAIN) => {
                    std::thread::sleep(Duration::from_micros(100));
                }
                Err(e) => {
                    self.count = 0;
                    return Err(SendError::Io(std::io::Error::from_raw_os_error(e as i32)));
                }
            }
        }

        self.count = 0;
        Ok(total_sent)
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
        let idx = self.count - 1;
        let off = idx * self.max_packet_size;
        let len = self.lengths[idx];
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
            supports_segmentation_offload: false,
            supports_zero_copy: false,
            typical_throughput_mbps: 250,
        }
    }

    fn name(&self) -> &'static str {
        "linux/sendmmsg"
    }
}
