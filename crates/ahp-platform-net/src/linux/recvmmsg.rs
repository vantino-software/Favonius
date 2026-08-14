// Favonius — high-performance file transfer over UDP
// Copyright (c) 2025-2026 Vantino SàRL
// SPDX-License-Identifier: Apache-2.0

//! Linux batched receive via `recvmmsg(2)`, with UDP GRO where the kernel
//! offers it.
//!
//! Pulls up to N datagrams per syscall instead of one per `recvfrom`. On a
//! busy data socket this amortizes syscall entry/exit across the batch,
//! which is the receive-side analogue of the sendmmsg/GSO send path.
//!
//! **UDP_GRO** goes further: the kernel coalesces consecutive same-size
//! datagrams from one flow into a single large buffer before the
//! application sees them, and reports the segment size in a control
//! message. One `recvmmsg` slot can then carry ~45 packets instead of one,
//! and the per-packet share of the stack's cost falls with it.
//!
//! This is the half of TCP's advantage that was missing. Measured
//! 2026-08-13 on the GCP pair, Favonius's receive path cost **12-26x more
//! CPU per byte than TCP's**, with kernel time (sys 33% + softirq 10%)
//! twice user time — the profile of a path paying per packet where TCP
//! pays per batch. The sender has used `UDP_SEGMENT` all along; nothing
//! used its receive-side counterpart.
//!
//! The receiver owns a flat buffer partitioned into slots. Callers process
//! packets in place — no per-packet copy — and with GRO on, a "packet" is a
//! segment inside a coalesced slot rather than a slot of its own.

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::os::unix::io::RawFd;

use crate::common::{PacketBatchReceiver, RecvCapabilities, RecvError};

/// `include/uapi/linux/udp.h`. Defined here rather than taken from `libc`
/// because the constant is not exposed for every linux target there, and
/// the value is kernel ABI.
const UDP_GRO: libc::c_int = 104;

/// Bytes per slot when GRO is active. The kernel will not coalesce beyond
/// 64 KiB, so a larger slot cannot be filled.
const GRO_SLOT: usize = 64 * 1024;

/// Slots when GRO is active. Each can hold ~45 MTU-sized segments, so a
/// handful of slots is already a deeper batch than the non-GRO path had —
/// and 8 x 64 KiB is 512 KiB per socket, which matters when a transfer
/// holds a run of them.
const GRO_SLOTS: usize = 8;

pub struct RecvmmsgReceiver {
    fd: RawFd,
    max_packet: usize,
    batch_capacity: usize,
    /// Bytes per slot: `max_packet`, or [`GRO_SLOT`] when coalescing.
    slot: usize,
    /// Whether the kernel accepted `UDP_GRO` on this socket.
    gro: bool,
    /// batch_capacity * slot contiguous bytes.
    buf: Vec<u8>,
    sources: Vec<SocketAddr>,
    /// Scratch reused across calls to avoid per-batch allocation. The raw
    /// pointers inside these are rewritten at the start of every `recv_batch`
    /// so they never dangle across calls.
    iovecs: Vec<libc::iovec>,
    msgs: Vec<libc::mmsghdr>,
    addr_storage: Vec<libc::sockaddr_storage>,
    /// Per-slot control-message buffer, for the GRO segment size.
    cmsg: Vec<u8>,
    cmsg_per_slot: usize,
    /// Flattened view of the last batch: (offset into `buf`, length, slot).
    /// Without GRO this is one entry per slot; with it, one per segment.
    segments: Vec<(usize, usize, usize)>,
}

// SAFETY: the raw pointers stored in `iovecs`/`msgs` reference this struct's
// own `buf`/`addr_storage`/`iovecs`/`cmsg` and are rewritten before each
// syscall. They are never used outside `recv_batch`, so moving the struct
// between threads (Send) is sound; the pointers are only ever dereferenced
// by the kernel during a `recvmmsg` call while `&mut self` is held.
unsafe impl Send for RecvmmsgReceiver {}

impl RecvmmsgReceiver {
    pub fn new(fd: RawFd, batch_capacity: usize, max_packet: usize) -> Self {
        // Opt-out, because this is a receive-path change and the receive
        // path is where bytes are lost rather than slowed. `FAVONIUS_UDP_GRO=0`
        // restores the datagram-per-slot behaviour from one binary, which is
        // what makes it A/B-able on a rig.
        let want_gro = std::env::var("FAVONIUS_UDP_GRO").map(|v| v != "0").unwrap_or(true);
        // Kernels before 5.0 reject this, as do non-UDP sockets; either way
        // the fallback is exactly the old behaviour.
        let gro = want_gro && unsafe {
            let on: libc::c_int = 1;
            libc::setsockopt(
                fd,
                libc::SOL_UDP,
                UDP_GRO,
                &on as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            ) == 0
        };

        let cap = if gro { GRO_SLOTS } else { batch_capacity.max(1) };
        let slot = if gro { GRO_SLOT } else { max_packet };
        // CMSG_SPACE for one u16 payload, rounded by the macro's own rules.
        let cmsg_per_slot = unsafe {
            libc::CMSG_SPACE(std::mem::size_of::<u16>() as libc::c_uint) as usize
        };

        Self {
            fd,
            max_packet,
            batch_capacity: cap,
            slot,
            gro,
            buf: vec![0u8; cap * slot],
            sources: vec![SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)); cap],
            iovecs: vec![unsafe { std::mem::zeroed() }; cap],
            msgs: vec![unsafe { std::mem::zeroed() }; cap],
            addr_storage: vec![unsafe { std::mem::zeroed() }; cap],
            cmsg: vec![0u8; cap * cmsg_per_slot],
            cmsg_per_slot,
            segments: Vec::with_capacity(cap * 64),
        }
    }

    /// Whether this socket is coalescing. Exposed for diagnostics — the
    /// difference between "GRO on and quiet" and "GRO never enabled" is
    /// otherwise invisible in a throughput number.
    pub fn gro_enabled(&self) -> bool {
        self.gro
    }

    /// The GRO segment size reported for slot `i`, if any.
    ///
    /// # Safety
    /// Reads the control buffer the kernel just filled for this slot.
    unsafe fn gro_segment_size(&self, i: usize) -> Option<usize> {
        let hdr = &self.msgs[i].msg_hdr;
        if hdr.msg_controllen == 0 {
            return None;
        }
        let mut cmsg = libc::CMSG_FIRSTHDR(hdr);
        while !cmsg.is_null() {
            let c = &*cmsg;
            if c.cmsg_level == libc::SOL_UDP && c.cmsg_type == UDP_GRO {
                let data = libc::CMSG_DATA(cmsg) as *const u16;
                let seg = std::ptr::read_unaligned(data) as usize;
                return (seg > 0).then_some(seg);
            }
            cmsg = libc::CMSG_NXTHDR(hdr, cmsg);
        }
        None
    }
}

/// Decode a filled `sockaddr_storage` into a `SocketAddr` (IPv4 only — AHP
/// is IPv4). Anything else maps to `0.0.0.0:0`.
fn decode_source(ss: &libc::sockaddr_storage) -> SocketAddr {
    if ss.ss_family as i32 == libc::AF_INET {
        // SAFETY: family is AF_INET, so the storage is a valid sockaddr_in.
        let sin = unsafe { &*(ss as *const _ as *const libc::sockaddr_in) };
        let ip = Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr));
        let port = u16::from_be(sin.sin_port);
        SocketAddr::V4(SocketAddrV4::new(ip, port))
    } else {
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0))
    }
}

impl PacketBatchReceiver for RecvmmsgReceiver {
    fn recv_batch(&mut self) -> Result<usize, RecvError> {
        let cap = self.batch_capacity;
        let ss_len = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;

        // (Re)point the scratch iovecs/mmsghdrs at our own buffers. Doing this
        // every call keeps the pointers valid even though the struct may have
        // moved since the last call.
        for i in 0..cap {
            let base = i * self.slot;
            self.iovecs[i] = libc::iovec {
                iov_base: self.buf[base..].as_mut_ptr() as *mut libc::c_void,
                iov_len: self.slot,
            };
        }
        let cmsg_len = self.cmsg_per_slot;
        for i in 0..cap {
            let control = if self.gro {
                self.cmsg[i * cmsg_len..].as_mut_ptr() as *mut libc::c_void
            } else {
                std::ptr::null_mut()
            };
            let hdr = &mut self.msgs[i].msg_hdr;
            hdr.msg_name = (&mut self.addr_storage[i] as *mut _) as *mut libc::c_void;
            hdr.msg_namelen = ss_len;
            hdr.msg_iov = &mut self.iovecs[i] as *mut libc::iovec;
            hdr.msg_iovlen = 1;
            hdr.msg_control = control;
            hdr.msg_controllen = if self.gro { cmsg_len as _ } else { 0 };
            hdr.msg_flags = 0;
            self.msgs[i].msg_len = 0;
        }

        // SAFETY: msgs is a valid array of `cap` mmsghdr, each pointing at
        // live iovec/addr/control storage owned by self for the duration of
        // the call.
        let ret = unsafe {
            libc::recvmmsg(
                self.fd,
                self.msgs.as_mut_ptr(),
                cap as libc::c_uint,
                0,
                std::ptr::null_mut(),
            )
        };

        if ret < 0 {
            let err = std::io::Error::last_os_error();
            self.segments.clear();
            if err.kind() == std::io::ErrorKind::WouldBlock {
                return Err(RecvError::WouldBlock);
            }
            return Err(RecvError::Io(err));
        }

        let n = ret as usize;
        self.segments.clear();
        for i in 0..n {
            let filled = self.msgs[i].msg_len as usize;
            self.sources[i] = decode_source(&self.addr_storage[i]);
            let base = i * self.slot;
            // SAFETY: the kernel has just filled this slot's control buffer.
            let seg = if self.gro { unsafe { self.gro_segment_size(i) } } else { None };
            match seg {
                // Coalesced: split into segments of `seg` bytes. The LAST
                // one may be shorter — that is what ends a GRO run, and
                // treating every segment as full-size would hand the caller
                // padding as if it were payload.
                Some(seg) if seg < filled => {
                    let mut off = 0;
                    while off < filled {
                        let len = seg.min(filled - off);
                        self.segments.push((base + off, len, i));
                        off += len;
                    }
                }
                // One datagram in this slot (GRO off, or nothing to coalesce).
                _ => self.segments.push((base, filled, i)),
            }
        }
        Ok(self.segments.len())
    }

    fn packet(&self, i: usize) -> &[u8] {
        let (off, len, _) = self.segments[i];
        &self.buf[off..off + len]
    }

    fn packet_mut(&mut self, i: usize) -> &mut [u8] {
        let (off, len, _) = self.segments[i];
        &mut self.buf[off..off + len]
    }

    fn source(&self, i: usize) -> SocketAddr {
        let (_, _, slot) = self.segments[i];
        self.sources[slot]
    }

    fn capabilities(&self) -> RecvCapabilities {
        RecvCapabilities {
            // With GRO a slot can carry many segments, so the ceiling is no
            // longer the slot count.
            max_batch_size: if self.gro {
                self.batch_capacity * (GRO_SLOT / self.max_packet.max(1))
            } else {
                self.batch_capacity
            },
            supports_batched_syscall: true,
            max_packet_size: self.max_packet,
        }
    }

    fn name(&self) -> &'static str {
        if self.gro {
            "linux/recvmmsg+gro"
        } else {
            "linux/recvmmsg"
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::UdpSocket;
    use std::os::unix::io::AsRawFd;
    use std::time::Duration;

    #[test]
    fn batches_multiple_datagrams_in_one_call() {
        let rx_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        rx_sock.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let rx_addr = rx_sock.local_addr().unwrap();

        let tx = UdpSocket::bind("127.0.0.1:0").unwrap();
        let tx_addr = tx.local_addr().unwrap();

        // Send 5 datagrams before the first recv so they queue in the socket
        // buffer and a single recvmmsg can pull several at once.
        for i in 0u8..5 {
            tx.send_to(&[i, i, i, i], rx_addr).unwrap();
        }

        let mut rx = RecvmmsgReceiver::new(rx_sock.as_raw_fd(), 16, 2048);
        let mut total = 0usize;
        let mut max_in_one_call = 0usize;
        // Drain until we've seen all 5.
        for _ in 0..10 {
            match rx.recv_batch() {
                Ok(n) => {
                    max_in_one_call = max_in_one_call.max(n);
                    for i in 0..n {
                        assert_eq!(rx.packet(i).len(), 4);
                        assert_eq!(rx.source(i).port(), tx_addr.port());
                    }
                    total += n;
                    if total >= 5 {
                        break;
                    }
                }
                Err(RecvError::WouldBlock) => break,
                Err(e) => panic!("recv_batch: {e}"),
            }
        }
        assert_eq!(total, 5, "should receive all 5 datagrams");
        assert!(max_in_one_call >= 2, "recvmmsg should batch >=2 datagrams in one call, got {max_in_one_call}");
    }

    #[test]
    fn would_block_on_empty_nonblocking_socket() {
        let rx_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        rx_sock.set_nonblocking(true).unwrap();
        let mut rx = RecvmmsgReceiver::new(rx_sock.as_raw_fd(), 8, 2048);
        match rx.recv_batch() {
            Err(RecvError::WouldBlock) => {}
            other => panic!("expected WouldBlock on empty non-blocking socket, got {other:?}"),
        }
    }

    /// Coalesced or not, the caller must see the same datagrams with the
    /// same boundaries — that is the whole contract of splitting a GRO
    /// slot, and getting it wrong hands payload and padding to the parser
    /// interchangeably.
    ///
    /// The kernel decides whether to coalesce, so this asserts the
    /// *invariant* rather than that coalescing happened: every datagram
    /// arrives once, intact, in order, with its own source.
    #[test]
    fn segments_reconstruct_the_original_datagrams() {
        let rx_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        rx_sock.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let rx_addr = rx_sock.local_addr().unwrap();
        let tx = UdpSocket::bind("127.0.0.1:0").unwrap();

        // 20 full-size datagrams then one short one: the short tail is what
        // ends a GRO run and is where an off-by-one in the split shows up.
        const FULL: usize = 1400;
        for i in 0u8..20 {
            tx.send_to(&vec![i + 1; FULL], rx_addr).unwrap();
        }
        tx.send_to(&vec![0xAA; 37], rx_addr).unwrap();

        let mut rx = RecvmmsgReceiver::new(rx_sock.as_raw_fd(), 16, 2048);
        let mut seen: Vec<(usize, u8)> = Vec::new();
        for _ in 0..40 {
            match rx.recv_batch() {
                Ok(n) => {
                    for i in 0..n {
                        let p = rx.packet(i);
                        assert!(!p.is_empty(), "a zero-length segment is a split bug");
                        // Every byte of a datagram is the same value, so a
                        // mis-split shows as a segment with mixed content.
                        let first = p[0];
                        assert!(
                            p.iter().all(|&b| b == first),
                            "segment {i} spans two datagrams: len {}", p.len()
                        );
                        seen.push((p.len(), first));
                    }
                    if seen.len() >= 21 {
                        break;
                    }
                }
                Err(RecvError::WouldBlock) => break,
                Err(e) => panic!("recv_batch: {e}"),
            }
        }
        assert_eq!(seen.len(), 21, "every datagram must arrive exactly once: {seen:?}");
        for (i, (len, val)) in seen.iter().take(20).enumerate() {
            assert_eq!(*len, FULL, "datagram {i} truncated or merged");
            assert_eq!(*val, i as u8 + 1, "datagram {i} out of order or corrupted");
        }
        assert_eq!(seen[20], (37, 0xAA), "the short tail must survive intact");
    }
}
