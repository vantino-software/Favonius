// Favonius — high-performance file transfer over UDP
// Copyright (c) 2025-2026 Vantino SàRL
// SPDX-License-Identifier: Apache-2.0

//! AF_XDP socket with TX ring and completion ring management.
//!
//! TX only: the receive path is not implemented. The fill ring size is
//! registered with the kernel because socket setup requires it, but no
//! fill or RX ring is ever mmap'd.

use std::os::unix::io::RawFd;
use std::sync::atomic::{AtomicU32, Ordering};

use crate::error::XdpError;
use crate::umem::Umem;

// ═══════════════════════════════════════════════════════════════════════════
// Kernel ABI constants (from linux/if_xdp.h)
// ═══════════════════════════════════════════════════════════════════════════

const AF_XDP: i32 = 44;
const SOL_XDP: i32 = 283;

// setsockopt options (from linux/if_xdp.h)
const XDP_MMAP_OFFSETS: i32 = 1;
const XDP_TX_RING: i32 = 3;
const XDP_UMEM_REG: i32 = 4;
const XDP_UMEM_FILL_RING: i32 = 5;
const XDP_UMEM_COMPLETION_RING: i32 = 6;

// mmap offsets for ring areas (from linux/if_xdp.h).
//
// These do not fit a 32-bit `off_t`: the completion ring sits at 0x1_8000_0000,
// which is 6 GB. AF_XDP is therefore a 64-bit-only path here — mapping the
// rings on a 32-bit target would need mmap2/mmap64, and no 32-bit machine
// this runs on has a NIC with an AF_XDP zero-copy driver anyway. The crate
// used to declare them as `libc::off_t` unconditionally, which failed to
// compile on armv7 with "literal out of range for i32" and broke every
// 32-bit ARM build of the workspace — the Raspberry Pi included.
const XDP_PGOFF_TX_RING: i64 = 0x80000000;
const XDP_UMEM_PGOFF_COMPLETION_RING: i64 = 0x180000000;

// bind flags
const XDP_COPY: u16 = 1 << 1;
const XDP_ZEROCOPY: u16 = 1 << 2;
/// Reserved: opt into the kernel's need-wakeup interface to skip
/// unnecessary `sendto` kicks when the driver is already polling.
#[allow(dead_code)]
const XDP_USE_NEED_WAKEUP: u16 = 1 << 3;

// ═══════════════════════════════════════════════════════════════════════════
// Ring offset structs returned by getsockopt(XDP_MMAP_OFFSETS)
// ═══════════════════════════════════════════════════════════════════════════

#[repr(C)]
#[derive(Debug, Default)]
struct XdpRingOffset {
    producer: u64,
    consumer: u64,
    desc: u64,
    flags: u64,
}

#[repr(C)]
#[derive(Debug, Default)]
struct XdpMmapOffsets {
    rx: XdpRingOffset,
    tx: XdpRingOffset,
    fr: XdpRingOffset, // fill ring
    cr: XdpRingOffset, // completion ring
}

#[repr(C)]
struct XdpUmemReg {
    addr: u64,
    len: u64,
    chunk_size: u32,
    headroom: u32,
    flags: u32,
    tx_metadata_len: u32,
}

/// AF_XDP descriptor (in TX/RX rings).
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct XdpDesc {
    pub addr: u64,
    pub len: u32,
    pub options: u32,
}

/// sockaddr_xdp for bind().
#[repr(C)]
struct SockaddrXdp {
    sxdp_family: u16,
    sxdp_flags: u16,
    sxdp_ifindex: u32,
    sxdp_queue_id: u32,
    sxdp_shared_umem_fd: u32,
}

// ═══════════════════════════════════════════════════════════════════════════
// TX ring (uses XdpDesc entries)
//
// A previous generic `Ring<T>` helper was removed when the TxRing and CompRing
// specializations diverged enough that sharing was no harm. If RX support is
// added, prefer to write a dedicated RxRing rather than reviving the generic.
// ═══════════════════════════════════════════════════════════════════════════

struct TxRing {
    producer: *mut AtomicU32,
    consumer: *mut AtomicU32,
    descs: *mut XdpDesc,
    ring_ptr: *mut u8,
    ring_size: usize,
    mask: u32,
    size: u32,
    cached_prod: u32,
}

impl TxRing {
    fn from_mmap(fd: RawFd, size: u32, offsets: &XdpRingOffset) -> Result<Self, XdpError> {
        let entry_size = std::mem::size_of::<XdpDesc>();
        let ring_size = offsets.desc as usize + size as usize * entry_size;

        // A 32-bit off_t cannot address the ring offsets above; the cast
        // would silently truncate and mmap something else entirely.
        if std::mem::size_of::<libc::off_t>() < 8 {
            return Err(XdpError::Socket(
                "AF_XDP requires a 64-bit target (ring mmap offsets exceed a 32-bit off_t)".into(),
            ));
        }

        let ring_ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                ring_size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED | libc::MAP_POPULATE,
                fd,
                XDP_PGOFF_TX_RING as libc::off_t,
            )
        };
        if ring_ptr == libc::MAP_FAILED {
            return Err(XdpError::Socket(format!("TX ring mmap: {}", std::io::Error::last_os_error())));
        }

        Ok(Self {
            producer: unsafe { (ring_ptr as *mut u8).add(offsets.producer as usize) as *mut AtomicU32 },
            consumer: unsafe { (ring_ptr as *mut u8).add(offsets.consumer as usize) as *mut AtomicU32 },
            descs: unsafe { (ring_ptr as *mut u8).add(offsets.desc as usize) as *mut XdpDesc },
            ring_ptr: ring_ptr as *mut u8,
            ring_size,
            mask: size - 1,
            size,
            cached_prod: 0,
        })
    }

    /// Submit a descriptor to the TX ring.
    fn submit(&mut self, addr: u64, len: u32) -> Result<(), XdpError> {
        let prod = self.cached_prod;
        let cons = unsafe { (*self.consumer).load(Ordering::Acquire) };
        if prod.wrapping_sub(cons) >= self.size {
            return Err(XdpError::RingFull);
        }

        let idx = prod & self.mask;
        unsafe {
            (*self.descs.add(idx as usize)) = XdpDesc { addr, len, options: 0 };
        }

        self.cached_prod = prod.wrapping_add(1);
        // Publish producer index.
        unsafe { (*self.producer).store(self.cached_prod, Ordering::Release); }

        Ok(())
    }

    /// Diagnostic helper: number of TX descriptors submitted to the kernel
    /// that have not yet been moved to the completion ring. Currently only
    /// used for debug-prints in development; the public `outstanding()` on
    /// `XdpSocket` is the canonical accessor for callers.
    #[allow(dead_code)]
    fn pending(&self) -> u32 {
        let cons = unsafe { (*self.consumer).load(Ordering::Acquire) };
        self.cached_prod.wrapping_sub(cons)
    }
}

impl Drop for TxRing {
    fn drop(&mut self) {
        if !self.ring_ptr.is_null() {
            unsafe { libc::munmap(self.ring_ptr as *mut _, self.ring_size); }
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Completion ring (kernel returns completed TX frame addresses)
// ═══════════════════════════════════════════════════════════════════════════

struct CompRing {
    producer: *mut AtomicU32,
    consumer: *mut AtomicU32,
    addrs: *const u64,
    ring_ptr: *mut u8,
    ring_size: usize,
    mask: u32,
    cached_cons: u32,
}

impl CompRing {
    fn from_mmap(fd: RawFd, size: u32, offsets: &XdpRingOffset) -> Result<Self, XdpError> {
        let ring_size = offsets.desc as usize + size as usize * std::mem::size_of::<u64>();

        let ring_ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                ring_size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED | libc::MAP_POPULATE,
                fd,
                XDP_UMEM_PGOFF_COMPLETION_RING as libc::off_t,
            )
        };
        if ring_ptr == libc::MAP_FAILED {
            return Err(XdpError::Socket(format!("comp ring mmap: {}", std::io::Error::last_os_error())));
        }

        Ok(Self {
            producer: unsafe { (ring_ptr as *mut u8).add(offsets.producer as usize) as *mut AtomicU32 },
            consumer: unsafe { (ring_ptr as *mut u8).add(offsets.consumer as usize) as *mut AtomicU32 },
            addrs: unsafe { (ring_ptr as *mut u8).add(offsets.desc as usize) as *const u64 },
            ring_ptr: ring_ptr as *mut u8,
            ring_size,
            mask: size - 1,
            cached_cons: 0,
        })
    }

    /// Drain completed TX frame addresses. Returns addresses of frames
    /// that can be reused.
    fn drain(&mut self) -> Vec<u64> {
        let prod = unsafe { (*self.producer).load(Ordering::Acquire) };
        let mut result = Vec::new();
        while self.cached_cons != prod {
            let idx = self.cached_cons & self.mask;
            let addr = unsafe { *self.addrs.add(idx as usize) };
            result.push(addr);
            self.cached_cons = self.cached_cons.wrapping_add(1);
        }
        unsafe { (*self.consumer).store(self.cached_cons, Ordering::Release); }
        result
    }
}

impl Drop for CompRing {
    fn drop(&mut self) {
        if !self.ring_ptr.is_null() {
            unsafe { libc::munmap(self.ring_ptr as *mut _, self.ring_size); }
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// XDP Socket
// ═══════════════════════════════════════════════════════════════════════════

pub struct XdpSocketConfig {
    pub ifindex: u32,
    pub queue_id: u32,
    pub tx_size: u32,
    /// Fill ring size. Registered with the kernel because socket setup
    /// requires it, but no fill ring is ever mmap'd (RX is not implemented).
    pub fill_size: u32,
    pub comp_size: u32,
    pub zero_copy: bool,
}

impl Default for XdpSocketConfig {
    fn default() -> Self {
        Self {
            ifindex: 0,
            queue_id: 0,
            tx_size: 2048,
            fill_size: 2048,
            comp_size: 2048,
            zero_copy: false,
        }
    }
}

pub struct XdpSocket {
    fd: RawFd,
    tx_ring: TxRing,
    comp_ring: CompRing,
    outstanding_tx: u32,
}

impl XdpSocket {
    /// Create an AF_XDP socket, register UMEM, mmap rings, and bind.
    pub fn new(umem: &mut Umem, config: &XdpSocketConfig) -> Result<Self, XdpError> {
        // Create socket. The guard closes the fd on every error path below;
        // it is disarmed only once the socket is fully constructed.
        let fd = unsafe { libc::socket(AF_XDP, libc::SOCK_RAW, 0) };
        if fd < 0 {
            return Err(XdpError::Socket(format!("socket: {}", std::io::Error::last_os_error())));
        }
        let fd_guard = FdGuard(fd);

        // Register UMEM.
        let reg = XdpUmemReg {
            addr: umem.area_ptr() as u64,
            len: umem.area_size() as u64,
            chunk_size: umem.frame_size(),
            headroom: 0,
            flags: 0,
            tx_metadata_len: 0,
        };
        setsockopt_xdp(fd, XDP_UMEM_REG, &reg)?;

        // Set ring sizes.
        setsockopt_xdp(fd, XDP_TX_RING, &config.tx_size)?;
        setsockopt_xdp(fd, XDP_UMEM_FILL_RING, &config.fill_size)?;
        setsockopt_xdp(fd, XDP_UMEM_COMPLETION_RING, &config.comp_size)?;

        // Get mmap offsets.
        let offsets = get_mmap_offsets(fd)?;

        // mmap TX and completion rings.
        let tx_ring = TxRing::from_mmap(fd, config.tx_size, &offsets.tx)?;
        let comp_ring = CompRing::from_mmap(fd, config.comp_size, &offsets.cr)?;

        // Bind to interface + queue.
        let addr = SockaddrXdp {
            sxdp_family: AF_XDP as u16,
            sxdp_flags: if config.zero_copy { XDP_ZEROCOPY } else { XDP_COPY },
            sxdp_ifindex: config.ifindex,
            sxdp_queue_id: config.queue_id,
            sxdp_shared_umem_fd: 0,
        };
        let ret = unsafe {
            libc::bind(
                fd,
                &addr as *const _ as *const libc::sockaddr,
                std::mem::size_of::<SockaddrXdp>() as u32,
            )
        };
        if ret < 0 {
            let err = std::io::Error::last_os_error();
            // fd_guard drops here and closes the fd.
            // Try copy mode if zero-copy failed.
            if config.zero_copy && err.raw_os_error() == Some(libc::ENOTSUP) {
                tracing::warn!("XDP zero-copy not supported, falling back to copy mode");
                let mut fallback = config.clone();
                fallback.zero_copy = false;
                return Self::new(umem, &fallback);
            }
            return Err(XdpError::Socket(format!("bind: {err}")));
        }

        tracing::info!(fd, ifindex = config.ifindex, queue = config.queue_id,
            zc = config.zero_copy, "AF_XDP socket bound");

        Ok(Self { fd: fd_guard.disarm(), tx_ring, comp_ring, outstanding_tx: 0 })
    }

    /// Submit a UMEM frame for transmission.
    pub fn tx_submit(&mut self, frame_addr: u64, frame_len: u32) -> Result<(), XdpError> {
        self.tx_ring.submit(frame_addr, frame_len)?;
        self.outstanding_tx += 1;
        Ok(())
    }

    /// Kick the kernel to process submitted TX frames.
    pub fn tx_kick(&self) -> Result<(), XdpError> {
        let ret = unsafe {
            libc::sendto(self.fd, std::ptr::null(), 0, libc::MSG_DONTWAIT, std::ptr::null(), 0)
        };
        if ret < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() != std::io::ErrorKind::WouldBlock
                && err.raw_os_error() != Some(libc::EAGAIN)
                && err.raw_os_error() != Some(libc::ENOBUFS)
            {
                return Err(XdpError::Io(err));
            }
        }
        Ok(())
    }

    /// Drain completed frames — returns UMEM addresses that can be reused.
    pub fn tx_complete(&mut self) -> Vec<u64> {
        let addrs = self.comp_ring.drain();
        self.outstanding_tx = self.outstanding_tx.saturating_sub(addrs.len() as u32);
        addrs
    }

    /// Number of frames waiting for completion.
    pub fn outstanding(&self) -> u32 {
        self.outstanding_tx
    }

    /// Socket file descriptor.
    pub fn fd(&self) -> RawFd {
        self.fd
    }

    /// Probe AF_XDP support (creates then closes a test socket).
    pub fn probe() -> bool {
        let fd = unsafe { libc::socket(AF_XDP, libc::SOCK_RAW, 0) };
        if fd >= 0 {
            unsafe { libc::close(fd); }
            true
        } else {
            false
        }
    }
}

impl Clone for XdpSocketConfig {
    fn clone(&self) -> Self {
        Self {
            ifindex: self.ifindex,
            queue_id: self.queue_id,
            tx_size: self.tx_size,
            fill_size: self.fill_size,
            comp_size: self.comp_size,
            zero_copy: self.zero_copy,
        }
    }
}

impl Drop for XdpSocket {
    fn drop(&mut self) {
        if self.fd >= 0 {
            unsafe { libc::close(self.fd); }
        }
    }
}

unsafe impl Send for XdpSocket {}

// ═══════════════════════════════════════════════════════════════════════════
// Helpers
// ═══════════════════════════════════════════════════════════════════════════

/// RAII guard that closes a raw fd on drop unless `disarm`ed. Ensures the
/// socket fd is not leaked when `XdpSocket::new` bails out midway.
struct FdGuard(RawFd);

impl FdGuard {
    /// Stop guarding the fd and return it — ownership passes to the caller.
    fn disarm(self) -> RawFd {
        let fd = self.0;
        std::mem::forget(self);
        fd
    }
}

impl Drop for FdGuard {
    fn drop(&mut self) {
        unsafe { libc::close(self.0); }
    }
}

fn setsockopt_xdp<T>(fd: RawFd, opt: i32, val: &T) -> Result<(), XdpError> {
    let ret = unsafe {
        libc::setsockopt(
            fd, SOL_XDP, opt,
            val as *const _ as *const _,
            std::mem::size_of::<T>() as u32,
        )
    };
    if ret < 0 {
        Err(XdpError::Socket(format!("setsockopt {opt}: {}", std::io::Error::last_os_error())))
    } else {
        Ok(())
    }
}

fn get_mmap_offsets(fd: RawFd) -> Result<XdpMmapOffsets, XdpError> {
    let mut offsets = XdpMmapOffsets::default();
    let mut len = std::mem::size_of::<XdpMmapOffsets>() as u32;
    let ret = unsafe {
        libc::getsockopt(
            fd, SOL_XDP, XDP_MMAP_OFFSETS,
            &mut offsets as *mut _ as *mut _,
            &mut len,
        )
    };
    if ret < 0 {
        Err(XdpError::Socket(format!("XDP_MMAP_OFFSETS: {}", std::io::Error::last_os_error())))
    } else {
        Ok(offsets)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fd_is_open(fd: RawFd) -> bool {
        (unsafe { libc::fcntl(fd, libc::F_GETFD) }) != -1
    }

    fn plain_fd() -> RawFd {
        // No privileges needed — a datagram socket is enough to observe
        // open/close behavior of the guard.
        let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
        assert!(fd >= 0, "test socket: {}", std::io::Error::last_os_error());
        fd
    }

    #[test]
    fn fd_guard_closes_on_drop() {
        let fd = plain_fd();
        assert!(fd_is_open(fd));
        drop(FdGuard(fd));
        assert!(!fd_is_open(fd), "guard must close the fd on drop");
    }

    #[test]
    fn fd_guard_disarm_keeps_fd_open() {
        let fd = plain_fd();
        let raw = FdGuard(fd).disarm();
        assert_eq!(raw, fd);
        assert!(fd_is_open(fd), "disarm must not close the fd");
        unsafe { libc::close(fd); }
        assert!(!fd_is_open(fd));
    }
}
