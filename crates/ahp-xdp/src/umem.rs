// Favonius — high-performance file transfer over UDP
// Copyright (c) 2025-2026 Vantino SàRL
// SPDX-License-Identifier: Apache-2.0

//! UMEM: shared memory region for AF_XDP zero-copy I/O.
//!
//! UMEM is a contiguous memory region divided into fixed-size frames.
//! Both userspace and the kernel NIC driver access this memory directly —
//! no copies between user and kernel space.

use crate::error::XdpError;

/// UMEM configuration.
pub struct UmemConfig {
    /// Size of each frame in bytes (must be power of 2, typically 4096).
    pub frame_size: u32,
    /// Number of frames in the UMEM region.
    pub frame_count: u32,
    /// Fill ring size (must be power of 2).
    pub fill_size: u32,
    /// Completion ring size (must be power of 2).
    pub comp_size: u32,
}

impl Default for UmemConfig {
    fn default() -> Self {
        Self {
            frame_size: 4096,
            frame_count: 4096,
            fill_size: 2048,
            comp_size: 2048,
        }
    }
}

/// UMEM region: mmap'd memory + frame allocator.
pub struct Umem {
    /// Raw pointer to the mmap'd region.
    area: *mut u8,
    /// Total size in bytes.
    area_size: usize,
    /// Frame size.
    frame_size: u32,
    /// Total frame count.
    frame_count: u32,
    /// Free frame indices (stack-based allocator).
    free_frames: Vec<u32>,
    /// File descriptor for the UMEM (from setsockopt XDP_UMEM_REG).
    /// Currently unused — kernel cleans up the UMEM when the XDP socket closes.
    /// Reserved for shared-UMEM (multiple XDP sockets sharing one UMEM) support.
    #[allow(dead_code)]
    pub(crate) fd: i32,
}

impl Umem {
    /// Allocate a UMEM region.
    pub fn new(config: &UmemConfig) -> Result<Self, XdpError> {
        let area_size = config.frame_size as usize * config.frame_count as usize;

        // mmap anonymous memory for the UMEM region.
        let area = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                area_size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_HUGETLB,
                -1,
                0,
            )
        };

        // Fall back to regular pages if huge pages aren't available.
        let area = if area == libc::MAP_FAILED {
            let area = unsafe {
                libc::mmap(
                    std::ptr::null_mut(),
                    area_size,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                    -1,
                    0,
                )
            };
            if area == libc::MAP_FAILED {
                return Err(XdpError::Umem(format!(
                    "mmap failed: {}",
                    std::io::Error::last_os_error()
                )));
            }
            area
        } else {
            area
        };

        // Initialize free frame list (all frames available).
        let free_frames: Vec<u32> = (0..config.frame_count).rev().collect();

        Ok(Self {
            area: area as *mut u8,
            area_size,
            frame_size: config.frame_size,
            frame_count: config.frame_count,
            free_frames,
            fd: -1,
        })
    }

    /// Get a pointer to a frame's data region.
    ///
    /// # Panics
    /// Panics if `frame_idx` is out of bounds. This is a real runtime check
    /// (not `debug_assert!`) — an out-of-bounds index must never become UB.
    pub fn frame_ptr(&self, frame_idx: u32) -> *mut u8 {
        let offset = frame_idx as usize * self.frame_size as usize;
        assert!(
            offset < self.area_size,
            "frame index {frame_idx} out of bounds ({} frames)",
            self.frame_count
        );
        unsafe { self.area.add(offset) }
    }

    /// Get a mutable slice for a frame. Returns `None` if `frame_idx` is
    /// out of bounds.
    ///
    /// Takes `&mut self` so the borrow checker guarantees the returned slice
    /// is the only live reference into the UMEM region — no aliasing `&mut`
    /// can be minted from a shared reference.
    pub fn frame_slice_mut(&mut self, frame_idx: u32) -> Option<&mut [u8]> {
        let offset = frame_idx as usize * self.frame_size as usize;
        if offset + self.frame_size as usize > self.area_size {
            return None;
        }
        // Safety: bounds-checked above; `&mut self` guarantees exclusive
        // access to the region for the lifetime of the returned slice.
        Some(unsafe { std::slice::from_raw_parts_mut(self.area.add(offset), self.frame_size as usize) })
    }

    /// Get a slice for a frame. Returns `None` if `frame_idx` is out of bounds.
    pub fn frame_slice(&self, frame_idx: u32, len: usize) -> Option<&[u8]> {
        let offset = frame_idx as usize * self.frame_size as usize;
        if offset >= self.area_size {
            return None;
        }
        // Safety: bounds-checked above; the returned slice is shared and
        // cannot outlive `&self`.
        Some(unsafe { std::slice::from_raw_parts(self.area.add(offset), len.min(self.frame_size as usize)) })
    }

    /// Allocate a free frame. Returns the frame index.
    pub fn alloc_frame(&mut self) -> Result<u32, XdpError> {
        self.free_frames.pop().ok_or(XdpError::NoFrames)
    }

    /// Return a frame to the free pool.
    pub fn free_frame(&mut self, idx: u32) {
        self.free_frames.push(idx);
    }

    /// Number of free frames available.
    pub fn free_count(&self) -> usize {
        self.free_frames.len()
    }

    /// Base address of the UMEM region (for kernel registration).
    pub fn area_ptr(&self) -> *mut u8 {
        self.area
    }

    /// Total size of the UMEM region.
    pub fn area_size(&self) -> usize {
        self.area_size
    }

    /// Frame size.
    pub fn frame_size(&self) -> u32 {
        self.frame_size
    }

    /// Address (byte offset) for a frame index.
    pub fn frame_addr(&self, idx: u32) -> u64 {
        idx as u64 * self.frame_size as u64
    }
}

impl Drop for Umem {
    fn drop(&mut self) {
        if !self.area.is_null() {
            unsafe {
                libc::munmap(self.area as *mut _, self.area_size);
            }
        }
    }
}

// Safety: Umem is only accessed from a single thread (the XDP sender/receiver).
unsafe impl Send for Umem {}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_umem() -> Umem {
        Umem::new(&UmemConfig {
            frame_size: 4096,
            frame_count: 8,
            fill_size: 8,
            comp_size: 8,
        })
        .expect("umem alloc")
    }

    #[test]
    fn frame_slice_mut_roundtrip() {
        let mut umem = test_umem();
        let idx = umem.alloc_frame().unwrap();
        {
            let frame = umem.frame_slice_mut(idx).expect("in-bounds frame");
            assert_eq!(frame.len(), 4096);
            frame[0] = 0xAB;
            frame[4095] = 0xCD;
        }
        let frame = umem.frame_slice(idx, 4096).expect("in-bounds frame");
        assert_eq!(frame[0], 0xAB);
        assert_eq!(frame[4095], 0xCD);
    }

    #[test]
    fn out_of_bounds_frame_index_returns_none() {
        let mut umem = test_umem();
        // These are real runtime checks — they must hold in release builds
        // too, not just under debug_assert.
        assert!(umem.frame_slice_mut(8).is_none());
        assert!(umem.frame_slice_mut(u32::MAX).is_none());
        assert!(umem.frame_slice(8, 100).is_none());
        assert!(umem.frame_slice(u32::MAX, 100).is_none());
    }

    #[test]
    #[should_panic(expected = "out of bounds")]
    fn frame_ptr_out_of_bounds_panics() {
        let umem = test_umem();
        let _ = umem.frame_ptr(8);
    }

    #[test]
    fn alloc_exhaustion_and_free() {
        let mut umem = test_umem();
        let mut idxs = Vec::new();
        for _ in 0..8 {
            idxs.push(umem.alloc_frame().unwrap());
        }
        assert_eq!(umem.free_count(), 0);
        assert!(matches!(umem.alloc_frame(), Err(XdpError::NoFrames)));
        umem.free_frame(idxs.pop().unwrap());
        assert_eq!(umem.free_count(), 1);
        assert!(umem.alloc_frame().is_ok());
    }
}
