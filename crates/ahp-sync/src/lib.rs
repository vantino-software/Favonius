// Favonius — high-performance file transfer over UDP
// Copyright (c) 2025-2026 Vantino SàRL
// SPDX-License-Identifier: Apache-2.0

//! AHP-S sync plane.
//!
//! Currently only the Merkle tree code is live: the daemon and CLI use it
//! on the resume path to identify which regions of a partially transferred
//! file still need retransmission. The delta/rolling-hash/region/conflict
//! modules were removed as dead code (see git history).

pub mod merkle;

/// A region map describing the hash fingerprint of each region (chunk) in a file.
///
/// Exchanged during sync to identify which regions differ between peers.
/// Each entry maps a region index to its BLAKE3 hash.
#[derive(Debug, Clone)]
pub struct RegionMap {
    /// File path relative to the sync root.
    pub path: String,
    /// Total file size at the time the map was computed.
    pub file_size: u64,
    /// Region (chunk) size used for splitting.
    pub region_size: u32,
    /// Ordered list of BLAKE3 hashes, one per region.
    pub hashes: Vec<[u8; 32]>,
}

impl RegionMap {
    /// Number of regions in this map.
    pub fn region_count(&self) -> usize {
        self.hashes.len()
    }
}

/// Errors from sync operations.
#[derive(Debug, thiserror::Error)]
pub enum SyncError {
    #[error("invalid payload size {0}: must be greater than zero")]
    InvalidPayloadSize(usize),
}
