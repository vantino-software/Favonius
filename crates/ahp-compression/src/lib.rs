// Favonius — high-performance file transfer over UDP
// Copyright (c) 2025-2026 Vantino SàRL
// SPDX-License-Identifier: Apache-2.0

//! AHP compression layer.
//!
//! Provides per-chunk compression using Zstandard with multiple profiles
//! tuned for different data types and throughput targets. An adaptive policy
//! can select the profile automatically based on content analysis.

pub mod policy;
pub mod zstd_impl;

use bytes::Bytes;

/// Compression profile controlling the trade-off between compression ratio
/// and CPU overhead.
///
/// Selected per-transfer or per-file based on content type heuristics or
/// explicit user configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CompressionProfile {
    /// No compression (pass-through). Used for already-compressed media.
    None,
    /// Zstd at level 1: minimal CPU, modest ratio. Good for high-throughput
    /// transfers of binary data where every cycle counts.
    ZstdFast,
    /// Zstd at level 3: balanced ratio and speed. Default for text and
    /// general-purpose data.
    ZstdBalanced,
    /// Zstd streaming mode with dictionary: best for log files and
    /// repetitive data where a pre-trained dictionary boosts ratio.
    ZstdStreaming,
}

impl CompressionProfile {
    /// Zstd compression level for this profile, or `None` for pass-through.
    pub fn zstd_level(&self) -> Option<i32> {
        match self {
            Self::None => None,
            Self::ZstdFast => Some(1),
            Self::ZstdBalanced => Some(3),
            Self::ZstdStreaming => Some(6),
        }
    }
}

impl Default for CompressionProfile {
    fn default() -> Self {
        Self::ZstdBalanced
    }
}

/// Trait for compressing and decompressing chunk data.
///
/// Implementations are stateless per call; any dictionary state is managed
/// internally by the implementation.
pub trait Compressor: Send + Sync {
    /// Compress the input data using the configured profile.
    ///
    /// Returns `Ok(compressed)` on success. If the compressed output is larger
    /// than the input, implementations should return the original data
    /// uncompressed and signal via the `was_compressed` flag in the packet.
    fn compress(&self, data: &[u8]) -> Result<Bytes, CompressionError>;

    /// Decompress previously compressed data.
    fn decompress(&self, data: &[u8]) -> Result<Bytes, CompressionError>;

    /// The compression profile this compressor uses.
    fn profile(&self) -> CompressionProfile;
}

/// Errors from compression operations.
#[derive(Debug, thiserror::Error)]
pub enum CompressionError {
    #[error("compression failed: {0}")]
    CompressFailed(String),

    #[error("decompression failed: {0}")]
    DecompressFailed(String),

    #[error("decompressed size {actual} exceeds maximum allowed {max}")]
    DecompressedTooLarge { actual: usize, max: usize },

    #[error("unsupported compression profile: {0:?}")]
    UnsupportedProfile(CompressionProfile),
}
