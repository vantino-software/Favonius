// Favonius — high-performance file transfer over UDP
// Copyright (c) 2025-2026 Vantino SàRL
// SPDX-License-Identifier: Apache-2.0

//! Zstd-based compressor implementing the AHP [`Compressor`] trait.

use std::io::Read;

use bytes::Bytes;

use crate::{CompressionError, CompressionProfile, Compressor};

/// Zstd-based compressor implementing the AHP Compressor trait.
#[derive(Debug)]
pub struct ZstdCompressor {
    profile: CompressionProfile,
    level: i32,
}

impl ZstdCompressor {
    /// Create a new Zstd compressor for the given profile.
    pub fn new(profile: CompressionProfile) -> Result<Self, CompressionError> {
        let level = profile
            .zstd_level()
            .ok_or(CompressionError::UnsupportedProfile(profile))?;
        Ok(Self { profile, level })
    }

    /// Decompress with a hard cap on the output size.
    ///
    /// Network-facing receive paths must use this instead of
    /// [`Compressor::decompress`] so a malicious or corrupt packet cannot
    /// expand into an unbounded allocation ("decompression bomb"). The cap
    /// is typically the transfer's expected payload size. Returns
    /// [`CompressionError::DecompressedTooLarge`] if the decoded output
    /// would exceed `max_size` bytes.
    pub fn decompress_bounded(
        &self,
        data: &[u8],
        max_size: usize,
    ) -> Result<Bytes, CompressionError> {
        let decoder = zstd::Decoder::new(data)
            .map_err(|e| CompressionError::DecompressFailed(e.to_string()))?;
        // Read at most max_size + 1 bytes to detect overflow without ever
        // buffering more than that.
        let mut out = Vec::new();
        decoder
            .take(max_size as u64 + 1)
            .read_to_end(&mut out)
            .map_err(|e| CompressionError::DecompressFailed(e.to_string()))?;
        if out.len() > max_size {
            return Err(CompressionError::DecompressedTooLarge {
                actual: out.len(),
                max: max_size,
            });
        }
        Ok(Bytes::from(out))
    }

    /// Create a reusable bulk compression context bound to this profile's
    /// level. Hot paths should create one context per transfer and pass it
    /// to [`ZstdCompressor::compress_with`] instead of paying for a fresh
    /// zstd context (`encode_all`) on every chunk.
    pub fn bulk_compressor(&self) -> Result<zstd::bulk::Compressor<'static>, CompressionError> {
        zstd::bulk::Compressor::new(self.level)
            .map_err(|e| CompressionError::CompressFailed(e.to_string()))
    }

    /// Create a reusable bulk decompression context for
    /// [`ZstdCompressor::decompress_bounded_with`].
    pub fn bulk_decompressor(&self) -> Result<zstd::bulk::Decompressor<'static>, CompressionError> {
        zstd::bulk::Decompressor::new()
            .map_err(|e| CompressionError::DecompressFailed(e.to_string()))
    }

    /// Compress using a reusable context created by [`Self::bulk_compressor`].
    ///
    /// Produces the same self-contained frame format as [`Compressor::compress`];
    /// output is decodable by `decompress`, `decompress_bounded` and
    /// `decompress_bounded_with` alike.
    pub fn compress_with(
        &self,
        ctx: &mut zstd::bulk::Compressor<'_>,
        data: &[u8],
    ) -> Result<Bytes, CompressionError> {
        ctx.compress(data)
            .map(Bytes::from)
            .map_err(|e| CompressionError::CompressFailed(e.to_string()))
    }

    /// [`Self::decompress_bounded`] using a reusable context created by
    /// [`Self::bulk_decompressor`]. The hard output cap is unchanged: the
    /// destination buffer is exactly `max_size` bytes and any frame that
    /// would expand beyond it fails with
    /// [`CompressionError::DecompressedTooLarge`] without ever allocating
    /// more than the cap.
    pub fn decompress_bounded_with(
        &self,
        ctx: &mut zstd::bulk::Decompressor<'_>,
        data: &[u8],
        max_size: usize,
    ) -> Result<Bytes, CompressionError> {
        let mut out = vec![0u8; max_size];
        match ctx.decompress_to_buffer(data, &mut out) {
            Ok(n) => {
                out.truncate(n);
                Ok(Bytes::from(out))
            }
            Err(e) => {
                // zstd reports expansion past the destination buffer with
                // this exact error name (ZSTD_error_dstSize_tooSmall).
                if e.to_string().contains("Destination buffer is too small") {
                    Err(CompressionError::DecompressedTooLarge {
                        actual: max_size + 1,
                        max: max_size,
                    })
                } else {
                    Err(CompressionError::DecompressFailed(e.to_string()))
                }
            }
        }
    }
}

impl Compressor for ZstdCompressor {
    fn compress(&self, data: &[u8]) -> Result<Bytes, CompressionError> {
        let compressed = zstd::encode_all(data, self.level)
            .map_err(|e| CompressionError::CompressFailed(e.to_string()))?;
        Ok(Bytes::from(compressed))
    }

    fn decompress(&self, data: &[u8]) -> Result<Bytes, CompressionError> {
        let decompressed = zstd::decode_all(data)
            .map_err(|e| CompressionError::DecompressFailed(e.to_string()))?;
        Ok(Bytes::from(decompressed))
    }

    fn profile(&self) -> CompressionProfile {
        self.profile
    }
}

/// Create a compressor for the given profile. Returns `None` for
/// [`CompressionProfile::None`].
pub fn create_compressor(profile: CompressionProfile) -> Option<ZstdCompressor> {
    match profile {
        CompressionProfile::None => None,
        other => ZstdCompressor::new(other).ok(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: roundtrip compress then decompress and assert equality.
    fn roundtrip(profile: CompressionProfile, data: &[u8]) {
        let compressor = ZstdCompressor::new(profile).expect("should create compressor");
        let compressed = compressor.compress(data).expect("compress should succeed");
        let decompressed = compressor
            .decompress(&compressed)
            .expect("decompress should succeed");
        assert_eq!(decompressed.as_ref(), data);
    }

    #[test]
    fn roundtrip_fast() {
        roundtrip(CompressionProfile::ZstdFast, b"hello world! this is a test of zstd fast compression.");
    }

    #[test]
    fn roundtrip_balanced() {
        roundtrip(CompressionProfile::ZstdBalanced, b"hello world! this is a test of zstd balanced compression.");
    }

    #[test]
    fn roundtrip_streaming() {
        roundtrip(CompressionProfile::ZstdStreaming, b"hello world! this is a test of zstd streaming compression.");
    }

    #[test]
    fn roundtrip_empty_data() {
        for profile in [
            CompressionProfile::ZstdFast,
            CompressionProfile::ZstdBalanced,
            CompressionProfile::ZstdStreaming,
        ] {
            roundtrip(profile, b"");
        }
    }

    #[test]
    fn none_profile_errors() {
        let result = ZstdCompressor::new(CompressionProfile::None);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, CompressionError::UnsupportedProfile(CompressionProfile::None)),
            "expected UnsupportedProfile(None), got: {err:?}"
        );
    }

    #[test]
    fn create_compressor_returns_none_for_none_profile() {
        assert!(create_compressor(CompressionProfile::None).is_none());
    }

    #[test]
    fn create_compressor_returns_some_for_valid_profiles() {
        assert!(create_compressor(CompressionProfile::ZstdFast).is_some());
        assert!(create_compressor(CompressionProfile::ZstdBalanced).is_some());
        assert!(create_compressor(CompressionProfile::ZstdStreaming).is_some());
    }

    #[test]
    fn profile_accessor() {
        let c = ZstdCompressor::new(CompressionProfile::ZstdBalanced).unwrap();
        assert_eq!(c.profile(), CompressionProfile::ZstdBalanced);
    }

    #[test]
    fn decompress_bounded_within_limit_roundtrips() {
        let data = b"hello world! this payload fits within the limit.";
        let compressor = ZstdCompressor::new(CompressionProfile::ZstdBalanced).unwrap();
        let compressed = compressor.compress(data).unwrap();
        let decompressed = compressor
            .decompress_bounded(&compressed, data.len())
            .expect("within-limit decompress should succeed");
        assert_eq!(decompressed.as_ref(), data);
    }

    #[test]
    fn decompress_bounded_rejects_expansion_bomb() {
        // Highly compressible data: small on the wire, huge decoded.
        let data = vec![0u8; 1024 * 1024];
        let compressor = ZstdCompressor::new(CompressionProfile::ZstdBalanced).unwrap();
        let compressed = compressor.compress(&data).unwrap();
        assert!(compressed.len() < data.len());

        let err = compressor
            .decompress_bounded(&compressed, 4096)
            .expect_err("expansion beyond the limit must fail");
        assert!(
            matches!(
                err,
                CompressionError::DecompressedTooLarge { max: 4096, .. }
            ),
            "expected DecompressedTooLarge, got: {err:?}"
        );
    }

    #[test]
    fn reusable_context_roundtrip_cross_compatible() {
        // Frames produced via the reusable context must decode through the
        // one-shot APIs and vice versa (same wire format).
        let data = b"reusable context roundtrip: same frame format either way.";
        let compressor = ZstdCompressor::new(CompressionProfile::ZstdFast).unwrap();
        let mut cctx = compressor.bulk_compressor().unwrap();
        let mut dctx = compressor.bulk_decompressor().unwrap();

        let compressed = compressor.compress_with(&mut cctx, data).unwrap();
        assert_eq!(
            compressor.decompress(&compressed).unwrap().as_ref(),
            data
        );
        assert_eq!(
            compressor
                .decompress_bounded_with(&mut dctx, &compressed, data.len())
                .unwrap()
                .as_ref(),
            data
        );

        // And the one-shot encode must decode via the reusable context.
        let one_shot = compressor.compress(data).unwrap();
        assert_eq!(
            compressor
                .decompress_bounded_with(&mut dctx, &one_shot, data.len())
                .unwrap()
                .as_ref(),
            data
        );

        // The context survives many chunks (state reset between frames).
        for _ in 0..64 {
            let c = compressor.compress_with(&mut cctx, data).unwrap();
            assert_eq!(
                compressor
                    .decompress_bounded_with(&mut dctx, &c, data.len())
                    .unwrap()
                    .as_ref(),
                data
            );
        }
    }

    #[test]
    fn decompress_bounded_with_rejects_expansion_bomb() {
        let data = vec![0u8; 1024 * 1024];
        let compressor = ZstdCompressor::new(CompressionProfile::ZstdBalanced).unwrap();
        let compressed = compressor.compress(&data).unwrap();
        let mut dctx = compressor.bulk_decompressor().unwrap();

        let err = compressor
            .decompress_bounded_with(&mut dctx, &compressed, 4096)
            .expect_err("expansion beyond the limit must fail");
        assert!(
            matches!(
                err,
                CompressionError::DecompressedTooLarge { max: 4096, .. }
            ),
            "expected DecompressedTooLarge, got: {err:?}"
        );
    }
}
