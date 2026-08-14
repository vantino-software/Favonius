// Favonius — high-performance file transfer over UDP
// Copyright (c) 2025-2026 Vantino SàRL
// SPDX-License-Identifier: Apache-2.0

//! Adaptive compression policy.
//!
//! Provides heuristics to decide whether data should be compressed and at which
//! profile, based on a quick entropy estimate of the payload.

use crate::CompressionProfile;

/// Decide whether data should be compressed, and at what profile.
///
/// Uses simple entropy estimation: if the data appears already compressed or
/// random (high entropy), skip compression.
pub fn select_profile(data: &[u8], hint: CompressionProfile) -> CompressionProfile {
    if hint == CompressionProfile::None {
        return CompressionProfile::None;
    }

    // Simple heuristic: sample first 1024 bytes, count unique values.
    // If > 250 unique byte values, data is likely incompressible.
    let sample_size = data.len().min(1024);
    if sample_size == 0 {
        return CompressionProfile::None;
    }

    let mut seen = [false; 256];
    let mut unique = 0usize;
    for &b in &data[..sample_size] {
        if !seen[b as usize] {
            seen[b as usize] = true;
            unique += 1;
        }
    }

    if unique > 250 {
        CompressionProfile::None
    } else {
        hint
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn low_entropy_returns_hint() {
        // Repetitive data has very few unique byte values.
        let data = vec![b'a'; 2048];
        let result = select_profile(&data, CompressionProfile::ZstdBalanced);
        assert_eq!(result, CompressionProfile::ZstdBalanced);
    }

    #[test]
    fn high_entropy_returns_none() {
        // Data with all 256 byte values in the first 256 bytes is high-entropy.
        let data: Vec<u8> = (0..=255).cycle().take(1024).collect();
        let result = select_profile(&data, CompressionProfile::ZstdBalanced);
        assert_eq!(result, CompressionProfile::None);
    }

    #[test]
    fn hint_none_always_returns_none() {
        let data = vec![b'a'; 512];
        let result = select_profile(&data, CompressionProfile::None);
        assert_eq!(result, CompressionProfile::None);
    }

    #[test]
    fn empty_data_returns_none() {
        let result = select_profile(&[], CompressionProfile::ZstdFast);
        assert_eq!(result, CompressionProfile::None);
    }

    #[test]
    fn moderate_entropy_returns_hint() {
        // 200 unique values is under the 250 threshold.
        let data: Vec<u8> = (0..200u8).cycle().take(1024).collect();
        let result = select_profile(&data, CompressionProfile::ZstdStreaming);
        assert_eq!(result, CompressionProfile::ZstdStreaming);
    }

    #[test]
    fn boundary_250_unique_returns_hint() {
        // Exactly 250 unique byte values should still compress (> 250 is the cutoff).
        let data: Vec<u8> = (0..250u8).cycle().take(1024).collect();
        let result = select_profile(&data, CompressionProfile::ZstdFast);
        assert_eq!(result, CompressionProfile::ZstdFast);
    }

    #[test]
    fn boundary_251_unique_returns_none() {
        // 251 unique byte values exceeds the threshold.
        let data: Vec<u8> = (0..=250u8).cycle().take(1024).collect();
        let result = select_profile(&data, CompressionProfile::ZstdFast);
        assert_eq!(result, CompressionProfile::None);
    }
}
