// Favonius — high-performance file transfer over UDP
// Copyright (c) 2025-2026 Vantino SàRL
// SPDX-License-Identifier: Apache-2.0

//! Header protection: masks sensitive header fields from on-path observers.
//!
//! Inspired by QUIC header protection (RFC 9001 §5.4). Generates a
//! pseudorandom mask from the `header_protection_key` and XORs it over
//! the packet_number and connection_id fields. The packet_type, version,
//! and payload_length remain visible (needed for routing/demuxing).
//!
//! Protected fields (byte offsets in the 42-byte header):
//! - `[6..14]`  connection_id (8 bytes) — prevents correlation by observers
//! - `[18..26]` packet_number (8 bytes) — prevents traffic analysis
//!
//! The mask is derived by encrypting a 16-byte sample of the encrypted
//! payload using AES-128-ECB with the header_protection_key (QUIC-style,
//! RFC 9001 §5.4.1). A full-width sample is essential: a shorter sample would
//! let an on-path observer link packets by connection_id after ~2^(n/2)
//! packets (birthday bound) — exactly the correlation header protection
//! exists to prevent.

use aes::cipher::{BlockEncrypt, KeyInit};
use aes::Aes128;

/// Header byte offsets for protected fields.
const CONN_ID_OFFSET: usize = 6;
const CONN_ID_LEN: usize = 8;
const PKT_NUM_OFFSET: usize = 18;
const PKT_NUM_LEN: usize = 8;

/// Header protector using AES-128-ECB to generate masks.
#[derive(Debug)]
pub struct HeaderProtector {
    cipher: Aes128,
}

impl HeaderProtector {
    /// Create a header protector from the 16-byte header_protection_key.
    pub fn new(key: &[u8; 16]) -> Self {
        Self {
            cipher: Aes128::new(key.into()),
        }
    }

    /// Generate a 16-byte mask from a 16-byte sample.
    /// The sample is taken from the first 16 bytes of the encrypted payload
    /// (always available: AEAD ciphertext carries a 16-byte tag), so the
    /// mask varies per packet with full 128-bit entropy.
    fn generate_mask(&self, sample: &[u8; 16]) -> [u8; 16] {
        let mut block = aes::Block::default();
        block.copy_from_slice(sample);
        // AES-ECB encrypt the sample to produce the mask.
        self.cipher.encrypt_block(&mut block);
        let mut mask = [0u8; 16];
        mask.copy_from_slice(&block);
        mask
    }

    /// Apply header protection to a packet buffer (in-place).
    /// `header` must be at least 42 bytes. `payload_start` is the offset
    /// where the (possibly encrypted) payload begins.
    ///
    /// Call this AFTER encrypting the payload (so the sample is from ciphertext).
    pub fn protect(&self, buf: &mut [u8], payload_start: usize) {
        if buf.len() < 42 {
            return;
        }
        let sample = self.extract_sample(buf, payload_start);
        let mask = self.generate_mask(&sample);

        // XOR mask over connection_id and packet_number.
        for i in 0..CONN_ID_LEN {
            buf[CONN_ID_OFFSET + i] ^= mask[i];
        }
        for i in 0..PKT_NUM_LEN {
            buf[PKT_NUM_OFFSET + i] ^= mask[CONN_ID_LEN + i];
        }
    }

    /// Remove header protection from a packet buffer (in-place).
    /// Inverse of `protect` — XOR is its own inverse.
    pub fn unprotect(&self, buf: &mut [u8], payload_start: usize) {
        // XOR is self-inverse: protect and unprotect are the same operation.
        self.protect(buf, payload_start);
    }

    /// Extract the 16-byte sample for mask generation.
    fn extract_sample(&self, buf: &[u8], payload_start: usize) -> [u8; 16] {
        let mut sample = [0u8; 16];
        let available = buf.len().saturating_sub(payload_start);
        let n = available.min(16);
        if n > 0 {
            // Sample from the start of the payload (ciphertext). Short
            // payloads leave the remainder zero — both sides compute the
            // sample over the same wire bytes, so they stay in sync.
            sample[..n].copy_from_slice(&buf[payload_start..payload_start + n]);
        }
        sample
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> [u8; 16] {
        [0xAB; 16]
    }

    #[test]
    fn protect_unprotect_roundtrip() {
        let hp = HeaderProtector::new(&test_key());

        // Build a fake 64-byte packet (42 header + 22 payload).
        let mut buf = vec![0u8; 64];
        // Set some recognizable header fields.
        buf[6..14].copy_from_slice(&0x1234567890ABCDEFu64.to_be_bytes()); // conn_id
        buf[18..26].copy_from_slice(&42u64.to_be_bytes()); // pkt_num
        // Set some payload bytes (the first 16 are the mask sample).
        buf[42..58].copy_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);

        let original = buf.clone();

        // Protect.
        hp.protect(&mut buf, 42);
        // connection_id and packet_number should be masked.
        assert_ne!(&buf[6..14], &original[6..14]);
        assert_ne!(&buf[18..26], &original[18..26]);
        // Version, packet_type, flags should be unchanged.
        assert_eq!(buf[0], original[0]);
        assert_eq!(buf[1], original[1]);
        assert_eq!(&buf[2..4], &original[2..4]);

        // Unprotect.
        hp.unprotect(&mut buf, 42);
        assert_eq!(&buf[6..14], &original[6..14]);
        assert_eq!(&buf[18..26], &original[18..26]);
    }

    #[test]
    fn different_payloads_produce_different_masks() {
        let hp = HeaderProtector::new(&test_key());

        let mut buf1 = vec![0u8; 64];
        buf1[6..14].copy_from_slice(&1u64.to_be_bytes());
        buf1[42..58].copy_from_slice(&[1, 2, 3, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);

        let mut buf2 = buf1.clone();
        buf2[42..58].copy_from_slice(&[5, 6, 7, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);

        hp.protect(&mut buf1, 42);
        hp.protect(&mut buf2, 42);

        // Different payload samples → different masks → different protected conn_ids.
        assert_ne!(&buf1[6..14], &buf2[6..14]);
    }

    #[test]
    fn sample_uses_full_16_bytes() {
        // S10 regression: the sample must cover 16 bytes, not just the first
        // 4 — two packets differing only in sample bytes 4..16 must still
        // produce different masks (otherwise ~2^16 packets suffice to link
        // packets by connection_id via the birthday bound).
        let hp = HeaderProtector::new(&test_key());

        let mut buf1 = vec![0u8; 64];
        buf1[6..14].copy_from_slice(&7u64.to_be_bytes());
        buf1[42..58].copy_from_slice(&[1, 2, 3, 4, 0xAA, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);

        let mut buf2 = buf1.clone();
        buf2[42..58].copy_from_slice(&[1, 2, 3, 4, 0xBB, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);

        hp.protect(&mut buf1, 42);
        hp.protect(&mut buf2, 42);

        assert_ne!(&buf1[6..14], &buf2[6..14]);
    }

    #[test]
    fn short_payload_sample_is_deterministic() {
        // Payload shorter than 16 bytes: zero-padded sample, identical on
        // both sides since it is computed over the same wire bytes.
        let hp = HeaderProtector::new(&test_key());

        let mut buf1 = vec![0u8; 46]; // 42 header + 4 payload
        buf1[6..14].copy_from_slice(&9u64.to_be_bytes());
        buf1[42..46].copy_from_slice(&[0xCA, 0xFE, 0xBA, 0xBE]);
        let mut buf2 = buf1.clone();

        hp.protect(&mut buf1, 42);
        hp.protect(&mut buf2, 42);
        assert_eq!(buf1, buf2);

        hp.unprotect(&mut buf1, 42);
        assert_eq!(&buf1[6..14], &9u64.to_be_bytes());
    }

    #[test]
    fn protect_is_deterministic() {
        let hp = HeaderProtector::new(&test_key());

        let mut buf1 = vec![0xAA; 64];
        let mut buf2 = buf1.clone();

        hp.protect(&mut buf1, 42);
        hp.protect(&mut buf2, 42);
        assert_eq!(buf1, buf2);
    }
}
