// Favonius — high-performance file transfer over UDP
// Copyright (c) 2025-2026 Vantino SàRL
// SPDX-License-Identifier: Apache-2.0

//! Key rotation via KEY_UPDATE.
//!
//! Derives a new set of session keys from the current `rekey_secret`,
//! producing a fresh key epoch. Each rotation increments the epoch counter
//! and produces completely independent keys via HKDF.
//!
//! Rotation triggers:
//! - Packet count exceeds 2^30 (conservative limit; the nonce space is 2^64
//!   per key — a 64-bit packet sequence XORed into the 12-byte IV)
//! - Explicit KEY_UPDATE request from the peer
//! - Periodic timer (configurable, default disabled)

use hkdf::Hkdf;
use sha2::Sha256;

use crate::{CryptoError, SessionKeys};

/// Maximum packets before mandatory key rotation.
/// Conservative: 2^30 (~1 billion). The nonce space is 2^64 per key
/// (64-bit packet sequence XORed into the 12-byte IV), so rotating at
/// 2^30 leaves an enormous safety margin.
pub const MAX_PACKETS_PER_KEY: u64 = 1 << 30;

/// Tracks the current key epoch and packet count.
#[derive(Debug, Clone)]
pub struct KeyEpoch {
    /// Current epoch number (starts at 0, increments on each rotation).
    pub epoch: u64,
    /// Packets encrypted with the current key.
    pub packet_count: u64,
    /// Current session keys.
    pub keys: SessionKeys,
    /// Previous epoch's keys, retained for a one-epoch authentication grace
    /// window (RFC §13.3): control packets sealed just before the last
    /// rotation must still authenticate. Replaced on every rotation, so at
    /// most one previous epoch is ever kept; the displaced keys are
    /// zeroized on drop.
    previous_keys: Option<SessionKeys>,
}

impl KeyEpoch {
    /// Create epoch 0 from initial handshake keys.
    pub fn new(keys: SessionKeys) -> Self {
        Self {
            epoch: 0,
            packet_count: 0,
            keys,
            previous_keys: None,
        }
    }

    /// Previous epoch's keys (the grace window), if a rotation has occurred.
    pub fn previous_keys(&self) -> Option<&SessionKeys> {
        self.previous_keys.as_ref()
    }

    /// Record that a packet was encrypted. Returns true if rotation is needed.
    pub fn on_packet_encrypted(&mut self) -> bool {
        self.packet_count += 1;
        self.packet_count >= MAX_PACKETS_PER_KEY
    }

    /// Rotate to the next key epoch.
    ///
    /// Derives new keys from the current `rekey_secret` + epoch counter.
    /// The new `rekey_secret` is also derived, enabling chained rotations.
    /// The outgoing keys become the previous-epoch grace window.
    pub fn rotate(&mut self) -> Result<(), CryptoError> {
        let new_keys = derive_next_keys(&self.keys)?;
        let old_keys = std::mem::replace(&mut self.keys, new_keys);
        self.previous_keys = Some(old_keys);
        self.epoch += 1;
        self.packet_count = 0;
        tracing::info!(epoch = self.epoch, "key rotation complete");
        Ok(())
    }
}

/// Derive the next epoch's session keys from the current rekey_secret.
///
/// Uses HKDF with the rekey_secret as IKM and the string "ahp-key-update-N"
/// (where N is implicit from the chained secret) as salt.
pub fn derive_next_keys(current: &SessionKeys) -> Result<SessionKeys, CryptoError> {
    let hk = Hkdf::<Sha256>::new(Some(b"ahp-key-update"), &current.rekey_secret);

    let mut keys = SessionKeys::zeroed();

    hk.expand(b"ahp-control-key-next", &mut keys.control_key)
        .map_err(|e| CryptoError::KeyDerivationFailed(e.to_string()))?;
    hk.expand(b"ahp-data-key-next", &mut keys.data_key)
        .map_err(|e| CryptoError::KeyDerivationFailed(e.to_string()))?;
    hk.expand(b"ahp-sync-key-next", &mut keys.sync_key)
        .map_err(|e| CryptoError::KeyDerivationFailed(e.to_string()))?;
    hk.expand(b"ahp-header-protect-next", &mut keys.header_protection_key)
        .map_err(|e| CryptoError::KeyDerivationFailed(e.to_string()))?;
    hk.expand(b"ahp-rekey-next", &mut keys.rekey_secret)
        .map_err(|e| CryptoError::KeyDerivationFailed(e.to_string()))?;
    hk.expand(b"ahp-resume-next", &mut keys.resume_secret)
        .map_err(|e| CryptoError::KeyDerivationFailed(e.to_string()))?;
    hk.expand(b"ahp-data-iv-next", &mut keys.data_iv)
        .map_err(|e| CryptoError::KeyDerivationFailed(e.to_string()))?;
    hk.expand(b"ahp-control-iv-next", &mut keys.control_iv)
        .map_err(|e| CryptoError::KeyDerivationFailed(e.to_string()))?;

    Ok(keys)
}

/// Encode a KEY_UPDATE packet payload.
/// Format: [8-byte new_epoch BE] (network byte order, like every header field)
pub fn encode_key_update(new_epoch: u64) -> [u8; 8] {
    new_epoch.to_be_bytes()
}

/// Decode a KEY_UPDATE packet payload.
pub fn decode_key_update(payload: &[u8]) -> Option<u64> {
    if payload.len() < 8 { return None; }
    Some(u64::from_be_bytes([
        payload[0], payload[1], payload[2], payload[3],
        payload[4], payload[5], payload[6], payload[7],
    ]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key_exchange::generate_keypair;
    use crate::key_schedule::derive_session_keys;

    fn make_keys() -> SessionKeys {
        let alice = generate_keypair();
        let bob = generate_keypair();
        let shared = crate::key_exchange::diffie_hellman(&alice.private, &bob.public).unwrap();
        derive_session_keys(&shared, b"init-nonce", b"resp-nonce").unwrap()
    }

    #[test]
    fn rotation_produces_different_keys() {
        let keys = make_keys();
        let next = derive_next_keys(&keys).unwrap();

        assert_ne!(keys.data_key, next.data_key);
        assert_ne!(keys.control_key, next.control_key);
        assert_ne!(keys.rekey_secret, next.rekey_secret);
    }

    #[test]
    fn chained_rotations_produce_unique_keys() {
        let k0 = make_keys();
        let k1 = derive_next_keys(&k0).unwrap();
        let k2 = derive_next_keys(&k1).unwrap();

        assert_ne!(k0.data_key, k1.data_key);
        assert_ne!(k1.data_key, k2.data_key);
        assert_ne!(k0.data_key, k2.data_key);
    }

    #[test]
    fn epoch_tracks_count() {
        let keys = make_keys();
        let mut epoch = KeyEpoch::new(keys);
        assert_eq!(epoch.epoch, 0);
        assert_eq!(epoch.packet_count, 0);

        for _ in 0..100 {
            epoch.on_packet_encrypted();
        }
        assert_eq!(epoch.packet_count, 100);
    }

    #[test]
    fn rotation_resets_counter() {
        let keys = make_keys();
        let mut epoch = KeyEpoch::new(keys);
        epoch.packet_count = 1000;
        epoch.rotate().unwrap();
        assert_eq!(epoch.epoch, 1);
        assert_eq!(epoch.packet_count, 0);
    }

    #[test]
    fn encode_decode_roundtrip() {
        let buf = encode_key_update(42);
        assert_eq!(decode_key_update(&buf), Some(42));
    }

    #[test]
    fn epoch_is_big_endian_on_the_wire() {
        // Wire convention: multi-byte integers are network byte order,
        // matching every ahp-proto header field.
        let buf = encode_key_update(0x0102_0304_0506_0708);
        assert_eq!(buf, [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
        assert_eq!(decode_key_update(&buf), Some(0x0102_0304_0506_0708));
    }

    #[test]
    fn rotation_retains_one_previous_epoch() {
        let keys = make_keys();
        let k0_control = keys.control_key;
        let mut epoch = KeyEpoch::new(keys);
        assert!(epoch.previous_keys().is_none());

        epoch.rotate().unwrap();
        assert_eq!(epoch.previous_keys().unwrap().control_key, k0_control);

        // The second rotation displaces the epoch-0 keys: at most one
        // previous epoch is ever kept in the grace window.
        let k1_control = epoch.keys.control_key;
        epoch.rotate().unwrap();
        assert_eq!(epoch.previous_keys().unwrap().control_key, k1_control);
    }
}
