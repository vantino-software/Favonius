// Favonius — high-performance file transfer over UDP
// Copyright (c) 2025-2026 Vantino SàRL
// SPDX-License-Identifier: Apache-2.0

//! HKDF-SHA256 key schedule.
//!
//! Derives the six independent session keys from the X25519 shared secret
//! and the initiator/responder nonces exchanged during the handshake.

use hkdf::Hkdf;
use sha2::Sha256;

use crate::{CryptoError, SessionKeys};

/// Derive a full set of session keys from the shared secret and handshake nonces.
///
/// The salt is the concatenation of `initiator_nonce || responder_nonce`.
/// Each key is derived using a distinct info string so that compromise of one
/// key does not reveal the others.
pub fn derive_session_keys(
    shared_secret: &[u8; 32],
    initiator_nonce: &[u8],
    responder_nonce: &[u8],
) -> Result<SessionKeys, CryptoError> {
    // Build the salt from both nonces.
    let mut salt = Vec::with_capacity(initiator_nonce.len() + responder_nonce.len());
    salt.extend_from_slice(initiator_nonce);
    salt.extend_from_slice(responder_nonce);

    let hk = Hkdf::<Sha256>::new(Some(&salt), shared_secret);

    let mut keys = SessionKeys::zeroed();

    hk.expand(b"ahp-control-key", &mut keys.control_key)
        .map_err(|e| CryptoError::KeyDerivationFailed(e.to_string()))?;
    hk.expand(b"ahp-data-key", &mut keys.data_key)
        .map_err(|e| CryptoError::KeyDerivationFailed(e.to_string()))?;
    hk.expand(b"ahp-sync-key", &mut keys.sync_key)
        .map_err(|e| CryptoError::KeyDerivationFailed(e.to_string()))?;
    hk.expand(b"ahp-header-protect", &mut keys.header_protection_key)
        .map_err(|e| CryptoError::KeyDerivationFailed(e.to_string()))?;
    hk.expand(b"ahp-rekey", &mut keys.rekey_secret)
        .map_err(|e| CryptoError::KeyDerivationFailed(e.to_string()))?;
    hk.expand(b"ahp-resume", &mut keys.resume_secret)
        .map_err(|e| CryptoError::KeyDerivationFailed(e.to_string()))?;
    hk.expand(b"ahp-data-iv", &mut keys.data_iv)
        .map_err(|e| CryptoError::KeyDerivationFailed(e.to_string()))?;
    hk.expand(b"ahp-control-iv", &mut keys.control_iv)
        .map_err(|e| CryptoError::KeyDerivationFailed(e.to_string()))?;

    Ok(keys)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derived_keys_are_nonzero() {
        let shared_secret = [0xABu8; 32];
        let initiator_nonce = b"initiator_nonce_1234";
        let responder_nonce = b"responder_nonce_5678";

        let keys = derive_session_keys(&shared_secret, initiator_nonce, responder_nonce)
            .expect("key derivation failed");

        assert!(!keys.control_key.iter().all(|&b| b == 0));
        assert!(!keys.data_key.iter().all(|&b| b == 0));
        assert!(!keys.sync_key.iter().all(|&b| b == 0));
        assert!(!keys.header_protection_key.iter().all(|&b| b == 0));
        assert!(!keys.rekey_secret.iter().all(|&b| b == 0));
        assert!(!keys.resume_secret.iter().all(|&b| b == 0));
    }

    #[test]
    fn derivation_is_deterministic() {
        let shared_secret = [0x42u8; 32];
        let initiator_nonce = b"nonce_a";
        let responder_nonce = b"nonce_b";

        let keys1 = derive_session_keys(&shared_secret, initiator_nonce, responder_nonce).unwrap();
        let keys2 = derive_session_keys(&shared_secret, initiator_nonce, responder_nonce).unwrap();

        assert_eq!(keys1.control_key, keys2.control_key);
        assert_eq!(keys1.data_key, keys2.data_key);
        assert_eq!(keys1.sync_key, keys2.sync_key);
        assert_eq!(keys1.header_protection_key, keys2.header_protection_key);
        assert_eq!(keys1.rekey_secret, keys2.rekey_secret);
        assert_eq!(keys1.resume_secret, keys2.resume_secret);
    }

    #[test]
    fn all_derived_keys_are_distinct() {
        let shared_secret = [0x99u8; 32];
        let initiator_nonce = b"init";
        let responder_nonce = b"resp";

        let keys = derive_session_keys(&shared_secret, initiator_nonce, responder_nonce).unwrap();

        // Each 32-byte key should be distinct from the others.
        let key_slices: Vec<&[u8]> = vec![
            &keys.control_key,
            &keys.data_key,
            &keys.sync_key,
            &keys.rekey_secret,
            &keys.resume_secret,
        ];
        for i in 0..key_slices.len() {
            for j in (i + 1)..key_slices.len() {
                assert_ne!(
                    key_slices[i], key_slices[j],
                    "keys at index {} and {} should differ",
                    i, j
                );
            }
        }
    }

    #[test]
    fn different_nonces_produce_different_keys() {
        let shared_secret = [0x77u8; 32];

        let keys_a = derive_session_keys(&shared_secret, b"nonce1", b"nonce2").unwrap();
        let keys_b = derive_session_keys(&shared_secret, b"nonce3", b"nonce4").unwrap();

        assert_ne!(keys_a.control_key, keys_b.control_key);
        assert_ne!(keys_a.data_key, keys_b.data_key);
    }
}
