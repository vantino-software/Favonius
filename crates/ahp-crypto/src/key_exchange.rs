// Favonius — high-performance file transfer over UDP
// Copyright (c) 2025-2026 Vantino SàRL
// SPDX-License-Identifier: Apache-2.0

//! X25519 Diffie-Hellman key exchange.
//!
//! Provides ephemeral and static key pair generation and shared secret
//! computation using the X25519 elliptic-curve Diffie-Hellman function.

use x25519_dalek::{PublicKey, StaticSecret};
use rand::rngs::OsRng;

use crate::{CryptoError, KeyPair};

/// Generate an X25519 key pair suitable for Diffie-Hellman key exchange.
///
/// Uses `StaticSecret` rather than `EphemeralSecret` so that the private key
/// bytes can be stored and re-used (e.g., for the duration of a handshake).
pub fn generate_keypair() -> KeyPair {
    let secret = StaticSecret::random_from_rng(OsRng);
    let public = PublicKey::from(&secret);
    KeyPair {
        private: secret.to_bytes(),
        public: public.to_bytes(),
    }
}

/// Perform X25519 Diffie-Hellman key agreement.
///
/// Returns the 32-byte shared secret, or an error if the peer's public key
/// is a low-order point (which would yield an all-zero shared secret).
pub fn diffie_hellman(
    our_private: &[u8; 32],
    their_public: &[u8; 32],
) -> Result<[u8; 32], CryptoError> {
    let secret = StaticSecret::from(*our_private);
    let public = PublicKey::from(*their_public);
    let shared = secret.diffie_hellman(&public);

    // Reject the all-zero shared secret produced by low-order points.
    if shared.as_bytes().iter().all(|&b| b == 0) {
        return Err(CryptoError::KeyExchangeFailed(
            "low-order point produced all-zero shared secret".into(),
        ));
    }

    Ok(*shared.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keypair_has_nonzero_bytes() {
        let kp = generate_keypair();
        // A random key pair should not be all zeros.
        assert!(!kp.private.iter().all(|&b| b == 0));
        assert!(!kp.public.iter().all(|&b| b == 0));
    }

    #[test]
    fn dh_both_directions_match() {
        let alice = generate_keypair();
        let bob = generate_keypair();

        let shared_ab =
            diffie_hellman(&alice.private, &bob.public).expect("DH alice->bob failed");
        let shared_ba =
            diffie_hellman(&bob.private, &alice.public).expect("DH bob->alice failed");

        assert_eq!(shared_ab, shared_ba, "shared secrets must be identical");
    }

    #[test]
    fn dh_different_peers_produce_different_secrets() {
        let alice = generate_keypair();
        let bob = generate_keypair();
        let carol = generate_keypair();

        let shared_ab = diffie_hellman(&alice.private, &bob.public).unwrap();
        let shared_ac = diffie_hellman(&alice.private, &carol.public).unwrap();

        assert_ne!(shared_ab, shared_ac);
    }

    #[test]
    fn dh_rejects_low_order_point() {
        let kp = generate_keypair();
        // The all-zero public key is a low-order point on Curve25519.
        let zero_public = [0u8; 32];
        let result = diffie_hellman(&kp.private, &zero_public);
        assert!(result.is_err());
        match result {
            Err(CryptoError::KeyExchangeFailed(_)) => {}
            other => panic!("expected KeyExchangeFailed, got {:?}", other),
        }
    }
}
