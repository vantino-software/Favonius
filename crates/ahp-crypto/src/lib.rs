// Favonius — high-performance file transfer over UDP
// Copyright (c) 2025-2026 Vantino SàRL
// SPDX-License-Identifier: Apache-2.0

//! AHP cryptographic primitives.
//!
//! Provides the cryptographic foundation for the Adaptive High-speed Protocol:
//! X25519 key exchange, AES-256-GCM packet protection, Ed25519 signatures,
//! and HKDF-based key scheduling.

pub mod control;
pub mod header_protection;
pub mod key_exchange;
pub mod key_schedule;
pub mod key_update;
pub mod packet_protection;
pub mod session_ticket;
pub mod grant;
pub mod signatures;

use bytes::Bytes;
use zeroize::Zeroize;

/// Cipher suite negotiated during session establishment.
///
/// AHP mandates `Aes256GcmX25519` as the baseline; future versions may add
/// post-quantum suites or ChaCha20-based alternatives.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CipherSuite {
    /// AES-256-GCM for packet protection, X25519 for key exchange, HKDF-SHA256
    /// for key derivation, Ed25519 for authentication signatures.
    Aes256GcmX25519,
}

impl Default for CipherSuite {
    fn default() -> Self {
        Self::Aes256GcmX25519
    }
}

/// A key pair consisting of a private scalar and its corresponding public point.
///
/// Used for both ephemeral (session) and static (identity) keys.
// Note: Debug is implemented manually below to avoid leaking key material,
// and the private key is zeroized on drop.
pub struct KeyPair {
    /// Raw private key bytes (32 bytes for X25519).
    pub private: [u8; 32],
    /// Raw public key bytes (32 bytes for X25519).
    pub public: [u8; 32],
}

impl std::fmt::Debug for KeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyPair")
            .field("private", &"[REDACTED]")
            .field("public", &self.public)
            .finish()
    }
}

impl Drop for KeyPair {
    fn drop(&mut self) {
        self.private.zeroize();
    }
}

impl KeyPair {
    /// Generate a new random X25519 key pair.
    pub fn generate() -> Self {
        crate::key_exchange::generate_keypair()
    }
}

/// Derived session keys produced by the key schedule after handshake completion.
///
/// The handshake derives six independent keys via HKDF expand:
/// - `control_key`: protects control-plane packets (CAPS, AUTH, MANIFEST, etc.)
/// - `data_key`: protects data-plane packets (DATA, ACK_BITMAP, etc.)
/// - `sync_key`: protects sync-plane packets (REGION_MAP, DELTA_MAP, etc.)
/// - `header_protection_key`: masks header fields for on-path observer resistance
/// - `rekey_secret`: input material for key rotation via KEY_UPDATE
/// - `resume_secret`: stored for 0-RTT session resumption
#[derive(Clone)]
pub struct SessionKeys {
    // Note: Debug is implemented manually below to avoid leaking key material.
    pub control_key: [u8; 32],
    pub data_key: [u8; 32],
    pub sync_key: [u8; 32],
    pub header_protection_key: [u8; 16],
    pub rekey_secret: [u8; 32],
    pub resume_secret: [u8; 32],
    /// IV for data-plane nonce generation (12 bytes).
    pub data_iv: [u8; 12],
    /// IV for control-plane nonce generation (12 bytes).
    pub control_iv: [u8; 12],
}

impl std::fmt::Debug for SessionKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionKeys")
            .field("control_key", &"[REDACTED]")
            .field("data_key", &"[REDACTED]")
            .field("sync_key", &"[REDACTED]")
            .field("header_protection_key", &"[REDACTED]")
            .field("rekey_secret", &"[REDACTED]")
            .field("resume_secret", &"[REDACTED]")
            .finish()
    }
}

impl Drop for SessionKeys {
    fn drop(&mut self) {
        self.control_key.zeroize();
        self.data_key.zeroize();
        self.sync_key.zeroize();
        self.header_protection_key.zeroize();
        self.rekey_secret.zeroize();
        self.resume_secret.zeroize();
        self.data_iv.zeroize();
        self.control_iv.zeroize();
    }
}

impl SessionKeys {
    /// Create a zeroed key set (for initialization before derivation).
    pub fn zeroed() -> Self {
        Self {
            control_key: [0u8; 32],
            data_key: [0u8; 32],
            sync_key: [0u8; 32],
            header_protection_key: [0u8; 16],
            rekey_secret: [0u8; 32],
            resume_secret: [0u8; 32],
            data_iv: [0u8; 12],
            control_iv: [0u8; 12],
        }
    }
}

/// State machine for the X25519 handshake key exchange.
///
/// Follows the pattern: generate ephemeral -> send public share -> receive
/// peer share -> derive shared secret -> run key schedule.
#[derive(Debug)]
pub enum HandshakeState {
    /// Initial state; no keys generated yet.
    Initial,
    /// Ephemeral key pair generated, waiting to send our public share.
    Generated { local: KeyPair },
    /// Our public share sent, waiting for the peer's public share.
    WaitingForPeer { local: KeyPair },
    /// Shared secret computed, ready for key schedule derivation.
    SharedSecretReady { shared_secret: [u8; 32] },
    /// Key schedule complete; session keys are available.
    Complete { session_keys: SessionKeys },
    /// Handshake failed.
    Failed,
}

impl HandshakeState {
    pub fn new() -> Self {
        Self::Initial
    }
}

impl Default for HandshakeState {
    fn default() -> Self {
        Self::new()
    }
}

/// Trait for encrypting and decrypting AHP packet payloads.
///
/// Implementations handle nonce construction, AEAD seal/open, and
/// associated-data binding (header bytes are authenticated but not encrypted).
pub trait PacketProtector: Send + Sync {
    /// Encrypt a plaintext payload in-place, appending the authentication tag.
    ///
    /// `header` is included as AEAD associated data.
    /// `nonce` is the per-packet nonce from the `NonceGenerator`.
    fn encrypt(
        &self,
        nonce: &[u8; 12],
        header: &[u8],
        plaintext: &[u8],
    ) -> Result<Bytes, CryptoError>;

    /// Decrypt a ciphertext payload, verifying the authentication tag.
    ///
    /// `header` is the associated data that was authenticated during encryption.
    fn decrypt(
        &self,
        nonce: &[u8; 12],
        header: &[u8],
        ciphertext: &[u8],
    ) -> Result<Bytes, CryptoError>;
}

/// Generates unique per-packet nonces from the packet sequence number.
///
/// Nonces are 12 bytes: a 4-byte fixed IV XORed with the 8-byte sequence number
/// left-padded to 12 bytes. This ensures nonce uniqueness as long as sequence
/// numbers are not reused within a key epoch.
#[derive(Debug)]
pub struct NonceGenerator {
    /// Fixed IV derived from the key schedule, XORed with the sequence number.
    iv: [u8; 12],
}

impl NonceGenerator {
    /// Create a generator from the derived fixed IV.
    pub fn new(iv: [u8; 12]) -> Self {
        Self { iv }
    }

    /// Derive the nonce for the given packet sequence number.
    pub fn nonce_for(&self, sequence_number: u64) -> [u8; 12] {
        let mut nonce = self.iv;
        let seq_bytes = sequence_number.to_be_bytes();
        // XOR sequence number into the last 8 bytes of the IV.
        for i in 0..8 {
            nonce[4 + i] ^= seq_bytes[i];
        }
        nonce
    }
}

/// Errors from cryptographic operations.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CryptoError {
    /// AEAD decryption failed (bad key, corrupted ciphertext, or tampered AAD).
    #[error("decryption failed: authentication tag mismatch")]
    DecryptionFailed,

    /// Key exchange produced an invalid shared secret (e.g., low-order point).
    #[error("key exchange failed: {0}")]
    KeyExchangeFailed(String),

    /// HKDF derivation failed (bad input length or invalid PRK).
    #[error("key derivation failed: {0}")]
    KeyDerivationFailed(String),

    /// Signature verification failed.
    #[error("signature verification failed")]
    SignatureInvalid,

    /// Nonce reuse detected (sequence number already used in this key epoch).
    #[error("nonce reuse detected for sequence {0}")]
    NonceReuse(u64),

    /// The handshake state machine received an unexpected event.
    #[error("invalid handshake state transition: {0}")]
    InvalidHandshakeState(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keypair_debug_redacts_private_key() {
        let kp = KeyPair {
            private: [0xA5; 32],
            public: [0x5A; 32],
        };
        let dbg = format!("{kp:?}");
        // The private key bytes must not appear in any recognizable form.
        assert!(dbg.contains("[REDACTED]"));
        assert!(!dbg.contains("165")); // 0xA5 as decimal
        assert!(!dbg.contains("a5a5")); // hex dump form
        // The public key is not secret and may be shown.
        assert!(dbg.contains("public"));
    }

    #[test]
    fn handshake_state_debug_does_not_leak_private_key() {
        let state = HandshakeState::Generated {
            local: KeyPair {
                private: [0xA5; 32],
                public: [0x5A; 32],
            },
        };
        let dbg = format!("{state:?}");
        assert!(dbg.contains("[REDACTED]"));
        assert!(!dbg.contains("165"));
    }

    #[test]
    fn keypair_drop_zeroizes_private_key() {
        let mut boxed = Box::new(KeyPair {
            private: [0xA5; 32],
            public: [0x5A; 32],
        });
        let ptr = &mut boxed.private as *mut [u8; 32];
        // Run the Drop impl without deallocating, then inspect the bytes.
        // SAFETY: `boxed` is valid for writes; the allocation stays alive
        // until the `forget` below, so the volatile read is in-bounds.
        unsafe { std::ptr::drop_in_place(&mut *boxed) };
        let after = unsafe { std::ptr::read_volatile(ptr) };
        std::mem::forget(boxed);
        assert_eq!(after, [0u8; 32]);
    }
}
