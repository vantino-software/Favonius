// Favonius — high-performance file transfer over UDP
// Copyright (c) 2025-2026 Vantino SàRL
// SPDX-License-Identifier: Apache-2.0

//! AES-256-GCM packet protection.
//!
//! Implements the `PacketProtector` trait using AES-256-GCM as the AEAD cipher.
//! Header bytes are bound as associated data (authenticated but not encrypted).

use aes_gcm::aead::{Aead, AeadInPlace};
use aes_gcm::{Aes256Gcm, Key, KeyInit, Nonce};
use bytes::Bytes;

use crate::{CryptoError, PacketProtector};

/// AES-256-GCM packet protector.
///
/// Wraps an `Aes256Gcm` cipher instance initialised from a 32-byte key.
pub struct Aes256GcmProtector {
    cipher: Aes256Gcm,
}

impl Aes256GcmProtector {
    /// Create a new protector from a 32-byte key.
    pub fn new(key: &[u8; 32]) -> Self {
        let key = Key::<Aes256Gcm>::from_slice(key);
        Self {
            cipher: Aes256Gcm::new(key),
        }
    }
}

impl Aes256GcmProtector {
    /// Zero-allocation encryption for the hot path.
    ///
    /// Encrypts `buffer[..plaintext_len]` in place and appends the 16-byte
    /// GCM tag. Returns the total length (plaintext_len + 16).
    /// The buffer must have at least `plaintext_len + 16` capacity.
    pub fn encrypt_in_place(
        &self,
        nonce: &[u8; 12],
        aad: &[u8],
        buffer: &mut [u8],
        plaintext_len: usize,
    ) -> Result<usize, CryptoError> {
        let n = Nonce::from_slice(nonce);
        let tag = self.cipher
            .encrypt_in_place_detached(n, aad, &mut buffer[..plaintext_len])
            .map_err(|_| CryptoError::DecryptionFailed)?;
        buffer[plaintext_len..plaintext_len + 16].copy_from_slice(&tag);
        Ok(plaintext_len + 16)
    }

    /// Zero-allocation decryption for the hot path.
    ///
    /// Verifies the 16-byte GCM tag at the end of `buffer[..ciphertext_len]`
    /// and decrypts in place. Returns the plaintext length (ciphertext_len - 16).
    pub fn decrypt_in_place(
        &self,
        nonce: &[u8; 12],
        aad: &[u8],
        buffer: &mut [u8],
        ciphertext_len: usize,
    ) -> Result<usize, CryptoError> {
        if ciphertext_len < 16 {
            return Err(CryptoError::DecryptionFailed);
        }
        let tag_start = ciphertext_len - 16;
        let tag = aes_gcm::Tag::clone_from_slice(&buffer[tag_start..ciphertext_len]);
        let n = Nonce::from_slice(nonce);
        self.cipher
            .decrypt_in_place_detached(n, aad, &mut buffer[..tag_start], &tag)
            .map_err(|_| CryptoError::DecryptionFailed)?;
        Ok(tag_start)
    }
}

impl PacketProtector for Aes256GcmProtector {
    fn encrypt(
        &self,
        nonce: &[u8; 12],
        header: &[u8],
        plaintext: &[u8],
    ) -> Result<Bytes, CryptoError> {
        let nonce = Nonce::from_slice(nonce);
        let payload = aes_gcm::aead::Payload {
            msg: plaintext,
            aad: header,
        };
        let ciphertext = self
            .cipher
            .encrypt(nonce, payload)
            .map_err(|_| CryptoError::DecryptionFailed)?;
        Ok(Bytes::from(ciphertext))
    }

    fn decrypt(
        &self,
        nonce: &[u8; 12],
        header: &[u8],
        ciphertext: &[u8],
    ) -> Result<Bytes, CryptoError> {
        let nonce = Nonce::from_slice(nonce);
        let payload = aes_gcm::aead::Payload {
            msg: ciphertext,
            aad: header,
        };
        let plaintext = self
            .cipher
            .decrypt(nonce, payload)
            .map_err(|_| CryptoError::DecryptionFailed)?;
        Ok(Bytes::from(plaintext))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> [u8; 32] {
        [0xDEu8; 32]
    }

    fn test_nonce() -> [u8; 12] {
        [0x01u8; 12]
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let protector = Aes256GcmProtector::new(&test_key());
        let header = b"packet-header";
        let plaintext = b"hello, AHP world!";
        let nonce = test_nonce();

        let ciphertext = protector
            .encrypt(&nonce, header, plaintext)
            .expect("encryption failed");

        let recovered = protector
            .decrypt(&nonce, header, &ciphertext)
            .expect("decryption failed");

        assert_eq!(&recovered[..], plaintext);
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let protector = Aes256GcmProtector::new(&test_key());
        let header = b"header";
        let plaintext = b"secret data";
        let nonce = test_nonce();

        let mut ciphertext = protector.encrypt(&nonce, header, plaintext).unwrap().to_vec();

        // Flip a byte in the ciphertext.
        if let Some(byte) = ciphertext.get_mut(0) {
            *byte ^= 0xFF;
        }

        let result = protector.decrypt(&nonce, header, &ciphertext);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), CryptoError::DecryptionFailed);
    }

    #[test]
    fn tampered_aad_fails() {
        let protector = Aes256GcmProtector::new(&test_key());
        let header = b"correct-header";
        let plaintext = b"secret data";
        let nonce = test_nonce();

        let ciphertext = protector.encrypt(&nonce, header, plaintext).unwrap();

        // Decrypt with a different header (associated data).
        let result = protector.decrypt(&nonce, b"wrong-header", &ciphertext);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), CryptoError::DecryptionFailed);
    }

    #[test]
    fn wrong_key_fails() {
        let protector_enc = Aes256GcmProtector::new(&[0xAA; 32]);
        let protector_dec = Aes256GcmProtector::new(&[0xBB; 32]);
        let header = b"hdr";
        let plaintext = b"payload";
        let nonce = test_nonce();

        let ciphertext = protector_enc.encrypt(&nonce, header, plaintext).unwrap();

        let result = protector_dec.decrypt(&nonce, header, &ciphertext);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), CryptoError::DecryptionFailed);
    }

    #[test]
    fn wrong_nonce_fails() {
        let protector = Aes256GcmProtector::new(&test_key());
        let header = b"hdr";
        let plaintext = b"payload";

        let ciphertext = protector
            .encrypt(&[0x01; 12], header, plaintext)
            .unwrap();

        let result = protector.decrypt(&[0x02; 12], header, &ciphertext);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), CryptoError::DecryptionFailed);
    }

    #[test]
    fn empty_plaintext_roundtrip() {
        let protector = Aes256GcmProtector::new(&test_key());
        let header = b"hdr";
        let nonce = test_nonce();

        let ciphertext = protector.encrypt(&nonce, header, b"").unwrap();
        // Even with empty plaintext, ciphertext should contain the 16-byte auth tag.
        assert_eq!(ciphertext.len(), 16);

        let recovered = protector.decrypt(&nonce, header, &ciphertext).unwrap();
        assert!(recovered.is_empty());
    }
}
