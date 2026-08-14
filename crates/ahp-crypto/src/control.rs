// Favonius — high-performance file transfer over UDP
// Copyright (c) 2025-2026 Vantino SàRL
// SPDX-License-Identifier: Apache-2.0

//! Control-plane packet protection.
//!
//! FINISH and KEY_UPDATE mutate transfer state (finalizing the output file,
//! rotating the key schedule), so when encryption is negotiated for a
//! transfer their payloads are AEAD-sealed with the session `control_key`
//! derived by the handshake. Before this, the whole control plane traveled
//! in cleartext: any on-path attacker could inject a FINISH to truncate a
//! transfer early, or a KEY_UPDATE for the next epoch to desync the chained
//! key schedule permanently.
//!
//! The construction mirrors the data plane: the nonce is `control_iv` XOR
//! the packet sequence number (see [`NonceGenerator`]), and the 42-byte
//! fixed header exactly as it appears on the wire is bound as associated
//! data (RFC §14.4), so header fields are integrity-protected too.
//!
//! Plaintext transfers keep cleartext control packets — both endpoints know
//! the negotiated mode, so sealed vs. cleartext is implicit and needs no
//! wire flag. HELLO/HELLO_ACK stay cleartext (pre-key by definition).
//!
//! Key-epoch grace window (RFC §13.3): after a rotation the receiver keeps
//! the previous epoch's keys (see [`crate::key_update::KeyEpoch`]) so
//! in-flight control packets sealed just before the rotation still
//! authenticate. [`unseal_control`] tries the current epoch first, then the
//! previous one; at most one previous epoch is ever retained.

use crate::packet_protection::Aes256GcmProtector;
use crate::{CryptoError, NonceGenerator, PacketProtector, SessionKeys};

/// AEAD tag length appended to a sealed control payload.
pub const CONTROL_TAG_LEN: usize = 16;

/// Seal a control-plane payload under the given epoch's control key.
///
/// `packet_number` is the sequence number carried in the packet header;
/// `aad` is the 42-byte fixed header exactly as it goes on the wire.
/// Returns `plaintext` with the 16-byte GCM tag appended.
pub fn seal_control(
    keys: &SessionKeys,
    packet_number: u64,
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let protector = Aes256GcmProtector::new(&keys.control_key);
    let nonce = NonceGenerator::new(keys.control_iv).nonce_for(packet_number);
    protector
        .encrypt(&nonce, aad, plaintext)
        .map(|b| b.to_vec())
}

/// Unseal a control-plane payload, trying the current epoch's control keys
/// first and then the previous epoch's (the post-rotation grace window).
///
/// Returns the plaintext on the first success, `None` if neither key set
/// authenticates the packet — the caller must drop, not process, such
/// packets. Failure is an expected case (forged or stale control packets),
/// not an error worth propagating.
pub fn unseal_control(
    current: &SessionKeys,
    previous: Option<&SessionKeys>,
    packet_number: u64,
    aad: &[u8],
    ciphertext: &[u8],
) -> Option<Vec<u8>> {
    for keys in [Some(current), previous].into_iter().flatten() {
        let protector = Aes256GcmProtector::new(&keys.control_key);
        let nonce = NonceGenerator::new(keys.control_iv).nonce_for(packet_number);
        if let Ok(plaintext) = protector.decrypt(&nonce, aad, ciphertext) {
            return Some(plaintext.to_vec());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key_exchange::{diffie_hellman, generate_keypair};
    use crate::key_schedule::derive_session_keys;
    use crate::key_update::{encode_key_update, KeyEpoch};

    fn make_keys() -> SessionKeys {
        let alice = generate_keypair();
        let bob = generate_keypair();
        let shared = diffie_hellman(&alice.private, &bob.public).unwrap();
        derive_session_keys(&shared, b"init-nonce", b"resp-nonce").unwrap()
    }

    const AAD: &[u8] = b"pretend-42-byte-fixed-header-on-the-wire!";

    #[test]
    fn seal_unseal_round_trip() {
        let keys = make_keys();
        let sealed = seal_control(&keys, 7, AAD, b"payload").unwrap();
        assert_eq!(sealed.len(), 7 + CONTROL_TAG_LEN);
        let opened = unseal_control(&keys, None, 7, AAD, &sealed).unwrap();
        assert_eq!(opened, b"payload");
    }

    #[test]
    fn empty_payload_round_trip() {
        // Sealed FINISH carries an empty plaintext — tag only.
        let keys = make_keys();
        let sealed = seal_control(&keys, 3, AAD, b"").unwrap();
        assert_eq!(sealed.len(), CONTROL_TAG_LEN);
        let opened = unseal_control(&keys, None, 3, AAD, &sealed).unwrap();
        assert!(opened.is_empty());
    }

    #[test]
    fn forged_packets_are_rejected() {
        let keys = make_keys();
        let sealed = seal_control(&keys, 7, AAD, b"payload").unwrap();

        // Bad tag.
        let mut tampered = sealed.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 0xFF;
        assert!(unseal_control(&keys, None, 7, AAD, &tampered).is_none());

        // Tampered AAD (header field flipped on the wire).
        assert!(unseal_control(&keys, None, 7, b"wrong-header", &sealed).is_none());

        // Wrong sequence number (nonce mismatch).
        assert!(unseal_control(&keys, None, 8, AAD, &sealed).is_none());

        // Wrong keys entirely.
        let other = make_keys();
        assert!(unseal_control(&other, None, 7, AAD, &sealed).is_none());

        // Cleartext (too short for a tag) is not accepted either.
        assert!(unseal_control(&keys, None, 7, AAD, b"").is_none());
    }

    #[test]
    fn previous_epoch_grace_window() {
        let keys = make_keys();
        let mut epoch = KeyEpoch::new(keys);

        // Control packet sealed under epoch 0.
        let sealed_e0 = seal_control(&epoch.keys, 5, AAD, b"finish").unwrap();

        // After rotation to epoch 1 it still authenticates (previous = 0).
        epoch.rotate().unwrap();
        assert_eq!(epoch.epoch, 1);
        let opened = unseal_control(&epoch.keys, epoch.previous_keys(), 5, AAD, &sealed_e0).unwrap();
        assert_eq!(opened, b"finish");

        // After a second rotation the epoch-0 packet falls out of the
        // one-epoch window and must fail.
        epoch.rotate().unwrap();
        assert_eq!(epoch.epoch, 2);
        assert!(unseal_control(&epoch.keys, epoch.previous_keys(), 5, AAD, &sealed_e0).is_none());
    }

    #[test]
    fn key_update_sealed_under_outgoing_epoch_flow() {
        // Sender and receiver start on the same epoch-0 keys.
        let keys = make_keys();
        let mut sender = KeyEpoch::new(keys.clone());
        let mut receiver = KeyEpoch::new(keys);

        // Sender rotates, then seals the KEY_UPDATE announcing epoch 1 with
        // the OUTGOING (epoch 0) control keys — the receiver still holds them.
        sender.rotate().unwrap();
        let ku_payload = encode_key_update(sender.epoch);
        let sealed = seal_control(
            sender.previous_keys().unwrap(),
            9,
            AAD,
            &ku_payload,
        )
        .unwrap();

        // First delivery: receiver (still at epoch 0) authenticates under its
        // current keys and rotates.
        let opened = unseal_control(&receiver.keys, receiver.previous_keys(), 9, AAD, &sealed).unwrap();
        assert_eq!(crate::key_update::decode_key_update(&opened), Some(1));
        receiver.rotate().unwrap();
        assert_eq!(receiver.epoch, 1);

        // Retransmission after the rotation: authenticates via the
        // previous-epoch grace window; the epoch guard makes it a no-op.
        let opened = unseal_control(&receiver.keys, receiver.previous_keys(), 9, AAD, &sealed).unwrap();
        let new_epoch = crate::key_update::decode_key_update(&opened).unwrap();
        assert_eq!(new_epoch, receiver.epoch, "duplicate KEY_UPDATE must be a no-op");
    }
}
