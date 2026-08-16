// Favonius — high-performance file transfer over UDP
// Copyright (c) 2025-2026 Vantino SàRL
// SPDX-License-Identifier: Apache-2.0

//! Ed25519 digital signatures for identity binding and authentication.
//!
//! Provides signing key generation, message signing, and signature verification
//! using Ed25519. Used during the AHP handshake to bind ephemeral session keys
//! to long-lived identity keys, preventing man-in-the-middle attacks.

use ed25519_dalek::{
    Signature, Signer, SigningKey, Verifier, VerifyingKey,
};
use rand::rngs::OsRng;

use crate::CryptoError;

/// An Ed25519 signing identity (private + public key).
///
/// The signing key is used to prove ownership of an identity during the
/// AHP handshake. The verifying key is exchanged with the peer.
pub struct SigningIdentity {
    signing_key: SigningKey,
}

impl SigningIdentity {
    /// Generate a new random Ed25519 identity.
    pub fn generate() -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        Self { signing_key }
    }

    /// Reconstruct from raw private key bytes.
    pub fn from_bytes(secret: &[u8; 32]) -> Self {
        let signing_key = SigningKey::from_bytes(secret);
        Self { signing_key }
    }

    /// Raw private key bytes (32 bytes).
    pub fn private_bytes(&self) -> [u8; 32] {
        self.signing_key.to_bytes()
    }

    /// Raw public (verifying) key bytes (32 bytes).
    pub fn public_bytes(&self) -> [u8; 32] {
        self.signing_key.verifying_key().to_bytes()
    }

    /// Get the verifying key for sharing with peers.
    pub fn verifying_key(&self) -> VerifyingKeyRef {
        VerifyingKeyRef {
            key: self.signing_key.verifying_key(),
        }
    }

    /// Sign a message, returning the 64-byte Ed25519 signature.
    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        let sig = self.signing_key.sign(message);
        sig.to_bytes()
    }

    /// Sign a handshake transcript binding ephemeral keys to this identity.
    ///
    /// The transcript includes both peers' ephemeral public keys and nonces
    /// to prevent replay and mismatch attacks.
    pub fn sign_handshake(
        &self,
        local_ephemeral_pub: &[u8; 32],
        remote_ephemeral_pub: &[u8; 32],
        local_nonce: &[u8],
        remote_nonce: &[u8],
    ) -> [u8; 64] {
        let transcript = build_handshake_transcript(
            local_ephemeral_pub,
            remote_ephemeral_pub,
            local_nonce,
            remote_nonce,
        );
        self.sign(&transcript)
    }

    /// Sign this end's *offer*: the ephemeral key and nonce it is about to
    /// put on the wire, bound to this identity.
    ///
    /// A client cannot sign the full transcript the way the daemon does.
    /// The daemon signs in HELLO_ACK, by which point it has seen both
    /// halves; the client sends HELLO first and has not yet seen the
    /// daemon's ephemeral key or nonce. Signing half a transcript is the
    /// only thing available without adding a round trip.
    ///
    /// That is weaker in one specific way and not in another, and the
    /// difference is worth being exact about:
    ///
    /// - **It does not prove freshness.** The same signature is valid
    ///   forever, so anyone who captures a HELLO can replay it.
    /// - **It still binds identity to the ephemeral key**, which is what
    ///   authorisation actually rests on. Session keys are derived from
    ///   that ephemeral, so a replayer who lacks its private half derives
    ///   nothing, cannot produce a valid encrypted packet, and therefore
    ///   cannot write a file. A replay costs the daemon a session it will
    ///   drop, not a byte on disk.
    ///
    /// The domain tag differs from the full-transcript one deliberately: a
    /// signature made for one purpose must never verify for the other, or
    /// an offer signature could be presented as proof of a completed
    /// handshake.
    pub fn sign_client_offer(
        &self,
        ephemeral_pub: &[u8; 32],
        nonce: &[u8],
    ) -> [u8; 64] {
        self.sign(&build_client_offer_transcript(ephemeral_pub, nonce))
    }

    /// Load an identity from a key file (see [`IDENTITY_FILE_MAGIC`]).
    pub fn load_from_file(path: &std::path::Path) -> Result<Self, String> {
        let contents = std::fs::read_to_string(path)
            .map_err(|e| format!("cannot read identity file {}: {e}", path.display()))?;
        let mut lines = contents.lines();
        let magic = lines.next().unwrap_or("");
        if magic != IDENTITY_FILE_MAGIC {
            return Err(format!(
                "{} is not a {IDENTITY_FILE_MAGIC} identity file",
                path.display()
            ));
        }
        let hex_secret = lines.next().unwrap_or("").trim();
        let secret = hex_decode(hex_secret)
            .filter(|s| s.len() == 32)
            .ok_or_else(|| format!("invalid secret in identity file {}", path.display()))?;
        let mut secret_bytes = [0u8; 32];
        secret_bytes.copy_from_slice(&secret);
        Ok(Self::from_bytes(&secret_bytes))
    }

    /// Write the identity to a key file with owner-only permissions (0600 on
    /// Unix). Refuses to overwrite an existing file.
    pub fn save_to_file(&self, path: &std::path::Path) -> Result<(), String> {
        let contents = format!("{IDENTITY_FILE_MAGIC}\n{}\n", hex_encode(&self.private_bytes()));
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut file = opts
            .open(path)
            .map_err(|e| format!("cannot create identity file {}: {e}", path.display()))?;
        use std::io::Write;
        file.write_all(contents.as_bytes())
            .map_err(|e| format!("cannot write identity file {}: {e}", path.display()))
    }
}

/// First line of an identity key file — a versioned plain-text format:
/// line 1 is this magic, line 2 is the 32-byte secret as 64 hex characters.
pub const IDENTITY_FILE_MAGIC: &str = "FAVONIUS-IDENTITY-V1";

/// Parse a public identity given either as 64 hex characters or as a path
/// to a file containing them.
///
/// Both spellings exist because both are what people actually have: the hex
/// is what `keygen` prints and what fits on a command line, and the file is
/// what configuration management writes. Accepting only one pushes the
/// other into shell quoting or a temporary file.
///
/// A value that looks like hex is read as hex; anything else is read as a
/// path. That ordering matters: a 64-character *filename* made only of hex
/// digits would be taken for a key, which is a strange enough file to own
/// that preferring the key is the safer reading.
pub fn parse_identity_pin(value: &str) -> Result<[u8; 32], String> {
    let trimmed = value.trim();
    let hex = if trimmed.len() == 64 && trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
        trimmed.to_string()
    } else {
        std::fs::read_to_string(trimmed)
            .map_err(|e| {
                format!("{trimmed} is neither a 64-character hex key nor a readable file ({e})")
            })?
            .trim()
            .to_string()
    };
    let bytes = hex_decode(&hex)
        .filter(|b| b.len() == 32)
        .ok_or_else(|| format!("{trimmed} does not contain a 32-byte hex Ed25519 public key"))?;
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// Hex-encode helper (no external dep).
pub fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Hex-decode helper; `None` on non-hex input or odd length.
pub fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
        .collect()
}

impl std::fmt::Debug for SigningIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SigningIdentity")
            .field("public", &hex_short(&self.public_bytes()))
            .finish()
    }
}

/// A peer's Ed25519 verifying (public) key.
///
/// Used to verify signatures received from a peer during the handshake.
#[derive(Clone)]
pub struct VerifyingKeyRef {
    key: VerifyingKey,
}

impl VerifyingKeyRef {
    /// Construct from raw public key bytes.
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self, CryptoError> {
        let key = VerifyingKey::from_bytes(bytes)
            .map_err(|_| CryptoError::SignatureInvalid)?;
        Ok(Self { key })
    }

    /// Raw public key bytes (32 bytes).
    pub fn to_bytes(&self) -> [u8; 32] {
        self.key.to_bytes()
    }

    /// Verify a signature on a message.
    pub fn verify(&self, message: &[u8], signature: &[u8; 64]) -> Result<(), CryptoError> {
        let sig = Signature::from_bytes(signature);
        self.key
            .verify(message, &sig)
            .map_err(|_| CryptoError::SignatureInvalid)
    }

    /// Verify a peer's *offer* signature — see
    /// [`SigningIdentity::sign_client_offer`] for what it does and does not
    /// prove.
    pub fn verify_client_offer(
        &self,
        ephemeral_pub: &[u8; 32],
        nonce: &[u8],
        signature: &[u8; 64],
    ) -> Result<(), CryptoError> {
        self.verify(&build_client_offer_transcript(ephemeral_pub, nonce), signature)
    }

    /// Verify a handshake transcript signature from the peer.
    ///
    /// Note: the local/remote order is swapped relative to the signer — the
    /// peer's "local" ephemeral key is our "remote" and vice versa.
    pub fn verify_handshake(
        &self,
        peer_ephemeral_pub: &[u8; 32],
        our_ephemeral_pub: &[u8; 32],
        peer_nonce: &[u8],
        our_nonce: &[u8],
        signature: &[u8; 64],
    ) -> Result<(), CryptoError> {
        let transcript = build_handshake_transcript(
            peer_ephemeral_pub,
            our_ephemeral_pub,
            peer_nonce,
            our_nonce,
        );
        self.verify(&transcript, signature)
    }
}

impl std::fmt::Debug for VerifyingKeyRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VerifyingKeyRef")
            .field("public", &hex_short(&self.to_bytes()))
            .finish()
    }
}

/// Build a deterministic handshake transcript from both peers' ephemeral keys
/// and nonces.
fn build_handshake_transcript(
    local_ephemeral_pub: &[u8; 32],
    remote_ephemeral_pub: &[u8; 32],
    local_nonce: &[u8],
    remote_nonce: &[u8],
) -> Vec<u8> {
    let mut transcript = Vec::with_capacity(
        b"AHP-HANDSHAKE-SIG-v1".len()
            + 32 + 32
            + 2 + local_nonce.len()
            + 2 + remote_nonce.len(),
    );
    transcript.extend_from_slice(b"AHP-HANDSHAKE-SIG-v1");
    transcript.extend_from_slice(local_ephemeral_pub);
    transcript.extend_from_slice(remote_ephemeral_pub);
    transcript.extend_from_slice(&(local_nonce.len() as u16).to_le_bytes());
    transcript.extend_from_slice(local_nonce);
    transcript.extend_from_slice(&(remote_nonce.len() as u16).to_le_bytes());
    transcript.extend_from_slice(remote_nonce);
    transcript
}

/// Transcript for a one-sided offer signature.
///
/// Deliberately *not* the same shape as the full handshake transcript, and
/// deliberately a different domain tag: the two are signed by different
/// parties at different points and must never be interchangeable. A shared
/// tag would let an offer signature be replayed as a handshake signature
/// over a transcript an attacker chose the other half of.
fn build_client_offer_transcript(ephemeral_pub: &[u8; 32], nonce: &[u8]) -> Vec<u8> {
    let mut transcript =
        Vec::with_capacity(b"AHP-CLIENT-OFFER-SIG-v1".len() + 32 + 2 + nonce.len());
    transcript.extend_from_slice(b"AHP-CLIENT-OFFER-SIG-v1");
    transcript.extend_from_slice(ephemeral_pub);
    transcript.extend_from_slice(&(nonce.len() as u16).to_le_bytes());
    transcript.extend_from_slice(nonce);
    transcript
}

/// Format first 4 bytes as hex for debug output.
fn hex_short(bytes: &[u8; 32]) -> String {
    format!(
        "{:02x}{:02x}{:02x}{:02x}...",
        bytes[0], bytes[1], bytes[2], bytes[3]
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_identity() {
        let id = SigningIdentity::generate();
        let pub_bytes = id.public_bytes();
        assert!(!pub_bytes.iter().all(|&b| b == 0));
    }

    #[test]
    fn from_bytes_round_trip() {
        let id = SigningIdentity::generate();
        let priv_bytes = id.private_bytes();
        let pub_bytes = id.public_bytes();

        let id2 = SigningIdentity::from_bytes(&priv_bytes);
        assert_eq!(id2.public_bytes(), pub_bytes);
    }

    #[test]
    fn sign_and_verify() {
        let id = SigningIdentity::generate();
        let message = b"hello AHP protocol";

        let sig = id.sign(message);
        let vk = id.verifying_key();
        vk.verify(message, &sig).expect("valid signature should verify");
    }

    #[test]
    fn wrong_message_fails() {
        let id = SigningIdentity::generate();
        let sig = id.sign(b"correct message");
        let vk = id.verifying_key();

        let result = vk.verify(b"wrong message", &sig);
        assert!(matches!(result, Err(CryptoError::SignatureInvalid)));
    }

    #[test]
    fn wrong_key_fails() {
        let id1 = SigningIdentity::generate();
        let id2 = SigningIdentity::generate();
        let message = b"test message";

        let sig = id1.sign(message);
        let vk2 = id2.verifying_key();

        let result = vk2.verify(message, &sig);
        assert!(matches!(result, Err(CryptoError::SignatureInvalid)));
    }

    #[test]
    fn tampered_signature_fails() {
        let id = SigningIdentity::generate();
        let message = b"important data";

        let mut sig = id.sign(message);
        sig[0] ^= 0xFF; // Flip bits.

        let vk = id.verifying_key();
        let result = vk.verify(message, &sig);
        assert!(matches!(result, Err(CryptoError::SignatureInvalid)));
    }

    #[test]
    fn verifying_key_from_bytes() {
        let id = SigningIdentity::generate();
        let pub_bytes = id.public_bytes();

        let vk = VerifyingKeyRef::from_bytes(&pub_bytes).unwrap();
        assert_eq!(vk.to_bytes(), pub_bytes);

        let sig = id.sign(b"data");
        vk.verify(b"data", &sig).unwrap();
    }

    #[test]
    fn verifying_key_from_invalid_bytes() {
        // All-zero is not a valid Ed25519 point for verification in strict mode,
        // but ed25519-dalek v2 may accept it. Test with obviously bad bytes.
        let bad = [0xFFu8; 32];
        let result = VerifyingKeyRef::from_bytes(&bad);
        // This may or may not error depending on the curve point check.
        // If it succeeds, verification with it should still fail.
        if let Ok(vk) = result {
            let result = vk.verify(b"msg", &[0u8; 64]);
            assert!(result.is_err());
        }
    }

    #[test]
    fn handshake_sign_and_verify() {
        let alice_identity = SigningIdentity::generate();
        let _bob_identity = SigningIdentity::generate();

        let alice_eph_pub = [1u8; 32];
        let bob_eph_pub = [2u8; 32];
        let alice_nonce = b"alice_nonce_1234";
        let bob_nonce = b"bob_nonce_567890";

        // Alice signs the handshake from her perspective.
        let sig = alice_identity.sign_handshake(
            &alice_eph_pub,
            &bob_eph_pub,
            alice_nonce,
            bob_nonce,
        );

        // Bob verifies using Alice's verifying key.
        // From Bob's perspective: peer=alice, our=bob.
        let alice_vk = alice_identity.verifying_key();
        alice_vk
            .verify_handshake(
                &alice_eph_pub, // peer's ephemeral = alice's
                &bob_eph_pub,   // our ephemeral = bob's
                alice_nonce,    // peer's nonce
                bob_nonce,      // our nonce
                &sig,
            )
            .expect("handshake signature should verify");
    }

    #[test]
    fn handshake_wrong_nonce_fails() {
        let id = SigningIdentity::generate();
        let eph_local = [1u8; 32];
        let eph_remote = [2u8; 32];

        let sig = id.sign_handshake(&eph_local, &eph_remote, b"nonce_a", b"nonce_b");

        let vk = id.verifying_key();
        let result = vk.verify_handshake(
            &eph_local,
            &eph_remote,
            b"nonce_a",
            b"WRONG_NONCE", // Different nonce.
            &sig,
        );
        assert!(matches!(result, Err(CryptoError::SignatureInvalid)));
    }

    #[test]
    fn handshake_swapped_keys_fails() {
        let id = SigningIdentity::generate();
        let eph_a = [1u8; 32];
        let eph_b = [2u8; 32];

        let sig = id.sign_handshake(&eph_a, &eph_b, b"na", b"nb");

        let vk = id.verifying_key();
        // Swap the ephemeral keys — should fail.
        let result = vk.verify_handshake(&eph_b, &eph_a, b"na", b"nb", &sig);
        assert!(matches!(result, Err(CryptoError::SignatureInvalid)));
    }

    #[test]
    fn different_identities_different_signatures() {
        let id1 = SigningIdentity::generate();
        let id2 = SigningIdentity::generate();
        let msg = b"same message";

        let sig1 = id1.sign(msg);
        let sig2 = id2.sign(msg);
        assert_ne!(sig1, sig2);
    }

    #[test]
    fn debug_does_not_leak_private_key() {
        let id = SigningIdentity::generate();
        let debug_str = format!("{:?}", id);
        assert!(debug_str.contains("SigningIdentity"));
        // Should not contain the full 32 bytes of the private key.
        assert!(!debug_str.contains(&format!("{:?}", id.private_bytes())));
    }

    #[test]
    fn signature_is_64_bytes() {
        let id = SigningIdentity::generate();
        let sig = id.sign(b"test");
        assert_eq!(sig.len(), 64);
    }

    #[test]
    fn empty_message_sign_verify() {
        let id = SigningIdentity::generate();
        let sig = id.sign(b"");
        let vk = id.verifying_key();
        vk.verify(b"", &sig).unwrap();
    }

    #[test]
    fn identity_file_round_trip() {
        let dir = std::env::temp_dir().join(format!("favonius-id-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("identity.key");

        let id = SigningIdentity::generate();
        id.save_to_file(&path).unwrap();

        // Owner-only permissions on Unix.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }

        let loaded = SigningIdentity::load_from_file(&path).unwrap();
        assert_eq!(loaded.public_bytes(), id.public_bytes());

        // Refuses to overwrite an existing identity.
        assert!(SigningIdentity::generate().save_to_file(&path).is_err());

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn identity_file_rejects_garbage() {
        let dir = std::env::temp_dir().join(format!("favonius-id-bad-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();

        let bad_magic = dir.join("bad1.key");
        std::fs::write(&bad_magic, "SOMETHING-ELSE\n00\n").unwrap();
        assert!(SigningIdentity::load_from_file(&bad_magic).is_err());

        let bad_hex = dir.join("bad2.key");
        std::fs::write(&bad_hex, format!("{IDENTITY_FILE_MAGIC}\nzz\n")).unwrap();
        assert!(SigningIdentity::load_from_file(&bad_hex).is_err());

        let short = dir.join("bad3.key");
        std::fs::write(&short, format!("{IDENTITY_FILE_MAGIC}\n00ff\n")).unwrap();
        assert!(SigningIdentity::load_from_file(&short).is_err());

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_client_offer_verifies_against_the_signer() {
        let id = SigningIdentity::generate();
        let eph = [7u8; 32];
        let nonce = [9u8; 16];
        let sig = id.sign_client_offer(&eph, &nonce);
        assert!(id.verifying_key().verify_client_offer(&eph, &nonce, &sig).is_ok());
    }

    #[test]
    fn a_client_offer_does_not_verify_for_another_identity() {
        let id = SigningIdentity::generate();
        let other = SigningIdentity::generate();
        let (eph, nonce) = ([7u8; 32], [9u8; 16]);
        let sig = id.sign_client_offer(&eph, &nonce);
        assert!(other.verifying_key().verify_client_offer(&eph, &nonce, &sig).is_err());
    }

    #[test]
    fn a_client_offer_is_bound_to_its_ephemeral_key_and_nonce() {
        // This binding is the whole security argument: an attacker who
        // replays the signature with a different ephemeral key must fail,
        // because the ephemeral is what session keys derive from.
        let id = SigningIdentity::generate();
        let (eph, nonce) = ([7u8; 32], [9u8; 16]);
        let sig = id.sign_client_offer(&eph, &nonce);
        let vk = id.verifying_key();
        assert!(vk.verify_client_offer(&[8u8; 32], &nonce, &sig).is_err(), "ephemeral not bound");
        assert!(vk.verify_client_offer(&eph, &[10u8; 16], &sig).is_err(), "nonce not bound");
    }

    #[test]
    fn an_offer_signature_is_not_a_handshake_signature() {
        // Domain separation. Without distinct tags, a one-sided offer
        // signature could be presented as proof of a completed two-sided
        // handshake — the peer's half chosen by whoever is replaying it.
        let id = SigningIdentity::generate();
        let (eph, nonce) = ([7u8; 32], [9u8; 16]);

        let offer = id.sign_client_offer(&eph, &nonce);
        assert!(
            id.verifying_key()
                .verify_handshake(&eph, &eph, &nonce, &nonce, &offer)
                .is_err(),
            "an offer signature verified as a handshake signature"
        );

        let handshake = id.sign_handshake(&eph, &eph, &nonce, &nonce);
        assert!(
            id.verifying_key().verify_client_offer(&eph, &nonce, &handshake).is_err(),
            "a handshake signature verified as an offer signature"
        );
    }

    #[test]
    fn hex_round_trip() {
        let bytes = [0x00u8, 0x0f, 0xf0, 0xff, 0x42];
        assert_eq!(hex_encode(&bytes), "000ff0ff42");
        assert_eq!(hex_decode("000ff0ff42"), Some(bytes.to_vec()));
        assert_eq!(hex_decode("abc"), None); // odd length
        assert_eq!(hex_decode("zz"), None); // non-hex
    }
}
