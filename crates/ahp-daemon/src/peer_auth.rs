// Favonius — high-performance file transfer over UDP
// Copyright (c) 2025-2026 Vantino SàRL
// SPDX-License-Identifier: Apache-2.0

//! Who is allowed to send to this daemon.
//!
//! Until now the answer was "anyone who can reach the port". `--dest-root`
//! confines *where* a transfer may write, which is a containment control,
//! not an authorisation one: it decides what a stranger may overwrite, not
//! whether a stranger may write at all.
//!
//! A client may now append its Ed25519 identity and an offer signature to
//! its HELLO. This module decides what to do about that, and nothing else —
//! no sockets, no packets — because an authorisation rule that can only be
//! exercised by running a transfer is a rule that gets tested once, by hand,
//! on the day it is written.
//!
//! # What a passing check means
//!
//! That the sender holds the private half of an identity on the allowlist,
//! and that the ephemeral key in this HELLO is theirs. Session keys derive
//! from that ephemeral, so nobody else can complete the handshake or write
//! a byte.
//!
//! It does **not** mean the HELLO is fresh. The signature covers only the
//! client's own half of the transcript — the daemon's half does not exist
//! when the client sends it — so a captured HELLO can be replayed forever.
//! A replayer still cannot derive the session keys, so what a replay buys
//! is a session the daemon will drop, not a file. See
//! `ahp_crypto::signatures::sign_client_offer`.

use std::collections::BTreeSet;

use ahp_crypto::signatures::{hex_encode, VerifyingKeyRef};

/// What the daemon decided about a sender.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// The sender proved an identity that is on the allowlist.
    Authenticated([u8; 32]),
    /// The sender did not authenticate, and this daemon does not insist.
    /// The historical behaviour, and still the default.
    Anonymous,
    /// Refused. The string is for the daemon's log, not the wire: a peer
    /// that failed authorisation is told nothing about why.
    Refused(String),
}

impl Decision {
    pub fn is_refused(&self) -> bool {
        matches!(self, Self::Refused(_))
    }
}

/// The daemon's peer-authorisation policy.
#[derive(Debug, Clone, Default)]
pub struct PeerPolicy {
    allowed: BTreeSet<[u8; 32]>,
    require: bool,
}

impl PeerPolicy {
    /// `allowed` is the set of sender identities that may write here;
    /// `require` refuses anyone who does not authenticate at all.
    ///
    /// The two are independent on purpose. An allowlist with `require`
    /// off is a useful intermediate state while an estate is being
    /// migrated: authenticated senders are checked against it, and
    /// unauthenticated ones still work, so the allowlist can be populated
    /// and verified before it starts turning anybody away.
    pub fn new(allowed: impl IntoIterator<Item = [u8; 32]>, require: bool) -> Self {
        Self { allowed: allowed.into_iter().collect(), require }
    }

    /// Whether this daemon will turn anyone away. Used to decide whether
    /// to advertise the capability and what to say at startup.
    pub fn is_enforcing(&self) -> bool {
        self.require || !self.allowed.is_empty()
    }

    pub fn allowed_count(&self) -> usize {
        self.allowed.len()
    }

    /// Decide about one HELLO.
    ///
    /// `presented` is the identity and signature the client appended, if
    /// any; `ephemeral_pub` and `nonce` are what it offered, and are what
    /// the signature must cover.
    pub fn decide(
        &self,
        presented: Option<(&[u8; 32], &[u8; 64])>,
        ephemeral_pub: &[u8; 32],
        nonce: &[u8],
    ) -> Decision {
        let Some((identity, signature)) = presented else {
            return if self.require {
                Decision::Refused(
                    "sender did not authenticate and --require-peer-auth is set".into(),
                )
            } else {
                Decision::Anonymous
            };
        };

        // Verify before consulting the allowlist. Checking membership first
        // would let anyone who knows an allowed *public* key — which is
        // public, and printed by keygen — learn whether it is allowed here,
        // by watching which unsigned claim gets further.
        let Ok(key) = VerifyingKeyRef::from_bytes(identity) else {
            return Decision::Refused(format!(
                "sender presented {} which is not a valid Ed25519 public key",
                hex_encode(&identity[..4])
            ));
        };
        if key.verify_client_offer(ephemeral_pub, nonce, signature).is_err() {
            return Decision::Refused(format!(
                "sender claiming {} did not prove it: bad offer signature",
                hex_encode(&identity[..4])
            ));
        }

        // An empty allowlist means "do not check membership". With
        // `require` on that is still meaningful — it demands a proven
        // identity without naming which — and it is the configuration an
        // operator reaches for first, before they know the keys.
        if !self.allowed.is_empty() && !self.allowed.contains(identity) {
            return Decision::Refused(format!(
                "sender {} proved its identity but is not on the allowlist",
                hex_encode(&identity[..4])
            ));
        }

        Decision::Authenticated(*identity)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ahp_crypto::signatures::SigningIdentity;

    const EPH: [u8; 32] = [7u8; 32];
    const NONCE: [u8; 16] = [9u8; 16];

    fn offer(id: &SigningIdentity) -> ([u8; 32], [u8; 64]) {
        (id.public_bytes(), id.sign_client_offer(&EPH, &NONCE))
    }

    #[test]
    fn the_default_policy_accepts_everyone_anonymously() {
        // The historical behaviour has to survive untouched, or upgrading
        // the daemon breaks every existing deployment.
        let p = PeerPolicy::default();
        assert!(!p.is_enforcing());
        assert_eq!(p.decide(None, &EPH, &NONCE), Decision::Anonymous);
    }

    #[test]
    fn requiring_auth_refuses_a_sender_that_offers_none() {
        let p = PeerPolicy::new([], true);
        assert!(p.decide(None, &EPH, &NONCE).is_refused());
    }

    #[test]
    fn requiring_auth_accepts_any_proven_identity_when_no_list_is_given() {
        // "Prove you are someone" is a real intermediate posture, and the
        // one an operator can adopt before they have collected keys.
        let id = SigningIdentity::generate();
        let (pk, sig) = offer(&id);
        let p = PeerPolicy::new([], true);
        assert_eq!(p.decide(Some((&pk, &sig)), &EPH, &NONCE), Decision::Authenticated(pk));
    }

    #[test]
    fn an_allowlisted_sender_is_authenticated() {
        let id = SigningIdentity::generate();
        let (pk, sig) = offer(&id);
        let p = PeerPolicy::new([pk], true);
        assert_eq!(p.decide(Some((&pk, &sig)), &EPH, &NONCE), Decision::Authenticated(pk));
    }

    #[test]
    fn a_sender_not_on_the_allowlist_is_refused_even_with_a_good_signature() {
        // The point of the allowlist: proving who you are is not the same
        // as being permitted.
        let allowed = SigningIdentity::generate();
        let stranger = SigningIdentity::generate();
        let (pk, sig) = offer(&stranger);
        let p = PeerPolicy::new([allowed.public_bytes()], true);
        assert!(p.decide(Some((&pk, &sig)), &EPH, &NONCE).is_refused());
    }

    #[test]
    fn a_forged_claim_to_an_allowed_identity_is_refused() {
        // The attack this exists to stop: presenting somebody else's
        // public key, which is public, with a signature you cannot make.
        let allowed = SigningIdentity::generate();
        let attacker = SigningIdentity::generate();
        let pk = allowed.public_bytes();
        let sig = attacker.sign_client_offer(&EPH, &NONCE);
        let p = PeerPolicy::new([pk], true);
        let d = p.decide(Some((&pk, &sig)), &EPH, &NONCE);
        assert!(d.is_refused(), "{d:?}");
        // Refused for the signature, not for membership — otherwise the
        // check order would leak whether that key is on the list.
        assert!(format!("{d:?}").contains("did not prove it"), "{d:?}");
    }

    #[test]
    fn a_signature_for_a_different_ephemeral_key_is_refused() {
        // Replaying a captured signature under a fresh ephemeral key is
        // exactly what the binding prevents; without this the whole scheme
        // reduces to "present any public key you have seen".
        let id = SigningIdentity::generate();
        let (pk, sig) = offer(&id);
        let p = PeerPolicy::new([pk], true);
        assert!(p.decide(Some((&pk, &sig)), &[8u8; 32], &NONCE).is_refused());
        assert!(p.decide(Some((&pk, &sig)), &EPH, &[10u8; 16]).is_refused());
    }

    #[test]
    fn an_allowlist_alone_still_lets_unauthenticated_senders_through() {
        // Deliberate, and the migration path: populate and verify the list
        // while nothing is being turned away, then set --require-peer-auth.
        // Worth a test because it looks like a bug from the outside.
        let id = SigningIdentity::generate();
        let p = PeerPolicy::new([id.public_bytes()], false);
        assert!(p.is_enforcing());
        assert_eq!(p.decide(None, &EPH, &NONCE), Decision::Anonymous);
    }

    #[test]
    fn an_allowlist_alone_still_refuses_a_stranger_who_does_authenticate() {
        let allowed = SigningIdentity::generate();
        let stranger = SigningIdentity::generate();
        let (pk, sig) = offer(&stranger);
        let p = PeerPolicy::new([allowed.public_bytes()], false);
        assert!(p.decide(Some((&pk, &sig)), &EPH, &NONCE).is_refused());
    }

    #[test]
    fn a_malformed_identity_is_refused_rather_than_panicking() {
        // All-zeros is not a valid Ed25519 point. It is also the first
        // thing anybody tries.
        let p = PeerPolicy::new([], true);
        let d = p.decide(Some((&[0u8; 32], &[0u8; 64])), &EPH, &NONCE);
        assert!(d.is_refused(), "{d:?}");
    }
}
