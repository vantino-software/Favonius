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

use ahp_crypto::grant::{Grant, VerifiedGrant};
use ahp_crypto::signatures::{hex_encode, VerifyingKeyRef};

/// What the daemon decided about a sender.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// The sender proved an identity the policy accepts, and — when it
    /// presented one — a grant that checked out. The grant travels with the
    /// decision because the path it permits cannot be checked yet: the
    /// destination path arrives in the MANIFEST, after this handshake.
    Authenticated {
        identity: [u8; 32],
        grant: Option<VerifiedGrant>,
    },
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
    /// Public keys whose signature makes a grant worth reading. A list, not
    /// one key, because that is what makes rotation possible without a flag
    /// day: publish the new anchor, let daemons accept both, switch
    /// issuance, retire the old one.
    anchors: Vec<[u8; 32]>,
    require_grant: bool,
    /// This daemon's own identity. A grant names the daemon it was issued
    /// for, and without knowing which daemon it is, this one cannot tell a
    /// permission meant for it from a permission meant for another machine
    /// trusting the same anchor.
    own_identity: Option<[u8; 32]>,
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
        Self {
            allowed: allowed.into_iter().collect(),
            require,
            anchors: Vec::new(),
            require_grant: false,
            own_identity: None,
        }
    }

    /// Accept grants signed by `anchors`, addressed to `own_identity`.
    ///
    /// `require_grant` implies requiring authentication, and is forced here
    /// rather than left to the caller: a grant names the sender it is for,
    /// so demanding one from a sender that proved no identity would be
    /// demanding a document nobody checked the bearer of.
    pub fn with_trust_anchors(
        mut self,
        anchors: impl IntoIterator<Item = [u8; 32]>,
        require_grant: bool,
        own_identity: Option<[u8; 32]>,
    ) -> Self {
        self.anchors = anchors.into_iter().collect();
        self.require_grant = require_grant;
        self.own_identity = own_identity;
        if require_grant {
            self.require = true;
        }
        self
    }

    pub fn requires_grant(&self) -> bool {
        self.require_grant
    }

    pub fn anchor_count(&self) -> usize {
        self.anchors.len()
    }

    /// Whether this daemon will turn anyone away. Used to decide whether
    /// to advertise the capability and what to say at startup.
    pub fn is_enforcing(&self) -> bool {
        self.require || !self.allowed.is_empty() || !self.anchors.is_empty()
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
        grant_bytes: Option<&[u8]>,
        ephemeral_pub: &[u8; 32],
        nonce: &[u8],
        now: u64,
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

        // ── The grant, if this daemon deals in them ──────────────────────
        let grant = match grant_bytes {
            Some(bytes) if !self.anchors.is_empty() => {
                // A daemon that accepts grants must know its own identity,
                // or it cannot check that one was addressed to it. Treated
                // as a refusal rather than as "skip the check": the
                // alternative is accepting a permission meant for another
                // machine.
                let Some(destination) = self.own_identity else {
                    return Decision::Refused(
                        "a grant was presented but this daemon has no --identity, so it \
                         cannot tell whether the grant was issued for it"
                            .into(),
                    );
                };
                match Grant::verify(bytes, &self.anchors, &destination, identity, now) {
                    Ok(v) => Some(v),
                    Err(e) => {
                        return Decision::Refused(format!(
                            "sender {} presented a grant that did not check out: {e}",
                            hex_encode(&identity[..4])
                        ))
                    }
                }
            }
            // Presented one, but this daemon trusts nobody to issue them, so
            // there is nothing to verify it against. Ignored rather than
            // refused: the sender may simply be talking to a daemon that
            // does not use grants, which is not its mistake.
            Some(_) => None,
            None => None,
        };

        if self.require_grant && grant.is_none() {
            return Decision::Refused(format!(
                "sender {} authenticated but presented no valid grant, and this daemon \
                 requires one",
                hex_encode(&identity[..4])
            ));
        }

        Decision::Authenticated { identity: *identity, grant }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ahp_crypto::signatures::SigningIdentity;

    const EPH: [u8; 32] = [7u8; 32];
    const NONCE: [u8; 16] = [9u8; 16];
    /// Any time after the clock-sanity floor; grants below set their own.
    const NOW: u64 = 1_800_000_000;

    /// `decide` for the cases that involve no grant.
    fn decide(p: &PeerPolicy, presented: Option<(&[u8; 32], &[u8; 64])>) -> Decision {
        p.decide(presented, None, &EPH, &NONCE, NOW)
    }

    fn offer(id: &SigningIdentity) -> ([u8; 32], [u8; 64]) {
        (id.public_bytes(), id.sign_client_offer(&EPH, &NONCE))
    }

    #[test]
    fn the_default_policy_accepts_everyone_anonymously() {
        // The historical behaviour has to survive untouched, or upgrading
        // the daemon breaks every existing deployment.
        let p = PeerPolicy::default();
        assert!(!p.is_enforcing());
        assert_eq!(decide(&p, None), Decision::Anonymous);
    }

    #[test]
    fn requiring_auth_refuses_a_sender_that_offers_none() {
        let p = PeerPolicy::new([], true);
        assert!(decide(&p, None).is_refused());
    }

    #[test]
    fn requiring_auth_accepts_any_proven_identity_when_no_list_is_given() {
        // "Prove you are someone" is a real intermediate posture, and the
        // one an operator can adopt before they have collected keys.
        let id = SigningIdentity::generate();
        let (pk, sig) = offer(&id);
        let p = PeerPolicy::new([], true);
        assert_eq!(decide(&p, Some((&pk, &sig))), Decision::Authenticated { identity: pk, grant: None });
    }

    #[test]
    fn an_allowlisted_sender_is_authenticated() {
        let id = SigningIdentity::generate();
        let (pk, sig) = offer(&id);
        let p = PeerPolicy::new([pk], true);
        assert_eq!(decide(&p, Some((&pk, &sig))), Decision::Authenticated { identity: pk, grant: None });
    }

    #[test]
    fn a_sender_not_on_the_allowlist_is_refused_even_with_a_good_signature() {
        // The point of the allowlist: proving who you are is not the same
        // as being permitted.
        let allowed = SigningIdentity::generate();
        let stranger = SigningIdentity::generate();
        let (pk, sig) = offer(&stranger);
        let p = PeerPolicy::new([allowed.public_bytes()], true);
        assert!(decide(&p, Some((&pk, &sig))).is_refused());
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
        let d = decide(&p, Some((&pk, &sig)));
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
        assert!(p.decide(Some((&pk, &sig)), None, &[8u8; 32], &NONCE, NOW).is_refused());
        assert!(p.decide(Some((&pk, &sig)), None, &EPH, &[10u8; 16], NOW).is_refused());
    }

    #[test]
    fn an_allowlist_alone_still_lets_unauthenticated_senders_through() {
        // Deliberate, and the migration path: populate and verify the list
        // while nothing is being turned away, then set --require-peer-auth.
        // Worth a test because it looks like a bug from the outside.
        let id = SigningIdentity::generate();
        let p = PeerPolicy::new([id.public_bytes()], false);
        assert!(p.is_enforcing());
        assert_eq!(decide(&p, None), Decision::Anonymous);
    }

    #[test]
    fn an_allowlist_alone_still_refuses_a_stranger_who_does_authenticate() {
        let allowed = SigningIdentity::generate();
        let stranger = SigningIdentity::generate();
        let (pk, sig) = offer(&stranger);
        let p = PeerPolicy::new([allowed.public_bytes()], false);
        assert!(decide(&p, Some((&pk, &sig))).is_refused());
    }

    #[test]
    fn a_malformed_identity_is_refused_rather_than_panicking() {
        // All-zeros is not a valid Ed25519 point. It is also the first
        // thing anybody tries.
        let p = PeerPolicy::new([], true);
        let d = decide(&p, Some((&[0u8; 32], &[0u8; 64])));
        assert!(d.is_refused(), "{d:?}");
    }

    // ── Grants ────────────────────────────────────────────────────────────

    use ahp_crypto::grant::Grant;

    fn a_grant(source: [u8; 32], destination: [u8; 32], prefix: &str) -> Grant {
        Grant {
            source,
            destination,
            not_after: NOW + 300,
            run_id: "run-1".into(),
            path_prefix: prefix.into(),
        }
    }

    struct GrantFixture {
        anchor: SigningIdentity,
        client: SigningIdentity,
        daemon_id: [u8; 32],
    }

    fn grant_fixture() -> GrantFixture {
        GrantFixture {
            anchor: SigningIdentity::generate(),
            client: SigningIdentity::generate(),
            daemon_id: SigningIdentity::generate().public_bytes(),
        }
    }

    fn policy_with_grants(f: &GrantFixture, require_grant: bool) -> PeerPolicy {
        PeerPolicy::new([], true).with_trust_anchors(
            [f.anchor.public_bytes()],
            require_grant,
            Some(f.daemon_id),
        )
    }

    #[test]
    fn a_valid_grant_is_carried_into_the_decision() {
        let f = grant_fixture();
        let (pk, sig) = offer(&f.client);
        let bytes = a_grant(pk, f.daemon_id, "/srv/in").sign(&f.anchor);
        let p = policy_with_grants(&f, true);
        match p.decide(Some((&pk, &sig)), Some(&bytes), &EPH, &NONCE, NOW) {
            Decision::Authenticated { grant: Some(g), .. } => {
                // The path scope has to survive to the caller: it is applied
                // later, when the manifest names a destination.
                assert!(g.permits_path("/srv/in/a.bin"));
                assert!(!g.permits_path("/etc/cron.d/pwn"));
            }
            other => panic!("expected an authenticated decision with a grant: {other:?}"),
        }
    }

    #[test]
    fn requiring_a_grant_refuses_a_sender_that_brings_none() {
        let f = grant_fixture();
        let (pk, sig) = offer(&f.client);
        let p = policy_with_grants(&f, true);
        assert!(p.decide(Some((&pk, &sig)), None, &EPH, &NONCE, NOW).is_refused());
    }

    #[test]
    fn a_grant_issued_to_another_sender_is_refused() {
        // The grant must be bound to the identity that actually
        // authenticated, or a grant captured off the wire would be usable by
        // anyone who replayed it.
        let f = grant_fixture();
        let (pk, sig) = offer(&f.client);
        let someone_else = SigningIdentity::generate().public_bytes();
        let bytes = a_grant(someone_else, f.daemon_id, "/srv/in").sign(&f.anchor);
        let p = policy_with_grants(&f, true);
        assert!(p.decide(Some((&pk, &sig)), Some(&bytes), &EPH, &NONCE, NOW).is_refused());
    }

    #[test]
    fn a_grant_from_an_untrusted_issuer_is_refused() {
        let f = grant_fixture();
        let (pk, sig) = offer(&f.client);
        let bytes = a_grant(pk, f.daemon_id, "/srv/in").sign(&SigningIdentity::generate());
        let p = policy_with_grants(&f, true);
        assert!(p.decide(Some((&pk, &sig)), Some(&bytes), &EPH, &NONCE, NOW).is_refused());
    }

    #[test]
    fn an_expired_grant_is_refused() {
        let f = grant_fixture();
        let (pk, sig) = offer(&f.client);
        let bytes = a_grant(pk, f.daemon_id, "/srv/in").sign(&f.anchor);
        let p = policy_with_grants(&f, true);
        assert!(p.decide(Some((&pk, &sig)), Some(&bytes), &EPH, &NONCE, NOW + 301).is_refused());
    }

    #[test]
    fn a_daemon_with_no_identity_refuses_a_grant_rather_than_skipping_the_check() {
        // It cannot tell whether the grant was addressed to it. Skipping
        // would accept a permission meant for another machine.
        let f = grant_fixture();
        let (pk, sig) = offer(&f.client);
        let bytes = a_grant(pk, f.daemon_id, "/srv/in").sign(&f.anchor);
        let p = PeerPolicy::new([], true)
            .with_trust_anchors([f.anchor.public_bytes()], true, None);
        assert!(p.decide(Some((&pk, &sig)), Some(&bytes), &EPH, &NONCE, NOW).is_refused());
    }

    #[test]
    fn requiring_a_grant_also_requires_authentication() {
        // A grant names its bearer. Demanding one from a sender that proved
        // nothing would be demanding a document nobody checked the bearer
        // of, so the constructor forces the stricter of the two.
        let f = grant_fixture();
        let p = PeerPolicy::new([], false)
            .with_trust_anchors([f.anchor.public_bytes()], true, Some(f.daemon_id));
        assert!(p.decide(None, None, &EPH, &NONCE, NOW).is_refused());
    }

    #[test]
    fn a_daemon_with_no_anchors_ignores_a_grant_rather_than_refusing_it() {
        // The sender may just be talking to a daemon that does not use
        // grants. That is not the sender's mistake, and refusing would make
        // a client configured for one estate unusable against another.
        let f = grant_fixture();
        let (pk, sig) = offer(&f.client);
        let bytes = a_grant(pk, f.daemon_id, "/srv/in").sign(&f.anchor);
        let p = PeerPolicy::new([pk], true);
        match p.decide(Some((&pk, &sig)), Some(&bytes), &EPH, &NONCE, NOW) {
            Decision::Authenticated { grant, .. } => assert!(grant.is_none()),
            other => panic!("expected acceptance without a grant: {other:?}"),
        }
    }

    #[test]
    fn any_configured_anchor_may_have_issued_the_grant() {
        // Rotation, at the policy layer: both anchors are accepted during
        // the overlap, so the estate is never reconfigured in one window.
        let f = grant_fixture();
        let retiring = SigningIdentity::generate();
        let (pk, sig) = offer(&f.client);
        let bytes = a_grant(pk, f.daemon_id, "/srv/in").sign(&retiring);
        let p = PeerPolicy::new([], true).with_trust_anchors(
            [f.anchor.public_bytes(), retiring.public_bytes()],
            true,
            Some(f.daemon_id),
        );
        assert!(!p.decide(Some((&pk, &sig)), Some(&bytes), &EPH, &NONCE, NOW).is_refused());
    }
}
