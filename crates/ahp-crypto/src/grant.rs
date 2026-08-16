// Favonius — high-performance file transfer over UDP
// Copyright (c) 2025-2026 Vantino SàRL
// SPDX-License-Identifier: Apache-2.0

//! A signed, expiring permission to write somewhere.
//!
//! `--allow-peer` says *this sender may write here*, and says it until
//! somebody edits the daemon's configuration. That is the right granularity
//! for an operator with a handful of machines and the wrong one for anything
//! that issues permissions per job: it cannot say *this sender, into this
//! directory, for the next few minutes*.
//!
//! A grant is that narrower statement, signed by a **trust anchor** the
//! daemon was configured with. The daemon verifies it offline — no callback,
//! no directory service, no network of any kind — which is what keeps this
//! usable by an operator who has nothing but two machines and a key, and what
//! keeps this crate from acquiring a dependency on whatever issued the grant.
//!
//! # What a grant binds
//!
//! - **Which sender.** The `source` identity must be the one that
//!   authenticated on this connection, so a captured grant is useless to
//!   anyone who cannot also prove that identity.
//! - **Which destination.** The `destination` identity names the daemon it
//!   is for. Without this, a grant would be accepted by *any* daemon
//!   trusting the same anchor, so a permission to write to one machine would
//!   be a permission to write to all of them.
//! - **Which paths**, as a prefix.
//! - **Until when.** Expiry is the revocation mechanism. A grant that lives
//!   minutes does not need a revocation list, which is the point: a
//!   revocation list is the thing short expiry exists to avoid.
//!
//! # What it does not do
//!
//! It does not authenticate the sender — the offer signature does that, and
//! a grant is only meaningful alongside one. It does not survive a clock
//! that is badly wrong; see [`Grant::verify`].

use crate::signatures::{SigningIdentity, VerifyingKeyRef};
use crate::CryptoError;

/// Domain tag. Distinct from every other signature this crate makes, so a
/// grant signature can never be presented as a handshake or offer signature,
/// nor either of those as a grant.
const GRANT_DOMAIN: &[u8] = b"AHP-GRANT-SIG-v1";

/// Wire version, so a daemon can refuse a grant it does not understand
/// rather than misread its fields.
const GRANT_VERSION: u8 = 1;

/// The longest a string field may be. Generous for a path, small enough that
/// a malformed length cannot make a daemon allocate arbitrarily.
const MAX_FIELD: usize = 4096;

/// A permission to write, before it has been checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Grant {
    /// Ed25519 identity of the sender this grant is for.
    pub source: [u8; 32],
    /// Ed25519 identity of the daemon this grant is for.
    pub destination: [u8; 32],
    /// Unix seconds after which this grant means nothing.
    pub not_after: u64,
    /// Opaque to this crate: whatever issued the grant uses it to tie the
    /// permission back to the job that asked for it. Carried so it can be
    /// logged at the receiving end, which is where somebody investigating
    /// an unexpected write will be looking.
    pub run_id: String,
    /// Absolute path prefix the sender may write under.
    pub path_prefix: String,
}

/// A grant whose signature, expiry and destination have been checked.
///
/// Deliberately a separate type: the path check happens later — the
/// requested path is not known at handshake time — and a `Grant` that has
/// merely been parsed must not be mistaken for one that has been verified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedGrant(Grant);

impl VerifiedGrant {
    pub fn grant(&self) -> &Grant {
        &self.0
    }

    /// Whether `path` falls under this grant's prefix.
    ///
    /// A plain `starts_with` on strings would accept `/srv/incoming-evil`
    /// for a prefix of `/srv/incoming`, so a prefix that does not already
    /// end in a separator is compared as though it did. Equality with the
    /// prefix itself is allowed: a grant for a file names that file.
    pub fn permits_path(&self, path: &str) -> bool {
        let prefix = &self.0.path_prefix;
        if prefix.is_empty() {
            return false;
        }
        if path == prefix {
            return true;
        }
        let with_sep =
            if prefix.ends_with('/') { prefix.clone() } else { format!("{prefix}/") };
        path.starts_with(&with_sep)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GrantError {
    /// Not a grant, or truncated, or a length field that does not fit.
    Malformed,
    /// A version this build does not understand.
    UnsupportedVersion(u8),
    /// The signature does not verify against any configured anchor.
    NotSignedByAnAnchor,
    /// Expired, with how long ago in seconds.
    Expired { by_secs: u64 },
    /// Issued for a different daemon.
    WrongDestination,
    /// Issued for a different sender than the one that authenticated.
    WrongSource,
    /// The verifier could not read its own clock, so expiry cannot be
    /// checked. Refused rather than waved through — see [`Grant::verify`].
    NoUsableClock,
}

impl std::fmt::Display for GrantError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Malformed => write!(f, "grant is malformed"),
            Self::UnsupportedVersion(v) => write!(f, "grant version {v} is not supported"),
            Self::NotSignedByAnAnchor => {
                write!(f, "grant is not signed by a configured trust anchor")
            }
            Self::Expired { by_secs } => write!(f, "grant expired {by_secs}s ago"),
            Self::WrongDestination => write!(f, "grant was issued for a different daemon"),
            Self::WrongSource => write!(f, "grant was issued for a different sender"),
            Self::NoUsableClock => write!(
                f,
                "this host's clock is before 2020, so a grant's expiry cannot be checked; \
                 set the time (NTP, or an RTC) before requiring grants"
            ),
        }
    }
}

impl std::error::Error for GrantError {}

/// Unix seconds at the start of 2020.
///
/// A host whose clock predates this has not set it — a Raspberry Pi with no
/// real-time clock boots in 1970, and one whose NTP has never run stays
/// there. Any expiry check against such a clock is meaningless, and the
/// meaningless answer it gives is *"not expired"*, which is the wrong way to
/// be wrong.
const CLOCK_SANITY_FLOOR: u64 = 1_577_836_800;

impl Grant {
    /// Serialise the signed portion: domain tag, then every field.
    fn signing_bytes(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(GRANT_DOMAIN.len() + 32 + 32 + 8 + 4 + 64);
        b.extend_from_slice(GRANT_DOMAIN);
        b.push(GRANT_VERSION);
        b.extend_from_slice(&self.source);
        b.extend_from_slice(&self.destination);
        b.extend_from_slice(&self.not_after.to_be_bytes());
        push_str(&mut b, &self.run_id);
        push_str(&mut b, &self.path_prefix);
        b
    }

    /// Sign this grant with a trust anchor's key, producing wire bytes.
    pub fn sign(&self, anchor: &SigningIdentity) -> Vec<u8> {
        let mut out = self.signing_bytes();
        let signature = anchor.sign(&out);
        // The domain tag is not transmitted: both ends know it, and a
        // verifier rebuilds the signed bytes from the parsed fields. Sending
        // it would let a peer choose it.
        out.drain(..GRANT_DOMAIN.len());
        out.extend_from_slice(&signature);
        out
    }

    /// Parse wire bytes into a grant and its signature.
    pub fn parse(bytes: &[u8]) -> Result<(Self, [u8; 64]), GrantError> {
        // version + source + destination + not_after + two length prefixes
        // + signature
        if bytes.len() < 1 + 32 + 32 + 8 + 2 + 2 + 64 {
            return Err(GrantError::Malformed);
        }
        let version = bytes[0];
        if version != GRANT_VERSION {
            return Err(GrantError::UnsupportedVersion(version));
        }
        let mut at = 1;
        let mut source = [0u8; 32];
        source.copy_from_slice(&bytes[at..at + 32]);
        at += 32;
        let mut destination = [0u8; 32];
        destination.copy_from_slice(&bytes[at..at + 32]);
        at += 32;
        let mut na = [0u8; 8];
        na.copy_from_slice(&bytes[at..at + 8]);
        let not_after = u64::from_be_bytes(na);
        at += 8;

        let run_id = take_str(bytes, &mut at)?;
        let path_prefix = take_str(bytes, &mut at)?;

        if bytes.len() != at + 64 {
            // Not "at least": trailing bytes after the signature would be
            // unsigned content, and a field nobody signed has no business
            // travelling inside something whose whole purpose is to be
            // signed.
            return Err(GrantError::Malformed);
        }
        let mut signature = [0u8; 64];
        signature.copy_from_slice(&bytes[at..at + 64]);

        Ok((Self { source, destination, not_after, run_id, path_prefix }, signature))
    }

    /// Parse and check a grant.
    ///
    /// `anchors` are the public keys this daemon was configured to trust;
    /// `destination` is this daemon's own identity; `source` is the identity
    /// that actually authenticated on this connection; `now` is unix
    /// seconds.
    ///
    /// Expiry is checked **once, here**, at handshake time. It is not
    /// rechecked mid-transfer: the sender is bound to the session keys by
    /// then, and expiring a running transfer would kill a six-hour copy for
    /// a permission that was valid when it started, buying nothing.
    ///
    /// A clock that is obviously unset is refused rather than tolerated,
    /// because tolerating it silently converts every expiry into "never".
    pub fn verify(
        bytes: &[u8],
        anchors: &[[u8; 32]],
        destination: &[u8; 32],
        source: &[u8; 32],
        now: u64,
    ) -> Result<VerifiedGrant, GrantError> {
        let (grant, signature) = Self::parse(bytes)?;

        // Signature first. Every check after this reads fields that only
        // mean something once they are known to be the issuer's words.
        let signed = grant.signing_bytes();
        let ok = anchors.iter().any(|a| {
            VerifyingKeyRef::from_bytes(a)
                .map(|k| k.verify(&signed, &signature).is_ok())
                .unwrap_or(false)
        });
        if !ok {
            return Err(GrantError::NotSignedByAnAnchor);
        }

        if &grant.destination != destination {
            return Err(GrantError::WrongDestination);
        }
        if &grant.source != source {
            return Err(GrantError::WrongSource);
        }
        if now < CLOCK_SANITY_FLOOR {
            return Err(GrantError::NoUsableClock);
        }
        if now > grant.not_after {
            return Err(GrantError::Expired { by_secs: now - grant.not_after });
        }
        Ok(VerifiedGrant(grant))
    }
}

/// Current unix seconds, or 0 when the clock is before the epoch.
///
/// 0 is deliberately a value [`Grant::verify`] refuses: an unreadable clock
/// must not become a passing expiry check.
pub fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn push_str(buf: &mut Vec<u8>, s: &str) {
    buf.extend_from_slice(&(s.len() as u16).to_be_bytes());
    buf.extend_from_slice(s.as_bytes());
}

fn take_str(bytes: &[u8], at: &mut usize) -> Result<String, GrantError> {
    if bytes.len() < *at + 2 {
        return Err(GrantError::Malformed);
    }
    let len = u16::from_be_bytes([bytes[*at], bytes[*at + 1]]) as usize;
    *at += 2;
    if len > MAX_FIELD || bytes.len() < *at + len {
        return Err(GrantError::Malformed);
    }
    let s = std::str::from_utf8(&bytes[*at..*at + len])
        .map_err(|_| GrantError::Malformed)?
        .to_string();
    *at += len;
    Ok(s)
}

impl From<GrantError> for CryptoError {
    fn from(_: GrantError) -> Self {
        CryptoError::SignatureInvalid
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_800_000_000; // well after the sanity floor

    fn grant_for(source: [u8; 32], destination: [u8; 32]) -> Grant {
        Grant {
            source,
            destination,
            not_after: NOW + 300,
            run_id: "run-1234".into(),
            path_prefix: "/srv/incoming/nightly".into(),
        }
    }

    struct Fixture {
        anchor: SigningIdentity,
        source: [u8; 32],
        destination: [u8; 32],
    }

    fn fixture() -> Fixture {
        Fixture {
            anchor: SigningIdentity::generate(),
            source: SigningIdentity::generate().public_bytes(),
            destination: SigningIdentity::generate().public_bytes(),
        }
    }

    #[test]
    fn a_valid_grant_verifies_and_round_trips() {
        let f = fixture();
        let g = grant_for(f.source, f.destination);
        let bytes = g.sign(&f.anchor);
        let v = Grant::verify(
            &bytes,
            &[f.anchor.public_bytes()],
            &f.destination,
            &f.source,
            NOW,
        )
        .expect("verifies");
        assert_eq!(v.grant(), &g, "fields did not survive the wire");
    }

    #[test]
    fn a_grant_signed_by_an_unknown_key_is_refused() {
        let f = fixture();
        let bytes = grant_for(f.source, f.destination).sign(&SigningIdentity::generate());
        assert_eq!(
            Grant::verify(&bytes, &[f.anchor.public_bytes()], &f.destination, &f.source, NOW),
            Err(GrantError::NotSignedByAnAnchor)
        );
    }

    #[test]
    fn any_configured_anchor_may_have_signed_it() {
        // Why the anchor list is a list: rotation. Publish the new anchor,
        // let daemons accept both, switch issuance, retire the old one. With
        // one anchor at a time, rotating means reconfiguring every daemon in
        // the estate in the same window.
        let f = fixture();
        let old = SigningIdentity::generate();
        let bytes = grant_for(f.source, f.destination).sign(&f.anchor);
        let anchors = [old.public_bytes(), f.anchor.public_bytes()];
        assert!(Grant::verify(&bytes, &anchors, &f.destination, &f.source, NOW).is_ok());
    }

    #[test]
    fn a_tampered_field_breaks_the_signature() {
        let f = fixture();
        let mut bytes = grant_for(f.source, f.destination).sign(&f.anchor);
        // Push the expiry far into the future: the field an attacker most
        // wants to edit.
        let at = 1 + 32 + 32;
        bytes[at..at + 8].copy_from_slice(&u64::MAX.to_be_bytes());
        assert_eq!(
            Grant::verify(&bytes, &[f.anchor.public_bytes()], &f.destination, &f.source, NOW),
            Err(GrantError::NotSignedByAnAnchor)
        );
    }

    #[test]
    fn a_grant_for_another_daemon_is_refused() {
        // Without this, a grant to write to one machine is a grant to write
        // to every machine trusting the same anchor.
        let f = fixture();
        let elsewhere = SigningIdentity::generate().public_bytes();
        let bytes = grant_for(f.source, elsewhere).sign(&f.anchor);
        assert_eq!(
            Grant::verify(&bytes, &[f.anchor.public_bytes()], &f.destination, &f.source, NOW),
            Err(GrantError::WrongDestination)
        );
    }

    #[test]
    fn a_grant_for_another_sender_is_refused() {
        // A grant captured off the wire is useless to anyone who cannot also
        // prove the identity it names.
        let f = fixture();
        let bytes = grant_for(f.source, f.destination).sign(&f.anchor);
        let someone_else = SigningIdentity::generate().public_bytes();
        assert_eq!(
            Grant::verify(
                &bytes,
                &[f.anchor.public_bytes()],
                &f.destination,
                &someone_else,
                NOW
            ),
            Err(GrantError::WrongSource)
        );
    }

    #[test]
    fn an_expired_grant_is_refused_and_says_by_how_much() {
        let f = fixture();
        let bytes = grant_for(f.source, f.destination).sign(&f.anchor);
        let err = Grant::verify(
            &bytes,
            &[f.anchor.public_bytes()],
            &f.destination,
            &f.source,
            NOW + 301,
        )
        .unwrap_err();
        assert_eq!(err, GrantError::Expired { by_secs: 1 });
    }

    #[test]
    fn an_unset_clock_refuses_rather_than_accepting_everything() {
        // A Pi with no RTC boots in 1970. Every grant looks unexpired to
        // that clock, which is the wrong way to be wrong.
        let f = fixture();
        let bytes = grant_for(f.source, f.destination).sign(&f.anchor);
        assert_eq!(
            Grant::verify(&bytes, &[f.anchor.public_bytes()], &f.destination, &f.source, 0),
            Err(GrantError::NoUsableClock)
        );
        // And the message says what to do about it.
        assert!(GrantError::NoUsableClock.to_string().contains("NTP"));
    }

    #[test]
    fn malformed_and_truncated_input_is_refused_without_panicking() {
        let f = fixture();
        let bytes = grant_for(f.source, f.destination).sign(&f.anchor);
        for n in 0..bytes.len() {
            // Every truncation must be an error, never a panic and never an
            // accidental accept.
            let r = Grant::verify(
                &bytes[..n],
                &[f.anchor.public_bytes()],
                &f.destination,
                &f.source,
                NOW,
            );
            assert!(r.is_err(), "truncation to {n} bytes was accepted");
        }
        let mut extra = bytes.clone();
        extra.push(0);
        assert_eq!(
            Grant::verify(&extra, &[f.anchor.public_bytes()], &f.destination, &f.source, NOW),
            Err(GrantError::Malformed),
            "unsigned trailing bytes were tolerated"
        );
    }

    #[test]
    fn an_unknown_version_is_refused_rather_than_misread() {
        let f = fixture();
        let mut bytes = grant_for(f.source, f.destination).sign(&f.anchor);
        bytes[0] = 99;
        assert_eq!(
            Grant::verify(&bytes, &[f.anchor.public_bytes()], &f.destination, &f.source, NOW),
            Err(GrantError::UnsupportedVersion(99))
        );
    }

    // ── Path scoping ──────────────────────────────────────────────────────

    fn verified(prefix: &str) -> VerifiedGrant {
        let f = fixture();
        let mut g = grant_for(f.source, f.destination);
        g.path_prefix = prefix.into();
        let bytes = g.sign(&f.anchor);
        Grant::verify(&bytes, &[f.anchor.public_bytes()], &f.destination, &f.source, NOW).unwrap()
    }

    #[test]
    fn a_path_under_the_prefix_is_permitted() {
        let v = verified("/srv/incoming");
        assert!(v.permits_path("/srv/incoming/a.bin"));
        assert!(v.permits_path("/srv/incoming/deep/a.bin"));
        assert!(v.permits_path("/srv/incoming"), "the prefix itself names a file");
    }

    #[test]
    fn a_sibling_sharing_the_prefix_string_is_not_permitted() {
        // The bug a plain starts_with would ship: /srv/incoming-evil begins
        // with /srv/incoming.
        let v = verified("/srv/incoming");
        assert!(!v.permits_path("/srv/incoming-evil/a.bin"));
        assert!(!v.permits_path("/srv/incomingevil"));
    }

    #[test]
    fn a_path_outside_the_prefix_is_not_permitted() {
        let v = verified("/srv/incoming");
        assert!(!v.permits_path("/etc/cron.d/pwn"));
        assert!(!v.permits_path("/srv/other/a.bin"));
    }

    #[test]
    fn a_trailing_separator_in_the_prefix_behaves_the_same() {
        let v = verified("/srv/incoming/");
        assert!(v.permits_path("/srv/incoming/a.bin"));
        assert!(!v.permits_path("/srv/incoming-evil/a.bin"));
    }

    #[test]
    fn an_empty_prefix_permits_nothing() {
        // Fail closed: an issuer that forgot to set a prefix must not have
        // written "anywhere".
        assert!(!verified("").permits_path("/srv/incoming/a.bin"));
        assert!(!verified("").permits_path("/"));
    }
}
