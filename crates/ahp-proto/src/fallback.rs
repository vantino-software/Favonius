// Favonius — high-performance file transfer over UDP
// Copyright (c) 2025-2026 Vantino SàRL
// SPDX-License-Identifier: Apache-2.0

//! The TCP fallback framing, shared by sender and daemon.
//!
//! # Why a UDP transfer engine ships a TCP path
//!
//! Enterprise egress is proxied and enterprise ingress is closed. Reaching
//! a receiving daemon means asking a network team to permit inbound UDP,
//! and plenty of policies decline that outright. Until now a blocked port
//! meant Favonius did not degrade — it failed. **A transfer that arrives
//! slowly beats one that needs a change request**, and an evaluator who
//! cannot move a file in their first ten minutes does not stay to read the
//! benchmarks.
//!
//! So this is deliberately *not* AHP over TCP. It borrows none of the
//! congestion control, none of the multi-stream machinery, and claims
//! none of the performance. The kernel's TCP stack does the work. It
//! exists so that "can we move a file at all" is always yes.
//!
//! # Same port number, both protocols
//!
//! The daemon listens for this on the **TCP** socket bearing its control
//! port number, so a deployment asks for one port rather than two, in a
//! sentence a network team can act on: *"permit 7801 to this host, UDP for
//! speed and TCP as the fallback."* UDP 7801 and TCP 7801 are separate
//! sockets and do not conflict.
//!
//! # The frame
//!
//! ```text
//!   magic      8   b"FVNFALL1"
//!   version    1   1
//!   flags      1   reserved, must be 0
//!   path_len   2   big-endian, <= MAX_PATH
//!   size       8   big-endian, file length in bytes
//!   path       path_len   UTF-8, relative, resolved against --dest-root
//!   payload    size       the file
//!   hash      32   BLAKE3 of the payload
//! ```
//!
//! The hash travels **after** the payload so the sender can stream a file
//! it is hashing as it reads, without a second pass over the data. The
//! receiver verifies before it commits, so a truncated or altered transfer
//! is refused rather than written.
//!
//! Integers are big-endian throughout, matching the rest of the wire
//! format. A previous module documented little-endian and was wrong, which
//! cost a debugging session — so this one is tested in both directions.

/// Connectivity probe payload, sent by `favonius check` to a UDP port.
///
/// A daemon answers with [`PROBE_REPLY`], which proves the round trip
/// without needing a handshake — the honest test of a datagram path is a
/// datagram that comes back.
pub const PROBE: &[u8; 8] = b"FVNPROBE";

/// The answer. **Exactly as long as [`PROBE`]**, deliberately: an
/// unauthenticated responder that replies with more bytes than it receives
/// is a reflection amplifier, and this port is reachable by anyone.
pub const PROBE_REPLY: &[u8; 8] = b"FVNPONG1";

/// Frame magic. Distinct from the UDP wire format: a client that reaches
/// the wrong port should be told so, not silently misparsed.
pub const MAGIC: &[u8; 8] = b"FVNFALL1";

/// Wire version of this framing.
pub const VERSION: u8 = 1;

/// Bytes before the path. Fixed, so a receiver can read the head in one go.
pub const HEADER_LEN: usize = 8 + 1 + 1 + 2 + 8;

/// Longest destination path accepted, in bytes.
///
/// Bounded because it is read from the network before anything is
/// validated: an unbounded length is an allocation an unauthenticated peer
/// controls.
pub const MAX_PATH: usize = 4096;

/// Largest file this path will accept, 1 TiB.
///
/// Not a statement about what the engine can move — it is a ceiling on
/// what a single unauthenticated frame may claim, so a bad length field
/// cannot make the receiver wait forever on bytes that are not coming.
pub const MAX_SIZE: u64 = 1024 * 1024 * 1024 * 1024;

/// What a sender announces before the bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FallbackHeader {
    /// Destination path, relative, resolved against the daemon's root.
    pub path: String,
    /// Payload length in bytes.
    pub size: u64,
}

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum FallbackError {
    #[error("not a Favonius fallback frame (wrong magic)")]
    BadMagic,
    #[error("unsupported fallback version {0}; this daemon speaks {VERSION}")]
    BadVersion(u8),
    #[error("reserved flags must be zero, got {0:#x}")]
    ReservedFlags(u8),
    #[error("path length {0} exceeds the {MAX_PATH}-byte maximum")]
    PathTooLong(usize),
    #[error("path is empty")]
    EmptyPath,
    #[error("declared size {0} exceeds the {MAX_SIZE}-byte maximum")]
    TooLarge(u64),
    #[error("path is not valid UTF-8")]
    BadUtf8,
    #[error("frame is truncated: expected {expected} bytes, got {got}")]
    Truncated { expected: usize, got: usize },
}

impl FallbackHeader {
    /// Serialise the fixed head plus the path.
    pub fn encode(&self) -> Result<Vec<u8>, FallbackError> {
        let path = self.path.as_bytes();
        if path.is_empty() {
            return Err(FallbackError::EmptyPath);
        }
        if path.len() > MAX_PATH {
            return Err(FallbackError::PathTooLong(path.len()));
        }
        if self.size > MAX_SIZE {
            return Err(FallbackError::TooLarge(self.size));
        }

        let mut out = Vec::with_capacity(HEADER_LEN + path.len());
        out.extend_from_slice(MAGIC);
        out.push(VERSION);
        out.push(0); // flags
        out.extend_from_slice(&(path.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.size.to_be_bytes());
        out.extend_from_slice(path);
        Ok(out)
    }

    /// Parse the fixed head. Returns the path length still to be read.
    ///
    /// Split from the path so a receiver can read exactly `HEADER_LEN`
    /// bytes, learn how many more it needs, and never guess.
    pub fn decode_head(buf: &[u8]) -> Result<(usize, u64), FallbackError> {
        if buf.len() < HEADER_LEN {
            return Err(FallbackError::Truncated {
                expected: HEADER_LEN,
                got: buf.len(),
            });
        }
        if &buf[0..8] != MAGIC {
            return Err(FallbackError::BadMagic);
        }
        if buf[8] != VERSION {
            return Err(FallbackError::BadVersion(buf[8]));
        }
        if buf[9] != 0 {
            return Err(FallbackError::ReservedFlags(buf[9]));
        }
        let path_len = u16::from_be_bytes([buf[10], buf[11]]) as usize;
        if path_len == 0 {
            return Err(FallbackError::EmptyPath);
        }
        if path_len > MAX_PATH {
            return Err(FallbackError::PathTooLong(path_len));
        }
        let size = u64::from_be_bytes(buf[12..20].try_into().expect("checked length"));
        if size > MAX_SIZE {
            return Err(FallbackError::TooLarge(size));
        }
        Ok((path_len, size))
    }

    /// Complete the header once the path bytes have been read.
    pub fn from_parts(path_bytes: &[u8], size: u64) -> Result<Self, FallbackError> {
        let path = std::str::from_utf8(path_bytes)
            .map_err(|_| FallbackError::BadUtf8)?
            .to_string();
        Ok(Self { path, size })
    }
}

/// The daemon's reply, one byte plus an optional reason.
///
/// Deliberately tiny: the sender needs to know whether the bytes were
/// committed, and if not, something a human can act on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FallbackReply {
    /// Written and verified.
    Accepted,
    /// Refused, with a reason meant for a person.
    Refused(String),
}

impl FallbackReply {
    pub fn encode(&self) -> Vec<u8> {
        match self {
            Self::Accepted => vec![0x01],
            Self::Refused(reason) => {
                let r = reason.as_bytes();
                let len = r.len().min(u16::MAX as usize);
                let mut out = Vec::with_capacity(3 + len);
                out.push(0x02);
                out.extend_from_slice(&(len as u16).to_be_bytes());
                out.extend_from_slice(&r[..len]);
                out
            }
        }
    }

    pub fn decode(buf: &[u8]) -> Option<Self> {
        match buf.first()? {
            0x01 => Some(Self::Accepted),
            0x02 => {
                let len = u16::from_be_bytes([*buf.get(1)?, *buf.get(2)?]) as usize;
                let bytes = buf.get(3..3 + len)?;
                Some(Self::Refused(String::from_utf8_lossy(bytes).into_owned()))
            }
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The reply must never be longer than the probe. A larger answer to
    /// an unauthenticated request is a reflection amplifier.
    #[test]
    fn the_probe_reply_cannot_amplify() {
        assert_eq!(PROBE.len(), PROBE_REPLY.len());
        assert_ne!(PROBE, PROBE_REPLY, "the reply must be distinguishable from the probe");
    }

    #[test]
    fn a_header_round_trips() {
        let h = FallbackHeader { path: "reports/q3.bin".into(), size: 3_145_728 };
        let bytes = h.encode().unwrap();
        let (path_len, size) = FallbackHeader::decode_head(&bytes).unwrap();
        assert_eq!(size, 3_145_728);
        let back = FallbackHeader::from_parts(&bytes[HEADER_LEN..HEADER_LEN + path_len], size).unwrap();
        assert_eq!(back, h);
    }

    /// Integers are big-endian. A sibling module documented little-endian,
    /// was wrong, and cost a debugging session; this pins the byte order
    /// so the next reader does not have to trust a comment.
    #[test]
    fn integers_are_big_endian_on_the_wire() {
        // Distinct bytes so a byte-swap is visible, and under MAX_SIZE --
        // the first draft of this test used a value the size cap
        // correctly refused, which is the cap working rather than a bug.
        let h = FallbackHeader { path: "x".into(), size: 0x0000_0001_0203_0405 };
        let b = h.encode().unwrap();
        assert_eq!(&b[12..20], &[0, 0, 0, 1, 2, 3, 4, 5], "size is not big-endian");
        assert_eq!(&b[10..12], &[0, 1], "path length is not big-endian");
    }

    #[test]
    fn a_unicode_path_survives() {
        let h = FallbackHeader { path: "dossier été/note.txt".into(), size: 7 };
        let b = h.encode().unwrap();
        let (n, size) = FallbackHeader::decode_head(&b).unwrap();
        assert_eq!(
            FallbackHeader::from_parts(&b[HEADER_LEN..HEADER_LEN + n], size).unwrap(),
            h
        );
    }

    // ── what must be refused ──────────────────────────────────────────

    #[test]
    fn a_foreign_frame_is_refused_rather_than_misparsed() {
        let mut b = FallbackHeader { path: "a".into(), size: 1 }.encode().unwrap();
        b[0] = b'X';
        assert_eq!(FallbackHeader::decode_head(&b), Err(FallbackError::BadMagic));
    }

    #[test]
    fn a_future_version_is_named_not_guessed() {
        let mut b = FallbackHeader { path: "a".into(), size: 1 }.encode().unwrap();
        b[8] = 9;
        assert_eq!(FallbackHeader::decode_head(&b), Err(FallbackError::BadVersion(9)));
    }

    #[test]
    fn reserved_flags_must_be_zero() {
        let mut b = FallbackHeader { path: "a".into(), size: 1 }.encode().unwrap();
        b[9] = 0x80;
        assert_eq!(
            FallbackHeader::decode_head(&b),
            Err(FallbackError::ReservedFlags(0x80))
        );
    }

    /// The length fields are read from the network before anything is
    /// trusted, so an absurd value must be refused rather than allocated.
    #[test]
    fn absurd_lengths_are_refused_before_allocating() {
        let mut b = FallbackHeader { path: "a".into(), size: 1 }.encode().unwrap();
        b[10..12].copy_from_slice(&(MAX_PATH as u16 + 1).to_be_bytes());
        assert!(matches!(
            FallbackHeader::decode_head(&b),
            Err(FallbackError::PathTooLong(_))
        ));

        let mut b = FallbackHeader { path: "a".into(), size: 1 }.encode().unwrap();
        b[12..20].copy_from_slice(&u64::MAX.to_be_bytes());
        assert!(matches!(
            FallbackHeader::decode_head(&b),
            Err(FallbackError::TooLarge(_))
        ));
    }

    #[test]
    fn a_truncated_head_says_how_short_it_is() {
        assert_eq!(
            FallbackHeader::decode_head(&[0u8; 4]),
            Err(FallbackError::Truncated { expected: HEADER_LEN, got: 4 })
        );
    }

    #[test]
    fn an_empty_path_is_refused_both_ways() {
        assert_eq!(
            FallbackHeader { path: String::new(), size: 1 }.encode(),
            Err(FallbackError::EmptyPath)
        );
        let mut b = FallbackHeader { path: "a".into(), size: 1 }.encode().unwrap();
        b[10..12].copy_from_slice(&0u16.to_be_bytes());
        assert_eq!(FallbackHeader::decode_head(&b), Err(FallbackError::EmptyPath));
    }

    #[test]
    fn replies_round_trip() {
        assert_eq!(
            FallbackReply::decode(&FallbackReply::Accepted.encode()),
            Some(FallbackReply::Accepted)
        );
        let refused = FallbackReply::Refused("destination path escapes --dest-root".into());
        assert_eq!(FallbackReply::decode(&refused.encode()), Some(refused));
    }

    #[test]
    fn a_reply_that_is_neither_is_not_read_as_success() {
        // The dangerous direction: an unrecognised byte must not decode as
        // Accepted, or a confused peer becomes a successful transfer.
        assert_eq!(FallbackReply::decode(&[0xFF]), None);
        assert_eq!(FallbackReply::decode(&[]), None);
    }
}
