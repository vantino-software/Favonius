// Favonius — high-performance file transfer over UDP
// Copyright (c) 2025-2026 Vantino SàRL
// SPDX-License-Identifier: Apache-2.0

//! HELLO / HELLO_ACK handshake payload formats.
//!
//! HELLO payload (first byte is a flag):
//!
//! ```text
//! 0x00: plaintext
//! 0x01: full DH      — [32-byte public key] [16-byte nonce]
//! 0x02: 0-RTT resume — [4-byte ticket_len BE] [ticket_data] [16-byte nonce]
//! ```
//!
//! HELLO_ACK payload:
//!
//! ```text
//! [1-byte mode] [mode-specific material] [2-byte data port BE]
//! ```
//!
//! The mode byte makes the negotiated crypto mode explicit so the client can
//! detect a mismatch (e.g. the daemon rejected a resume ticket after a
//! restart and fell back to plaintext) instead of streaming ciphertext the
//! peer parses as plaintext — silent file corruption. `FullHandshake` carries
//! [32-byte public key] [16-byte nonce] as material; when the daemon has an
//! Ed25519 identity it additionally carries [32-byte identity pubkey]
//! [64-byte signature] (S5, RFC §12.2) — the signature covers the handshake
//! transcript (both DH public keys + both nonces, see
//! `ahp_crypto::signatures`). `Resumed` carries a [16-byte server nonce]
//! (mixed into the resumed key derivation so a replayed ticket never
//! reproduces earlier session keys); `Plaintext` carries none. A bare "busy"
//! acknowledgement (transfer queued behind a running one) may carry only the
//! mode byte, without a data port.

/// Crypto mode negotiated for a transfer, carried as the first byte of every
/// HELLO_ACK payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HelloAckMode {
    /// No encryption for this transfer.
    Plaintext = 0x00,
    /// Encrypted; full X25519 DH handshake. HELLO_ACK carries the daemon's
    /// public key and nonce as key material.
    FullHandshake = 0x01,
    /// Encrypted; 0-RTT resume from a session ticket. HELLO_ACK carries a
    /// fresh 16-byte server nonce as material; resumed keys are derived from
    /// the ticket's resume_secret, the client nonce, and this server nonce.
    Resumed = 0x02,
}

impl HelloAckMode {
    /// Wire byte for this mode.
    pub fn to_byte(self) -> u8 {
        self as u8
    }

    /// Parse a wire byte; `None` for unknown modes.
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0x00 => Some(Self::Plaintext),
            0x01 => Some(Self::FullHandshake),
            0x02 => Some(Self::Resumed),
            _ => None,
        }
    }
}

/// Parsed HELLO_ACK payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HelloAckPayload {
    /// Negotiated crypto mode.
    pub mode: HelloAckMode,
    /// Data port for DATA packets; `None` for a bare "busy" acknowledgement
    /// (the caller falls back to the control port).
    pub data_port: Option<u16>,
    /// DH key material (daemon public key + nonce); present for
    /// `FullHandshake` acks that carry it.
    pub dh_material: Option<([u8; 32], [u8; 16])>,
    /// Server authentication material (Ed25519 identity pubkey + signature
    /// over the handshake transcript); present for `FullHandshake` acks from
    /// a daemon started with an identity. Inferred from payload length.
    pub auth_material: Option<([u8; 32], [u8; 64])>,
    /// Fresh server nonce for resumed key derivation; present for `Resumed`
    /// acks that carry it.
    pub resume_server_nonce: Option<[u8; 16]>,
    /// Capability bitfield the daemon advertised, or `CAP_NONE` if it sent
    /// no capability block — which is what every peer built before this
    /// existed does. Absent and zero are deliberately the same thing.
    pub capabilities: u32,
}

/// Marks a capability block appended after the HELLO_ACK data port: two
/// bytes of magic, then a big-endian u32 bitfield.
///
/// The magic exists so a decoder can tell "the peer advertised
/// capabilities" from "there happen to be trailing bytes". This is an
/// *append* to a format older peers already parse: for `FullHandshake` and
/// `Resumed` the port is read at a fixed offset, so an old peer ignores
/// anything after it and interoperates unchanged.
///
/// `Plaintext` used to be the exception — its port was read as the *last
/// two bytes* of the payload, so appending would have shifted what an old
/// peer read as the port. That arm now reads a fixed offset too, which is
/// byte-identical for every payload any released version emits and is what
/// makes this append safe in all three modes.
/// See the per-stream data ports section of the README.
pub const CAPABILITY_MAGIC: [u8; 2] = [0xCA, 0xB1];

/// No capabilities advertised.
pub const CAP_NONE: u32 = 0;

/// Bit 0: the daemon can receive one transfer's streams on *separate* data
/// ports, and has reserved a run of them for this connection.
///
/// The run is contiguous and starts at the data port already carried by
/// HELLO_ACK, so nothing new goes on the wire: the sender derives stream
/// *i*'s destination from the base port and the count in
/// [`data_port_count`].
pub const CAP_PER_STREAM_PORTS: u32 = 1 << 0;

/// Bits 8..16 of the capability bitfield: how many contiguous data ports are
/// reserved, counting the advertised one.
const DATA_PORT_COUNT_SHIFT: u32 = 8;
const DATA_PORT_COUNT_MASK: u32 = 0xFF << DATA_PORT_COUNT_SHIFT;

/// Encode a per-stream port run into a capability bitfield.
///
/// A *count* rather than a set of ports, because the daemon must publish
/// this before it knows how many streams the transfer will use:
/// `num_streams` arrives in the MANIFEST, which is read after HELLO_ACK is
/// sent. The sender takes the minimum of the two.
///
/// `n <= 1` advertises nothing — one port is what every peer already
/// assumes, and the bit is only meaningful when there is a run to use.
pub fn per_stream_ports(n: usize) -> u32 {
    if n <= 1 {
        return CAP_NONE;
    }
    CAP_PER_STREAM_PORTS | ((n.min(u8::MAX as usize) as u32) << DATA_PORT_COUNT_SHIFT)
}

/// How many contiguous data ports the peer reserved, counting the advertised
/// one. Returns 1 when the capability is absent — i.e. "everything goes to
/// the one port you were told about", which is what a daemon that predates
/// this does.
pub fn data_port_count(capabilities: u32) -> usize {
    if capabilities & CAP_PER_STREAM_PORTS == 0 {
        return 1;
    }
    (((capabilities & DATA_PORT_COUNT_MASK) >> DATA_PORT_COUNT_SHIFT) as usize).max(1)
}

/// Magic + bitfield.
const CAPABILITY_BLOCK_LEN: usize = 2 + 4;

/// DH material length for a `FullHandshake` ack: pubkey + nonce.
const DH_MATERIAL_LEN: usize = 32 + 16;
/// Server auth material length: Ed25519 identity pubkey + signature.
const AUTH_MATERIAL_LEN: usize = 32 + 64;

/// Encode a HELLO_ACK payload: `[mode] [dh material] [auth material]
/// [2-byte data port BE]`.
pub fn encode_hello_ack_payload(
    mode: HelloAckMode,
    data_port: Option<u16>,
    dh_material: Option<(&[u8; 32], &[u8; 16])>,
    auth_material: Option<(&[u8; 32], &[u8; 64])>,
    capabilities: u32,
) -> Vec<u8> {
    let mut buf =
        Vec::with_capacity(1 + DH_MATERIAL_LEN + AUTH_MATERIAL_LEN + 2 + CAPABILITY_BLOCK_LEN);
    buf.push(mode.to_byte());
    if let Some((public, nonce)) = dh_material {
        buf.extend_from_slice(public);
        buf.extend_from_slice(nonce);
    }
    if let Some((identity_pub, signature)) = auth_material {
        buf.extend_from_slice(identity_pub);
        buf.extend_from_slice(signature);
    }
    if let Some(port) = data_port {
        buf.extend_from_slice(&port.to_be_bytes());
    }
    append_capabilities(&mut buf, data_port.is_some(), capabilities);
    buf
}

/// Append the capability block, if there is anything to say.
///
/// Only ever appended *after* a data port. Without one the payload is a
/// bare "busy" ack whose length is what tells the peer it is bare, and the
/// short-payload fallback in the decoder reads the tail as a port — so a
/// block there would be read as a port number by an old peer. Refusing to
/// emit it in that case is the whole safety argument, not an optimisation.
fn append_capabilities(buf: &mut Vec<u8>, has_port: bool, capabilities: u32) {
    if capabilities == CAP_NONE || !has_port {
        return;
    }
    buf.extend_from_slice(&CAPABILITY_MAGIC);
    buf.extend_from_slice(&capabilities.to_be_bytes());
}

/// Encode a `Resumed` HELLO_ACK payload: `[mode] [16-byte server nonce]
/// [2-byte data port BE]`. The server nonce is mixed into the resumed key
/// derivation (S4 replay protection).
pub fn encode_hello_ack_resumed(
    data_port: Option<u16>,
    server_nonce: &[u8; 16],
    capabilities: u32,
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(1 + 16 + 2 + CAPABILITY_BLOCK_LEN);
    buf.push(HelloAckMode::Resumed.to_byte());
    buf.extend_from_slice(server_nonce);
    if let Some(port) = data_port {
        buf.extend_from_slice(&port.to_be_bytes());
    }
    append_capabilities(&mut buf, data_port.is_some(), capabilities);
    buf
}

/// Decode a HELLO_ACK payload. Returns `None` on an empty payload or an
/// unknown mode byte; truncated key material or port decode as absent.
/// Material parsing is mode-aware: `FullHandshake` expects 48 bytes of DH
/// material, optionally followed by 96 bytes of auth material (presence
/// inferred from payload length), `Resumed` a 16-byte server nonce,
/// `Plaintext` none.
pub fn decode_hello_ack_payload(buf: &[u8]) -> Option<HelloAckPayload> {
    let (&mode_byte, rest) = buf.split_first()?;
    let mode = HelloAckMode::from_byte(mode_byte)?;

    let mut dh_material = None;
    let mut auth_material = None;
    let mut resume_server_nonce = None;
    // Offset of the port within `rest`, when it is at a known fixed
    // position. `None` means the tail fallback was used, and nothing may be
    // appended after a payload parsed that way.
    let mut port_at: Option<usize> = None;
    // The data port, when present, always follows the mode material.
    let port_bytes = match mode {
        HelloAckMode::FullHandshake if rest.len() >= DH_MATERIAL_LEN => {
            let mut public = [0u8; 32];
            public.copy_from_slice(&rest[..32]);
            let mut nonce = [0u8; 16];
            nonce.copy_from_slice(&rest[32..DH_MATERIAL_LEN]);
            dh_material = Some((public, nonce));
            let auth_end = DH_MATERIAL_LEN + AUTH_MATERIAL_LEN;
            if rest.len() >= auth_end {
                let mut identity_pub = [0u8; 32];
                identity_pub.copy_from_slice(&rest[DH_MATERIAL_LEN..DH_MATERIAL_LEN + 32]);
                let mut signature = [0u8; 64];
                signature.copy_from_slice(&rest[DH_MATERIAL_LEN + 32..auth_end]);
                auth_material = Some((identity_pub, signature));
                port_at = Some(auth_end);
                rest.get(auth_end..auth_end + 2)
            } else {
                port_at = Some(DH_MATERIAL_LEN);
                rest.get(DH_MATERIAL_LEN..DH_MATERIAL_LEN + 2)
            }
        }
        HelloAckMode::Resumed if rest.len() >= 16 => {
            let mut nonce = [0u8; 16];
            nonce.copy_from_slice(&rest[..16]);
            resume_server_nonce = Some(nonce);
            port_at = Some(16);
            rest.get(16..18)
        }
        // Plaintext carries no material, so the port is the first two bytes.
        //
        // This used to fall through to the `rest.len() >= 2` arm below and
        // read the *last* two bytes, which is identical for every payload
        // any released version emits (plaintext payloads are exactly
        // `[mode][port]`) but makes appending anything impossible: a
        // capability block would be read as the port number. Reading the
        // fixed offset is the change that makes the format extensible.
        HelloAckMode::Plaintext if rest.len() >= 2 => {
            port_at = Some(0);
            rest.get(0..2)
        }
        // Truncated material: fall back to the tail, as before. No
        // capability block can be present on a payload this short, and
        // `port_at` stays `None` so none is looked for.
        _ if rest.len() >= 2 => Some(&rest[rest.len() - 2..]),
        _ => None,
    };
    let data_port = port_bytes.map(|b| u16::from_be_bytes([b[0], b[1]]));

    // Capabilities, if the peer appended a block after the port. A peer that
    // predates this sends nothing and reads as CAP_NONE.
    let mut capabilities = CAP_NONE;
    if let Some(off) = port_at {
        let cap_start = off + 2;
        if let Some(block) = rest.get(cap_start..cap_start + CAPABILITY_BLOCK_LEN) {
            if block[..2] == CAPABILITY_MAGIC {
                capabilities =
                    u32::from_be_bytes([block[2], block[3], block[4], block[5]]);
            }
        }
    }

    Some(HelloAckPayload {
        mode,
        data_port,
        dh_material,
        auth_material,
        resume_server_nonce,
        capabilities,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const PORT: u16 = 7801;
    const PUBLIC: [u8; 32] = [0xA5; 32];
    const NONCE: [u8; 16] = [0x5A; 16];
    const IDENTITY: [u8; 32] = [0x1D; 32];
    const SIGNATURE: [u8; 64] = [0x51; 64];

    fn roundtrip(mode: HelloAckMode, port: Option<u16>, dh: Option<(&[u8; 32], &[u8; 16])>) -> HelloAckPayload {
        let encoded = encode_hello_ack_payload(mode, port, dh, None, CAP_NONE);
        decode_hello_ack_payload(&encoded).expect("freshly encoded payload must decode")
    }

    // Each daemon HELLO_ACK path, encoded on the daemon side and decoded on
    // the client side, must preserve the negotiated mode.

    #[test]
    fn path_full_handshake_roundtrip() {
        let ack = roundtrip(HelloAckMode::FullHandshake, Some(PORT), Some((&PUBLIC, &NONCE)));
        assert_eq!(ack.mode, HelloAckMode::FullHandshake);
        assert_eq!(ack.data_port, Some(PORT));
        assert_eq!(ack.dh_material, Some((PUBLIC, NONCE)));
    }

    #[test]
    fn path_resume_success_roundtrip() {
        let encoded = encode_hello_ack_resumed(Some(PORT), &NONCE, CAP_NONE);
        let ack = decode_hello_ack_payload(&encoded).expect("freshly encoded payload must decode");
        assert_eq!(ack.mode, HelloAckMode::Resumed);
        assert_eq!(ack.data_port, Some(PORT));
        assert_eq!(ack.resume_server_nonce, Some(NONCE));
        assert_eq!(ack.dh_material, None);
    }

    #[test]
    fn path_full_handshake_with_auth_roundtrip() {
        // Daemon with an Ed25519 identity: DH material + auth material + port.
        let encoded = encode_hello_ack_payload(
            HelloAckMode::FullHandshake,
            Some(PORT),
            Some((&PUBLIC, &NONCE)),
            Some((&IDENTITY, &SIGNATURE)),
            CAP_NONE,
        );
        let ack = decode_hello_ack_payload(&encoded).expect("freshly encoded payload must decode");
        assert_eq!(ack.mode, HelloAckMode::FullHandshake);
        assert_eq!(ack.data_port, Some(PORT));
        assert_eq!(ack.dh_material, Some((PUBLIC, NONCE)));
        assert_eq!(ack.auth_material, Some((IDENTITY, SIGNATURE)));
    }

    #[test]
    fn path_full_handshake_without_auth_decodes_auth_none() {
        // Anonymous daemon: 48-byte DH material only — no auth material.
        let ack = roundtrip(HelloAckMode::FullHandshake, Some(PORT), Some((&PUBLIC, &NONCE)));
        assert_eq!(ack.auth_material, None);
    }

    #[test]
    fn path_resume_failure_fallback_roundtrip() {
        // Ticket rejected (e.g. daemon restarted): daemon falls back to
        // plaintext and must say so — this used to be byte-identical to the
        // resume-success ack.
        let fallback = encode_hello_ack_payload(HelloAckMode::Plaintext, Some(PORT), None, None, CAP_NONE);
        let success = encode_hello_ack_resumed(Some(PORT), &NONCE, CAP_NONE);
        assert_ne!(fallback, success);
        let ack = decode_hello_ack_payload(&fallback).unwrap();
        assert_eq!(ack.mode, HelloAckMode::Plaintext);
        assert_eq!(ack.data_port, Some(PORT));
    }

    #[test]
    fn path_plaintext_roundtrip() {
        let ack = roundtrip(HelloAckMode::Plaintext, Some(PORT), None);
        assert_eq!(ack.mode, HelloAckMode::Plaintext);
        assert_eq!(ack.data_port, Some(PORT));
    }

    #[test]
    fn busy_ack_without_port_roundtrip() {
        let ack = roundtrip(HelloAckMode::Plaintext, None, None);
        assert_eq!(ack.mode, HelloAckMode::Plaintext);
        assert_eq!(ack.data_port, None);
    }

    #[test]
    fn decode_rejects_malformed_payloads() {
        assert_eq!(decode_hello_ack_payload(&[]), None);
        assert_eq!(decode_hello_ack_payload(&[0x7F]), None);
        // Truncated DH material: parses, but without material or port.
        let ack = decode_hello_ack_payload(&[0x01, 0xAA]).unwrap();
        assert_eq!(ack.mode, HelloAckMode::FullHandshake);
        assert_eq!(ack.dh_material, None);
    }

    #[test]
    fn mode_byte_roundtrip() {
        for mode in [HelloAckMode::Plaintext, HelloAckMode::FullHandshake, HelloAckMode::Resumed] {
            assert_eq!(HelloAckMode::from_byte(mode.to_byte()), Some(mode));
        }
        assert_eq!(HelloAckMode::from_byte(0x03), None);
    }

    /// The compatibility claim this whole design rests on: a payload
    /// carrying capabilities must still decode correctly on a peer that has
    /// never heard of them. Simulated by decoding the port the old way (the
    /// tail) and asserting it now differs — i.e. that the *old* parse would
    /// have been wrong, which is exactly why the plaintext arm had to move
    /// to a fixed offset before anything could be appended.
    #[test]
    fn plaintext_capability_append_would_have_broken_the_old_tail_parse() {
        let buf = encode_hello_ack_payload(HelloAckMode::Plaintext, Some(PORT), None, None, 0x5);
        let decoded = decode_hello_ack_payload(&buf).unwrap();
        assert_eq!(decoded.data_port, Some(PORT));
        assert_eq!(decoded.capabilities, 0x5);

        // What the pre-fix decoder did: last two bytes are the port.
        let rest = &buf[1..];
        let old_parse = u16::from_be_bytes([rest[rest.len() - 2], rest[rest.len() - 1]]);
        assert_ne!(old_parse, PORT, "the fixed-offset parse is what makes this safe");
    }

    #[test]
    fn full_handshake_capabilities_round_trip_and_old_peers_ignore_them() {
        let with = encode_hello_ack_payload(
            HelloAckMode::FullHandshake,
            Some(PORT),
            Some((&PUBLIC, &NONCE)),
            None,
            0xDEAD_BEEF,
        );
        let d = decode_hello_ack_payload(&with).unwrap();
        assert_eq!(d.data_port, Some(PORT));
        assert_eq!(d.capabilities, 0xDEAD_BEEF);
        assert_eq!(d.dh_material, Some((PUBLIC, NONCE)));

        // An old peer reads the port at the same fixed offset and stops.
        let without =
            encode_hello_ack_payload(HelloAckMode::FullHandshake, Some(PORT), Some((&PUBLIC, &NONCE)), None, CAP_NONE);
        assert_eq!(&with[..without.len()], &without[..],
            "the capability block must be a pure append, changing no earlier byte");
    }

    #[test]
    fn authenticated_ack_capabilities_survive_the_signature_material() {
        let buf = encode_hello_ack_payload(
            HelloAckMode::FullHandshake,
            Some(PORT),
            Some((&PUBLIC, &NONCE)),
            Some((&IDENTITY, &SIGNATURE)),
            0x1,
        );
        let d = decode_hello_ack_payload(&buf).unwrap();
        assert_eq!(d.data_port, Some(PORT));
        assert_eq!(d.auth_material, Some((IDENTITY, SIGNATURE)));
        assert_eq!(d.capabilities, 0x1);
    }

    #[test]
    fn resumed_capabilities_round_trip() {
        let d = decode_hello_ack_payload(&encode_hello_ack_resumed(Some(PORT), &NONCE, 0x2)).unwrap();
        assert_eq!(d.data_port, Some(PORT));
        assert_eq!(d.resume_server_nonce, Some(NONCE));
        assert_eq!(d.capabilities, 0x2);
    }

    /// A peer that predates capabilities sends none, and must read as
    /// CAP_NONE rather than as garbage from whatever follows.
    #[test]
    fn absent_capability_block_reads_as_none() {
        for buf in [
            encode_hello_ack_payload(HelloAckMode::Plaintext, Some(PORT), None, None, CAP_NONE),
            encode_hello_ack_payload(HelloAckMode::FullHandshake, Some(PORT), Some((&PUBLIC, &NONCE)), None, CAP_NONE),
            encode_hello_ack_resumed(Some(PORT), &NONCE, CAP_NONE),
        ] {
            assert_eq!(decode_hello_ack_payload(&buf).unwrap().capabilities, CAP_NONE);
        }
    }

    /// Trailing bytes that are not a capability block must not be read as
    /// one — that is what the magic is for.
    #[test]
    fn trailing_garbage_is_not_mistaken_for_capabilities() {
        let mut buf = encode_hello_ack_payload(HelloAckMode::Plaintext, Some(PORT), None, None, CAP_NONE);
        buf.extend_from_slice(&[0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF]);
        let d = decode_hello_ack_payload(&buf).unwrap();
        assert_eq!(d.data_port, Some(PORT));
        assert_eq!(d.capabilities, CAP_NONE);
    }

    /// The per-stream port run round-trips through the bitfield, and the
    /// count field cannot collide with the support bit.
    #[test]
    fn per_stream_port_count_round_trips() {
        for n in 2..=255usize {
            let caps = per_stream_ports(n);
            assert_eq!(caps & CAP_PER_STREAM_PORTS, CAP_PER_STREAM_PORTS);
            assert_eq!(data_port_count(caps), n, "count {n} must survive the bitfield");
        }
        // A single port is not a run: advertising it would tell an old peer
        // nothing and a new peer something it already assumes.
        assert_eq!(per_stream_ports(1), CAP_NONE);
        assert_eq!(per_stream_ports(0), CAP_NONE);
    }

    /// A daemon that never heard of per-stream ports advertises nothing, and
    /// the sender must read that as "one port", not "zero ports" — the
    /// difference is a division by zero in the destination mapping.
    #[test]
    fn absent_per_stream_capability_means_one_port() {
        assert_eq!(data_port_count(CAP_NONE), 1);
        // Support bit set with a zero count is malformed (the daemon would
        // have had to hand-build it); clamp to 1 rather than trust it.
        assert_eq!(data_port_count(CAP_PER_STREAM_PORTS), 1);
        // Other capability bits must not be mistaken for a port count.
        assert_eq!(data_port_count(0xFF00_0000), 1);
    }

    /// A bare "busy" ack has no port, so the decoder falls back to the tail
    /// and nothing may be appended. The encoder must refuse to.
    #[test]
    fn busy_ack_never_carries_capabilities() {
        let buf = encode_hello_ack_payload(HelloAckMode::Plaintext, None, None, None, 0xFFFF);
        assert_eq!(buf.len(), 1, "no port means no capability block");
    }
}
