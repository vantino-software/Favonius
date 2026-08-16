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

/// Bit 1: the daemon understands the peer-authentication material a client
/// may append to its HELLO, and has checked it.
///
/// A client that requires authentication uses this to tell "the daemon
/// checked me and let me in" apart from "the daemon is older than this
/// feature and ignored the bytes entirely". Both look identical on the wire
/// otherwise — the append is designed to be ignorable — so without this bit
/// a client could believe it had authenticated to a daemon that has no idea
/// what peer authentication is.
pub const CAP_PEER_AUTH: u32 = 1 << 1;

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

// ── HELLO (client → daemon), full-handshake form ───────────────────────────

/// Flag byte for a full-DH HELLO.
pub const HELLO_FULL_DH: u8 = 0x01;

/// `[flag] [32-byte ephemeral public] [16-byte nonce]`.
pub const HELLO_FULL_DH_LEN: usize = 1 + 32 + 16;

/// Client auth material appended to a full-DH HELLO: Ed25519 identity
/// public key + offer signature.
const PEER_AUTH_LEN: usize = 32 + 64;

/// Encode a full-DH HELLO, optionally authenticating the client.
///
/// The auth material is **appended after** the fixed 49-byte prefix rather
/// than signalled by a new flag byte, and that choice is the whole
/// compatibility story. A daemon built before this feature dispatches on
/// `flag == 0x01 && len >= 49` and reads the key and nonce at fixed
/// offsets, so trailing bytes are invisible to it: it completes the
/// handshake exactly as it always did, simply without checking who is
/// calling.
///
/// A new flag value would have done the opposite. Unknown flags fall
/// through to the plaintext branch, so an authenticated client talking to
/// an older daemon would have silently downgraded to an unencrypted
/// transfer — worse than not authenticating at all.
///
/// Whether the daemon *understood* the appended bytes is answered by
/// [`CAP_PEER_AUTH`] in its HELLO_ACK, not by guessing from success.
pub fn encode_hello_full(
    ephemeral_pub: &[u8; 32],
    nonce: &[u8; 16],
    peer_auth: Option<(&[u8; 32], &[u8; 64])>,
    grant: Option<&[u8]>,
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(HELLO_FULL_DH_LEN + PEER_AUTH_LEN);
    buf.push(HELLO_FULL_DH);
    buf.extend_from_slice(ephemeral_pub);
    buf.extend_from_slice(nonce);
    if let Some((identity_pub, signature)) = peer_auth {
        buf.extend_from_slice(identity_pub);
        buf.extend_from_slice(signature);
        // Length-prefixed, and only ever after auth material: a grant names
        // the sender it is for, so one arriving without a proven identity
        // could not be checked against anything and has no meaning. The
        // encoder refuses to produce that shape rather than leaving the
        // decoder to decide what it would mean.
        if let Some(grant) = grant {
            buf.extend_from_slice(&(grant.len() as u16).to_be_bytes());
            buf.extend_from_slice(grant);
        }
    }
    buf
}

/// A parsed full-DH HELLO.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HelloFull {
    pub ephemeral_pub: [u8; 32],
    pub nonce: [u8; 16],
    /// Present when the client appended an identity and offer signature.
    /// Absent means the client did not authenticate — which is every client
    /// built before this existed, and is not by itself an error.
    pub peer_auth: Option<([u8; 32], [u8; 64])>,
    /// An opaque signed permission, when the client presented one. This
    /// crate does not interpret it: parsing and checking belong to whatever
    /// holds the trust anchors, and a wire format that understood the
    /// contents would have to be revised every time they changed.
    pub grant: Option<Vec<u8>>,
}

/// Decode a full-DH HELLO payload. `None` when it is not one, or is short.
///
/// Trailing bytes that are not exactly the auth material are ignored rather
/// than rejected: this format is explicitly extensible by appending, and a
/// decoder that refused unknown trailing bytes would make the next
/// extension a breaking change.
pub fn decode_hello_full(payload: &[u8]) -> Option<HelloFull> {
    if payload.first() != Some(&HELLO_FULL_DH) || payload.len() < HELLO_FULL_DH_LEN {
        return None;
    }
    let mut ephemeral_pub = [0u8; 32];
    ephemeral_pub.copy_from_slice(&payload[1..33]);
    let mut nonce = [0u8; 16];
    nonce.copy_from_slice(&payload[33..HELLO_FULL_DH_LEN]);

    let auth_end = HELLO_FULL_DH_LEN + PEER_AUTH_LEN;
    let mut peer_auth = None;
    let mut grant = None;
    if payload.len() >= auth_end {
        let mut identity_pub = [0u8; 32];
        identity_pub.copy_from_slice(&payload[HELLO_FULL_DH_LEN..HELLO_FULL_DH_LEN + 32]);
        let mut signature = [0u8; 64];
        signature.copy_from_slice(&payload[HELLO_FULL_DH_LEN + 32..auth_end]);
        peer_auth = Some((identity_pub, signature));

        // A grant, if one follows. A truncated or over-long length reads as
        // "no grant" rather than as an error: this is an append point, and a
        // decoder that rejected what it could not fully parse would make the
        // next extension a breaking change. A daemon that requires a grant
        // refuses the absence, which is where that decision belongs.
        if let Some(len_bytes) = payload.get(auth_end..auth_end + 2) {
            let len = u16::from_be_bytes([len_bytes[0], len_bytes[1]]) as usize;
            let start = auth_end + 2;
            if let Some(bytes) = payload.get(start..start + len) {
                if len > 0 {
                    grant = Some(bytes.to_vec());
                }
            }
        }
    }
    Some(HelloFull { ephemeral_pub, nonce, peer_auth, grant })
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

    // ── HELLO with client authentication ──────────────────────────────────

    const EPH: [u8; 32] = [7u8; 32];
    const HN: [u8; 16] = [9u8; 16];
    const CID: [u8; 32] = [1u8; 32];
    const CSIG: [u8; 64] = [2u8; 64];

    /// The compatibility property the whole design rests on: what an older
    /// daemon reads out of an authenticated HELLO is byte-for-byte what it
    /// reads out of an unauthenticated one.
    #[test]
    fn appending_client_auth_does_not_disturb_the_fixed_prefix() {
        let plain = encode_hello_full(&EPH, &HN, None, None);
        let authed = encode_hello_full(&EPH, &HN, Some((&CID, &CSIG)), None);

        assert_eq!(plain.len(), HELLO_FULL_DH_LEN);
        assert_eq!(
            &authed[..HELLO_FULL_DH_LEN],
            &plain[..],
            "the bytes an old daemon reads changed"
        );
        // Which is exactly how such a daemon parses it: fixed offsets.
        assert_eq!(authed[0], HELLO_FULL_DH);
        assert_eq!(&authed[1..33], &EPH);
        assert_eq!(&authed[33..49], &HN);
    }

    #[test]
    fn client_auth_round_trips() {
        let buf = encode_hello_full(&EPH, &HN, Some((&CID, &CSIG)), None);
        let got = decode_hello_full(&buf).expect("decodes");
        assert_eq!(got.ephemeral_pub, EPH);
        assert_eq!(got.nonce, HN);
        assert_eq!(got.peer_auth, Some((CID, CSIG)));
    }

    #[test]
    fn an_unauthenticated_hello_reports_no_peer_auth() {
        // The negative control: without it the test above passes for a
        // decoder that invents auth material.
        let buf = encode_hello_full(&EPH, &HN, None, None);
        assert_eq!(decode_hello_full(&buf).expect("decodes").peer_auth, None);
    }

    #[test]
    fn a_truncated_auth_append_is_read_as_absent_not_as_garbage() {
        // A half-written append must never decode into a partial identity
        // that then fails verification for the wrong reason — or worse,
        // matches something.
        let mut buf = encode_hello_full(&EPH, &HN, Some((&CID, &CSIG)), None);
        buf.truncate(HELLO_FULL_DH_LEN + 40);
        assert_eq!(decode_hello_full(&buf).expect("decodes").peer_auth, None);
    }

    #[test]
    fn a_short_or_wrong_flag_payload_is_not_a_full_hello() {
        assert!(decode_hello_full(&[]).is_none());
        assert!(decode_hello_full(&[0x00]).is_none());
        // Right flag, one byte short of the fixed prefix.
        let mut buf = encode_hello_full(&EPH, &HN, None, None);
        buf.truncate(HELLO_FULL_DH_LEN - 1);
        assert!(decode_hello_full(&buf).is_none());
    }

    #[test]
    fn the_peer_auth_capability_is_its_own_bit() {
        // Must not collide with the per-stream-port bit or the count field
        // packed into bits 8..16.
        assert_eq!(CAP_PEER_AUTH & CAP_PER_STREAM_PORTS, 0);
        assert_eq!(data_port_count(CAP_PEER_AUTH), 1, "read as a port count");
        let both = per_stream_ports(4) | CAP_PEER_AUTH;
        assert_eq!(data_port_count(both), 4, "the count survives the new bit");
        assert!(both & CAP_PEER_AUTH != 0);
    }

    // ── HELLO carrying a grant ────────────────────────────────────────────

    #[test]
    fn a_grant_round_trips_after_the_auth_material() {
        let grant = b"opaque signed permission".to_vec();
        let buf = encode_hello_full(&EPH, &HN, Some((&CID, &CSIG)), Some(&grant));
        let got = decode_hello_full(&buf).expect("decodes");
        assert_eq!(got.peer_auth, Some((CID, CSIG)));
        assert_eq!(got.grant.as_deref(), Some(&grant[..]));
    }

    #[test]
    fn a_grant_does_not_disturb_what_older_peers_read() {
        // The same compatibility property as the auth append, one layer out:
        // a daemon that predates grants reads the fixed prefix, then the
        // auth material it does understand, and ignores the rest.
        let grant = b"opaque".to_vec();
        let with = encode_hello_full(&EPH, &HN, Some((&CID, &CSIG)), Some(&grant));
        let without = encode_hello_full(&EPH, &HN, Some((&CID, &CSIG)), None);
        assert_eq!(&with[..without.len()], &without[..]);
        let older_view = decode_hello_full(&without).expect("decodes");
        assert_eq!(older_view.peer_auth, Some((CID, CSIG)));
        assert_eq!(older_view.grant, None);
    }

    #[test]
    fn a_grant_without_auth_material_is_never_encoded() {
        // A grant names the sender it is for. Without a proven identity
        // there is nothing to check it against, so the shape is refused at
        // the encoder rather than left for a decoder to interpret.
        let grant = b"opaque".to_vec();
        let buf = encode_hello_full(&EPH, &HN, None, Some(&grant));
        assert_eq!(buf.len(), HELLO_FULL_DH_LEN);
        assert_eq!(decode_hello_full(&buf).expect("decodes").grant, None);
    }

    #[test]
    fn a_truncated_grant_reads_as_absent_not_as_a_short_grant() {
        // A half-arrived grant must not verify against anything. Absent is
        // the safe reading: a daemon requiring one refuses.
        let grant = b"opaque signed permission".to_vec();
        let mut buf = encode_hello_full(&EPH, &HN, Some((&CID, &CSIG)), Some(&grant));
        buf.truncate(buf.len() - 4);
        let got = decode_hello_full(&buf).expect("decodes");
        assert_eq!(got.peer_auth, Some((CID, CSIG)), "auth survives");
        assert_eq!(got.grant, None, "a partial grant was surfaced");
    }

    #[test]
    fn a_zero_length_grant_is_absent() {
        let buf = encode_hello_full(&EPH, &HN, Some((&CID, &CSIG)), Some(&[]));
        assert_eq!(decode_hello_full(&buf).expect("decodes").grant, None);
    }
}
