// Favonius — high-performance file transfer over UDP
// Copyright (c) 2025-2026 Vantino SàRL
// SPDX-License-Identifier: Apache-2.0

//! The 42-byte fixed AHP common header.
//!
//! Every AHP packet begins with this header. Multi-byte integers are encoded in
//! network byte order (big endian). The last 4 bytes of the header are a CRC32C
//! computed over the preceding 38 bytes.
//!
//! ```text
//! +---------+-----------+-------+---------------+
//! | Version | PacketType| Flags | Header Length |
//! |  1 byte |   1 byte  |2 bytes|    2 bytes    |
//! +---------+-----------+-------+---------------+
//! |              Connection ID (8 bytes)        |
//! +---------------------------------------------+
//! |              Stream ID (4 bytes)            |
//! +---------------------------------------------+
//! |             Packet Number (8 bytes)         |
//! +---------------------------------------------+
//! |              Timestamp (8 bytes)            |
//! +---------------------------------------------+
//! |           Payload Length (4 bytes)          |
//! +---------------------------------------------+
//! |            Header CRC (4 bytes)            |
//! +---------------------------------------------+
//! ```

use bytes::{Buf, BufMut, BytesMut};

use crate::error::ProtoError;
use crate::flags::PacketFlags;
use crate::packet_type::PacketType;

/// Size of the fixed common header in bytes.
pub const HEADER_SIZE: usize = 42;

/// Current protocol version.
pub const PROTOCOL_VERSION: u8 = 1;

/// The fixed AHP common header present at the start of every packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PacketHeader {
    /// Protocol version (currently 1).
    pub version: u8,
    /// Packet type discriminator.
    pub packet_type: PacketType,
    /// Bit flags.
    pub flags: PacketFlags,
    /// Total header length including extensions (>= HEADER_SIZE).
    pub header_length: u16,
    /// Logical session identifier.
    pub connection_id: u64,
    /// Logical stream within the session.
    pub stream_id: u32,
    /// Monotonically increasing packet number.
    pub packet_number: u64,
    /// Sender timestamp in microseconds since an epoch.
    pub timestamp: u64,
    /// Length of the (potentially encrypted) payload that follows the header.
    pub payload_length: u32,
    /// CRC32C over the first 38 bytes of the header. Populated on encode,
    /// validated on decode.
    pub header_crc: u32,
}

/// Recomputes the CRC32C of an encoded header in place.
///
/// Call this after mutating any of the first [`HEADER_SIZE`] - 4 bytes of an
/// already-encoded header (e.g. OR-ing per-packet flags post-encode) so the
/// stored CRC keeps covering the exact header bytes the receiver validates —
/// after header-protection removal, if any: HP masks only the connection_id
/// and packet_number fields, never the flags or CRC bytes.
///
/// No-op if `header` is shorter than [`HEADER_SIZE`].
pub fn update_crc(header: &mut [u8]) {
    if header.len() < HEADER_SIZE {
        return;
    }
    let crc = crc32c::crc32c(&header[..HEADER_SIZE - 4]);
    header[HEADER_SIZE - 4..HEADER_SIZE].copy_from_slice(&crc.to_be_bytes());
}

impl PacketHeader {
    /// Encodes the header into `dst`, computing and appending the CRC32C.
    ///
    /// The caller must ensure `dst` has enough remaining capacity (at least
    /// [`HEADER_SIZE`] bytes).
    pub fn encode(&self, dst: &mut BytesMut) {
        let start = dst.len();

        dst.put_u8(self.version);
        dst.put_u8(self.packet_type as u8);
        dst.put_u16(self.flags.bits());
        dst.put_u16(self.header_length);
        dst.put_u64(self.connection_id);
        dst.put_u32(self.stream_id);
        dst.put_u64(self.packet_number);
        dst.put_u64(self.timestamp);
        dst.put_u32(self.payload_length);

        // CRC32C over the 38 bytes we just wrote.
        let crc = crc32c::crc32c(&dst[start..start + HEADER_SIZE - 4]);
        dst.put_u32(crc);
    }

    /// Encodes the header directly into a raw byte slice, returning the number
    /// of bytes written ([`HEADER_SIZE`]).
    ///
    /// This is the zero-allocation fast path used by [`BatchSender`] to encode
    /// packets directly into a pre-allocated send buffer.
    ///
    /// # Panics
    ///
    /// Panics if `dst.len() < HEADER_SIZE`.
    pub fn encode_into(&self, dst: &mut [u8]) -> usize {
        debug_assert!(dst.len() >= HEADER_SIZE);

        dst[0] = self.version;
        dst[1] = self.packet_type as u8;
        dst[2..4].copy_from_slice(&self.flags.bits().to_be_bytes());
        dst[4..6].copy_from_slice(&self.header_length.to_be_bytes());
        dst[6..14].copy_from_slice(&self.connection_id.to_be_bytes());
        dst[14..18].copy_from_slice(&self.stream_id.to_be_bytes());
        dst[18..26].copy_from_slice(&self.packet_number.to_be_bytes());
        dst[26..34].copy_from_slice(&self.timestamp.to_be_bytes());
        dst[34..38].copy_from_slice(&self.payload_length.to_be_bytes());

        let crc = crc32c::crc32c(&dst[..38]);
        dst[38..42].copy_from_slice(&crc.to_be_bytes());

        HEADER_SIZE
    }

    /// Decodes a header without CRC32C validation (fast path for DATA packets).
    ///
    /// UDP already provides checksum protection. Skipping CRC saves ~100ns per
    /// packet on the hot path.
    pub fn decode_unchecked(src: &mut &[u8]) -> Result<Self, ProtoError> {
        if src.len() < HEADER_SIZE {
            return Err(ProtoError::BufferTooShort {
                need: HEADER_SIZE,
                have: src.len(),
            });
        }

        let version = src.get_u8();
        let packet_type_raw = src.get_u8();
        let flags_raw = src.get_u16();
        let header_length = src.get_u16();
        let connection_id = src.get_u64();
        // The RFC specifies version negotiation and `ProtoError` has carried
        // an `UnsupportedVersion` variant since the beginning, but nothing
        // ever read this byte: a peer speaking any future version was
        // decoded as if it were version 1, and would fail later as a
        // corrupt-looking packet rather than as a version mismatch. Reject
        // it here, where the reason is still known.
        if version != PROTOCOL_VERSION {
            return Err(ProtoError::UnsupportedVersion(version));
        }

        let stream_id = src.get_u32();
        let packet_number = src.get_u64();
        let timestamp = src.get_u64();
        let payload_length = src.get_u32();
        let _stored_crc = src.get_u32();

        let packet_type = PacketType::try_from(packet_type_raw)?;
        let flags = PacketFlags::from_bits_truncate(flags_raw);

        if header_length < HEADER_SIZE as u16 {
            return Err(ProtoError::InvalidHeaderLength(
                header_length,
                HEADER_SIZE as u16,
            ));
        }

        Ok(Self {
            version,
            packet_type,
            flags,
            header_length,
            connection_id,
            stream_id,
            packet_number,
            timestamp,
            payload_length,
            header_crc: 0,
        })
    }

    /// Decodes a header from `src`, validating the CRC32C.
    ///
    /// On success the cursor in `src` is advanced past the header. The caller
    /// should not advance `src` beforehand.
    pub fn decode(src: &mut &[u8]) -> Result<Self, ProtoError> {
        if src.len() < HEADER_SIZE {
            return Err(ProtoError::BufferTooShort {
                need: HEADER_SIZE,
                have: src.len(),
            });
        }

        // Compute CRC over the first 38 bytes before consuming.
        let computed_crc = crc32c::crc32c(&src[..HEADER_SIZE - 4]);

        let version = src.get_u8();
        let packet_type_raw = src.get_u8();
        let flags_raw = src.get_u16();
        let header_length = src.get_u16();
        let connection_id = src.get_u64();
        let stream_id = src.get_u32();
        let packet_number = src.get_u64();
        let timestamp = src.get_u64();
        let payload_length = src.get_u32();
        let stored_crc = src.get_u32();

        if stored_crc != computed_crc {
            return Err(ProtoError::CrcMismatch {
                expected: stored_crc,
                computed: computed_crc,
            });
        }

        // The RFC specifies version negotiation and `ProtoError` has carried
        // an `UnsupportedVersion` variant since the beginning, but nothing
        // ever read this byte: a peer speaking any future version was
        // decoded as if it were version 1, and would fail later as a
        // corrupt-looking packet rather than as a version mismatch. Reject
        // it here, where the reason is still known.
        if version != PROTOCOL_VERSION {
            return Err(ProtoError::UnsupportedVersion(version));
        }


        let packet_type = PacketType::try_from(packet_type_raw)?;
        let flags = PacketFlags::from_bits_truncate(flags_raw);

        if header_length < HEADER_SIZE as u16 {
            return Err(ProtoError::InvalidHeaderLength(
                header_length,
                HEADER_SIZE as u16,
            ));
        }

        Ok(Self {
            version,
            packet_type,
            flags,
            header_length,
            connection_id,
            stream_id,
            packet_number,
            timestamp,
            payload_length,
            header_crc: stored_crc,
        })
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn a_future_protocol_version_is_rejected_not_silently_accepted() {
        // The RFC specifies version negotiation; nothing implemented it, so
        // a peer speaking version 2 was decoded as version 1 and failed
        // later looking like corruption.
        let mut h = sample_header();
        h.version = 9;
        let mut buf = BytesMut::with_capacity(HEADER_SIZE);
        h.encode(&mut buf);

        let mut slice = &buf[..];
        match PacketHeader::decode(&mut slice) {
            Err(ProtoError::UnsupportedVersion(v)) => assert_eq!(v, 9),
            other => panic!("expected UnsupportedVersion, got {other:?}"),
        }

        let mut slice = &buf[..];
        match PacketHeader::decode_unchecked(&mut slice) {
            Err(ProtoError::UnsupportedVersion(v)) => assert_eq!(v, 9),
            other => panic!("expected UnsupportedVersion, got {other:?}"),
        }
    }

    #[test]
    fn the_current_version_still_decodes() {
        // Positive control: the rejection above must not be rejecting
        // everything.
        let h = sample_header();
        let mut buf = BytesMut::with_capacity(HEADER_SIZE);
        h.encode(&mut buf);
        let mut slice = &buf[..];
        let got = PacketHeader::decode(&mut slice).expect("current version must decode");
        assert_eq!(got.version, PROTOCOL_VERSION);
    }

    use super::*;

    fn sample_header() -> PacketHeader {
        PacketHeader {
            version: PROTOCOL_VERSION,
            packet_type: PacketType::Data,
            flags: PacketFlags::ACK_ELICITING | PacketFlags::ENCRYPTED,
            header_length: HEADER_SIZE as u16,
            connection_id: 0xDEAD_BEEF_CAFE_BABE,
            stream_id: 42,
            packet_number: 1000,
            timestamp: 1_700_000_000_000_000,
            payload_length: 1200,
            header_crc: 0, // Will be computed during encode.
        }
    }

    #[test]
    fn encode_decode_round_trip() {
        let original = sample_header();
        let mut buf = BytesMut::with_capacity(HEADER_SIZE);
        original.encode(&mut buf);

        assert_eq!(buf.len(), HEADER_SIZE);

        let mut slice: &[u8] = &buf;
        let decoded = PacketHeader::decode(&mut slice).unwrap();

        assert_eq!(decoded.version, original.version);
        assert_eq!(decoded.packet_type, original.packet_type);
        assert_eq!(decoded.flags, original.flags);
        assert_eq!(decoded.header_length, original.header_length);
        assert_eq!(decoded.connection_id, original.connection_id);
        assert_eq!(decoded.stream_id, original.stream_id);
        assert_eq!(decoded.packet_number, original.packet_number);
        assert_eq!(decoded.timestamp, original.timestamp);
        assert_eq!(decoded.payload_length, original.payload_length);
        // CRC should be non-zero and match.
        assert_ne!(decoded.header_crc, 0);
    }

    #[test]
    fn crc_mismatch_detected() {
        let hdr = sample_header();
        let mut buf = BytesMut::with_capacity(HEADER_SIZE);
        hdr.encode(&mut buf);

        // Corrupt a byte in the middle of the header.
        buf[10] ^= 0xFF;

        let mut slice: &[u8] = &buf;
        let err = PacketHeader::decode(&mut slice).unwrap_err();
        assert!(matches!(err, ProtoError::CrcMismatch { .. }));
    }

    #[test]
    fn buffer_too_short() {
        let short = [0u8; 10];
        let mut slice: &[u8] = &short;
        let err = PacketHeader::decode(&mut slice).unwrap_err();
        assert!(matches!(
            err,
            ProtoError::BufferTooShort {
                need: HEADER_SIZE,
                have: 10,
            }
        ));
    }

    #[test]
    fn invalid_header_length_rejected() {
        let mut hdr = sample_header();
        hdr.header_length = 10; // Less than HEADER_SIZE.
        let mut buf = BytesMut::with_capacity(HEADER_SIZE);

        // Manually encode with the bad header_length so CRC covers it.
        buf.put_u8(hdr.version);
        buf.put_u8(hdr.packet_type as u8);
        buf.put_u16(hdr.flags.bits());
        buf.put_u16(hdr.header_length);
        buf.put_u64(hdr.connection_id);
        buf.put_u32(hdr.stream_id);
        buf.put_u64(hdr.packet_number);
        buf.put_u64(hdr.timestamp);
        buf.put_u32(hdr.payload_length);
        let crc = crc32c::crc32c(&buf[..HEADER_SIZE - 4]);
        buf.put_u32(crc);

        let mut slice: &[u8] = &buf;
        let err = PacketHeader::decode(&mut slice).unwrap_err();
        assert!(matches!(err, ProtoError::InvalidHeaderLength(10, _)));
    }

    #[test]
    fn encode_into_matches_encode() {
        let hdr = sample_header();

        // encode via BytesMut
        let mut buf1 = BytesMut::with_capacity(HEADER_SIZE);
        hdr.encode(&mut buf1);

        // encode via raw slice
        let mut buf2 = [0u8; HEADER_SIZE];
        let n = hdr.encode_into(&mut buf2);
        assert_eq!(n, HEADER_SIZE);

        assert_eq!(&buf1[..], &buf2[..]);

        // verify it decodes correctly
        let mut slice: &[u8] = &buf2;
        let decoded = PacketHeader::decode(&mut slice).unwrap();
        assert_eq!(decoded.version, hdr.version);
        assert_eq!(decoded.packet_type, hdr.packet_type);
        assert_eq!(decoded.connection_id, hdr.connection_id);
        assert_eq!(decoded.packet_number, hdr.packet_number);
    }

    #[test]
    fn update_crc_keeps_mutated_header_decodable() {
        // A post-encode flag mutation (e.g. COMPRESSED) invalidates the
        // stored CRC until update_crc refreshes it.
        let hdr = sample_header();
        let mut buf = [0u8; HEADER_SIZE];
        hdr.encode_into(&mut buf);

        let cur = u16::from_be_bytes([buf[2], buf[3]]);
        buf[2..4].copy_from_slice(&(cur | 0x0010).to_be_bytes());

        let mut slice: &[u8] = &buf;
        assert!(matches!(
            PacketHeader::decode(&mut slice),
            Err(ProtoError::CrcMismatch { .. })
        ));

        update_crc(&mut buf);
        let mut slice: &[u8] = &buf;
        let decoded = PacketHeader::decode(&mut slice).unwrap();
        assert_eq!(decoded.flags.bits(), hdr.flags.bits() | 0x0010);
    }

    #[test]
    fn header_size_is_42() {
        assert_eq!(HEADER_SIZE, 42);

        // Also verify by encoding.
        let hdr = sample_header();
        let mut buf = BytesMut::new();
        hdr.encode(&mut buf);
        assert_eq!(buf.len(), 42);
    }
}
