// Favonius — high-performance file transfer over UDP
// Copyright (c) 2025-2026 Vantino SàRL
// SPDX-License-Identifier: Apache-2.0

//! Full-packet encode/decode codec for AHP.
//!
//! Assembles a complete [`Packet`] from its constituent header, extensions, and
//! payload. Handles header CRC validation and extension parsing based on the
//! `header_length` field.

use bytes::{Bytes, BytesMut};

use crate::error::ProtoError;
use crate::extensions::{decode_extensions, Extension};
use crate::header::{PacketHeader, HEADER_SIZE};

/// A fully decoded AHP packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Packet {
    /// The fixed 42-byte common header.
    pub header: PacketHeader,
    /// Zero or more header extensions (present when `header_length > HEADER_SIZE`).
    pub extensions: Vec<Extension>,
    /// The (potentially encrypted) payload following the header + extensions.
    pub payload: Bytes,
}

/// Encodes a [`Packet`] into a fresh `BytesMut` ready for transmission.
///
/// The caller should populate `header.header_length` and `header.payload_length`
/// consistently with the extensions and payload provided. This function trusts
/// those values and writes them verbatim so that the receiver can reconstruct
/// the packet.
///
/// If you want the function to compute `header_length` and `payload_length` for
/// you, use [`encode_packet_auto`] instead.
pub fn encode_packet(packet: &Packet) -> BytesMut {
    let ext_size: usize = packet.extensions.iter().map(|e| e.wire_size()).sum();
    let total = HEADER_SIZE + ext_size + packet.payload.len();
    let mut buf = BytesMut::with_capacity(total);

    packet.header.encode(&mut buf);

    for ext in &packet.extensions {
        ext.encode(&mut buf);
    }

    if !packet.payload.is_empty() {
        buf.extend_from_slice(&packet.payload);
    }

    buf
}

/// Like [`encode_packet`], but automatically sets `header.header_length` and
/// `header.payload_length` from the provided extensions and payload.
pub fn encode_packet_auto(packet: &mut Packet) -> BytesMut {
    let ext_size: usize = packet.extensions.iter().map(|e| e.wire_size()).sum();
    packet.header.header_length = (HEADER_SIZE + ext_size) as u16;
    packet.header.payload_length = packet.payload.len() as u32;
    encode_packet(packet)
}

/// Encodes a DATA packet directly into a pre-allocated byte slice.
///
/// Writes the 42-byte header followed by the 22-byte DataPayload header and
/// then copies `data` (the chunk payload) in place.  Returns the total number
/// of bytes written.
///
/// This is the zero-allocation hot-path encoder used by [`BatchSender`].
///
/// # Panics
///
/// Panics if `dst` is too small to hold the full packet.
pub fn encode_data_packet_into(
    dst: &mut [u8],
    conn_id: u64,
    packet_number: u64,
    timestamp: u64,
    stream_id: u32,
    file_id: u64,
    chunk_index: u64,
    chunk_offset: u32,
    data: &[u8],
) -> usize {
    use crate::data::DATA_PAYLOAD_HEADER_SIZE;
    use crate::flags::PacketFlags;
    use crate::header::PROTOCOL_VERSION;
    use crate::packet_type::PacketType;

    let payload_len = DATA_PAYLOAD_HEADER_SIZE + data.len();
    let total = HEADER_SIZE + payload_len;
    debug_assert!(dst.len() >= total);

    // -- Header (42 bytes) --
    let hdr = PacketHeader {
        version: PROTOCOL_VERSION,
        packet_type: PacketType::Data,
        flags: PacketFlags::ACK_ELICITING,
        header_length: HEADER_SIZE as u16,
        connection_id: conn_id,
        stream_id,
        packet_number,
        timestamp,
        payload_length: payload_len as u32,
        header_crc: 0,
    };
    hdr.encode_into(&mut dst[..HEADER_SIZE]);

    // -- DataPayload header (22 bytes) --
    let dp = &mut dst[HEADER_SIZE..];
    dp[0..8].copy_from_slice(&file_id.to_be_bytes());
    dp[8..16].copy_from_slice(&chunk_index.to_be_bytes());
    dp[16..20].copy_from_slice(&chunk_offset.to_be_bytes());
    dp[20..22].copy_from_slice(&(data.len() as u16).to_be_bytes());

    // -- Data bytes --
    dp[22..22 + data.len()].copy_from_slice(data);

    total
}

/// Fast-path decode without CRC validation (for DATA packets on the hot path).
///
/// UDP already checksums the payload, so CRC is redundant for data integrity.
/// Saves ~100ns per packet at 50k+ pps.
pub fn decode_packet_unchecked(data: &[u8]) -> Result<Packet, ProtoError> {
    let mut cursor: &[u8] = data;
    let header = PacketHeader::decode_unchecked(&mut cursor)?;

    let header_len = header.header_length as usize;
    let ext_region_size = header_len.saturating_sub(HEADER_SIZE);

    if cursor.len() < ext_region_size {
        return Err(ProtoError::BufferTooShort {
            need: header_len,
            have: HEADER_SIZE + cursor.len(),
        });
    }

    // Skip extensions for DATA packets (they never have extensions).
    cursor = &cursor[ext_region_size..];

    let payload_len = header.payload_length as usize;
    if cursor.len() < payload_len {
        return Err(ProtoError::PayloadOverflow {
            declared: header.payload_length,
            available: cursor.len(),
        });
    }

    let payload = Bytes::copy_from_slice(&cursor[..payload_len]);

    Ok(Packet {
        header,
        extensions: vec![],
        payload,
    })
}

/// Zero-copy inline decode of a DATA packet directly from a receive buffer.
///
/// Returns borrowed header fields and a `&[u8]` slice into the original buffer
/// for the chunk data — no heap allocations. This is the hot-path decoder for
/// the receiver, replacing `decode_packet_unchecked` + `DataPayload::decode`
/// (which does 2 allocations per packet).
///
/// Returns `None` if the packet is not a DATA packet or is malformed.
pub fn decode_data_inline(buf: &[u8]) -> Option<DataPayloadRef<'_>> {
    use crate::data::DATA_PAYLOAD_HEADER_SIZE;

    if buf.len() < HEADER_SIZE + DATA_PAYLOAD_HEADER_SIZE {
        return None;
    }

    // Byte 1 = packet type. DATA = 0x20.
    if buf[1] != 0x20 {
        return None;
    }

    // Header fields we need (big-endian).
    let stream_id = u32::from_be_bytes([buf[14], buf[15], buf[16], buf[17]]);

    // DataPayload starts at HEADER_SIZE (42).
    let dp = &buf[HEADER_SIZE..];
    // file_id: dp[0..8], chunk_index: dp[8..16], chunk_offset: dp[16..20], data_len: dp[20..22]
    let chunk_index = u64::from_be_bytes([dp[8], dp[9], dp[10], dp[11], dp[12], dp[13], dp[14], dp[15]]);
    let data_len = u16::from_be_bytes([dp[20], dp[21]]) as usize;

    let data_start = HEADER_SIZE + DATA_PAYLOAD_HEADER_SIZE;
    let data_end = data_start + data_len;
    if buf.len() < data_end {
        return None;
    }

    Some(DataPayloadRef {
        stream_id,
        chunk_index,
        data: &buf[data_start..data_end],
    })
}

/// Borrowed DATA packet fields — zero-copy reference into the receive buffer.
pub struct DataPayloadRef<'a> {
    pub stream_id: u32,
    pub chunk_index: u64,
    pub data: &'a [u8],
}

/// Encodes an ACK bitmap packet directly into a pre-allocated byte slice.
///
/// Zero-allocation hot-path encoder for the threaded receiver. Returns the
/// total number of bytes written.
pub fn encode_ack_bitmap_into(
    dst: &mut [u8],
    conn_id: u64,
    seq: u64,
    stream_id: u32,
    base: u64,
    highest_contiguous: u64,
    bitmap: &[u8],
) -> usize {
    use crate::data::ACK_BITMAP_HEADER_SIZE;
    use crate::flags::PacketFlags;
    use crate::header::PROTOCOL_VERSION;
    use crate::packet_type::PacketType;

    let payload_len = ACK_BITMAP_HEADER_SIZE + bitmap.len();
    let total = HEADER_SIZE + payload_len;
    debug_assert!(dst.len() >= total);

    // Header (42 bytes)
    let hdr = PacketHeader {
        version: PROTOCOL_VERSION,
        packet_type: PacketType::AckBitmap,
        flags: PacketFlags::empty(),
        header_length: HEADER_SIZE as u16,
        connection_id: conn_id,
        stream_id: 0,
        packet_number: seq,
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_micros() as u64,
        payload_length: payload_len as u32,
        header_crc: 0,
    };
    hdr.encode_into(&mut dst[..HEADER_SIZE]);

    // AckBitmap payload (26 + bitmap bytes)
    let p = &mut dst[HEADER_SIZE..];
    p[0..4].copy_from_slice(&stream_id.to_be_bytes());
    p[4..12].copy_from_slice(&base.to_be_bytes());
    p[12..20].copy_from_slice(&highest_contiguous.to_be_bytes());
    p[20..24].copy_from_slice(&0u32.to_be_bytes()); // ack_delay_micros
    p[24..26].copy_from_slice(&(bitmap.len() as u16).to_be_bytes());
    p[26..26 + bitmap.len()].copy_from_slice(bitmap);

    total
}

/// Encodes a minimal control packet (no payload) into a pre-allocated slice.
///
/// Used for Finish replies in the threaded receiver. Returns bytes written.
pub fn encode_ctrl_packet_into(
    dst: &mut [u8],
    ptype: crate::packet_type::PacketType,
    conn_id: u64,
    seq: u64,
) -> usize {
    encode_ctrl_packet_with_payload_into(dst, ptype, conn_id, seq, 0)
}

/// Encodes the header of a control packet that carries a payload into a
/// pre-allocated slice.
///
/// Only the header is written; the caller appends the payload itself (e.g. as
/// a second iovec in a scatter-gather send, which places it immediately after
/// the header in the datagram). The header declares
/// `payload_length = payload_len` so the receiver can decode the payload with
/// [`decode_packet`]. Returns bytes written (header only).
pub fn encode_ctrl_packet_with_payload_into(
    dst: &mut [u8],
    ptype: crate::packet_type::PacketType,
    conn_id: u64,
    seq: u64,
    payload_len: u32,
) -> usize {
    use crate::flags::PacketFlags;
    use crate::header::PROTOCOL_VERSION;

    let hdr = PacketHeader {
        version: PROTOCOL_VERSION,
        packet_type: ptype,
        flags: PacketFlags::empty(),
        header_length: HEADER_SIZE as u16,
        connection_id: conn_id,
        stream_id: 0,
        packet_number: seq,
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_micros() as u64,
        payload_length: payload_len,
        header_crc: 0,
    };
    hdr.encode_into(&mut dst[..HEADER_SIZE]);
    HEADER_SIZE
}

/// Decodes a [`Packet`] from `data`.
///
/// Steps:
/// 1. Decode and CRC-validate the fixed header.
/// 2. Parse header extensions (bytes between `HEADER_SIZE` and `header_length`).
/// 3. Extract the payload (next `payload_length` bytes after header+extensions).
pub fn decode_packet(data: &[u8]) -> Result<Packet, ProtoError> {
    let mut cursor: &[u8] = data;

    // 1. Decode the fixed header.
    let header = PacketHeader::decode(&mut cursor)?;

    let header_len = header.header_length as usize;
    let ext_region_size = header_len.saturating_sub(HEADER_SIZE);

    // cursor now points past the fixed header. Verify that enough bytes remain
    // for the extensions region.
    if cursor.len() < ext_region_size {
        return Err(ProtoError::BufferTooShort {
            need: header_len,
            have: HEADER_SIZE + cursor.len(),
        });
    }

    // 2. Parse extensions from the extension region.
    let ext_slice = &cursor[..ext_region_size];
    let extensions = decode_extensions(ext_slice)?;

    // Advance past the extension region.
    cursor = &cursor[ext_region_size..];

    // 3. Extract the payload.
    let payload_len = header.payload_length as usize;
    if cursor.len() < payload_len {
        return Err(ProtoError::PayloadOverflow {
            declared: header.payload_length,
            available: cursor.len(),
        });
    }

    let payload = Bytes::copy_from_slice(&cursor[..payload_len]);

    Ok(Packet {
        header,
        extensions,
        payload,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::extensions::ExtensionType;
    use crate::flags::PacketFlags;
    use crate::header::PROTOCOL_VERSION;
    use crate::packet_type::PacketType;

    fn make_packet(
        extensions: Vec<Extension>,
        payload: &[u8],
    ) -> Packet {
        let ext_size: usize = extensions.iter().map(|e| e.wire_size()).sum();
        Packet {
            header: PacketHeader {
                version: PROTOCOL_VERSION,
                packet_type: PacketType::Data,
                flags: PacketFlags::ACK_ELICITING | PacketFlags::ENCRYPTED,
                header_length: (HEADER_SIZE + ext_size) as u16,
                connection_id: 0x0102030405060708,
                stream_id: 7,
                packet_number: 42,
                timestamp: 1_000_000,
                payload_length: payload.len() as u32,
                header_crc: 0,
            },
            extensions,
            payload: Bytes::copy_from_slice(payload),
        }
    }

    #[test]
    fn round_trip_no_extensions_no_payload() {
        let original = make_packet(vec![], b"");
        let buf = encode_packet(&original);
        let decoded = decode_packet(&buf).unwrap();

        assert_eq!(decoded.header.version, original.header.version);
        assert_eq!(decoded.header.packet_type, original.header.packet_type);
        assert_eq!(decoded.header.connection_id, original.header.connection_id);
        assert_eq!(decoded.extensions.len(), 0);
        assert!(decoded.payload.is_empty());
    }

    #[test]
    fn round_trip_with_payload() {
        let payload = b"the quick brown fox jumps over the lazy dog";
        let original = make_packet(vec![], payload);
        let buf = encode_packet(&original);
        let decoded = decode_packet(&buf).unwrap();

        assert_eq!(decoded.payload.as_ref(), payload);
    }

    #[test]
    fn round_trip_with_extensions_and_payload() {
        let exts = vec![
            Extension {
                ext_type: ExtensionType::KeyPhase as u16,
                value: Bytes::from_static(&[0x01]),
            },
            Extension {
                ext_type: ExtensionType::ChunkId as u16,
                value: Bytes::from_static(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0A]),
            },
        ];
        let payload = b"encrypted chunk data here";
        let original = make_packet(exts, payload);

        let buf = encode_packet(&original);
        let decoded = decode_packet(&buf).unwrap();

        assert_eq!(decoded.extensions.len(), 2);
        assert_eq!(decoded.extensions[0].ext_type, ExtensionType::KeyPhase as u16);
        assert_eq!(decoded.extensions[1].ext_type, ExtensionType::ChunkId as u16);
        assert_eq!(decoded.payload.as_ref(), payload);
    }

    #[test]
    fn encode_packet_auto_sets_lengths() {
        let exts = vec![Extension {
            ext_type: ExtensionType::PathId as u16,
            value: Bytes::from_static(&[0x00, 0x01]),
        }];
        let mut packet = Packet {
            header: PacketHeader {
                version: PROTOCOL_VERSION,
                packet_type: PacketType::Hello,
                flags: PacketFlags::empty(),
                header_length: 0,   // will be auto-set
                connection_id: 1,
                stream_id: 0,
                packet_number: 0,
                timestamp: 0,
                payload_length: 0,  // will be auto-set
                header_crc: 0,
            },
            extensions: exts,
            payload: Bytes::from_static(b"caps-data"),
        };

        let buf = encode_packet_auto(&mut packet);
        assert_eq!(
            packet.header.header_length as usize,
            HEADER_SIZE + 4 + 2 // ext header(4) + value(2)
        );
        assert_eq!(packet.header.payload_length, 9);

        let decoded = decode_packet(&buf).unwrap();
        assert_eq!(decoded.extensions.len(), 1);
        assert_eq!(decoded.payload.as_ref(), b"caps-data");
    }

    #[test]
    fn encode_data_packet_into_round_trip() {
        let data = b"chunk payload data here!";
        let mut buf = [0u8; 1500];
        let n = super::encode_data_packet_into(
            &mut buf, 0xDEAD, 42, 1_000_000, 0, 7, 99, 0, data,
        );
        assert_eq!(n, HEADER_SIZE + 22 + data.len());

        // Decode as a full packet
        let pkt = decode_packet(&buf[..n]).unwrap();
        assert_eq!(pkt.header.packet_type, PacketType::Data);
        assert_eq!(pkt.header.connection_id, 0xDEAD);
        assert_eq!(pkt.header.packet_number, 42);

        // Decode the DataPayload from the packet payload
        let dp = crate::data::DataPayload::decode(&mut &pkt.payload[..]).unwrap();
        assert_eq!(dp.file_id, 7);
        assert_eq!(dp.chunk_index, 99);
        assert_eq!(dp.chunk_offset, 0);
        assert_eq!(dp.data.as_ref(), data);
    }

    #[test]
    fn nack_range_ctrl_packet_wire_round_trip() {
        // Mirror the daemon's NACK send path: the header is written by
        // encode_ctrl_packet_with_payload_into and the NackRange payload is
        // appended (the daemon sends the two as a scatter-gather pair, which
        // produces exactly this contiguous datagram on the wire).
        let nack = crate::data::NackRange {
            stream_id: 3,
            ranges: vec![(10, 12), (40, 40), (100, 250)],
        };
        let mut payload_buf = BytesMut::new();
        nack.encode(&mut payload_buf);

        let mut datagram = vec![0u8; HEADER_SIZE + payload_buf.len()];
        let n = super::encode_ctrl_packet_with_payload_into(
            &mut datagram,
            PacketType::NackRange,
            0x1122_3344_5566_7788,
            7,
            payload_buf.len() as u32,
        );
        assert_eq!(n, HEADER_SIZE);
        datagram[n..].copy_from_slice(&payload_buf);

        // Decode the way the sender does (decode_packet + NackRange::decode).
        let pkt = decode_packet(&datagram).unwrap();
        assert_eq!(pkt.header.packet_type, PacketType::NackRange);
        assert_eq!(pkt.header.connection_id, 0x1122_3344_5566_7788);
        assert_eq!(pkt.header.payload_length as usize, payload_buf.len());
        let decoded = crate::data::NackRange::decode(&mut &pkt.payload[..]).unwrap();
        assert_eq!(decoded, nack);
    }

    #[test]
    fn decode_truncated_buffer() {
        let err = decode_packet(&[0u8; 20]).unwrap_err();
        assert!(matches!(err, ProtoError::BufferTooShort { .. }));
    }

    #[test]
    fn decode_payload_overflow() {
        // Build a packet that claims a larger payload than the buffer contains.
        let mut packet = make_packet(vec![], b"short");
        packet.header.payload_length = 9999;
        let buf = encode_packet(&packet);
        let err = decode_packet(&buf).unwrap_err();
        assert!(matches!(err, ProtoError::PayloadOverflow { .. }));
    }

    #[test]
    fn crc_validated_on_decode() {
        let original = make_packet(vec![], b"payload");
        let mut buf = encode_packet(&original);

        // Corrupt a byte inside the header region.
        buf[5] ^= 0xFF;

        let err = decode_packet(&buf).unwrap_err();
        assert!(matches!(err, ProtoError::CrcMismatch { .. }));
    }

    #[test]
    fn extension_region_overflow() {
        // Manually build a header that claims a header_length beyond the buffer.
        let mut packet = make_packet(vec![], b"");
        packet.header.header_length = 200; // Way more than HEADER_SIZE + 0 extensions.
        let buf = encode_packet(&packet);
        let err = decode_packet(&buf).unwrap_err();
        assert!(matches!(err, ProtoError::BufferTooShort { .. }));
    }
}
