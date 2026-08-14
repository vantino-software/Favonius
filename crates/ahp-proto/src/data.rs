// Favonius — high-performance file transfer over UDP
// Copyright (c) 2025-2026 Vantino SàRL
// SPDX-License-Identifier: Apache-2.0

//! Data-plane payload structures for AHP-D.
//!
//! This module defines the binary layout for the most frequently used data-plane
//! payloads: [`DataPayload`], [`AckBitmap`], and [`NackRange`].

use bytes::{Buf, BufMut, Bytes, BytesMut};

use crate::error::ProtoError;

// ---------------------------------------------------------------------------
// AckMode
// ---------------------------------------------------------------------------

/// Acknowledgement mode negotiated in the file manifest.
///
/// Determines how the receiver reports delivery status to the sender.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AckMode {
    /// Traditional bitmap ACK every N packets.
    Bitmap,
    /// NACK-based: receiver sends NACKs on gap detection + sparse progress ACKs.
    Nack,
}

// ---------------------------------------------------------------------------
// DataPayload
// ---------------------------------------------------------------------------

/// Payload structure for a `DATA` packet (packet type 0x20).
///
/// Wire layout (RFC section 44.2):
///
/// | Field          | Size     |
/// |----------------|----------|
/// | File ID        | 8 bytes  |
/// | Chunk Index    | 8 bytes  |
/// | Chunk Offset   | 4 bytes  |
/// | Data Length     | 2 bytes  |
/// | Payload Bytes  | variable |
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataPayload {
    /// Logical file identifier.
    pub file_id: u64,
    /// Chunk index within the file.
    pub chunk_index: u64,
    /// Byte offset within the chunk.
    pub chunk_offset: u32,
    /// The actual data bytes.
    pub data: Bytes,
}

/// Fixed overhead of a `DataPayload` before the variable-length data.
pub const DATA_PAYLOAD_HEADER_SIZE: usize = 8 + 8 + 4 + 2; // 22 bytes

impl DataPayload {
    /// Encodes the data payload into `dst`.
    pub fn encode(&self, dst: &mut BytesMut) {
        dst.put_u64(self.file_id);
        dst.put_u64(self.chunk_index);
        dst.put_u32(self.chunk_offset);
        dst.put_u16(self.data.len() as u16);
        dst.put_slice(&self.data);
    }

    /// Decodes a data payload from `src`, advancing the cursor.
    pub fn decode(src: &mut &[u8]) -> Result<Self, ProtoError> {
        if src.len() < DATA_PAYLOAD_HEADER_SIZE {
            return Err(ProtoError::BufferTooShort {
                need: DATA_PAYLOAD_HEADER_SIZE,
                have: src.len(),
            });
        }

        let file_id = src.get_u64();
        let chunk_index = src.get_u64();
        let chunk_offset = src.get_u32();
        let data_len = src.get_u16() as usize;

        if src.len() < data_len {
            return Err(ProtoError::InvalidDataPayload(format!(
                "DATA declares {data_len} bytes but only {} remain",
                src.len()
            )));
        }

        let data = Bytes::copy_from_slice(&src[..data_len]);
        src.advance(data_len);

        Ok(Self {
            file_id,
            chunk_index,
            chunk_offset,
            data,
        })
    }

    /// Total wire size of this payload.
    pub fn wire_size(&self) -> usize {
        DATA_PAYLOAD_HEADER_SIZE + self.data.len()
    }
}

// ---------------------------------------------------------------------------
// AckBitmap
// ---------------------------------------------------------------------------

/// Payload structure for an `ACK_BITMAP` packet (packet type 0x21).
///
/// Wire layout (RFC section 44.1):
///
/// | Field               | Size     |
/// |---------------------|----------|
/// | Stream ID           | 4 bytes  |
/// | Base Packet Number  | 8 bytes  |
/// | Highest Contiguous  | 8 bytes  |
/// | Ack Delay Micros    | 4 bytes  |
/// | Bitmap Length Bytes  | 2 bytes  |
/// | Bitmap              | variable |
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AckBitmap {
    /// Stream this ACK applies to.
    pub stream_id: u32,
    /// Base packet number; bitmap bits are relative offsets from this.
    pub base_packet_number: u64,
    /// Highest packet number received contiguously.
    pub highest_contiguous: u64,
    /// Receiver-side ACK processing delay in microseconds.
    pub ack_delay_micros: u32,
    /// Bitmap of received packets after `base_packet_number`.
    pub bitmap: Bytes,
}

/// Fixed overhead of an `AckBitmap` before the variable-length bitmap.
pub const ACK_BITMAP_HEADER_SIZE: usize = 4 + 8 + 8 + 4 + 2; // 26 bytes

impl AckBitmap {
    /// Encodes the ACK bitmap payload into `dst`.
    pub fn encode(&self, dst: &mut BytesMut) {
        dst.put_u32(self.stream_id);
        dst.put_u64(self.base_packet_number);
        dst.put_u64(self.highest_contiguous);
        dst.put_u32(self.ack_delay_micros);
        dst.put_u16(self.bitmap.len() as u16);
        dst.put_slice(&self.bitmap);
    }

    /// Decodes an ACK bitmap payload from `src`, advancing the cursor.
    pub fn decode(src: &mut &[u8]) -> Result<Self, ProtoError> {
        if src.len() < ACK_BITMAP_HEADER_SIZE {
            return Err(ProtoError::BufferTooShort {
                need: ACK_BITMAP_HEADER_SIZE,
                have: src.len(),
            });
        }

        let stream_id = src.get_u32();
        let base_packet_number = src.get_u64();
        let highest_contiguous = src.get_u64();
        let ack_delay_micros = src.get_u32();
        let bitmap_len = src.get_u16() as usize;

        if src.len() < bitmap_len {
            return Err(ProtoError::InvalidDataPayload(format!(
                "ACK_BITMAP declares {bitmap_len} bitmap bytes but only {} remain",
                src.len()
            )));
        }

        let bitmap = Bytes::copy_from_slice(&src[..bitmap_len]);
        src.advance(bitmap_len);

        Ok(Self {
            stream_id,
            base_packet_number,
            highest_contiguous,
            ack_delay_micros,
            bitmap,
        })
    }

    /// Total wire size of this payload.
    pub fn wire_size(&self) -> usize {
        ACK_BITMAP_HEADER_SIZE + self.bitmap.len()
    }
}

// ---------------------------------------------------------------------------
// NackRange
// ---------------------------------------------------------------------------

/// Payload structure for a `NACK_RANGE` packet (packet type 0x22).
///
/// Wire layout:
///
/// | Field       | Size                |
/// |-------------|---------------------|
/// | Stream ID   | 4 bytes             |
/// | Range Count | 2 bytes             |
/// | Ranges      | 16 bytes each       |
///
/// Each range is a `(start: u64, end: u64)` pair representing a contiguous
/// span of missing packet numbers (inclusive on both ends).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NackRange {
    /// Stream this NACK applies to.
    pub stream_id: u32,
    /// Missing packet number ranges (start, end) inclusive.
    pub ranges: Vec<(u64, u64)>,
}

/// Fixed overhead of a `NackRange` before the variable-length ranges.
pub const NACK_RANGE_HEADER_SIZE: usize = 4 + 2; // 6 bytes

/// Wire size of a single (start, end) range pair.
pub const NACK_RANGE_ENTRY_SIZE: usize = 16;

impl NackRange {
    /// Encodes the NACK range payload into `dst`.
    pub fn encode(&self, dst: &mut BytesMut) {
        dst.put_u32(self.stream_id);
        dst.put_u16(self.ranges.len() as u16);
        for &(start, end) in &self.ranges {
            dst.put_u64(start);
            dst.put_u64(end);
        }
    }

    /// Decodes a NACK range payload from `src`, advancing the cursor.
    pub fn decode(src: &mut &[u8]) -> Result<Self, ProtoError> {
        if src.len() < NACK_RANGE_HEADER_SIZE {
            return Err(ProtoError::BufferTooShort {
                need: NACK_RANGE_HEADER_SIZE,
                have: src.len(),
            });
        }

        let stream_id = src.get_u32();
        let range_count = src.get_u16() as usize;

        let needed = range_count * NACK_RANGE_ENTRY_SIZE;
        if src.len() < needed {
            return Err(ProtoError::InvalidDataPayload(format!(
                "NACK_RANGE declares {range_count} ranges ({needed} bytes) but only {} remain",
                src.len()
            )));
        }

        let mut ranges = Vec::with_capacity(range_count);
        for _ in 0..range_count {
            let start = src.get_u64();
            let end = src.get_u64();
            ranges.push((start, end));
        }

        Ok(Self { stream_id, ranges })
    }

    /// Total wire size of this payload.
    pub fn wire_size(&self) -> usize {
        NACK_RANGE_HEADER_SIZE + self.ranges.len() * NACK_RANGE_ENTRY_SIZE
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── DataPayload ───────────────────────────────────────────────────

    #[test]
    fn data_payload_round_trip() {
        let original = DataPayload {
            file_id: 42,
            chunk_index: 7,
            chunk_offset: 65536,
            data: Bytes::from_static(b"hello world payload data"),
        };

        let mut buf = BytesMut::with_capacity(original.wire_size());
        original.encode(&mut buf);
        assert_eq!(buf.len(), original.wire_size());

        let mut slice: &[u8] = &buf;
        let decoded = DataPayload::decode(&mut slice).unwrap();
        assert_eq!(decoded, original);
        assert!(slice.is_empty());
    }

    #[test]
    fn data_payload_empty_data() {
        let original = DataPayload {
            file_id: 1,
            chunk_index: 0,
            chunk_offset: 0,
            data: Bytes::new(),
        };

        let mut buf = BytesMut::new();
        original.encode(&mut buf);

        let mut slice: &[u8] = &buf;
        let decoded = DataPayload::decode(&mut slice).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn data_payload_buffer_too_short() {
        let short = [0u8; 10];
        let mut slice: &[u8] = &short;
        let err = DataPayload::decode(&mut slice).unwrap_err();
        assert!(matches!(err, ProtoError::BufferTooShort { .. }));
    }

    #[test]
    fn data_payload_truncated_data() {
        let payload = DataPayload {
            file_id: 1,
            chunk_index: 0,
            chunk_offset: 0,
            data: Bytes::from_static(b"full data"),
        };
        let mut buf = BytesMut::new();
        payload.encode(&mut buf);

        // Truncate the buffer so the data length field says 9 but fewer bytes remain.
        buf.truncate(DATA_PAYLOAD_HEADER_SIZE + 3);
        let mut slice: &[u8] = &buf;
        let err = DataPayload::decode(&mut slice).unwrap_err();
        assert!(matches!(err, ProtoError::InvalidDataPayload(_)));
    }

    // ── AckBitmap ─────────────────────────────────────────────────────

    #[test]
    fn ack_bitmap_round_trip() {
        let original = AckBitmap {
            stream_id: 5,
            base_packet_number: 1000,
            highest_contiguous: 1015,
            ack_delay_micros: 250,
            bitmap: Bytes::from_static(&[0xFF, 0x0F, 0x00, 0x80]),
        };

        let mut buf = BytesMut::with_capacity(original.wire_size());
        original.encode(&mut buf);
        assert_eq!(buf.len(), original.wire_size());

        let mut slice: &[u8] = &buf;
        let decoded = AckBitmap::decode(&mut slice).unwrap();
        assert_eq!(decoded, original);
        assert!(slice.is_empty());
    }

    #[test]
    fn ack_bitmap_empty_bitmap() {
        let original = AckBitmap {
            stream_id: 0,
            base_packet_number: 0,
            highest_contiguous: 0,
            ack_delay_micros: 0,
            bitmap: Bytes::new(),
        };

        let mut buf = BytesMut::new();
        original.encode(&mut buf);

        let mut slice: &[u8] = &buf;
        let decoded = AckBitmap::decode(&mut slice).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn ack_bitmap_buffer_too_short() {
        let short = [0u8; 10];
        let mut slice: &[u8] = &short;
        let err = AckBitmap::decode(&mut slice).unwrap_err();
        assert!(matches!(err, ProtoError::BufferTooShort { .. }));
    }

    // ── NackRange ─────────────────────────────────────────────────────

    #[test]
    fn nack_range_round_trip() {
        let original = NackRange {
            stream_id: 3,
            ranges: vec![(100, 105), (200, 210), (500, 500)],
        };

        let mut buf = BytesMut::with_capacity(original.wire_size());
        original.encode(&mut buf);
        assert_eq!(buf.len(), original.wire_size());

        let mut slice: &[u8] = &buf;
        let decoded = NackRange::decode(&mut slice).unwrap();
        assert_eq!(decoded, original);
        assert!(slice.is_empty());
    }

    #[test]
    fn nack_range_no_ranges() {
        let original = NackRange {
            stream_id: 1,
            ranges: vec![],
        };

        let mut buf = BytesMut::new();
        original.encode(&mut buf);

        let mut slice: &[u8] = &buf;
        let decoded = NackRange::decode(&mut slice).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn nack_range_buffer_too_short() {
        let short = [0u8; 3];
        let mut slice: &[u8] = &short;
        let err = NackRange::decode(&mut slice).unwrap_err();
        assert!(matches!(err, ProtoError::BufferTooShort { .. }));
    }

    #[test]
    fn nack_range_truncated_ranges() {
        // Declare 2 ranges (32 bytes) but only supply 20 bytes.
        let mut buf = BytesMut::new();
        buf.put_u32(1); // stream_id
        buf.put_u16(2); // range_count = 2
        buf.put_u64(10); // range[0].start
        buf.put_u32(0); // partial range[0].end (only 4 bytes, need 8)

        let mut slice: &[u8] = &buf;
        let err = NackRange::decode(&mut slice).unwrap_err();
        assert!(matches!(err, ProtoError::InvalidDataPayload(_)));
    }
}
