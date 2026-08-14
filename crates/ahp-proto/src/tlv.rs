// Favonius — high-performance file transfer over UDP
// Copyright (c) 2025-2026 Vantino SàRL
// SPDX-License-Identifier: Apache-2.0

//! TLV (Type-Length-Value) encoding and decoding.
//!
//! Most AHP control payloads use TLV-encoded fields. Each TLV consists of a
//! 2-byte type, 2-byte length, and variable-length value. TLVs with the high
//! bit set on the type are considered *critical*: unknown critical TLVs MUST
//! cause a protocol error.

use bytes::{Buf, BufMut, Bytes, BytesMut};

use crate::error::ProtoError;
use core::fmt;

/// Minimum TLV header overhead: 2 (type) + 2 (length) = 4 bytes.
pub const TLV_HEADER_SIZE: usize = 4;

/// Standard TLV types defined in the AHP RFC section 10.2.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum TlvType {
    /// Human-readable endpoint name.
    EndpointName = 0x0001,
    /// List of protocol versions supported by the sender.
    ProtocolVersionList = 0x0002,
    /// Cipher suites supported by the sender.
    SupportedCipherSuites = 0x0003,
    /// Compression profiles supported by the sender.
    SupportedCompressionProfiles = 0x0004,
    /// Congestion control profiles supported by the sender.
    CongestionControlProfiles = 0x0005,
    /// Maximum UDP payload size the sender can handle.
    MaxUdpPayload = 0x0006,
    /// Maximum number of concurrent streams.
    MaxStreams = 0x0007,
    /// Authentication method identifier.
    AuthenticationMethod = 0x0008,
    /// Opaque authentication or session token.
    Token = 0x0009,
    /// Cryptographic nonce.
    Nonce = 0x000A,
    /// Public key material.
    PublicKey = 0x000B,
    /// Cryptographic signature.
    Signature = 0x000C,
    /// Hash of the file/transfer manifest.
    ManifestHash = 0x000D,
    /// Checkpoint identifier for resume.
    CheckpointId = 0x000E,
    /// Negotiated chunk size in bytes.
    ChunkSize = 0x000F,
    /// Negotiated region size in bytes.
    RegionSize = 0x0010,
    /// Logical file identifier.
    FileId = 0x0011,
    /// Logical file path.
    FilePath = 0x0012,
    /// File size in bytes.
    FileSize = 0x0013,
    /// Stable byte offset for a growing file.
    WatermarkOffset = 0x0014,
    /// Timestamp value (context-dependent).
    Timestamp = 0x0015,
    /// Wire-level error code.
    ErrorCode = 0x0016,
    /// Human-readable error detail string.
    ErrorDetail = 0x0017,
    /// Opaque resume ticket.
    ResumeTicket = 0x0018,
    /// Path token for relay or probe correlation.
    PathToken = 0x0019,
    /// Fairness profile identifier.
    FairnessProfile = 0x001A,
    /// Bitmap of negotiated feature flags.
    FeatureBitmap = 0x001B,
}

impl TlvType {
    /// Returns `true` if this TLV type has the critical bit (high bit) set.
    ///
    /// For the standard types (0x0001..0x001B) this is always `false`. Custom
    /// or future types with bit 15 set are considered critical.
    pub fn is_critical(self) -> bool {
        (self as u16) & 0x8000 != 0
    }
}

impl TryFrom<u16> for TlvType {
    type Error = ProtoError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            0x0001 => Ok(Self::EndpointName),
            0x0002 => Ok(Self::ProtocolVersionList),
            0x0003 => Ok(Self::SupportedCipherSuites),
            0x0004 => Ok(Self::SupportedCompressionProfiles),
            0x0005 => Ok(Self::CongestionControlProfiles),
            0x0006 => Ok(Self::MaxUdpPayload),
            0x0007 => Ok(Self::MaxStreams),
            0x0008 => Ok(Self::AuthenticationMethod),
            0x0009 => Ok(Self::Token),
            0x000A => Ok(Self::Nonce),
            0x000B => Ok(Self::PublicKey),
            0x000C => Ok(Self::Signature),
            0x000D => Ok(Self::ManifestHash),
            0x000E => Ok(Self::CheckpointId),
            0x000F => Ok(Self::ChunkSize),
            0x0010 => Ok(Self::RegionSize),
            0x0011 => Ok(Self::FileId),
            0x0012 => Ok(Self::FilePath),
            0x0013 => Ok(Self::FileSize),
            0x0014 => Ok(Self::WatermarkOffset),
            0x0015 => Ok(Self::Timestamp),
            0x0016 => Ok(Self::ErrorCode),
            0x0017 => Ok(Self::ErrorDetail),
            0x0018 => Ok(Self::ResumeTicket),
            0x0019 => Ok(Self::PathToken),
            0x001A => Ok(Self::FairnessProfile),
            0x001B => Ok(Self::FeatureBitmap),
            _ => Err(ProtoError::InvalidTlv(format!(
                "unknown TLV type: 0x{value:04X}"
            ))),
        }
    }
}

impl From<TlvType> for u16 {
    fn from(t: TlvType) -> u16 {
        t as u16
    }
}

impl fmt::Display for TlvType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?} (0x{:04X})", self, *self as u16)
    }
}

/// A single decoded TLV record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tlv {
    /// The raw 16-bit type code.
    pub tlv_type: u16,
    /// The value bytes (length is implicit from `value.len()`).
    pub value: Bytes,
}

impl Tlv {
    /// Total wire size of this TLV: 4-byte header + value length.
    pub fn wire_size(&self) -> usize {
        TLV_HEADER_SIZE + self.value.len()
    }

    /// Returns `true` if the high bit of the type code is set, indicating that
    /// the TLV is critical and MUST be understood.
    pub fn is_critical(&self) -> bool {
        self.tlv_type & 0x8000 != 0
    }

    /// Encodes this TLV into `dst`.
    pub fn encode(&self, dst: &mut BytesMut) {
        dst.put_u16(self.tlv_type);
        dst.put_u16(self.value.len() as u16);
        dst.put_slice(&self.value);
    }

    /// Decodes a single TLV from `src`, advancing the cursor.
    pub fn decode(src: &mut &[u8]) -> Result<Self, ProtoError> {
        if src.len() < TLV_HEADER_SIZE {
            return Err(ProtoError::InvalidTlv(format!(
                "buffer too short for TLV header: need {TLV_HEADER_SIZE}, have {}",
                src.len()
            )));
        }

        let tlv_type = src.get_u16();
        let length = src.get_u16() as usize;

        if src.len() < length {
            return Err(ProtoError::InvalidTlv(format!(
                "TLV 0x{tlv_type:04X} declares length {length} but only {} bytes remain",
                src.len()
            )));
        }

        let value = Bytes::copy_from_slice(&src[..length]);
        src.advance(length);

        Ok(Self { tlv_type, value })
    }
}

/// An iterator that yields [`Tlv`] records from a byte slice.
pub struct TlvIterator<'a> {
    remaining: &'a [u8],
}

impl<'a> TlvIterator<'a> {
    /// Creates a new iterator over the TLVs in `data`.
    pub fn new(data: &'a [u8]) -> Self {
        Self { remaining: data }
    }
}

impl<'a> Iterator for TlvIterator<'a> {
    type Item = Result<Tlv, ProtoError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining.is_empty() {
            return None;
        }
        Some(Tlv::decode(&mut self.remaining))
    }
}

/// Convenience: encode a sequence of TLVs into a fresh `BytesMut`.
pub fn encode_tlvs(tlvs: &[Tlv]) -> BytesMut {
    let total: usize = tlvs.iter().map(|t| t.wire_size()).sum();
    let mut buf = BytesMut::with_capacity(total);
    for tlv in tlvs {
        tlv.encode(&mut buf);
    }
    buf
}

/// Convenience: decode all TLVs from a byte slice, collecting into a `Vec`.
pub fn decode_tlvs(mut src: &[u8]) -> Result<Vec<Tlv>, ProtoError> {
    let mut out = Vec::new();
    while !src.is_empty() {
        out.push(Tlv::decode(&mut src)?);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tlv_round_trip() {
        let original = Tlv {
            tlv_type: TlvType::EndpointName as u16,
            value: Bytes::from_static(b"test-node-01"),
        };

        let mut buf = BytesMut::with_capacity(64);
        original.encode(&mut buf);

        assert_eq!(buf.len(), TLV_HEADER_SIZE + 12);

        let mut slice: &[u8] = &buf;
        let decoded = Tlv::decode(&mut slice).unwrap();
        assert_eq!(decoded, original);
        assert!(slice.is_empty());
    }

    #[test]
    fn multiple_tlvs_round_trip() {
        let tlvs = vec![
            Tlv {
                tlv_type: TlvType::Nonce as u16,
                value: Bytes::from_static(&[0xDE, 0xAD, 0xBE, 0xEF]),
            },
            Tlv {
                tlv_type: TlvType::MaxUdpPayload as u16,
                value: Bytes::from_static(&[0x04, 0xB0]), // 1200
            },
            Tlv {
                tlv_type: TlvType::EndpointName as u16,
                value: Bytes::from_static(b"peer"),
            },
        ];

        let buf = encode_tlvs(&tlvs);
        let decoded = decode_tlvs(&buf).unwrap();
        assert_eq!(decoded, tlvs);
    }

    #[test]
    fn tlv_iterator() {
        let tlvs = vec![
            Tlv {
                tlv_type: 0x0001,
                value: Bytes::from_static(b"a"),
            },
            Tlv {
                tlv_type: 0x0002,
                value: Bytes::from_static(b"bb"),
            },
        ];
        let buf = encode_tlvs(&tlvs);

        let mut iter = TlvIterator::new(&buf);
        let first = iter.next().unwrap().unwrap();
        assert_eq!(first.tlv_type, 0x0001);
        let second = iter.next().unwrap().unwrap();
        assert_eq!(second.tlv_type, 0x0002);
        assert!(iter.next().is_none());
    }

    #[test]
    fn critical_bit_check() {
        let non_critical = Tlv {
            tlv_type: 0x0001,
            value: Bytes::new(),
        };
        assert!(!non_critical.is_critical());

        let critical = Tlv {
            tlv_type: 0x8001,
            value: Bytes::new(),
        };
        assert!(critical.is_critical());
    }

    #[test]
    fn standard_types_not_critical() {
        let all_standard = [
            TlvType::EndpointName,
            TlvType::ProtocolVersionList,
            TlvType::FeatureBitmap,
        ];
        for t in all_standard {
            assert!(!t.is_critical());
        }
    }

    #[test]
    fn truncated_tlv_header_rejected() {
        let short = [0x00, 0x01]; // Only 2 bytes, need 4.
        let mut slice: &[u8] = &short;
        assert!(Tlv::decode(&mut slice).is_err());
    }

    #[test]
    fn truncated_tlv_value_rejected() {
        // Type = 0x0001, Length = 10, but only 3 bytes of value follow.
        let bad = [0x00, 0x01, 0x00, 0x0A, 0x01, 0x02, 0x03];
        let mut slice: &[u8] = &bad;
        assert!(Tlv::decode(&mut slice).is_err());
    }

    #[test]
    fn tlv_type_display() {
        let s = format!("{}", TlvType::Nonce);
        assert!(s.contains("Nonce"));
        assert!(s.contains("0x000A"));
    }

    #[test]
    fn empty_value_tlv() {
        let tlv = Tlv {
            tlv_type: TlvType::FeatureBitmap as u16,
            value: Bytes::new(),
        };
        assert_eq!(tlv.wire_size(), TLV_HEADER_SIZE);

        let mut buf = BytesMut::new();
        tlv.encode(&mut buf);
        let mut slice: &[u8] = &buf;
        let decoded = Tlv::decode(&mut slice).unwrap();
        assert_eq!(decoded, tlv);
    }
}
