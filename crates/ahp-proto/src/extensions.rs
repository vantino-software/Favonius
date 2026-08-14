// Favonius — high-performance file transfer over UDP
// Copyright (c) 2025-2026 Vantino SàRL
// SPDX-License-Identifier: Apache-2.0

//! Header extensions for AHP packets.
//!
//! Extensions follow the fixed 42-byte common header and are included in the
//! region between `HEADER_SIZE` and `header_length`. Each extension is
//! type-length-value encoded with a 2-byte type, 2-byte length, and
//! variable-length value.

use bytes::{Buf, BufMut, Bytes, BytesMut};

use crate::error::ProtoError;
use core::fmt;

/// Minimum extension overhead: 2 (type) + 2 (length) = 4 bytes.
pub const EXTENSION_HEADER_SIZE: usize = 4;

/// Known header extension types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum ExtensionType {
    /// Identifies the network path for multi-path support.
    PathId = 0x0001,
    /// Current key phase for encryption rotation.
    KeyPhase = 0x0002,
    /// Hint for receiver ACK delay.
    AckDelayHint = 0x0003,
    /// Identifies the active compression profile.
    CompressionProfileId = 0x0004,
    /// Chunk identifier carried inline in the header.
    ChunkId = 0x0005,
    /// Region identifier for sync operations.
    RegionId = 0x0006,
    /// File identifier carried inline in the header.
    FileId = 0x0007,
    /// Stable byte offset for a growing file.
    WatermarkOffset = 0x0008,
    /// Opaque tag identifying a relay path.
    RelayPathTag = 0x0009,
}

impl ExtensionType {
    /// Returns `true` if the high bit is set, marking this extension as
    /// critical (MUST be understood by the receiver).
    pub fn is_critical(self) -> bool {
        (self as u16) & 0x8000 != 0
    }
}

impl TryFrom<u16> for ExtensionType {
    type Error = ProtoError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            0x0001 => Ok(Self::PathId),
            0x0002 => Ok(Self::KeyPhase),
            0x0003 => Ok(Self::AckDelayHint),
            0x0004 => Ok(Self::CompressionProfileId),
            0x0005 => Ok(Self::ChunkId),
            0x0006 => Ok(Self::RegionId),
            0x0007 => Ok(Self::FileId),
            0x0008 => Ok(Self::WatermarkOffset),
            0x0009 => Ok(Self::RelayPathTag),
            _ => Err(ProtoError::InvalidExtension(format!(
                "unknown extension type: 0x{value:04X}"
            ))),
        }
    }
}

impl From<ExtensionType> for u16 {
    fn from(e: ExtensionType) -> u16 {
        e as u16
    }
}

impl fmt::Display for ExtensionType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?} (0x{:04X})", self, *self as u16)
    }
}

/// A single header extension record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Extension {
    /// Raw 16-bit extension type code.
    pub ext_type: u16,
    /// Extension value bytes.
    pub value: Bytes,
}

impl Extension {
    /// Total wire size: 4-byte header + value length.
    pub fn wire_size(&self) -> usize {
        EXTENSION_HEADER_SIZE + self.value.len()
    }

    /// Returns `true` if the high bit of the type code is set (critical).
    pub fn is_critical(&self) -> bool {
        self.ext_type & 0x8000 != 0
    }

    /// Encodes this extension into `dst`.
    pub fn encode(&self, dst: &mut BytesMut) {
        dst.put_u16(self.ext_type);
        dst.put_u16(self.value.len() as u16);
        dst.put_slice(&self.value);
    }

    /// Decodes a single extension from `src`, advancing the cursor.
    pub fn decode(src: &mut &[u8]) -> Result<Self, ProtoError> {
        if src.len() < EXTENSION_HEADER_SIZE {
            return Err(ProtoError::InvalidExtension(format!(
                "buffer too short for extension header: need {EXTENSION_HEADER_SIZE}, have {}",
                src.len()
            )));
        }

        let ext_type = src.get_u16();
        let length = src.get_u16() as usize;

        if src.len() < length {
            return Err(ProtoError::InvalidExtension(format!(
                "extension 0x{ext_type:04X} declares length {length} but only {} bytes remain",
                src.len()
            )));
        }

        let value = Bytes::copy_from_slice(&src[..length]);
        src.advance(length);

        Ok(Self { ext_type, value })
    }
}

/// Decode all extensions from a byte slice.
pub fn decode_extensions(mut src: &[u8]) -> Result<Vec<Extension>, ProtoError> {
    let mut out = Vec::new();
    while !src.is_empty() {
        out.push(Extension::decode(&mut src)?);
    }
    Ok(out)
}

/// Encode a sequence of extensions into a fresh `BytesMut`.
pub fn encode_extensions(exts: &[Extension]) -> BytesMut {
    let total: usize = exts.iter().map(|e| e.wire_size()).sum();
    let mut buf = BytesMut::with_capacity(total);
    for ext in exts {
        ext.encode(&mut buf);
    }
    buf
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extension_round_trip() {
        let original = Extension {
            ext_type: ExtensionType::PathId as u16,
            value: Bytes::from_static(&[0x00, 0x00, 0x00, 0x01]),
        };

        let mut buf = BytesMut::with_capacity(32);
        original.encode(&mut buf);

        assert_eq!(buf.len(), EXTENSION_HEADER_SIZE + 4);

        let mut slice: &[u8] = &buf;
        let decoded = Extension::decode(&mut slice).unwrap();
        assert_eq!(decoded, original);
        assert!(slice.is_empty());
    }

    #[test]
    fn multiple_extensions_round_trip() {
        let exts = vec![
            Extension {
                ext_type: ExtensionType::KeyPhase as u16,
                value: Bytes::from_static(&[0x02]),
            },
            Extension {
                ext_type: ExtensionType::ChunkId as u16,
                value: Bytes::from_static(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07]),
            },
            Extension {
                ext_type: ExtensionType::RelayPathTag as u16,
                value: Bytes::from_static(b"relay-us-west"),
            },
        ];

        let buf = encode_extensions(&exts);
        let decoded = decode_extensions(&buf).unwrap();
        assert_eq!(decoded, exts);
    }

    #[test]
    fn empty_extension_value() {
        let ext = Extension {
            ext_type: ExtensionType::AckDelayHint as u16,
            value: Bytes::new(),
        };
        assert_eq!(ext.wire_size(), EXTENSION_HEADER_SIZE);

        let mut buf = BytesMut::new();
        ext.encode(&mut buf);
        let mut slice: &[u8] = &buf;
        let decoded = Extension::decode(&mut slice).unwrap();
        assert_eq!(decoded, ext);
    }

    #[test]
    fn critical_bit() {
        let normal = Extension {
            ext_type: 0x0001,
            value: Bytes::new(),
        };
        assert!(!normal.is_critical());

        let critical = Extension {
            ext_type: 0x8001,
            value: Bytes::new(),
        };
        assert!(critical.is_critical());
    }

    #[test]
    fn truncated_extension_header() {
        let short = [0x00, 0x01]; // Only 2 bytes.
        let mut slice: &[u8] = &short;
        assert!(Extension::decode(&mut slice).is_err());
    }

    #[test]
    fn truncated_extension_value() {
        // Type=0x0001, Length=8, but only 2 bytes of value.
        let bad = [0x00, 0x01, 0x00, 0x08, 0xAA, 0xBB];
        let mut slice: &[u8] = &bad;
        assert!(Extension::decode(&mut slice).is_err());
    }

    #[test]
    fn extension_type_try_from_known() {
        assert_eq!(ExtensionType::try_from(0x0001).unwrap(), ExtensionType::PathId);
        assert_eq!(ExtensionType::try_from(0x0009).unwrap(), ExtensionType::RelayPathTag);
    }

    #[test]
    fn extension_type_try_from_unknown() {
        assert!(ExtensionType::try_from(0x00FF).is_err());
    }

    #[test]
    fn extension_type_display() {
        let s = format!("{}", ExtensionType::KeyPhase);
        assert!(s.contains("KeyPhase"));
        assert!(s.contains("0x0002"));
    }
}
