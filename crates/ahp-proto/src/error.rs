// Favonius — high-performance file transfer over UDP
// Copyright (c) 2025-2026 Vantino SàRL
// SPDX-License-Identifier: Apache-2.0

//! Protocol error types for AHP.
//!
//! Defines both wire-level error codes (sent in ERROR packets) and codec-level
//! errors encountered during packet parsing and serialization.

use core::fmt;

/// Wire-level error codes as defined in the AHP RFC section 29.2.
///
/// These codes are transmitted inside ERROR packets to communicate protocol-level
/// failures between endpoints.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum ErrorCode {
    /// Peer advertised an unsupported protocol version.
    UnsupportedVersion = 0x0001,
    /// Peer requires a feature not supported by this endpoint.
    UnsupportedFeature = 0x0002,
    /// Authentication handshake failed.
    AuthFailed = 0x0003,
    /// Authenticated peer lacks permission for the requested operation.
    PermissionDenied = 0x0004,
    /// Manifest is malformed or fails integrity checks.
    BadManifest = 0x0005,
    /// Checkpoint data is invalid or incompatible with current state.
    CheckpointInvalid = 0x0006,
    /// Decryption of a received packet failed.
    PacketDecryptFailed = 0x0007,
    /// Flow-control limits were violated.
    FlowControl = 0x0008,
    /// A generic protocol-level violation was detected.
    ProtocolViolation = 0x0009,
    /// The network path has failed or become unreachable.
    PathFailure = 0x000A,
    /// Storage backend encountered an unrecoverable error.
    StorageFailure = 0x000B,
    /// A sync conflict was detected that could not be automatically resolved.
    Conflict = 0x000C,
    /// The requested relay is unavailable.
    RelayUnavailable = 0x000D,
}

impl ErrorCode {
    /// Returns the numeric wire representation.
    pub fn as_u16(self) -> u16 {
        self as u16
    }

    /// Returns a human-readable name for the error code.
    pub fn name(self) -> &'static str {
        match self {
            Self::UnsupportedVersion => "UNSUPPORTED_VERSION",
            Self::UnsupportedFeature => "UNSUPPORTED_FEATURE",
            Self::AuthFailed => "AUTH_FAILED",
            Self::PermissionDenied => "PERMISSION_DENIED",
            Self::BadManifest => "BAD_MANIFEST",
            Self::CheckpointInvalid => "CHECKPOINT_INVALID",
            Self::PacketDecryptFailed => "PACKET_DECRYPT_FAILED",
            Self::FlowControl => "FLOW_CONTROL",
            Self::ProtocolViolation => "PROTOCOL_VIOLATION",
            Self::PathFailure => "PATH_FAILURE",
            Self::StorageFailure => "STORAGE_FAILURE",
            Self::Conflict => "CONFLICT",
            Self::RelayUnavailable => "RELAY_UNAVAILABLE",
        }
    }
}

impl TryFrom<u16> for ErrorCode {
    type Error = ProtoError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            0x0001 => Ok(Self::UnsupportedVersion),
            0x0002 => Ok(Self::UnsupportedFeature),
            0x0003 => Ok(Self::AuthFailed),
            0x0004 => Ok(Self::PermissionDenied),
            0x0005 => Ok(Self::BadManifest),
            0x0006 => Ok(Self::CheckpointInvalid),
            0x0007 => Ok(Self::PacketDecryptFailed),
            0x0008 => Ok(Self::FlowControl),
            0x0009 => Ok(Self::ProtocolViolation),
            0x000A => Ok(Self::PathFailure),
            0x000B => Ok(Self::StorageFailure),
            0x000C => Ok(Self::Conflict),
            0x000D => Ok(Self::RelayUnavailable),
            other => Err(ProtoError::UnknownErrorCode(other)),
        }
    }
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{:04X} {}", self.as_u16(), self.name())
    }
}

/// Errors encountered during packet codec operations (encoding, decoding, validation).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ProtoError {
    /// The input buffer does not contain enough bytes for the requested operation.
    #[error("buffer too short: need {need} bytes, have {have}")]
    BufferTooShort {
        /// Minimum bytes required.
        need: usize,
        /// Bytes actually available.
        have: usize,
    },

    /// The packet type byte does not map to any known `PacketType`.
    #[error("invalid packet type: 0x{0:02X}")]
    InvalidPacketType(u8),

    /// CRC32C computed over the header does not match the stored value.
    #[error("CRC mismatch: expected 0x{expected:08X}, computed 0x{computed:08X}")]
    CrcMismatch {
        /// The CRC value stored in the header.
        expected: u32,
        /// The CRC value recomputed over the header bytes.
        computed: u32,
    },

    /// A TLV field is malformed (truncated, invalid type, etc.).
    #[error("invalid TLV: {0}")]
    InvalidTlv(String),

    /// The protocol version is not supported by this implementation.
    #[error("unsupported protocol version: {0}")]
    UnsupportedVersion(u8),

    /// The header length field is smaller than the fixed header size.
    #[error("invalid header length: {0} (minimum is {1})")]
    InvalidHeaderLength(u16, u16),

    /// The payload length exceeds the remaining buffer.
    #[error("payload length {declared} exceeds remaining buffer {available}")]
    PayloadOverflow {
        /// Length declared in the header.
        declared: u32,
        /// Bytes remaining after header + extensions.
        available: usize,
    },

    /// An extension field is malformed.
    #[error("invalid extension: {0}")]
    InvalidExtension(String),

    /// A wire-level error code was not recognised.
    #[error("unknown error code: 0x{0:04X}")]
    UnknownErrorCode(u16),

    /// A data-plane payload is malformed.
    #[error("invalid data payload: {0}")]
    InvalidDataPayload(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_code_round_trip() {
        let codes = [
            (0x0001u16, ErrorCode::UnsupportedVersion),
            (0x0002, ErrorCode::UnsupportedFeature),
            (0x0003, ErrorCode::AuthFailed),
            (0x0004, ErrorCode::PermissionDenied),
            (0x0005, ErrorCode::BadManifest),
            (0x0006, ErrorCode::CheckpointInvalid),
            (0x0007, ErrorCode::PacketDecryptFailed),
            (0x0008, ErrorCode::FlowControl),
            (0x0009, ErrorCode::ProtocolViolation),
            (0x000A, ErrorCode::PathFailure),
            (0x000B, ErrorCode::StorageFailure),
            (0x000C, ErrorCode::Conflict),
            (0x000D, ErrorCode::RelayUnavailable),
        ];
        for (raw, expected) in codes {
            let parsed = ErrorCode::try_from(raw).unwrap();
            assert_eq!(parsed, expected);
            assert_eq!(parsed.as_u16(), raw);
        }
    }

    #[test]
    fn unknown_error_code_rejected() {
        assert!(ErrorCode::try_from(0x00FF).is_err());
        assert!(ErrorCode::try_from(0x0000).is_err());
    }

    #[test]
    fn error_code_display() {
        let code = ErrorCode::AuthFailed;
        let s = format!("{code}");
        assert!(s.contains("0x0003"));
        assert!(s.contains("AUTH_FAILED"));
    }

    #[test]
    fn proto_error_display() {
        let e = ProtoError::BufferTooShort { need: 42, have: 10 };
        let s = format!("{e}");
        assert!(s.contains("42"));
        assert!(s.contains("10"));
    }
}
