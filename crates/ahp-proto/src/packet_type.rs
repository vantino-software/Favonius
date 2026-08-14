// Favonius — high-performance file transfer over UDP
// Copyright (c) 2025-2026 Vantino SàRL
// SPDX-License-Identifier: Apache-2.0

//! AHP packet type definitions.
//!
//! Every AHP packet carries a single-byte type code in the common header.
//! Types are grouped into four families: Control, Data, Sync, and Relay.

use crate::error::ProtoError;
use core::fmt;

/// All packet types defined by the AHP protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum PacketType {
    // ── Control (0x01..0x0F) ──────────────────────────────────────────
    /// Initiate session handshake.
    Hello = 0x01,
    /// Acknowledge HELLO and select parameters.
    HelloAck = 0x02,
    /// Exchange capability parameters.
    Caps = 0x03,
    /// Authentication request.
    Auth = 0x04,
    /// Authentication acknowledgement.
    AuthAck = 0x05,
    /// Path probing request.
    PathProbe = 0x06,
    /// Path probing acknowledgement.
    PathProbeAck = 0x07,
    /// File/transfer manifest.
    Manifest = 0x08,
    /// Checkpoint state exchange.
    Checkpoint = 0x09,
    /// Resume request after reconnect.
    ResumeReq = 0x0A,
    /// Resume acknowledgement.
    ResumeAck = 0x0B,
    /// Transfer completion signal.
    Finish = 0x0C,
    /// Error signal.
    Error = 0x0D,
    /// Session keepalive.
    Keepalive = 0x0E,
    /// Key rotation announcement.
    KeyUpdate = 0x0F,

    // ── Data (0x20..0x26) ─────────────────────────────────────────────
    /// File data payload.
    Data = 0x20,
    /// Bitmap-based acknowledgement.
    AckBitmap = 0x21,
    /// Negative acknowledgement with missing ranges.
    NackRange = 0x22,
    /// Sender rate hint from receiver.
    RateHint = 0x23,
    /// Receiver flow-control window update.
    WindowUpdate = 0x24,
    /// Chunk delivery commit notification.
    ChunkCommit = 0x25,
    /// Chunk repair request.
    ChunkRepair = 0x26,

    // ── Sync (0x40..0x45) ─────────────────────────────────────────────
    /// Announce sync intent.
    SyncAnnounce = 0x40,
    /// Region hash map for sync.
    RegionMap = 0x41,
    /// Changed-region delta map.
    DeltaMap = 0x42,
    /// Sync conflict notification.
    Conflict = 0x43,
    /// Growing-file watermark update.
    Watermark = 0x44,
    /// Final commit for a live file.
    LiveCommit = 0x45,

    // ── Relay (0x60..0x63) ────────────────────────────────────────────
    /// Rendezvous coordination.
    Rendezvous = 0x60,
    /// Relay session assignment.
    RelayAssign = 0x61,
    /// Relay-forwarded packet wrapper.
    RelayForward = 0x62,
    /// Relay health heartbeat.
    RelayHeartbeat = 0x63,
}

impl PacketType {
    /// Returns `true` if this is a control-plane packet type (0x01..0x0F).
    pub fn is_control(self) -> bool {
        let v = self as u8;
        (0x01..=0x0F).contains(&v)
    }

    /// Returns `true` if this is a data-plane packet type (0x20..0x26).
    pub fn is_data(self) -> bool {
        let v = self as u8;
        (0x20..=0x26).contains(&v)
    }

    /// Returns `true` if this is a sync-plane packet type (0x40..0x45).
    pub fn is_sync(self) -> bool {
        let v = self as u8;
        (0x40..=0x45).contains(&v)
    }

    /// Returns `true` if this is a relay packet type (0x60..0x63).
    pub fn is_relay(self) -> bool {
        let v = self as u8;
        (0x60..=0x63).contains(&v)
    }

    /// Returns the canonical protocol name for this packet type.
    pub fn name(self) -> &'static str {
        match self {
            Self::Hello => "HELLO",
            Self::HelloAck => "HELLO_ACK",
            Self::Caps => "CAPS",
            Self::Auth => "AUTH",
            Self::AuthAck => "AUTH_ACK",
            Self::PathProbe => "PATH_PROBE",
            Self::PathProbeAck => "PATH_PROBE_ACK",
            Self::Manifest => "MANIFEST",
            Self::Checkpoint => "CHECKPOINT",
            Self::ResumeReq => "RESUME_REQ",
            Self::ResumeAck => "RESUME_ACK",
            Self::Finish => "FINISH",
            Self::Error => "ERROR",
            Self::Keepalive => "KEEPALIVE",
            Self::KeyUpdate => "KEY_UPDATE",
            Self::Data => "DATA",
            Self::AckBitmap => "ACK_BITMAP",
            Self::NackRange => "NACK_RANGE",
            Self::RateHint => "RATE_HINT",
            Self::WindowUpdate => "WINDOW_UPDATE",
            Self::ChunkCommit => "CHUNK_COMMIT",
            Self::ChunkRepair => "CHUNK_REPAIR",
            Self::SyncAnnounce => "SYNC_ANNOUNCE",
            Self::RegionMap => "REGION_MAP",
            Self::DeltaMap => "DELTA_MAP",
            Self::Conflict => "CONFLICT",
            Self::Watermark => "WATERMARK",
            Self::LiveCommit => "LIVE_COMMIT",
            Self::Rendezvous => "RENDEZVOUS",
            Self::RelayAssign => "RELAY_ASSIGN",
            Self::RelayForward => "RELAY_FORWARD",
            Self::RelayHeartbeat => "RELAY_HEARTBEAT",
        }
    }
}

impl TryFrom<u8> for PacketType {
    type Error = ProtoError;

    fn try_from(value: u8) -> Result<Self, <Self as TryFrom<u8>>::Error> {
        match value {
            0x01 => Ok(Self::Hello),
            0x02 => Ok(Self::HelloAck),
            0x03 => Ok(Self::Caps),
            0x04 => Ok(Self::Auth),
            0x05 => Ok(Self::AuthAck),
            0x06 => Ok(Self::PathProbe),
            0x07 => Ok(Self::PathProbeAck),
            0x08 => Ok(Self::Manifest),
            0x09 => Ok(Self::Checkpoint),
            0x0A => Ok(Self::ResumeReq),
            0x0B => Ok(Self::ResumeAck),
            0x0C => Ok(Self::Finish),
            0x0D => Ok(Self::Error),
            0x0E => Ok(Self::Keepalive),
            0x0F => Ok(Self::KeyUpdate),
            0x20 => Ok(Self::Data),
            0x21 => Ok(Self::AckBitmap),
            0x22 => Ok(Self::NackRange),
            0x23 => Ok(Self::RateHint),
            0x24 => Ok(Self::WindowUpdate),
            0x25 => Ok(Self::ChunkCommit),
            0x26 => Ok(Self::ChunkRepair),
            0x40 => Ok(Self::SyncAnnounce),
            0x41 => Ok(Self::RegionMap),
            0x42 => Ok(Self::DeltaMap),
            0x43 => Ok(Self::Conflict),
            0x44 => Ok(Self::Watermark),
            0x45 => Ok(Self::LiveCommit),
            0x60 => Ok(Self::Rendezvous),
            0x61 => Ok(Self::RelayAssign),
            0x62 => Ok(Self::RelayForward),
            0x63 => Ok(Self::RelayHeartbeat),
            other => Err(ProtoError::InvalidPacketType(other)),
        }
    }
}

impl From<PacketType> for u8 {
    fn from(pt: PacketType) -> u8 {
        pt as u8
    }
}

impl fmt::Display for PacketType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} (0x{:02X})", self.name(), *self as u8)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_all_types() {
        let all: &[PacketType] = &[
            PacketType::Hello,
            PacketType::HelloAck,
            PacketType::Caps,
            PacketType::Auth,
            PacketType::AuthAck,
            PacketType::PathProbe,
            PacketType::PathProbeAck,
            PacketType::Manifest,
            PacketType::Checkpoint,
            PacketType::ResumeReq,
            PacketType::ResumeAck,
            PacketType::Finish,
            PacketType::Error,
            PacketType::Keepalive,
            PacketType::KeyUpdate,
            PacketType::Data,
            PacketType::AckBitmap,
            PacketType::NackRange,
            PacketType::RateHint,
            PacketType::WindowUpdate,
            PacketType::ChunkCommit,
            PacketType::ChunkRepair,
            PacketType::SyncAnnounce,
            PacketType::RegionMap,
            PacketType::DeltaMap,
            PacketType::Conflict,
            PacketType::Watermark,
            PacketType::LiveCommit,
            PacketType::Rendezvous,
            PacketType::RelayAssign,
            PacketType::RelayForward,
            PacketType::RelayHeartbeat,
        ];

        for &pt in all {
            let raw: u8 = pt.into();
            let back = PacketType::try_from(raw).unwrap();
            assert_eq!(back, pt);
        }
    }

    #[test]
    fn unknown_type_rejected() {
        assert!(PacketType::try_from(0x00).is_err());
        assert!(PacketType::try_from(0x10).is_err());
        assert!(PacketType::try_from(0x30).is_err());
        assert!(PacketType::try_from(0xFF).is_err());
    }

    #[test]
    fn family_classification() {
        assert!(PacketType::Hello.is_control());
        assert!(!PacketType::Hello.is_data());

        assert!(PacketType::Data.is_data());
        assert!(!PacketType::Data.is_control());

        assert!(PacketType::SyncAnnounce.is_sync());
        assert!(!PacketType::SyncAnnounce.is_relay());

        assert!(PacketType::Rendezvous.is_relay());
        assert!(!PacketType::Rendezvous.is_sync());
    }

    #[test]
    fn display_format() {
        let s = format!("{}", PacketType::Data);
        assert!(s.contains("DATA"));
        assert!(s.contains("0x20"));
    }
}
