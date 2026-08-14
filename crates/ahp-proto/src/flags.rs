// Favonius — high-performance file transfer over UDP
// Copyright (c) 2025-2026 Vantino SàRL
// SPDX-License-Identifier: Apache-2.0

//! Packet-level bit flags for the AHP common header.
//!
//! Flags occupy a 16-bit field (bits 0..15). Bits 10-15 are reserved and MUST
//! be zero unless a future extension is negotiated.

use bitflags::bitflags;

bitflags! {
    /// Flags carried in the 16-bit flags field of the AHP common header.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct PacketFlags: u16 {
        /// Packet should provoke ACK feedback from the receiver.
        const ACK_ELICITING      = 0x0001;
        /// Packet contains retransmitted content.
        const RETRANSMIT         = 0x0002;
        /// Packet is used for path probing.
        const PROBE              = 0x0004;
        /// Final packet in a logical stream segment.
        const FINAL              = 0x0008;
        /// Payload is compressed.
        const COMPRESSED         = 0x0010;
        /// Payload is encrypted.
        const ENCRYPTED          = 0x0020;
        /// Packet contains forward error correction data.
        const FEC                = 0x0040;
        /// Packet relates to a checkpoint or resume operation.
        const CHECKPOINT_RELATED = 0x0080;
        /// Packet belongs to a growing (live) file transfer.
        const LIVE_FILE          = 0x0100;
        /// Packet belongs to a sync delta operation.
        const DELTA              = 0x0200;
    }
}

impl PacketFlags {
    /// Mask covering all reserved bits (10..15). These MUST be zero on the wire
    /// unless explicitly negotiated.
    pub const RESERVED_MASK: u16 = 0xFC00;

    /// Returns `true` if any reserved bits are set.
    pub fn has_reserved_bits(self) -> bool {
        self.bits() & Self::RESERVED_MASK != 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flag_values() {
        assert_eq!(PacketFlags::ACK_ELICITING.bits(), 0x0001);
        assert_eq!(PacketFlags::RETRANSMIT.bits(), 0x0002);
        assert_eq!(PacketFlags::PROBE.bits(), 0x0004);
        assert_eq!(PacketFlags::FINAL.bits(), 0x0008);
        assert_eq!(PacketFlags::COMPRESSED.bits(), 0x0010);
        assert_eq!(PacketFlags::ENCRYPTED.bits(), 0x0020);
        assert_eq!(PacketFlags::FEC.bits(), 0x0040);
        assert_eq!(PacketFlags::CHECKPOINT_RELATED.bits(), 0x0080);
        assert_eq!(PacketFlags::LIVE_FILE.bits(), 0x0100);
        assert_eq!(PacketFlags::DELTA.bits(), 0x0200);
    }

    #[test]
    fn combine_flags() {
        let flags = PacketFlags::ACK_ELICITING | PacketFlags::ENCRYPTED | PacketFlags::COMPRESSED;
        assert!(flags.contains(PacketFlags::ACK_ELICITING));
        assert!(flags.contains(PacketFlags::ENCRYPTED));
        assert!(flags.contains(PacketFlags::COMPRESSED));
        assert!(!flags.contains(PacketFlags::RETRANSMIT));
    }

    #[test]
    fn reserved_bits_detected() {
        let clean = PacketFlags::ACK_ELICITING | PacketFlags::DELTA;
        assert!(!clean.has_reserved_bits());

        // Bit 10 is reserved.
        let dirty = PacketFlags::from_bits_retain(0x0400);
        assert!(dirty.has_reserved_bits());
    }

    #[test]
    fn from_raw_bits() {
        let raw: u16 = 0x0021; // ACK_ELICITING | ENCRYPTED
        let flags = PacketFlags::from_bits_truncate(raw);
        assert!(flags.contains(PacketFlags::ACK_ELICITING));
        assert!(flags.contains(PacketFlags::ENCRYPTED));
    }
}
