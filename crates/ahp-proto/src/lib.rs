// Favonius — high-performance file transfer over UDP
// Copyright (c) 2025-2026 Vantino SàRL
// SPDX-License-Identifier: Apache-2.0

//! `ahp-proto` -- AHP wire format: packet framing, types, TLV encoding, and codec.
//!
//! This crate implements the binary wire format for the **Adaptive High-speed
//! Protocol** (AHP), the custom UDP-based transport used by Favonius. It covers:
//!
//! * The 42-byte fixed packet header with CRC32C integrity.
//! * All packet types across Control, Data, Sync, and Relay families.
//! * Packet-level bit flags.
//! * TLV (Type-Length-Value) encoding for control payloads.
//! * Header extensions.
//! * Data-plane payload structures (DATA, ACK_BITMAP, NACK_RANGE).
//! * Full packet encode/decode codec.
//! * Protocol-level and codec-level error types.
//!
//! # Wire format overview
//!
//! Every AHP packet on the wire looks like:
//!
//! ```text
//! +---------------------+
//! | Fixed Header (42B)  |
//! +---------------------+
//! | Extensions (var)    |
//! +---------------------+
//! | Payload (var)       |
//! +---------------------+
//! ```
//!
//! Multi-byte integers are **big endian** (network byte order).

pub mod codec;
pub mod data;
pub mod error;
pub mod extensions;
pub mod fallback;
pub mod flags;
pub mod header;
pub mod hello;
pub mod packet_type;
pub mod tlv;

// ── Re-exports for convenience ────────────────────────────────────────────

pub use codec::{decode_packet, decode_packet_unchecked, decode_data_inline, DataPayloadRef, encode_data_packet_into, encode_ack_bitmap_into, encode_ctrl_packet_into, encode_ctrl_packet_with_payload_into, encode_packet, encode_packet_auto, Packet};
pub use data::{AckBitmap, AckMode, DataPayload, NackRange};
pub use error::{ErrorCode, ProtoError};
pub use extensions::{Extension, ExtensionType};
pub use flags::PacketFlags;
pub use header::{update_crc, PacketHeader, HEADER_SIZE, PROTOCOL_VERSION};
pub use hello::{
    decode_hello_ack_payload, encode_hello_ack_payload, encode_hello_ack_resumed,
    data_port_count, per_stream_ports,
    HelloAckMode, CAPABILITY_MAGIC, CAP_NONE, CAP_PER_STREAM_PORTS,
    HelloAckPayload,
};
pub use packet_type::PacketType;
pub use tlv::{Tlv, TlvIterator, TlvType};
