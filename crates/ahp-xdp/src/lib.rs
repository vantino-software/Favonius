// Favonius — high-performance file transfer over UDP
// Copyright (c) 2025-2026 Vantino SàRL
// SPDX-License-Identifier: Apache-2.0

//! AF_XDP zero-copy transmit path for Favonius.
//!
//! Bypasses the kernel network stack by using XDP sockets.
//! Packets are constructed as raw Ethernet + IP + UDP + AHP frames
//! in a shared UMEM region between userspace and the NIC driver.
//!
//! Only the TX path is implemented: the socket owns a TX ring and a
//! completion ring. The receive path is not implemented — the production
//! receiver uses `recvmmsg` via `ahp-platform-net`. Accordingly, this
//! crate contains no BPF loading code; if an interface needs an XDP
//! program attached, do it externally (`ip link set dev <if> xdp ...`).
//!
//! Requires:
//! - Linux 4.18+ (AF_XDP sockets)
//! - Linux 5.4+ for NIC zero-copy mode
//! - CAP_NET_ADMIN or root
//! - NIC with XDP support (Intel i40e/ice, Mellanox mlx5, Broadcom bnxt)

pub mod umem;
pub mod socket;
pub mod packet;
pub mod error;

pub use error::XdpError;
pub use socket::XdpSocket;
pub use umem::Umem;
pub use packet::PacketBuilder;
