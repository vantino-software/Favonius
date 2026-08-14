// Favonius — high-performance file transfer over UDP
// Copyright (c) 2025-2026 Vantino SàRL
// SPDX-License-Identifier: Apache-2.0

//! Linux backends: GSO (preferred) and sendmmsg fallback.

mod gso;
mod recvmmsg;
mod sendmmsg;

pub use gso::{GsoBatchSender, probe_gso};
pub use recvmmsg::RecvmmsgReceiver;
pub use sendmmsg::SendmmsgBatchSender;
