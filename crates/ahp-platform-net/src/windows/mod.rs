// Favonius — high-performance file transfer over UDP
// Copyright (c) 2025-2026 Vantino SàRL
// SPDX-License-Identifier: Apache-2.0

//! Windows backends: USO (preferred) and WSASendTo loop fallback.

mod uso;
mod sendto_loop;
mod recvfrom;

pub use uso::{UsoBatchSender, probe_uso};
pub use sendto_loop::SendtoLoopSender;
pub use recvfrom::RecvfromReceiver;
