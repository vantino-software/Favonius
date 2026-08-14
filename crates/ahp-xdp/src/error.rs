// Favonius — high-performance file transfer over UDP
// Copyright (c) 2025-2026 Vantino SàRL
// SPDX-License-Identifier: Apache-2.0

#[derive(Debug, thiserror::Error)]
pub enum XdpError {
    #[error("UMEM allocation failed: {0}")]
    Umem(String),
    #[error("socket creation failed: {0}")]
    Socket(String),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("ring full")]
    RingFull,
    #[error("no frames available")]
    NoFrames,
}
