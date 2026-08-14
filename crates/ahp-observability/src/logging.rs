// Favonius — high-performance file transfer over UDP
// Copyright (c) 2025-2026 Vantino SàRL
// SPDX-License-Identifier: Apache-2.0

//! Structured transfer event logging.
//!
//! Provides a `TransferEvent` enum and `log_event()` helper for emitting
//! structured log records via `tracing`. Each event carries typed fields
//! that can be filtered and queried in log aggregation systems.

use std::time::Duration;

/// Events emitted during a transfer lifecycle.
///
/// Each variant carries the minimum context needed to understand the event
/// in isolation when reading log output.
#[derive(Debug, Clone)]
pub enum TransferEvent {
    /// A new transfer session has started.
    SessionStarted {
        session_id: String,
        source: String,
        destination: String,
        compression: bool,
        encryption: bool,
    },

    /// Handshake completed, session keys derived.
    HandshakeComplete {
        session_id: String,
        rtt: Duration,
    },

    /// A chunk has been fully transmitted and acknowledged.
    ChunkComplete {
        session_id: String,
        chunk_index: u64,
        total_chunks: u64,
        bytes: u64,
    },

    /// Packet loss detected.
    PacketLoss {
        session_id: String,
        lost_packets: Vec<u64>,
        loss_rate: f64,
    },

    /// Retransmission triggered.
    Retransmission {
        session_id: String,
        packet_number: u64,
        bytes: u64,
    },

    /// Congestion controller state change.
    CongestionUpdate {
        session_id: String,
        cwnd: u64,
        send_rate_bps: u64,
        smoothed_rtt_us: u64,
        loss_rate: f64,
    },

    /// Periodic performance snapshot.
    PerformanceSnapshot {
        session_id: String,
        throughput_bps: u64,
        bytes_transferred: u64,
        packets_sent: u64,
        packets_lost: u64,
        smoothed_rtt_us: u64,
        cwnd: u64,
    },

    /// Transfer completed successfully.
    TransferComplete {
        session_id: String,
        bytes_transferred: u64,
        duration: Duration,
        throughput_bps: u64,
    },

    /// Transfer failed.
    TransferFailed {
        session_id: String,
        error: String,
        bytes_transferred: u64,
        duration: Duration,
    },
}

/// Emit a structured log record for a transfer event.
///
/// Uses `tracing` spans and events at the appropriate severity level.
pub fn log_event(event: &TransferEvent) {
    match event {
        TransferEvent::SessionStarted {
            session_id,
            source,
            destination,
            compression,
            encryption,
        } => {
            tracing::info!(
                session_id = %session_id,
                source = %source,
                destination = %destination,
                compression = compression,
                encryption = encryption,
                "transfer session started"
            );
        }

        TransferEvent::HandshakeComplete { session_id, rtt } => {
            tracing::info!(
                session_id = %session_id,
                rtt_ms = rtt.as_millis() as u64,
                "handshake complete"
            );
        }

        TransferEvent::ChunkComplete {
            session_id,
            chunk_index,
            total_chunks,
            bytes,
        } => {
            tracing::debug!(
                session_id = %session_id,
                chunk_index = chunk_index,
                total_chunks = total_chunks,
                bytes = bytes,
                "chunk complete"
            );
        }

        TransferEvent::PacketLoss {
            session_id,
            lost_packets,
            loss_rate,
        } => {
            tracing::warn!(
                session_id = %session_id,
                lost_count = lost_packets.len(),
                loss_rate = loss_rate,
                "packet loss detected"
            );
        }

        TransferEvent::Retransmission {
            session_id,
            packet_number,
            bytes,
        } => {
            tracing::debug!(
                session_id = %session_id,
                packet_number = packet_number,
                bytes = bytes,
                "retransmission"
            );
        }

        TransferEvent::CongestionUpdate {
            session_id,
            cwnd,
            send_rate_bps,
            smoothed_rtt_us,
            loss_rate,
        } => {
            tracing::debug!(
                session_id = %session_id,
                cwnd = cwnd,
                send_rate_bps = send_rate_bps,
                smoothed_rtt_us = smoothed_rtt_us,
                loss_rate = loss_rate,
                "congestion state update"
            );
        }

        TransferEvent::PerformanceSnapshot {
            session_id,
            throughput_bps,
            bytes_transferred,
            packets_sent,
            packets_lost,
            smoothed_rtt_us,
            cwnd,
        } => {
            tracing::info!(
                session_id = %session_id,
                throughput_mibps = (*throughput_bps as f64) / (1024.0 * 1024.0),
                bytes_transferred = bytes_transferred,
                packets_sent = packets_sent,
                packets_lost = packets_lost,
                smoothed_rtt_us = smoothed_rtt_us,
                cwnd = cwnd,
                "performance snapshot"
            );
        }

        TransferEvent::TransferComplete {
            session_id,
            bytes_transferred,
            duration,
            throughput_bps,
        } => {
            tracing::info!(
                session_id = %session_id,
                bytes_transferred = bytes_transferred,
                duration_ms = duration.as_millis() as u64,
                throughput_mibps = (*throughput_bps as f64) / (1024.0 * 1024.0),
                "transfer complete"
            );
        }

        TransferEvent::TransferFailed {
            session_id,
            error,
            bytes_transferred,
            duration,
        } => {
            tracing::error!(
                session_id = %session_id,
                error = %error,
                bytes_transferred = bytes_transferred,
                duration_ms = duration.as_millis() as u64,
                "transfer failed"
            );
        }
    }
}

/// Initialize the tracing subscriber with structured JSON/text output.
///
/// Call once at application startup. `env_filter` sets the default filter
/// (e.g. "info", "ahp_daemon=debug").
pub fn init_logging(env_filter: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(env_filter)),
        )
        .with_target(true)
        .with_thread_ids(true)
        .with_file(true)
        .with_line_number(true)
        .try_init()
        .map_err(|e| format!("failed to init logging: {}", e))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn log_event_session_started() {
        let _ = tracing_subscriber::fmt()
            .with_test_writer()
            .try_init();

        log_event(&TransferEvent::SessionStarted {
            session_id: "test-001".to_string(),
            source: "/tmp/src".to_string(),
            destination: "/tmp/dst".to_string(),
            compression: true,
            encryption: true,
        });
    }

    #[test]
    fn log_event_chunk_complete() {
        let _ = tracing_subscriber::fmt()
            .with_test_writer()
            .try_init();

        log_event(&TransferEvent::ChunkComplete {
            session_id: "test-001".to_string(),
            chunk_index: 3,
            total_chunks: 10,
            bytes: 65536,
        });
    }

    #[test]
    fn log_event_transfer_complete() {
        let _ = tracing_subscriber::fmt()
            .with_test_writer()
            .try_init();

        log_event(&TransferEvent::TransferComplete {
            session_id: "test-001".to_string(),
            bytes_transferred: 262144,
            duration: Duration::from_millis(150),
            throughput_bps: 1_747_626,
        });
    }

    #[test]
    fn log_event_transfer_failed() {
        let _ = tracing_subscriber::fmt()
            .with_test_writer()
            .try_init();

        log_event(&TransferEvent::TransferFailed {
            session_id: "test-002".to_string(),
            error: "connection reset".to_string(),
            bytes_transferred: 1024,
            duration: Duration::from_millis(500),
        });
    }

    #[test]
    fn log_event_congestion_update() {
        let _ = tracing_subscriber::fmt()
            .with_test_writer()
            .try_init();

        log_event(&TransferEvent::CongestionUpdate {
            session_id: "test-001".to_string(),
            cwnd: 65535,
            send_rate_bps: 10_000_000,
            smoothed_rtt_us: 50_000,
            loss_rate: 0.01,
        });
    }

    #[test]
    fn log_event_packet_loss() {
        let _ = tracing_subscriber::fmt()
            .with_test_writer()
            .try_init();

        log_event(&TransferEvent::PacketLoss {
            session_id: "test-001".to_string(),
            lost_packets: vec![5, 8, 12],
            loss_rate: 0.03,
        });
    }

    #[test]
    fn log_event_performance_snapshot() {
        let _ = tracing_subscriber::fmt()
            .with_test_writer()
            .try_init();

        log_event(&TransferEvent::PerformanceSnapshot {
            session_id: "test-001".to_string(),
            throughput_bps: 50_000_000,
            bytes_transferred: 1_000_000,
            packets_sent: 850,
            packets_lost: 3,
            smoothed_rtt_us: 45_000,
            cwnd: 131072,
        });
    }
}
