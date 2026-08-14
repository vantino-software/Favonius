// Favonius — high-performance file transfer over UDP
// Copyright (c) 2025-2026 Vantino SàRL
// SPDX-License-Identifier: Apache-2.0

//! Favonius observability: Prometheus metrics and structured logging.
//!
//! Provides a centralized metrics registry for transfer performance counters,
//! gauges, and histograms. All metrics follow Prometheus naming conventions
//! and are exposed via the `/metrics` HTTP endpoint.

pub mod logging;
pub mod metrics;

use prometheus::{
    Histogram, HistogramOpts, IntCounter, IntGauge, Registry,
};

/// Collection of Prometheus metrics for monitoring transfer performance.
///
/// Create a single instance at startup via `TransferMetrics::new()` and
/// share it (via `Arc`) across the transfer engine, data plane, and API.
pub struct TransferMetrics {
    /// Registry that owns all metrics.
    pub registry: Registry,

    /// Total bytes transferred (sent + received) across all sessions.
    pub bytes_transferred: IntCounter,
    /// Total packets sent across all sessions.
    pub packets_sent: IntCounter,
    /// Total packets detected as lost.
    pub packets_lost: IntCounter,
    /// Total retransmission events.
    pub retransmissions: IntCounter,

    /// Number of currently active transfers.
    pub active_transfers: IntGauge,
    /// Current aggregate throughput in bytes per second.
    pub throughput_bps: IntGauge,

    /// Distribution of round-trip times (in seconds).
    pub rtt_histogram: Histogram,
}

/// The process-wide metrics instance.
///
/// `/metrics` is served by `ahp-api`, which used to build its own
/// `TransferMetrics` while the UDP data plane lived in `ahp-daemon` and
/// referenced none at all. The endpoint therefore reported
/// `favonius_bytes_transferred_total 0` no matter how much traffic moved —
/// measured at 0 after ~900 MB of transfers. Zeros from a working exporter
/// are worse than no exporter, because they read as "idle" rather than
/// "not wired".
///
/// Both sides now take the same instance from here.
pub fn global() -> &'static TransferMetrics {
    static GLOBAL: std::sync::OnceLock<TransferMetrics> = std::sync::OnceLock::new();
    GLOBAL.get_or_init(|| {
        TransferMetrics::new().expect("failed to register the global metrics")
    })
}

impl TransferMetrics {
    /// Create and register all metrics.
    ///
    /// Returns an error if metrics with the same names are already registered
    /// (should not happen in normal usage).
    pub fn new() -> Result<Self, prometheus::Error> {
        let registry = Registry::new();

        let bytes_transferred = IntCounter::new(
            "favonius_bytes_transferred_total",
            "Total bytes transferred across all sessions",
        )?;
        let packets_sent = IntCounter::new(
            "favonius_packets_sent_total",
            "Total packets sent across all sessions",
        )?;
        let packets_lost = IntCounter::new(
            "favonius_packets_lost_total",
            "Total packets detected as lost",
        )?;
        let retransmissions = IntCounter::new(
            "favonius_retransmissions_total",
            "Total retransmission events",
        )?;
        let active_transfers = IntGauge::new(
            "favonius_active_transfers",
            "Number of currently active transfers",
        )?;
        let throughput_bps = IntGauge::new(
            "favonius_throughput_bytes_per_second",
            "Current aggregate throughput in bytes per second",
        )?;
        let rtt_histogram = Histogram::with_opts(
            HistogramOpts::new(
                "favonius_rtt_seconds",
                "Distribution of round-trip times in seconds",
            )
            .buckets(vec![
                0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0,
            ]),
        )?;

        registry.register(Box::new(bytes_transferred.clone()))?;
        registry.register(Box::new(packets_sent.clone()))?;
        registry.register(Box::new(packets_lost.clone()))?;
        registry.register(Box::new(retransmissions.clone()))?;
        registry.register(Box::new(active_transfers.clone()))?;
        registry.register(Box::new(throughput_bps.clone()))?;
        registry.register(Box::new(rtt_histogram.clone()))?;

        Ok(Self {
            registry,
            bytes_transferred,
            packets_sent,
            packets_lost,
            retransmissions,
            active_transfers,
            throughput_bps,
            rtt_histogram,
        })
    }
}

/// Initialize the global metrics instance.
///
/// Call once at daemon startup. Returns the metrics handle to be shared
/// across subsystems.
pub fn init_metrics() -> Result<TransferMetrics, prometheus::Error> {
    TransferMetrics::new()
}
