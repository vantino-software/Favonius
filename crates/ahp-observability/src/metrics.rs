// Favonius — high-performance file transfer over UDP
// Copyright (c) 2025-2026 Vantino SàRL
// SPDX-License-Identifier: Apache-2.0

//! Per-session metrics collection and Prometheus text format export.
//!
//! Provides `SessionMetrics` for tracking individual transfer sessions and
//! `encode_prometheus_text` for exporting all registered metrics in the
//! Prometheus exposition text format.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use prometheus::{Encoder, Registry, TextEncoder};

/// Per-session metrics that track the progress and health of a single transfer.
///
/// These are lightweight counters local to a session; aggregate values are
/// flushed to the shared `TransferMetrics` periodically or on completion.
#[derive(Debug)]
pub struct SessionMetrics {
    /// Session / transfer identifier.
    pub session_id: String,
    /// When the session started.
    pub start_time: Instant,
    /// Bytes sent by this session.
    pub bytes_sent: AtomicU64,
    /// Bytes received by this session.
    pub bytes_received: AtomicU64,
    /// Packets sent.
    pub packets_sent: AtomicU64,
    /// Packets acknowledged.
    pub packets_acked: AtomicU64,
    /// Packets detected as lost.
    pub packets_lost: AtomicU64,
    /// Retransmissions triggered.
    pub retransmissions: AtomicU64,
    /// Latest smoothed RTT in microseconds.
    pub smoothed_rtt_us: AtomicU64,
    /// Minimum RTT observed in microseconds.
    pub min_rtt_us: AtomicU64,
    /// Current congestion window in bytes.
    pub congestion_window: AtomicU64,
    /// Current send rate in bytes per second.
    pub send_rate_bps: AtomicU64,
}

impl SessionMetrics {
    /// Create a new session metrics tracker.
    pub fn new(session_id: String) -> Self {
        Self {
            session_id,
            start_time: Instant::now(),
            bytes_sent: AtomicU64::new(0),
            bytes_received: AtomicU64::new(0),
            packets_sent: AtomicU64::new(0),
            packets_acked: AtomicU64::new(0),
            packets_lost: AtomicU64::new(0),
            retransmissions: AtomicU64::new(0),
            smoothed_rtt_us: AtomicU64::new(0),
            min_rtt_us: AtomicU64::new(0),
            congestion_window: AtomicU64::new(0),
            send_rate_bps: AtomicU64::new(0),
        }
    }

    /// Record bytes sent.
    pub fn record_send(&self, bytes: u64) {
        self.bytes_sent.fetch_add(bytes, Ordering::Relaxed);
        self.packets_sent.fetch_add(1, Ordering::Relaxed);
    }

    /// Record bytes received.
    pub fn record_receive(&self, bytes: u64) {
        self.bytes_received.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Record a successful ACK.
    pub fn record_ack(&self) {
        self.packets_acked.fetch_add(1, Ordering::Relaxed);
    }

    /// Record packet losses.
    pub fn record_loss(&self, count: u64) {
        self.packets_lost.fetch_add(count, Ordering::Relaxed);
    }

    /// Record a retransmission.
    pub fn record_retransmission(&self) {
        self.retransmissions.fetch_add(1, Ordering::Relaxed);
    }

    /// Update the RTT measurement (in microseconds).
    pub fn update_rtt(&self, smoothed_us: u64, min_us: u64) {
        self.smoothed_rtt_us.store(smoothed_us, Ordering::Relaxed);
        self.min_rtt_us.store(min_us, Ordering::Relaxed);
    }

    /// Update the congestion state snapshot.
    pub fn update_congestion(&self, cwnd: u64, rate_bps: u64) {
        self.congestion_window.store(cwnd, Ordering::Relaxed);
        self.send_rate_bps.store(rate_bps, Ordering::Relaxed);
    }

    /// Elapsed duration since session start.
    pub fn elapsed(&self) -> std::time::Duration {
        self.start_time.elapsed()
    }

    /// Compute current throughput in bytes per second.
    pub fn throughput_bps(&self) -> u64 {
        let elapsed = self.elapsed().as_secs_f64();
        if elapsed > 0.0 {
            (self.bytes_sent.load(Ordering::Relaxed) as f64 / elapsed) as u64
        } else {
            0
        }
    }

    /// Snapshot of all counters for logging or display.
    pub fn snapshot(&self) -> SessionSnapshot {
        SessionSnapshot {
            session_id: self.session_id.clone(),
            elapsed_ms: self.elapsed().as_millis() as u64,
            bytes_sent: self.bytes_sent.load(Ordering::Relaxed),
            bytes_received: self.bytes_received.load(Ordering::Relaxed),
            packets_sent: self.packets_sent.load(Ordering::Relaxed),
            packets_acked: self.packets_acked.load(Ordering::Relaxed),
            packets_lost: self.packets_lost.load(Ordering::Relaxed),
            retransmissions: self.retransmissions.load(Ordering::Relaxed),
            smoothed_rtt_us: self.smoothed_rtt_us.load(Ordering::Relaxed),
            min_rtt_us: self.min_rtt_us.load(Ordering::Relaxed),
            congestion_window: self.congestion_window.load(Ordering::Relaxed),
            send_rate_bps: self.send_rate_bps.load(Ordering::Relaxed),
            throughput_bps: self.throughput_bps(),
        }
    }
}

/// Immutable snapshot of session metrics at a point in time.
#[derive(Debug, Clone)]
pub struct SessionSnapshot {
    pub session_id: String,
    pub elapsed_ms: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub packets_sent: u64,
    pub packets_acked: u64,
    pub packets_lost: u64,
    pub retransmissions: u64,
    pub smoothed_rtt_us: u64,
    pub min_rtt_us: u64,
    pub congestion_window: u64,
    pub send_rate_bps: u64,
    pub throughput_bps: u64,
}

impl SessionSnapshot {
    /// Loss rate as a fraction [0.0, 1.0].
    pub fn loss_rate(&self) -> f64 {
        if self.packets_sent == 0 {
            0.0
        } else {
            self.packets_lost as f64 / self.packets_sent as f64
        }
    }
}

/// Encode the contents of a Prometheus `Registry` into the text exposition format.
///
/// Delegates to the `prometheus` crate's [`TextEncoder`], which handles
/// label-value escaping and summary/histogram rendering correctly.
///
/// Returns a `String` suitable for serving at the `/metrics` HTTP endpoint.
/// Returns an empty string if encoding fails (should not happen in practice).
pub fn encode_prometheus_text(registry: &Registry) -> String {
    let metric_families = registry.gather();
    let encoder = TextEncoder::new();
    let mut buf = Vec::new();
    if let Err(e) = encoder.encode(&metric_families, &mut buf) {
        tracing::warn!(error = %e, "failed to encode Prometheus metrics");
        return String::new();
    }
    String::from_utf8(buf).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::TransferMetrics;

    #[test]
    fn session_metrics_basic_operations() {
        let sm = SessionMetrics::new("test-session-1".to_string());

        sm.record_send(1200);
        sm.record_send(1200);
        sm.record_receive(2400);
        sm.record_ack();
        sm.record_loss(1);
        sm.record_retransmission();
        sm.update_rtt(50_000, 40_000);
        sm.update_congestion(65535, 1_000_000);

        let snap = sm.snapshot();
        assert_eq!(snap.session_id, "test-session-1");
        assert_eq!(snap.bytes_sent, 2400);
        assert_eq!(snap.bytes_received, 2400);
        assert_eq!(snap.packets_sent, 2);
        assert_eq!(snap.packets_acked, 1);
        assert_eq!(snap.packets_lost, 1);
        assert_eq!(snap.retransmissions, 1);
        assert_eq!(snap.smoothed_rtt_us, 50_000);
        assert_eq!(snap.min_rtt_us, 40_000);
        assert_eq!(snap.congestion_window, 65535);
        assert_eq!(snap.send_rate_bps, 1_000_000);
    }

    #[test]
    fn session_snapshot_loss_rate() {
        let sm = SessionMetrics::new("loss-test".to_string());
        for _ in 0..100 {
            sm.record_send(100);
        }
        sm.record_loss(5);

        let snap = sm.snapshot();
        assert!((snap.loss_rate() - 0.05).abs() < 0.001);
    }

    #[test]
    fn session_snapshot_loss_rate_zero_packets() {
        let sm = SessionMetrics::new("empty".to_string());
        let snap = sm.snapshot();
        assert_eq!(snap.loss_rate(), 0.0);
    }

    #[test]
    fn prometheus_text_export() {
        let metrics = TransferMetrics::new().unwrap();
        metrics.bytes_transferred.inc_by(42000);
        metrics.packets_sent.inc_by(35);
        metrics.packets_lost.inc_by(2);
        metrics.active_transfers.set(3);
        metrics.rtt_histogram.observe(0.05);

        let text = encode_prometheus_text(&metrics.registry);
        assert!(text.contains("favonius_bytes_transferred_total 42000"));
        assert!(text.contains("favonius_packets_sent_total 35"));
        assert!(text.contains("favonius_packets_lost_total 2"));
        assert!(text.contains("favonius_active_transfers 3"));
        assert!(text.contains("favonius_rtt_seconds_count 1"));
        assert!(text.contains("# TYPE favonius_rtt_seconds histogram"));
    }

    #[test]
    fn prometheus_text_histogram_buckets() {
        let metrics = TransferMetrics::new().unwrap();
        metrics.rtt_histogram.observe(0.001);
        metrics.rtt_histogram.observe(0.01);
        metrics.rtt_histogram.observe(0.1);

        let text = encode_prometheus_text(&metrics.registry);
        assert!(text.contains("favonius_rtt_seconds_bucket{le=\"0.001\"}"));
        assert!(text.contains("favonius_rtt_seconds_bucket{le=\"+Inf\"}"));
        assert!(text.contains("favonius_rtt_seconds_sum"));
        assert!(text.contains("favonius_rtt_seconds_count 3"));
    }

    #[test]
    fn prometheus_text_escapes_label_values() {
        use prometheus::{GaugeVec, Opts, Registry};

        let registry = Registry::new();
        let gauge = GaugeVec::new(
            Opts::new("test_labelled_gauge", "gauge with tricky labels"),
            &["session"],
        )
        .unwrap();
        registry.register(Box::new(gauge.clone())).unwrap();

        // Label value containing a quote, a backslash and a newline.
        let tricky = "sess\"ion\\\n01";
        gauge.with_label_values(&[tricky]).set(7.0);

        let text = encode_prometheus_text(&registry);
        assert!(
            text.contains("session=\"sess\\\"ion\\\\\\n01\""),
            "label value not escaped correctly:\n{}",
            text
        );
        // The raw newline inside the label value must not leak into the
        // output as a line break inside the sample line.
        let sample_line = text
            .lines()
            .find(|l| l.starts_with("test_labelled_gauge{"))
            .expect("sample line missing");
        assert!(sample_line.ends_with(" 7"));
    }

    #[test]
    fn prometheus_text_renders_summary() {
        // The crate has no native Summary metric, but a custom collector can
        // still return a SUMMARY family — the branch the old hand-rolled
        // encoder rendered as an invalid bare value.
        use prometheus::core::{Collector, Desc};
        use prometheus::proto::{
            LabelPair, Metric, MetricFamily, MetricType, Quantile, Summary,
        };
        use prometheus::Registry;

        struct FixedCollector(MetricFamily);
        impl Collector for FixedCollector {
            fn desc(&self) -> Vec<&Desc> {
                Vec::new() // unchecked collector
            }
            fn collect(&self) -> Vec<MetricFamily> {
                vec![self.0.clone()]
            }
        }

        let mut q50 = Quantile::new();
        q50.set_quantile(0.5);
        q50.set_value(0.25);
        let mut summary = Summary::new();
        summary.set_sample_count(2);
        summary.set_sample_sum(1.0);
        summary.mut_quantile().push(q50);

        let mut label = LabelPair::new();
        label.set_name("path".to_string());
        label.set_value("we\"ird\\pa\nth".to_string());
        let mut metric = Metric::new();
        metric.set_summary(summary);
        metric.mut_label().push(label);

        let mut family = MetricFamily::new();
        family.set_name("test_summary_seconds".to_string());
        family.set_help("a summary metric".to_string());
        family.set_field_type(MetricType::SUMMARY);
        family.mut_metric().push(metric);

        let registry = Registry::new();
        registry.register(Box::new(FixedCollector(family))).unwrap();

        let text = encode_prometheus_text(&registry);
        assert!(text.contains("# TYPE test_summary_seconds summary"), "{}", text);
        assert!(
            text.contains("test_summary_seconds{path=\"we\\\"ird\\\\pa\\nth\",quantile=\"0.5\"} 0.25"),
            "{}",
            text
        );
        assert!(text.contains("test_summary_seconds_sum{path=\"we\\\"ird\\\\pa\\nth\"} 1"), "{}", text);
        assert!(text.contains("test_summary_seconds_count{path=\"we\\\"ird\\\\pa\\nth\"} 2"), "{}", text);
    }
}
