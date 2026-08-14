// Favonius — high-performance file transfer over UDP
// Copyright (c) 2025-2026 Vantino SàRL
// SPDX-License-Identifier: Apache-2.0

//! Integration tests for observability: metrics collection, export, and logging.

use std::time::Duration;

use ahp_observability::logging::{log_event, TransferEvent};
use ahp_observability::metrics::{encode_prometheus_text, SessionMetrics};
use ahp_observability::TransferMetrics;

#[test]
fn metrics_full_lifecycle() {
    let metrics = TransferMetrics::new().unwrap();

    // Simulate a transfer.
    metrics.active_transfers.inc();
    metrics.bytes_transferred.inc_by(262144);
    metrics.packets_sent.inc_by(220);
    metrics.packets_lost.inc_by(3);
    metrics.retransmissions.inc_by(3);
    metrics.throughput_bps.set(50_000_000);
    metrics.rtt_histogram.observe(0.045);
    metrics.rtt_histogram.observe(0.052);
    metrics.rtt_histogram.observe(0.048);

    // Transfer completes.
    metrics.active_transfers.dec();

    // Export and verify.
    let text = encode_prometheus_text(&metrics.registry);

    assert!(text.contains("favonius_bytes_transferred_total 262144"));
    assert!(text.contains("favonius_packets_sent_total 220"));
    assert!(text.contains("favonius_packets_lost_total 3"));
    assert!(text.contains("favonius_retransmissions_total 3"));
    assert!(text.contains("favonius_active_transfers 0"));
    assert!(text.contains("favonius_throughput_bytes_per_second 50000000"));
    assert!(text.contains("favonius_rtt_seconds_count 3"));
    assert!(text.contains("# TYPE favonius_rtt_seconds histogram"));
    assert!(text.contains("# HELP favonius_bytes_transferred_total"));
}

#[test]
fn session_metrics_snapshot_and_throughput() {
    let sm = SessionMetrics::new("session-abc".to_string());

    // Simulate sends.
    for _ in 0..100 {
        sm.record_send(1200);
    }
    sm.record_loss(5);
    sm.record_ack();
    sm.record_ack();
    sm.update_rtt(45_000, 40_000);
    sm.update_congestion(131072, 50_000_000);

    let snap = sm.snapshot();
    assert_eq!(snap.bytes_sent, 120_000);
    assert_eq!(snap.packets_sent, 100);
    assert_eq!(snap.packets_lost, 5);
    assert_eq!(snap.packets_acked, 2);
    assert!((snap.loss_rate() - 0.05).abs() < 0.001);
    assert_eq!(snap.congestion_window, 131072);
    assert_eq!(snap.send_rate_bps, 50_000_000);
    // Throughput depends on elapsed time, just check it's reasonable.
    assert!(snap.throughput_bps > 0);
}

#[test]
fn logging_all_event_types() {
    let _ = tracing_subscriber::fmt()
        .with_test_writer()
        .try_init();

    let events = vec![
        TransferEvent::SessionStarted {
            session_id: "s1".into(),
            source: "/src".into(),
            destination: "/dst".into(),
            compression: true,
            encryption: true,
        },
        TransferEvent::HandshakeComplete {
            session_id: "s1".into(),
            rtt: Duration::from_millis(50),
        },
        TransferEvent::ChunkComplete {
            session_id: "s1".into(),
            chunk_index: 0,
            total_chunks: 4,
            bytes: 65536,
        },
        TransferEvent::PacketLoss {
            session_id: "s1".into(),
            lost_packets: vec![5, 8],
            loss_rate: 0.02,
        },
        TransferEvent::Retransmission {
            session_id: "s1".into(),
            packet_number: 5,
            bytes: 1200,
        },
        TransferEvent::CongestionUpdate {
            session_id: "s1".into(),
            cwnd: 65535,
            send_rate_bps: 10_000_000,
            smoothed_rtt_us: 50_000,
            loss_rate: 0.02,
        },
        TransferEvent::PerformanceSnapshot {
            session_id: "s1".into(),
            throughput_bps: 50_000_000,
            bytes_transferred: 200_000,
            packets_sent: 170,
            packets_lost: 3,
            smoothed_rtt_us: 45_000,
            cwnd: 131072,
        },
        TransferEvent::TransferComplete {
            session_id: "s1".into(),
            bytes_transferred: 262144,
            duration: Duration::from_millis(200),
            throughput_bps: 1_310_720,
        },
        TransferEvent::TransferFailed {
            session_id: "s2".into(),
            error: "timeout".into(),
            bytes_transferred: 0,
            duration: Duration::from_secs(30),
        },
    ];

    // All events should log without panic.
    for event in &events {
        log_event(event);
    }
}

#[test]
fn prometheus_export_empty_registry() {
    let metrics = TransferMetrics::new().unwrap();
    let text = encode_prometheus_text(&metrics.registry);

    // Should have type/help lines even with zero values.
    assert!(text.contains("# TYPE favonius_bytes_transferred_total counter"));
    assert!(text.contains("favonius_bytes_transferred_total 0"));
    assert!(text.contains("# TYPE favonius_active_transfers gauge"));
    assert!(text.contains("favonius_active_transfers 0"));
}

#[test]
fn multiple_sessions_independent() {
    let s1 = SessionMetrics::new("s1".into());
    let s2 = SessionMetrics::new("s2".into());

    s1.record_send(1000);
    s2.record_send(2000);
    s2.record_send(3000);

    assert_eq!(s1.snapshot().bytes_sent, 1000);
    assert_eq!(s1.snapshot().packets_sent, 1);
    assert_eq!(s2.snapshot().bytes_sent, 5000);
    assert_eq!(s2.snapshot().packets_sent, 2);
}
