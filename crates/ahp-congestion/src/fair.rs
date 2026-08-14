// Favonius — high-performance file transfer over UDP
// Copyright (c) 2025-2026 Vantino SàRL
// SPDX-License-Identifier: Apache-2.0

//! AHP-Fair: conservative AIMD congestion control for shared networks.
//!
//! Designed to be TCP-friendly and avoid dominating shared links.
//! Uses traditional Additive Increase / Multiplicative Decrease with
//! linear startup (no exponential slow-start) and optional rate caps.

use std::time::{Duration, Instant};

use crate::metrics::RttEstimator;
use crate::pacer::Pacer;
use crate::{AckInfo, CongestionController};

/// Default MTU.
const MTU: usize = 1200;

/// Initial congestion window: conservative start.
const INITIAL_CWND: usize = 4 * MTU;

/// Minimum congestion window.
const MIN_CWND: usize = 2 * MTU;

/// Multiplicative decrease factor on loss (Reno-style).
const LOSS_DECREASE_FACTOR: f64 = 0.5;

/// AHP-Fair congestion controller.
#[derive(Debug)]
pub struct FairController {
    /// Current congestion window in bytes.
    cwnd: usize,
    /// RTT estimator.
    rtt: RttEstimator,
    /// Packet pacer.
    pacer: Pacer,
    /// Optional maximum rate cap (bytes per second). None means uncapped.
    max_rate: Option<u64>,
    /// Bytes delivered since last cwnd increase.
    delivered_since_increase: usize,
    /// Whether we're in a recovery period (waiting for an ACK past loss point).
    in_recovery: bool,
    /// Packet number at start of recovery.
    recovery_start_pkt: u64,
}

/// Queue budget above which loss counts as congestion rather than the
/// path's own: a fixed allowance plus a fraction of the base RTT.
///
/// This was a ratio, `srtt / min_rtt >= 1.25`. That form cannot work,
/// for the same reason A1's delay leg could not: about 7.3 ms of the
/// excess delay on any path is fixed overhead rather than queue --
/// serialisation, GSO batching, the 5 ms control tick -- and on a 25 ms
/// path that constant alone is a ratio of 1.29. The gate therefore fired
/// on every loss on short paths as soon as the controller could see a
/// truthful srtt, and AIMD collapsed: `fair` timed out on cross-country.
///
/// While srtt was fed the minimum RTT of each ACK batch the gate never
/// fired at all, which hid this. Fixing the feed exposed it immediately.
const LOSS_QUEUE_FIXED: Duration = Duration::from_millis(8);
const LOSS_QUEUE_FRACTION: f64 = 0.25;

impl FairController {

    /// Whether the queue exceeds the budget, i.e. whether a loss here
    /// should be read as congestion rather than as the path's own.
    fn queue_above_budget(&self) -> bool {
        match (self.rtt.smoothed_rtt(), self.rtt.min_rtt()) {
            (Some(s), Some(m)) => {
                let budget = LOSS_QUEUE_FIXED.as_secs_f64()
                    + LOSS_QUEUE_FRACTION * m.as_secs_f64();
                s.as_secs_f64() - m.as_secs_f64() >= budget
            }
            // No estimate yet: keep the historical behaviour.
            _ => true,
        }
    }

    pub fn new() -> Self {
        Self {
            cwnd: INITIAL_CWND,
            rtt: RttEstimator::new(),
            pacer: Pacer::new(0),
            max_rate: None,
            delivered_since_increase: 0,
            in_recovery: false,
            recovery_start_pkt: 0,
        }
    }

    /// Create a FairController with a maximum rate cap.
    pub fn with_max_rate(mut self, max_rate_bps: u64) -> Self {
        self.max_rate = Some(max_rate_bps);
        self
    }

    /// Set or remove the maximum rate cap.
    pub fn set_max_rate(&mut self, max_rate_bps: Option<u64>) {
        self.max_rate = max_rate_bps;
        self.update_pacing_rate();
    }

    fn update_pacing_rate(&mut self) {
        if let Some(srtt) = self.rtt.smoothed_rtt() {
            if !srtt.is_zero() {
                let mut rate = (self.cwnd as f64 / srtt.as_secs_f64()) as u64;
                // Apply rate cap.
                if let Some(max) = self.max_rate {
                    rate = rate.min(max);
                    // Also cap cwnd if rate-limited.
                    let max_cwnd = (max as f64 * srtt.as_secs_f64()) as usize;
                    if self.cwnd > max_cwnd && max_cwnd >= MIN_CWND {
                        self.cwnd = max_cwnd;
                    }
                }
                self.pacer.set_rate(rate);
            }
        }
    }
}

impl Default for FairController {
    fn default() -> Self {
        Self::new()
    }
}

impl CongestionController for FairController {
    fn on_packet_sent(&mut self, _packet_number: u64, bytes: usize, now: Instant) {
        self.pacer.on_packet_sent(bytes, now);
    }

    fn on_ack_received(&mut self, acked: &AckInfo, _now: Instant) {
        let delivered = acked.delivered_bytes as usize;

        // Check if we've exited recovery.
        if self.in_recovery {
            if acked.packet_number >= self.recovery_start_pkt {
                self.in_recovery = false;
                tracing::debug!("fair: exiting recovery");
            } else {
                return;
            }
        }

        // Linear increase (Reno-style): cwnd += MTU per RTT.
        // Per ACK: cwnd += MTU * delivered / cwnd.
        self.delivered_since_increase += delivered;
        if self.delivered_since_increase >= self.cwnd {
            self.delivered_since_increase -= self.cwnd;
            self.cwnd += MTU;
            tracing::trace!(cwnd = self.cwnd, "fair: cwnd increased");
        }

        self.update_pacing_rate();
    }

    fn on_packet_lost(&mut self, lost: &[u64], _now: Instant) {
        // Halve only when the loss came with a queue.
        //
        // AIMD with no congestion gate cannot hold a window on a path that
        // loses packets for reasons other than congestion: the equilibrium
        // is Mathis's `MSS / sqrt(p)`, about 20 KB at 0.5% loss, which on a
        // 25 ms path is roughly 1 MB/s no matter how much capacity there
        // is. Measured before this gate existed: cross-country stalled at
        // cwnd 29 KB and timed out at 43.8% of a 128 MB transfer.
        //
        // Classic gates its loss response on corroborating congestion
        // evidence and RL on `srtt/min_rtt >= LOSS_QUEUE_GATE`. Fair had
        // neither. Standing queue is the signal that separates the two
        // cases, and it is the same one rl.rs uses.
        if !self.queue_above_budget() {
            return;
        }
        if !lost.is_empty() && !self.in_recovery {
            let new_cwnd = ((self.cwnd as f64) * LOSS_DECREASE_FACTOR) as usize;
            self.cwnd = new_cwnd.max(MIN_CWND);
            self.in_recovery = true;
            self.recovery_start_pkt = lost.iter().copied().max().unwrap_or(0);
            tracing::debug!(cwnd = self.cwnd, "fair: loss detected, halved cwnd");
            self.update_pacing_rate();
        }
    }

    fn congestion_window(&self) -> usize {
        self.cwnd
    }

    fn send_rate(&self) -> Option<u64> {
        let rate = self.pacer.rate_bps();
        if rate > 0 {
            Some(rate)
        } else {
            None
        }
    }

    fn can_send(&self, bytes_in_flight: usize) -> bool {
        bytes_in_flight < self.cwnd
    }

    fn on_rtt_update(&mut self, rtt: Duration) {
        self.rtt.update(rtt);
        self.update_pacing_rate();
    }

    fn on_rtt_batch(&mut self, mean: Duration, min: Duration) {
        self.rtt.update_batch(mean, min);
    }

    fn pacing_interval(&self, packet_size: usize) -> Duration {
        self.pacer.pacing_interval(packet_size)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AckInfo;

    fn ack(pkt: u64, delivered: u64, rate: u64) -> AckInfo {
        AckInfo {
            packet_number: pkt,
            ack_delay: Duration::ZERO,
            delivered_bytes: delivered,
            delivery_rate: rate,
        }
    }

    #[test]
    fn initial_state() {
        let cc = FairController::new();
        assert_eq!(cc.congestion_window(), INITIAL_CWND);
        assert!(cc.can_send(0));
        assert!(!cc.can_send(INITIAL_CWND));
    }

    #[test]
    fn linear_increase() {
        let mut cc = FairController::new();
        let now = Instant::now();

        cc.on_rtt_update(Duration::from_millis(50));

        let initial = cc.congestion_window();

        // Send and ack enough to trigger increase.
        let mut t = now;
        for i in 0..20 {
            cc.on_packet_sent(i, MTU, t);
            t += Duration::from_millis(5);
        }
        for i in 0..20 {
            cc.on_ack_received(&ack(i, MTU as u64, 500_000), t);
            t += Duration::from_millis(5);
        }

        assert!(cc.congestion_window() > initial);
        // Increase should be modest (linear, not exponential).
        // At most a few MTU increases.
        let increase = cc.congestion_window() - initial;
        assert!(increase <= 10 * MTU);
    }

    #[test]
    fn loss_halves_cwnd() {
        let mut cc = FairController::new();
        let now = Instant::now();

        // A standing queue, so the loss reads as congestion. Without it
        // the gate correctly declines to halve and this test would be
        // asserting the ungated behaviour.
        cc.on_rtt_update(Duration::from_millis(50));
        for _ in 0..8 {
            cc.on_rtt_update(Duration::from_millis(150));
        }

        // Grow cwnd first.
        cc.cwnd = 20 * MTU;

        cc.on_packet_sent(1, MTU, now);
        cc.on_packet_lost(&[1], now + Duration::from_millis(100));

        let expected = ((20 * MTU) as f64 * LOSS_DECREASE_FACTOR) as usize;
        assert_eq!(cc.congestion_window(), expected);
        assert!(cc.in_recovery);
    }

    #[test]
    fn recovery_prevents_cwnd_growth() {
        let mut cc = FairController::new();
        let now = Instant::now();

        // A standing queue, so the loss reads as congestion. Without it
        // the gate correctly declines to halve and this test would be
        // asserting the ungated behaviour.
        cc.on_rtt_update(Duration::from_millis(50));
        for _ in 0..8 {
            cc.on_rtt_update(Duration::from_millis(150));
        }
        cc.cwnd = 20 * MTU;

        for i in 1..=10 {
            cc.on_packet_sent(i, MTU, now);
        }

        cc.on_packet_lost(&[5], now + Duration::from_millis(100));
        let cwnd_after_loss = cc.congestion_window();

        // ACK packets before recovery point: should not grow.
        cc.on_ack_received(
            &ack(3, MTU as u64, 500_000),
            now + Duration::from_millis(110),
        );
        assert_eq!(cc.congestion_window(), cwnd_after_loss);
    }

    #[test]
    fn recovery_exits_on_ack_past_loss() {
        let mut cc = FairController::new();
        let now = Instant::now();

        // A standing queue, so the loss reads as congestion. Without it
        // the gate correctly declines to halve and this test would be
        // asserting the ungated behaviour.
        cc.on_rtt_update(Duration::from_millis(50));
        for _ in 0..8 {
            cc.on_rtt_update(Duration::from_millis(150));
        }
        cc.cwnd = 20 * MTU;

        for i in 1..=10 {
            cc.on_packet_sent(i, MTU, now);
        }

        cc.on_packet_lost(&[5], now + Duration::from_millis(100));
        assert!(cc.in_recovery);

        cc.on_ack_received(
            &ack(6, MTU as u64, 500_000),
            now + Duration::from_millis(150),
        );
        assert!(!cc.in_recovery);
    }

    #[test]
    fn min_cwnd_respected() {
        let mut cc = FairController::new();
        let now = Instant::now();

        cc.cwnd = MIN_CWND;
        cc.on_packet_sent(1, MTU, now);
        cc.on_packet_lost(&[1], now + Duration::from_millis(100));

        assert!(cc.congestion_window() >= MIN_CWND);
    }

    #[test]
    fn max_rate_cap() {
        let mut cc = FairController::new().with_max_rate(100_000);
        cc.on_rtt_update(Duration::from_millis(50));

        // Even if cwnd would allow more, rate should be capped.
        cc.cwnd = 1_000_000;
        cc.update_pacing_rate();

        let rate = cc.send_rate();
        assert!(rate.is_some());
        assert!(rate.unwrap() <= 100_000);
    }

    #[test]
    fn set_max_rate_dynamically() {
        let mut cc = FairController::new();
        cc.on_rtt_update(Duration::from_millis(50));

        cc.set_max_rate(Some(50_000));
        cc.cwnd = 1_000_000;
        cc.update_pacing_rate();

        let rate = cc.send_rate().unwrap();
        assert!(rate <= 50_000);

        // Remove cap.
        cc.set_max_rate(None);
        cc.cwnd = 1_000_000;
        cc.update_pacing_rate();
        let rate = cc.send_rate().unwrap();
        assert!(rate > 50_000);
    }

    #[test]
    fn tcp_friendly_no_exponential_growth() {
        let mut cc = FairController::new();
        let now = Instant::now();

        cc.on_rtt_update(Duration::from_millis(50));

        // Start with a larger cwnd to make the linear-vs-exponential
        // distinction clearer: with Reno-style AIMD, cwnd grows by
        // 1 MTU per cwnd-worth of delivered data.
        cc.cwnd = 50 * MTU;
        let initial = cc.congestion_window();

        // Simulate delivering 100 packets worth of data.
        let mut t = now;
        for i in 0..100 {
            cc.on_packet_sent(i, MTU, t);
            t += Duration::from_millis(5);
        }
        for i in 0..100 {
            cc.on_ack_received(&ack(i, MTU as u64, 500_000), t);
            t += Duration::from_millis(5);
        }

        let growth = cc.congestion_window() - initial;
        // 100 acks * 1200 bytes = 120,000 delivered.
        // cwnd starts at 60,000, so we expect ~2 MTU increases (120000/60000).
        // With a truly exponential scheme we'd see growth >> initial.
        assert!(
            growth < initial / 2,
            "growth ({growth}) should be much less than initial/2 ({}) for linear AIMD",
            initial / 2
        );
        // But we should see some growth.
        assert!(growth > 0, "should have grown at least once");
    }
}
