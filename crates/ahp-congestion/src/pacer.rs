// Favonius — high-performance file transfer over UDP
// Copyright (c) 2025-2026 Vantino SàRL
// SPDX-License-Identifier: Apache-2.0

//! Packet pacing: spreads packet transmissions evenly to avoid bursts.

use std::time::{Duration, Instant};

/// Default burst allowance in packets.
const DEFAULT_BURST_ALLOWANCE: usize = 10;

/// Default MTU for burst size calculation.
const DEFAULT_MTU: usize = 1200;

/// Packet pacer that regulates send timing based on a target rate.
#[derive(Debug)]
pub struct Pacer {
    /// Target send rate in bytes per second.
    rate_bps: u64,
    /// Timestamp of last packet sent.
    last_send_time: Option<Instant>,
    /// Accumulated credit (bytes) from elapsed time not yet used.
    credit: f64,
    /// Maximum burst size in bytes.
    burst_allowance: usize,
    /// MTU for calculations.
    mtu: usize,
}

impl Pacer {
    /// Create a new pacer with the given initial rate.
    pub fn new(rate_bps: u64) -> Self {
        Self {
            rate_bps,
            last_send_time: None,
            credit: 0.0,
            burst_allowance: DEFAULT_BURST_ALLOWANCE * DEFAULT_MTU,
            mtu: DEFAULT_MTU,
        }
    }

    /// Create a pacer with custom burst allowance (in packets).
    pub fn with_burst_allowance(mut self, packets: usize) -> Self {
        self.burst_allowance = packets * self.mtu;
        self
    }

    /// Create a pacer with custom MTU.
    pub fn with_mtu(mut self, mtu: usize) -> Self {
        self.mtu = mtu;
        self.burst_allowance = DEFAULT_BURST_ALLOWANCE * mtu;
        self
    }

    /// Update the send rate.
    pub fn set_rate(&mut self, rate_bps: u64) {
        self.rate_bps = rate_bps;
        tracing::trace!(rate_bps, "pacer rate updated");
    }

    /// Record that a packet of the given size was sent.
    pub fn on_packet_sent(&mut self, bytes: usize, now: Instant) {
        // Accumulate credit from time elapsed since last send.
        self.accumulate_credit(now);
        // Deduct the sent bytes from credit.
        self.credit -= bytes as f64;
        if self.credit < -(self.burst_allowance as f64) {
            self.credit = -(self.burst_allowance as f64);
        }
        self.last_send_time = Some(now);
    }

    /// Compute when the next packet of the given size can be sent.
    ///
    /// Returns `None` if the packet can be sent immediately (enough credit
    /// or burst allowance). Returns `Some(instant)` if the caller must
    /// wait until that time.
    pub fn next_send_time(&self, packet_size: usize, now: Instant) -> Option<Instant> {
        if self.rate_bps == 0 {
            return None;
        }

        let mut credit = self.credit;

        // Add credit from elapsed time.
        if let Some(last) = self.last_send_time {
            if now > last {
                let elapsed = now.duration_since(last).as_secs_f64();
                credit += elapsed * self.rate_bps as f64;
                if credit > self.burst_allowance as f64 {
                    credit = self.burst_allowance as f64;
                }
            }
        } else {
            // No packets sent yet; allow immediate send.
            return None;
        }

        let needed = packet_size as f64;
        if credit >= needed {
            None
        } else {
            let deficit = needed - credit;
            let wait_secs = deficit / self.rate_bps as f64;
            Some(now + Duration::from_secs_f64(wait_secs))
        }
    }

    /// Whether a packet of the given size can be sent now.
    pub fn can_send_now(&self, packet_size: usize, now: Instant) -> bool {
        self.next_send_time(packet_size, now).is_none()
    }

    /// Compute the pacing interval for a given packet size at the current rate.
    pub fn pacing_interval(&self, packet_size: usize) -> Duration {
        if self.rate_bps == 0 {
            return Duration::ZERO;
        }
        Duration::from_secs_f64(packet_size as f64 / self.rate_bps as f64)
    }

    /// Current rate in bytes per second.
    pub fn rate_bps(&self) -> u64 {
        self.rate_bps
    }

    fn accumulate_credit(&mut self, now: Instant) {
        if let Some(last) = self.last_send_time {
            if now > last {
                let elapsed = now.duration_since(last).as_secs_f64();
                self.credit += elapsed * self.rate_bps as f64;
                // Cap credit at burst allowance.
                if self.credit > self.burst_allowance as f64 {
                    self.credit = self.burst_allowance as f64;
                }
            }
        } else {
            // First packet: start with full burst allowance.
            self.credit = self.burst_allowance as f64;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pacer_first_packet_immediate() {
        let pacer = Pacer::new(1_000_000);
        let now = Instant::now();
        assert!(pacer.can_send_now(1200, now));
        assert!(pacer.next_send_time(1200, now).is_none());
    }

    #[test]
    fn pacer_rate_limiting() {
        let mut pacer = Pacer::new(12_000); // 12KB/s = 10 packets/s at 1200B
        let now = Instant::now();

        // Send burst of packets to exhaust credit.
        pacer.on_packet_sent(1200, now);
        for i in 0..DEFAULT_BURST_ALLOWANCE {
            pacer.on_packet_sent(1200, now + Duration::from_micros(i as u64));
        }

        // Next packet should be delayed.
        let check_time = now + Duration::from_millis(1);
        let next = pacer.next_send_time(1200, check_time);
        // At 12KB/s with burst exhausted, we should need to wait.
        assert!(next.is_some());
    }

    #[test]
    fn pacer_credit_accumulates() {
        let mut pacer = Pacer::new(1_200_000); // 1.2MB/s
        let now = Instant::now();

        pacer.on_packet_sent(1200, now);

        // Exhaust credit.
        for i in 0..DEFAULT_BURST_ALLOWANCE {
            pacer.on_packet_sent(1200, now + Duration::from_micros(i as u64));
        }

        // Wait 10ms: should accumulate 12,000 bytes of credit.
        let later = now + Duration::from_millis(10);
        assert!(pacer.can_send_now(1200, later));
    }

    #[test]
    fn pacer_pacing_interval() {
        let pacer = Pacer::new(1_200_000); // 1.2MB/s
        let interval = pacer.pacing_interval(1200);
        // 1200 / 1_200_000 = 1ms
        assert_eq!(interval, Duration::from_millis(1));
    }

    #[test]
    fn pacer_set_rate() {
        let mut pacer = Pacer::new(1_000_000);
        pacer.set_rate(2_000_000);
        assert_eq!(pacer.rate_bps(), 2_000_000);
    }

    #[test]
    fn pacer_zero_rate() {
        let pacer = Pacer::new(0);
        let now = Instant::now();
        // Zero rate means no pacing restriction.
        assert!(pacer.can_send_now(1200, now));
        assert_eq!(pacer.pacing_interval(1200), Duration::ZERO);
    }

    #[test]
    fn pacer_custom_burst() {
        let pacer = Pacer::new(100_000).with_burst_allowance(5);
        // burst_allowance = 5 * 1200 = 6000 bytes
        assert_eq!(pacer.burst_allowance, 5 * DEFAULT_MTU);
    }
}
