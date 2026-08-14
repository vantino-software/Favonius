// Favonius — high-performance file transfer over UDP
// Copyright (c) 2025-2026 Vantino SàRL
// SPDX-License-Identifier: Apache-2.0

//! Path metrics tracking: RTT estimation, loss tracking, bandwidth estimation.

use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

/// Standard EWMA-based RTT estimator following RFC 6298.
#[derive(Debug)]
pub struct RttEstimator {
    /// Smoothed round-trip time.
    smoothed_rtt: Option<Duration>,
    /// RTT variance (mean deviation).
    rtt_var: Duration,
    /// Minimum RTT observed.
    min_rtt: Option<Duration>,
    /// Most recent RTT sample.
    latest_rtt: Duration,
}

impl RttEstimator {
    pub fn new() -> Self {
        Self {
            smoothed_rtt: None,
            rtt_var: Duration::ZERO,
            min_rtt: None,
            latest_rtt: Duration::ZERO,
        }
    }

    /// Update from an ACK batch, using a different sample for each of the
    /// two quantities this estimator holds.
    ///
    /// `min` drives the minimum RTT and `mean` drives the smoothed RTT and
    /// its variance. They are different questions: the minimum wants the
    /// least-queued sample available, and the smoothed value wants what a
    /// packet actually experienced.
    ///
    /// Feeding one number to both -- the batch minimum -- is what
    /// `process_feedback` did, and it made every delay-based congestion
    /// signal in this codebase inert. A controller's srtt read 25.7 ms
    /// while the transfer's mean RTT was 56.2 ms, so Classic's `queueing`
    /// evidence could never fire and its pacing rate, `cwnd / srtt`,
    /// divided by a number less than half the truth: it commanded ~235
    /// Mbit and achieved 127 Mbit into a 100 Mbit link.
    pub fn update_batch(&mut self, mean: Duration, min: Duration) {
        self.update(mean);
        // The minimum is the one quantity that must not carry queueing.
        self.min_rtt = Some(match self.min_rtt {
            Some(m) => m.min(min),
            None => min,
        });
    }

    /// Update the estimator with a new RTT sample.
    pub fn update(&mut self, rtt: Duration) {
        self.latest_rtt = rtt;

        // Update min_rtt
        self.min_rtt = Some(match self.min_rtt {
            Some(min) => min.min(rtt),
            None => rtt,
        });

        match self.smoothed_rtt {
            None => {
                // First sample: initialize per RFC 6298.
                self.smoothed_rtt = Some(rtt);
                self.rtt_var = rtt / 2;
            }
            Some(srtt) => {
                // EWMA update:
                //   rtt_var = (1 - 1/4) * rtt_var + 1/4 * |srtt - rtt|
                //   srtt    = (1 - 1/8) * srtt    + 1/8 * rtt
                let diff = if srtt > rtt {
                    srtt - rtt
                } else {
                    rtt - srtt
                };
                self.rtt_var = (self.rtt_var * 3 + diff) / 4;
                self.smoothed_rtt = Some((srtt * 7 + rtt) / 8);
            }
        }
    }

    pub fn smoothed_rtt(&self) -> Option<Duration> {
        self.smoothed_rtt
    }

    pub fn rtt_var(&self) -> Duration {
        self.rtt_var
    }

    pub fn min_rtt(&self) -> Option<Duration> {
        self.min_rtt
    }

    pub fn latest_rtt(&self) -> Duration {
        self.latest_rtt
    }

    /// Retransmission timeout: srtt + max(4 * rtt_var, 1ms), minimum 200ms.
    /// With no samples yet, the conservative RFC 6298 initial value of 1s.
    pub fn rto(&self) -> Duration {
        match self.smoothed_rtt {
            Some(_) => self.rto_with_min(Duration::from_millis(200)),
            None => Duration::from_secs(1),
        }
    }

    /// Retransmission timeout with a caller-supplied lower bound.
    ///
    /// The RFC 6298 formula is `srtt + max(4 * rtt_var, granularity)`; the
    /// floor is what keeps a spurious low sample from arming a timer that
    /// fires before the path can physically answer.  Callers on a measured
    /// path should pass a floor derived from that measurement (e.g. twice
    /// the probed base RTT) rather than the generic 200 ms of [`rto`]:
    /// on a LAN the generic floor is three orders of magnitude above the
    /// real RTT and needlessly delays loss recovery, while on a satellite
    /// path it is *below* the RTT and causes a retransmit storm.
    ///
    /// With no samples yet the floor is returned rather than a fixed
    /// constant, so a probed path starts out with a credible timer.
    pub fn rto_with_min(&self, min: Duration) -> Duration {
        match self.smoothed_rtt {
            Some(srtt) => {
                let rto = srtt + self.rtt_var.max(Duration::from_millis(1)) * 4;
                rto.max(min)
            }
            None => min,
        }
    }
}

impl Default for RttEstimator {
    fn default() -> Self {
        Self::new()
    }
}

/// Tracks packet loss with a windowed recent loss rate.
///
/// Each sent packet contributes exactly one entry to the sliding window; a
/// loss report *marks* an outstanding entry as lost instead of appending a
/// new one, so a lost packet is never counted twice and `recent_loss_rate`
/// is exactly `lost / sent` over the window.
///
/// Loss reports are deduplicated by packet (chunk) index: a report for an
/// index that was already counted as lost — and has not been (re-)sent
/// since — is ignored.  This suppresses duplicate NACKs and NACK+timeout
/// pairs for the same loss, while a genuine re-loss of a retransmitted
/// chunk still counts (the re-send re-arms accounting for that index).
#[derive(Debug)]
pub struct LossTracker {
    total_sent: u64,
    total_lost: u64,
    /// Recent window of (timestamp, was_lost) events, one per sent packet.
    window: VecDeque<(Instant, bool)>,
    /// Number of `was_lost` entries at the front of `window`.  Lost entries
    /// always form a prefix because losses mark the oldest outstanding entry.
    lost_prefix: usize,
    /// Packet indices counted as lost (mapped to the loss timestamp) and not
    /// re-sent since; used to dedup duplicate NACK / NACK+timeout reports.
    /// Entries expire with the window.
    lost_ids: HashMap<u64, Instant>,
    /// FIFO of (timestamp, packet index) mirroring `lost_ids` for expiry.
    lost_fifo: VecDeque<(Instant, u64)>,
    /// Duration of the sliding window.
    window_duration: Duration,
}

impl LossTracker {
    pub fn new(window_duration: Duration) -> Self {
        Self {
            total_sent: 0,
            total_lost: 0,
            window: VecDeque::new(),
            lost_prefix: 0,
            lost_ids: HashMap::new(),
            lost_fifo: VecDeque::new(),
            window_duration,
        }
    }

    /// Record a packet send event.  Retransmits re-report the same packet
    /// index; a (re-)send re-arms loss accounting for that index.
    pub fn on_packet_sent(&mut self, packet_number: u64, now: Instant) {
        self.expire_old(now);
        self.total_sent += 1;
        self.window.push_back((now, false));
        self.lost_ids.remove(&packet_number);
    }

    /// Record packet losses by packet (chunk) index.
    ///
    /// Each distinct packet is counted once: duplicate reports for an index
    /// that has not been re-sent since (duplicate NACKs, or a NACK followed
    /// by a retransmission timeout for the same loss) are ignored.
    pub fn on_packets_lost(&mut self, lost: &[u64], now: Instant) {
        self.expire_old(now);
        for &pkt in lost {
            if self.lost_ids.insert(pkt, now).is_some() {
                continue;
            }
            self.lost_fifo.push_back((now, pkt));
            self.total_lost += 1;
            // Mark the oldest not-yet-lost sent entry as lost rather than
            // pushing a new entry, so each packet counts once in the window.
            if self.lost_prefix < self.window.len() {
                self.window[self.lost_prefix].1 = true;
                self.lost_prefix += 1;
            }
        }
    }

    /// Total packets sent.
    pub fn total_sent(&self) -> u64 {
        self.total_sent
    }

    /// Total packets lost.
    pub fn total_lost(&self) -> u64 {
        self.total_lost
    }

    /// Overall loss rate.
    pub fn loss_rate(&self) -> f64 {
        if self.total_sent == 0 {
            0.0
        } else {
            self.total_lost as f64 / self.total_sent as f64
        }
    }

    /// Recent loss rate within the sliding window.
    pub fn recent_loss_rate(&self, now: Instant) -> f64 {
        self.expire_old_peek(now);
        let cutoff = now.checked_sub(self.window_duration);
        let (total, lost) = self.window.iter().fold((0u64, 0u64), |(t, l), (ts, was_lost)| {
            if cutoff.map_or(true, |c| *ts >= c) {
                (t + 1, if *was_lost { l + 1 } else { l })
            } else {
                (t, l)
            }
        });
        if total == 0 {
            0.0
        } else {
            lost as f64 / total as f64
        }
    }

    fn expire_old(&mut self, now: Instant) {
        if let Some(cutoff) = now.checked_sub(self.window_duration) {
            while let Some((ts, _)) = self.window.front() {
                if *ts < cutoff {
                    if self.lost_prefix > 0 {
                        self.lost_prefix -= 1;
                    }
                    self.window.pop_front();
                } else {
                    break;
                }
            }
            while let Some((ts, pkt)) = self.lost_fifo.front() {
                if *ts < cutoff {
                    let (ts, pkt) = (*ts, *pkt);
                    self.lost_fifo.pop_front();
                    // Only remove the id if this FIFO entry is the live one:
                    // the same index may have been re-sent and lost again.
                    if self.lost_ids.get(&pkt) == Some(&ts) {
                        self.lost_ids.remove(&pkt);
                    }
                } else {
                    break;
                }
            }
        }
    }

    fn expire_old_peek(&self, _now: Instant) {
        // Non-mutating version for read-only methods; actual expiration
        // happens on next mutable call.
    }
}

/// Windowed maximum bandwidth estimator.
#[derive(Debug)]
pub struct BandwidthEstimator {
    /// Maximum bandwidth observed (bytes per second).
    max_bandwidth: u64,
    /// Current bandwidth estimate (bytes per second).
    current_bandwidth: u64,
    /// Windowed samples: (timestamp, bandwidth_bps).
    samples: VecDeque<(Instant, u64)>,
    /// How many RTT intervals to keep samples.
    window_count: usize,
    /// Current RTT estimate for window sizing.
    rtt_estimate: Duration,
}

impl BandwidthEstimator {
    pub fn new(window_count: usize) -> Self {
        Self {
            max_bandwidth: 0,
            current_bandwidth: 0,
            samples: VecDeque::new(),
            window_count,
            rtt_estimate: Duration::from_millis(100),
        }
    }

    /// Add a bandwidth sample.
    /// Record a sample and re-derive the windowed maximum.
    ///
    /// `samples` is kept as a **monotonic deque**: strictly decreasing in
    /// bandwidth, so the front is always the maximum over the window and
    /// every operation is O(1) amortised. A sample that is not larger than
    /// one already behind it can never become the maximum before the older
    /// one expires, so dropping it loses nothing.
    ///
    /// This used to push every sample and then rescan the whole ring to
    /// recompute the max, on every call. Profiled at 1 Gbit
    /// (`PROFILE_SUMMARY`), Model paid **776 us per feedback datagram**
    /// against Classic's 15 — 51x — while receiving only 1.8x as many, so
    /// it was per-ACK cost and not volume. The window holds ~15,500 samples
    /// at that rate (about 62,000 ACKs/s across a 250 ms window), and 767k
    /// acknowledged packets each triggering a rescan is 1.2e10 element
    /// visits: ~5 seconds of a 12.4 second transfer, and a third of every
    /// send pass spent in feedback processing.
    ///
    /// The cost is invisible at 100 Mbit, where a tenth of the ACK rate
    /// leaves a hundredth of the work.
    pub fn add_sample(&mut self, bandwidth_bps: u64, now: Instant) {
        self.current_bandwidth = bandwidth_bps;
        while let Some(&(_, bw)) = self.samples.back() {
            if bw <= bandwidth_bps {
                self.samples.pop_back();
            } else {
                break;
            }
        }
        self.samples.push_back((now, bandwidth_bps));
        self.expire_old(now);
    }

    /// Update the RTT estimate used for windowing.
    pub fn update_rtt(&mut self, rtt: Duration) {
        if !rtt.is_zero() {
            self.rtt_estimate = rtt;
        }
    }

    /// How many candidate samples the window currently holds.
    ///
    /// This is the length of the monotonic deque, not the number of
    /// samples fed in: a sample dominated by an earlier, larger one is
    /// discarded on arrival because it can never become the maximum. It is
    /// a diagnostic of filter occupancy and is reported as `samples=` in
    /// Model's debug line.
    ///
    /// The doc below predates the monotonic deque and its "zero means the
    /// filter
    /// has forgotten everything it ever measured.
    pub fn sample_count(&self) -> usize {
        self.samples.len()
    }

    /// The filter's current window length: `window_count * rtt_estimate`.
    ///
    /// Worth logging because it is derived from the *latest raw* RTT sample
    /// (see `update_rtt`), so it moves with the path. When it falls below
    /// `PROBE_RTT_DURATION` every sample expires during a ProbeRtt hold.
    pub fn window_duration(&self) -> Duration {
        self.rtt_estimate * self.window_count as u32
    }

    /// Maximum bandwidth observed within the window.
    pub fn max_bandwidth(&self) -> u64 {
        self.max_bandwidth
    }

    /// Current (most recent) bandwidth estimate.
    pub fn current_bandwidth(&self) -> u64 {
        self.current_bandwidth
    }

    /// Windowed maximum bandwidth.
    ///
    /// Takes `&self`, so it cannot expire; it walks forward past entries
    /// already older than the cutoff and returns the first live one. The
    /// deque is monotonic, so that first live entry *is* the maximum — no
    /// scan of the remainder is needed.
    pub fn windowed_max_bandwidth(&self, now: Instant) -> u64 {
        let window_duration = self.rtt_estimate * self.window_count as u32;
        let cutoff = now.checked_sub(window_duration);
        self.samples
            .iter()
            .find(|(ts, _)| cutoff.map_or(true, |c| *ts >= c))
            .map(|(_, bw)| *bw)
            .unwrap_or(0)
    }

    fn expire_old(&mut self, now: Instant) {
        let window_duration = self.rtt_estimate * self.window_count as u32;
        if let Some(cutoff) = now.checked_sub(window_duration) {
            while let Some((ts, _)) = self.samples.front() {
                if *ts < cutoff {
                    self.samples.pop_front();
                } else {
                    break;
                }
            }
        }

        // The deque is monotonic decreasing, so the front is the maximum.
        // No scan.
        self.max_bandwidth = self.samples.front().map(|(_, bw)| *bw).unwrap_or(0);
    }
}

/// Tracks delivery rate from ACK feedback.
#[derive(Debug)]
pub struct DeliveryRateEstimator {
    /// Total bytes delivered (acknowledged).
    total_delivered: u64,
    /// Trailing `(timestamp, total_delivered)` marks, used to measure a
    /// rate over a span rather than over one ACK.
    trail: VecDeque<(Instant, u64)>,
    /// Current delivery rate estimate (bytes per second).
    delivery_rate: u64,
    /// Span the current estimate was measured over, in microseconds.
    last_span_us: u64,
    /// Total bytes handed to the wire, and trailing marks for it.
    ///
    /// The delivery rate is clamped by the send rate over the same span,
    /// because **a path cannot deliver more than it was given**. See
    /// `delivery_rate()`.
    total_sent: u64,
    sent_trail: VecDeque<(Instant, u64)>,
}

impl DeliveryRateEstimator {
    pub fn new() -> Self {
        Self {
            total_delivered: 0,
            trail: VecDeque::new(),
            delivery_rate: 0,
            last_span_us: 0,
            total_sent: 0,
            sent_trail: VecDeque::new(),
        }
    }

    /// Record delivered bytes from an ACK and re-measure the rate.
    ///
    /// The rate is bytes acknowledged divided by the span they arrived
    /// over, where the span is at least half of `window` -- and `window`
    /// should be a round trip.
    ///
    /// This replaces two things that were both wrong. It used to accept a
    /// caller-supplied `delivery_rate` and adopt it verbatim when nonzero,
    /// and otherwise divide one ACK's bytes by the gap since the previous
    /// ACK. Both are instantaneous per-ACK figures, and ACKs arrive in
    /// batches: a clump landing together reads as an enormous momentary
    /// rate even when the path delivered exactly capacity. Feeding that to
    /// a max filter latches the highest noise sample. the CC research notes
    /// section 2.4 measured 4.0x capacity from this; Model's own trace
    /// measured **759 Mbit on a 100 Mbit link**, 7.6x, and the fabricated
    /// peak then pinned `full_bw` so that startup exited within 200 ms and
    /// the controller never recovered.
    ///
    /// Averaging over a single control tick is not enough either -- ACKs do
    /// not respect tick boundaries, so a batch arriving just before one is
    /// credited to the interval after it, and that interval gets two
    /// intervals' bytes over one interval's duration (measured at 2.2x).
    /// Over a whole round trip a small attribution error is a small
    /// fraction of the window, and a rate averaged over an RTT cannot
    /// exceed what the bottleneck passed in that RTT however the ACKs were
    /// clumped.
    ///
    /// This is the estimator `rl.rs` was rewritten to use; Model and WiFi
    /// were not brought along at the time. They are now.
    /// The span the most recent rate was measured over, in microseconds.
    /// Zero before the first measurement.
    pub fn last_span_us(&self) -> u64 {
        self.last_span_us
    }

    /// Record bytes handed to the wire, for the send-rate clamp.
    ///
    /// Kept over the same trailing window as the delivery marks so the two
    /// can be compared over one span.
    pub fn on_sent(&mut self, bytes: u64, now: Instant, window: Duration) {
        self.total_sent = self.total_sent.saturating_add(bytes);
        self.sent_trail.push_back((now, self.total_sent));
        while self.sent_trail.len() > 2 {
            let second = self.sent_trail[1].0;
            if now.duration_since(second) >= window {
                self.sent_trail.pop_front();
            } else {
                break;
            }
        }
    }

    /// Bytes/second handed to the wire over the same trailing span, or
    /// `None` before there is enough history to say.
    fn send_rate(&self, now: Instant) -> Option<u64> {
        let &(t0, s0) = self.sent_trail.front()?;
        let span = now.duration_since(t0).as_secs_f64();
        if span <= 0.0 {
            return None;
        }
        Some(((self.total_sent - s0) as f64 / span) as u64)
    }

    pub fn on_ack(&mut self, delivered_bytes: u64, now: Instant, window: Duration) {
        self.total_delivered = self.total_delivered.saturating_add(delivered_bytes);
        self.trail.push_back((now, self.total_delivered));

        // Keep one mark older than the window, so the measured span is at
        // least the window rather than at most it.
        while self.trail.len() > 2 {
            let second = self.trail[1].0;
            if now.duration_since(second) >= window {
                self.trail.pop_front();
            } else {
                break;
            }
        }

        if let Some(&(t0, b0)) = self.trail.front() {
            let span = now.duration_since(t0).as_secs_f64();
            if span > 0.0 && span >= window.as_secs_f64() * 0.5 {
                let measured = ((self.total_delivered - b0) as f64 / span) as u64;
                // Clamp to what was actually handed to the wire over the
                // same span. **A path cannot deliver more than it was
                // given**, and without this the estimate reads well above
                // the link.
                //
                // A cumulative ACK bitmap releases a whole contiguous run
                // the moment a retransmit fills a hole ahead of it. Those
                // bytes arrived over several round trips; they are counted
                // as delivered at one instant. Measured at 1 Gbit
                // (`dr=`/`drmax=` in Model's debug line): the raw estimate
                // peaks at 1365 Mbit on cross-country and **1977 Mbit on
                // satellite**, over correctly-measured 30 ms and 150 ms
                // spans. Satellite is worst because it carries both the
                // largest window and the most holes.
                //
                // Feeding that to a max filter pinned Model's `bw` at
                // ~2.5x the link there, and `cwnd = gain x bw x min_rtt`
                // followed it to 95 MB against an 18.75 MB BDP.
                //
                // This is a bound, not a substitute for BBR's per-packet
                // delivery-rate sampling, which anchors each sample to the
                // send time of the packet being acked and is immune to
                // bunched ACKs by construction. It needs per-packet state
                // in the sender; this needs nothing the estimator does not
                // already see.
                self.delivery_rate = match self.send_rate(now) {
                    Some(sent) if sent > 0 => measured.min(sent),
                    _ => measured,
                };
                self.last_span_us = (span * 1e6) as u64;
            }
        }
    }

    /// Current delivery rate in bytes per second. Zero until a span of at
    /// least half a window has been observed -- an honest "not yet known"
    /// rather than a guess from one ACK.
    pub fn delivery_rate(&self) -> u64 {
        self.delivery_rate
    }

    /// Total bytes delivered.
    pub fn total_delivered(&self) -> u64 {
        self.total_delivered
    }
}

impl Default for DeliveryRateEstimator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn instant_at(base: Instant, millis: u64) -> Instant {
        base + Duration::from_millis(millis)
    }

    #[test]
    fn rtt_estimator_first_sample() {
        let mut est = RttEstimator::new();
        let rtt = Duration::from_millis(100);
        est.update(rtt);

        assert_eq!(est.smoothed_rtt(), Some(rtt));
        assert_eq!(est.rtt_var(), rtt / 2);
        assert_eq!(est.min_rtt(), Some(rtt));
        assert_eq!(est.latest_rtt(), rtt);
    }

    /// The monotonic deque must return the same maximum as a full rescan.
    ///
    /// The O(1) structure discards dominated samples on arrival, which is
    /// only sound if a sample smaller than an older one can never become
    /// the window maximum before that older one expires. This checks the
    /// claim against a brute-force scan over a random-ish walk, at every
    /// step, including across expiries.
    #[test]
    fn windowed_max_matches_a_brute_force_scan() {
        let mut est = BandwidthEstimator::new(10);
        est.update_rtt(Duration::from_millis(10)); // 100 ms window
        let t0 = Instant::now();
        let mut reference: Vec<(Instant, u64)> = Vec::new();
        // A deterministic walk with rises, falls and plateaus.
        let mut bw: u64 = 1_000_000;
        for i in 0..400u64 {
            bw = match i % 7 {
                0 | 1 => bw + 250_000,
                2 => bw.saturating_sub(400_000).max(100_000),
                3 => bw,
                4 => bw + 50_000,
                5 => bw.saturating_sub(120_000).max(100_000),
                _ => bw.saturating_sub(30_000).max(100_000),
            };
            let now = t0 + Duration::from_millis(i);
            est.add_sample(bw, now);
            reference.push((now, bw));

            // Brute force: max over everything inside the window.
            let cutoff = now - Duration::from_millis(100);
            let expected = reference
                .iter()
                .filter(|(ts, _)| *ts >= cutoff)
                .map(|(_, b)| *b)
                .max()
                .unwrap_or(0);
            assert_eq!(
                est.max_bandwidth(),
                expected,
                "step {i}: deque gave {}, brute force {}",
                est.max_bandwidth(),
                expected
            );
        }
    }

    /// A dominated sample is discarded, so occupancy stays small.
    ///
    /// This is what makes the structure O(1) amortised rather than merely
    /// correct: under a monotonically falling series every new sample
    /// evicts nothing and the deque grows, but under a rising one it
    /// collapses to a single entry.
    #[test]
    fn monotonic_deque_collapses_on_a_rising_series() {
        let mut est = BandwidthEstimator::new(10);
        est.update_rtt(Duration::from_secs(60)); // window never expires here
        let t0 = Instant::now();
        for i in 0..500u64 {
            est.add_sample(1_000_000 + i * 1_000, t0 + Duration::from_millis(i));
        }
        assert_eq!(
            est.sample_count(),
            1,
            "a strictly rising series should leave exactly one candidate, got {}",
            est.sample_count()
        );
        assert_eq!(est.max_bandwidth(), 1_000_000 + 499 * 1_000);
    }

    /// The delivery rate cannot exceed the send rate over the same span.
    ///
    /// Reproduces the shape that inflated Model's estimate: a long quiet
    /// period during which the sender hands over a steady stream, then one
    /// cumulative ACK releasing everything at once. Without the clamp the
    /// sample reads the whole backlog over one short span.
    #[test]
    fn delivery_rate_is_clamped_by_the_send_rate() {
        let mut est = DeliveryRateEstimator::new();
        let w = Duration::from_millis(100);
        let t0 = Instant::now();

        // The sender hands over 1 MB spread evenly across 400 ms — a send
        // rate of 2.5 MB/s.
        for i in 0..400u64 {
            est.on_sent(2_500, t0 + Duration::from_millis(i), w);
        }
        // ACKs arrive for the first 300 ms worth, spread out.
        for i in 0..300u64 {
            est.on_ack(2_500, t0 + Duration::from_millis(i), w);
        }
        let steady = est.delivery_rate();

        // Then one bitmap releases 250 KB in a single instant.
        est.on_ack(250_000, t0 + Duration::from_millis(400), w);
        let after_burst = est.delivery_rate();

        // 250 KB over a ~100 ms span is 2.5 MB/s of *apparent* delivery on
        // top of the steady flow; the clamp holds it to what was sent.
        let sent_rate = 2_500_000u64; // 2500 B/ms
        assert!(
            after_burst <= sent_rate + sent_rate / 10,
            "burst sample {after_burst} exceeds the send rate {sent_rate} — \
             the clamp did not hold (steady was {steady})"
        );
    }

    /// The clamp must not depress an honest estimate.
    #[test]
    fn clamp_does_not_lower_a_truthful_delivery_rate() {
        let mut est = DeliveryRateEstimator::new();
        let w = Duration::from_millis(100);
        let t0 = Instant::now();
        // Everything sent is delivered one interval later, same rate.
        for i in 0..400u64 {
            est.on_sent(2_500, t0 + Duration::from_millis(i), w);
            est.on_ack(2_500, t0 + Duration::from_millis(i), w);
        }
        let r = est.delivery_rate();
        assert!(
            r >= 2_300_000 && r <= 2_700_000,
            "honest 2.5 MB/s reads {r} — the clamp is distorting it"
        );
    }

    #[test]
    fn rtt_estimator_multiple_samples() {
        let mut est = RttEstimator::new();
        est.update(Duration::from_millis(100));
        est.update(Duration::from_millis(120));
        est.update(Duration::from_millis(80));

        let srtt = est.smoothed_rtt().unwrap();
        // Should be somewhere between 80 and 120.
        assert!(srtt > Duration::from_millis(80));
        assert!(srtt < Duration::from_millis(120));

        // Min should be 80.
        assert_eq!(est.min_rtt(), Some(Duration::from_millis(80)));
        assert_eq!(est.latest_rtt(), Duration::from_millis(80));
    }

    #[test]
    fn rtt_estimator_rto() {
        let mut est = RttEstimator::new();
        est.update(Duration::from_millis(100));

        let rto = est.rto();
        // rto = 100ms + 4 * 50ms = 300ms
        assert_eq!(rto, Duration::from_millis(300));
    }

    #[test]
    fn rtt_estimator_rto_default() {
        let est = RttEstimator::new();
        assert_eq!(est.rto(), Duration::from_secs(1));
    }

    #[test]
    fn rto_with_min_never_undercuts_the_path() {
        // The failure this guards: a 100 ms retransmit timer on a 150 ms
        // path declares every packet lost before its ACK can arrive.
        let floor = Duration::from_millis(300); // e.g. 2x a 150 ms base RTT

        // No samples yet — the caller's measured floor is used verbatim,
        // not the generic 200 ms / 1 s constants.
        let est = RttEstimator::new();
        assert_eq!(est.rto_with_min(floor), floor);

        // Samples consistent with the path keep the timer above it.
        let mut est = RttEstimator::new();
        for _ in 0..20 {
            est.update(Duration::from_millis(150));
        }
        assert!(
            est.rto_with_min(floor) >= floor,
            "rto {:?} fell below the measured floor",
            est.rto_with_min(floor)
        );

        // Even a run of spuriously tiny samples cannot pull the timer
        // under the floor — which is what stops the storm being
        // self-sustaining once RTT samples are corrupted.
        for _ in 0..50 {
            est.update(Duration::from_micros(300));
        }
        assert_eq!(est.rto_with_min(floor), floor);

        // On a fast path the floor is what the caller configured, and a
        // genuinely larger RTT still wins.
        let lan_floor = Duration::from_millis(100);
        let mut est = RttEstimator::new();
        est.update(Duration::from_micros(40));
        assert_eq!(est.rto_with_min(lan_floor), lan_floor);
        for _ in 0..20 {
            est.update(Duration::from_millis(400));
        }
        assert!(est.rto_with_min(lan_floor) > lan_floor);
    }

    #[test]
    fn loss_tracker_basic() {
        let now = Instant::now();
        let mut tracker = LossTracker::new(Duration::from_secs(10));

        for i in 0..100 {
            tracker.on_packet_sent(i, instant_at(now, i * 10));
        }
        tracker.on_packets_lost(&[0, 1, 2, 3, 4], instant_at(now, 1000));

        assert_eq!(tracker.total_sent(), 100);
        assert_eq!(tracker.total_lost(), 5);

        let rate = tracker.loss_rate();
        assert!((rate - 0.05).abs() < 0.001);
    }

    #[test]
    fn loss_tracker_recent_rate() {
        let now = Instant::now();
        let mut tracker = LossTracker::new(Duration::from_secs(1));

        // Old events (will be outside window).
        for i in 0..50u64 {
            tracker.on_packet_sent(i, instant_at(now, i * 10));
        }
        // New events (within 1s window).
        let recent_base = 5000;
        for i in 0..50u64 {
            tracker.on_packet_sent(50 + i, instant_at(now, recent_base + i * 10));
        }
        let lost: Vec<u64> = (50..60).collect();
        tracker.on_packets_lost(&lost, instant_at(now, recent_base + 500));

        let recent = tracker.recent_loss_rate(instant_at(now, recent_base + 600));
        // Recent window has 50 sent entries, 10 of them marked lost.
        assert!((recent - 0.2).abs() < 0.001);
    }

    #[test]
    fn loss_tracker_counts_each_loss_once() {
        let now = Instant::now();
        let mut tracker = LossTracker::new(Duration::from_secs(10));

        // Known sequence: 100 sent, 10 lost -> recent rate must be exactly
        // 10/100. The old implementation appended extra loss markers and
        // reported the biased-low 10/110.
        for i in 0..100u64 {
            tracker.on_packet_sent(i, instant_at(now, i * 10));
        }
        let lost: Vec<u64> = (0..10).collect();
        tracker.on_packets_lost(&lost, instant_at(now, 1100));

        let recent = tracker.recent_loss_rate(instant_at(now, 1100));
        assert!((recent - 0.1).abs() < 1e-9);
    }

    #[test]
    fn loss_tracker_dedups_duplicate_reports() {
        let now = Instant::now();
        let mut tracker = LossTracker::new(Duration::from_secs(10));

        for i in 0..10u64 {
            tracker.on_packet_sent(i, instant_at(now, i * 10));
        }

        // Duplicate NACK: same indices reported twice.
        tracker.on_packets_lost(&[3, 4], instant_at(now, 200));
        tracker.on_packets_lost(&[3, 4], instant_at(now, 210));

        assert_eq!(tracker.total_lost(), 2);
        let recent = tracker.recent_loss_rate(instant_at(now, 210));
        assert!((recent - 0.2).abs() < 1e-9);

        // NACK followed by a retransmission timeout for the same chunk:
        // still one loss.
        tracker.on_packets_lost(&[5], instant_at(now, 300));
        tracker.on_packets_lost(&[5], instant_at(now, 600));

        assert_eq!(tracker.total_lost(), 3);
        let recent = tracker.recent_loss_rate(instant_at(now, 600));
        assert!((recent - 0.3).abs() < 1e-9);
    }

    #[test]
    fn loss_tracker_resend_rearms_accounting() {
        let now = Instant::now();
        let mut tracker = LossTracker::new(Duration::from_secs(10));

        for i in 0..10u64 {
            tracker.on_packet_sent(i, instant_at(now, i * 10));
        }

        // NACK-driven loss of chunk 3, then its retransmission is lost too:
        // the re-send re-arms accounting, so the second loss counts.
        tracker.on_packets_lost(&[3], instant_at(now, 200));
        tracker.on_packet_sent(3, instant_at(now, 250));
        tracker.on_packets_lost(&[3], instant_at(now, 600));

        assert_eq!(tracker.total_lost(), 2);
        assert_eq!(tracker.total_sent(), 11);
        let recent = tracker.recent_loss_rate(instant_at(now, 600));
        assert!((recent - 2.0 / 11.0).abs() < 1e-9);
    }

    #[test]
    fn loss_tracker_dedup_expires_with_window() {
        let now = Instant::now();
        let mut tracker = LossTracker::new(Duration::from_secs(1));

        tracker.on_packet_sent(0, instant_at(now, 0));
        tracker.on_packets_lost(&[0], instant_at(now, 100));

        // After the window expires, a stale duplicate report may be counted
        // again -- there is no outstanding state to dedup against. It must
        // not panic and must not inflate the (empty) window beyond 100%.
        tracker.on_packets_lost(&[0], instant_at(now, 2000));
        assert_eq!(tracker.total_lost(), 2);
        let recent = tracker.recent_loss_rate(instant_at(now, 2000));
        assert!((recent - 0.0).abs() < 1e-9);
    }

    #[test]
    fn bandwidth_estimator_basic() {
        let now = Instant::now();
        let mut est = BandwidthEstimator::new(10);

        est.add_sample(1_000_000, instant_at(now, 0));
        est.add_sample(2_000_000, instant_at(now, 100));
        est.add_sample(1_500_000, instant_at(now, 200));

        assert_eq!(est.current_bandwidth(), 1_500_000);
        assert_eq!(est.max_bandwidth(), 2_000_000);
    }

    #[test]
    fn bandwidth_estimator_windowed() {
        let now = Instant::now();
        let mut est = BandwidthEstimator::new(10);
        est.update_rtt(Duration::from_millis(100));

        // Window = 10 * 100ms = 1s
        est.add_sample(5_000_000, instant_at(now, 0));
        est.add_sample(3_000_000, instant_at(now, 500));

        let max = est.windowed_max_bandwidth(instant_at(now, 800));
        assert_eq!(max, 5_000_000);

        // After window expires, the old high sample should be gone.
        est.add_sample(2_000_000, instant_at(now, 1500));
        let max = est.windowed_max_bandwidth(instant_at(now, 1500));
        assert!(max <= 3_000_000);
    }

    #[test]
    fn delivery_rate_estimator() {
        let now = Instant::now();
        let mut est = DeliveryRateEstimator::new();
        let window = Duration::from_millis(50);

        est.on_ack(1200, instant_at(now, 0), window);
        assert_eq!(est.total_delivered(), 1200);
        // No span yet, so no rate. The previous version of this test
        // asserted the opposite on both counts: that a caller-supplied
        // rate hint was adopted verbatim, and that a single ACK
        // "calculates from elapsed time". That is the per-ACK sampling
        // which measured 7.6x capacity on the rig, and it was pinned here
        // as the expected behaviour.
        assert_eq!(est.delivery_rate(), 0);

        est.on_ack(2400, instant_at(now, 100), window);
        assert_eq!(est.total_delivered(), 3600);
        // 2400 bytes over the 100 ms since the first mark.
        assert_eq!(est.delivery_rate(), 24_000);
    }
}
#[cfg(test)]
mod delivery_estimator_tests {
    use super::*;

    /// A batch of ACKs arriving together must not read as an enormous rate.
    ///
    /// This is the defect that made Model unusable: per-ACK sampling on a
    /// 100 Mbit link produced a 759 Mbit estimate, which pinned `full_bw`
    /// at 7.6x capacity, ended startup within 200 ms, and left the
    /// controller pacing at 0.12 Mbit for the rest of the transfer.
    #[test]
    fn ack_batch_does_not_inflate_the_rate() {
        let mut d = DeliveryRateEstimator::new();
        let t0 = Instant::now();
        let rtt = Duration::from_millis(25);
        // True path: 12.5 MB/s. One RTT carries 312_500 bytes. Deliver it
        // as 250 ACKs of 1250 bytes that all land in the last 2 ms of the
        // round trip -- the clumping a real receiver produces.
        for i in 0..250u32 {
            let at = t0 + Duration::from_millis(23) + Duration::from_micros(i as u64 * 8);
            d.on_ack(1250, at, rtt);
        }
        // Advance a further round trip delivering the same amount, so a
        // full span is available.
        for i in 0..250u32 {
            let at = t0 + Duration::from_millis(48) + Duration::from_micros(i as u64 * 8);
            d.on_ack(1250, at, rtt);
        }
        let rate = d.delivery_rate();
        assert!(
            rate > 0,
            "estimator produced nothing after two round trips of delivery"
        );
        assert!(
            rate < 25_000_000,
            "rate {rate} B/s is more than 2x the 12.5 MB/s path — ACK batching latched"
        );
    }

    /// And it must report nothing rather than guessing from one ACK.
    #[test]
    fn reports_nothing_until_a_span_exists() {
        let mut d = DeliveryRateEstimator::new();
        let t0 = Instant::now();
        d.on_ack(1250, t0, Duration::from_millis(25));
        d.on_ack(1250, t0 + Duration::from_micros(50), Duration::from_millis(25));
        assert_eq!(
            d.delivery_rate(),
            0,
            "a rate was invented from two ACKs 50us apart"
        );
    }
}
