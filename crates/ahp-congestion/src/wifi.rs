// Favonius — high-performance file transfer over UDP
// Copyright (c) 2025-2026 Vantino SàRL
// SPDX-License-Identifier: Apache-2.0

//! AHP-WiFi: bandwidth-probing congestion control for dedicated WiFi LAN.
//!
//! Measures actual link bandwidth from delivery rate samples, then sends at
//! the measured rate. Uses UDT-style loss handling: only reduces rate when
//! the loss rate exceeds a per-window threshold, and reduces by 1/9 (not 1/2).
//!
//! Three phases:
//! - **Measuring**: First 5 RTTs — measure delivery rate from ACK feedback.
//! - **Steady**: Send at 95% of measured bandwidth, continuously update.
//! - **Probing**: Every 10 RTTs, increase rate by 5% for one RTT to discover
//!   more bandwidth.
//!
//! **Not suitable for shared networks** — use `Fair` instead.

use std::time::{Duration, Instant};

use crate::metrics::{BandwidthEstimator, DeliveryRateEstimator, LossTracker, RttEstimator};
use crate::pacer::Pacer;
use crate::{AckInfo, CongestionController};

/// Default MTU.
const MTU: usize = 1200;

/// Initial cwnd: large enough to measure bandwidth in the first RTTs.
const INITIAL_CWND: usize = 256 * MTU;

/// Bandwidth estimation window in RTT multiples.
const BW_WINDOW_RTTS: usize = 10;

/// Loss tracking window.
const LOSS_WINDOW: Duration = Duration::from_secs(10);

/// RTTs to spend in the Measuring phase before transitioning to Steady.
const MEASURING_ROUNDS: u64 = 5;

/// Ceiling on the slow-start window during Measuring.
///
/// 4096 packets is ~4.9 MB, which covers a 300 ms path at 100 Mbit (a
/// 3.75 MB BDP) with headroom. It exists so that a path which never
/// delivers an ACK cannot grow the window without bound, not as a target;
/// Steady replaces it with `2 x BDP` from the measurement.
const STARTUP_MAX_CWND: usize = 4096 * MTU;

/// RTTs between bandwidth probes in Steady state.
const PROBE_INTERVAL_ROUNDS: u64 = 10;

/// Pacing gain during probe phase (5% above target).
const PROBE_GAIN: f64 = 1.05;

/// Round trips a probe must run before it is evaluated.
///
/// One is too few, and it is the same defect `rl.rs` had as defect 11: a
/// probe raises the rate, and the ACKs that say whether the path *delivered*
/// the higher rate arrive one round trip later. Evaluating after exactly one
/// RTT reads the estimate from before the probe, so the probe can never
/// show a gain and the rate cannot ratchet up.
///
/// Measured on satellite: `target_rate` reached 42 Mbit in the first second
/// and then oscillated between 37.4 and 39.9 -- exactly +/-5%, the probe
/// firing and its result being discarded -- for the whole 33 s transfer, on
/// a 100 Mbit link. Fixing the equivalent in rl.rs took that controller's
/// coefficient of variation from 23.3% to 0.6%.
const PROBE_RTTS: u32 = 2;

/// Gain applied while the bandwidth estimate is still climbing.
///
/// `target_rate = measured_bw * STEADY_RATE_FACTOR` with the factor at 1.0
/// is a fixed point at *any* rate: the controller paces at what it last
/// delivered, so it delivers that, so it paces at it. The probe is the only
/// escape, and it is worth +5% every PROBE_INTERVAL_ROUNDS rounds plus
/// PROBE_RTTS of probing -- about 1.8 s on a 150 ms path.
///
/// Climbing from a measured 37 Mbit to a 100 Mbit ceiling that way needs
/// log(2.7)/log(1.05) = 20 probes, or 37 seconds. The satellite transfer
/// takes 33. So the controller never arrived: measured `ach_mbit=36.7` with
/// a faithful pacer (debt_ratio 0.994) while Classic commanded 100.8 on the
/// same path.
///
/// This is the third controller today with bandwidth discovery clocked by
/// something other than the round trip -- `rl.rs` by its gain cycle,
/// `model.rs` by a growth threshold its estimator could not satisfy, and
/// this by a probe interval. The remedy is the same: while the estimate is
/// still rising and the queue is demonstrably empty, drive it at a real
/// gain every round trip instead of nudging it every tenth.
const RAMP_GAIN: f64 = 1.5;

/// Growth below this over one round trip counts as no growth.
const RAMP_PLATEAU_RATIO: f64 = 1.05;

/// Consecutive non-growing round trips before the ramp hands over to the
/// ordinary Steady/Probing cycle.
const RAMP_PLATEAU_ROUNDS: u32 = 3;

/// Delay budget above `min_rtt` below which the queue counts as empty, as
/// a fixed term plus a fraction. A bare ratio cannot work here: this rig
/// has a ~7.4 ms floor that is not queueing, which is 1.30x at a 25 ms base
/// and 1.05x at 150 ms.
const RAMP_QUEUE_FIXED: Duration = Duration::from_millis(10);
const RAMP_QUEUE_FRACTION: f64 = 0.10;

/// Target rate = measured_bandwidth × this factor (5% below to avoid self-congestion).
/// Steady-state pacing gain on the measured delivery rate.
///
/// Must not be below 1.0. `target_rate = k * measured_bw` where
/// `measured_bw` is delivery observed *under that same target* is a
/// contraction mapping for any k < 1: the sender paces at k x what it
/// last delivered, so it delivers k x that, so it paces at k^2. It was
/// 0.95, applied on every round in Steady, against a PROBE_GAIN of 1.05
/// applied once per PROBE_INTERVAL_ROUNDS -- a net 0.95^10 * 1.05 = 0.63
/// per ten rounds. Measured on cross-country: 88.41 -> 80.16 -> ... ->
/// 26.10 -> 25.06 Mbit, monotonic, until the transfer timed out at 45%.
///
/// A windowed maximum does not rescue it; it only slows the descent,
/// because the high samples expire and the max follows the rate down.
///
/// At 1.0 the steady state is neutral at whatever rate the path is
/// delivering, and the probe is the only drift -- upward, and checked
/// against what comes back. Headroom belongs in the window, which
/// `update_cwnd_and_pacing` already sets to 2x BDP.
const STEADY_RATE_FACTOR: f64 = 1.0;

/// UDT-style loss decrease: reduce by 1/9 (≈11%).
const LOSS_DECREASE_DIVISOR: u64 = 9;

/// Minimum rate: never drop below 50% of measured bandwidth.
const MIN_RATE_FACTOR: f64 = 0.50;

/// States of the WiFi controller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WifiState {
    /// First rounds: measure bandwidth from delivery rate samples.
    Measuring,
    /// Send at measured rate, continuously update bandwidth estimate.
    Steady,
    /// One RTT at elevated rate to probe for more bandwidth.
    Probing,
}

/// WiFi congestion controller with bandwidth probing.
#[derive(Debug)]
pub struct WifiController {
    state: WifiState,
    /// Current congestion window in bytes.
    cwnd: usize,
    /// RTT estimator.
    rtt: RttEstimator,
    /// Bandwidth estimator (windowed max of delivery rate samples).
    bandwidth: BandwidthEstimator,
    /// Delivery rate estimator.
    delivery: DeliveryRateEstimator,
    /// Loss tracker.
    loss: LossTracker,
    /// Packet pacer.
    pacer: Pacer,
    /// Measured bottleneck bandwidth (bytes/sec).
    measured_bw: u64,
    /// Current target sending rate (bytes/sec).
    target_rate: u64,
    /// Round-trip counter.
    round_count: u64,
    /// Packet number at start of current round.
    round_start_pkt: u64,
    /// Whether the current round has been counted.
    round_started: bool,
    /// Round when the last probe started.
    last_probe_round: u64,
    /// Timestamp when the last probe started.
    probe_start: Option<Instant>,
    /// Packets sent (for per-window loss threshold).
    total_sent: u64,
    /// Whether the bandwidth estimate is still climbing. See `RAMP_GAIN`.
    ramp_active: bool,
    ramp_checked: Option<Instant>,
    ramp_ref_bw: u64,
    ramp_flat_rounds: u32,
}

impl WifiController {
    pub fn new() -> Self {
        // No seed. This was `50_000_000` -- 400 Mbit, asserted, never
        // measured -- and it paced the entire Measuring phase, so on a 100
        // Mbit link the controller opened at four times capacity and
        // measured the path while overrunning it. Whatever the max filter
        // happened to hold at the Measuring->Steady transition then set the
        // rate for the rest of the transfer, which is a lottery, and this
        // cell is the least reproducible on the rig: cv 53.9%, 1.0-7.2 MB/s
        // on identical configuration.
        //
        // `rate_bps == 0` means unpaced in `Pacer::next_send_time`, so the
        // window governs until something has actually been measured. Same
        // shape as `model.rs`, whose `target_pacing_rate()` returns 0 while
        // `bw == 0`. Two identical seeds were removed from the send path in
        // this same investigation; this one survived inside the controller.
        let initial_rate = 0u64;
        Self {
            state: WifiState::Measuring,
            cwnd: INITIAL_CWND,
            rtt: RttEstimator::new(),
            bandwidth: BandwidthEstimator::new(BW_WINDOW_RTTS),
            delivery: DeliveryRateEstimator::new(),
            loss: LossTracker::new(LOSS_WINDOW),
            pacer: Pacer::new(initial_rate),
            measured_bw: 0,
            target_rate: initial_rate,
            round_count: 0,
            round_start_pkt: 0,
            round_started: false,
            last_probe_round: 0,
            probe_start: None,
            total_sent: 0,
            ramp_active: true,
            ramp_checked: None,
            ramp_ref_bw: 0,
            ramp_flat_rounds: 0,
        }
    }

    fn update_round(&mut self, acked_pkt: u64) {
        if acked_pkt >= self.round_start_pkt && self.round_started {
            self.round_count += 1;
            self.round_started = false;
        }
    }

    fn start_round(&mut self, sent_pkt: u64) {
        if !self.round_started {
            // Retransmits re-report an older chunk index; keep the high-water mark.
            self.round_start_pkt = self.round_start_pkt.max(sent_pkt);
            self.round_started = true;
        }
    }

    fn update_cwnd_and_pacing(&mut self) {
        // cwnd = 2x BDP for jitter headroom.
        //
        // `min_rtt`, not `srtt`. `target_rate` tracks measured delivery,
        // which once the window exceeds the BDP is approximately
        // `cwnd / srtt`, so with srtt here:
        //
        //     cwnd' = 2 * target_rate * srtt ~= 2 * (cwnd/srtt) * srtt
        //           = 2 * cwnd
        //
        // The window doubles every round for as long as the estimate holds,
        // independently of the path, and only loss stops it -- and the
        // queueing that loss comes from inflates srtt further on the way.
        // This is the loop documented at length in `model.rs::
        // on_ack_received`, which is why that controller samples nothing
        // derived from its own window. Against `min_rtt` the expression has
        // a fixed point at 2x BDP, which is the intended target.
        if let Some(min_rtt) = self.rtt.min_rtt() {
            if !min_rtt.is_zero() && self.target_rate > 0 {
                let bdp = (self.target_rate as f64 * min_rtt.as_secs_f64()) as usize;
                self.cwnd = (bdp * 2).max(INITIAL_CWND);
            }
        }
        self.pacer.set_rate(self.target_rate);
    }


    /// Is the bottleneck queue empty enough for the ramp to keep pushing?
    fn ramp_queue_empty(&self) -> bool {
        match (self.rtt.min_rtt(), self.rtt.smoothed_rtt()) {
            (Some(min), Some(srtt)) => {
                let budget = RAMP_QUEUE_FIXED.as_secs_f64()
                    + RAMP_QUEUE_FRACTION * min.as_secs_f64();
                srtt.as_secs_f64() - min.as_secs_f64() < budget
            }
            // No estimate yet: absence of evidence is not an empty queue.
            _ => false,
        }
    }

    /// Advance the ramp's plateau detector and report whether it still
    /// applies. Clocked on the round trip, which is the point.
    fn ramp_gain(&mut self, now: Instant) -> Option<f64> {
        if !self.ramp_active {
            return None;
        }
        let min_rtt = self.rtt.min_rtt().unwrap_or(Duration::from_millis(50));
        let checked = *self.ramp_checked.get_or_insert(now);
        if now.saturating_duration_since(checked) >= min_rtt {
            let bw = self.bandwidth.max_bandwidth();
            let grew = self.ramp_ref_bw == 0
                || (bw as f64) > self.ramp_ref_bw as f64 * RAMP_PLATEAU_RATIO;
            if grew {
                self.ramp_flat_rounds = 0;
            } else {
                self.ramp_flat_rounds += 1;
            }
            self.ramp_ref_bw = bw;
            self.ramp_checked = Some(now);
            if self.ramp_flat_rounds >= RAMP_PLATEAU_ROUNDS {
                self.ramp_active = false;
                tracing::debug!(bw, "wifi: ramp plateau, entering steady");
                return None;
            }
        }
        if self.ramp_queue_empty() {
            Some(RAMP_GAIN)
        } else {
            None
        }
    }

    /// Compute the loss rate threshold: 1/cwnd_in_packets (UDT-style).
    /// Only trigger rate reduction when loss exceeds this.
    fn loss_threshold(&self) -> f64 {
        let cwnd_pkts = (self.cwnd / MTU).max(1);
        1.0 / cwnd_pkts as f64
    }
}

impl Default for WifiController {
    fn default() -> Self {
        Self::new()
    }
}

impl CongestionController for WifiController {
    fn on_packet_sent(&mut self, packet_number: u64, bytes: usize, now: Instant) {
        self.total_sent += 1;
        self.start_round(packet_number);
        self.loss.on_packet_sent(packet_number, now);
        self.pacer.on_packet_sent(bytes, now);
        // Feed the delivery estimator's send-rate clamp. Same window as
        // `on_ack` below so the two are comparable over one span.
        //
        // WiFi shares `DeliveryRateEstimator` with Model and therefore
        // shares the over-read fixed in metrics.rs: a cumulative ACK
        // bitmap releases a whole contiguous run when a retransmit fills
        // the hole ahead of it, and every one of those bytes is counted as
        // delivered at that instant. Model measured 1977 Mbit on a 1 Gbit
        // link that way. Without this call the clamp has nothing to clamp
        // against and WiFi keeps the unbounded estimate.
        let dr_window = self
            .rtt
            .min_rtt()
            .unwrap_or(Duration::from_millis(50))
            .max(Duration::from_millis(20));
        self.delivery.on_sent(bytes as u64, now, dr_window);
    }

    fn on_ack_received(&mut self, acked: &AckInfo, now: Instant) {
        // Update delivery rate and bandwidth estimates.
        let dr_window = self
            .rtt
            .min_rtt()
            .unwrap_or(Duration::from_millis(50))
            .max(Duration::from_millis(20));
        self.delivery.on_ack(acked.delivered_bytes, now, dr_window);
        // Only the byte-counted, RTT-windowed measurement. `acked.
        // delivery_rate` is a per-ACK figure the sender EWMAs over whatever
        // interval its ACK batches happen to span; preferring it here is
        // the defect that was measured at 7.6x capacity and removed from
        // `model.rs`. A max filter over an inflated sample latches the
        // inflation, and Steady has no mechanism to climb back down.
        let rate = self.delivery.delivery_rate();
        if rate > 0 {
            self.bandwidth.add_sample(rate, now);
        }

        self.update_round(acked.packet_number);

        match self.state {
            WifiState::Measuring => {
                // Slow start, ACK-clocked: the window grows by what was
                // delivered, so it doubles each round trip.
                //
                // Without this the whole Measuring phase runs at a fixed
                // `INITIAL_CWND`, and the bandwidth it "measures" is
                // therefore `INITIAL_CWND / rtt` -- a number set by a
                // constant in this file rather than by the path. On the
                // short scenario that is 6.1 MB/s and roughly right; on the
                // long ones it is not:
                //
                //     scenario        RTT     307200 B / RTT   measured
                //     transatlantic  100ms       3.07 MB/s      5.37
                //     degraded       200ms       1.54 MB/s      1.08
                //     satellite      300ms       1.02 MB/s      1.61
                //
                // Steady then starts from that floor, and on the lossy
                // paths its 1/9 reduction fires often enough that it never
                // climbs out: satellite fell from 6.70 to 1.61 MB/s, -76%.
                //
                // This is defect 3 exactly. Model had no slow start either,
                // and nobody could tell while a fabricated 400 Mbit seed was
                // covering for it. Removing that seed here uncovered the
                // same hole in the same way -- which is the argument for
                // removing fabricated values even when the code "works".
                let acked = acked.delivered_bytes as usize;
                self.cwnd = self
                    .cwnd
                    .saturating_add(acked)
                    .min(STARTUP_MAX_CWND);

                // After MEASURING_ROUNDS, transition to Steady with the
                // measured bandwidth.
                //
                // The windowed maximum, not the most recent sample. This
                // took `current_bandwidth()` to avoid being inflated by
                // ACK-batching artifacts -- a real hazard, but one that
                // lived in DeliveryRateEstimator, which sampled per ACK and
                // read 7.6x capacity. That is now byte-counted over a round
                // trip, so the max is safe and the single-sample read is
                // not: whatever value happened to land last became the rate
                // for the entire transfer, and Steady's adjustments are too
                // small to climb out. Measured before this change:
                // cross-country ran at ~0.23 MB/s of a 12.5 MB/s link and
                // timed out at 16%.
                if self.round_count >= MEASURING_ROUNDS {
                    let bw = self.bandwidth.max_bandwidth();
                    if bw > 0 {
                        self.measured_bw = bw;
                        self.target_rate = (bw as f64 * STEADY_RATE_FACTOR) as u64;
                        self.state = WifiState::Steady;
                        self.last_probe_round = self.round_count;
                        self.update_cwnd_and_pacing();
                        tracing::debug!(
                            bw_mbps = bw / (1024 * 1024),
                            rate_mbps = self.target_rate / (1024 * 1024),
                            "wifi: measured bandwidth, entering steady"
                        );
                    }
                }
            }

            WifiState::Steady => {
                // Track the windowed *maximum* delivery, not an EWMA of the
                // most recent sample.
                //
                // `target_rate = measured_bw * STEADY_RATE_FACTOR` with a
                // factor below 1, where `measured_bw` was an EWMA of
                // delivery measured *under that very rate*, is a contraction
                // mapping whose fixed point is zero. Each round the sender
                // paced at 0.95x what it last delivered, so it delivered
                // 0.95x, so it paced at 0.90x. Measured on cross-country:
                // 74.09 -> 64.40 -> 59.62 -> ... -> 11.76 -> 10.91 -> 10.13
                // Mbit, monotonic, until the transfer timed out. The probe
                // phase was meant to counteract this and is far too
                // infrequent to outrun a 5%-per-round decay.
                //
                // A windowed maximum cannot be dragged down by the
                // controller's own throttling: it holds what the path was
                // last seen to carry, so `0.95 * max` is a stable operating
                // point below capacity rather than a step in a descent.
                // This is what btlbw does in rl.rs and max_bandwidth in
                // model.rs. It is only safe because DeliveryRateEstimator is
                // now byte-counted over a round trip -- while it sampled per
                // ACK it read 7.6x capacity, and a max filter over that
                // latches the noise peak, which is why this code reached for
                // the current sample in the first place.
                let bw = self.bandwidth.max_bandwidth();
                if bw > 0 {
                    self.measured_bw = bw;
                    // While the estimate is still climbing on an empty
                    // queue, drive it -- STEADY_RATE_FACTOR of 1.0 is a
                    // fixed point and cannot climb on its own.
                    let gain = self.ramp_gain(now).unwrap_or(STEADY_RATE_FACTOR);
                    self.target_rate = (self.measured_bw as f64 * gain) as u64;
                    self.update_cwnd_and_pacing();
                }

                // Every PROBE_INTERVAL_ROUNDS, probe for more bandwidth.
                if self.round_count >= self.last_probe_round + PROBE_INTERVAL_ROUNDS {
                    self.state = WifiState::Probing;
                    self.probe_start = Some(now);
                    self.target_rate = (self.measured_bw as f64 * PROBE_GAIN) as u64;
                    self.update_cwnd_and_pacing();
                }
            }

            WifiState::Probing => {
                // Probe for PROBE_RTTS round trips, then evaluate.
                let probe_done = if let (Some(start), Some(srtt)) =
                    (self.probe_start, self.rtt.smoothed_rtt())
                {
                    // PROBE_RTTS, not one: the probe's own result arrives a
                    // round trip after it starts. See PROBE_RTTS.
                    now.duration_since(start) >= srtt * PROBE_RTTS
                } else {
                    self.round_count > self.last_probe_round + PROBE_INTERVAL_ROUNDS
                };

                if probe_done {
                    // The windowed maximum, not the latest sample. The
                    // Measuring->Steady transition above had the same bug
                    // and its comment explains it: whatever value happened
                    // to land last became the rate, and Steady's
                    // adjustments are too small to climb out of a bad one.
                    let bw = self.bandwidth.max_bandwidth();
                    if bw > self.measured_bw {
                        // Adopt it. This averaged -- `(measured_bw + bw)/2`
                        // -- so a successful probe kept half of what it
                        // found, and with PROBE_GAIN at 1.05 that is 2.5%
                        // retained per probe. On a long path, where probes
                        // are PROBE_INTERVAL_ROUNDS apart, the rate cannot
                        // reach capacity inside a transfer.
                        //
                        // Adopting a *measured maximum* is not a jump to an
                        // assumed value: the path delivered it.
                        self.measured_bw = bw;
                        tracing::debug!(
                            bw_mbps = bw / (1024 * 1024),
                            "wifi: probe discovered higher bandwidth"
                        );
                    }
                    self.target_rate = (self.measured_bw as f64 * STEADY_RATE_FACTOR) as u64;
                    self.state = WifiState::Steady;
                    self.last_probe_round = self.round_count;
                    self.update_cwnd_and_pacing();
                }
            }
        }
    }

    fn on_packet_lost(&mut self, lost: &[u64], now: Instant) {
        self.loss.on_packets_lost(lost, now);

        // Nothing has been measured yet, so there is no rate to reduce.
        //
        // Without this, a loss during Measuring runs the arithmetic below
        // on `target_rate == 0`: the reduction is 0, the floor is 0
        // (`measured_bw` is also still 0), and `.max(1)` -- a guard against
        // a zero divisor -- pins the rate at **1 byte per second**, which
        // is 1200 seconds per packet. The transfer stalls outright. On the
        // degraded path, whose 5% loss guarantees a loss before Measuring
        // completes, that took the controller from 26.3% of the link to
        // not completing at all.
        //
        // The guard was harmless only while `new()` asserted a 400 Mbit
        // seed, which is the defect above. Removing a fabricated value
        // exposes every place that quietly depended on it being nonzero.
        if self.state == WifiState::Measuring {
            // Loss ends slow start, as it does in every other controller
            // here. Without this the ACK-clocked growth above has no exit
            // except MEASURING_ROUNDS, and on a short path five round trips
            // of doubling is 15x the BDP: cross-country collapsed to 0.1%
            // of the link in simulation, caught by
            // `no_controller_collapses` in 8 s.
            //
            // Settle at what the path has actually been seen to deliver.
            // There is nothing else honest to settle at -- the window that
            // caused the loss is by definition too big, and `INITIAL_CWND`
            // is the constant this phase exists to stop depending on.
            let bw = self.bandwidth.max_bandwidth();
            if bw > 0 {
                self.measured_bw = bw;
                self.target_rate = (bw as f64 * STEADY_RATE_FACTOR) as u64;
                self.state = WifiState::Steady;
                self.last_probe_round = self.round_count;
                self.update_cwnd_and_pacing();
                tracing::debug!(
                    bw_mbps = bw / (1024 * 1024),
                    "wifi: loss ended measuring, entering steady"
                );
            }
            return;
        }
        if self.target_rate == 0 {
            return;
        }

        // UDT-style: only reduce rate when loss rate exceeds 1/cwnd_in_packets.
        let recent_loss = self.loss.recent_loss_rate(now);
        if recent_loss > self.loss_threshold() {
            // Reduce by 1/9 (UDT-style gentle decrease).
            let reduction = self.target_rate / LOSS_DECREASE_DIVISOR;
            let new_rate = self.target_rate.saturating_sub(reduction);
            // Floor at 50% of measured bandwidth.
            let floor = (self.measured_bw as f64 * MIN_RATE_FACTOR) as u64;
            self.target_rate = new_rate.max(floor).max(1);
            self.update_cwnd_and_pacing();
        }
        // Otherwise: ignore the loss (WiFi interference, not congestion).
    }

    fn congestion_window(&self) -> usize {
        self.cwnd
    }

    fn send_rate(&self) -> Option<u64> {
        if self.target_rate > 0 {
            Some(self.target_rate)
        } else {
            None
        }
    }

    fn can_send(&self, bytes_in_flight: usize) -> bool {
        bytes_in_flight < self.cwnd
    }

    fn on_rtt_update(&mut self, rtt: Duration) {
        self.rtt.update(rtt);
        self.bandwidth.update_rtt(rtt);
    }

    fn on_rtt_batch(&mut self, mean: Duration, min: Duration) {
        self.rtt.update_batch(mean, min);
        self.bandwidth.update_rtt(mean);
    }

    fn pacing_interval(&self, packet_size: usize) -> Duration {
        self.pacer.pacing_interval(packet_size)
    }

    fn diag_line(&self) -> Option<String> {
        Some(format!(
            "state={:?} cwnd={}KB target_rate={:.2}Mbit measured_bw={:.2}Mbit \
bw_max={:.2}Mbit bw_cur={:.2}Mbit round={} pace={:.2}Mbit",
            self.state,
            self.cwnd / 1024,
            self.target_rate as f64 * 8.0 / 1e6,
            self.measured_bw as f64 * 8.0 / 1e6,
            self.bandwidth.max_bandwidth() as f64 * 8.0 / 1e6,
            self.bandwidth.current_bandwidth() as f64 * 8.0 / 1e6,
            self.round_count,
            self.pacer.rate_bps() as f64 * 8.0 / 1e6,
        ))
    }

}

#[cfg(test)]
mod tests {
    use super::*;

    fn ack(pkt: u64, delivered: u64, rate: u64) -> AckInfo {
        AckInfo {
            packet_number: pkt,
            ack_delay: Duration::ZERO,
            delivered_bytes: delivered,
            delivery_rate: rate,
        }
    }

    #[test]
    fn initial_state_is_measuring() {
        let cc = WifiController::new();
        assert_eq!(cc.state, WifiState::Measuring);
        assert_eq!(cc.congestion_window(), INITIAL_CWND);
        // Unpaced until the path has been measured. This asserted a
        // positive rate while `new()` seeded 400 Mbit; the window is the
        // only limit the controller is entitled to impose before it has
        // observed anything.
        assert!(cc.send_rate().is_none());
    }

    #[test]
    fn measuring_transitions_to_steady() {
        let mut cc = WifiController::new();
        let now = Instant::now();
        cc.on_rtt_update(Duration::from_millis(10));

        // Simulate MEASURING_ROUNDS worth of sends and acks.
        let rate = 50_000_000u64; // 50 MB/s
        for i in 0..100 {
            let t = now + Duration::from_millis(i * 2);
            cc.on_packet_sent(i, MTU, t);
            cc.on_ack_received(&ack(i, MTU as u64, rate), t + Duration::from_millis(10));
        }

        // Should have left Measuring with a measured bandwidth. Not
        // `== Steady`: once out of Measuring the controller alternates
        // Steady and Probing, and a probe now spans PROBE_RTTS round trips,
        // so which of the two it is at any instant is a timing detail
        // rather than the thing this test is about.
        assert_ne!(cc.state, WifiState::Measuring);
        assert!(cc.measured_bw > 0);
    }

    #[test]
    fn loss_below_threshold_ignored() {
        let mut cc = WifiController::new();
        let now = Instant::now();
        cc.on_rtt_update(Duration::from_millis(10));
        // Was `seed_bandwidth(80_000_000)`; the method is gone, so set the
        // state it set. This is test setup, not a bootstrap the sender does.
        cc.target_rate = 80_000_000;
        cc.measured_bw = 80_000_000;
        cc.update_cwnd_and_pacing();
        cc.state = WifiState::Steady;

        let rate_before = cc.target_rate;

        // Send many packets, lose very few (well below 1/cwnd threshold).
        // cwnd_in_packets ≈ 1333, threshold ≈ 0.075%.
        // 1 loss in 5000 = 0.02% — safely below.
        for i in 0..5000 {
            cc.on_packet_sent(i, MTU, now + Duration::from_micros(i * 20));
        }
        cc.on_packet_lost(&[1], now + Duration::from_millis(200));

        // Rate should not change.
        assert_eq!(cc.target_rate, rate_before);
    }

    #[test]
    fn loss_above_threshold_reduces_by_ninth() {
        let mut cc = WifiController::new();
        let now = Instant::now();
        cc.on_rtt_update(Duration::from_millis(10));
        // Was `seed_bandwidth(80_000_000)`; the method is gone, so set the
        // state it set. This is test setup, not a bootstrap the sender does.
        cc.target_rate = 80_000_000;
        cc.measured_bw = 80_000_000;
        cc.update_cwnd_and_pacing();
        cc.measured_bw = 80_000_000;
        cc.state = WifiState::Steady;

        let rate_before = cc.target_rate;

        // Send some packets and trigger heavy loss.
        for i in 0..100 {
            cc.on_packet_sent(i, MTU, now + Duration::from_micros(i * 20));
        }
        // Lose a large batch to exceed the threshold.
        let lost: Vec<u64> = (0..50).collect();
        cc.on_packet_lost(&lost, now + Duration::from_millis(100));

        // Rate should have decreased.
        assert!(cc.target_rate < rate_before);
        // But not below 50% of measured.
        assert!(cc.target_rate >= (cc.measured_bw as f64 * MIN_RATE_FACTOR) as u64);
    }

    #[test]
    fn loss_threshold_uses_corrected_rate() {
        let mut cc = WifiController::new();
        let now = Instant::now();
        cc.on_rtt_update(Duration::from_millis(10));
        // Was `seed_bandwidth(80_000_000)`; the method is gone, so set the
        // state it set. This is test setup, not a bootstrap the sender does.
        cc.target_rate = 80_000_000;
        cc.measured_bw = 80_000_000;
        cc.update_cwnd_and_pacing();
        cc.measured_bw = 80_000_000;
        cc.state = WifiState::Steady;
        // Pin cwnd so the UDT-style threshold is exactly 1/4 = 25%.
        cc.cwnd = 4 * MTU;

        let rate_before = cc.target_rate;

        // 10 losses out of 35 sent: corrected recent rate = 10/35 ≈ 28.6%
        // exceeds the 25% threshold.  The old double-counted rate
        // (10/45 ≈ 22.2%) would have slipped below it.
        for i in 0..35 {
            cc.on_packet_sent(i, MTU, now + Duration::from_micros(i * 20));
        }
        let lost: Vec<u64> = (0..10).collect();
        cc.on_packet_lost(&lost, now + Duration::from_millis(100));

        assert!(cc.target_rate < rate_before);
    }

    #[test]
    fn duplicate_loss_report_does_not_double_count() {
        let mut cc = WifiController::new();
        let now = Instant::now();
        cc.on_rtt_update(Duration::from_millis(10));
        // Was `seed_bandwidth(80_000_000)`; the method is gone, so set the
        // state it set. This is test setup, not a bootstrap the sender does.
        cc.target_rate = 80_000_000;
        cc.measured_bw = 80_000_000;
        cc.update_cwnd_and_pacing();
        cc.state = WifiState::Steady;

        for i in 0..100 {
            cc.on_packet_sent(i, MTU, now + Duration::from_micros(i * 20));
        }
        // NACK and retransmission timeout report the same chunks.
        let lost: Vec<u64> = (0..10).collect();
        cc.on_packet_lost(&lost, now + Duration::from_millis(100));
        cc.on_packet_lost(&lost, now + Duration::from_millis(400));

        // Only the first report is counted: recent rate = 10/100 = 10%.
        let recent = cc.loss.recent_loss_rate(now + Duration::from_millis(400));
        assert!((recent - 0.1).abs() < 1e-9);
        assert_eq!(cc.loss.total_lost(), 10);
    }

    #[test]
    fn rate_never_below_floor() {
        let mut cc = WifiController::new();
        let now = Instant::now();
        cc.on_rtt_update(Duration::from_millis(10));
        // Was `seed_bandwidth(80_000_000)`; the method is gone, so set the
        // state it set. This is test setup, not a bootstrap the sender does.
        cc.target_rate = 80_000_000;
        cc.measured_bw = 80_000_000;
        cc.update_cwnd_and_pacing();
        cc.measured_bw = 80_000_000;
        cc.state = WifiState::Steady;

        // Trigger many loss events.
        for round in 0..20 {
            for i in 0..100 {
                let pkt = round * 100 + i;
                cc.on_packet_sent(pkt, MTU, now + Duration::from_micros(pkt * 20));
            }
            let lost: Vec<u64> = (round * 100..round * 100 + 50).collect();
            cc.on_packet_lost(&lost, now + Duration::from_millis(round * 100));
        }

        let floor = (80_000_000f64 * MIN_RATE_FACTOR) as u64;
        assert!(cc.target_rate >= floor);
    }
}
