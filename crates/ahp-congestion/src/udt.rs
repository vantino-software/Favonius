// Favonius — high-performance file transfer over UDP
// Copyright (c) 2025-2026 Vantino SàRL
// SPDX-License-Identifier: Apache-2.0

//! AHP-UDT: Rust port of UDT4's CUDTCC congestion control algorithm.
//!
//! Faithful reimplementation of UDT's rate-based CC as described in the UDT4
//! source (ccc.cpp). Key properties:
//!
//! - **Rate-controlled, not window-controlled**: `pkt_snd_period` (inter-packet
//!   interval in μs) is the primary control variable.
//! - **Gentle loss response**: On loss, sending period increases by 12.5%
//!   (rate decreases ~11%), with at most 5 decreases per congestion epoch.
//! - **Bandwidth-driven**: Uses estimated bandwidth from receiver feedback to
//!   compute rate increases.
//! - **Slow start**: cwnd grows by acked packets until it hits max_cwnd, then
//!   switches to rate-based control.

use std::time::{Duration, Instant};

use crate::metrics::RttEstimator;
use crate::pacer::Pacer;
use crate::{AckInfo, CongestionController};

/// Default MTU for rate calculations.
const MTU: usize = 1200;

/// SYN interval: rate control happens at most once per this interval.
/// UDT uses 10ms; we use 5ms for faster convergence on short transfers.
const SYN_INTERVAL: Duration = Duration::from_millis(5);

/// Initial cwnd in packets (UDT default: 16).
const INITIAL_CWND_PKTS: f64 = 16.0;

/// Initial packet sending period in microseconds (send as fast as possible).
const INITIAL_SND_PERIOD: f64 = 1.0;

/// Minimum rate increase per SYN interval.
/// Multiple of the BDP the congestion window is allowed to reach.
///
/// This was 4.0, inherited from UDT v3, which is three BDPs of standing
/// queue on a link buffered at one BDP -- a full buffer by construction.
/// `rl.rs` demoted the identical constant to 2.0 with measurements; UDT
/// was not brought along, and sat at cwnd 1476 KB against a 312 KB BDP,
/// 4.73x, with 31 ms of excess delay on a 25 ms path.
///
/// 1.25 is A1's delay budget expressed as a window: `8 ms + 0.25 x
/// base_rtt` less about 7 ms of fixed overhead leaves roughly a quarter
/// of a BDP for queue.
///
/// **This did not reduce the standing queue.** Excess delay measured
/// 31.0 ms on cross-country and 39.0 ms on transatlantic both before and
/// after, to the tenth of a millisecond. The window is not what governs
/// here: the pacer is faithful (debt_ratio 0.995) and commands 102.4 Mbit
/// into a 100 Mbit link, so a 2.4% overdrive fills the buffer regardless
/// of how much window is available. The constant is changed for
/// consistency with rl.rs, which demoted the identical 4.0 with
/// measurements, and not because it fixed anything.
const CWND_BDP_GAIN: f64 = 1.25;

/// Multiple of the measured BDP that `max_cwnd` may ratchet up to.
///
/// Replaces a bare `4096.0`. See the use site, and rl.rs's constant of the
/// same name for the measurement that motivated it.
const MAX_CWND_BDP_MULT: f64 = 1.5;

/// Floor for the `max_cwnd` ceiling, in packets — the historical initial
/// `max_cwnd`. `rcv_rate` is zero until the first measurement, so without
/// this the window could never open.
const MAX_CWND_FLOOR_PKTS: f64 = 1024.0;

/// Absolute backstop on `max_cwnd`, in packets. Not a control parameter —
/// it bounds memory if the rate estimate goes pathological.
const MAX_CWND_HARD_PKTS: f64 = 65536.0;

/// Standing-queue budget above `min_rtt` before loss counts as congestion.
///
/// Same form and constants as `rl.rs`, `fair.rs` and `classic.rs`, which all
/// received this as defect 15. UDT was the fourth file with the identical
/// shape and never got it: `srtt` and `min_rtt` appeared in its diagnostic
/// line and in no decision, so it reduced its rate on every loss of three or
/// more packets regardless of whether a queue existed.
///
/// On a 2% random-loss path that is the Mathis trap. Measured on satellite:
/// srtt 157.5 ms against a min_rtt of 150.1 -- an excess of 7.4 ms, which is
/// this rig's fixed delay floor and not queueing at all -- while the
/// controller commanded 80 Mbit of a 100 Mbit link and oscillated 74 to 83
/// as it backed off and recovered. Classic on the same path holds 45 ms of
/// real queue and delivers 8.90 MB/s against UDT's 7.50.
///
/// A fixed term plus a fraction, not a ratio: the 7.4 ms floor is 1.30x at a
/// 25 ms base and 1.05x at 150 ms, so any bare `srtt/min_rtt >= k` means a
/// different thing on every path.
// REJECTED (2): a probe/drain cycle for the send rate.
//
// The second attempt at UDT's satellite gap, and it fixes what the first got
// wrong while still not fixing the gap. Gains and phase lengths taken from
// rl.rs -- probe 1.25x for 2 RTTs, drain 0.75x for 2, cruise 1.0x for 4 --
// so the offered load averages exactly the measured rate over a cycle, and
// the rate is *recomputed* as `measured * gain` rather than multiplied into
// its own previous value.
//
// Both of those worked. The permanent overdrive of attempt (1) is gone:
// satellite and degraded held empty queues (1.05x and 1.15x) with
// retransmits at the path's own loss.
//
//   scenario        goodput           retx            delay
//   cross-country   10.37 -> 10.63   2.17 -> 6.47%    2.23x
//   transatlantic   10.00 -> 10.10   2.38 -> 6.43%    2.11x
//   satellite        7.50 ->  7.33   2.04 -> 2.13%    1.05x
//   degraded         7.57 ->  8.83   5.30 -> 5.03%    1.15x
//
// But **satellite, the scenario this was for, did not move** (-2.2%), while
// the two short paths tripled their retransmits for 1-2.5% of throughput.
// degraded gained 16.7% cleanly, which is real but was not the target and
// sits at roughly twice that cell's resolution.
//
// So the cycle is not what limits UDT on a long path. Whatever does is still
// unidentified: on satellite the controller holds an empty queue, loses only
// what the path loses, and stops at 7.3-7.5 MB/s where Classic reaches 8.9.
// The bandwidth estimate, the window bound and the loss response have all now
// been examined and none of them explains it.
//
// Keeping the cycle for degraded alone would mean gating a mechanism on the
// scenario, which the controller cannot know; gating it on RTT would be
// tuning to this benchmark.

// REJECTED: an RTT-clocked multiplicative ramp for the send rate.// REJECTED: an RTT-clocked multiplicative ramp for the send rate.
//
// UDT's increase is `inc` derived from `b = bandwidth - current_rate`, and
// `bandwidth` tracks observed *delivery*, which the rate caps. So the
// estimate converges on the rate, the headroom on zero, and the increase on
// its minimum increment: the rate cannot climb to a ceiling it has not
// already reached. Measured on satellite, the controller commanded 80 Mbit
// of a 100 Mbit link while holding srtt 157.5 ms against a min_rtt of 150.1
// -- an empty queue -- and crept upward by fractions of a percent. That is
// the same self-referential shape fixed in rl.rs, model.rs and wifi.rs.
//
// The fix that worked there does not work here, and the measurement is worth
// keeping. A ramp multiplying `pkt_snd_period` once per min_rtt while the
// queue is empty, bounded at 1.5x measured delivery, produced:
//
//   scenario        goodput            retx            delay
//   cross-country   10.37 -> 10.70   2.17 -> 16.82%    2.24x
//   transatlantic   10.00 -> 10.07   2.38 ->  5.39%    2.11x
//   satellite        7.50 ->  8.47   2.04 -> 26.23%    2.04x
//   degraded         7.57 ->  9.37   5.30 -> 22.43%    2.05x
//
// Throughput up 13-24% on the long paths, bought with 14-24 *points* of
// self-inflicted loss and a doubled round trip. That is the trade this
// project rejected when a trained RL policy made it at smaller magnitude,
// and it fails the criteria in the CC research notes section 6 item 3.
//
// The difference from rl.rs is structural: there the rate is *recomputed*
// as `gain * btlbw` every interval and the gain cycle drains afterwards, so
// an overshoot is transient. Here the ramp *compounds* the period with no
// drain, so a ceiling of C is a permanent (C-1)/C overdrive -- 33% at 1.5,
// against 26% measured. Even C = 1.05 would sit at ~5% permanent loss.
//
// Making this work needs a drain phase, i.e. restructuring UDT's rate law
// toward the cruise/probe/drain shape rl.rs already has. That is a larger
// change than a constant and it has not been attempted.
const LOSS_QUEUEING_FIXED: Duration = Duration::from_millis(8);
const LOSS_QUEUEING_FRACTION: f64 = 0.25;

const MIN_INC: f64 = 0.01;

/// Loss decrease factor: period *= 1.125 (rate *= 0.889, ~11% decrease).
const LOSS_INCREASE_FACTOR: f64 = 1.125;

/// Maximum decreases per congestion epoch.
const MAX_DEC_PER_EPOCH: usize = 5;

/// UDT CC controller.
#[derive(Debug)]
pub struct UdtController {
    /// Packet sending period in microseconds.
    pkt_snd_period: f64,
    /// Congestion window in packets.
    cwnd: f64,
    /// Maximum cwnd in packets (bounded to prevent bloat without receiver flow control).
    max_cwnd: f64,
    /// Estimated bandwidth in packets/sec (from receiver feedback).
    bandwidth: u64,
    /// Receiver-side packet arrival rate (packets/sec).
    rcv_rate: u64,
    /// RTT estimator.
    rtt: RttEstimator,
    /// Pacer for pacing_interval() output.
    pacer: Pacer,
    /// MSS (maximum segment size) in bytes.
    mss: usize,

    // Rate control state
    /// Whether we're in slow start phase.
    slow_start: bool,
    /// Last ACKed sequence number.
    last_ack: u64,
    /// Whether loss occurred since last rate increase.
    loss_flag: bool,
    /// Highest sent chunk index when last decrease happened.
    last_dec_seq: u64,
    /// Sending period value when last decrease happened.
    last_dec_period: f64,
    /// NAK count in current congestion epoch.
    nak_count: u32,
    /// Random threshold for decrease (avoids global synchronization).
    dec_random: u32,
    /// Average NAKs per congestion epoch (EWMA).
    avg_nak_num: f64,
    /// Number of decreases in current congestion epoch.
    dec_count: usize,
    /// Timestamp of last rate control update.
    last_rc_time: Instant,
    /// Current highest sent chunk index (high-water mark).
    snd_curr_seq: u64,
}

impl UdtController {
    pub fn new() -> Self {
        Self {
            pkt_snd_period: INITIAL_SND_PERIOD,
            cwnd: INITIAL_CWND_PKTS,
            max_cwnd: 1024.0,
            bandwidth: 0,
            rcv_rate: 0,
            rtt: RttEstimator::new(),
            pacer: Pacer::new(100_000_000), // ~100 MB/s initial
            mss: 1414, // AHP wire packet size
            slow_start: true,
            last_ack: 0,
            loss_flag: false,
            last_dec_seq: 0,
            last_dec_period: 1.0,
            nak_count: 0,
            dec_random: 1,
            avg_nak_num: 0.0,
            dec_count: 0,
            last_rc_time: Instant::now(),
            snd_curr_seq: 0,
        }
    }

    /// Convert pkt_snd_period (μs) to bytes/sec rate.
    fn rate_bps(&self) -> u64 {
        if self.pkt_snd_period <= 0.0 {
            return 100_000_000; // fallback
        }
        // rate = MSS / period_seconds = MSS * 1_000_000 / period_us
        (self.mss as f64 * 1_000_000.0 / self.pkt_snd_period) as u64
    }

    /// Update the Pacer to match current sending rate.
    fn sync_pacer(&mut self) {
        self.pacer.set_rate(self.rate_bps());
    }

    /// Get RTT in microseconds.
    fn rtt_us(&self) -> u64 {
        self.rtt.smoothed_rtt()
            .unwrap_or(Duration::from_millis(10))
            .as_micros() as u64
    }


    /// Did this loss arrive with a standing queue? Loss without one is the
    /// path being lossy, not full, and reducing the rate for it is how a
    /// controller talks itself down a link it was coping with.
    fn queue_above_budget(&self) -> bool {
        match (self.rtt.smoothed_rtt(), self.rtt.min_rtt()) {
            (Some(srtt), Some(min)) => {
                let budget = LOSS_QUEUEING_FIXED.as_secs_f64()
                    + LOSS_QUEUEING_FRACTION * min.as_secs_f64();
                srtt.as_secs_f64() - min.as_secs_f64() >= budget
            }
            // No estimate yet: keep the historical behaviour.
            _ => true,
        }
    }
}

impl Default for UdtController {
    fn default() -> Self {
        Self::new()
    }
}

impl CongestionController for UdtController {
    fn on_packet_sent(&mut self, packet_number: u64, bytes: usize, now: Instant) {
        // Retransmits re-report an older chunk index; keep the high-water mark.
        self.snd_curr_seq = self.snd_curr_seq.max(packet_number);
        self.pacer.on_packet_sent(bytes, now);
    }

    fn on_ack_received(&mut self, acked: &AckInfo, now: Instant) {
        // Update both rcv_rate and bandwidth from delivery rate feedback.
        // Without packet-pair probing, the delivery rate is our best estimate
        // of link capacity.
        if acked.delivery_rate > 0 {
            let pps = acked.delivery_rate / self.mss as u64;
            if pps > 0 {
                // EWMA-smooth rcv_rate (same as UDT: 7/8 old + 1/8 new).
                self.rcv_rate = if self.rcv_rate == 0 {
                    pps
                } else {
                    (self.rcv_rate * 7 + pps) / 8
                };
                // Update bandwidth: track observed delivery rate to maintain
                // headroom for the rate increase formula. Ratchet up quickly
                // (3/4 new) so headroom appears promptly; never decrease
                // below the seed.
                if pps > self.bandwidth {
                    self.bandwidth = (self.bandwidth / 4) + (pps * 3 / 4);
                }
            }
        }

        let ack_seq = acked.packet_number;
        let rtt_us = self.rtt_us();
        let syn_us = SYN_INTERVAL.as_micros() as u64;

        // Rate control: at most once per SYN interval.
        if now.duration_since(self.last_rc_time) < SYN_INTERVAL {
            return;
        }
        self.last_rc_time = now;

        if self.slow_start {
            // Slow start: grow cwnd by number of newly acked packets.
            let newly_acked = ack_seq.saturating_sub(self.last_ack);
            self.cwnd += newly_acked as f64;
            self.last_ack = ack_seq;

            if self.cwnd > self.max_cwnd {
                self.slow_start = false;
                // Clamp cwnd to max_cwnd on exit — don't carry bloat forward.
                self.cwnd = self.max_cwnd;
                // Adopt the measured period. This was guarded by
                // `if rcv_period < self.pkt_snd_period`, which only ever
                // *decreases* the period -- and the period starts at 1.0 us,
                // "send as fast as possible", so no measurement can ever be
                // smaller and it never moved. Its own comment said to keep
                // the current period "if it's already faster", assuming
                // `seed_bandwidth` had set a sane one. That seed was
                // `min_cwnd_floor / base_rtt`, a window floor rather than a
                // measurement, and removing it left this at 1.0 us for the
                // whole transfer: a commanded 11,312 Mbit on a 100 Mbit
                // link, i.e. no pacing at all, with cwnd ratcheting to its
                // 4096-packet ceiling -- 18x the BDP -- and 77% of packets
                // retransmitted.
                //
                // Leaving slow start is exactly when a controller should
                // settle at what it measured, as Classic's plateau exit and
                // Model's target_cwnd do.
                self.pkt_snd_period = if self.rcv_rate > 0 {
                    1_000_000.0 / self.rcv_rate as f64
                } else {
                    (rtt_us + syn_us) as f64 / self.cwnd
                };
                self.sync_pacer();
            }
            return; // No rate increase during slow start.
        }

        // Steady state: cwnd sized from the target sending rate so the
        // window doesn't bottleneck the pacing rate.
        // cwnd = max(rcv_rate, target_rate_pps) * (RTT + SYN) + 16
        // For rate-based CC the pacing rate is the real throughput control.
        // cwnd just needs enough headroom for GSO batching and burst.
        // Set to 4× BDP — generous enough to never bottleneck pacing,
        // bounded enough to report a meaningful value.
        let rate_for_cwnd = self.rcv_rate.max(
            (1_000_000.0 / self.pkt_snd_period) as u64
        );
        if rate_for_cwnd > 0 {
            let bdp = rate_for_cwnd as f64 / 1_000_000.0
                * (rtt_us + syn_us) as f64
                + 16.0;
            // `.min`, not `.max`. `max_cwnd` is a cap everywhere else --
            // it clamps cwnd downward at the other sites in this file --
            // and only here was it applied as a floor, which is what its
            // name says it is not. Identical to the defect measured and
            // fixed in rl.rs, where the floor turned out to be what set
            // the window in every scenario: cross-country landed on 1024
            // packets exactly, against a 2xBDP bound of 452.
            self.cwnd = (bdp * CWND_BDP_GAIN).min(self.max_cwnd);
        }

        // If loss happened since last increase, skip this round.
        if self.loss_flag {
            self.loss_flag = false;
            return;
        }

        // Rate increase (UDT algorithm).
        // B = bandwidth - current_rate (available bandwidth headroom).
        let current_rate_pps = (1_000_000.0 / self.pkt_snd_period) as i64;
        let b = self.bandwidth as i64 - current_rate_pps;

        let inc = if b <= 0 {
            MIN_INC
        } else {
            let raw = 10.0_f64.powf(
                (b as f64 * self.mss as f64 * 8.0).log10().ceil()
            ) * 0.0000015 / self.mss as f64;
            raw.max(MIN_INC)
        };

        // period = period * SYN / (period * inc + SYN)
        self.pkt_snd_period = (self.pkt_snd_period * syn_us as f64)
            / (self.pkt_snd_period * inc + syn_us as f64);

        // Grow max_cwnd when the *measured* pipe approaches the cap.
        //
        // This used `pkt_snd_period` -- the controller's own commanded send
        // period -- to compute the BDP that decides whether the window may
        // grow. That is a closed loop: a low rate gives a small BDP, a small
        // BDP fails the test, `max_cwnd` does not grow, and the window keeps
        // the rate low. Measured on satellite, `max_cwnd` crawled 1024 ->
        // 1600 -> 2000 and stalled, against a path whose BDP is 1326
        // packets and which Classic filled.
        //
        // `rcv_rate` is the receiver's measured arrival rate, so it is a
        // property of the path rather than of the window, and the loop is
        // open. It falls back to the commanded period only before any
        // measurement exists, where there is nothing better and the window
        // is at its initial value anyway.
        //
        // Same defect class as rl.rs's `btlbw` staircase and model.rs's
        // premature Startup exit -- a bound on the window derived from a
        // quantity the window itself constrains.
        let rate_pps = if self.rcv_rate > 0 {
            self.rcv_rate as f64
        } else {
            1_000_000.0 / self.pkt_snd_period
        };
        let bdp_pkts = rate_pps / 1_000_000.0 * (rtt_us + syn_us) as f64 + 16.0;

        // The ceiling the ratchet may reach is derived from the measured
        // BDP, not from a constant. See rl.rs's `MAX_CWND_BDP_MULT` and
        // the project engineering log: the `4096.0` this replaces
        // was 5.73 MB on every path regardless of that path's BDP, and at
        // 1 Gbit an A/B against 65536 moved satellite +26% and degraded
        // +15% here.
        //
        // `min_rtt`, not `rtt_us`: the smoothed RTT rises with the queue
        // this window builds, so a ceiling derived from it grows as the
        // window overshoots. That is the same closed loop the growth
        // trigger above was fixed for.
        //
        // The multiple is 1.5 rather than rl.rs's 1.25 because `max_cwnd`
        // does more work in this file — it is also the slow-start exit
        // (`cwnd > max_cwnd` above) — and `CWND_BDP_GAIN` here is already
        // 1.25. Leaving the ceiling above the gain keeps the gain the
        // operating point and the ceiling a backstop, rather than having
        // the cap bind permanently.
        let measured_bdp_pkts = match self.rtt.min_rtt() {
            Some(m) if self.rcv_rate > 0 => self.rcv_rate as f64 * m.as_secs_f64(),
            _ => 0.0,
        };
        let ceiling = (measured_bdp_pkts * MAX_CWND_BDP_MULT)
            .max(MAX_CWND_FLOOR_PKTS)
            .min(MAX_CWND_HARD_PKTS);

        if bdp_pkts > self.max_cwnd * 0.8 && self.max_cwnd < ceiling {
            self.max_cwnd = (self.max_cwnd * 1.25).min(ceiling);
        }
        // High-water mark: it does not follow the ceiling down. See the
        // matching comment in rl.rs — clamping downward closes a loop
        // through delivery and cost `rl` 94.3 -> 28.6 MiB/s at 1 Gbit.

        self.sync_pacer();
    }


    fn on_packet_lost(&mut self, lost: &[u64], _now: Instant) {
        if lost.is_empty() {
            return;
        }

        // Exit slow start on first loss.
        if self.slow_start {
            self.slow_start = false;
            if self.rcv_rate > 0 {
                // Adopt the measured period unconditionally; see the
                // matching site in the ACK path. The guard here referred to
                // a "faster seeded period" that no longer exists, and with
                // the period starting at 1.0 us it could never fire.
                self.pkt_snd_period = 1_000_000.0 / self.rcv_rate as f64;
            } else {
                // No rate measurement yet: slow down to one cwnd per
                // (RTT + SYN), UDT4-style. Period is µs/packet, i.e.
                // (rtt + syn) / cwnd — not cwnd / (rtt + syn).
                let rtt_us = self.rtt_us();
                let syn_us = SYN_INTERVAL.as_micros() as u64;
                self.pkt_snd_period = (rtt_us + syn_us) as f64 / self.cwnd;
            }
            self.sync_pacer();
            return;
        }

        // Only trigger rate decrease on significant loss (≥ 3 packets).
        // Sporadic 1-2 packet losses from WiFi interference are ignored
        // for rate control (they still get retransmitted via the sender's
        // retx queue).
        if lost.len() < 3 {
            return;
        }

        // ...and only when the loss came with a queue. See
        // `LOSS_QUEUEING_FIXED`.
        if !self.queue_above_budget() {
            return;
        }

        self.loss_flag = true;
        let first_loss = lost[0];

        if first_loss > self.last_dec_seq {
            // New congestion epoch.
            self.last_dec_period = self.pkt_snd_period;
            self.pkt_snd_period = (self.pkt_snd_period * LOSS_INCREASE_FACTOR).ceil();

            self.avg_nak_num = self.avg_nak_num * 0.875 + self.nak_count as f64 * 0.125;
            self.nak_count = 1;
            self.dec_count = 1;

            self.last_dec_seq = self.snd_curr_seq;

            // Random threshold to avoid global synchronization.
            self.dec_random = ((self.avg_nak_num * rand::random::<f64>()).ceil() as u32).max(1);
        } else if self.dec_count < MAX_DEC_PER_EPOCH {
            self.nak_count += 1;
            if self.nak_count % self.dec_random == 0 {
                // Additional decrease within the same epoch.
                // 0.889^5 ≈ 0.55: rate won't drop below ~55% in one epoch.
                self.pkt_snd_period = (self.pkt_snd_period * LOSS_INCREASE_FACTOR).ceil();
                self.last_dec_seq = self.snd_curr_seq;
                self.dec_count += 1;
            }
        }

        self.sync_pacer();
    }

    fn congestion_window(&self) -> usize {
        (self.cwnd as usize * self.mss).max(16 * MTU)
    }

    fn send_rate(&self) -> Option<u64> {
        Some(self.rate_bps())
    }

    fn can_send(&self, bytes_in_flight: usize) -> bool {
        bytes_in_flight < self.congestion_window()
    }

    fn on_rtt_update(&mut self, rtt: Duration) {
        self.rtt.update(rtt);
    }

    fn on_rtt_batch(&mut self, mean: Duration, min: Duration) {
        self.rtt.update_batch(mean, min);
    }

    fn pacing_interval(&self, packet_size: usize) -> Duration {
        self.pacer.pacing_interval(packet_size)
    }

    fn diag_line(&self) -> Option<String> {
        let srtt_us = self.rtt.smoothed_rtt().map(|r| r.as_micros()).unwrap_or(0);
        let min_us = self.rtt.min_rtt().map(|r| r.as_micros()).unwrap_or(0);
        Some(format!(
            "slow_start={} cwnd={:.0}pkt max_cwnd={:.0}pkt rate={:.2}Mbit \
rcv_rate={:.2}Mbit bw={:.2}Mbit srtt={:.1}ms min_rtt={:.1}ms infl={:.2} \
period={:.1}us",
            self.slow_start,
            self.cwnd,
            self.max_cwnd,
            self.rate_bps() as f64 * 8.0 / 1e6,
            self.rcv_rate as f64 * self.mss as f64 * 8.0 / 1e6,
            self.bandwidth as f64 * self.mss as f64 * 8.0 / 1e6,
            srtt_us as f64 / 1000.0,
            min_us as f64 / 1000.0,
            if min_us > 0 { srtt_us as f64 / min_us as f64 } else { 0.0 },
            self.pkt_snd_period,
        ))
    }

    fn wants_timeout_loss(&self) -> bool { false }

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
    fn initial_state() {
        let cc = UdtController::new();
        assert!(cc.slow_start);
        assert!(cc.congestion_window() > 0);
        assert!(cc.send_rate().unwrap() > 0);
    }

    #[test]
    fn slow_start_grows_cwnd() {
        let mut cc = UdtController::new();
        let now = Instant::now();
        cc.on_rtt_update(Duration::from_millis(10));

        let initial_cwnd = cc.cwnd;
        cc.on_packet_sent(1, MTU, now);
        // Wait SYN interval.
        let t = now + SYN_INTERVAL + Duration::from_millis(1);
        cc.on_ack_received(&ack(1, MTU as u64, 50_000_000), t);

        assert!(cc.cwnd > initial_cwnd);
        assert!(cc.slow_start); // Still in slow start (cwnd < max_cwnd)
    }

    #[test]
    fn loss_exits_slow_start() {
        let mut cc = UdtController::new();
        let now = Instant::now();
        cc.on_rtt_update(Duration::from_millis(10));
        cc.on_packet_sent(1, MTU, now);
        cc.on_packet_sent(2, MTU, now);

        assert!(cc.slow_start);
        cc.on_packet_lost(&[1], now + Duration::from_millis(50));
        assert!(!cc.slow_start);
    }

    /// Drive srtt above min_rtt by more than the queue budget, so a loss
    /// counts as congestion. The reduction tests below predate the gate and
    /// fed a single RTT sample, which leaves srtt == min_rtt and no queue --
    /// they were asserting that the controller backs off on an idle path.
    fn build_queue(cc: &mut UdtController) {
        let min = Duration::from_millis(10);
        cc.on_rtt_update(min);
        for _ in 0..20 {
            cc.on_rtt_update(Duration::from_millis(80));
        }
        assert!(cc.queue_above_budget(), "test setup failed to build a queue");
    }

    /// The gate: loss on a path with no standing queue must not reduce the
    /// rate. This is the whole point -- UDT reduced on every loss of three
    /// or more packets, and on satellite it did so while holding srtt 157.5
    /// ms against a min_rtt of 150.1, i.e. no queue at all, commanding 80
    /// Mbit of a 100 Mbit link.
    #[test]
    fn random_loss_without_a_queue_does_not_slow_the_sender() {
        let mut cc = UdtController::new();
        let now = Instant::now();
        // An idle path: srtt tracks min_rtt.
        let rtt = Duration::from_millis(150);
        for _ in 0..20 {
            cc.on_rtt_update(rtt);
        }
        assert!(!cc.queue_above_budget());

        cc.slow_start = false;
        cc.pkt_snd_period = 20.0;
        cc.snd_curr_seq = 100;
        cc.last_dec_seq = 0;
        let before = cc.pkt_snd_period;

        cc.on_packet_lost(&[50, 51, 52], now);
        assert_eq!(
            cc.pkt_snd_period, before,
            "slowed down for random loss on an empty queue"
        );
    }

    #[test]
    fn loss_increases_period() {
        let mut cc = UdtController::new();
        let now = Instant::now();
        build_queue(&mut cc);
        cc.slow_start = false;
        cc.pkt_snd_period = 20.0;
        cc.snd_curr_seq = 100;
        cc.last_dec_seq = 0;

        let period_before = cc.pkt_snd_period;
        // Need ≥3 lost packets to exceed the loss threshold.
        cc.on_packet_lost(&[50, 51, 52], now);

        // Period should increase by 12.5%.
        assert!((cc.pkt_snd_period - (period_before * LOSS_INCREASE_FACTOR).ceil()).abs() < 0.01);
    }

    #[test]
    fn max_five_decreases_per_epoch() {
        let mut cc = UdtController::new();
        let now = Instant::now();
        cc.on_rtt_update(Duration::from_millis(10));
        cc.slow_start = false;
        cc.pkt_snd_period = 20.0;
        cc.snd_curr_seq = 100;
        cc.last_dec_seq = 0;
        cc.dec_random = 1; // Trigger decrease on every NAK.

        // First loss: new epoch.
        cc.on_packet_lost(&[50], now);
        let period_after_first = cc.pkt_snd_period;

        // 10 more losses within the same epoch.
        for i in 1..=10 {
            cc.on_packet_lost(&[50 + i], now + Duration::from_millis(i as u64));
        }

        // Should have decreased at most 5 times total (dec_count capped).
        // 0.889^5 ≈ 0.55, so period should be at most ~2× the first decrease value.
        assert!(cc.pkt_snd_period < period_after_first * 2.0);
    }

    #[test]
    fn loss_slow_start_exit_reduces_rate() {
        let mut cc = UdtController::new();
        let now = Instant::now();
        cc.on_rtt_update(Duration::from_millis(10));
        // No seed: rcv_rate == 0, period = 1 µs (send as fast as possible).
        for i in 0..16 {
            cc.on_packet_sent(i, MTU, now);
        }
        let rate_before = cc.rate_bps();

        cc.on_packet_lost(&[3], now + Duration::from_millis(20));
        let rate_after = cc.rate_bps();

        // First loss must slow the sender down, not speed it up. The
        // inverted formula (cwnd / (rtt+syn)) produced ~1.4 TB/s here.
        assert!(rate_after < rate_before,
            "rate after first loss ({rate_after}) must be below pre-loss rate ({rate_before})");
        // Order of magnitude: (10ms RTT + 5ms SYN) / 16 pkts = 937.5 µs/pkt
        // → ~1.5 MB/s.
        assert!(rate_after > 100_000 && rate_after < 10_000_000,
            "rate after first loss ({rate_after}) has wrong order of magnitude");
    }

    #[test]
    fn epoch_suppression_in_chunk_index_space() {
        let mut cc = UdtController::new();
        let now = Instant::now();
        // A queue must exist or the loss gate suppresses every reduction and
        // there is no epoch behaviour to observe.
        build_queue(&mut cc);
        cc.slow_start = false;
        cc.pkt_snd_period = 20.0;

        // Packet numbers are global chunk indices (0-based).
        for i in 0..20 {
            cc.on_packet_sent(i, MTU, now);
        }
        // First loss: new epoch, period increases; epoch marked at chunk 19.
        // (The new-epoch path recomputes dec_random from avg_nak_num, so pin
        // it afterwards to isolate the epoch-boundary behavior.)
        cc.on_packet_lost(&[1, 2, 3], now);
        let period_after_first = cc.pkt_snd_period;
        assert!(period_after_first > 20.0);
        cc.dec_random = 1000; // no randomized extra decreases within the epoch

        // A retransmit re-reports an old chunk index; the epoch high-water
        // mark must not regress.
        cc.on_packet_sent(2, MTU, now);
        assert_eq!(cc.snd_curr_seq, 19);

        // Duplicate loss report in the same epoch: suppressed.
        cc.on_packet_lost(&[4, 5, 6], now);
        assert_eq!(cc.pkt_snd_period, period_after_first);

        // Loss above the epoch mark: new epoch, decrease applied again.
        for i in 20..30 {
            cc.on_packet_sent(i, MTU, now);
        }
        cc.on_packet_lost(&[25, 26, 27], now);
        assert!(cc.pkt_snd_period > period_after_first);
    }

#[cfg(test)]
mod cap_tests {
    use super::*;

    /// `max_cwnd` is a cap, not a floor.
    ///
    /// It was applied with `.max()` at the BDP site while two other sites
    /// clamp downward to it. Same defect as rl.rs, where the floor turned
    /// out to be what set the window in every measured scenario.
    #[test]
    fn max_cwnd_bounds_the_window_from_above() {
        let mut cc = UdtController::new();
        let now = Instant::now();
        cc.on_rtt_update(Duration::from_millis(25));
        cc.slow_start = false;
        cc.max_cwnd = 64.0;
        cc.rcv_rate = 100_000;

        for i in 0..64u64 {
            cc.on_packet_sent(i, MTU, now);
            cc.on_ack_received(
                &AckInfo {
                    packet_number: i,
                    ack_delay: Duration::ZERO,
                    delivered_bytes: MTU as u64,
                    delivery_rate: 12_500_000,
                },
                now + Duration::from_millis(25 + i),
            );
        }

        assert!(
            cc.cwnd <= cc.max_cwnd,
            "cwnd {} exceeded the cap {}",
            cc.cwnd,
            cc.max_cwnd
        );
    }

    /// The `max_cwnd` ceiling scales with the path.
    ///
    /// It was the constant `4096.0` on every path: 5.73 MB whether the BDP
    /// was 3 MB or 19 MB. Measured at 1 Gbit, that constant was the binding
    /// limit on all four rig scenarios simultaneously — arm A's peak window
    /// read 5656 KB (= 4096 x 1400) on each of them, one number across four
    /// different bandwidth-delay products. See the engineering log.
    /// 
    ///
    /// This drives two paths that differ only in delay and asserts the
    /// ceilings differ in the same direction. The absolute values are not
    /// pinned — the growth ratchet is 1.25x per interval, so where a run
    /// stops depends on how many intervals it got — only that a 150 ms path
    /// is allowed a larger window than a 10 ms one at the same rate.
    #[test]
    fn max_cwnd_ceiling_scales_with_the_path() {
        fn drive(delay_ms: u64) -> f64 {
            let mut cc = UdtController::new();
            let now = Instant::now();
            cc.on_rtt_update(Duration::from_millis(delay_ms));
            cc.slow_start = false;
            // 1 Gbit in packets/s, so the BDP differs only via the delay.
            let pps = 1_000_000_000u64 / 8 / MTU as u64;
            cc.rcv_rate = pps;

            for i in 0..4000u64 {
                cc.on_packet_sent(i, MTU, now);
                cc.on_ack_received(
                    &AckInfo {
                        packet_number: i,
                        ack_delay: Duration::ZERO,
                        delivered_bytes: MTU as u64,
                        delivery_rate: 125_000_000,
                    },
                    now + Duration::from_millis(delay_ms + i),
                );
            }
            cc.max_cwnd
        }

        let short = drive(10);
        let long = drive(150);

        assert!(
            long > short,
            "the ceiling did not scale with delay: 10ms gave {short}, 150ms gave {long}"
        );
        // A 10 ms path at 1 Gbit has a BDP of ~1042 packets at this MTU.
        // The old constant permitted 4096 on it regardless — 3.9x the BDP —
        // and that is the specific thing being fixed, so assert the short
        // path now lands below it.
        assert!(
            short < 4096.0,
            "short path allowed {short} packets; the constant it replaced allowed 4096"
        );
        // And that it is within a ratchet step of its own BDP bound. The
        // ratchet multiplies by 1.25 and clamps to the ceiling, so the
        // reachable value is the ceiling itself.
        let bdp_10ms = 1_000_000_000.0 / 8.0 / MTU as f64 * 0.010;
        assert!(
            short <= (bdp_10ms * MAX_CWND_BDP_MULT).max(MAX_CWND_FLOOR_PKTS) + 1.0,
            "short path allowed {short} packets, above its measured BDP bound of {:.0}",
            bdp_10ms * MAX_CWND_BDP_MULT
        );
        assert!(
            long <= MAX_CWND_HARD_PKTS,
            "ceiling {long} exceeded the absolute backstop"
        );
    }
}
}
