// Favonius — high-performance file transfer over UDP
// Copyright (c) 2025-2026 Vantino SàRL
// SPDX-License-Identifier: Apache-2.0

//! AHP-Model: BBR-inspired bandwidth/RTT model-based congestion control.
//!
//! Maintains an explicit model of the network path (max bandwidth, min RTT)
//! and sets the sending rate to match the estimated bottleneck capacity.

use std::time::{Duration, Instant};

use crate::metrics::{BandwidthEstimator, DeliveryRateEstimator, RttEstimator};
use crate::pacer::Pacer;
use crate::{AckInfo, CongestionController};

/// Default MTU.
const MTU: usize = 1200;

/// Minimum congestion window: 16 * MTU (~19 KB).
/// Higher than BBR's 4*MTU to prevent WiFi jitter from collapsing throughput.
const MIN_CWND: usize = 16 * MTU;

/// Bandwidth window size in RTT multiples.
///
/// This must comfortably exceed the ProbeBW gain cycle, and at 10 it does
/// not. The cycle is `PROBE_BW_GAINS.len()` phases of one min-RTT each
/// except the probe, which runs `PROBE_BW_PROBE_RTTS` — so 7 + 2 = **9**
/// against a window of 10. The estimate only ratchets upward through the
/// probe, so the probe's sample has to survive a whole cycle before the
/// next probe can renew it, and it has one round trip of margin in which
/// to do that. BBR runs an 8-RTT cycle against the same 10, which is 25%
/// margin against this 11%.
///
/// That margin was spent by a previous fix. `PROBE_BW_PROBE_RTTS` was
/// raised from 1 to 2 because a one-RTT probe could not see its own result
/// (defect 11); that lengthened the cycle from 8 to 9 and left the filter
/// with almost none.
const BW_WINDOW_RTTS: usize = 10;

/// Sweep override for `BW_WINDOW_RTTS`. Measurement instrument, read once.
fn bw_window_rtts_from_env() -> usize {
    std::env::var("FAVONIUS_MODEL_BW_WINDOW")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .filter(|w| *w >= 4 && *w <= 40)
        .unwrap_or(BW_WINDOW_RTTS)
}

/// ProbeRtt interval: how often to probe for true min_rtt.
const PROBE_RTT_INTERVAL: Duration = Duration::from_secs(10);

/// ProbeRtt duration: how long to hold reduced cwnd.
const PROBE_RTT_DURATION: Duration = Duration::from_millis(200);

/// ProbeRtt cwnd.
const PROBE_RTT_CWND: usize = 16 * MTU;

/// Startup pacing gain.
const STARTUP_PACING_GAIN: f64 = 2.0;

/// Startup cwnd gain.
const STARTUP_CWND_GAIN: f64 = 2.0;

/// Drain pacing gain.
const DRAIN_PACING_GAIN: f64 = 0.5;

/// Hard bound on Drain, in min-RTTs.
///
/// Draining a startup overshoot at half rate takes about one round trip.
/// This is the liveness guarantee, not the expected duration: without it
/// Drain's exit condition can recede faster than inflight approaches it,
/// and the controller never leaves. Measured before the bound existed:
/// 90 seconds in Drain, 542 rounds, inflight 763 KB against a target that
/// had shrunk to 784 bytes.
const DRAIN_MAX_RTTS: u32 = 4;

/// Hard bound on Startup, in min-RTTs.
///
/// Startup ends when the bandwidth estimate stops growing for
/// STARTUP_FULL_BW_ROUNDS *rounds*, and a round only advances when an ACK
/// carries a chunk index at or past the round's start. Retransmissions
/// carry older indices, so under heavy loss the round counter stops, the
/// plateau can never be counted, and Startup keeps pacing at
/// STARTUP_PACING_GAIN into the loss that is causing it -- a closed loop
/// with no exit.
///
/// Measured in the path simulator, which reaches that state where the rig
/// does not: 662,417 packets sent to deliver 1,046, 99.8% dropped, still
/// `state=startup round=4` after 60 s, pacing 200 Mbit into a 100 Mbit
/// link.
///
/// Doubling every round trip reaches any plausible BDP in well under
/// twenty; thirty is a liveness guarantee rather than an expected
/// duration, and the same shape as DRAIN_MAX_RTTS.
const STARTUP_MAX_RTTS: u32 = 30;

/// Declare the ACK clock lost after this many min-RTTs with no delivery.
///
/// Every state transition in this controller lives in `on_ack_received`,
/// and `wants_timeout_loss()` is false, so loss does not reach it either.
/// If the path stops delivering, *nothing* runs: the controller freezes in
/// whatever state it held and keeps commanding the rate that caused the
/// blackhole. It cannot back off, because backing off is something it only
/// does on an ACK, and there are no ACKs.
///
/// Measured in the path simulator: 662,417 packets sent to deliver 1,046,
/// and the 1,046 all arrived in the first second. After that Model held
/// `state=startup pgain=2.00` at 200 Mbit into a 100 Mbit link for the
/// remaining ~40 s with no feedback of any kind.
///
/// Eight round trips is well past any plausible reordering or ACK
/// aggregation, and short enough to react before the sender's 30 s stall
/// detector gives up on the transfer entirely.
const STARVE_RTTS: u32 = 8;

/// Multiplicative reduction applied per starvation interval.
const STARVE_BACKOFF: f64 = 0.5;

/// Floor on the starvation scale, so recovery stays possible: the rate
/// must stay high enough to put *some* packet on the wire, or no ACK can
/// ever arrive to lift it back.
const STARVE_SCALE_MIN: f64 = 0.01;

/// ProbeBandwidth gain cycle phases.
///
/// **The first entry was 1.25 and is 2.0, measured.** BBR uses 1.25 with a
/// pacer that delivers what it commands; this send path delivers about 80%
/// of its command (see `PROFILE_SUMMARY`), and
/// `1.25 x 0.8` is 1 — the estimate can then neither grow nor shrink, which
/// is the ~330 Mbit attractor. Raising the gain restores headroom.
///
/// Swept at n=8, 1 Gbit cross-country, with the harness actually forwarding
/// the override (an earlier sweep did not, because the variables never
/// reached the container):
///
/// | gain | MB/s | sd   | cv    | settled bw | retx  | RTT infl |
/// |------|------|------|-------|------------|-------|----------|
/// | 1.25 | 28.6 | 4.71 | 16.4% |  294 Mbit  | 0.54% | 1.37x    |
/// | 1.75 | 66.4 | 5.08 |  7.6% | 1117 Mbit  | 0.53% | 1.30x    |
/// | 2.0  | 70.7 | 1.84 |  2.6% | 1237 Mbit  | 0.61% | 1.31x    |
/// | 2.5  | 58.1 | 2.52 |  4.3% | 1008 Mbit  | 0.55% | 1.34x    |
///
/// An interior optimum — 2.5 is worse — with retransmits and queueing flat
/// across the whole range *on this cell*. **That does not generalise, and
/// the original note here said it did.** At 100 Mbit on the impaired paths
/// the gain buys throughput with a standing queue:
///
/// | 100 Mbit      | gain 1.25        | gain 2.0         |
/// |---------------|------------------|------------------|
/// | cross-country | 10.75 @ 14.4 ms  | 10.78 @ 14.3 ms  |
/// | transatlantic | 10.60 @ 33.5 ms  | 10.62 @ 26.7 ms  |
/// | satellite     |  8.25 @ 14.6 ms  |  9.90 @ 91.1 ms  |
/// | degraded      |  9.60 @ 16.7 ms  | 10.04 @ 50.1 ms  |
///
/// (excess delay over base RTT). Satellite is +20% goodput for 6.2x the
/// queue, and it is what fails Model's A1 delay leg on all four scenarios.
///
/// Swept at 100 Mbit, n=5, on the two paths where the trade appears
/// (A1's delay budget is 45.5 ms satellite / 33.0 ms degraded):
///
/// | gain | satellite      | degraded       | A1 delay  |
/// |------|----------------|----------------|-----------|
/// | 1.25 | 8.50 @ 16.7 ms | 8.92 @ 14.8 ms | PASS both |
/// | 1.5  | 9.10 @ 58.1 ms | 9.82 @ 40.2 ms | fail      |
/// | 1.75 | 9.84 @ 76.6 ms | 10.02 @ 46.4ms | fail      |
/// | 2.0  | 9.74 @ 89.6 ms | 10.00 @ 48.5ms | fail      |
///
/// **There is no knee.** 1.25 is the only value inside the delay budget and
/// the trade begins immediately above it, so the choice is a product
/// decision — bulk throughput against standing queue — not an optimisation.
///
/// The value is 1.75 rather than 2.0 because **2.0 is strictly dominated at
/// 100 Mbit**: equal or lower goodput (9.74 against 9.84 on satellite) for
/// 13 ms more queue. 2.0's only advantage is 1 Gbit cross-country
/// (70.7 against 66.4 at n=8), which buys the last 6% of a rate-specific
/// gain at a cost on every impaired 100 Mbit path.
///
/// If latency matters more than bulk throughput for a deployment, 1.25 is
/// the value that passes A1 and it costs 14% on these two paths.
///
/// **The queue is not antisocial.** `coexist.sh` on the `clean` path
/// (25 ms, no injected loss, so TCP is healthy and the queue is the only
/// signal), Favonius against an iperf3 cubic flow over the same bottleneck,
/// n=3, reporting TCP's share of its solo throughput:
///
///   classic          0.68  (both arms — a control confirming no drift)
///   model @ 1.25     0.55
///   model @ 1.75     0.49
///
/// The gate fails below 0.35 and 0.50 is an equal share. Model takes about
/// half at either gain and the difference between them is smaller than the
/// 1.75 arm's own spread (0.41-0.57), so it is not resolvable at n=3.
/// Classic is the polite one, yielding TCP more than half.
///
/// So the standing queue costs *this transfer's own* latency and does not
/// starve a competing flow. That is the argument for 1.75 being
/// acceptable: the delay is self-inflicted, not externalised.
/// The
/// variance collapsing from cv 16.4% to 2.6% is the corroboration: the
/// run-to-run spread was the loop drifting along a flat equilibrium, not
/// noise in the rig.
///
/// Validated across all four scenarios at both rates, n=3, against 1.25
/// measured in the same session:
///
///   1 Gbit    +50% / +51% / +23% / +27%
///   100 Mbit   +4% /  +7% / +33% / +16%
///
/// with retransmits at each path's own loss floor (0.43% on the 0.5%-loss
/// path, 2.03% on 2%, 5.07% on 5%).
///
/// **The first entry sets the controller's equilibrium rate.** `bw` is a
/// max filter, and the maximum it sees is produced by this phase, which
/// commands `gain x bw`. The sender puts `eta(R) x R` on the wire, where
/// eta is the send path's efficiency and falls with rate. So
/// `bw_next = gain x eta x bw`, and the loop is at equilibrium exactly when
/// `eta = 1 / gain` — the network never enters the equation. See
/// the CC dynamics notes, "Model's attractor".
const PROBE_BW_GAINS: [f64; 8] = [1.75, 0.75, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0];

/// Sweep override for `PROBE_BW_GAINS[0]`. Measurement instrument.
fn probe_gain_from_env() -> f64 {
    std::env::var("FAVONIUS_MODEL_PROBE_GAIN")
        .ok()
        .and_then(|v| v.parse::<f64>().ok())
        .filter(|g| *g >= 1.0 && *g <= 3.0)
        .unwrap_or(PROBE_BW_GAINS[0])
}

/// Round trips the *probe* phase runs for. Every other phase runs for one.
///
/// One is too few, and it is defect 11 for the third time in this crate.
/// The probe raises the rate for a round trip; the ACKs that say whether
/// the path *delivered* the higher rate arrive a round trip later, which
/// under a one-RTT phase is the drain. The delivery estimator's window is
/// also one `min_rtt`, so the sample that should carry the probe's result
/// straddles the probe and the 0.75x drain that follows and averages them
/// away. The probe can then never show a gain, and the bandwidth estimate
/// cannot ratchet upward.
///
/// Invisible at 100 Mbit, where Startup reaches the ceiling and ProbeBW
/// only has to hold it. At 1 Gbit Startup does not, and the estimate decays
/// instead: measured on cross-country, `bw` peaked at 754 Mbit and fell
/// monotonically to 250 while `cwnd` followed it from 4474 packets to 1700,
/// with the pacer faithful at debt_ratio 0.972 and the controller
/// *commanding* 301 Mbit of a 1000 Mbit link.
///
/// `rl.rs` fixed the same thing with CYCLE_PROBE_RTTS and `wifi.rs` with
/// PROBE_RTTS, both 2, both measured.
const PROBE_BW_PROBE_RTTS: u32 = 2;

/// Number of rounds without bandwidth increase to declare startup over.
const STARTUP_FULL_BW_ROUNDS: u32 = 3;

/// Minimum bandwidth growth ratio to stay in startup.
const STARTUP_FULL_BW_THRESHOLD: f64 = 1.05;

/// Rounds that must pass before the plateau detector may end Startup.
///
/// Classic learned this as defect 10: an early unrepresentative round
/// decided the whole transfer. Model had no equivalent guard, and on
/// satellite it left Startup at round 5 with `full_bw` latched at 11.56
/// Mbit on a 100 Mbit link -- then took 11 s of a 20 s transfer to climb
/// back through the ProbeBW cycle.
const STARTUP_MIN_ROUNDS: u32 = 4;

/// Ceiling on the ACK-clocked startup window.
///
/// Slow start doubles every round trip, so it needs a bound that does not
/// depend on the bandwidth estimate -- the estimate is what it exists to
/// bootstrap. 4096 packets is ~4.9 MB at this MTU, past the BDP of any
/// path this controller targets, and the model takes over well before it.
const STARTUP_MAX_CWND: usize = 4096 * MTU;

/// Standing-queue budget, above which the gain cycle stops probing.
///
/// **Model had no delay response at all.** `cwnd_gain` is 2.0 and the
/// probe gain 1.75, neither reacts to queue, and the only retreat is
/// ProbeRtt once every ten seconds — so on a high-BDP path the controller
/// fills the bottleneck buffer and stays there. Measured at 100 Mbit,
/// satellite: 91.2 ms of standing queue on a 150 ms path, against `fair`'s
/// 7.8 ms on the same cell, and A1's delay leg fails it on all four
/// scenarios.
///
/// It is also why raising the probe gain was a throughput-for-latency
/// trade with no knee (a parameter sweep): with no queue bound, the gain is
/// the *only* lever, so it has to do a job this bound should be doing.
///
/// Same form and constants as `rl.rs`, `udt.rs`, `fair.rs` and
/// `classic.rs`, and the same as A1's delay budget — 8 ms absorbs the
/// transient a batch-mode burst leaves even at low utilisation, and the
/// fraction is the actual standing-queue allowance. A bare RTT *ratio*
/// would be path-dependent: 8 ms is 1.32x at a 25 ms RTT and 1.05x at
/// 150 ms.
///
/// **Measured, this does not fix satellite, and the reason is worth
/// keeping.** n=5 at 1 Gbit: cross-country 106.9 -> 108.0 MB/s, satellite
/// 44.5 -> 45.8. Neutral, not a repair.
///
/// The trace says why. On satellite `cwnd` reaches 95 MB against an
/// 18.75 MB BDP, and since `cwnd = cwnd_gain x bw x min_rtt` that puts
/// `bw` at about 318 MB/s — **2.5x the link**. Scaling a rate already
/// 2.5x capacity by 0.75 leaves it at 1.9x, so the bound fires and changes
/// nothing. The defect on that path is the bandwidth estimate, not the
/// gain, and this bound is a precondition for fixing it rather than a fix.
///
/// It is kept because Model had *no* delay response of any kind — the only
/// retreat was ProbeRtt once every ten seconds — and because it can only
/// lower the gain, never raise it, so it cannot make matters worse. It
/// should start doing real work as soon as `max_bandwidth` stops reading
/// 2.5x capacity.
const QUEUE_BUDGET_FIXED: Duration = Duration::from_millis(8);
const QUEUE_BUDGET_FRACTION: f64 = 0.25;

/// Gain used in place of the probe when the queue is already over budget.
///
/// Not 1.0: holding at unity keeps the queue where it is. BBR drains with
/// 0.75 in the phase after its probe, and this reuses that rather than
/// inventing a constant.
const QUEUE_OVER_GAIN: f64 = 0.75;

/// States of the AHP-Model controller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    /// Increase sending rate until delivery rate plateaus.
    Startup,
    /// Reduce inflight to drain the queue built during startup.
    Drain,
    /// Cycle through gain phases to probe for more bandwidth.
    ProbeBandwidth,
    /// Periodically reduce cwnd to measure true min_rtt.
    ProbeRtt,
}

/// AHP-Model congestion controller.
#[derive(Debug)]
pub struct ModelController {
    state: State,
    /// Current congestion window in bytes.
    cwnd: usize,
    /// RTT estimator.
    rtt: RttEstimator,
    /// Bandwidth estimator (windowed max).
    bandwidth: BandwidthEstimator,
    /// Delivery rate estimator.
    delivery: DeliveryRateEstimator,
    /// Packet pacer.
    pacer: Pacer,
    /// Current pacing gain.
    pacing_gain: f64,
    /// Current cwnd gain.
    cwnd_gain: f64,
    /// Current phase index in ProbeBandwidth gain cycle.
    probe_bw_phase: usize,
    /// Timestamp when current ProbeBandwidth phase started.
    phase_start: Option<Instant>,
    /// Last time ProbeRtt was entered.
    last_probe_rtt: Option<Instant>,
    /// Timestamp when ProbeRtt started (for duration tracking).
    probe_rtt_start: Option<Instant>,
    /// Cwnd saved before entering ProbeRtt.
    prior_cwnd: usize,
    /// Highest bandwidth observed in startup for full-pipe detection.
    full_bw: u64,
    /// How many times ProbeRtt has been entered. `MIN_CWND` and
    /// `PROBE_RTT_CWND` are the same 19,200 bytes, so a window at that
    /// value is ambiguous without this counter.
    probe_rtt_count: u64,
    /// When Drain began, for the `DRAIN_MAX_RTTS` bound.
    drain_started: Option<Instant>,
    /// Rounds since bandwidth last increased in startup.
    full_bw_count: u32,
    /// Round at which the startup plateau was last evaluated.
    full_bw_count_round: u64,
    /// Round-trip counter.
    round_count: u64,
    /// Packet number at start of current round.
    round_start_pkt: u64,
    /// Whether the current round has been counted.
    round_started: bool,
    /// Bytes in flight.
    bytes_in_flight: usize,

    /// Total bytes delivered (monotonically increasing).
    total_delivered: u64,
    /// When Startup began, for the `STARTUP_MAX_RTTS` bound.
    startup_started: Option<Instant>,
    /// Delivery samples bucketed by the pacing gain in force when they were
    /// taken. The question this answers: does the 1.25x probe actually
    /// produce more measured delivery than cruise? If it does not, the
    /// bandwidth estimate cannot ratchet and the controller sits at a fixed
    /// point. Diagnostic only.
    /// Instrumentation for whether a probe actually raises the estimate.
    ///
    /// The phase buckets below bin delivery samples by the gain in force at
    /// *ACK* time, so a probe's own result — which arrives a round trip
    /// after the probe sent it — lands in a later bucket. That makes them
    /// unable to separate "the path did not deliver the probe" from "it
    /// did, and the max filter lost it again before the next one".
    ///
    /// These do separate it: `max_bandwidth` is latched when a probe starts
    /// and compared against itself two round trips after the probe ends,
    /// by which time the probe's ACKs have certainly landed.
    probe_entry_bw: u64,
    probe_eval_at: Option<Instant>,
    probes_run: u64,
    probes_that_raised_bw: u64,
    probe_gain_ratio_sum: f64,
    dbg_probe_sum: f64,
    dbg_probe_n: u64,
    dbg_cruise_sum: f64,
    dbg_cruise_n: u64,
    dbg_drain_sum: f64,
    dbg_drain_n: u64,
    /// Effective `PROBE_BW_GAINS[0]`; see `probe_gain_from_env`.
    probe_gain: f64,
    /// Multiplier on rate and window while the ACK clock is lost. 1.0
    /// whenever deliveries are arriving; halved per starvation interval.
    starve_scale: f64,
    /// When the last starvation backoff was applied, to rate-limit it to
    /// one per interval rather than one per packet sent.
    last_starve_backoff: Option<Instant>,
    /// Largest single delivery-rate sample fed to the max filter, and the
    /// span the most recent one was measured over. The filter is supposed
    /// to be immune to spikes because it averages over a round trip; these
    /// say whether that holds at 150 ms.
    dbg_dr_max: u64,
    dbg_last_span_us: u64,
    /// Count of starvation backoffs applied over the transfer.
    ///
    /// `starve_scale` resets to 1.0 on the first delivery, so a controller
    /// that is repeatedly starved and recovering reads as healthy at any
    /// instant a diagnostic happens to sample it. The count does not reset.
    starve_events: u64,
    /// Timestamp of the last delivery event.
    last_delivery_time: Instant,
}

impl ModelController {
    pub fn new() -> Self {
        // Start with a large initial cwnd (same as classic CC) so that
        // startup can measure meaningful delivery rates on the first RTT
        // instead of cold-starting at 12KB.
        let initial_cwnd = 128 * MTU;
        let initial_rate = 100_000_000u64; // 100 MB/s — aggressive initial pace
        let now = Instant::now();
        Self {
            state: State::Startup,
            cwnd: initial_cwnd,
            rtt: RttEstimator::new(),
            bandwidth: BandwidthEstimator::new(bw_window_rtts_from_env()),
            delivery: DeliveryRateEstimator::new(),
            pacer: Pacer::new(initial_rate),
            pacing_gain: STARTUP_PACING_GAIN,
            cwnd_gain: STARTUP_CWND_GAIN,
            probe_bw_phase: 0,
            phase_start: None,
            last_probe_rtt: None,
            probe_rtt_start: None,
            prior_cwnd: 0,
            full_bw: 0,
            startup_started: None,
            probe_entry_bw: 0,
            probe_eval_at: None,
            probes_run: 0,
            probes_that_raised_bw: 0,
            probe_gain_ratio_sum: 0.0,
            dbg_probe_sum: 0.0,
            dbg_probe_n: 0,
            dbg_cruise_sum: 0.0,
            dbg_cruise_n: 0,
            dbg_drain_sum: 0.0,
            dbg_drain_n: 0,
            probe_gain: probe_gain_from_env(),
            starve_scale: 1.0,
            last_starve_backoff: None,
            dbg_dr_max: 0,
            dbg_last_span_us: 0,
            starve_events: 0,
            probe_rtt_count: 0,
            drain_started: None,
            full_bw_count: 0,
            full_bw_count_round: 0,
            round_count: 0,
            round_start_pkt: 0,
            round_started: false,
            bytes_in_flight: 0,
            total_delivered: 0,
            last_delivery_time: now,
        }
    }

    /// Compute the target cwnd from the model.
    fn target_cwnd(&self) -> usize {
        let bw = self.bandwidth.max_bandwidth();
        let min_rtt = self.rtt.min_rtt().unwrap_or(Duration::from_millis(100));

        if bw == 0 || min_rtt.is_zero() {
            return self.cwnd;
        }

        let bdp = (bw as f64 * min_rtt.as_secs_f64()) as usize;
        let target = (bdp as f64 * self.cwnd_gain * self.starve_scale) as usize;
        target.max(MIN_CWND)
    }

    /// Whether the standing queue exceeds the budget.
    ///
    /// `srtt - min_rtt`, not a ratio of the two: see `QUEUE_BUDGET_FIXED`.
    fn queue_above_budget(&self) -> bool {
        match (self.rtt.smoothed_rtt(), self.rtt.min_rtt()) {
            (Some(s), Some(m)) => {
                let budget = QUEUE_BUDGET_FIXED.as_secs_f64()
                    + QUEUE_BUDGET_FRACTION * m.as_secs_f64();
                s.as_secs_f64() - m.as_secs_f64() >= budget
            }
            // No estimate yet — do not throttle a controller that cannot
            // yet see the path.
            _ => false,
        }
    }

    /// The pacing gain actually applied, after the queue bound.
    ///
    /// Probing into a queue that is already over budget cannot discover
    /// capacity — the extra packets go into the buffer, not onto the wire —
    /// and it is what put 91.2 ms of standing queue on a 150 ms path. This
    /// only ever *lowers* the gain, so it cannot make the controller more
    /// aggressive than the cycle already permits, and it is inert whenever
    /// the queue is inside budget.
    fn effective_pacing_gain(&self) -> f64 {
        if self.state == State::ProbeBandwidth
            && self.pacing_gain > 1.0
            && self.queue_above_budget()
        {
            QUEUE_OVER_GAIN
        } else {
            self.pacing_gain
        }
    }

    /// Compute the target pacing rate from the model.
    fn target_pacing_rate(&self) -> u64 {
        let bw = self.bandwidth.max_bandwidth();
        (bw as f64 * self.effective_pacing_gain() * self.starve_scale) as u64
    }

    fn update_model(&mut self, now: Instant) {
        self.cwnd = self.target_cwnd();
        let rate = self.target_pacing_rate();
        self.pacer.set_rate(rate);

        tracing::trace!(
            state = ?self.state,
            cwnd = self.cwnd,
            rate,
            pacing_gain = self.pacing_gain,
            cwnd_gain = self.cwnd_gain,
            "model updated"
        );

        // Check if we should enter ProbeRtt.
        if self.state != State::ProbeRtt && self.state != State::Startup {
            if let Some(last) = self.last_probe_rtt {
                if now.duration_since(last) >= PROBE_RTT_INTERVAL {
                    self.enter_probe_rtt(now);
                }
            } else if self.state == State::ProbeBandwidth {
                // First probe after startup.
                self.last_probe_rtt = Some(now);
            }
        }
    }

    /// Respond to the loss of the ACK clock.
    ///
    /// Reduces rate and window geometrically for as long as nothing is
    /// being delivered. This is the controller's only feedback when the
    /// path blackholes; see `STARVE_RTTS`.
    fn check_ack_starvation(&mut self, now: Instant) {
        // Arm only once the path has delivered something. Before the first
        // ACK there is no min_rtt, the fallback is 100 ms, and a path whose
        // round trip exceeds 800 ms would be declared starved during its
        // own handshake. A transfer that never delivers at all is the
        // sender's stall detector to handle, not this.
        if self.total_delivered == 0 {
            return;
        }
        let min_rtt = self.rtt.min_rtt().unwrap_or(Duration::from_millis(100));
        let interval = min_rtt * STARVE_RTTS;
        if now.duration_since(self.last_delivery_time) < interval {
            return;
        }
        // Once per interval, not once per packet.
        if let Some(last) = self.last_starve_backoff {
            if now.duration_since(last) < interval {
                return;
            }
        }
        self.last_starve_backoff = Some(now);
        self.starve_events += 1;
        self.starve_scale = (self.starve_scale * STARVE_BACKOFF).max(STARVE_SCALE_MIN);

        // Startup's exit is counted in rounds, and rounds only advance on
        // ACKs. Leave it explicitly or it is never left.
        if self.state == State::Startup {
            self.enter_drain(now);
        }
        // Everything sent is presumed lost: `on_packet_lost` is not
        // delivered to this controller, so the in-flight count has been
        // accumulating sends with no corresponding removals, and Drain's
        // exit test reads it.
        self.bytes_in_flight = 0;

        tracing::debug!(
            scale = self.starve_scale,
            idle_ms = now.duration_since(self.last_delivery_time).as_millis() as u64,
            "ack clock lost, backing off"
        );
        self.update_model(now);
    }

    /// BBR full-pipe detection: declare startup over when the bandwidth
    /// estimate has not grown by STARTUP_FULL_BW_THRESHOLD for
    /// STARTUP_FULL_BW_ROUNDS consecutive round-trips. The plateau is
    /// evaluated at most once per round — BBR counts rounds, not ACKs,
    /// so many ACKs within a single RTT must not trip it early.
    fn check_startup_full_pipe(&mut self, now: Instant) {
        // Bound the phase regardless of what the round counter is doing.
        // Under heavy loss the counter stops advancing, and every exit
        // from Startup is expressed in rounds.
        let started = *self.startup_started.get_or_insert(now);
        let min_rtt = self.rtt.min_rtt().unwrap_or(Duration::from_millis(100));
        if now.duration_since(started) >= min_rtt * STARTUP_MAX_RTTS {
            tracing::debug!("startup: bound reached, entering drain");
            self.enter_drain(now);
            return;
        }

        let bw = self.bandwidth.max_bandwidth();
        if bw == 0 {
            return;
        }

        // An early round is not evidence about the path. Classic's defect
        // 10 was exactly this: one unrepresentative round decided the
        // operating point for the whole transfer.
        if self.round_count < STARTUP_MIN_ROUNDS as u64 {
            self.full_bw = self.full_bw.max(bw);
            return;
        }

        if self.full_bw == 0 || bw as f64 >= self.full_bw as f64 * STARTUP_FULL_BW_THRESHOLD {
            self.full_bw = bw;
            self.full_bw_count = 0;
            self.full_bw_count_round = self.round_count;
            return;
        }

        // Already evaluated this round; further ACKs are not new evidence.
        if self.round_count == self.full_bw_count_round {
            return;
        }
        self.full_bw_count_round = self.round_count;

        self.full_bw_count += 1;
        if self.full_bw_count >= STARTUP_FULL_BW_ROUNDS {
            tracing::debug!(bw, "startup: pipe full, entering drain");
            self.enter_drain(now);
        }
    }

    fn enter_drain(&mut self, now: Instant) {
        self.state = State::Drain;
        self.drain_started = Some(now);
        self.pacing_gain = DRAIN_PACING_GAIN;
        self.cwnd_gain = STARTUP_CWND_GAIN; // Keep cwnd high to avoid drops during drain.
    }

    fn enter_probe_bw(&mut self, now: Instant) {
        self.state = State::ProbeBandwidth;
        self.probe_bw_phase = 0;
        self.pacing_gain = self.probe_gain;
        // ProbeBW cwnd gain. Sweepable: the window permits a rate of
        // `cwnd_gain x bw x min_rtt / srtt`, which at the measured 1.36x
        // RTT inflation is `1.47 x bw` — less than a 1.5 or 1.75 probe
        // asks for. If that is what pins the attractor, raising this must
        // move it. See the CC dynamics notes, "Model's attractor".
        self.cwnd_gain = std::env::var("FAVONIUS_MODEL_CWND_GAIN")
            .ok()
            .and_then(|v| v.parse::<f64>().ok())
            .filter(|g| *g >= 1.0 && *g <= 8.0)
            .unwrap_or(2.0);
        self.phase_start = Some(now);
        tracing::debug!("entering probe bandwidth");
    }

    fn enter_probe_rtt(&mut self, now: Instant) {
        tracing::debug!("entering probe RTT");
        self.state = State::ProbeRtt;
        self.probe_rtt_count += 1;
        self.prior_cwnd = self.cwnd;
        self.cwnd = PROBE_RTT_CWND;
        self.pacing_gain = 1.0;
        self.probe_rtt_start = Some(now);
    }

    /// End ProbeRtt once its 200 ms have elapsed.
    ///
    /// **ProbeRtt is a timer, not an ack-driven phase, and this must be
    /// reachable without acks.** It used to be checked only inside
    /// `on_ack_received`, which deadlocks the controller: ProbeRtt clamps
    /// `cwnd` to `PROBE_RTT_CWND` (16 * MTU), and if everything in flight is
    /// then lost — one radio burst is enough — no ack ever arrives, so the
    /// exit is never evaluated and the window stays clamped for the rest of
    /// the transfer. The sender crawls on RTO retransmits alone.
    ///
    /// Measured on the 802.11ac hardware rig, 2026-08-15: one run in six of
    /// `--congestion model` collapsed to **0.02 MiB/s** and was killed by the
    /// receiver's 300 s timeout, while the other five averaged 39.4 MiB/s.
    /// ProbeRtt runs 200 ms in every 10 s, so a loss burst has roughly a 2%
    /// chance of landing inside it — which is the shape of a one-in-six
    /// failure that never reproduces on a clean link.
    ///
    /// It is therefore called from every callback that carries a clock:
    /// `on_ack_received`, `on_packet_lost` and `on_packet_sent`. The last is
    /// the one that matters, because it is the only one still firing when the
    /// path has stopped delivering entirely.
    fn maybe_exit_probe_rtt(&mut self, now: Instant) {
        if self.state != State::ProbeRtt {
            return;
        }
        // A ProbeRtt with no start stamp can never expire. Treat it as
        // starting now rather than leaving the phase unbounded.
        let Some(start) = self.probe_rtt_start else {
            self.probe_rtt_start = Some(now);
            return;
        };
        if now.duration_since(start) < PROBE_RTT_DURATION {
            return;
        }
        self.last_probe_rtt = Some(now);
        tracing::debug!("exiting probe RTT");
        self.enter_probe_bw(now);
        self.update_model(now);
        // ProbeRtt is a 200 ms measurement, not a congestion event, so it
        // must not cost the window it was holding.
        //
        // This used to be `self.cwnd = self.prior_cwnd` *before*
        // `update_model`, whose first act is `self.cwnd = self.target_cwnd()`.
        // The restore was therefore dead code in every case except
        // `bw == 0`: if the estimate survived the probe it was redundant, and
        // if the estimate decayed during the probe it was overwritten by the
        // smaller value. Since PROBE_RTT_CWND and MIN_CWND are the same
        // 16 * MTU, the result was indistinguishable in a log from a
        // starved-estimate collapse.
        self.cwnd = self.cwnd.max(self.prior_cwnd);
    }

    fn advance_probe_bw_phase(&mut self, now: Instant) {
        if let Some(start) = self.phase_start {
            let min_rtt = self.rtt.min_rtt().unwrap_or(Duration::from_millis(100));
            // The probe runs longer than the other phases so its own result
            // can arrive inside it. See PROBE_BW_PROBE_RTTS.
            let phase_len = if self.probe_bw_phase == 0 {
                min_rtt * PROBE_BW_PROBE_RTTS
            } else {
                min_rtt
            };
            if now.duration_since(start) >= phase_len {
                self.probe_bw_phase = (self.probe_bw_phase + 1) % PROBE_BW_GAINS.len();
                self.pacing_gain = if self.probe_bw_phase == 0 {
                    self.probe_gain
                } else {
                    PROBE_BW_GAINS[self.probe_bw_phase]
                };
                self.phase_start = Some(now);
                if self.probe_bw_phase == 0 {
                    // Entering a probe: latch the estimate it starts from,
                    // and schedule the comparison for two round trips after
                    // the probe ends.
                    self.probe_entry_bw = self.bandwidth.max_bandwidth();
                    self.probe_eval_at =
                        Some(now + min_rtt * (PROBE_BW_PROBE_RTTS + 2));
                    self.probes_run += 1;
                }
            }
        } else {
            self.phase_start = Some(now);
        }
    }

    /// Advance the round counter when an ACK arrives for a chunk sent in
    /// the current round (chunk index >= round_start_pkt). Retransmitted
    /// old chunks carry a lower index and never advance the round.
    fn update_round(&mut self, acked_pkt: u64) {
        if acked_pkt >= self.round_start_pkt {
            if self.round_started {
                self.round_count += 1;
                self.round_started = false;
            }
        }
    }

    fn start_round(&mut self, sent_pkt: u64) {
        if !self.round_started {
            // Retransmits re-report an older chunk index; keep the high-water mark.
            self.round_start_pkt = self.round_start_pkt.max(sent_pkt);
            self.round_started = true;
        }
    }
}

impl Default for ModelController {
    fn default() -> Self {
        Self::new()
    }
}

/// A snapshot of `ModelController`'s internal state.
///
/// Model exported nothing, which is why a measured collapse could only be
/// described as "cwnd=101KB, then cwnd=18KB" -- with no way to say which
/// state the controller was in, whether the bandwidth filter had emptied,
/// or whether the window was at `PROBE_RTT_CWND` deliberately or at
/// `MIN_CWND` by starvation. Those are the same number.
#[derive(Debug, Clone, Copy)]
pub struct ModelDiag {
    pub state: &'static str,
    pub cwnd: usize,
    /// What `target_cwnd()` would return right now. When this is
    /// `MIN_CWND` while `cwnd` is larger, the next `update_model` collapses
    /// the window.
    pub target_cwnd: usize,
    pub max_bandwidth: u64,
    /// Samples left in the bandwidth filter, and the window they live in.
    /// Zero samples means the filter has forgotten everything it measured.
    pub bw_samples: usize,
    pub bw_window_us: u64,
    pub min_rtt_us: u64,
    pub full_bw: u64,
    pub full_bw_count: u32,
    pub round_count: u64,
    pub pacing_rate: u64,
    pub pacing_gain: f64,
    pub cwnd_gain: f64,
    pub probe_rtt_count: u64,
    pub bytes_in_flight: usize,
}

impl ModelController {
    /// Current internal state, for diagnostics.
    pub fn diag(&self) -> ModelDiag {
        ModelDiag {
            state: match self.state {
                State::Startup => "startup",
                State::Drain => "drain",
                State::ProbeBandwidth => "probe_bw",
                State::ProbeRtt => "probe_rtt",
            },
            cwnd: self.cwnd,
            target_cwnd: self.target_cwnd(),
            max_bandwidth: self.bandwidth.max_bandwidth(),
            bw_samples: self.bandwidth.sample_count(),
            bw_window_us: self.bandwidth.window_duration().as_micros() as u64,
            min_rtt_us: self.rtt.min_rtt().map(|r| r.as_micros() as u64).unwrap_or(0),
            full_bw: self.full_bw,
            full_bw_count: self.full_bw_count,
            round_count: self.round_count,
            pacing_rate: self.pacer.rate_bps(),
            pacing_gain: self.pacing_gain,
            cwnd_gain: self.cwnd_gain,
            probe_rtt_count: self.probe_rtt_count,
            bytes_in_flight: self.bytes_in_flight,
        }
    }
}

impl CongestionController for ModelController {
    fn on_packet_sent(&mut self, packet_number: u64, bytes: usize, now: Instant) {
        self.bytes_in_flight += bytes;
        // Feed the send-rate clamp. Same window as the delivery marks so
        // the two are comparable over one span.
        let dr_window = self
            .rtt
            .min_rtt()
            .unwrap_or(Duration::from_millis(50))
            .max(Duration::from_millis(20));
        self.delivery.on_sent(bytes as u64, now, dr_window);
        self.start_round(packet_number);
        self.pacer.on_packet_sent(bytes, now);
        // The only callback still running when the path has stopped
        // delivering, so the only place a response to that can live.
        self.check_ack_starvation(now);
        // Same reason: ProbeRtt's 200 ms must be able to expire on a path
        // that is delivering nothing. See `maybe_exit_probe_rtt`.
        self.maybe_exit_probe_rtt(now);
    }

    fn on_ack_received(&mut self, acked: &AckInfo, now: Instant) {
        // Delivery is arriving again: whatever the path was doing, it is
        // carrying traffic now.
        self.starve_scale = 1.0;
        self.last_starve_backoff = None;

        let delivered = acked.delivered_bytes as usize;
        if delivered <= self.bytes_in_flight {
            self.bytes_in_flight -= delivered;
        } else {
            self.bytes_in_flight = 0;
        }

        self.total_delivered += acked.delivered_bytes;
        self.last_delivery_time = now;

        // Update delivery rate estimator.
        // Measure delivery over a round trip. `min_rtt` rather than srtt:
        // srtt contains this controller's own queueing, so a window built
        // from it grows as the controller misbehaves.
        // The delivery window, as a fraction of min_rtt.
        //
        // Entry 31: a 1.25x probe moves the estimate by 0.8%, and the
        // suspected reason is that this window cannot resolve the probe.
        // It measures over a span of *at least* one window, the probe runs
        // two round trips, and the probe's own result arrives a round trip
        // after it was sent — so the sample is smeared across phases and
        // reads close to the cycle's mean gain (1.028) rather than the
        // probe's (1.25). Measured 1.008.
        //
        // Made settable so the hypothesis can be tested against
        // `probe_ratio` without a rebuild per value. Read once per call;
        // this is a measurement instrument, not a user-facing knob.
        // Cached: this runs per ACK, and at 1 Gbit an env lookup per ACK
        // would cost more than the thing being measured.
        static DR_DIV: std::sync::OnceLock<u32> = std::sync::OnceLock::new();
        let dr_divisor = *DR_DIV.get_or_init(|| {
            std::env::var("FAVONIUS_MODEL_DR_DIV")
                .ok()
                .and_then(|v| v.parse::<u32>().ok())
                .filter(|d| *d >= 1 && *d <= 8)
                .unwrap_or(1)
        });
        let dr_window = self
            .rtt
            .min_rtt()
            .unwrap_or(Duration::from_millis(50))
            .max(Duration::from_millis(20))
            / dr_divisor;
        self.delivery.on_ack(acked.delivered_bytes, now, dr_window);

        // Sample only rates that describe what the path *delivered*.
        //
        // A third term used to be included here: `bytes_in_flight / srtt`.
        // That is the rate the sender is *offering*, not one the network
        // has demonstrated, and feeding it to the bandwidth estimator
        // closes a positive feedback loop with the window it derives:
        //
        //     cwnd = CWND_GAIN * bw * min_rtt,  in_flight -> cwnd
        //     bw   = max(.., in_flight/srtt) ~= cwnd/srtt
        //  => cwnd' ~= CWND_GAIN * cwnd * (min_rtt/srtt)
        //
        // With CWND_GAIN = 2.0 that doubles the window on every update
        // until queueing has stretched srtt to twice min_rtt — by which
        // point the queue is enormous. Measured on a 150 ms link: a 235 MB
        // window and 98.6% of packets retransmitted, against Classic's
        // 3.5 MB and 13% on the same path. In simulation the window
        // reached 8-40x BDP and goodput collapsed to ~0.
        //
        // BBR takes its samples exclusively from ACK-derived delivery for
        // exactly this reason: a control loop must not be fed its own
        // output.
        // Only the byte-counted, RTT-windowed measurement. `acked.
        // delivery_rate` is a per-ACK instantaneous figure supplied by the
        // sender, and taking `max()` of the two meant the noisier of them
        // always won: it read 759 Mbit on a 100 Mbit link, pinned `full_bw`
        // at 7.6x capacity, and ended startup inside 200 ms.
        let rate = self.delivery.delivery_rate();
        if rate > 0 {
            if rate > self.dbg_dr_max {
                self.dbg_dr_max = rate;
            }
            self.dbg_last_span_us = self.delivery.last_span_us();
            self.bandwidth.add_sample(rate, now);
            if let Some(at) = self.probe_eval_at {
                if now >= at {
                    self.probe_eval_at = None;
                    if self.probe_entry_bw > 0 {
                        let after = self.bandwidth.max_bandwidth();
                        let ratio = after as f64 / self.probe_entry_bw as f64;
                        self.probe_gain_ratio_sum += ratio;
                        if after > self.probe_entry_bw {
                            self.probes_that_raised_bw += 1;
                        }
                    }
                }
            }
            // Bucket by the gain in force, so the probe can be compared
            // against cruise directly.
            if self.state == State::ProbeBandwidth {
                if self.pacing_gain > 1.1 {
                    self.dbg_probe_sum += rate as f64;
                    self.dbg_probe_n += 1;
                } else if self.pacing_gain < 0.9 {
                    self.dbg_drain_sum += rate as f64;
                    self.dbg_drain_n += 1;
                } else {
                    self.dbg_cruise_sum += rate as f64;
                    self.dbg_cruise_n += 1;
                }
            }
        }

        self.update_round(acked.packet_number);

        match self.state {
            State::Startup => {
                // Slow start, ACK-clocked: cwnd grows by what was acked, so
                // it doubles each round trip independently of the bandwidth
                // estimate.
                //
                // Model had no such mechanism. `target_cwnd()` is a pure
                // function of `max_bandwidth()` and returns the window
                // *unchanged* when that is zero, and `target_pacing_rate()`
                // is likewise zero -- so with no bandwidth sample yet, the
                // window could not move and the rate could not be set. The
                // only thing that ever broke the circle was the seeded
                // bandwidth, and the seed was a fabrication
                // (`min_cwnd_floor / base_rtt`, a window floor divided by an
                // RTT). When it was removed the controller deadlocked at
                // MIN_CWND: 18 KB, 20730 retransmits, 13% of a transfer
                // before the timeout, on every scenario.
                //
                // A bandwidth estimate built from delivery cannot bootstrap
                // itself. Something has to put packets in flight first, and
                // that is what slow start is for.
                let ack_clocked = self
                    .cwnd
                    .saturating_add(acked.delivered_bytes as usize)
                    .min(STARTUP_MAX_CWND);
                self.cwnd = ack_clocked;
                self.check_startup_full_pipe(now);
                self.update_model(now);
                // The model may compute a smaller window than slow start has
                // reached while the estimate is still catching up. Never
                // shrink on that basis during startup; Drain exists to give
                // the window back once the pipe is known to be full.
                self.cwnd = self.cwnd.max(ack_clocked);
            }
            State::Drain => {
                // Drain to the pipe size startup concluded, not to the live
                // estimate.
                //
                // `max_bandwidth()` decays whenever delivery falls, and
                // Drain halves the send rate by construction, so draining
                // lowers delivery, which lowers the estimate, which lowers
                // the very target being drained to. The exit condition then
                // recedes faster than inflight approaches it and the state
                // never terminates -- measured at 90 s, 542 rounds, 763 KB
                // inflight against a 784-byte target.
                //
                // `full_bw` is the bandwidth at which startup concluded the
                // pipe was full. It is fixed at that moment and does not
                // move while draining, which is exactly the property the
                // target needs. Take the larger of the two so a genuinely
                // higher live estimate is still honoured.
                let min_rtt = self.rtt.min_rtt().unwrap_or(Duration::from_millis(100));
                let bw = self.full_bw.max(self.bandwidth.max_bandwidth());
                let bdp = (bw as f64 * min_rtt.as_secs_f64()) as usize;

                // And a bound regardless, so no future change to the target
                // can reintroduce a state with no exit. Draining longer than
                // this means the premise -- that there is a startup
                // overshoot to shed -- was already wrong.
                let overdue = self
                    .drain_started
                    .is_some_and(|t| now.duration_since(t) >= min_rtt * DRAIN_MAX_RTTS);

                if self.bytes_in_flight <= bdp || overdue {
                    self.enter_probe_bw(now);
                }
                self.update_model(now);
            }
            State::ProbeBandwidth => {
                self.advance_probe_bw_phase(now);
                self.update_model(now);
            }
            State::ProbeRtt => self.maybe_exit_probe_rtt(now),
        }
    }

    fn on_packet_lost(&mut self, lost: &[u64], now: Instant) {
        // Loss is the other event that keeps arriving when acks have stopped.
        self.maybe_exit_probe_rtt(now);
        let lost_bytes = lost.len() * MTU;
        if lost_bytes <= self.bytes_in_flight {
            self.bytes_in_flight -= lost_bytes;
        } else {
            self.bytes_in_flight = 0;
        }
        // Model-based: loss doesn't directly reduce cwnd. The model
        // adjusts naturally. However, we do ensure cwnd doesn't go
        // below minimum.
        if self.cwnd < MIN_CWND {
            self.cwnd = MIN_CWND;
        }
    }

    fn congestion_window(&self) -> usize {
        self.cwnd
    }

    fn send_rate(&self) -> Option<u64> {
        let rate = self.target_pacing_rate();
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
        let d = self.diag();
        Some(format!(
            "probe_mbit={:.1}/{} cruise_mbit={:.1}/{} drain_mbit={:.1}/{} \
state={} cwnd={}KB target={}KB inflight={}KB bw={:.2}Mbit \
dr={:.2}Mbit drmax={:.2}Mbit span_ms={:.1} \
samples={} bw_window={}ms min_rtt={:.1}ms full_bw={:.2}Mbit plateau={} \
round={} pace={:.2}Mbit pgain={:.2} cgain={:.2} probe_rtt_n={} \
starve={:.3} starve_n={} probes={} raised={} probe_ratio={:.3}",
            if self.dbg_probe_n > 0 {
                self.dbg_probe_sum / self.dbg_probe_n as f64 * 8.0 / 1e6
            } else { 0.0 },
            self.dbg_probe_n,
            if self.dbg_cruise_n > 0 {
                self.dbg_cruise_sum / self.dbg_cruise_n as f64 * 8.0 / 1e6
            } else { 0.0 },
            self.dbg_cruise_n,
            if self.dbg_drain_n > 0 {
                self.dbg_drain_sum / self.dbg_drain_n as f64 * 8.0 / 1e6
            } else { 0.0 },
            self.dbg_drain_n,
            d.state,
            d.cwnd / 1024,
            d.target_cwnd / 1024,
            d.bytes_in_flight / 1024,
            d.max_bandwidth as f64 * 8.0 / 1e6,
            self.delivery.delivery_rate() as f64 * 8.0 / 1e6,
            self.dbg_dr_max as f64 * 8.0 / 1e6,
            self.dbg_last_span_us as f64 / 1000.0,
            d.bw_samples,
            d.bw_window_us / 1000,
            d.min_rtt_us as f64 / 1000.0,
            d.full_bw as f64 * 8.0 / 1e6,
            d.full_bw_count,
            d.round_count,
            d.pacing_rate as f64 * 8.0 / 1e6,
            d.pacing_gain,
            d.cwnd_gain,
            d.probe_rtt_count,
            // `starve_scale` multiplies *both* the pacing rate and the
            // target window, and can take them to 1% of what the model
            // computed. It was the one mechanism able to produce the
            // symptom under investigation — Model commanding ~28% of a
            // 1 Gbit link with the send loop burst-limited 95.3% and
            // window-limited 0.1% — and it appeared in no diagnostic at
            // all. `starve_n` counts the backoffs so a scale that has
            // recovered to 1.0 by sampling time still leaves a trace.
            self.starve_scale,
            self.starve_events,
            self.probes_run,
            self.probes_that_raised_bw,
            if self.probes_run > 0 {
                self.probe_gain_ratio_sum / self.probes_run as f64
            } else {
                0.0
            },
        ))
    }

    /// Rate-based CC should not respond to timeout losses.
    fn wants_timeout_loss(&self) -> bool { false }

}

#[cfg(test)]
mod queue_bound_tests {
    use super::*;

    fn drive(cc: &mut ModelController, srtt: Duration, min_rtt: Duration) {
        cc.rtt.update(min_rtt);
        for _ in 0..40 {
            cc.rtt.update(srtt);
        }
    }

    /// The bound fires only when the queue is genuinely over budget.
    #[test]
    fn queue_budget_is_an_absolute_not_a_ratio() {
        let mut cc = ModelController::new();
        // 25 ms path: budget is 8 + 0.25*25 = 14.25 ms. An 12 ms queue is
        // 1.48x the RTT as a *ratio* and still inside budget.
        drive(&mut cc, Duration::from_millis(37), Duration::from_millis(25));
        assert!(
            !cc.queue_above_budget(),
            "12 ms of queue on a 25 ms path is inside the 14.25 ms budget"
        );
        // 150 ms path: budget is 45.5 ms. A 40 ms queue is only 1.27x as a
        // ratio — a bare ratio bar would fire here and not above.
        let mut cc2 = ModelController::new();
        drive(&mut cc2, Duration::from_millis(190), Duration::from_millis(150));
        assert!(
            !cc2.queue_above_budget(),
            "40 ms of queue on a 150 ms path is inside the 45.5 ms budget"
        );
        let mut cc3 = ModelController::new();
        drive(&mut cc3, Duration::from_millis(250), Duration::from_millis(150));
        assert!(cc3.queue_above_budget(), "100 ms of queue must be over budget");
    }

    /// Over budget, the probe is replaced by a drain — and only the probe.
    #[test]
    fn the_bound_only_ever_lowers_the_gain() {
        let mut cc = ModelController::new();
        drive(&mut cc, Duration::from_millis(250), Duration::from_millis(150));
        cc.state = State::ProbeBandwidth;

        cc.pacing_gain = PROBE_BW_GAINS[0]; // the probe
        assert_eq!(cc.effective_pacing_gain(), QUEUE_OVER_GAIN);

        cc.pacing_gain = 1.0; // cruise — untouched
        assert_eq!(cc.effective_pacing_gain(), 1.0);

        cc.pacing_gain = 0.75; // already draining — not raised
        assert_eq!(cc.effective_pacing_gain(), 0.75);
    }

    /// Inside budget the bound is inert, so the cycle is unchanged.
    #[test]
    fn inside_budget_the_bound_does_nothing() {
        let mut cc = ModelController::new();
        drive(&mut cc, Duration::from_millis(152), Duration::from_millis(150));
        cc.state = State::ProbeBandwidth;
        cc.pacing_gain = PROBE_BW_GAINS[0];
        assert_eq!(cc.effective_pacing_gain(), PROBE_BW_GAINS[0]);
    }

    /// Startup must not be throttled: it has no queue estimate worth
    /// trusting yet and it is how the path is discovered at all.
    #[test]
    fn startup_is_not_throttled() {
        let mut cc = ModelController::new();
        drive(&mut cc, Duration::from_millis(250), Duration::from_millis(150));
        cc.state = State::Startup;
        cc.pacing_gain = STARTUP_PACING_GAIN;
        assert_eq!(cc.effective_pacing_gain(), STARTUP_PACING_GAIN);
    }
}

#[cfg(test)]
mod starvation_tests {
    use super::*;
    use crate::CongestionController;

    fn ack(pn: u64, bytes: u64) -> AckInfo {
        AckInfo {
            packet_number: pn,
            ack_delay: Duration::ZERO,
            delivered_bytes: bytes,
            delivery_rate: 0,
        }
    }

    /// Feed one round trip's worth of RTT, as the send path does.
    fn feed_rtt(cc: &mut ModelController, rtt: Duration) {
        cc.on_rtt_batch(rtt, rtt);
    }

    /// A path that keeps delivering must never see the starvation scale,
    /// however long the transfer runs. A controller that backs off
    /// spuriously is worse than the deadlock this mechanism fixes.
    #[test]
    fn healthy_path_never_starves() {
        let mut cc = ModelController::new();
        let mut now = Instant::now();
        let rtt = Duration::from_millis(24);
        let mut pn = 0u64;
        // 200 round trips of steady delivery: ~5 s at 24 ms, well past the
        // 8-RTT starvation interval many times over.
        for _ in 0..200 {
            for _ in 0..10 {
                pn += 1;
                cc.on_packet_sent(pn, 1500, now);
            }
            now += rtt;
            feed_rtt(&mut cc, rtt);
            for i in 0..10 {
                cc.on_ack_received(&ack(pn - 9 + i, 1500), now);
            }
            assert_eq!(
                cc.starve_scale, 1.0,
                "healthy path backed off at packet {pn}"
            );
        }
    }

    /// The reverse: once delivery stops, the scale must fall, and the
    /// controller must leave Startup -- whose only other exit is counted
    /// in rounds, and rounds only advance on ACKs.
    #[test]
    fn blackhole_backs_off_and_leaves_startup() {
        let mut cc = ModelController::new();
        let mut now = Instant::now();
        let rtt = Duration::from_millis(24);
        let mut pn = 0u64;
        // Establish an ACK clock and a min_rtt, with delivery still
        // *growing* -- a constant rate plateaus and ends Startup in three
        // rounds on its own, which is the legitimate exit and not the one
        // under test here.
        let mut per_round = 10u64;
        for _ in 0..5 {
            for _ in 0..per_round {
                pn += 1;
                cc.on_packet_sent(pn, 1500, now);
            }
            now += rtt;
            feed_rtt(&mut cc, rtt);
            for i in 0..per_round {
                cc.on_ack_received(&ack(pn - (per_round - 1) + i, 1500), now);
            }
            per_round *= 2;
        }
        assert_eq!(
            cc.state,
            State::Startup,
            "test precondition: must still be in Startup when the path dies"
        );
        assert_eq!(cc.starve_scale, 1.0);

        // Now the path blackholes: sends continue, nothing is delivered.
        for _ in 0..40 {
            for _ in 0..10 {
                pn += 1;
                cc.on_packet_sent(pn, 1500, now);
            }
            now += rtt;
        }
        assert!(
            cc.starve_scale < 1.0,
            "no back-off after 40 RTTs of blackhole (scale {})",
            cc.starve_scale
        );
        assert_ne!(
            cc.state,
            State::Startup,
            "still in Startup, whose exit is counted in rounds that ACKs advance"
        );

        // And it must recover the moment delivery resumes.
        pn += 1;
        cc.on_packet_sent(pn, 1500, now);
        now += rtt;
        feed_rtt(&mut cc, rtt);
        cc.on_ack_received(&ack(pn, 1500), now);
        assert_eq!(cc.starve_scale, 1.0, "did not recover on delivery");
    }

    /// The scale must not reach zero: a rate of zero puts no packet on the
    /// wire, so no ACK can arrive to lift it back.
    #[test]
    fn backoff_leaves_room_to_recover() {
        let mut cc = ModelController::new();
        let mut now = Instant::now();
        let mut pn = 0u64;
        for _ in 0..10 {
            pn += 1;
            cc.on_packet_sent(pn, 1500, now);
        }
        now += Duration::from_millis(24);
        feed_rtt(&mut cc, Duration::from_millis(24));
        for i in 0..10 {
            cc.on_ack_received(&ack(pn - 9 + i, 1500), now);
        }
        // Long enough to hit the floor many times over.
        for _ in 0..500 {
            pn += 1;
            cc.on_packet_sent(pn, 1500, now);
            now += Duration::from_millis(24);
        }
        assert!(cc.starve_scale >= STARVE_SCALE_MIN);
        assert!(cc.starve_scale > 0.0);
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
    fn initial_state_is_startup() {
        let cc = ModelController::new();
        assert_eq!(cc.state, State::Startup);
        assert_eq!(cc.congestion_window(), 128 * MTU);
        assert_eq!(cc.pacing_gain, STARTUP_PACING_GAIN);
    }

    #[test]
    fn startup_detects_full_pipe() {
        let mut cc = ModelController::new();
        let now = Instant::now();

        cc.on_rtt_update(Duration::from_millis(50));

        // Simulate sending and receiving with flat delivery rate.
        let rate = 1_000_000u64;
        for i in 0..20 {
            let t = now + Duration::from_millis(i * 10);
            cc.on_packet_sent(i, MTU, t);
            cc.on_ack_received(&ack(i, MTU as u64, rate), t + Duration::from_millis(50));
        }

        // After enough rounds with no bandwidth increase, should exit startup.
        // The full_bw_count should have incremented.
        assert!(cc.full_bw_count > 0 || cc.state != State::Startup);
    }

    #[test]
    fn full_pipe_counts_rounds_not_acks() {
        let mut cc = ModelController::new();
        let now = Instant::now();

        cc.on_rtt_update(Duration::from_millis(50));

        // One round: send a burst, then ACK all of it without new sends.
        // Many flat ACKs within a single round must not trip full-pipe.
        let rate = 1_000_000u64;
        for i in 0..10 {
            cc.on_packet_sent(i, MTU, now + Duration::from_millis(i));
        }
        for i in 0..10 {
            cc.on_ack_received(&ack(i, MTU as u64, rate), now + Duration::from_millis(50 + i));
        }

        assert_eq!(cc.state, State::Startup);
        assert_eq!(cc.round_count, 1);
        // At most one plateau evaluation per round: the first completed
        // round only establishes full_bw, so nothing is counted yet.
        assert_eq!(cc.full_bw_count, 0);
    }

    #[test]
    fn full_pipe_triggers_after_flat_rounds_but_not_before_the_minimum() {
        let mut cc = ModelController::new();
        let now = Instant::now();
        cc.on_rtt_update(Duration::from_millis(50));

        // Flat delivery: the plateau detector should eventually end
        // Startup -- but not before STARTUP_MIN_ROUNDS, which exists
        // because an early unrepresentative round used to decide the whole
        // transfer (on satellite it ended Startup at round 5 with full_bw
        // latched at 11.56 Mbit on a 100 Mbit link).
        //
        // Asserted as a property rather than an exact round number: the
        // arithmetic depends on the estimator's warm-up, and pinning it
        // made this test break whenever either constant moved.
        let rate = 1_000_000u64;
        let mut exited_at = None;
        for i in 0..40u64 {
            let t = now + Duration::from_millis(i * 100);
            cc.on_packet_sent(i, MTU, t);
            cc.on_ack_received(&ack(i, MTU as u64, rate), t + Duration::from_millis(50));
            if cc.state != State::Startup && exited_at.is_none() {
                exited_at = Some(cc.round_count);
            }
        }
        let exited = exited_at.expect("startup never ended on a flat path");
        assert!(
            exited >= STARTUP_MIN_ROUNDS as u64,
            "left startup at round {exited}, before the {STARTUP_MIN_ROUNDS}-round minimum"
        );
        assert!(exited <= 20, "left startup at round {exited}; far too slow");
    }

    #[test]
    fn retransmits_dont_corrupt_round_state() {
        let mut cc = ModelController::new();
        let now = Instant::now();

        cc.on_rtt_update(Duration::from_millis(50));
        let rate = 1_000_000u64;

        // Round 1: two chunks sent, both ACKed.
        cc.on_packet_sent(0, MTU, now);
        cc.on_packet_sent(1, MTU, now);
        cc.on_ack_received(&ack(0, MTU as u64, rate), now + Duration::from_millis(50));
        assert_eq!(cc.round_count, 1);
        // Second ACK of the same round does not advance it again.
        cc.on_ack_received(&ack(1, MTU as u64, rate), now + Duration::from_millis(51));
        assert_eq!(cc.round_count, 1);

        // Round 2 starts with chunk 2. A retransmitted old chunk (and its
        // ACK) must not move the high-water mark backwards or end the round.
        cc.on_packet_sent(2, MTU, now + Duration::from_millis(52));
        cc.on_packet_sent(0, MTU, now + Duration::from_millis(53));
        cc.on_ack_received(&ack(0, MTU as u64, rate), now + Duration::from_millis(100));
        assert_eq!(cc.round_count, 1);
        // The ACK for the round's own chunk advances it exactly once.
        cc.on_ack_received(&ack(2, MTU as u64, rate), now + Duration::from_millis(101));
        assert_eq!(cc.round_count, 2);

        // A retransmit sent while no round is open starts a round but keeps
        // the high-water mark, so its stale ACK cannot close that round.
        cc.on_packet_sent(0, MTU, now + Duration::from_millis(102));
        cc.on_ack_received(&ack(0, MTU as u64, rate), now + Duration::from_millis(150));
        assert_eq!(cc.round_count, 2);
        // A new chunk's ACK closes the round normally.
        cc.on_packet_sent(3, MTU, now + Duration::from_millis(103));
        cc.on_ack_received(&ack(3, MTU as u64, rate), now + Duration::from_millis(151));
        assert_eq!(cc.round_count, 3);
    }

    #[test]
    fn seeded_startup_drains_after_rounds_not_acks() {
        let mut cc = ModelController::new();
        let now = Instant::now();
        cc.on_rtt_update(Duration::from_millis(50));

        let rate = 1_000_000u64;
        let seeded = rate * 5 / 4;
        cc.bandwidth.add_sample(seeded, now);
        cc.full_bw = seeded;

        // Round 1: a burst of 10 chunks, all ACKed -- 10 flat ACKs but one
        // round. The point of the test is that the plateau counts *rounds*,
        // not ACKs, so a burst must not advance it.
        for i in 0..10 {
            cc.on_packet_sent(i, MTU, now + Duration::from_millis(i));
        }
        for i in 0..10 {
            cc.on_ack_received(&ack(i, MTU as u64, rate), now + Duration::from_millis(50 + i));
            assert_eq!(cc.state, State::Startup, "a burst of ACKs advanced the plateau");
        }
        assert_eq!(cc.round_count, 1);

        // Then flat rounds until it drains. STARTUP_MIN_ROUNDS gates how
        // early that may happen, so the count is asserted as a bound
        // rather than an exact value.
        let mut pkt = 10u64;
        let mut exited_at = None;
        for r in 1..30u64 {
            let t = now + Duration::from_millis(100 + r * 100);
            cc.on_packet_sent(pkt, MTU, t);
            cc.on_ack_received(&ack(pkt, MTU as u64, rate), t + Duration::from_millis(50));
            pkt += 1;
            if cc.state != State::Startup && exited_at.is_none() {
                exited_at = Some(cc.round_count);
            }
        }
        let exited = exited_at.expect("startup never ended");
        assert!(
            exited >= STARTUP_MIN_ROUNDS as u64,
            "left startup at round {exited}, before the minimum"
        );
    }

    #[test]
    fn drain_exits_when_inflight_drops() {
        let mut cc = ModelController::new();
        let now = Instant::now();

        cc.on_rtt_update(Duration::from_millis(50));
        cc.bandwidth.add_sample(1_000_000, now);

        // Force into drain state.
        cc.enter_drain(now);
        assert_eq!(cc.state, State::Drain);

        // Simulate inflight dropping to BDP.
        cc.bytes_in_flight = 0;
        cc.on_ack_received(
            &ack(1, MTU as u64, 1_000_000),
            now + Duration::from_millis(100),
        );

        assert_eq!(cc.state, State::ProbeBandwidth);
    }

    #[test]
    fn probe_bw_cycles_through_phases() {
        let mut cc = ModelController::new();
        let now = Instant::now();

        cc.on_rtt_update(Duration::from_millis(50));
        cc.bandwidth.add_sample(1_000_000, now);
        cc.enter_probe_bw(now);

        assert_eq!(cc.probe_bw_phase, 0);
        assert_eq!(cc.pacing_gain, PROBE_BW_GAINS[0]);

        // One RTT is not enough to leave the probe: it runs for
        // PROBE_BW_PROBE_RTTS so its own result can arrive inside it.
        let t1 = now + Duration::from_millis(60);
        cc.on_ack_received(&ack(1, MTU as u64, 1_000_000), t1);
        assert_eq!(cc.probe_bw_phase, 0, "probe ended after one round trip");

        // Past the probe's length: on to the drain.
        let t2 = now + Duration::from_millis(50 * PROBE_BW_PROBE_RTTS as u64 + 10);
        cc.on_ack_received(&ack(2, MTU as u64, 1_000_000), t2);
        assert_eq!(cc.probe_bw_phase, 1);
        assert_eq!(cc.pacing_gain, PROBE_BW_GAINS[1]);

        // The other phases are one round trip each.
        let t3 = t2 + Duration::from_millis(60);
        cc.on_ack_received(&ack(3, MTU as u64, 1_000_000), t3);
        assert_eq!(cc.probe_bw_phase, 2);
    }

    #[test]
    fn probe_rtt_reduces_cwnd() {
        let mut cc = ModelController::new();
        let now = Instant::now();

        cc.on_rtt_update(Duration::from_millis(50));
        cc.bandwidth.add_sample(1_000_000, now);
        cc.cwnd = 100_000;

        cc.enter_probe_rtt(now);
        assert_eq!(cc.state, State::ProbeRtt);
        assert_eq!(cc.cwnd, PROBE_RTT_CWND);

        // After PROBE_RTT_DURATION, should exit.
        let t = now + PROBE_RTT_DURATION + Duration::from_millis(1);
        cc.on_ack_received(&ack(1, MTU as u64, 1_000_000), t);
        assert_eq!(cc.state, State::ProbeBandwidth);
        // cwnd should be restored.
        assert!(cc.cwnd > PROBE_RTT_CWND);
    }

    /// ProbeRtt must end on its timer even if not one ack ever arrives.
    ///
    /// The deadlock this guards against was found on a real 802.11ac path:
    /// ProbeRtt clamps cwnd to 16 * MTU, a radio burst lost everything in
    /// flight, and because the exit was only evaluated in `on_ack_received`
    /// it was never evaluated again. One transfer in six collapsed to
    /// 0.02 MiB/s until the receiver's 300 s timeout killed it.
    ///
    /// Both callbacks below are checked because both keep firing when the
    /// path has stopped delivering: the sender still retransmits on RTO, and
    /// loss detection still reports.
    #[test]
    fn probe_rtt_exits_on_loss_alone_without_any_ack() {
        let mut cc = ModelController::new();
        let now = Instant::now();
        cc.on_rtt_update(Duration::from_millis(50));
        cc.bandwidth.add_sample(1_000_000, now);
        cc.cwnd = 100_000;
        cc.enter_probe_rtt(now);
        assert_eq!(cc.state, State::ProbeRtt);

        // Not yet due: loss must not end the phase early.
        cc.on_packet_lost(&[1], now + Duration::from_millis(10));
        assert_eq!(cc.state, State::ProbeRtt, "ended ProbeRtt before its timer");

        // Due, and still no ack has ever been delivered.
        cc.on_packet_lost(&[2], now + PROBE_RTT_DURATION + Duration::from_millis(1));
        assert_eq!(
            cc.state,
            State::ProbeBandwidth,
            "ProbeRtt never exited without acks — the window stays clamped and the transfer stalls"
        );
        assert!(cc.cwnd > PROBE_RTT_CWND, "cwnd not restored on exit");
    }

    #[test]
    fn probe_rtt_exits_on_send_alone_without_any_ack() {
        let mut cc = ModelController::new();
        let now = Instant::now();
        cc.on_rtt_update(Duration::from_millis(50));
        cc.bandwidth.add_sample(1_000_000, now);
        cc.cwnd = 100_000;
        cc.enter_probe_rtt(now);

        // An RTO retransmit is a send, and it is the last callback still
        // firing when a path delivers nothing at all.
        cc.on_packet_sent(1, MTU, now + PROBE_RTT_DURATION + Duration::from_millis(1));
        assert_eq!(cc.state, State::ProbeBandwidth);
        assert!(cc.cwnd > PROBE_RTT_CWND);
    }

    /// A ProbeRtt with no start stamp must not be unbounded.
    #[test]
    fn probe_rtt_without_start_stamp_is_bounded() {
        let mut cc = ModelController::new();
        let now = Instant::now();
        cc.on_rtt_update(Duration::from_millis(50));
        cc.bandwidth.add_sample(1_000_000, now);
        cc.enter_probe_rtt(now);
        cc.probe_rtt_start = None;

        // First call adopts a start stamp rather than hanging forever...
        cc.maybe_exit_probe_rtt(now);
        assert_eq!(cc.state, State::ProbeRtt);
        assert!(cc.probe_rtt_start.is_some(), "no start stamp adopted");
        // ...and the phase then expires normally.
        cc.maybe_exit_probe_rtt(now + PROBE_RTT_DURATION + Duration::from_millis(1));
        assert_eq!(cc.state, State::ProbeBandwidth);
    }

    #[test]
    fn loss_doesnt_crash_model() {
        let mut cc = ModelController::new();
        let now = Instant::now();

        cc.on_rtt_update(Duration::from_millis(50));
        cc.on_packet_sent(1, MTU, now);
        cc.on_packet_sent(2, MTU, now);

        cc.on_packet_lost(&[1], now + Duration::from_millis(100));
        assert!(cc.congestion_window() >= MIN_CWND);
    }

    #[test]
    fn can_send_respects_cwnd() {
        let cc = ModelController::new();
        assert!(cc.can_send(0));
        assert!(!cc.can_send(cc.congestion_window()));
    }

    #[test]
    fn send_rate_reflects_model() {
        let mut cc = ModelController::new();
        let now = Instant::now();

        cc.on_rtt_update(Duration::from_millis(50));
        cc.bandwidth.add_sample(2_000_000, now);
        cc.update_model(now);

        let rate = cc.send_rate();
        assert!(rate.is_some());
        // In startup with 2x gain, rate should be ~4MB/s.
        let r = rate.unwrap();
        assert!(r > 2_000_000);
    }

    /// Drain must terminate even if the bandwidth estimate collapses.
    ///
    /// Drain halves the send rate, which lowers delivery, which lowers
    /// `max_bandwidth()`, which lowers the BDP it is draining to. Measured
    /// before this was bounded: 90 s in Drain, 542 rounds, 763 KB inflight
    /// against a target that had decayed to 784 bytes. A state whose exit
    /// condition is computed from an estimate the state itself depresses
    /// cannot terminate.
    #[test]
    fn drain_terminates_when_the_estimate_collapses_under_it() {
        let mut cc = ModelController::new();
        let t0 = Instant::now();
        cc.on_rtt_update(Duration::from_millis(25));
        cc.full_bw = 12_500_000;
        cc.enter_drain(t0);
        assert_eq!(cc.state, State::Drain);

        // Inflight far above any plausible BDP, and an estimate that decays
        // to nothing underneath it — the measured failure exactly.
        cc.bytes_in_flight = 16 * 1024 * 1024;
        for i in 1..=40u64 {
            let at = t0 + Duration::from_millis(i * 10);
            cc.bandwidth = BandwidthEstimator::new(BW_WINDOW_RTTS);
            cc.on_packet_sent(i, MTU, at);
            cc.on_ack_received(
                &AckInfo {
                    packet_number: i,
                    ack_delay: Duration::ZERO,
                    delivered_bytes: MTU as u64,
                    delivery_rate: 0,
                },
                at,
            );
            if cc.state != State::Drain {
                break;
            }
        }

        assert_ne!(
            cc.state,
            State::Drain,
            "still draining after {} min-RTTs with inflight {} — no exit",
            DRAIN_MAX_RTTS,
            cc.bytes_in_flight
        );
    }

    /// Startup must open the window without a bandwidth estimate.
    ///
    /// `target_cwnd()` returns the window unchanged when `max_bandwidth()`
    /// is zero, and a bandwidth estimate built from delivery cannot produce
    /// a first sample until something is in flight. Before slow start was
    /// ACK-clocked the only thing that broke that circle was a seeded
    /// bandwidth -- and the seed was `min_cwnd_floor / base_rtt`, a window
    /// floor divided by an RTT, which is not a measurement of anything.
    /// With it removed the controller sat at MIN_CWND for entire transfers.
    #[test]
    fn startup_opens_the_window_with_no_bandwidth_estimate() {
        let mut cc = ModelController::new();
        let now = Instant::now();
        cc.on_rtt_update(Duration::from_millis(25));

        assert_eq!(cc.bandwidth.max_bandwidth(), 0, "test premise: cold start");
        let initial = cc.congestion_window();

        // One round trip of ACKs carrying no delivery-rate information at
        // all, which is what a cold start actually looks like.
        for i in 0..16u64 {
            cc.on_packet_sent(i, MTU, now);
        }
        for i in 0..16u64 {
            cc.on_ack_received(
                &AckInfo {
                    packet_number: i,
                    ack_delay: Duration::ZERO,
                    delivered_bytes: MTU as u64,
                    delivery_rate: 0,
                },
                now + Duration::from_millis(25),
            );
        }

        assert!(
            cc.congestion_window() > initial,
            "window stuck at {} with no bandwidth estimate — startup cannot bootstrap",
            cc.congestion_window()
        );
    }

    /// And it must stay bounded rather than doubling forever.
    #[test]
    fn startup_growth_is_bounded() {
        let mut cc = ModelController::new();
        let now = Instant::now();
        cc.on_rtt_update(Duration::from_millis(25));
        for i in 0..200_000u64 {
            cc.on_packet_sent(i, MTU, now);
            cc.on_ack_received(
                &AckInfo {
                    packet_number: i,
                    ack_delay: Duration::ZERO,
                    delivered_bytes: MTU as u64,
                    delivery_rate: 0,
                },
                now + Duration::from_millis(25),
            );
        }
        assert!(
            cc.congestion_window() <= STARTUP_MAX_CWND,
            "startup window {} escaped STARTUP_MAX_CWND",
            cc.congestion_window()
        );
    }
}
