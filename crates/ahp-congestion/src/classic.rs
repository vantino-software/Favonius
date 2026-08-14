// Favonius — high-performance file transfer over UDP
// Copyright (c) 2025-2026 Vantino SàRL
// SPDX-License-Identifier: Apache-2.0

//! AHP-Classic: hybrid delay and rate-based congestion control.
//!
//! Uses delay-based signals (RTT inflation) to detect congestion before loss
//! occurs, with a loss-based fallback. Combines the responsiveness of
//! delay-based algorithms with the robustness of loss-based ones.

use std::time::{Duration, Instant};

use crate::metrics::RttEstimator;
use crate::pacer::Pacer;
use crate::{AckInfo, CongestionController};

/// Default MTU for AHP.
const MTU: usize = 1200;

/// Initial congestion window: 128 * MTU (~150 KB).
/// Large enough to reach useful throughput within the first RTT on LAN links.
const INITIAL_CWND: usize = 128 * MTU;

/// Minimum congestion window: 4 * MTU.
const MIN_CWND: usize = 4 * MTU;

/// Delay threshold factor: if RTT > baseline * this, exit slow start.
/// Set high (5×) to tolerate WiFi jitter and ACK batching delay without
/// exiting slow start prematurely.  Loss-based fallback still catches
/// real congestion. The baseline is max(min_rtt, feedback cadence) — see
/// `check_delay_signal`.
const DELAY_THRESHOLD_FACTOR: f64 = 5.0;

/// Slow-start growth bound, as a multiple of the delivery-rate BDP
/// estimate (BBR's startup cwnd gain is 2.885). Bounds overshoot on
/// loss-free fast-feedback links without strangling the ramp on lossy
/// WAN paths, where delivery-rate estimates lag the true path capacity.
const STARTUP_BDP_GAIN: f64 = 3.0;

/// Delivery-plateau growth threshold (BBR's StartupFullGain). Slow start
/// doubles the window per feedback round, so per-round delivery growing
/// less than 5/4 over a full round means the path — not the window —
/// now limits delivery: the ramp has found the available bandwidth.
const STARTUP_FULL_GAIN: f64 = 1.25;

/// Consecutive plateau rounds before exiting slow start (BBR's
/// StartupFullRounds).
const STARTUP_PLATEAU_ROUNDS: u8 = 3;

/// Minimum closed feedback rounds before the plateau exit may fire, so
/// the first noisy delivery estimates cannot strand the ramp.
const STARTUP_MIN_ROUNDS: u64 = 4;

/// Minimum ACK-arrival gap treated as a new feedback batch. The receiver
/// sends one ACK datagram per stream, so a batch arrives as a burst of
/// back-to-back datagrams (sub-ms apart); only gaps at or above this floor
/// represent the actual feedback cadence (receiver ACK timer or RTT).
const ACK_BATCH_GAP_FLOOR: Duration = Duration::from_millis(2);

/// Multiplicative decrease factor on loss.
/// 0.875 = 12.5% decrease, matching UDT's gentle response. Previous 0.70
/// was too aggressive on lossy WiFi — the deep cuts combined with slow AIMD
/// recovery kept the window suppressed.
const LOSS_DECREASE_FACTOR: f64 = 0.875;

/// Queue budget above which loss counts as congestion: a fixed allowance
/// plus a fraction of the baseline RTT. Same form and same values as the
/// gates in fair.rs and rl.rs, and as A1's delay leg.
const LOSS_QUEUEING_FIXED: Duration = Duration::from_millis(8);
const LOSS_QUEUEING_FRACTION: f64 = 0.25;

/// How far the window may exceed the estimated bandwidth-delay product
/// before it is treated as overshooting, regardless of what the delay
/// signal says.
///
/// Multiple of the BDP above which the window is itself congestion
/// evidence.
///
/// 2.0 permits a full BDP of standing queue by construction: a window of 2 x BDP on a link buffered at one BDP fills
/// the buffer and holds it there. Measured on cross-country, Classic sat
/// at cwnd 743 KB against a 312 KB BDP -- 2.38x -- with 28 ms of excess
/// delay on a 25 ms path, and the encrypted profile, which uses this
/// controller, showed the same.
///
/// The delay leg of A1 allows `8 ms + 0.25 x base_rtt`, of which about
/// 7 ms is fixed overhead, leaving roughly a quarter of a BDP for queue.
/// A window of 1.25 x BDP would be that budget expressed as a window, and
/// it does not work: at 1.25 the simulator's `does_not_idle_a_link_it_has
/// _measured_as_empty` guard drops to 28.5% worst-case utilisation, and
/// the smallest value that keeps it above its 60% floor is 1.75 -- which
/// still permits 0.75 BDP of queue. Bounding the window cannot reach the
/// delay budget from here.
///
/// The reason is upstream. Classic paces at `cwnd / srtt`, and
/// `process_feedback` feeds the controller the *minimum* RTT of each ACK
/// batch, so srtt reads 25.7 ms while the transfer's mean RTT is 56.2 ms.
/// The controller cannot see the queue it is building, and its pacing
/// rate is computed by dividing by a number that is too small: at cwnd
/// 743 KB and srtt 25 ms it commands ~235 Mbit and achieves 127 Mbit into
/// a 100 Mbit link. Lowering this constant only scales that down; it does
/// not remove the overdrive. The min-of-batch feed is shared by every
/// controller and is the thing to fix.
const OVERSHOOT_BDP_FACTOR: f64 = 2.0;
/// Delay budget below which the bottleneck queue counts as empty, as a
/// fixed term plus a fraction of the baseline.
///
/// This was a bare ratio (`srtt < baseline * 1.10`) and this rig has a
/// ~7.4 ms delay
/// floor that is not queueing -- `fair` reaches it at 13% utilisation. As
/// a ratio that constant is 1.30x at a 25 ms base and 1.15x at 50 ms, both
/// above the 1.10 bar, so the geometric recovery this gate controls could
/// never fire on either short path:
///
///   scenario        base   floor srtt   1.10x bar   fired?
///   cross-country   25ms    32.4 (1.30)     27.5      never
///   transatlantic   50ms    57.4 (1.15)     55.0      never
///   satellite      150ms   157.4 (1.05)    165.0      yes
///   degraded       100ms   107.4 (1.07)    110.0      yes
///
/// The gate was added to cure the satellite bimodality and worked there,
/// on the two paths where the ratio happens to clear the floor. Same
/// defect as A1's delay leg and the three loss gates: a fixed overhead is
/// not a ratio.
const QUEUE_EMPTY_FIXED: Duration = Duration::from_millis(10);
/// Mostly fixed, with only a token fraction. The budget has to clear the
/// ~7.4 ms floor, which is what the old bare ratio could not do on short
/// paths -- but it must not *loosen* the long ones, where the old
/// `0.10 x base` was already 15 ms at 150 ms and a looser test just lets
/// the window keep growing into a queue that is genuinely forming. At
/// 0.10 the budget was 25 ms on satellite and cost 6-15% there.
///
///   scenario        base   old bar   this budget   floor
///   cross-country   25ms      2.5ms       12.5ms    7.4ms
///   transatlantic   50ms      5.0ms       15.0ms    7.4ms
///   satellite      150ms     15.0ms       25.0ms    7.4ms
///   degraded       100ms     10.0ms       20.0ms    7.4ms
const QUEUE_EMPTY_FRACTION: f64 = 0.10;

/// Fraction of the window added per round while the queue is empty:
/// `cwnd / 16` is about 6% per round trip.
///
/// Sized to close a realistic under-shoot in a few round trips rather than
/// to probe aggressively — on the measured satellite case it reaches the
/// BDP from 0.85x in roughly four rounds instead of 209. Faster than this
/// starts to resemble a second slow start, and slow start already has a
/// bounded ramp and four exit conditions of its own.
const QUEUE_EMPTY_GROWTH_DIVISOR: usize = 16;

/// How many round trips a congestion epoch may last before a loss counts
/// as a new one regardless of its chunk indices. See `apply_loss`.
///
/// This is a stuck-detector, not a congestion-control rule, so it wants to
/// be as long as it can be while still draining an overdriven window
/// inside one transfer. At four round trips it fired often enough on the
/// 2-5% loss paths to act as an ordinary rule and cost 8-17% of throughput
/// there (satellite/encrypt 9.13 -> 7.73, degraded/encrypt 9.03 -> 7.49).
/// At sixteen it still gives ~13 opportunities across a 12 s transatlantic
/// transfer, which is ample to break a block that would otherwise last
/// forever.
const EPOCH_MAX_RTTS: u32 = 16;

/// States of the AHP-Classic controller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    /// Exponential growth until delay threshold or loss.
    SlowStart,
    /// Additive increase based on delivered bytes.
    CongestionAvoidance,
}

/// AHP-Classic congestion controller.
#[derive(Debug)]
pub struct ClassicController {
    state: State,
    /// Current congestion window in bytes.
    cwnd: usize,
    /// Slow-start threshold.
    ssthresh: usize,
    /// RTT estimator.
    rtt: RttEstimator,
    /// Packet pacer.
    pacer: Pacer,
    /// Skip one increase round after loss (UDT-style, avoids freezing cwnd).
    loss_flag: bool,
    /// Highest sent chunk index when the last decrease happened (epoch
    /// tracking). `None` until the first decrease — 0 is a real chunk
    /// index, so a sentinel of 0 silently swallowed the first loss report
    /// of every transfer.
    last_dec_seq: Option<u64>,
    /// When the last congestion decrease was applied. The epoch is a
    /// duration, not a sequence range; see `apply_loss`.
    last_dec_time: Option<Instant>,
    /// Current highest sent chunk index (high-water mark).
    snd_curr_seq: u64,
    /// Bytes delivered since last cwnd increase in congestion avoidance.
    delivered_since_increase: usize,
    /// External minimum cwnd (from probe floor). The CC will never reduce
    /// cwnd below this, keeping the pacing rate aligned with the floor.
    external_min_cwnd: usize,
    /// Estimated bandwidth in bytes/sec from delivery rate feedback.
    bw_estimate: u64,
    /// EWMA of the gap between ACK batch arrivals (feedback cadence).
    /// RTT samples on a window-limited sender include the receiver's ACK
    /// batching delay (up to its ~15 ms timer), which is feedback latency,
    /// not queueing delay — the delay-based slow-start exit must not
    /// compare srtt against a bare min_rtt that is orders of magnitude
    /// smaller (loopback: 40 µs RTT vs 15 ms ACK cadence).
    ack_gap_ewma: Duration,
    /// Arrival time of the previous ACK batch (see `on_ack_received`).
    last_ack_batch_at: Option<Instant>,
    /// Number of distinct ACK batches observed (see `on_ack_received`).
    ack_batch_count: u64,
    /// Delay-signal hysteresis: the ACK batch (by `ack_batch_count`) in
    /// which srtt was first observed above the delay threshold. The exit
    /// requires the inflation to persist into a later batch — the first
    /// inflated sample after a window wait is indistinguishable from
    /// receiver ACK-batching delay.
    delay_inflated_batch: Option<u64>,
    /// Chunk index that closes the current open feedback round: the send
    /// high-water mark at the moment the round opened. Acking it means a
    /// full RTT of feedback has elapsed (see `track_round`).
    round_end_pn: Option<u64>,
    /// Congestion window at the moment the current round opened, used to
    /// tell "the path stopped delivering more" from "the window stopped
    /// asking for more" (see `track_round`).
    round_start_cwnd: usize,
    /// Bytes delivered in the current open feedback round.
    round_delivered: usize,
    /// Bytes delivered in the most recently closed feedback round.
    round_last_bytes: usize,
    /// Maximum bytes delivered in any closed feedback round — the
    /// per-round delivery the path has demonstrably absorbed. Used both
    /// for the plateau exit and as a cap on the loss target.
    round_full_bytes: usize,
    /// Number of closed feedback rounds.
    round_count: u64,
    /// Consecutive closed rounds without ≥STARTUP_FULL_GAIN delivery
    /// growth (BBR startup full-bandwidth plateau).
    plateau_rounds: u8,
    /// Which signal ended slow start; None while still in it. Diagnostic
    /// only — never read by the control logic.
    exit_reason: Option<&'static str>,
    /// Which branch of `congestion_evidence` first admitted a loss, and
    /// the controller's state at that moment. Diagnostic only.
    gate_reason: Option<&'static str>,
    gate_snapshot: Option<GateSnapshot>,
    /// Number of multiplicative decreases applied. Diagnostic only.
    decreases: u64,
}

impl ClassicController {
    pub fn new() -> Self {
        let initial_rate = (INITIAL_CWND as u64 * 1000) / 100; // rough initial pacing
        Self {
            state: State::SlowStart,
            cwnd: INITIAL_CWND,
            ssthresh: usize::MAX,
            rtt: RttEstimator::new(),
            pacer: Pacer::new(initial_rate),
            loss_flag: false,
            last_dec_seq: None,
            last_dec_time: None,
            snd_curr_seq: 0,
            delivered_since_increase: 0,
            external_min_cwnd: MIN_CWND,
            bw_estimate: 0,
            ack_gap_ewma: Duration::ZERO,
            last_ack_batch_at: None,
            ack_batch_count: 0,
            delay_inflated_batch: None,
            round_end_pn: None,
            round_start_cwnd: INITIAL_CWND,
            round_delivered: 0,
            round_last_bytes: 0,
            round_full_bytes: 0,
            round_count: 0,
            plateau_rounds: 0,
            exit_reason: None,
            gate_reason: None,
            gate_snapshot: None,
            decreases: 0,
        }
    }

    /// Gentle loss response: cut cwnd by 12.5%, skip one increase round.
    /// Only triggers once per congestion epoch (like UDT).
    fn apply_loss(&mut self, first_loss_seq: u64, now: Instant) {
        // One decrease per congestion epoch, with a time bound on how
        // long an epoch may last.
        //
        // The epoch is a sequence range: no second cut until loss is seen
        // above the high-water mark at the previous cut. That is right in
        // the healthy case and it is why this is not simply a timer --
        // making the epoch purely time-based cut too often and cost 34% of
        // throughput on transatlantic (10.55 -> 6.93 MB/s over 20 runs),
        // even though it did remove the overdriven mode.
        //
        // Its fault is that it can be blocked *forever*. `first_loss_seq`
        // is `lost[0]`, the lowest index in the batch, and retransmitted
        // chunks re-report their original index -- so once retransmission
        // is heavy, every batch contains a stale chunk, every batch looks
        // like the current epoch, and the window is never reduced again.
        // The brake is disabled by the condition it exists to correct.
        //
        // Measured on transatlantic, 20 runs: 4 sat at 2.07-2.09x RTT
        // inflation and 8.2-10.3% retransmits against a 1% path loss,
        // while the other 16 held 1.52-1.79x and 0.79-2.29%. No overlap in
        // either statistic -- an attractor, not a tail.
        //
        // So the sequence rule stands and gets a deadline. After
        // `EPOCH_MAX_RTTS` round trips with no cut, a loss is a new epoch
        // whatever its indices say. In the healthy mode the sequence test
        // has long since passed and this never fires; in the stuck mode it
        // is the only thing that can.
        //
        // It is defect 16's shape in a second controller: a mechanism keyed
        // on index monotonicity that stops firing exactly when
        // retransmission is heavy. Time cannot be re-reported.
        let srtt = self
            .rtt
            .smoothed_rtt()
            .filter(|d| !d.is_zero())
            .unwrap_or(Duration::from_millis(50));
        let epoch_expired = matches!(
            self.last_dec_time,
            Some(t) if now.duration_since(t) >= srtt * EPOCH_MAX_RTTS
        );
        let same_epoch = matches!(self.last_dec_seq, Some(last) if first_loss_seq <= last);
        if same_epoch && !epoch_expired {
            return;
        }
        tracing::debug!(
            cwnd = self.cwnd,
            new_cwnd = (self.cwnd as f64 * LOSS_DECREASE_FACTOR) as usize,
            "loss decrease"
        );
        let leaving_slow_start = self.state == State::SlowStart;
        if leaving_slow_start {
            self.state = State::CongestionAvoidance;
            self.exit_reason = Some("loss");
        }
        self.decreases += 1;
        self.ssthresh = ((self.cwnd as f64) * LOSS_DECREASE_FACTOR) as usize;
        // Cap the target at the demonstrated per-round delivery, but only
        // while delivery is stalled (plateau strikes active): a stalled
        // round proves the path could not absorb the window (socket
        // buffer overflow on fast links), so the 12.5% cut alone would
        // converge far above the loss point and the storm would repeat
        // every epoch. While delivery still grows (healthy ramp) or
        // matches the window (lossy WAN), the shortfall is explained by
        // growth or random loss and the cap stays out of the way.
        //
        // Leaving slow start is the other case, and it is why Classic was
        // bimodal. There are two exits from the ramp and they settled the
        // window differently: the plateau exit takes
        // `round_full_bytes.min(cwnd)`, the demonstrated per-round
        // delivery, while this one took a fraction of whatever the window
        // had reached. Which fires is a race between the plateau counter
        // reaching STARTUP_PLATEAU_ROUNDS and the first congestion-
        // classified loss, and slow start doubles every round, so losing
        // that race by one round doubles the window the transfer then runs
        // at for good.
        //
        // Measured, same binary, six consecutive runs of one cell: five
        // exited on plateau at 400-546 KB against a 312 KB BDP and
        // retransmitted 0.67-2.34%; the sixth exited here at 1364 KB,
        // 4.4x BDP, and retransmitted 33.56% -- sending 149,651 packets
        // where the others sent ~100,000 for identical goodput.
        //
        // Slow start exists to find the delivery limit, and
        // `round_full_bytes` is the best measurement of it the ramp
        // produced. Settle there whichever signal ends the ramp, so the
        // two exits agree.
        // The cap stays out of the way on a healthy ramp *below* the BDP,
        // where the last closed round held a half-size window and its
        // delivery is growth rather than saturation. Once the window is
        // demonstrably past the BDP the same reasoning inverts: delivery
        // has saturated, so `round_full_bytes` is a measurement of the
        // path rather than of the ramp, and it is the right place to
        // settle.
        let overshot_ramp = leaving_slow_start && self.window_exceeds_bdp();
        if self.round_full_bytes > 0 && (self.plateau_rounds > 0 || overshot_ramp) {
            self.ssthresh = self.ssthresh.min(self.round_full_bytes);
        }
        // Leaving the ramp *because the window exceeds the BDP* settles at
        // the BDP, not merely at the demonstrated delivery.
        //
        // `round_full_bytes` is a running maximum of per-round delivery,
        // and an early round can deliver more than the path can sustain --
        // a queue that was empty when the transfer started, a token bucket
        // that had filled while the link was idle. Slow start doubles on
        // that, so the ramp is already far past the BDP when the gate
        // fires, and capping at the inflated maximum settles well above it.
        //
        // Measured, same binary, first transfer after the qdisc was
        // configured versus later ones: the ramp reached 1997 KB against a
        // 625 KB BDP and settled at 1261 KB, 2x BDP, retransmitting 10.25%;
        // a later run's gate fired at 227 KB and grew additively to 393 KB,
        // retransmitting 1.03%. Three of ten first-runs did this and none
        // of twenty-four later runs did.
        //
        // The gate has already computed that the window is past the BDP.
        // Settling anywhere above it re-creates the standing queue the gate
        // exists to prevent.
        // ...but only once the bandwidth estimate behind that BDP has had
        // rounds to converge.
        //
        // Without the round guard this fires inside the first 200 ms,
        // while `bw_estimate` is still a fraction of the path's capacity,
        // and caps ssthresh at a BDP computed from it. Measured on
        // transatlantic, six runs of one binary: four left slow start
        // normally and reached 7.7-10.8 MB/s; two exited here at ssthresh
        // 126 and 137 KB against a 625 KB BDP and reached 5.1 and 5.4.
        // From 130 KB, additive increase needs about 354 round trips to
        // reach the BDP -- 17.7 s at this RTT, against a 20 s transfer, so
        // it never arrives. The encrypted profile landed in that mode on
        // every run.
        //
        // This cap was added in e71e711 to stop the exit settling *above*
        // the BDP, which was a real defect. It needs the same
        // STARTUP_MIN_ROUNDS guard the plateau exit already has, or it
        // trades settling too high for settling far too low.
        if overshot_ramp && self.round_count >= STARTUP_MIN_ROUNDS {
            if let Some(min_rtt) = self.rtt.min_rtt() {
                // Same baseline as `window_exceeds_bdp`, same reason:
                // capping ssthresh at a bare-min_rtt BDP puts it below the
                // working window on a feedback-clocked path, leaving only
                // the external floor to rescue it.
                let baseline = min_rtt.max(self.ack_gap_ewma);
                let bdp = (self.bw_estimate as f64 * baseline.as_secs_f64()) as usize;
                if bdp > 0 {
                    self.ssthresh = self.ssthresh.min(bdp);
                }
            }
        }
        self.ssthresh = self.ssthresh.max(self.external_min_cwnd);
        self.cwnd = self.ssthresh;
        self.loss_flag = true;
        self.last_dec_seq = Some(self.snd_curr_seq);
        self.last_dec_time = Some(now);
        // The startup measurements have now been spent on the cut above.
        // Keeping them would let a single early extreme govern every later
        // congestion epoch, since `round_full_bytes` is a running maximum
        // that no later round can lower.
        self.reset_startup_evidence();
        self.update_pacing_rate();
    }

    /// Drop the startup delivery evidence on leaving slow start.
    ///
    /// `round_full_bytes` is a running maximum and `plateau_rounds` only
    /// accumulates in slow start, so once the ramp is over both are frozen
    /// history. Left in place they would keep arming the loss cap in
    /// congestion avoidance against a number the path may have long since
    /// outgrown (or fallen below).
    fn reset_startup_evidence(&mut self) {
        self.plateau_rounds = 0;
        self.round_full_bytes = 0;
        self.round_delivered = 0;
        self.round_end_pn = Some(self.snd_curr_seq);
        self.round_start_cwnd = self.cwnd;
    }

    /// Whether a loss report should be read as congestion.
    ///
    /// Loss alone does not mean the path is full: on a satellite or
    /// degraded WAN link, packets are dropped at a steady rate that has
    /// nothing to do with the window, and cutting on each one is exactly
    /// what collapses loss-based CC on such links. A cut therefore needs
    /// corroborating evidence that the path is actually at capacity:
    ///
    /// - a queue building — srtt inflated over the delay baseline — or
    /// - delivery having plateaued while the window kept opening, which
    ///   is the signature of a sender overrunning a buffer on a fast link
    ///   (where the drop happens before any queueing delay is visible).
    ///
    /// Random loss produces neither, so the window is left alone and the
    /// sender simply retransmits.
    /// Whether a loss report should be read as congestion.
    pub fn loss_indicates_congestion(&self) -> bool {
        self.congestion_evidence().is_some()
    }

    /// Which corroborating signal, if any, says the path is at capacity.
    ///
    /// Split out from the boolean so the branch that fired can be named.
    /// "Loss ended slow start" is not a diagnosis on its own — the useful
    /// question is which evidence the gate accepted, and a bool cannot
    /// answer it.
    fn congestion_evidence(&self) -> Option<&'static str> {
        // Hold this to the same standard as the exit that consumes it.
        // Accepting a single strike meant one noisy feedback round could
        // convince the gate that random loss was congestion, while three
        // consecutive rounds are required before the same signal is
        // trusted to end the ramp on its own — the weaker bar being wired
        // to the more consequential outcome.
        if self.plateau_rounds >= STARTUP_PLATEAU_ROUNDS {
            return Some("plateau");
        }
        // A window far past the BDP is congestion evidence in either
        // state. It was briefly restricted to congestion avoidance because
        // it appeared to misfire at 0.12x BDP during slow start — but that
        // was a lagging bandwidth estimate in the simulator, not a real
        // ramp, and disabling it here removed the only brake on a window
        // that had already overshot: a run was observed stuck in slow
        // start at 2.24x BDP retransmitting 99.3% of its packets, with the
        // plateau exit one strike short of firing and its rounds no longer
        // closing because forward progress had stalled.
        if self.window_exceeds_bdp() {
            return Some("over-bdp");
        }
        match (self.rtt.min_rtt(), self.rtt.smoothed_rtt()) {
            (Some(min_rtt), Some(srtt)) => {
                // A fixed allowance plus a fraction of the baseline, not a
                // bare ratio.
                //
                // About 7.3 ms of the excess delay on any path is fixed
                // overhead rather than queue -- serialisation, GSO
                // batching, the 5 ms control tick. On a 25 ms path that
                // constant alone is a ratio of 1.29, so a 1.25 factor
                // fired on every loss there as soon as the controller
                // could see a truthful srtt, and Classic backed off
                // continuously: cross-country goodput fell 10.83 -> 10.43
                // and transatlantic 10.47 -> 8.30, with the encrypted
                // profile losing 38%.
                //
                // The same defect was fixed in fair.rs and rl.rs when the
                // RTT feed was corrected; this branch was missed, and it
                // is why Classic over-corrected rather than simply
                // improving.
                let baseline = min_rtt.max(self.ack_gap_ewma);
                let budget = LOSS_QUEUEING_FIXED.as_secs_f64()
                    + LOSS_QUEUEING_FRACTION * baseline.as_secs_f64();
                if srtt.as_secs_f64() - baseline.as_secs_f64() > budget {
                    Some("queueing")
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    /// Whether the bottleneck queue is demonstrably empty.
    ///
    /// Uses the same `max(min_rtt, ack_gap_ewma)` baseline as
    /// `congestion_evidence`, so the growth test and the congestion test
    /// cannot disagree about what the path's unloaded delay is. The
    /// `ack_gap_ewma` floor matters on fast paths, where a bare min_rtt can
    /// be far below the feedback cadence and every measurement then looks
    /// like queueing.
    ///
    /// Returns false when either measurement is missing: absence of
    /// evidence is not evidence of an empty queue, and the caller uses this
    /// to grow geometrically.
    fn queue_is_empty(&self) -> bool {
        match (self.rtt.min_rtt(), self.rtt.smoothed_rtt()) {
            (Some(min_rtt), Some(srtt)) => {
                let baseline = min_rtt.max(self.ack_gap_ewma).as_secs_f64();
                if baseline <= 0.0 {
                    return false;
                }
                // A fixed term plus a fraction, not a bare ratio. See
                // `QUEUE_EMPTY_FIXED`: the ~7.4 ms floor on this rig is
                // 1.30x at a 25 ms base, so the old `< baseline * 1.10`
                // test was unreachable on the two short paths and the
                // recovery it gates never ran there.
                let budget = QUEUE_EMPTY_FIXED.as_secs_f64()
                    + QUEUE_EMPTY_FRACTION * baseline;
                srtt.as_secs_f64() - baseline < budget
            }
            _ => false,
        }
    }

    /// Whether the window is more than `OVERSHOOT_BDP_FACTOR` times the
    /// estimated bandwidth-delay product.
    ///
    /// `min_rtt` rather than `srtt` is deliberate: srtt inflates under
    /// queueing, which would make an overshooting window look *smaller*
    /// relative to the BDP exactly when it is worst. min_rtt approximates
    /// the propagation delay, so `bw x min_rtt` is the amount genuinely
    /// in flight rather than sitting in a buffer.
    fn window_exceeds_bdp(&self) -> bool {
        let Some(min_rtt) = self.rtt.min_rtt() else { return false };
        if self.bw_estimate == 0 || min_rtt.is_zero() {
            return false;
        }
        // Delivery is clocked by feedback, not by propagation. Where the ACK
        // cadence is longer than the RTT the window has to cover
        // `bw x cadence`, and a BDP taken from bare min_rtt brands the
        // minimum working window a permanent overshoot.
        //
        // This was the last gate here still dividing by bare min_rtt;
        // `congestion_evidence`, `queue_is_empty` and `check_delay_signal`
        // already use this baseline, each noting that on fast paths a bare
        // min_rtt makes every measurement look like queueing. Measured on
        // an 802.11 first hop: min_rtt 2.3 ms against a 4 ms ACK cadence,
        // so 2 x bw x min_rtt = ~200 KB classified the 512 KB floor itself
        // as overshoot — throttling congestion avoidance to 1 MTU per
        // window and letting every 3-packet loss burst cut 12.5%.
        //
        // Inert on the WAN scenarios, and that is measured rather than
        // argued: on `degraded` the two terms are min_rtt 100.1 ms against
        // ack_gap 15.0 ms, so `max` returns min_rtt and the expression is
        // unchanged. Same-batch n=6-10: +2.5 / -0.2 / +1.4 / -1.3%, worst
        // Welch t = -0.71.
        let baseline = min_rtt.max(self.ack_gap_ewma);
        let bdp = self.bw_estimate as f64 * baseline.as_secs_f64();
        bdp > 0.0 && (self.cwnd as f64) > OVERSHOOT_BDP_FACTOR * bdp
    }

    fn check_delay_signal(&mut self) {
        if self.state != State::SlowStart {
            return;
        }
        if let (Some(min_rtt), Some(srtt)) = (self.rtt.min_rtt(), self.rtt.smoothed_rtt()) {
            // Compare srtt against the larger of the path RTT and the
            // measured feedback cadence. On links whose RTT is far below
            // the receiver's ACK-batching interval (loopback: 40 µs RTT,
            // ~15 ms ACK timer), every RTT sample carries up to one ACK
            // interval of feedback delay; treating that inflation as
            // queueing would exit slow start on the first ACK and strand
            // the transfer at ~cwnd/ACK-interval throughput. When ACKs
            // are timely (busy WAN links, per-128-packet ACKs) the EWMA
            // stays below min_rtt and the baseline is exactly min_rtt,
            // i.e. unchanged behavior.
            let baseline = min_rtt.max(self.ack_gap_ewma);
            let threshold = baseline.as_secs_f64() * DELAY_THRESHOLD_FACTOR;
            if srtt.as_secs_f64() <= threshold {
                self.delay_inflated_batch = None;
                return;
            }
            // Inflation must persist into a second feedback batch before
            // exiting: the first inflated sample after a window wait is
            // indistinguishable from receiver ACK-batching delay (the
            // cadence EWMA has not observed a gap yet). This check runs
            // only from `on_ack_received` so `ack_batch_count` identifies
            // the current feedback batch.
            match self.delay_inflated_batch {
                Some(armed) if armed < self.ack_batch_count => {
                    tracing::debug!(
                        srtt_ms = srtt.as_millis(),
                        min_rtt_ms = min_rtt.as_millis(),
                        "delay threshold hit, exiting slow start"
                    );
                    self.ssthresh = self.cwnd;
                    self.state = State::CongestionAvoidance;
                    self.exit_reason = Some("delay");
                    self.delay_inflated_batch = None;
                    self.update_pacing_rate();
                }
                Some(_) => {} // same batch, already counted
                None => self.delay_inflated_batch = Some(self.ack_batch_count),
            }
        }
    }

    /// Accumulate delivered bytes into the open feedback round and close
    /// the round once it completes.  On close, update the plateau counters
    /// and — in slow start — exit on a sustained delivery plateau (BBR's
    /// full-bandwidth test): the delivery rate stopped growing because the
    /// path is saturated, so further doubling only overruns the receiver.
    ///
    /// Rounds are measured in **packet-number space**, not wall time: a
    /// round opens by recording the highest chunk index sent so far and
    /// closes when that index is acked, which is exactly one RTT of
    /// feedback regardless of what the RTT estimator believes.  A
    /// wall-clock round of `max(srtt, ack_cadence)` looks equivalent but
    /// is not: any downward error in srtt shortens the round below a real
    /// RTT, and a sub-RTT round always reads as flat delivery — delivery
    /// per round is bounded by the window, so slicing an RTT into pieces
    /// reports a plateau that says nothing about the path.  On a high-RTT
    /// link (where such errors are both likeliest and costliest) that
    /// stranded slow start within the first few ACKs.
    fn track_round(&mut self, delivered: usize, acked_pn: u64) {
        self.round_delivered += delivered;
        // Rounds are armed in `on_packet_sent`; an ACK with nothing sent
        // carries no round information.
        let end_pn = match self.round_end_pn {
            None => return,
            Some(e) => e,
        };
        if acked_pn < end_pn {
            return;
        }
        let round_bytes = self.round_delivered;
        let start_cwnd = self.round_start_cwnd;
        self.round_delivered = 0;
        self.round_end_pn = Some(self.snd_curr_seq);
        self.round_start_cwnd = self.cwnd;
        self.round_last_bytes = round_bytes;
        self.round_count += 1;
        if round_bytes > 0 {
            // A plateau is only evidence about the *path* if the window
            // asked for more during the round.  When the window held flat
            // — the startup BDP cap binding — delivery holds flat with it
            // by definition, and counting that as saturation would let the
            // window pin itself: the cap suppresses growth, the flat
            // delivery reads as a full pipe, and the ramp ends early.
            //
            // Restricted to slow start for the same reason: congestion
            // avoidance opens the window by ~1 MTU per window delivered,
            // which is far too little to expect a 5/4 rise in delivery, so
            // every steady-state round would read as a plateau.
            if self.state == State::SlowStart && self.cwnd > start_cwnd {
                if (round_bytes as f64) < STARTUP_FULL_GAIN * self.round_full_bytes as f64 {
                    self.plateau_rounds = self.plateau_rounds.saturating_add(1);
                } else {
                    self.plateau_rounds = 0;
                }
            }
            self.round_full_bytes = self.round_full_bytes.max(round_bytes);
        }
        if self.state == State::SlowStart
            && self.round_count >= STARTUP_MIN_ROUNDS
            && self.plateau_rounds >= STARTUP_PLATEAU_ROUNDS
        {
            // Settle the window at the demonstrated per-round delivery:
            // large enough to keep the pipe full, small enough not to
            // overrun the receiver. Never grows the window, never drops
            // below the external floor.
            let target = self.round_full_bytes.min(self.cwnd).max(self.external_min_cwnd);
            tracing::debug!(
                cwnd = self.cwnd,
                target,
                full = self.round_full_bytes,
                "delivery plateau, exiting slow start"
            );
            self.ssthresh = target;
            self.cwnd = target;
            self.state = State::CongestionAvoidance;
            self.exit_reason = Some("plateau");
            // Same reasoning as in `apply_loss`: the startup evidence has
            // been spent on `target` and must not govern later epochs.
            self.reset_startup_evidence();
            self.update_pacing_rate();
        }
    }

    fn update_pacing_rate(&mut self) {
        if let Some(srtt) = self.rtt.smoothed_rtt() {
            if !srtt.is_zero() {
                let rate = (self.cwnd as f64 / srtt.as_secs_f64()) as u64;
                self.pacer.set_rate(rate);
            }
        }
    }
}

impl Default for ClassicController {
    fn default() -> Self {
        Self::new()
    }
}

/// Controller state at the moment the loss gate first opened.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GateSnapshot {
    pub in_slow_start: bool,
    pub cwnd: usize,
    pub plateau_rounds: u8,
    pub round_count: u64,
    pub bw_estimate: u64,
    pub min_rtt_us: u64,
    pub srtt_us: u64,
    pub ack_gap_us: u64,
}

/// A snapshot of `ClassicController`'s internal state.
///
/// Exposed because the interesting failures are transitions — which exit
/// ended slow start, whether plateau strikes were accruing — and those are
/// invisible from `congestion_window()` alone. Used by the path simulator
/// (`crate::pathsim`) and useful for operational tracing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClassicDiag {
    pub in_slow_start: bool,
    pub cwnd: usize,
    pub ssthresh: usize,
    pub plateau_rounds: u8,
    pub round_count: u64,
    pub bw_estimate: u64,
    pub decreases: u64,
}

impl ClassicController {
    /// Which branch of the loss gate first admitted a loss report.
    pub fn gate_reason(&self) -> Option<&'static str> {
        self.gate_reason
    }

    /// Controller state when that happened.
    pub fn gate_snapshot(&self) -> Option<GateSnapshot> {
        self.gate_snapshot
    }

    /// Current internal state, for diagnostics.
    pub fn diag(&self) -> ClassicDiag {
        ClassicDiag {
            in_slow_start: self.state == State::SlowStart,
            cwnd: self.cwnd,
            ssthresh: self.ssthresh,
            plateau_rounds: self.plateau_rounds,
            round_count: self.round_count,
            bw_estimate: self.bw_estimate,
            decreases: self.decreases,
        }
    }

}

impl CongestionController for ClassicController {
    fn on_ack_received(&mut self, acked: &AckInfo, now: Instant) {
        let delivered = acked.delivered_bytes as usize;

        // Track the feedback cadence: the transport calls this once per
        // acked packet, but all packets from one received ACK datagram
        // share the same `now`, and per-stream datagrams arrive as a
        // back-to-back burst — so only gaps at or above
        // ACK_BATCH_GAP_FLOOR mark a new feedback batch.
        match self.last_ack_batch_at {
            Some(prev) => {
                let gap = now.saturating_duration_since(prev);
                if gap >= ACK_BATCH_GAP_FLOOR {
                    self.ack_gap_ewma = if self.ack_gap_ewma.is_zero() {
                        gap
                    } else {
                        (self.ack_gap_ewma * 7 + gap) / 8
                    };
                    self.last_ack_batch_at = Some(now);
                    self.ack_batch_count += 1;
                }
            }
            None => {
                self.last_ack_batch_at = Some(now);
                self.ack_batch_count = 1;
            }
        }

        // Feedback-round accounting: plateau detection and the loss cap
        // both reason about per-round delivered bytes.
        self.track_round(delivered, acked.packet_number);

        // EWMA smooth bandwidth estimate (7/8 old + 1/8 new).
        if acked.delivery_rate > 0 {
            self.bw_estimate = if self.bw_estimate == 0 {
                acked.delivery_rate
            } else {
                (self.bw_estimate * 7 + acked.delivery_rate) / 8
            };
        }

        // Skip one increase round after loss (like UDT's loss_flag).
        if self.loss_flag {
            self.loss_flag = false;
            return;
        }

        match self.state {
            State::SlowStart => {
                // Exponential growth: increase cwnd by delivered bytes,
                // capped at STARTUP_BDP_GAIN times the delivery-rate BDP
                // estimate so the ramp cannot overshoot the path's
                // demonstrated capacity without bound (BBR's startup
                // bound). Without the cap, loss-free fast-feedback links
                // (loopback) double the window until socket-buffer drops
                // cause loss storms. The cap bounds growth only — it
                // never shrinks the window — and is self-raising:
                // delivering the capped window lifts the bandwidth
                // estimate, which lifts the cap.
                let grown = self.cwnd + delivered;
                self.cwnd = match self.rtt.smoothed_rtt().filter(|r| !r.is_zero()) {
                    Some(srtt) if self.bw_estimate > 0 => {
                        let cap = ((STARTUP_BDP_GAIN * self.bw_estimate as f64
                            * srtt.as_secs_f64()) as usize)
                            .max(self.external_min_cwnd)
                            .max(self.cwnd);
                        grown.min(cap)
                    }
                    _ => grown,
                };
                tracing::trace!(cwnd = self.cwnd, "slow start: cwnd increased");
                self.check_delay_signal();
                if self.cwnd >= self.ssthresh {
                    self.state = State::CongestionAvoidance;
                    self.exit_reason.get_or_insert("ssthresh");
                }
            }
            State::CongestionAvoidance => {
                // Bandwidth-aware increase: if we have headroom, grow faster.
                let current_rate = self.rtt.smoothed_rtt()
                    .filter(|r| !r.is_zero())
                    .map(|r| self.cwnd as u64 * 1_000_000 / r.as_micros() as u64)
                    .unwrap_or(0);

                // Past the BDP bound, fall back to plain additive
                // increase. A hard freeze would be defensible — the window
                // is already larger than the path can hold — but it can
                // deadlock: the bound is derived from measured delivery,
                // and delivery cannot rise if the window may never grow.
                // One MTU per round still converges, just slowly, and
                // leaves the loss path responsible for reductions.
                let over_bdp = self.window_exceeds_bdp();
                let increase = if !over_bdp && self.bw_estimate > 0 && current_rate > 0
                    && self.bw_estimate > current_rate
                {
                    // Headroom available: increase proportional to gap.
                    // Ramp up to fill the gap over ~4 RTTs.
                    let headroom_bytes = ((self.bw_estimate - current_rate) as f64
                        * self.rtt.smoothed_rtt()
                            .unwrap_or(Duration::from_millis(10))
                            .as_secs_f64()) as usize;
                    (headroom_bytes / 4).max(MTU)
                } else if !over_bdp && self.queue_is_empty() {
                    // The headroom test above compares `bw_estimate`, which
                    // is measured *delivery*, against `current_rate`, which
                    // is `cwnd / srtt` — a property of the window, not of
                    // the path. cwnd/srtt exceeds delivery whenever the
                    // window is not perfectly utilised, which is most of the
                    // time with multiple streams and any retransmission. So
                    // the test reads "no headroom" from a large window
                    // rather than from a full link, and the branch dies.
                    //
                    // Measured on the 150 ms satellite path: cwnd sat at
                    // 1.50 MB, cwnd/srtt = 9.95 MB/s, delivery 6.8 MB/s on a
                    // 12.5 MB/s link. 46% of the link idle, and the gate
                    // concluded there was no room. Additive increase then
                    // needed 209 rounds — 33 s — to close a 0.29 MB gap in a
                    // 19 s transfer, so the window was frozen for the whole
                    // run at 6.8 MB/s while an identical run that happened
                    // to overshoot in slow start reached 10.3. That is the
                    // Classic satellite bimodality: not two behaviours, one
                    // behaviour that cannot correct a low starting point.
                    //
                    // An empty queue is direct evidence the bottleneck is
                    // not full, and it does not depend on the window at all.
                    // Grow geometrically while it holds; the delay signal
                    // ends the growth as soon as the queue starts to build,
                    // which is well before it is full, so this converges
                    // toward a just-full pipe rather than the standing-queue
                    // state the overshooting runs land in.
                    (self.cwnd / QUEUE_EMPTY_GROWTH_DIVISOR).max(MTU)
                } else {
                    // At or above estimated bandwidth: standard additive increase.
                    MTU
                };

                self.delivered_since_increase += delivered;
                if self.delivered_since_increase >= self.cwnd {
                    self.delivered_since_increase -= self.cwnd;
                    self.cwnd += increase;
                    tracing::trace!(cwnd = self.cwnd, increase, "congestion avoidance: cwnd increased");
                }
                self.check_delay_signal();
            }
        }

        self.update_pacing_rate();
    }

    fn on_packet_sent(&mut self, packet_number: u64, bytes: usize, now: Instant) {
        // Retransmits re-report an older chunk index; keep the high-water mark.
        self.snd_curr_seq = self.snd_curr_seq.max(packet_number);
        // Arm the first feedback round on the first packet out, so the
        // round is already open when its ACK arrives. Arming on the first
        // ACK instead would set the mark to a high-water that the ACKs
        // being processed have already passed, and the round would not
        // close until a whole extra window had been acked.
        if self.round_end_pn.is_none() {
            self.round_end_pn = Some(packet_number);
            self.round_start_cwnd = self.cwnd;
        }
        self.pacer.on_packet_sent(bytes, now);
    }

    fn on_packet_lost(&mut self, lost: &[u64], now: Instant) {
        // Only decrease on significant loss (≥3 packets), like UDT.
        // Sporadic 1-2 packet losses from WiFi interference are ignored.
        if lost.len() < 3 {
            return;
        }
        // ...and only when the loss actually says the path is full. See
        // `loss_indicates_congestion`: random loss on a lossy-but-idle
        // link must not shrink the window.
        let evidence = self.congestion_evidence();
        if evidence.is_none() {
            tracing::trace!(
                lost = lost.len(),
                "loss without congestion evidence, window unchanged"
            );
            return;
        }
        if self.gate_reason.is_none() {
            self.gate_reason = evidence;
            self.gate_snapshot = Some(GateSnapshot {
                in_slow_start: self.state == State::SlowStart,
                cwnd: self.cwnd,
                plateau_rounds: self.plateau_rounds,
                round_count: self.round_count,
                bw_estimate: self.bw_estimate,
                min_rtt_us: self.rtt.min_rtt().map(|d| d.as_micros() as u64).unwrap_or(0),
                srtt_us: self.rtt.smoothed_rtt().map(|d| d.as_micros() as u64).unwrap_or(0),
                ack_gap_us: self.ack_gap_ewma.as_micros() as u64,
            });
        }
        self.apply_loss(lost[0], now);
    }

    fn congestion_window(&self) -> usize {
        self.cwnd
    }

    fn send_rate(&self) -> Option<u64> {
        Some(self.pacer.rate_bps())
    }

    fn can_send(&self, bytes_in_flight: usize) -> bool {
        bytes_in_flight < self.cwnd
    }

    fn on_rtt_update(&mut self, rtt: Duration) {
        self.rtt.update(rtt);
        // No delay-signal check here: the transport feeds one RTT sample
        // per ACK batch immediately before that batch's per-packet ACKs,
        // and the hysteresis can only tell batches apart from within
        // `on_ack_received` (see `ack_batch_count`).
        self.update_pacing_rate();
    }

    fn on_rtt_batch(&mut self, mean: Duration, min: Duration) {
        self.rtt.update_batch(mean, min);
    }

    fn pacing_interval(&self, packet_size: usize) -> Duration {
        self.pacer.pacing_interval(packet_size)
    }

    fn diag_line(&self) -> Option<String> {
        let d = self.diag();
        Some(format!(
            "slow_start={} cwnd={}KB ssthresh={}KB plateau={} round={} bw={:.2}Mbit decreases={} gate={} min_rtt={:.1}ms ack_gap={:.1}ms bdp={}KB",
            d.in_slow_start,
            d.cwnd / 1024,
            d.ssthresh / 1024,
            d.plateau_rounds,
            d.round_count,
            d.bw_estimate as f64 * 8.0 / 1e6,
            d.decreases,
            self.gate_reason().unwrap_or("-"),
            self.rtt.min_rtt().map(|d| d.as_secs_f64()*1000.0).unwrap_or(0.0),
            self.ack_gap_ewma.as_secs_f64()*1000.0,
            self.rtt.min_rtt()
                .map(|m| (self.bw_estimate as f64 * m.as_secs_f64()) as usize / 1024)
                .unwrap_or(0),
        ))
    }

    /// Classic is window-based and does want a loss signal.
    ///
    /// This was previously off because the sender's retransmit timer was a
    /// fixed 100 ms: on any path with a longer RTT every packet "timed
    /// out" before its ACK could arrive, so the timeouts were noise and
    /// silencing them was the only way to keep the window from collapsing.
    /// The timer is now derived from the measured RTT (and floored at
    /// twice the probed base RTT), so a timeout is real evidence the
    /// packet was dropped. Whether that evidence justifies shrinking the
    /// window is then decided by `loss_indicates_congestion`, which is
    /// what keeps random loss on a lossy link from cutting the rate.
    fn wants_timeout_loss(&self) -> bool { true }

    fn exit_reason(&self) -> Option<&'static str> {
        self.exit_reason
    }

}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AckInfo;

    /// Establish a low delay baseline and then inflate srtt well past the
    /// queueing threshold, so a loss report reads as congestion rather
    /// than as random loss (see `loss_indicates_congestion`).
    fn build_queue(cc: &mut ClassicController) {
        cc.on_rtt_update(Duration::from_millis(50));
        for _ in 0..20 {
            cc.on_rtt_update(Duration::from_millis(200));
        }
    }

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
        let cc = ClassicController::new();
        assert_eq!(cc.congestion_window(), INITIAL_CWND);
        assert_eq!(cc.state, State::SlowStart);
        assert!(cc.can_send(0));
        assert!(!cc.can_send(INITIAL_CWND));
    }

    #[test]
    fn slow_start_grows_exponentially() {
        let mut cc = ClassicController::new();
        let now = Instant::now();

        cc.on_rtt_update(Duration::from_millis(50));

        let initial = cc.congestion_window();
        cc.on_packet_sent(1, MTU, now);
        // Delivery rate well above cwnd/srtt so the 2×BDP startup bound
        // does not constrain growth.
        cc.on_ack_received(&ack(1, MTU as u64, 100_000_000), now + Duration::from_millis(50));

        assert!(cc.congestion_window() > initial);
        assert_eq!(cc.state, State::SlowStart);
    }

    #[test]
    fn loss_decreases_cwnd() {
        let mut cc = ClassicController::new();
        let now = Instant::now();

        cc.on_rtt_update(Duration::from_millis(50));
        for i in 1..=10 {
            cc.on_packet_sent(i, MTU, now);
        }

        // A cut needs corroborating evidence that the path is full.
        build_queue(&mut cc);

        let cwnd_before = cc.congestion_window();
        // Need ≥3 packets to trigger decrease.
        let lost: Vec<u64> = (1..=5).collect();
        cc.on_packet_lost(&lost, now + Duration::from_millis(100));

        let expected = ((cwnd_before as f64) * LOSS_DECREASE_FACTOR) as usize;
        assert_eq!(cc.congestion_window(), expected.max(MIN_CWND));
        // Should be in CA after loss, not frozen.
        assert_eq!(cc.state, State::CongestionAvoidance);
    }

    #[test]
    fn loss_flag_skips_one_increase() {
        let mut cc = ClassicController::new();
        let now = Instant::now();

        cc.on_rtt_update(Duration::from_millis(50));
        cc.state = State::CongestionAvoidance;
        for i in 1..=10 {
            cc.on_packet_sent(i, MTU, now);
        }

        // Trigger loss.
        build_queue(&mut cc);
        cc.on_packet_lost(&[1, 2, 3], now + Duration::from_millis(50));
        let cwnd_after_loss = cc.congestion_window();
        assert!(cc.loss_flag);

        // Next ACK should clear loss_flag but NOT increase cwnd.
        cc.on_ack_received(
            &ack(5, MTU as u64, 1_000_000),
            now + Duration::from_millis(100),
        );
        assert!(!cc.loss_flag);
        assert_eq!(cc.congestion_window(), cwnd_after_loss);
    }

    #[test]
    fn epoch_prevents_double_decrease() {
        let mut cc = ClassicController::new();
        let now = Instant::now();

        cc.on_rtt_update(Duration::from_millis(50));
        for i in 1..=20 {
            cc.on_packet_sent(i, MTU, now);
        }

        // First loss: triggers decrease.
        cc.on_packet_lost(&[1, 2, 3], now + Duration::from_millis(50));
        let cwnd_after_first = cc.congestion_window();

        // Second loss in same epoch (seq <= last_dec_seq): no additional decrease.
        cc.on_packet_lost(&[4, 5, 6], now + Duration::from_millis(60));
        assert_eq!(cc.congestion_window(), cwnd_after_first);
    }

    #[test]
    fn a_congestion_epoch_has_a_deadline() {
        let mut cc = ClassicController::new();
        let now = Instant::now();

        cc.on_rtt_update(Duration::from_millis(50));
        for i in 0..20 {
            cc.on_packet_sent(i, MTU, now);
        }

        // First loss: decrease, epoch starts.
        build_queue(&mut cc);
        cc.on_packet_lost(&[1, 2, 3], now + Duration::from_millis(50));
        let cwnd_after_first = cc.congestion_window();

        // Stale indices, inside the epoch and well inside the deadline:
        // suppressed, which is the healthy-path behaviour being preserved.
        cc.on_packet_lost(&[4, 5, 6], now + Duration::from_millis(60));
        assert_eq!(
            cc.congestion_window(),
            cwnd_after_first,
            "a second cut inside one epoch"
        );

        // Fresh indices, above the high-water mark: a new epoch straight
        // away, no deadline needed. This is the common case and it is why
        // the rule stays sequence-primary -- making it purely time-based
        // cut too often and cost 34% of throughput on the rig.
        for i in 20..30 {
            cc.on_packet_sent(i, MTU, now + Duration::from_millis(65));
        }
        build_queue(&mut cc);
        cc.on_packet_lost(&[25, 26, 27], now + Duration::from_millis(70));
        assert!(
            cc.congestion_window() < cwnd_after_first,
            "loss above the high-water mark should open a new epoch"
        );
        let cwnd_after_second = cc.congestion_window();
        // `build_queue` drives srtt to ~200 ms and the deadline is
        // EPOCH_MAX_RTTS of those, so steps below are spaced past ~3.2 s.

        // Past the deadline: a new epoch, even though every index in the
        // batch is *below* the high-water mark. This is the case the bare
        // sequence guard could not express, and it is the one that
        // matters: under heavy retransmission every batch looks old.
        build_queue(&mut cc);
        cc.on_packet_lost(&[1, 2, 3], now + Duration::from_millis(4000));
        assert!(
            cc.congestion_window() < cwnd_after_second,
            "stale chunk indices blocked the window reduction past the deadline"
        );
    }

    /// The transatlantic bimodality, in one assertion.
    ///
    /// `lost[0]` is the lowest index in the batch and retransmits re-report
    /// their original index, so under heavy loss every batch contains a
    /// stale chunk and `lost[0] <= snd_curr_seq` always held. The window
    /// could then never be reduced again, which is what made the
    /// overdriven mode an attractor rather than a transient: 4 of 20 rig
    /// runs sat at 2.07-2.09x RTT inflation and 8.2-10.3% retransmits
    /// against a 1% path loss.
    #[test]
    fn repeated_loss_of_old_chunks_still_reduces_the_window() {
        let mut cc = ClassicController::new();
        let now = Instant::now();
        cc.on_rtt_update(Duration::from_millis(50));
        for i in 0..1000 {
            cc.on_packet_sent(i, MTU, now);
        }

        build_queue(&mut cc);
        cc.on_packet_lost(&[10, 11, 12], now + Duration::from_millis(50));
        let after_first = cc.congestion_window();

        // Ten further round trips, every one losing the *same* early
        // chunks -- exactly what a persistently full queue produces.
        // Spaced past the deadline (EPOCH_MAX_RTTS x the ~200 ms srtt
        // `build_queue` establishes), so each is a distinct epoch even
        // though every index is stale.
        let mut t = 3500u64;
        for _ in 0..10 {
            build_queue(&mut cc);
            cc.on_packet_lost(&[10, 11, 12], now + Duration::from_millis(t));
            t += 3500;
        }

        assert!(
            cc.congestion_window() < after_first / 2,
            "window {} did not fall below half of {} after ten congestion \
             epochs of repeated loss",
            cc.congestion_window(),
            after_first
        );
    }

    #[test]
    fn delay_signal_exits_slow_start() {
        let mut cc = ClassicController::new();
        let mut now = Instant::now();

        // Establish a low min_rtt.
        cc.on_rtt_update(Duration::from_millis(10));

        // Feed many high-RTT samples so the EWMA converges above the 5×
        // threshold (10ms * 5 = 50ms).
        for _ in 0..10 {
            cc.on_rtt_update(Duration::from_millis(200));
        }

        // The exit requires the inflation to persist across two ACK
        // batches: the first inflated batch only arms the signal. The
        // batches themselves stay timely (3ms apart) so the feedback-
        // cadence baseline does not absorb the inflation.
        cc.on_packet_sent(1, MTU, now);
        cc.on_ack_received(
            &ack(1, MTU as u64, 1_000_000),
            now + Duration::from_millis(200),
        );
        assert_eq!(cc.state, State::SlowStart);

        now += Duration::from_millis(203);
        cc.on_rtt_update(Duration::from_millis(200));
        cc.on_packet_sent(2, MTU, now);
        cc.on_ack_received(&ack(2, MTU as u64, 1_000_000), now);

        // srtt well above 50ms in two consecutive batches → exits.
        assert_ne!(cc.state, State::SlowStart);
    }

    #[test]
    fn congestion_avoidance_additive_increase() {
        let mut cc = ClassicController::new();
        let now = Instant::now();

        // Force into congestion avoidance.
        cc.state = State::CongestionAvoidance;
        cc.on_rtt_update(Duration::from_millis(50));
        let initial_cwnd = cc.congestion_window();

        // Deliver enough bytes to trigger an increase.
        // Need to deliver >= cwnd worth of bytes (INITIAL_CWND = 128*MTU = 153600).
        let n_pkts = 140; // 140 * 1200 = 168000 > 153600
        let mut t = now;
        for i in 0..n_pkts {
            cc.on_packet_sent(i, MTU, t);
            t += Duration::from_millis(5);
        }
        for i in 0..n_pkts {
            cc.on_ack_received(&ack(i, MTU as u64, 1_000_000), t);
            t += Duration::from_millis(5);
        }

        assert!(cc.congestion_window() > initial_cwnd);
    }

    #[test]
    fn min_cwnd_respected() {
        let mut cc = ClassicController::new();
        let now = Instant::now();

        // Set cwnd to minimum.
        cc.cwnd = MIN_CWND;
        cc.on_packet_sent(1, MTU, now);

        // Loss should not reduce below MIN_CWND.
        cc.on_packet_lost(&[1], now + Duration::from_millis(100));
        assert!(cc.congestion_window() >= MIN_CWND);
    }

    #[test]
    fn pacing_interval_reasonable() {
        let mut cc = ClassicController::new();
        cc.on_rtt_update(Duration::from_millis(50));

        let interval = cc.pacing_interval(MTU);
        // Should be some positive duration.
        assert!(interval > Duration::ZERO);
        // At initial cwnd of 38400 bytes and 50ms RTT, rate ~ 768KB/s.
        // Interval for 1200 bytes ~ 1.6ms.
        assert!(interval < Duration::from_millis(100));
    }

    #[test]
    fn slow_start_survives_ack_batch_delay() {
        // Loopback-shaped feedback: 40 µs path RTT, but the receiver's ACK
        // timer batches feedback at ~15 ms, so every RTT sample is ~15 ms.
        // The delay signal must read that as feedback latency, not
        // queueing, and stay in slow start (doubling per ACK batch).
        let mut cc = ClassicController::new();
        let mut now = Instant::now();

        cc.on_rtt_update(Duration::from_micros(40));
        let mut cwnd_prev = cc.congestion_window();

        for batch in 1..=6 {
            now += Duration::from_millis(15);
            // Inflate the RTT estimator exactly like a window-limited
            // sender's min-of-batch sample would.
            cc.on_rtt_update(Duration::from_millis(15));
            for i in 0..8 {
                cc.on_packet_sent(batch * 8 + i, MTU, now);
            }
            // Delivery doubles per batch — an unsaturated ramp, so the
            // plateau exit must not fire either.
            cc.on_ack_received(&ack(batch * 8, (8 * MTU << (batch - 1)) as u64, 50_000_000), now);

            assert_eq!(cc.state, State::SlowStart, "batch {batch}: premature exit");
            assert!(cc.congestion_window() > cwnd_prev, "batch {batch}: no growth");
            cwnd_prev = cc.congestion_window();
        }
    }

    #[test]
    fn slow_start_exits_on_real_queueing_despite_ack_gap() {
        // Same 15 ms feedback cadence, but srtt inflates far beyond even
        // the gap-aware baseline: real queueing must still exit slow start.
        let mut cc = ClassicController::new();
        let mut now = Instant::now();

        cc.on_rtt_update(Duration::from_micros(40));
        for batch in 0..4 {
            now += Duration::from_millis(15);
            cc.on_rtt_update(Duration::from_millis(15));
            cc.on_ack_received(&ack(batch, MTU as u64, 1_000_000), now);
        }
        assert_eq!(cc.state, State::SlowStart);

        // Queue builds: srtt climbs beyond even the gap-aware baseline
        // (5 × 15 ms = 75 ms) and stays there — two consecutive inflated
        // batches exit slow start.
        for round in 0..2 {
            now += Duration::from_millis(15);
            for _ in 0..4 {
                cc.on_rtt_update(Duration::from_millis(200));
            }
            cc.on_ack_received(&ack(100 + round, MTU as u64, 1_000_000), now);
        }
        assert_eq!(cc.state, State::CongestionAvoidance);
    }

    #[test]
    fn slow_start_growth_bounded_by_delivery_bdp() {
        // A low delivery-rate estimate must bound slow-start growth at
        // ~3×BDP without ever shrinking the window.
        let mut cc = ClassicController::new();
        let mut now = Instant::now();

        cc.on_rtt_update(Duration::from_millis(10));
        let mut prev = cc.congestion_window();
        for batch in 0..20 {
            now += Duration::from_millis(10);
            cc.on_packet_sent(batch, MTU, now);
            // 1 MB/s delivery rate, 10 ms srtt → cap ≈ 3 × 1e6 × 0.01 = 30 KB.
            // Delivery doubles per batch so the plateau exit stays quiet.
            cc.on_ack_received(&ack(batch, (MTU << batch) as u64, 1_000_000), now);
            assert!(cc.congestion_window() >= prev, "window shrank in slow start");
            prev = cc.congestion_window();
        }
        // Cap binds immediately: the window freezes at its initial value,
        // well below the uncapped INITIAL_CWND + 20×MTU it would reach.
        assert_eq!(cc.congestion_window(), INITIAL_CWND);
    }

    /// Packets per simulated window.
    const WINDOW_PKTS: u64 = 8;

    /// Drives a pipelined sender: one window is always in flight ahead of
    /// the ACKs being processed, which is what makes a packet-number round
    /// exactly one window long. `cwnd_growth` is applied to the controller
    /// between rounds to model the window opening (or not).
    struct RoundDriver {
        next_pkt: u64,
        oldest_unacked: u64,
    }

    impl RoundDriver {
        /// Prime the pipe with one window in flight.
        fn new(cc: &mut ClassicController, now: Instant) -> Self {
            let mut d = RoundDriver { next_pkt: 1, oldest_unacked: 1 };
            d.send_window(cc, now);
            d
        }

        fn send_window(&mut self, cc: &mut ClassicController, now: Instant) {
            for _ in 0..WINDOW_PKTS {
                cc.on_packet_sent(self.next_pkt, MTU, now);
                self.next_pkt += 1;
            }
        }

        /// Close exactly one feedback round delivering `round_bytes`: put
        /// the next window on the wire, then ACK the outstanding one.
        fn round(&mut self, cc: &mut ClassicController, now: &mut Instant, round_bytes: u64) {
            *now += Duration::from_millis(15);
            self.send_window(cc, *now);
            let first = self.oldest_unacked;
            self.oldest_unacked += WINDOW_PKTS;
            for i in 0..WINDOW_PKTS {
                cc.on_ack_received(
                    &ack(first + i, round_bytes / WINDOW_PKTS, 50_000_000),
                    *now,
                );
            }
        }
    }

    #[test]
    fn slow_start_exits_on_delivery_plateau() {
        // BBR-style full-bandwidth exit: while per-round delivery keeps
        // growing the ramp continues; once it stalls for
        // STARTUP_PLATEAU_ROUNDS consecutive rounds the path is saturated
        // and the window settles at the demonstrated per-round delivery.
        let mut cc = ClassicController::new();
        let mut now = Instant::now();

        cc.on_rtt_update(Duration::from_millis(15));
        let mut d = RoundDriver::new(&mut cc, now);

        // Ramp: delivery doubles per round — no plateau.
        for round_bytes in [16 * 1024, 32 * 1024, 64 * 1024] {
            d.round(&mut cc, &mut now, round_bytes);
            assert_eq!(cc.state, State::SlowStart, "ramp: premature plateau exit");
        }

        // Plateau: delivery stuck at 64 KB while the window keeps opening.
        d.round(&mut cc, &mut now, 64 * 1024);
        d.round(&mut cc, &mut now, 64 * 1024);
        assert_eq!(cc.state, State::SlowStart, "exit before third flat round");
        let demonstrated = cc.round_full_bytes;
        d.round(&mut cc, &mut now, 64 * 1024);
        assert_eq!(cc.state, State::CongestionAvoidance, "no exit after third flat round");

        // The window settles at the demonstrated per-round delivery,
        // below the value the unbounded ramp had reached.
        assert_eq!(cc.congestion_window(), demonstrated);
        assert_eq!(cc.ssthresh, demonstrated);
    }

    #[test]
    fn plateau_exit_respects_warmup() {
        // Flat delivery from the very first round: the exit must not fire
        // before STARTUP_MIN_ROUNDS rounds have closed — early estimates
        // are too noisy to end the ramp — and must fire once enough flat
        // rounds have accumulated.
        let mut cc = ClassicController::new();
        let mut now = Instant::now();

        cc.on_rtt_update(Duration::from_millis(15));
        let mut d = RoundDriver::new(&mut cc, now);

        let mut rounds_at_exit = None;
        for _ in 0..12 {
            d.round(&mut cc, &mut now, 32 * 1024);
            if cc.state == State::CongestionAvoidance {
                rounds_at_exit = Some(cc.round_count);
                break;
            }
        }
        let rounds = rounds_at_exit.expect("flat delivery never ended the ramp");
        assert!(
            rounds >= STARTUP_MIN_ROUNDS,
            "exited after {rounds} rounds, before the {STARTUP_MIN_ROUNDS}-round warmup"
        );
    }

    #[test]
    fn plateau_ignored_while_window_is_flat() {
        // The regression that stranded slow start on high-RTT paths: when
        // the window is not growing, flat delivery is a property of the
        // window, not of the path, and must not count as saturation.
        // Here the startup BDP cap pins the window (delivery rate is low),
        // so no number of flat rounds may end the ramp.
        let mut cc = ClassicController::new();
        let mut now = Instant::now();

        cc.on_rtt_update(Duration::from_millis(15));
        let mut d = RoundDriver::new(&mut cc, now);
        let cwnd_before = cc.congestion_window();

        for _ in 0..STARTUP_PLATEAU_ROUNDS as usize * 4 {
            // A 1 MB/s delivery-rate estimate with 15 ms srtt caps the
            // window at ~45 KB, well under INITIAL_CWND: it cannot grow.
            now += Duration::from_millis(15);
            d.send_window(&mut cc, now);
            let first = d.oldest_unacked;
            d.oldest_unacked += WINDOW_PKTS;
            for i in 0..WINDOW_PKTS {
                cc.on_ack_received(&ack(first + i, 8 * 1024 / WINDOW_PKTS, 1_000_000), now);
            }
        }

        assert_eq!(cc.congestion_window(), cwnd_before, "window should be pinned by the cap");
        assert_eq!(cc.plateau_rounds, 0, "flat window must not accumulate strikes");
        assert_eq!(cc.state, State::SlowStart, "ramp ended on a window-limited plateau");
    }

    #[test]
    fn loss_caps_target_at_demonstrated_delivery() {
        // While delivery is stalled below the window (plateau strikes
        // active), the loss target must drop to the demonstrated
        // per-round delivery, not just 12.5% below the overgrown window.
        let mut cc = ClassicController::new();
        let mut now = Instant::now();

        cc.on_rtt_update(Duration::from_millis(15));
        let mut d = RoundDriver::new(&mut cc, now);
        for _ in 0..3 {
            d.round(&mut cc, &mut now, 64 * 1024);
        }
        assert!(cc.plateau_rounds > 0);
        assert!(cc.congestion_window() > 64 * 1024);

        // The gate now requires STARTUP_PLATEAU_ROUNDS strikes, which the
        // plateau *exit* also requires — so strikes alone can no longer
        // admit a loss before the ramp has already ended. Open the gate
        // via queueing instead: that is the reachable path on which the
        // cap still has to behave.
        build_queue(&mut cc);

        // The cut lands on the demonstrated per-round delivery, not on
        // the plain 12.5% below the overgrown window.
        let demonstrated = cc.round_full_bytes;
        assert!(demonstrated < cc.congestion_window());
        cc.on_packet_lost(&[1, 2, 3], now + Duration::from_millis(1));
        assert_eq!(cc.congestion_window(), demonstrated);
        assert_eq!(cc.state, State::CongestionAvoidance);
    }

    #[test]
    fn random_loss_without_congestion_leaves_window_alone() {
        // The degraded/satellite case: a steady drop rate with no queue
        // building and no delivery plateau. Cutting on each report is what
        // collapses loss-based CC on such links, so the window must hold.
        let mut cc = ClassicController::new();
        let now = Instant::now();

        // Flat RTT: min_rtt == srtt, so no queueing signal.
        for _ in 0..20 {
            cc.on_rtt_update(Duration::from_millis(150));
        }
        for i in 1..=64 {
            cc.on_packet_sent(i, MTU, now);
        }
        let cwnd_before = cc.congestion_window();
        assert_eq!(cc.plateau_rounds, 0);

        // Repeated significant loss, each in its own epoch.
        for round in 0..5u64 {
            let base = 1 + round * 10;
            cc.on_packet_lost(&[base, base + 1, base + 2], now);
            for i in 0..10 {
                cc.on_packet_sent(65 + round * 10 + i, MTU, now);
            }
        }

        assert_eq!(
            cc.congestion_window(),
            cwnd_before,
            "random loss must not shrink the window"
        );
        assert_eq!(cc.state, State::SlowStart, "random loss ended the ramp");
    }

    #[test]
    fn queueing_turns_the_same_loss_into_a_cut() {
        // Counterpart to the test above: identical loss reports, but with
        // srtt inflated over the baseline, must cut. Otherwise the gate
        // would have simply disabled loss response.
        let mut cc = ClassicController::new();
        let now = Instant::now();

        for i in 1..=64 {
            cc.on_packet_sent(i, MTU, now);
        }
        build_queue(&mut cc);
        let cwnd_before = cc.congestion_window();

        cc.on_packet_lost(&[1, 2, 3], now);
        assert!(
            cc.congestion_window() < cwnd_before,
            "queueing loss must shrink the window"
        );
        assert_eq!(cc.state, State::CongestionAvoidance);
    }

    #[test]
    fn startup_evidence_is_cleared_on_leaving_slow_start() {
        // `round_full_bytes` is a running maximum and `plateau_rounds` only
        // accrues in slow start. Carrying either into congestion avoidance
        // would let one early extreme govern every later congestion epoch
        // through the loss cap.
        let mut cc = ClassicController::new();
        let mut now = Instant::now();

        cc.on_rtt_update(Duration::from_millis(15));
        let mut d = RoundDriver::new(&mut cc, now);
        for _ in 0..12 {
            d.round(&mut cc, &mut now, 64 * 1024);
            if cc.state == State::CongestionAvoidance {
                break;
            }
        }
        assert_eq!(cc.state, State::CongestionAvoidance, "ramp never ended");
        assert_eq!(cc.plateau_rounds, 0, "stale plateau strikes survived the exit");
        assert_eq!(cc.round_full_bytes, 0, "stale delivery maximum survived the exit");

        // A later congestion epoch therefore takes the plain 12.5% cut,
        // not one bounded by a number measured during startup.
        build_queue(&mut cc);
        let cwnd_before = cc.congestion_window();
        for i in 0..64 {
            cc.on_packet_sent(10_000 + i, MTU, now);
        }
        cc.on_packet_lost(&[10_000, 10_001, 10_002], now);
        let expected = ((cwnd_before as f64) * LOSS_DECREASE_FACTOR) as usize;
        assert_eq!(cc.congestion_window(), expected.max(MIN_CWND));
    }

    /// Both exits from slow start must settle at the same place.
    ///
    /// Classic was bimodal because they did not. The plateau exit settles
    /// at `round_full_bytes.min(cwnd)` -- the demonstrated per-round
    /// delivery -- while the loss exit took a fraction of whatever the
    /// window had reached. Which fires is a race between the plateau
    /// counter and the first congestion-classified loss, and since slow
    /// start doubles every round, losing that race by one round doubled
    /// the window the transfer then ran at.
    ///
    /// Measured, same binary, six consecutive runs of one cell: five
    /// settled at 400-546 KB against a 312 KB BDP and retransmitted
    /// 0.67-2.34%; the sixth settled at 1364 KB and retransmitted 33.56%.
    #[test]
    fn slow_start_loss_exit_settles_near_demonstrated_delivery() {
        let mut cc = ClassicController::new();
        let mut now = Instant::now();
        cc.on_rtt_update(Duration::from_millis(25));

        // Ramp until delivery saturates: rounds stop growing because the
        // path is at capacity, which is what a real overshoot looks like.
        let mut d = RoundDriver::new(&mut cc, now);
        for round_bytes in [64 * 1024, 128 * 1024, 256 * 1024, 256 * 1024] {
            d.round(&mut cc, &mut now, round_bytes);
        }
        assert_eq!(cc.state, State::SlowStart, "test premise: still ramping");

        let demonstrated = cc.round_full_bytes;
        build_queue(&mut cc);
        cc.on_packet_lost(&[1, 2, 3], now + Duration::from_millis(1));

        assert_eq!(cc.state, State::CongestionAvoidance);
        assert!(
            cc.congestion_window() <= demonstrated.max(MIN_CWND),
            "settled at {} against demonstrated delivery {} — the loss exit \
             is not agreeing with the plateau exit",
            cc.congestion_window(),
            demonstrated
        );
    }

    #[test]
    fn loss_cap_inactive_while_delivery_grows() {
        // On a healthy ramp the last closed round holds the previous
        // (half-size) window — that is growth, not saturation, so the
        // demonstrated-delivery cap must stay out of the way and the
        // loss target is the plain 12.5% cut.
        let mut cc = ClassicController::new();
        let mut now = Instant::now();

        cc.on_rtt_update(Duration::from_millis(15));
        let mut d = RoundDriver::new(&mut cc, now);
        for round_bytes in [16 * 1024, 32 * 1024, 64 * 1024] {
            d.round(&mut cc, &mut now, round_bytes);
        }
        assert_eq!(cc.plateau_rounds, 0);

        build_queue(&mut cc);
        let cwnd_before = cc.congestion_window();
        cc.on_packet_lost(&[1, 2, 3], now + Duration::from_millis(1));
        let expected = ((cwnd_before as f64) * LOSS_DECREASE_FACTOR) as usize;
        assert_eq!(cc.congestion_window(), expected);
    }

    #[test]
    fn loss_cap_noop_when_delivery_matches_window() {
        // Stalled delivery that matches the window (lossy WAN steady
        // state): the demonstrated-delivery cap must not deepen the 12.5%
        // cut. In congestion avoidance the window only creeps up
        // additively, so no round sees the 1.25x growth that would let a
        // flat-delivery round count as saturation — the cap stays unarmed.
        let mut cc = ClassicController::new();
        let mut now = Instant::now();

        cc.on_rtt_update(Duration::from_millis(15));
        cc.state = State::CongestionAvoidance;
        cc.cwnd = 1_000_000;
        let mut d = RoundDriver::new(&mut cc, now);
        d.round(&mut cc, &mut now, 1_000_000);
        d.round(&mut cc, &mut now, 1_000_000);
        assert_eq!(cc.plateau_rounds, 0, "flat window must not arm the cap");

        build_queue(&mut cc);
        let cwnd_before = cc.congestion_window();
        cc.on_packet_lost(&[1, 2, 3], now + Duration::from_millis(1));
        let expected = ((cwnd_before as f64) * LOSS_DECREASE_FACTOR) as usize;
        assert_eq!(cc.congestion_window(), expected);
    }

    #[test]
    fn ack_gap_ewma_ignores_intra_burst_gaps() {
        // Per-stream ACK datagrams arrive back-to-back; sub-floor gaps must
        // not dilute the cadence estimate.
        let mut cc = ClassicController::new();
        let now = Instant::now();

        cc.on_rtt_update(Duration::from_millis(1));
        cc.on_ack_received(&ack(0, MTU as u64, 1_000_000), now);
        // First batch at +15 ms, then three intra-burst datagrams.
        cc.on_ack_received(&ack(1, MTU as u64, 1_000_000), now + Duration::from_millis(15));
        for i in 2..5 {
            cc.on_ack_received(
                &ack(i, MTU as u64, 1_000_000),
                now + Duration::from_millis(15) + Duration::from_micros(50 * i),
            );
        }
        assert_eq!(cc.ack_gap_ewma, Duration::from_millis(15));
        // Next batch another 15 ms later: EWMA stays at 15 ms.
        cc.on_ack_received(&ack(5, MTU as u64, 1_000_000), now + Duration::from_millis(30));
        assert_eq!(cc.ack_gap_ewma, Duration::from_millis(15));
    }
}

#[cfg(test)]
mod overshoot_regression {
    use super::*;

    /// Regression for the congestion-avoidance overshoot measured on the
    /// 100ms/5% path: the window ran to 18x the BDP (~40 MB against a
    /// ~2.2 MB BDP) and retransmitted 27% of everything it sent.
    ///
    /// The cause was that both branches of `loss_indicates_congestion`
    /// were unreachable once slow start ended. Plateau strikes only
    /// accrue in slow start and are cleared on exit, so `plateau_rounds`
    /// is pinned at 0; and the queueing branch needed srtt/min_rtt above
    /// 1.5 when the measured ratio on that path was 1.44 — and only 1.21
    /// on the 150ms path. Classic therefore had no loss response at all
    /// in congestion avoidance.
    ///
    /// Delay could not have detected this: with no bottleneck to queue at,
    /// an overshooting window is dropped rather than buffered, so RTT
    /// never inflates however far the window runs. That is why the fix is
    /// a window-vs-BDP test rather than a lower delay threshold.
    #[test]
    fn overshooting_window_is_treated_as_congestion() {
        let mut cc = ClassicController::new();
        let now = Instant::now();

        // The measured *satellite* profile: min_rtt 125.5ms, srtt ~152ms,
        // ratio ~1.23. The degraded profile (1.44) no longer works here —
        // the queueing branch must stay shut here, or this would stop
        // exercising the BDP branch it was written for.
        // Satellite stays under the threshold and still overshot 18x, which
        // is exactly why a delay-only fix was not sufficient.
        cc.on_rtt_update(Duration::from_micros(125_500));
        for _ in 0..40 {
            cc.on_rtt_update(Duration::from_micros(152_000));
        }
        assert!(
            cc.congestion_evidence() != Some("queueing"),
            "the queueing branch opened on its own — this test no longer \
             exercises the BDP branch it was written for"
        );

        cc.state = State::CongestionAvoidance;
        cc.reset_startup_evidence();
        assert_eq!(cc.plateau_rounds, 0);

        // ~29 MB/s delivered over a 125.5ms min RTT => BDP ~3.6 MB.
        cc.bw_estimate = 29 * 1024 * 1024;
        cc.cwnd = 40 * 1024 * 1024; // the 18x-BDP window actually observed

        assert!(
            cc.loss_indicates_congestion(),
            "an 18x-BDP window must read as congestion"
        );

        let before = cc.cwnd;
        for i in 100..164 {
            cc.on_packet_sent(i, MTU, now);
        }
        cc.on_packet_lost(&[100, 101, 102], now);
        assert!(cc.cwnd < before, "loss did not reach the window");
    }

    /// The converse: a window sized at the BDP on a genuinely lossy but
    /// uncongested path must NOT be cut. This is the property the gate
    /// exists to protect — backing off on random loss is what collapses
    /// loss-based CC on satellite links.
    #[test]
    fn random_loss_at_correct_window_size_is_still_ignored() {
        let mut cc = ClassicController::new();
        let now = Instant::now();
        for _ in 0..40 {
            cc.on_rtt_update(Duration::from_millis(150));
        }
        cc.state = State::CongestionAvoidance;
        cc.reset_startup_evidence();

        // Window sitting right at the BDP: 20 MB/s x 150ms = 3 MB.
        cc.bw_estimate = 20 * 1024 * 1024;
        cc.cwnd = 3 * 1024 * 1024;
        assert!(!cc.loss_indicates_congestion(), "well-sized window flagged");

        let before = cc.cwnd;
        for round in 0..10u64 {
            for i in 0..64 {
                cc.on_packet_sent(1000 + round * 64 + i, MTU, now);
            }
            cc.on_packet_lost(&[1000 + round * 64, 1001 + round * 64, 1002 + round * 64], now);
        }
        assert_eq!(cc.cwnd, before, "random loss shrank a correctly-sized window");
    }

    /// The epoch guard used 0 as "no decrease yet", but 0 is a real chunk
    /// index, so the first loss report of every transfer was swallowed.
    #[test]
    fn first_loss_of_a_transfer_is_not_swallowed() {
        let mut cc = ClassicController::new();
        let now = Instant::now();
        for _ in 0..20 {
            cc.on_rtt_update(Duration::from_millis(100));
        }
        cc.state = State::CongestionAvoidance;
        cc.bw_estimate = 1024 * 1024;
        cc.cwnd = 8 * 1024 * 1024; // well past BDP so the gate is open
        assert_eq!(cc.last_dec_seq, None);

        let before = cc.cwnd;
        for i in 0..64 {
            cc.on_packet_sent(i, MTU, now);
        }
        // Loss report starting at chunk 0 — previously ignored outright.
        cc.on_packet_lost(&[0, 1, 2], now);
        assert!(cc.cwnd < before, "loss at chunk 0 was swallowed by the epoch guard");
        assert!(cc.last_dec_seq.is_some());
    }
}
