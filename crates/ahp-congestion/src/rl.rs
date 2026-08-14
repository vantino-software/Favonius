// Favonius — high-performance file transfer over UDP
// Copyright (c) 2025-2026 Vantino SàRL
// SPDX-License-Identifier: Apache-2.0

//! AHP-RL: Reinforcement-learning congestion controller.
//!
//! Uses a small MLP (8→32→16→1) to map live path metrics to a rate
//! multiplier, enabling learned, adaptive rate control. When no model
//! is loaded, falls back to UDT-style rate-based control.
//!
//! Two modes:
//! - **Exploit**: loads a trained model from disk, runs pure inference.
//! - **Explore**: records (state, action, reward) traces for offline
//!   training with epsilon-greedy exploration.
//!
//! Configuration via environment variables:
//! - `FAVONIUS_RL_MODEL` — path to binary weights file
//! - `FAVONIUS_RL_EXPLORE` — set to `1` to enable explore mode
//! - `FAVONIUS_RL_EPSILON` — epsilon-greedy probability (default: 0.1)
//! - `FAVONIUS_RL_TRACE_DIR` — directory for trace output

use std::fs;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use crate::metrics::RttEstimator;
use crate::pacer::Pacer;
use crate::{AckInfo, CongestionController};

// ── Constants ────────────────────────────────────────────────────────────────

/// MLP architecture.
const INPUT_DIM: usize = 8;
const HIDDEN1_DIM: usize = 32;
const HIDDEN2_DIM: usize = 16;
const OUTPUT_DIM: usize = 1;

/// Total weight count: 8*32 + 32 + 32*16 + 16 + 16*1 + 1 = 833.
const TOTAL_WEIGHTS: usize =
    INPUT_DIM * HIDDEN1_DIM + HIDDEN1_DIM +
    HIDDEN1_DIM * HIDDEN2_DIM + HIDDEN2_DIM +
    HIDDEN2_DIM * OUTPUT_DIM + OUTPUT_DIM;

/// Magic header for the binary weight file.
///
/// Bumped 001 -> 002 when the action changed meaning. The file layout is
/// identical — same 833 f64 weights for the same 8->32->16->1 network — so
/// an AHPRL001 file loads cleanly under the new semantics and means
/// something entirely different: it was trained to emit a compounding
/// multiplier on the current rate in [0.5, 2.0] and is now read as a gain
/// on measured delivery in [0.90, 1.15].
///
/// That mismatch was measured, not hypothesised. Running the shipped v2
/// weights against the new controller on a 150 ms path gave a 16.5 MB
/// window against a 1.875 MB BDP, RTT inflated from 150 to 303 ms, and a
/// 53% retransmit rate — while loading without a word of complaint and
/// looking like a working configuration.
///
/// The magic is the only thing that can catch this, because nothing about
/// the weights themselves records what their output was supposed to mean.
/// A rejected file falls back to UDT-style rate control, which is a known
/// and bounded behaviour; a silently misinterpreted one is not.
const WEIGHT_MAGIC: &[u8; 8] = b"AHPRL002";

/// Rate control interval (same as UDT).
const SYN_INTERVAL: Duration = Duration::from_millis(5);

/// How far above the measured delivery rate the learned policy may push.
///
/// Probing above what has been delivered is how a controller discovers
/// capacity, so this is deliberately loose — it exists only to stop the
/// compounding multiplier running away, not to steer. 2x mirrors the
/// bound Classic applies to its window.
///
/// Since the action became a gain on the delivery rate this is redundant
/// on the main path — a gain of at most ACTION_MAX on the delivery rate is
/// itself the same bound — and it applies only to the fallback taken
/// before any delivery estimate exists.
const RATE_PROBE_CEILING: f64 = 2.0;

/// Multiple of the bandwidth-delay product the congestion window is
/// allowed to reach.
///
/// The window is a bound, not the operating point — the pacing rate is
/// what controls the send rate here. 4x, inherited from UDT v3, is three
/// BDPs of standing queue on a link buffered at one BDP, i.e. a full
/// buffer by construction. 2x matches classic.rs and BBR's steady-state
/// cwnd_gain.
///
/// **2.0 was measured and is not the best value.** Once the `max_cwnd`
/// ceiling was made a genuine backstop (measured), this gain became the
/// operating point, and it had never been swept. Swept at 1 Gbit, 1 GB,
/// n=3:
///
/// **RETRACTED (2026-08-09).** This was briefly 1.5, on a sweep that
/// reported 1.25/1.5/2.0 as 66.6/69.5/63.5 MB/s on satellite with
/// retransmits of 10.8%/8.4%/19.0% — a clean Pareto win for 1.5.
///
/// That sweep set `FAVONIUS_RL_CWND_GAIN`, and the benchmark harness passed
/// an explicit env whitelist to `docker exec` which did not include it. All
/// three arms therefore ran at 2.0, and the "effect" was run-to-run spread
/// on a controller whose cv is around 10%. Reverted to the value that was
/// actually measured in every table in this crate.
///
/// The harness now forwards every `FAVONIUS_*` variable and logs what it
/// forwarded (`env -> container:`). Check for that line before believing a
/// sweep.
///
/// Swept at n=8, 1 Gbit, on a rig verified stable by two 20-run studies an
/// hour apart (self-infl = retransmits above the path's own injected-loss
/// floor):
///
/// | gain | satellite | cv   | degraded | cv   | self-infl     |
/// |------|-----------|------|----------|------|---------------|
/// | 1.25 | **68.6**  | 9.1% | **78.9** | 4.0% | **7.2/3.8pp** |
/// | 1.5  | 67.2      | 5.0% | 76.2     | 3.5% | 8.1/10.1pp    |
/// | 1.75 | 66.0      | 5.5% | 74.2     | 6.3% | 15.3/15.9pp   |
/// | 2.0  | 63.5      | 7.7% | 74.6     | 6.5% | 17.1/18.2pp   |
///
/// **1.25 is best on both axes on both paths** — fastest and least
/// wasteful — monotone throughout, at spreads small enough to resolve it.
///
/// An earlier sweep of the same four values reported this as non-monotone
/// with cv up to 32%, and concluded that goodput could not select a value
/// and 1.25 had to be chosen on waste alone. That sweep ran during a
/// session which also measures 45.9 MB/s on the cell three later batches
/// put at 65.7-66.8 — the instrument was unstable, not the controller.
/// The conclusion happened to be right and the reasoning behind it was an
/// artefact.
///
/// `coexist.sh` (n=3, `clean`) shows `rl` is polite at every gain, leaving
/// a competing TCP flow 0.65-0.77 of its solo throughput against a 0.35
/// bar — more considerate than the other profiles.
const CWND_BDP_GAIN: f64 = 1.25;

/// Sweep override for `CWND_BDP_GAIN`, read once at construction.
///
/// Entry 29 ended by showing that the `max_cwnd` ceiling cannot be the loss
/// control — at 2.5x measured BDP it never binds, so the operating point is
/// this gain, and at 2.0 that means 15.8% retransmits on satellite. `udt`,
/// whose gain is 1.25, took the same ceiling change at unchanged
/// retransmits. The constant has never been swept, and it is now the
/// binding decision, so it is made settable rather than requiring a rebuild
/// per value.
///
/// This is a measurement instrument. It is read once in `new()`, it is not
/// documented as a user-facing knob, and the default is the constant.
fn cwnd_bdp_gain_from_env() -> f64 {
    std::env::var("FAVONIUS_RL_CWND_GAIN")
        .ok()
        .and_then(|v| v.parse::<f64>().ok())
        .filter(|g| *g >= 1.0 && *g <= 4.0)
        .unwrap_or(CWND_BDP_GAIN)
}

/// Multiple of the *measured* BDP that `max_cwnd` may ratchet up to.
///
/// This replaced a bare `4096.0`. That constant was 5.73 MB at this MTU,
/// applied identically on every path, every rate-control interval — and it
/// was the binding limit on all of them. Measured at 1 Gbit as an A/B
/// against 65536 (measured): arm A's peak cwnd
/// was 5656 KB on all four scenarios, one number across four different
/// bandwidth-delay products, and lifting it moved satellite +161% and
/// degraded +120%.
///
/// A larger constant is not the answer. 65536 let the window reach 3.1x
/// BDP on satellite, which bought the throughput with 70 ms of standing
/// queue and an 11.3% retransmit share against arm A's 2.1%. The bound has
/// to scale with the path, which is what Classic — the one controller here
/// with no fixed-count cap, and the one holding all four paths — already
/// does.
///
/// **This multiplier has a hard lower bound, and it is not a tuning
/// preference.** It was first set to 1.25, on the reasoning that a quarter
/// BDP of standing queue is a reasonable allowance. That froze the window
/// at its initial 1024 packets for entire transfers and cost cross-country
/// 94.3 -> 28.2 MiB/s at 1 Gbit.
///
/// The reason is a units mismatch that is easy to miss. `btlbw x min_rtt`
/// is what the path delivers in one *minimum* round trip, but the window
/// in flight drains at the *actual* round trip. So the measured BDP is
/// always smaller than the window sustaining it, by exactly the RTT
/// inflation ratio. If this multiplier is below that ratio, the ceiling
/// sits permanently underneath the window, `max_cwnd < ceiling` is never
/// true, and the ratchet cannot fire — the window freezes at whatever
/// value it held when the ceiling first passed below it.
///
/// Measured directly (`FAVONIUS_CC_DEBUG`, cross-country, 1 Gbit):
/// `cwnd=1024pkt max_cwnd=1024pkt btlbw=290Mbit rcv_rate=246Mbit`,
/// unchanged for the whole transfer. 290 Mbit over a 25 ms min_rtt is 755
/// packets; 1.25 x 755 = 944, below the 1024 already held. These
/// controllers run at an inflation of about 1.3-1.4x, so anything under
/// ~1.5 is a trap.
///
/// 2.5 clears it with margin and leaves the ceiling a genuine backstop
/// above `CWND_BDP_GAIN` rather than the operating point. The consequence
/// is that the operating point is the gain, so the throughput/loss
/// trade-off is `CWND_BDP_GAIN`'s to make and not this constant's — a
/// window bound cannot serve as loss control, which is what the 1.25
/// attempt was really trying to do.
const MAX_CWND_BDP_MULT: f64 = 2.5;

/// Floor for the `max_cwnd` ceiling, in packets.
///
/// `btlbw` is zero until the first delivery sample, so without a floor the
/// ceiling would be zero and the window could never open at all. This is
/// the historical initial `max_cwnd`.
const MAX_CWND_FLOOR_PKTS: f64 = 1024.0;

/// Absolute backstop on `max_cwnd`, in packets — ~91 MB at this MTU.
///
/// Not a control parameter. It exists so that a pathological `btlbw`
/// over-estimate cannot translate into unbounded memory pressure.
const MAX_CWND_HARD_PKTS: f64 = 65536.0;


/// Gain applied to the windowed-max delivery estimate when no learned
/// policy is loaded.
///
/// **This is not the shipped controller, and it is not reached in the
/// shipped configuration.** `update_rate` routes `weights.is_none() &&
/// mode == Exploit` to `advance_cycle()`, so `get_action`'s constant arm --
/// the only place this value or `FAVONIUS_RL_GAIN` is read -- is
/// unreachable except from a unit test. What runs with no weights is the
/// gain cycle (`CYCLE_*`), whose time-weighted mean gain is 1.0.
///
/// The value is kept because it is the constant the trainer's gate uses as
/// one point on its baseline grid, and because a policy loaded into
/// `get_action` still needs a defined fallback. It is not what a user gets.
///
/// An earlier version of this comment called it "the controller, not a
/// stopgap", and a panel review on 2026-08-07 found that claim had
/// propagated into CLAUDE.md, the CC research notes and a day of rig
/// measurements -- including an A/B of two gains that measured the same
/// controller twice, because the knob under test does nothing.
///
/// The comparison below is real and was measured in the closed-loop
/// trainer, where the gain *is* the action, across eight scenarios: a
/// single constant against a 400k-timestep 833-parameter network.
///
/// ```text
///                     mean    worst
///  trained network   21.3%     0.1%
///  constant 1.075    30.2%     8.5%
/// ```
///
/// The network wins four scenarios and loses four, but where it loses it
/// loses the transfer: 0.1% on satellite against 22.1%. The criterion for a
/// controller is worst case.
///
/// Note the `(g-1)/g` reasoning that used to close this comment does not
/// apply to the shipped path: the cycle offers exactly capacity on average
/// (2x1.25 + 2x0.75 + 4x1.00 over 8 RTTs), so it has no permanent overload,
/// and its measured induced loss is within noise of zero. See
/// the CC research notes.
const DEFAULT_GAIN: f64 = 1.075;

/// Packets per round trip the sender will always be allowed to pace, no
/// matter what the policy asks for.
///
/// The rate is now a gain on the measured delivery rate, which removes the
/// compounding excursion that first motivated this floor — but not the
/// absorbing state, which is why the floor stays. `rate <- g * delivered`
/// has a fixed point at zero: if delivery ever reaches nearly nothing, any
/// gain times nearly nothing is still nearly nothing. Rate control runs
/// only on ACK arrival, so once the rate is too low to keep ACKs coming
/// there are no more decisions and no way out, and the transfer hangs until
/// the sender's 30 s stall detector fires.
///
/// (Under the old compounding multiplier the same state was reached far
/// more easily: a policy averaging even slightly below 1.0 drove the rate to
/// the `max(1.0, ..)` floor of one byte per second within about 100 ms, before
/// a single ACK of the opening burst had returned.)
///
/// A floor of a few packets per RTT keeps data moving, which keeps ACKs
/// arriving, which keeps the controller live. It bounds the damage a bad
/// policy can do rather than making a bad policy good.
const MIN_PACED_PKTS_PER_RTT: f64 = 8.0;

/// Default MTU.
const MTU: usize = 1200;

/// MSS for AHP wire packets.
const MSS: usize = 1414;

/// Initial congestion window in packets.
const INITIAL_CWND_PKTS: f64 = 16.0;

/// Loss decrease factor (same gentle response as UDT/Classic v3).
const LOSS_INCREASE_FACTOR: f64 = 1.125;

/// Ratio of smoothed to minimum RTT above which loss is treated as a
/// congestion signal rather than the path's own.
///
/// Below this the queue is judged empty, so a drop is far likelier to be
/// the link's random loss than evidence the controller is overdriving —
/// and `rate <- gain * btlbw` already backs off on real congestion by
/// construction, because congestion is what stops delivery from rising.
///
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

/// Upper bound on the exogenous-loss compensation factor.
///
/// 1.15 covers a path losing ~13% of packets to something other than
/// congestion. Beyond that the assumption behind the compensation — that
/// the loss is the link's and sending harder gets more through — stops
/// being a safe thing to believe, so the controller stops acting on it.
const LOSS_COMP_MAX: f64 = 1.15;

/// EWMA weight for moving the compensation factor toward its target.
///
/// Deliberately slow. The factor multiplies the send rate, so letting it
/// track a noisy per-interval loss estimate directly would put jitter
/// straight onto the wire.
const LOSS_COMP_ALPHA: f64 = 0.125;

/// Pacing gain while probing for more bandwidth.
/// Round trips each delivery-rate sample is averaged over.
///
/// `btlbw` is a maximum over these samples, and the maximum of a noisy
/// estimator is biased upward: the noisier the samples, the further above
/// the truth the maximum sits. Measured at one RTT per sample on a 100
/// Mbit link, `btlbw` read a mean of 104.72 Mbit and a maximum of 112.74 --
/// a 4.7% overestimate of capacity. The gain cycle averages to 1.0, so the
/// controller commanded 4.7% more than the path could carry, permanently,
/// which is exactly the `rate <- g * capacity` equilibrium that fills a
/// BDP-sized queue and holds it there.
///
/// Averaging each sample over more round trips reduces its variance and so
/// reduces the maximum's bias. The cost is that the estimate reacts more
/// slowly to a genuine capacity change, and on a long path that costs
/// throughput. Measured across all four impaired scenarios, 5 runs each:
///
///   window   btlbw bias   transatlantic   satellite   degraded
///   1 RTT       +4.7%      1.44x 10.03    9.03 MB/s   9.63 MB/s
///   2 RTT       +2.7%      1.25x 10.06    8.08        9.20
///   3 RTT       +2.2%      1.24x 10.18    6.90        8.24
///
/// Two is the choice: three buys 0.01x of delay and costs 15% of
/// satellite's goodput, which fails A1's utilisation leg outright.
const DELIVERY_WINDOW_RTTS: u64 = 2;

const CYCLE_PROBE_GAIN: f64 = 1.25;
/// Pacing gain while draining the queue the probe just built.
const CYCLE_DRAIN_GAIN: f64 = 0.75;
/// Pacing gain while cruising: hold at the measured delivery rate.
const CYCLE_CRUISE_GAIN: f64 = 1.0;

/// Nominal probe length, in min-RTTs.
///
/// Two, not one, because of how delivery is sampled. A sample spans at
/// least half a round trip, so with a one-RTT probe followed straight by a
/// one-RTT drain every sample window straddled both phases and averaged
/// (1.25 + 0.75) / 2 = 1.0. The bandwidth filter therefore never saw a
/// clean probe-rate sample, `btlbw` never ratcheted, and cruise parked at
/// whatever rate it started from: measured on transatlantic, the
/// controller sat at 15 Mbit of a 100 Mbit link for the whole transfer,
/// oscillating 11.5 <-> 15.9 as the cycle turned beneath it. A two-RTT
/// probe leaves room for one whole sample inside the probe.
const CYCLE_PROBE_RTTS: f64 = 2.0;

/// Minimum drain length. A two-RTT probe at 1.25 puts ~0.5 BDP in the
/// queue, which two RTTs at 0.75 remove exactly.
const CYCLE_DRAIN_RTTS: f64 = 2.0;
/// Hard bound on the drain, so a path that never reports itself drained
/// cannot stall the cycle.
///
/// This is what keeps the cycle inside the bandwidth filter's horizon. The
/// filter holds the delivery maximum over `10 * srtt` and the capacity
/// sample it latches during a probe has to survive until the next one, so
/// the cycle must stay shorter than the horizon: 1 + 2 + 6 = 9 at worst
/// against 10, since `srtt >= min_rtt` always.
const CYCLE_DRAIN_MAX_RTTS: f64 = 3.0;
/// Cruise length, in min-RTTs. Gives an 8-RTT nominal cycle whose mean
/// gain is (2 x 1.25 + 2 x 0.75 + 4 x 1.0) / 8 = 1.0 — no standing
/// overdrive, which is the whole point of cycling rather than picking a
/// constant.
const CYCLE_CRUISE_RTTS: f64 = 4.0;

/// Gain applied while the bottleneck estimate is still climbing.
///
/// This controller had no equivalent of BBR's Startup. Its estimate could
/// only rise through the cycle's probe phase, which is 1.25x for 2 RTTs
/// out of every 8 -- so `btlbw` ratchets by about x1.21 per *cycle*, and a
/// cycle is 8 round trips. On a 150 ms path that is 1.2 s per 25% step.
///
/// Measured on satellite: btlbw climbed 42.04 -> 50.26 -> 60.65 -> 73.40
/// -> 86.16 -> 98.15 Mbit, a visible staircase reaching capacity at about
/// 9 s, while Classic was there at 5.6 s. Classic's recovery is geometric
/// in the *round trip* (`cwnd/16` per RTT while its queue-empty gate
/// holds), so its clock is the RTT and this controller's was the cycle
/// period. On a long path the cycle is much the slower clock, and the
/// difference was 32% of goodput on a 128 MB transfer.
///
/// 1.5 rather than BBR's 2.0: the action range this controller is bounded
/// to is [0.90, 1.15] and the cycle already probes at 1.25, so 1.5 is a
/// meaningful step up without being a different controller. It applies
/// only while the queue is demonstrably empty, so the cost of being wrong
/// is one round trip of queueing, which the drain then removes.
const RAMP_GAIN: f64 = 1.5;

/// Growth below this over one round trip counts as no growth.
const RAMP_PLATEAU_RATIO: f64 = 1.05;

/// Consecutive non-growing round trips before the ramp gives up and the
/// ordinary cycle takes over. Three matches Model's `STARTUP_FULL_BW_ROUNDS`
/// and BBR's plateau rule.
const RAMP_PLATEAU_ROUNDS: u32 = 3;

/// srtt/min_rtt at or below which the queue counts as drained.
const CYCLE_DRAINED_RATIO: f64 = 1.05;

/// A policy over the gain cycle's own parameters, selected by context.
///
/// **This is what "RL" in `--congestion rl` is being made to mean.** The
/// previous attempt learned `rate <- action x btlbw`, a rate law reachable
/// only through `get_action` and therefore not the shipped controller, in
/// an offline environment that disagreed with the rig by four to eight
/// times. Both are retired. This learns the *cycle's* parameters instead,
/// leaves every shipped mechanism in place — ramp, queue gate, BDP
/// ceiling, delivery clamp, loss response — and is trained on the rig.
///
/// Six arms: probe gain {1.10, 1.25, 1.50} x probe length {2, 4} RTTs.
/// Six contexts: min_rtt {<40ms, 40-100ms, >100ms} x loss {<1%, >=1%}.
/// Small enough that a bandit can visit every cell in a few hundred
/// transfers, which is the only sample budget the rig can honestly supply.
///
/// With no policy loaded every context returns the shipped constants, so
/// the default build is byte-for-byte the controller measured in
/// the engineering log.
#[derive(Debug, Clone, Copy)]
pub struct CycleArm {
    pub probe_gain: f64,
    pub probe_rtts: f64,
}

/// The arms, in table order. Index is what a policy file stores.
pub const CYCLE_ARMS: [CycleArm; 6] = [
    CycleArm { probe_gain: 1.10, probe_rtts: 2.0 },
    // The shipped default, defined *from* the constants rather than
    // duplicating their values, so the two cannot drift apart.
    CycleArm { probe_gain: CYCLE_PROBE_GAIN, probe_rtts: CYCLE_PROBE_RTTS },
    CycleArm { probe_gain: 1.50, probe_rtts: 2.0 },
    CycleArm { probe_gain: 1.10, probe_rtts: 4.0 },
    CycleArm { probe_gain: 1.25, probe_rtts: 4.0 },
    CycleArm { probe_gain: 1.50, probe_rtts: 4.0 },
];

/// Index of the arm that reproduces the shipped constants exactly.
pub const CYCLE_ARM_DEFAULT: usize = 1;

/// Number of context buckets: 3 RTT bands x 2 loss bands.
pub const CYCLE_CONTEXTS: usize = 6;

/// Bucket the observable path into a context index.
///
/// Deliberately coarse. A finer context would need more samples per cell
/// than the rig can produce in a session, and an under-sampled bandit cell
/// is indistinguishable from a real preference — the failure this whole
/// investigation keeps meeting.
pub fn cycle_context(min_rtt: Duration, loss_rate: f64) -> usize {
    let rtt_band = if min_rtt < Duration::from_millis(40) {
        0
    } else if min_rtt <= Duration::from_millis(100) {
        1
    } else {
        2
    };
    let loss_band = usize::from(loss_rate >= 0.01);
    rtt_band * 2 + loss_band
}

/// A loaded policy: one arm index per context. `None` means "use the
/// shipped constants", which is the default build.
#[derive(Debug, Clone)]
pub struct CyclePolicy {
    arms: [usize; CYCLE_CONTEXTS],
}

impl CyclePolicy {
    /// Magic for the on-disk table. Deliberately *not* `AHPRL00x`: this is
    /// a different object from the MLP weights, and reusing a magic across
    /// a semantic change is exactly what forced `AHPRL001` -> `AHPRL002`.
    pub const MAGIC: &'static [u8; 8] = b"AHPCB001";

    /// Parse `MAGIC` followed by `CYCLE_CONTEXTS` little-endian u8 arm
    /// indices. Any malformed or out-of-range file is rejected whole —
    /// a partially-applied policy would be untraceable in a measurement.
    pub fn parse(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 8 + CYCLE_CONTEXTS || &bytes[..8] != Self::MAGIC {
            return None;
        }
        let mut arms = [CYCLE_ARM_DEFAULT; CYCLE_CONTEXTS];
        for (i, slot) in arms.iter_mut().enumerate() {
            let v = bytes[8 + i] as usize;
            if v >= CYCLE_ARMS.len() {
                return None;
            }
            *slot = v;
        }
        Some(Self { arms })
    }

    pub fn arm_for(&self, context: usize) -> CycleArm {
        CYCLE_ARMS[self.arms[context.min(CYCLE_CONTEXTS - 1)]]
    }
}

/// Where the pacing-gain cycle currently is.
///
/// A constant gain cannot satisfy A1: `g > 1` holds a standing queue and
/// `g <= 1` never probes upward, so the controller has to alternate. This
/// is BBRv1's gain cycle with BBRv2's condition-based drain exit — the
/// drain ends when the queue is actually gone, not when a timer says it
/// should be, because at a 5 ms control tick a fixed one-RTT drain is
/// +/-20% at a 25 ms RTT.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CyclePhase {
    ProbeUp,
    Drain,
    Cruise,
}

/// Action output range: gain mapped from sigmoid [0,1] to [MIN, MAX].
///
/// Must match `ACTION_MIN`/`ACTION_MAX` in `training/closed_loop_env.py`:
/// the network emits a sigmoid and both sides map it onto this interval, so
/// a mismatch silently rescales every action a trained policy produces.
///
/// Was 0.5-2.0, inherited from when the action was a compounding multiplier
/// on the current rate. As a gain on measured delivery that range is badly
/// conditioned: the steady state of `rate <- g * delivered` is `g *
/// capacity`, with a permanent loss fraction of `(g-1)/g`. So 1.25 parks the
/// link at 20% loss and 2.0 at 50%, while anything below 1.0 shrinks the
/// rate — the band that steers is roughly 1.0 to 1.11, about 7% of the old
/// range. Measured in the trainer, the reward over constant gains peaks
/// sharply at 1.1 on five of eight scenarios and falls off a cliff by 1.25.
///
/// Narrowing puts the network's whole output resolution on the part that
/// does work. Recalibrating the range against the new dynamics moved
/// satellite from 10.8% utilisation at 10.7% loss to 22.1% at 0.8%, and
/// degraded from 5.1% at 15.0% to 70.1% at 2.9%.
const ACTION_MIN: f64 = 0.90;
const ACTION_MAX: f64 = 1.15;

/// Normalization constants for the state vector.
const RTT_NORM: f64 = 1.0; // 1 second
const BW_NORM: f64 = 1_000_000_000.0; // 1 Gbps in bytes/sec
const GRADIENT_CLIP: f64 = 1.0;

// ── MLP weights ──────────────────────────────────────────────────────────────

/// Weights for the 8→32→16→1 MLP.
#[derive(Debug, Clone)]
pub struct MlpWeights {
    w1: Vec<f64>, // HIDDEN1 × INPUT  (row-major)
    b1: Vec<f64>, // HIDDEN1
    w2: Vec<f64>, // HIDDEN2 × HIDDEN1
    b2: Vec<f64>, // HIDDEN2
    w3: Vec<f64>, // OUTPUT × HIDDEN2
    b3: f64,
}

impl MlpWeights {
    /// Load weights from the binary format: magic(8) + f64-LE values.
    pub fn load(path: &std::path::Path) -> Option<Self> {
        let data = fs::read(path).ok()?;
        let expected = 8 + TOTAL_WEIGHTS * 8;
        if data.len() != expected {
            tracing::warn!(
                path = %path.display(), expected, got = data.len(),
                "rl weights: size mismatch"
            );
            return None;
        }
        if &data[..8] != WEIGHT_MAGIC {
            tracing::warn!("rl weights: bad magic");
            return None;
        }
        let floats: Vec<f64> = data[8..]
            .chunks_exact(8)
            .map(|c| f64::from_le_bytes(c.try_into().unwrap()))
            .collect();

        let mut i = 0;
        let w1 = floats[i..i + INPUT_DIM * HIDDEN1_DIM].to_vec(); i += INPUT_DIM * HIDDEN1_DIM;
        let b1 = floats[i..i + HIDDEN1_DIM].to_vec(); i += HIDDEN1_DIM;
        let w2 = floats[i..i + HIDDEN1_DIM * HIDDEN2_DIM].to_vec(); i += HIDDEN1_DIM * HIDDEN2_DIM;
        let b2 = floats[i..i + HIDDEN2_DIM].to_vec(); i += HIDDEN2_DIM;
        let w3 = floats[i..i + HIDDEN2_DIM].to_vec(); i += HIDDEN2_DIM;
        let b3 = floats[i];

        Some(Self { w1, b1, w2, b2, w3, b3 })
    }

    /// Save weights to the binary format.
    pub fn save(&self, path: &std::path::Path) -> std::io::Result<()> {
        let mut buf = Vec::with_capacity(8 + TOTAL_WEIGHTS * 8);
        buf.extend_from_slice(WEIGHT_MAGIC);
        for &v in self.w1.iter()
            .chain(self.b1.iter())
            .chain(self.w2.iter())
            .chain(self.b2.iter())
            .chain(self.w3.iter())
            .chain(std::iter::once(&self.b3))
        {
            buf.extend_from_slice(&v.to_le_bytes());
        }
        fs::write(path, &buf)
    }

    /// Forward pass: state(8) → multiplier in [ACTION_MIN, ACTION_MAX].
    fn forward(&self, input: &[f64; INPUT_DIM]) -> f64 {
        // Layer 1: ReLU(W1 @ input + b1)
        let mut h1 = [0.0f64; HIDDEN1_DIM];
        for i in 0..HIDDEN1_DIM {
            let mut sum = self.b1[i];
            for j in 0..INPUT_DIM {
                sum += self.w1[i * INPUT_DIM + j] * input[j];
            }
            h1[i] = sum.max(0.0); // ReLU
        }

        // Layer 2: ReLU(W2 @ h1 + b2)
        let mut h2 = [0.0f64; HIDDEN2_DIM];
        for i in 0..HIDDEN2_DIM {
            let mut sum = self.b2[i];
            for j in 0..HIDDEN1_DIM {
                sum += self.w2[i * HIDDEN1_DIM + j] * h1[j];
            }
            h2[i] = sum.max(0.0); // ReLU
        }

        // Output: sigmoid(W3 @ h2 + b3) mapped to [ACTION_MIN, ACTION_MAX]
        let mut out = self.b3;
        for i in 0..HIDDEN2_DIM {
            out += self.w3[i] * h2[i];
        }
        let sigmoid = 1.0 / (1.0 + (-out).exp());
        ACTION_MIN + sigmoid * (ACTION_MAX - ACTION_MIN)
    }
}

// ── Trace recording ──────────────────────────────────────────────────────────

/// A single (state, action, reward) record for offline training.
#[derive(Debug, Clone)]
struct TraceRecord {
    state: [f64; INPUT_DIM],
    action: f64,
    reward: f64,
}

// ── Controller ───────────────────────────────────────────────────────────────

/// Operating mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RlMode {
    /// Load model, pure inference.
    Exploit,
    /// Record traces, epsilon-greedy exploration.
    Explore,
}

/// RL-based congestion controller.
#[derive(Debug)]
pub struct RlController {
    // ── Rate control ─────────────────────────────────────────────────────
    /// Packet sending period in μs (primary control variable, UDT-style).
    pkt_snd_period: f64,
    cwnd: f64,
    max_cwnd: f64,
    /// Effective `CWND_BDP_GAIN`; see `cwnd_bdp_gain_from_env`.
    cwnd_bdp_gain: f64,
    /// Loaded cycle policy, if any. `None` = the shipped constants.
    cycle_policy: Option<CyclePolicy>,
    /// Arm forced by the trainer for this transfer, if any. Overrides the
    /// policy so a bandit can explore a specific arm.
    forced_arm: Option<usize>,
    /// Constant gain override from `FAVONIUS_RL_GAIN`, if set.
    gain_override: Option<f64>,
    /// Whether the bottleneck estimate is still climbing. See `RAMP_GAIN`.
    ramp_active: bool,
    /// When the ramp last evaluated growth, and what it saw.
    ramp_checked: Option<Instant>,
    ramp_ref_btlbw: u64,
    ramp_flat_rounds: u32,
    mss: usize,
    rtt: RttEstimator,
    pacer: Pacer,
    bytes_in_flight: usize,
    slow_start: bool,
    last_ack: u64,
    snd_curr_seq: u64,

    // ── Bandwidth / delivery tracking ────────────────────────────────────
    bandwidth: u64,
    rcv_rate: u64,
    delivery_rate: u64,
    /// Windowed maximum of `delivery_rate` — BBR's btlbw.
    ///
    /// The action is a gain on this rather than on the latest delivery
    /// sample. `rate <- g * delivered` has no restoring force: a few
    /// intervals below 1.0 shrink the rate, which shrinks delivery, which
    /// shrinks the rate again, so the quantity the gain multiplies is
    /// destroyed by the backing-off it is meant to recover from. Measured
    /// in the trainer, satellite and degraded pinned against the progress
    /// floor at 1.9% and 2.7% utilisation while a constant gain reached
    /// 22% and 70% on the same paths. A max filter survives a probe-down,
    /// so a gain above 1.0 can always climb back out.
    btlbw: u64,
    /// Ring of recent interval-averaged delivery samples backing `btlbw`.
    dr_window: std::collections::VecDeque<(Instant, u64)>,
    /// Bytes acknowledged since the last rate-control tick.
    bytes_acked_interval: u64,
    /// Cumulative acknowledged bytes, and a trail of (time, cumulative)
    /// samples used to average delivery over at least one round trip.
    acked_total: u64,
    acked_trail: std::collections::VecDeque<(Instant, u64)>,

    // ── Loss tracking ────────────────────────────────────────────────────
    loss_flag: bool,
    /// Highest sent chunk index at the last rate decrease. `None` until
    /// the first one — 0 is a real chunk index, so a sentinel of 0
    /// swallowed the first loss report of every transfer (same defect
    /// fixed in `classic.rs`).
    last_dec_seq: Option<u64>,
    recent_loss_count: u64,
    /// Multiplier compensating for loss the controller cannot avoid. 1.0
    /// means no compensation; see `update_loss_comp`.
    loss_comp: f64,
    /// Current phase of the pacing-gain cycle, and when it began.
    cycle_phase: CyclePhase,
    phase_started: Option<Instant>,
    recent_ack_count: u64,

    // ── State vector history (for gradients) ─────────────────────────────
    prev_smoothed_rtt: Option<Duration>,
    prev_delivery_rate: u64,

    // ── RL model ─────────────────────────────────────────────────────────
    weights: Option<MlpWeights>,
    mode: RlMode,
    epsilon: f64,

    // ── Trace recording ──────────────────────────────────────────────────
    trace_log: Vec<TraceRecord>,
    trace_dir: Option<PathBuf>,

    // ── Timing ───────────────────────────────────────────────────────────
    last_rc_time: Instant,
}

impl RlController {
    /// Create a new RL controller. Reads env vars for configuration:
    /// - `FAVONIUS_RL_MODEL`: path to weights file
    /// - `FAVONIUS_RL_EXPLORE`: set to "1" for explore mode
    /// - `FAVONIUS_RL_EPSILON`: epsilon for exploration (default 0.1)
    /// - `FAVONIUS_RL_TRACE_DIR`: directory for trace output
    pub fn new() -> Self {
        // Whether the operator named a file, or we are just probing the
        // default location. The two failures are not the same event: no
        // file at the default path is the normal shipping configuration,
        // while a named file that does not load is a request that was
        // silently not honoured.
        let explicit_path = std::env::var("FAVONIUS_RL_MODEL").ok().map(PathBuf::from);
        let model_path = explicit_path
            .clone()
            .or_else(|| dirs_config().map(|d| d.join("rl_weights.bin")));

        let weights = model_path.as_ref().and_then(|p| {
            let w = MlpWeights::load(p);
            match (&w, explicit_path.is_some()) {
                (Some(_), _) => {
                    tracing::info!(path = %p.display(), "rl: loaded model weights");
                }
                (None, true) => {
                    // Asked for by name and not honoured. This changes
                    // which controller runs -- constant gain instead of the
                    // learned policy -- so it must not be a debug line.
                    // Retired `AHPRL001` files land here: the magic moved
                    // to `AHPRL002` when the weights' meaning changed, and
                    // the layout did not, so an old file would otherwise
                    // load cleanly and mean something else.
                    tracing::warn!(
                        path = %p.display(),
                        "rl: FAVONIUS_RL_MODEL was set but the file could not be \
                         loaded (missing, unreadable, or not an AHPRL002 weight \
                         set) -- falling back to the constant-gain controller"
                    );
                }
                (None, false) => {
                    tracing::debug!(path = %p.display(), "rl: no model found, using fallback");
                }
            }
            w
        });

        // Gain override, for locating the stability boundary.
        //
        // The steady state of `rate <- g * btlbw` is `g * capacity` at a
        // permanent loss of `(g-1)/g`, which predicts 7.0% at 1.075 and
        // 10.7% at 1.12. The rig measures 1.3% and 59%. The prediction is
        // wrong in both directions because the loss back-off stabilises the
        // loop below `g * capacity` -- until it cannot, and then the system
        // runs away. Where that boundary sits is a shipping question: it
        // says how much margin DEFAULT_GAIN has.
        //
        // Read once at construction and clamped to the action range, so a
        // sweep needs one binary rather than one per gain.
        let gain_override = std::env::var("FAVONIUS_RL_GAIN")
            .ok()
            .and_then(|v| v.parse::<f64>().ok())
            .filter(|g| g.is_finite())
            .map(|g| g.clamp(ACTION_MIN, ACTION_MAX));
        if let Some(g) = gain_override {
            tracing::warn!(gain = g, "rl: constant gain overridden by FAVONIUS_RL_GAIN");
        }

        let explore = std::env::var("FAVONIUS_RL_EXPLORE")
            .map(|v| v == "1")
            .unwrap_or(false);

        let epsilon: f64 = std::env::var("FAVONIUS_RL_EPSILON")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(0.1);

        let trace_dir = if explore {
            let dir = std::env::var("FAVONIUS_RL_TRACE_DIR")
                .ok()
                .map(PathBuf::from)
                .or_else(|| dirs_config().map(|d| d.join("rl_traces")));
            if let Some(ref d) = dir {
                let _ = fs::create_dir_all(d);
            }
            dir
        } else {
            None
        };

        let mode = if explore { RlMode::Explore } else { RlMode::Exploit };
        let now = Instant::now();

        Self {
            pkt_snd_period: 1.0, // send as fast as possible initially
            cwnd: INITIAL_CWND_PKTS,
            max_cwnd: 1024.0,
            cwnd_bdp_gain: cwnd_bdp_gain_from_env(),
            cycle_policy: load_cycle_policy(),
            forced_arm: forced_arm_from_env(),
            gain_override,
            ramp_active: true,
            ramp_checked: None,
            ramp_ref_btlbw: 0,
            ramp_flat_rounds: 0,
            mss: MSS,
            rtt: RttEstimator::new(),
            pacer: Pacer::new(100_000_000),
            bytes_in_flight: 0,
            slow_start: true,
            last_ack: 0,
            snd_curr_seq: 0,

            bandwidth: 0,
            rcv_rate: 0,
            delivery_rate: 0,
            btlbw: 0,
            dr_window: std::collections::VecDeque::new(),
            bytes_acked_interval: 0,
            acked_total: 0,
            acked_trail: std::collections::VecDeque::new(),

            loss_flag: false,
            last_dec_seq: None,
            recent_loss_count: 0,
            loss_comp: 1.0,
            cycle_phase: CyclePhase::Cruise,
            phase_started: None,
            recent_ack_count: 0,

            prev_smoothed_rtt: None,
            prev_delivery_rate: 0,

            weights,
            mode,
            epsilon,

            trace_log: Vec::new(),
            trace_dir,

            last_rc_time: now,
        }
    }

    /// Convert pkt_snd_period (μs) to bytes/sec.
    fn rate_bps(&self) -> u64 {
        if self.pkt_snd_period <= 0.0 {
            return 100_000_000;
        }
        (self.mss as f64 * 1_000_000.0 / self.pkt_snd_period) as u64
    }

    fn sync_pacer(&mut self) {
        self.pacer.set_rate(self.rate_bps());
    }

    fn rtt_us(&self) -> u64 {
        self.rtt.smoothed_rtt()
            .unwrap_or(Duration::from_millis(10))
            .as_micros() as u64
    }

    /// Build the 8-element normalized state vector.
    fn compute_state(&self) -> [f64; INPUT_DIM] {
        let srtt = self.rtt.smoothed_rtt()
            .unwrap_or(Duration::from_millis(10))
            .as_secs_f64();
        let min_rtt = self.rtt.min_rtt()
            .unwrap_or(Duration::from_millis(1))
            .as_secs_f64();

        let rtt_gradient = match self.prev_smoothed_rtt {
            Some(prev) => {
                let delta = srtt - prev.as_secs_f64();
                (delta / RTT_NORM).clamp(-GRADIENT_CLIP, GRADIENT_CLIP)
            }
            None => 0.0,
        };

        let dr = self.delivery_rate as f64;
        let dr_gradient = {
            let delta = dr - self.prev_delivery_rate as f64;
            (delta / BW_NORM).clamp(-GRADIENT_CLIP, GRADIENT_CLIP)
        };

        let loss_rate = if self.recent_ack_count > 0 {
            self.recent_loss_count as f64
                / (self.recent_ack_count + self.recent_loss_count) as f64
        } else {
            0.0
        };

        let cwnd_bytes = (self.cwnd as usize * self.mss).max(1);
        let inflight_ratio = (self.bytes_in_flight as f64 / cwnd_bytes as f64).clamp(0.0, 2.0);

        let queue_delay = if min_rtt > 0.0 {
            ((srtt - min_rtt) / min_rtt).clamp(0.0, 10.0)
        } else {
            0.0
        };

        [
            (srtt / RTT_NORM).clamp(0.0, 1.0),
            (min_rtt / RTT_NORM).clamp(0.0, 1.0),
            rtt_gradient,
            (dr / BW_NORM).clamp(0.0, 1.0),
            dr_gradient,
            loss_rate.clamp(0.0, 1.0),
            inflight_ratio,
            queue_delay / 10.0, // normalized to [0, 1]
        ]
    }

    /// Get a rate multiplier from the model (or exploration).
    fn get_action(&self, state: &[f64; INPUT_DIM]) -> f64 {
        match (&self.weights, self.mode) {
            (Some(w), RlMode::Exploit) => w.forward(state),
            (Some(w), RlMode::Explore) => {
                if rand::random::<f64>() < self.epsilon {
                    // Random exploration
                    ACTION_MIN + rand::random::<f64>() * (ACTION_MAX - ACTION_MIN)
                } else {
                    w.forward(state)
                }
            }
            (None, RlMode::Explore) => {
                // No model yet: random exploration
                ACTION_MIN + rand::random::<f64>() * (ACTION_MAX - ACTION_MIN)
            }
            (None, RlMode::Exploit) => {
                // No model: the constant-gain controller. Not a no-op —
                // 1.0 would hold the rate wherever it happened to be and
                // never probe up, since the fixed point of `rate <- g *
                // btlbw` at g = 1.0 is any rate at all.
                self.gain_override.unwrap_or(DEFAULT_GAIN)
            }
        }
    }

    /// Compute reward for the current step.
    ///
    /// Reward = goodput × (1 - loss²) - queue_penalty
    ///
    /// Components:
    /// - **Goodput**: delivery_rate × (1 - loss²). Squared loss gives a
    ///   gentler penalty at low loss rates (1% loss → 0.9999 multiplier)
    ///   while still punishing high loss aggressively.
    /// - **Queue delay penalty**: discourages bufferbloat by penalizing
    ///   high queue delay (srtt - min_rtt).
    ///
    /// Note this is the reward *recorded into traces*. It is not
    /// currently what the offline trainer optimises — see the limitations
    /// note at the top of `training/train_rl.py`.
    fn compute_reward(&self) -> f64 {
        let dr_norm = (self.delivery_rate as f64 / BW_NORM).clamp(0.0, 1.0);
        let loss_rate = if self.recent_ack_count > 0 {
            self.recent_loss_count as f64
                / (self.recent_ack_count + self.recent_loss_count) as f64
        } else {
            0.0
        };

        // Goodput: squared loss penalty is gentler at low loss rates.
        let goodput = dr_norm * (1.0 - loss_rate * loss_rate);

        // Queue delay penalty: penalize bufferbloat.
        let min_rtt = self.rtt.min_rtt().unwrap_or(Duration::from_millis(1)).as_secs_f64();
        let srtt = self.rtt.smoothed_rtt().unwrap_or(Duration::from_millis(10)).as_secs_f64();
        let queue_delay = if min_rtt > 0.0 { ((srtt - min_rtt) / min_rtt).max(0.0) } else { 0.0 };
        let queue_penalty = 0.05 * queue_delay.min(1.0);

        (goodput - queue_penalty).clamp(0.0, 1.0)
    }

    /// Record a trace entry (explore mode only).
    fn record_trace(&mut self, state: [f64; INPUT_DIM], action: f64) {
        if self.mode == RlMode::Explore {
            let reward = self.compute_reward();
            self.trace_log.push(TraceRecord { state, action, reward });
        }
    }

    /// UDT-style rate increase (fallback when no model loaded).
    fn udt_rate_increase(&mut self) {
        let syn_us = SYN_INTERVAL.as_micros() as u64;
        let current_rate_pps = (1_000_000.0 / self.pkt_snd_period) as i64;
        let b = self.bandwidth as i64 - current_rate_pps;

        let inc = if b <= 0 {
            0.01
        } else {
            let raw = 10.0_f64.powf(
                (b as f64 * self.mss as f64 * 8.0).log10().ceil()
            ) * 0.0000015 / self.mss as f64;
            raw.max(0.01)
        };

        self.pkt_snd_period = (self.pkt_snd_period * syn_us as f64)
            / (self.pkt_snd_period * inc + syn_us as f64);
    }

    /// Flush trace log to disk.
    fn flush_traces(&mut self) {
        if self.trace_log.is_empty() {
            return;
        }
        let Some(ref dir) = self.trace_dir else { return };

        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let path = dir.join(format!("trace_{}.jsonl", timestamp));

        let mut buf = String::new();
        for rec in &self.trace_log {
            buf.push_str(&format!(
                "{{\"s\":[{:.6},{:.6},{:.6},{:.6},{:.6},{:.6},{:.6},{:.6}],\"a\":{:.6},\"r\":{:.6}}}\n",
                rec.state[0], rec.state[1], rec.state[2], rec.state[3],
                rec.state[4], rec.state[5], rec.state[6], rec.state[7],
                rec.action, rec.reward,
            ));
        }

        if let Err(e) = fs::write(&path, buf) {
            tracing::warn!(path = %path.display(), err = %e, "rl: failed to write trace");
        } else {
            tracing::info!(path = %path.display(), records = self.trace_log.len(), "rl: trace saved");
        }
        self.trace_log.clear();
    }
    /// Ratio of smoothed to minimum RTT, or `INFINITY` before an estimate
    /// exists. Above `LOSS_QUEUE_GATE` the controller is holding a queue.
    fn queue_ratio(&self) -> f64 {
        match (self.rtt.smoothed_rtt(), self.rtt.min_rtt()) {
            (Some(s), Some(m)) if m.as_secs_f64() > 0.0 => {
                s.as_secs_f64() / m.as_secs_f64()
            }
            _ => f64::INFINITY,
        }
    }

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

    /// Advance the pacing-gain cycle and return the gain for this interval.
    ///
    /// Phases are timed on the wall clock against `min_rtt` rather than by
    /// counting 5 ms control ticks: a tick is 1/5th of a 25 ms RTT and
    /// 1/60th of a 300 ms one, so tick-counting would make the cycle mean
    /// something different on every path — the same mistake the compounding
    /// multiplier made before it was replaced by a gain on delivery.
    ///
    /// Probe and drain exit early on measured conditions. A probe that has
    /// already put a quarter-BDP in flight has learned what it is going to
    /// learn, and a drain should end when the queue is gone rather than
    /// when a timer expires.
    fn advance_cycle(&mut self, now: Instant) -> f64 {
        let min_rtt = self
            .rtt
            .min_rtt()
            .unwrap_or(Duration::from_millis(10))
            .max(Duration::from_millis(1));

        // Ramp: while the estimate is still climbing and the queue is
        // empty, drive it at RAMP_GAIN instead of waiting for the cycle's
        // probe phase. Clocked on the round trip, which is what makes it
        // scale with the path; the cycle's 8-RTT period does not.
        if self.ramp_active {
            let checked = *self.ramp_checked.get_or_insert(now);
            if now.saturating_duration_since(checked) >= min_rtt {
                let grew = self.ramp_ref_btlbw == 0
                    || (self.btlbw as f64)
                        > self.ramp_ref_btlbw as f64 * RAMP_PLATEAU_RATIO;
                if grew {
                    self.ramp_flat_rounds = 0;
                } else {
                    self.ramp_flat_rounds += 1;
                }
                self.ramp_ref_btlbw = self.btlbw;
                self.ramp_checked = Some(now);
                if self.ramp_flat_rounds >= RAMP_PLATEAU_ROUNDS {
                    self.ramp_active = false;
                    tracing::debug!(btlbw = self.btlbw, "rl: ramp plateau, entering cycle");
                }
            }
            // Only while the queue is demonstrably empty. The moment
            // queueing appears the path is telling us the ramp has found
            // the ceiling, and the ordinary cycle -- which can drain -- is
            // the right thing to be running.
            if self.ramp_active && !self.queue_above_budget() {
                self.cycle_phase = CyclePhase::Cruise;
                self.phase_started = Some(now);
                return RAMP_GAIN;
            }
        }
        let started = *self.phase_started.get_or_insert(now);
        let elapsed = now.saturating_duration_since(started);
        let after = |rtts: f64| elapsed >= min_rtt.mul_f64(rtts);

        // BDP from the delivery estimate. Zero until the first sample, in
        // which case the inflight-based exits simply do not fire and the
        // phases run to their nominal lengths.
        let bdp = self.btlbw as f64 * min_rtt.as_secs_f64();
        let inflight = self.bytes_in_flight as f64;

        let next = match self.cycle_phase {
            CyclePhase::ProbeUp => {
                // Runs its full length. There is no early exit on inflight.
                //
                // There used to be: `inflight >= CYCLE_PROBE_INFLIGHT * bdp`,
                // on the reasoning that a probe which has already put a
                // quarter-BDP extra in flight "has learned what it is going
                // to learn". That is wrong, and it is the reason the probe
                // could not raise the rate. Inflight rising is not the
                // learning -- the probe's whole purpose is to find out
                // whether the path *delivers* more, and that answer arrives
                // one round trip later in the ACKs. Inflight crosses the
                // threshold almost immediately, so the probe was cut short
                // before its own result could exist, and the elevated rate
                // never appeared in a delivery sample.
                //
                // Measured on transatlantic: ProbeUp occupied 1 of 21
                // samples where the 2/2/4 cycle should give roughly a
                // quarter, and `btlbw` sat at 52 Mbit for an entire
                // transfer on a 100 Mbit link while a parallel run held
                // 104. The rate is a fixed point of `gain * btlbw` at cruise
                // gain 1.0, so with the probe disabled there is no upward
                // force at all and the controller freezes at whatever the
                // ramp happened to latch.
                after(self.active_arm().probe_rtts).then_some(CyclePhase::Drain)
            }
            CyclePhase::Drain => {
                let drained = (bdp > 0.0 && inflight <= bdp)
                    || self.queue_ratio() <= CYCLE_DRAINED_RATIO;
                ((after(CYCLE_DRAIN_RTTS) && drained) || after(CYCLE_DRAIN_MAX_RTTS))
                    .then_some(CyclePhase::Cruise)
            }
            CyclePhase::Cruise => after(CYCLE_CRUISE_RTTS).then_some(CyclePhase::ProbeUp),
        };

        if let Some(phase) = next {
            self.cycle_phase = phase;
            self.phase_started = Some(now);
        }

        match self.cycle_phase {
            CyclePhase::ProbeUp => self.active_arm().probe_gain,
            CyclePhase::Drain => CYCLE_DRAIN_GAIN,
            CyclePhase::Cruise => CYCLE_CRUISE_GAIN,
        }
    }

    /// Track a multiplier that offsets loss the controller did not cause.
    ///
    /// `rate <- gain * btlbw` sets the rate from *delivered* bytes, so on a
    /// path losing a fraction `p` to something other than congestion each
    /// round trip multiplies the rate by `gain * (1 - p)`. Holding station
    /// therefore needs `gain > 1/(1-p)` — 1.053 at 5% loss — and the 1.075
    /// constant clears that by so little that the measured climb on the
    /// `degraded` path was ~0.45% per round trip. Reaching capacity took
    /// longer than the transfer did.
    ///
    /// Dividing by `(1 - p_hat)` cancels the term, restoring the loss-free
    /// growth rate without touching the saturated equilibrium: once the
    /// bottleneck is full, `btlbw` is capacity and the fixed point is
    /// `gain * capacity` either way.
    ///
    /// The estimate is only updated while the queue is empty. Loss measured
    /// behind a standing queue is the controller's own doing, and
    /// compensating for it would be a positive feedback loop — overdrive
    /// causing loss, loss raising the compensation, compensation causing
    /// more overdrive. Above the gate the factor decays back toward 1.0
    /// instead.
    fn update_loss_comp(&mut self) {
        let accounted = self.recent_ack_count + self.recent_loss_count;
        let target = if self.queue_above_budget() || accounted == 0 {
            1.0
        } else {
            let p = self.recent_loss_count as f64 / accounted as f64;
            (1.0 / (1.0 - p).max(0.5)).clamp(1.0, LOSS_COMP_MAX)
        };
        self.loss_comp += (target - self.loss_comp) * LOSS_COMP_ALPHA;
    }

}

impl Default for RlController {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for RlController {
    fn drop(&mut self) {
        self.flush_traces();
    }
}

/// Load a cycle policy from `FAVONIUS_CYCLE_POLICY`.
///
/// Absent or malformed means the shipped constants, logged at warn level
/// rather than swallowed — a policy that silently failed to load would be
/// indistinguishable from one that did nothing, which is the error class
/// this crate has hit four times.
fn load_cycle_policy() -> Option<CyclePolicy> {
    let path = std::env::var("FAVONIUS_CYCLE_POLICY").ok()?;
    match std::fs::read(&path) {
        Ok(bytes) => match CyclePolicy::parse(&bytes) {
            Some(p) => {
                tracing::info!(path = %path, "cycle policy loaded");
                Some(p)
            }
            None => {
                tracing::warn!(path = %path, "cycle policy rejected (bad magic or arm index) — using shipped constants");
                None
            }
        },
        Err(e) => {
            tracing::warn!(path = %path, error = %e, "cycle policy unreadable — using shipped constants");
            None
        }
    }
}

/// Arm forced for this transfer, for bandit exploration. Training only.
fn forced_arm_from_env() -> Option<usize> {
    std::env::var("FAVONIUS_CYCLE_ARM")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .filter(|a| *a < CYCLE_ARMS.len())
}

impl RlController {
    /// The cycle parameters in force: forced arm, else policy lookup on the
    /// observed context, else the shipped constants.
    fn active_arm(&self) -> CycleArm {
        if let Some(a) = self.forced_arm {
            return CYCLE_ARMS[a];
        }
        match (&self.cycle_policy, self.rtt.min_rtt()) {
            (Some(p), Some(min_rtt)) => {
                let loss = if self.recent_ack_count > 0 {
                    self.recent_loss_count as f64 / self.recent_ack_count as f64
                } else {
                    0.0
                };
                p.arm_for(cycle_context(min_rtt, loss))
            }
            _ => CYCLE_ARMS[CYCLE_ARM_DEFAULT],
        }
    }
}

impl CongestionController for RlController {
    fn on_packet_sent(&mut self, packet_number: u64, bytes: usize, now: Instant) {
        self.bytes_in_flight += bytes;
        // Retransmits re-report an older chunk index; keep the high-water mark.
        self.snd_curr_seq = self.snd_curr_seq.max(packet_number);
        self.pacer.on_packet_sent(bytes, now);
    }

    fn on_ack_received(&mut self, acked: &AckInfo, now: Instant) {
        let delivered = acked.delivered_bytes as usize;
        self.bytes_in_flight = self.bytes_in_flight.saturating_sub(delivered);
        self.recent_ack_count += 1;

        // Bytes delivered since the last rate-control tick. btlbw is
        // computed from this, not from `acked.delivery_rate`.
        //
        // `acked.delivery_rate` is an instantaneous per-ACK figure: a batch
        // of ACKs arriving together reads as an enormous momentary rate even
        // when the path delivered exactly capacity. Max-filtering that is
        // not BBR's bottleneck estimate, it is a noise-peak detector — one
        // spike latches the filter for its whole window. Measured at 4.0x
        // capacity from a single spike, which let the `2 x btlbw` rate
        // ceiling permit 8x capacity; on the rig the pacing rate reached
        // 53 MB/s on a 12.5 MB/s link and the controller retransmitted 52-60%
        // of everything it sent.
        //
        // BBR max-filters delivery-rate samples measured *over an interval*.
        // Accumulating here and dividing by the elapsed interval at the tick
        // gives that: an average over ~5 ms, which cannot exceed what the
        // path actually delivered in those 5 ms.
        self.bytes_acked_interval = self.bytes_acked_interval.saturating_add(delivered as u64);

        // Update delivery rate tracking.
        if acked.delivery_rate > 0 {
            self.delivery_rate = acked.delivery_rate;
            let pps = acked.delivery_rate / self.mss as u64;
            if pps > 0 {
                self.rcv_rate = if self.rcv_rate == 0 {
                    pps
                } else {
                    (self.rcv_rate * 7 + pps) / 8
                };
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

        // Delivery sample averaged over at least one round trip, then
        // max-filtered over ~10 of them.
        //
        // Averaging over a single 5 ms control tick is not enough. ACKs do
        // not respect tick boundaries: a batch arriving just before one is
        // attributed to the interval *after* it, so a tick can be credited
        // with two intervals' bytes over one interval's duration. Measured
        // at 2.2x capacity — better than the 4.0x from per-ACK sampling, and
        // still enough for the `2 x btlbw` ceiling to permit 4.3x.
        //
        // Averaging over a whole round trip makes a 5 ms attribution error a
        // small fraction of the window, and a rate averaged over an RTT
        // cannot exceed what the bottleneck passed in that RTT regardless of
        // how the ACKs were clumped.
        self.acked_total = self.acked_total.saturating_add(self.bytes_acked_interval);
        self.bytes_acked_interval = 0;
        self.acked_trail.push_back((now, self.acked_total));
        let avg_window = Duration::from_micros(
            (self.rtt_us() * DELIVERY_WINDOW_RTTS).max(SYN_INTERVAL.as_micros() as u64 * 4),
        );
        // Keep one sample older than the window so the span is >= the window.
        while self.acked_trail.len() > 2 {
            let second = self.acked_trail[1].0;
            if now.duration_since(second) >= avg_window {
                self.acked_trail.pop_front();
            } else {
                break;
            }
        }
        if let Some(&(t0, b0)) = self.acked_trail.front() {
            let span = now.duration_since(t0).as_secs_f64();
            if span >= avg_window.as_secs_f64() * 0.5 && span > 0.0 {
                let sample = ((self.acked_total - b0) as f64 / span) as u64;
                let horizon =
                    Duration::from_micros(self.rtt_us().saturating_mul(10).max(50_000));
                self.dr_window.push_back((now, sample));
                while let Some(&(t, _)) = self.dr_window.front() {
                    if now.duration_since(t) > horizon {
                        self.dr_window.pop_front();
                    } else {
                        break;
                    }
                }
                self.btlbw = self.dr_window.iter().map(|&(_, r)| r).max().unwrap_or(0);
            }
        }

        // ── Slow start (same as UDT) ────────────────────────────────────
        if self.slow_start {
            let newly_acked = ack_seq.saturating_sub(self.last_ack);
            self.cwnd += newly_acked as f64;
            self.last_ack = ack_seq;

            if self.cwnd > self.max_cwnd {
                self.slow_start = false;
                self.cwnd = self.max_cwnd;
                if self.rcv_rate > 0 {
                    let rcv_period = 1_000_000.0 / self.rcv_rate as f64;
                    if rcv_period < self.pkt_snd_period {
                        self.pkt_snd_period = rcv_period;
                    }
                }
                self.sync_pacer();
            }
            // Save state for gradient computation.
            self.prev_smoothed_rtt = self.rtt.smoothed_rtt();
            self.prev_delivery_rate = self.delivery_rate;
            return;
        }

        // ── Steady state: RL or fallback ─────────────────────────────────

        // Skip one round after loss (UDT-style).
        if self.loss_flag {
            self.loss_flag = false;
            self.prev_smoothed_rtt = self.rtt.smoothed_rtt();
            self.prev_delivery_rate = self.delivery_rate;
            return;
        }

        let has_model = self.weights.is_some() || self.mode == RlMode::Explore;

        // Take the gain path whenever there is a delivery estimate to apply
        // it to.
        //
        // **The no-weights case is a different algorithm, not a constant.**
        // The dispatch sixteen lines below routes `weights.is_none() &&
        // Exploit` to `advance_cycle()` — the probe/drain/cruise gain cycle
        // plus the RTT-clocked ramp. `get_action`'s `DEFAULT_GAIN` arm is
        // unreachable in the shipped configuration.
        //
        // This comment previously asserted the opposite, and that error is
        // the reason a day of rig measurements was spent characterising a
        // constant that never executes. Do not restate it without reading
        // the `if` below.
        //
        // It used to fall through to `udt_rate_increase`, which is a
        // separate control law with separate failure modes — and an unbound
        // one, measured at 1.42 GB/s on a 10 MB/s path. That is still the
        // path taken before any delivery sample exists, where a gain has
        // nothing to multiply, but no longer the steady state.
        if has_model || self.btlbw > 0 {
            // RL path: compute state, get action, apply rate multiplier.
            let state = self.compute_state();
            // With no policy loaded the gain comes from the hand-designed
            // cycle rather than a constant. A learned policy, if one is
            // ever loaded, still emits its own gain — but see the review
            // note in the CC research notes: per-interval gain is the wrong action
            // space precisely because it asks a policy to rediscover this
            // cycle from inside a 5 ms window with no phase memory.
            let multiplier = if self.weights.is_none() && self.mode == RlMode::Exploit {
                self.advance_cycle(now)
            } else {
                self.get_action(&state)
            };

            // Apply multiplier to current rate.
            let current_rate = self.rate_bps() as f64;
            // The model's output is applied as a *compounding* multiplier
            // on the sending rate, once per SYN interval (5 ms). With no
            // ceiling, any policy whose mean output exceeds 1.0 diverges
            // geometrically: at the shipped model's typical 1.70 that is
            // x4e4 in 100 ms and x1e46 in a second. Measured on a
            // rate-limited link it produced a 15.5 GB congestion window
            // and a 96-99% retransmission ratio on every scenario.
            //
            // So bound the rate by what the path has actually been
            // observed to deliver. This is a guardrail, not control: it
            // leaves the model free to probe up to RATE_PROBE_CEILING x
            // the measured delivery rate, and it is self-raising, since
            // delivering more lifts the bound. It cannot be expressed as
            // a better-trained policy — nothing in the loop enforced a
            // ceiling at all.
            // The action is a gain on the *measured delivery rate*, not a
            // multiplier on the current rate.
            //
            // As a compounding multiplier the action's meaning depended on
            // the RTT: it is applied once per 5 ms SYN interval regardless
            // of path length, so the gain per round trip is
            // `m^(rtt / 5ms)` — the 60th power at a 300 ms RTT. The band of
            // outputs that neither collapses nor diverges is the whole
            // action range at 1 ms and about 1.5% of it at 300 ms, and no
            // policy can be trained to land inside a target that narrow.
            // Worse, "hold steady" was not a fixed output: it was 1.0 at
            // every RTT, but the *distance* from 1.0 to ruin shrank with
            // RTT, so the same policy was gentle on a LAN and explosive on
            // a satellite path.
            //
            // As a gain on delivery it is RTT-invariant and does not
            // compound. One bad action costs one interval instead of
            // starting an excursion, and the fixed point of `rate <-
            // g * delivered` is the path's actual delivery rate, which is
            // where a controller should sit. This is BBR's pacing-gain
            // shape; the 0.5-2.0 range the network already emits maps onto
            // it directly, so the weight format is unchanged.
            //
            // RATE_PROBE_CEILING is now implied — a gain of at most 2.0 on
            // the delivery rate *is* the ceiling — so it is applied only on
            // the fallback path below, where no delivery estimate exists.
            self.update_loss_comp();
            let mut new_rate = if self.btlbw > 0 {
                (multiplier * self.loss_comp * self.btlbw as f64).max(1.0)
            } else {
                // No delivery measurement yet (first intervals). Fall back
                // to the compounding form, still bounded, until one exists.
                (current_rate * multiplier).max(1.0).min(current_rate * RATE_PROBE_CEILING)
            };
            // Apply the progress floor last, so it also overrides the
            // delivery-rate ceiling: when delivery has collapsed the
            // ceiling is itself near zero, and clamping to it is exactly
            // what makes the collapse unrecoverable.
            let rtt_s = (rtt_us.max(1) as f64) / 1_000_000.0;
            let floor_rate = MIN_PACED_PKTS_PER_RTT * self.mss as f64 / rtt_s;
            new_rate = new_rate.max(floor_rate);
            self.pkt_snd_period = self.mss as f64 * 1_000_000.0 / new_rate;

            if has_model {
                self.record_trace(state, multiplier);
            }
        } else {
            // Fallback: UDT rate increase.
            self.udt_rate_increase();
        }

        // Bound both paths, not just the learned one.
        //
        // The ceiling and floor used to live inside the `has_model` branch,
        // on the assumption that the fallback was inherently safe. It is
        // not: with a 10 MB/s path held constant, `udt_rate_increase` runs
        // to 1.42 GB/s — 135x the delivery rate — because nothing in it is
        // bounded by what the path returns.
        //
        // That went unnoticed because the guardrail test happened to load
        // weights, so it only ever exercised the RL branch. Bumping the
        // weight magic made every pre-existing weight file fail to load,
        // which sent the controller down the fallback and surfaced it
        // immediately. A fallback reached by rejecting bad input has to be
        // at least as safe as the path it replaces, or the rejection makes
        // things worse rather than better.
        let mut rate = 1_000_000.0 * self.mss as f64 / self.pkt_snd_period.max(f64::MIN_POSITIVE);
        if self.btlbw > 0 {
            rate = rate.min(self.btlbw as f64 * RATE_PROBE_CEILING);
        }
        let rtt_s = (rtt_us.max(1) as f64) / 1_000_000.0;
        rate = rate.max(MIN_PACED_PKTS_PER_RTT * self.mss as f64 / rtt_s);
        self.pkt_snd_period = self.mss as f64 * 1_000_000.0 / rate.max(1.0);

        // Update cwnd from the BDP.
        //
        // Two changes from the UDT v3 rule this inherited, both measured.
        //
        // First, the BDP is computed from min_rtt, not srtt. srtt inflates
        // under queueing, so `4 x rate x srtt` is a positive feedback loop:
        // a larger window builds more queue, which raises srtt, which
        // enlarges the window. On the 25 ms cross-country path the window
        // reached 3138 KB against a true BDP of 312 KB — 10x — with srtt
        // sitting at 53.4 ms, almost exactly `4 x rate x srtt`. This is the
        // same self-referential shape already removed from model.rs (a
        // bandwidth sample derived from bytes_in_flight) and from
        // classic.rs (a headroom test against cwnd/srtt): an estimate that
        // reads back the controller's own effect on the path and treats it
        // as a property of the path. min_rtt approximates propagation
        // delay, which the window cannot change.
        //
        // Second, the gain drops from 4x to 2x. 4x BDP of in-flight data on
        // a bottleneck with a BDP-sized queue is three BDPs of standing
        // queue, which is a full buffer by construction. 2x matches the
        // bound classic.rs applies and BBR's steady-state cwnd_gain, and
        // leaves the pacing rate — which is bounded at `gain x btlbw` — as
        // the thing that actually controls the send rate, with the window
        // as a safety bound rather than the operating point.
        //
        // Without this the rate bound is decorative: the pacer was held at
        // ~1.075x capacity while the window let 60% of transmitted packets
        // be retransmissions.
        let rate_for_cwnd = self.rcv_rate.max(
            (1_000_000.0 / self.pkt_snd_period) as u64
        );
        let cwnd_rtt_us = self
            .rtt
            .min_rtt()
            .map(|r| r.as_micros() as u64)
            .filter(|r| *r > 0)
            .unwrap_or(rtt_us);
        if rate_for_cwnd > 0 {
            let bdp = rate_for_cwnd as f64 / 1_000_000.0
                * (cwnd_rtt_us + syn_us) as f64
                + 16.0;
            // `.min`, not `.max`. max_cwnd is a cap everywhere else in this
            // file — two other sites clamp cwnd *down* to it — and only here
            // was it applied as a floor, which is what its name says it is
            // not. It starts at 1024 packets, ratchets up by 1.25x and
            // never decreases. (It was also set by seed_bandwidth from
            // smoothed RTT; that seed has been removed.)
            //
            // Measured after the delivery estimator was fixed, the floor was
            // what set the window in every scenario:
            //
            //   scenario         cwnd     = pkts   2 x BDP
            //   cross-country    1414 KB   1024     624 KB   <- 1024 exactly
            //   transatlantic    2209 KB   1600    1250 KB
            //   satellite        5393 KB   3906    3750 KB
            //   degraded         3452 KB   2500    2500 KB
            //
            // INITIAL_CWND_PKTS keeps a small absolute floor so the window
            // cannot collapse to nothing on a path whose BDP estimate is
            // briefly near zero.
            self.cwnd = (bdp * self.cwnd_bdp_gain)
                .min(self.max_cwnd)
                .max(INITIAL_CWND_PKTS);
        }

        // Grow max_cwnd dynamically, up to a ceiling derived from the
        // measured BDP rather than from a constant.
        //
        // The ceiling is computed from `btlbw` and `min_rtt`, not from
        // `pkt_snd_period` and `srtt`. That distinction is the whole point:
        // the pacing period is set from this window, and the smoothed RTT
        // rises with the queue this window builds, so a ceiling derived
        // from either is a bound that moves with the thing it is bounding —
        // the defect shape this file has been carrying in five other
        // places. `btlbw` is a windowed maximum of *delivered* bytes and
        // cannot exceed what the path carried.
        //
        // The growth trigger below still uses the pacing-derived estimate,
        // because it is only asking "is the window close to binding?" — a
        // question about this controller's own state, which is what that
        // estimate legitimately describes.
        let rate_pps = 1_000_000.0 / self.pkt_snd_period;
        let bdp_pkts = rate_pps / 1_000_000.0 * (rtt_us + syn_us) as f64 + 16.0;

        let measured_bdp_pkts = match self.rtt.min_rtt() {
            Some(m) if self.btlbw > 0 => {
                self.btlbw as f64 * m.as_secs_f64() / self.mss as f64
            }
            _ => 0.0,
        };
        let ceiling = (measured_bdp_pkts * MAX_CWND_BDP_MULT)
            .max(MAX_CWND_FLOOR_PKTS)
            .min(MAX_CWND_HARD_PKTS);

        if bdp_pkts > self.max_cwnd * 0.8 && self.max_cwnd < ceiling {
            self.max_cwnd = (self.max_cwnd * 1.25).min(ceiling);
        }
        // `max_cwnd` is a high-water mark and does **not** follow the
        // ceiling downward.
        //
        // It briefly did. The reasoning was that `btlbw` is a windowed
        // maximum, so a genuine capacity drop should be allowed to shrink a
        // window sized for capacity that no longer exists. Measured at
        // 1 Gbit, that clamp cost `rl` cross-country 94.3 -> 28.6 MiB/s and
        // transatlantic 69.0 -> 18.0.
        //
        // The clamp closes the loop it was written to avoid. `btlbw`
        // measures *delivery*, and delivery is bounded by the window
        // whenever the window is what limits — so a window reduced for any
        // reason lowers delivery, which lowers `btlbw`, which lowers the
        // ceiling, which clamps the window again. Each gain-cycle drain
        // phase supplies the initial dip. It is a downward ratchet, and the
        // exact mirror of the runaway the ceiling exists to prevent: the
        // defect class this crate has now produced in seven places, and the
        // first time it was introduced by a change whose own comment
        // claimed to be avoiding it.
        //
        // `btlbw` is a sound *capacity* estimate only while the window is
        // not the binding limit. Bounding the window with it is therefore
        // safe upward — the estimate can only be too low, so the bound can
        // only be too generous — and unsound downward.

        self.sync_pacer();

        // Save state for gradient computation.
        self.prev_smoothed_rtt = self.rtt.smoothed_rtt();
        self.prev_delivery_rate = self.delivery_rate;

        // Decay loss counters using EWMA (factor 0.875) to avoid
        // integer truncation bias that underestimates sustained loss.
        if self.recent_ack_count > 1000 {
            self.recent_loss_count = (self.recent_loss_count as f64 * 0.875) as u64;
            self.recent_ack_count = (self.recent_ack_count as f64 * 0.875) as u64;
        }
    }

    fn on_packet_lost(&mut self, lost: &[u64], _now: Instant) {
        let lost_bytes = lost.len() * MTU;
        self.bytes_in_flight = self.bytes_in_flight.saturating_sub(lost_bytes);
        self.recent_loss_count += lost.len() as u64;

        if lost.is_empty() {
            return;
        }

        // Exit slow start on first loss.
        if self.slow_start {
            self.slow_start = false;
            // Left as an assignment to `max_cwnd`, which is wrong in
            // principle and still measures best.
            //
            // A first loss while the window is small *raises* it here --
            // 16 packets to max_cwnd's initial 1024, a 64x growth event on
            // the back-off path, and on a 0.5-5% loss path the first loss
            // lands inside the first window essentially always. It should
            // settle at the window measured delivery implies, as Classic's
            // plateau exit and Model's target_cwnd do.
            //
            // Two replacements were built and measured twice: once while
            // the gain cycle's probe was inert, and again after 5a63dff
            // fixed it. The first round of measurements was worthless and
            // is recorded here because the conclusion drawn from it was
            // wrong. With the probe disabled, wherever the ramp latched was
            // permanent, so this assignment's oversized window was the only
            // thing that could reach a high rate at all:
            //
            //                            probe inert        probe working
            //   cwnd = max_cwnd          7.03 / 7.53      9.03 / 9.63 MB/s
            //   cwnd.min(max_cwnd)       5.27 / 3.53      8.20 / 7.57
            //   bdp * CWND_BDP_GAIN      7.10 / 4.75      8.23 / 8.23
            //                            (3 of 6 timeouts)  (0 timeouts)
            //
            // satellite / degraded, 3 runs each. The BDP variant was
            // rejected the first time for being unstable. It is not: the
            // instability was the frozen latch, and it disappeared when the
            // probe started working. Delay is within noise across all three
            // (1.18-1.25x), so the choice rests on throughput, where this
            // still leads by about 1 MB/s.
            //
            // Keep `max_cwnd` for the measured case. It is wrong in
            // principle and it still measures best, and the reason is now
            // understood rather than guessed.
            //
            // Putting the constant against each path's BDP says what the
            // winning value actually is -- 1024 packets is 0.66x BDP on
            // satellite and 0.98x on degraded, and one BDP beat both
            // alternatives there (9.03/9.63 against 8.23/8.23 for
            // `bdp * CWND_BDP_GAIN` and 8.20/7.57 for a strict
            // non-growing rule). So the rule ought to be "settle at one
            // measured BDP".
            //
            // It is not, because the measurement is depressed by the very
            // loss that triggers this exit. `btlbw` is a max filter over
            // *delivered* bytes, so on a 5% path it reads well below
            // capacity, and a small window depresses it further: window ->
            // delivery -> btlbw -> window is a closed loop with a low fixed
            // point. Implementing `bdp * 1.0` here took RL on the degraded
            // path from 33.2% of the link to 11.1% in simulation -- a
            // three-fold drop, far outside the simulator's grading spread.
            //
            // The constant works *because* it is exogenous. That is the
            // same reason the pacer's burst overshoot was load-bearing
            // before defect 1: an injected value breaks a self-referential
            // estimate. The honest fix is a capacity estimate that does not
            // depend on the window -- packet-pair probing, or the receiver
            // rate on a path where that is trustworthy -- and not a
            // different gain on this one.
            self.cwnd = match (self.rtt.min_rtt(), self.btlbw) {
                // Nothing measured yet: no basis to change the window at
                // all, and assigning `max_cwnd` here is a 64x growth event
                // on the back-off path. The window is not stranded --
                // the periodic update recomputes it from
                // `bdp * CWND_BDP_GAIN` as soon as `btlbw` is non-zero.
                (None, _) | (_, 0) => self.cwnd,
                _ => self.max_cwnd,
            };
            if self.rcv_rate > 0 {
                let rcv_period = 1_000_000.0 / self.rcv_rate as f64;
                if rcv_period < self.pkt_snd_period {
                    self.pkt_snd_period = rcv_period;
                }
            }
            self.sync_pacer();
            return;
        }

        // Only trigger rate decrease on significant loss (≥3 packets).
        if lost.len() < 3 {
            return;
        }

        let first_loss = lost[0];
        if matches!(self.last_dec_seq, Some(last) if first_loss <= last) {
            return;
        }

        // Back off only when the loss came with a queue.
        //
        // The rate law is `rate <- gain * btlbw` on *measured delivery*, so
        // congestion is already priced in: when the bottleneck saturates,
        // delivery stops rising and the rate stops with it. A UDT-style
        // multiplicative decrease layered on top double-counts congestion,
        // and — worse — it cannot tell congestion loss from random loss.
        //
        // On the 5%-loss `degraded` path that made the controller command
        // 18-21 Mbit of a 100 Mbit link, at an equilibrium where the 7.5%
        // gain per tick balanced repeated 11% cuts. The pacer was faithful
        // (commanded/achieved 0.94), so this was the controller asking for
        // a fifth of the link. The same defect produced the opposite
        // symptom at 0.5% loss, where the cut almost never fired and the
        // controller sat at `gain * capacity` with a permanently full
        // queue.
        //
        // Standing queue is the signal that separates the two, so require
        // it. Below the gate, loss is treated as the path's own and the
        // delivery-rate law is left to do its job; above it, the decrease
        // fires as before.
        // No RTT estimate yet: keep the historical behaviour rather than
        // silently disabling the loss response.
        if !self.queue_above_budget() {
            return;
        }

        self.loss_flag = true;
        self.last_dec_seq = Some(self.snd_curr_seq);
        self.pkt_snd_period = (self.pkt_snd_period * LOSS_INCREASE_FACTOR).ceil();
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
            "slow_start={} phase={:?} arm[gain={:.2} rtts={:.0}] src={} \
cwnd={:.0}pkt max_cwnd={:.0}pkt \
rate={:.2}Mbit btlbw={:.2}Mbit rcv_rate={:.2}Mbit comp={:.3} \
srtt={:.1}ms min_rtt={:.1}ms infl={:.2} period={:.1}us",
            self.slow_start,
            self.cycle_phase,
            // The cycle parameters actually in force, and where they came
            // from. Without this a forced arm or a loaded policy is
            // indistinguishable from the default in a trace — the failure
            // that turned six parameter sweeps into no-ops.
            self.active_arm().probe_gain,
            self.active_arm().probe_rtts,
            if self.forced_arm.is_some() {
                "forced"
            } else if self.cycle_policy.is_some() {
                "policy"
            } else {
                "shipped"
            },
            self.cwnd,
            self.max_cwnd,
            self.rate_bps() as f64 * 8.0 / 1e6,
            self.btlbw as f64 * 8.0 / 1e6,
            self.rcv_rate as f64 * self.mss as f64 * 8.0 / 1e6,
            self.loss_comp,
            srtt_us as f64 / 1000.0,
            min_us as f64 / 1000.0,
            if min_us > 0 { srtt_us as f64 / min_us as f64 } else { 0.0 },
            self.pkt_snd_period,
        ))
    }

    /// RL opts in to timeout-detected loss.
    ///
    /// It was opted out, so the controller never observed the primary
    /// congestion signal — `on_packet_lost` (which does slow the rate)
    /// was only ever reached via receiver-detected loss. The measured
    /// consequence: when a sender fix restored loss *detection*, Classic
    /// converted it into recovery (+170% on a 5 ms path) while RL, unable
    /// to see it, converted it into more flooding (-57% on a 100 ms
    /// path). Now that the retransmit timer is RTT-derived rather than a
    /// fixed 100 ms, a timeout is credible evidence of a drop.
    fn wants_timeout_loss(&self) -> bool { true }

}

/// Get the favonius config directory (~/.config/favonius/).
fn dirs_config() -> Option<PathBuf> {
    std::env::var("HOME").ok().map(|h| {
        PathBuf::from(h).join(".config").join("favonius")
    })
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
        let cc = RlController::new();
        assert!(cc.slow_start);
        assert!(cc.congestion_window() > 0);
        assert!(cc.send_rate().unwrap() > 0);
    }

    /// Without a model the controller is the constant-gain controller.
    ///
    /// This asserted 1.0 — a no-op handing over to UDT-style logic. 1.0 is
    /// precisely the wrong constant: the steady state of `rate <- g * btlbw`
    /// at g = 1.0 is whatever rate the controller already had, so it never
    /// probes upward and can never recover an undershoot. The gain has to
    /// exceed 1.0 to be a controller at all, and it has to stay inside the
    /// band where the excess does not become a standing overdrive, since the
    /// permanent loss fraction is (g-1)/g.
    #[test]
    fn without_a_model_the_gain_is_a_controller_not_a_no_op() {
        // `RlController::new()` falls back to `~/.config/favonius/rl_weights.bin`,
        // so clear the model explicitly rather than relying on that file being
        // absent — otherwise this test fails on any machine that has ever run a
        // transfer.
        let mut cc = RlController::new();
        cc.weights = None;
        cc.mode = RlMode::Exploit;
        let state = [0.0; INPUT_DIM];
        assert_eq!(cc.get_action(&state), DEFAULT_GAIN);
        assert!(DEFAULT_GAIN > 1.0, "a gain of 1.0 or less never probes upward");
        assert!(
            DEFAULT_GAIN <= 1.15,
            "steady-state loss is (g-1)/g = {:.1}% — a standing overdrive",
            100.0 * (DEFAULT_GAIN - 1.0) / DEFAULT_GAIN
        );
        assert!(DEFAULT_GAIN >= ACTION_MIN && DEFAULT_GAIN <= ACTION_MAX,
                "the default must be reachable by a learned policy too");
    }

    #[test]
    fn mlp_forward_produces_valid_range() {
        // Create synthetic weights (all small values).
        let weights = MlpWeights {
            w1: vec![0.01; INPUT_DIM * HIDDEN1_DIM],
            b1: vec![0.0; HIDDEN1_DIM],
            w2: vec![0.01; HIDDEN1_DIM * HIDDEN2_DIM],
            b2: vec![0.0; HIDDEN2_DIM],
            w3: vec![0.01; HIDDEN2_DIM],
            b3: 0.0,
        };

        let state = [0.5; INPUT_DIM];
        let result = weights.forward(&state);
        assert!(result >= ACTION_MIN, "result {} < {}", result, ACTION_MIN);
        assert!(result <= ACTION_MAX, "result {} > {}", result, ACTION_MAX);
    }

    #[test]
    fn weight_save_load_round_trip() {
        let weights = MlpWeights {
            w1: vec![0.1; INPUT_DIM * HIDDEN1_DIM],
            b1: vec![0.2; HIDDEN1_DIM],
            w2: vec![0.3; HIDDEN1_DIM * HIDDEN2_DIM],
            b2: vec![0.4; HIDDEN2_DIM],
            w3: vec![0.5; HIDDEN2_DIM],
            b3: 0.6,
        };

        let dir = std::env::temp_dir();
        let path = dir.join("test_rl_weights.bin");
        weights.save(&path).unwrap();

        let loaded = MlpWeights::load(&path).expect("should load");
        assert_eq!(loaded.w1.len(), weights.w1.len());
        assert!((loaded.b3 - 0.6).abs() < 1e-10);

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn state_vector_is_bounded() {
        let mut cc = RlController::new();
        cc.on_rtt_update(Duration::from_millis(10));
        cc.delivery_rate = 50_000_000;
        cc.recent_ack_count = 100;
        cc.recent_loss_count = 5;
        cc.prev_smoothed_rtt = Some(Duration::from_millis(8));
        cc.prev_delivery_rate = 48_000_000;

        let state = cc.compute_state();
        for (i, &v) in state.iter().enumerate() {
            assert!(v >= -1.0 && v <= 10.0,
                "state[{}] = {} out of expected range", i, v);
        }
    }

    #[test]
    fn slow_start_grows_cwnd() {
        let mut cc = RlController::new();
        let now = Instant::now();
        cc.on_rtt_update(Duration::from_millis(10));

        let initial = cc.cwnd;
        cc.on_packet_sent(1, MTU, now);
        let t = now + SYN_INTERVAL + Duration::from_millis(1);
        cc.on_ack_received(&ack(1, MTU as u64, 50_000_000), t);

        assert!(cc.cwnd > initial);
    }

    #[test]
    fn loss_exits_slow_start() {
        let mut cc = RlController::new();
        let now = Instant::now();
        cc.on_rtt_update(Duration::from_millis(10));
        cc.on_packet_sent(1, MTU, now);

        assert!(cc.slow_start);
        cc.on_packet_lost(&[1], now + Duration::from_millis(50));
        assert!(!cc.slow_start);
    }

    #[test]
    fn epoch_suppression_in_chunk_index_space() {
        let mut cc = RlController::new();
        let now = Instant::now();
        // Establish a standing queue: this test is about loss *epochs*, and
        // the decrease is now gated on srtt/min_rtt >= LOSS_QUEUE_GATE, so
        // without a queue every decrease below would be correctly skipped
        // and the test would pass for the wrong reason.
        cc.on_rtt_update(Duration::from_millis(10));
        for _ in 0..4 {
            cc.on_rtt_update(Duration::from_millis(40));
        }
        cc.slow_start = false;
        cc.pkt_snd_period = 20.0;

        // Packet numbers are global chunk indices (0-based).
        for i in 0..20 {
            cc.on_packet_sent(i, MTU, now);
        }
        // First loss: period increases, epoch marked at chunk index 19.
        cc.on_packet_lost(&[1, 2, 3], now);
        let period_after_first = cc.pkt_snd_period;
        assert!(period_after_first > 20.0);

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

    /// Loss without a queue must not slow the rate.
    ///
    /// On the 5%-loss `degraded` rig path the ungated decrease pinned the
    /// controller at 18-21 Mbit of a 100 Mbit link: random loss fired the
    /// 11% cut often enough to cancel the 7.5% per-tick gain, and the pacer
    /// delivered that faithfully (commanded/achieved 0.94). Nothing about
    /// that loss was evidence of congestion — the queue was empty
    /// throughout, srtt/min_rtt 1.07.
    #[test]
    fn loss_backoff_gated_by_standing_queue() {
        let now = Instant::now();

        // Empty queue: srtt == min_rtt, ratio 1.0. Rate must hold.
        let mut drained = RlController::new();
        drained.on_rtt_update(Duration::from_millis(100));
        drained.slow_start = false;
        drained.pkt_snd_period = 20.0;
        for i in 0..20 {
            drained.on_packet_sent(i, MTU, now);
        }
        drained.on_packet_lost(&[1, 2, 3], now);
        assert_eq!(
            drained.pkt_snd_period, 20.0,
            "random loss on a drained path must not slow the rate"
        );

        // Same loss, same controller, but with a full queue: ratio well
        // above the gate, so this *is* a congestion signal and the
        // historical decrease must still apply.
        let mut queued = RlController::new();
        queued.on_rtt_update(Duration::from_millis(100));
        for _ in 0..8 {
            queued.on_rtt_update(Duration::from_millis(200));
        }
        queued.slow_start = false;
        queued.pkt_snd_period = 20.0;
        for i in 0..20 {
            queued.on_packet_sent(i, MTU, now);
        }
        assert!(
            queued.queue_above_budget(),
            "test setup: queue is within budget, so the gate correctly \
             declines and this would assert the ungated behaviour"
        );
        queued.on_packet_lost(&[1, 2, 3], now);
        assert!(
            queued.pkt_snd_period > 20.0,
            "loss with a standing queue must still back off"
        );
    }
}

#[cfg(test)]
mod shipped_model_tests {
    use super::*;

    /// Load the retired `AHPRL001` weight set, if it is present.
    ///
    /// It no longer ships — no weight file does — so these tests skip in a
    /// clean checkout. They are kept because they are the evidence for why
    /// that weight set was retired, and they will need to run again against
    /// whatever first passes the trainer's baseline gate.
    ///
    /// Note this returns None even if the file is restored: the magic moved
    /// to AHPRL002 and `MlpWeights::load` now rejects the old header. To run
    /// them against a historical file, check it out and rewrite the magic.
    fn shipped() -> Option<MlpWeights> {
        let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("weights/rl_weights_v2.bin");
        MlpWeights::load(&p)
    }

    /// Sweep the model over a spread of plausible path states and report
    /// the spread of rate multipliers it produces.
    ///
    /// This exists because of how the model was trained: the offline
    /// trainer (`training/train_rl.py`) replays recorded traces, and its
    /// `step()` advances to the next recorded sample regardless of the
    /// action taken, so the reward carries no information about what an
    /// action actually did.
    ///
    /// The tempting conclusion — that the reward-maximising policy is
    /// therefore the constant 1.0, making the controller a no-op — is
    /// **not** what the shipped weights do. Measured over 1024 sampled
    /// states they span roughly [0.56, 2.00] with a standard deviation
    /// near 0.36, and only ~5% of states land within ±0.05 of 1.0. PPO
    /// did not converge to the degenerate optimum; the distillation step
    /// then fitted whatever state-dependent surface it had found.
    ///
    /// So the model is not inert — it is *ungrounded*: a confident,
    /// varying mapping from state to rate that was never scored against
    /// its own consequences. That is the harder problem to spot, which is
    /// why this test records the numbers rather than asserting a bound.
    #[test]
    fn shipped_model_action_range() {
        let Some(w) = shipped() else {
            eprintln!("shipped weights missing or unreadable — skipping");
            return;
        };

        // 8-dim state: [srtt, min_rtt, rtt_grad, dr, dr_grad, loss,
        //               inflight_ratio, queue_delay]. All normalised.
        let mut actions = Vec::new();
        for &srtt in &[0.001f64, 0.05, 0.2, 0.6] {
            for &dr in &[0.0f64, 0.05, 0.3, 0.9] {
                for &loss in &[0.0f64, 0.02, 0.1, 0.4] {
                    for &qd in &[0.0f64, 0.05, 0.3, 0.9] {
                        for &infl in &[0.0f64, 0.5, 1.0, 1.9] {
                            let s = [srtt, srtt * 0.8, 0.0, dr, 0.0, loss, infl, qd];
                            actions.push(w.forward(&s));
                        }
                    }
                }
            }
        }

        let n = actions.len() as f64;
        let min = actions.iter().cloned().fold(f64::INFINITY, f64::min);
        let max = actions.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
        let mean = actions.iter().sum::<f64>() / n;
        let var = actions.iter().map(|a| (a - mean).powi(2)).sum::<f64>() / n;
        let near_one = actions.iter().filter(|a| (**a - 1.0).abs() < 0.05).count();

        println!(
            "shipped RL model over {} states: min={:.4} max={:.4} mean={:.4} \
             sd={:.4} spread={:.4} within±0.05 of 1.0: {}/{}",
            actions.len(), min, max, mean, var.sqrt(), max - min,
            near_one, actions.len()
        );

        // The action space is [0.5, 2.0]; a controller that actually
        // controls should use a noticeable slice of it.
        assert!(
            (ACTION_MIN..=ACTION_MAX).contains(&min) && (ACTION_MIN..=ACTION_MAX).contains(&max),
            "actions escaped the declared range"
        );
    }
    /// Does the policy respond sensibly to the two signals a congestion
    /// controller exists to react to — loss and queueing delay?
    ///
    /// A controller that raises its rate as loss climbs is not a
    /// conservative controller or an aggressive one; it is an unsteered
    /// one. This is the check the training pipeline cannot make for
    /// itself, because its reward never observed what an action did.
    #[test]
    fn shipped_model_response_to_loss_and_queueing() {
        let Some(w) = shipped() else { return };

        let base = |loss: f64, qd: f64| -> f64 {
            // Mid-range path, sweep one signal at a time.
            w.forward(&[0.1, 0.08, 0.0, 0.3, 0.0, loss, 1.0, qd])
        };

        println!("\n  loss ->  action        queue_delay ->  action");
        let losses = [0.0, 0.01, 0.02, 0.05, 0.10, 0.20, 0.40];
        let qds = [0.0, 0.01, 0.02, 0.05, 0.10, 0.20, 0.40];
        for i in 0..losses.len() {
            println!(
                "  {:>5.2}  {:>7.4}        {:>11.2}  {:>7.4}",
                losses[i], base(losses[i], 0.0), qds[i], base(0.0, qds[i])
            );
        }

        let loss_lo = base(0.0, 0.0);
        let loss_hi = base(0.40, 0.0);
        let qd_lo = base(0.0, 0.0);
        let qd_hi = base(0.0, 0.40);
        println!(
            "\n  loss 0%->40%: {:.4} -> {:.4} ({})",
            loss_lo, loss_hi,
            if loss_hi < loss_lo { "backs off (sane)" } else { "SPEEDS UP as loss rises" }
        );
        println!(
            "  queue 0->0.4: {:.4} -> {:.4} ({})\n",
            qd_lo, qd_hi,
            if qd_hi < qd_lo { "backs off (sane)" } else { "SPEEDS UP as the queue grows" }
        );
    }
}

#[cfg(test)]
mod guardrail_tests {
    use super::*;

    fn ack(pn: u64, delivered: u64, rate: u64) -> AckInfo {
        AckInfo {
            packet_number: pn,
            ack_delay: Duration::ZERO,
            delivered_bytes: delivered,
            delivery_rate: rate,
        }
    }

    /// The compounding multiplier must not diverge.
    ///
    /// Before the ceiling, `rate *= model_output` ran once per 5 ms with
    /// no upper bound, so any policy averaging above 1.0 grew the rate
    /// geometrically — the shipped model's typical 1.70 reaches x4e4 in
    /// 100 ms. On a rate-limited link that produced a 15.5 GB window and
    /// 96-99% retransmissions.
    #[test]
    fn rate_cannot_run_away_past_measured_delivery() {
        let mut cc = RlController::new();
        let mut now = Instant::now();
        // A path delivering 10 MB/s, held constant.
        const DELIVERED: u64 = 10 * 1024 * 1024;

        cc.on_rtt_update(Duration::from_millis(50));
        for i in 0..2000u64 {
            now += Duration::from_millis(6); // one SYN interval apart
            cc.on_packet_sent(i, MTU, now);
            cc.on_ack_received(&ack(i, MTU as u64, DELIVERED), now);
        }

        let rate = cc.rate_bps() as f64;
        let ceiling = DELIVERED as f64 * RATE_PROBE_CEILING;
        println!(
            "  after 2000 rate-control steps: {:.1} MB/s (ceiling {:.1} MB/s)",
            rate / 1e6, ceiling / 1e6
        );
        assert!(
            rate <= ceiling * 1.05,
            "rate {rate:.0} escaped the {ceiling:.0} ceiling — the multiplier is diverging"
        );
    }

    /// A loss report on chunk 0 must not be silently ignored.
    #[test]
    fn first_loss_of_a_transfer_is_not_swallowed() {
        let mut cc = RlController::new();
        let now = Instant::now();
        // A standing queue, so the decrease is not skipped by
        // LOSS_QUEUE_GATE — this test is about the epoch guard, and an
        // empty queue would make it pass without ever reaching that guard.
        cc.on_rtt_update(Duration::from_millis(50));
        for _ in 0..8 { cc.on_rtt_update(Duration::from_millis(150)); }
        for i in 0..64 { cc.on_packet_sent(i, MTU, now); }
        cc.slow_start = false;
        assert_eq!(cc.last_dec_seq, None);

        let before = cc.pkt_snd_period;
        cc.on_packet_lost(&[0, 1, 2], now);
        assert!(
            cc.pkt_snd_period > before,
            "loss at chunk 0 was swallowed by the epoch guard"
        );
    }

    /// Loss compensation must engage on a drained lossy path, and must not
    /// engage behind a standing queue.
    ///
    /// The second half is the safety property: compensating for loss the
    /// controller itself caused is a positive feedback loop — overdrive
    /// causes loss, loss raises the compensation, compensation causes more
    /// overdrive.
    #[test]
    fn loss_compensation_only_applies_to_a_drained_path() {
        // Drained path losing 5%: compensation rises toward 1/(1-p).
        let mut drained = RlController::new();
        drained.on_rtt_update(Duration::from_millis(100));
        drained.recent_ack_count = 950;
        drained.recent_loss_count = 50;
        for _ in 0..100 {
            drained.update_loss_comp();
        }
        assert!(
            (drained.loss_comp - 1.0 / 0.95).abs() < 0.005,
            "expected ~{:.4}, got {:.4}",
            1.0 / 0.95,
            drained.loss_comp
        );

        // Same loss rate, but behind a standing queue: no compensation.
        let mut queued = RlController::new();
        queued.on_rtt_update(Duration::from_millis(100));
        for _ in 0..8 {
            queued.on_rtt_update(Duration::from_millis(200));
        }
        queued.recent_ack_count = 950;
        queued.recent_loss_count = 50;
        queued.loss_comp = 1.0 / 0.95;
        for _ in 0..100 {
            queued.update_loss_comp();
        }
        assert!(
            (queued.loss_comp - 1.0).abs() < 0.005,
            "compensation must decay to 1.0 behind a queue, got {:.4}",
            queued.loss_comp
        );
    }

    /// The compensation is bounded even on an absurdly lossy path.
    #[test]
    fn loss_compensation_is_bounded() {
        let mut cc = RlController::new();
        cc.on_rtt_update(Duration::from_millis(100));
        cc.recent_ack_count = 100;
        cc.recent_loss_count = 900; // 90% loss
        for _ in 0..200 {
            cc.update_loss_comp();
        }
        assert!(
            cc.loss_comp <= LOSS_COMP_MAX + 1e-9,
            "compensation {} escaped LOSS_COMP_MAX",
            cc.loss_comp
        );
    }

    /// The cycle must visit all three phases and come back round.

    /// The ramp drives the estimate while it is climbing, then gets out of
    /// the way.
    ///
    /// Without it the estimate could only rise through the cycle's probe
    /// phase -- 1.25x for 2 of every 8 RTTs -- so it ratcheted by ~x1.21
    /// per *cycle*. On a 150 ms path that is 1.2 s per 25% step, and it
    /// cost 32% of goodput against Classic, whose recovery is clocked on
    /// the round trip.
    #[test]
    fn ramp_ends_and_hands_over_to_the_cycle() {
        let mut cc = RlController::new();
        let rtt = Duration::from_millis(100);
        cc.on_rtt_batch(rtt, rtt);
        let t0 = Instant::now();

        // A climbing estimate on an empty queue: the ramp drives.
        cc.btlbw = 10_000_000;
        assert_eq!(cc.advance_cycle(t0), RAMP_GAIN, "ramp should drive a climbing estimate");
        cc.btlbw = 20_000_000;
        assert_eq!(cc.advance_cycle(t0 + Duration::from_millis(150)), RAMP_GAIN);

        // Flat for RAMP_PLATEAU_ROUNDS round trips: the ramp gives up.
        let mut t = t0 + Duration::from_millis(150);
        for _ in 0..RAMP_PLATEAU_ROUNDS + 1 {
            t += Duration::from_millis(110);
            cc.advance_cycle(t);
        }
        assert!(!cc.ramp_active, "ramp should have plateaued");
        let g = cc.advance_cycle(t + Duration::from_millis(110));
        assert!(
            g == CYCLE_CRUISE_GAIN || g == CYCLE_PROBE_GAIN || g == CYCLE_DRAIN_GAIN,
            "after the ramp the ordinary cycle should run, got {g}"
        );
    }

    /// The ramp must not run into a queue it is building.
    #[test]
    fn ramp_yields_when_the_queue_is_not_empty() {
        let mut cc = RlController::new();
        let min = Duration::from_millis(100);
        // srtt well above min_rtt: a real standing queue.
        for _ in 0..20 {
            cc.on_rtt_batch(Duration::from_millis(400), min);
        }
        cc.btlbw = 10_000_000;
        assert!(cc.queue_above_budget(), "test premise: a queue exists");
        let g = cc.advance_cycle(Instant::now());
        assert_ne!(g, RAMP_GAIN, "ramp ran while the queue was full");
    }

    #[test]
    fn gain_cycle_advances_through_its_phases() {
        let mut cc = RlController::new();
        cc.on_rtt_update(Duration::from_millis(100));
        let t0 = Instant::now();
        // The ramp is a separate mechanism and intercepts `advance_cycle`
        // while the estimate is still climbing; these are cycle tests, so
        // it is switched off. `ramp_ends_and_hands_over_to_the_cycle`
        // covers the handover.
        cc.ramp_active = false;

        // min_rtt is 100 ms, so one RTT is 100 ms throughout.

        // Cruise for its full 4 RTTs, then probe.
        assert_eq!(cc.advance_cycle(t0), CYCLE_CRUISE_GAIN);
        assert_eq!(cc.advance_cycle(t0 + Duration::from_millis(300)), CYCLE_CRUISE_GAIN);
        let t_probe = t0 + Duration::from_millis(400);
        assert_eq!(cc.advance_cycle(t_probe), CYCLE_PROBE_GAIN);

        // Probe runs a full 2 RTTs — long enough for one whole delivery
        // sample to land inside it, which is the entire reason it is 2.
        assert_eq!(cc.advance_cycle(t_probe + Duration::from_millis(100)), CYCLE_PROBE_GAIN);
        let t_drain = t_probe + Duration::from_millis(200);
        assert_eq!(cc.advance_cycle(t_drain), CYCLE_DRAIN_GAIN);

        // srtt/min_rtt here is 1.0, so the queue reads drained and the
        // drain exits at its minimum length rather than at the bound.
        assert_eq!(cc.advance_cycle(t_drain + Duration::from_millis(100)), CYCLE_DRAIN_GAIN);
        assert_eq!(cc.advance_cycle(t_drain + Duration::from_millis(200)), CYCLE_CRUISE_GAIN);
    }

    /// The probe must run its full length regardless of inflight.
    ///
    /// It used to exit early once inflight passed 1.25x BDP, which happens
    /// almost immediately. The probe's purpose is to discover whether the
    /// path *delivers* more, and that answer arrives one round trip later
    /// in the ACKs -- so cutting it short on inflight ended it before its
    /// own result could exist. Measured: ProbeUp occupied 1 of 21 samples,
    /// and `btlbw` froze at half the link rate for a whole transfer.
    #[test]
    fn gain_cycle_probe_runs_its_full_length() {
        let mut cc = RlController::new();
        cc.on_rtt_update(Duration::from_millis(100));
        cc.cycle_phase = CyclePhase::ProbeUp;
        let t0 = Instant::now();
        // The ramp is a separate mechanism and intercepts `advance_cycle`
        // while the estimate is still climbing; these are cycle tests, so
        // it is switched off. `ramp_ends_and_hands_over_to_the_cycle`
        // covers the handover.
        cc.ramp_active = false;
        cc.phase_started = Some(t0);

        // 1 MB/s over 100 ms => 100 KB BDP. Put well over 1.25 BDP in
        // flight, which is what used to end the probe on the spot.
        cc.btlbw = 1_000_000;
        cc.bytes_in_flight = 400_000;

        assert_eq!(
            cc.advance_cycle(t0 + Duration::from_millis(10)),
            CYCLE_PROBE_GAIN,
            "probe ended early on inflight; it cannot observe its own effect"
        );
        assert_eq!(
            cc.advance_cycle(t0 + Duration::from_millis(150)),
            CYCLE_PROBE_GAIN,
            "probe should still be running before CYCLE_PROBE_RTTS elapses"
        );
        // Two min-RTTs is the nominal length.
        assert_eq!(
            cc.advance_cycle(t0 + Duration::from_millis(200)),
            CYCLE_DRAIN_GAIN,
            "probe should end once its full length has elapsed"
        );
    }

    /// The cycle must fit inside the bandwidth filter's horizon.
    ///
    /// The filter holds the delivery maximum over `10 * srtt`; the capacity
    /// sample latched during one probe has to survive until the next, or
    /// the drain's low delivery becomes the estimate and the controller
    /// ratchets itself down. `srtt >= min_rtt`, so comparing in min-RTTs is
    /// the worst case.
    #[test]
    fn gain_cycle_fits_inside_the_bandwidth_filter_horizon() {
        let worst_case =
            CYCLE_PROBE_RTTS + CYCLE_DRAIN_MAX_RTTS + CYCLE_CRUISE_RTTS;
        assert!(
            worst_case < 10.0,
            "cycle of {worst_case} RTTs does not fit in the 10-RTT filter horizon"
        );
    }

    /// Mean gain over a nominal cycle must be 1.0 — no standing overdrive.
    #[test]
    fn gain_cycle_has_unit_mean() {
        let total = CYCLE_PROBE_GAIN * CYCLE_PROBE_RTTS
            + CYCLE_DRAIN_GAIN * CYCLE_DRAIN_RTTS
            + CYCLE_CRUISE_GAIN * CYCLE_CRUISE_RTTS;
        let rtts = CYCLE_PROBE_RTTS + CYCLE_DRAIN_RTTS + CYCLE_CRUISE_RTTS;
        assert!(
            (total / rtts - 1.0).abs() < 1e-9,
            "mean gain {} is not 1.0 — a constant offset is exactly what cycling exists to remove",
            total / rtts
        );
    }

    /// Leaving slow start on loss must not enlarge the window.
    ///
    /// `cwnd = max_cwnd` was an assignment, so a first loss while the
    /// window was still small raised it from 16 packets to max_cwnd's
    /// initial 1024 -- a 64x growth event on the loss path. On a
    /// 0.5-5% loss path the first loss lands inside the first window
    /// essentially always, so this was the normal case.
    #[test]
    fn slow_start_loss_exit_never_grows_the_window() {
        let mut cc = RlController::new();
        let now = Instant::now();
        cc.on_rtt_update(Duration::from_millis(25));
        assert!(cc.slow_start, "test premise: still in slow start");

        let before = cc.cwnd;
        assert!(
            before < cc.max_cwnd,
            "test premise: window {before} below the cap {}",
            cc.max_cwnd
        );
        for i in 0..8 {
            cc.on_packet_sent(i, MTU, now);
        }
        cc.on_packet_lost(&[0, 1, 2], now);

        assert!(!cc.slow_start, "loss should have ended slow start");
        assert!(
            cc.cwnd <= before,
            "window grew from {before} to {} on a loss, with nothing measured",
            cc.cwnd
        );
    }


    /// RL must see timeout-detected loss at all.
    #[test]
    fn rl_opts_in_to_timeout_loss() {
        assert!(RlController::new().wants_timeout_loss());
    }
}

#[cfg(test)]
mod progress_floor_tests {
    use super::*;

    fn ack(pn: u64, rate: u64) -> AckInfo {
        AckInfo {
            packet_number: pn,
            ack_delay: Duration::ZERO,
            delivered_bytes: MSS as u64,
            delivery_rate: rate,
        }
    }

    /// A policy that always backs off must not be able to stop the sender.
    ///
    /// Before the floor, a sustained sub-1.0 multiplier drove the rate to
    /// 1 byte/s on a high-RTT path within ~20 control intervals, and
    /// nothing recovered it: the delivery-rate ceiling caps a collapsed
    /// rate at twice ~zero, and rate control only runs on ACK arrival, so
    /// once ACKs stop the controller never acts again. That is a hang, not
    /// a slow transfer.
    #[test]
    fn rate_cannot_collapse_to_a_standstill() {
        let mut cc = RlController::new();
        let mut now = Instant::now();
        // 300 ms path — 60 control intervals per round trip.
        for _ in 0..20 {
            cc.on_rtt_update(Duration::from_millis(300));
        }
        cc.slow_start = false;

        // Drive many intervals with collapsing delivery, as a backing-off
        // policy on a stalled path would see.
        for i in 0..400u64 {
            now += SYN_INTERVAL + Duration::from_millis(1);
            cc.on_packet_sent(i, MSS, now);
            cc.on_ack_received(&ack(i, 1), now);
        }

        let rtt_s = 0.300_f64;
        let floor = MIN_PACED_PKTS_PER_RTT * MSS as f64 / rtt_s;
        let rate = cc.rate_bps() as f64;
        println!(
            "  after 400 collapsing intervals: rate {:.0} B/s (floor {:.0} B/s = {} pkts/RTT)",
            rate, floor, MIN_PACED_PKTS_PER_RTT
        );
        assert!(
            rate >= floor * 0.95,
            "rate {rate:.0} fell below the progress floor {floor:.0} — the sender can stall"
        );
    }

    /// The floor must not become a rate *ceiling* on fast paths: on a 1 ms
    /// link it is only ~11 MB/s, and a controller that has measured more
    /// must still be allowed to exceed it.
    #[test]
    fn progress_floor_does_not_cap_a_healthy_path() {
        let mut cc = RlController::new();
        let mut now = Instant::now();
        for _ in 0..20 {
            cc.on_rtt_update(Duration::from_millis(1));
        }
        cc.slow_start = false;
        // Deliver at 100 MB/s for real: btlbw is now computed from bytes
        // acknowledged over time, so a test that reports a high
        // `delivery_rate` while acknowledging one packet per interval is
        // describing a path that delivers 272 KB/s. It used to pass because
        // the controller took the reported figure at face value, which is
        // exactly the behaviour that let a per-ACK spike latch btlbw to 4x
        // capacity on the rig.
        const RATE: f64 = 100.0 * 1024.0 * 1024.0;
        let tick = SYN_INTERVAL + Duration::from_micros(200);
        let per_tick = (RATE * tick.as_secs_f64()) as u64 / MSS as u64;
        let mut pn = 0u64;
        for _ in 0..300u64 {
            for k in 0..per_tick.max(1) {
                let at = now + tick.mul_f64((k + 1) as f64 / per_tick.max(1) as f64);
                cc.on_packet_sent(pn, MSS, at);
                cc.on_ack_received(&ack(pn, RATE as u64), at);
                pn += 1;
            }
            now += tick;
        }
        let floor = MIN_PACED_PKTS_PER_RTT * MSS as f64 / 0.001;
        println!("  fast path: rate {:.1} MB/s (floor would be {:.1} MB/s)",
                 cc.rate_bps() as f64 / 1e6, floor / 1e6);
        assert!(cc.rate_bps() as f64 > floor,
                "the progress floor is acting as a ceiling on a fast path");
    }
}

#[cfg(test)]
mod weight_versioning {
    use super::*;

    /// A weight file from before the action changed meaning must be
    /// rejected, not reinterpreted.
    ///
    /// The layout is byte-identical across the change — 8-byte magic plus
    /// 833 f64 — so nothing else can catch it. Loading v2 weights into the
    /// delivery-gain controller was measured on a 150 ms path at a 16.5 MB
    /// window against a 1.875 MB BDP and a 53% retransmit rate, with no
    /// error anywhere.
    #[test]
    fn rejects_weights_from_the_previous_action_semantics() {
        let dir = std::env::temp_dir().join("ahp_rl_magic_test");
        let _ = fs::create_dir_all(&dir);
        let path = dir.join("v1.bin");

        let mut buf = Vec::new();
        buf.extend_from_slice(b"AHPRL001");
        for _ in 0..TOTAL_WEIGHTS {
            buf.extend_from_slice(&0.5f64.to_le_bytes());
        }
        fs::write(&path, &buf).unwrap();
        assert_eq!(buf.len(), 8 + TOTAL_WEIGHTS * 8, "layout must be identical");

        assert!(
            MlpWeights::load(&path).is_none(),
            "an AHPRL001 file loaded into the AHPRL002 controller — its outputs \
             would be silently reinterpreted as delivery gains"
        );

        // The same bytes under the current magic must still load, so the
        // test is about the version and not about the parser rejecting
        // everything.
        let mut ok = Vec::new();
        ok.extend_from_slice(WEIGHT_MAGIC);
        ok.extend_from_slice(&buf[8..]);
        let path2 = dir.join("v2.bin");
        fs::write(&path2, &ok).unwrap();
        assert!(MlpWeights::load(&path2).is_some(), "current-version weights must load");

        let _ = fs::remove_dir_all(&dir);
    }
}

#[cfg(test)]
mod cycle_policy_tests {
    use super::*;

    /// With no policy loaded the controller is the one that was measured.
    ///
    /// This is the property that makes the bandit safe to add: a default
    /// build must be byte-for-byte the controller that was measured, or
    /// every published number silently stops applying.
    #[test]
    fn default_build_is_the_shipped_cycle() {
        let cc = RlController::new();
        assert!(cc.cycle_policy.is_none(), "a policy must not load by default");
        assert!(cc.forced_arm.is_none());
        let arm = cc.active_arm();
        assert_eq!(arm.probe_gain, CYCLE_PROBE_GAIN);
        assert_eq!(arm.probe_rtts, CYCLE_PROBE_RTTS);
        assert_eq!(CYCLE_ARMS[CYCLE_ARM_DEFAULT].probe_gain, CYCLE_PROBE_GAIN);
    }

    /// Context buckets are what the trainer and the controller must agree
    /// on; a mismatch would train one table and apply another.
    #[test]
    fn context_buckets_match_the_documented_bands() {
        // <40ms / 40-100ms / >100ms  x  <1% / >=1%
        assert_eq!(cycle_context(Duration::from_millis(25), 0.005), 0);
        assert_eq!(cycle_context(Duration::from_millis(25), 0.02), 1);
        assert_eq!(cycle_context(Duration::from_millis(50), 0.005), 2);
        assert_eq!(cycle_context(Duration::from_millis(100), 0.05), 3);
        assert_eq!(cycle_context(Duration::from_millis(150), 0.005), 4);
        assert_eq!(cycle_context(Duration::from_millis(150), 0.02), 5);
        // every context is reachable and in range
        for c in 0..CYCLE_CONTEXTS {
            assert!(c < CYCLE_CONTEXTS);
        }
    }

    /// A malformed policy is rejected whole, never partially applied.
    #[test]
    fn a_bad_policy_is_rejected_not_partially_applied() {
        assert!(CyclePolicy::parse(b"").is_none(), "empty");
        assert!(CyclePolicy::parse(b"AHPRL002\x00\x00\x00\x00\x00\x00").is_none(),
                "wrong magic — the MLP weights must not load as a cycle policy");
        let mut short = CyclePolicy::MAGIC.to_vec();
        short.extend_from_slice(&[0, 1, 2]);
        assert!(CyclePolicy::parse(&short).is_none(), "truncated");
        let mut bad_arm = CyclePolicy::MAGIC.to_vec();
        bad_arm.extend_from_slice(&[0, 1, 2, 3, 4, 99]);
        assert!(CyclePolicy::parse(&bad_arm).is_none(), "arm index out of range");
    }

    /// A well-formed policy selects the arm it names, per context.
    #[test]
    fn a_valid_policy_selects_its_arms() {
        let mut bytes = CyclePolicy::MAGIC.to_vec();
        bytes.extend_from_slice(&[5, 4, 3, 2, 1, 0]);
        let p = CyclePolicy::parse(&bytes).expect("well-formed policy must parse");
        assert_eq!(p.arm_for(0).probe_gain, CYCLE_ARMS[5].probe_gain);
        assert_eq!(p.arm_for(5).probe_gain, CYCLE_ARMS[0].probe_gain);
        // out-of-range context is clamped, not a panic
        assert_eq!(p.arm_for(99).probe_gain, CYCLE_ARMS[0].probe_gain);
    }

    /// The arm table is duplicated in `training/train_cycle_bandit.py` and
    /// the two must agree.
    ///
    /// They cannot share a definition across the language boundary, so this
    /// pins the values. If it fails, the Python `ARMS` list needs the same
    /// edit — a trainer that explores one table while the controller
    /// applies another would produce a policy that is wrong in a way no
    /// measurement could attribute.
    #[test]
    fn arm_table_matches_the_trainer() {
        let expect: [(f64, f64); 6] = [
            (1.10, 2.0),
            (1.25, 2.0),
            (1.50, 2.0),
            (1.10, 4.0),
            (1.25, 4.0),
            (1.50, 4.0),
        ];
        for (i, (g, r)) in expect.iter().enumerate() {
            assert_eq!(CYCLE_ARMS[i].probe_gain, *g, "arm {i} gain drifted from the trainer");
            assert_eq!(CYCLE_ARMS[i].probe_rtts, *r, "arm {i} length drifted from the trainer");
        }
        assert_eq!(CYCLE_ARMS.len(), expect.len());
    }

    /// Every arm must be distinguishable — a duplicate arm wastes a cell
    /// of an already small sample budget.
    #[test]
    fn arms_are_distinct() {
        for i in 0..CYCLE_ARMS.len() {
            for j in (i + 1)..CYCLE_ARMS.len() {
                let a = CYCLE_ARMS[i];
                let b = CYCLE_ARMS[j];
                assert!(
                    a.probe_gain != b.probe_gain || a.probe_rtts != b.probe_rtts,
                    "arms {i} and {j} are identical"
                );
            }
        }
    }
}

#[cfg(test)]
mod btlbw_tests {
    use super::*;

    /// btlbw must reflect what the path delivered, not how the ACKs were
    /// shaped.
    ///
    /// The rig said the rate bound was not binding: on the 150 ms path the
    /// implied pacing rate was 53 MB/s on a 12.5 MB/s link, 4.2x capacity,
    /// which requires btlbw to be reading about 2.1x capacity for the
    /// `2 x btlbw` ceiling to have let it through. This reproduces that.
    /// BBR's max filter is applied to delivery-rate samples measured over
    /// an interval; applied to instantaneous per-ACK samples it is a
    /// noise-peak detector.
    #[test]
    fn max_filter_latches_delivery_spikes() {
        let mut cc = RlController::new();
        let mut now = Instant::now();
        for _ in 0..10 {
            cc.on_rtt_update(Duration::from_millis(150));
        }
        cc.slow_start = false;

        const CAPACITY: u64 = 12_500_000;
        let mut pn = 0u64;
        // The path delivers exactly capacity every interval. What varies is
        // how the ACKs are shaped: sometimes they arrive spread out, and
        // sometimes the whole interval's worth lands in one batch, which
        // reports a per-ACK `delivery_rate` many times capacity. The bytes
        // are identical either way — only the instantaneous figure lies.
        let tick = SYN_INTERVAL + Duration::from_millis(1);
        let per_interval = (CAPACITY as f64 * tick.as_secs_f64()) as u64;
        for i in 0..300u64 {
            let batched = i % 50 == 7;
            let acks = (per_interval / MSS as u64).max(1);
            for k in 0..acks {
                // Batched: every ACK at the very end of the interval.
                let at = if batched {
                    now + tick
                } else {
                    now + tick.mul_f64((k + 1) as f64 / acks as f64)
                };
                cc.on_packet_sent(pn, MSS, at);
                cc.on_ack_received(
                    &AckInfo {
                        packet_number: pn,
                        ack_delay: Duration::ZERO,
                        delivered_bytes: MSS as u64,
                        // The instantaneous figure the sender would report.
                        delivery_rate: if batched { CAPACITY * 4 } else { CAPACITY },
                    },
                    at,
                );
                pn += 1;
            }
            now += tick;
        }

        let ratio = cc.btlbw as f64 / CAPACITY as f64;
        println!(
            "  btlbw {:.1} MB/s on a {:.1} MB/s path = {:.1}x capacity",
            cc.btlbw as f64 / 1e6,
            CAPACITY as f64 / 1e6,
            ratio
        );
        assert!(
            ratio <= 1.25,
            "btlbw is {ratio:.1}x capacity — the max filter latched a spike, so the \
             `2 x btlbw` rate ceiling permits {:.1}x capacity",
            2.0 * ratio
        );
    }

    /// A dip in delivery must not ratchet `max_cwnd` down.
    ///
    /// The BDP-derived ceiling is computed from `btlbw`, and `btlbw`
    /// measures delivery, which the window bounds whenever the window is
    /// the binding limit. So a clamp that follows the ceiling *downward*
    /// closes a loop: window down -> delivery down -> btlbw down -> ceiling
    /// down -> window down. Each gain-cycle drain phase supplies the dip
    /// that starts it.
    ///
    /// Measured at 1 Gbit before this was removed: `rl` cross-country
    /// 94.3 -> 28.6 MiB/s, transatlantic 69.0 -> 18.0. The ceiling is safe
    /// upward — an under-estimate only makes the bound too generous — and
    /// unsound downward.
    #[test]
    fn a_delivery_dip_does_not_shrink_the_window_ceiling() {
        let mut cc = RlController::new();
        let mut now = Instant::now();
        for _ in 0..10 {
            cc.on_rtt_update(Duration::from_millis(25));
        }
        cc.slow_start = false;

        const CAPACITY: u64 = 125_000_000; // 1 Gbit
        let tick = SYN_INTERVAL + Duration::from_millis(1);
        let mut pn = 0u64;

        // Feed capacity for long enough that the ceiling opens up, then
        // collapse delivery to a tenth and keep it there.
        let mut drive = |cc: &mut RlController, rate: u64, rounds: u64, now: &mut Instant| {
            let per_interval = (rate as f64 * tick.as_secs_f64()) as u64;
            for _ in 0..rounds {
                let acks = (per_interval / MSS as u64).max(1);
                for k in 0..acks {
                    let at = *now + tick.mul_f64((k + 1) as f64 / acks as f64);
                    cc.on_packet_sent(pn, MSS, at);
                    cc.on_ack_received(
                        &AckInfo {
                            packet_number: pn,
                            ack_delay: Duration::ZERO,
                            delivered_bytes: MSS as u64,
                            delivery_rate: rate,
                        },
                        at,
                    );
                    pn += 1;
                }
                *now += tick;
            }
        };

        drive(&mut cc, CAPACITY, 200, &mut now);
        let peak = cc.max_cwnd;

        drive(&mut cc, CAPACITY / 10, 400, &mut now);
        let after_dip = cc.max_cwnd;

        println!("  max_cwnd {peak:.0} -> {after_dip:.0} pkts across a 10x delivery dip");
        assert!(
            after_dip >= peak,
            "the ceiling ratcheted down across a delivery dip: {peak:.0} -> {after_dip:.0}. \
             btlbw is bounded by the window, so this is a closed loop toward zero."
        );
    }

    /// The ceiling must clear the RTT inflation the controller runs at.
    ///
    /// `btlbw x min_rtt` is what the path delivers in one *minimum* round
    /// trip, while the window drains at the *actual* one — so the measured
    /// BDP is smaller than the window sustaining it by the inflation ratio.
    /// A multiplier below that ratio puts the ceiling permanently under the
    /// window, `max_cwnd < ceiling` never holds, and the window freezes.
    ///
    /// This drives a path with a realistic 1.4x inflation and asserts the
    /// window gets off its initial floor. With the multiplier at 1.25 it did
    /// not: measured on the rig at `max_cwnd=1024pkt` for a whole transfer,
    /// cross-country 94.3 -> 28.2 MiB/s.
    #[test]
    fn the_ceiling_clears_the_rtt_inflation_it_runs_at() {
        const INFLATION: f64 = 1.4;
        assert!(
            MAX_CWND_BDP_MULT > INFLATION,
            "MAX_CWND_BDP_MULT {MAX_CWND_BDP_MULT} is below the {INFLATION}x RTT inflation \
             these controllers operate at — the ceiling will sit under the window and freeze it"
        );

        let mut cc = RlController::new();
        let mut now = Instant::now();
        let min_rtt = Duration::from_millis(25);
        let actual_rtt = min_rtt.mul_f64(INFLATION);
        cc.on_rtt_update(min_rtt);
        for _ in 0..10 {
            cc.on_rtt_update(actual_rtt);
        }
        cc.slow_start = false;

        // Delivery consistent with a window of `initial max_cwnd` draining
        // at the inflated RTT — i.e. exactly the regime that froze.
        let start = cc.max_cwnd;
        let rate = (start * MSS as f64 / actual_rtt.as_secs_f64()) as u64;
        let tick = SYN_INTERVAL + Duration::from_millis(1);
        let per_interval = (rate as f64 * tick.as_secs_f64()) as u64;
        let mut pn = 0u64;
        for _ in 0..300 {
            let acks = (per_interval / MSS as u64).max(1);
            for k in 0..acks {
                let at = now + tick.mul_f64((k + 1) as f64 / acks as f64);
                cc.on_packet_sent(pn, MSS, at);
                cc.on_ack_received(
                    &AckInfo {
                        packet_number: pn,
                        ack_delay: Duration::ZERO,
                        delivered_bytes: MSS as u64,
                        delivery_rate: rate,
                    },
                    at,
                );
                pn += 1;
            }
            now += tick;
        }

        println!("  max_cwnd {start:.0} -> {:.0} pkts at {INFLATION}x inflation", cc.max_cwnd);
        assert!(
            cc.max_cwnd > start,
            "window froze at its floor ({start:.0} pkts): the ceiling never rose above it"
        );
    }
}
