// Favonius — high-performance file transfer over UDP
// Copyright (c) 2025-2026 Vantino SàRL
// SPDX-License-Identifier: Apache-2.0

//! Deterministic closed-loop path simulator for congestion control.
//!
//! Built to diagnose one problem: Classic lands in one of two very
//! different operating regimes on impaired paths — roughly 26 MiB/s with
//! ~26% retransmits, or ~5 MiB/s with ~1.5% — apparently at random, with
//! medians differing more than 6x between benchmark runs of one binary.
//!
//! An earlier version of this file delivered one ACK per packet the
//! instant it arrived and reported every drop immediately and perfectly.
//! It showed *no* instability at all (spread 1.0x across loss seeds) and
//! the window never left its initial value. That negative result is why
//! this version exists: the instability is not in the controller in
//! isolation, it is in the coupling between the controller and the
//! **loss-detection path**. A simulator that hands the controller a clean
//! loss signal cannot reproduce it by construction.
//!
//! So this models what the sender actually does:
//!
//! - **Batched ACK bitmaps.** The receiver emits an ACK after
//!   `ack_every_pkts` arrivals or `ack_timer`, whichever comes first —
//!   not one per packet. Feedback arrives in bursts, which is what drives
//!   the controller's round and cadence accounting.
//! - **Sender-inferred loss.** Nothing tells the sender a packet was
//!   dropped; it discovers this only when a chunk is still unacked after
//!   the retransmit timer expires, on a periodic scan. Loss is therefore
//!   detected late and in batches — and a timer shorter than the RTT
//!   manufactures loss that never happened.
//! - **The adaptive RTO**, `srtt + 4*rttvar` floored at
//!   `max(configured, 2*base_rtt)`, matching the sender.
//! - **Karn's algorithm**, so a retransmitted chunk yields no RTT sample.
//! - **Min-of-batch RTT**, the sender's actual choice, which interacts
//!   with Karn: the minimum actively selects the most corrupted sample
//!   when suppression is off.
//!
//! Each is switchable ([`SimConfig`]) — the point is that ablations can
//! say *which* mechanism produces the instability instead of leaving it
//! to be inferred from throughput.
//!
//! Not modelled: reordering, ACK loss, multiple streams, competing flows,
//! variable propagation delay, receiver processing cost. Conclusions
//! about those do not belong here.
//!
//! Unlike the netem rig, the path has a real bottleneck, so there is a
//! *correct* window — the bandwidth-delay product — to converge to. That
//! is what makes "did it converge, and to what" well-posed here.

use std::collections::{HashSet, VecDeque};
use std::time::{Duration, Instant};

use crate::metrics::RttEstimator;
use crate::{AckInfo, CongestionController};

/// Packet payload size used throughout the simulation.
pub const PKT: usize = 1200;

/// Path parameters.
#[derive(Debug, Clone, Copy)]
pub struct Path {
    /// One-way propagation delay; RTT is twice this.
    pub delay: Duration,
    /// Bottleneck capacity in bytes per second.
    pub capacity_bps: f64,
    /// Bottleneck queue depth in packets; overflow is dropped.
    pub queue_pkts: usize,
    /// Independent random drop probability, applied before queueing.
    pub loss: f64,
}

impl Path {
    /// The window that exactly fills the pipe.
    pub fn bdp(&self) -> f64 {
        self.capacity_bps * self.delay.as_secs_f64() * 2.0
    }
    pub fn rtt(&self) -> f64 {
        self.delay.as_secs_f64() * 2.0
    }
}

/// Sender/receiver behaviour, mirroring the real defaults. Each knob
/// exists so it can be switched off in an ablation.
#[derive(Debug, Clone, Copy)]
pub struct SimConfig {
    /// Receiver emits an ACK bitmap after this many arrivals...
    pub ack_every_pkts: usize,
    /// ...or after this long, whichever comes first.
    pub ack_timer: Duration,
    /// How often the sender scans for timed-out chunks.
    pub retx_scan: Duration,
    /// Lower bound on the retransmit timer before RTT adaptation.
    pub retx_configured_floor: Duration,
    /// Use `srtt + 4*rttvar` (true) or the fixed floor (false, pre-fix).
    pub adaptive_rto: bool,
    /// Suppress RTT samples from retransmitted chunks (Karn).
    pub karn: bool,
    /// Feed the CC the minimum of each batch (production) or the mean.
    pub min_of_batch_rtt: bool,
    /// Honour `pacing_interval()` as well as the congestion window.
    ///
    /// The sender paces; for as long as this simulator did not, it could
    /// only ever exercise window control, and any conclusion it reached
    /// about a rate-based controller was a conclusion about a mechanism
    /// that controller was not using. A simulator that omits the actuator
    /// under test cannot reproduce a fault in it -- the same reason the
    /// earlier per-packet-ACK version showed no instability at all.
    pub pacing: bool,
}

impl Default for SimConfig {
    fn default() -> Self {
        Self {
            ack_every_pkts: 128,
            ack_timer: Duration::from_millis(15),
            retx_scan: Duration::from_millis(20),
            retx_configured_floor: Duration::from_millis(100),
            adaptive_rto: true,
            karn: true,
            min_of_batch_rtt: true,
            // Off by default, deliberately. Every test in this file was
            // written and calibrated against an unpaced simulator, and
            // flipping this would silently reinterpret all of them rather
            // than test anything -- the module header records four
            // confident wrong findings that came from trusting this
            // simulator about something it did not model, and quietly
            // changing what it models is the same error wearing a hat.
            //
            // Use `SimConfig::paced()` to exercise the production sender,
            // which does pace.
            pacing: false,
        }
    }
}

impl SimConfig {
    /// The pre-fix sender: fixed 100 ms timer, no Karn suppression.
    pub fn prefix() -> Self {
        Self { adaptive_rto: false, karn: false, ..Self::default() }
    }

    /// The sender as it actually ships: window *and* pacer.
    ///
    /// Prefer this for anything about a rate-based controller. Under the
    /// window alone, `pacing_interval()` is never consulted, so Model and
    /// RL are evaluated on a mechanism they do not use.
    pub fn paced() -> Self {
        Self { pacing: true, ..Self::default() }
    }
}

/// Outcome of one simulated transfer.
#[derive(Debug, Clone)]
pub struct SimResult {
    pub delivered_bytes: u64,
    /// Packets put on the wire, including retransmissions.
    pub sent_packets: u64,
    /// Packets actually dropped by the path.
    pub dropped_packets: u64,
    /// Chunks the sender chose to retransmit.
    pub retransmits: u64,
    /// Retransmits of chunks that were still in flight and undropped —
    /// pure waste, the signature of a timer shorter than the RTT.
    pub spurious_retransmits: u64,
    pub elapsed: Duration,
    pub completed: bool,
    pub final_cwnd: usize,
    pub peak_cwnd: usize,
    /// Which signal ended slow start, if it ended.
    pub exit_reason: Option<&'static str>,
    pub exit_at: Option<f64>,
    pub exit_cwnd: Option<usize>,
    /// Smallest RTT sample the estimator accepted — the Karn tell.
    pub min_rtt_sample: f64,
    pub cwnd_trace: Vec<(f64, usize)>,
}

impl SimResult {
    pub fn goodput_bps(&self) -> f64 {
        if self.elapsed.as_secs_f64() <= 0.0 { return 0.0; }
        self.delivered_bytes as f64 / self.elapsed.as_secs_f64()
    }
    pub fn retx_ratio(&self) -> f64 {
        if self.sent_packets == 0 { return 0.0; }
        self.retransmits as f64 / self.sent_packets as f64
    }
    pub fn cwnd_over_bdp(&self, path: &Path) -> f64 {
        let bdp = path.bdp();
        if bdp <= 0.0 { return 0.0; }
        self.final_cwnd as f64 / bdp
    }
}

/// xorshift64* — deterministic, seedable, no dependencies.
struct Rng(u64);
impl Rng {
    fn new(seed: u64) -> Self { Rng(seed | 1) }
    fn next_f64(&mut self) -> f64 {
        let mut x = self.0;
        x ^= x >> 12; x ^= x << 25; x ^= x >> 27;
        self.0 = x;
        ((x.wrapping_mul(0x2545_F491_4F6C_DD1D) >> 11) as f64) / ((1u64 << 53) as f64)
    }
}

/// Per-chunk sender state, mirroring `StreamState` in the real sender.
#[derive(Clone, Copy, Default)]
struct ChunkState {
    sent_at: f64,
    acked: bool,
    in_retx: bool,
    retransmitted: bool,
    ever_sent: bool,
}

/// Mirrors `DeliveryTracker` in the real sender: bytes acked over elapsed
/// wall time, sampled no more often than every 5 ms and EWMA-smoothed.
///
/// Getting this wrong is not a detail. An earlier version reported
/// `batch_size / RTT`, which is independent of the window — so the
/// controller's bandwidth estimate could never rise however far the window
/// opened, and the startup BDP cap (`3 x bw x srtt`) pinned the window at
/// a fixed fraction of the true BDP. The resulting "slow start never ends
/// and the window sits at 13% of BDP" was entirely an artifact of this
/// function.
#[derive(Default)]
struct DeliveryTracker {
    total_acked: u64,
    prev_acked: u64,
    prev_time: Option<f64>,
    rate: u64,
}

impl DeliveryTracker {
    fn on_ack(&mut self, bytes: u64, now: f64) {
        self.total_acked += bytes;
        let Some(prev) = self.prev_time else {
            self.prev_time = Some(now);
            self.prev_acked = self.total_acked;
            return;
        };
        let elapsed = now - prev;
        if elapsed >= 0.005 {
            let sample = ((self.total_acked - self.prev_acked) as f64 / elapsed) as u64;
            if sample > 0 {
                self.rate = if self.rate == 0 { sample } else { (self.rate * 7 + sample) / 8 };
            }
            self.prev_acked = self.total_acked;
            self.prev_time = Some(now);
        }
    }
}

struct Wire { arrive: f64, chunk: u64, dropped: bool }
/// Mirrors the real `AckBitmap`: everything up to `hc` is received, plus
/// the individually-received chunks above the first gap. Sending the whole
/// received set instead is both unfaithful and quadratic — on a 128 MB
/// transfer it dominates the run.
struct Ack { arrive: f64, hc: i64, above: Vec<u64> }

/// Run one transfer and report what happened.
pub fn run(
    cc: &mut dyn CongestionController,
    path: &Path,
    cfg: &SimConfig,
    bytes: u64,
    seed: u64,
    max_secs: f64,
) -> SimResult {
    let t0 = Instant::now();
    let mut rng = Rng::new(seed);
    let owd = path.delay.as_secs_f64();
    let pkt_time = PKT as f64 / path.capacity_bps;
    let total_chunks = bytes.div_ceil(PKT as u64);

    let mut chunks = vec![ChunkState::default(); total_chunks as usize];
    let mut next_new: u64 = 0;
    let mut hc_applied: u64 = 0;
    let mut retx_queue: Vec<u64> = Vec::new();
    let mut acked_count: u64 = 0;
    let mut bytes_in_flight = 0usize;

    // Both queues are pushed in non-decreasing arrival order (the
    // bottleneck serialises sends, and ACKs inherit that order), so the
    // earliest event is always at the front. Scanning a Vec for the
    // minimum each iteration was O(in-flight) per event, which is fine at
    // 4 MB and quadratic by 128 MB.
    let mut wire: VecDeque<Wire> = VecDeque::new();
    let mut acks: VecDeque<Ack> = VecDeque::new();
    let mut rx_received: HashSet<u64> = HashSet::new();
    let mut rx_hc: i64 = -1; // highest contiguous chunk received
    let mut rx_since_ack = 0usize;
    let mut rx_last_ack = 0.0f64;

    let mut delivery = DeliveryTracker::default();
    let mut rtt_est = RttEstimator::new();
    rtt_est.update(Duration::from_secs_f64(path.rtt()));
    cc.on_rtt_update(Duration::from_secs_f64(path.rtt()));
    let retx_floor = cfg
        .retx_configured_floor
        .max(Duration::from_secs_f64(path.rtt() * 2.0));

    let mut now = 0.0f64;
    let mut next_send_at = 0.0f64;
    let mut bottleneck_free = 0.0f64;
    let mut next_scan = cfg.retx_scan.as_secs_f64();
    let mut scan_cursor: u64 = 0;
    let (mut sent_packets, mut dropped, mut retransmits, mut spurious) = (0u64, 0u64, 0u64, 0u64);
    let mut trace = Vec::new();
    let mut last_trace = -1.0f64;
    let mut min_rtt_sample = f64::INFINITY;
    let (mut exit_reason, mut exit_at, mut exit_cwnd) = (None, None, None);
    let mut peak_cwnd = cc.congestion_window();

    while acked_count < total_chunks && now < max_secs {
        // ── send what the window allows; retransmits first ──────────────
        loop {
            if bytes_in_flight + PKT > cc.congestion_window() || !cc.can_send(bytes_in_flight) {
                break;
            }
            // The pacer is a second gate, not an alternative to the
            // window: production sends only when both allow it.
            if cfg.pacing && now < next_send_at {
                break;
            }
            let chunk = if let Some(c) = retx_queue.pop() {
                chunks[c as usize].in_retx = false;
                if chunks[c as usize].acked { continue; }
                retransmits += 1;
                c
            } else if next_new < total_chunks {
                let c = next_new;
                next_new += 1;
                c
            } else {
                break;
            };

            if bottleneck_free < now { bottleneck_free = now; }
            let qlen = ((bottleneck_free - now) / pkt_time).round() as usize;
            let drop = qlen >= path.queue_pkts || rng.next_f64() < path.loss;

            bottleneck_free += pkt_time;
            wire.push_back(Wire { arrive: bottleneck_free + owd, chunk, dropped: drop });

            let st = &mut chunks[chunk as usize];
            st.sent_at = now;
            st.ever_sent = true;
            cc.on_packet_sent(chunk, PKT, t0 + Duration::from_secs_f64(now));
            bytes_in_flight += PKT;
            sent_packets += 1;
            if drop { dropped += 1; }
            if cfg.pacing {
                let iv = cc.pacing_interval(PKT).as_secs_f64();
                next_send_at = if iv > 0.0 { now + iv } else { now };
            }
        }

        if now - last_trace >= 0.02 {
            trace.push((now, cc.congestion_window()));
            last_trace = now;
        }
        peak_cwnd = peak_cwnd.max(cc.congestion_window());

        // ── advance to the next event ───────────────────────────────────
        let next_wire = wire.front().map(|w| w.arrive).unwrap_or(f64::INFINITY);
        let next_ack = acks.front().map(|a| a.arrive).unwrap_or(f64::INFINITY);
        let next_timer = if rx_since_ack > 0 {
            rx_last_ack + cfg.ack_timer.as_secs_f64()
        } else { f64::INFINITY };
        // The pacing deadline is an event in its own right. Without it,
        // time advances only on ACK/wire/scan events, so a paced sender
        // emits one packet per ACK burst regardless of its rate -- which
        // reads as a controller that will not seek capacity, and is
        // really the simulator refusing to let it.
        let next_pace = if cfg.pacing
            && bytes_in_flight + PKT <= cc.congestion_window()
            && (next_new < total_chunks || !retx_queue.is_empty())
        {
            next_send_at
        } else {
            f64::INFINITY
        };
        let t_next = next_wire
            .min(next_ack)
            .min(next_timer)
            .min(next_scan)
            .min(next_pace);
        if !t_next.is_finite() { break; }
        now = t_next.max(now);
        let at = t0 + Duration::from_secs_f64(now);

        // ── arrivals at the receiver ────────────────────────────────────
        let mut arrived = 0usize;
        while let Some(w) = wire.front() {
            if w.arrive > now + 1e-12 { break; }
            if !w.dropped { rx_received.insert(w.chunk); arrived += 1; }
            wire.pop_front();
        }
        rx_since_ack += arrived;
        if rx_since_ack >= cfg.ack_every_pkts
            || (rx_since_ack > 0 && now >= rx_last_ack + cfg.ack_timer.as_secs_f64())
        {
            // Advance the contiguous prefix, then report only what lies
            // above the first gap.
            while rx_received.contains(&((rx_hc + 1) as u64)) {
                rx_hc += 1;
            }
            let above: Vec<u64> = rx_received
                .iter()
                .copied()
                .filter(|c| (*c as i64) > rx_hc)
                .collect();
            acks.push_back(Ack { arrive: now + owd, hc: rx_hc, above });
            rx_since_ack = 0;
            rx_last_ack = now;
        }

        // ── ACKs arriving at the sender ─────────────────────────────────
        let mut due = Vec::new();
        while let Some(a) = acks.front() {
            if a.arrive > now + 1e-12 { break; }
            due.push(acks.pop_front().unwrap());
        }

        for a in due {
            let mut samples = Vec::new();
            let mut newly = Vec::new();
            // The contiguous prefix is applied from a cursor, so each
            // chunk is visited once across the whole transfer rather than
            // once per ACK — the same reason the real sender keeps
            // `hc_applied`.
            let mut prefix: Vec<u64> = Vec::new();
            while (hc_applied as i64) <= a.hc {
                prefix.push(hc_applied);
                hc_applied += 1;
            }
            for c in prefix.into_iter().chain(a.above.into_iter()) {
                let st = &mut chunks[c as usize];
                if st.acked { continue; }
                st.acked = true;
                acked_count += 1;
                bytes_in_flight = bytes_in_flight.saturating_sub(PKT);
                if !(cfg.karn && st.retransmitted) {
                    samples.push((now - st.sent_at).max(1e-6));
                }
                newly.push(c);
            }
            if newly.is_empty() { continue; }

            if !samples.is_empty() {
                let s = if cfg.min_of_batch_rtt {
                    samples.iter().cloned().fold(f64::INFINITY, f64::min)
                } else {
                    samples.iter().sum::<f64>() / samples.len() as f64
                };
                min_rtt_sample = min_rtt_sample.min(s);
                rtt_est.update(Duration::from_secs_f64(s));
                cc.on_rtt_update(Duration::from_secs_f64(s));
            }
            delivery.on_ack((newly.len() * PKT) as u64, now);
            let rate = delivery.rate;
            for c in &newly {
                cc.on_ack_received(
                    &AckInfo {
                        packet_number: *c,
                        ack_delay: Duration::ZERO,
                        delivered_bytes: PKT as u64,
                        delivery_rate: rate,
                    },
                    at,
                );
            }
        }

        // ── sender-side timeout scan ────────────────────────────────────
        if now >= next_scan {
            next_scan = now + cfg.retx_scan.as_secs_f64();

            // Recompute in-flight from authoritative counters rather than
            // trusting the accumulated deltas, exactly as the real sender
            // does (`net_sender.rs:2698`). Incremental accounting drifts:
            // a chunk that is sent (+1), times out (-1), is resent (+1),
            // and then has its *original* copy acked (-1) nets to zero
            // while a retransmitted copy is still on the wire. Each such
            // event under-counts by one packet; enough of them and the
            // window looks permanently open, so the sender floods. That
            // produced a 10-million-packet spiral in this simulator, and
            // it is precisely what the recompute exists to prevent.
            let outstanding = (next_new - acked_count) as usize;
            bytes_in_flight = outstanding.saturating_sub(retx_queue.len()) * PKT;
            let rto = if cfg.adaptive_rto {
                rtt_est.rto_with_min(retx_floor).min(Duration::from_secs(5))
            } else {
                cfg.retx_configured_floor
            }
            .as_secs_f64();

            let mut lost = Vec::new();
            // Judge spuriousness at the moment the sender decides a chunk
            // is lost, not when it later gets around to resending it: by
            // then the original may well have arrived, which would hide
            // exactly the mistake we are trying to count.
            let in_flight_ok: HashSet<u64> =
                wire.iter().filter(|w| !w.dropped).map(|w| w.chunk).collect();
            // Scan only the unacked tail; everything below the cursor is
            // acked by construction (the real sender's `scan_cursor`).
            while (scan_cursor as usize) < chunks.len() && chunks[scan_cursor as usize].acked {
                scan_cursor += 1;
            }
            for c in scan_cursor..next_new {
                let st = &mut chunks[c as usize];
                if st.acked || st.in_retx || !st.ever_sent { continue; }
                if now - st.sent_at > rto {
                    st.in_retx = true;
                    st.retransmitted = true;
                    retx_queue.push(c);
                    lost.push(c);
                    // Release the window this chunk was holding. It is
                    // about to be counted again when it is re-sent, and
                    // the real sender does the same subtraction in its
                    // timeout branch. Omitting it made every lost packet
                    // consume window permanently, so on a lossy path the
                    // window silently filled with phantom bytes and
                    // throughput collapsed — a simulator artifact that
                    // looks exactly like a controller failure.
                    bytes_in_flight = bytes_in_flight.saturating_sub(PKT);
                    if in_flight_ok.contains(&c) { spurious += 1; }
                }
            }
            if !lost.is_empty() && cc.wants_timeout_loss() {
                cc.on_packet_lost(&lost, at);
            }
        }

        if exit_reason.is_none() {
            if let Some(r) = cc.exit_reason() {
                exit_reason = Some(r);
                exit_at = Some(now);
                exit_cwnd = Some(cc.congestion_window());
            }
        }
    }

    SimResult {
        delivered_bytes: acked_count * PKT as u64,
        sent_packets,
        dropped_packets: dropped,
        retransmits,
        spurious_retransmits: spurious,
        elapsed: Duration::from_secs_f64(now),
        completed: acked_count >= total_chunks,
        final_cwnd: cc.congestion_window(),
        peak_cwnd,
        exit_reason,
        exit_at,
        exit_cwnd,
        min_rtt_sample: if min_rtt_sample.is_finite() { min_rtt_sample } else { 0.0 },
        cwnd_trace: trace,
    }
}

#[cfg(test)]
mod diagnosis {
    use super::*;
    use crate::classic::ClassicController;

    fn satellite() -> Path {
        Path { delay: Duration::from_millis(150), capacity_bps: 12.5e6, queue_pkts: 500, loss: 0.02 }
    }
    fn degraded() -> Path {
        Path { delay: Duration::from_millis(100), capacity_bps: 12.5e6, queue_pkts: 500, loss: 0.05 }
    }

    fn sweep(path: &Path, cfg: &SimConfig, label: &str) -> (f64, f64) {
        let mut gs = Vec::new();
        println!("\n  {label}  (BDP {:.0} KB, RTT {:.0} ms)", path.bdp() / 1024.0, path.rtt() * 1e3);
        println!("    {:>4} {:>9} {:>8} {:>9} {:>8} {:>10} {:>9} {:>5}",
                 "seed", "MB/s", "retx%", "spurious", "cwnd/BDP", "exit", "minRTT ms", "done");
        for seed in 1..=8u64 {
            let mut cc = ClassicController::new();
            let r = run(&mut cc, path, cfg, 4 * 1024 * 1024, seed, 120.0);
            gs.push(r.goodput_bps() / 1e6);
            println!("    {:>4} {:>9.2} {:>7.1}% {:>9} {:>8.2} {:>10} {:>9.1} {:>5}",
                     seed, r.goodput_bps() / 1e6, r.retx_ratio() * 100.0,
                     r.spurious_retransmits, r.cwnd_over_bdp(path),
                     r.exit_reason.unwrap_or("-"), r.min_rtt_sample * 1e3,
                     if r.completed { "yes" } else { "NO" });
        }
        let min = gs.iter().cloned().fold(f64::INFINITY, f64::min);
        let max = gs.iter().cloned().fold(0.0f64, f64::max);
        println!("    spread {:.2}x", max / min.max(1e-9));
        (min, max)
    }

    /// Does the simulator reproduce the spurious-retransmit storm now that
    /// loss must be *inferred* rather than reported?
    #[test]
    #[ignore = "diagnostic sweep, ~30s; run with --ignored"]
    fn prefix_sender_reproduces_the_storm() {
        let path = satellite();
        sweep(&path, &SimConfig::prefix(), "PRE-FIX sender (fixed 100ms RTO, no Karn)");
        sweep(&path, &SimConfig::default(), "POST-FIX sender (adaptive RTO + Karn)");
    }

    /// Which of the two fixes actually removes the storm?
    #[test]
    #[ignore = "diagnostic sweep, ~60s; run with --ignored"]
    fn ablate_rto_and_karn() {
        let path = satellite();
        for (label, cfg) in [
            ("fixed RTO, no Karn ", SimConfig { adaptive_rto: false, karn: false, ..Default::default() }),
            ("fixed RTO, Karn    ", SimConfig { adaptive_rto: false, karn: true,  ..Default::default() }),
            ("adaptive RTO, noKarn", SimConfig { adaptive_rto: true,  karn: false, ..Default::default() }),
            ("adaptive RTO, Karn ", SimConfig { adaptive_rto: true,  karn: true,  ..Default::default() }),
        ] {
            let mut spur = 0u64; let mut retx = 0u64; let mut sent = 0u64;
            let mut gs = Vec::new();
            for seed in 1..=6u64 {
                let mut cc = ClassicController::new();
                let r = run(&mut cc, &path, &cfg, 4 * 1024 * 1024, seed, 120.0);
                spur += r.spurious_retransmits; retx += r.retransmits; sent += r.sent_packets;
                gs.push(r.goodput_bps() / 1e6);
            }
            let min = gs.iter().cloned().fold(f64::INFINITY, f64::min);
            let max = gs.iter().cloned().fold(0.0f64, f64::max);
            println!("  {label}  retx {:>5.1}%  spurious {:>5.1}%  goodput {:.2}-{:.2} MB/s  spread {:.2}x",
                     100.0 * retx as f64 / sent as f64,
                     100.0 * spur as f64 / sent.max(1) as f64,
                     min, max, max / min.max(1e-9));
        }
    }

    /// Is the landing point stable across loss patterns on both profiles?
    #[test]
    #[ignore = "diagnostic sweep, ~15s; run with --ignored"]
    fn landing_point_stability() {
        sweep(&satellite(), &SimConfig::default(), "satellite, post-fix");
        sweep(&degraded(), &SimConfig::default(), "degraded, post-fix");
    }
}

#[cfg(test)]
mod gate_attribution {
    use super::*;
    use crate::classic::ClassicController;

    /// Slow start always ends on `loss` in the sweeps — so *which* branch
    /// of the congestion gate admitted that loss, and what did the
    /// controller believe at the time?
    ///
    /// The gate exists to keep random loss on a lossy-but-uncongested path
    /// from shrinking the window. If it is opening during slow start on a
    /// path with no queue built and a window far below the BDP, then it is
    /// admitting exactly the reports it was written to reject.
    #[test]
    #[ignore = "diagnostic sweep; run with --ignored"]
    fn which_branch_admits_the_first_loss() {
        for (name, path) in [
            ("satellite", Path { delay: Duration::from_millis(150), capacity_bps: 12.5e6, queue_pkts: 500, loss: 0.02 }),
            ("degraded ", Path { delay: Duration::from_millis(100), capacity_bps: 12.5e6, queue_pkts: 500, loss: 0.05 }),
            ("cross-cty", Path { delay: Duration::from_millis(25),  capacity_bps: 12.5e6, queue_pkts: 500, loss: 0.005 }),
        ] {
            println!("\n  {name}  BDP {:.0} KB  RTT {:.0} ms", path.bdp() / 1024.0, path.rtt() * 1e3);
            println!("    {:>4} {:>10} {:>7} {:>9} {:>8} {:>9} {:>10}",
                     "seed", "gate", "in SS", "cwnd KB", "cwnd/BDP", "plateau", "srtt/min");
            for seed in 1..=5u64 {
                let mut cc = ClassicController::new();
                let _ = run(&mut cc, &path, &SimConfig::default(), 4 * 1024 * 1024, seed, 60.0);
                match cc.gate_snapshot() {
                    Some(g) => {
                        let ratio = if g.min_rtt_us > 0 {
                            g.srtt_us as f64 / g.min_rtt_us as f64
                        } else { 0.0 };
                        println!("    {:>4} {:>10} {:>7} {:>9.0} {:>8.3} {:>9} {:>10.2}",
                                 seed, cc.gate_reason().unwrap_or("-"),
                                 if g.in_slow_start { "yes" } else { "no" },
                                 g.cwnd as f64 / 1024.0,
                                 g.cwnd as f64 / path.bdp(),
                                 g.plateau_rounds, ratio);
                    }
                    None => println!("    {:>4} {:>10}", seed, "never"),
                }
            }
        }
    }
}

#[cfg(test)]
mod long_transfer {
    use super::*;
    use crate::classic::ClassicController;

    /// What happens when slow start genuinely has to end?
    ///
    /// The short sweeps mostly finish while still in slow start, so they
    /// say nothing about the steady state. A 128 MB transfer — the size
    /// the benchmark rig uses — cannot avoid it.
    #[test]
    #[ignore = "long simulation; run with --ignored --release"]
    fn slow_start_must_end_on_a_128mb_transfer() {
        for (name, path) in [
            ("satellite", Path { delay: Duration::from_millis(150), capacity_bps: 12.5e6, queue_pkts: 500, loss: 0.02 }),
            ("degraded ", Path { delay: Duration::from_millis(100), capacity_bps: 12.5e6, queue_pkts: 500, loss: 0.05 }),
            ("metro    ", Path { delay: Duration::from_millis(5),   capacity_bps: 12.5e6, queue_pkts: 500, loss: 0.001 }),
        ] {
            println!("\n  {name}  BDP {:.0} KB  RTT {:.0} ms  cap {:.1} MB/s",
                     path.bdp() / 1024.0, path.rtt() * 1e3, path.capacity_bps / 1e6);
            println!("    {:>4} {:>8} {:>9} {:>7} {:>10} {:>9} {:>9} {:>6}",
                     "seed", "MB/s", "util%", "retx%", "exit", "exit@s", "cwnd/BDP", "done");
            for seed in 1..=5u64 {
                let mut cc = ClassicController::new();
                let r = run(&mut cc, &path, &SimConfig::default(), 128 * 1024 * 1024, seed, 900.0);
                println!("    {:>4} {:>8.2} {:>8.1}% {:>6.1}% {:>10} {:>9} {:>9.2} {:>6}  [sent={} deliv={:.1}MB t={:.1}s]",
                         seed,
                         r.goodput_bps() / 1e6,
                         100.0 * r.goodput_bps() / path.capacity_bps,
                         r.retx_ratio() * 100.0,
                         r.exit_reason.unwrap_or("-"),
                         r.exit_at.map(|t| format!("{t:.1}")).unwrap_or_else(|| "-".into()),
                         r.cwnd_over_bdp(&path),
                         if r.completed { "yes" } else { "NO" },
                         r.sent_packets,
                         r.delivered_bytes as f64 / 1e6,
                         r.elapsed.as_secs_f64());
            }
        }
    }
}

#[cfg(test)]
mod spiral {
    use super::*;
    use crate::classic::ClassicController;

    /// Degraded profile, seed 4: 10M packets to deliver 5 MB. What is the
    /// controller actually doing while that happens?
    #[test]
    #[ignore = "long simulation; run with --ignored --release"]
    fn anatomy_of_the_spiral() {
        let path = Path { delay: Duration::from_millis(100), capacity_bps: 12.5e6, queue_pkts: 500, loss: 0.05 };
        println!("\n  degraded seed 4 — BDP {:.0} KB, queue {} pkts ({:.2} x BDP)",
                 path.bdp() / 1024.0, path.queue_pkts,
                 path.queue_pkts as f64 * PKT as f64 / path.bdp());

        for label in ["spiral (seed 4)", "healthy (seed 1)"] {
            let seed = if label.starts_with("spiral") { 4 } else { 1 };
            let mut cc = ClassicController::new();
            let r = run(&mut cc, &path, &SimConfig::default(), 16 * 1024 * 1024, seed, 120.0);
            let d = cc.diag();
            println!("\n    {label}");
            println!("      goodput {:.2} MB/s  sent {}  retx {:.1}%  done {}",
                     r.goodput_bps() / 1e6, r.sent_packets, r.retx_ratio() * 100.0, r.completed);
            println!("      in slow start: {}   exit: {:?}", d.in_slow_start, r.exit_reason);
            println!("      cwnd {:.2} x BDP   ssthresh {}", r.final_cwnd as f64 / path.bdp(),
                     if d.ssthresh == usize::MAX { "MAX".into() } else { format!("{}", d.ssthresh) });
            println!("      rounds closed: {}   plateau strikes: {}   decreases: {}",
                     d.round_count, d.plateau_rounds, d.decreases);
            println!("      bw_estimate {:.2} MB/s (capacity {:.2})",
                     d.bw_estimate as f64 / 1e6, path.capacity_bps / 1e6);
            println!("      gate: {:?}", cc.gate_reason());
        }
    }
}

#[cfg(test)]
mod shaped_baseline {
    use super::*;
    use crate::classic::ClassicController;

    /// The rig's shaped baseline: 100 Mbit, ~0 delay, no random loss, and
    /// a 256 KB bottleneck queue. On the real rig Classic stalls there —
    /// cwnd frozen near 420 KB, 24.5% of a 64 MB transfer in 120 s, which
    /// is ~200x below what cwnd/RTT would predict. Does it reproduce?
    #[test]
    #[ignore = "diagnostic; run with --ignored --release"]
    fn classic_on_a_shaped_zero_delay_link() {
        // 256 KB queue at 12.5 MB/s = 213 packets.
        for (label, queue_pkts) in [("256KB queue", 213usize), ("1MB queue", 873)] {
            let path = Path {
                delay: Duration::from_micros(100), // ~0, as on the bridge
                capacity_bps: 12.5e6,
                queue_pkts,
                loss: 0.0,
            };
            let mut cc = ClassicController::new();
            let r = run(&mut cc, &path, &SimConfig::default(), 64 * 1024 * 1024, 1, 300.0);
            let d = cc.diag();
            println!(
                "  {label:<12} {:>7.2} MB/s ({:>5.1}% of link)  retx {:>5.1}%  cwnd {} KB  \
                 exit {:?}  decreases {}  done {}",
                r.goodput_bps() / 1e6,
                100.0 * r.goodput_bps() / path.capacity_bps,
                r.retx_ratio() * 100.0,
                r.final_cwnd / 1024,
                r.exit_reason,
                d.decreases,
                r.completed
            );
        }
    }
}

#[cfg(test)]
mod model_divergence {
    use super::*;
    use crate::classic::ClassicController;
    use crate::model::ModelController;

    /// Model reaches a 235 MB window and retransmits 98.6% of packets on a
    /// 150 ms path where Classic sits at 3.5 MB and 13%. Does the window
    /// diverge here too, and does it track RTT the way the suspected
    /// feedback loop predicts?
    #[test]
    #[ignore = "diagnostic; run with --ignored --release"]
    fn model_window_vs_rtt() {
        println!("\n  {:>8} {:>12} {:>12} {:>10} {:>10}",
                 "RTT ms", "classic MB/s", "model MB/s", "cls cwnd/BDP", "mdl cwnd/BDP");
        for owd_ms in [1u64, 5, 25, 50, 150] {
            let path = Path {
                delay: Duration::from_millis(owd_ms),
                capacity_bps: 12.5e6,
                queue_pkts: 500,
                loss: 0.01,
            };
            let mut c = ClassicController::new();
            let rc = run(&mut c, &path, &SimConfig::default(), 16 * 1024 * 1024, 1, 300.0);
            let mut m = ModelController::new();
            let rm = run(&mut m, &path, &SimConfig::default(), 16 * 1024 * 1024, 1, 300.0);
            println!("  {:>8} {:>12.2} {:>12.2} {:>10.2} {:>10.2}",
                     owd_ms * 2,
                     rc.goodput_bps() / 1e6, rm.goodput_bps() / 1e6,
                     rc.cwnd_over_bdp(&path), rm.cwnd_over_bdp(&path));
        }
        println!();
    }
}

#[cfg(test)]
mod classic_bimodality {
    use super::*;
    use crate::classic::ClassicController;

    /// The satellite cell from the 2026-08-03 rig run: 150 ms RTT (netem
    /// delays one way and ACKs return unimpeded), 100 Mbit, BDP-sized
    /// queue, 2% loss.
    fn satellite() -> Path {
        Path {
            // pathsim's RTT is 2 x delay; the rig's is 1 x.
            delay: Duration::from_micros(75_000),
            capacity_bps: 12.5e6,
            queue_pkts: 1562, // 1.0 BDP
            loss: 0.02,
        }
    }

    /// Three identical rig runs produced 6.09, 8.80 and 4.96 MiB/s. The
    /// fast one was not a better run, it was a *worse-behaved* one: it
    /// overshot in slow start into a standing queue (cwnd 6.5 MB, RTT
    /// 150 -> 301 ms, 41% retransmits) and bought throughput with latency.
    /// The two slow ones were the well-behaved shape — empty queue, 2%
    /// retransmits — stuck at 0.85x BDP with no way back up, because
    /// congestion avoidance grew by one MTU per round and needed 209 of
    /// them to close the gap in a transfer that lasted 120.
    ///
    /// So the property to hold is not "always fast". It is: do not finish
    /// with an empty queue and a window below the BDP. That state is pure
    /// waste — the link is idle and nothing in the controller is trying to
    /// use it.
    ///
    /// **This simulator does not reproduce the bimodality, and this test
    /// therefore does not validate the fix for it.** Measured both ways:
    /// without the queue-empty growth branch it already lands at
    /// cwnd/BDP 0.98-1.00 and 68.7-72.0% of the link across six seeds; with
    /// it, 1.06-1.26 and 69.0-72.4%. No frozen 0.85x mode, no runaway mode,
    /// same 3.3-point spread. Whatever splits the rig into two attractors
    /// is not modelled here — the most likely candidates are the four
    /// concurrent streams and GSO, which makes netem drop up to 46
    /// consecutive packets as one superpacket while this drops packets
    /// independently.
    ///
    /// It is kept as a floor, not as evidence: it fails if congestion
    /// avoidance ever loses the ability to reach the BDP at all. The
    /// evidence for the fix is on the rig, in ALGORITHMS.md. Recording this
    /// because this simulator has produced four confident wrong findings
    /// already (see the CC dynamics notes) and every one of them came
    /// from trusting it about something it did not model.
    #[test]
    fn does_not_idle_a_link_it_has_measured_as_empty() {
        let path = satellite();
        let bdp = path.bdp();
        let mut worst_util = f64::MAX;
        let mut utils = Vec::new();

        println!("\n  {:>4} {:>10} {:>9} {:>11} {:>9}",
                 "seed", "MB/s", "% link", "cwnd/BDP", "retx");
        for seed in 1..=6u64 {
            let mut cc = ClassicController::new();
            let r = run(&mut cc, &path, &SimConfig::default(), 32 * 1024 * 1024, seed, 300.0);
            let util = r.goodput_bps() / path.capacity_bps;
            utils.push(util);
            worst_util = worst_util.min(util);
            println!("  {:>4} {:>10.2} {:>8.1}% {:>11.2} {:>8.1}%",
                     seed, r.goodput_bps() / 1e6, util * 100.0,
                     r.final_cwnd as f64 / bdp, r.retx_ratio() * 100.0);
        }

        let mean = utils.iter().sum::<f64>() / utils.len() as f64;
        let spread = utils.iter().cloned().fold(f64::MIN, f64::max) - worst_util;
        println!("  mean {:.1}%  worst {:.1}%  spread {:.1} points",
                 mean * 100.0, worst_util * 100.0, spread * 100.0);

        // The frozen mode measured 55% of the link with the queue empty.
        // Anything at or below that is the defect reappearing.
        assert!(
            worst_util > 0.60,
            "worst-case utilisation {:.1}% is at the frozen-window level; \
             congestion avoidance is not recovering an undershoot",
            worst_util * 100.0
        );
    }

    /// Why does no controller reach capacity once the pacer is honest?
    ///
    /// The rig says every controller under-commands: with the pacing fix
    /// in place Model holds a 50 KB window against a 312 KB BDP and asks
    /// for ~10 Mbit of a 100 Mbit link. This runs each controller against
    /// a path whose capacity is known exactly, with pacing on and off, so
    /// "did it converge, and to what" is answerable rather than inferred
    /// from goodput.
    ///
    /// Run with --nocapture; it reports rather than asserts, because its
    /// job is to locate the mechanism, not to pin a number.
    #[test]
    #[ignore = "diagnostic; reports rather than asserts. cargo test -p ahp-congestion capacity_seeking -- --ignored --nocapture"]
    fn capacity_seeking_across_controllers() {
        let cases = [
            ("cross-cty", Path { delay: Duration::from_millis(25),  capacity_bps: 12.5e6, queue_pkts: 260, loss: 0.005 }),
            ("degraded ", Path { delay: Duration::from_millis(100), capacity_bps: 12.5e6, queue_pkts: 1040, loss: 0.05 }),
        ];

        for (label, path) in cases {
            let bdp = path.bdp();
            println!("\n{label}: BDP {:.0} KB, rtt {:.0} ms, capacity {:.2} MB/s, loss {:.1}%",
                     bdp / 1024.0, path.rtt() * 1e3, path.capacity_bps / 1e6, path.loss * 100.0);
            println!("  {:<9} {:>6} {:>10} {:>9} {:>11} {:>8}",
                     "cc", "paced", "MB/s", "util", "cwnd/BDP", "retx");

            for paced in [false, true] {
                let cfg = if paced { SimConfig::paced() } else { SimConfig::default() };
                for (name, profile) in [
                    ("classic", crate::CongestionProfile::Classic),
                    ("model", crate::CongestionProfile::Model),
                    ("rl", crate::CongestionProfile::Rl),
                ] {
                    let mut cc = crate::create_controller(profile);
                    let r = run(&mut *cc, &path, &cfg, 16 << 20, 1, 60.0);
                    println!("  {:<9} {:>6} {:>10.2} {:>8.1}% {:>10.2}x {:>7.1}%",
                             name, paced, r.goodput_bps() / 1e6,
                             100.0 * r.goodput_bps() / path.capacity_bps,
                             r.final_cwnd as f64 / bdp,
                             r.retx_ratio() * 100.0);
                }
            }
        }
    }

    /// Close the gap between this simulator and the netem rig.
    ///
    /// The rig measures Model at ~9% of a 100 Mbit cross-country link;
    /// `capacity_seeking_across_controllers` measures 80.9% for the same
    /// controller and the same nominal scenario. One of the two is wrong.
    /// This walks the rig's parameters in one at a time so the disagreement
    /// can be attributed instead of argued about.
    ///
    /// The rig applies netem one-way on the sender's egress and lets ACKs
    /// return unshaped, so its "25 ms cross-country" path has a ~25 ms RTT.
    /// `Path::rtt()` here is `2 * delay`, so the same label means 50 ms.
    #[test]
    #[ignore = "diagnostic; reports rather than asserts. cargo test -p ahp-congestion rig_gap -- --ignored --nocapture"]
    fn rig_gap_parameter_sweep() {
        let cap = 12.5e6;
        // (label, one-way delay ms, queue pkts, loss, bytes)
        let cases = [
            ("sim as written  (rtt 50, 16MB)", 25.0, 260, 0.005, 16u64 << 20),
            ("rig rtt         (rtt 25, 16MB)", 12.5, 260, 0.005, 16u64 << 20),
            ("rig rtt + size  (rtt 25,128MB)", 12.5, 260, 0.005, 128u64 << 20),
            ("rig rtt, queue=1BDP of 25ms   ", 12.5, 130, 0.005, 128u64 << 20),
        ];
        // The "seeded" column that used to be here demonstrated the
        // bandwidth seed collapsing Model from 87.5% to 52.8% of the link.
        // The seed is gone (see lib.rs), so the demonstration is now only
        // in git history -- ecf33fe has the numbers.
        println!("\n  {:<32} {:>9} {:>9} {:>10} {:>8}",
                 "case", "MB/s", "util", "cwnd/BDP", "retx");
        for (label, delay_ms, queue_pkts, loss, bytes) in cases {
            let path = Path {
                delay: Duration::from_secs_f64(delay_ms / 1000.0),
                capacity_bps: cap,
                queue_pkts,
                loss,
            };
            let mut cc = crate::create_controller(crate::CongestionProfile::Model);
            let r = run(&mut *cc, &path, &SimConfig::paced(), bytes, 1, 300.0);
            println!("  {:<32} {:>9.2} {:>8.1}% {:>9.2}x {:>7.1}%",
                     label, r.goodput_bps() / 1e6,
                     100.0 * r.goodput_bps() / cap,
                     r.final_cwnd as f64 / path.bdp(),
                     r.retx_ratio() * 100.0);
        }
    }

    /// A seconds-scale gate: no controller may stop working.
    ///
    /// This runs before the rig, not instead of it. The rig is the only
    /// thing that closes a question, but an 84-cell run costs forty
    /// minutes and most regressions in this codebase were not subtle
    /// tuning shifts -- they were a controller that stopped completing
    /// transfers at all. `fair` timed out when the RTT feed was fixed,
    /// Model deadlocked when the bandwidth seed was removed, RL locked at
    /// half rate when the probe was inert. Each cost a full rig cycle to
    /// discover and each is visible here in under a second.
    ///
    /// The thresholds are deliberately loose. This is not a performance
    /// test and must not become one: it asserts that a controller moves
    /// data and does not sit at its floor, nothing more. Anything tighter
    /// would fail on simulator/rig divergence rather than on defects.
    #[test]
    fn no_controller_collapses() {
        let paths = [
            ("cross-cty", Path { delay: Duration::from_millis(12), capacity_bps: 12.5e6, queue_pkts: 260, loss: 0.005 }),
            ("degraded ", Path { delay: Duration::from_millis(50), capacity_bps: 12.5e6, queue_pkts: 1040, loss: 0.05 }),
        ];
        let ccs = [
            ("classic", crate::CongestionProfile::Classic),
            ("model",   crate::CongestionProfile::Model),
            ("rl",      crate::CongestionProfile::Rl),
            ("fair",    crate::CongestionProfile::Fair),
            ("wifi",    crate::CongestionProfile::Wifi),
            ("udt",     crate::CongestionProfile::Udt),
        ];
        // What this gate can and cannot say.
        //
        // Measured against the rig baseline on the same two scenarios, the
        // simulator's utilisation is 0.27x to 1.45x the rig's, per cell:
        //
        //              classic  model  rl    fair  wifi  udt
        //   cross-cty  0.67     0.67   0.78  0.30  1.45  0.56
        //   degraded   0.29     0.42   0.47  0.27  1.09  0.46
        //
        // A five-fold spread, and it inverts on wifi. The simulator is
        // single-stream, has no GSO batching and a different loss model, so
        // it does not predict the rig's level and must never be used to
        // grade one controller against another or a change against its
        // predecessor. That is what the rig is for.
        //
        // What it does resolve is collapse. Model paced sat at 0.2% of the
        // link here -- 662,417 packets sent to deliver 1,046 -- while the
        // rig ran the same controller at 86%. The worst legitimate cell on
        // either instrument is fair, at 12.8% on the rig and 4.6% here.
        // A floor of 3% separates "working badly" from "not working" with
        // roughly a factor of fifteen either side, and costs no rig time.
        const COLLAPSE_FLOOR: f64 = 0.03;

        let mut failures = Vec::new();
        for (pname, path) in paths {
            for (cname, profile) in ccs {
                let mut cc = crate::create_controller(profile);
                let r = run(&mut *cc, &path, &SimConfig::paced(), 8 << 20, 1, 120.0);
                let util = r.goodput_bps() / path.capacity_bps;
                println!("  {cname:<8} {pname}  {:>5.1}% of link  {}",
                         util * 100.0,
                         if r.completed { "completed" } else { "DID NOT COMPLETE" });
                if !r.completed {
                    failures.push(format!("{cname}/{pname}: did not complete"));
                } else if util < COLLAPSE_FLOOR {
                    failures.push(format!("{cname}/{pname}: {:.1}% of link", util * 100.0));
                }
            }
        }
        assert!(
            failures.is_empty(),
            "controller(s) collapsed in simulation, before any rig time was spent:\n  {}",
            failures.join("\n  ")
        );
    }

    /// Why does the simulator think Model does not work?
    ///
    /// It reads 0.1% of the link and "did not complete" here while running
    /// at 10.77 MB/s on the rig. Until that is closed the simulator cannot
    /// gate anything, and it is the only instrument without an observer
    /// effect -- which matters, because `FAVONIUS_CC_DEBUG` was measured
    /// eliminating UDT's bimodality outright.
    /// Does anything cap the window below the path's BDP?
    ///
    /// Driven directly rather than through `run()`: a transfer long enough
    /// for the window to plateau on a 1 Gbit path is ~100k chunks, which
    /// this simulator does not do quickly, and a shorter one measures slow
    /// start instead of the steady state. Feeding ACKs at a known rate
    /// answers the question exactly and in milliseconds.
    ///
    /// `rl.rs` and `udt.rs` both grow `max_cwnd` toward the measured BDP
    /// and then stop at a hard-coded 4096 packets -- 4.9 MB at this MTU.
    /// That is a constant, not a measurement, and on a long fat path it
    /// becomes the binding constraint instead of the network:
    ///
    ///   scenario        RTT     BDP        4096 pkts as a multiple
    ///   cross-country    50ms    521 pkt   7.9x   not binding
    ///   transatlantic   100ms   1042 pkt   3.9x   not binding
    ///   satellite       300ms   3125 pkt   1.31x  binding: RL's
    ///                                             CWND_BDP_GAIN of 2.0
    ///                                             asks for 6250
    ///   1 Gbit x 100ms  100ms  10416 pkt   0.39x  hard wall
    #[test]
    #[ignore = "diagnostic; run with --ignored --nocapture"]
    fn window_ceiling_on_long_fat_paths() {
        // 1 Gbit, 100 ms RTT, no loss: BDP is 12.5 MB, 10,416 packets.
        let rate: u64 = 125_000_000;
        let rtt = Duration::from_millis(100);
        let bdp_pkts = rate as f64 * rtt.as_secs_f64() / PKT as f64;
        println!("\n  1 Gbit x 100ms, BDP = {bdp_pkts:.0} packets, zero loss");
        println!("  driving each controller with clean ACKs at exactly that rate\n");

        for (name, profile) in [
            ("classic", crate::CongestionProfile::Classic),
            ("model",   crate::CongestionProfile::Model),
            ("rl",      crate::CongestionProfile::Rl),
            ("udt",     crate::CongestionProfile::Udt),
            ("wifi",    crate::CongestionProfile::Wifi),
        ] {
            let mut cc = crate::create_controller(profile);
            let mut now = Instant::now();
            let mut pn: u64 = 0;
            // 200 round trips: far past any plateau.
            for _ in 0..200 {
                // One BDP of packets per round trip, which is what a
                // sender filling this path would put on the wire.
                let per_round = (bdp_pkts as u64).min(
                    (cc.congestion_window() / PKT).max(1) as u64,
                );
                for _ in 0..per_round {
                    pn += 1;
                    cc.on_packet_sent(pn, PKT, now);
                }
                now += rtt;
                cc.on_rtt_batch(rtt, rtt);
                for i in 0..per_round {
                    cc.on_ack_received(
                        &crate::AckInfo {
                            packet_number: pn - (per_round - 1) + i,
                            ack_delay: Duration::ZERO,
                            delivered_bytes: PKT as u64,
                            delivery_rate: rate,
                        },
                        now,
                    );
                }
            }
            let pkts = cc.congestion_window() as f64 / PKT as f64;
            println!(
                "  {name:<8} final cwnd {:>7.0} pkt = {:>6.2} MB  ({:.2}x BDP){}",
                pkts,
                cc.congestion_window() as f64 / (1024.0 * 1024.0),
                pkts / bdp_pkts,
                if pkts < bdp_pkts { "   <-- below BDP on a loss-free path" } else { "" },
            );
        }
    }

    #[test]
    #[ignore = "diagnostic; run with --ignored --nocapture"]
    fn why_model_stalls_here() {
        let path = Path {
            delay: Duration::from_millis(12),
            capacity_bps: 12.5e6,
            queue_pkts: 260,
            loss: 0.005,
        };
        for (label, cfg) in [("paced", SimConfig::paced()), ("unpaced", SimConfig::default())] {
            let mut cc = crate::create_controller(crate::CongestionProfile::Model);
            let r = run(&mut *cc, &path, &cfg, 8 << 20, 1, 60.0);
            println!("\n  === model, {label} ===");
            println!("    completed={} goodput={:.2} MB/s ({:.1}% of link)",
                     r.completed, r.goodput_bps() / 1e6,
                     100.0 * r.goodput_bps() / path.capacity_bps);
            println!("    sent={} dropped={} retx={} spurious={}",
                     r.sent_packets, r.dropped_packets, r.retransmits,
                     r.spurious_retransmits);
            println!("    final_cwnd={} ({:.2}x BDP)  peak_cwnd={}",
                     r.final_cwnd, r.final_cwnd as f64 / path.bdp(), r.peak_cwnd);
            println!("    exit_reason={:?} at {:?}", r.exit_reason, r.exit_at);
            if let Some(d) = cc.diag_line() { println!("    {d}"); }
        }
    }
}