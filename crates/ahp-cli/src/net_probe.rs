// Favonius — high-performance file transfer over UDP
// Copyright (c) 2025-2026 Vantino SàRL
// SPDX-License-Identifier: Apache-2.0

//! Network path probing and link-type classification.
//!
//! Before a file transfer begins, the sender sends a burst of small probe
//! packets (PathProbe / PathProbeAck) to measure RTT, jitter, and loss.
//! The results are used to classify the link type and set congestion
//! control parameters accordingly.

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use bytes::Bytes;
use tokio::net::UdpSocket;

use ahp_proto::*;

// The link type vocabulary is owned by ahp-policy (it is persisted in
// `policy.json`); re-exported here so existing `net_probe::LinkType`
// users keep working.
pub use ahp_policy::LinkType;

/// Number of probe round-trips to attempt.
const PROBE_COUNT: usize = 10;
/// Delay between consecutive probes. This is pure spacing between samples —
/// each RTT is measured from its own send time — so it is fixed dead time in
/// the setup phase: 10 probes × 15 ms used to cost ~150 ms before every
/// transfer (dominating small-file wall time) without improving the RTT
/// min/avg/jitter estimate in a way the link classifier can tell apart.
const PROBE_INTERVAL: Duration = Duration::from_millis(5);
/// Timeout waiting for a single probe reply.
const PROBE_REPLY_TIMEOUT: Duration = Duration::from_millis(200);

// ── Link classification ──────────────────────────────────────────────────────

/// Measured network path characteristics.
#[derive(Debug, Clone)]
pub struct NetworkProfile {
    /// Minimum RTT observed across probes.
    pub base_rtt: Duration,
    /// Mean RTT.
    pub avg_rtt: Duration,
    /// RTT standard deviation (jitter indicator).
    pub rtt_jitter: Duration,
    /// Probe loss rate (0.0–1.0).
    pub probe_loss_rate: f64,
    /// Classified link type.
    pub link_type: LinkType,
    /// Recommended minimum congestion window (bytes).
    pub min_cwnd: usize,
}

/// Real-time transfer metrics tracked during the data phase.
/// `1h 04m` / `12m 30s` / `45s` — an ETA nobody has to parse.
fn format_duration(secs: f64) -> String {
    if !secs.is_finite() || secs < 0.0 {
        return "--:--".to_string();
    }
    let s = secs as u64;
    if s >= 3600 {
        format!("{}h{:02}m", s / 3600, (s % 3600) / 60)
    } else if s >= 60 {
        format!("{}m{:02}s", s / 60, s % 60)
    } else {
        format!("{}s", s)
    }
}

#[derive(Debug)]
pub struct TransferMetrics {
    rtt_samples: Vec<Duration>,
    loss_events: u64,
    total_acks: u64,
    last_report: Instant,
    started: Instant,
    report_interval: Duration,
}

impl TransferMetrics {
    pub fn new() -> Self {
        Self {
            rtt_samples: Vec::with_capacity(256),
            loss_events: 0,
            total_acks: 0,
            last_report: Instant::now(),
            started: Instant::now(),
            report_interval: Duration::from_secs(2),
        }
    }

    /// Record an RTT sample from an acknowledged packet.
    pub fn record_rtt(&mut self, rtt: Duration) {
        self.rtt_samples.push(rtt);
        self.total_acks += 1;
    }

    /// Record a loss event (N packets lost).
    pub fn record_loss(&mut self, count: u64) {
        self.loss_events += count;
    }

    /// If enough time has passed since the last report, compute and log
    /// current metrics and return them. Otherwise return None.
    pub fn maybe_report(
        &mut self,
        n_acked: u64,
        total_chunks: u64,
        cc_cwnd: usize,
        retransmits: u64,
        chunk_bytes: u64,
    ) -> Option<RealtimeSnapshot> {
        let now = Instant::now();
        if now.duration_since(self.last_report) < self.report_interval {
            return None;
        }
        self.last_report = now;

        if self.rtt_samples.is_empty() {
            return None;
        }

        let min_rtt = *self.rtt_samples.iter().min().unwrap();
        let avg_ns: u128 =
            self.rtt_samples.iter().map(|d| d.as_nanos()).sum::<u128>()
                / self.rtt_samples.len() as u128;
        let avg_rtt = Duration::from_nanos(avg_ns as u64);
        let variance: f64 = self.rtt_samples.iter()
            .map(|d| {
                let diff = d.as_secs_f64() - avg_rtt.as_secs_f64();
                diff * diff
            })
            .sum::<f64>() / self.rtt_samples.len() as f64;
        let jitter = Duration::from_secs_f64(variance.sqrt());

        let progress = if total_chunks > 0 {
            n_acked as f64 / total_chunks as f64 * 100.0
        } else {
            0.0
        };

        let snap = RealtimeSnapshot {
            min_rtt,
            avg_rtt,
            jitter,
            cc_cwnd,
            loss_events: self.loss_events,
            retransmits,
            progress,
            sample_count: self.rtt_samples.len(),
        };

        // Log to stderr for real-time visibility.
        //
        // Rate and ETA are here because percent alone is not enough on a
        // long transfer: a 50 GB file over a WAN runs for over an hour, and
        // "37.2%" twice in a row cannot distinguish healthy progress from a
        // flow that is about to hit the 30 s stall abort.
        let elapsed = now.duration_since(self.started).as_secs_f64();
        let frac = snap.progress / 100.0;
        let rate = if elapsed > 0.0 && chunk_bytes > 0 {
            (n_acked * chunk_bytes) as f64 / elapsed / 1_048_576.0
        } else {
            0.0
        };
        let eta = if frac > 0.001 {
            let total = elapsed / frac;
            format_duration(total - elapsed)
        } else {
            "--:--".to_string()
        };
        eprintln!(
            "  [{:5.1}%] {:6.1} MiB/s  ETA {:>6}  | rtt min={:.1}ms avg={:.1}ms jitter={:.2}ms | cwnd={}KB | retx={} loss_events={}",
            snap.progress,
            rate,
            eta,
            snap.min_rtt.as_secs_f64() * 1000.0,
            snap.avg_rtt.as_secs_f64() * 1000.0,
            snap.jitter.as_secs_f64() * 1000.0,
            snap.cc_cwnd / 1024,
            snap.retransmits,
            snap.loss_events,
        );

        // Keep only recent samples for next window.
        self.rtt_samples.clear();

        Some(snap)
    }
}

/// Snapshot of real-time transfer metrics.
#[derive(Debug, Clone)]
pub struct RealtimeSnapshot {
    pub min_rtt: Duration,
    pub avg_rtt: Duration,
    pub jitter: Duration,
    pub cc_cwnd: usize,
    pub loss_events: u64,
    pub retransmits: u64,
    pub progress: f64,
    pub sample_count: usize,
}

// ── Probe phase ──────────────────────────────────────────────────────────────

/// Probe the network path by sending PathProbe packets and measuring responses.
///
/// Returns a `NetworkProfile` with the measured characteristics and a
/// recommended minimum congestion window.
pub async fn probe_path(
    socket: &UdpSocket,
    remote: SocketAddr,
    conn_id: u64,
    seq: &mut u64,
) -> NetworkProfile {
    let mut recv_buf = vec![0u8; 1500];

    eprintln!("Probing network path ({} probes)...", PROBE_COUNT);

    // Send the probes and collect the echoes *concurrently*.
    //
    // This phase used to send one probe and block on its own reply before
    // sending the next, so it cost `PROBE_COUNT` round trips — 425 ms on a
    // 38 ms path, paid before the first byte of every transfer. (The
    // 15 ms -> 5 ms cut to PROBE_INTERVAL addressed only the spacing, which
    // on a WAN path is the small half of it.)
    //
    // Sending them all first and reading afterwards is *not* the fix: a
    // reply then sits in the socket buffer until the sender stops sending,
    // and every RTT sample is inflated by that wait — measured at 28 ms
    // average on loopback, where the true figure is 0.1 ms. The estimate
    // feeds link classification and the initial window, so corrupting it to
    // save time is a bad trade.
    //
    // So: pace the probes out, and spend the gap between them *receiving*
    // rather than sleeping. The index carried in the payload matches each
    // echo to its own send time. The phase costs the spacing plus one round
    // trip — 83 ms on a 38 ms path — and each sample is measured from its
    // own send.
    //
    // The gap is a receive, not a `sleep`, and that is the whole point.
    // This was first written as two `tokio::join!` halves — a sender that
    // slept between probes and a receiver that read in a loop — on the
    // assumption that the runtime would poll the reader whenever an echo
    // landed. It does not do so reliably here: both halves live in one
    // task, and in practice the reader was serviced once at the start and
    // then not again until the sender's last sleep expired.
    //
    // The corruption that produced is worth recognising on sight. Measured
    // against a Raspberry Pi over 802.11ac, true RTT ~4 ms:
    //
    //     PROBE_SAMPLES ms: [5.30, 48.97, 42.46, 36.39, 30.32,
    //                        24.55, 18.51, 12.38, 6.25, 3.93]
    //
    // Sample 0 is right, sample 9 is right, and 1..8 fall in a straight
    // line decreasing by exactly one PROBE_INTERVAL per index. That is the
    // shape of every echo being read at one instant and differenced against
    // its own staggered send time — a staircase, not a distribution. It
    // reported avg_rtt 22.9 ms and jitter 15.4 ms where ping alongside it
    // measured 3.9 ms and 2.1 ms: a 5.8x overestimate, which inflates the
    // estimated bandwidth-delay product and hence the initial window.
    //
    // A packet capture at the receiver settled where the fault was: it
    // echoed every probe within 0.25 ms and the echoes left 6 ms apart, so
    // they were on the wire on time and read late. Interleaving explicitly
    // removes the dependency on cross-future scheduling entirely.
    let mut send_times: Vec<Option<Instant>> = vec![None; PROBE_COUNT];
    let mut arrivals: Vec<Option<Instant>> = vec![None; PROBE_COUNT];
    let mut probes_sent = 0usize;
    // (datagrams, undecodable, wrong-type) — only for the debug line.
    let mut seen = (0usize, 0usize, 0usize);

    // Read echoes until `until`, or until every probe has been answered.
    // Returns true when nothing more can arrive.
    async fn drain_until(
        socket: &UdpSocket,
        buf: &mut [u8],
        arrivals: &mut [Option<Instant>],
        until: Instant,
        seen: &mut (usize, usize, usize),
    ) -> bool {
        loop {
            if arrivals.iter().all(|a| a.is_some()) {
                return true;
            }
            let now = Instant::now();
            if now >= until {
                return false;
            }
            match tokio::time::timeout(until - now, socket.recv_from(buf)).await {
                Ok(Ok((len, _))) => {
                    let at = Instant::now();
                    seen.0 += 1;
                    let Ok(pkt) = decode_packet(&buf[..len]) else {
                        seen.1 += 1;
                        continue;
                    };
                    if pkt.header.packet_type != PacketType::PathProbeAck {
                        seen.2 += 1;
                        continue;
                    }
                    let Some(b) = pkt.payload.get(..4) else { continue };
                    let idx = u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as usize;
                    if idx < PROBE_COUNT && arrivals[idx].is_none() {
                        arrivals[idx] = Some(at);
                    }
                }
                Ok(Err(_)) => return false, // socket error — the rest count as loss
                Err(_) => return false,     // deadline for this gap
            }
        }
    }

    // Two attempts, and the second is not paranoia — it is the difference
    // between measuring the path and measuring a radio waking up.
    //
    // A link that has been idle can drop most of a burst while it
    // renegotiates. Captured at the receiver on an 802.11ac path after a
    // 3 s pause: of ten probes, **one** arrived, its echo was lost coming
    // back, and the client saw nothing at all — while the HELLO sent
    // 265 ms later, and every packet after it, went through untouched. The
    // whole probe phase had landed inside the wake-up window.
    //
    // Concluding "100% loss, link unknown" from that is wrong twice over:
    // the path is not lossy, and the fallback profile it selects (64 KB
    // cwnd) throttles a transfer that was about to run at full rate. With a
    // 3 s gap between transfers this happened in 6 runs out of 8.
    //
    // The first burst is what warms the link, so retrying costs one extra
    // burst only in the case that was already broken, and nothing at all on
    // a path that answers.
    let mut attempts = 0;
    loop {
        attempts += 1;
        for i in 0..PROBE_COUNT {
            let payload = (i as u32).to_le_bytes();
            if send_probe(socket, remote, conn_id, *seq, &payload).await.is_ok() {
                send_times[i] = Some(Instant::now());
                if attempts == 1 {
                    probes_sent += 1;
                }
                *seq += 1;
            }
            if i < PROBE_COUNT - 1 {
                let next = Instant::now() + PROBE_INTERVAL;
                if drain_until(socket, &mut recv_buf, &mut arrivals, next, &mut seen).await {
                    break;
                }
            }
        }
        // The last probe's echo is still outstanding, and so is anything
        // the gaps did not catch.
        let tail = Instant::now() + PROBE_REPLY_TIMEOUT;
        drain_until(socket, &mut recv_buf, &mut arrivals, tail, &mut seen).await;

        // Retry only on *total* silence. One echo back means the path is
        // answering and the loss figure is a real measurement, not a
        // cold start.
        if attempts >= 2 || arrivals.iter().any(|a| a.is_some()) {
            break;
        }
        // A second set of sends needs its own send times; the first set's
        // are stale and would be differenced against the wrong burst.
        send_times = vec![None; PROBE_COUNT];
    }

    // Drop samples that were delivered as a batch.
    //
    // Several echoes arriving in the same instant did not each take that
    // long to come back: they were held somewhere and released together,
    // and only the last one *sent* has an RTT close to the path's. The
    // others are inflated by however long they waited, and since the sends
    // were paced, that inflation is one PROBE_INTERVAL per position — the
    // straight-line staircase described above.
    //
    // Batching is not ours to prevent. A packet capture at the receiver
    // showed it echoing every probe within 0.25 ms, 6 ms apart, while the
    // sending host stamped eight of them at one instant ~50 ms later:
    // an 802.11 client coalescing downlink delivery. Interleaving the
    // receive with the sends does not change it either — that was tried.
    //
    // So detect it instead. Group arrivals that land within
    // `BATCH_EPSILON`, and keep only the smallest RTT from each group,
    // which is the one that waited least. On the path above this reduces
    // ten samples to three and brings avg_rtt from 22.9 ms to about 4 ms,
    // against ping's 3.5 ms measured alongside.
    let answered: Vec<(Instant, Duration)> = arrivals
        .iter()
        .enumerate()
        .filter_map(|(i, arrival)| {
            let (a, s) = (arrival.as_ref()?, send_times[i].as_ref()?);
            Some((*a, a.duration_since(*s)))
        })
        .collect();
    let answered_total = answered.len();
    let rtt_samples = collapse_batched(answered);
    let batched_out = answered_total - rtt_samples.len();

    if std::env::var("FAVONIUS_PROBE_DEBUG").is_ok() {
        let per: Vec<String> = rtt_samples
            .iter()
            .map(|d| format!("{:.2}", d.as_secs_f64() * 1000.0))
            .collect();
        eprintln!(
            "PROBE_SAMPLES ms: [{}]  (batched-out: {}, sent: {}, dgrams: {}, undecodable: {}, other-type: {})",
            per.join(", "),
            batched_out,
            probes_sent,
            seen.0,
            seen.1,
            seen.2
        );
    }

    let answered_count = arrivals.iter().filter(|a| a.is_some()).count();
    let profile = classify(&rtt_samples, probes_sent, answered_count);

    eprintln!(
        "Network: {} | base_rtt={:.2}ms avg_rtt={:.2}ms jitter={:.3}ms loss={:.0}% | min_cwnd={}KB",
        profile.link_type,
        profile.base_rtt.as_secs_f64() * 1000.0,
        profile.avg_rtt.as_secs_f64() * 1000.0,
        profile.rtt_jitter.as_secs_f64() * 1000.0,
        profile.probe_loss_rate * 100.0,
        profile.min_cwnd / 1024,
    );

    profile
}

// ── Classification ───────────────────────────────────────────────────────────

/// Arrivals that land within this of one another were delivered together.
/// Must stay well below `PROBE_INTERVAL`, or genuinely separate samples
/// (which are one interval apart by construction) would be merged.
const BATCH_EPSILON: Duration = Duration::from_millis(1);

/// Collapse batched deliveries to one trustworthy sample each.
///
/// Takes `(arrival, rtt)` pairs and returns the RTTs worth keeping. Echoes
/// sharing an arrival instant were released together, so only the smallest
/// RTT among them — the one that waited least — reflects the path. The rest
/// are inflated by their wait and are discarded rather than averaged in.
fn collapse_batched(mut answered: Vec<(Instant, Duration)>) -> Vec<Duration> {
    answered.sort_by_key(|(at, _)| *at);
    let mut kept: Vec<Duration> = Vec::new();
    let mut group_start: Option<Instant> = None;
    let mut group_best: Option<Duration> = None;
    for (at, rtt) in answered {
        if group_start.is_some_and(|g| at.duration_since(g) < BATCH_EPSILON) {
            group_best = Some(group_best.map_or(rtt, |b: Duration| b.min(rtt)));
        } else {
            if let Some(b) = group_best.take() {
                kept.push(b);
            }
            group_start = Some(at);
            group_best = Some(rtt);
        }
    }
    if let Some(b) = group_best {
        kept.push(b);
    }
    kept
}

/// `answered` is how many probes were echoed at all; `samples` is the subset
/// whose RTT is trustworthy after batched deliveries are collapsed. They are
/// different numbers and loss must be computed from the first: a de-batched
/// sample was still delivered, and counting it as lost reported 70% loss on a
/// path with none.
fn classify(samples: &[Duration], probes_sent: usize, answered: usize) -> NetworkProfile {
    if samples.is_empty() {
        return NetworkProfile {
            base_rtt: Duration::from_millis(100),
            avg_rtt: Duration::from_millis(100),
            rtt_jitter: Duration::from_millis(50),
            probe_loss_rate: 1.0,
            link_type: LinkType::Unknown,
            min_cwnd: 64 * 1024,
        };
    }

    let base_rtt = *samples.iter().min().unwrap();
    let avg_ns: u128 =
        samples.iter().map(|d| d.as_nanos()).sum::<u128>() / samples.len() as u128;
    let avg_rtt = Duration::from_nanos(avg_ns as u64);

    let variance: f64 = samples
        .iter()
        .map(|d| {
            let diff = d.as_secs_f64() - avg_rtt.as_secs_f64();
            diff * diff
        })
        .sum::<f64>()
        / samples.len() as f64;
    let jitter = Duration::from_secs_f64(variance.sqrt());

    let loss_rate = if probes_sent > 0 {
        (1.0 - (answered as f64 / probes_sent as f64)).clamp(0.0, 1.0)
    } else {
        1.0
    };

    let jitter_ratio = if !base_rtt.is_zero() {
        jitter.as_secs_f64() / base_rtt.as_secs_f64()
    } else {
        0.0
    };

    // Classification thresholds.
    //
    // Every branch below except the first two turns on `jitter`, and with
    // too few samples the spread is not a measurement at all: one surviving
    // sample has zero variance *by definition*, and that zero is exactly
    // what selects LanEthernet over LanWifi — or, on an unluckily low
    // sample, Loopback over both. Observed on an 802.11ac path that a
    // concurrent ping put at 3 ms: a single sample of 0.46 ms classified it
    // `loopback`.
    //
    // This is not a rare corner. Collapsing a batched delivery routinely
    // leaves two or three samples, so the guard is on the common path.
    //
    // Below the threshold, classify on `base_rtt` alone and take the
    // jitter-tolerant reading. The asymmetry is deliberate: assuming wifi
    // on an ethernet link costs almost nothing, while assuming ethernet on
    // a wifi link tells the controller to read real jitter as congestion.
    const MIN_CLASSIFY_SAMPLES: usize = 3;
    let jitter_is_measured = samples.len() >= MIN_CLASSIFY_SAMPLES;

    let link_type = if !jitter_is_measured {
        if base_rtt >= Duration::from_millis(20) {
            LinkType::Wan
        } else {
            LinkType::LanWifi
        }
    } else if base_rtt < Duration::from_micros(500) {
        LinkType::Loopback
    } else if base_rtt < Duration::from_millis(3) && jitter_ratio < 0.3 && jitter < Duration::from_millis(1) {
        LinkType::LanEthernet
    } else if base_rtt < Duration::from_millis(50) && (jitter_ratio > 0.25 || jitter > Duration::from_millis(1)) {
        LinkType::LanWifi
    } else if base_rtt >= Duration::from_millis(20) {
        LinkType::Wan
    } else {
        // Low RTT, low jitter but above loopback — likely Ethernet.
        LinkType::LanEthernet
    };

    // Recommended minimum cwnd based on link type.
    //
    // On WiFi/loopback/LAN we enforce a floor so the CC can never starve
    // the link even when it misinterprets jitter as congestion.
    let min_cwnd = match link_type {
        LinkType::Loopback => 512 * 1024,
        LinkType::LanEthernet => 512 * 1024,
        LinkType::LanWifi => 512 * 1024,
        LinkType::Wan => 16 * 1024,
        LinkType::Unknown => 64 * 1024,
    };

    NetworkProfile {
        base_rtt,
        avg_rtt,
        rtt_jitter: jitter,
        probe_loss_rate: loss_rate,
        link_type,
        min_cwnd,
    }
}

// ── Packet helpers ───────────────────────────────────────────────────────────

async fn send_probe(
    socket: &UdpSocket,
    to: SocketAddr,
    conn_id: u64,
    seq: u64,
    payload: &[u8],
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let header = PacketHeader {
        version: PROTOCOL_VERSION,
        packet_type: PacketType::PathProbe,
        flags: PacketFlags::ACK_ELICITING,
        header_length: HEADER_SIZE as u16,
        connection_id: conn_id,
        stream_id: 0,
        packet_number: seq,
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_micros() as u64,
        payload_length: payload.len() as u32,
        header_crc: 0,
    };
    let mut pkt = Packet {
        header,
        extensions: vec![],
        payload: Bytes::copy_from_slice(payload),
    };
    let buf = encode_packet_auto(&mut pkt);
    socket.send_to(&buf, to).await?;
    Ok(())
}

#[cfg(test)]
mod probe_tests {
    use super::*;

    fn at(base: Instant, ms: f64) -> Instant {
        base + Duration::from_secs_f64(ms / 1000.0)
    }
    fn ms(v: f64) -> Duration {
        Duration::from_secs_f64(v / 1000.0)
    }

    /// The staircase this exists to remove, taken verbatim from a run
    /// against a Raspberry Pi over 802.11ac. Ten probes paced 6 ms apart;
    /// the first echo arrives on time, eight are delivered together ~50 ms
    /// in, the last arrives on time again. True RTT is about 4 ms.
    #[test]
    fn collapses_a_batched_delivery_to_its_least_delayed_sample() {
        let t0 = Instant::now();
        let mut answered = vec![(at(t0, 5.3), ms(5.30))];
        // Eight echoes released in one burst at ~54 ms, each differenced
        // against its own staggered send: 48.97 down to 6.25 by ~6 ms.
        let burst = [48.97, 42.46, 36.39, 30.32, 24.55, 18.51, 12.38, 6.25];
        for (k, rtt) in burst.iter().enumerate() {
            answered.push((at(t0, 54.0 + k as f64 * 0.05), ms(*rtt)));
        }
        answered.push((at(t0, 57.4), ms(3.93)));

        let kept = collapse_batched(answered);

        assert_eq!(kept.len(), 3, "the burst should collapse to one sample");
        // Un-collapsed, the mean of those ten is ~22.9 ms against a true 4 ms.
        let mean = kept.iter().sum::<Duration>() / kept.len() as u32;
        assert!(
            mean < ms(7.0),
            "mean {:?} still carries the batching inflation",
            mean
        );
        assert!(kept.contains(&ms(6.25)), "should keep the burst's least-delayed sample");
    }

    /// Samples that are genuinely one probe-interval apart are separate
    /// measurements and must all survive.
    #[test]
    fn keeps_samples_that_are_not_batched() {
        let t0 = Instant::now();
        let answered: Vec<_> = (0..5)
            .map(|i| (at(t0, 4.0 + i as f64 * 6.0), ms(4.0 + i as f64 * 0.1)))
            .collect();
        assert_eq!(collapse_batched(answered).len(), 5);
    }

    #[test]
    fn empty_input_yields_no_samples() {
        assert!(collapse_batched(vec![]).is_empty());
    }

    /// **Loss is counted from echoes received, not from samples kept.**
    /// De-batching discards samples whose packets did arrive; charging those
    /// to loss reported 70% loss on a path with none, which would drive the
    /// controller off a cliff.
    #[test]
    fn debatched_samples_are_not_counted_as_loss() {
        // Ten probes, all ten answered, but only three samples survive.
        let p = classify(&[ms(4.0), ms(6.2), ms(3.9)], 10, 10);
        assert!(
            p.probe_loss_rate.abs() < 1e-9,
            "loss {} — de-batched arrivals were charged as loss",
            p.probe_loss_rate
        );
    }

    #[test]
    fn genuine_loss_is_still_reported() {
        // Ten sent, four echoed, three samples kept after collapsing.
        let p = classify(&[ms(4.0), ms(6.2), ms(3.9)], 10, 4);
        assert!((p.probe_loss_rate - 0.6).abs() < 1e-9, "got {}", p.probe_loss_rate);
    }

    /// One sample has zero variance by construction, so the jitter-based
    /// branches are meaningless. The exact case seen on the hardware rig:
    /// a lone 0.46 ms sample on an 802.11ac path that ping put at 3 ms,
    /// classified `Loopback` and so treated as a zero-jitter link.
    #[test]
    fn a_single_low_sample_is_not_classified_as_loopback() {
        let p = classify(&[ms(0.46)], 10, 1);
        assert_ne!(p.link_type, LinkType::Loopback, "classified on one sample");
        assert_eq!(p.link_type, LinkType::LanWifi);
    }

    /// Two samples are still too few to call a link jitter-free.
    #[test]
    fn two_samples_do_not_pick_ethernet_over_wifi() {
        // Tight spread that would otherwise satisfy the LanEthernet branch.
        let p = classify(&[ms(1.0), ms(1.02)], 10, 2);
        assert_eq!(p.link_type, LinkType::LanWifi);
    }

    /// The guard must not swallow a genuine WAN: base_rtt alone decides it.
    #[test]
    fn few_samples_still_recognise_a_wan() {
        let p = classify(&[ms(85.0), ms(86.0)], 10, 2);
        assert_eq!(p.link_type, LinkType::Wan);
        assert_eq!(p.min_cwnd, 16 * 1024);
    }

    /// With enough samples the original thresholds still apply, so a real
    /// loopback and a real ethernet link are still told apart.
    #[test]
    fn enough_samples_restores_the_full_classification() {
        let lo = classify(&[ms(0.05), ms(0.06), ms(0.05), ms(0.07)], 10, 4);
        assert_eq!(lo.link_type, LinkType::Loopback);

        let eth = classify(&[ms(1.0), ms(1.05), ms(1.02), ms(1.01)], 10, 4);
        assert_eq!(eth.link_type, LinkType::LanEthernet);

        let wifi = classify(&[ms(3.0), ms(9.0), ms(4.0), ms(11.0)], 10, 4);
        assert_eq!(wifi.link_type, LinkType::LanWifi);
    }
}
