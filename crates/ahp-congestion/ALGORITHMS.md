# AHP Congestion Control & ACK Mode Algorithms

This document describes the congestion control algorithms and acknowledgement
modes implemented in the AHP (Adaptive High-speed Protocol) used by
Favonius for UDP file transfer.

---

## Architecture Overview

```
Sender                                           Receiver
┌──────────────────────┐                  ┌──────────────────────┐
│  send_file()         │                  │  handle_transfer()   │
│  ┌────────────────┐  │   DATA packets   │  ┌────────────────┐ │
│  │ StreamState[N] │──┼─────────────────►│  │StreamRecvState │ │
│  │ (round-robin)  │  │  (multi-stream)  │  │    [N]         │ │
│  └───────┬────────┘  │                  │  └───────┬────────┘ │
│          │           │   ACK / NACK     │          │          │
│  ┌───────▼────────┐  │◄─────────────────┤  ┌───────▼────────┐ │
│  │  CC Controller │  │  (per-stream)    │  │ ACK/NACK logic │ │
│  │  + Pacer       │  │                  │  │ (bitmap/nack)  │ │
│  └───────┬────────┘  │                  │  └────────────────┘ │
│          │           │                  │                     │
│  ┌───────▼────────┐  │                  │                     │
│  │ PacketSender   │  │                  │                     │
│  │ (GSO/sendmmsg) │  │                  │                     │
│  └────────────────┘  │                  │                     │
└──────────────────────┘                  └──────────────────────┘
```

All streams share **one CC controller** and **one in_flight counter**. Each
stream independently tracks acked/received chunks, retransmit queues, and send
times. The sender round-robins across streams when staging packets.

---

## Congestion Control Algorithms

Favonius provides six CC profiles selectable via `--congestion`, plus
`auto`, which is the default and picks one from the probed link type. Each implements
the `CongestionController` trait and can be hot-swapped at the start of a
transfer.

| Profile | Family | Primary control | Best for |
|---------|--------|----------------|----------|
| **Classic** | CUBIC / Compound TCP | cwnd (window-based) | General purpose; what `auto` picks on WAN |
| **Model** | BBR (Google) | pacing rate (model-based) | High-BW long-RTT paths |
| **Fair** | Reno / NewReno AIMD | cwnd (window-based) | Shared / congested networks |
| **WiFi** | Fixed-rate / SampleRate | fixed send rate | Dedicated WiFi LAN |
| **UDT** | UDT4 CUDTCC | inter-packet interval (rate-based) | Bulk transfer on dedicated links |
| **Cycle** (`rl`) | BBR-family gain cycle | probe/drain/cruise gain on a windowed-max delivery estimate | High random loss, no shared bottleneck |

### Shared design choices

The rate-based profiles (UDT, Cycle, Model) share these properties:
- **`wants_timeout_loss() = false`**: only receiver-detected loss (ACK bitmap
  gaps) triggers CC loss handling. Sender-side retransmit timeouts still
  re-queue packets, but do NOT signal the CC.

Classic is window-based and sets **`wants_timeout_loss() = true`**. It was
previously `false` for a defensive reason that no longer applies: the
sender's retransmit timer was a fixed 100 ms, so on any path with a longer
RTT every packet "timed out" before its ACK could arrive and the timeouts
were pure noise. The timer is now derived from the measured RTT and floored
at twice the probed base RTT (`RttEstimator::rto_with_min`), so a timeout is
real evidence of a drop.

Whether that evidence shrinks the window is a separate decision, made by
`loss_indicates_congestion()`: Classic cuts only when something independent
confirms the path is at capacity — a queue building (srtt more than
`LOSS_QUEUEING_FACTOR` = 1.5x the delay baseline), or delivery having
plateaued while the window kept opening. Steady random loss on a satellite
or degraded WAN link produces neither, so the window holds and the sender
simply retransmits. This gate applies to receiver-detected loss as well as
to timeouts.
- **Epoch tracking**: a loss decrease only fires once per congestion epoch
  (`last_dec_seq`). Multiple loss events within the same epoch do not cause
  additional cuts.
- **Seed bandwidth**: the network probe seeds the CC with an initial bandwidth
  estimate so the algorithm does not cold-start from zero.

---

### 1. Classic Controller

**File**: `src/classic.rs` | **Family**: Hybrid delay/loss-based (CUBIC-inspired)

What `auto` selects on WAN, loopback and unclassifiable paths, and the
recommended explicit choice. Uses delay signals (RTT inflation) to
detect congestion before loss occurs, with a loss-based fallback. Redesigned
in v3 (2026-03) to eliminate the Recovery freeze and adopt UDT-style gentle
loss response.

#### State Machine

```
         ┌─────────────┐
         │  SlowStart   │ cwnd += delivered (exponential)
         └──────┬───────┘
    delay signal │ (srtt > 5× min_rtt)
    or cwnd ≥    │ ssthresh
         ┌──────▼───────────────┐
         │ CongestionAvoidance  │ bandwidth-aware increase (see below)
         └──────────────────────┘
                 │
          loss ≥ 3 pkts → cwnd *= 0.875, set loss_flag, skip 1 round
```

**No Recovery state.** On loss, cwnd is cut by 12.5% and the next increase
round is skipped (UDT-style `loss_flag`). This avoids the old v1 behaviour
where cwnd was frozen during Recovery, starving throughput.

#### Bandwidth-Aware Increase

In Congestion Avoidance, the increase is proportional to available headroom:

```
if bw_estimate > current_rate:
    headroom = (bw_estimate - current_rate) × RTT
    increase = headroom / 4   (fill gap over ~4 RTTs)
else:
    increase = 1 MTU           (standard AIMD)
```

This lets Classic ramp quickly when capacity is available (e.g., after link
improves) while falling back to conservative AIMD near saturation.

#### Constants

| Constant | Value | Purpose |
|----------|-------|---------|
| `INITIAL_CWND` | 128 × 1200 = 153,600 B | Fast LAN ramp-up |
| `MIN_CWND` | 4 × 1200 = 4,800 B | Absolute minimum |
| `DELAY_THRESHOLD_FACTOR` | 5.0× | Tolerates WiFi jitter |
| `LOSS_DECREASE_FACTOR` | 0.875 | 12.5% reduction (gentle) |

#### Pacing

Rate = cwnd / smoothed_rtt. Seed bandwidth initialises the pacer directly
from the probe estimate for fast initial convergence.

---

### 2. Model Controller (BBR-Inspired)

**File**: `src/model.rs` | **Family**: Model-based (BBR)

Maintains explicit estimates of bottleneck bandwidth and propagation RTT, and
sets the sending rate to match. Inspired by Google's BBR (Bottleneck Bandwidth
and Round-trip propagation time).

#### State Machine

```
  ┌──────────┐
  │ Startup  │  pacing_gain=2.0, cwnd_gain=2.0
  └────┬─────┘  Exit: bandwidth doesn't grow 25% for 3 rounds
       │
  ┌────▼─────┐
  │  Drain   │  pacing_gain=0.5 (drain queue built in startup)
  └────┬─────┘  Exit: bytes_in_flight ≤ estimated BDP
       │
  ┌────▼─────────────┐
  │ ProbeBandwidth   │  8-phase gain cycle [1.25, 0.75, 1.0, …]
  └────┬─────────────┘  Each phase lasts one min_rtt
       │ every 10s
  ┌────▼─────────┐
  │  ProbeRtt    │  cwnd = 16×MTU for 200ms (measure true min_rtt)
  └──────────────┘  Then restore cwnd → ProbeBandwidth
```

#### Key Formulas

```
target_cwnd      = max_bandwidth × min_rtt × cwnd_gain
target_pacing    = max_bandwidth × pacing_gain
```

#### Loss Handling

Loss does **not** reduce cwnd. The model adjusts naturally through bandwidth
samples. Only ensures cwnd ≥ MIN_CWND (16 × MTU = 19,200 B).

#### Limitations

**Superseded.** This section recorded ~27-30 MiB/s and blamed a cold-starting
bandwidth estimator. Three separate defects were behind it, all now fixed:
the windowed-max bandwidth estimate rescanned its whole sample buffer on
every ACK (O(n) per ACK, ~5 s of a 12.4 s transfer — now a monotonic
deque); the delivery-rate estimate over-read when a retransmit released a
long contiguous run of a cumulative ACK bitmap (now clamped by the measured
send rate); and the pacing deadline ran from the end of the previous flush
rather than the start of the pass, so each pass's own work was added to the
debt instead of absorbed into it. Model now reaches ~100 MiB/s on a 1 Gbit
cross-country path. What remains unexplained is `drain` — feedback
processing — at ~285 us per send pass against Classic's 1.2 us.

---

### 3. Fair Controller (Conservative AIMD)

**File**: `src/fair.rs` | **Family**: Reno / NewReno AIMD

The original TCP congestion avoidance algorithm: Additive Increase,
Multiplicative Decrease. Designed to be "fair" — it backs off aggressively on
loss so that multiple flows sharing a bottleneck converge to equal bandwidth
shares.

#### Behaviour

- **No slow start**: begins at 4 × MTU, grows linearly from the start.
- **Additive increase**: cwnd += MTU per cwnd worth of delivered data (~1 MTU/RTT).
- **Multiplicative decrease**: cwnd × 0.50 on loss (standard Reno halving).
- **Optional rate cap**: pacing rate can be capped externally; cwnd is adjusted
  to match: `cwnd = min(cwnd, max_rate × RTT)`.

| Constant | Value |
|----------|-------|
| `INITIAL_CWND` | 4 × 1200 = 4,800 B |
| `MIN_CWND` | 2 × 1200 = 2,400 B |
| `LOSS_DECREASE_FACTOR` | 0.50 |

#### When to use

Best for transfers sharing bandwidth with other TCP flows (e.g., over a WAN
link). The aggressive loss response ensures fair coexistence but sacrifices
peak throughput on dedicated links.

---

### 4. WiFi Controller (Fixed-Rate)

**File**: `src/wifi.rs` | **Family**: Fixed-rate / SampleRate

A measurement-then-send approach similar to how WiFi rate adaptation works at
the MAC layer. Measures the link capacity during an initial phase, then sends
at a fixed fraction of measured bandwidth.

#### State Machine

```
  ┌───────────┐
  │ Measuring │  Send at initial rate, observe delivery rate
  └─────┬─────┘  Exit: after 20 RTT samples
        │
  ┌─────▼─────┐
  │  Steady   │  Send at 95% of measured bandwidth
  └─────┬─────┘  Periodic re-probing
        │ every 5s
  ┌─────▼─────┐
  │ Probing   │  Brief rate bump to detect capacity changes
  └───────────┘
```

#### Loss Handling

Loss above a threshold (>5% of window) reduces the sending rate by ~11%.
Below-threshold loss is ignored (WiFi interference, not congestion).

#### Limitations

The fixed-rate approach doesn't adapt well to dynamic WiFi conditions.
Classic CC with its gentle loss response and bandwidth-aware increase handles
WiFi better in practice.

---

### 5. UDT Controller

**File**: `src/udt.rs` | **Family**: UDT4 CUDTCC (rate-based)

A faithful Rust port of UDT4's congestion control algorithm. The primary
control variable is `pkt_snd_period` (inter-packet interval in microseconds),
not a congestion window. This rate-based approach is fundamentally different
from window-based TCP CC.

#### Key Properties

- **Rate-based**: controls the sending period between packets.
- **Gentle loss response**: period *= 1.125 (~11% rate decrease), with at most
  5 decreases per congestion epoch.
- **Bandwidth-driven increase**: uses `B = bandwidth - current_rate` headroom
  to compute rate increases. Large headroom = fast ramp, no headroom = minimal
  increase.
- **Slow start**: cwnd grows by acked packets until `max_cwnd`, then switches
  to rate control.

#### Rate Increase Formula (UDT4)

```
B = estimated_bandwidth - current_rate_pps     (available headroom)

if B > 0:
    inc = 10^(ceil(log10(B × MSS × 8))) × 0.0000015 / MSS
else:
    inc = MIN_INC (0.01)

period = period × SYN / (period × inc + SYN)
```

#### Constants

| Constant | Value | Purpose |
|----------|-------|---------|
| `SYN_INTERVAL` | 5 ms | Rate control check interval |
| `INITIAL_SND_PERIOD` | 1.0 μs | Start sending as fast as possible |
| `LOSS_INCREASE_FACTOR` | 1.125 | Gentle 11% rate decrease on loss |
| `MAX_DEC_PER_EPOCH` | 5 | Rate won't drop below ~55% in one epoch |

#### cwnd in UDT

The cwnd is set to **4× BDP** and exists only to prevent the window from
bottlenecking the pacing rate. The pacing rate (from `pkt_snd_period`) is the
real throughput control. Dynamic `max_cwnd` growth (up to 4096 packets)
prevents the window from capping throughput on long transfers.

---

### 6. Cycle Controller (`--congestion cycle`, alias `rl`)

**File**: `src/rl.rs` | **Family**: BBR-adjacent gain cycle

**No learned policy ships, and this section previously described one that
does not run.** The file is still `rl.rs` and the CLI still accepts `rl`
because both are load-bearing names; what executes is a fixed gain cycle.

#### What runs

The sending rate is `gain x btlbw`, where `btlbw` is a windowed maximum of
measured delivery over roughly 10 RTTs — BBR's bottleneck estimate — and
`gain` comes from a probe/drain/cruise cycle clocked in round trips:

| phase | gain | length |
|---|---|---|
| probe | 1.25 | 2 RTTs |
| drain | 0.75 | 2 RTTs |
| cruise | 1.00 | 4 RTTs |

Mean gain over a cycle is 1.0. An RTT-clocked ramp governs startup. The
window is bounded at a multiple of the BDP and the rate is bounded by the
same delivery ceiling and progress floor the other rate-based profiles use.

If a weight file is present (`$FAVONIUS_RL_MODEL` or
`~/.config/favonius/rl_weights.bin`, magic `AHPRL002`), an 8->32->16->1 MLP
supplies the gain instead, bounded to **[0.90, 1.15]**. **No weight file
ships**, so this path is not the shipped configuration. `AHPRL001` files
are rejected by magic: the layout did not change when the semantics did, so
an old file would load cleanly and mean something else.

#### Why there is no learned policy

Nine attempts have failed to beat the fixed cycle: three offline retrains,
PPO seeds 0-3 at 300k timesteps, one run at 1M, and a contextual bandit
over the cycle's own parameters trained on the rig (36 real transfers, six
arms). The bandit's best candidate was +27% on one context with a
within-arm standard deviation larger than the effect (Welch t = 0.91,
n = 3), and was discarded.

The one effect that did survive: a 1.50 gain with a 2-RTT probe is
genuinely worse than the shipped setting (84.3 +-1.6 against 93.6 +-1.2,
t = -8.3, at 7.3% retransmits against 0.9%). The arms around the shipped
setting are indistinguishable from it. **The parameters sit in a flat
region, which is why tuning them learns nothing.**

Two earlier action designs were removed as defects, and they carried all of
the apparent performance: a multiplier compounded once per 5 ms regardless
of RTT (so "hold steady" meant a different thing at every RTT), and an
action applied to *instantaneous* delivery, which backing off destroys —
making a probe-down unrecoverable.

#### Training

`training/train_closed_loop.py` is the current trainer and gates export on
beating the fixed cycle on both worst case and mean; it writes no weights
on failure. `training/train_rl.py` is superseded — it emits `AHPRL001`,
which the loader rejects. `training/train_cycle_bandit.py` tunes the cycle
parameters on the rig and gates on a significance test.

---

## Pacing

**File**: `src/pacer.rs`

Token-bucket pacer that spreads packet transmissions evenly.

### Mechanism

- **Credit accumulates** over time at `rate_bps` bytes/sec.
- **Burst allowance**: up to 10 packets (12,000 B) can be sent instantly.
- **Per-packet deduction**: sending a packet deducts its size from credit.
- **Throttling**: when credit is negative, `next_send_time()` returns when
  credit will recover.

The sender's hot path does not sleep (which has ~1 ms floor on Linux). Instead
it drains ACKs in a busy loop until the pacing deadline, turning idle pacing
time into useful feedback processing.

---

## Supporting Estimators

**File**: `src/metrics.rs`

### RTT Estimator (RFC 6298 EWMA)

```
srtt    = 7/8 × srtt + 1/8 × sample
rtt_var = 3/4 × rtt_var + 1/4 × |srtt − sample|
RTO     = srtt + max(4 × rtt_var, 1 ms), minimum 200 ms
min_rtt = rolling minimum (never resets)
```

The sender feeds the CC with the **minimum RTT** from each ACK batch to avoid
inflating the estimate with sender-side queuing or ACK batching delays.

### Bandwidth Estimator

Windowed maximum over the last `BW_WINDOW_RTTS` (10) round-trip intervals.
Samples are timestamped; expired samples are evicted and `max_bandwidth`
recomputed from remaining entries.

### Delivery Rate Estimator

Computed as `in_flight_bytes / min_rtt` per ACK batch. This captures the
aggregate sending rate across all streams, not just the per-ACK subset.

---

## ACK Modes

### Bitmap Mode (Default)

The receiver sends an **AckBitmap** packet after every 128 data packets per
stream, plus a 15 ms periodic timer for stragglers.

**AckBitmap wire format** (26-byte header + variable bitmap):

| Field | Size | Description |
|-------|------|-------------|
| Stream ID | 4 B | Which stream this ACK covers |
| Base Packet Number | 8 B | Start of the acknowledged range |
| Highest Contiguous | 8 B | All packets from base..=hc received |
| Ack Delay | 4 B | Receiver processing delay (μs) |
| Bitmap Length | 2 B | Bitmap size in bytes |
| Bitmap | var | LSB-first bits for packets after hc |

**Sender processing**: marks chunks as acked, subtracts from `in_flight`,
feeds RTT + delivery rate to CC.

**Retransmission**: timeout-based. The timer is adaptive —
`srtt + 4*rttvar`, floored at `max(configured, 2 x probed base RTT)` and
capped at 5 s — so it can never fire before the path is physically able to
answer. The configured value (100 ms bitmap / 500 ms NACK) acts as the
floor on fast links, preserving LAN recovery latency. If a chunk's
`sent_time` exceeds the timer and it hasn't been acked, it's queued for
retransmit. The CC is **only** notified of loss if `wants_timeout_loss()`
returns true (the rate-based CCs opt out).

**RTT sampling** follows Karn's algorithm: a chunk that has been queued for
retransmit exists in more than one copy on the wire, so an ACK for it can no
longer be attributed to a known send time and yields no RTT sample at all.
Sampling it anyway produces a value bounded by the retransmit interval
rather than by the path — and since the sender feeds the CC the *minimum*
sample of each ACK batch, such a value would be preferentially selected.

### NACK Mode

The receiver detects **gaps** in each stream's chunk sequence and immediately
sends a **NackRange** packet listing missing chunk ranges.

**NackRange wire format** (6-byte header + ranges):

| Field | Size | Description |
|-------|------|-------------|
| Stream ID | 4 B | Which stream |
| Range Count | 2 B | Number of missing ranges |
| Ranges | 16 B each | (start_pn, end_pn) inclusive pairs |

**Gap detection**: per-stream `expected_next_local` high-water mark. When a
chunk arrives ahead of expected, the gap between expected and received is
scanned for unreceived chunks.

**Progress ACKs**: sparse AckBitmaps are still sent — every 64 data packets
inline, plus a 10 ms timer — to provide RTT feedback for the CC.

**Sender processing**: missing chunks are queued at the **front** of the
stream's retransmit queue (priority). Crucially:

- `in_flight` is **not** decremented (the chunk is still outstanding until acked).
- The CC **is** notified of newly-detected loss, but each controller decides
  what to do with it; Classic applies the congestion gate described above,
  so a NACK burst with no queueing and no plateau does not shrink the window.

Not decrementing `in_flight` prevents the retransmit-burst spiral that occurs
when NACKs falsely create window capacity on WiFi, where reordering is common.

**Fallback timeout floor**: 500 ms (longer than bitmap mode's 100 ms). Only
fires if NACKs themselves are lost.

| Aspect | Bitmap | NACK |
|--------|--------|------|
| Feedback trigger | Every 128 packets + 15 ms timer | Immediate on gap + 10 ms timer |
| Retransmit driver | Sender timeout (>=100 ms, RTT-adaptive) | Receiver NACK (immediate) |
| CC loss signal | Only if `wants_timeout_loss()` | Yes, subject to each CC's own gating |
| Best for | General purpose | Low-loss wired links |

---

## Multi-Stream Multiplexing

### Stream Assignment

The file is split into N contiguous chunk ranges:

```
Stream 0: global chunks [0, chunks_per_stream)
Stream 1: global chunks [chunks_per_stream, 2×chunks_per_stream)
…
```

Remainder chunks are distributed one-per-stream to the first R streams.

### Shared vs Independent State

| Shared (one instance) | Per-stream |
|-----------------------|------------|
| CC controller | `acked[]`, `n_acked` |
| `in_flight` counter | `sent_times[]` |
| Packet sequence number | `retx_queue` |
| Batch sender | `next_local` (unsent cursor) |
| Metrics tracker | `received[]`, `n_received` (receiver) |

### Benefits

- **Loss isolation**: a burst of loss affecting stream 2's chunks doesn't stall
  streams 0, 1, 3 from making progress.
- **Better window utilisation**: round-robin distributes the cwnd across
  independent chunk sequences, avoiding head-of-line blocking.

---

## GSO (Generic Segmentation Offload)

When the kernel supports UDP GSO (Linux 4.18+), the sender uses `sendmsg(2)`
with a `UDP_SEGMENT` control message instead of `sendmmsg(2)`. This passes one
large buffer to the kernel, which splits it into individual UDP datagrams at
`segment_size` boundaries.

### Benefits

- One skb allocation instead of N
- One checksum computation instead of N
- One socket lock acquisition instead of N
- Better NIC batching

### Constraints

- All segments must be the same wire size (last segment may be smaller).
- Maximum super-packet size: ~64 KB → capped at `65535 / segment_size` segments.
- Runtime-detected with automatic fallback to `sendmmsg`.

---

## Network Probe & cwnd Floor

Before data transfer, the sender sends 10 PathProbe packets to classify the
link:

| Link Type | base_rtt | Jitter | cwnd Floor |
|-----------|----------|--------|------------|
| Loopback | < 0.5 ms | — | 512 KB |
| LAN/Ethernet | < 3 ms | < 0.3 ratio, < 1 ms | 512 KB |
| LAN/WiFi | < 50 ms | > 0.25 ratio or > 1 ms | 512 KB |
| WAN | ≥ 20 ms | — | 16 KB |

The floor is applied in two places:

1. **Sender window check**: `effective_cwnd = max(cc.cwnd, floor)`
2. **CC internal minimum**: `seed_bandwidth(floor / base_rtt)` sets
   the CC's pacing rate and bandwidth estimate so it doesn't cold-start.

---

## Performance (2026-03-28)

Measured transferring 1 GB to a Raspberry Pi 4.

### Ethernet (local → Pi, ~0.5 ms RTT, 0% loss)

| Profile | Throughput | Retransmits |
|---------|------------|-------------|
| **Classic** | **65 MiB/s** | 2-6K |
| **UDT** | **67 MiB/s** | 0-741 |
| UDT C++ reference | 17 MiB/s | — |
| rsync (SSH) | ~25 MiB/s | — |

### WiFi (local → Pi, ~7 ms RTT, 10% probe loss)

| Profile | Throughput | Retransmits |
|---------|------------|-------------|
| **Classic** | **28 MiB/s** | 210-412K |
| **UDT** | **28 MiB/s** | 440-568K |
| UDT C++ reference | 21 MiB/s | — |

Both Classic and UDT perform equally well and are the recommended profiles.
WiFi performance is link-limited, not CC-limited.

### WAN simulation (2026-04-05, veth + tc netem, 128 MB)

Fair comparison using network namespaces with veth pairs (netem affects
all algorithms equally). RL model trained on diverse traces (LAN, metro,
WAN, satellite, degraded — 9 scenarios x 3 runs x 256 MB).

| Scenario | RTT | Loss | Classic | Model | UDT CC | **RL** |
|----------|-----|------|---------|-------|--------|--------|
| Baseline | 0 ms | 0% | 27.8 | 22.4 | 27.2 | **33.5** |
| Metro | 10 ms | 0.1% | 4.4 | 10.5 | 25.6 | **26.7** |
| Cross-country | 50 ms | 0.5% | 6.6 | TIMEOUT | 15.8 | **23.1** |
| Transatlantic | 100 ms | 1% | TIMEOUT | TIMEOUT | **13.6** | TIMEOUT |
| Satellite | 300 ms | 2% | TIMEOUT | 10.3 | 9.6 | **12.2** |
| Degraded | 200 ms | 5% | TIMEOUT | 10.6 | 8.7 | **17.9** |

All values in MiB/s. TIMEOUT = stalled (no progress for 30s). veth namespace
with GSO enabled.

> **SUPERSEDED — do not cite this table.** It was measured on an
> **unshaped** veth pair: netem dropped a fixed fraction of packets and
> forwarded the rest at bridge speed. With no bottleneck there is nothing to
> congest, so a window far past the BDP costs nothing, queueing delay never
> builds, and the ranking rewards whichever algorithm opens its window
> fastest. That is not a congestion-control result. Re-measured behind a
> 100 Mbit token bucket (below), the ordering changes and most of the
> spread disappears. Kept for provenance only.

### WAN simulation behind a real bottleneck (2026-08-03)

Same netem impairments, but with a `tbf` token bucket at 100 Mbit and a
BDP-sized queue, so a window past the BDP now costs queueing delay and
drops. 128 MB, 3 runs per cell, jitter off (see the note in
`benchmarks/scripts/bench_netem_fair_v2.sh` on why reordering is a separate
axis). netem delays are one-way, so RTT is twice the figure shown. Link
ceiling 11.92 MiB/s.

> This is the **n=3 run of 2026-08-03**
> (`benchmarks/results/netem_fair_v2_100mbit_q1.0_j0_2026-08-03.csv`). The
> README quotes a later **n=8** re-recording of the same four cells
> (`benchmarks/baselines/main.tsv`), which reads +1.8 to +3.5 MiB/s higher on
> the impaired paths for `classic` — the column the README quotes — and
> +0.2 to +1.6 for `model` and `rl`. Both are published; the n=8 figures are the ones to cite.
> `encrypt` below is Classic plus AES-256-GCM, not a selectable profile.

| Scenario | delay/loss | Classic | Model | RL | encrypt | QUIC | UDT | UFTP |
|---|---|---|---|---|---|---|---|---|
| Baseline | 0 ms / 0% | 10.79 | 10.83 | 10.85 | 10.67 | **11.08** | 10.87 | 10.69 |
| Metro | 5 ms / 0.1% | 10.74 | 10.73 | 10.81 | 10.62 | **11.05** | 7.04 | 10.84 |
| Cross-country | 25 ms / 0.5% | 9.04 | 9.89 | **10.29** | 8.96 | 2.55 | 5.27 | 8.28 |
| Transatlantic | 50 ms / 1% | 7.35 | 9.08 | **9.60** | 7.62 | 0.86 | 3.24 | 6.43 |
| Satellite | 150 ms / 2% | 6.62 | 7.25 | 7.06 | **8.67** | FAIL | 1.94 | 3.74 |
| Degraded | 100 ms / 5% | 5.22 | 7.97 | **8.70** | 4.80 | FAIL | 0.30 | 4.31 |

MiB/s, mean of 3. FAIL = no run delivered a verified file within 180 s.
QUIC is quinn 0.11 + cubic, UDT is the C++ reference implementation, UFTP
is unicast. `encrypt` is Classic plus AES-256-GCM, not a separate profile.

**Read the retransmit column before reading the throughput column.** RL
tops three of six scenarios, and it gets there by brute force:

| Scenario | Classic retx | Model retx | RL retx |
|---|---|---|---|
| Cross-country | 0.4% | 1.7% | **60.6%** |
| Transatlantic | 1.1% | 1.4% | **60.7%** |
| Satellite | 2.1% | 3.2% | **61.6%** |
| Degraded | 5.1% | 5.6% | **60.2%** |

Percentage of transmitted packets that were retransmissions, run 1 of each
cell. RL moves the same 128 MB using ~250k packets where Classic and Model
use ~100k. On satellite its window reaches 29 MB against a 3.75 MB BDP —
about 8x — and it holds the bottleneck queue full, taking the path from
150 ms to 301 ms RTT for the whole transfer.

So RL's 8-10% goodput edge over Model costs 2.5x the link and doubles
latency for anything sharing the path. It is not a faster controller, it is
a louder one, and the selection criterion for a default is what it does to
a shared link, not what it scores on a dedicated one.

**Key findings:**
- **SUPERSEDED (2026-08-10, again 2026-08-12).** Model is not the default
  and neither is `classic`: the default is `auto`, which resolves to
  `classic` on WAN and `model` on LAN. The
  recommendation below predated a 448-cell measurement and the `congested`
  scenario, which together reversed it. `classic` is within 10% of the best
  in every scenario, never fails, and stays under 6% retransmits
  throughout.
- **Behind a bottleneck the algorithms converge at low RTT.** Every
  profile lands within 2% of every other at 0-5 ms, at ~91% of the link.
  The large spreads in the 2026-04-05 table were the missing bottleneck.
- **QUIC collapses on WAN**: 11.08 at baseline, 2.55 at 25 ms/0.5%, 0.86 at
  50 ms/1%, nothing at all beyond. Verified against a clean rig — an
  earlier run that showed QUIC failing from `metro` onward was a harness
  fault, not a QUIC result (the kill list could name itself; fixed).
- **UDT degrades monotonically to near-zero** (0.30 MiB/s at 100 ms/5%).
- Tsunami did not complete a single cell in any scenario, including
  baseline. Unresolved; treated as a rig/tool integration failure rather
  than a measurement.
- **Classic remains bimodal on satellite**: 6.09 / 8.80 / 4.96 across three
  identical runs. Unexplained. `encrypt` — the same controller with
  encryption added — lands tightly at 8.60/8.79/8.62 and so appears to beat
  it; that is Classic's fast mode reached consistently, not a gain from
  encryption, and it does not reproduce on degraded (4.27-5.48 vs
  4.53-6.00).
- **The RL rows above are historical.** They were measured with the
  `AHPRL001` weights and the compounding-multiplier action. Both are gone:
  the action is now a gain on a windowed-max delivery estimate, the magic
  is `AHPRL002`, and no weight file ships. With no weights, `--congestion
  rl` runs the **probe/drain/cruise gain cycle** — probe 1.25x for 2 RTTs,
  drain 0.75x for 2, cruise 1.0x for 4, mean gain 1.0. It does *not* run
  the `DEFAULT_GAIN = 1.075` constant: that constant lives in `get_action`,
  which the no-weights path never reaches, so it and `FAVONIUS_RL_GAIN` are
  dead code in the shipped configuration. An earlier revision of this file
  said the constant is what runs. It is not, and the error cost a day of
  rig measurements before it was caught. A learned policy has to beat the
  constant on worst case and mean before the trainer writes weights at all.

> A note on a retraction. An earlier revision of this file stated that RL
> "delivers 0% on 200 ms+ paths". That figure came from the closed-loop
> training simulator evaluating the *v3* retrained weights, not from this
> rig and not from the weights that ship. On hardware with v2 weights RL
> delivers 7.06 and 8.70 MiB/s on those two scenarios. The conclusion —
> do not default to RL — survives, but the stated reason was wrong, and
> the real reason is the retransmit table above.

**Recommendation.** `classic` is what `auto` picks on WAN, and the supported choice
everywhere. Which profile is *fastest* depends on where the loss comes
from, and at 1 Gbit the split is clean (MiB/s, n=5-8):

| path | loss source | `classic` | `cycle` | `model` |
|---|---|---|---|---|
| 25 ms, 0.5% | injected | 93.7 | 93.3 | **100.2** |
| 50 ms, 1% | injected | 80.3 | **87.5** | 84.7 |
| 150 ms, 2% | injected | 49.0 | **59.3** | 47.0 |
| 100 ms, 5% | injected | 55.1 | **68.9** | 63.3 |
| 25 ms, shallow queue | congestion | 100.8 | 96.3 | **101.9** |
| 50 ms, shallow queue | congestion | **95.5** | 85.0 | 86.2 |
| 150 ms, shallow queue | congestion | **70.8** | 59.3 | 54.9 |

The rate-based profiles win every injected-loss path by 7-25% because they
do not read loss as congestion. On congestion-induced loss they lose the
50 ms and 150 ms cells by 11-19% for the same reason — but not the 25 ms
one, which `model` takes by 1.1%, a margin inside the noise. Delay and
queue depth covary across these three cells (0.80, 0.40, 0.25 BDP as RTT
rises), so the sweep separates loss *origin* cleanly and delay from queue
depth not at all. No profile currently distinguishes the two kinds of
loss, so none is right on both.

`auto` resolves to `classic` on WAN because congestion-induced loss is what a shared
link produces, and because a controller that ignores congestion signals is
not merely slower there — it is unfriendly to everything else on the link.
On a path with high random loss and no shared bottleneck (satellite, a poor
radio link), measure `cycle` or `wifi`.

`--congestion cycle` is the profile formerly called `rl`; `rl` still works
as an alias. No learned policy ships and none is planned — nine attempts
failed to beat the fixed cycle, the last a rig-trained contextual bandit
over the cycle's own parameters whose best result was smaller than its own
run-to-run spread (Welch t = 0.91 at n=3). What runs is the gain cycle
described above. The 60% retransmit figure in older revisions belonged to
the compounding action, which is gone; on the current tree retransmits
track the path's own loss floor.

Data: `benchmarks/results/netem_fair_v2_100mbit_q1.0_j0_2026-08-03.csv`.
No pre-trained weights ship; see the note on `--congestion rl` above.
Note: weights are **not loaded automatically** — the controller only reads
`$FAVONIUS_RL_MODEL` or `~/.config/favonius/rl_weights.bin` (copy the file
there); without weights `--congestion rl` runs `advance_cycle()` — the probe/drain/cruise gain cycle plus the RTT-clocked ramp. The UDT-style path is only the pre-first-delivery-sample bootstrap, not the steady state, and a rejected weight file is logged at warn level rather than swallowed silently.

### Raw send path microbenchmark (loopback, 137 MB)

| Sender | Throughput | Packet rate |
|--------|-----------|-------------|
| **AF_XDP** (raw packet submission) | **417 MiB/s** | **303K pps** |
| io_uring (sendmsg SQE batching) | 57 MiB/s | ~42K pps |
| GSO (sendmsg + UDP_SEGMENT cmsg) | 55 MiB/s | ~40K pps |
| Zero-copy (2-iovec sendmmsg) | ~58 MiB/s | ~42K pps |
| sendmmsg (vectored syscall) | ~26 MiB/s | ~19K pps |

**Caveat on io_uring**: the loopback +4% over GSO is misleading. Under loss
and latency io_uring degrades **60-82%** vs GSO because `submit_and_wait`
blocks the send loop when the kernel socket buffer fills. **GSO is the
recommended pacing mode**; io_uring is debug-only.

AF_XDP is ~7.5x faster than GSO on raw packet submission. This is the ceiling
for AHP send path performance. Full AHP integration (with CC, reliability,
and encryption) would add overhead but could still exceed current throughput
significantly on dedicated high-speed links.

### GSO vs io_uring under WAN simulation (veth + tc netem, 128 MB, RL CC)

| Scenario | RTT/Loss | GSO | io_uring | delta |
|----------|---------|-----|----------|-------|
| baseline | 0/0% | 27.6 | 24.8 | -10% |
| metro | 10ms/0.1% | 26.1 | 32.8 | +26% |
| cross-country | 50ms/0.5% | 23.0 | 9.2 | -60% |
| transatlantic | 100ms/1% | TIMEOUT | TIMEOUT | — |
| satellite | 300ms/2% | 12.9 | 2.4 | **-82%** |
| degraded | 200ms/5% | 17.3 | 3.5 | **-80%** |

io_uring catastrophically underperforms on lossy/high-latency links.
**Always use `--pacing batch` (GSO, the default).**

Requires: Linux 4.18+, root/CAP_NET_ADMIN, XDP-capable NIC for zero-copy mode.
Train on your own link: see `benchmarks/scripts/collect_rl_traces.sh`.
