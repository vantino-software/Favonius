#!/usr/bin/env python3
# Favonius — high-performance file transfer over UDP
# Copyright (c) 2025-2026 Vantino SàRL
# SPDX-License-Identifier: Apache-2.0

"""
Closed-loop congestion-control training environment.

READ THIS BEFORE TRUSTING ANY NUMBER THIS PRODUCES.

**This environment cannot currently validate anything about the shipped
controller, and its export gate is not evidence.** Two independent reasons,
both measured on 2026-08-08:

1. **It models a code path that does not execute in production.** The rate
   law here is `rate <- action * btlbw`, which in rl.rs is reached only when
   weights are loaded (`get_action`). No weights ship, so the shipped
   controller runs `advance_cycle` plus the RTT-clocked ramp instead. Of the
   five mechanisms rl.rs uses -- gain cycle, ramp, loss back-off, loss
   compensation, and a delivery estimator averaged over
   DELIVERY_WINDOW_RTTS -- this file implemented **none**. Three have since
   been added (the estimator, the loss back-off, and the constants they
   need); the cycle and ramp have not, because a policy would *replace*
   them, which is the only coherent reading of what a policy is for here.

2. **Its absolute numbers do not match the rig by a factor of four to
   eight.** With the estimator corrected, constant gains across the action
   range score 7-17% utilisation here. The same controllers on the rig
   measure 56-87%. Before the correction the figures were 9-36%, inflated by
   a per-tick sample fed to a max filter -- exactly the estimator rl.rs
   measured at 2.2x capacity and rejected. Correcting it did not make this
   environment agree with the rig; it revealed that it never had.

It also cannot rank two constant gains the way the rig does, which was
measured separately and is the cheapest available check.

What it is still good for: it is a closed loop, so an action has
consequences, which the trace-replay trainer it replaced could not offer. It
is a reasonable place to develop a policy *shape*. It is not a place to
decide whether one ships.

What calibration would require, in order:
  - rig ground truth for the policy path at several gains, obtained with
    `train_closed_loop.py --export-rejected` and the bench image, since
    DEFAULT_GAIN is unreachable in the shipped configuration;
  - this environment reproducing that ranking, and roughly that level;
  - only then, an export gate whose verdict means something.

Original description follows.

Replaces the trace-replay pipeline in train_rl.py, whose environment
advanced to the next recorded sample regardless of the action, so the agent
never observed a consequence. Here the action sets the sending rate, the
bottleneck decides what that produces, and the reward reflects it.
"""

from __future__ import annotations

import math
from collections import deque
import numpy as np
import gymnasium as gym
from gymnasium import spaces

# ── constants mirrored from crates/ahp-congestion/src/rl.rs ────────────────
INPUT_DIM = 8
# Action range: a gain on the measured delivery rate.
#
# Was 0.5-2.0, inherited from when the action was a compounding multiplier
# on the *current* rate. As a gain on delivery that range is badly
# conditioned: the steady state of `rate <- g * delivered` is `g * capacity`
# with a permanent loss fraction of (g-1)/g, so g=1.25 parks the link at 20%
# loss and g=2.0 at 50%. Everything above ~1.11 is a standing overdrive and
# everything below 1.0 shrinks the rate; the band that does useful work is
# about 7% of the range. Measured: the reward landscape over constant gains
# peaks sharply at 1.1 on five of eight scenarios and falls off a cliff by
# 1.25.
#
# Narrowing the range puts the network's whole output resolution on the part
# that steers. It is the same fix as making the action RTT-invariant, one
# level down: that stopped "hold steady" from meaning different things on
# different paths, this stops most of the action space from meaning nothing
# at all.
ACTION_MIN, ACTION_MAX = 0.90, 1.15
RTT_NORM = 1.0                  # seconds
BW_NORM = 1_000_000_000.0       # 1 Gbps in bytes/sec
GRADIENT_CLIP = 1.0
SYN_INTERVAL = 0.005            # 5 ms rate-control cadence
MSS = 1414
RATE_PROBE_CEILING = 2.0

# ── sender/receiver behaviour, mirroring pathsim.rs ────────────────────────
# Reference utilisation per scenario: what a constant max-push policy
# achieves there. Reward is scored *relative* to this rather than as a
# fraction of link capacity.
#
# Absolute utilisation is not comparable across these paths. A 5% loss,
# 200 ms link tops out near 5% of link under any constant policy, while
# metro reaches 97%; optimising the unnormalised mean therefore means
# optimising metro and ignoring the rest. Worse, an absolute idle floor
# (tried at 10%) is unreachable on four of the eight scenarios even under
# max push, so the penalty fired no matter what the agent did — a constant
# offset carrying no gradient, which is exactly why the first two policies
# stalled on satellite and degraded and still scored well.
REFERENCE_UTILISATION = {
    # Recalibrated 2026-08-03 against the delivery-gain dynamics. The
    # previous values were measured under the compounding-multiplier
    # action and were stale the moment that changed -- satellite's 0.108
    # was literally the old max-push figure, so no policy could earn a
    # positive reward there however well it behaved. Each entry is the
    # mean utilisation of the best constant gain in that scenario.
    "lan": 0.362,
    "metro": 0.092,
    "cross-country": 0.066,
    "transatlantic": 0.629,
    "satellite": 0.221,
    "degraded": 0.701,
    "fat-fast": 0.51,
    "shallow-queue": 0.056,
}
# Fraction of the reference below which the controller counts as idling.
IDLE_FLOOR_REL = 0.25
# Weight on sustained queueing delay. Large enough to matter against a
# reward of order 1, small enough that it cannot by itself beat the idle
# penalty -- stalling must stay worse than queueing.
QUEUE_DELAY_PENALTY = 0.4
# Progress floor, mirroring MIN_PACED_PKTS_PER_RTT in rl.rs.
MIN_PACED_PKTS_PER_RTT = 8.0
IDLE_PENALTY = 0.5

ACK_EVERY = 128
ACK_TIMER = 0.015
RETX_SCAN = 0.020
RETX_FLOOR_MIN = 0.100


class PathSim:
    """Bottleneck path with a finite queue, propagation delay and loss."""

    def __init__(self, rng, delay_s, capacity_bps, queue_pkts, loss):
        self.rng = rng
        self.delay = delay_s
        self.capacity = capacity_bps
        self.queue_pkts = queue_pkts
        self.loss = loss
        self.pkt_time = MSS / capacity_bps
        self.bottleneck_free = 0.0
        # Packets are enqueued in non-decreasing arrival order (the
        # bottleneck serialises), so the earliest is always at the front.
        # Rebuilding a list each call is O(n) per step and quadratic over an
        # episode — the same trap fixed in pathsim.rs.
        self.inflight = deque()  # (arrive_time, chunk_id, dropped)

    def rtt(self):
        return self.delay * 2.0

    def bdp(self):
        return self.capacity * self.rtt()

    def send(self, now, chunk):
        """Enqueue one packet; returns True if it will be delivered."""
        if self.bottleneck_free < now:
            self.bottleneck_free = now
        qlen = (self.bottleneck_free - now) / self.pkt_time
        dropped = qlen >= self.queue_pkts or self.rng.random() < self.loss
        self.bottleneck_free += self.pkt_time
        arrive = self.bottleneck_free + self.delay
        self.inflight.append((arrive + self.delay, chunk, dropped))
        return not dropped

    def arrivals(self, now):
        """Pop everything whose ACK has reached the sender by `now`."""
        due = []
        while self.inflight and self.inflight[0][0] <= now + 1e-12:
            due.append(self.inflight.popleft())
        return due

    def queue_delay(self, now):
        return max(0.0, self.bottleneck_free - now)


# Training scenarios: (name, one-way delay s, capacity B/s, queue pkts, loss).
# Spread deliberately wide — a policy that only sees one regime learns that
# regime's constant, which is how the previous model ended up emitting ~1.70
# everywhere.
# Delivery is averaged over this many round trips before being max-filtered,
# matching rl.rs's DELIVERY_WINDOW_RTTS. A per-tick sample fed to a max
# filter reads 2.2x capacity; rl.rs measured that and rejected it.
DELIVERY_WINDOW_RTTS = 2.0

# Loss back-off, matching rl.rs: only when the loss came with a queue.
LOSS_QUEUE_FIXED = 0.008
LOSS_QUEUE_FRACTION = 0.25
LOSS_DECREASE_FACTOR = 0.875

SCENARIOS = [
    ("lan",           0.0005, 12.5e6,  200, 0.000),
    ("metro",         0.005,  12.5e6,  400, 0.001),
    ("cross-country", 0.025,  12.5e6,  600, 0.005),
    ("transatlantic", 0.050,  12.5e6,  800, 0.010),
    ("satellite",     0.150,  12.5e6, 1200, 0.020),
    ("degraded",      0.100,  12.5e6,  500, 0.050),
    ("fat-fast",      0.020, 125.0e6, 2000, 0.001),
    ("shallow-queue", 0.030,  12.5e6,  100, 0.002),
]


class WorstCaseSampler:
    """Scenario sampler that concentrates on whatever the policy is worst at.

    PPO maximises *expected* return over the scenario distribution, and the
    export gate is *worst case* across scenarios. Those are different
    objectives, and the 1M-timestep run of 2026-08-07 is the proof: it
    reached a mean utilisation of 31.6% against the constant's 30.2% -- it
    won the objective it was given -- and lost the worst case 1.4% to 8.5%.

    Uniform sampling spends 7/8 of its episodes on scenarios that are
    already fine. This reweights toward the failing ones, which is a cheap
    stand-in for a CVaR objective: the expectation under this distribution
    is dominated by the tail that the gate actually reads.

    Shared across the vector envs so all workers see one estimate.
    """

    def __init__(self, scenarios, beta: float = 6.0, floor: float = 0.05):
        self.scenarios = scenarios
        # Optimistic init: every scenario is sampled until it has a score.
        self.score = {s[0]: 1.0 for s in scenarios}
        self.beta = beta
        self.floor = floor

    def observe(self, name: str, utilisation: float) -> None:
        prev = self.score.get(name, 1.0)
        self.score[name] = 0.9 * prev + 0.1 * float(utilisation)

    def weights(self) -> np.ndarray:
        # Softmax over the *negative* score: worse scenarios get more
        # episodes. The floor keeps every scenario in the mix, so the policy
        # cannot forget one it has already solved and regress there.
        raw = np.array([np.exp(-self.beta * self.score[s[0]]) for s in self.scenarios])
        w = raw / raw.sum()
        w = (1.0 - self.floor * len(w)) * w + self.floor
        return w / w.sum()

    def pick(self, rng) -> int:
        return int(rng.choice(len(self.scenarios), p=self.weights()))


class ClosedLoopCcEnv(gym.Env):
    """Gymnasium environment where the action actually changes the path state."""

    metadata = {"render_modes": []}

    def __init__(self, episode_steps: int = 400, scenarios=None, seed: int | None = None,
                 sampler: "WorstCaseSampler | None" = None):
        super().__init__()
        self.observation_space = spaces.Box(
            low=-1.0, high=2.0, shape=(INPUT_DIM,), dtype=np.float32
        )
        self.action_space = spaces.Box(low=-1.0, high=1.0, shape=(1,), dtype=np.float32)
        self.episode_steps = episode_steps
        self.scenarios = scenarios if scenarios is not None else SCENARIOS
        self.sampler = sampler
        self._seed = seed
        self._ep_rel = []

    # ── helpers ───────────────────────────────────────────────────────────
    def _map_action(self, a) -> float:
        return ACTION_MIN + (float(a[0]) + 1.0) / 2.0 * (ACTION_MAX - ACTION_MIN)

    def _observe(self) -> np.ndarray:
        srtt = self.srtt if self.srtt else self.path.rtt()
        min_rtt = self.min_rtt if self.min_rtt else self.path.rtt()
        rtt_grad = np.clip((srtt - self.prev_srtt) / RTT_NORM, -GRADIENT_CLIP, GRADIENT_CLIP)
        dr_grad = np.clip((self.delivery_rate - self.prev_dr) / BW_NORM,
                          -GRADIENT_CLIP, GRADIENT_CLIP)
        total = self.recent_acks + self.recent_losses
        loss_rate = (self.recent_losses / total) if total > 0 else 0.0
        cwnd_bytes = max(1.0, self.cwnd_pkts * MSS)
        inflight_ratio = np.clip(self.bytes_in_flight / cwnd_bytes, 0.0, 2.0)
        qd = np.clip((srtt - min_rtt) / min_rtt, 0.0, 10.0) if min_rtt > 0 else 0.0
        return np.array([
            np.clip(srtt / RTT_NORM, 0.0, 1.0),
            np.clip(min_rtt / RTT_NORM, 0.0, 1.0),
            rtt_grad,
            np.clip(self.delivery_rate / BW_NORM, 0.0, 1.0),
            dr_grad,
            np.clip(loss_rate, 0.0, 1.0),
            inflight_ratio,
            qd / 10.0,
        ], dtype=np.float32)

    # ── gym API ───────────────────────────────────────────────────────────
    def reset(self, seed=None, options=None):
        super().reset(seed=seed)
        rng = np.random.default_rng(self.np_random.integers(0, 2**31 - 1))
        if self.sampler is not None:
            idx = self.sampler.pick(self.np_random)
        else:
            idx = int(self.np_random.integers(0, len(self.scenarios)))
        name, delay, cap, q, loss = self.scenarios[idx]
        self._ep_rel = []
        self.scenario_name = name
        self.path = PathSim(rng, delay, cap, q, loss)

        self.now = 0.0
        self.next_chunk = 0
        self.acked = set()
        self.sent_at = {}
        self.retransmitted = set()
        self.retx_queue = []
        self.bytes_in_flight = 0.0
        self.cwnd_pkts = 16.0

        self.rate = cap * 0.05            # start well below capacity
        self.srtt = 0.0
        self.min_rtt = 0.0
        self.rtt_var = 0.0
        self.prev_srtt = 0.0
        self.delivery_rate = 0.0
        self._dr_window = deque()
        self._tick_window = deque()
        self.btlbw = 0.0
        self.prev_dr = 0.0
        self.recent_acks = 0
        self.recent_losses = 0
        self.total_delivered = 0
        self.total_sent = 0
        self.total_retx = 0
        self.rx_since_ack = 0
        self.rx_last_ack = 0.0
        self.next_scan = RETX_SCAN
        self.steps = 0
        return self._observe(), {}

    def step(self, action):
        mult = self._map_action(action)

        # The action sets the rate for this control interval. This is the
        # line the trace-replay environment lacked: everything below depends
        # on it, so the reward can attribute outcomes to the choice.
        # The action is a gain on the measured delivery rate, not a
        # compounding multiplier on the current rate. Mirrors rl.rs; see the
        # long comment there. As a compounding multiplier the action's
        # meaning scaled with RTT -- applied once per 5 ms interval whatever
        # the path length, so the per-round-trip gain was m^(rtt/5ms), the
        # 60th power at 300 ms -- and the band of safe outputs shrank from
        # the whole action range at 1 ms to about 1.5% of it at 300 ms. The
        # policy could not be trained to hit a target that narrow, and the
        # environment could not teach it to, because "hold steady" was a
        # different number on every path.
        if self.btlbw > 0:
            # Gain applies to a windowed MAX of delivery, not to the latest
            # sample. `rate <- g * delivered` has no restoring force: a few
            # intervals below 1.0 shrink the rate, which shrinks delivery,
            # which shrinks the rate again, and the quantity the gain
            # multiplies has been destroyed by the very backing-off it is
            # meant to recover from. Measured: satellite and degraded sat at
            # 1.9% and 2.7% utilisation -- pinned against the progress floor,
            # not stalled at zero -- while a constant gain reached 22% and
            # 70% on the same paths.
            #
            # A max filter survives backing off, so a gain above 1.0 can
            # always climb back out. This is why BBR's pacing gain multiplies
            # btlbw rather than the last delivery sample.
            new_rate = max(1.0, mult * self.btlbw)
        else:
            new_rate = min(max(1.0, self.rate * mult), self.rate * RATE_PROBE_CEILING)
        # Same progress floor the controller enforces: rate <- g * delivered
        # has a fixed point at zero, and a controller that stops sending
        # stops receiving the ACKs that would let it decide otherwise.
        floor = MIN_PACED_PKTS_PER_RTT * MSS / max(self.path.rtt(), 1e-6)
        self.rate = max(new_rate, floor)

        self.prev_srtt = self.srtt
        self.prev_dr = self.delivery_rate
        self.recent_acks = 0
        self.recent_losses = 0
        delivered_before = self.total_delivered

        # Advance one control interval. Stepping time in microseconds was
        # correct but ~5000 iterations per control step; the path is a
        # token bucket, so how many packets fit in the interval can be
        # computed directly.
        target_end = self.now + SYN_INTERVAL
        pkt_interval = MSS / max(self.rate, 1.0)

        # Paced budget for this interval, capped by window room.
        paced = int(SYN_INTERVAL / pkt_interval) if pkt_interval > 0 else 0
        room = int(max(0.0, self.cwnd_pkts * MSS - self.bytes_in_flight) // MSS)
        # Bound the burst: on a 125 MB/s path an interval admits ~440
        # packets, and an unbounded episode then spends all its time in
        # bookkeeping rather than learning.
        to_send = max(0, min(paced, room, 512))

        for i in range(to_send):
            at = self.now + i * pkt_interval
            chunk = self.retx_queue.pop() if self.retx_queue else self.next_chunk
            if chunk == self.next_chunk:
                self.next_chunk += 1
            else:
                self.total_retx += 1
            self.path.send(at, chunk)
            self.sent_at[chunk] = at
            self.bytes_in_flight += MSS
            self.total_sent += 1

        self.now = target_end

        # Deliver everything whose ACK has arrived by now.
        for _arrive, chunk, dropped in self.path.arrivals(self.now):
            if dropped:
                continue
            self.rx_since_ack += 1
            if chunk in self.acked:
                self.bytes_in_flight = max(0.0, self.bytes_in_flight - MSS)
                continue
            self.acked.add(chunk)
            self.total_delivered += 1
            self.recent_acks += 1
            self.bytes_in_flight = max(0.0, self.bytes_in_flight - MSS)
            # Karn: a retransmitted chunk cannot be timed.
            if chunk not in self.retransmitted:
                sample = max(1e-6, self.now - self.sent_at.get(chunk, self.now))
                self.min_rtt = sample if self.min_rtt == 0 else min(self.min_rtt, sample)
                if self.srtt == 0:
                    self.srtt, self.rtt_var = sample, sample / 2
                else:
                    self.rtt_var = 0.75 * self.rtt_var + 0.25 * abs(self.srtt - sample)
                    self.srtt = 0.875 * self.srtt + 0.125 * sample

        if self.rx_since_ack >= ACK_EVERY or (
            self.rx_since_ack > 0 and self.now >= self.rx_last_ack + ACK_TIMER
        ):
            self.rx_since_ack = 0
            self.rx_last_ack = self.now

        # Sender-inferred loss: one scan per interval, against the adaptive
        # RTO. Only unacked chunks are candidates, and acked entries are
        # dropped so the scan stays proportional to what is outstanding.
        if self.now >= self.next_scan:
            self.next_scan = self.now + RETX_SCAN
            rto = max(RETX_FLOOR_MIN, 2 * self.path.rtt())
            if self.srtt > 0:
                rto = max(rto, self.srtt + 4 * max(self.rtt_var, 0.001))
            queued = set(self.retx_queue)
            done = []
            for c, t in self.sent_at.items():
                if c in self.acked:
                    done.append(c)
                    continue
                if c in queued:
                    continue
                if self.now - t > rto:
                    self.retx_queue.append(c)
                    self.retransmitted.add(c)
                    self.recent_losses += 1
                    self.bytes_in_flight = max(0.0, self.bytes_in_flight - MSS)
            for c in done:
                del self.sent_at[c]

        # Window tracks the rate-delay product, as rl.rs does.
        self.cwnd_pkts = max(16.0, (self.rate * self.path.rtt() / MSS) * 2.0)

        delivered = self.total_delivered - delivered_before

        # Delivery averaged over DELIVERY_WINDOW_RTTS round trips, then
        # max-filtered -- not a per-tick sample fed to a max filter.
        #
        # This environment sampled delivery once per 5 ms SYN interval and
        # took the maximum of those. rl.rs measured exactly that estimator at
        # **2.2x capacity** and replaced it: a max filter over a noisy
        # per-tick sample latches the noise peak, and the controller then
        # paces at a rate the path never carried. Correcting it here matters
        # more than it looks, because `btlbw` is the denominator of the whole
        # rate law the policy acts on.
        self._tick_window.append(delivered * MSS)
        span_ticks = max(1, int(DELIVERY_WINDOW_RTTS * self.path.rtt() / SYN_INTERVAL))
        while len(self._tick_window) > span_ticks:
            self._tick_window.popleft()
        span_s = len(self._tick_window) * SYN_INTERVAL
        self.delivery_rate = (sum(self._tick_window) / span_s) if span_s > 0 else 0.0

        # Windowed max of that average (BBR's btlbw), over ~10 round trips.
        self._dr_window.append(self.delivery_rate)
        horizon = max(4, int(10 * self.path.rtt() / SYN_INTERVAL))
        while len(self._dr_window) > horizon:
            self._dr_window.popleft()
        self.btlbw = max(self._dr_window) if self._dr_window else 0.0

        # Loss back-off, gated on a standing queue.
        #
        # rl.rs reduces the rate on significant loss only when
        # `srtt - min_rtt >= 8ms + 0.25 * min_rtt`, so random loss on an
        # uncongested path does not slow the sender. Without it here, a
        # policy is trained in a world where loss is free, and then deployed
        # into one where the engine brakes -- which is a different control
        # problem. a defect in the engineering log.
        if self.recent_losses >= 3 and self.min_rtt > 0:
            budget = LOSS_QUEUE_FIXED + LOSS_QUEUE_FRACTION * self.min_rtt
            if (self.srtt - self.min_rtt) >= budget:
                self.rate *= LOSS_DECREASE_FACTOR

        # Reward = the engine's recorded reward (RlController::compute_reward):
        # goodput x (1 - loss^2) - queue penalty, plus an idle penalty.
        #
        # The idle term is not cosmetic. Without it the first trained policy
        # scored best on mean reward by *stalling* on satellite and degraded
        # (0.0% utilisation, 0.0% loss on both) and harvesting the easy
        # scenarios: with reward bounded below at zero, delivering nothing is
        # perfectly safe, so "back off whenever unsure" dominates. Sending
        # nothing is the one outcome a transfer controller must never choose,
        # so it has to cost more than sending badly.
        total = self.recent_acks + self.recent_losses
        loss_rate = (self.recent_losses / total) if total > 0 else 0.0
        goodput = min(1.0, self.delivery_rate / self.path.capacity)
        qd = ((self.srtt - self.min_rtt) / self.min_rtt) if self.min_rtt > 0 else 0.0
        ref = REFERENCE_UTILISATION.get(self.scenario_name, 0.10)
        # Capped above 1.0 so beating the reference is rewarded, but not
        # without limit — the cap keeps one easy scenario from dominating.
        rel = min(1.5, goodput / ref) if ref > 0 else 0.0
        # Efficiency -- delivered per packet *sent* -- multiplies the
        # reward, linearly.
        #
        # The previous term was (1 - loss^2), which is close to free until
        # waste is already severe: 20% loss cost 4% of the reward and 60%
        # cost 36%. A controller that floods to hold a standing queue was
        # therefore profitable, and the shipped one does exactly that --
        # measured on the rig at 60-62% retransmits in every impaired
        # scenario, buying an 8-10% goodput edge over Model with 2.5x the
        # packets. Squaring is what made the first 20% of waste nearly free,
        # so the fix is to stop squaring, not to add a second term.
        #
        # Linear efficiency prices it correctly: at 60% waste the reward is
        # multiplied by 0.4, so the flood has to more than double goodput to
        # break even, and against a bottleneck it cannot.
        efficiency = 1.0 - min(1.0, max(0.0, loss_rate))
        # Queueing delay was charged at most 0.05 -- noise next to a reward
        # of order 1. Doubling the path RTT is a real cost imposed on
        # everything sharing the link, and the shipped controller does
        # exactly that (150 ms -> 301 ms), so it has to be visible. Charged
        # against inflation beyond 25%, which is roughly where Classic's own
        # queueing signal starts calling it congestion.
        queue_excess = max(0.0, qd - 0.25)
        reward = rel * efficiency - QUEUE_DELAY_PENALTY * min(1.0, queue_excess)
        # Sending nothing is the one outcome a transfer controller must
        # never choose, so it has to cost more than sending badly — and the
        # threshold is relative, so it stays reachable on every path.
        if rel < IDLE_FLOOR_REL:
            reward -= IDLE_PENALTY * (1.0 - rel / IDLE_FLOOR_REL)

        self.steps += 1
        terminated = False
        truncated = self.steps >= self.episode_steps
        # Feed the sampler the utilisation actually achieved, so the next
        # episode is drawn toward whatever is currently failing.
        self._ep_rel.append(goodput)
        if (terminated or truncated) and self.sampler is not None:
            self.sampler.observe(
                self.scenario_name,
                float(np.mean(self._ep_rel)) if self._ep_rel else 0.0,
            )

        return self._observe(), float(reward), terminated, truncated, {
            "scenario": self.scenario_name,
            "goodput": goodput,
            "loss_rate": loss_rate,
            "rate_mbps": self.rate / 1e6,
        }


def evaluate(policy_fn, episodes: int = 3, steps: int = 400, seed: int = 0):
    """Run a policy across every scenario; returns per-scenario summaries."""
    out = {}
    for idx, (name, delay, cap, q, loss) in enumerate(SCENARIOS):
        env = ClosedLoopCcEnv(episode_steps=steps, scenarios=[SCENARIOS[idx]])
        gp, lr = [], []
        for ep in range(episodes):
            obs, _ = env.reset(seed=seed + ep)
            done = False
            while not done:
                a = policy_fn(obs)
                obs, _r, term, trunc, info = env.step(a)
                done = term or trunc
                gp.append(info["goodput"])
                lr.append(info["loss_rate"])
        out[name] = {
            "utilisation": float(np.mean(gp)),
            "loss_rate": float(np.mean(lr)),
        }
    return out
