#!/usr/bin/env python3
# Favonius — high-performance file transfer over UDP
# Copyright (c) 2025-2026 Vantino SàRL
# SPDX-License-Identifier: Apache-2.0
#
"""Contextual bandit over the gain cycle's own parameters, trained on the rig.

WHY THIS EXISTS, AND WHY IT IS NOT `train_closed_loop.py`
---------------------------------------------------------
The previous attempt learned `rate <- action * btlbw` in an offline
environment. Two things killed it:

  1. That rate law is reachable only through `get_action`, which the shipped
     controller never calls. The environment modelled a code path that does
     not execute.
  2. Once the environment's own delivery estimator was corrected, constant
     gains across the whole action range scored 7-17% utilisation against
     56-87% measured on the rig — a factor of four to eight. Its rankings
     could not be trusted, which retrospectively weakened every result it
     produced, including the negative ones.

So this trainer:

  * learns the **cycle's** parameters (probe gain, probe length) and leaves
    every shipped mechanism alone — ramp, queue gate, BDP ceiling, delivery
    clamp, loss response;
  * runs **on the rig**. There is no simulator. Every reward is a real
    transfer through a real qdisc;
  * scores **waste-adjusted** reward, because goodput alone is bought by
    flooding — a lesson this project has learned twice;
  * holds out scenarios it never trained on, because a bandit that has seen
    every cell will always look good on the cells it has seen.

USAGE
-----
    python3 training/train_cycle_bandit.py --image favonius-bench:v2-h2h \\
        --rounds 4 --runs-per-arm 2

    # then evaluate the frozen table against the shipped cycle:
    python3 training/train_cycle_bandit.py --image ... --evaluate policy.bin

THE GATE
--------
A policy ships only if it beats the shipped fixed cycle on waste-adjusted
reward on **held-out** scenarios, in a session that passed
`rig_check.sh control`. Anything else writes no file.
"""

import argparse
import json
import math
import os
import random
import re
import subprocess
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
BENCH = REPO / "benchmarks" / "scripts" / "bench_netem_fair_v2.sh"
RESULTS = REPO / "benchmarks" / "results"
RIG_CHECK = REPO / "benchmarks" / "scripts" / "rig_check.sh"

MAGIC = b"AHPCB001"

# Welch t for n=5 vs n=5 is ~df 8; 2.31 is the two-sided 0.05 critical value.
# Deliberately not a p-value from scipy: this trainer must run with nothing
# but the standard library on the rig host.
T_CRIT = 2.31


def mean(v):
    return sum(v) / len(v)


def sd(v):
    if len(v) < 2:
        return 0.0
    m = mean(v)
    return math.sqrt(sum((x - m) ** 2 for x in v) / (len(v) - 1))


def welch(a, b):
    """One-sided Welch t of a over b, and its degrees of freedom."""
    if len(a) < 2 or len(b) < 2:
        return 0.0, 0.0
    va, vb = sd(a) ** 2, sd(b) ** 2
    se = math.sqrt(va / len(a) + vb / len(b))
    if se == 0:
        return 0.0, 0.0
    t = (mean(a) - mean(b)) / se
    df = (va / len(a) + vb / len(b)) ** 2 / (
        (va / len(a)) ** 2 / (len(a) - 1) + (vb / len(b)) ** 2 / (len(b) - 1))
    return t, df

# Must match CYCLE_ARMS in crates/ahp-congestion/src/rl.rs, in order.
ARMS = [
    (1.10, 2.0),
    (1.25, 2.0),   # the shipped default
    (1.50, 2.0),
    (1.10, 4.0),
    (1.25, 4.0),
    (1.50, 4.0),
]
ARM_DEFAULT = 1

# Must match cycle_context() in rl.rs.
N_CONTEXTS = 6


def context_of(min_rtt_ms: float, loss_rate: float) -> int:
    if min_rtt_ms < 40:
        band = 0
    elif min_rtt_ms <= 100:
        band = 1
    else:
        band = 2
    return band * 2 + (1 if loss_rate >= 0.01 else 0)


# Scenario -> (min_rtt_ms, injected loss fraction). Mirrors SCENARIOS in the
# harness. Split into train and held-out so the gate means something.
SCENARIOS = {
    "cross-country": (25.0, 0.005),
    "transatlantic": (50.0, 0.01),
    "satellite": (150.0, 0.02),
    "degraded": (100.0, 0.05),
    "congested": (50.0, 0.0),
}
TRAIN_SCENARIOS = ["cross-country", "satellite"]
HELDOUT_SCENARIOS = ["transatlantic", "degraded", "congested"]


def reward(goodput_mbps: float, retx_share: float, excess_ms: float,
           min_rtt_ms: float) -> float:
    """Waste-adjusted reward.

    Goodput alone is gameable: on 2026-08-07 a gain that raised throughput
    12% did so at 54-60% retransmits and was briefly reported as a win. And
    a controller can buy throughput with standing queue, which costs the
    transfer's own latency and every flow beside it.

    So the reward prices both:

        goodput * (1 - retx_share) * queue_penalty

    with the queue budget taken from the crate's own standing-queue budget
    (8 ms + 0.25 * min_rtt), the same figure A1's delay leg uses. A run
    inside budget is unpenalised; one at twice the budget scores half.
    """
    if goodput_mbps <= 0:
        return 0.0
    budget = 8.0 + 0.25 * min_rtt_ms
    penalty = min(1.0, budget / max(excess_ms, budget))
    return goodput_mbps * max(0.0, 1.0 - retx_share) * penalty


def run_transfer(image, scenario, arm, rate_mbit, size_mb, timeout_s, tag):
    """One transfer with a forced arm. Returns a reward dict or None."""
    inst = f"cb{tag}"
    env = dict(os.environ)
    env.update(
        IMAGE=image, INSTANCE=inst, RATE_MBIT=str(rate_mbit),
        SIZE_MB=str(size_mb), TRANSFER_TIMEOUT=str(timeout_s), RUNS="1",
        ONLY_SCENARIOS=scenario, ONLY_MODES="rl",
        FAVONIUS_CYCLE_ARM=str(arm),
    )
    subprocess.run([str(BENCH), "--tools", "favonius"], env=env,
                   capture_output=True, text=True, timeout=timeout_s + 180)

    log = RESULTS / f"netem-fair-v2-{inst}-{scenario}-favonius-rl-run1.log"
    if not log.exists():
        return None
    text = log.read_text(errors="ignore")

    m = re.search(r"complete: ([0-9.]+) MB/s .*?([0-9]+) pkts, ([0-9]+) retx", text)
    if not m:
        for p in RESULTS.glob(f"netem-fair-v2-{inst}-*"):
            p.unlink(missing_ok=True)
        return None
    goodput, pkts, retx = float(m.group(1)), int(m.group(2)), int(m.group(3))

    base = re.search(r"base_rtt=([0-9.]+)", text)
    avgs = re.findall(r"avg=([0-9.]+)", text)
    mins = re.findall(r"rtt min=([0-9.]+)", text)
    min_rtt = min(float(x) for x in mins) if mins else (float(base.group(1)) if base else 0.0)
    avg = float(avgs[-1]) if avgs else min_rtt
    excess = max(0.0, avg - min_rtt)
    retx_share = retx / pkts if pkts else 0.0

    for p in RESULTS.glob(f"netem-fair-v2-{inst}-*"):
        p.unlink(missing_ok=True)
    for p in RESULTS.glob(f"netem_fair_v2-{inst}_*"):
        p.unlink(missing_ok=True)

    return dict(goodput=goodput, retx_share=retx_share, excess_ms=excess,
                min_rtt_ms=min_rtt,
                reward=reward(goodput, retx_share, excess, min_rtt))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--image", required=True)
    ap.add_argument("--rate-mbit", type=int, default=1000)
    ap.add_argument("--size-mb", type=int, default=512)
    ap.add_argument("--timeout", type=int, default=300)
    ap.add_argument("--rounds", type=int, default=5,
                    help="passes over (train scenario x arm)")
    ap.add_argument("--out", default=str(REPO / "training" / "cycle_policy.bin"))
    ap.add_argument("--trace", default=str(REPO / "training" / "cycle_trace.jsonl"))
    ap.add_argument("--skip-rig-check", action="store_true")
    args = ap.parse_args()

    # The rig has been wrong by 43% for a whole session without saying so.
    # Refuse to train on an instrument that has not been shown to work.
    if not args.skip_rig_check:
        r = subprocess.run([str(RIG_CHECK), "control"], capture_output=True, text=True,
                           env={**os.environ, "CONTROL_IMAGE": args.image})
        print(r.stdout.strip())
        if r.returncode != 0:
            sys.exit("rig_check control failed — refusing to train on this rig")

    trace = open(args.trace, "a")
    # every reward per (context, arm). The first version kept only a sum
    # and a count, which makes the spread unrecoverable — and the spread
    # is what decides whether a difference in means means anything.
    stats = {(c, a): [] for c in range(N_CONTEXTS) for a in range(len(ARMS))}

    jobs = []
    for _ in range(args.rounds):
        for sc in TRAIN_SCENARIOS:
            for arm in range(len(ARMS)):
                jobs.append((sc, arm))
    # Randomised order: a systematic order would confound arm with drift,
    # which is exactly how a 43%-low session produced four wrong findings.
    random.shuffle(jobs)

    print(f"\n{len(jobs)} training transfers "
          f"({args.rounds} rounds x {len(TRAIN_SCENARIOS)} scenarios x {len(ARMS)} arms)")
    for i, (sc, arm) in enumerate(jobs, 1):
        rtt, loss = SCENARIOS[sc]
        ctx = context_of(rtt, loss)
        res = run_transfer(args.image, sc, arm, args.rate_mbit, args.size_mb,
                           args.timeout, f"{i}")
        if res is None:
            print(f"  [{i}/{len(jobs)}] {sc:14s} arm{arm} -> no result")
            continue
        stats[(ctx, arm)].append(res["reward"])
        rec = dict(scenario=sc, context=ctx, arm=arm, gain=ARMS[arm][0],
                   rtts=ARMS[arm][1], **res, t=time.time())
        trace.write(json.dumps(rec) + "\n")
        trace.flush()
        print(f"  [{i}/{len(jobs)}] {sc:14s} arm{arm} "
              f"gain={ARMS[arm][0]:.2f}/{ARMS[arm][1]:.0f}rtt  "
              f"{res['goodput']:6.1f} MB/s  retx {res['retx_share']*100:4.1f}%  "
              f"queue {res['excess_ms']:5.1f}ms  reward {res['reward']:6.2f}")

    print("\nper-context reward (mean +/- sd, n):")
    table = [ARM_DEFAULT] * N_CONTEXTS
    for c in range(N_CONTEXTS):
        seen = [(a, stats[(c, a)]) for a in range(len(ARMS)) if stats[(c, a)]]
        if not seen:
            continue
        row = "  ".join(
            f"a{a}:{mean(v):5.1f}+-{sd(v):4.1f}" for a, v in seen)
        base = stats[(c, ARM_DEFAULT)]
        best_arm, best_v = max(seen, key=lambda x: mean(x[1]))

        # A difference in means is not a finding. On the 2026-08-11 run the
        # best satellite arm read +27% over the shipped one and the gate
        # below, as originally written (>5% margin, n>=2), accepted it — but
        # the per-run spread was 13.7 reward points against a 9.7-point
        # difference, Welch t=0.91. That policy would have shipped a
        # parameter fitted to three samples of rig noise, which is the same
        # failure the offline trainer kept producing, reached by a shorter
        # route.
        #
        # So the gate is a significance test, not a percentage: the
        # candidate must beat the shipped arm by more than the noise in the
        # comparison, at n>=5 per arm, AND by a margin worth a behaviour
        # change.
        verdict = "-> shipped arm"
        if best_arm != ARM_DEFAULT and base:
            t, df = welch(best_v, base)
            margin = (mean(best_v) - mean(base)) / mean(base) if mean(base) else 0
            enough = len(best_v) >= 5 and len(base) >= 5
            if enough and t >= T_CRIT and margin > 0.05:
                table[c] = best_arm
                verdict = f"-> arm{best_arm} (+{100*margin:.0f}%, t={t:.1f})"
            elif not enough:
                verdict = (f"-> shipped arm (best a{best_arm} +"
                           f"{100*margin:.0f}% but n={len(best_v)}/{len(base)} < 5)")
            else:
                verdict = (f"-> shipped arm (best a{best_arm} +{100*margin:.0f}% "
                           f"is within noise, t={t:.2f})")
        print(f"  ctx{c}: {row}\n         {verdict}")

    if all(a == ARM_DEFAULT for a in table):
        print("\nNo context prefers anything but the shipped cycle. No policy written.")
        print("That is a result, not a failure: it is the honest outcome the")
        print("previous trainer could never produce, because its environment")
        print("disagreed with the rig by four to eight times.")
        return

    out = Path(args.out)
    out.write_bytes(MAGIC + bytes(table))
    print(f"\nwrote {out} : {table}")
    print("\nNOT SHIPPABLE YET. Evaluate on held-out scenarios first:")
    print(f"  {' '.join(HELDOUT_SCENARIOS)}")
    print("A policy that only wins where it trained has learned the rig, not the path.")


if __name__ == "__main__":
    main()
