#!/usr/bin/env python3
# Favonius — high-performance file transfer over UDP
# Copyright (c) 2025-2026 Vantino SàRL
# SPDX-License-Identifier: Apache-2.0

"""
Train the AHP-RL congestion controller against a closed-loop environment.

Replaces the trace-replay pipeline in train_rl.py, whose environment
advanced to the next recorded sample regardless of the action, so the agent
never observed a consequence. Here the action sets the sending rate, the
bottleneck decides what that produces, and the reward reflects it.

Usage:
    ./venv/bin/python train_closed_loop.py --timesteps 300000 \
        --out ../crates/ahp-congestion/weights/rl_weights_v3.bin

The exported file is the AHPRL002 format rl.rs loads: an 8-byte magic
followed by 833 little-endian f64 weights for an 8->32->16->1 MLP.
"""

from __future__ import annotations

import argparse
import struct
from pathlib import Path

import numpy as np
import torch
import torch.nn as nn
from stable_baselines3 import PPO
from stable_baselines3.common.vec_env import DummyVecEnv

from closed_loop_env import (
    ClosedLoopCcEnv, SCENARIOS, WorstCaseSampler, evaluate,
    ACTION_MIN, ACTION_MAX, INPUT_DIM,
)

# Must match DEFAULT_GAIN in crates/ahp-congestion/src/rl.rs — this is the
# baseline a learned policy has to beat, so a mismatch would gate against a
# controller that is not the one shipping.
DEFAULT_GAIN = 1.075

HIDDEN1, HIDDEN2 = 32, 16
# Must match WEIGHT_MAGIC in rl.rs. Bumped when the action changed from a
# compounding multiplier on the rate to a gain on measured delivery: the
# file layout is unchanged, so only the magic can stop an older file from
# being loaded and silently reinterpreted.
MAGIC = b"AHPRL002"
TOTAL_WEIGHTS = INPUT_DIM * HIDDEN1 + HIDDEN1 + HIDDEN1 * HIDDEN2 + HIDDEN2 + HIDDEN2 + 1


class SmallMlp(nn.Module):
    """The exact network rl.rs evaluates: 8->32->16->1, ReLU, sigmoid out."""

    def __init__(self):
        super().__init__()
        self.net = nn.Sequential(
            nn.Linear(INPUT_DIM, HIDDEN1), nn.ReLU(),
            nn.Linear(HIDDEN1, HIDDEN2), nn.ReLU(),
            nn.Linear(HIDDEN2, 1), nn.Sigmoid(),
        )

    def forward(self, x):
        return self.net(x)


def distil(model: PPO, samples: int = 60000, epochs: int = 150) -> SmallMlp:
    """Fit the small MLP to the PPO policy's mean action.

    States are drawn from the environment under the trained policy rather
    than sampled uniformly: a uniform grid over an 8-dimensional box is
    mostly states the controller will never occupy, and fitting those wastes
    the little capacity 833 parameters have.
    """
    env = ClosedLoopCcEnv(episode_steps=400)
    obs_buf = []
    obs, _ = env.reset(seed=12345)
    while len(obs_buf) < samples:
        act, _ = model.predict(obs, deterministic=True)
        obs_buf.append(obs.copy())
        obs, _r, term, trunc, _i = env.step(act)
        if term or trunc:
            obs, _ = env.reset()
    states = torch.as_tensor(np.array(obs_buf[:samples]), dtype=torch.float32)

    with torch.no_grad():
        mean = model.policy.get_distribution(states).distribution.mean
        # SB3 acts in [-1, 1]; the exported net emits a sigmoid in [0, 1]
        # which rl.rs maps to [ACTION_MIN, ACTION_MAX].
        targets = ((mean.clamp(-1, 1) + 1.0) / 2.0).float()

    net = SmallMlp()
    opt = torch.optim.Adam(net.parameters(), lr=1e-3)
    lossf = nn.MSELoss()
    ds = torch.utils.data.TensorDataset(states, targets)
    dl = torch.utils.data.DataLoader(ds, batch_size=512, shuffle=True)
    for ep in range(epochs):
        tot = 0.0
        for xb, yb in dl:
            pred = net(xb)
            loss = lossf(pred, yb)
            opt.zero_grad(); loss.backward(); opt.step()
            tot += loss.item()
        if (ep + 1) % 50 == 0:
            print(f"    distil epoch {ep+1}/{epochs}  mse {tot/len(dl):.6f}")
    return net, states


def shrink(net: SmallMlp, states: torch.Tensor, lam: float) -> SmallMlp:
    """Return a copy of `net` whose output is pulled toward its own mean.

    The 2026-08-07 sweep showed the deficit is not the operating point but
    the spread around it. The 1M-timestep policy emitted a mean multiplier
    of 1.076 against the shipped constant's 1.075 -- it found the optimum --
    and lost the worst case six-fold, with an emitted sd of 0.080. Seed 3
    settles it: mean 1.089, *above* the constant, and still 17.2%/2.7%.

    The asymmetry is structural. `rate <- g * btlbw` multiplies a
    max-filtered estimate, so a probe up costs one round trip of loss while
    a probe down lowers the filter's own input and takes ~10 to climb back.
    Symmetric exploration, asymmetric consequence.

    Shrinking happens in pre-sigmoid space, where it is exact and needs only
    the last layer: with z' = lam*z + (1-lam)*zbar, scale the final weight
    matrix by lam and shift its bias. lam=1 is the network unchanged; lam=0
    is the best constant the network knows how to name. Every value in
    between is available to the gate, so this can only match or beat the
    raw policy.
    """
    import copy
    out = copy.deepcopy(net)
    with torch.no_grad():
        pre = out.net[:5](states)          # everything up to the sigmoid
        zbar = pre.mean().item()
        out.net[4].weight.mul_(lam)
        out.net[4].bias.mul_(lam).add_((1.0 - lam) * zbar)
    return out


def export(net: SmallMlp, path: Path):
    sd = net.state_dict()
    vals = []
    vals += sd["net.0.weight"].numpy().flatten().tolist()
    vals += sd["net.0.bias"].numpy().flatten().tolist()
    vals += sd["net.2.weight"].numpy().flatten().tolist()
    vals += sd["net.2.bias"].numpy().flatten().tolist()
    vals += sd["net.4.weight"].numpy().flatten().tolist()
    vals += sd["net.4.bias"].numpy().flatten().tolist()
    assert len(vals) == TOTAL_WEIGHTS, f"{len(vals)} != {TOTAL_WEIGHTS}"
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "wb") as f:
        f.write(MAGIC)
        f.write(struct.pack(f"<{len(vals)}d", *vals))
    print(f"  wrote {path} ({path.stat().st_size} bytes, {len(vals)} weights)")


def net_policy(net: SmallMlp):
    """Wrap the exported net as a policy over the env's [-1,1] action space."""
    def fn(obs):
        with torch.no_grad():
            s = net(torch.as_tensor(obs, dtype=torch.float32).unsqueeze(0)).item()
        mult = ACTION_MIN + s * (ACTION_MAX - ACTION_MIN)
        return np.array([(mult - ACTION_MIN) / (ACTION_MAX - ACTION_MIN) * 2.0 - 1.0])
    return fn


def score(v) -> float:
    """Utilisation actually earned, after paying for waste.

    The gate used to read `utilisation` alone. That is goodput, and goodput
    is trivially bought by flooding: on 2026-08-07 a constant gain of 1.12
    scored 11.2% worst case against 1.075's 8.5%, looked like a clear win,
    and on the rig delivered 2.5-8.7% more throughput with **54-60%
    retransmissions** and a doubled RTT. It is the exact failure the retired
    v2 weights had -- 60-62% retransmits for an 8-10% goodput edge.

    The reward function already prices waste linearly; the gate did not, so
    a policy could be trained against one objective and accepted against
    another. Multiplying by delivered-per-sent closes that: a controller
    retransmitting 60% of its packets keeps 40% of its score, and the flood
    has to more than double goodput to break even, which against a
    bottleneck it cannot.
    """
    return v["utilisation"] * (1.0 - min(1.0, max(0.0, v["loss_rate"])))


def report(title, results):
    print(f"\n  {title}")
    print(f"    {'scenario':<16}{'utilisation':>13}{'loss':>9}")
    for k, v in results.items():
        print(f"    {k:<16}{v['utilisation']:>12.1%}{v['loss_rate']:>9.1%}")
    print(f"    {'MEAN':<16}{np.mean([v['utilisation'] for v in results.values()]):>12.1%}"
          f"{np.mean([v['loss_rate'] for v in results.values()]):>9.1%}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--timesteps", type=int, default=300_000)
    ap.add_argument("--out", type=Path,
                    default=Path("../crates/ahp-congestion/weights/rl_weights_v3.bin"))
    ap.add_argument("--seed", type=int, default=0)
    # Export a policy the gate rejected, for rig measurement only.
    #
    # Section 6 item 2 of the CC research notes requires a candidate to be
    # measured on the rig and not only in this environment -- and you cannot
    # measure what was never written. Without this flag the only artifacts
    # that exist are ones the simulator already approved, which is the
    # opposite of the check being asked for.
    #
    # It prints loudly and the file it writes is not a ship candidate.
    ap.add_argument("--export-rejected", action="store_true",
                    help="write weights even if the gate fails (rig testing only)")
    args = ap.parse_args()

    torch.manual_seed(args.seed)
    np.random.seed(args.seed)

    print(f"  training PPO for {args.timesteps} timesteps over "
          f"{len(SCENARIOS)} scenarios (closed loop)")
    # One sampler shared by every worker, so the estimate of "which
    # scenario is currently failing" is pooled rather than per-env.
    sampler = WorstCaseSampler(SCENARIOS)
    venv = DummyVecEnv([
        lambda: ClosedLoopCcEnv(episode_steps=400, sampler=sampler) for _ in range(4)
    ])
    model = PPO("MlpPolicy", venv, verbose=0, seed=args.seed,
                n_steps=512, batch_size=256, learning_rate=3e-4, gamma=0.99)
    model.learn(total_timesteps=args.timesteps, progress_bar=False)

    print("\n  distilling the policy into the 8->32->16->1 network rl.rs runs")
    net, distil_states = distil(model)

    # Baselines the learned policy has to beat to be worth shipping.
    const = lambda c: (lambda o: np.array([(c - ACTION_MIN) /
                                           (ACTION_MAX - ACTION_MIN) * 2.0 - 1.0]))
    report("hold rate (1.0x)", evaluate(const(1.0), episodes=2, steps=300, seed=7))
    report("max push (2.0x)", evaluate(const(2.0), episodes=2, steps=300, seed=7))
    report("trained policy", evaluate(net_policy(net), episodes=2, steps=300, seed=7))

    # ── The gate ────────────────────────────────────────────────────────
    #
    # Weights are only written if the learned policy beats the constant-gain
    # controller that ships in rl.rs. That controller is not a placeholder:
    # after the action was made RTT-invariant, the range narrowed to where it
    # steers, and the estimator max-filtered, a single constant beat a
    # 400k-timestep 833-parameter network 30.2% to 21.3% on mean utilisation
    # and 8.5% to 0.1% on worst case. Three separate retrains each produced a
    # policy that stalled somewhere, and each time the result was written to
    # disk and had to be caught by hand afterwards.
    #
    # Worst case is the binding criterion, not mean. A controller that
    # averages well by winning easy scenarios and delivering 0.1% on
    # satellite is not a controller. Mean must not regress either, so a
    # policy cannot pass by being uniformly mediocre.
    print("\n  gate: must beat the best constant gain to earn weights")
    # The baseline is the *best* constant, not the shipped one.
    #
    # Grading against DEFAULT_GAIN asks "is this better than the number we
    # happen to ship", which is a different and much easier question than
    # "is a policy worth having at all". On 2026-08-07 that difference
    # mattered: three seeds passed against DEFAULT_GAIN = 1.075 and wrote
    # weights, and a direct sweep then showed a plain 1.12 reaching the same
    # 11.2% worst case with a mean inside the policies' own spread. Against
    # the best constant every one of them ties and fails, which is correct.
    #
    # A learned controller has to beat the best thing of its simplest form,
    # or the comparison is flattering by construction.
    grid = [1.00, 1.025, 1.05, 1.075, 1.09, 1.10, 1.11, 1.12, 1.13, 1.15]
    best_const, base = None, None
    for g in grid:
        r = evaluate(const(g), episodes=2, steps=300, seed=7)
        w = min(score(v) for v in r.values())
        m = np.mean([score(v) for v in r.values()])
        if base is None or w > base[0] or (w == base[0] and m > base[1]):
            base, best_const = (w, m), g
    b_worst, b_mean = base
    print(f"    best constant gain on this grid: {best_const} "
          f"(mean {b_mean:.1%}, worst {b_worst:.1%})")
    if abs(best_const - DEFAULT_GAIN) > 1e-9:
        print(f"    NOTE: DEFAULT_GAIN in rl.rs is {DEFAULT_GAIN}, which this "
              f"grid says is not the best constant.")

    # Sweep the variance shrinkage. lam=1 is the raw policy, lam=0 the best
    # constant it knows how to name; the gate reads every value in between,
    # so this cannot do worse than the raw policy.
    print(f"    {'':<10}{'mean':>9}{'worst':>9}{'emitted sd':>13}")
    print(f"    {'const '+str(best_const):<10}{b_mean:>8.1%}{b_worst:>9.1%}{0.0:>13.3f}")
    best = None
    for lam in (1.0, 0.75, 0.5, 0.25, 0.0):
        cand = shrink(net, distil_states, lam)
        res = evaluate(net_policy(cand), episodes=2, steps=300, seed=7)
        t_worst = min(score(v) for v in res.values())
        t_mean = np.mean([score(v) for v in res.values()])
        with torch.no_grad():
            sig = cand(distil_states[:4000]).squeeze(1)
            mult = ACTION_MIN + sig * (ACTION_MAX - ACTION_MIN)
            sd = mult.std().item()
        passes = t_worst > b_worst and t_mean >= b_mean
        print(f"    lam={lam:<6.2f}{t_mean:>8.1%}{t_worst:>9.1%}{sd:>13.3f}"
              f"{'   PASS' if passes else ''}")
        if passes and (best is None or t_worst > best[1]):
            best = (lam, t_worst, t_mean, cand)

    if best is not None:
        lam, t_worst, t_mean, cand = best
        export(cand, args.out)
        print(f"    PASS at lam={lam} - wrote {args.out}")
        net = cand
    elif args.export_rejected:
        # Best available candidate by worst case, then mean.
        cands = []
        for lam in (1.0, 0.75, 0.5, 0.25, 0.0):
            c = shrink(net, distil_states, lam)
            r = evaluate(net_policy(c), episodes=2, steps=300, seed=7)
            cands.append((min(score(v) for v in r.values()),
                          np.mean([score(v) for v in r.values()]), lam, c))
        cands.sort(key=lambda t: (t[0], t[1]))
        w, m, lam, cand = cands[-1]
        export(cand, args.out)
        print(f"    FAIL, but --export-rejected: wrote lam={lam} "
              f"(mean {m:.1%}, worst {w:.1%}) to {args.out}")
        print("    THIS IS NOT A SHIP CANDIDATE. It exists to be measured on")
        print("    the rig, which is the check the gate cannot perform.")
        net = cand
    else:
        print("    FAIL at every shrinkage - no weights written.")
        print("    The constant-gain controller in rl.rs remains the shipped one.")

    # What does it actually emit? The previous model sat near 1.70 almost
    # everywhere, which is how it diverged.
    with torch.no_grad():
        env = ClosedLoopCcEnv(episode_steps=300)
        obs, _ = env.reset(seed=99)
        outs = []
        for _ in range(3000):
            s = net(torch.as_tensor(obs, dtype=torch.float32).unsqueeze(0)).item()
            m = ACTION_MIN + s * (ACTION_MAX - ACTION_MIN)
            outs.append(m)
            obs, _r, t, tr, _i = env.step(net_policy(net)(obs))
            if t or tr:
                obs, _ = env.reset()
    outs = np.array(outs)
    print(f"\n  emitted multiplier: mean {outs.mean():.3f}  sd {outs.std():.3f}  "
          f"min {outs.min():.3f}  max {outs.max():.3f}")
    print(f"  fraction above 1.0 (rate-increasing): {(outs > 1.0).mean():.1%}")


if __name__ == "__main__":
    main()
