# training/

**No trained weights ship with Favonius, and none are planned.** This
directory exists because the attempt is worth documenting, not because the
result is pending.

`--congestion cycle` (formerly `rl`) runs a fixed probe/drain/cruise gain
cycle. It was designed to run a learned policy instead. Nine attempts to
produce one that beats the fixed cycle have failed:

| attempt | method | result |
|---|---|---|
| 1–3 | offline retrains on recorded traces | lost to a single constant gain |
| 4–7 | PPO seeds 0–3, 300k timesteps | lost |
| 8 | PPO, 1M timesteps | lost |
| 9 | contextual bandit over the cycle's own parameters, trained on the rig | found nothing (below) |

## What the files are

| file | status |
|---|---|
| `train_closed_loop.py` | **current.** Trains against a closed-loop path model and gates export on beating the fixed cycle on both worst case and mean. Writes no weights on failure. |
| `train_cycle_bandit.py` | **current.** Tunes the cycle's own parameters (probe gain, probe length) on the real rig — no simulator — and gates on a significance test. |
| `train_rl.py` | **superseded.** Open-loop trace replay. Emits `AHPRL001`, which the loader rejects by magic. Kept for history. |
| `closed_loop_env.py` | the path model `train_closed_loop.py` trains against |
| `cycle_trace.jsonl` | the 36 rig transfers from attempt 9, for anyone who wants to re-score them |

## Why the ninth attempt is the interesting one

The bandit ran 36 real transfers over six arms and reported its best
candidate as **+27%** on one context. That result is noise. The
within-arm standard deviation was 12–14 reward points against a 9.7-point
difference, at n=3 — Welch t = 0.91.

The gate that accepted it required "beat the shipped arm by >5% with n≥2".
**A percentage margin cannot see variance**, so it would have shipped a
parameter fitted to three samples of rig noise. The gate is now a one-sided
Welch t at n≥5, and re-scoring the same 36 samples through it returns both
contexts to the shipped arm.

One real effect did survive: a 1.50 gain with a 2-RTT probe is genuinely
worse than the shipped setting (84.3 ±1.6 against 93.6 ±1.2, t = −8.3, at
7.3% retransmits against 0.9%). The arms around the shipped setting are
indistinguishable from one another.

That is the finding worth carrying: **the cycle's parameters sit in a flat
region.** Tuning them learns nothing because there is nothing there to
learn. What a policy would need is not in the parameters — it is in a
distinction the controller cannot currently make, between loss caused by
the queue and loss caused by the path. Favonius's own measurements show the
rate-based profiles winning every random-loss path by 7-25% and losing
the 50 ms and 150 ms congested cells by 11-19%, while `model` takes the
25 ms one by a margin inside the noise. A controller that
told those apart would take the better side of both.

## Running them

```bash
pip install -r requirements.txt

# Parameter search on the rig (requires Docker and the benchmark image)
python3 train_cycle_bandit.py --image favonius-bench:v2 --rounds 5

# Closed-loop policy training
python3 train_closed_loop.py
```

Both refuse to emit weights that do not beat the shipped controller. If a
run produces no file, that is the intended outcome, not a failure.
