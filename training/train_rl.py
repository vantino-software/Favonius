#!/usr/bin/env python3

# Favonius — high-performance file transfer over UDP
# Copyright (c) 2025-2026 Vantino SàRL
# SPDX-License-Identifier: Apache-2.0

"""
AHP-RL: Train a congestion control policy from transfer traces.

LIMITATION — READ BEFORE TRUSTING THIS MODEL
--------------------------------------------
This trainer is **open-loop**. `AhpCcEnv.step()` advances to the next
recorded trace sample regardless of the action the agent chose, and the
reward is computed from recorded path statistics. The environment
therefore never observes what an action *did*: no counterfactual, no
credit assignment. What the agent learns is a correlation between states
and the rates that happened to be in the trace, not a control policy.

This is not offline RL done properly. Methods that do learn control from
logged data (e.g. Sage) need explicit counterfactual machinery —
importance weighting, a learned dynamics model, or conservative value
estimation — none of which is present here.

Consequences visible in the shipped model (see the `shipped_model_*`
tests in `crates/ahp-congestion/src/rl.rs`): it outputs a rate multiplier
near 1.70 across most of the state space, backs off mildly as queueing
delay rises, and — wrongly — nudges its rate *up* as loss rises. Treat
`--congestion rl` as experimental, and benchmark it against
`--congestion udt` (its fallback) before drawing conclusions from it.

Fixing this properly means training against a closed-loop simulator or a
live link, not a trace replay.

Traces are JSONL files produced by the Rust RL controller in explore mode.
Each line: {"s": [8 floats], "a": float, "r": float}

The training pipeline:
1. Loads all trace files from --traces directory
2. Creates a Gymnasium environment that replays trace transitions
3. Trains a PPO policy with stable-baselines3
4. Exports the actor network weights in AHP binary format

Usage:
    python train_rl.py --traces ~/.config/favonius/rl_traces/ --output rl_model.pt
    python train_rl.py --traces ./traces/ --export ~/.config/favonius/rl_weights.bin
"""

import argparse
import json
import struct
import sys
from pathlib import Path

import gymnasium as gym
import numpy as np
import torch
import torch.nn as nn
from gymnasium import spaces
from stable_baselines3 import PPO
from stable_baselines3.common.vec_env import DummyVecEnv


# ── Constants matching Rust rl.rs ─────────────────────────────────────────

INPUT_DIM = 8
HIDDEN1_DIM = 32
HIDDEN2_DIM = 16
OUTPUT_DIM = 1

ACTION_MIN = 0.5
ACTION_MAX = 2.0

# AHPRL001 — the old action semantics (a compounding multiplier on the
# current rate). rl.rs now expects AHPRL002 and will reject these files
# rather than reinterpret them as delivery gains, which is deliberate:
# this trainer is open-loop and its weights are superseded. Kept so the
# format history stays readable, not because it should be run.
WEIGHT_MAGIC = b"AHPRL001"


# ── Trace loading ─────────────────────────────────────────────────────────

def load_traces(trace_dir: Path) -> list[dict]:
    """Load all JSONL trace files from a directory."""
    records = []
    for f in sorted(trace_dir.glob("trace_*.jsonl")):
        with open(f) as fh:
            for line in fh:
                line = line.strip()
                if line:
                    records.append(json.loads(line))
    print(f"Loaded {len(records)} trace records from {trace_dir}")
    return records


# ── Replay environment ────────────────────────────────────────────────────

class AhpCcEnv(gym.Env):
    """
    Gymnasium environment that replays recorded CC trace data.

    Observation: 8-dim state vector (RTT, BW, loss, etc.)
    Action: continuous rate multiplier in [ACTION_MIN, ACTION_MAX]
    Reward: the reward recorded by the engine (see module docstring for
    why this environment cannot teach control regardless)

    Episodes are contiguous windows of trace records.
    """

    metadata = {"render_modes": []}

    def __init__(self, records: list[dict], episode_len: int = 200):
        super().__init__()
        self.records = records
        self.episode_len = episode_len

        self.observation_space = spaces.Box(
            low=-1.0, high=10.0, shape=(INPUT_DIM,), dtype=np.float32
        )
        # Action is a rate multiplier, mapped from [-1, 1] to [ACTION_MIN, ACTION_MAX]
        self.action_space = spaces.Box(
            low=-1.0, high=1.0, shape=(1,), dtype=np.float32
        )

        self._idx = 0
        self._step = 0

    def _map_action(self, action: np.ndarray) -> float:
        """Map from [-1, 1] (SB3 convention) to [ACTION_MIN, ACTION_MAX]."""
        return ACTION_MIN + (action[0] + 1.0) / 2.0 * (ACTION_MAX - ACTION_MIN)

    def reset(self, seed=None, options=None):
        super().reset(seed=seed)
        # Pick a random starting point in the trace
        max_start = max(0, len(self.records) - self.episode_len - 1)
        self._idx = self.np_random.integers(0, max_start + 1) if max_start > 0 else 0
        self._step = 0
        obs = np.array(self.records[self._idx]["s"], dtype=np.float32)
        return obs, {}

    def step(self, action):
        self._step += 1
        self._idx = min(self._idx + 1, len(self.records) - 1)

        record = self.records[self._idx]
        obs = np.array(record["s"], dtype=np.float32)

        # Use the reward the engine recorded, so the objective optimised
        # here is the one documented in `RlController::compute_reward`
        # (goodput x (1 - loss^2) - queue_penalty). Recomputing a
        # different formula from the state vector, as this did before,
        # meant the trainer silently optimised something the engine never
        # measured. Falls back to the old expression for traces recorded
        # before "r" was written.
        if "r" in record:
            base_reward = float(record["r"])
        else:
            dr_norm = record["s"][3]   # delivery_rate / 1Gbps
            loss_rate = record["s"][5] # loss_rate [0,1]
            base_reward = dr_norm * (1.0 - loss_rate)

        # Small penalty for extreme actions (encourage stability)
        mapped_action = self._map_action(action)
        stability_penalty = 0.05 * abs(mapped_action - 1.0)
        reward = base_reward - stability_penalty

        terminated = self._step >= self.episode_len
        truncated = self._idx >= len(self.records) - 1

        return obs, reward, terminated, truncated, {}


# ── Weight export ─────────────────────────────────────────────────────────

def export_weights(model: PPO, output_path: Path):
    """
    Extract the PPO actor network weights and save in AHP binary format.

    SB3's PPO with MlpPolicy creates an actor with architecture:
      policy_net: Linear(8, 64) -> ReLU -> Linear(64, 64) -> ReLU
      action_net: Linear(64, 1)

    We train a separate small MLP (8->32->16->1) and export that instead,
    or we adapt the export to match whatever architecture SB3 produces.

    For simplicity, we train a custom small network and export it.
    """
    # Extract the actor weights from SB3
    actor = model.policy
    state_dict = actor.state_dict()

    # Print all parameter names for debugging
    print("Model parameters:")
    for name, param in state_dict.items():
        print(f"  {name}: {param.shape}")

    # We'll create a custom small MLP and train it to mimic the SB3 policy
    # For now, export the SB3 policy directly using our custom network
    print(f"\nExporting weights to {output_path}")
    _export_custom_mlp(model, output_path)


def _export_custom_mlp(model: PPO, output_path: Path):
    """
    Distill the SB3 policy into our 8->32->16->1 MLP and export.
    """
    # Create our target architecture
    small_net = nn.Sequential(
        nn.Linear(INPUT_DIM, HIDDEN1_DIM),
        nn.ReLU(),
        nn.Linear(HIDDEN1_DIM, HIDDEN2_DIM),
        nn.ReLU(),
        nn.Linear(HIDDEN2_DIM, OUTPUT_DIM),
        nn.Sigmoid(),
    )

    # Generate training data by querying the SB3 policy.
    # Use real state distributions from traces + augmented samples for coverage.
    print("Distilling SB3 policy into small MLP...")
    n_samples = 50000

    # Try to load real states from the training environment.
    real_states = None
    try:
        env_inner = model.get_env().envs[0]
        if hasattr(env_inner, 'records') and len(env_inner.records) > 0:
            real_states = np.array([r['s'] for r in env_inner.records], dtype=np.float32)
            print(f"  Using {len(real_states)} real states from traces for distillation")
    except Exception:
        pass

    if real_states is not None and len(real_states) >= 1000:
        # 70% real states (sampled with replacement), 30% augmented around real distribution
        n_real = int(n_samples * 0.7)
        n_aug = n_samples - n_real
        idx = np.random.choice(len(real_states), size=n_real, replace=True)
        sampled_real = real_states[idx]
        # Augment: add Gaussian noise to real states (explore nearby regions)
        noise = np.random.normal(0, 0.1, size=(n_aug, INPUT_DIM)).astype(np.float32)
        aug_idx = np.random.choice(len(real_states), size=n_aug, replace=True)
        sampled_aug = np.clip(real_states[aug_idx] + noise, -1.0, 2.0)
        states = np.vstack([sampled_real, sampled_aug])
    else:
        # Fallback: sample from per-dimension ranges matching Rust normalization.
        print("  No trace data available; sampling from expected state ranges")
        states = np.column_stack([
            np.random.uniform(0, 1, n_samples),    # srtt
            np.random.uniform(0, 1, n_samples),    # min_rtt
            np.random.uniform(-1, 1, n_samples),   # rtt_gradient
            np.random.uniform(0, 1, n_samples),    # delivery_rate
            np.random.uniform(-1, 1, n_samples),   # dr_gradient
            np.random.uniform(0, 1, n_samples),    # loss_rate
            np.random.uniform(0, 2, n_samples),    # in_flight_ratio
            np.random.uniform(0, 0.1, n_samples),  # queue_delay
        ]).astype(np.float32)
    with torch.no_grad():
        obs_tensor = torch.FloatTensor(states)
        # Get SB3 policy outputs (mean of action distribution)
        actions = model.policy.get_distribution(obs_tensor).distribution.mean
        # Map from [-1, 1] to [0, 1] (sigmoid target)
        targets = (actions - (-1.0)) / 2.0  # map [-1,1] -> [0,1]

    # Train the small network
    dataset = torch.utils.data.TensorDataset(obs_tensor, targets)
    loader = torch.utils.data.DataLoader(dataset, batch_size=512, shuffle=True)
    optimizer = torch.optim.Adam(small_net.parameters(), lr=1e-3)
    loss_fn = nn.MSELoss()

    for epoch in range(100):
        total_loss = 0.0
        for batch_x, batch_y in loader:
            pred = small_net(batch_x)
            loss = loss_fn(pred, batch_y)
            optimizer.zero_grad()
            loss.backward()
            optimizer.step()
            total_loss += loss.item()
        if (epoch + 1) % 20 == 0:
            print(f"  Epoch {epoch+1}/100, loss: {total_loss/len(loader):.6f}")

    # Export to binary format
    sd = small_net.state_dict()
    w1 = sd["0.weight"].numpy().flatten()  # [HIDDEN1, INPUT] row-major
    b1 = sd["0.bias"].numpy().flatten()
    w2 = sd["2.weight"].numpy().flatten()  # [HIDDEN2, HIDDEN1] row-major
    b2 = sd["2.bias"].numpy().flatten()
    w3 = sd["4.weight"].numpy().flatten()  # [OUTPUT, HIDDEN2] row-major
    b3 = sd["4.bias"].numpy().flatten()

    with open(output_path, "wb") as f:
        f.write(WEIGHT_MAGIC)
        for arr in [w1, b1, w2, b2, w3, b3]:
            for v in arr:
                f.write(struct.pack("<d", float(v)))

    total_params = len(w1) + len(b1) + len(w2) + len(b2) + len(w3) + len(b3)
    print(f"Exported {total_params} parameters ({output_path.stat().st_size} bytes)")


# ── Main ──────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Train AHP-RL congestion control policy")
    parser.add_argument("--traces", type=Path, required=True,
                        help="Directory containing trace JSONL files")
    parser.add_argument("--output", type=Path, default=Path("rl_model.pt"),
                        help="Path to save the trained model checkpoint")
    parser.add_argument("--export", type=Path, default=None,
                        help="Export weights in AHP binary format to this path")
    parser.add_argument("--timesteps", type=int, default=100_000,
                        help="Total training timesteps for PPO")
    parser.add_argument("--episode-len", type=int, default=200,
                        help="Episode length for replay environment")
    args = parser.parse_args()

    if not args.traces.is_dir():
        print(f"Error: {args.traces} is not a directory", file=sys.stderr)
        sys.exit(1)

    records = load_traces(args.traces)
    if len(records) < 100:
        print(f"Error: need at least 100 trace records, got {len(records)}", file=sys.stderr)
        sys.exit(1)

    # Train/validation split (80/20).
    split = int(len(records) * 0.8)
    train_records = records[:split]
    val_records = records[split:]
    print(f"Records: {len(train_records)} train, {len(val_records)} validation")

    # Create environment
    env = DummyVecEnv([lambda: AhpCcEnv(train_records, episode_len=args.episode_len)])

    # Train PPO
    print(f"\nTraining PPO for {args.timesteps} timesteps...")
    model = PPO(
        "MlpPolicy",
        env,
        verbose=1,
        learning_rate=3e-4,
        n_steps=2048,
        batch_size=64,
        n_epochs=10,
        gamma=0.99,
        gae_lambda=0.95,
        clip_range=0.2,
        policy_kwargs=dict(
            net_arch=dict(pi=[64, 64], vf=[64, 64]),
        ),
    )
    model.learn(total_timesteps=args.timesteps)

    # Evaluate on validation set.
    if len(val_records) >= args.episode_len:
        from stable_baselines3.common.evaluation import evaluate_policy
        val_env = DummyVecEnv([lambda: AhpCcEnv(val_records, episode_len=args.episode_len)])
        mean_reward, std_reward = evaluate_policy(model, val_env, n_eval_episodes=50)
        print(f"\nValidation: mean_reward={mean_reward:.4f} +/- {std_reward:.4f}")
    else:
        print("\nValidation: not enough records for evaluation")

    # Save model
    model.save(str(args.output))
    print(f"Model saved to {args.output}")

    # Export if requested
    export_path = args.export or Path.home() / ".config" / "favonius" / "rl_weights.bin"
    export_path.parent.mkdir(parents=True, exist_ok=True)
    export_weights(model, export_path)
    print(f"\nDone. To use: favonius send --congestion rl ...")


if __name__ == "__main__":
    main()
