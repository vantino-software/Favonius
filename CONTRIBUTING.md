# Contributing to Favonius

Thanks for looking. Favonius is early software — 0.1.0, one author, no
external review yet — so the most valuable contributions right now are
reproductions, measurements that disagree with ours, and bug reports with
enough detail to act on.

## Before you spend real effort

Open an issue first for anything larger than a bug fix. The congestion
control in particular has a long history of changes that looked like wins
and were not (see `crates/ahp-congestion/ALGORITHMS.md`), so a change there
needs measurements attached, and we would rather agree on what to measure
before you spend a weekend on it.

## Sign-off (DCO)

Every commit must carry a `Signed-off-by` line:

```bash
git commit -s -m "your message"
```

That line is the [Developer Certificate of Origin](https://developercertificate.org/)
1.1 — you are stating you wrote the patch, or have the right to submit it
under Apache-2.0. There is no CLA and no copyright assignment: your
contribution stays yours, licensed to the project under Apache-2.0 like the
rest of the tree.

Because there is no CLA, the project cannot unilaterally relicense your
contribution: it stays under Apache-2.0 unless you agree otherwise. That is
a deliberate commitment, not an omission.

## Building and testing

```bash
cargo build --release
cargo test --workspace          # the full suite, all must pass
cargo clippy --workspace --all-targets
```

CI runs with `RUSTFLAGS="-D warnings"`, so warnings fail the build. Clippy
is deliberately *not* gated on `-D warnings` — a number of style lints
remain, and clippy's lint set drifts between toolchains.

**MSRV is 1.87**, checked in CI. It is not a stylistic preference: the
tree uses `is_multiple_of`, stable since 1.87. If you raise the floor,
raise `rust-version` in `Cargo.toml` in the same commit — the MSRV was
wrong by twelve releases for a while precisely because a clippy suggestion
raised it silently and nothing tested it.

## Testing a change to the transfer path

Unit tests do not catch transport regressions. There are two harnesses:

```bash
# Correctness: 15 checks over send, directory sync, filters, mirror,
# append-only. Asserts on received bytes, not exit codes.
./benchmarks/scripts/verify_sync.sh

# Performance: shaped container pair (needs Docker; builds its own image)
RATE_MBIT=100 INSTANCE=mine ONLY_MODES="classic" \
  ./benchmarks/scripts/bench_netem_fair_v2.sh --runs 3 --tools favonius
```

If you change congestion control, also run
`./benchmarks/scripts/self_fairness.sh --image <tag>` — a controller that
gets faster by taking more of a shared link is not faster.

**Measurement discipline.** The benchmark rig drifts about 20% between
batches and was once 43% low for an entire session without saying so. Do
not compare a number you took today against one from the README taken
another day: re-measure the baseline in the same batch, and run
`./benchmarks/scripts/rig_check.sh control` first — it asserts a known cell
into a numeric range and fails if the rig is lying.

## Conventions

- Every `.rs` file starts with the three-line licence header (copy an
  existing one).
- Per-crate error enums with `thiserror`.
- Tests live inline in `#[cfg(test)] mod tests`.
- Comments should say *why*, especially where the code looks wrong but
  is not. Most of the comments in `ahp-congestion` exist because someone
  "fixed" the thing they describe and made it worse.

## Reporting a security issue

Do not open a public issue. See [SECURITY.md](SECURITY.md).
