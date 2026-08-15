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

Every commit in a pull request must carry a `Signed-off-by` line:

```bash
git commit -s -m "your message"
```

That line is your certification under the
[Developer Certificate of Origin](https://developercertificate.org/) 1.1 —
that you wrote the patch, or otherwise have the right to submit it under
the project's licence. There is no CLA and no copyright assignment: your
contribution stays yours, licensed under Apache-2.0 — to the project and to
everyone who receives it — like the rest of the tree.

Because there is no CLA, the project cannot unilaterally relicense your
contribution: it stays under Apache-2.0 unless you agree otherwise. That is
a deliberate commitment, not an omission.

CI checks this on every pull request, and only on the commits your PR adds.
If you forget, it tells you the one command that fixes it. The commits
already on `main` predate the check and are not signed off — the rule is
scoped to pull requests rather than rewriting published history to match a
check added afterwards.

**If a tool wrote more of the patch than you did, say so in the PR
description.** It does not disqualify anything — it changes how the patch
gets reviewed, and it is a question the DCO's wording does not really
answer for you.

## Building and testing

```bash
RUSTFLAGS="-D warnings" cargo build --workspace
RUSTFLAGS="-D warnings" cargo test --workspace   # the full suite, all must pass
cargo clippy --workspace --all-targets
```

**Use the `RUSTFLAGS` prefix.** CI sets it, so a warning that is merely
annoying locally is a failed build there. Running the bare commands is the
easiest way to have a PR fail on something your own machine told you was
fine. Clippy is deliberately *not* gated on `-D warnings` — a number of
style lints remain, and clippy's lint set drifts between toolchains — so it
is the one command here without the prefix.

Two more jobs run that these commands do not cover, so a green local run is
not a green CI run:

- **cross-platform** builds and tests `ahp-platform-net`, `ahp-cli` and
  `ahp-daemon` on Windows and on both macOS architectures. Code that is
  fine on Linux can fail here — most often a Unix-only call, or a function
  that is dead code once the Linux-gated callers are compiled out.
- **loopback-smoke** runs eight real transfers against a real daemon and
  checks the SHA-256 of what arrived, including a regression guard for a
  silent-corruption bug. Unit tests do not catch transport regressions.

If you cannot run those locally, say so in the PR and let CI do it.

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
