## What this changes

<!-- and why. Link the issue if there is one. -->

## Checks

- [ ] `cargo test --workspace` passes
- [ ] `cargo clippy --workspace --all-targets` produces no new warnings
- [ ] Commits are signed off (`git commit -s`) — see CONTRIBUTING.md

## If this touches the transfer or congestion path

- [ ] `./benchmarks/scripts/verify_sync.sh` passes
- [ ] `./benchmarks/scripts/rig_check.sh control` passed before I measured
- [ ] Before/after numbers below, from the **same batch** — this rig drifts
      ~20% between sessions, so a number from the README is not a baseline
- [ ] If congestion control changed: `self_fairness.sh` run, and the
      controller does not get faster by taking more of a shared link

<!--
Measurements:

| scenario | before | after | n |
|---|---|---|---|
|  |  |  |  |
-->
