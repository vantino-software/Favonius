#!/usr/bin/env bash
# Favonius — high-performance file transfer over UDP
# Copyright (c) 2025-2026 Vantino SàRL
# SPDX-License-Identifier: Apache-2.0
#
#
# benchmarks/scripts/preflight.sh
#
# A cheap gate: does every controller still move data?
#
# Why this exists. Work on this codebase oscillates between regressions,
# and the cost is the feedback loop rather than the regressions
# themselves. Controllers are mutually calibrated around shared defects,
# so any change to the send path ripples through all seven -- that part is
# inherent. What is not inherent is discovering it forty minutes later.
#
# Every regression that cost a full rig cycle this week was the same
# shape, and none of them was subtle:
#
#   fair    timed out when the RTT feed was corrected
#   model   deadlocked at MIN_CWND when the bandwidth seed was removed
#   rl      locked at half rate while the gain cycle's probe was inert
#   udt     sent 4.4x the packets it needed, for months, unmeasured
#
# Each is visible in one transfer per controller. This runs 6 controllers
# on 2 scenarios, one run each -- about five minutes against forty for a
# full table -- and fails on a timeout or on a controller sitting near its
# floor. It does not replace bench_all_controllers.sh; it stops you
# spending forty minutes to learn something a fifth of that would have
# told you.
#
# The simulator is faster still and now runs first, below: twelve cells in
# 1.6 s with no rig at all. It does not replace this either. Its
# utilisation runs 0.27x to 1.45x the rig's per cell and inverts on `wifi`,
# so it resolves collapse and nothing finer -- see the comment on
# `no_controller_collapses` in pathsim.rs.
#
# Usage:  preflight.sh --image favonius-bench:v2-<tag>
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RESULTS_DIR="$(cd "$HERE/../results" && pwd)"
IMAGE=""; INSTANCE="preflight"
MODES="${MODES:-classic,model,rl,encrypt,fair,wifi,udt}"
SCENARIOS="${SCENARIOS:-cross-country,degraded}"
# A controller below this fraction of the link is not "slower", it is
# broken. Deliberately far below any performance target.
FLOOR="${FLOOR:-0.10}"
RATE_MBIT="${RATE_MBIT:-100}"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --image) IMAGE="$2"; shift 2 ;;
        --instance) INSTANCE="$2"; shift 2 ;;
        *) echo "unknown argument: $1" >&2; exit 64 ;;
    esac
done
[ -n "$IMAGE" ] || { echo "--image is required" >&2; exit 64; }

# Free, and it has caught a collapse the rig cannot reach at all: Model
# froze in Startup with no feedback path when a path blackholed, which the
# rig never enters. No reason to spend five minutes before spending 1.6 s.
echo "Simulator collapse gate:"
if ! (cd "$HERE/../.." && cargo test -q -p ahp-congestion no_controller_collapses 2>&1 | tail -20); then
    echo "preflight: a controller collapsed in simulation; not spending rig time." >&2
    exit 1
fi

"$HERE/rig_check.sh" pre || exit 1
rm -f "$RESULTS_DIR"/netem-fair-v2-"$INSTANCE"-*.log
RATE_MBIT="$RATE_MBIT" QUEUE_BDP="${QUEUE_BDP:-1.0}" JITTER=0 PACING="${PACING:-batch}" \
IMAGE="$IMAGE" INSTANCE="$INSTANCE" ONLY_MODES="$MODES" ONLY_SCENARIOS="$SCENARIOS" \
TRANSFER_TIMEOUT="${TRANSFER_TIMEOUT:-90}" \
    "$HERE/bench_netem_fair_v2.sh" --runs 1 --tools favonius > /dev/null 2>&1

cap=$(awk -v r="$RATE_MBIT" 'BEGIN{print r/8}')
fail=0
printf '%-15s %-8s %8s %8s\n' scenario controller "MB/s" "% link"
IFS=',' read -r -a SC <<< "$SCENARIOS"
IFS=',' read -r -a MD <<< "$MODES"
for sc in "${SC[@]}"; do
  for m in "${MD[@]}"; do
    f="$RESULTS_DIR/netem-fair-v2-$INSTANCE-$sc-favonius-$m-run1.log"
    if [ ! -f "$f" ] || ! grep -q "Transfer complete" "$f" 2>/dev/null; then
        printf '%-15s %-8s %8s %8s   DID NOT COMPLETE\n' "$sc" "$m" "-" "-"
        fail=$((fail + 1)); continue
    fi
    mb=$(grep -h "Transfer complete" "$f" | grep -oP '\K[0-9.]+(?= Mi?B/s)')
    pct=$(awk -v a="$mb" -v c="$cap" 'BEGIN{printf "%.0f", 100*a/c}')
    bad=$(awk -v a="$mb" -v c="$cap" -v fl="$FLOOR" 'BEGIN{print (a/c < fl) ? 1 : 0}')
    printf '%-15s %-8s %8s %7s%%%s\n' "$sc" "$m" "$mb" "$pct" \
        "$([ "$bad" = 1 ] && echo "   AT ITS FLOOR" || true)"
    [ "$bad" = 1 ] && fail=$((fail + 1))
  done
done

echo
if [ "$fail" != 0 ]; then
    echo "preflight: $fail cell(s) broken. Do not spend a full rig run on this build."
    exit 1
fi
echo "preflight: all $((${#SC[@]} * ${#MD[@]})) cells move data. A full table is worth running."
exit 0
