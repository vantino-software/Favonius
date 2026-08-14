#!/usr/bin/env bash
# Favonius — high-performance file transfer over UDP
# Copyright (c) 2025-2026 Vantino SàRL
# SPDX-License-Identifier: Apache-2.0
#
#
# benchmarks/scripts/variance.sh
#
# Repeat one cell many times and report what difference the rig can
# actually resolve.
#
# Why this exists. Every table in this project outside one Classic
# investigation is n=2 or n=3, and decisions have been made on differences
# of 10-15% at that sample. Two concrete cases from the same week:
#
#   - Classic's transatlantic cell was recorded as "5.61%, unexplained".
#     It was a 9.84% run averaged with a 0.97% one, and the mode hit three
#     of ten first-runs. n=2 could not see that; it reported the mean of a
#     bimodal distribution as if it were a value.
#   - RL's transatlantic goodput moved 9.65 -> 8.70 MB/s between two runs
#     with no RL change. That sits exactly at the 0.90x regression
#     tolerance, so the harness stayed silent, and it flipped an A1 leg
#     from PASS to FAIL. Whether it was real is still unknown.
#
# A change smaller than what the rig can resolve is unfalsifiable, and
# tuning against unfalsifiable results is how a codebase accumulates
# confident wrong findings. This measures the resolution so the question
# can be asked before the tuning, not after.
#
# Usage:
#   variance.sh --image <tag> --mode rl --scenario transatlantic [--runs 20]
#   variance.sh --mode rl --scenario transatlantic --no-run   # analyse only
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RESULTS_DIR="$(cd "$HERE/../results" && pwd)"

IMAGE=""; MODE=""; SCENARIO=""; RUNS=20; SKIP_RUN=0
INSTANCE=""
RATE_MBIT="${RATE_MBIT:-100}"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --image) IMAGE="$2"; shift 2 ;;
        --mode) MODE="$2"; shift 2 ;;
        --scenario) SCENARIO="$2"; shift 2 ;;
        --runs) RUNS="$2"; shift 2 ;;
        --instance) INSTANCE="$2"; shift 2 ;;
        --no-run) SKIP_RUN=1; shift ;;
        *) echo "unknown argument: $1" >&2; exit 64 ;;
    esac
done
[ -n "$MODE" ] && [ -n "$SCENARIO" ] || {
    echo "--mode and --scenario are required" >&2; exit 64; }
INSTANCE="${INSTANCE:-var-$MODE-$SCENARIO}"

if [ "$SKIP_RUN" = 0 ]; then
    [ -n "$IMAGE" ] || { echo "--image is required unless --no-run" >&2; exit 64; }
    "$HERE/rig_check.sh" pre || exit 1
    echo "Running $MODE x $SCENARIO, $RUNS repeats at ${RATE_MBIT}Mbit."
    RATE_MBIT="$RATE_MBIT" QUEUE_BDP="${QUEUE_BDP:-1.0}" JITTER=0 \
    PACING="${PACING:-batch}" IMAGE="$IMAGE" INSTANCE="$INSTANCE" \
    ONLY_MODES="$MODE" ONLY_SCENARIOS="$SCENARIO" \
    TRANSFER_TIMEOUT="${TRANSFER_TIMEOUT:-180}" \
        "$HERE/bench_netem_fair_v2.sh" --runs "$RUNS" --tools favonius > /dev/null 2>&1
    "$HERE/rig_check.sh" post "$INSTANCE" "$RATE_MBIT" >/dev/null 2>&1 \
        || echo "WARNING: rig_check failed; treat the spread below with suspicion." >&2
fi

# Collect goodput, retx% and srtt/base_rtt per run.
DATA=$(
for f in "$RESULTS_DIR"/netem-fair-v2-"$INSTANCE"-"$SCENARIO"-favonius-"$MODE"-run*.log; do
    [ -f "$f" ] || continue
    line=$(grep -h "Transfer complete" "$f" 2>/dev/null) || continue
    [ -z "$line" ] && continue
    mb=$(grep -oP '\K[0-9.]+(?= Mi?B/s)' <<< "$line")
    pk=$(grep -oP '\K[0-9]+(?= pkts)' <<< "$line")
    rx=$(grep -oP '\K[0-9]+(?= retx)' <<< "$line")
    b=$(grep -hoP 'base_rtt=\K[0-9.]+' "$f" | head -1)
    a=$(grep -hoP 'avg=\K[0-9.]+' "$f" | tail -1)
    [ -z "$b" ] || [ -z "$a" ] && continue
    awk -v mb="$mb" -v pk="$pk" -v rx="$rx" -v b="$b" -v a="$a" \
        'BEGIN{printf "%s %.3f %.3f\n", mb, 100*rx/pk, a/b}'
done
)

[ -z "$DATA" ] && { echo "No completed runs for instance '$INSTANCE'." >&2; exit 2; }

echo
echo "$MODE / $SCENARIO — $(wc -l <<< "$DATA") completed runs"
echo
awk '
function stats(name, col,   i, n, s, ss, mean, sd, lo, hi, sorted, mdd) {
    n = 0; s = 0; ss = 0; lo = 1e18; hi = -1e18
    for (i = 1; i <= rows; i++) {
        v = val[i, col]
        n++; s += v; ss += v * v
        if (v < lo) lo = v
        if (v > hi) hi = v
    }
    mean = s / n
    var = (n > 1) ? (ss - n * mean * mean) / (n - 1) : 0
    if (var < 0) var = 0
    sd = sqrt(var)
    # Smallest difference two arms of THIS size could distinguish, roughly:
    # 2.8 * sd / sqrt(n) is the classic 80%-power / alpha=0.05 two-sample
    # figure. Reported for n=3 because that is what the tables use.
    mdd3 = 2.8 * sd / sqrt(3)
    printf "  %-12s mean %8.2f   sd %7.3f   cv %5.1f%%   min %8.2f   max %8.2f\n",
        name, mean, sd, (mean != 0 ? 100 * sd / mean : 0), lo, hi
    printf "  %-12s at n=3 the rig can resolve a difference of about %.2f (%.1f%% of mean)\n\n",
        "", mdd3, (mean != 0 ? 100 * mdd3 / mean : 0)
}
{ rows++; val[rows,1] = $1; val[rows,2] = $2; val[rows,3] = $3 }
END {
    stats("goodput MB/s", 1)
    stats("retx %", 2)
    stats("srtt/base", 3)
}' <<< "$DATA"

echo "  Raw goodput, sorted:"
awk '{print $1}' <<< "$DATA" | sort -g | tr '\n' ' '
echo
