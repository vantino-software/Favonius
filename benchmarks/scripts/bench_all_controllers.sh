#!/usr/bin/env bash
# Favonius — high-performance file transfer over UDP
# Copyright (c) 2025-2026 Vantino SàRL
# SPDX-License-Identifier: Apache-2.0
#
#
# benchmarks/scripts/bench_all_controllers.sh
#
# Run every congestion controller across the impaired scenarios and print
# one table. Optionally diff that table against a recorded baseline.
#
# Why this exists. `crates/ahp-cli/src/net_sender.rs` and
# `ahp-platform-net` are shared by every congestion profile, so a change to
# the send path is a change to all of them. The pacing fix in 9412d26 was
# validated on `--congestion rl` only; it was correct for RL and it moved
# Model -- the default controller -- from 9-10 MB/s to 1.1-3.3 MB/s. That
# regression sat in the tree until somebody happened to run Model for an
# unrelated reason.
#
# The converse failure is just as expensive and lasted longer: `fair`,
# `wifi` and `udt` were shipped profiles with no benchmark coverage at all,
# and udt.rs kept a `max_cwnd`-used-as-a-floor bug for months after the
# identical defect was found, measured and fixed in rl.rs. Nothing measured
# UDT, so nothing could show the bug or show a fix working.
#
# Any change under the send path or ahp-congestion should show this table
# before and after. It is ~7x the cost of a single-controller run and it is
# cheaper than discovering the regression months later.
#
# Usage:
#   bench_all_controllers.sh --image <tag> --instance <name> [--runs N]
#   bench_all_controllers.sh --instance after --baseline before
#   bench_all_controllers.sh --instance run1 --save-baseline main
#
# Baselines live in benchmarks/baselines/<name>.tsv. See the README there
# before recording one: no baseline taken before 9412d26 is trustworthy.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RESULTS_DIR="$(cd "$HERE/../results" && pwd)"
BASELINE_DIR="$HERE/../baselines"

IMAGE=""; INSTANCE=""; RUNS=3; BASELINE=""; SAVE_BASELINE=""; SKIP_RUN=0
RATE_MBIT="${RATE_MBIT:-100}"
SCENARIOS="${SCENARIOS:-cross-country,transatlantic,satellite,degraded}"
# All seven favonius congestion profiles. `fair`, `wifi` and `udt` were
# outside this set, so a send-path change could not be shown safe for them
# and a fix to them could not be shown to work. Narrow with MODES= when
# rig time matters more than coverage.
MODES="${MODES:-classic,model,rl,encrypt,fair,wifi,udt}"
# A controller may not regress more than this against the baseline before
# the script fails.
REGRESS_TOLERANCE="${REGRESS_TOLERANCE:-0.90}"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --image) IMAGE="$2"; shift 2 ;;
        --instance) INSTANCE="$2"; shift 2 ;;
        --runs) RUNS="$2"; shift 2 ;;
        --baseline) BASELINE="$2"; shift 2 ;;
        --save-baseline) SAVE_BASELINE="$2"; shift 2 ;;
        --no-run) SKIP_RUN=1; shift ;;
        *) echo "unknown argument: $1" >&2; exit 64 ;;
    esac
done
[ -n "$INSTANCE" ] || { echo "--instance is required" >&2; exit 64; }

if [ "$SKIP_RUN" = 0 ]; then
    [ -n "$IMAGE" ] || { echo "--image is required unless --no-run" >&2; exit 64; }

    "$HERE/rig_check.sh" pre || {
        echo "bench_all_controllers: environment not clean, refusing to run." >&2
        exit 1
    }

    echo "Running $MODES x $SCENARIOS at ${RATE_MBIT}Mbit, $RUNS run(s) each."
    RATE_MBIT="$RATE_MBIT" QUEUE_BDP="${QUEUE_BDP:-1.0}" JITTER=0 \
    PACING="${PACING:-batch}" IMAGE="$IMAGE" INSTANCE="$INSTANCE" \
    ONLY_MODES="$MODES" ONLY_SCENARIOS="$SCENARIOS" \
    TRANSFER_TIMEOUT="${TRANSFER_TIMEOUT:-180}" \
        "$HERE/bench_netem_fair_v2.sh" --runs "$RUNS" --tools favonius > /dev/null 2>&1

    "$HERE/rig_check.sh" post "$INSTANCE" "$RATE_MBIT" || {
        echo "bench_all_controllers: rig_check failed; the table below is not evidence." >&2
    }
fi

# mean MB/s, retx%, run count and goodput sd for one (instance, scenario,
# mode). The count and sd are recorded so a baseline carries its own
# uncertainty: leg 3 of A1 divides by this, and a reference measured at
# n=3 on a cell with 10% spread contributes ~6% of error to every ratio
# graded against it, before the candidate's own.
cell() {
    local inst="$1" sc="$2" mode="$3"
    local pk=0 rx=0 n=0 f line vals=""
    for f in "$RESULTS_DIR"/netem-fair-v2-"$inst"-"$sc"-favonius-"$mode"-run*.log; do
        [ -f "$f" ] || continue
        line=$(grep -h "Transfer complete" "$f" 2>/dev/null) || continue
        [ -z "$line" ] && continue
        local mb p r
        mb=$(grep -oP '\K[0-9.]+(?= Mi?B/s)' <<< "$line")
        p=$(grep -oP '\K[0-9]+(?= pkts)' <<< "$line")
        r=$(grep -oP '\K[0-9]+(?= retx)' <<< "$line")
        pk=$((pk + p)); rx=$((rx + r)); n=$((n + 1))
        vals="$vals $mb"
    done
    [ "$n" = 0 ] && { echo ""; return; }
    awk -v v="$vals" -v n="$n" -v rx="$rx" -v pk="$pk" 'BEGIN{
        c = split(v, a, " ")
        for (i = 1; i <= c; i++) { s += a[i]; ss += a[i]*a[i] }
        mean = s / c
        var = (c > 1) ? (ss - c*mean*mean) / (c - 1) : 0
        if (var < 0) var = 0
        sd = sqrt(var)
        printf "%.2f %.2f %d %.4f", mean, 100*rx/pk, n, sd
    }'
}

IFS=',' read -r -a SC_LIST <<< "$SCENARIOS"
IFS=',' read -r -a MODE_LIST <<< "$MODES"

TABLE=$(mktemp)
for sc in "${SC_LIST[@]}"; do
    for mode in "${MODE_LIST[@]}"; do
        read -r mb retx cn csd <<< "$(cell "$INSTANCE" "$sc" "$mode")"
        [ -n "${mb:-}" ] && printf '%s\t%s\t%s\t%s\t%s\t%s\n' \
            "$sc" "$mode" "$mb" "$retx" "$cn" "$csd" >> "$TABLE"
    done
done

if [ ! -s "$TABLE" ]; then
    echo "No completed runs for instance '$INSTANCE'." >&2
    rm -f "$TABLE"; exit 2
fi

if [ -n "$SAVE_BASELINE" ]; then
    mkdir -p "$BASELINE_DIR"
    cp "$TABLE" "$BASELINE_DIR/$SAVE_BASELINE.tsv"
    echo "Baseline written: benchmarks/baselines/$SAVE_BASELINE.tsv"
fi

BASE_FILE="$BASELINE_DIR/$BASELINE.tsv"
if [ -n "$BASELINE" ] && [ ! -f "$BASE_FILE" ]; then
    echo "No such baseline: $BASE_FILE" >&2; rm -f "$TABLE"; exit 2
fi

printf '%-15s %-8s %8s %8s' scenario controller "MB/s" "retx%"
[ -n "$BASELINE" ] && printf ' %10s %8s %7s' "base MB/s" "delta" "95% ci"
printf '\n'

regressions=0
unresolved=0
need_max=0
while IFS=$'\t' read -r sc mode mb retx cn csd; do
    printf '%-15s %-8s %8s %7s%%' "$sc" "$mode" "$mb" "$retx"
    if [ -n "$BASELINE" ]; then
        read -r base bn bsd <<< "$(awk -F'\t' -v s="$sc" -v m="$mode" \
            '$1==s && $2==m {print $3, ($5==""?1:$5), ($6==""?0:$6)}' "$BASE_FILE")"
        if [ -n "${base:-}" ]; then
            read -r ratio band verdict need <<< "$(awk \
                -v a="$mb" -v asd="${csd:-0}" -v an="${cn:-1}" \
                -v b="$base" -v bsd="$bsd" -v bn="$bn" -v t="$REGRESS_TOLERANCE" '
# Student t critical value at 95%, two-sided, for small samples.
#
# An sd estimated from three runs is itself a noisy estimate, and using
# 1.96 with it asserts a precision the sample cannot support: three runs
# that happen to land close together produce a tiny sd and a tight band.
# `model / degraded` was flagged at +/-0.10 when a 20-run measurement of
# the same cell gives cv 9.0% and a range of 7.3-9.8 -- both the baseline
# and the candidate sit inside it. At two degrees of freedom the critical
# value is 4.30, not 1.96.
function tcrit(df) {
    if (df <= 0)  return 12.71
    if (df == 1)  return 12.71
    if (df == 2)  return 4.30
    if (df == 3)  return 3.18
    if (df == 4)  return 2.78
    if (df == 5)  return 2.57
    if (df == 6)  return 2.45
    if (df == 8)  return 2.31
    if (df <= 10) return 2.26
    if (df <= 20) return 2.09
    if (df <= 30) return 2.04
    return 1.96
}
BEGIN{
                if (b <= 0) { print "0.00 0.00 unresolved"; exit }
                r = a / b
                sea = (an > 1) ? asd / sqrt(an) : asd
                seb = (bn > 1) ? bsd / sqrt(bn) : bsd
                rel = 0
                if (a > 0) rel += (sea/a)*(sea/a)
                if (b > 0) rel += (seb/b)*(seb/b)
                df = ((an < bn) ? an : bn) - 1
                ci = tcrit(df) * r * sqrt(rel)
                # A regression only when the whole interval is below the
                # bar. Short of the bar but overlapping it is unresolved.
                if (r + ci < t)      v = "regression"
                else if (r - ci < t) v = (r < t) ? "unresolved" : "ok"
                else                 v = "ok"
                # Runs per arm that would resolve a shortfall of this size,
                # holding the observed spread. Reported so "cannot tell"
                # comes with a price rather than a shrug.
                need = 0
                if (v == "unresolved" && r < t && rel > 0) {
                    gap = t - r
                    if (gap > 0) {
                        need = int(2.0 * (1.96*1.96) * rel * r * r / (gap*gap)) + 1
                        if (need < 4) need = 4
                    }
                }
                printf "%.2f %.2f %s %d", r, ci, v, need
            }')"
            printf ' %10s %7sx %s' "$base" "$ratio" "$(printf '+/-%.2f' "$band")"
            case "$verdict" in
                regression) printf '  REGRESSION'; regressions=$((regressions + 1)) ;;
                unresolved)
                    printf '  (below bar, unresolved; ~%s runs would tell)' "$need"
                    unresolved=$((unresolved + 1))
                    [ "${need:-0}" -gt "${need_max:-0}" ] && need_max="$need"
                    ;;
            esac
        else
            printf ' %10s %8s %7s' "-" "-" "-"
        fi
    fi
    printf '\n'
done < "$TABLE"
rm -f "$TABLE"

echo
if [ -n "$BASELINE" ] && [ "$regressions" != 0 ]; then
    echo "$regressions cell(s) resolvably below ${REGRESS_TOLERANCE}x of '$BASELINE'."
    exit 1
fi
if [ -n "$BASELINE" ] && [ "${unresolved:-0}" != 0 ]; then
    echo "CANNOT TELL: $unresolved cell(s) sit below ${REGRESS_TOLERANCE}x of"
    echo "'$BASELINE', and this run cannot say whether that is real. At the"
    echo "spread these cells show, about $need_max runs per arm would decide"
    echo "the widest of them. This is not a pass."
    exit 2
fi
[ -n "$BASELINE" ] && echo "No cell is below ${REGRESS_TOLERANCE}x of '$BASELINE'."
exit 0
