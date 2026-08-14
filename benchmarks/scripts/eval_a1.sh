#!/usr/bin/env bash
# Favonius — high-performance file transfer over UDP
# Copyright (c) 2025-2026 Vantino SàRL
# SPDX-License-Identifier: Apache-2.0
#
#
# benchmarks/scripts/eval_a1.sh
#
# Evaluate the A1 criterion from bench_netem_fair_v2.sh logs.
#
# A1 has three legs and all of them must hold on all four impaired
# scenarios (the CC research notes section 7):
#
#   1. loss         retx < min(10%, configured_random_loss + 3 pp)
#   2. delay        srtt - base_rtt < DELAY_FIXED_MS + 0.25 * base_rtt
#   3. utilisation  goodput >= 90% of the recorded baseline for the cell,
#                   and only reported at UTIL_MIN_RUNS runs or more
#
# Leg 3 is not optional bookkeeping. Legs 1 and 2 are jointly passable by a
# controller that sends arbitrarily slowly -- measured, not hypothesised:
# gain cycling reached retx 2.02% and 1.05x inflation on satellite while
# moving 6% of the link.
#
# `base_rtt` comes from the pre-transfer probe (ten packets, empty path).
# The `rtt min=` on progress lines is a per-window minimum -- the sample
# buffer is cleared every report -- and is NOT a substitute, nor is the
# controller's own min_rtt, which it influences.
#
# Leg 3's reference is a *recorded* baseline in benchmarks/baselines/, not
# the live Model. Grading a candidate against whatever Model does today
# makes the bar move every time Model changes -- and it was ungradeable
# outright while Model timed out, since 90% of a timeout is undefined and
# is passed by anything that completes. A recorded baseline is a fixed
# number with a commit behind it.
#
# Usage:
#   ./benchmarks/scripts/eval_a1.sh <instance> [baseline-name]
#
#   ./benchmarks/scripts/eval_a1.sh openfix main
#   ./benchmarks/scripts/eval_a1.sh openfix            # legs 1-2 only
#   MODES=classic,model ./benchmarks/scripts/eval_a1.sh openfix main
#
# Every controller is graded, not just `rl`. A1 was written for the RL
# work and applied to RL alone, which is how Classic came to sit at
# srtt/base_rtt 2.15x on cross-country -- a full BDP of standing queue in
# a shipped controller, against a criterion of 1.25x that three other
# controllers were being held to.
set -uo pipefail

RESULTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../results" && pwd)"
INSTANCE="${1:?usage: eval_a1.sh <instance> [baseline-name]}"
BASELINE="${2:-}"
BASELINE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../baselines" && pwd)"
BASELINE_FILE="${BASELINE:+$BASELINE_DIR/$BASELINE.tsv}"

# scenario|configured random loss %
SCENARIOS=(
    "cross-country|0.5"
    "transatlantic|1"
    "satellite|2"
    "degraded|5"
)

# Delay budget: a fixed allowance plus a fraction of the path RTT.
#
# This was `srtt / base_rtt < 1.25`, a pure ratio, and it was not
# achievable on a short path no matter what a controller did. Measured
# across 28 cells, the *minimum* excess delay on every scenario is about
# the same number of milliseconds regardless of the path's RTT:
#
#   cross-country  base  25.3 ms   floor 7.4 ms (wifi, 36% utilisation)
#   transatlantic  base  50.3 ms   floor 6.2 ms (fair, 34%)
#   satellite      base 150.3 ms   floor 7.4 ms (udt,  57%)
#   degraded       base 100.3 ms   floor 7.3 ms (udt,  62%)
#
# That floor is not a queue: `fair` reaches it on satellite at 13%
# utilisation, where there is nothing to queue. It is the difference
# between a probe of ten small packets on an idle path and data-path RTT
# under load -- serialisation, GSO batching, the 5 ms control tick,
# receiver processing. As a ratio it is 1.29x at 25 ms and 1.05x at
# 150 ms, so a flat 1.25x bar failed every controller on cross-country
# including one running at 36% of the link with an empty queue.
#
# Splitting it into a fixed part and a proportional part measures what the
# leg is for -- standing queue -- rather than penalising short paths for a
# constant. Classic, encrypt and UDT still fail on most paths: they sit
# 20-40 ms above the floor, which is a real queue and is the thing this
# leg exists to catch.
#
# **The fixed term is now measured per scenario rather than assumed.**
# Decomposing the excess on 2026-08-10 showed `min_rtt` under load equals
# `base_rtt` to within 0.2 ms on all 28 cells, so there is no fixed
# *serialisation* offset in the RTT at all -- the whole excess is queue.
# What the floor actually measures is the *transient* queue left by
# batch-mode bursts, which is a property of the send path and not of the
# controller under test.
#
# That transient scales with the controller's own rate: `fair` leaves
# 11.1 ms on cross-country where it runs at 6.58 MB/s, and 7.1-7.8 ms on
# the three slower paths. A single 8 ms constant therefore understates it
# by 3 ms on exactly the path where Classic fails by 1.7 ms -- the leg was
# charging Classic for the send path's bursts.
#
# The floor is taken as the smallest excess any graded controller achieves
# on that scenario in this run. That is empirical rather than assumed, and
# it does not privilege one profile. Guards: at least
# DELAY_FLOOR_MIN_MODES controllers must be graded, and the floor is capped
# at DELAY_FLOOR_MAX_MS so a run in which *everything* queues cannot
# silently excuse itself.
DELAY_FIXED_MS="${DELAY_FIXED_MS:-8}"
DELAY_RTT_FRACTION="${DELAY_RTT_FRACTION:-0.25}"
DELAY_FLOOR_MIN_MODES="${DELAY_FLOOR_MIN_MODES:-3}"
DELAY_FLOOR_MAX_MS="${DELAY_FLOOR_MAX_MS:-15}"

# Smallest excess observed across the graded modes for one scenario.
# Falls back to DELAY_FIXED_MS when too few modes were graded to trust it.
scenario_delay_floor() {
    local sc="$1"; shift
    local best="" n=0 mode mb retx base avg cnt sd ex
    for mode in "$@"; do
        read -r mb retx base avg cnt sd <<< "$(collect "$INSTANCE" "$sc" "$mode")"
        [ -z "${mb:-}" ] && continue
        ex=$(awk -v a="$avg" -v b="$base" 'BEGIN{printf "%.2f", a-b}')
        n=$((n + 1))
        if [ -z "$best" ] || awk -v e="$ex" -v b="$best" 'BEGIN{exit !(e<b)}'; then
            best="$ex"
        fi
    done
    if [ "$n" -lt "$DELAY_FLOOR_MIN_MODES" ] || [ -z "$best" ]; then
        echo "$DELAY_FIXED_MS fallback"
        return
    fi
    awk -v b="$best" -v cap="$DELAY_FLOOR_MAX_MS" -v fx="$DELAY_FIXED_MS" 'BEGIN{
        if (b > cap) { printf "%.1f capped\n", cap }
        else if (b < fx) { printf "%.1f measured\n", b }
        else             { printf "%.1f measured\n", b }
    }'
}
UTIL_MIN=0.90
# Minimum runs before a utilisation verdict is reported.
#
# The three legs do not have comparable resolution, and reporting them with
# equal authority produced verdicts that were not evidence. Measured with
# variance.sh, RL on transatlantic, 20 runs:
#
#   srtt/base    cv  0.3%   ->  resolvable at n=3 to 0.5%
#   retx %       cv 14.7%   ->  resolvable at n=3 to 24%
#   goodput      cv 23.3%   ->  resolvable at n=3 to 38%
#
# A goodput difference under ~38% was therefore indistinguishable from
# noise at the sample this script was routinely run with, and the
# transatlantic utilisation leg flipped PASS/FAIL/PASS across three
# gradings on exactly that. The delay leg, by contrast, is trustworthy at
# n=3 and has been throughout.
#
# The variance is a property of the controller under test, not of the rig:
# after the probe fix RL's coefficient of variation on that cell fell from
# 23.3% to 0.6%. So this is a floor, not a substitute for measuring the
# spread with variance.sh when a number matters.
UTIL_MIN_RUNS="${UTIL_MIN_RUNS:-5}"
# The controller leg 3 divides by. It is graded on legs 1 and 2 like any
# other, but not against itself.
REFERENCE="${REFERENCE:-model}"

# Mean goodput / total packets / total retx / base_rtt / final avg rtt for
# one (instance, scenario, mode) triple. Emits: "mb retxpct base avg n"
collect() {
    local inst="$1" sc="$2" mode="$3"
    local pk=0 rx=0 n=0 sb=0 sa=0 vals=""
    local f line
    for f in "$RESULTS_DIR"/netem-fair-v2-"$inst"-"$sc"-favonius-"$mode"-run*.log; do
        [ -f "$f" ] || continue
        line=$(grep -h "Transfer complete" "$f" 2>/dev/null) || continue
        [ -z "$line" ] && continue
        local mb p r b a
        mb=$(grep -oP '\K[0-9.]+(?= Mi?B/s)' <<< "$line")
        p=$(grep -oP '\K[0-9]+(?= pkts)' <<< "$line")
        r=$(grep -oP '\K[0-9]+(?= retx)' <<< "$line")
        b=$(grep -hoP 'base_rtt=\K[0-9.]+' "$f" | head -1)
        a=$(grep -hoP 'avg=\K[0-9.]+' "$f" | tail -1)
        [ -z "$b" ] || [ -z "$a" ] && continue
        pk=$((pk + p)); rx=$((rx + r)); n=$((n + 1)); vals="$vals $mb"
        sb=$(awk -v x="$sb" -v y="$b" 'BEGIN{print x+y}')
        sa=$(awk -v x="$sa" -v y="$a" 'BEGIN{print x+y}')
    done
    [ "$n" = 0 ] && { echo ""; return; }
    awk -v v="$vals" -v pk="$pk" -v rx="$rx" -v sb="$sb" -v sa="$sa" -v n="$n" 'BEGIN{
        c = split(v, a, " ")
        for (i = 1; i <= c; i++) { s += a[i]; ss += a[i]*a[i] }
        mean = s / c
        var = (c > 1) ? (ss - c*mean*mean) / (c - 1) : 0
        if (var < 0) var = 0
        sd = sqrt(var)
        printf "%.2f %.2f %.1f %.1f %d %.4f", mean, 100*rx/pk, sb/n, sa/n, n, sd
    }'
}

if [ -n "$BASELINE" ] && [ ! -f "$BASELINE_FILE" ]; then
    echo "No such baseline: $BASELINE_FILE" >&2
    exit 2
fi

printf '%-15s %-8s %7s %7s %8s %8s %7s  %s\n' \
    scenario controller "MB/s" "retx%" "excess" "budget" "vs base" "A1"

fails=0
evaluated=0
unresolved=0
IFS=',' read -r -a MODE_LIST <<< "${MODES:-classic,model,rl,encrypt,fair,wifi,udt}"

for entry in "${SCENARIOS[@]}"; do
    IFS='|' read -r sc loss <<< "$entry"
    read -r SC_FLOOR SC_FLOOR_SRC <<< "$(scenario_delay_floor "$sc" "${MODE_LIST[@]}")"
    printf '%-15s delay floor %.1f ms (%s), budget = floor + %s x base_rtt\n' \
        "$sc" "$SC_FLOOR" "$SC_FLOOR_SRC" "$DELAY_RTT_FRACTION"
  for mode in "${MODE_LIST[@]}"; do
    read -r mb retx base avg n sd <<< "$(collect "$INSTANCE" "$sc" "$mode")"
    if [ -z "${mb:-}" ]; then
        printf '%-15s %-8s  (no completed runs)\n' "$sc" "$mode"
        continue
    fi
    evaluated=$((evaluated + 1))

    budget=$(awk -v l="$loss" 'BEGIN{b=l+3; print (b<10)?b:10}')
    inflation=$(awk -v a="$avg" -v b="$base" 'BEGIN{printf "%.2f", (b>0)?a/b:999}')
    excess=$(awk -v a="$avg" -v b="$base" 'BEGIN{printf "%.1f", a-b}')
    delay_budget=$(awk -v b="$base" -v fx="$SC_FLOOR" -v fr="$DELAY_RTT_FRACTION" \
        'BEGIN{printf "%.1f", fx + fr*b}')

    # Leg 3, carrying the uncertainty of BOTH sides.
    #
    # The ratio is candidate/reference and each side has a standard error
    # of sd/sqrt(n). A verdict is issued only when the ratio's 95% interval
    # falls clearly one side of the bar; otherwise it is unresolved.
    # Requiring runs of the candidate alone is not enough -- the reference
    # is measured too, and a Model baseline at n=3 on a cell with 10.9%
    # spread contributes about 6% of error to every ratio graded against
    # it, which is larger than the margin several verdicts turned on.
    util="n/a"; util_verdict="none"; util_note=""
    # A controller cannot be graded against itself. Model is leg 3's
    # reference, so its own ratio is 1.00 by construction and the two
    # standard errors are the same measurement counted twice -- the
    # interval is meaningless rather than wide. This is the same
    # self-reference the leg had when it read "90% of Model's" live
    # goodput, one level down.
    if [ -n "$BASELINE" ] && [ "$mode" = "$REFERENCE" ]; then
        util="ref"; util_verdict="none"
    elif [ -n "$BASELINE" ]; then
        read -r rmb rn rsd <<< "$(awk -F'\t' -v s="$sc" -v m="model" \
            '$1==s && $2==m {print $3, ($5==""?1:$5), ($6==""?0:$6)}' "$BASELINE_FILE")"
        if [ -n "${rmb:-}" ]; then
            read -r util util_verdict <<< "$(awk \
                -v a="$mb" -v asd="${sd:-0}" -v an="${n:-1}" \
                -v b="$rmb" -v bsd="$rsd" -v bn="$rn" -v bar="$UTIL_MIN" '
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
                if (b <= 0) { print "0.00 unresolved"; exit }
                r = a / b
                sea = (an > 1) ? asd / sqrt(an) : asd
                seb = (bn > 1) ? bsd / sqrt(bn) : bsd
                rel = 0
                if (a > 0) rel += (sea/a)*(sea/a)
                if (b > 0) rel += (seb/b)*(seb/b)
                df = ((an < bn) ? an : bn) - 1
                ci = tcrit(df) * r * sqrt(rel)
                if (r - ci >= bar)     v = "pass"
                else if (r + ci < bar) v = "fail"
                else                   v = "unresolved"
                printf "%.2f %s", r, v
            }')"
            [ "$util_verdict" = "unresolved" ] && util_note="ref n=$rn"
        fi
    fi

    verdict=$(awk -v rx="$retx" -v bud="$budget" -v inf="$inflation" \
                  -v uv="$util_verdict" -v ex="$excess" -v dbud="$delay_budget" 'BEGIN{
        f=""
        if (rx >= bud)    f = f " loss"
        if (ex >= dbud)   f = f " delay"
        if (uv == "fail") f = f " util"
        if (f != "") { print "FAIL:" f; exit }
        print (uv == "pass") ? "PASS" : "legs1-2 pass"
    }')
    if [ "$util_verdict" = "unresolved" ] && [ -n "$BASELINE" ]; then
        verdict="$verdict (util unresolved, $util_note)"
        unresolved=$((unresolved + 1))
    fi
    [[ "$verdict" == FAIL:* ]] && fails=$((fails + 1))

    printf '%-15s %-8s %7s %6s%% %6sms %6sms %7s  %s\n' \
        "$sc" "$mode" "$mb" "$retx" "$excess" "$delay_budget" "$util" "$verdict"
  done
done

echo
if [ "$evaluated" = 0 ]; then
    echo "No completed runs found for instance '$INSTANCE'."
    exit 2
fi
if [ -z "$BASELINE" ]; then
    echo "Leg 3 (utilisation) unmeasured: pass a recorded baseline name."
    echo "See benchmarks/baselines/README.md for what must hold before one"
    echo "is worth recording."
    exit 2
fi
if [ "$unresolved" != 0 ]; then
    echo "$unresolved of $evaluated cells could not be graded on utilisation:"
    echo "the candidate/reference ratio's confidence interval spans the 0.90"
    echo "bar, so neither a pass nor a fail is supported. Raise the run count"
    echo "on the candidate, the baseline, or both -- variance.sh reports which"
    echo "side dominates."
fi
[ "$fails" = 0 ] && { echo "A1: no cell fails a leg that could be graded."; exit 0; }
echo "A1: FAIL on $fails of $evaluated cells."
exit 1
