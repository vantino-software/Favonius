#!/usr/bin/env bash
# Favonius — high-performance file transfer over UDP
# Copyright (c) 2025-2026 Vantino SàRL
# SPDX-License-Identifier: Apache-2.0
#
#
# benchmarks/scripts/rig_check.sh
#
# Assert that a benchmark run measured the transport and not the harness.
#
# Why this exists. Of the twenty-five commits before it, at least six fix a
# measurement rather than a feature:
#
#   f7dbcba  give the benchmark rig a real bottleneck, and stop it lying
#   e01735f  stop Model feeding its own output to its bandwidth estimator
#   a326fed  the kill list could name itself, and did
#   841aab9  retract the RL benchmark claims
#   28bd40c  ... and a correction to the retraction
#   9412d26  the pacer could not pace, and every RL rig number measured that
#
# The common property is that nothing was anchored to an independent
# ground truth: the controller's estimate, the test's input and the rig's
# output all came from the same loop, so an error was self-consistent and
# survived until something external forced a re-measurement. These checks
# are that external thing. They are deliberately cheap and deliberately
# fatal -- a failed check should stop a number from being believed, not
# annotate it.
#
# Usage:
#   rig_check.sh pre                       # before a run: environment is clean
#   rig_check.sh post <instance> [mbit]    # after a run: every log is sound
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RESULTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../results" && pwd)"

# debt_ratio outside this band means the pacer is not what sets the send
# rate. It read ~15 while batch mode capped a 30 ms pacing debt at 2 ms.
DEBT_MIN=0.80
DEBT_MAX=1.20
# Wire throughput above the configured bottleneck by more than this means
# the bottleneck is not in the path (see f7dbcba).
BOTTLENECK_TOLERANCE=1.05

fail=0
note() { printf '  %-6s %s\n' "$1" "$2"; }
bad()  { note "FAIL" "$1"; fail=$((fail + 1)); }

cmd_pre() {
    echo "rig_check pre:"

    # Stray transport processes from an earlier run will share the
    # bottleneck and be attributed to whatever runs next. Eight tsunamid at
    # 99.8% CPU once flooded the link for 69 minutes and the CSV blamed the
    # tools. Match on exact names: `pgrep -f` matches this script's own
    # command line, which is the a326fed bug.
    local stray
    stray=$(pgrep -x 'favonius|favonius-daemon|tsunamid|tsunami|udt|quic-bench|uftpd' 2>/dev/null | wc -l)
    [ "$stray" != 0 ] && bad "$stray stray transport process(es) running; kill them first"

    local conts
    conts=$(docker ps --format '{{.Names}}' 2>/dev/null | grep -c '^hbv2-' || true)
    [ "${conts:-0}" != 0 ] && note "warn" "$conts hbv2-* container(s) already up (concurrent run?)"

    [ "$fail" = 0 ] && note "ok" "environment clean"
    return $fail
}

cmd_post() {
    local instance="${1:?usage: rig_check.sh post <instance> [bottleneck_mbit]}"
    local mbit="${2:-0}"
    echo "rig_check post: instance=$instance bottleneck=${mbit:-unset}Mbit"

    local logs=("$RESULTS_DIR"/netem-fair-v2-"$instance"-*.log)
    [ -e "${logs[0]}" ] || { bad "no logs for instance '$instance'"; return 1; }

    local checked=0 f
    for f in "${logs[@]}"; do
        [ -f "$f" ] || continue
        local name; name=$(basename "$f" .log)

        grep -q "Transfer complete" "$f" || continue
        checked=$((checked + 1))

        # 1. Was the pacer the actuator? This is the check that would have
        #    caught 9412d26 in a single run.
        local summary; summary=$(grep -h "PACE_SUMMARY" "$f" | tail -1)
        if [ -z "$summary" ]; then
            bad "$name: no PACE_SUMMARY (binary predates rig_check; rebuild)"
        else
            local dr; dr=$(grep -oP 'debt_ratio=\K[0-9.]+' <<< "$summary")
            if awk -v d="$dr" -v lo="$DEBT_MIN" -v hi="$DEBT_MAX" \
                   'BEGIN{exit !(d<lo || d>hi)}'; then
                bad "$name: debt_ratio=$dr outside [$DEBT_MIN,$DEBT_MAX] — the pacer is not setting the rate"
            fi
        fi

        # 2. Did the bottleneck exist? Wire throughput cannot exceed it.
        if [ "$mbit" != 0 ] && [ -n "$summary" ]; then
            local wire ach
            wire=$(grep -oP 'wire_mbit=\K[0-9.]+' <<< "$summary")
            ach=$(grep -oP 'ach_mbit=\K[0-9.]+' <<< "$summary")
            # Emitted rate above the link is NOT evidence the bottleneck is
            # missing: a sender may legitimately emit more than the link
            # carries, and the excess is dropped. That is what overdriving
            # looks like, and calling it a rig fault sends the reader to the
            # harness when the fault is in the controller. Measured: Classic
            # emitting 144 Mbit into a 100 Mbit link with 32.8% retransmits
            # -- a real defect, reported here as the wrong one.
            #
            # Delivered goodput above the link would be impossible and is
            # the signal that actually implicates the rig; it is not in
            # PACE_SUMMARY yet, so this is a warning until it is.
            if awk -v w="$wire" -v c="$mbit" -v t="$BOTTLENECK_TOLERANCE" \
                   'BEGIN{exit !(w > c*t)}'; then
                note "warn" "$name: emitting ${wire}Mbit into a ${mbit}Mbit link — controller is overdriving"
            fi
            # The rate sustained across paced intervals cannot exceed the
            # link either. This is the sharper of the two: a sender that
            # bursts past its own pacing shows up here long before the
            # whole-transfer average does, because the average is diluted
            # by slow start and by any interval the sender spent blocked.
            if awk -v a="$ach" -v c="$mbit" -v t="$BOTTLENECK_TOLERANCE" \
                   'BEGIN{exit !(a > c*t)}'; then
                note "warn" "$name: ${ach}Mbit sustained across paced intervals on a ${mbit}Mbit link — overdriving, or the pacer is not binding"
            fi
        fi

        # 3. Did the controller under test actually run? A rejected weight
        #    file silently changes which code path executes.
        # The controller name is Display-formatted and capitalised
        # ("Rl", "Model"), so lowercase before comparing. A case-sensitive
        # match here silently matched nothing and made this check inert --
        # which is the exact failure mode this file exists to prevent.
        local cc; cc=$(grep -hoP 'CC_SUMMARY controller=\K[A-Za-z]+' "$f" | tail -1 | tr 'A-Z' 'a-z')
        local want; want=$(sed -E 's/.*-favonius-([a-z]+)-run[0-9]+$/\1/' <<< "$name")
        if [ -n "$cc" ] && [ -n "$want" ] && [ "$cc" != "$want" ] && [ "$want" != "encrypt" ]; then
            bad "$name: ran controller '$cc' but the cell is '$want'"
        fi
        if grep -q "bad magic" "$f" && [ "$want" = "rl" ]; then
            note "warn" "$name: weight file rejected — constant/cycle path, not a learned policy"
        fi

        # 4. Did it deliver the file it claims? Truncated transfers that
        #    still print a rate are worse than failures.
        local bytes; bytes=$(grep -h "Transfer complete" "$f" | grep -oP '\(\K[0-9]+(?= bytes)')
        [ -n "$bytes" ] && [ "$bytes" -lt 1048576 ] && bad "$name: only $bytes bytes transferred"
    done

    [ "$checked" = 0 ] && bad "no completed transfers among ${#logs[@]} log(s)"
    [ "$fail" = 0 ] && note "ok" "$checked transfer(s) sound"
    return $fail
}

# Every other check in this file tests a *mechanism* — no stray processes,
# a faithful pacer, a clean environment. None of them tests the *number*,
# and on 2026-08-08 that gap cost a day.
#
# A whole measurement session read `rl`/satellite at 45.9 MB/s where three
# later batches read 65.7-66.8 on identical configuration: 43% wrong, for
# hours, silently. `rig_check pre` passed throughout, because nothing was
# mechanically wrong. Four conclusions were drawn from that session and one
# of them was committed as a shipped default.
#
# This runs one transfer of a known cell and compares it against a stored
# range. It cannot diagnose *why* the rig is off; it only refuses to let a
# session start when it is.
#
# Calibrate with `--calibrate`, which prints a line to paste into
# CONTROL_EXPECT below. Recalibrate whenever the send path changes — the
# range is a property of a build as much as of the rig.
CONTROL_IMAGE="${CONTROL_IMAGE:-favonius-bench:v2-rlbi}"
CONTROL_SCENARIO="${CONTROL_SCENARIO:-cross-country}"
CONTROL_MODE="${CONTROL_MODE:-classic}"
CONTROL_RATE="${CONTROL_RATE:-100}"
# scenario|mode|rate|lo|hi  (MB/s, generous enough that only a broken rig
# trips it — this is a smoke test, not a regression gate)
CONTROL_EXPECT="${CONTROL_EXPECT:-cross-country|classic|100|9.3|11.3}"

cmd_control() {
    local calibrate="${1:-}"
    echo "rig_check control:"
    local inst="rigctl$$"
    local out
    out=$(IMAGE="$CONTROL_IMAGE" INSTANCE="$inst" RATE_MBIT="$CONTROL_RATE" \
          SIZE_MB=128 TRANSFER_TIMEOUT=120 RUNS=1 \
          ONLY_SCENARIOS="$CONTROL_SCENARIO" ONLY_MODES="$CONTROL_MODE" \
          "$HERE/bench_netem_fair_v2.sh" --tools favonius 2>&1) || true
    local mb
    mb=$(grep -oP '=> \d+ms \K[0-9.]+(?= Mi?B/s)' <<< "$out" | head -1)
    rm -f "$RESULTS_DIR"/netem-fair-v2-"$inst"-* \
          "$RESULTS_DIR"/netem_fair_v2-"$inst"_* 2>/dev/null

    if [ -z "$mb" ]; then
        bad "control cell did not complete — the rig cannot measure anything"
        return 1
    fi
    if [ -n "$calibrate" ]; then
        awk -v m="$mb" -v s="$CONTROL_SCENARIO" -v c="$CONTROL_MODE" -v r="$CONTROL_RATE" \
            'BEGIN{printf "  measured %.2f MB/s\n  CONTROL_EXPECT=\"%s|%s|%s|%.1f|%.1f\"\n",
                   m, s, c, r, m*0.90, m*1.10}'
        return 0
    fi
    local lo hi
    lo=$(cut -d'|' -f4 <<< "$CONTROL_EXPECT"); hi=$(cut -d'|' -f5 <<< "$CONTROL_EXPECT")
    if awk -v m="$mb" -v l="$lo" -v h="$hi" 'BEGIN{exit !(m>=l && m<=h)}'; then
        note "ok" "control $CONTROL_MODE/$CONTROL_SCENARIO ${mb} MB/s (expect $lo-$hi)"
    else
        bad "control $CONTROL_MODE/$CONTROL_SCENARIO read ${mb} MB/s, outside $lo-$hi.
       The rig is not in a state to measure. Do not start a session."
    fi
    return $fail
}

case "${1:-}" in
    pre)  shift; cmd_pre "$@" ;;
    post) shift; cmd_post "$@" ;;
    control)   shift; cmd_control "$@" ;;
    calibrate) shift; cmd_control calibrate ;;
    *)    echo "usage: rig_check.sh pre | post <instance> [mbit] | control | calibrate" >&2; exit 64 ;;
esac

if [ "$fail" != 0 ]; then
    echo
    echo "rig_check: $fail failure(s). Do not trust numbers from this run."
    exit 1
fi
exit 0
