#!/usr/bin/env bash

# Favonius — high-performance file transfer over UDP
# Copyright (c) 2025-2026 Vantino SàRL
# SPDX-License-Identifier: Apache-2.0

# benchmarks/scripts/summarize.sh
# Parse benchmark results and produce a comparison report.
#
# Usage: ./summarize.sh [RESULTS_DIR]

set -euo pipefail

RESULTS_DIR="${1:-/tmp/favonius-bench/results}"

if [ ! -d "$RESULTS_DIR" ] || [ -z "$(ls "$RESULTS_DIR"/*.log 2>/dev/null)" ]; then
    echo "No results found in $RESULTS_DIR"
    echo "Run a benchmark first: ./bench_quick.sh or ./bench_loopback_large.sh"
    exit 1
fi

# ── Parse all results into arrays ────────────────────────────────────────────
declare -A LABELS TIMES CPU RSS

for logfile in "$RESULTS_DIR"/*.log; do
    [[ "$logfile" == *.stdout ]] && continue
    [ -f "$logfile" ] || continue

    label=$(grep "^label=" "$logfile" 2>/dev/null | cut -d= -f2) || continue
    [ -z "$label" ] && continue

    elapsed_ms=$(grep "^elapsed_ms=" "$logfile" | cut -d= -f2)
    wall=$(grep "^wall_clock=" "$logfile" | cut -d= -f2)
    cpu_pct=$(grep "^cpu_percent=" "$logfile" | cut -d= -f2)
    rss_kb=$(grep "^peak_rss_kb=" "$logfile" | cut -d= -f2)

    LABELS[$label]=1
    TIMES[$label]="${elapsed_ms:-0}"
    CPU[$label]="${cpu_pct:-?}"
    RSS[$label]="${rss_kb:-?}"
done

if [ ${#LABELS[@]} -eq 0 ]; then
    echo "No benchmark results found."
    exit 1
fi

# ── Group by tool (strip -runN suffix) ───────────────────────────────────────
declare -A TOOL_TIMES  # tool -> "ms1 ms2 ms3"

for label in "${!LABELS[@]}"; do
    # Strip -run1, -run2, etc.
    tool=$(echo "$label" | sed 's/-run[0-9]*$//')
    TOOL_TIMES[$tool]="${TOOL_TIMES[$tool]:-} ${TIMES[$label]}"
done

# ── Compute median ───────────────────────────────────────────────────────────
median() {
    echo "$@" | tr ' ' '\n' | sort -n | awk '{
        a[NR] = $1
    } END {
        if (NR % 2 == 1) print a[(NR+1)/2]
        else print (a[NR/2] + a[NR/2+1]) / 2
    }'
}

# ── Print report ─────────────────────────────────────────────────────────────
echo
echo "┌──────────────────────────────────────────────────────────────────────────┐"
echo "│                     FAVONIUS BENCHMARK REPORT                            │"
echo "├──────────────────────────────────────────────────────────────────────────┤"
printf "│  %-70s │\n" "Date: $(date '+%Y-%m-%d %H:%M:%S')"
printf "│  %-70s │\n" "Host: $(hostname) ($(uname -m))"
printf "│  %-70s │\n" "Kernel: $(uname -r)"

# CPU info
if [ -f /proc/cpuinfo ]; then
    cpu_model=$(grep "model name" /proc/cpuinfo | head -1 | cut -d: -f2 | xargs)
    cpu_cores=$(nproc)
    printf "│  %-70s │\n" "CPU: $cpu_model ($cpu_cores cores)"
fi

# Memory info
if [ -f /proc/meminfo ]; then
    total_mem=$(grep MemTotal /proc/meminfo | awk '{printf "%.0f GB", $2/1048576}')
    printf "│  %-70s │\n" "RAM: $total_mem"
fi

echo "└──────────────────────────────────────────────────────────────────────────┘"
echo

# ── All individual runs ──────────────────────────────────────────────────────
echo "INDIVIDUAL RUNS"
echo "━━━━━━━━━━━━━━━"
printf "%-42s %10s %10s %10s\n" "LABEL" "TIME (ms)" "CPU (%)" "RSS (KB)"
printf "%s\n" "$(printf '─%.0s' {1..74})"

for label in $(echo "${!LABELS[@]}" | tr ' ' '\n' | sort); do
    printf "%-42s %10s %10s %10s\n" \
        "$label" "${TIMES[$label]}" "${CPU[$label]}" "${RSS[$label]}"
done

echo

# ── Median summary by tool ───────────────────────────────────────────────────
echo "MEDIAN SUMMARY (across runs)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
printf "%-42s %10s %8s\n" "TOOL" "MEDIAN (ms)" "RUNS"
printf "%s\n" "$(printf '─%.0s' {1..62})"

# Sort tools by median time
declare -A TOOL_MEDIANS
for tool in "${!TOOL_TIMES[@]}"; do
    med=$(median ${TOOL_TIMES[$tool]})
    TOOL_MEDIANS[$tool]="$med"
done

# Print sorted by median
for tool in $(for t in "${!TOOL_MEDIANS[@]}"; do echo "$t ${TOOL_MEDIANS[$t]}"; done | sort -k2 -n | awk '{print $1}'); do
    times="${TOOL_TIMES[$tool]}"
    n_runs=$(echo "$times" | wc -w)
    med="${TOOL_MEDIANS[$tool]}"
    printf "%-42s %10.0f %8d\n" "$tool" "$med" "$n_runs"
done

echo

# ── Relative comparison ──────────────────────────────────────────────────────
# Find the fastest tool
fastest_time=999999999
fastest_tool=""
for tool in "${!TOOL_MEDIANS[@]}"; do
    med="${TOOL_MEDIANS[$tool]}"
    if awk "BEGIN {exit !($med < $fastest_time)}" 2>/dev/null; then
        fastest_time="$med"
        fastest_tool="$tool"
    fi
done

if [ -n "$fastest_tool" ] && [ "$fastest_time" != "0" ]; then
    echo "RELATIVE PERFORMANCE (1.0x = fastest)"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    printf "%-42s %10s\n" "TOOL" "SLOWDOWN"
    printf "%s\n" "$(printf '─%.0s' {1..54})"

    for tool in $(for t in "${!TOOL_MEDIANS[@]}"; do echo "$t ${TOOL_MEDIANS[$t]}"; done | sort -k2 -n | awk '{print $1}'); do
        med="${TOOL_MEDIANS[$tool]}"
        ratio=$(awk "BEGIN { printf \"%.2f\", $med / $fastest_time }")
        bar_len=$(awk "BEGIN { printf \"%.0f\", $ratio * 20 }")
        bar=$(printf '█%.0s' $(seq 1 "$bar_len"))
        printf "%-42s %7sx  %s\n" "$tool" "$ratio" "$bar"
    done

    echo
    echo "Fastest: $fastest_tool (median ${fastest_time} ms)"
fi

echo
echo "Raw logs: $RESULTS_DIR/"
