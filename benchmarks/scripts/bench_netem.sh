#!/usr/bin/env bash

# Favonius — high-performance file transfer over UDP
# Copyright (c) 2025-2026 Vantino SàRL
# SPDX-License-Identifier: Apache-2.0

# benchmarks/scripts/bench_netem.sh
#
# Benchmark Favonius congestion control algorithms and UDT under simulated
# WAN conditions using tc netem on the loopback interface.
#
# Usage:
#   sudo ./benchmarks/scripts/bench_netem.sh [--size SIZE_MB] [--runs N]
#
# Requires: root (for tc netem), favonius + daemon built in release mode.

set -uo pipefail
# Note: NOT using set -e because transfer commands may fail (timeout, loss, etc.)

# Always clean up netem on exit
trap 'tc qdisc del dev lo root 2>/dev/null; pkill -f favonius-daemon 2>/dev/null; pkill -f recvfile 2>/dev/null' EXIT

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/bench_common.sh"

# ── Configuration ───────────────────────────────────────────────────────────

SIZE_MB="${SIZE_MB:-256}"
RUNS="${RUNS:-1}"
LISTEN_ADDR="127.0.0.1"
CONTROL_PORT=7801
DATA_PORT=7802
API_PORT=7800

# Parse CLI args
while [[ $# -gt 0 ]]; do
    case "$1" in
        --size) SIZE_MB="$2"; shift 2 ;;
        --runs) RUNS="$2"; shift 2 ;;
        *) echo "Unknown arg: $1"; exit 1 ;;
    esac
done

DATA_BYTES=$((SIZE_MB * 1048576))

# CC algorithms to test
CC_PROFILES=( classic model fair udt rl )

# Per-transfer timeout in seconds (skip if stuck).
TRANSFER_TIMEOUT=120

# Network scenarios: name, delay, jitter, loss%
# NOTE: netem on loopback applies delay BOTH directions, so effective RTT = 2x delay.
# Values below are one-way delays; actual RTT is double.
# Format: "name|delay_ms|jitter_ms|loss_pct"
SCENARIOS=(
    "baseline|0|0|0"
    "metro|5|1|0.1"
    "cross-country|25|5|0.5"
    "transatlantic|50|10|1"
    "satellite|150|25|2"
    "degraded|100|25|5"
)

# ── Preflight checks ───────────────────────────────────────────────────────

if [ "$(id -u)" != "0" ]; then
    echo "ERROR: This script requires root for tc netem. Run with sudo."
    exit 1
fi

ensure_dirs
check_favonius || { echo "Build first: cargo build --release"; exit 1; }

# Check UDT availability
HAS_UDT=0
if check_udt 2>/dev/null; then HAS_UDT=1; fi

# ── Generate test data ──────────────────────────────────────────────────────

TEST_FILE="$SRC_DIR/netem_${SIZE_MB}mb.bin"
if [ ! -f "$TEST_FILE" ]; then
    log_info "Generating ${SIZE_MB}MB test file..."
    dd if=/dev/urandom of="$TEST_FILE" bs=1M count="$SIZE_MB" 2>/dev/null
fi
log_ok "Test file: $TEST_FILE ($(du -h "$TEST_FILE" | cut -f1))"

# ── Helper functions ────────────────────────────────────────────────────────

apply_netem() {
    local delay="$1" jitter="$2" loss="$3"
    # Remove any existing qdisc
    tc qdisc del dev lo root 2>/dev/null || true

    if [ "$delay" = "0" ] && [ "$loss" = "0" ]; then
        return  # baseline: no shaping
    fi

    if [ "$jitter" = "0" ]; then
        tc qdisc add dev lo root netem delay "${delay}ms" loss "${loss}%"
    else
        tc qdisc add dev lo root netem delay "${delay}ms" "${jitter}ms" loss "${loss}%"
    fi
}

clear_netem() {
    tc qdisc del dev lo root 2>/dev/null || true
}

start_daemon() {
    # Kill any existing daemon
    pkill -f "favonius-daemon" 2>/dev/null || true
    sleep 0.5
    "$FAVONIUS_DAEMON_BIN" \
        --listen "$LISTEN_ADDR:$API_PORT" \
        --protocol-listen "$LISTEN_ADDR:$CONTROL_PORT" \
        --data-listen "$LISTEN_ADDR:$DATA_PORT" \
        --log-level warn &
    DAEMON_PID=$!
    sleep 1
}

stop_daemon() {
    kill "$DAEMON_PID" 2>/dev/null || true
    wait "$DAEMON_PID" 2>/dev/null || true
}

start_udt_recv() {
    # Kill any existing UDT receiver
    pkill -f "recvfile" 2>/dev/null || true
    sleep 0.3
    local recv_port=9001
    "$UDT_RECVFILE" "$recv_port" > /dev/null 2>&1 &
    UDT_RECV_PID=$!
    sleep 0.5
}

stop_udt_recv() {
    kill "$UDT_RECV_PID" 2>/dev/null || true
    wait "$UDT_RECV_PID" 2>/dev/null || true
}

# ── Results CSV ─────────────────────────────────────────────────────────────

CSV_FILE="$RESULTS_DIR/netem_results.csv"
echo "scenario,delay_ms,jitter_ms,loss_pct,transport,cc_profile,run,elapsed_ms,throughput_mbps" > "$CSV_FILE"

append_csv() {
    local scenario="$1" delay="$2" jitter="$3" loss="$4" transport="$5" cc="$6" run="$7" ms="$8"
    local mbps
    if [ "$ms" -gt 0 ]; then
        mbps=$(awk "BEGIN { printf \"%.2f\", ($DATA_BYTES / 1048576) / ($ms / 1000) }")
    else
        mbps="0"
    fi
    echo "$scenario,$delay,$jitter,$loss,$transport,$cc,$run,$ms,$mbps" >> "$CSV_FILE"
}

# ── Main benchmark loop ─────────────────────────────────────────────────────

# Clear old results
rm -f "$RESULTS_DIR"/netem-*.log "$RESULTS_DIR"/netem-*.log.stdout

TOTAL_TESTS=$(( ${#SCENARIOS[@]} * (${#CC_PROFILES[@]} + HAS_UDT) * RUNS ))
CURRENT=0

log_header "NETEM BENCHMARK: ${SIZE_MB}MB, ${RUNS} run(s), ${#SCENARIOS[@]} scenarios, ${#CC_PROFILES[@]} CC + UDT"

for scenario_str in "${SCENARIOS[@]}"; do
    IFS='|' read -r scenario delay jitter loss <<< "$scenario_str"

    log_header "SCENARIO: $scenario (delay=${delay}ms jitter=${jitter}ms loss=${loss}%)"

    apply_netem "$delay" "$jitter" "$loss"

    # ── Favonius CC algorithms ────────────────────────────────────────────
    for cc in "${CC_PROFILES[@]}"; do
        for run in $(seq 1 "$RUNS"); do
            CURRENT=$((CURRENT + 1))
            label="netem-${scenario}-ahp-${cc}-run${run}"
            log_info "[$CURRENT/$TOTAL_TESTS] $label"

            start_daemon
            clean_dst

            DEST_FILE="$DST_DIR/recv.bin"
            start_ns=$(date +%s%N)

            exit_code=0
            FAVONIUS_RL_MODEL="${FAVONIUS_RL_MODEL:-$HOME/.config/favonius/rl_weights.bin}" \
            timeout "$TRANSFER_TIMEOUT" \
                "$FAVONIUS_BIN" send "$TEST_FILE" \
                "$LISTEN_ADDR:$CONTROL_PORT:$DEST_FILE" \
                --congestion "$cc" \
                --compression none \
                --streams 4 \
                --log-level warn \
                > "$RESULTS_DIR/${label}.log.stdout" 2>&1 || exit_code=$?

            end_ns=$(date +%s%N)
            elapsed_ms=$(( (end_ns - start_ns) / 1000000 ))

            # If timeout killed it, mark as timeout
            if [ "$exit_code" = "124" ]; then
                elapsed_ms=0
            fi

            stop_daemon

            # Verify transfer
            if [ "$exit_code" = "124" ]; then
                status="TIMEOUT(${TRANSFER_TIMEOUT}s)"
            elif [ -f "$DEST_FILE" ]; then
                recv_size=$(stat -c%s "$DEST_FILE" 2>/dev/null || echo 0)
                if [ "$recv_size" -eq "$DATA_BYTES" ]; then
                    status="OK"
                else
                    status="INCOMPLETE($recv_size)"
                fi
            else
                status="MISSING"
                elapsed_ms=0
            fi

            if [ "$elapsed_ms" -gt 0 ]; then
                mbps=$(awk "BEGIN { printf \"%.1f\", ($DATA_BYTES / 1048576) / ($elapsed_ms / 1000) }")
            else
                mbps="0"
            fi

            append_csv "$scenario" "$delay" "$jitter" "$loss" "ahp" "$cc" "$run" "$elapsed_ms"
            log_ok "$label  =>  ${elapsed_ms}ms  ${mbps} MB/s  [$status]"
        done
    done

    # ── UDT baseline ─────────────────────────────────────────────────────
    if [ "$HAS_UDT" = "1" ]; then
        for run in $(seq 1 "$RUNS"); do
            CURRENT=$((CURRENT + 1))
            label="netem-${scenario}-udt-run${run}"
            log_info "[$CURRENT/$TOTAL_TESTS] $label"

            start_udt_recv
            clean_dst

            start_ns=$(date +%s%N)

            timeout "$TRANSFER_TIMEOUT" \
                "$UDT_SENDFILE" "$LISTEN_ADDR" 9001 "$TEST_FILE" \
                > "$RESULTS_DIR/${label}.log.stdout" 2>&1 || true

            end_ns=$(date +%s%N)
            elapsed_ms=$(( (end_ns - start_ns) / 1000000 ))

            stop_udt_recv

            if [ "$elapsed_ms" -gt 0 ]; then
                mbps=$(awk "BEGIN { printf \"%.1f\", ($DATA_BYTES / 1048576) / ($elapsed_ms / 1000) }")
            else
                mbps="0"
            fi

            append_csv "$scenario" "$delay" "$jitter" "$loss" "udt" "udt" "$run" "$elapsed_ms"
            log_ok "$label  =>  ${elapsed_ms}ms  ${mbps} MB/s"
        done
    fi

    clear_netem
done

# ── Print results ───────────────────────────────────────────────────────────

log_header "RESULTS SUMMARY"
echo ""
printf "${BOLD}%-20s %-10s %-12s %10s %12s${RESET}\n" \
    "SCENARIO" "TRANSPORT" "CC" "TIME (ms)" "THROUGHPUT"
printf "%s\n" "$(printf '─%.0s' {1..68})"

while IFS=, read -r scenario delay jitter loss transport cc run ms mbps; do
    [ "$scenario" = "scenario" ] && continue  # skip header
    printf "%-20s %-10s %-12s %10s %10s MB/s\n" \
        "$scenario" "$transport" "$cc" "$ms" "$mbps"
done < "$CSV_FILE"

echo ""
log_info "CSV results: $CSV_FILE"
log_info "Detailed logs: $RESULTS_DIR/netem-*.log.stdout"

# ── Best algorithm per scenario ─────────────────────────────────────────────

echo ""
log_header "BEST ALGORITHM PER SCENARIO"
python3 -c "
import csv, sys
from collections import defaultdict

results = defaultdict(list)
with open('$CSV_FILE') as f:
    for row in csv.DictReader(f):
        ms = int(row['elapsed_ms'])
        if ms > 0:
            results[row['scenario']].append((float(row['throughput_mbps']), row['transport'], row['cc_profile']))

for scenario in sorted(results.keys()):
    entries = sorted(results[scenario], reverse=True)
    if entries:
        best = entries[0]
        print(f'  {scenario:20s}  best: {best[1]}/{best[2]:8s}  {best[0]:.1f} MB/s')
        for e in entries[1:]:
            pct = (e[0] / best[0] * 100) if best[0] > 0 else 0
            print(f'  {\"\":20s}        {e[1]}/{e[2]:8s}  {e[0]:.1f} MB/s  ({pct:.0f}%)')
" 2>/dev/null || true

echo ""
log_ok "Benchmark complete. Netem cleaned up."
