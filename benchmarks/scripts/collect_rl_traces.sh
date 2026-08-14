#!/usr/bin/env bash

# Favonius — high-performance file transfer over UDP
# Copyright (c) 2025-2026 Vantino SàRL
# SPDX-License-Identifier: Apache-2.0

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/bench_common.sh"

# Override set -e from bench_common.sh — transfers may fail under netem.
set +e

SIZE_MB="${SIZE_MB:-256}"
RUNS="${RUNS:-3}"
LISTEN_ADDR="127.0.0.1"
CONTROL_PORT=7801
DATA_PORT=7802
API_PORT=7800
TRANSFER_TIMEOUT=180

TRACE_DIR="${FAVONIUS_RL_TRACE_DIR:-$HOME/.config/favonius/rl_traces}"
mkdir -p "$TRACE_DIR"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --size) SIZE_MB="$2"; shift 2 ;;
        --runs) RUNS="$2"; shift 2 ;;
        *) echo "Unknown: $1"; exit 1 ;;
    esac
done

DATA_BYTES=$((SIZE_MB * 1048576))

if [ "$(id -u)" != "0" ]; then
    echo "ERROR: requires root for tc netem."
    exit 1
fi

ensure_dirs || true
check_favonius || { echo "Build first: cargo build --release"; exit 1; }

# Diverse scenarios: name|delay|jitter|loss
SCENARIOS=(
    "lan|0|0|0"
    "lan-lossy|0|0|0.5"
    "metro|5|1|0.1"
    "metro-lossy|5|2|1"
    "wan|25|5|0.5"
    "wan-lossy|25|10|2"
    "transatlantic|50|10|1"
    "satellite|150|25|2"
    "degraded|100|25|5"
)

trap 'tc qdisc del dev lo root 2>/dev/null; pkill -f favonius-daemon 2>/dev/null' EXIT

# Generate test data
TEST_FILE="$SRC_DIR/rl_collect_${SIZE_MB}mb.bin"
if [ ! -f "$TEST_FILE" ]; then
    log_info "Generating ${SIZE_MB}MB test file..."
    dd if=/dev/urandom of="$TEST_FILE" bs=1M count="$SIZE_MB" 2>/dev/null
fi

# Count existing traces
EXISTING=$(ls "$TRACE_DIR"/*.jsonl 2>/dev/null | wc -l)
log_info "Existing traces: $EXISTING in $TRACE_DIR"

TOTAL=$((${#SCENARIOS[@]} * RUNS))
CURRENT=0

log_header "RL TRACE COLLECTION: ${SIZE_MB}MB, ${RUNS} runs x ${#SCENARIOS[@]} scenarios = $TOTAL transfers"

for scenario_str in "${SCENARIOS[@]}"; do
    IFS='|' read -r scenario delay jitter loss <<< "$scenario_str"
    log_header "SCENARIO: $scenario (delay=${delay}ms jitter=${jitter}ms loss=${loss}%)"

    # Apply netem
    tc qdisc del dev lo root 2>/dev/null || true
    if [ "$delay" != "0" ] || [ "$loss" != "0" ]; then
        if [ "$jitter" = "0" ]; then
            tc qdisc add dev lo root netem delay "${delay}ms" loss "${loss}%"
        else
            tc qdisc add dev lo root netem delay "${delay}ms" "${jitter}ms" loss "${loss}%"
        fi
    fi

    for run in $(seq 1 "$RUNS"); do
        CURRENT=$((CURRENT + 1))
        log_info "[$CURRENT/$TOTAL] $scenario run $run"

        # Restart daemon
        pkill -f favonius-daemon 2>/dev/null || true
        sleep 0.5
        "$FAVONIUS_DAEMON_BIN" \
            --listen "$LISTEN_ADDR:$API_PORT" \
            --protocol-listen "$LISTEN_ADDR:$CONTROL_PORT" \
            --data-listen "$LISTEN_ADDR:$DATA_PORT" \
            --log-level warn &
        DAEMON_PID=$!
        sleep 1

        clean_dst
        DEST_FILE="$DST_DIR/recv.bin"

        # Run with RL explore mode
        FAVONIUS_RL_EXPLORE=1 \
        FAVONIUS_RL_EPSILON=0.15 \
        FAVONIUS_RL_TRACE_DIR="$TRACE_DIR" \
            timeout "$TRANSFER_TIMEOUT" \
            "$FAVONIUS_BIN" send "$TEST_FILE" \
            "$LISTEN_ADDR:$CONTROL_PORT:$DEST_FILE" \
            --congestion rl \
            --compression none \
            --streams 4 \
            --log-level warn 2>&1 || true

        kill "$DAEMON_PID" 2>/dev/null || true
        wait "$DAEMON_PID" 2>/dev/null || true

        # Check result
        if [ -f "$DEST_FILE" ]; then
            recv=$(stat -c%s "$DEST_FILE" 2>/dev/null || echo 0)
            [ "$recv" -eq "$DATA_BYTES" ] && status="OK" || status="PARTIAL"
        else
            status="FAIL"
        fi
        log_ok "$scenario run $run: $status"
    done
done

# Cleanup
tc qdisc del dev lo root 2>/dev/null || true

# Count new traces
NEW_TRACES=$(ls "$TRACE_DIR"/*.jsonl 2>/dev/null | wc -l)
COLLECTED=$((NEW_TRACES - EXISTING))

log_header "COLLECTION COMPLETE"
log_ok "New traces: $COLLECTED"
log_ok "Total traces: $NEW_TRACES in $TRACE_DIR"

# Summary stats
TOTAL_RECORDS=$(cat "$TRACE_DIR"/*.jsonl 2>/dev/null | wc -l)
log_ok "Total training records: $TOTAL_RECORDS"
log_info "Train with: cd training && ./venv/bin/python train_rl.py --traces $TRACE_DIR --timesteps 200000"
