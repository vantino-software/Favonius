#!/usr/bin/env bash

# Favonius — high-performance file transfer over UDP
# Copyright (c) 2025-2026 Vantino SàRL
# SPDX-License-Identifier: Apache-2.0

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/bench_common.sh"

# ── Configuration ───────────────────────────────────────────────────────────

SIZE_MB="${SIZE_MB:-128}"
RUNS="${RUNS:-1}"
# Stall detector in favonius aborts after 30s of no progress.
# This timeout is a safety net — should rarely be hit now.
TRANSFER_TIMEOUT=180

# Namespace network config
NS_NAME="favonius-bench"
VETH_HOST="veth-host"
VETH_NS="veth-ns"
HOST_IP="10.99.0.1"
NS_IP="10.99.0.2"
CONTROL_PORT=7801
DATA_PORT=7802
API_PORT=7800

while [[ $# -gt 0 ]]; do
    case "$1" in
        --size) SIZE_MB="$2"; shift 2 ;;
        --runs) RUNS="$2"; shift 2 ;;
        *) echo "Unknown arg: $1"; exit 1 ;;
    esac
done

DATA_BYTES=$((SIZE_MB * 1048576))

CC_PROFILES=( classic model udt rl )

# Pacing modes to test. "batch" = GSO (default), "iouring" = io_uring SQE batching.
PACING_MODES=( batch iouring )

# Scenarios: name|delay_ms|jitter_ms|loss_pct
# These are ONE-WAY delays applied on the veth (not doubled like loopback).
SCENARIOS=(
    "baseline|0|0|0"
    "metro|5|1|0.1"
    "cross-country|25|5|0.5"
    "transatlantic|50|10|1"
    "satellite|150|25|2"
    "degraded|100|25|5"
)

# ── Preflight ───────────────────────────────────────────────────────────────

if [ "$(id -u)" != "0" ]; then
    echo "ERROR: requires root for network namespaces + tc netem."
    exit 1
fi

ensure_dirs
check_favonius || exit 1
HAS_UDT=0
check_udt 2>/dev/null && HAS_UDT=1

# ── Network namespace setup ─────────────────────────────────────────────────

setup_netns() {
    # Clean up any previous run
    teardown_netns 2>/dev/null || true

    # Create namespace
    ip netns add "$NS_NAME"

    # Create veth pair
    ip link add "$VETH_HOST" type veth peer name "$VETH_NS"

    # Move one end into the namespace
    ip link set "$VETH_NS" netns "$NS_NAME"

    # Configure host side
    ip addr add "$HOST_IP/24" dev "$VETH_HOST"
    ip link set "$VETH_HOST" up

    # Configure namespace side
    ip netns exec "$NS_NAME" ip addr add "$NS_IP/24" dev "$VETH_NS"
    ip netns exec "$NS_NAME" ip link set "$VETH_NS" up
    ip netns exec "$NS_NAME" ip link set lo up

    # Verify connectivity
    if ping -c 1 -W 1 "$NS_IP" > /dev/null 2>&1; then
        log_ok "network namespace ready: $HOST_IP <-> $NS_IP"
    else
        log_error "namespace connectivity failed"
        exit 1
    fi
}

teardown_netns() {
    ip netns del "$NS_NAME" 2>/dev/null || true
    ip link del "$VETH_HOST" 2>/dev/null || true
}

apply_netem_veth() {
    local delay="$1" jitter="$2" loss="$3"
    # Remove existing qdisc
    tc qdisc del dev "$VETH_HOST" root 2>/dev/null || true

    if [ "$delay" = "0" ] && [ "$loss" = "0" ]; then
        return
    fi

    if [ "$jitter" = "0" ]; then
        tc qdisc add dev "$VETH_HOST" root netem delay "${delay}ms" loss "${loss}%"
    else
        tc qdisc add dev "$VETH_HOST" root netem delay "${delay}ms" "${jitter}ms" loss "${loss}%"
    fi
}

clear_netem_veth() {
    tc qdisc del dev "$VETH_HOST" root 2>/dev/null || true
}

# Cleanup on exit
trap 'teardown_netns 2>/dev/null; pkill -f favonius-daemon 2>/dev/null; pkill -f recvfile 2>/dev/null' EXIT

# ── Helpers ─────────────────────────────────────────────────────────────────

start_daemon_in_ns() {
    # Run daemon inside the namespace (receiver side)
    pkill -f favonius-daemon 2>/dev/null || true
    sleep 0.3
    ip netns exec "$NS_NAME" \
        "$FAVONIUS_DAEMON_BIN" \
        --listen "$NS_IP:$API_PORT" \
        --protocol-listen "$NS_IP:$CONTROL_PORT" \
        --data-listen "$NS_IP:$DATA_PORT" \
        --log-level warn &
    DAEMON_PID=$!
    sleep 1
}

stop_daemon() {
    kill "$DAEMON_PID" 2>/dev/null || true
    wait "$DAEMON_PID" 2>/dev/null || true
}

start_udt_recv_in_ns() {
    pkill -f recvfile 2>/dev/null || true
    sleep 0.3
    ip netns exec "$NS_NAME" "$UDT_RECVFILE" 9001 > /dev/null 2>&1 &
    UDT_RECV_PID=$!
    sleep 0.5
}

stop_udt_recv() {
    kill "$UDT_RECV_PID" 2>/dev/null || true
    wait "$UDT_RECV_PID" 2>/dev/null || true
}

# ── Test data ───────────────────────────────────────────────────────────────

TEST_FILE="$SRC_DIR/netem_${SIZE_MB}mb.bin"
if [ ! -f "$TEST_FILE" ]; then
    log_info "Generating ${SIZE_MB}MB test file..."
    dd if=/dev/urandom of="$TEST_FILE" bs=1M count="$SIZE_MB" 2>/dev/null
fi
log_ok "Test file: $TEST_FILE ($(du -h "$TEST_FILE" | cut -f1))"

# ── Results CSV ─────────────────────────────────────────────────────────────

CSV_FILE="$RESULTS_DIR/netem_fair_results.csv"
echo "scenario,delay_ms,jitter_ms,loss_pct,transport,cc_profile,pacing,run,elapsed_ms,throughput_mbps" > "$CSV_FILE"

append_csv() {
    local scenario="$1" delay="$2" jitter="$3" loss="$4" transport="$5" cc="$6" pacing="$7" run="$8" ms="$9"
    local mbps=0
    if [ "$ms" -gt 0 ]; then
        mbps=$(awk "BEGIN { printf \"%.2f\", ($DATA_BYTES / 1048576) / ($ms / 1000) }")
    fi
    echo "$scenario,$delay,$jitter,$loss,$transport,$cc,$pacing,$run,$ms,$mbps" >> "$CSV_FILE"
}

# ── Setup namespace ─────────────────────────────────────────────────────────

setup_netns

# Make test file accessible from namespace (it's on the host filesystem,
# but the daemon in the namespace writes to a path on the host too via bind).
# Actually, namespace shares the filesystem — only the network is isolated.

# ── Main benchmark loop ─────────────────────────────────────────────────────

rm -f "$RESULTS_DIR"/netem-fair-*.log "$RESULTS_DIR"/netem-fair-*.log.stdout

TOTAL_TESTS=$(( ${#SCENARIOS[@]} * ${#CC_PROFILES[@]} * ${#PACING_MODES[@]} * RUNS ))
CURRENT=0

log_header "FAIR NETEM BENCHMARK: ${SIZE_MB}MB, ${RUNS} run(s), ${#SCENARIOS[@]} scenarios, veth namespace"

for scenario_str in "${SCENARIOS[@]}"; do
    IFS='|' read -r scenario delay jitter loss <<< "$scenario_str"

    log_header "SCENARIO: $scenario (delay=${delay}ms jitter=${jitter}ms loss=${loss}%)"
    apply_netem_veth "$delay" "$jitter" "$loss"

    # ── AHP CC algorithms x pacing modes ────────────────────────────────
    for cc in "${CC_PROFILES[@]}"; do
        for pacing in "${PACING_MODES[@]}"; do
            for run in $(seq 1 "$RUNS"); do
                CURRENT=$((CURRENT + 1))
                label="netem-fair-${scenario}-${cc}-${pacing}-run${run}"
                log_info "[$CURRENT/$TOTAL_TESTS] $label"

                start_daemon_in_ns
                clean_dst

                DEST_FILE="$DST_DIR/recv.bin"
                start_ns_ts=$(date +%s%N)

                exit_code=0
                FAVONIUS_RL_MODEL="${FAVONIUS_RL_MODEL:-$HOME/.config/favonius/rl_weights.bin}" \
                timeout "$TRANSFER_TIMEOUT" \
                    "$FAVONIUS_BIN" send "$TEST_FILE" \
                    "$NS_IP:$CONTROL_PORT:$DEST_FILE" \
                    --congestion "$cc" \
                    --pacing "$pacing" \
                    --compression none \
                    --streams 4 \
                    --log-level warn \
                    > "$RESULTS_DIR/${label}.log.stdout" 2>&1 || exit_code=$?

                end_ns_ts=$(date +%s%N)
                elapsed_ms=$(( (end_ns_ts - start_ns_ts) / 1000000 ))

                if [ "$exit_code" = "124" ]; then elapsed_ms=0; fi

                stop_daemon

                if [ "$exit_code" = "124" ]; then
                    status="TIMEOUT"
                elif [ -f "$DEST_FILE" ]; then
                    recv_size=$(stat -c%s "$DEST_FILE" 2>/dev/null || echo 0)
                    [ "$recv_size" -eq "$DATA_BYTES" ] && status="OK" || status="INCOMPLETE"
                else
                    status="MISSING"; elapsed_ms=0
                fi

                mbps=0
                [ "$elapsed_ms" -gt 0 ] && mbps=$(awk "BEGIN { printf \"%.1f\", ($DATA_BYTES / 1048576) / ($elapsed_ms / 1000) }")

                append_csv "$scenario" "$delay" "$jitter" "$loss" "ahp" "$cc" "$pacing" "$run" "$elapsed_ms"
                log_ok "$label  =>  ${elapsed_ms}ms  ${mbps} MB/s  [$status]"
            done
        done
    done

    # NOTE: --transport udt uses raw UDT C++ sendfile/recvfile via SSH,
    # not the Favonius daemon. It cannot be tested fairly under netem.
    # The UDT *algorithm* is already tested as --congestion udt above.

    clear_netem_veth
done

# ── Print results ───────────────────────────────────────────────────────────

log_header "FAIR COMPARISON RESULTS"
echo ""
printf "${BOLD}%-16s %-10s %-10s %10s %12s${RESET}\n" \
    "SCENARIO" "CC" "PACING" "TIME (ms)" "THROUGHPUT"
printf "%s\n" "$(printf '─%.0s' {1..66})"

while IFS=, read -r scenario delay jitter loss transport cc pacing run ms mbps; do
    [ "$scenario" = "scenario" ] && continue
    printf "%-16s %-10s %-10s %10s %10s MB/s\n" \
        "$scenario" "$cc" "$pacing" "$ms" "$mbps"
done < "$CSV_FILE"

# ── GSO vs io_uring comparison table ────────────────────────────────────────

echo ""
log_header "GSO vs io_uring per CC profile"
python3 << PYEOF
import csv
from collections import defaultdict

# row: (scenario, cc) -> {pacing: mbps}
data = defaultdict(dict)
with open('$CSV_FILE') as f:
    for row in csv.DictReader(f):
        ms = int(row['elapsed_ms'])
        mbps = float(row['throughput_mbps']) if ms > 0 else 0.0
        key = (row['scenario'], row['cc_profile'])
        data[key][row['pacing']] = mbps

scenarios = ['baseline','metro','cross-country','transatlantic','satellite','degraded']
ccs = ['classic','model','udt','rl']

print(f"  {'SCENARIO':<16} {'CC':<10} {'GSO (batch)':>14} {'io_uring':>14} {'delta':>8}")
print('  ' + '─' * 66)
for s in scenarios:
    for cc in ccs:
        d = data.get((s, cc), {})
        gso = d.get('batch', 0.0)
        iou = d.get('iouring', 0.0)
        gso_s = f"{gso:.1f} MB/s" if gso > 0 else "TIMEOUT"
        iou_s = f"{iou:.1f} MB/s" if iou > 0 else "TIMEOUT"
        if gso > 0 and iou > 0:
            delta = (iou - gso) / gso * 100
            delta_s = f"{delta:+.0f}%"
        else:
            delta_s = "—"
        print(f"  {s:<16} {cc:<10} {gso_s:>14} {iou_s:>14} {delta_s:>8}")
    print()
PYEOF

echo ""
log_info "CSV: $CSV_FILE"
log_ok "Benchmark complete. Namespace cleaned up."
