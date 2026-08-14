#!/usr/bin/env bash

# Favonius — high-performance file transfer over UDP
# Copyright (c) 2025-2026 Vantino SàRL
# SPDX-License-Identifier: Apache-2.0

# benchmarks/scripts/train_policy.sh
# Train the adaptive policy engine by running Favonius transfers with
# --adaptive enabled.  The hill-climbing optimizer explores parameter
# combinations and converges on the best set for the current link.
#
# Usage: ./train_policy.sh --remote USER@HOST [--size SIZE_MB] [--iterations N]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/bench_common.sh"

# ── Options ──────────────────────────────────────────────────────────────────
SIZE_MB=256
ITERATIONS=30
REMOTE=""
REMOTE_DIR="/tmp/favonius-bench-dst"
POLICY_PATH="${HOME}/.config/favonius/policy.json"
FRESH=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        --remote)         REMOTE="$2"; shift 2 ;;
        --size)           SIZE_MB="$2"; shift 2 ;;
        --iterations)     ITERATIONS="$2"; shift 2 ;;
        --remote-dir)     REMOTE_DIR="$2"; shift 2 ;;
        --policy-path)    POLICY_PATH="$2"; shift 2 ;;
        --fresh)          FRESH=true; shift ;;
        -h|--help)
            echo "Usage: $0 --remote USER@HOST [OPTIONS]"
            echo
            echo "Train the adaptive policy engine over a real network link."
            echo
            echo "Options:"
            echo "  --remote USER@HOST   Remote machine (required)"
            echo "  --size SIZE_MB       File size in MB (default: 256)"
            echo "  --iterations N       Training iterations (default: 30)"
            echo "  --remote-dir DIR     Destination on remote (default: /tmp/favonius-bench-dst)"
            echo "  --policy-path PATH   Policy JSON file (default: ~/.config/favonius/policy.json)"
            echo "  --fresh              Clear existing policy data before training"
            exit 0
            ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

if [ -z "$REMOTE" ]; then
    echo "Error: --remote USER@HOST is required"
    exit 1
fi

DATA_BYTES=$(( SIZE_MB * 1048576 ))
LARGE_FILE="$SRC_DIR/large_${SIZE_MB}mb.bin"

# ── Setup ────────────────────────────────────────────────────────────────────
log_header "Adaptive Policy Training (${SIZE_MB} MB, ${ITERATIONS} iterations)"

ensure_dirs

# Generate test data
"$SCRIPT_DIR/generate_data.sh" --size "$SIZE_MB" --large-only

if [ ! -f "$LARGE_FILE" ]; then
    log_error "Test file not found: $LARGE_FILE"
    exit 1
fi

log_info "File: $LARGE_FILE ($(du -h "$LARGE_FILE" | cut -f1))"
log_info "Iterations: $ITERATIONS"
log_info "Remote: $REMOTE:$REMOTE_DIR"
log_info "Policy: $POLICY_PATH"
echo

# ── Connectivity ─────────────────────────────────────────────────────────────
log_header "Connectivity"

if ! ssh -o BatchMode=yes -o ConnectTimeout=5 "$REMOTE" true 2>/dev/null; then
    log_error "Cannot SSH to $REMOTE (key-based auth required)"
    exit 1
fi
log_ok "SSH to $REMOTE: OK"

REMOTE_UNAME=$(ssh "$REMOTE" "uname -m" 2>/dev/null || echo "unknown")
REMOTE_HOST=$(ssh "$REMOTE" "hostname" 2>/dev/null || echo "unknown")
log_info "Remote: $REMOTE_HOST ($REMOTE_UNAME)"

PING_RTT=$(ping -c 5 -q "$(echo "$REMOTE" | cut -d@ -f2)" 2>/dev/null \
    | grep "rtt" | awk -F'/' '{print $5}') || PING_RTT="?"
log_info "RTT: ${PING_RTT} ms (avg of 5 pings)"
echo

# ── Check Favonius ────────────────────────────────────────────────────────────
log_header "Checking Favonius"

FAVONIUS_CLI="$SCRIPT_DIR/../../target/release/favonius"
if [ ! -x "$FAVONIUS_CLI" ]; then
    log_error "Favonius CLI not built: $FAVONIUS_CLI"
    log_error "  Run: cargo build --release -p ahp-cli"
    exit 1
fi
log_ok "CLI: $FAVONIUS_CLI"

if ! ssh "$REMOTE" "test -x /tmp/favonius-bench/favonius-daemon" 2>/dev/null; then
    log_error "Favonius daemon not deployed on remote"
    log_error "  Deploy: scp target/<arch>/release/favonius-daemon $REMOTE:/tmp/favonius-bench/"
    exit 1
fi
log_ok "Daemon on remote: /tmp/favonius-bench/favonius-daemon"
echo

# ── Prepare ──────────────────────────────────────────────────────────────────
ssh "$REMOTE" "mkdir -p '$REMOTE_DIR'" 2>/dev/null

clean_remote_dst() {
    ssh "$REMOTE" "rm -f '$REMOTE_DIR'/*" 2>/dev/null
    sync
}

if $FRESH; then
    rm -f "$POLICY_PATH"
    log_info "Cleared existing policy data"
fi

EXISTING_RECORDS=0
if [ -f "$POLICY_PATH" ]; then
    EXISTING_RECORDS=$(python3 -c "import json; print(len(json.load(open('$POLICY_PATH'))))" 2>/dev/null || echo 0)
    log_info "Existing policy records: $EXISTING_RECORDS"
fi

# ── Start daemon ─────────────────────────────────────────────────────────────
REMOTE_HOST_ADDR=$(echo "$REMOTE" | cut -d@ -f2)
AHP_PORT=7801

ssh "$REMOTE" "pkill -f favonius-daemon 2>/dev/null" || true
sleep 0.3
ssh "$REMOTE" "nohup /tmp/favonius-bench/favonius-daemon \
    --protocol-listen 0.0.0.0:$AHP_PORT \
    --log-level warn \
    > /tmp/favonius-daemon.log 2>&1 & disown" </dev/null
sleep 2
log_ok "Daemon started on $REMOTE_HOST_ADDR:$AHP_PORT"
echo

# ── Training loop ────────────────────────────────────────────────────────────
log_header "Training: $ITERATIONS iterations"

SUCCESSES=0
FAILURES=0

for i in $(seq 1 "$ITERATIONS"); do
    clean_remote_dst
    sleep 0.3

    printf "${CYAN}[%2d/%d]${RESET} " "$i" "$ITERATIONS"

    OUTPUT=$("$FAVONIUS_CLI" send "$LARGE_FILE" \
        "${REMOTE_HOST_ADDR}:${AHP_PORT}:${REMOTE_DIR}/large_${SIZE_MB}mb.bin" \
        --adaptive \
        --policy-path "$POLICY_PATH" \
        --log-level warn \
        2>&1) || true

    # Extract the "Transfer complete" line (stdout) and adaptive params (stderr)
    TRANSFER_LINE=$(echo "$OUTPUT" | grep "Transfer complete" || true)
    ADAPTIVE_LINE=$(echo "$OUTPUT" | grep "adaptive:" || true)

    if [ -n "$TRANSFER_LINE" ]; then
        SUCCESSES=$((SUCCESSES + 1))
        # Extract throughput for a compact summary
        THROUGHPUT=$(echo "$TRANSFER_LINE" | grep -oP '[\d.]+ Mi?B/s' || echo "?")
        RETX=$(echo "$TRANSFER_LINE" | grep -oP '\d+ retx' || echo "?")
        echo "$THROUGHPUT, $RETX"
        if [ -n "$ADAPTIVE_LINE" ]; then
            echo "       $ADAPTIVE_LINE"
        fi
    else
        FAILURES=$((FAILURES + 1))
        echo -e "${RED}FAILED${RESET} (handshake timeout?)"

        # Restart daemon after failure
        ssh "$REMOTE" "pkill -f favonius-daemon 2>/dev/null" || true
        sleep 0.5
        ssh "$REMOTE" "nohup /tmp/favonius-bench/favonius-daemon \
            --protocol-listen 0.0.0.0:$AHP_PORT \
            --log-level warn \
            > /tmp/favonius-daemon.log 2>&1 & disown" </dev/null
        sleep 2
    fi
done

echo
log_info "Completed: $SUCCESSES successful, $FAILURES failed"

# ── Stop daemon ──────────────────────────────────────────────────────────────
ssh "$REMOTE" "pkill -f favonius-daemon 2>/dev/null" || true

# ── Display results ──────────────────────────────────────────────────────────
echo
log_header "Training Results"

if [ ! -f "$POLICY_PATH" ]; then
    log_error "No policy file found at $POLICY_PATH"
    exit 1
fi

TOTAL_RECORDS=$(python3 -c "import json; print(len(json.load(open('$POLICY_PATH'))))" 2>/dev/null || echo "?")
log_info "Total records: $TOTAL_RECORDS (was $EXISTING_RECORDS before training)"
echo

python3 -c "
import json, sys

records = json.load(open('$POLICY_PATH'))
if not records:
    print('No records found.')
    sys.exit(0)

# Best overall
best = max(records, key=lambda r: r.get('score', 0))

# Top 5 unique parameter sets by score
seen = set()
top = []
for r in sorted(records, key=lambda r: -r.get('score', 0)):
    p = r['params']
    key = (p.get('cc_profile','?'), p.get('ack_mode','?'), p.get('payload_size',0),
           p.get('socket_buf_kb',0), p['min_cwnd_kb'], p['batch_size'],
           p['retx_timeout_ms'], p['progress_ack_interval_ms'])
    if key not in seen:
        seen.add(key)
        top.append(r)
    if len(top) >= 5:
        break

print('Top parameter sets by score:')
print()
print(f'{\"RANK\":<5} {\"CC\":>8} {\"ACK\":>7} {\"PAYLOAD\":>8} {\"SOCK\":>6} {\"CWND\":>6} {\"BATCH\":>6} {\"RETX\":>6} {\"ACK_INT\":>8}  {\"THRU\":>10} {\"RETX%\":>7} {\"SCORE\":>10}')
print('-' * 100)

for rank, r in enumerate(top, 1):
    p = r['params']
    thru_mbs = r['throughput'] / (1024*1024)
    score_mbs = r['score'] / (1024*1024)
    print(f'{rank:<5} {p.get(\"cc_profile\",\"?\"):>8} {p.get(\"ack_mode\",\"?\"):>7} {p.get(\"payload_size\",1350):>7}B {p.get(\"socket_buf_kb\",208):>5}K {p[\"min_cwnd_kb\"]:>5}K {p[\"batch_size\"]:>5} {p[\"retx_timeout_ms\"]:>5}ms {p[\"progress_ack_interval_ms\"]:>6}ms  {thru_mbs:>8.1f} MB/s {r[\"retx_ratio\"]*100:>6.2f}% {score_mbs:>8.1f} MB/s')

print()
print('Best parameter set:')
bp = best['params']
print(f'  cc_profile:             {bp.get(\"cc_profile\", \"classic\")}')
print(f'  ack_mode:               {bp.get(\"ack_mode\", \"bitmap\")}')
print(f'  payload_size:           {bp.get(\"payload_size\", 1350)} bytes')
print(f'  socket_buf_kb:          {bp.get(\"socket_buf_kb\", 208)} KB')
print(f'  min_cwnd_kb:            {bp[\"min_cwnd_kb\"]} KB')
print(f'  batch_size:             {bp[\"batch_size\"]}')
print(f'  retx_timeout_ms:        {bp[\"retx_timeout_ms\"]} ms')
print(f'  progress_ack_interval:  {bp[\"progress_ack_interval_ms\"]} ms')
print(f'  ---')
print(f'  throughput:             {best[\"throughput\"]/(1024*1024):.1f} MB/s')
print(f'  retx_ratio:             {best[\"retx_ratio\"]*100:.2f}%')
print(f'  score:                  {best[\"score\"]/(1024*1024):.1f} MB/s')
"

# ── Cleanup ──────────────────────────────────────────────────────────────────
echo
log_header "Cleanup"
ssh "$REMOTE" "rm -rf '$REMOTE_DIR'" 2>/dev/null || true
log_ok "Removed $REMOTE:$REMOTE_DIR"

log_header "Done"
log_info "Policy file: $POLICY_PATH"
