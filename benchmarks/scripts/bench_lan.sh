#!/usr/bin/env bash

# Favonius — high-performance file transfer over UDP
# Copyright (c) 2025-2026 Vantino SàRL
# SPDX-License-Identifier: Apache-2.0

# benchmarks/scripts/bench_lan.sh
# Scenario: LAN file transfer between two machines.
#
# Compares: rsync (SSH), rsync (SSH + compress), scp, UDT (if available)
# Network:  real LAN link (WiFi or Ethernet)
#
# Usage: ./bench_lan.sh --remote USER@HOST [--size SIZE_MB] [--runs N]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/bench_common.sh"

# ── Options ──────────────────────────────────────────────────────────────────
SIZE_MB=256
RUNS=3
REMOTE=""
REMOTE_DIR="/tmp/favonius-bench-dst"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --remote)         REMOTE="$2"; shift 2 ;;
        --size)           SIZE_MB="$2"; shift 2 ;;
        --runs)           RUNS="$2"; shift 2 ;;
        --remote-dir)     REMOTE_DIR="$2"; shift 2 ;;
        -h|--help)
            echo "Usage: $0 --remote USER@HOST [--size SIZE_MB] [--runs N] [--remote-dir DIR]"
            echo
            echo "Options:"
            echo "  --remote USER@HOST   Remote machine (required)"
            echo "  --size SIZE_MB       File size in MB (default: 256)"
            echo "  --runs N             Runs per benchmark (default: 3)"
            echo "  --remote-dir DIR     Destination directory on remote (default: /tmp/favonius-bench-dst)"
            exit 0
            ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

if [ -z "$REMOTE" ]; then
    echo "Error: --remote USER@HOST is required"
    echo "Usage: $0 --remote USER@HOST [--size SIZE_MB] [--runs N]"
    exit 1
fi

DATA_BYTES=$(( SIZE_MB * 1048576 ))
LARGE_FILE="$SRC_DIR/large_${SIZE_MB}mb.bin"

# ── Setup ────────────────────────────────────────────────────────────────────
log_header "Benchmark: LAN file transfer (${SIZE_MB} MB) — to $REMOTE"

ensure_dirs

# Clean previous results for this scenario
rm -f "$RESULTS_DIR"/lan-*.log
rm -f "$RESULTS_DIR"/lan-*.log.stdout

# Generate test data locally
"$SCRIPT_DIR/generate_data.sh" --size "$SIZE_MB" --large-only

if [ ! -f "$LARGE_FILE" ]; then
    log_error "Test file not found: $LARGE_FILE"
    exit 1
fi

log_info "File: $LARGE_FILE ($(du -h "$LARGE_FILE" | cut -f1))"
log_info "Runs per tool: $RUNS"
log_info "Remote: $REMOTE:$REMOTE_DIR"
echo

# ── Connectivity check ───────────────────────────────────────────────────────
log_header "Connectivity"

if ! ssh -o BatchMode=yes -o ConnectTimeout=5 "$REMOTE" true 2>/dev/null; then
    log_error "Cannot SSH to $REMOTE (key-based auth required)"
    log_error "Run: ssh-copy-id $REMOTE"
    exit 1
fi
log_ok "SSH to $REMOTE: OK"

# Gather remote info
REMOTE_UNAME=$(ssh "$REMOTE" "uname -m" 2>/dev/null || echo "unknown")
REMOTE_HOST=$(ssh "$REMOTE" "hostname" 2>/dev/null || echo "unknown")
log_info "Remote: $REMOTE_HOST ($REMOTE_UNAME)"

# Measure baseline latency
PING_RTT=$(ping -c 5 -q "$(echo "$REMOTE" | cut -d@ -f2)" 2>/dev/null \
    | grep "rtt" | awk -F'/' '{print $5}') || PING_RTT="?"
log_info "RTT: ${PING_RTT} ms (avg of 5 pings)"

# Show local network interface
LOCAL_IF=$(ip route get "$(echo "$REMOTE" | cut -d@ -f2)" 2>/dev/null \
    | head -1 | awk '{for(i=1;i<=NF;i++) if($i=="dev") print $(i+1)}') || LOCAL_IF="?"
LOCAL_IP=$(ip route get "$(echo "$REMOTE" | cut -d@ -f2)" 2>/dev/null \
    | head -1 | awk '{for(i=1;i<=NF;i++) if($i=="src") print $(i+1)}') || LOCAL_IP="?"
log_info "Local interface: $LOCAL_IF ($LOCAL_IP)"
echo

# ── Prepare remote ───────────────────────────────────────────────────────────
log_header "Preparing remote"

ssh "$REMOTE" "mkdir -p '$REMOTE_DIR'" 2>/dev/null
log_ok "Remote directory: $REMOTE_DIR"

# Helper: clean remote destination between runs
clean_remote_dst() {
    ssh "$REMOTE" "rm -f '$REMOTE_DIR'/*" 2>/dev/null
    sync
}

# ── Dependency check ─────────────────────────────────────────────────────────
log_header "Checking tools"

HAS_RSYNC=false
HAS_SCP=true  # scp is always available with SSH
HAS_UDT=false
HAS_BBCP=false
HAS_FAVONIUS=false

check_command rsync rsync && HAS_RSYNC=true

# Check if UDT binaries exist locally AND on the remote
if [ -x "$UDT_SENDFILE" ] && [ -x "$UDT_RECVFILE" ]; then
    # Check if compatible UDT binaries exist on remote
    if ssh "$REMOTE" "test -x /tmp/udt-bench/sendfile" 2>/dev/null; then
        log_ok "UDT on remote: /tmp/udt-bench/sendfile"
        HAS_UDT=true
    else
        log_warn "UDT not available on remote ($REMOTE_UNAME) — skipping"
        log_warn "  To enable: build UDT on the remote and place in /tmp/udt-bench/"
    fi
else
    log_warn "UDT not built locally — skipping"
fi

# Check if bbcp is built locally and available on the remote
if [ -x "$BBCP_BIN" ]; then
    if ssh "$REMOTE" "command -v bbcp" 2>/dev/null >/dev/null; then
        log_ok "bbcp local: $BBCP_BIN"
        log_ok "bbcp on remote: $(ssh "$REMOTE" "which bbcp" 2>/dev/null)"
        HAS_BBCP=true
    else
        log_warn "bbcp not available on remote — skipping"
        log_warn "  To enable: build bbcp on the remote and install to PATH"
    fi
else
    log_warn "bbcp not built locally ($BBCP_BIN) — skipping"
fi

# Check Favonius: CLI locally, daemon on remote
FAVONIUS_CLI="$SCRIPT_DIR/../../target/release/favonius"
if [ -x "$FAVONIUS_CLI" ]; then
    if ssh "$REMOTE" "test -x /tmp/favonius-bench/favonius-daemon" 2>/dev/null; then
        log_ok "Favonius daemon on remote: /tmp/favonius-bench/favonius-daemon"
        HAS_FAVONIUS=true
    else
        log_warn "Favonius daemon not deployed on remote — skipping"
        log_warn "  To enable: cross-compile and deploy favonius-daemon to $REMOTE:/tmp/favonius-bench/"
    fi
else
    log_warn "Favonius CLI not built locally — skipping"
    log_warn "  To enable: cargo build --release"
fi

if ! $HAS_RSYNC && ! $HAS_SCP; then
    log_error "No benchmark tools available."
    exit 1
fi

# ── Helper: bench_run adapted for remote transfers ────────────────────────────
# We override bench_run to clean the remote destination before each run.
bench_run_lan() {
    local label="$1"; shift
    local logfile="$RESULTS_DIR/${label}.log"

    log_info "Running: ${BOLD}$label${RESET}"
    clean_remote_dst
    sync

    local start_ns
    start_ns=$(date +%s%N)

    /usr/bin/time -v "$@" > "$logfile.stdout" 2> "$logfile" || true

    local end_ns
    end_ns=$(date +%s%N)
    local elapsed_ms=$(( (end_ns - start_ns) / 1000000 ))

    local wall cpu_pct rss_kb
    wall=$(grep "Elapsed (wall clock)" "$logfile" | sed 's/.*): //')
    cpu_pct=$(grep "Percent of CPU" "$logfile" | sed 's/.*: //')
    rss_kb=$(grep "Maximum resident set" "$logfile" | awk '{print $NF}')

    cat >> "$logfile" <<EOF

--- BENCH SUMMARY ---
label=$label
elapsed_ms=$elapsed_ms
wall_clock=$wall
cpu_percent=$cpu_pct
peak_rss_kb=$rss_kb
EOF

    log_ok "$label  =>  ${wall:-${elapsed_ms}ms}  CPU: ${cpu_pct:-?}  RSS: ${rss_kb:-?} KB"
}

# ── Helper: run N times ──────────────────────────────────────────────────────
run_n_lan() {
    local base_label="$1"; shift
    for run in $(seq 1 "$RUNS"); do
        bench_run_lan "${base_label}-run${run}" "$@"
    done
}

# ══════════════════════════════════════════════════════════════════════════════
# BENCHMARK: scp (baseline — SSH encrypted transfer)
# ══════════════════════════════════════════════════════════════════════════════
log_header "scp — baseline SSH transfer"

run_n_lan "lan-scp" \
    scp -q "$LARGE_FILE" "$REMOTE:$REMOTE_DIR/large_${SIZE_MB}mb.bin"

# ══════════════════════════════════════════════════════════════════════════════
# BENCHMARK: rsync over SSH (no compression)
# ══════════════════════════════════════════════════════════════════════════════
if $HAS_RSYNC; then
    log_header "rsync — over SSH (no compression)"

    run_n_lan "lan-rsync-ssh" \
        rsync -a --no-compress --inplace \
            "$LARGE_FILE" \
            "$REMOTE:$REMOTE_DIR/large_${SIZE_MB}mb.bin"
fi

# ══════════════════════════════════════════════════════════════════════════════
# BENCHMARK: rsync over SSH with compression
# ══════════════════════════════════════════════════════════════════════════════
if $HAS_RSYNC; then
    log_header "rsync — over SSH with compression"

    run_n_lan "lan-rsync-ssh-compress" \
        rsync -az --inplace \
            "$LARGE_FILE" \
            "$REMOTE:$REMOTE_DIR/large_${SIZE_MB}mb.bin"
fi

# ══════════════════════════════════════════════════════════════════════════════
# BENCHMARK: UDT (sendfile/recvfile over LAN)
# ══════════════════════════════════════════════════════════════════════════════
if $HAS_UDT; then
    log_header "UDT — sendfile/recvfile over LAN"

    UDT_PORT=9000

    for run in $(seq 1 "$RUNS"); do
        clean_remote_dst

        # Start sendfile server LOCALLY (it serves the file from local disk).
        "$UDT_SENDFILE" "$UDT_PORT" &
        LOCAL_PID=$!
        sleep 1  # Let server bind

        # Run recvfile client ON THE REMOTE, connecting back to our local IP.
        # We time the SSH + recvfile together (SSH overhead is negligible vs transfer).
        bench_run_lan "lan-udt-run${run}" \
            ssh "$REMOTE" \
                "LD_LIBRARY_PATH=/tmp/udt-src/src /tmp/udt-bench/recvfile \
                    $LOCAL_IP $UDT_PORT \
                    $LARGE_FILE \
                    $REMOTE_DIR/large_${SIZE_MB}mb.bin"

        # Stop local server
        kill "$LOCAL_PID" 2>/dev/null || true
        wait "$LOCAL_PID" 2>/dev/null || true

        UDT_PORT=$((UDT_PORT + 1))
    done
fi

# ══════════════════════════════════════════════════════════════════════════════
# BENCHMARK: bbcp (multi-stream SSH transfer)
# ══════════════════════════════════════════════════════════════════════════════
if $HAS_BBCP; then
    log_header "bbcp — multi-stream SSH transfer"

    run_n_lan "lan-bbcp" \
        "$BBCP_BIN" -P 2 \
            "$LARGE_FILE" \
            "$REMOTE:$REMOTE_DIR/large_${SIZE_MB}mb.bin"
fi

# ══════════════════════════════════════════════════════════════════════════════
# BENCHMARK: Favonius AHP (UDP direct transfer)
# ══════════════════════════════════════════════════════════════════════════════
if $HAS_FAVONIUS; then
    REMOTE_HOST_ADDR=$(echo "$REMOTE" | cut -d@ -f2)
    AHP_PORT=7801

    for ACK_MODE in bitmap nack; do
        for CC_PROFILE in classic model; do
            log_header "Favonius AHP — CC: $CC_PROFILE, ACK: $ACK_MODE"

            for run in $(seq 1 "$RUNS"); do
                # Restart daemon before EVERY run to avoid stale state.
                ssh "$REMOTE" "pkill -f favonius-daemon 2>/dev/null" || true
                sleep 0.5
                ssh "$REMOTE" "nohup /tmp/favonius-bench/favonius-daemon \
                    --protocol-listen 0.0.0.0:$AHP_PORT \
                    --log-level warn \
                    > /tmp/favonius-daemon.log 2>&1 & disown" </dev/null
                sleep 2  # Let daemon bind

                clean_remote_dst
                sleep 0.5

                bench_run_lan "lan-favonius-${ACK_MODE}-${CC_PROFILE}-run${run}" \
                    "$FAVONIUS_CLI" send "$LARGE_FILE" \
                        "${REMOTE_HOST_ADDR}:${AHP_PORT}:${REMOTE_DIR}/large_${SIZE_MB}mb.bin" \
                        --congestion "$CC_PROFILE" \
                        --ack-mode "$ACK_MODE" \
                        --log-level warn
            done

            # Stop remote daemon
            ssh "$REMOTE" "pkill -f favonius-daemon 2>/dev/null" || true
        done
    done
fi

# ══════════════════════════════════════════════════════════════════════════════
# RESULTS
# ══════════════════════════════════════════════════════════════════════════════
echo
log_header "RESULTS"
printf "${BOLD}%-35s %12s %12s %10s %12s${RESET}\n" \
    "BENCHMARK" "TIME" "THROUGHPUT" "CPU" "PEAK RSS"
printf "%s\n" "$(printf '─%.0s' {1..83})"

for logfile in "$RESULTS_DIR"/lan-*.log; do
    [ -f "$logfile" ] || continue
    [[ "$logfile" == *.stdout ]] && continue

    label=$(grep "^label=" "$logfile" 2>/dev/null | cut -d= -f2) || continue
    [ -z "$label" ] && continue

    wall=$(grep "^wall_clock=" "$logfile" | cut -d= -f2)
    cpu_pct=$(grep "^cpu_percent=" "$logfile" | cut -d= -f2)
    rss_kb=$(grep "^peak_rss_kb=" "$logfile" | cut -d= -f2)
    elapsed_ms=$(grep "^elapsed_ms=" "$logfile" | cut -d= -f2)

    if [ "$DATA_BYTES" -gt 0 ] && [ "${elapsed_ms:-0}" -gt 0 ]; then
        thru=$(calc_throughput "$DATA_BYTES" "$elapsed_ms")
    else
        thru="—"
    fi

    printf "%-35s %12s %12s %10s %10s KB\n" \
        "$label" "${wall:-?}" "$thru" "${cpu_pct:-?}" "${rss_kb:-?}"
done

echo

# ── Verify last transfer ────────────────────────────────────────────────────
log_header "Verification"

EXPECTED_SIZE=$(stat -c%s "$LARGE_FILE" 2>/dev/null || stat -f%z "$LARGE_FILE")
REMOTE_SIZE=$(ssh "$REMOTE" "stat -c%s '$REMOTE_DIR/large_${SIZE_MB}mb.bin' 2>/dev/null || echo 0")

if [ "$EXPECTED_SIZE" = "$REMOTE_SIZE" ]; then
    log_ok "Last transfer verified: sizes match ($REMOTE_SIZE bytes)"

    log_info "Computing remote checksum (this may take a moment on the Pi)..."
    SRC_HASH=$(sha256sum "$LARGE_FILE" | awk '{print $1}')
    DST_HASH=$(ssh "$REMOTE" "sha256sum '$REMOTE_DIR/large_${SIZE_MB}mb.bin'" | awk '{print $1}')
    if [ "$SRC_HASH" = "$DST_HASH" ]; then
        log_ok "SHA-256 match: $SRC_HASH"
    else
        log_error "SHA-256 MISMATCH!"
        log_error "  Source: $SRC_HASH"
        log_error "  Remote: $DST_HASH"
    fi
else
    log_error "Size mismatch: expected $EXPECTED_SIZE, got $REMOTE_SIZE"
fi

# ── Cleanup remote ──────────────────────────────────────────────────────────
log_header "Cleanup"
ssh "$REMOTE" "rm -rf '$REMOTE_DIR'" 2>/dev/null || true
log_ok "Removed $REMOTE:$REMOTE_DIR"

log_header "Done"
log_info "Raw logs: $RESULTS_DIR/"
