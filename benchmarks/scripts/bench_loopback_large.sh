#!/usr/bin/env bash

# Favonius — high-performance file transfer over UDP
# Copyright (c) 2025-2026 Vantino SàRL
# SPDX-License-Identifier: Apache-2.0

# benchmarks/scripts/bench_loopback_large.sh
# Scenario 3.1 — Large file transfer over loopback.
#
# Compares: Favonius (AHP), UDT, rsync
# Network:  localhost (measures pure software overhead)
#
# Usage: ./bench_loopback_large.sh [--size SIZE_MB] [--runs N] [--skip-generate]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/bench_common.sh"

# ── Options ──────────────────────────────────────────────────────────────────
SIZE_MB=1024
RUNS=3
SKIP_GENERATE=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        --size)           SIZE_MB="$2"; shift 2 ;;
        --runs)           RUNS="$2"; shift 2 ;;
        --skip-generate)  SKIP_GENERATE=true; shift ;;
        -h|--help)
            echo "Usage: $0 [--size SIZE_MB] [--runs N] [--skip-generate]"
            echo
            echo "Options:"
            echo "  --size SIZE_MB     Large file size in MB (default: 1024)"
            echo "  --runs N           Number of runs per benchmark (default: 3)"
            echo "  --skip-generate    Skip test data generation"
            exit 0
            ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

DATA_BYTES=$(( SIZE_MB * 1048576 ))
LARGE_FILE="$SRC_DIR/large_${SIZE_MB}mb.bin"

# ── Setup ────────────────────────────────────────────────────────────────────
log_header "Benchmark: Large file transfer (${SIZE_MB} MB) — Loopback"

ensure_dirs

# Clean any previous results for this scenario
rm -f "$RESULTS_DIR"/loopback-large-*.log
rm -f "$RESULTS_DIR"/loopback-large-*.log.stdout

# Generate test data
if [ "$SKIP_GENERATE" = false ]; then
    "$SCRIPT_DIR/generate_data.sh" --size "$SIZE_MB" --large-only
fi

if [ ! -f "$LARGE_FILE" ]; then
    log_error "Test file not found: $LARGE_FILE"
    log_error "Run generate_data.sh first or remove --skip-generate"
    exit 1
fi

log_info "File: $LARGE_FILE ($(du -h "$LARGE_FILE" | cut -f1))"
log_info "Runs per tool: $RUNS"
echo

# ── Dependency check ─────────────────────────────────────────────────────────
log_header "Checking tools"

HAS_RSYNC=false
HAS_UDT=false
HAS_FAVONIUS=false

check_command rsync rsync             && HAS_RSYNC=true
check_udt                             && HAS_UDT=true
check_favonius                         && HAS_FAVONIUS=true

if ! $HAS_RSYNC && ! $HAS_UDT && ! $HAS_FAVONIUS; then
    log_error "No benchmark tools available. Install at least one."
    exit 1
fi

# ── Helper: run N times, keep all results ────────────────────────────────────
run_n_times() {
    local base_label="$1"; shift
    for run in $(seq 1 "$RUNS"); do
        bench_run "${base_label}-run${run}" "$@"
    done
}

# ══════════════════════════════════════════════════════════════════════════════
# BENCHMARK: rsync (local copy via rsync protocol — no SSH overhead)
# ══════════════════════════════════════════════════════════════════════════════
if $HAS_RSYNC; then
    log_header "rsync — local file copy (no SSH)"

    run_n_times "loopback-large-rsync-local" \
        rsync -a --no-compress --inplace \
            "$LARGE_FILE" \
            "$DST_DIR/large_${SIZE_MB}mb.bin"
fi

# ══════════════════════════════════════════════════════════════════════════════
# BENCHMARK: rsync over SSH to localhost
# ══════════════════════════════════════════════════════════════════════════════
if $HAS_RSYNC; then
    # Only run if SSH to localhost works without a password prompt
    if ssh -o BatchMode=yes -o ConnectTimeout=3 localhost true 2>/dev/null; then
        log_header "rsync — over SSH to localhost"

        run_n_times "loopback-large-rsync-ssh" \
            rsync -a --no-compress --inplace \
                "$LARGE_FILE" \
                "localhost:$DST_DIR/large_${SIZE_MB}mb.bin"
    else
        log_warn "SSH to localhost not available (no key-based auth). Skipping rsync-ssh."
    fi
fi

# ══════════════════════════════════════════════════════════════════════════════
# BENCHMARK: rsync with compression
# ══════════════════════════════════════════════════════════════════════════════
if $HAS_RSYNC; then
    log_header "rsync — local copy with compression"

    run_n_times "loopback-large-rsync-compress" \
        rsync -az --inplace \
            "$LARGE_FILE" \
            "$DST_DIR/large_${SIZE_MB}mb.bin"
fi

# ══════════════════════════════════════════════════════════════════════════════
# BENCHMARK: UDT (sendfile / recvfile)
# ══════════════════════════════════════════════════════════════════════════════
if $HAS_UDT; then
    log_header "UDT — sendfile/recvfile over localhost"

    UDT_PORT=9000

    for run in $(seq 1 "$RUNS"); do
        clean_dst

        # Start sendfile server in background (serves the source file).
        "$UDT_SENDFILE" "$UDT_PORT" &
        SEND_PID=$!
        sleep 0.5  # Let server bind

        # Time the recvfile client (downloads the file).
        bench_run "loopback-large-udt-run${run}" \
            "$UDT_RECVFILE" 127.0.0.1 "$UDT_PORT" \
            "$LARGE_FILE" "$DST_DIR/large_${SIZE_MB}mb.bin"

        # Stop server
        kill "$SEND_PID" 2>/dev/null || true
        wait "$SEND_PID" 2>/dev/null || true

        # Increment port to avoid TIME_WAIT collisions
        UDT_PORT=$((UDT_PORT + 1))
    done
fi

# ══════════════════════════════════════════════════════════════════════════════
# BENCHMARK: cp (baseline — measures pure I/O overhead)
# ══════════════════════════════════════════════════════════════════════════════
log_header "cp — baseline I/O copy"

run_n_times "loopback-large-cp" \
    cp "$LARGE_FILE" "$DST_DIR/large_${SIZE_MB}mb.bin"

# ══════════════════════════════════════════════════════════════════════════════
# BENCHMARK: Favonius (AHP)
# ══════════════════════════════════════════════════════════════════════════════
if $HAS_FAVONIUS; then
    log_header "Favonius (AHP) — send over localhost"

    # Start daemon in background
    DAEMON_PORT=7800
    AHP_PORT=7801  # daemon default AHP control port (--protocol-listen)
    "$FAVONIUS_DAEMON_BIN" --listen "127.0.0.1:${DAEMON_PORT}" &
    DAEMON_PID=$!
    sleep 1  # Wait for daemon startup

    for run in $(seq 1 "$RUNS"); do
        # Destination uses the remote AHP syntax host:port:/path so the
        # transfer exercises the real AHP/UDP network path. A plain local
        # path would go through the daemon HTTP API and its copy_file_range
        # fast path, bypassing the protocol entirely.
        bench_run "loopback-large-favonius-run${run}" \
            "$FAVONIUS_BIN" --daemon "127.0.0.1:${DAEMON_PORT}" \
                send "$LARGE_FILE" "127.0.0.1:${AHP_PORT}:$DST_DIR/large_${SIZE_MB}mb.bin" \
                --compression none
    done

    # Stop daemon
    kill "$DAEMON_PID" 2>/dev/null || true
    wait "$DAEMON_PID" 2>/dev/null || true
else
    log_warn "Favonius not built — skipping. Run: cd $REPO_ROOT && cargo build --release"
fi

# ══════════════════════════════════════════════════════════════════════════════
# RESULTS
# ══════════════════════════════════════════════════════════════════════════════
print_results_table "$DATA_BYTES"

# ── Verify correctness ───────────────────────────────────────────────────────
log_header "Verification"

EXPECTED_SIZE=$(stat -c%s "$LARGE_FILE" 2>/dev/null || stat -f%z "$LARGE_FILE")
DST_FILE="$DST_DIR/large_${SIZE_MB}mb.bin"

if [ -f "$DST_FILE" ]; then
    ACTUAL_SIZE=$(stat -c%s "$DST_FILE" 2>/dev/null || stat -f%z "$DST_FILE")
    if [ "$EXPECTED_SIZE" = "$ACTUAL_SIZE" ]; then
        log_ok "Last transfer verified: sizes match ($ACTUAL_SIZE bytes)"

        # Quick hash check on the last run
        log_info "Computing checksums (this may take a moment)..."
        SRC_HASH=$(sha256sum "$LARGE_FILE" | awk '{print $1}')
        DST_HASH=$(sha256sum "$DST_FILE" | awk '{print $1}')
        if [ "$SRC_HASH" = "$DST_HASH" ]; then
            log_ok "SHA-256 match: $SRC_HASH"
        else
            log_error "SHA-256 MISMATCH!"
            log_error "  Source: $SRC_HASH"
            log_error "  Dest:   $DST_HASH"
        fi
    else
        log_error "Size mismatch: expected $EXPECTED_SIZE, got $ACTUAL_SIZE"
    fi
else
    log_warn "No destination file to verify (all tools may have been skipped)"
fi

log_header "Done"
log_info "Raw logs: $RESULTS_DIR/"
