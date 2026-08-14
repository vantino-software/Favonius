#!/usr/bin/env bash

# Favonius — high-performance file transfer over UDP
# Copyright (c) 2025-2026 Vantino SàRL
# SPDX-License-Identifier: Apache-2.0

# benchmarks/scripts/bench_common.sh
# Shared utilities for all benchmark scripts.
#
# Source this file — do not execute directly.

set -euo pipefail

# ── Paths ────────────────────────────────────────────────────────────────────
BENCH_ROOT="${BENCH_ROOT:-/tmp/favonius-bench}"
RESULTS_DIR="$BENCH_ROOT/results"
SRC_DIR="$BENCH_ROOT/src"
DST_DIR="$BENCH_ROOT/dst"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
FAVONIUS_BIN="$REPO_ROOT/target/release/favonius"
FAVONIUS_DAEMON_BIN="$REPO_ROOT/target/release/favonius-daemon"
UDT_DIR="$REPO_ROOT/benchmarks/UDT"
UDT_SENDFILE="$UDT_DIR/sendfile"
UDT_RECVFILE="$UDT_DIR/recvfile"
BBCP_BIN="$REPO_ROOT/benchmarks/bbcp/bin/amd64_linux/bbcp"

# ── Formatting ───────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
RESET='\033[0m'

log_info()  { echo -e "${CYAN}[INFO]${RESET}  $*"; }
log_ok()    { echo -e "${GREEN}[OK]${RESET}    $*"; }
log_warn()  { echo -e "${YELLOW}[WARN]${RESET}  $*"; }
log_error() { echo -e "${RED}[ERROR]${RESET} $*"; }
log_header(){ echo -e "\n${BOLD}━━━ $* ━━━${RESET}\n"; }

# ── Directory setup ──────────────────────────────────────────────────────────
ensure_dirs() {
    mkdir -p "$RESULTS_DIR" "$SRC_DIR" "$DST_DIR"
}

# Clear destination between runs to ensure a full transfer.
clean_dst() {
    rm -rf "${DST_DIR:?}"/*
    sync
}

# ── Timing ───────────────────────────────────────────────────────────────────
# bench_run <label> <command...>
#
# Runs the command with /usr/bin/time, stores structured output in
# $RESULTS_DIR/<label>.log, and prints a one-line summary.
bench_run() {
    local label="$1"; shift
    local logfile="$RESULTS_DIR/${label}.log"

    log_info "Running: ${BOLD}$label${RESET}"
    clean_dst
    sync

    # Drop caches if root (optional, best effort)
    if [ "$(id -u)" = "0" ]; then
        echo 3 > /proc/sys/vm/drop_caches 2>/dev/null || true
    fi

    local start_ns
    start_ns=$(date +%s%N)

    /usr/bin/time -v "$@" > "$logfile.stdout" 2> "$logfile" || true

    local end_ns
    end_ns=$(date +%s%N)
    local elapsed_ms=$(( (end_ns - start_ns) / 1000000 ))

    # Extract metrics from /usr/bin/time -v output
    local wall cpu_pct rss_kb
    wall=$(grep "Elapsed (wall clock)" "$logfile" | sed 's/.*): //')
    cpu_pct=$(grep "Percent of CPU" "$logfile" | sed 's/.*: //')
    rss_kb=$(grep "Maximum resident set" "$logfile" | awk '{print $NF}')

    # Store machine-readable summary
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

# ── Throughput calculation ───────────────────────────────────────────────────
# calc_throughput <bytes> <milliseconds>
calc_throughput() {
    local bytes="$1" ms="$2"
    if [ "$ms" -gt 0 ]; then
        awk "BEGIN { printf \"%.1f MB/s\", ($bytes / 1048576) / ($ms / 1000) }"
    else
        echo "— (too fast to measure)"
    fi
}

# ── Dependency checks ────────────────────────────────────────────────────────
check_command() {
    local cmd="$1" name="${2:-$1}"
    if command -v "$cmd" &>/dev/null; then
        log_ok "$name found: $(command -v "$cmd")"
        return 0
    else
        log_warn "$name not found — its benchmarks will be skipped"
        return 1
    fi
}

check_favonius() {
    if [ -x "$FAVONIUS_BIN" ]; then
        log_ok "Favonius CLI: $FAVONIUS_BIN"
        return 0
    else
        log_warn "Favonius not built. Run: cargo build --release"
        return 1
    fi
}

check_udt() {
    if [ -x "$UDT_SENDFILE" ] && [ -x "$UDT_RECVFILE" ]; then
        log_ok "UDT sendfile: $UDT_SENDFILE"
        log_ok "UDT recvfile: $UDT_RECVFILE"
        return 0
    else
        log_warn "UDT not built — run: cd $UDT_DIR && make"
        return 1
    fi
}

# ── Results table ────────────────────────────────────────────────────────────
# print_results_table <data_size_bytes>
#
# Scans $RESULTS_DIR/*.log for BENCH SUMMARY blocks and prints a table.
print_results_table() {
    local data_bytes="${1:-0}"

    echo
    log_header "RESULTS"
    printf "${BOLD}%-30s %12s %12s %10s %12s${RESET}\n" \
        "BENCHMARK" "TIME" "THROUGHPUT" "CPU" "PEAK RSS"
    printf "%s\n" "$(printf '─%.0s' {1..78})"

    for logfile in "$RESULTS_DIR"/*.log; do
        [ -f "$logfile" ] || continue
        # Skip .stdout files
        [[ "$logfile" == *.stdout ]] && continue

        local label wall cpu_pct rss_kb elapsed_ms thru

        label=$(grep "^label=" "$logfile" 2>/dev/null | cut -d= -f2) || continue
        [ -z "$label" ] && continue

        wall=$(grep "^wall_clock=" "$logfile" | cut -d= -f2)
        cpu_pct=$(grep "^cpu_percent=" "$logfile" | cut -d= -f2)
        rss_kb=$(grep "^peak_rss_kb=" "$logfile" | cut -d= -f2)
        elapsed_ms=$(grep "^elapsed_ms=" "$logfile" | cut -d= -f2)

        if [ "$data_bytes" -gt 0 ] && [ "${elapsed_ms:-0}" -gt 0 ]; then
            thru=$(calc_throughput "$data_bytes" "$elapsed_ms")
        else
            thru="—"
        fi

        printf "%-30s %12s %12s %10s %10s KB\n" \
            "$label" "${wall:-?}" "$thru" "${cpu_pct:-?}" "${rss_kb:-?}"
    done

    echo
}
