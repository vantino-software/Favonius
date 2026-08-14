#!/usr/bin/env bash

# Favonius — high-performance file transfer over UDP
# Copyright (c) 2025-2026 Vantino SàRL
# SPDX-License-Identifier: Apache-2.0

# benchmarks/scripts/generate_data.sh
# Generate test datasets for benchmarking.
#
# Usage: ./generate_data.sh [--size SIZE_MB]
#   --size SIZE_MB   Size of the large file in MB (default: 1024 = 1 GB)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/bench_common.sh"

SIZE_MB=1024
LARGE_ONLY=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        --size)       SIZE_MB="$2"; shift 2 ;;
        --large-only) LARGE_ONLY=true; shift ;;
        *)            echo "Usage: $0 [--size SIZE_MB] [--large-only]"; exit 1 ;;
    esac
done

ensure_dirs

log_header "Generating test data (${SIZE_MB} MB large file)"

# ── 1. Large file ────────────────────────────────────────────────────────────
LARGE_FILE="$SRC_DIR/large_${SIZE_MB}mb.bin"
if [ -f "$LARGE_FILE" ]; then
    existing_mb=$(( $(stat -c%s "$LARGE_FILE" 2>/dev/null || stat -f%z "$LARGE_FILE") / 1048576 ))
    if [ "$existing_mb" -eq "$SIZE_MB" ]; then
        log_ok "Large file already exists: $LARGE_FILE (${existing_mb} MB)"
    else
        log_info "Regenerating large file (size changed)..."
        dd if=/dev/urandom of="$LARGE_FILE" bs=1M count="$SIZE_MB" status=progress 2>&1
        log_ok "Created: $LARGE_FILE"
    fi
else
    log_info "Creating ${SIZE_MB} MB random file..."
    dd if=/dev/urandom of="$LARGE_FILE" bs=1M count="$SIZE_MB" status=progress 2>&1
    log_ok "Created: $LARGE_FILE"
fi

# ── 2. Many small files ─────────────────────────────────────────────────────
if [ "$LARGE_ONLY" = false ]; then
    SMALL_DIR="$SRC_DIR/smallfiles"
    SMALL_COUNT=10000
    if [ -d "$SMALL_DIR" ] && [ "$(find "$SMALL_DIR" -type f | wc -l)" -ge "$SMALL_COUNT" ]; then
        log_ok "Small files already exist: $SMALL_DIR ($SMALL_COUNT files)"
    else
        log_info "Creating $SMALL_COUNT x 4 KB files..."
        mkdir -p "$SMALL_DIR"
        for i in $(seq 1 "$SMALL_COUNT"); do
            dd if=/dev/urandom of="$SMALL_DIR/file_${i}.dat" bs=4096 count=1 2>/dev/null
        done
        log_ok "Created: $SMALL_DIR/"
    fi

    # ── 3. Mixed workload ───────────────────────────────────────────────────
    MIXED_DIR="$SRC_DIR/mixed"
    if [ -d "$MIXED_DIR" ] && [ "$(find "$MIXED_DIR" -type f | wc -l)" -ge 10 ]; then
        log_ok "Mixed workload already exists: $MIXED_DIR"
    else
        log_info "Creating mixed workload..."
        mkdir -p "$MIXED_DIR"

        # 100 MB compressible text
        log_info "  Generating 100 MB text file..."
        dd if=/dev/urandom bs=1M count=100 2>/dev/null | base64 > "$MIXED_DIR/text_100mb.txt" || true

        # 500 MB binary
        log_info "  Generating 500 MB binary file..."
        dd if=/dev/urandom of="$MIXED_DIR/binary_500mb.bin" bs=1M count=500 2>/dev/null

        # 1000 medium files (64 KB each)
        log_info "  Generating 1000 x 64 KB files..."
        for i in $(seq 1 1000); do
            dd if=/dev/urandom of="$MIXED_DIR/med_${i}.dat" bs=65536 count=1 2>/dev/null
        done

        log_ok "Created: $MIXED_DIR/"
    fi
fi

# ── Summary ──────────────────────────────────────────────────────────────────
echo
log_header "Test data summary"
du -sh "$SRC_DIR/large_${SIZE_MB}mb.bin" 2>/dev/null || true
[ "$LARGE_ONLY" = false ] && du -sh "$SRC_DIR/smallfiles/" 2>/dev/null || true
[ "$LARGE_ONLY" = false ] && du -sh "$SRC_DIR/mixed/" 2>/dev/null || true
echo
du -sh "$SRC_DIR/"
log_ok "Test data ready in $SRC_DIR/"
