#!/usr/bin/env bash

# Favonius — high-performance file transfer over UDP
# Copyright (c) 2025-2026 Vantino SàRL
# SPDX-License-Identifier: Apache-2.0

# benchmarks/scripts/loopback_startup.sh
# The concurrent-admission case, on loopback.
#
# This exists because two startup defects were found by running exactly this
# shape and watching the wall clock: the path probe cost one round trip per
# probe instead of one in total, and a transfer declined for want of a data
# socket was sent no reply at all, so it waited out a 2 s timeout while the
# sockets it wanted were already back in the pool.
#
# Loopback is the right rig for that: it removes RTT, so anything left is
# software. A pool of ten ports with `per_transfer_cap` at five means two
# transfers exhaust it and the other two must be declined and readmitted —
# which is the path under test. Raise the range and the effect vanishes,
# which is the control.
#
# Usage:
#   ./benchmarks/scripts/loopback_startup.sh [--size-mb 256] [--runs 5]

set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
RESULTS="$REPO/benchmarks/results"
BIN="$REPO/target/release"
mkdir -p "$RESULTS"

SIZE_MB=256
RUNS=5
DEST="${DEST:-/tmp/favonius-loopback-in}"
SRC="${SRC:-/tmp/favonius-loopback-src.bin}"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --size-mb) SIZE_MB="$2"; shift 2 ;;
        --runs)    RUNS="$2";    shift 2 ;;
        *) echo "unknown option: $1" >&2; exit 2 ;;
    esac
done

DATE=$(date +%F)
OUT="$RESULTS/loopback_startup_${DATE}.csv"

command -v "$BIN/favonius" >/dev/null || { echo "build first: cargo build --release" >&2; exit 1; }

mkdir -p "$DEST"
head -c $((SIZE_MB * 1024 * 1024)) /dev/urandom > "$SRC"
SHA=$(sha256sum "$SRC" | cut -d' ' -f1)

echo "date,arm,concurrency,streams,ports,size_mib,run,seconds,mib_s,verified" > "$OUT"
echo "source $SIZE_MB MiB sha ${SHA:0:16}  ->  $OUT"

# $1 label  $2 concurrency  $3 streams  $4 port range
run_case() {
    local label=$1 n=$2 st=$3 range=$4 r i t0 t1 ok
    for r in $(seq 1 "$RUNS"); do
        pkill -9 -x favonius-daemon 2>/dev/null
        sleep 0.5
        rm -f "$DEST"/*.bin
        "$BIN/favonius-daemon" --protocol-listen 127.0.0.1:7801 \
            --data-listen 127.0.0.1:7802 --data-port-range "$range" \
            --max-concurrent 8 --dest-root "$DEST" > /tmp/favonius-loopback-daemon.log 2>&1 &
        sleep 1.5

        # `wait` with no arguments also waits on the daemon, which is
        # backgrounded in this same shell and never exits. Wait on the
        # senders by pid, or the first run hangs forever.
        local pids=()
        t0=$(date +%s%N)
        for i in $(seq 1 "$n"); do
            "$BIN/favonius" send "$SRC" "127.0.0.1:7801:$DEST/o$i.bin" \
                --streams "$st" > /dev/null 2>&1 &
            pids+=($!)
        done
        wait "${pids[@]}"
        t1=$(date +%s%N)
        pkill -9 -x favonius-daemon 2>/dev/null

        # A throughput number for a corrupt transfer is not a throughput number.
        ok=0
        for f in "$DEST"/o*.bin; do
            [ -f "$f" ] && [ "$(sha256sum "$f" | cut -d' ' -f1)" = "$SHA" ] && ok=$((ok + 1))
        done

        awk -v d="$DATE" -v l="$label" -v n="$n" -v st="$st" -v p="$range" -v sz="$SIZE_MB" \
            -v r="$r" -v a="$t0" -v b="$t1" -v ok="$ok" \
            'BEGIN { s=(b-a)/1e9;
                     printf "%s,%s,%d,%d,%s,%d,%d,%.3f,%.1f,%s\n",
                            d, l, n, st, p, sz, r, s, (sz*n)/s, (ok==n ? "ok" : "BAD") }' >> "$OUT"
    done
    awk -F, -v l="$label" '$2==l { n++; s+=$9 } END { printf "  %-22s n=%d  mean %.1f MiB/s\n", l, n, s/n }' "$OUT"
}

run_case single           1 4 7803-7812
run_case concurrent4      4 1 7803-7812   # pool exhausts: the admission path
run_case concurrent4_wide 4 1 7803-7842   # pool ample: the control

rm -f "$SRC"
rm -rf "$DEST"
echo "wrote $OUT"
