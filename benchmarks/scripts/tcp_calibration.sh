#!/usr/bin/env bash
# Favonius — high-performance file transfer over UDP
# Copyright (c) 2025-2026 Vantino SàRL
# SPDX-License-Identifier: Apache-2.0
#
# Kernel-TCP calibration through the identical qdisc the v2 harness builds.
#
# Question: at 1 Gbit the best Favonius controller reaches 46-48% of link on
# long paths and uftp lands at the same place. Is that the controllers, or
# is it the rig? Kernel cubic through the same netem+tbf answers it: if
# cubic also lands near 46%, the shaped path cannot deliver more and every
# "% of link" figure in this project is measured against the wrong ceiling.
#
# Topology is copied from bench_netem_fair_v2.sh, not re-derived: netem is
# root, tbf hangs beneath it, shaping on the CLI (data sender) egress,
# limit = RATE x delay x QUEUE_BDP with a 2*burst floor.
set -uo pipefail

IMAGE="${IMAGE:-favonius-bench:v2-coex}"   # base image has no iperf3
NET="tcpcal-net"; SRV="tcpcal-srv"; CLI="tcpcal-cli"
RATE_MBIT="${RATE_MBIT:-1000}"
QUEUE_BDP="${QUEUE_BDP:-1.0}"
SECS="${SECS:-60}"
RUNS="${RUNS:-2}"
CCS="${CCS:-cubic reno}"
TIMEOUT="${TIMEOUT:-90}"
OUT="${OUT:-/tmp/tcp_calib.csv}"

SCENARIOS=(
    "cross-country|25|0.5"
    "transatlantic|50|1"
    "satellite|150|2"
    "degraded|100|5"
)

log() { echo "[$(date +%H:%M:%S)] $*"; }

cleanup() { docker rm -f "$SRV" "$CLI" >/dev/null 2>&1 || true
            docker network rm "$NET" >/dev/null 2>&1 || true; }
trap cleanup EXIT
cleanup

docker network create "$NET" >/dev/null || exit 1
docker run -d --name "$SRV" --network "$NET" --cap-add NET_ADMIN "$IMAGE" >/dev/null || exit 1
docker run -d --name "$CLI" --network "$NET" --cap-add NET_ADMIN "$IMAGE" >/dev/null || exit 1
SRV_IP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$SRV")
log "topology srv=$SRV_IP rate=${RATE_MBIT}mbit queue=${QUEUE_BDP}xBDP secs=${SECS}s"

apply() {   # $1 delay_ms  $2 loss_pct
    local d="$1" l="$2" burst limit
    docker exec "$SRV" tc qdisc del dev eth0 root 2>/dev/null || true
    docker exec "$CLI" tc qdisc del dev eth0 root 2>/dev/null || true
    burst=$(awk -v r="$RATE_MBIT" 'BEGIN{b=r*1000000/8/100; if(b<131072)b=131072; printf "%d",b}')
    limit=$(awk -v r="$RATE_MBIT" -v d="$d" -v q="$QUEUE_BDP" -v b="$burst" 'BEGIN{
        lim = (r*1000000/8)*(d/1000)*q; if(lim < 2*b) lim = 2*b; printf "%d", lim}')
    docker exec "$CLI" tc qdisc add dev eth0 root handle 1: \
        netem delay "${d}ms" loss "${l}%" limit 100000
    docker exec "$CLI" tc qdisc add dev eth0 parent 1: handle 10: \
        tbf rate "${RATE_MBIT}mbit" burst "$burst" limit "$limit"
}

echo "scenario,delay_ms,loss_pct,cc,run,mbit_s,mib_s,retransmits,max_cwnd_kb" > "$OUT"

for s in "${SCENARIOS[@]}"; do
    IFS='|' read -r name delay loss <<< "$s"
    apply "$delay" "$loss"
    for cc in $CCS; do
        for r in $(seq 1 "$RUNS"); do
            docker exec "$SRV" pkill -x iperf3 2>/dev/null || true
            sleep 0.3
            docker exec -d "$SRV" iperf3 -s -1 >/dev/null 2>&1
            sleep 0.7
            j=$(timeout $((TIMEOUT + 20)) docker exec "$CLI" \
                    iperf3 -c "$SRV_IP" -t "$SECS" -C "$cc" -J 2>/dev/null)
            read -r mbit retr cwnd <<< "$(printf '%s' "$j" | python3 -c '
import sys, json
try:
    d = json.load(sys.stdin)
    e = d["end"]["sum_sent"]
    bps = e["bits_per_second"]
    retr = e.get("retransmits", -1)
    cw = max((i["streams"][0].get("snd_cwnd",0) for i in d.get("intervals",[])), default=0)
    print(f"{bps/1e6:.1f} {retr} {cw//1024}")
except Exception:
    print("0 -1 0")')"
            printf "%-14s %-6s run%d  %8.1f Mbit/s  %7.1f MiB/s  retr=%-7s cwnd_max=%sKB\n" \
                "$name" "$cc" "$r" "$mbit" \
                "$(awk -v m="$mbit" 'BEGIN{printf "%.1f", m*1000000/8/1048576}')" "$retr" "$cwnd"
            echo "$name,$delay,$loss,$cc,$r,$mbit,$(awk -v m="$mbit" 'BEGIN{printf "%.1f", m*1000000/8/1048576}'),$retr,$cwnd" >> "$OUT"
        done
    done
done

echo
echo "=== TCP_CALIB_FINISHED ==="
cat "$OUT"
