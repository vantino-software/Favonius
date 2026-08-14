#!/usr/bin/env bash
# Favonius — high-performance file transfer over UDP
# Copyright (c) 2025-2026 Vantino SàRL
# SPDX-License-Identifier: Apache-2.0
#
# benchmarks/scripts/bench_rl_ablation.sh
#
# Does the trained RL model do anything, and is what it does good?
#
# `--congestion rl` silently falls back to UDT-style rate control when no
# weights are loaded, so every published RL result is only meaningful
# relative to that fallback. This script runs the same transfer four ways:
#
#   rl-model     --congestion rl, FAVONIUS_RL_MODEL pointing at the weights
#   rl-fallback  --congestion rl, no weights reachable  <- the control
#   udt          --congestion udt (what the fallback is modelled on)
#   classic      --congestion classic (reference)
#
# If rl-model and rl-fallback are within noise of each other, the model is
# not contributing and the "RL wins N/6 scenarios" claim is really a claim
# about the fallback.
#
# Offline probing of the shipped weights (the `shipped_model_*` tests in
# crates/ahp-congestion/src/rl.rs) says they are NOT inert: the model
# spans ~[0.56, 2.00], sits near 1.70 on a mid-range path, backs off on
# queueing delay, and nudges its rate *up* as loss rises. So the expected
# result is that rl-model differs from rl-fallback — the open question is
# whether "push hard, ignore loss" helps or hurts per scenario.
#
# ISOLATION: uses its own network and container names (rlabl-*), so it will
# not disturb a concurrent bench_netem_fair_v2.sh run. It will still
# contend for CPU, though — do not run the two at the same time if you
# care about either set of numbers.
#
# Usage:
#   ./benchmarks/scripts/bench_rl_ablation.sh [--runs N] [--scenarios a,b]
#
# Env: SIZE_MB (128), RUNS (5), TRANSFER_TIMEOUT (180), IMAGE

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
CONTEXT_DIR="$REPO_ROOT/benchmarks/docker/bench-v2"
RESULTS_DIR="$REPO_ROOT/benchmarks/results"
mkdir -p "$RESULTS_DIR"

IMAGE="${IMAGE:-favonius-bench:v2}"
NET_NAME="rlabl-net"
SRV="rlabl-srv"
CLI="rlabl-cli"
SIZE_MB="${SIZE_MB:-128}"
RUNS="${RUNS:-5}"
TRANSFER_TIMEOUT="${TRANSFER_TIMEOUT:-180}"
DATA_BYTES=$((SIZE_MB * 1048576))

while [[ $# -gt 0 ]]; do
    case "$1" in
        --runs) RUNS="$2"; shift 2 ;;
        --scenarios) ONLY_SCENARIOS="$2"; shift 2 ;;
        *) echo "Unknown arg: $1"; exit 1 ;;
    esac
done
ONLY_SCENARIOS="${ONLY_SCENARIOS:-}"

# Scenarios: name|delay_ms|jitter_ms|loss_pct (true one-way, sender egress).
# baseline is where RL currently *loses* badly (175 vs 325 MB/s) and
# satellite/degraded are where it wins — the ablation needs both.
SCENARIOS=(
    "baseline|0|0|0"
    "cross-country|25|5|0.5"
    "satellite|150|25|2"
    "degraded|100|25|5"
)

# arm|congestion|use_weights
ARMS=(
    "rl-model|rl|1"
    "rl-fallback|rl|0"
    "udt|udt|0"
    "classic|classic|0"
)

log() { echo "[$(date +%H:%M:%S)] $*"; }
die() { echo "ERROR: $*" >&2; exit 1; }

if ! docker image inspect "$IMAGE" > /dev/null 2>&1; then
    log "Image $IMAGE missing — building from $CONTEXT_DIR"
    docker build -t "$IMAGE" "$CONTEXT_DIR" > /dev/null || die "image build failed"
fi

SRC_SHA="$(docker run --rm "$IMAGE" sha256sum /data/test.bin | awk '{print $1}')"
log "Source sha256: $SRC_SHA"

cleanup() {
    docker rm -f "$SRV" "$CLI" > /dev/null 2>&1 || true
    docker network rm "$NET_NAME" > /dev/null 2>&1 || true
}
trap cleanup EXIT

cleanup
docker network create "$NET_NAME" > /dev/null || die "network create failed"
docker run -d --name "$SRV" --network "$NET_NAME" --cap-add NET_ADMIN "$IMAGE" > /dev/null \
    || die "server container failed"
docker run -d --name "$CLI" --network "$NET_NAME" --cap-add NET_ADMIN "$IMAGE" > /dev/null \
    || die "client container failed"
docker exec "$SRV" mkdir -p /tmp/dst
SRV_IP="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$SRV")"
[ -n "$SRV_IP" ] || die "no server IP"
log "Topology: srv=$SRV_IP on $NET_NAME"

apply_netem() {
    # Shape the data sender (client pushes), matching bench_netem_fair_v2.
    docker exec "$CLI" tc qdisc del dev eth0 root 2> /dev/null || true
    [ "$1" = "0" ] && [ "$3" = "0" ] && return
    # limit 100000: the default 1000-packet queue turns a model loss rate
    # into burst loss at these rates, which is not what we are measuring.
    if [ "$2" = "0" ]; then
        docker exec "$CLI" tc qdisc add dev eth0 root netem limit 100000 delay "${1}ms" loss "${3}%"
    else
        docker exec "$CLI" tc qdisc add dev eth0 root netem limit 100000 delay "${1}ms" "${2}ms" loss "${3}%"
    fi
}

CSV_FILE="$RESULTS_DIR/rl_ablation_$(date +%Y-%m-%d).csv"
[ -f "$CSV_FILE" ] || echo "scenario,delay,jitter,loss,arm,congestion,weights,run,elapsed_ms,throughput_mib_s,status,retx,notes" > "$CSV_FILE"

log "RL ABLATION: ${SIZE_MB}MB, ${RUNS} run(s), ${#SCENARIOS[@]} scenarios x ${#ARMS[@]} arms"

for scenario_str in "${SCENARIOS[@]}"; do
    IFS='|' read -r scenario delay jitter loss <<< "$scenario_str"
    if [ -n "$ONLY_SCENARIOS" ] && [[ ",$ONLY_SCENARIOS," != *",$scenario,"* ]]; then continue; fi
    log "=== $scenario (delay=${delay}ms jitter=${jitter}ms loss=${loss}%) ==="
    apply_netem "$delay" "$jitter" "$loss"

    for arm_str in "${ARMS[@]}"; do
        IFS='|' read -r arm cc use_weights <<< "$arm_str"

        for run in $(seq 1 "$RUNS"); do
            docker exec "$SRV" sh -c 'pkill -f favonius-daemon' 2> /dev/null || true
            docker exec "$CLI" sh -c 'pkill -x favonius' 2> /dev/null || true
            docker exec "$SRV" rm -f /tmp/dst/recv.bin 2> /dev/null || true
            sleep 0.5
            docker exec -d "$SRV" /opt/bench/bin/favonius-daemon \
                --listen 127.0.0.1:7800 --protocol-listen 0.0.0.0:7801 \
                --data-listen 0.0.0.0:7802 --dest-root /tmp/dst --log-level warn
            sleep 1.5

            logfile="$RESULTS_DIR/rl-ablation-${scenario}-${arm}-run${run}.log"
            # HOME is redirected so the ~/.config/favonius/rl_weights.bin
            # fallback path cannot resolve either — otherwise "no weights"
            # would silently still load weights.
            if [ "$use_weights" = "1" ]; then
                ENVS=(env HOME=/tmp/norl FAVONIUS_RL_MODEL=/opt/bench/rl_weights.bin)
            else
                ENVS=(env HOME=/tmp/norl -u FAVONIUS_RL_MODEL)
            fi

            start_ns=$(date +%s%N)
            timeout "$((TRANSFER_TIMEOUT + 15))" docker exec "$CLI" \
                timeout "$TRANSFER_TIMEOUT" \
                "${ENVS[@]}" \
                /opt/bench/bin/favonius send /data/test.bin \
                "$SRV_IP:7801:/tmp/dst/recv.bin" \
                --congestion "$cc" --pacing batch --compression none \
                --streams 4 --log-level warn \
                > "$logfile" 2>&1
            rc=$?
            end_ns=$(date +%s%N)
            elapsed_ms=$(( (end_ns - start_ns) / 1000000 ))

            sha="$(docker exec "$SRV" sha256sum /tmp/dst/recv.bin 2> /dev/null | awk '{print $1}')"
            if [ "$rc" = "124" ]; then
                status="TIMEOUT"
            elif [ -z "$sha" ]; then
                status="MISSING"
            elif [ "$sha" != "$SRC_SHA" ]; then
                status="CORRUPT"
            else
                status="OK"
            fi

            # A transfer that did not deliver the file has no throughput.
            # Recording one is how the earlier CSV ended up showing a tool
            # "winning" scenarios it never completed.
            if [ "$status" != "OK" ]; then
                elapsed_ms=0
                mibs=0
            else
                mibs=$(awk "BEGIN { printf \"%.2f\", ($DATA_BYTES / 1048576) / ($elapsed_ms / 1000) }")
            fi

            retx=$(grep -oP '\b\K[0-9]+(?= retx)' "$logfile" 2> /dev/null | tail -1)
            retx="${retx:-}"

            echo "$scenario,$delay,$jitter,$loss,$arm,$cc,$use_weights,$run,$elapsed_ms,$mibs,$status,$retx," >> "$CSV_FILE"
            log "  $arm run$run => ${elapsed_ms}ms ${mibs} MiB/s [$status] retx=${retx:-n/a}"
        done
    done
done

docker exec "$CLI" tc qdisc del dev eth0 root 2> /dev/null || true

log "CSV: $CSV_FILE"
echo
echo "=== median MiB/s by scenario x arm (OK runs only) ==="
awk -F, 'NR>1 && $11=="OK" { key=$1" "$5; v[key]=v[key]" "$10 }
END {
  for (k in v) {
    n=split(v[k], a, " "); c=0
    for (i=1;i<=n;i++) if (a[i]!="") b[++c]=a[i]+0
    for (i=1;i<c;i++) for (j=i+1;j<=c;j++) if (b[j]<b[i]) { t=b[i];b[i]=b[j];b[j]=t }
    printf "%-28s %8.2f  (n=%d)\n", k, (c%2)?b[(c+1)/2]:(b[c/2]+b[c/2+1])/2, c
  }
}' "$CSV_FILE" | sort
