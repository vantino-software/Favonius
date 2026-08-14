#!/usr/bin/env bash
# Favonius — high-performance file transfer over UDP
# Copyright (c) 2025-2026 Vantino SàRL
# SPDX-License-Identifier: Apache-2.0
#
# benchmarks/scripts/bench_ab_ccfix.sh
#
# Interleaved A/B: pre-fix vs post-fix Favonius congestion control.
#
# WHY INTERLEAVED. The absolute numbers on this host are not trustworthy —
# there is no bottleneck rate limit, so an unshaped scenario measures
# send-path CPU, and the box is shared with unrelated jobs. Comparing a run
# taken now against one taken hours ago conflates the code change with
# whatever else the machine was doing. Alternating the two binaries back to
# back within each run makes host load a common-mode term that largely
# cancels in the A/B *ratio*, even while it wrecks both absolute values.
#
# Two complete topologies are stood up in parallel, one per binary, so the
# alternation costs no container churn:
#   abA-*  favonius-bench:v2-prefix   (pre-fix: fixed 100ms RTO, Karn bug,
#                                     wall-clock rounds, no loss signal)
#   abB-*  favonius-bench:v2-ccfix    (post-fix)
#
# The `rl` arm is the control: its controller was not touched, so any A/B
# difference there is measurement noise and bounds how much of the classic
# delta is real.
#
# Load average is recorded per row — a row taken under load 10 is not
# comparable to one taken under load 1, and the CSV should say so.
#
# Usage: ./benchmarks/scripts/bench_ab_ccfix.sh [--runs N] [--scenarios a,b]

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
RESULTS_DIR="$REPO_ROOT/benchmarks/results"
mkdir -p "$RESULTS_DIR"

IMAGE_A="${IMAGE_A:-favonius-bench:v2-prefix}"
IMAGE_B="${IMAGE_B:-favonius-bench:v2-ccfix}"
# Bottleneck rate in Mbit/s (0 = unshaped, the historical behaviour).
# Without one there is no capacity to converge to, so a window past the
# BDP costs nothing and no congestion-control comparison is well founded.
RATE_MBIT="${RATE_MBIT:-0}"
QUEUE_BDP="${QUEUE_BDP:-1.0}"
SIZE_MB="${SIZE_MB:-128}"
RUNS="${RUNS:-3}"
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

# The scenarios the CC fixes target are satellite and degraded, whose RTTs
# sat at or past the old fixed 100 ms retransmit timer. cross-country is
# the control: RTT well under the timer, so no storm to fix and no change
# expected.
SCENARIOS=(
    "metro|5|1|0.1"
    "cross-country|25|5|0.5"
    "transatlantic|50|10|1"
    "satellite|150|25|2"
    "degraded|100|25|5"
)
CCS=("classic" "rl")

log() { echo "[$(date +%H:%M:%S)] $*"; }
die() { echo "ERROR: $*" >&2; exit 1; }

for img in "$IMAGE_A" "$IMAGE_B"; do
    docker image inspect "$img" > /dev/null 2>&1 || die "image $img missing"
done
SRC_SHA="$(docker run --rm "$IMAGE_A" sha256sum /data/test.bin | awk '{print $1}')"
SRC_SHA_B="$(docker run --rm "$IMAGE_B" sha256sum /data/test.bin | awk '{print $1}')"
[ "$SRC_SHA" = "$SRC_SHA_B" ] || die "images carry different /data/test.bin — not comparable"
log "Both images share test.bin sha256: ${SRC_SHA:0:16}..."

cleanup() {
    docker rm -f abA-srv abA-cli abB-srv abB-cli > /dev/null 2>&1 || true
    docker network rm abA-net abB-net > /dev/null 2>&1 || true
}
trap cleanup EXIT
cleanup

declare -A SRV_IP
for arm in A B; do
    img_var="IMAGE_$arm"; img="${!img_var}"
    docker network create "ab${arm}-net" > /dev/null || die "network create failed"
    docker run -d --name "ab${arm}-srv" --network "ab${arm}-net" --cap-add NET_ADMIN "$img" > /dev/null \
        || die "srv $arm failed"
    docker run -d --name "ab${arm}-cli" --network "ab${arm}-net" --cap-add NET_ADMIN "$img" > /dev/null \
        || die "cli $arm failed"
    docker exec "ab${arm}-srv" mkdir -p /tmp/dst
    SRV_IP[$arm]="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "ab${arm}-srv")"
    [ -n "${SRV_IP[$arm]}" ] || die "no IP for arm $arm"
done
log "Topologies up: A(prefix)=${SRV_IP[A]}  B(ccfix)=${SRV_IP[B]}"

apply_netem() {
    # Shape both clients identically; the sender is the client in both arms.
    # netem is the root (delay/loss) and tbf hangs beneath it (rate +
    # bounded queue), so the queue congestion control contends with is
    # tbf's and its depth is known rather than tangled with netem's delay
    # buffer.
    local burst limit
    burst=$(awk -v r="$RATE_MBIT" 'BEGIN {
        b = r * 1000000 / 8 / 100; if (b < 131072) b = 131072; printf "%d", b }')
    limit=$(awk -v r="$RATE_MBIT" -v d="$1" -v q="$QUEUE_BDP" -v b="$burst" 'BEGIN {
        bdp = (r * 1000000 / 8) * (d / 1000); lim = bdp * q
        if (lim < 2 * b) lim = 2 * b            # tbf drops all if limit < burst
        printf "%d", lim }')
    for arm in A B; do
        docker exec "ab${arm}-cli" tc qdisc del dev eth0 root 2> /dev/null || true
        local want_netem=1
        [ "$1" = "0" ] && [ "$3" = "0" ] && want_netem=0
        if [ "$want_netem" = "1" ]; then
            if [ "$2" = "0" ]; then
                docker exec "ab${arm}-cli" tc qdisc add dev eth0 root handle 1: \
                    netem limit 100000 delay "${1}ms" loss "${3}%"
            else
                docker exec "ab${arm}-cli" tc qdisc add dev eth0 root handle 1: \
                    netem limit 100000 delay "${1}ms" "${2}ms" loss "${3}%"
            fi
        fi
        if [ "$RATE_MBIT" != "0" ]; then
            if [ "$want_netem" = "1" ]; then
                docker exec "ab${arm}-cli" tc qdisc add dev eth0 parent 1: handle 10: \
                    tbf rate "${RATE_MBIT}mbit" burst "$burst" limit "$limit"
            else
                docker exec "ab${arm}-cli" tc qdisc add dev eth0 root handle 10: \
                    tbf rate "${RATE_MBIT}mbit" burst "$burst" limit "$limit"
            fi
        fi
    done
}

CSV="$RESULTS_DIR/ab_ccfix_${RATE_MBIT}mbit_$(date +%Y-%m-%d).csv"
[ -f "$CSV" ] || echo "scenario,delay,jitter,loss,cc,arm,build,run,elapsed_ms,throughput_mib_s,status,retx,pkts,loadavg" > "$CSV"

# one transfer; echoes "elapsed_ms status retx pkts"
run_one() {
    local arm="$1" cc="$2" scenario="$3" run="$4"
    local srv="ab${arm}-srv" cli="ab${arm}-cli" ip="${SRV_IP[$arm]}"

    docker exec "$srv" sh -c 'pkill -f favonius-daemon' 2> /dev/null || true
    docker exec "$cli" sh -c 'pkill -x favonius' 2> /dev/null || true
    docker exec "$srv" rm -f /tmp/dst/recv.bin 2> /dev/null || true
    sleep 0.4
    docker exec -d "$srv" /opt/bench/bin/favonius-daemon \
        --listen 127.0.0.1:7800 --protocol-listen 0.0.0.0:7801 \
        --data-listen 0.0.0.0:7802 --dest-root /tmp/dst --log-level warn
    sleep 1.2

    local logfile="$RESULTS_DIR/ab-${scenario}-${cc}-${arm}-run${run}.log"
    local s_ns e_ns rc
    s_ns=$(date +%s%N)
    timeout "$((TRANSFER_TIMEOUT + 15))" docker exec "$cli" \
        timeout "$TRANSFER_TIMEOUT" \
        env FAVONIUS_RL_MODEL=/opt/bench/rl_weights.bin \
        /opt/bench/bin/favonius send /data/test.bin "$ip:7801:/tmp/dst/recv.bin" \
        --congestion "$cc" --pacing batch --compression none \
        --streams 4 --log-level warn > "$logfile" 2>&1
    rc=$?
    e_ns=$(date +%s%N)
    local elapsed=$(( (e_ns - s_ns) / 1000000 ))

    local sha status
    sha="$(docker exec "$srv" sha256sum /tmp/dst/recv.bin 2> /dev/null | awk '{print $1}')"
    if [ "$rc" = "124" ]; then status="TIMEOUT"
    elif [ -z "$sha" ];   then status="MISSING"
    elif [ "$sha" != "$SRC_SHA" ]; then status="CORRUPT"
    else status="OK"; fi
    [ "$status" != "OK" ] && elapsed=0

    local retx pkts
    retx=$(grep -oP '\b\K[0-9]+(?= retx)' "$logfile" 2> /dev/null | tail -1)
    pkts=$(grep -oP '\b\K[0-9]+(?= pkts)' "$logfile" 2> /dev/null | tail -1)
    echo "$elapsed ${status} ${retx:-} ${pkts:-}"
}

log "A/B: ${SIZE_MB}MB, ${RUNS} interleaved run(s), ${#SCENARIOS[@]} scenarios x ${#CCS[@]} cc"
log "A=prefix  B=ccfix  (alternated back to back within each run)"

for scenario_str in "${SCENARIOS[@]}"; do
    IFS='|' read -r scenario delay jitter loss <<< "$scenario_str"
    if [ -n "$ONLY_SCENARIOS" ] && [[ ",$ONLY_SCENARIOS," != *",$scenario,"* ]]; then continue; fi
    log "=== $scenario (delay=${delay}ms jitter=${jitter}ms loss=${loss}%) ==="
    apply_netem "$delay" "$jitter" "$loss"

    for cc in "${CCS[@]}"; do
        for run in $(seq 1 "$RUNS"); do
            # Alternate the leading arm per run so that any slow drift in
            # host load does not systematically favour whichever goes first.
            if [ $((run % 2)) -eq 1 ]; then order=(A B); else order=(B A); fi
            for arm in "${order[@]}"; do
                # Record the image, not a positional label. Hardcoding
                # "prefix"/"ccfix" meant a second run appended rows whose
                # labels collided with the first, and merging them looked
                # entirely plausible.
                img_var="IMAGE_$arm"; build="${!img_var##*:}"
                loadavg=$(cut -d' ' -f1 /proc/loadavg)
                read -r elapsed status retx pkts <<< "$(run_one "$arm" "$cc" "$scenario" "$run")"
                mibs=0
                [ "$elapsed" -gt 0 ] && mibs=$(awk "BEGIN{printf \"%.2f\", ($DATA_BYTES/1048576)/($elapsed/1000)}")
                echo "$scenario,$delay,$jitter,$loss,$cc,$arm,$build,$run,$elapsed,$mibs,$status,${retx:-},${pkts:-},$loadavg" >> "$CSV"
                log "  $cc $build run$run => ${elapsed}ms ${mibs} MiB/s [$status] retx=${retx:-n/a} load=$loadavg"
            done
        done
    done
done

for arm in A B; do docker exec "ab${arm}-cli" tc qdisc del dev eth0 root 2> /dev/null || true; done
log "CSV: $CSV"

echo
echo "=== A/B medians (OK runs only): prefix -> ccfix ==="
awk -F, 'NR>1 && $11=="OK" { k=$1"|"$5"|"$7; v[k]=v[k]" "$10; r[k]=r[k]" "$12 }
END {
  for (k in v) {
    n=split(v[k],a," "); c=0
    for (i=1;i<=n;i++) if (a[i]!="") b[++c]=a[i]+0
    for (i=1;i<c;i++) for (j=i+1;j<=c;j++) if (b[j]<b[i]) { t=b[i];b[i]=b[j];b[j]=t }
    med[k] = (c%2)?b[(c+1)/2]:(b[c/2]+b[c/2+1])/2; cnt[k]=c
  }
  for (k in med) { split(k,p,"|"); key=p[1]"|"p[2]
    if (p[3]=="prefix") pre[key]=med[k]; else post[key]=med[k]
    n_[key]=cnt[k] }
  printf "%-16s %-8s %10s %10s %9s\n", "scenario","cc","prefix","ccfix","change"
  for (key in pre) { split(key,p,"|")
    ch = (pre[key]>0) ? sprintf("%+.0f%%", 100*(post[key]-pre[key])/pre[key]) : "n/a"
    printf "%-16s %-8s %10.2f %10.2f %9s\n", p[1], p[2], pre[key], post[key], ch }
}' "$CSV" | (read -r h; echo "$h"; sort)
