#!/usr/bin/env bash
# Favonius — high-performance file transfer over UDP
# Copyright (c) 2025-2026 Vantino SàRL
# SPDX-License-Identifier: Apache-2.0
#
#
# benchmarks/scripts/coexist.sh
#
# Does this controller share a bottleneck, or take it?
#
# Why this exists. Every benchmark in this repository runs one flow on an
# otherwise empty link. That measures how fast a controller is and says
# nothing about what it does to anything else using the same queue -- and
# the one previous shipped failure of this engine was exactly that: a model
# that held 60-62% retransmits and a permanent standing queue to buy an
# 8-10% goodput edge. On a dedicated link that is merely wasteful. On a
# shared one it is theft, and no test here could see it.
#
# A review panel on 2026-08-07 called this a ship gate rather than a
# research nicety, and it is the right call: a single-flow delay ratio
# under-reports what a controller does to a competing flow, so no
# congestion-control change should ship on single-flow numbers alone.
#
# Method. One Favonius transfer and one TCP (cubic) iperf3 flow cross the
# same shaped qdisc in the same direction, started together. Each is also
# measured alone. The interesting number is not either throughput but what
# the TCP flow retains when Favonius is present:
#
#     tcp_share = tcp_with_favonius / tcp_alone
#
# 1.0 means Favonius took nothing it was not owed. Two flows sharing a
# bottleneck fairly would each get about half, so ~0.5 is the *expected*
# value for a well-behaved controller, not a failure. Well below that is a
# controller that does not yield.
#
# Run it on a path where TCP is healthy. On the impaired scenarios cubic is
# loss-limited to a couple of Mbit by Mathis and occupies ~1.5% of the
# link, so any controller "passes" without yielding anything. Use `clean`
# or `metro`; the impaired ones are there for completeness.
#
# Usage:
#   coexist.sh --image <tag> [--modes classic,model,rl] [--scenario transatlantic]
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RESULTS_DIR="$(cd "$HERE/../results" && pwd)"

IMAGE=""; MODES="classic,model,rl"; SCENARIO="transatlantic"; SECS=20
RATE_MBIT="${RATE_MBIT:-100}"
while [[ $# -gt 0 ]]; do
    case "$1" in
        --image) IMAGE="$2"; shift 2 ;;
        --modes) MODES="$2"; shift 2 ;;
        --scenario) SCENARIO="$2"; shift 2 ;;
        --secs) SECS="$2"; shift 2 ;;
        *) echo "unknown argument: $1" >&2; exit 64 ;;
    esac
done
[ -n "$IMAGE" ] || { echo "--image is required" >&2; exit 64; }

NET=hbx-net; SRV=hbx-srv; CLI=hbx-cli
cleanup() { docker rm -f "$SRV" "$CLI" >/dev/null 2>&1 || true
            docker network rm "$NET" >/dev/null 2>&1 || true; }
trap cleanup EXIT
cleanup

case "$SCENARIO" in
    # A path where TCP is *healthy* is the one that actually tests
    # coexistence. On transatlantic (1% loss) cubic collapses to 1.5 Mbit of
    # a 100 Mbit link by Mathis, so it is using 1.5% of the bottleneck and
    # nothing Favonius does can starve it -- the test passes trivially and
    # proves nothing. `clean` and `metro` are where contention is real.
    clean)         DELAY=25; JIT=0;  LOSS=0 ;;
    metro)         DELAY=5;  JIT=1;  LOSS=0.1 ;;
    cross-country) DELAY=25; JIT=5;  LOSS=0.5 ;;
    transatlantic) DELAY=50; JIT=10; LOSS=1 ;;
    satellite)     DELAY=150;JIT=25; LOSS=2 ;;
    degraded)      DELAY=100;JIT=25; LOSS=5 ;;
    *) echo "unknown scenario: $SCENARIO" >&2; exit 64 ;;
esac

# Let docker pick the subnet and discover the addresses, as
# bench_netem_fair_v2.sh does. Pinning 172.31.0.0/24 collided with another
# network on this host and every transfer failed with "deadline has
# elapsed", which reads exactly like a congestion-control failure.
docker network create "$NET" >/dev/null
docker run -d --name "$SRV" --network "$NET" --cap-add NET_ADMIN "$IMAGE" >/dev/null
docker run -d --name "$CLI" --network "$NET" --cap-add NET_ADMIN "$IMAGE" >/dev/null
docker exec "$SRV" mkdir -p /tmp/dst
docker exec "$CLI" mkdir -p /tmp/dst
SRV_IP="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$SRV")"
sleep 2

# Shape the client's egress: both flows leave from there, so they share it.
docker exec "$CLI" tc qdisc del dev eth0 root 2>/dev/null || true
docker exec "$CLI" tc qdisc add dev eth0 root handle 1: tbf \
    rate "${RATE_MBIT}mbit" burst 32kbit latency 400ms >/dev/null
docker exec "$CLI" tc qdisc add dev eth0 parent 1: handle 10: netem \
    delay "${DELAY}ms" "${JIT}ms" loss "${LOSS}%" >/dev/null

start_daemon() {
    # The main harness creates this; without it every transfer fails with
    # "deadline has elapsed", which looks like a congestion problem.
    docker exec "$SRV" mkdir -p /tmp/dst 2>/dev/null || true
    docker exec "$CLI" mkdir -p /tmp/dst 2>/dev/null || true
    docker exec "$SRV" pkill -x favonius-daemon 2>/dev/null || true
    docker exec -d "$SRV" /opt/bench/bin/favonius-daemon \
        --listen 127.0.0.1:7800 --protocol-listen 0.0.0.0:7801 \
        --data-listen 0.0.0.0:7802 --dest-root /tmp/dst --log-level warn
    sleep 1
}
start_iperf_srv() {
    docker exec "$SRV" pkill -x iperf3 2>/dev/null || true
    docker exec -d "$SRV" iperf3 -s -1 >/dev/null 2>&1
    sleep 1
}
favonius_run() {  # $1 = mode ; prints MB/s
    local cc="$1" extra=()
    [ "$cc" = "encrypt" ] && { extra+=(--encrypt); cc=classic; }
    docker exec "$CLI" rm -f /tmp/dst/recv.bin 2>/dev/null || true
    docker exec "$SRV" rm -f /tmp/dst/recv.bin 2>/dev/null || true
    # Forward every FAVONIUS_* variable, for the reason recorded in
    # bench_netem_fair_v2.sh: `docker exec` does not inherit the caller's
    # environment, and an explicit whitelist drops overrides silently —
    # which produced six no-op parameter sweeps on 2026-08-09.
    local favonius_env=()
    local _v
    for _v in $(compgen -v | grep '^FAVONIUS_' || true); do
        [ "$_v" = "FAVONIUS_RL_MODEL" ] && continue
        favonius_env+=("$_v=${!_v}")
    done
    [ "${#favonius_env[@]}" -gt 0 ] && echo "    env -> container: ${favonius_env[*]}" >&2
    timeout 180 docker exec "$CLI" env FAVONIUS_RL_MODEL=/opt/bench/rl_weights.bin \
        ${favonius_env[@]+"${favonius_env[@]}"} \
        /opt/bench/bin/favonius send /data/test.bin "$SRV_IP:7801:/tmp/dst/recv.bin" \
        --congestion "$cc" --pacing batch --compression none --streams 4 \
        --log-level warn "${extra[@]}" 2>&1 | grep -oP 'complete: \K[0-9.]+(?= Mi?B/s)' | tail -1
}
iperf_run() {    # prints Mbit/s
    timeout $((SECS + 20)) docker exec "$CLI" iperf3 -c "$SRV_IP" -t "$SECS" -J 2>/dev/null \
      | grep -A5 '"sum_sent"' | grep -oP '"bits_per_second":\s*\K[0-9.]+' | head -1 \
      | awk '{printf "%.2f", $1/1e6}'
}

echo "coexistence on $SCENARIO (${DELAY}ms/${JIT}ms/${LOSS}%), ${RATE_MBIT}Mbit shared"
echo

start_iperf_srv; TCP_ALONE=$(iperf_run)
echo "  TCP (cubic) alone: ${TCP_ALONE} Mbit/s"
echo
printf "  %-9s %10s %10s %12s %10s %9s\n" mode "hesp solo" "hesp+tcp" "tcp+hesp" "tcp alone" "tcp share"

# A controller that leaves TCP less than this fraction of its solo
# throughput is not sharing. Perfect fairness between two flows is 0.50, so
# 0.35 allows a controller to be somewhat greedy before failing -- it is a
# floor against the previous shipped failure (a permanent standing queue
# bought with 60% retransmits), not a fairness target.
FAIL_BELOW="${FAIL_BELOW:-0.35}"
failures=0

IFS=',' read -r -a MODE_LIST <<< "$MODES"
for m in "${MODE_LIST[@]}"; do
    start_daemon
    SOLO=$(favonius_run "$m")

    start_daemon; start_iperf_srv
    TMP=$(mktemp)
    ( iperf_run > "$TMP" ) &
    IPERF_PID=$!
    sleep 1
    TOGETHER=$(favonius_run "$m")
    wait "$IPERF_PID" 2>/dev/null || true
    TCP_TOGETHER=$(cat "$TMP"); rm -f "$TMP"

    share=$(awk -v tt="$TCP_TOGETHER" -v ta="$TCP_ALONE" 'BEGIN{
        printf "%.4f", (ta>0 && tt!="" ? tt/ta : 0)}')
    verdict=$(awk -v sh="$share" -v f="$FAIL_BELOW" 'BEGIN{print (sh<f ? "  DOES NOT SHARE" : "")}')
    [ -n "$verdict" ] && failures=$((failures + 1))
    awk -v m="$m" -v s="$SOLO" -v t="$TOGETHER" -v tt="$TCP_TOGETHER" -v ta="$TCP_ALONE" \
        -v sh="$share" -v v="$verdict" 'BEGIN{
        printf "  %-9s %7s MB/s %7s MB/s %8s Mbit %7s Mbit %8.2f%s\n",
               m, (s==""?"-":s), (t==""?"-":t), (tt==""?"-":tt), (ta==""?"-":ta), sh, v}'
done

echo
if [ "$failures" != 0 ]; then
    echo "$failures controller(s) left TCP below ${FAIL_BELOW} of its solo throughput."
    exit 1
fi
echo "All controllers left TCP at or above ${FAIL_BELOW} of its solo throughput."
echo "(0.50 is an equal share of the bottleneck; above that is yielding more"
echo " than half.)"
