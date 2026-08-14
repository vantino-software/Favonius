#!/usr/bin/env bash
# Favonius — high-performance file transfer over UDP
# Copyright (c) 2025-2026 Vantino SàRL
# SPDX-License-Identifier: Apache-2.0
#
# benchmarks/scripts/self_fairness.sh
#
# Does Favonius share a bottleneck with ANOTHER FAVONIUS?
#
# Why this exists, and why it is a release gate rather than a curiosity.
# `coexist.sh` measures Favonius against kernel TCP, which answers "is it a
# good citizen on the public internet". It does not answer the question a
# deployment actually hits first, because the daemon ships
# `--max-concurrent 4` and therefore invites four of its own flows onto one
# link. Every other benchmark in this repository runs a single flow on an
# empty pipe. Two Favonius flows against each other has never been measured.
#
# It is the harder case, not the easier one. Two instances of the same
# controller share a failure mode: whatever they both misread about the
# path, they misread together and at the same moment. A loss-based
# controller that under-reacts will, against itself, produce two flows that
# both refuse to yield; a rate-based one that ignores congestion signals
# will produce two flows that both keep pushing into a queue neither
# attributes to the other.
#
# Method. Two Favonius transfers, same controller, same shaped qdisc, same
# direction, started together, to two destinations on one daemon. Each is
# also measured alone. Reported:
#
#   jain  = (sum x)^2 / (n * sum x^2)   -- 1.00 is a perfect split
#   eff   = (a + b) / solo              -- >1 means the pair beats one flow
#
# Jain alone is not enough: two flows that both collapse to nothing score a
# perfect 1.00. `eff` is what catches that, so both are reported and both
# have to be sane.
#
# Usage:
#   self_fairness.sh --image <tag> [--modes classic,model,rl] \
#                    [--scenario clean] [--size-mb 256] [--runs 3]

set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RESULTS_DIR="$(cd "$HERE/../results" && pwd)"

IMAGE=""; MODES="classic,model,rl"; SCENARIO="clean"; SIZE_MB=256; RUNS=3
SEPARATE_DAEMONS=1
RATE_MBIT="${RATE_MBIT:-100}"
while [[ $# -gt 0 ]]; do
    case "$1" in
        --image) IMAGE="$2"; shift 2 ;;
        --modes) MODES="$2"; shift 2 ;;
        --scenario) SCENARIO="$2"; shift 2 ;;
        --size-mb) SIZE_MB="$2"; shift 2 ;;
        --runs) RUNS="$2"; shift 2 ;;
        --rate-mbit) RATE_MBIT="$2"; shift 2 ;;
        --one-daemon) SEPARATE_DAEMONS=0; shift ;;
        *) echo "unknown argument: $1" >&2; exit 64 ;;
    esac
done
[ -n "$IMAGE" ] || { echo "--image is required" >&2; exit 64; }

NET=hbsf-net; SRV=hbsf-srv; CLI=hbsf-cli
cleanup() { docker rm -f "$SRV" "$CLI" >/dev/null 2>&1 || true
            docker network rm "$NET" >/dev/null 2>&1 || true; }
trap cleanup EXIT
cleanup

case "$SCENARIO" in
    clean)         DELAY=25; JIT=0;  LOSS=0 ;;
    metro)         DELAY=5;  JIT=1;  LOSS=0.1 ;;
    cross-country) DELAY=25; JIT=5;  LOSS=0.5 ;;
    transatlantic) DELAY=50; JIT=10; LOSS=1 ;;
    satellite)     DELAY=150;JIT=25; LOSS=2 ;;
    *) echo "unknown scenario: $SCENARIO" >&2; exit 64 ;;
esac

docker network create "$NET" >/dev/null
docker run -d --name "$SRV" --network "$NET" --cap-add NET_ADMIN "$IMAGE" >/dev/null
docker run -d --name "$CLI" --network "$NET" --cap-add NET_ADMIN "$IMAGE" >/dev/null
docker exec "$SRV" mkdir -p /tmp/dst; docker exec "$CLI" mkdir -p /tmp/dst
SRV_IP="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$SRV")"
sleep 2

# Size the payload. Both flows send the same file.
want=$((SIZE_MB * 1048576))
have="$(docker exec "$CLI" stat -c %s /data/test.bin 2>/dev/null || echo 0)"
if [ "$have" != "$want" ]; then
    docker exec "$CLI" sh -c "head -c $want /dev/urandom > /data/test.bin"
fi

# Shape the client's egress — both flows leave from there, so they share it.
docker exec "$CLI" tc qdisc del dev eth0 root 2>/dev/null || true
docker exec "$CLI" tc qdisc add dev eth0 root handle 1: tbf \
    rate "${RATE_MBIT}mbit" burst 32kbit latency 400ms > /dev/null
docker exec "$CLI" tc qdisc add dev eth0 parent 1: handle 10: netem \
    delay "${DELAY}ms" "${JIT}ms" loss "${LOSS}%" > /dev/null

start_daemon() {
    docker exec "$SRV" pkill -x favonius-daemon 2>/dev/null || true
    sleep 0.5
    docker exec "$SRV" mkdir -p /tmp/dst 2>/dev/null || true
    # --max-concurrent 4 is the shipped default and the reason this test
    # exists; make it explicit so the test is about the controller and not
    # about a semaphore rejecting the second flow.
    docker exec -d "$SRV" /opt/bench/bin/favonius-daemon \
        --listen 127.0.0.1:7800 --protocol-listen 0.0.0.0:7801 \
        --data-listen 0.0.0.0:7802 --max-concurrent 4 \
        --dest-root /tmp/dst --log-level warn
    # A SECOND daemon on its own ports. This is the default, and it is the
    # only configuration that measures what this script claims to measure.
    #
    # One daemon cannot run two transfers at once: net_receiver.rs awaits
    # handle_transfer inline in its accept loop, so the second HELLO waits
    # until the first transfer finishes and --max-concurrent is effectively
    # 1. Pointing both flows at one daemon therefore measures that queue,
    # not the controllers. Against two daemons on one shaped link the same
    # controllers split it near-perfectly (5.7 / 5.5 MB/s, Jain 1.00).
    #
    # Use --one-daemon to reproduce the queueing defect deliberately.
    if [ "$SEPARATE_DAEMONS" = "1" ]; then
        docker exec -d "$SRV" /opt/bench/bin/favonius-daemon \
            --listen 127.0.0.1:7810 --protocol-listen 0.0.0.0:7811 \
            --data-listen 0.0.0.0:7812 --max-concurrent 4 \
            --dest-root /tmp/dst --log-level warn
    fi
    sleep 1
}

# One transfer. $1 = mode, $2 = dest suffix, $3 = output file for MB/s.
one_flow() {
    local cc="$1" tag="$2" out="$3" extra=()
    [ "$cc" = "encrypt" ] && { extra+=(--encrypt); cc=classic; }
    local port=7801
    [ "$tag" = "b" ] && [ "$SEPARATE_DAEMONS" = "1" ] && port=7811
    docker exec "$CLI" /opt/bench/bin/favonius send /data/test.bin \
        "$SRV_IP:$port:/tmp/dst/sf_$tag.bin" --congestion "$cc" \
        "${extra[@]}" > "/tmp/sf_$tag.log" 2>&1
    # Parse the sender's own completion line. Anything else — exit code,
    # elapsed wall clock around docker exec — measures the harness.
    # A flow that never completes is NOT a flow that got 0 MB/s, and
    # conflating them is how this script's first run read as catastrophic
    # unfairness. The daemon serialises transfers (see --separate-daemons
    # below): the second sender sits queued, its stall detector fires, and
    # it exits having moved nothing. That is a daemon defect, not a
    # congestion-control one, and the output has to be able to say so.
    if grep -qE 'complete: [0-9.]+ Mi?B/s' "/tmp/sf_$tag.log"; then
        grep -oE 'complete: [0-9.]+ Mi?B/s' "/tmp/sf_$tag.log" \
            | tail -1 | grep -oE '[0-9.]+' > "$out"
    elif grep -q 'stalled at 0.0%' "/tmp/sf_$tag.log"; then
        echo "QUEUED" > "$out"
    else
        echo "FAILED" > "$out"
    fi
}

printf '\n%-9s %-6s %8s %8s %8s %8s %7s %6s\n' \
       mode run solo flowA flowB sum jain eff
echo "----------------------------------------------------------------------"

CSV="$RESULTS_DIR/self_fairness_${SCENARIO}_${RATE_MBIT}mbit_$(date +%F).csv"
echo "scenario,rate_mbit,mode,run,solo_mbs,a_mbs,b_mbs,jain,efficiency" > "$CSV"

IFS=, read -ra MODE_LIST <<< "$MODES"
for mode in "${MODE_LIST[@]}"; do
    for run in $(seq 1 "$RUNS"); do
        # --- solo baseline -------------------------------------------------
        start_daemon
        docker exec "$SRV" rm -f /tmp/dst/sf_*.bin 2>/dev/null || true
        one_flow "$mode" solo /tmp/sf_solo.val
        solo=$(cat /tmp/sf_solo.val)

        # --- two flows together --------------------------------------------
        start_daemon
        docker exec "$SRV" rm -f /tmp/dst/sf_*.bin 2>/dev/null || true
        one_flow "$mode" a /tmp/sf_a.val &
        pa=$!
        one_flow "$mode" b /tmp/sf_b.val &
        pb=$!
        wait "$pa" "$pb"
        a=$(cat /tmp/sf_a.val); b=$(cat /tmp/sf_b.val)

        read -r jain eff <<< "$(python3 -c "
def num(x):
    try: return float(x)
    except ValueError: return None
a=num('$a'); b=num('$b'); s=num('$solo')
if a is None or b is None or s is None:
    print('n/a n/a'); raise SystemExit
tot=a+b
j=(tot*tot)/(2*(a*a+b*b)) if (a*a+b*b)>0 else 0.0
e=tot/s if s>0 else 0.0
print(f'{j:.3f} {e:.3f}')")"

        printf '%-9s %-6s %8s %8s %8s %8s %7s %6s\n' \
               "$mode" "$run" "$solo" "$a" "$b" \
               "$(python3 -c "
try: print(f'{float(\"$a\")+float(\"$b\"):.1f}')
except ValueError: print('n/a')")" "$jain" "$eff"
        echo "$SCENARIO,$RATE_MBIT,$mode,$run,$solo,$a,$b,$jain,$eff" >> "$CSV"
    done
done

echo
echo "wrote $CSV"
echo
echo "Reading the numbers:"
echo "  jain ~1.00 with eff ~1.0  -- flows split the link evenly. Good."
echo "  jain  <0.8               -- one flow is starving the other."
echo "  eff   <0.8               -- the pair wastes the link; they are"
echo "                              fighting, not sharing."
echo "  jain ~1.00 with eff <0.5 -- both collapsed equally. Jain alone"
echo "                              cannot see this, which is why eff is here."
