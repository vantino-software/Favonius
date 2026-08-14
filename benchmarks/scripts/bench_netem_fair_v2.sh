#!/usr/bin/env bash
# Favonius — high-performance file transfer over UDP
# Copyright (c) 2025-2026 Vantino SàRL
# SPDX-License-Identifier: Apache-2.0
#
# benchmarks/scripts/bench_netem_fair_v2.sh
#
# Fair cross-tool impaired-network benchmark, Docker-based (v2).
#
# Replaces bench_netem.sh / bench_netem_fair.sh, which shaped the host
# loopback: UDT C++ bypassed the lo qdisc entirely and netem on lo doubled
# the delay. Here every byte of every tool crosses a shaped qdisc:
#
#   - Two containers (hbv2-srv, hbv2-cli) on a dedicated docker bridge.
#   - tc netem is applied on the DATA SENDER's eth0 egress, so the delay is
#     a true ONE-WAY delay (unlike the old loopback setup where it was hit
#     twice). ACKs return unimpeded.
#   - Which container is shaped depends on the tool's data direction:
#       favonius (client push)  -> shape hbv2-cli
#       uftp   (sender push)   -> shape hbv2-cli
#       quic / udt / tsunami (server push) -> shape hbv2-srv
#
# No host network state is touched (no host tc, no netns).
#
# Usage:
#   ./benchmarks/scripts/bench_netem_fair_v2.sh [--runs N] [--tools a,b,c]
#
# Env: SIZE_MB (128), RUNS (1), TRANSFER_TIMEOUT (120), IMAGE, KEEP_CONTAINERS=1

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
CONTEXT_DIR="$REPO_ROOT/benchmarks/docker/bench-v2"
RESULTS_DIR="$REPO_ROOT/benchmarks/results"
mkdir -p "$RESULTS_DIR"

IMAGE="${IMAGE:-favonius-bench:v2}"

# Container and network names are overridable so two invocations can run
# against separate topologies. They were hardcoded, and the failure mode
# was ugly: a second invocation's setup() calls cleanup(), which does
# `docker rm -f` on the shared names and kills the first run's transfers
# mid-flight. Those show up as MISSING(rc=137) — 128+9, SIGKILL — with a
# plausible-looking elapsed time attached.
#
# Note this only prevents the two runs from destroying each other's
# containers. They still share the host CPU, and these are timing
# measurements, so running two benchmarks at once remains a bad idea.
# Use INSTANCE to namespace everything at once:
#   INSTANCE=rerun ./bench_netem_fair_v2.sh --tools favonius
INSTANCE="${INSTANCE:-}"
_suffix="${INSTANCE:+-$INSTANCE}"
NET_NAME="${NET_NAME:-hbv2${_suffix}-net}"
SRV="${SRV:-hbv2${_suffix}-srv}"
CLI="${CLI:-hbv2${_suffix}-cli}"
# Bottleneck rate in Mbit/s. 0 disables shaping entirely, which is the
# historical behaviour and remains the default so existing invocations are
# unchanged.
#
# Without a rate limit there is no bottleneck: netem drops a fixed
# fraction and forwards the rest at bridge speed, so a window past the BDP
# costs nothing, queueing delay never builds, and no congestion-control
# claim from the results is well founded. The unshaped "baseline" scenario
# in particular measures send-path CPU, not transport.
# Apply the per-scenario jitter. Off by default.
#
# netem's `delay X Y` assigns each packet an independent random delay, so
# packets can overtake one another. That is far more reordering than real
# paths produce within a flow, and tools differ enormously in how they
# tolerate it — UDT treats a sequence gap as loss and NAKs immediately, so
# it collapses. Measured on metro (5 ms, 0.1% loss), twice each:
#
#   delay 5ms 1ms loss 0.1%  ->  13 MB of 128 MB, timeout
#   delay 5ms      loss 0.1%  ->  128 MB, complete
#
# With jitter on, the benchmark largely measures reordering tolerance
# rather than transport efficiency, and it did: UDT completed only the one
# scenario configured without jitter. Delay, loss and a bottleneck are
# modelled by default; reordering is a separate axis and should be tested
# deliberately with JITTER=1 rather than confounding every other result.
JITTER="${JITTER:-0}"
RATE_MBIT="${RATE_MBIT:-0}"
# Tsunami's rate, defaulting to 80% of the shaped link.
#
# Tsunami is a 2006 fixed-rate protocol with no congestion control, and its
# own inter-packet-delay control overshoots whatever it is told: set to the
# link rate exactly it reached 120 Mbps on a 100 Mbit link, hit 17%
# retransmits at 2.1 s, filled its 2048-entry retransmit ring and wedged
# permanently with 40,307 blocks undelivered. At 80 Mbit it completes
# cross-country in 39.1 s at 3.27 MB/s, sha256-verified.
#
# So it needs headroom, and giving it headroom is the fair configuration --
# it is what a competent operator would do with a protocol that cannot
# discover capacity for itself. The previous setting was a hardcoded
# `4000M`, forty times the bottleneck, which timed out in every cell
# including baseline (zero delay, zero loss). That was a measurement of our
# configuration, not of tsunami.
TSUNAMI_RATE="${TSUNAMI_RATE_MBIT:-$(( RATE_MBIT * 80 / 100 ))}"
# Bottleneck queue depth, as a multiple of the bandwidth-delay product.
# 1.0 is the classic sizing rule; 0.25 emulates a shallow-buffered link,
# and larger values emulate bufferbloat.
QUEUE_BDP="${QUEUE_BDP:-1.0}"
SIZE_MB="${SIZE_MB:-128}"
RUNS="${RUNS:-1}"
RUN_OFFSET="${RUN_OFFSET:-0}"
TRANSFER_TIMEOUT="${TRANSFER_TIMEOUT:-120}"
DATA_BYTES=$((SIZE_MB * 1048576))

# Favonius send-path pacing mode. `batch` was hardcoded here and is retained
# as the default so existing invocations are unchanged.
#
# It is not a neutral choice. Batch mode stages up to `batch_size` packets
# (default 256), flushes them in one burst, then sleeps
# `min(pace * n_flushed, 2ms)` -- see net_sender.rs. At 100 Mbit a packet
# costs ~120us, so a full batch owes ~30ms of pacing debt and pays 2ms of
# it. The pacer therefore cannot rate-limit below ~1.5 Gbit/s, the flow is
# governed by cwnd alone, and any congestion-control claim measured this
# way is a claim about the window, not the rate. Use PACING=perpacket to
# put the rate command on the wire.
PACING="${PACING:-batch}"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --runs) RUNS="$2"; shift 2 ;;
        --tools) ONLY_TOOLS="$2"; shift 2 ;;
        *) echo "Unknown arg: $1"; exit 1 ;;
    esac
done
ONLY_TOOLS="${ONLY_TOOLS:-}"

# Scenarios: name|delay_ms|jitter_ms|loss_pct[|queue_bdp]  (delay is true one-way)
#
# The optional 5th field overrides the global QUEUE_BDP for that scenario.
#
# Every scenario except `congested` injects *uniform random* loss, and that
# is the one condition under which loss-based congestion control is
# guaranteed to collapse -- Mathis puts sqrt(p) in the denominator, so at 5%
# kernel cubic gets 0.08% of a 1 Gbit link (measured, see
# `benchmarks/scripts/tcp_calibration.sh`). Every cross-protocol margin this
# harness has produced was measured under that model, and real WAN loss is
# mostly congestion-induced and bursty rather than uniform random.
#
# `congested` injects no loss at all. Its loss comes from a shallow
# bottleneck queue overflowing -- which is what a controller meets on a real
# path, and the only scenario here that tests whether these controllers
# respond to a congestion signal rather than to a coin flip. See
# the engineering log.
SCENARIOS=(
    "baseline|0|0|0"
    "metro|5|1|0.1"
    "cross-country|25|5|0.5"
    "transatlantic|50|10|1"
    "satellite|150|25|2"
    "degraded|100|25|5"
    "congested-lo|25|0|0|0.25"
    "congested|50|0|0|0.25"
    "congested-hi|150|0|0|0.25"
)

# Tools: tool|mode|shaped_container (srv|cli)
# quic-nogso only runs when explicitly requested via --tools quic-nogso
# (quinn-udp patched in the harness vendor/ tree to honor QUIC_BENCH_NO_GSO=1).
# Every congestion profile the CLI accepts is listed here. `fair`, `wifi`
# and `udt` were absent, which meant three shipped profiles had no
# measurement at all -- and that is how udt.rs kept a `max_cwnd`-used-as-a-
# floor bug for months after the identical defect was found, measured and
# fixed in rl.rs. A defect in an unmeasured controller cannot be found by
# the rig and cannot be shown fixed either, so a correct-looking change to
# one is unverifiable.
#
# Note `favonius|udt` is Favonius's UDT-style *congestion profile*, which is
# a different thing from the `udt` tool below (the C++ libudt reference
# implementation). Their log names do not collide: `favonius-udt-runN`
# against `udt-default-runN`.
TOOLS=(
    "favonius|classic|cli"
    "favonius|model|cli"
    "favonius|rl|cli"
    "favonius|encrypt|cli"
    "favonius|fair|cli"
    "favonius|wifi|cli"
    "favonius|udt|cli"
    "quic|cubic|srv"
    "udt|default|srv"
    "tsunami|linkrate|srv"
    "uftp|unicast|cli"
    # TCP, the comparison this table lacked for its whole existence.
    #
    # Every cross-tool number here was against other UDP tools, while the
    # claim the table is used to support — that loss-based TCP collapses on
    # long lossy paths — had no TCP column behind it. `-P 4` is included
    # because multi-stream TCP is what a real competitor does and what
    # Favonius's own 4-stream default should be read against.
    #
    # `bbr` is appended at runtime only if the kernel offers it: the modern
    # form of the claim is about loss-based CC, and BBR does not treat loss
    # as congestion, so testing only cubic would answer a question nobody
    # is asking in 2026.
    "tcp|cubic|cli"
    "tcp|cubic-p4|cli"
)
if sysctl -n net.ipv4.tcp_available_congestion_control 2>/dev/null | grep -qw bbr; then
    TOOLS+=("tcp|bbr|cli" "tcp|bbr-p4|cli")
else
    log "NOTE: kernel offers only '$(sysctl -n net.ipv4.tcp_available_congestion_control 2>/dev/null)' \
— BBR arms skipped. 'sudo modprobe tcp_bbr' to include them."
fi
[[ ",${ONLY_TOOLS:-}," == *",quic-nogso,"* ]] && TOOLS+=("quic-nogso|cubic-nogso|srv")

log() { echo "[$(date +%H:%M:%S)] $*"; }
die() { echo "ERROR: $*" >&2; exit 1; }

# ── Image ───────────────────────────────────────────────────────────────────

if ! docker image inspect "$IMAGE" > /dev/null 2>&1; then
    # Two images, two build contexts. The internal Dockerfile copies
    # prebuilt binaries sitting beside it, so its context is its own
    # directory. Dockerfile.public builds Favonius from source, so its
    # context has to be the repository root.
    if [ -f "$CONTEXT_DIR/Dockerfile" ]; then
        log "Image $IMAGE missing — building from $CONTEXT_DIR"
        docker build -t "$IMAGE" "$CONTEXT_DIR" > /dev/null || die "image build failed"
    elif [ -f "$CONTEXT_DIR/Dockerfile.public" ]; then
        log "Image $IMAGE missing — building Favonius from source (this takes a few minutes)"
        docker build -t "$IMAGE" -f "$CONTEXT_DIR/Dockerfile.public" "$REPO_ROOT" \
            > /dev/null || die "image build failed"
    else
        die "no Dockerfile in $CONTEXT_DIR"
    fi
fi

# SRC_SHA is computed in setup(), after the data file is sized, because
# SIZE_MB may replace it. See `size_data_file`.
SRC_SHA=""

# ── Topology ────────────────────────────────────────────────────────────────

cleanup() {
    docker rm -f "$SRV" "$CLI" > /dev/null 2>&1 || true
    docker network rm "$NET_NAME" > /dev/null 2>&1 || true
}
if [ "${KEEP_CONTAINERS:-0}" != "1" ]; then
    trap cleanup EXIT
fi


# Make /data/test.bin actually SIZE_MB, in every container that sends.
#
# SIZE_MB used to set `DATA_BYTES` and nothing else: the file is baked into
# the image at 128 MB, so asking for 512 changed the throughput arithmetic
# and not the transfer. A size comparison run that way returns the same
# number twice and reads as "size makes no difference", which is what
# happened on 2026-08-08 before the discrepancy was noticed.
#
# It matters most at high rates. 128 MB at 1 Gbit is about one second, which
# is shorter than slow start on any long path -- the measurement would be
# almost entirely ramp.
#
# The file is generated identically in both containers from a fixed pattern
# so the receiver-side sha check still means something, and SRC_SHA is taken
# from the sender afterwards rather than from the image.
size_data_file() {
    local want=$((SIZE_MB * 1048576))
    local have
    have="$(docker exec "$CLI" stat -c %s /data/test.bin 2> /dev/null || echo 0)"
    if [ "$have" != "$want" ]; then
        log "Sizing /data/test.bin to ${SIZE_MB}MB (was $((have / 1048576))MB)"
        for c in "$SRV" "$CLI"; do
            docker exec "$c" sh -c \
                "head -c $want /dev/urandom > /data/test.bin.tmp && mv /data/test.bin.tmp /data/test.bin" \
                || die "could not size data file in $c"
        done
        # Both containers generated independently, so they differ. The
        # receiver compares against the *sender's* file, so copy the
        # sender's into the server too.
        docker cp "$CLI":/data/test.bin /tmp/_bench_src.bin > /dev/null \
            || die "could not read generated file"
        docker cp /tmp/_bench_src.bin "$SRV":/data/test.bin > /dev/null \
            || die "could not place generated file"
        rm -f /tmp/_bench_src.bin
    fi
    SRC_SHA="$(docker exec "$CLI" sha256sum /data/test.bin | awk '{print $1}')"
    log "Source /data/test.bin: $((want / 1048576))MB sha256 ${SRC_SHA:0:16}"
}

setup() {
    # Refuse to bulldoze someone else's live topology. cleanup() below
    # force-removes these containers, so without this check a concurrent
    # invocation silently kills the other run's in-flight transfers.
    for c in "$SRV" "$CLI"; do
        if [ -n "$(docker ps -q --filter "name=^${c}$" 2>/dev/null)" ]; then
            die "container '$c' is already running — another benchmark is using it.
       Wait for it to finish, or namespace this run with INSTANCE=<name>."
        fi
    done
    cleanup
    docker network create "$NET_NAME" > /dev/null || die "network create failed"
    docker run -d --name "$SRV" --network "$NET_NAME" --cap-add NET_ADMIN \
        "$IMAGE" > /dev/null || die "server container failed"
    docker run -d --name "$CLI" --network "$NET_NAME" --cap-add NET_ADMIN \
        "$IMAGE" > /dev/null || die "client container failed"
    docker exec "$SRV" mkdir -p /tmp/dst
    docker exec "$CLI" mkdir -p /tmp/dst
    size_data_file
    SRV_IP="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$SRV")"
    CLI_IP="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$CLI")"
    [ -n "$SRV_IP" ] || die "no server IP"
    log "Topology: srv=$SRV_IP cli=$CLI_IP on $NET_NAME"
}

container_of() { [ "$1" = "srv" ] && echo "$SRV" || echo "$CLI"; }

# Bottleneck queue depth in bytes for a given delay, from RATE_MBIT and
# QUEUE_BDP. netem applies a *one-way* delay here and ACKs return
# unimpeded, so the RTT this path presents is the one-way figure and the
# BDP is rate x delay (not rate x 2 x delay).
#
# $3 is the queue depth in BDPs. It defaults to the global QUEUE_BDP but a
# scenario may override it (see the `queue` field in SCENARIOS) — a shallow
# bottleneck is the only way this harness can produce loss that congestion
# actually caused, rather than loss netem injected.
bdp_limit_bytes() {
    local delay_ms="$1" burst="$2" q="${3:-$QUEUE_BDP}"
    awk -v r="$RATE_MBIT" -v d="$delay_ms" -v q="$q" -v b="$burst" 'BEGIN {
        bytes_per_sec = r * 1000000 / 8
        bdp = bytes_per_sec * (d / 1000)
        lim = bdp * q
        # `limit` below `burst` leaves tbf unable to admit even one burst
        # of tokens, and it drops essentially everything — which presents
        # as a corrupt transfer rather than as a slow one. A zero-delay
        # path has a zero BDP, so this floor is what the baseline scenario
        # actually runs with.
        if (lim < 2 * b) lim = 2 * b
        printf "%d", lim
    }'
}

apply_netem() {
    # $1 = srv|cli (data sender), $2 delay, $3 jitter, $4 loss, $5 queue_bdp
    #
    # Sets EFF_QUEUE_BDP to the depth tbf was *actually* configured with,
    # which is not always the one requested: the `2 * burst` floor below
    # raises a shallow request, and at 1 Gbit that floor is 2.5 MB. Reading
    # the requested value back as though it were applied is exactly the
    # mistake the jitter field made for the whole history of this harness.
    local shaped; shaped="$(container_of "$1")"
    local queue_bdp="${5:-$QUEUE_BDP}"
    [ "$JITTER" = "1" ] || set -- "$1" "$2" 0 "$4"
    local other;  other="$([ "$1" = "srv" ] && echo "$CLI" || echo "$SRV")"
    docker exec "$other"  tc qdisc del dev eth0 root 2> /dev/null || true
    docker exec "$shaped" tc qdisc del dev eth0 root 2> /dev/null || true

    local want_netem=1
    [ "$2" = "0" ] && [ "$4" = "0" ] && want_netem=0
    [ "$want_netem" = "0" ] && [ "$RATE_MBIT" = "0" ] && return

    # netem is the root and tbf hangs beneath it: packets take the
    # propagation delay and loss first, then contend for the bottleneck.
    # The queue congestion control actually interacts with is tbf's, which
    # is why the two are separated rather than using netem's own `rate` —
    # netem's `limit` would otherwise conflate the delay buffer with the
    # bottleneck queue and make the effective queue depth unknowable.
    #
    # limit 100000 (~150MB) on netem: the delay queue must hold the
    # delay x rate product (default 1000 packets = 1.5MB overflows for any
    # tool pushing >300MB/s at 5ms or >10MB/s at 150ms, turning model loss
    # into burst loss).
    if [ "$want_netem" = "1" ]; then
        if [ "$3" = "0" ]; then
            docker exec "$shaped" tc qdisc add dev eth0 root handle 1: \
                netem delay "${2}ms" loss "${4}%" limit 100000
        else
            docker exec "$shaped" tc qdisc add dev eth0 root handle 1: \
                netem delay "${2}ms" "${3}ms" loss "${4}%" limit 100000
        fi
    fi

    if [ "$RATE_MBIT" != "0" ]; then
        local limit_bytes burst_bytes
        # burst must cover at least one timer tick's worth of tokens or tbf
        # cannot reach the configured rate; rate/100 with a 128 KB floor is
        # comfortably above that for every rate used here.
        burst_bytes=$(awk -v r="$RATE_MBIT" 'BEGIN {
            b = r * 1000000 / 8 / 100; if (b < 131072) b = 131072; printf "%d", b }')
        limit_bytes="$(bdp_limit_bytes "$2" "$burst_bytes" "$queue_bdp")"
        EFF_QUEUE_BDP="$(awk -v r="$RATE_MBIT" -v d="$2" -v l="$limit_bytes" 'BEGIN {
            bdp = (r * 1000000 / 8) * (d / 1000)
            if (bdp <= 0) { print "inf" } else { printf "%.2f", l / bdp } }')"
        if [ "$EFF_QUEUE_BDP" != "inf" ] && \
           awk -v e="$EFF_QUEUE_BDP" -v q="$queue_bdp" 'BEGIN{exit !(e > q * 1.05)}'; then
            log "  note: queue floor raised the bottleneck from ${queue_bdp} to ${EFF_QUEUE_BDP} BDP (2 x burst = $((burst_bytes * 2)) B)"
        fi
        if [ "$want_netem" = "1" ]; then
            docker exec "$shaped" tc qdisc add dev eth0 parent 1: handle 10: \
                tbf rate "${RATE_MBIT}mbit" burst "$burst_bytes" limit "$limit_bytes"
        else
            docker exec "$shaped" tc qdisc add dev eth0 root handle 10: \
                tbf rate "${RATE_MBIT}mbit" burst "$burst_bytes" limit "$limit_bytes"
        fi
    fi
}

# ── Server lifecycle helpers ────────────────────────────────────────────────

# Every binary this harness starts, by exact process name. `favonius-daemon`
# is 14 chars so it fits comm's 15-char field and -x matches it; verified
# rather than assumed, because the whole bug below turned on that detail.
BENCH_PROCS='favonius-daemon quic-bench sendfile recvfile tsunamid tsunami uftpd uftp favonius'

kill_servers() {
    # Kill both server- and client-side binaries (leftover clients can survive
    # a host-side timeout kill of `docker exec`).
    #
    # This ran `sh -c 'pkill -f favonius-daemon; pkill -x quic-bench; ...'`.
    # The `sh -c` process's own argv contains the whole command string,
    # including the literal text `favonius-daemon`, so `pkill -f` matched the
    # shell running it and killed it. The shell died at the first command
    # (exit 143 = SIGTERM) and *not one of the remaining pkills ever ran*.
    #
    # The result was invisible and expensive: favonius daemons were reaped
    # (first in the list) and nothing else ever was. tsunamid accumulated
    # eight copies spinning at 99.8% CPU for 69 minutes, flooding the
    # server's 100 Mbit tbf — 2.8M packets dropped in a 10s sample — which
    # starved every later server-shaped tool. quic and udt were recorded as
    # TIMEOUT in scenario after scenario and the CSV blamed the tools.
    #
    # No `-f` anywhere: matching on the full command line is what made a
    # kill list able to name itself.
    local p
    for p in $BENCH_PROCS; do
        docker exec "$SRV" pkill -x "$p" 2> /dev/null || true
        docker exec "$CLI" pkill -x "$p" 2> /dev/null || true
    done
    sleep 0.5

    # Escalate to SIGKILL for anything that ignored SIGTERM, then report
    # what is still standing. Silence here previously meant "no survivors"
    # only by assumption; a survivor is a bandwidth thief that corrupts
    # every subsequent cell, so it has to be loud.
    local c leftover
    for c in "$SRV" "$CLI"; do
        for p in $BENCH_PROCS; do
            docker exec "$c" pkill -9 -x "$p" 2> /dev/null || true
        done
    done
    sleep 0.2
    # Zombies do not count. tsunamid forks per session, and when the parent
    # is killed the children reparent to the container's PID 1, which is a
    # plain `sleep`-style command that never calls wait(). They show in ps
    # as STAT Z with a stale %CPU, but hold no sockets and cannot send a
    # packet, so they are not what corrupts a measurement. Warning about
    # them trains the reader to ignore the warning that matters.
    for c in "$SRV" "$CLI"; do
        leftover="$(docker exec "$c" sh -c \
            'ps -eo stat=,comm= 2>/dev/null' 2> /dev/null \
            | awk -v list="$BENCH_PROCS" '
                BEGIN { n = split(list, a, " "); for (i = 1; i <= n; i++) want[a[i]] = 1 }
                $1 ~ /^Z/ { next }
                $2 in want { seen[$2]++ }
                END { for (p in seen) printf "%s x%s ", p, seen[p] }')"
        [ -n "$leftover" ] && log "  WARNING: live survivors in $c after SIGKILL: $leftover"
    done
    return 0
}

clean_dst() {
    docker exec "$SRV" rm -f /tmp/dst/recv.bin /tmp/dst/quic.bin /tmp/dst/udt.bin /tmp/dst/tsunami.bin /tmp/dst/test.bin 2> /dev/null || true
    docker exec "$CLI" rm -f /tmp/dst/recv.bin /tmp/dst/quic.bin /tmp/dst/udt.bin /tmp/dst/tsunami.bin /tmp/dst/test.bin 2> /dev/null || true
}

start_server() {
    case "$1" in
        favonius)
            # --dest-root is mandatory: the daemon refuses to start without
            # it (it would otherwise accept arbitrary sender-chosen absolute
            # paths). Omitting it here made every cell report
            # MISSING(rc=1) — a harness failure that looks exactly like a
            # transport regression.
            docker exec -d "$SRV" /opt/bench/bin/favonius-daemon \
                --listen 127.0.0.1:7800 \
                --protocol-listen 0.0.0.0:7801 \
                --data-listen 0.0.0.0:7802 \
                --dest-root /tmp/dst \
                --log-level warn
            ;;
        quic)
            docker exec -d "$SRV" /opt/bench/bin/quic-bench server --addr 0.0.0.0:4433
            ;;
        quic-nogso)
            docker exec -d "$SRV" env QUIC_BENCH_NO_GSO=1 /opt/bench/bin/quic-bench server --addr 0.0.0.0:4433
            ;;
        udt)
            docker exec -d "$SRV" /opt/bench/bin/sendfile 9000
            ;;
        tsunami)
            docker exec -d -w /data "$SRV" /opt/bench/bin/tsunamid
            ;;
        uftp)
            docker exec -d "$SRV" /opt/bench/bin/uftpd -d -D /tmp/dst -B 20971520
            ;;
        tcp)
            # iperf3 is already in the image. One-shot server; the client
            # below transfers a fixed byte count so the comparison is
            # "same bytes, same shaped path" as every other tool, not a
            # fixed-duration rate test.
            docker exec -d "$SRV" iperf3 -s -1
            ;;
    esac
    sleep 1.5
}

# run_client <tool> <mode> <logfile> ; echoes nothing, sets global RC
run_client() {
    local tool="$1" mode="$2" logfile="$3"
    case "$tool" in
        favonius)
            local extra=()
            [ "$mode" = "encrypt" ] && extra+=(--encrypt)
            # `encrypt` is a transport variant that still uses classic;
            # every other mode names its congestion profile directly.
            local cc="$mode"
            [ "$mode" = "encrypt" ] && cc="classic"
            # Forward every FAVONIUS_* variable set in the caller's
            # environment.
            #
            # `docker exec` does not inherit the caller's environment, so an
            # explicit whitelist silently drops anything not on it. Six
            # parameter sweeps on 2026-08-09 ran three identical arms each
            # because FAVONIUS_MODEL_PROBE_GAIN, FAVONIUS_MODEL_CWND_GAIN,
            # FAVONIUS_MODEL_BW_WINDOW, FAVONIUS_MODEL_DR_DIV,
            # FAVONIUS_PACING_BURST_US and FAVONIUS_RL_CWND_GAIN were all
            # dropped here. Every one of them read as "no effect", and one
            # of those non-results was committed as a default. The failure
            # is silent by construction: the run completes, the numbers look
            # plausible, and nothing distinguishes it from a real null.
            local favonius_env=()
            local _v
            for _v in $(compgen -v | grep '^FAVONIUS_' || true); do
                case "$_v" in
                    FAVONIUS_RL_MODEL|FAVONIUS_PACE_DEBUG|FAVONIUS_CC_DEBUG) continue ;;
                esac
                favonius_env+=("$_v=${!_v}")
            done
            if [ "${#favonius_env[@]}" -gt 0 ]; then
                log "  env -> container: ${favonius_env[*]}"
            fi
            timeout "$((TRANSFER_TIMEOUT + 15))" docker exec "$CLI" \
                timeout "$TRANSFER_TIMEOUT" \
                env FAVONIUS_RL_MODEL=/opt/bench/rl_weights.bin \
                    FAVONIUS_PACE_DEBUG="${FAVONIUS_PACE_DEBUG:-0}" \
                    FAVONIUS_CC_DEBUG="${FAVONIUS_CC_DEBUG:-0}" \
                    ${favonius_env[@]+"${favonius_env[@]}"} \
                /opt/bench/bin/favonius send /data/test.bin \
                "$SRV_IP:7801:/tmp/dst/recv.bin" \
                --congestion "$cc" --pacing "$PACING" --compression none \
                --streams "${STREAMS:-4}" --log-level warn "${extra[@]}" \
                > "$logfile" 2>&1
            ;;
        quic)
            timeout "$((TRANSFER_TIMEOUT + 15))" docker exec "$CLI" \
                timeout "$TRANSFER_TIMEOUT" /opt/bench/bin/quic-bench client \
                --addr "$SRV_IP:4433" --src /data/test.bin --dst /tmp/dst/quic.bin \
                > "$logfile" 2>&1
            ;;
        quic-nogso)
            timeout "$((TRANSFER_TIMEOUT + 15))" docker exec "$CLI" \
                timeout "$TRANSFER_TIMEOUT" \
                env QUIC_BENCH_NO_GSO=1 /opt/bench/bin/quic-bench client \
                --addr "$SRV_IP:4433" --src /data/test.bin --dst /tmp/dst/quic.bin \
                > "$logfile" 2>&1
            ;;
        udt)
            timeout "$((TRANSFER_TIMEOUT + 15))" docker exec "$CLI" \
                timeout "$TRANSFER_TIMEOUT" /opt/bench/bin/recvfile "$SRV_IP" 9000 /data/test.bin /tmp/dst/udt.bin \
                > "$logfile" 2>&1
            ;;
        tsunami)
            # blocksize 1400: default 32768 fragments into ~23 IP packets per
            # datagram; under per-packet delay/jitter the fragments spread in
            # time and the receiver's 4MB ipfrag cache evicts them -> ~0 goodput.
            #
            # rate: the shaped link rate, not a constant.
            #
            # This was `set rate 4000M` against a 100 Mbit shaped link --
            # forty times capacity. Tsunami is a fixed-rate protocol with no
            # congestion control; told to send at 40x the bottleneck it
            # thrashes on retransmits and stalls. It recorded TIMEOUT in
            # every cell of the 2026-08-03 cross-tool run *including
            # baseline*, which has zero delay and zero loss, so the number
            # was never a measurement of tsunami -- it was a measurement of
            # our configuration.
            #
            # Reporting that as a win over tsunami would be false. The link
            # rate is what a competent operator would set, and tsunami's own
            # error-rate throttle takes it from there.
            printf 'connect %s 46224\nset rate %sM\nset blocksize 1400\nget test.bin /tmp/dst/tsunami.bin\nquit\n' "$SRV_IP" "$TSUNAMI_RATE" \
                | timeout "$((TRANSFER_TIMEOUT + 15))" docker exec -i "$CLI" \
                    timeout "$TRANSFER_TIMEOUT" /opt/bench/bin/tsunami \
                > "$logfile" 2>&1
            ;;
        tcp)
            # Fixed byte count (-n), not fixed duration, so this is timed
            # the same way as every other tool in the table. -C selects the
            # congestion control per connection, which avoids touching the
            # host sysctl and lets cubic and bbr run in one batch.
            local algo="${mode%%-p4}" parallel=()
            [ "$mode" = "${mode%-p4}" ] || parallel=(-P 4)
            timeout "$((TRANSFER_TIMEOUT + 15))" docker exec "$CLI" \
                timeout "$TRANSFER_TIMEOUT" iperf3 -c "$SRV_IP" \
                -n "$((SIZE_MB * 1024 * 1024))" -C "$algo" "${parallel[@]}" -f m \
                > "$logfile" 2>&1
            ;;
        uftp)
            # Unicast: -H lists receivers. ~2.1s fixed session overhead is
            # included in wall time; the data-phase line is parsed into notes.
            timeout "$((TRANSFER_TIMEOUT + 15))" docker exec "$CLI" \
                timeout "$TRANSFER_TIMEOUT" \
                /opt/bench/bin/uftp -Y none -R -1 -B 20971520 -H "$SRV_IP" /data/test.bin \
                > "$logfile" 2>&1
            ;;
    esac
    RC=$?
}

# iperf3 prints totals in K/M/GBytes; normalise to MBytes.
iperf_mb() {
    case "$2" in
        K) awk -v n="$1" 'BEGIN{printf "%.1f", n/1024}' ;;
        G) awk -v n="$1" 'BEGIN{printf "%.1f", n*1024}' ;;
        *) printf "%s" "$1" ;;
    esac
}

verify_dst() {
    # $1 tool ; prints OK | BAD | MISSING
    local tool="$1" logfile="$2" cont path
    # iperf3 streams bytes and writes no file, so there is nothing to hash.
    # Verify what it does report instead: the RECEIVER-side byte count. That
    # is the same property the sha256 checks establish for the other tools —
    # that the bytes arrived — just attested by the peer rather than by a
    # file on disk.
    #
    # Returning a non-OK status here instead would zero the row: the guard
    # below deliberately refuses to report throughput for a transfer that
    # did not deliver, because a tool that transferred nothing once "won"
    # four scenarios. Exempting TCP from verification would have been the
    # wrong way round — it needs verifying, just differently.
    if [ "$tool" = "tcp" ]; then
        local n unit mb sn sunit smb
        read -r n unit <<< "$(grep -E '(SUM|\[ *[0-9]+\]).*receiver' "$logfile" 2>/dev/null \
            | tail -1 | grep -oP '\K[0-9.]+ [KMG]Bytes' | tail -1 | sed 's/Bytes//')"
        read -r sn sunit <<< "$(grep -E '(SUM|\[ *[0-9]+\]).*sender' "$logfile" 2>/dev/null \
            | tail -1 | grep -oP '\K[0-9.]+ [KMG]Bytes' | tail -1 | sed 's/Bytes//')"
        [ -z "$n" ] && { echo "MISSING"; return; }
        mb=$(iperf_mb "$n" "$unit")
        smb=$(iperf_mb "${sn:-0}" "${sunit:-M}")
        # Two separate questions, and conflating them cost a whole column.
        #
        # `-n` mode makes the SENDER total the statement that the run reached
        # completion: 128 of 128 finished, 80 of 128 means the timeout cut it
        # off. The RECEIVER total is the statement that the bytes landed --
        # the analogue of the sha256 every other tool is held to.
        #
        # The receiver total runs short of the sender's whenever the transfer
        # closes with data still in flight, and `-P 4` makes it worse because
        # each of the four streams closes with its own tail. Measured on this
        # rig: 121-127 MBytes received against 128 sent, up to 5.5% short, on
        # runs that completed cleanly and printed "iperf Done." A 2%
        # tolerance marked six of those BAD and zeroed them, which reads in
        # the CSV as "TCP transferred nothing" -- a false zero in a
        # competitor's column, in our own favour.
        #
        # The bound below is loose on purpose, and the reason matters. For
        # every other tool the sha256 is what proves delivery. For TCP the
        # transport itself proves it: bytes cannot go missing without the
        # connection failing, so a completed `-n` run has delivered all of
        # them by construction. The receiver figure is therefore a sampling
        # artifact, not an integrity measure, and gating on it tightly
        # measures the wrong thing -- a 95% bound still zeroed a clean run
        # that reported 121. What actually distinguishes a real failure is
        # the sender total, and it is decisive here: every completed run
        # sent 128 of 128, every timeout sent 14-82 and printed no receiver
        # line at all.
        awk -v got="$mb" -v snd="$smb" -v want="$SIZE_MB" \
            'BEGIN{exit !(snd >= want*0.98 && got >= want*0.90 && got <= want*1.02)}' \
            && echo "OK" || echo "BAD"
        return
    fi
    if [ "$tool" = "uftp" ]; then cont="$SRV"; path="/tmp/dst/test.bin"
    elif [ "$tool" = "favonius" ]; then cont="$SRV"; path="/tmp/dst/recv.bin"
    elif [ "$tool" = "quic" ] || [ "$tool" = "quic-nogso" ]; then cont="$CLI"; path="/tmp/dst/quic.bin"
    elif [ "$tool" = "udt" ]; then cont="$CLI"; path="/tmp/dst/udt.bin"
    else cont="$CLI"; path="/tmp/dst/tsunami.bin"; fi

    local sha
    sha="$(docker exec "$cont" sha256sum "$path" 2> /dev/null | awk '{print $1}')"
    if [ -z "$sha" ]; then echo "MISSING"; return; fi
    [ "$sha" = "$SRC_SHA" ] && echo "OK" || echo "BAD"
}

# ── CSV ─────────────────────────────────────────────────────────────────────

# Shaped and unshaped runs are not comparable — one has a bottleneck to
# converge to and the other does not — so they go to different files. The
# rate is in the name rather than only in a column, because a merged file
# looks entirely plausible and silently mixes the two.
#
# INSTANCE is part of the name too. It namespaced the containers and the
# network but not the output file, so a second invocation launched to
# investigate a failure appended its rows straight into the running
# benchmark's CSV — the one artifact the isolation existed to protect.
if [ "$RATE_MBIT" = "0" ]; then
    CSV_FILE="$RESULTS_DIR/netem_fair_v2${_suffix}_$(date +%Y-%m-%d).csv"
else
    CSV_FILE="$RESULTS_DIR/netem_fair_v2${_suffix}_${RATE_MBIT}mbit_q${QUEUE_BDP}_j${JITTER}_$(date +%Y-%m-%d).csv"
fi
if [ ! -f "$CSV_FILE" ]; then
    echo "scenario,delay,jitter,loss,rate_mbit,queue_bdp,tool,mode,run,elapsed_ms,throughput_mib_s,notes" > "$CSV_FILE"
fi

append_csv() {
    # scenario delay jitter loss tool mode run elapsed_ms notes
    local mbps=0
    if [ "$8" -gt 0 ] 2> /dev/null; then
        mbps=$(awk "BEGIN { printf \"%.2f\", ($DATA_BYTES / 1048576) / ($8 / 1000) }")
    fi
    # Column 6 is the queue depth tbf actually got, not the one requested.
    # `2 x burst` raises a shallow request and at 1 Gbit that floor is
    # 2.5 MB, so the two differ exactly where the shallow-queue scenario
    # needs them to be told apart.
    echo "$1,$2,$(( JITTER == 1 ? $3 : 0 )),$4,$RATE_MBIT,${EFF_QUEUE_BDP:-$QUEUE_BDP},$5,$6,$7,$8,$mbps,$9" >> "$CSV_FILE"
}

# ── Main loop ───────────────────────────────────────────────────────────────

setup

log "FAIR NETEM V2: ${SIZE_MB}MB, ${RUNS} run(s), ${#SCENARIOS[@]} scenarios x ${#TOOLS[@]} tool-modes, timeout ${TRANSFER_TIMEOUT}s"

for scenario_str in "${SCENARIOS[@]}"; do
    IFS='|' read -r scenario delay jitter loss scen_queue <<< "$scenario_str"
    scen_queue="${scen_queue:-$QUEUE_BDP}"
    if [ -n "${ONLY_SCENARIOS:-}" ] && [[ ",$ONLY_SCENARIOS," != *",$scenario,"* ]]; then continue; fi
    # Report the jitter that will actually be applied, not the one in the
    # scenario table. `apply_netem` replaces it with 0 unless JITTER=1, and
    # JITTER defaults to 0 -- so every run of bench_all_controllers.sh and
    # variance.sh has been jitter-free while this line announced 5-25 ms.
    # That claim reached the README's published scenario descriptions.
    eff_jitter=0
    [ "$JITTER" = "1" ] && eff_jitter="$jitter"
    log "=== SCENARIO: $scenario (delay=${delay}ms jitter=${eff_jitter}ms loss=${loss}% queue=${scen_queue}xBDP, one-way on sender egress) ==="

    for tool_str in "${TOOLS[@]}"; do
        IFS='|' read -r tool mode shaped <<< "$tool_str"
        if [ -n "$ONLY_TOOLS" ] && [[ ",$ONLY_TOOLS," != *",$tool,"* ]]; then continue; fi
        # Symmetric with ONLY_SCENARIOS. `--tools favonius` otherwise runs all
        # four favonius modes, which is 4x the rig time when a single
        # controller is under test.
        if [ -n "${ONLY_MODES:-}" ] && [[ ",$ONLY_MODES," != *",$mode,"* ]]; then continue; fi

        apply_netem "$shaped" "$delay" "$jitter" "$loss" "$scen_queue"

        for run in $(seq $((RUN_OFFSET + 1)) $((RUN_OFFSET + RUNS))); do
            kill_servers
            clean_dst
            start_server "$tool"

            # INSTANCE in the name for the same reason it is in the CSV
            # name: without it a second invocation overwrites the first
            # run's per-run logs, which are the only record of cwnd,
            # RTT and retransmit traces. That happened once already.
            logfile="$RESULTS_DIR/netem-fair-v2${_suffix}-${scenario}-${tool}-${mode}-run${run}.log"
            start_ns=$(date +%s%N)
            run_client "$tool" "$mode" "$logfile"
            end_ns=$(date +%s%N)
            elapsed_ms=$(( (end_ns - start_ns) / 1000000 ))
            rc=$RC

            kill_servers

            notes=""
            if [ "$rc" = "124" ]; then
                # Distinguish "slow but progressing" from "wedged".
                #
                # A timeout used to record 0.00 MB/s and the bare word
                # TIMEOUT, which reads identically for a controller that
                # stalled and one that simply needed longer. `fair` on
                # satellite at 1 Gbit was recorded as a failure on that
                # basis for weeks; given 900 s it completes in 236 s at
                # 4.3 MB/s. It was never broken — Reno's additive increase
                # is 7.8 KB/s of window at a 150 ms RTT, so it cannot fill
                # an 18.75 MB BDP inside the 180 s the harness allows for
                # 1 GB, and it does not need to in order to finish.
                #
                # The last progress line gives how far it got, which turns
                # a misleading zero into a rate.
                # No `local` here: this block runs at top level, not inside a
                # function, so `local` fails with "can only be used in a
                # function" on every timeout. The bare assignments below
                # always run, so no measurement was ever affected — it was
                # eleven lines of stderr noise in a run that otherwise
                # claims to be careful.
                pct=$(grep -oP '\[\s*\K[0-9.]+(?=%\])' "$logfile" 2>/dev/null | tail -1)
                if [ -n "$pct" ] && awk -v p="$pct" 'BEGIN{exit !(p>1)}'; then
                    eff=$(awk -v p="$pct" -v mb="$SIZE_MB" -v t="$TRANSFER_TIMEOUT" \
                        'BEGIN{printf "%.2f", (mb*p/100)/t}')
                    notes="TIMEOUT(${pct}% done, ~${eff} MB/s)"
                else
                    notes="TIMEOUT(no progress)"
                fi
                elapsed_ms=0
                status="TIMEOUT"
            else
                status="$(verify_dst "$tool" "$logfile")"
                [ "$status" != "OK" ] && { notes="$status(rc=$rc)"; }
                # UFTP: record its self-reported data-phase time if present
                if [ "$tool" = "uftp" ]; then
                    dp=$(grep -oP '(Total elapsed time|Transfer time): \K[0-9.]+' "$logfile" 2> /dev/null | head -1)
                    [ -n "$dp" ] && notes="${notes:+$notes; }data-phase ${dp}s"
                fi
                [ "$rc" != "0" ] && [ "$status" = "OK" ] && notes="${notes:+$notes; }rc=$rc"
                # A transfer that did not deliver a verified file has no
                # throughput. TIMEOUT was already zeroed above; MISSING,
                # BAD and anything else must be too, or the CSV reports a
                # rate for work that never happened. That is how a tool
                # that transferred nothing came to "win" four scenarios at
                # 235 MB/s, and how a container killed at 27 ms produced
                # 4740 MB/s.
                if [ "$status" != "OK" ]; then
                    elapsed_ms=0
                fi
            fi

            mbps=0
            [ "$elapsed_ms" -gt 0 ] && mbps=$(awk "BEGIN { printf \"%.1f\", ($DATA_BYTES / 1048576) / ($elapsed_ms / 1000) }")
            append_csv "$scenario" "$delay" "$jitter" "$loss" "$tool" "$mode" "$run" "$elapsed_ms" "$notes"
            log "  $tool/$mode run$run => ${elapsed_ms}ms ${mbps} MB/s [$status] $notes"
        done
    done
done

# Final: make sure no qdisc lingers
docker exec "$SRV" tc qdisc del dev eth0 root 2> /dev/null || true
docker exec "$CLI" tc qdisc del dev eth0 root 2> /dev/null || true

log "CSV: $CSV_FILE"
log "Done. (containers cleaned by trap unless KEEP_CONTAINERS=1)"
