#!/usr/bin/env bash
# Favonius — high-performance file transfer over UDP
# Copyright (c) 2025-2026 Vantino SàRL
# SPDX-License-Identifier: Apache-2.0
#
# benchmarks/scripts/competitor_bench.sh
#
# Favonius against tsunami-udp, UDT4, quinn (QUIC) and uftp over a real
# peer, every arm verified by hashing what arrived.
#
# Install the competitors first with install_competitors.sh (on BOTH ends).
#
# Two rules, both bought with wrong numbers:
#
#   1. A tool has transferred nothing until the destination hashes equal to
#      the source. uftp reports clean completions while writing to a
#      directory it was not asked to use; a python sender reports 16 GB/s
#      when its connection failed. Timing without verification is fiction.
#   2. Exit status is not the signal. tsunami exits NON-ZERO after a normal
#      `quit`, so an exit-code check marks a completed transfer as failed
#      (an earlier run reported exactly that).
#
# Usage:
#   REMOTE=user@host REMOTE_IP=10.0.0.2 DEST_ROOT=/dev/shm \
#     ./benchmarks/scripts/competitor_bench.sh [--runs N] [--size-mb N]
set -uo pipefail

REPO="$(cd "$(dirname "$0")/../.." && pwd)"
RESULTS="$REPO/benchmarks/results"; mkdir -p "$RESULTS"
REMOTE="${REMOTE:?set REMOTE}"; REMOTE_IP="${REMOTE_IP:?set REMOTE_IP}"
REMOTE_BIN="${REMOTE_BIN:-/opt/favonius/bin}"
COMP="${COMP:-/opt/competitors/bin}"
DEST_ROOT="${DEST_ROOT:-/dev/shm}"
SSH="ssh -o BatchMode=yes -o ConnectTimeout=10"
RUNS=3; SIZE_MB=512
TOOLS="${TOOLS:-favonius-1,favonius-4,favonius-4x1,tsunami,udt,quinn,uftp}"
while [[ $# -gt 0 ]]; do
    case "$1" in
        --runs) RUNS="$2"; shift 2 ;;
        --size-mb) SIZE_MB="$2"; shift 2 ;;
        --tools) TOOLS="$2"; shift 2 ;;
        *) echo "unknown argument: $1" >&2; exit 64 ;;
    esac
done
SIZE=$((SIZE_MB * 1024 * 1024))
SRC="/tmp/comp_bench_src.bin"
[ -s "$SRC" ] && [ "$(stat -c %s "$SRC")" = "$SIZE" ] || head -c "$SIZE" /dev/urandom > "$SRC"
SRC_SHA=$(sha256sum "$SRC" | cut -d' ' -f1)
CSV="$RESULTS/competitors_$(date +%F).csv"
k=1; while [ -e "$CSV" ]; do k=$((k+1)); CSV="$RESULTS/competitors_$(date +%F)_$k.csv"; done
echo "date,peer,rtt_ms,tool,run,seconds,mbs,verified" > "$CSV"

rtt=$(ping -c 5 -q "$REMOTE_IP" 2>/dev/null | awk -F'/' '/rtt|round-trip/{print $5}')
echo "peer $REMOTE_IP, rtt ${rtt:-?} ms, ${SIZE_MB} MB x $RUNS runs, src $SRC_SHA"

# Verify at the receiver and clear the destination for the next run.
# Returns the elapsed seconds only when the hash matches.
verify() {  # remote_path
    $SSH "$REMOTE" "sha256sum '$1' 2>/dev/null | cut -d' ' -f1"
}
clear_dest() { $SSH "$REMOTE" "rm -f '$1' 2>/dev/null; exit 0"; }

now() { date +%s.%N; }
elapsed() { awk -v a="$1" -v b="$2" 'BEGIN{printf "%.3f", b-a}'; }

run_favonius() {  # streams
    local streams=$1 dst="$DEST_ROOT/comp.bin"
    clear_dest "$dst"
    $SSH "$REMOTE" "pkill -x favonius-daemon 2>/dev/null; sleep 1; \
        setsid nohup $REMOTE_BIN/favonius-daemon --listen 127.0.0.1:7800 \
          --protocol-listen 0.0.0.0:7801 --data-listen 0.0.0.0:7802 \
          --data-port-range 7803-7812 --dest-root $DEST_ROOT --log-level warn \
          > /tmp/hd.log 2>&1 < /dev/null &" 2>/dev/null
    for _ in $(seq 1 20); do
        $SSH "$REMOTE" "ss -lun 2>/dev/null | grep -q ':7801 '" && break; sleep 1
    done
    local t0 t1
    t0=$(now)
    "$REPO/target/release/favonius" send "$SRC" "$REMOTE_IP:7801:$dst" --streams "$streams" > /tmp/comp_h.log 2>&1
    t1=$(now)
    $SSH "$REMOTE" "pkill -x favonius-daemon 2>/dev/null; exit 0"
    echo "$(elapsed "$t0" "$t1") $(verify "$dst")"
}

# N concurrent Favonius transfers, one stream each: N congestion
# controllers on N sockets, which is what `iperf3 -P N` actually is.
# `--streams N` is ONE controller however many sockets it uses, so it is
# not the counterpart to a 4-flow TCP test and never was.
#
# Timed as a batch: total bytes over the wall clock from the first sender
# starting to the last one finishing, which is the same quantity iperf3's
# SUM row reports.
run_favonius_concurrent() {  # n
    local n=$1 i base; base=$(basename "$SRC")
    $SSH "$REMOTE" "pkill -x favonius-daemon 2>/dev/null; sleep 1; \
        rm -f $DEST_ROOT/conc_*.bin; \
        setsid nohup $REMOTE_BIN/favonius-daemon --listen 127.0.0.1:7800 \
          --protocol-listen 0.0.0.0:7801 --data-listen 0.0.0.0:7802 \
          --data-port-range 7803-7812 --max-concurrent 8 \
          --dest-root $DEST_ROOT --log-level warn \
          > /tmp/hd.log 2>&1 < /dev/null &" 2>/dev/null
    for _ in $(seq 1 20); do
        $SSH "$REMOTE" "ss -lun 2>/dev/null | grep -q ':7801 '" && break; sleep 1
    done
    local t0 t1
    t0=$(now)
    for i in $(seq 1 "$n"); do
        "$REPO/target/release/favonius" send "$SRC" "$REMOTE_IP:7801:$DEST_ROOT/conc_$i.bin" \
            --streams 1 > "/tmp/comp_conc_$i.log" 2>&1 &
    done
    wait
    t1=$(now)
    $SSH "$REMOTE" "pkill -x favonius-daemon 2>/dev/null; exit 0"
    # Every destination must match, and the rate is the aggregate.
    local okc; okc=$($SSH "$REMOTE" "sha256sum $DEST_ROOT/conc_*.bin 2>/dev/null | cut -d' ' -f1 | grep -c '^$SRC_SHA\$'")
    if [ "${okc:-0}" = "$n" ]; then echo "$(elapsed "$t0" "$t1") $SRC_SHA MULT$n"; else echo "$(elapsed "$t0" "$t1") short"; fi
}

# tsunami and quinn are PULL protocols: the file must sit on the serving
# side. Everything else here pushes tx -> rx, so for these two the server
# runs HERE and the client runs on the peer over ssh — same data direction
# as every other arm, and the destination is hashed on the peer the same
# way. Running the server on the peer (the obvious reading of "the remote
# is the server") asks it to serve a file it does not have.
LOCAL_IP="${LOCAL_IP:-$(ip -4 route get "$REMOTE_IP" 2>/dev/null | grep -oP 'src \K[0-9.]+' | head -1)}"

# tsunami: TCP control channel on 46224, UDP data. The client is a shell
# ("get <file>" then "quit") and exits NON-ZERO after a clean quit, so the
# hash is the only completion signal.
run_tsunami() {
    local base; base=$(basename "$SRC")
    $SSH "$REMOTE" "rm -f '$DEST_ROOT/$base'; exit 0"
    pkill -x tsunamid 2>/dev/null; sleep 0.5
    ( cd "$(dirname "$SRC")" && setsid nohup "$COMP/tsunamid" "$base" \
        > /tmp/tsunamid.log 2>&1 < /dev/null & ) 2>/dev/null
    sleep 1
    local t0 t1
    t0=$(now)
    # Commands are separate argv tokens, NOT quoted phrases: quoting them
    # gets "Unsupported command console command: connect <ip>", which reads
    # like a protocol problem and is a shell one.
    $SSH "$REMOTE" "cd $DEST_ROOT && timeout 300 $COMP/tsunami \
        connect $LOCAL_IP get $base quit" > /tmp/comp_ts.log 2>&1
    t1=$(now)
    pkill -x tsunamid 2>/dev/null
    echo "$(elapsed "$t0" "$t1") $(verify "$DEST_ROOT/$base")"
}

# UDT4 is a PULL too, and the names invert what they suggest: `sendfile
# <port>` is the SERVER (it serves files from its cwd) and `recvfile
# <ip> <port> <remote> <local>` is the client. Reading them as
# push-sender/push-receiver produces "usage: sendfile [server_port]" and a
# 0.1 s "transfer".
run_udt() {
    local base; base=$(basename "$SRC")
    $SSH "$REMOTE" "rm -f '$DEST_ROOT/$base'; exit 0"
    pkill -x sendfile 2>/dev/null; sleep 0.5
    ( cd "$(dirname "$SRC")" && setsid nohup env LD_LIBRARY_PATH="$COMP" \
        "$COMP/sendfile" 9000 > /tmp/udt_send.log 2>&1 < /dev/null & ) 2>/dev/null
    sleep 1
    local t0 t1
    t0=$(now)
    $SSH "$REMOTE" "cd $DEST_ROOT && LD_LIBRARY_PATH=$COMP timeout 300 \
        $COMP/recvfile $LOCAL_IP 9000 $base $base" > /tmp/comp_udt.log 2>&1
    t1=$(now)
    pkill -x sendfile 2>/dev/null
    echo "$(elapsed "$t0" "$t1") $(verify "$DEST_ROOT/$base")"
}

# quinn's example client fetches a path over QUIC from its example server.
#
# There is no --insecure — the client verifies TLS — and this version of
# the example server generates its self-signed cert IN MEMORY, writing
# nothing to disk, so there is no cert file to hand the client. Supply an
# explicit pair instead: PEM to the server, the same cert in DER to the
# client, and `--host localhost` because that is the name in it. Every one
# of those surfaces only as an opaque TLS failure.
run_quinn() {
    local base; base=$(basename "$SRC")
    local d=/tmp/quinn_pki
    # rustls will not accept a self-signed CA certificate as a server
    # identity — `openssl req -x509` produces exactly that, and the failure
    # is "invalid peer certificate: CaUsedAsEndEntity". It needs a real
    # two-level chain: a CA that signs an end-entity cert carrying
    # SAN=localhost and CA:FALSE. The client trusts the CA (DER), the
    # server presents the leaf (PEM).
    if [ ! -s "$d/ca.der" ]; then
        mkdir -p "$d"
        openssl req -x509 -newkey rsa:2048 -nodes -keyout "$d/ca.key" -out "$d/ca.pem" \
            -days 2 -subj "/CN=bench-ca" > /dev/null 2>&1
        openssl req -newkey rsa:2048 -nodes -keyout "$d/srv.key" -out "$d/srv.csr" \
            -subj "/CN=localhost" > /dev/null 2>&1
        printf 'subjectAltName=DNS:localhost\nbasicConstraints=critical,CA:FALSE\nextendedKeyUsage=serverAuth\n' > "$d/ext"
        openssl x509 -req -in "$d/srv.csr" -CA "$d/ca.pem" -CAkey "$d/ca.key" \
            -CAcreateserial -out "$d/srv.pem" -days 2 -extfile "$d/ext" > /dev/null 2>&1
        openssl x509 -in "$d/ca.pem" -outform der -out "$d/ca.der" > /dev/null 2>&1
    fi
    [ -s "$d/ca.der" ] || { echo "0 NOCERT"; return; }
    pkill -x quinn-server 2>/dev/null; sleep 0.5
    ( cd /tmp && setsid nohup "$COMP/quinn-server" --listen 0.0.0.0:4433 \
        -k "$d/srv.key" -c "$d/srv.pem" /tmp > /tmp/quinn_srv.log 2>&1 < /dev/null & ) 2>/dev/null
    sleep 2
    $SSH "$REMOTE" "rm -f '$DEST_ROOT/$base' /tmp/quinn_ca.der; exit 0"
    scp -q -o BatchMode=yes "$d/ca.der" "$REMOTE:/tmp/quinn_ca.der" 2>/dev/null
    local t0 t1
    t0=$(now)
    # The example client writes the response BODY to stdout and says
    # nothing about files, so the destination is a redirect.
    $SSH "$REMOTE" "timeout 300 $COMP/quinn-client \
        'https://$LOCAL_IP:4433/$base' --host localhost --ca /tmp/quinn_ca.der \
        > '$DEST_ROOT/$base'" > /tmp/comp_quinn.log 2>&1
    t1=$(now)
    pkill -x quinn-server 2>/dev/null
    echo "$(elapsed "$t0" "$t1") $(verify "$DEST_ROOT/$base")"
}

# uftp: multicast by default, which no cloud VPC carries — `-M <rx>` makes
# the announce unicast (measured). It also ignores -D and writes to the
# daemon's temp dir, so the destination is discovered, not assumed.
run_uftp() {
    $SSH "$REMOTE" "sudo pkill -x uftpd 2>/dev/null; sudo rm -f /tmp/$(basename "$SRC"); \
        sudo setsid nohup uftpd -D /tmp -t > /tmp/uftpd.log 2>&1 < /dev/null &" 2>/dev/null
    sleep 2
    local t0 t1
    t0=$(now)
    timeout 300 uftp -M "$REMOTE_IP" -R 3000000 "$SRC" > /tmp/comp_uftp.log 2>&1
    t1=$(now)
    echo "$(elapsed "$t0" "$t1") $(verify "/tmp/$(basename "$SRC")")"
}

printf '  %-12s %5s %10s %10s  %s\n' tool run "seconds" "MB/s" verified
echo "  --------------------------------------------------------"
for tool in ${TOOLS//,/ }; do
    for run in $(seq 1 "$RUNS"); do
        case "$tool" in
            favonius-1) out=$(run_favonius 1) ;;
            favonius-4) out=$(run_favonius 4) ;;
            favonius-4x1) out=$(run_favonius_concurrent 4) ;;
            tsunami)   out=$(run_tsunami) ;;
            udt)       out=$(run_udt) ;;
            quinn)     out=$(run_quinn) ;;
            uftp)      out=$(run_uftp) ;;
            *) echo "unknown tool $tool" >&2; continue ;;
        esac
        secs=${out%% *}; sha=$(awk '{print $2}' <<<"$out")
        # An aggregate arm moved n x SIZE bytes in that wall clock.
        mult=1
        case "$out" in *MULT*) mult=${out##*MULT} ;; esac
        if [ "$sha" = "$SRC_SHA" ] && [ -n "$secs" ]; then
            mbs=$(awk -v s="$secs" -v b="$SIZE" -v m="$mult" 'BEGIN{printf "%.1f", m*b/s/1048576}')
            ver=ok
        else
            mbs=""; ver="MISMATCH"
        fi
        printf '  %-12s %5s %10s %10s  %s\n' "$tool" "$run" "$secs" "${mbs:-—}" "$ver"
        echo "$(date +%F),$REMOTE_IP,${rtt:-},$tool,$run,$secs,${mbs},$ver" >> "$CSV"
    done
done

python3 - "$CSV" <<'PY'
import csv, sys, collections, statistics as st
rows=[r for r in csv.DictReader(open(sys.argv[1])) if r["mbs"] and r["verified"]=="ok"]
by=collections.OrderedDict()
for r in rows: by.setdefault(r["tool"],[]).append(float(r["mbs"]))
print(f"\n  {'tool':12s} {'MB/s':>8s} {'cv':>7s} {'n':>3s}   (verified transfers only)")
for t,v in sorted(by.items(), key=lambda kv:-st.mean(kv[1])):
    cv=100*st.stdev(v)/st.mean(v) if len(v)>1 else 0.0
    print(f"  {t:12s} {st.mean(v):8.1f} {cv:6.1f}% {len(v):3d}")
PY
echo; echo "wrote $CSV"
