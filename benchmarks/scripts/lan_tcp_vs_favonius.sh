#!/usr/bin/env bash
# Favonius — high-performance file transfer over UDP
# Copyright (c) 2025-2026 Vantino SàRL
# SPDX-License-Identifier: Apache-2.0
#
# benchmarks/scripts/lan_tcp_vs_favonius.sh
#
# Favonius against kernel TCP over a real LAN peer, at matched *congestion
# controller* counts rather than matched "streams".
#
# The distinction is the point of this script. `iperf3 -P 4` is four
# independent congestion controllers, four windows and four sockets;
# `favonius --streams 4` is ONE controller and one window multiplexed across
# four logical streams (four sockets too, since per-stream data ports, but
# still one controller). So the honest pairing for a per-flow comparison is
#
#     favonius --streams N   vs   TCP with ONE stream
#
# and TCP with 4 streams is the aggregate-capacity question, which Favonius
# answers with N concurrent *transfers*, not with --streams. Entry 65's
# competitor table compared one controller against four and read the
# difference as a tool deficit; this script exists so that cannot recur
# silently — every row prints its controller count.
#
# Usage:
#   REMOTE=user@10.0.0.2 REMOTE_IP=10.0.0.2 DEST_ROOT=/dev/shm \
#     ./benchmarks/scripts/lan_tcp_vs_favonius.sh [--runs N] [--size-mb N]
#
# The peer needs python3 and (for the AHP arms) favonius-daemon in
# REMOTE_BIN. No competitor tools are invoked: uftp/tsunami/udt/quinn are
# not installed on this peer, and a comparison that silently drops them is
# better than one that silently misconfigures them (an earlier run recorded two
# such false wins).
set -uo pipefail

REPO="$(cd "$(dirname "$0")/../.." && pwd)"
RESULTS="$REPO/benchmarks/results"; mkdir -p "$RESULTS"
REMOTE="${REMOTE:?set REMOTE}"; REMOTE_IP="${REMOTE_IP:?set REMOTE_IP}"
REMOTE_BIN="${REMOTE_BIN:-/opt/favonius/bin}"
DEST_ROOT="${DEST_ROOT:-/dev/shm}"
SSH="ssh -o BatchMode=yes -o ConnectTimeout=10"
RUNS=4; SIZE_MB=128
MODES="${MODES:-tcp-cubic-1,tcp-bbr-1,tcp-bbr-4,favonius-1,favonius-4,favonius-adaptive}"
while [[ $# -gt 0 ]]; do
    case "$1" in
        --runs) RUNS="$2"; shift 2 ;;
        --size-mb) SIZE_MB="$2"; shift 2 ;;
        --modes) MODES="$2"; shift 2 ;;
        *) echo "unknown argument: $1" >&2; exit 64 ;;
    esac
done
SIZE=$((SIZE_MB * 1024 * 1024))
SRC="/tmp/lan_bench_src.bin"
[ -s "$SRC" ] && [ "$(stat -c %s "$SRC")" = "$SIZE" ] || head -c "$SIZE" /dev/urandom > "$SRC"
CSV="$RESULTS/lan_tcp_vs_favonius_$(date +%F).csv"
n=1; while [ -e "$CSV" ]; do n=$((n+1)); CSV="$RESULTS/lan_tcp_vs_favonius_$(date +%F)_$n.csv"; done
echo "date,peer,rtt_ms,mode,controllers,run,mbs" > "$CSV"

rtt=$(ping -c 5 -q "$REMOTE_IP" 2>/dev/null | awk -F'/' '/rtt|round-trip/{print $5}')
echo "peer $REMOTE_IP, rtt ${rtt:-?} ms, ${SIZE_MB} MB x $RUNS runs"

# ── TCP sink (peer) and source (here) ────────────────────────────────────
# Written locally and scp'd, never piped into a remote heredoc: under some
# ssh/stdin arrangements the heredoc never arrives, the remote `cat`
# creates an EMPTY file, and the failure surfaces as "connection refused"
# — indistinguishable from a firewall. hardware_bench.sh paid for that.
SINK=$(mktemp -t lan_sink.XXXXXX.py)
cat > "$SINK" <<'PY'
import socket, sys, threading
streams = int(sys.argv[1])
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("0.0.0.0", 5998)); s.listen(streams + 2)
print("ready", flush=True)
got = [0] * streams
def drain(c, i):
    n = 0
    while True:
        b = c.recv(1 << 20)
        if not b:
            break
        n += len(b)
    got[i] = n
    # Let the sender's blocking recv() return, so its clock covers delivery
    # rather than stopping when the socket buffer accepted the tail.
    try:
        c.shutdown(socket.SHUT_WR)
    except OSError:
        pass
    c.close()
ts = []
for i in range(streams):
    c, _ = s.accept()
    t = threading.Thread(target=drain, args=(c, i)); t.start(); ts.append(t)
for t in ts:
    t.join()
# The byte count is the point of printing anything here. A sender whose
# connections failed reports a spectacular rate for data that never left
# it, and only the receiver can contradict that.
print(f"RECEIVED {sum(got)}", flush=True)
PY
scp -q -o BatchMode=yes "$SINK" "$REMOTE:/tmp/lan_sink.py" || { echo "scp of sink failed"; exit 1; }
rm -f "$SINK"
[ "$($SSH "$REMOTE" 'wc -c < /tmp/lan_sink.py')" -gt 100 ] || { echo "sink did not arrive"; exit 1; }

SOURCE=$(mktemp -t lan_source.XXXXXX.py)
cat > "$SOURCE" <<'PY'
import socket, sys, threading, time
host, port, total, streams, cc = sys.argv[1], 5998, int(sys.argv[2]), int(sys.argv[3]), sys.argv[4]
TCP_CONGESTION = getattr(socket, "TCP_CONGESTION", 13)
per = total // streams
buf = b"\xa5" * (1 << 20)
errors = []
def send(n):
    # An exception in a thread does NOT fail the process: join() returns,
    # the timer stops early, and 128 MB that never left the host reports as
    # 16000 MB/s over wifi. This script measured exactly that on its first
    # run, which is the same class of false win as an earlier run's uftp and
    # tsunami rows — a tool that failed, reported as a tool that flew.
    try:
        c = socket.socket()
        if cc != "default":
            # Non-root may set any algorithm listed in
            # tcp_allowed_congestion_control. A failure here must be fatal,
            # not a warning: silently measuring cubic and labelling it bbr
            # is worse than not measuring.
            c.setsockopt(socket.IPPROTO_TCP, TCP_CONGESTION, cc.encode())
        c.connect((host, port))
        left = n
        while left > 0:
            k = min(left, len(buf))
            c.sendall(buf[:k]); left -= k
        # Block until the receiver has drained everything and closed.
        c.shutdown(socket.SHUT_WR)
        c.recv(1)
        c.close()
    except Exception as e:
        errors.append(repr(e))
t0 = time.time()
ts = [threading.Thread(target=send, args=(per,)) for _ in range(streams)]
for t in ts: t.start()
for t in ts: t.join()
el = time.time() - t0
if errors:
    print("ERROR " + "; ".join(errors[:3]), file=sys.stderr)
    sys.exit(1)
print(f"RESULT {per*streams/el/1048576:.2f}")
PY

run_tcp() {  # cc, streams
    local cc=$1 streams=$2
    # Remove the log BEFORE starting, or the readiness grep reads the
    # previous run's "ready" and the source connects before this sink has
    # bound — which surfaces as "connection refused" and reads as a
    # firewall (hardware_bench.sh's comment records the same trap).
    # The kill goes in its OWN ssh call, and nothing else in that command
    # line may name the sink.
    #
    # `pkill -f` matches the full command line of every process, including
    # the shell ssh spawns to run the command. Bracketing the pattern
    # (`[l]an_sink`) is the usual defence and is NOT sufficient here: the
    # pattern is a regex matching "lan_sink", and the same line went on to
    # say `/tmp/lan_sink.log` and `/tmp/lan_sink.py`, which it matches. So
    # the shell killed itself, ssh returned 255, no sink ever bound, and
    # all twelve TCP arms reported FAILED while the Favonius arms — which do
    # not use pkill -f — ran fine.
    #
    # the engineering log warns about exactly this second
    # mention. Reading the warning is not the same as noticing it applies.
    $SSH "$REMOTE" "pkill -f '[l]an_sink' 2>/dev/null; exit 0" 2>/dev/null
    $SSH "$REMOTE" "rm -f /tmp/lan_sink.log; \
        setsid nohup python3 /tmp/lan_sink.py $streams > /tmp/lan_sink.log 2>&1 < /dev/null &" 2>/dev/null
    local ready=""
    for _ in $(seq 1 30); do
        $SSH "$REMOTE" 'grep -q ready /tmp/lan_sink.log 2>/dev/null' && { ready=1; break; }
        sleep 0.5
    done
    [ -n "$ready" ] || { echo ""; return; }
    local out mbs rx
    out=$(python3 "$SOURCE" "$REMOTE_IP" "$SIZE" "$streams" "$cc" 2>&1)
    mbs=$(grep -oP 'RESULT \K[0-9.]+' <<<"$out")
    # Confirm at the RECEIVER that every byte arrived. Without this the
    # sender's own clock is the only witness, and a failed connection is
    # indistinguishable from an extremely fast one.
    for _ in $(seq 1 20); do
        rx=$($SSH "$REMOTE" "grep -oP 'RECEIVED \\K[0-9]+' /tmp/lan_sink.log 2>/dev/null")
        [ -n "${rx:-}" ] && break
        sleep 0.5
    done
    if [ -z "$mbs" ] || [ "${rx:-0}" != "$SIZE" ]; then
        echo ""   # the runner prints FAILED and leaves the CSV cell empty
        return
    fi
    echo "$mbs"
}

run_favonius() {  # extra favonius args...
    # `--data-port-range` is not optional for a multi-stream arm, and
    # leaving it out is what made the first WAN table say `--streams 4` was
    # slightly WORSE than `--streams 1` (116.3 against 121.5).
    #
    # Without a port range every stream lands on one receive socket and one
    # kernel queue, so four streams buy nothing on the receive side and pay
    # the scatter — which is the state an earlier run measured. With the range the
    # daemon hands the transfer a contiguous run and the streams drain N
    # queues; the same A/B on this rig measured 144.2 against 125.3 MB/s.
    # A benchmark that omits it is measuring the 2026-08-11 daemon.
    #
    # 10 ports against a concurrency of 4: one transfer may hold at most
    # half the pool, so this yields a run of 5 and the sender takes
    # min(5, --streams).
    $SSH "$REMOTE" "pkill -x favonius-daemon 2>/dev/null; sleep 1; rm -f $DEST_ROOT/lan.bin; \
        setsid nohup $REMOTE_BIN/favonius-daemon --listen 127.0.0.1:7800 \
          --protocol-listen 0.0.0.0:7801 --data-listen 0.0.0.0:7802 \
          --data-port-range 7803-7812 \
          --dest-root $DEST_ROOT --log-level warn > /tmp/hd.log 2>&1 < /dev/null &" 2>/dev/null
    for _ in $(seq 1 20); do
        $SSH "$REMOTE" "ss -lun 2>/dev/null | grep -q ':7801 '" && break
        sleep 1
    done
    "$REPO/target/release/favonius" send "$SRC" "$REMOTE_IP:7801:$DEST_ROOT/lan.bin" "$@" 2>&1 \
        | grep -oP 'complete: \K[0-9.]+'
}

printf '  %-18s %-12s %6s %10s\n' mode controllers run "MB/s"
echo "  ------------------------------------------------"
for mode in ${MODES//,/ }; do
    case "$mode" in
        tcp-cubic-1)      ctl=1 ;;
        tcp-bbr-1)        ctl=1 ;;
        tcp-bbr-4)        ctl=4 ;;
        favonius-*)        ctl=1 ;;   # one controller regardless of --streams
        *) echo "unknown mode $mode" >&2; continue ;;
    esac
    for run in $(seq 1 "$RUNS"); do
        case "$mode" in
            tcp-cubic-1) mbs=$(run_tcp cubic 1) ;;
            tcp-bbr-1)   mbs=$(run_tcp bbr 1) ;;
            tcp-bbr-4)   mbs=$(run_tcp bbr 4) ;;
            favonius-1)   mbs=$(run_favonius --streams 1) ;;
            favonius-4)   mbs=$(run_favonius --streams 4) ;;
            favonius-adaptive) mbs=$(run_favonius --adaptive) ;;
        esac
        printf '  %-18s %-12s %6s %10s\n' "$mode" "$ctl" "$run" "${mbs:-FAILED}"
        echo "$(date +%F),$REMOTE_IP,${rtt:-},$mode,$ctl,$run,${mbs:-}" >> "$CSV"
    done
done
rm -f "$SOURCE"
$SSH "$REMOTE" 'pkill -f "[l]an_sink" 2>/dev/null; pkill -x favonius-daemon 2>/dev/null; exit 0'

python3 - "$CSV" <<'PY'
import csv, sys, statistics as st
rows = [r for r in csv.DictReader(open(sys.argv[1])) if r["mbs"]]
by = {}
for r in rows: by.setdefault((r["mode"], r["controllers"]), []).append(float(r["mbs"]))
print(f"\n  {'mode':18s} {'ctlrs':>5s} {'mean MB/s':>10s} {'cv':>7s} {'n':>3s}")
for (m, c), v in by.items():
    cv = 100 * st.stdev(v) / st.mean(v) if len(v) > 1 else 0.0
    print(f"  {m:18s} {c:>5s} {st.mean(v):10.1f} {cv:6.1f}% {len(v):3d}")
print("\n  Pair on CONTROLLER COUNT: favonius-* (1) against tcp-*-1 (1).")
print("  tcp-bbr-4 is the aggregate-capacity question; Favonius answers that")
print("  with N concurrent transfers, not with --streams.")
PY
echo; echo "wrote $CSV"
