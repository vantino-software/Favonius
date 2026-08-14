#!/usr/bin/env bash
# Favonius — high-performance file transfer over UDP
# Copyright (c) 2025-2026 Vantino SàRL
# SPDX-License-Identifier: Apache-2.0
#
# benchmarks/scripts/hardware_bench.sh
#
# Run Favonius between two REAL machines over a REAL network.
#
# Why this exists. Every other number in this repository comes from a
# container pair on one host, shaped with netem. That rig cannot show
# whether the results survive contact with a physical NIC, a driver, an
# interrupt path, a second CPU and a real radio or switch — and a reviewer
# is right to discount a transport benchmark that never left one kernel.
#
# What it measures, in order:
#
#   1. A TCP baseline over the same path, using nothing but python3 on both
#      ends. Without it a Favonius number has no ceiling to be read against:
#      "25 MB/s" means one thing on a 30 MB/s path and another on a 110 MB/s
#      one. Deliberately dependency-free — no iperf3 to install on a device
#      that may not be yours to modify.
#   2. Favonius, n runs per congestion profile, restarting the daemon between
#      runs because it serves one transfer at a time.
#   3. sha256 of every received file. A throughput number for a corrupt
#      transfer is not a throughput number.
#
# Usage:
#   REMOTE=pi@192.168.0.155 REMOTE_IP=192.168.0.155 \
#     ./benchmarks/scripts/hardware_bench.sh [--size-mb 256] [--runs 5]

set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
RESULTS="$REPO/benchmarks/results"
mkdir -p "$RESULTS"

REMOTE="${REMOTE:?set REMOTE, e.g. pi@192.168.0.155}"
REMOTE_IP="${REMOTE_IP:?set REMOTE_IP, e.g. 192.168.0.155}"
REMOTE_BIN="${REMOTE_BIN:-/opt/favonius/bin}"
# Extra flags for the peer daemon, identical in every arm.
DAEMON_ARGS="${DAEMON_ARGS:-}"
DEST_ROOT="${DEST_ROOT:-/srv/favonius-incoming}"
SIZE_MB=256
RUNS=5
MODES="${MODES:-classic,model,cycle}"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --size-mb) SIZE_MB="$2"; shift 2 ;;
        --runs) RUNS="$2"; shift 2 ;;
        --modes) MODES="$2"; shift 2 ;;
        *) echo "unknown argument: $1" >&2; exit 64 ;;
    esac
done

SSH="ssh -o BatchMode=yes -o ConnectTimeout=10"
SRC=/tmp/hw_bench_src.bin
BYTES=$((SIZE_MB * 1048576))

say() { printf '\n\033[1m%s\033[0m\n' "$1"; }

say "path"
echo "  local  : $(ip -4 -o addr show scope global | grep -v docker | grep -v ' br-' | head -1 | awk '{print $2" "$4}')"
echo "  remote : $REMOTE_IP"
rtt=$(ping -c 5 -q "$REMOTE_IP" 2>/dev/null | awk -F'/' '/rtt|round-trip/{print $5}')
echo "  rtt    : ${rtt:-?} ms (avg of 5)"
$SSH "$REMOTE" 'echo "  peer   : $(uname -m) $(uname -r), $(nproc) cores"' 2>/dev/null

# ── 1. TCP baseline ──────────────────────────────────────────────────────
say "TCP baseline (python3, same path, ${SIZE_MB}MB)"
# Written locally and copied, not piped into a remote `cat` heredoc. Under
# some ssh/stdin arrangements the heredoc never reaches the remote `cat`,
# which then creates an EMPTY file and exits 0 — the deploy "succeeds", the
# sink exits instantly, and the failure surfaces as "connection refused" at
# the client, indistinguishable from the two other causes documented below.
# scp either transfers the bytes or fails loudly, and the size is checked.
SINK_LOCAL="$(mktemp -t tcp_sink.XXXXXX.py)"
cat > "$SINK_LOCAL" <<'PY'
import socket, sys, time
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("0.0.0.0", 5999)); s.listen(1)
print("ready", flush=True)
c, _ = s.accept()
n = 0; t0 = time.time()
while True:
    b = c.recv(1 << 20)
    if not b: break
    n += len(b)
t = time.time() - t0
print(f"RESULT {n/t/1048576:.2f}", flush=True)
PY
scp -q -o BatchMode=yes -o ConnectTimeout=10 "$SINK_LOCAL" "$REMOTE:/tmp/tcp_sink.py" \
    || echo "  (scp of the sink failed — baseline will be blank)"
rm -f "$SINK_LOCAL"
sink_bytes=$($SSH "$REMOTE" 'wc -c < /tmp/tcp_sink.py 2>/dev/null || echo 0')
[ "${sink_bytes:-0}" -gt 100 ] || echo "  (sink script is ${sink_bytes:-0} bytes on the peer — baseline will be blank)"
# `setsid`, not just `nohup ... & disown`. Both of the latter were tried and
# both let the sink die the moment ssh tore the session down: it reached
# listen(), wrote "ready" to its log, and was gone before the first readiness
# poll — so the log said the server had started while `ss` showed no listener,
# and the client got "connection refused". That combination reads as a
# firewall and is not one. `setsid` puts it in its own session, where the
# teardown's SIGHUP cannot reach it. Measured 2026-08-11: with `& disown` the
# sink survived 0 of 3 attempts, with `setsid` 3 of 3.
#
# Remove the log BEFORE starting. Grepping it for "ready" without doing so
# reads the previous run's line: the check passed instantly, the client
# connected before the new sink had bound, and the failure surfaced as
# "connection refused" — indistinguishable from a firewall.
#
# The kill goes in its OWN ssh invocation, and the pattern is bracketed.
# Both halves are needed and each was learned the hard way on 2026-08-11:
#
#   pkill -f tcp_sink.py       matches the remote shell running it (the
#                              pattern is in its own command line) -> the
#                              chain dies before `rm`/`setsid`, ssh exits 255
#   pkill -f "[t]cp_sink.py"   fixes the pattern, but if the SAME command
#      ...; python3 /tmp/tcp_sink.py    line goes on to name the sink
#                              unbracketed, the regex matches THAT and the
#                              shell is killed anyway — silently, exit 255,
#                              no stderr, leaving the previous run's log in
#                              place so it reads as "the sink started fine".
#
# Splitting them means the killing command line contains only the bracketed
# form and the starting one contains no pkill. Same family as the `pgrep -f`
# self-match in the engineering log: a process-matching check must
# not be reachable by its own pattern.
$SSH "$REMOTE" 'pkill -f "[t]cp_sink.py" 2>/dev/null; exit 0'
sleep 1
$SSH "$REMOTE" 'rm -f /tmp/tcp_sink.out; setsid nohup python3 /tmp/tcp_sink.py > /tmp/tcp_sink.out 2>&1 < /dev/null & disown' \
    || echo "  (sink launch returned $? — baseline will be blank)"
# Ask the PEER what is listening. Probing by connecting from here consumed
# the sink's single accept(), so the readiness check itself ended the
# server and the real client then got "connection refused".
tcp_ready=0
for _ in $(seq 1 20); do
    if $SSH "$REMOTE" "ss -ltn 2>/dev/null | grep -q ':5999 ' || netstat -ltn 2>/dev/null | grep -q ':5999 '"; then tcp_ready=1; break; fi
    sleep 1
done
[ "$tcp_ready" = 1 ] || echo "  (sink never came up — baseline will be blank)" 
tcp_mbs=$(python3 - "$REMOTE_IP" "$BYTES" <<'PY'
import socket, sys, time
ip, total = sys.argv[1], int(sys.argv[2])
buf = b"x" * (1 << 20)
s = socket.create_connection((ip, 5999), timeout=30)
sent = 0; t0 = time.time()
while sent < total:
    n = s.send(buf[: min(len(buf), total - sent)])
    sent += n
s.close()
print(f"{sent/(time.time()-t0)/1048576:.2f}")
PY
)
echo "  TCP: ${tcp_mbs} MiB/s"
# Bracketed, same reason as the launch above — this one is only a cleanup,
# but an unbracketed pattern here kills its own shell and silently leaves
# the sink holding port 5999.
$SSH "$REMOTE" 'pkill -f "[t]cp_sink.py" 2>/dev/null; exit 0' 2>/dev/null

# ── 2. Favonius ───────────────────────────────────────────────────────────
say "Favonius (${SIZE_MB}MB x ${RUNS} runs per profile)"
[ -f "$SRC" ] && [ "$(stat -c %s "$SRC")" = "$BYTES" ] || head -c "$BYTES" /dev/urandom > "$SRC"
SRC_SHA=$(sha256sum "$SRC" | cut -d' ' -f1)

CSV="$RESULTS/hardware_$(date +%F).csv"
echo "date,peer,rtt_ms,tcp_mbs,mode,run,mbs,retx,sha_ok,blk_win_pct,blk_nowork_pct,blocked_pct_loop,flush_pct,wait_pct,stage_pct,drain_pct" > "$CSV"

# Sender stderr, every run, not only failures. The 2026-08-11 TCP-gap
# session had to reconstruct where the wall clock went by subtracting
# profiled time from elapsed, because the successful runs' PROFILE_SUMMARY
# and GATE_SUMMARY were captured into a shell variable, grepped for one
# number, and discarded. The counters cost nothing to keep and the run they
# describe cannot be repeated once the radio has drifted.
RUNLOGS="$RESULTS/hw_runs_$(date +%F)"
mkdir -p "$RUNLOGS"

printf '  %-9s %-4s %10s %8s %8s %9s %9s\n' mode run "MiB/s" retx sha256 "blk_win" "blk_loop"
echo "  ------------------------------------------------------------------"
for mode in ${MODES//,/ }; do
    for run in $(seq 1 "$RUNS"); do
        # `setsid` for the same reason as the TCP sink above — a bare
        # `nohup ... &` here is one ssh teardown away from the daemon dying
        # between bind and first packet, which the port poll below would
        # then wait out in full before the transfer failed at the handshake.
        # $DAEMON_ARGS reaches the peer daemon. Without it there is no way
        # to enable a daemon-side feature for a run, and a comparison of
        # sender profiles then silently measures the receive path of an
        # older daemon — which is how a `--streams 4` arm came to look
        # slower than `--streams 1` (measured).
        $SSH "$REMOTE" "pkill -x favonius-daemon 2>/dev/null; sleep 1;
            rm -f $DEST_ROOT/hw.bin;
            setsid nohup $REMOTE_BIN/favonius-daemon --listen 127.0.0.1:7800 \
              --protocol-listen 0.0.0.0:7801 --data-listen 0.0.0.0:7802 \
              $DAEMON_ARGS \
              --dest-root $DEST_ROOT --log-level warn > /tmp/hd.log 2>&1 < /dev/null &" 2>/dev/null
        # Wait for the control port to be BOUND. `sleep 2` raced it: about
        # one run in five failed with "deadline has elapsed" at the
        # handshake, which reads exactly like a network fault and is not one.
        for _ in $(seq 1 20); do
            $SSH "$REMOTE" "ss -lun 2>/dev/null | grep -q ':7801 ' || netstat -lun 2>/dev/null | grep -q ':7801 '" && break
            sleep 1
        done
        out=$("$REPO/target/release/favonius" send "$SRC" \
              "$REMOTE_IP:7801:$DEST_ROOT/hw.bin" --congestion "$mode" 2>&1)
        printf '%s\n' "$out" > "$RUNLOGS/${mode}_run${run}.log"
        # Accept both spellings. The client's label was corrected from "MB/s"
        # to "MiB/s" — the divisor was always 1048576, only the label was
        # wrong — and this pattern still said MB/s, so it matched nothing.
        # Every throughput cell came out empty and the run read as a total
        # transfer failure when in fact every transfer had succeeded. A
        # parser keyed on a cosmetic label breaks when the label is fixed.
        mbs=$(grep -oE 'complete: [0-9.]+ M(i)?B/s' <<<"$out" | grep -oE '[0-9.]+' | tail -1)
        retx=$(grep -oE '[0-9]+ retx' <<<"$out" | grep -oE '[0-9]+' | tail -1)
        if [ -z "$mbs" ]; then
            reason=$(grep -oE 'stalled at [0-9.]+%|deadline has elapsed|Error[^\n]*' <<<"$out" | head -1)
            printf '  %-9s %-4s %10s %8s %8s  %s\n' "$mode" "$run" "FAILED" "-" "-" "${reason:-see log}"
            echo "$(date +%F),$REMOTE_IP,${rtt:-},$tcp_mbs,$mode,$run,,,,,,,,,," >> "$CSV"
            continue
        fi
        # Where the loop's wall clock went. `blk_win` is the share of passes
        # that had work and could not send it — the controller's own window.
        # This is the number GATE_SUMMARY could not report before 7c1132e.
        pass_line=$(grep -m1 '^PASS_SUMMARY' <<<"$out")
        blk_win=$(grep -oP 'blocked_window=\d+ \(\K[0-9.]+' <<<"$pass_line")
        blk_now=$(grep -oP 'blocked_nowork=\d+ \(\K[0-9.]+' <<<"$pass_line")
        blk_loop=$(grep -oP 'blocked_ms=\d+ \(\K[0-9.]+' <<<"$pass_line")
        # The wall-clock split too. `.gitignore` excludes *.log, so the run
        # logs below are local-only; if the buckets are not lifted into the
        # CSV here, the evidence for how a session split its time is not in
        # the repository. Entry 53's finding — that the pacer's sleep is a
        # larger term than the window — lives in these four numbers.
        prof_line=$(grep -m1 '^PROFILE_SUMMARY' <<<"$out")
        # `head -1` on every one of these, and a leading space on `wait`.
        # Without the space, `wait=` also matches `feedback_in_wait=`, so the
        # capture held two values separated by a newline — which split every
        # CSV row in two, gave the rows 14 fields against a 16-field header,
        # and made the integrity summary report 16 MISMATCH on a run where
        # all 16 transfers verified `ok`. A multi-match grep does not fail
        # loudly; it corrupts the file and slanders the data.
        p_flush=$(grep -oP 'flush=\d+us \(\K[0-9.]+' <<<"$prof_line" | head -1)
        p_wait=$(grep -oP ' wait=\d+us \(\K[0-9.]+' <<<"$prof_line" | head -1)
        p_stage=$(grep -oP 'stage=\d+us \(\K[0-9.]+' <<<"$prof_line" | head -1)
        p_drain=$(grep -oP 'drain=\d+us \(\K[0-9.]+' <<<"$prof_line" | head -1)
        # Integrity, every run. A fast corrupt transfer is not a result.
        rsha=$($SSH "$REMOTE" "sha256sum $DEST_ROOT/hw.bin 2>/dev/null | cut -d' ' -f1")
        if [ "$rsha" = "$SRC_SHA" ]; then ok=ok; else ok=MISMATCH; fi
        printf '  %-9s %-4s %10s %8s %8s %8s%% %8s%%\n' \
            "$mode" "$run" "$mbs" "${retx:-0}" "$ok" "${blk_win:-?}" "${blk_loop:-?}"
        echo "$(date +%F),$REMOTE_IP,${rtt:-},$tcp_mbs,$mode,$run,$mbs,${retx:-0},$ok,${blk_win:-},${blk_now:-},${blk_loop:-},${p_flush:-},${p_wait:-},${p_stage:-},${p_drain:-}" >> "$CSV"
    done
done

say "summary"
python3 - "$CSV" "$tcp_mbs" <<'PY'
import csv, statistics as st, sys
from collections import defaultdict
rows = list(csv.DictReader(open(sys.argv[1])))
d = defaultdict(list)
blk = defaultdict(list)
for r in rows:
    if r["mbs"]:
        d[r["mode"]].append(float(r["mbs"]))
        if r.get("blk_win_pct"):
            blk[r["mode"]].append((float(r["blk_win_pct"]),
                                   float(r["blk_nowork_pct"] or 0),
                                   float(r["blocked_pct_loop"] or 0)))
tcp = float(sys.argv[2]) if sys.argv[2] else 0.0
print(f"  {'profile':10s} {'mean MB/s':>10s} {'cv':>7s} {'n':>3s} {'vs TCP':>8s}")
for m, v in d.items():
    cv = (st.stdev(v) / st.mean(v) * 100) if len(v) > 1 else 0.0
    rel = f"{st.mean(v)/tcp:.2f}x" if tcp else "-"
    print(f"  {m:10s} {st.mean(v):10.1f} {cv:6.1f}% {len(v):3d} {rel:>8s}")
# Where the deficit is. A gap against TCP with blk_win near zero is not a
# window problem, and no amount of cwnd tuning will close it.
if blk:
    print(f"\n  {'profile':10s} {'blk_window':>11s} {'blk_nowork':>11s} {'blocked/loop':>13s}")
    for m, v in blk.items():
        print(f"  {m:10s} {st.mean([x[0] for x in v]):10.1f}% "
              f"{st.mean([x[1] for x in v]):10.1f}% "
              f"{st.mean([x[2] for x in v]):12.1f}%")
print(f"\n  TCP baseline: {tcp:.1f} MB/s")
bad = [r for r in rows if r["sha_ok"] not in ("ok", "")]
print(f"  integrity: {'all runs verified' if not bad else str(len(bad)) + ' MISMATCH'}")
PY
echo
echo "wrote $CSV"
