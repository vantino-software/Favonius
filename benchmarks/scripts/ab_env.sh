#!/usr/bin/env bash
# Favonius — high-performance file transfer over UDP
# Copyright (c) 2025-2026 Vantino SàRL
# SPDX-License-Identifier: Apache-2.0
#
# benchmarks/scripts/ab_env.sh
#
# A/B two settings of one environment variable over a real peer, from a
# single binary, with the order counterbalanced.
#
# Why it exists, and why it is not just a loop over two arms:
#
#   1. ONE BINARY. Rebuilding between arms on a rig with ~20% cross-batch
#      drift produces differences that are not the change. The variable
#      under test must be read at runtime.
#
#   2. COUNTERBALANCED ORDER (ABBA). A previous A/B here ran control first
#      in every round. Pairing protects against a shock common to both
#      transfers in a pair; it does nothing about a shock that lands
#      *between* them, which then hits the second arm every time. That is a
#      real risk on a radio: thermal state, rate adaptation, a neighbour
#      starting a download. ABBA puts each arm first half the time, so an
#      order effect cancels in the mean instead of loading onto one arm.
#      (2026-08-11: the confound was found by review, not by the author.)
#
#   3. IT REPORTS ITS OWN MINIMUM DETECTABLE EFFECT. The same A/B reported
#      "no throughput change, t=-0.44" from n=6 without noticing that the
#      design could only have detected ~20%. A null is not a finding unless
#      you know what the test could see. The MDE is printed next to the
#      result, every time, so the two cannot be read apart.
#
# Usage:
#   REMOTE=pi@10.0.0.2 REMOTE_IP=10.0.0.2 DEST_ROOT=/dev/shm \
#     ./benchmarks/scripts/ab_env.sh FAVONIUS_PACE_DEBT 0 1 --pairs 10
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
RESULTS="$REPO/benchmarks/results"; mkdir -p "$RESULTS"

VAR="${1:?usage: ab_env.sh VAR CONTROL_VALUE TEST_VALUE [--pairs N]}"
CTL="${2:?}"; TST="${3:?}"; shift 3
PAIRS=8; SRC=/tmp/hw_bench_src.bin
while [[ $# -gt 0 ]]; do
    case "$1" in
        --pairs) PAIRS="$2"; shift 2 ;;
        --src) SRC="$2"; shift 2 ;;
        *) echo "unknown argument: $1" >&2; exit 64 ;;
    esac
done

REMOTE="${REMOTE:?set REMOTE}"; REMOTE_IP="${REMOTE_IP:?set REMOTE_IP}"
REMOTE_BIN="${REMOTE_BIN:-/opt/favonius/bin}"
DEST_ROOT="${DEST_ROOT:-/dev/shm}"
# Extra daemon flags, identical in both arms. Some knobs are only reachable
# through a daemon that was started a particular way — `--data-port-range` is
# what makes per-stream data ports available at all — and without this the A
# arm and the B arm would silently be the same daemon.
DAEMON_ARGS="${DAEMON_ARGS:-}"
# Extra sender flags, identical in both arms — `--encrypt`, `--streams N`,
# `--congestion X`. A knob whose effect depends on the pipeline it runs in
# (per-stream sockets under encryption, say) is otherwise only ever measured
# in the default configuration.
SEND_ARGS="${SEND_ARGS:-}"
SSH="ssh -o BatchMode=yes -o ConnectTimeout=10"
DEST="$DEST_ROOT/ab.bin"
SRC_SHA=$(sha256sum "$SRC" | cut -d' ' -f1)
# One file per run, never per (variable, day). Three A/Bs of the same knob in
# one session — different pipelines, different pair counts — silently
# overwrote each other on 2026-08-12 and two datasets survived only as
# summary text in a terminal. The rig is reproducible; the rows were not.
CSV="$RESULTS/ab_${VAR,,}_$(date +%F).csv"
run_n=1
while [ -e "$CSV" ]; do
    run_n=$((run_n + 1))
    CSV="$RESULTS/ab_${VAR,,}_$(date +%F)_$run_n.csv"
done

echo "pair,slot,arm,value,mbs,retx,retx_pct,sha,wait_pct,blocked_pct,flush_pct" > "$CSV"
printf '  %-5s %-5s %-22s %8s %8s %8s %9s\n' pair slot "$VAR" "MB/s" "retx%" "wait%" "blocked%"

# The variable under test is exported to BOTH ends: some knobs are
# sender-side, some daemon-side, and guessing wrong yields a null that
# looks like a finding.
run_one() {  # $1=pair $2=slot $3=value
    $SSH "$REMOTE" 'pkill -x favonius-daemon 2>/dev/null; exit 0'; sleep 1
    $SSH "$REMOTE" "rm -f $DEST; $VAR=$3 setsid nohup $REMOTE_BIN/favonius-daemon \
        --listen 127.0.0.1:7800 --protocol-listen 0.0.0.0:7801 \
        --data-listen 0.0.0.0:7802 --dest-root $DEST_ROOT --log-level warn \
        $DAEMON_ARGS > /tmp/hd.log 2>&1 < /dev/null & disown"
    for _ in $(seq 1 20); do
        $SSH "$REMOTE" "ss -lun 2>/dev/null | grep -q ':7801 '" && break; sleep 1
    done
    local o mbs pkts rtx rp bl wt fl ok rsha
    # shellcheck disable=SC2086 # SEND_ARGS is a flag list, deliberately split
    o=$(env "$VAR=$3" "$REPO/target/release/favonius" send "$SRC" \
        "$REMOTE_IP:7801:$DEST" $SEND_ARGS 2>&1)
    # Anchor on the completion line. A bare `[0-9]+(?= retx)` also matches
    # CC_SUMMARY's "packets=N retx=", which made every run report 100%.
    local done_line
    done_line=$(grep -m1 -oP 'complete: [0-9.]+ MB/s \([0-9]+ bytes in [0-9.]+s, [0-9]+ pkts, [0-9]+ retx' <<<"$o")
    mbs=$(grep -oP 'complete: \K[0-9.]+' <<<"$done_line")
    pkts=$(grep -oP '\K[0-9]+(?= pkts)' <<<"$done_line")
    rtx=$(grep -oP '\K[0-9]+(?= retx)' <<<"$done_line")
    bl=$(grep -m1 '^PROFILE_SUMMARY' <<<"$o" | grep -oP 'blocked=[0-9]+us \(\K[0-9.]+')
    wt=$(grep -m1 '^PROFILE_SUMMARY' <<<"$o" | grep -oP ' wait=[0-9]+us \(\K[0-9.]+')
    fl=$(grep -m1 '^PROFILE_SUMMARY' <<<"$o" | grep -oP 'flush=[0-9]+us \(\K[0-9.]+')
    if [ -z "$mbs" ]; then
        printf '  %-5s %-5s %-22s %8s\n' "$1" "$2" "$3" FAILED
        echo "$1,$2,$3,$3,,,,,,," >> "$CSV"; return
    fi
    rp=$(awk -v r="$rtx" -v p="$pkts" 'BEGIN{printf "%.2f", 100*r/p}')
    rsha=$($SSH "$REMOTE" "sha256sum $DEST 2>/dev/null | cut -d' ' -f1")
    [ "$rsha" = "$SRC_SHA" ] && ok=ok || ok=MISMATCH
    printf '  %-5s %-5s %-22s %8s %8s %8s %9s  %s\n' "$1" "$2" "$3" "$mbs" "$rp" "${wt:-?}" "${bl:-?}" "$ok"
    echo "$1,$2,$3,$3,$mbs,$rtx,$rp,$ok,${wt:-},${bl:-},${fl:-}" >> "$CSV"
}

slot=0
for p in $(seq 1 "$PAIRS"); do
    # ABBA: odd pairs run control first, even pairs run test first.
    if [ $((p % 2)) -eq 1 ]; then order="$CTL $TST"; else order="$TST $CTL"; fi
    for v in $order; do slot=$((slot+1)); run_one "$p" "$slot" "$v"; done
done

python3 - "$CSV" "$CTL" "$TST" <<'PY'
import csv, sys, math, statistics as st
rows=[r for r in csv.DictReader(open(sys.argv[1])) if r["mbs"]]
ctl,tst=sys.argv[2],sys.argv[3]
pairs={}
for r in rows: pairs.setdefault(r["pair"],{})[r["value"]]=r
full=[p for p in pairs.values() if ctl in p and tst in p]
def col(k,v): return [float(p[v][k]) for p in full]
def have(k):
    return all(p[c][k] not in (None,"") for p in full for c in (ctl,tst))
print(f"\n  complete pairs: {len(full)}")
print(f"  {'':14s} {'control':>9s} {'test':>9s} {'delta':>9s} {'paired t':>9s}")
for lab,k in [("throughput","mbs"),("retx %","retx_pct"),("wait %","wait_pct"),("blocked %","blocked_pct")]:
    if not have(k):
        print(f"  {lab:14s} (not captured in every run — skipped)"); continue
    a,b=col(k,ctl),col(k,tst)
    d=[y-x for x,y in zip(a,b)]
    if len(d)<2 or st.stdev(d)==0: continue
    t=st.mean(d)/(st.stdev(d)/math.sqrt(len(d)))
    print(f"  {lab:14s} {st.mean(a):9.2f} {st.mean(b):9.2f} {100*(st.mean(b)/st.mean(a)-1):+8.1f}% {t:+9.2f}")
a,b=col("mbs",ctl),col("mbs",tst)
d=[y-x for x,y in zip(a,b)]; n=len(d); sd=st.stdev(d); se=sd/math.sqrt(n)
# two-sided .05 critical t and one-sided .2 t, by df
tc={1:12.71,2:4.303,3:3.182,4:2.776,5:2.571,6:2.447,7:2.365,8:2.306,9:2.262,
    10:2.228,11:2.201,12:2.179,14:2.145,19:2.093,29:2.045}.get(n-1,1.96)
tb={1:1.376,2:1.061,3:0.978,4:0.941,5:0.920,6:0.906,7:0.896,8:0.889,9:0.883,
    10:0.879,11:0.876,12:0.873,14:0.868,19:0.861,29:0.854}.get(n-1,0.842)
mde=(tc+tb)*se
print(f"\n  sd(paired delta) {sd:.2f} MB/s   se {se:.2f}")
print(f"  95% CI on delta: {st.mean(d)-tc*se:+.2f} to {st.mean(d)+tc*se:+.2f} MB/s "
      f"({100*(st.mean(d)-tc*se)/st.mean(a):+.1f}% to {100*(st.mean(d)+tc*se)/st.mean(a):+.1f}%)")
print(f"  MINIMUM DETECTABLE EFFECT at n={n}, power .8: {mde:.2f} MB/s = {100*mde/st.mean(a):.1f}%")
print(f"  -> a null here rules out nothing smaller than {100*mde/st.mean(a):.1f}%.")
PY
echo; echo "wrote $CSV"
