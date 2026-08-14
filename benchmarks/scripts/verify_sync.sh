#!/usr/bin/env bash
# Favonius — high-performance file transfer over UDP
# Copyright (c) 2025-2026 Vantino SàRL
# SPDX-License-Identifier: Apache-2.0
#
# End-to-end verification of the CLI's file and directory transfer surface.
#
# Every check asserts on the RECEIVED BYTES, not on the exit code and not on
# what the sender printed. A transfer tool that reports success while writing
# nothing passes any check built on exit status, and this project has twice
# drawn a conclusion from a log line that meant something other than it
# looked like.
#
# Runs against a daemon on loopback. No containers, no traffic shaping — this
# tests correctness of the sync plan and the transfer, not performance.
#
#   ./benchmarks/scripts/verify_sync.sh

set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
FAVONIUS="$REPO/target/release/favonius"
DAEMON="$REPO/target/release/favonius-daemon"
WORK="$(mktemp -d)"
SRC="$WORK/src"
DST="$WORK/dst"
API=127.0.0.1:7800

pass=0
fail=0
ok()   { printf '  \033[32mok\033[0m    %s\n' "$1"; pass=$((pass + 1)); }
bad()  { printf '  \033[31mFAIL\033[0m  %s\n' "$1"; fail=$((fail + 1)); }
head_() { printf '\n\033[1m%s\033[0m\n' "$1"; }

cleanup() {
    [ -n "${DPID:-}" ] && kill "$DPID" 2>/dev/null
    rm -rf "$WORK"
}
trap cleanup EXIT

[ -x "$FAVONIUS" ] || { echo "build first: cargo build --release"; exit 1; }

# ── daemon ───────────────────────────────────────────────────────────────
mkdir -p "$SRC" "$DST"
# --dest-root is required for `sync`: it both confines and enables the
# filesystem endpoints sync uses to list and prune the destination.
"$DAEMON" --listen "$API" --protocol-listen 0.0.0.0:7801 \
          --data-listen 0.0.0.0:7802 --dest-root "$DST" \
          --log-level warn > "$WORK/daemon.log" 2>&1 &
DPID=$!
for _ in $(seq 1 40); do
    curl -sf "http://$API/health" > /dev/null 2>&1 && break
    sleep 0.25
done

# ── fixtures ─────────────────────────────────────────────────────────────
mkdir -p "$SRC/sub/deep" "$SRC/skipme"
head -c 1048576 /dev/urandom  > "$SRC/big.bin"
echo "alpha"                   > "$SRC/a.txt"
echo "beta"                    > "$SRC/sub/b.txt"
echo "gamma"                   > "$SRC/sub/deep/c.log"
echo "delta"                   > "$SRC/skipme/d.txt"
head -c 4096 /dev/urandom      > "$SRC/sub/e.dat"

sha() { sha256sum "$1" 2>/dev/null | cut -d' ' -f1; }

# Compare two trees by content. Returns the list of differences.
tree_diff() {
    diff -r "$1" "$2" 2>&1
}

send() { "$FAVONIUS" send "$@" --daemon "$API" 2>&1; }
sync_() { "$FAVONIUS" sync "$@" --daemon "$API" 2>&1; }

# ── 1. single file ───────────────────────────────────────────────────────
head_ "single file"
rm -rf "${DST:?}/"* 2>/dev/null
out=$(send "$SRC/big.bin" "127.0.0.1:7801:$DST/big.bin")
if [ -f "$DST/big.bin" ] && [ "$(sha "$SRC/big.bin")" = "$(sha "$DST/big.bin")" ]; then
    ok "1 MB file arrives byte-identical"
else
    bad "single file: $(echo "$out" | tail -2 | tr '\n' ' ')"
fi

# positive control: the comparison can actually fail
printf 'x' >> "$DST/big.bin"
if [ "$(sha "$SRC/big.bin")" != "$(sha "$DST/big.bin")" ]; then
    ok "control: hash comparison detects a 1-byte change"
else
    bad "control: hash comparison is broken — every check above is void"
fi

# ── 2. recursive directory ───────────────────────────────────────────────
head_ "recursive directory"
rm -rf "${DST:?}/"* 2>/dev/null
out=$(sync_ "$SRC" "127.0.0.1:7801:$DST")
d=$(tree_diff "$SRC" "$DST")
if [ -z "$d" ]; then
    ok "whole tree matches, including nested and binary files"
else
    bad "tree differs:"; echo "$d" | head -6 | sed 's/^/        /'
    echo "$out" | tail -3 | sed 's/^/        sender: /'
fi

# ── 3. --dry-run changes nothing ─────────────────────────────────────────
head_ "--dry-run"
rm -rf "${DST:?}/"* 2>/dev/null
out=$(sync_ "$SRC" "127.0.0.1:7801:$DST" --dry-run)
n=$(find "$DST" -type f | wc -l)
if [ "$n" -eq 0 ]; then
    ok "dry run transfers nothing"
else
    bad "dry run wrote $n files"
fi
if echo "$out" | grep -qiE 'a\.txt|would|plan|[0-9]+ file'; then
    ok "dry run reports a plan"
else
    bad "dry run printed no plan: $(echo "$out" | head -3 | tr '\n' ' ')"
fi

# ── 4. --exclude / --include ─────────────────────────────────────────────
head_ "filters"
rm -rf "${DST:?}/"* 2>/dev/null
out=$(sync_ "$SRC" "127.0.0.1:7801:$DST" --exclude 'skipme/*')
if [ ! -f "$DST/skipme/d.txt" ] && [ -f "$DST/a.txt" ]; then
    ok "--exclude omits the excluded path and keeps the rest"
else
    bad "--exclude: skipme present=$([ -f "$DST/skipme/d.txt" ] && echo yes || echo no), a.txt present=$([ -f "$DST/a.txt" ] && echo yes || echo no)"
fi

rm -rf "${DST:?}/"* 2>/dev/null
out=$(sync_ "$SRC" "127.0.0.1:7801:$DST" --include '*.txt')
txt=$(find "$DST" -name '*.txt' | wc -l)
non=$(find "$DST" -type f ! -name '*.txt' | wc -l)
if [ "$txt" -gt 0 ] && [ "$non" -eq 0 ]; then
    ok "--include transfers only matching files ($txt .txt, 0 others)"
else
    bad "--include: $txt .txt and $non non-.txt arrived"
fi

# ── 5. incremental: unchanged files are skipped ──────────────────────────
head_ "incremental re-sync"
rm -rf "${DST:?}/"* 2>/dev/null
sync_ "$SRC" "127.0.0.1:7801:$DST" > /dev/null
before=$(sha "$DST/big.bin")
out=$(sync_ "$SRC" "127.0.0.1:7801:$DST")
after=$(sha "$DST/big.bin")
if [ "$before" = "$after" ] && [ -z "$(tree_diff "$SRC" "$DST")" ]; then
    ok "re-sync of an unchanged tree leaves it correct"
else
    bad "re-sync corrupted or changed the tree"
fi

echo "new file" > "$SRC/added.txt"
out=$(sync_ "$SRC" "127.0.0.1:7801:$DST")
if [ -f "$DST/added.txt" ]; then
    ok "a file added since the last sync is picked up"
else
    bad "added file did not transfer"
fi

# ── 6. --checksum catches a same-length edit ─────────────────────────────
head_ "--checksum"
printf 'alpha' > "$SRC/a.txt"   # same length as "alpha\n"? no — force equal length
printf 'ALPHA\n' > "$SRC/a.txt" # 6 bytes, same as "alpha\n"
out=$(sync_ "$SRC" "127.0.0.1:7801:$DST" --checksum)
if [ "$(cat "$DST/a.txt" 2>/dev/null)" = "ALPHA" ]; then
    ok "--checksum detects an edit that preserves file length"
else
    bad "--checksum missed a same-length edit (dest still '$(cat "$DST/a.txt" 2>/dev/null)')"
fi

# ── 7. mirror mode ───────────────────────────────────────────────────────
head_ "mirror mode"
echo "orphan" > "$DST/orphan.txt"
out=$(sync_ "$SRC" "127.0.0.1:7801:$DST" --mode mirror)
if [ -f "$DST/orphan.txt" ]; then
    ok "mirror without --confirm-delete does not delete"
else
    bad "mirror deleted without --confirm-delete — that is a data-loss bug"
fi

out=$(sync_ "$SRC" "127.0.0.1:7801:$DST" --mode mirror --confirm-delete)
if [ ! -f "$DST/orphan.txt" ]; then
    ok "mirror --confirm-delete removes a file absent from the source"
else
    bad "mirror --confirm-delete left the orphan"
fi
if [ -f "$DST/a.txt" ] && [ -f "$DST/big.bin" ]; then
    ok "mirror kept every file that is in the source"
else
    bad "mirror deleted files it should have kept"
fi

# ── 8. append-only never removes ─────────────────────────────────────────
head_ "append-only mode"
echo "keep me" > "$DST/kept.txt"
out=$(sync_ "$SRC" "127.0.0.1:7801:$DST" --mode append-only --confirm-delete)
if [ -f "$DST/kept.txt" ]; then
    ok "append-only ignores --confirm-delete and keeps extra files"
else
    bad "append-only deleted a file — the mode's one guarantee"
fi

# ── 9. a file that shrinks ───────────────────────────────────────────────
head_ "overwrite with a shorter file"
head -c 100000 /dev/urandom > "$SRC/big.bin"
out=$(sync_ "$SRC" "127.0.0.1:7801:$DST")
if [ "$(sha "$SRC/big.bin")" = "$(sha "$DST/big.bin")" ]; then
    ok "a file replaced by a shorter one is not left with trailing bytes"
else
    bad "shrunk file: src $(stat -c %s "$SRC/big.bin") vs dst $(stat -c %s "$DST/big.bin" 2>/dev/null)"
fi

printf '\n%d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
