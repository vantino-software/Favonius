#!/usr/bin/env bash
# Favonius — high-performance file transfer over UDP
# Copyright (c) 2025-2026 Vantino SàRL
# SPDX-License-Identifier: Apache-2.0
#
# benchmarks/scripts/install_competitors.sh
#
# Build tsunami-udp, UDT4 and quinn (QUIC) from source on a benchmark host.
#
# Run it ON the host, not from a workstation: `bash install_competitors.sh`.
# Works on x86_64 and armv7 (the Pi), Ubuntu/Debian. Everything lands in
# /opt/competitors/bin.
#
# Why a script rather than a page of instructions: an earlier run measured uftp
# and tsunami, reported both, and both numbers were wrong — uftp needed
# `-M` for unicast announce on a network without multicast, and tsunami
# exits non-zero after a normal `quit`, which the harness read as failure.
# Neither trap is discoverable from the tool's own output, and the rig they
# were found on has been deleted twice since. A recipe that is not
# executable is a recipe that will be rediscovered.
#
# Each tool is independent: a failure is logged and the script continues,
# because three tools that mostly build is a better outcome than one that
# aborts the run. The summary at the end is the authority on what exists.
set -uo pipefail

PREFIX="${PREFIX:-/opt/competitors}"
SRC="$PREFIX/src"
BIN="$PREFIX/bin"
LOG="$PREFIX/build.log"
sudo mkdir -p "$SRC" "$BIN"
sudo chown -R "$(id -u):$(id -g)" "$PREFIX"
: > "$LOG"

say() { printf '\n\033[1m== %s\033[0m\n' "$1"; }
ok()  { printf '   \033[32mok\033[0m   %s\n' "$1"; }
bad() { printf '   \033[31mFAIL\033[0m %s (see %s)\n' "$1" "$LOG"; }

say "build dependencies"
sudo DEBIAN_FRONTEND=noninteractive apt-get -qq update >> "$LOG" 2>&1
sudo DEBIAN_FRONTEND=noninteractive apt-get -qq install -y \
    build-essential autoconf automake libtool git curl pkg-config \
    libssl-dev ca-certificates uftp iperf3 >> "$LOG" 2>&1 \
    && ok "toolchain" || bad "apt-get"

# ── tsunami-udp ──────────────────────────────────────────────────────────
# Rate-controlled UDP with a TCP control channel. Upstream is SourceForge;
# the GitHub mirrors are tried first because SF's "latest/download"
# redirect is unreliable from a headless host.
#
# TRAP (measured): `tsunami ... quit` exits NON-ZERO after a completed
# transfer. Any harness that checks the exit status will record a
# successful transfer as a failure — which is how it was first reported.
say "tsunami-udp"
if [ ! -x "$BIN/tsunamid" ]; then
    cd "$SRC"
    rm -rf tsunami-udp
    got=""
    # Verified to clone 2026-08-12. The SourceForge git endpoint
    # (git.code.sf.net/p/tsunami-udp/code) 404s, and a wrong GitHub path
    # does not fail cleanly — git asks for a username and the clone hangs
    # or dies with "could not read Username", which reads like an auth
    # problem rather than a typo.
    for url in \
        "https://github.com/cheetahmobile/tsunami-udp.git" \
        "https://github.com/sebsto/tsunami-udp.git" \
        "https://github.com/rriley/tsunami-udp.git"
    do
        if GIT_TERMINAL_PROMPT=0 git clone -q --depth 1 "$url" tsunami-udp >> "$LOG" 2>&1; then got="$url"; break; fi
    done
    if [ -z "$got" ]; then
        bad "tsunami: no source could be cloned"
    else
        cd tsunami-udp
        echo "tsunami source: $got" >> "$LOG"
        # The tree ships a generated Makefile, so plain `make` works and
        # `./configure` does not exist. Fall back to autoreconf for forks
        # that ship only configure.ac.
        { make -j"$(nproc)" || { autoreconf -fi && ./configure && make -j"$(nproc)"; }; } >> "$LOG" 2>&1
        n=0
        for f in server/tsunamid client/tsunami; do
            [ -x "$f" ] && { cp "$f" "$BIN/"; n=$((n+1)); }
        done
        [ "$n" -eq 2 ] && ok "tsunamid + tsunami" || bad "tsunami: built $n of 2 binaries"
    fi
else
    ok "tsunamid (already present)"
fi

# ── UDT4 ─────────────────────────────────────────────────────────────────
# The reference rate-based UDP transport. Its `sendfile`/`recvfile` apps are
# what a file-transfer comparison should use.
#
# UDT4 predates C++11 hygiene: it omits <cstring>, <cstdlib> and <unistd.h>
# and will not compile on any modern GCC without them. Patching by
# insertion rather than by a patch file, because the fork layouts differ.
say "UDT4"
if [ ! -x "$BIN/sendfile" ]; then
    cd "$SRC"
    rm -rf udt
    got=""
    # MUST be a fork that ships app/ — the library alone gives no
    # file-transfer program, and netvirt/udt4 (the first hit) has no app
    # directory at all.
    for url in \
        "https://github.com/whtghst1/udt.git" \
        "https://github.com/gary109/UDT.git" \
        "https://github.com/libinzhangyuan/udt_patch_for_epoll.git"
    do
        if GIT_TERMINAL_PROMPT=0 git clone -q --depth 1 "$url" udt >> "$LOG" 2>&1; then
            [ -d "$(find "$SRC/udt" -maxdepth 3 -type d -name app | head -1)" ] && { got="$url"; break; }
            rm -rf udt
        fi
    done
    if [ -z "$got" ]; then
        bad "UDT: no source with app/ could be cloned"
    else
        echo "udt source: $got" >> "$LOG"
        root="$(cd "$(dirname "$(find "$SRC/udt" -maxdepth 3 -type d -name app | head -1)")" && pwd)"
        echo "udt root: $root" >> "$LOG"
        # UDT4 predates C++11 hygiene and omits <cstring>/<cstdlib>; it does
        # not compile on any modern GCC without them.
        for f in "$root"/src/*.cpp "$root"/src/*.h "$root"/app/*.cpp; do
            [ -f "$f" ] || continue
            grep -q '#include <cstring>' "$f" || sed -i '1i #include <cstring>' "$f"
            grep -q '#include <cstdlib>' "$f" || sed -i '1i #include <cstdlib>' "$f"
        done
        arch=AMD64
        case "$(uname -m)" in
            # An UNKNOWN arch value is the correct one on ARM. The makefile
            # only branches on IA32/AMD64/IA64/POWERPC, and each branch
            # defines a matching macro that selects an inline-assembly
            # clock in common.cpp — `arch=IA32` on a Pi compiles `rdtsc`
            # and dies with "impossible constraint in asm". Matching
            # nothing defines nothing, and UDT falls through to its
            # portable gettimeofday path.
            armv7l|armv6l|aarch64) arch=ARM ;;
            i?86)                  arch=IA32 ;;
        esac
        # Do NOT pass CCFLAGS here. `make -e` lets the environment override
        # the makefile, and app/Makefile sets `-I../src` in CCFLAGS — so
        # supplying our own silently removed the include path and the app
        # build failed with "udt.h: No such file or directory" while the
        # library built fine. The sed patches above are what modern GCC
        # actually needs.
        make -C "$root" -e os=LINUX arch="$arch" >> "$LOG" 2>&1
        n=0
        for f in "$root"/app/sendfile "$root"/app/recvfile; do
            [ -x "$f" ] && { cp "$f" "$BIN/"; n=$((n+1)); }
        done
        [ -f "$root/src/libudt.so" ] && cp "$root/src/libudt.so" "$BIN/"
        [ "$n" -eq 2 ] && ok "sendfile + recvfile" || bad "UDT: built $n of 2 apps"
    fi
else
    ok "UDT sendfile (already present)"
fi

# ── quinn (QUIC) ─────────────────────────────────────────────────────────
# quinn's own examples move a file over QUIC, which is the comparison we
# want; `perf` measures a synthetic stream and is not the same question.
#
# On armv7 this is the slow one — budget 15-30 minutes on a Pi 4. Nothing
# here is parallel to the network test, so it is worth starting first.
say "quinn (QUIC)"
if [ ! -x "$BIN/quinn-server" ]; then
    if ! command -v cargo > /dev/null; then
        curl -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal >> "$LOG" 2>&1
    fi
    export PATH="$HOME/.cargo/bin:$PATH"
    cd "$SRC"
    rm -rf quinn
    if git clone --depth 1 https://github.com/quinn-rs/quinn.git >> "$LOG" 2>&1; then
        cd quinn
        if cargo build --release --examples >> "$LOG" 2>&1; then
            n=0
            for f in target/release/examples/server target/release/examples/client; do
                [ -x "$f" ] && { cp "$f" "$BIN/quinn-$(basename "$f")"; n=$((n+1)); }
            done
            [ "$n" -eq 2 ] && ok "quinn-server + quinn-client" || bad "quinn: built $n of 2 examples"
        else
            bad "quinn: cargo build failed"
        fi
    else
        bad "quinn: clone failed"
    fi
else
    ok "quinn-server (already present)"
fi

say "summary"
for b in tsunamid tsunami sendfile recvfile quinn-server quinn-client; do
    if [ -x "$BIN/$b" ]; then printf '   %-14s %s\n' "$b" "$BIN/$b"
    else printf '   %-14s MISSING\n' "$b"; fi
done
echo
echo "   build log: $LOG"
