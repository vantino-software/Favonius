#!/usr/bin/env bash

# Favonius — high-performance file transfer over UDP
# Copyright (c) 2025-2026 Vantino SàRL
# SPDX-License-Identifier: Apache-2.0

# Favonius: AF_XDP TX benchmark through veth pair.
# Usage: sudo ./benchmarks/scripts/bench_xdp.sh [--size SIZE_MB]

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/bench_common.sh"
set +e

SIZE_MB="${SIZE_MB:-128}"
NS_NAME="favonius-xdp-bench"
VETH_HOST="xdp-host"
VETH_NS="xdp-ns"
HOST_IP="10.88.0.1"
NS_IP="10.88.0.2"
CONTROL_PORT=7801
DATA_PORT=7802
API_PORT=7800

while [[ $# -gt 0 ]]; do
    case "$1" in
        --size) SIZE_MB="$2"; shift 2 ;;
        *) echo "Unknown: $1"; exit 1 ;;
    esac
done

DATA_BYTES=$((SIZE_MB * 1048576))

if [ "$(id -u)" != "0" ]; then
    echo "ERROR: requires root for namespaces + XDP."
    exit 1
fi

ensure_dirs
check_favonius || exit 1

cleanup() {
    ip netns del "$NS_NAME" 2>/dev/null || true
    ip link del "$VETH_HOST" 2>/dev/null || true
    pkill -f favonius-daemon 2>/dev/null || true
}
trap cleanup EXIT

# Setup namespace + veth.
cleanup
ip netns add "$NS_NAME"
ip link add "$VETH_HOST" type veth peer name "$VETH_NS"
ip link set "$VETH_NS" netns "$NS_NAME"
ip addr add "$HOST_IP/24" dev "$VETH_HOST"
ip link set "$VETH_HOST" up
ip netns exec "$NS_NAME" ip addr add "$NS_IP/24" dev "$VETH_NS"
ip netns exec "$NS_NAME" ip link set "$VETH_NS" up
ip netns exec "$NS_NAME" ip link set lo up

# Populate ARP cache on host side so XDP sender has the MAC.
# Send an ARP request via a ping.
ping -c 1 -W 1 "$NS_IP" > /dev/null 2>&1 || true

log_ok "veth ready: $HOST_IP <-> $NS_IP"
log_info "host MAC: $(cat /sys/class/net/$VETH_HOST/address)"
log_info "ns MAC: $(ip netns exec $NS_NAME cat /sys/class/net/$VETH_NS/address)"

# Check ARP cache
arp -n | grep "$NS_IP" || log_warn "ARP entry missing"

# Generate test file.
TEST_FILE="$SRC_DIR/xdp_${SIZE_MB}mb.bin"
if [ ! -f "$TEST_FILE" ] || [ "$(stat -c%s "$TEST_FILE")" != "$DATA_BYTES" ]; then
    dd if=/dev/urandom of="$TEST_FILE" bs=1M count="$SIZE_MB" 2>/dev/null
fi

# Start daemon in namespace.
ip netns exec "$NS_NAME" "$FAVONIUS_DAEMON_BIN" \
    --listen "$NS_IP:$API_PORT" \
    --protocol-listen "$NS_IP:$CONTROL_PORT" \
    --data-listen "$NS_IP:$DATA_PORT" \
    --log-level warn &
DPID=$!
sleep 1

# Run tests.
log_header "A: GSO baseline (unencrypted)"
clean_dst
DEST_FILE="$DST_DIR/recv-gso.bin"
start=$(date +%s%N)
"$FAVONIUS_BIN" send "$TEST_FILE" "$NS_IP:$CONTROL_PORT:$DEST_FILE" \
    --compression none --congestion udt --log-level warn 2>&1 | tail -3
end=$(date +%s%N)
gso_ms=$(( (end - start) / 1000000 ))

# Restart daemon.
kill $DPID 2>/dev/null; wait $DPID 2>/dev/null
ip netns exec "$NS_NAME" "$FAVONIUS_DAEMON_BIN" \
    --listen "$NS_IP:$API_PORT" \
    --protocol-listen "$NS_IP:$CONTROL_PORT" \
    --data-listen "$NS_IP:$DATA_PORT" \
    --log-level warn &
DPID=$!
sleep 1

log_header "B: AF_XDP"
clean_dst
DEST_FILE="$DST_DIR/recv-xdp.bin"
start=$(date +%s%N)
FAVONIUS_XDP_IFACE="$VETH_HOST" "$FAVONIUS_BIN" send "$TEST_FILE" "$NS_IP:$CONTROL_PORT:$DEST_FILE" \
    --pacing xdp --compression none --congestion udt --log-level warn 2>&1 | tail -5
end=$(date +%s%N)
xdp_ms=$(( (end - start) / 1000000 ))

kill $DPID 2>/dev/null; wait $DPID 2>/dev/null

echo ""
log_header "RESULTS"
if [ "$gso_ms" -gt 0 ]; then
    gso_mbps=$(awk "BEGIN { printf \"%.1f\", ($DATA_BYTES / 1048576) / ($gso_ms / 1000) }")
else
    gso_mbps="?"
fi
if [ "$xdp_ms" -gt 0 ]; then
    xdp_mbps=$(awk "BEGIN { printf \"%.1f\", ($DATA_BYTES / 1048576) / ($xdp_ms / 1000) }")
else
    xdp_mbps="?"
fi
echo "  GSO:     ${gso_ms}ms  ${gso_mbps} MB/s"
echo "  AF_XDP:  ${xdp_ms}ms  ${xdp_mbps} MB/s"
