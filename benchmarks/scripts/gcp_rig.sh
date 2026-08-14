#!/usr/bin/env bash
# Favonius — high-performance file transfer over UDP
# Copyright (c) 2025-2026 Vantino SàRL
# SPDX-License-Identifier: Apache-2.0
#
# benchmarks/scripts/gcp_rig.sh
#
# Bring up (and tear down) the two-VM GCP WAN rig every WAN number in
# the WAN measurements were taken on: europe-west3 <-> europe-north1,
# ~38 ms RTT, e2-standard-4, ~1 Gbit of usable path.
#
# It existed as prose in a handoff document and was rebuilt by hand three
# times. Entry 65's lesson is the reason it is now a script: a number that
# took a rig to produce and lives outside the repository is already lost,
# and so is the rig. Roughly 10 minutes and $0.30 per cycle.
#
#   ./benchmarks/scripts/gcp_rig.sh up       # create instances + firewall
#   ./benchmarks/scripts/gcp_rig.sh deploy   # build + copy the two binaries
#   ./benchmarks/scripts/gcp_rig.sh env      # print REMOTE/REMOTE_IP exports
#   ./benchmarks/scripts/gcp_rig.sh down     # delete everything it created
#
# ONLY THE TWO BINARIES ARE COPIED, never the tree. A benchmark host has no
# use for source, and a working repository can hold more than the project
# being benchmarked.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"

TX="${TX:-favonius-tx}"
RX="${RX:-favonius-rx}"
TX_ZONE="${TX_ZONE:-europe-west3-a}"
RX_ZONE="${RX_ZONE:-europe-north1-a}"
# Optional SECOND receiver, so one sender can be measured against two paths
# in a single session — same binaries, same host, same hour. Two separate
# rig cycles cannot be compared that tightly: the tx image, the source file
# and the day all change underneath.
RX2="${RX2:-favonius-rx2}"
RX2_ZONE="${RX2_ZONE:-}"
MACHINE="${MACHINE:-e2-standard-4}"
IMAGE_FAMILY="${IMAGE_FAMILY:-ubuntu-2404-lts-amd64}"
IMAGE_PROJECT="${IMAGE_PROJECT:-ubuntu-os-cloud}"
TAG=favonius-bench
FW=favonius-bench-allow
REMOTE_BIN=/opt/favonius/bin

# Both VMs run the same Ubuntu release as the build host on purpose: the
# binaries are copied, not rebuilt, so a newer glibc on the builder than on
# the runner surfaces as a link error minutes into a benchmark.

gc() { gcloud "$@"; }

# Every host this rig owns, as name:zone. The second receiver only exists
# when RX2_ZONE is set.
hosts() {
    printf '%s:%s %s:%s' "$TX" "$TX_ZONE" "$RX" "$RX_ZONE"
    [ -n "$RX2_ZONE" ] && printf ' %s:%s' "$RX2" "$RX2_ZONE"
    printf '\n'
}

up() {
    gc compute firewall-rules describe "$FW" >/dev/null 2>&1 || \
    gc compute firewall-rules create "$FW" \
        --allow=tcp,udp,icmp --source-ranges=10.128.0.0/9 \
        --target-tags="$TAG" --description="Favonius benchmark rig (temporary)"
    for spec in $(hosts); do
        local name="${spec%%:*}" zone="${spec##*:}"
        gc compute instances describe "$name" --zone "$zone" >/dev/null 2>&1 && continue
        gc compute instances create "$name" --zone "$zone" \
            --machine-type="$MACHINE" --image-family="$IMAGE_FAMILY" \
            --image-project="$IMAGE_PROJECT" --tags="$TAG" &
    done
    wait
    gc compute instances list --filter="tags.items=$TAG"
}

# tx drives the benchmark and needs its own key to rx. OS Login is enforced
# project-wide, so the key goes to the login profile rather than to
# authorized_keys, and a TTL keeps it from outliving the rig.
keys() {
    gc compute ssh "$TX" --zone "$TX_ZONE" --command \
        "test -f ~/.ssh/id_ed25519 || ssh-keygen -q -t ed25519 -N '' -f ~/.ssh/id_ed25519; cat ~/.ssh/id_ed25519.pub" \
        > /tmp/favonius_rig_tx.pub || return 1
    gc compute os-login ssh-keys add --key-file=/tmp/favonius_rig_tx.pub --ttl=1d >/dev/null
    local ips; ips="$(rx_ip) $(rx2_ip)"
    gc compute ssh "$TX" --zone "$TX_ZONE" --command \
        "for ip in $ips; do ssh-keyscan -H \$ip >> ~/.ssh/known_hosts 2>/dev/null; done; echo ok"
}

rx_ip() { gc compute instances describe "$RX" --zone "$RX_ZONE" \
    --format='get(networkInterfaces[0].networkIP)'; }
rx2_ip() { [ -n "$RX2_ZONE" ] || return 0; gc compute instances describe "$RX2" --zone "$RX2_ZONE" \
    --format='get(networkInterfaces[0].networkIP)'; }

deploy() {
    (cd "$REPO" && cargo build --release -p ahp-cli -p ahp-daemon) || return 1
    for spec in $(hosts); do
        local name="${spec%%:*}" zone="${spec##*:}"
        gc compute ssh "$name" --zone "$zone" --command "sudo mkdir -p $REMOTE_BIN && sudo chown \$(id -u) $REMOTE_BIN"
        # Only these two files. Never the tree.
        gc compute scp "$REPO/target/release/favonius" "$REPO/target/release/favonius-daemon" \
            "$name:$REMOTE_BIN/" --zone "$zone" &
    done
    wait
    gc compute ssh "$TX" --zone "$TX_ZONE" --command \
        "test -s /tmp/hw_bench_src.bin || head -c 536870912 /dev/urandom > /tmp/hw_bench_src.bin; ls -l /tmp/hw_bench_src.bin"
}

env_exports() {
    local ip user
    ip="$(rx_ip)"
    user="$(gc compute ssh "$TX" --zone "$TX_ZONE" --command 'id -un' 2>/dev/null | tail -1)"
    cat <<EOF
# on tx (gcloud compute ssh $TX --zone $TX_ZONE):
export REMOTE=$user@$ip REMOTE_IP=$ip DEST_ROOT=/dev/shm REMOTE_BIN=$REMOTE_BIN
${RX2_ZONE:+# second receiver ($RX2_ZONE): REMOTE_IP=$(rx2_ip)}
EOF
}

down() {
    for spec in $(hosts); do
        gc compute instances delete "${spec%%:*}" --zone "${spec##*:}" --quiet --delete-disks=all &
    done
    wait
    gc compute firewall-rules delete "$FW" --quiet
    echo "-- remaining (must be empty of $TAG) --"
    gc compute instances list --filter="tags.items=$TAG"
    gc compute disks list --filter="name~'favonius-'"
}

case "${1:-}" in
    up) up ;;
    keys) keys ;;
    deploy) deploy ;;
    env) env_exports ;;
    down) down ;;
    *) echo "usage: $0 {up|keys|deploy|env|down}" >&2; exit 64 ;;
esac
