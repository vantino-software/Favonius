#!/usr/bin/env bash

# Favonius — high-performance file transfer over UDP
# Copyright (c) 2025-2026 Vantino SàRL
# SPDX-License-Identifier: Apache-2.0

# benchmarks/scripts/bench_quick.sh
# Quick validation run with a small file (128 MB, 1 run per tool).
# Use this to verify the benchmark harness before the full run.
#
# Usage: ./bench_quick.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "╔══════════════════════════════════════════════════════════╗"
echo "║  Favonius Benchmark — Quick validation (128 MB, 1 run)  ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo

exec "$SCRIPT_DIR/bench_loopback_large.sh" --size 128 --runs 1
