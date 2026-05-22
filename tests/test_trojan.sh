#!/usr/bin/env bash
# Trojan adapter integration test runner.
#
# Uses an embedded mock Trojan server (no external binary needed).
# Self-signed TLS cert is generated in-process via rcgen.
#
# Usage: bash tests/test_trojan.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

cd "$ROOT_DIR"

echo "=== Running Trojan integration tests ==="

echo "Building..."
cargo build -p meow-proxy 2>&1

echo "Running integration test..."
if cargo test --test trojan_integration -- --nocapture 2>&1; then
    echo ""
    echo "=== PASS: All Trojan integration tests passed ==="
else
    echo ""
    echo "=== FAIL: Trojan integration tests failed ==="
    exit 1
fi
