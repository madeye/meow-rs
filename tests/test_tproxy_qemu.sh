#!/usr/bin/env bash
# End-to-end transparent proxy integration test using Docker.
#
# Runs a privileged Linux container with nftables support, builds mihomo
# inside it, starts the tproxy listener, and verifies firewall setup,
# traffic interception, SNI extraction, and clean teardown.
#
# Works on both macOS (Docker Desktop uses native ARM64 VM) and Linux.
#
# Requirements: docker
#
# Usage: bash tests/test_tproxy_qemu.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

# --- Dependency check ---
if ! command -v docker &>/dev/null; then
    echo "SKIP: docker not found in PATH"
    exit 0
fi

if ! docker info >/dev/null 2>&1; then
    echo "SKIP: docker daemon not running"
    exit 0
fi

echo "=== Building test container ==="

# Build a Docker image with Rust toolchain + nftables
DOCKER_IMAGE="mihomo-tproxy-test"

docker build -t "$DOCKER_IMAGE" -f - "$ROOT_DIR" <<'DOCKERFILE'
FROM rust:1-alpine AS builder
# git + perl + make + cmake are required by boring-sys to build the bundled
# BoringSSL when the boring-tls feature is on (default since 11970cf).
RUN apk add --no-cache musl-dev nftables bash busybox-extras \
    git perl make cmake clang clang-dev linux-headers g++
WORKDIR /src
COPY . .
RUN cargo build -p mihomo-app 2>&1

FROM alpine:latest
RUN apk add --no-cache nftables bash busybox-extras
COPY --from=builder /src/target/debug/mihomo /usr/local/bin/mihomo
COPY tests/tproxy-qemu/mihomo-tproxy.yaml /etc/mihomo-tproxy.yaml
COPY tests/tproxy-qemu/guest-init.sh /run-tests.sh
RUN chmod +x /run-tests.sh
DOCKERFILE

echo ""
echo "=== Running tproxy tests in container ==="

CONTAINER_LOG=$(mktemp)
docker run --rm --privileged \
    "$DOCKER_IMAGE" \
    /bin/bash /run-tests.sh 2>&1 | tee "$CONTAINER_LOG" || true

echo ""
echo "=== Parsing test results ==="

PASS_COUNT=0
FAIL_COUNT=0
TOTAL_COUNT=0

while IFS= read -r line; do
    test_name="${line#TEST_PASS:}"
    echo "  PASS: $test_name"
    PASS_COUNT=$((PASS_COUNT + 1))
    TOTAL_COUNT=$((TOTAL_COUNT + 1))
done < <(grep "^TEST_PASS:" "$CONTAINER_LOG" 2>/dev/null || true)

while IFS= read -r line; do
    test_name="${line#TEST_FAIL:}"
    echo "  FAIL: $test_name"
    FAIL_COUNT=$((FAIL_COUNT + 1))
    TOTAL_COUNT=$((TOTAL_COUNT + 1))
done < <(grep "^TEST_FAIL:" "$CONTAINER_LOG" 2>/dev/null || true)

rm -f "$CONTAINER_LOG"

echo ""
echo "Results: $PASS_COUNT passed, $FAIL_COUNT failed, $TOTAL_COUNT total"

if [ "$TOTAL_COUNT" -eq 0 ]; then
    echo ""
    echo "=== FAIL: No tests ran ==="
    exit 1
elif [ "$FAIL_COUNT" -gt 0 ]; then
    echo ""
    echo "=== FAIL: $FAIL_COUNT test(s) failed ==="
    exit 1
else
    echo ""
    echo "=== All TProxy integration tests passed ==="
    exit 0
fi
