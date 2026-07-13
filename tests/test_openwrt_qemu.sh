#!/usr/bin/env bash
# QEMU-based OpenWrt end-to-end test (#284).
#
# Boots an official OpenWrt armsr/armv8 initramfs image in
# qemu-system-aarch64, builds the meow + luci-app-meow .ipk packages with
# openwrt/build-ipk.sh, installs them inside the guest over the slirp
# network, and verifies: opkg install, procd service lifecycle, REST API,
# the built-in web panel at /ui, HTTP proxying through mixed-port, and the
# LuCI app file layout.
#
# Requirements: qemu-system-aarch64, expect, python3, curl,
#               cargo-zigbuild + aarch64-unknown-linux-musl target
#               (unless MEOW_BINARY points at a prebuilt aarch64 musl binary)
#
# Environment overrides:
#   MEOW_BINARY          prebuilt static aarch64 musl meow binary
#   OPENWRT_VERSION      OpenWrt release to test against (default below)
#   OPENWRT_IMAGE_CACHE  directory to cache the downloaded image
#
# Usage: bash tests/test_openwrt_qemu.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

OPENWRT_VERSION="${OPENWRT_VERSION:-24.10.7}"
IMAGE_NAME="openwrt-${OPENWRT_VERSION}-armsr-armv8-generic-initramfs-kernel.bin"
IMAGE_URL="https://downloads.openwrt.org/releases/${OPENWRT_VERSION}/targets/armsr/armv8/${IMAGE_NAME}"
CACHE_DIR="${OPENWRT_IMAGE_CACHE:-$ROOT_DIR/target/openwrt-images}"
RUST_TARGET="aarch64-unknown-linux-musl"

# --- Dependency checks (SKIP, not FAIL, when tooling is absent) ---
for dep in qemu-system-aarch64 expect python3 curl; do
    if ! command -v "$dep" &>/dev/null; then
        echo "SKIP: $dep not found in PATH"
        exit 0
    fi
done

# --- Build (or locate) the aarch64 musl binary ---
if [ -n "${MEOW_BINARY:-}" ]; then
    BINARY="$MEOW_BINARY"
else
    if ! command -v cargo-zigbuild &>/dev/null; then
        echo "SKIP: cargo-zigbuild not found (set MEOW_BINARY to use a prebuilt binary)"
        exit 0
    fi
    echo "=== Building static ${RUST_TARGET} binary ==="
    # boring-tls needs a target clang; use the rustls-only `full` feature set
    # here (same trade-off as tests/test_tproxy_qemu.sh). Packaging, procd,
    # API and relay behaviour under test are identical.
    (cd "$ROOT_DIR" && cargo zigbuild --release --target "$RUST_TARGET" \
        --no-default-features --features full -p meow-app --bin meow)
    BINARY="$ROOT_DIR/target/$RUST_TARGET/release/meow"
fi

if [ ! -f "$BINARY" ]; then
    echo "FAIL: binary not found: $BINARY"
    exit 1
fi

# --- Assemble ipks + HTTP-served work dir ---
WORK_DIR="$(mktemp -d)"
HTTP_PID=""
QEMU_LOG="$WORK_DIR/qemu.log"
cleanup() {
    [ -n "$HTTP_PID" ] && kill "$HTTP_PID" 2>/dev/null || true
    rm -rf "$WORK_DIR"
}
trap cleanup EXIT

echo "=== Building ipk packages ==="
bash "$ROOT_DIR/openwrt/build-ipk.sh" meow \
    --binary "$BINARY" --version 0.0.0-e2e --arch aarch64_generic \
    --outdir "$WORK_DIR"
bash "$ROOT_DIR/openwrt/build-ipk.sh" luci \
    --version 0.0.0-e2e --outdir "$WORK_DIR"

# Stable names for the guest script.
mv "$WORK_DIR/meow_0.0.0-e2e_aarch64_generic.ipk" "$WORK_DIR/meow.ipk"
mv "$WORK_DIR/luci-app-meow_0.0.0-e2e_all.ipk" "$WORK_DIR/luci-app-meow.ipk"
cp "$SCRIPT_DIR/openwrt-qemu/guest-test.sh" "$WORK_DIR/guest-test.sh"
echo "hello-from-host" > "$WORK_DIR/hello.txt"

# --- Fetch the OpenWrt image (cached) ---
mkdir -p "$CACHE_DIR"
if [ ! -s "$CACHE_DIR/$IMAGE_NAME" ]; then
    echo "=== Downloading $IMAGE_NAME ==="
    curl -fL --retry 3 -o "$CACHE_DIR/$IMAGE_NAME.tmp" "$IMAGE_URL"
    mv "$CACHE_DIR/$IMAGE_NAME.tmp" "$CACHE_DIR/$IMAGE_NAME"
fi

# --- Host HTTP server on an ephemeral port (guest reaches us at 10.0.2.2) ---
echo "=== Starting host HTTP server ==="
# -u: unbuffered, so the "Serving HTTP on ... port NNNNN" line is visible
# immediately even with stdout redirected to a file.
python3 -u -m http.server --bind 127.0.0.1 --directory "$WORK_DIR" 0 \
    > "$WORK_DIR/httpd.log" 2>&1 &
HTTP_PID=$!
# http.server prints "Serving HTTP on 127.0.0.1 port NNNNN ..." once up.
HTTP_PORT=""
for _ in $(seq 1 50); do
    HTTP_PORT="$(sed -n 's/.*port \([0-9]*\).*/\1/p' "$WORK_DIR/httpd.log" | head -1)"
    [ -n "$HTTP_PORT" ] && break
    sleep 0.2
done
if [ -z "$HTTP_PORT" ]; then
    echo "FAIL: host HTTP server did not start"
    exit 1
fi
echo "host HTTP server on port $HTTP_PORT (pid $HTTP_PID)"

# --- Boot the guest and run the tests ---
echo "=== Booting OpenWrt ${OPENWRT_VERSION} (armsr/armv8) in QEMU ==="
OPENWRT_IMAGE="$CACHE_DIR/$IMAGE_NAME" HOST_HTTP_PORT="$HTTP_PORT" \
    expect "$SCRIPT_DIR/openwrt-qemu/driver.exp" 2>&1 | tee "$QEMU_LOG" || true

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
done < <(grep "^TEST_PASS:" "$QEMU_LOG" 2>/dev/null | sort -u || true)

while IFS= read -r line; do
    test_name="${line#TEST_FAIL:}"
    echo "  FAIL: $test_name"
    FAIL_COUNT=$((FAIL_COUNT + 1))
    TOTAL_COUNT=$((TOTAL_COUNT + 1))
done < <(grep "^TEST_FAIL:" "$QEMU_LOG" 2>/dev/null | sort -u || true)

while IFS= read -r line; do
    echo "  SKIP: ${line#TEST_SKIP:}"
done < <(grep "^TEST_SKIP:" "$QEMU_LOG" 2>/dev/null | sort -u || true)

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
    echo "=== All OpenWrt e2e tests passed ==="
    exit 0
fi
