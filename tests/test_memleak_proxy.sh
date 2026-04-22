#!/usr/bin/env bash
# Memory-leak detector: download a large file through mihomo's SOCKS5
# listener (DIRECT mode) and check that RSS does not grow beyond a
# threshold across repeated transfers.
#
# Default setup stresses only the inbound-listener + tunnel + TCP-relay
# path (no remote proxy), which covers the DashMap-backed connection
# tracking, the per-conn relay buffers, and the stats Arc<..> graph —
# i.e. the spots the M2 memory audit flagged. Swap the generated config
# for something Trojan-based to exercise the TLS cap as well.
#
# Requirements: cargo, curl, an internet connection that can reach
# speed.cloudflare.com. No Docker. Runs on macOS and Linux.
#
# Usage:
#   bash tests/test_memleak_proxy.sh
#   ITERATIONS=5 BYTES=500000000 bash tests/test_memleak_proxy.sh
#   MAX_RSS_GROWTH_KB=20000 bash tests/test_memleak_proxy.sh
#
# Exits non-zero iff RSS growth exceeds MAX_RSS_GROWTH_KB.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

# --- Tunables (all env-overridable) ---
ITERATIONS="${ITERATIONS:-3}"
BYTES="${BYTES:-200000000}"                      # 200 MB per transfer
URL="${URL:-https://speed.cloudflare.com/__down?bytes=${BYTES}}"
MIXED_PORT="${MIXED_PORT:-17891}"
API_PORT="${API_PORT:-$((MIXED_PORT + 100))}"
MAX_RSS_GROWTH_KB="${MAX_RSS_GROWTH_KB:-15000}"  # 15 MB
CURL_TIMEOUT="${CURL_TIMEOUT:-180}"              # seconds per transfer

# --- Dependency check ---
for cmd in cargo curl; do
    if ! command -v "$cmd" &>/dev/null; then
        echo "Error: '$cmd' is required but not found in PATH" >&2
        exit 1
    fi
done

# --- Preflight: can we reach the speed endpoint? ---
if ! curl -sS --max-time 10 -o /dev/null -I "https://speed.cloudflare.com/"; then
    echo "Error: cannot reach speed.cloudflare.com (need outbound HTTPS)" >&2
    exit 1
fi

# --- Build release binary (no-op if already up to date) ---
echo "==> Building mihomo (release)..."
cargo build --release --quiet --bin mihomo

# --- Generate a minimal DIRECT-mode config ---
CONFIG="$(mktemp -t mihomo-memleak.XXXXXX)"
LOG="$(mktemp -t mihomo-memleak.log.XXXXXX)"
MIHOMO_PID=""

cleanup() {
    if [[ -n "$MIHOMO_PID" ]]; then
        kill "$MIHOMO_PID" 2>/dev/null || true
        wait "$MIHOMO_PID" 2>/dev/null || true
    fi
    rm -f "$CONFIG" "$LOG"
}
trap cleanup EXIT INT TERM

cat > "$CONFIG" <<EOF
mixed-port: $MIXED_PORT
allow-lan: false
bind-address: "127.0.0.1"
mode: direct
log-level: warning
ipv6: false
external-controller: 127.0.0.1:$API_PORT
dns:
  enable: false
EOF

# --- Spawn mihomo ---
echo "==> Starting mihomo on SOCKS5/HTTP port $MIXED_PORT (direct mode)..."
"$ROOT_DIR/target/release/mihomo" -f "$CONFIG" >"$LOG" 2>&1 &
MIHOMO_PID=$!

# Wait for readiness by probing the mixed port.
ready=0
for _ in $(seq 1 30); do
    if curl -sS --max-time 2 --socks5-hostname "127.0.0.1:$MIXED_PORT" \
        -o /dev/null "https://speed.cloudflare.com/" 2>/dev/null; then
        ready=1
        break
    fi
    if ! kill -0 "$MIHOMO_PID" 2>/dev/null; then
        echo "Error: mihomo exited during startup. Log:" >&2
        cat "$LOG" >&2
        exit 1
    fi
    sleep 1
done
if [[ "$ready" -ne 1 ]]; then
    echo "Error: mihomo did not become ready within 30s. Log:" >&2
    cat "$LOG" >&2
    exit 1
fi

# --- RSS sampler (ps -o rss= returns KB on both darwin and linux) ---
rss_kb() { ps -o rss= -p "$MIHOMO_PID" | tr -d ' '; }

# Warmup transfer so the first-use allocations aren't attributed to the loop.
echo "==> Warmup transfer ($BYTES bytes)..."
curl -sS --fail --max-time "$CURL_TIMEOUT" \
    --socks5-hostname "127.0.0.1:$MIXED_PORT" \
    -o /dev/null "$URL" || {
    echo "Error: warmup transfer failed" >&2
    exit 1
}
sleep 2
BEFORE="$(rss_kb)"
printf "RSS before loop: %8s KB\n" "$BEFORE"

# --- Measured iterations ---
for i in $(seq 1 "$ITERATIONS"); do
    printf "==> Transfer %d/%s...\n" "$i" "$ITERATIONS"
    start=$(date +%s)
    curl -sS --fail --max-time "$CURL_TIMEOUT" \
        --socks5-hostname "127.0.0.1:$MIXED_PORT" \
        -o /dev/null "$URL"
    end=$(date +%s)
    printf "    took %ss, RSS now: %8s KB\n" "$((end - start))" "$(rss_kb)"
done

# Let the allocator release pages it was holding for reuse.
sleep 3
AFTER="$(rss_kb)"
DELTA=$((AFTER - BEFORE))

printf "RSS after loop:  %8s KB\n" "$AFTER"
printf "Growth:          %8s KB (limit %s KB)\n" "$DELTA" "$MAX_RSS_GROWTH_KB"

if [[ "$DELTA" -gt "$MAX_RSS_GROWTH_KB" ]]; then
    echo "FAIL: RSS growth exceeds MAX_RSS_GROWTH_KB — probable leak"
    exit 1
fi

echo "PASS: no leak detected"
