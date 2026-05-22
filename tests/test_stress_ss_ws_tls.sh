#!/usr/bin/env bash
# Local SS + WS + TLS stress: stand up ssserver with v2ray-plugin in
# WS+TLS server mode, point meow at it, then run the gstatic crawl
# stress. Measures peak RSS the same way as test_stress_gstatic.sh.
#
# Requirements: ssserver, v2ray-plugin, openssl, curl.
#
# Usage:
#   bash tests/test_stress_ss_ws_tls.sh
#   CONCURRENCY=512 DURATION=60 MAX_RSS_MB=50 bash tests/test_stress_ss_ws_tls.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

CONCURRENCY="${CONCURRENCY:-512}"
DURATION="${DURATION:-60}"
COOLDOWN="${COOLDOWN:-15}"
MAX_RSS_MB="${MAX_RSS_MB:-50}"
PROXY_PORT="${PROXY_PORT:-17892}"
SS_PORT="${SS_PORT:-18388}"
PLUGIN_PORT="${PLUGIN_PORT:-18443}"
SS_PASSWORD="${SS_PASSWORD:-stress-pw}"
SS_CIPHER="${SS_CIPHER:-aes-256-gcm}"

for cmd in ssserver v2ray-plugin openssl curl; do
    command -v "$cmd" >/dev/null || { echo "ERROR: $cmd not on PATH" >&2; exit 1; }
done

WORK_DIR="$(mktemp -d -t meow-ss-stress.XXXXXX)"
MEOW_LOG="$WORK_DIR/meow.log"
RSS_LOG="$WORK_DIR/rss.log"
SS_LOG="$WORK_DIR/ss.log"
PLUGIN_LOG="$WORK_DIR/plugin.log"
MEOW_CONFIG="$WORK_DIR/meow.yaml"

PIDS=()

cleanup() {
    for p in "${PIDS[@]:-}"; do
        [[ -n "$p" ]] && kill "$p" 2>/dev/null || true
        [[ -n "$p" ]] && wait "$p" 2>/dev/null || true
    done
    rm -rf "$WORK_DIR"
}
trap cleanup EXIT INT TERM

# Self-signed cert (CN=localhost) for the v2ray-plugin TLS server.
openssl req -x509 -newkey rsa:2048 -sha256 -days 1 -nodes \
    -keyout "$WORK_DIR/key.pem" -out "$WORK_DIR/cert.pem" \
    -subj "/CN=localhost" >/dev/null 2>&1

# --- Start v2ray-plugin in WS+TLS server mode, fronting ssserver ---
echo "==> Starting v2ray-plugin (WS+TLS) on :$PLUGIN_PORT -> ssserver :$SS_PORT"
v2ray-plugin -server \
    -localAddr 127.0.0.1 -localPort "$PLUGIN_PORT" \
    -remoteAddr 127.0.0.1 -remotePort "$SS_PORT" \
    -path /ws \
    -host localhost \
    -tls \
    -cert "$WORK_DIR/cert.pem" -key "$WORK_DIR/key.pem" \
    >"$PLUGIN_LOG" 2>&1 &
PIDS+=($!)

# --- Start ssserver (plain TCP; v2ray-plugin terminates WS+TLS for it) ---
echo "==> Starting ssserver on :$SS_PORT (method=$SS_CIPHER)"
ssserver -s "127.0.0.1:$SS_PORT" -k "$SS_PASSWORD" -m "$SS_CIPHER" \
    >"$SS_LOG" 2>&1 &
PIDS+=($!)

sleep 1

# --- meow config: client uses built-in v2ray-plugin (ws+tls) ---
cat > "$MEOW_CONFIG" <<EOF
mixed-port: $PROXY_PORT
allow-lan: false
bind-address: "127.0.0.1"
mode: rule
log-level: warning
ipv6: false
external-controller: 127.0.0.1:$((PROXY_PORT + 100))

dns:
  enable: false

proxies:
  - name: local-ss
    type: ss
    server: 127.0.0.1
    port: $PLUGIN_PORT
    cipher: $SS_CIPHER
    password: $SS_PASSWORD
    plugin: v2ray-plugin
    plugin-opts:
      mode: websocket
      tls: true
      host: localhost
      path: /ws
      skip-cert-verify: true

rules:
  - MATCH,local-ss
EOF

echo "==> Starting meow on :$PROXY_PORT"
"$ROOT_DIR/target/release/meow" -f "$MEOW_CONFIG" >"$MEOW_LOG" 2>&1 &
MEOW_PID=$!
PIDS+=($MEOW_PID)

# Wait for the inbound port to come up.
for _ in $(seq 1 30); do
    if curl -sS --max-time 2 -x "http://127.0.0.1:$PROXY_PORT" \
        -o /dev/null "http://www.gstatic.com/generate_204" 2>/dev/null; then
        break
    fi
    if ! kill -0 "$MEOW_PID" 2>/dev/null; then
        echo "ERROR: meow died. Log:" >&2
        cat "$MEOW_LOG" >&2
        exit 1
    fi
    sleep 1
done

echo "==> Stress: workers=$CONCURRENCY duration=${DURATION}s cap=${MAX_RSS_MB}MB"

URLS=(
    "http://www.gstatic.com/generate_204"
    "https://www.gstatic.com/generate_204"
    "https://connectivitycheck.gstatic.com/generate_204"
    "https://clients3.google.com/generate_204"
)

# RSS sampler.
(
    end=$(( $(date +%s) + DURATION + COOLDOWN + 5 ))
    while [[ $(date +%s) -lt $end ]]; do
        rss_kb=$(ps -o rss= -p "$MEOW_PID" 2>/dev/null | tr -d ' ')
        [[ -n "$rss_kb" ]] && echo "$(date +%s) $rss_kb" >> "$RSS_LOG"
        sleep 1
    done
) &
PIDS+=($!)

# Worker pool.
WORKER_PIDS=()
end=$(( $(date +%s) + DURATION ))
for i in $(seq 1 "$CONCURRENCY"); do
    (
        idx=$(( i % ${#URLS[@]} ))
        while [[ $(date +%s) -lt $end ]]; do
            curl -sS --max-time 10 -x "http://127.0.0.1:$PROXY_PORT" \
                -o /dev/null -w "" "${URLS[$idx]}" 2>/dev/null || true
            idx=$(( (idx + 1) % ${#URLS[@]} ))
        done
    ) &
    WORKER_PIDS+=($!)
done
for p in "${WORKER_PIDS[@]}"; do wait "$p" 2>/dev/null || true; done

echo "==> Cooldown ${COOLDOWN}s"
sleep "$COOLDOWN"

# Analyze.
peak_kb=$(awk '{print $2}' "$RSS_LOG" | sort -n | tail -1)
min_kb=$(awk '{print $2}' "$RSS_LOG" | sort -n | head -1)
median_kb=$(awk '{print $2}' "$RSS_LOG" | sort -n | awk '{a[NR]=$1} END {print a[int(NR/2)+1]}')
final_kb=$(tail -1 "$RSS_LOG" | awk '{print $2}')
n=$(wc -l < "$RSS_LOG")

mb() { awk "BEGIN { printf \"%.2f\", $1 / 1024 }"; }

echo "==> RSS samples: $n"
echo "    min            : $(mb $min_kb) MB"
echo "    median         : $(mb $median_kb) MB"
echo "    PEAK           : $(mb $peak_kb) MB"
echo "    final (cooldown): $(mb $final_kb) MB"
echo "    cap            : $MAX_RSS_MB MB"

peak_mb=$(mb $peak_kb)
if (( $(echo "$peak_mb > $MAX_RSS_MB" | bc -l) )); then
    echo "==> FAIL: peak RSS $peak_mb MB exceeds cap $MAX_RSS_MB MB"
    exit 1
fi
echo "==> PASS: peak RSS $peak_mb MB <= cap $MAX_RSS_MB MB"
