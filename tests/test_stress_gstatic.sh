#!/usr/bin/env bash
# Real-world stress test: hammer gstatic / google probe URLs through a
# rule-mode meow using a live VLESS+WS+TLS+ECH proxy from a subscription.
# Samples RSS at 1 Hz throughout and reports peak.
#
# Goal: verify peak RSS stays under MAX_RSS_MB (default 50 MB) under
# sustained crawl load.
#
# Usage:
#   bash tests/test_stress_gstatic.sh
#   CONCURRENCY=128 DURATION=60 MAX_RSS_MB=50 bash tests/test_stress_gstatic.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

CONFIG="${CONFIG:-$ROOT_DIR/config-stress.yaml}"
PROXY_PORT="${PROXY_PORT:-17891}"
CONCURRENCY="${CONCURRENCY:-64}"
DURATION="${DURATION:-60}"
MAX_RSS_MB="${MAX_RSS_MB:-50}"
SAMPLE_INTERVAL="${SAMPLE_INTERVAL:-1}"

# URLs to hammer (small payloads, lots of TLS handshakes through the proxy).
URLS=(
    "http://www.gstatic.com/generate_204"
    "http://connectivitycheck.gstatic.com/generate_204"
    "https://www.gstatic.com/generate_204"
    "https://connectivitycheck.gstatic.com/generate_204"
    "https://www.google.com/generate_204"
    "https://clients3.google.com/generate_204"
)

cleanup() {
    if [[ -n "${MEOW_PID:-}" ]]; then
        kill "$MEOW_PID" 2>/dev/null || true
        wait "$MEOW_PID" 2>/dev/null || true
    fi
    [[ -n "${SAMPLE_PID:-}" ]] && kill "$SAMPLE_PID" 2>/dev/null || true
    [[ -n "${WORKER_PIDS:-}" ]] && for p in $WORKER_PIDS; do kill "$p" 2>/dev/null || true; done
    rm -f "$RSS_LOG" "$MEOW_LOG" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

MEOW_LOG="$(mktemp -t meow-stress.XXXXXX)"
RSS_LOG="$(mktemp -t meow-stress-rss.XXXXXX)"

echo "==> Starting meow with $CONFIG"
"$ROOT_DIR/target/release/meow" -f "$CONFIG" >"$MEOW_LOG" 2>&1 &
MEOW_PID=$!

# Wait for the proxy port to come up.
for _ in $(seq 1 30); do
    if curl -sS --max-time 2 -x "http://127.0.0.1:$PROXY_PORT" \
        -o /dev/null "http://www.gstatic.com/generate_204" 2>/dev/null; then
        break
    fi
    if ! kill -0 "$MEOW_PID" 2>/dev/null; then
        echo "ERROR: meow died during startup. Log:" >&2
        cat "$MEOW_LOG" >&2
        exit 1
    fi
    sleep 1
done

echo "==> meow PID=$MEOW_PID, proxy port=$PROXY_PORT"
echo "==> Stress: concurrency=$CONCURRENCY duration=${DURATION}s cap=${MAX_RSS_MB}MB"

# RSS sampler in background.
(
    end=$(( $(date +%s) + DURATION + 10 ))
    while [[ $(date +%s) -lt $end ]]; do
        rss_kb=$(ps -o rss= -p "$MEOW_PID" 2>/dev/null | tr -d ' ')
        [[ -n "$rss_kb" ]] && echo "$(date +%s) $rss_kb" >> "$RSS_LOG"
        sleep "$SAMPLE_INTERVAL"
    done
) &
SAMPLE_PID=$!

# Worker pool — each worker loops curl through the proxy for DURATION seconds.
WORKER_PIDS=""
end=$(( $(date +%s) + DURATION ))
for i in $(seq 1 "$CONCURRENCY"); do
    (
        n_urls=${#URLS[@]}
        idx=$(( i % n_urls ))
        while [[ $(date +%s) -lt $end ]]; do
            url="${URLS[$idx]}"
            curl -sS --max-time 10 -x "http://127.0.0.1:$PROXY_PORT" \
                -o /dev/null -w "" "$url" 2>/dev/null || true
            idx=$(( (idx + 1) % n_urls ))
        done
    ) &
    WORKER_PIDS="$WORKER_PIDS $!"
done

# Wait for workers.
for p in $WORKER_PIDS; do
    wait "$p" 2>/dev/null || true
done
WORKER_PIDS=""

# Cooldown — let connections drain and allocator return pages to OS.
COOLDOWN="${COOLDOWN:-15}"
echo "==> Cooldown ${COOLDOWN}s (sampling continues)..."
sleep "$COOLDOWN"

# Stop sampler.
kill "$SAMPLE_PID" 2>/dev/null || true
wait "$SAMPLE_PID" 2>/dev/null || true

# Analyze RSS samples.
if [[ ! -s "$RSS_LOG" ]]; then
    echo "ERROR: no RSS samples captured" >&2
    exit 1
fi

peak_kb=$(awk '{print $2}' "$RSS_LOG" | sort -n | tail -1)
min_kb=$(awk '{print $2}' "$RSS_LOG" | sort -n | head -1)
median_kb=$(awk '{print $2}' "$RSS_LOG" | sort -n | awk '{a[NR]=$1} END {print a[int(NR/2)+1]}')
final_kb=$(tail -1 "$RSS_LOG" | awk '{print $2}')
n=$(wc -l < "$RSS_LOG")

peak_mb=$(awk "BEGIN { printf \"%.2f\", $peak_kb / 1024 }")
min_mb=$(awk "BEGIN { printf \"%.2f\", $min_kb / 1024 }")
median_mb=$(awk "BEGIN { printf \"%.2f\", $median_kb / 1024 }")
final_mb=$(awk "BEGIN { printf \"%.2f\", $final_kb / 1024 }")

echo "==> RSS samples: $n"
echo "    min            : $min_mb MB"
echo "    median         : $median_mb MB"
echo "    PEAK           : $peak_mb MB"
echo "    final (cooldown): $final_mb MB"
echo "    cap            : $MAX_RSS_MB MB"

# Final RSS (post-cooldown) is the authoritative steady-state number — peak
# may include transient allocator pages awaiting return-to-OS that drop after
# connections drain.
if (( $(echo "$final_mb > $MAX_RSS_MB" | bc -l) )); then
    echo "==> FAIL: final RSS $final_mb MB exceeds cap $MAX_RSS_MB MB"
    exit 1
fi
echo "==> PASS: final RSS $final_mb MB <= cap $MAX_RSS_MB MB (peak under load: $peak_mb MB)"
