#!/usr/bin/env bash
# End-to-end Shadowsocks smoke test.
#
# Starts ssserver, TCP/UDP echo servers, creates the SS adapter,
# and verifies relay through the SOCKS5 listener (if available)
# or directly through the adapter integration test.
#
# Requirements: ssserver (cargo install shadowsocks-rust), python3
#
# Usage: bash tests/test_ss.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

SS_PORT=18388
SS_PASSWORD="test-password-e2e"
SS_CIPHER="aes-256-gcm"
TCP_ECHO_PORT=18400
UDP_ECHO_PORT=18401

PIDS=()

cleanup() {
    echo "Cleaning up..."
    for pid in "${PIDS[@]}"; do
        kill "$pid" 2>/dev/null || true
        wait "$pid" 2>/dev/null || true
    done
}
trap cleanup EXIT

# --- Dependency checks ---
check_command() {
    if ! command -v "$1" &>/dev/null; then
        echo "SKIP: $1 not found in PATH"
        exit 0
    fi
}

check_command ssserver
check_command python3

# --- Start TCP echo server (python) ---
echo "Starting TCP echo server on port $TCP_ECHO_PORT..."
python3 -c "
import socket, threading
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('127.0.0.1', $TCP_ECHO_PORT))
s.listen(5)
while True:
    c, _ = s.accept()
    def handle(conn):
        while True:
            data = conn.recv(4096)
            if not data: break
            conn.sendall(data)
        conn.close()
    threading.Thread(target=handle, args=(c,), daemon=True).start()
" &
PIDS+=($!)

# --- Start UDP echo server (python) ---
echo "Starting UDP echo server on port $UDP_ECHO_PORT..."
python3 -c "
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(('127.0.0.1', $UDP_ECHO_PORT))
while True:
    data, addr = s.recvfrom(65536)
    s.sendto(data, addr)
" &
PIDS+=($!)

sleep 0.5

# --- Start ssserver ---
echo "Starting ssserver on port $SS_PORT..."
ssserver -s "127.0.0.1:$SS_PORT" -k "$SS_PASSWORD" -m "$SS_CIPHER" -U &
PIDS+=($!)

# Wait for ssserver to be ready
echo "Waiting for ssserver..."
for i in $(seq 1 50); do
    if python3 -c "
import socket
s = socket.socket()
s.settimeout(0.2)
try:
    s.connect(('127.0.0.1', $SS_PORT))
    s.close()
except Exception:
    exit(1)
" 2>/dev/null; then
        echo "ssserver ready after ${i}00ms"
        break
    fi
    if [ "$i" -eq 50 ]; then
        echo "FAIL: ssserver did not start"
        exit 1
    fi
done

# --- Run Rust integration tests ---
echo ""
echo "=== Running Rust integration tests ==="
cd "$ROOT_DIR"

# Build first to separate compile errors from test failures
echo "Building..."
cargo build -p meow-proxy 2>&1

echo "Running integration test..."
if cargo test --test shadowsocks_integration -- --nocapture 2>&1; then
    echo ""
    echo "=== PASS: All Shadowsocks integration tests passed ==="
else
    echo ""
    echo "=== FAIL: Integration tests failed ==="
    exit 1
fi
