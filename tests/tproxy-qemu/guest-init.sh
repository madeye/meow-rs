#!/bin/bash
# run-tests.sh — Runs inside a privileged Docker container.
# Starts mihomo with tproxy config, verifies nftables rules,
# tests transparent proxy interception, and prints results.

set -uo pipefail

# Helper functions
pass() { echo "TEST_PASS:$1"; }
fail() { echo "TEST_FAIL:$1"; }

# --- Setup networking ---
ip link set lo up 2>/dev/null || true
# Add a non-loopback IP on lo for testing — traffic to this IP will be
# intercepted by nftables (loopback 127.0.0.0/8 is bypassed by design).
ip addr add 10.88.0.1/32 dev lo 2>/dev/null || true

# --- Start a TCP echo server on 10.88.0.1:9999 ---
(while true; do
    echo "ECHO_RESPONSE" | nc -l -s 10.88.0.1 -p 9999 2>/dev/null || true
done) &
ECHO_PID=$!
echo "Echo server started on 10.88.0.1:9999 (PID $ECHO_PID)"

# --- Start mihomo ---
mihomo -f /etc/mihomo-tproxy.yaml > /tmp/mihomo.log 2>&1 &
MIHOMO_PID=$!
echo "mihomo started (PID $MIHOMO_PID)"

# --- Wait for TProxy listener to be ready (up to 10s) ---
READY=0
for i in $(seq 1 20); do
    # Match both legacy "TProxy listener started" and current
    # "TProxy listener '<name>' started on <addr>" formats.
    if grep -qE "TProxy listener( '[^']*')? started" /tmp/mihomo.log 2>/dev/null; then
        READY=1
        echo "TProxy listener ready after $((i * 500))ms"
        break
    fi
    if ! kill -0 "$MIHOMO_PID" 2>/dev/null; then
        echo "mihomo exited prematurely"
        break
    fi
    sleep 0.5
done

echo ""
echo "=== Running test assertions ==="

# Test 1: tproxy_ready — TProxy listener started successfully
if [ "$READY" -eq 1 ]; then
    pass "tproxy_ready"
else
    fail "tproxy_ready"
fi

# Test 2: mihomo_alive — mihomo process is still running
if kill -0 "$MIHOMO_PID" 2>/dev/null; then
    pass "mihomo_alive"
else
    fail "mihomo_alive"
fi

# Test 3: nftables_table — nftables table was created
if nft list table inet mihomo_tproxy >/dev/null 2>&1; then
    pass "nftables_table"
else
    fail "nftables_table"
fi

# Test 4: nftables_redirect — redirect rule exists in output chain
if nft list chain inet mihomo_tproxy output 2>/dev/null | grep -q "redirect to :7893"; then
    pass "nftables_redirect"
else
    fail "nftables_redirect"
fi

# Test 5: nftables_bypass — bypass rule for upstream proxy IP (10.99.0.1) exists
if nft list chain inet mihomo_tproxy output 2>/dev/null | grep -q "10.99.0.1"; then
    pass "nftables_bypass"
else
    fail "nftables_bypass"
fi

# Test 5b: nftables_mark — SO_MARK bypass rule exists (routing-mark: 9527 = 0x2537)
if nft list chain inet mihomo_tproxy output 2>/dev/null | grep -q "meta mark"; then
    pass "nftables_mark"
else
    fail "nftables_mark"
fi

# Test 6: tproxy_listening — tproxy port is actually listening
if nc -z 127.0.0.1 7893 2>/dev/null; then
    pass "tproxy_listening"
else
    fail "tproxy_listening"
fi

# Test 7: tproxy_intercept — transparent proxy intercepts a TCP connection
# Connect to 10.88.0.1:9999 (non-loopback); nftables redirects through tproxy
RESPONSE=""
RESPONSE=$(echo "HELLO" | timeout 5 nc -w 3 10.88.0.1 9999 2>/dev/null) || true
sleep 1

# Verify mihomo logged the intercepted connection to 10.88.0.1:9999
if grep -q "10.88.0.1:9999" /tmp/mihomo.log 2>/dev/null; then
    pass "tproxy_intercept"
else
    fail "tproxy_intercept"
fi

# Test 8: tproxy_relay — data was relayed end-to-end through the proxy
if [ "$RESPONSE" = "ECHO_RESPONSE" ]; then
    pass "tproxy_relay"
else
    fail "tproxy_relay"
fi

# Test 9: tproxy_sni_extract — SNI extraction from TLS ClientHello
# Build a minimal TLS ClientHello with SNI "sni.example.com" (15 bytes)
# Lengths: SNI name=15, entry=18(3+15), list=18, ext_data=20(2+18), ext=24(4+20)
# Extensions total=24
# ClientHello body: 2+32+1+4+2+2+24 = 67 = 0x43
# Handshake: 4+67 = 71
# Record: 5+71 = 76
{
    printf '\x16\x03\x01\x00\x47'           # TLS record: handshake, len=71
    printf '\x01\x00\x00\x43'               # ClientHello, len=67
    printf '\x03\x03'                        # Version TLS 1.2
    dd if=/dev/zero bs=32 count=1 2>/dev/null  # Random (32 bytes)
    printf '\x00'                            # Session ID length: 0
    printf '\x00\x02\x00\x2f'               # Cipher suites: len=2, one suite
    printf '\x01\x00'                        # Compression: len=1, null
    printf '\x00\x18'                        # Extensions length: 24
    printf '\x00\x00'                        # SNI extension type (0x0000)
    printf '\x00\x14'                        # SNI extension data length: 20
    printf '\x00\x12'                        # Server name list length: 18
    printf '\x00'                            # Host name type: 0
    printf '\x00\x0f'                        # Host name length: 15
    printf 'sni.example.com'                # Hostname (15 bytes)
} | timeout 3 nc -w 2 10.88.0.1 443 2>/dev/null || true
sleep 1

if grep -q "sni.example.com" /tmp/mihomo.log 2>/dev/null; then
    pass "tproxy_sni_extract"
else
    fail "tproxy_sni_extract"
fi

# Test 10: firewall_teardown — stop mihomo, verify nftables rules cleaned up
kill -TERM "$MIHOMO_PID" 2>/dev/null
# Wait for process to exit (up to 5s)
for i in $(seq 1 10); do
    kill -0 "$MIHOMO_PID" 2>/dev/null || break
    sleep 0.5
done
# Force kill if still alive
kill -9 "$MIHOMO_PID" 2>/dev/null || true
sleep 1

if nft list table inet mihomo_tproxy >/dev/null 2>&1; then
    fail "firewall_teardown"
else
    pass "firewall_teardown"
fi

# --- Debug output ---
echo ""
echo "=== mihomo log ==="
cat /tmp/mihomo.log 2>/dev/null || echo "(no log)"
echo "=== end log ==="

echo ""
echo "=== nftables state ==="
nft list ruleset 2>/dev/null || echo "(empty)"
echo "=== end nftables ==="

# Cleanup
kill "$ECHO_PID" 2>/dev/null || true
