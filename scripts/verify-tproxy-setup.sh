#!/usr/bin/env bash
# verify-tproxy-setup.sh — bring up / tear down a rig for testing meow's
# *local-outbound* transparent proxy (the firewall meow auto-manages when a
# tproxy listener is configured; NOT the LAN-gateway rules).
#
# `up` aliases a non-loopback IP onto the loopback (10.88.0.1), runs a TCP echo
# server there, confirms the path is open, then starts meow with a tproxy
# listener and a single `MATCH,REJECT` rule — and leaves it all running.
# Then run verify-tproxy-test.sh to assert interception. `down` cleans up.
#
# REJECT (not DIRECT) avoids a redirect loop: on macOS the rdr is `on lo0`, so a
# DIRECT relay back to the lo0 test IP would be re-redirected into meow.
#
# macOS loop-avoidance is UID-based, so meow skips its own uid — meow must run
# as a different user than the test client. meow needs root for pf/nft anyway,
# so it runs as root here; run THIS script (and the test) as a NON-root user.
#
# Usage:
#   ./verify-tproxy-setup.sh up --meow /path/to/meow
#   ./verify-tproxy-setup.sh down
#   ./verify-tproxy-setup.sh status
set -uo pipefail

STATE_DIR="${TMPDIR:-/tmp}/meow-tproxy-verify"
STATE="$STATE_DIR/state"
LOG="$STATE_DIR/meow.log"
CFG="$STATE_DIR/meow.yaml"
ECHO_PY="$STATE_DIR/echo.py"
MEOW_PIDF="$STATE_DIR/meow.pid"
ECHO_PIDF="$STATE_DIR/echo.pid"

TEST_IP="10.88.0.1"
ECHO_PORT="9999"
TPROXY_PORT="7893"
DNS_PORT="15353"
MEOW="${MEOW:-meow}"
OS="$(uname)"

die() { echo "error: $*" >&2; exit 2; }
asroot() { if [ "$(id -u)" = 0 ]; then "$@"; else sudo "$@"; fi; }
remove_alias() {
  if [ "$OS" = Darwin ]; then asroot ifconfig lo0 -alias "$TEST_IP" 2>/dev/null || true
  else asroot ip addr del "$TEST_IP/32" dev lo 2>/dev/null || true; fi
}

cmd="${1:-}"; shift || true
while [ $# -gt 0 ]; do case "$1" in
  --meow) MEOW="$2"; shift 2;;
  -h|--help) sed -n '2,28p' "$0"; exit 0;;
  *) die "unknown option: $1";;
esac; done

case "$cmd" in
  down)
    [ -f "$MEOW_PIDF" ] && asroot kill "$(cat "$MEOW_PIDF")" 2>/dev/null || true
    [ -f "$ECHO_PIDF" ] && kill "$(cat "$ECHO_PIDF")" 2>/dev/null || true
    sleep 1; remove_alias; rm -rf "$STATE_DIR"
    echo "tproxy test rig torn down"; exit 0;;
  status)
    [ -f "$STATE" ] && cat "$STATE" || echo "(no rig up)"; exit 0;;
  up) ;;
  ""|-h|--help) sed -n '2,28p' "$0"; exit 0;;
  *) die "unknown command '$cmd' (use: up | down | status)";;
esac

[ "$(id -u)" != 0 ] || die "run as a NON-root user (the test client must not be uid-bypassed); it sudo's where needed"
command -v "$MEOW" >/dev/null 2>&1 || die "meow binary not found ($MEOW); pass --meow PATH"

mkdir -p "$STATE_DIR"

# 1. loopback alias
if [ "$OS" = Darwin ]; then asroot ifconfig lo0 alias "$TEST_IP"
else asroot ip addr add "$TEST_IP/32" dev lo 2>/dev/null || true; fi

# 2. echo server (detached, survives this script)
cat > "$ECHO_PY" <<'PY'
import socket, sys
ip, port = sys.argv[1], int(sys.argv[2])
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind((ip, port)); s.listen(8)
while True:
    c, _ = s.accept()
    try: c.recv(1024); c.sendall(b"ECHO_OK\n")
    finally: c.close()
PY
nohup python3 "$ECHO_PY" "$TEST_IP" "$ECHO_PORT" >/dev/null 2>&1 &
echo $! > "$ECHO_PIDF"
sleep 1

# 3. baseline: without meow the path must be open, or the rig is broken
BASE="$(printf 'HELLO\n' | nc -w 4 "$TEST_IP" "$ECHO_PORT" 2>/dev/null || true)"
printf '%s' "$BASE" | grep -q ECHO_OK || { remove_alias; kill "$(cat "$ECHO_PIDF")" 2>/dev/null; die "baseline failed: echo server unreachable ('${BASE:-<none>}')"; }

# 4. meow config: tproxy listener + MATCH,REJECT
cat > "$CFG" <<EOF
tproxy-port: $TPROXY_PORT
mode: rule
log-level: info
dns: { enable: true, listen: "127.0.0.1:$DNS_PORT", enhanced-mode: normal, nameserver: ["127.0.0.1"] }
proxies: []
proxy-groups: []
rules: [ "MATCH,REJECT" ]
EOF

# 5. meow as root, detached; wait up to 90s (first start may fetch geodata DBs)
asroot bash -c "nohup '$MEOW' -f '$CFG' >'$LOG' 2>&1 & echo \$! > '$MEOW_PIDF'"
for _ in $(seq 1 180); do
  grep -qE "TProxy listener.*started" "$LOG" 2>/dev/null && break
  asroot kill -0 "$(cat "$MEOW_PIDF" 2>/dev/null)" 2>/dev/null || break
  sleep 0.5
done

cat > "$STATE" <<EOF
OS=$OS
TEST_IP=$TEST_IP
ECHO_PORT=$ECHO_PORT
TPROXY_PORT=$TPROXY_PORT
LOG=$LOG
MEOW_PID=$(cat "$MEOW_PIDF" 2>/dev/null)
ECHO_PID=$(cat "$ECHO_PIDF" 2>/dev/null)
EOF

echo "tproxy test rig up (baseline path OK):"; sed 's/^/  /' "$STATE"
echo "now run:  ./verify-tproxy-test.sh"
echo "teardown: ./verify-tproxy-setup.sh down"
