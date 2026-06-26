#!/usr/bin/env bash
# tproxy-local-macos.sh — run meow as a LOCAL transparent proxy for THIS host's
# own outbound traffic (macOS / pf).
#
# You do NOT install firewall rules yourself: meow's built-in firewall loads a
# pf anchor (`com.apple/com.meow.tproxy`, rdr on lo0) when a tproxy listener is
# configured, and flushes it on exit. This wrapper runs meow with such a config
# and confirms the anchor came up. To forward OTHER devices' traffic, use
# tproxy-gateway-macos.sh instead.
#
# NOTE (see GitHub issue on macOS tproxy): macOS interception is currently
# loopback-only and the redirected connection's handshake does not complete, so
# this does not yet proxy real outbound traffic. The wrapper still demonstrates
# that the listener + pf anchor are installed correctly.
#
# Usage:
#   sudo ./tproxy-local-macos.sh up [--config FILE] [--meow PATH]
#   sudo ./tproxy-local-macos.sh down
#   sudo ./tproxy-local-macos.sh status
set -uo pipefail

STATE_DIR="${TMPDIR:-/tmp}/meow-tproxy-local"
PIDF="$STATE_DIR/meow.pid"
LOG="$STATE_DIR/meow.log"
GENCFG="$STATE_DIR/meow.yaml"
ANCHOR="com.apple/com.meow.tproxy"   # the anchor meow auto-loads
MEOW="${MEOW:-meow}"
CONFIG=""

die() { echo "error: $*" >&2; exit 2; }

cmd="${1:-}"; shift || true
while [ $# -gt 0 ]; do case "$1" in
  --config) CONFIG="$2"; shift 2;;
  --meow)   MEOW="$2"; shift 2;;
  -h|--help) sed -n '2,24p' "$0"; exit 0;;
  *) die "unknown option: $1";;
esac; done

[ "$(uname)" = Darwin ] || die "this script is for macOS; use tproxy-local-linux.sh on Linux"

fw_present() { pfctl -a "$ANCHOR" -sn 2>/dev/null | grep -q rdr; }

case "$cmd" in
  down)
    [ -f "$PIDF" ] && kill "$(cat "$PIDF")" 2>/dev/null || true
    sleep 1
    if fw_present; then echo "warning: anchor $ANCHOR still present"; else echo "stopped; pf anchor flushed"; fi
    rm -rf "$STATE_DIR"; exit 0;;
  status)
    if [ -f "$PIDF" ] && kill -0 "$(cat "$PIDF")" 2>/dev/null; then echo "meow: running (pid $(cat "$PIDF"))"; else echo "meow: not running"; fi
    if fw_present; then echo "firewall: pf anchor $ANCHOR present"; pfctl -a "$ANCHOR" -sn 2>/dev/null | sed 's/^/  /'; else echo "firewall: absent"; fi
    exit 0;;
  up) ;;
  ""|-h|--help) sed -n '2,24p' "$0"; exit 0;;
  *) die "unknown command '$cmd' (use: up | down | status)";;
esac

[ "$(id -u)" = 0 ] || die "must run as root (pfctl)"
command -v "$MEOW" >/dev/null 2>&1 || die "meow binary not found ($MEOW); pass --meow PATH"
mkdir -p "$STATE_DIR"

if [ -n "$CONFIG" ]; then
  CFG="$CONFIG"
  echo "using config: $CFG"
else
  CFG="$GENCFG"
  cat > "$CFG" <<EOF
# Demo local-tproxy config (no real proxy — MATCH,DIRECT). Replace the proxies
# and rules with your own; keep \`tproxy-port\` to enable transparent proxy.
tproxy-port: 7893
routing-mark: 9527
mode: rule
log-level: info
dns: { enable: true, listen: "127.0.0.1:1053", enhanced-mode: normal, nameserver: ["1.1.1.1"] }
proxies: []
proxy-groups: []
rules: [ "MATCH,DIRECT" ]
EOF
  echo "using generated demo config: $CFG (MATCH,DIRECT — no real proxy)"
fi

"$MEOW" -f "$CFG" -t >/dev/null 2>&1 || die "config failed validation ($MEOW -f $CFG -t)"
grep -qE "^tproxy-port:|type: *tproxy" "$CFG" || echo "warning: config has no tproxy listener; meow will not set up a redirect"

nohup "$MEOW" -f "$CFG" >"$LOG" 2>&1 &
echo $! > "$PIDF"

# Wait for the listener (first start may download geodata DBs).
for _ in $(seq 1 180); do
  grep -qE "TProxy listener.*started" "$LOG" 2>/dev/null && break
  kill -0 "$(cat "$PIDF")" 2>/dev/null || { echo "meow exited early:"; tail -5 "$LOG"; exit 1; }
  sleep 0.5
done

if fw_present; then
  echo "local transparent proxy active — pf anchor $ANCHOR loaded."
  echo "meow pid $(cat "$PIDF"). (See the macOS-tproxy note above re: loopback-only.)"
  echo "stop with: sudo $0 down"
else
  echo "warning: meow started but pf anchor $ANCHOR is absent; check $LOG"
  exit 1
fi
