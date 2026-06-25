#!/usr/bin/env bash
# tproxy-gateway-macos.sh — set up / tear down pf rules that make a macOS host a
# transparent-proxy LAN gateway for meow.
#
# EXPERIMENTAL. meow's built-in macOS transparent proxy targets the host's OWN
# traffic only (a pf anchor on lo0). Using macOS as a *forwarding* LAN gateway
# is not officially supported and is provided here as a best-effort convenience;
# the pf syntax is validated but the end-to-end path is not part of CI. On Linux
# prefer tproxy-gateway-linux.sh (verified). See docs/tproxy-gateway.md.
#
# Mechanism: pf `rdr` redirects forwarded TCP to meow's tproxy listener on
# 127.0.0.1; meow recovers the original destination via the pf NAT state table
# (DIOCNATLOOK), which is keyed on the listen address — so the meow tproxy
# listener MUST bind 127.0.0.1 (its macOS default; do NOT move it). TCP only.
#
# Usage:
#   sudo ./tproxy-gateway-macos.sh up   [options]
#   sudo ./tproxy-gateway-macos.sh down
#   sudo ./tproxy-gateway-macos.sh status
#
# Options (for `up`):
#   -i, --iface IFACE     LAN-facing interface       (default: default-route iface)
#   -p, --tproxy-port N   meow tproxy listener port  (default: 7893)
#   -d, --dns-port N      meow DNS listener port     (default: 1053)
#       --no-dns          do not hijack LAN :53 to meow
set -euo pipefail

ANCHOR="com.meow.gateway"
IFACE=""
TPROXY_PORT="7893"
DNS_PORT="1053"
DO_DNS=1

die() { echo "error: $*" >&2; exit 1; }

cmd="${1:-}"; shift || true
while [ $# -gt 0 ]; do
  case "$1" in
    -i|--iface)       IFACE="$2"; shift 2;;
    -p|--tproxy-port) TPROXY_PORT="$2"; shift 2;;
    -d|--dns-port)    DNS_PORT="$2"; shift 2;;
    --no-dns)         DO_DNS=0; shift;;
    *) die "unknown option: $1";;
  esac
done

[ "$(uname)" = "Darwin" ] || die "this script is for macOS; use tproxy-gateway-linux.sh on Linux"
[ "$(id -u)" = 0 ] || die "must run as root (pfctl + sysctl)"

case "$cmd" in
  down)
    pfctl -a "$ANCHOR" -F all >/dev/null 2>&1 || true
    sysctl -w net.inet.ip.forwarding=0 >/dev/null 2>&1 || true
    echo "flushed pf anchor '$ANCHOR' and disabled IPv4 forwarding"
    echo "note: pf itself left enabled (pfctl -d to disable globally if you set it up)"
    exit 0;;
  status)
    echo "# net.inet.ip.forwarding: $(sysctl -n net.inet.ip.forwarding)"
    echo "# pf anchor $ANCHOR rules:"; pfctl -a "$ANCHOR" -sn 2>/dev/null || echo "  (none)"
    exit 0;;
  up) ;;
  ""|-h|--help) sed -n '2,33p' "$0"; exit 0;;
  *) die "unknown command '$cmd' (use: up | down | status)";;
esac

[ -n "$IFACE" ] || IFACE="$(route -n get default 2>/dev/null | awk '/interface:/{print $2; exit}')"
[ -n "$IFACE" ] || die "could not autodetect LAN interface; pass --iface"

echo "Setting up transparent-proxy gateway (EXPERIMENTAL):"
echo "  interface   : $IFACE"
echo "  tproxy port  : 127.0.0.1:$TPROXY_PORT"
echo "  DNS hijack   : $([ "$DO_DNS" = 1 ] && echo ":53 -> 127.0.0.1:$DNS_PORT" || echo disabled)"
echo "  pf anchor    : $ANCHOR"

# Enable IPv4 forwarding.
sysctl -w net.inet.ip.forwarding=1 >/dev/null

# Reserved/private destinations that must NOT be proxied. The fake-ip range
# (e.g. 198.18.0.0/16) is deliberately absent so meow can map it -> domain.
reserved="{ 0.0.0.0/8, 10.0.0.0/8, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.168.0.0/16, 224.0.0.0/4, 240.0.0.0/4 }"
dns_rdr=""
[ "$DO_DNS" = 1 ] && dns_rdr="rdr pass on ${IFACE} inet proto { tcp, udp } from any to any port 53 -> 127.0.0.1 port ${DNS_PORT}"

ruleset="$(cat <<EOF
# meow transparent-gateway anchor (${ANCHOR})
no rdr on ${IFACE} inet proto tcp from any to ${reserved}
${dns_rdr}
rdr pass on ${IFACE} inet proto tcp from any to any -> 127.0.0.1 port ${TPROXY_PORT}
EOF
)"

# Validate syntax, then load into the dedicated anchor and enable pf.
echo "$ruleset" | pfctl -vnf - >/dev/null || die "pf ruleset failed validation"
echo "$ruleset" | pfctl -a "$ANCHOR" -f - 2>/dev/null
pfctl -e 2>/dev/null || true   # no-op / harmless if pf already enabled

echo "done. pf anchor '${ANCHOR}' loaded."
echo
echo "Next steps:"
echo "  1. meow config: keep the tproxy listener on 127.0.0.1 (macOS default) —"
echo "     the pf NAT-state lookup is keyed to it. Set dns.listen to"
echo "     127.0.0.1:${DNS_PORT} (or 0.0.0.0:${DNS_PORT})."
echo "  2. Point LAN clients' default route (and DNS) at this host."
echo "  3. Tear down with: sudo $0 down"
echo
echo "If the anchor's rules don't take effect, your main /etc/pf.conf may need a"
echo "  rdr-anchor \"${ANCHOR}\"  and  anchor \"${ANCHOR}\"  reference (pf evaluates"
echo "anchors only when the active ruleset calls them)."
