#!/usr/bin/env bash
# tproxy-gateway-linux.sh — set up / tear down the firewall rules that make a
# Linux host a transparent-proxy LAN gateway for meow.
#
# meow's built-in tproxy firewall only redirects the host's OWN traffic
# (nftables `output` chain). This script adds the `prerouting` rules needed to
# intercept traffic FORWARDED from other LAN devices, plus a DNS hijack — the
# pieces meow does not create itself. See docs/tproxy-gateway.md for the full
# explanation and the systemd wiring.
#
# Mechanism: nftables `nat` REDIRECT; meow recovers the original destination
# (incl. fake-ip addresses) via SO_ORIGINAL_DST. TCP only — UDP/QUIC is not
# intercepted (suppress it at the DNS layer with fake-ip's AAAA suppression).
#
# Usage:
#   sudo ./tproxy-gateway-linux.sh up      [options]
#   sudo ./tproxy-gateway-linux.sh down
#   sudo ./tproxy-gateway-linux.sh status
#
# Options (for `up`):
#   -i, --iface IFACE     LAN-facing interface        (default: default-route iface)
#   -a, --lan-ip IP       this host's IP on IFACE     (default: autodetected)
#   -p, --tproxy-port N   meow tproxy listener port   (default: 7893)
#   -d, --dns-port N      meow DNS listener port      (default: 1053)
#       --no-dns          do not hijack LAN :53 to meow
#       --no-ipv6         do not redirect IPv6 (return it unproxied)
#       --table NAME      nftables table name         (default: meow_gateway)
#
# Idempotent: `up` replaces any existing table of the same name.
set -euo pipefail

TABLE="meow_gateway"
IFACE=""
LAN_IP=""
TPROXY_PORT="7893"
DNS_PORT="1053"
DO_DNS=1
DO_IPV6=1

die() { echo "error: $*" >&2; exit 1; }

cmd="${1:-}"; shift || true
while [ $# -gt 0 ]; do
  case "$1" in
    -i|--iface)       IFACE="$2"; shift 2;;
    -a|--lan-ip)      LAN_IP="$2"; shift 2;;
    -p|--tproxy-port) TPROXY_PORT="$2"; shift 2;;
    -d|--dns-port)    DNS_PORT="$2"; shift 2;;
    --no-dns)         DO_DNS=0; shift;;
    --no-ipv6)        DO_IPV6=0; shift;;
    --table)          TABLE="$2"; shift 2;;
    *) die "unknown option: $1";;
  esac
done

[ "$(id -u)" = 0 ] || die "must run as root (nftables + sysctl)"
command -v nft >/dev/null || die "nft (nftables) not found"

case "$cmd" in
  down)
    nft list table inet "$TABLE" >/dev/null 2>&1 && nft delete table inet "$TABLE"
    echo "removed nftables table inet $TABLE"
    exit 0;;
  status)
    echo "# ip_forward: $(cat /proc/sys/net/ipv4/ip_forward)"
    echo "# inet $TABLE:"
    nft list table inet "$TABLE" 2>/dev/null || echo "  (not loaded)"
    exit 0;;
  up) ;;
  ""|-h|--help) sed -n '2,40p' "$0"; exit 0;;
  *) die "unknown command '$cmd' (use: up | down | status)";;
esac

# --- autodetect iface / IP ---
[ -n "$IFACE" ] || IFACE="$(ip route show default 2>/dev/null | awk '/^default/{print $5; exit}')"
[ -n "$IFACE" ] || die "could not autodetect LAN interface; pass --iface"
[ -n "$LAN_IP" ] || LAN_IP="$(ip -4 -o addr show dev "$IFACE" 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | head -1)"
[ -n "$LAN_IP" ] || die "could not autodetect IP for $IFACE; pass --lan-ip"

echo "Setting up transparent-proxy gateway:"
echo "  interface   : $IFACE"
echo "  host IP      : $LAN_IP"
echo "  tproxy port  : $TPROXY_PORT"
echo "  DNS hijack   : $([ "$DO_DNS" = 1 ] && echo ":53 -> $LAN_IP:$DNS_PORT" || echo disabled)"
echo "  IPv6 redirect: $([ "$DO_IPV6" = 1 ] && echo enabled || echo disabled)"
echo "  nft table    : inet $TABLE"

# --- enable forwarding ---
sysctl -wq net.ipv4.ip_forward=1
[ "$DO_IPV6" = 1 ] && sysctl -wq net.ipv6.conf.all.forwarding=1 || true

# --- build ruleset ---
dns_rule=""
[ "$DO_DNS" = 1 ] && dns_rule="meta nfproto ipv4 meta l4proto { tcp, udp } th dport 53 dnat ip to ${LAN_IP}:${DNS_PORT}"
v6_guard=""
[ "$DO_IPV6" = 1 ] || v6_guard="meta nfproto ipv6 return"

nft -f - <<EOF
table inet ${TABLE} {
    # Destinations that must NOT be proxied. NOTE: the fake-ip range
    # (e.g. 198.18.0.0/16) is deliberately absent — those MUST be redirected
    # so meow can map fake IP -> domain.
    set reserved4 {
        type ipv4_addr; flags interval
        elements = {
            0.0.0.0/8, 10.0.0.0/8, 127.0.0.0/8, 169.254.0.0/16,
            172.16.0.0/12, 192.168.0.0/16, 224.0.0.0/4, 240.0.0.0/4
        }
    }
    set reserved6 {
        type ipv6_addr; flags interval
        elements = { ::1/128, fc00::/7, fe80::/10, ff00::/8 }
    }
    chain prerouting {
        type nat hook prerouting priority dstnat; policy accept;
        iifname != "${IFACE}" return
        ${dns_rule}
        fib daddr type local return
        ip  daddr @reserved4 return
        ip6 daddr @reserved6 return
        ${v6_guard}
        meta l4proto tcp redirect to :${TPROXY_PORT}
    }
}
EOF

echo "done. nftables table 'inet ${TABLE}' is active."
echo
echo "Next steps:"
echo "  1. meow config: declare the tproxy listener on a NON-loopback address"
echo "     (the top-level 'tproxy-port' binds 127.0.0.1 and will not catch"
echo "     forwarded traffic):"
echo "        listeners:"
echo "          - { name: tproxy-gw, type: tproxy, listen: '::', port: ${TPROXY_PORT} }"
echo "     and set dns.listen to 0.0.0.0:${DNS_PORT}."
echo "  2. Point LAN clients' default route (and DNS) at ${LAN_IP}."
echo "  3. Tear down with: sudo $0 down --table ${TABLE}"
