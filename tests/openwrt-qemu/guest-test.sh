#!/bin/sh
# Runs INSIDE the OpenWrt guest (busybox ash). Fetched over the QEMU slirp
# network and executed by tests/openwrt-qemu/driver.exp. Emits
# TEST_PASS:<name> / TEST_FAIL:<name> lines parsed by the host script, and
# ALL_TESTS_DONE when finished (the driver waits for that marker).
#
# $1 = host HTTP port (host is reachable at 10.0.2.2 via slirp)

HOST=10.0.2.2
PORT="$1"

pass() { echo "TEST_PASS:$1"; }
fail() { echo "TEST_FAIL:$1"; }

check() {
    name="$1"; shift
    if "$@" >/dev/null 2>&1; then pass "$name"; else fail "$name"; fi
}

# ── Fetch ipks from the host ─────────────────────────────────────────
wget -q -O /tmp/meow.ipk "http://$HOST:$PORT/meow.ipk"
check "fetch-meow-ipk" test -s /tmp/meow.ipk
wget -q -O /tmp/luci-app-meow.ipk "http://$HOST:$PORT/luci-app-meow.ipk"
check "fetch-luci-ipk" test -s /tmp/luci-app-meow.ipk

# ── Install meow ipk ─────────────────────────────────────────────────
if opkg install /tmp/meow.ipk >/tmp/opkg-meow.log 2>&1; then
    pass "opkg-install-meow"
else
    fail "opkg-install-meow"
    cat /tmp/opkg-meow.log
fi

check "binary-installed" test -x /usr/bin/meow
check "init-script-installed" test -x /etc/init.d/meow
check "uci-config-installed" test -f /etc/config/meow
check "default-config-installed" test -f /etc/meow/config.yaml

# postinst must have enabled the service (rc.d symlink present)
check "service-enabled" ls /etc/rc.d/S95meow

# ── Config test with the shipped default config ──────────────────────
check "config-test" /usr/bin/meow -d /etc/meow -f /etc/meow/config.yaml -t

# ── Start via procd ──────────────────────────────────────────────────
uci set meow.main.enabled='1'
uci commit meow
/etc/init.d/meow start
sleep 3
check "service-running" pgrep -f /usr/bin/meow

# ── REST API + built-in web panel ────────────────────────────────────
wget -q -O /tmp/version.json http://127.0.0.1:9090/version
if grep -q '"version"' /tmp/version.json 2>/dev/null; then
    pass "rest-api-version"
else
    fail "rest-api-version"
fi

wget -q -O /tmp/ui.html http://127.0.0.1:9090/ui
if grep -q '<title>meow-rs</title>' /tmp/ui.html 2>/dev/null; then
    pass "builtin-ui-served"
else
    fail "builtin-ui-served"
fi

# ── Proxy data path: HTTP proxy on mixed-port 7890 → host ────────────
# busybox nc if available; OpenWrt's wget (uclient-fetch) has no proxy support.
if command -v nc >/dev/null 2>&1; then
    printf 'GET http://%s:%s/hello.txt HTTP/1.1\r\nHost: %s:%s\r\nConnection: close\r\n\r\n' \
        "$HOST" "$PORT" "$HOST" "$PORT" | nc 127.0.0.1 7890 > /tmp/proxy-out 2>/dev/null
    if grep -q 'hello-from-host' /tmp/proxy-out 2>/dev/null; then
        pass "http-proxy-relay"
    else
        fail "http-proxy-relay"
    fi
else
    echo "TEST_SKIP:http-proxy-relay (no nc in image)"
fi

# ── LuCI app ─────────────────────────────────────────────────────────
# luci-base is preinstalled in official release images; fall back to the
# online feed if this image lacks it (needs internet via slirp).
if ! opkg list-installed 2>/dev/null | grep -q '^luci-base'; then
    opkg update >/dev/null 2>&1 && opkg install luci-base >/dev/null 2>&1
fi

if opkg install /tmp/luci-app-meow.ipk >/tmp/opkg-luci.log 2>&1; then
    pass "opkg-install-luci-app"
    check "luci-menu-installed" test -f /usr/share/luci/menu.d/luci-app-meow.json
    check "luci-acl-installed" test -f /usr/share/rpcd/acl.d/luci-app-meow.json
    check "luci-panel-view-installed" test -f /www/luci-static/resources/view/meow/panel.js
    check "luci-settings-view-installed" test -f /www/luci-static/resources/view/meow/settings.js
else
    fail "opkg-install-luci-app"
    cat /tmp/opkg-luci.log
fi

# ── Service stop / restart behaviour ─────────────────────────────────
/etc/init.d/meow stop
sleep 2
if pgrep -f /usr/bin/meow >/dev/null 2>&1; then
    fail "service-stop"
else
    pass "service-stop"
fi

echo "ALL_TESTS_DONE"
