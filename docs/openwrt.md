# meow on OpenWrt

Official `.ipk` packages for arm OpenWrt devices are attached to every
[GitHub release](https://github.com/madeye/meow-rs/releases) (issue
[#284](https://github.com/madeye/meow-rs/issues/284)):

| Package | Architectures |
|---------|---------------|
| `meow_<ver>_<arch>.ipk` | `aarch64_generic`, `aarch64_cortex-a53`, `aarch64_cortex-a72`, `aarch64_cortex-a76`, `arm_cortex-a7_neon-vfpv4`, `arm_cortex-a8_vfpv3`, `arm_cortex-a9_vfpv3-d16`, `arm_cortex-a15_neon-vfpv4` |
| `luci-app-meow_<ver>_all.ipk` | any (LuCI app, architecture-independent) |

The binaries are fully static musl builds, so they have no library
dependencies beyond OpenWrt's base system. All 32-bit arm packages contain
the same `armv7` (vfpv3-d16, no NEON assumed) binary; all aarch64 packages
contain the same `aarch64` binary — only the opkg `Architecture:` label
differs so that `opkg` accepts the package on your device.

Feature note: the armv7 binaries are built without the `boring-tls`
feature (boring-sys does not compile for 32-bit musl targets), so ECH and
uTLS fingerprinting are unavailable on 32-bit arm; every other `full`
feature (all protocols, DNS, listeners) is present. aarch64 binaries are
full-featured.

Find your device's architecture with:

```sh
. /etc/openwrt_release; echo "$DISTRIB_ARCH"
```

For example, a Linksys WRT1900ACS (Marvell Armada 385) is
`arm_cortex-a9_vfpv3-d16`. If your architecture is not in the table but is a
superset of one that is (e.g. a NEON-capable core), the closest smaller
package works — the binary makes no assumptions beyond the baseline listed
above. Devices of other families (mips, x86) can use the static binaries
from the release tarballs directly; `x86_64` OpenWrt can also run the
`x86_64-unknown-linux-musl` tarball binary as-is.

## Install

Transfer the ipks to the device and install:

```sh
opkg install ./meow_<ver>_<arch>.ipk
# optional, for the LuCI integration:
opkg install ./luci-app-meow_<ver>_all.ipk
```

The `meow` package installs:

- `/usr/bin/meow` — the static binary
- `/etc/init.d/meow` — procd init script (enabled on install, but the
  service is **not started** until you set `enabled` to `1`)
- `/etc/config/meow` — UCI service settings (enable flag, config path,
  working directory, panel port)
- `/etc/meow/config.yaml` — default meow configuration (mixed HTTP/SOCKS5
  proxy on `:7890` for the LAN, REST API + web panel on `:9090`,
  rule mode with `MATCH,DIRECT`)

Both `/etc/config/meow` and `/etc/meow/config.yaml` are conffiles: opkg
preserves your edits across upgrades.

## Configure and start

Edit `/etc/meow/config.yaml` (add your proxies, groups and rules — see
[config.example.yaml](../config.example.yaml)), then:

```sh
uci set meow.main.enabled='1'
uci commit meow
/etc/init.d/meow start
```

The init script validates the config (`meow -t`) before starting and logs a
message via `logger` if validation fails. procd restarts the service when
either `/etc/config/meow` or the YAML config changes, and respawns it if it
crashes.

## LuCI app

`luci-app-meow` adds **Services → meow** with two tabs:

- **Panel** — embeds meow's built-in web dashboard (served by the REST API
  at `http://<router>:9090/ui`) directly in LuCI: proxy selection, latency
  tests, connections, rules, logs and traffic live here. No separate
  dashboard is bundled — this is the same panel the binary always serves.
- **Settings** — service status plus the UCI options (enable, config file
  path, working directory, panel port). Save & Apply restarts the service.

For the panel to load, `external-controller` in the YAML config must listen
on a LAN-reachable address (the shipped default `0.0.0.0:9090`) and the
`panel_port` UCI option must match its port. OpenWrt's default firewall
blocks WAN-side access to the router; set `secret:` in the YAML config if
untrusted hosts share your LAN.

## Transparent proxy / gateway

The packages set up meow as a regular HTTP/SOCKS5 proxy for LAN clients.
To transparently redirect all LAN traffic, follow
[tproxy-gateway.md](tproxy-gateway.md) — the nftables rules there adapt to
OpenWrt's fw4 stack.

## Building ipks yourself

`openwrt/build-ipk.sh` assembles ipks from any static musl build without
the OpenWrt SDK:

```sh
cargo zigbuild --release --target aarch64-unknown-linux-musl --bin meow
openwrt/build-ipk.sh meow \
    --binary target/aarch64-unknown-linux-musl/release/meow \
    --version 0.16.0-1 --arch aarch64_generic --outdir dist
openwrt/build-ipk.sh luci --version 0.16.0-1 --outdir dist
```

## End-to-end test

`tests/test_openwrt_qemu.sh` boots an official OpenWrt armsr/armv8 image in
`qemu-system-aarch64`, installs both ipks inside the guest and verifies the
procd service, REST API, built-in panel and proxy data path. It runs in CI
(`.github/workflows/test.yml`, `openwrt` job) and locally:

```sh
# requirements: qemu-system-aarch64, expect, python3, curl, cargo-zigbuild
bash tests/test_openwrt_qemu.sh
```

## Not yet provided

- An opkg feed (per-release ipks only; `opkg update`-able feed may come
  later once this stabilizes).
- `apk` packages for OpenWrt snapshot/main builds (which replaced opkg).
- mips builds — blocked on Rust dropping stable `rust-std` for
  `mipsel-unknown-linux-musl` (see ADR-0007).
