# OpenWrt packaging

Packaging sources for the official OpenWrt `.ipk` release artifacts
(issue [#284](https://github.com/madeye/meow-rs/issues/284)).

- `build-ipk.sh` — assembles opkg-format `.ipk` packages from a prebuilt
  static musl binary, without the OpenWrt SDK. Run with no arguments for
  usage.
- `meow/files/` — procd init script, `/etc/config/meow` UCI settings and
  the default `/etc/meow/config.yaml` shipped on-device.
- `luci-app-meow/` — LuCI app: `root/` overlays `/` on the device,
  `htdocs/` maps to `/www`. The Panel tab embeds the built-in web UI served
  by the meow REST API at `/ui` instead of reimplementing a dashboard.

Release wiring lives in `.github/workflows/release.yml` (ipk matrix), the
QEMU end-to-end test in `tests/test_openwrt_qemu.sh`, and user-facing
documentation in [docs/openwrt.md](../docs/openwrt.md).
