# Geodata

Geolocation rules need data files: a GeoIP country database for `GEOIP`/`SRC-GEOIP`, a
GeoLite2-ASN database for `IP-ASN`/`SRC-IP-ASN`, and a GeoSite database for `GEOSITE`. The
optional `geodata` block points at them and controls auto-updates.

```yaml
geodata:
  mmdb-path: /etc/meow/Country.mmdb
  auto-update: true
  auto-update-interval: 24
```

## Fields

| Field | Type | Default | Description |
| --- | --- | --- | --- |
| `mmdb-path` | string | auto | Path to `Country.mmdb` (GeoIP) |
| `asn-path` | string | auto | Path to `GeoLite2-ASN.mmdb` |
| `geosite-path` | string | auto | Path to the GeoSite database (`.dat` / `.mrs`) |
| `auto-update` | bool | `false` | Refresh the databases in the background |
| `auto-update-interval` | u32 (hours) | — | Hours between updates (min 1) |
| `url` | map | CDN defaults | Override download URLs (`mmdb`, `asn`, `geosite`) |

## Discovery

When a path isn't given explicitly, meow-rs searches a standard chain:

```
$XDG_CONFIG_HOME/meow/<file>
$HOME/.config/meow/<file>
./meow/<file>
```

The `-d` / home directory flag also influences where resources are looked up.

## Auto-update

On startup meow-rs downloads any missing database. With `auto-update: true`, a background
task re-checks every `auto-update-interval` hours, using conditional requests
(`If-Modified-Since` / 304) to avoid needless downloads, and hot-reloads new data into
memory. Failures are logged and retried next interval — they never crash the process.

```yaml
geodata:
  auto-update: true
  auto-update-interval: 24
  url:
    mmdb: https://cdn.example.com/Country.mmdb
    asn: https://cdn.example.com/GeoLite2-ASN.mmdb
    geosite: https://cdn.example.com/geosite.dat
```

## Rule requirements

| Rule | Needs | If missing |
| --- | --- | --- |
| `GEOIP` / `SRC-GEOIP` | Country MMDB | Hard error at load |
| `IP-ASN` / `SRC-IP-ASN` | GeoLite2-ASN MMDB | Hard error at load |
| `GEOSITE` | GeoSite DB | Tolerated — the rule simply never matches |

GeoSite is intentionally lenient so configs that conditionally load it still parse. See
[Rules](./rules) for the matching semantics.
