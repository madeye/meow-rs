# Providers & Subscriptions

Providers let proxies and rules live **outside** your config — fetched from a URL or a
file, cached to disk, and optionally refreshed in the background. This is how you consume
airport subscriptions and shared rule sets.

## Proxy providers

`proxy-providers` is a map of named sources. A [proxy group](./proxy-groups) pulls members
from one via `use:`.

```yaml
proxy-providers:
  airport:
    type: http
    url: https://example.com/proxies.yaml
    path: ./providers/airport.yaml
    interval: 86400
    filter: "^(HK|JP)"
    health-check:
      enable: true
      url: https://www.gstatic.com/generate_204
      interval: 300

proxy-groups:
  - name: Proxy
    type: select
    use: [airport]
```

### Common fields

| Field | Type | Default | Notes |
| --- | --- | --- | --- |
| `type` | string | — | **Required.** `http` or `file` |
| `filter` | regex | — | Keep only proxies whose name matches |
| `exclude-filter` | regex | — | Drop proxies whose name matches |
| `exclude-type` | string \| list | `[]` | Drop proxy types, e.g. `[ss]` |
| `health-check` | block | — | Periodic probing (below) |
| `header` | map | `{}` | Extra HTTP request headers (`http` only) |

### `type: http`

| Field | Type | Default | Notes |
| --- | --- | --- | --- |
| `url` | string | — | **Required.** Source URL |
| `path` | string | `provider_{name}.yaml` | Local cache (absolute or relative to config dir) |
| `interval` | u64 | `0` | Refresh seconds; `0` = no periodic refresh |

The cached file is reused on startup for instant boot and offline resilience.

### `type: file`

| Field | Type | Default | Notes |
| --- | --- | --- | --- |
| `path` | string | — | **Required.** Local YAML file of proxies |

### Health check

| Field | Type | Default |
| --- | --- | --- |
| `enable` | bool | `true` |
| `url` | string | `https://www.gstatic.com/generate_204` |
| `interval` | u64 | `300` |
| `timeout` | u64 (ms) | `5000` |
| `lazy` | bool | `false` |

## Rule providers

`rule-providers` supplies external rule sets, referenced from `rules` via
`RULE-SET,<name>,<target>`.

```yaml
rule-providers:
  gfw:
    type: http
    url: https://cdn.example.com/gfw.yaml
    path: ./rules/gfw.yaml
    behavior: domain
    format: yaml
    interval: 604800

rules:
  - RULE-SET,gfw,Proxy
  - MATCH,DIRECT
```

### Common fields

| Field | Type | Default | Notes |
| --- | --- | --- | --- |
| `type` | string | — | **Required.** `http` · `file` · `inline` |
| `behavior` | string | — | **Required.** `domain` · `ipcidr` · `classical` |
| `format` | string | auto | `yaml` · `text` · `mrs` (auto-detected for http/file) |
| `interval` | u64 | `0` | Refresh seconds (ignored for `file` / `inline`) |

`behavior` describes the payload: `domain` (domain list), `ipcidr` (CIDR list), or
`classical` (full `TYPE,payload` rule lines). `mrs` is the compiled binary format.

### `type: http` / `file`

- `http` — needs `url`; caches to `path` (default `rule-providers/{name}.yaml`).
- `file` — needs `path`; loaded from disk, no refresh.

### `type: inline`

Embed the rules directly:

```yaml
rule-providers:
  internal:
    type: inline
    behavior: classical
    payload:
      - DOMAIN,internal.corp,Corporate
      - IP-CIDR,192.168.0.0/16,Corporate
```

`interval > 0` on an inline provider is a hard error (nothing to refresh).

## Subscriptions

Subscriptions are managed at runtime through the [REST API](../reference/rest-api) — they
fetch a remote Clash-format document and apply its proxies, groups, and rules:

- `GET /api/subscriptions` — list, with per-subscription counts and last-updated times.
- `POST /api/subscriptions` — add `{ name, url, interval? }` and apply immediately.
- `POST /api/subscriptions/{name}/refresh` — re-fetch.
- `DELETE /api/subscriptions/{name}` — remove and clear its contents.

HTTP providers with a non-zero `interval` are also refreshed automatically by a background
task.
