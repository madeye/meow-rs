# Spec: Unified named listeners (M1.F-1)

Status: Approved (architect 2026-04-11)
Owner: pm
Tracks roadmap item: **M1.F-1**
Blocks: M1.D-4 (IN-TYPE, IN-NAME, IN-USER rules — need `Metadata.in_name` populated).
See also: [`docs/specs/inbound-auth-acl.md`](inbound-auth-acl.md) — auth
layered on top of named listeners.
Upstream reference: `listener/listener.go`, `config/config.go::parseListeners`.

## Motivation

`Metadata.in_name` and `Metadata.in_port` exist in the struct but are never
populated — they are always the zero values (`""` and `0`). This means
`IN-NAME`, `IN-PORT` (partially), and `IN-TYPE` rules silently never match
on traffic from named listeners, even when the user configures them.

Naming listeners also enables split-routing topologies: traffic arriving on
a "corp-socks" listener can be routed through a different proxy group than
traffic from a "personal-mixed" listener. Real enterprise subscriptions use
this for policy separation.

The existing flat per-protocol port config (`mixed-port`, `http-port`,
`socks-port`, `tproxy-port`) remains supported as short-hand; the new
`listeners:` array adds named instances and is the long-form.

## Scope

In scope:

1. Parse `listeners:` YAML array in `meow-config`. Each entry has
   `name`, `type`, `port`, and optional `listen` (bind address).
2. Support listener types: `mixed`, `http`, `socks5`, `tproxy`.
3. Spawn named listener instances in `main.rs`, each propagating `in_name`
   and `in_port` into every `Metadata` it creates.
4. Existing flat fields (`mixed-port`, `http-port`, `socks-port`, `tproxy-port`)
   continue to work. Auto-assign names: `"mixed"`, `"http"`, `"socks"`,
   `"tproxy"`. Multiple instances of the same type are allowed via `listeners:`.
5. Wire `Metadata.in_name` and `Metadata.in_port` in all four listener
   implementations (`mixed.rs`, `http_proxy.rs`, `socks5.rs`, `tproxy/`).
6. Expose listener list in `GET /listeners` REST endpoint (simple list of
   name, type, port, listen).
7. `IN-NAME` and `IN-PORT` rules (already in the rule enum) now function
   correctly because Metadata carries the listener name and port.
8. `IN-TYPE` rule: maps listener `type` field to Metadata.conn_type categories.
   `IN-TYPE: HTTP` matches both HTTP and HTTPS; `IN-TYPE: SOCKS5` matches
   SOCKS5; `IN-TYPE: TPROXY` matches TProxy.

Out of scope:

- **IN-USER rule** (M1.D-4's third variant) — requires auth infrastructure
  (M1.F-3). Deferred. `IN-USER` rule returns no-match until F-3 lands and
  populates `Metadata.in_user`.
- **Redir listener** (M1.F-4) — deferred to M1.x.
- **Tunnel listener** (M1.F-5) — deferred.
- **Per-listener proxy overrides** — e.g., "this listener always uses DIRECT".
  Out of scope for M1; use rules instead.
- **Hot-adding/removing listeners at runtime** — M3. M1 reads the listener
  list at startup only.
- **Multiple listeners on the same port** — hard parse error.

## User-facing config

**Short-hand (unchanged):**
```yaml
mixed-port: 7890    # auto-name: "mixed"
http-port: 7891     # auto-name: "http"
socks-port: 1080    # auto-name: "socks"
tproxy-port: 7892   # auto-name: "tproxy"
```

**Named listeners (new):**
```yaml
listeners:
  - name: corp-socks
    type: socks5
    port: 7891
    listen: 0.0.0.0   # optional; overrides global bind-address for this listener

  - name: personal-mixed
    type: mixed
    port: 7892

  - name: transparent
    type: tproxy
    port: 7893
    tproxy-sni: true   # type-specific options
```

**Rules using listener names:**
```yaml
rules:
  - IN-NAME,corp-socks,ProxyGroup-Corp
  - IN-NAME,personal-mixed,ProxyGroup-Personal
  - IN-TYPE,SOCKS5,SelectGroup
  - IN-PORT,7892,DirectGroup
```

Field reference for each `listeners:` entry:

| Field | Type | Required | Default | Meaning |
|-------|------|:-------:|---------|---------|
| `name` | string | yes | — | Unique listener name. Referenced by `IN-NAME` rules. Must be unique across all listeners (including auto-named shorthand ones). |
| `type` | enum | yes | — | `mixed`, `http`, `socks5`, `tproxy`. |
| `port` | u16 | yes | — | Listen port. Must be unique. |
| `listen` | string | no | global `bind-address` | Per-listener bind address override. |
| `tproxy-sni` | bool | no | global `tproxy-sni` | Only for `type: tproxy`. |

**Divergences from upstream** (classified per
[ADR-0002](../adr/0002-upstream-divergence-policy.md)):

| # | Case | Class | Rationale |
|---|------|:-----:|-----------|
| 1 | Duplicate listener port — upstream silently overwrites | A | Hard parse error: "port N already used by listener 'M'". |
| 2 | Duplicate listener name — upstream silently overwrites | A | Hard parse error: "listener name 'X' already defined". |
| 3 | Unknown listener type — upstream ignores | A | Hard parse error. `type: redir` is a known-future type; still errors in M1. |
| 4 | Short-hand `mixed-port` + `listeners:` entry on same port — upstream accepts | A | Hard parse error. Same as duplicate port rule. |

## Internal design

### Listener lifecycle

Each named listener is represented by a `ListenerConfig` and a running
`tokio::task`:

```rust
// meow-config/src/lib.rs

pub struct NamedListener {
    pub name: String,
    pub listener_type: ListenerType,
    pub port: u16,
    pub listen: SocketAddr,          // resolved from `listen` field + port
    pub tproxy_sni: bool,            // only for TProxy; default from global config
}

pub enum ListenerType { Mixed, Http, Socks5, TProxy }
```

### Metadata population

Every listener implementation receives `name: String` at construction and
stores it. When building `Metadata` for each accepted connection:

```rust
metadata.in_name = self.name.clone();
metadata.in_port = self.listen.port();
// metadata.conn_type already set per listener (HTTP/HTTPS/SOCKS5/TProxy/etc.)
```

This is the only behaviour change to existing listener code. No routing
logic changes.

### IN-TYPE rule mapping

`IN-TYPE` values the user can write and what they match:

| `IN-TYPE` value | Matches `Metadata.conn_type` |
|-----------------|------------------------------|
| `HTTP` | `ConnType::Http` or `ConnType::Https` |
| `HTTPS` | `ConnType::Https` only |
| `SOCKS5` | `ConnType::Socks5` |
| `TPROXY` | `ConnType::TProxy` |
| `INNER` | `ConnType::Inner` (tunnel-internal) |

Unknown `IN-TYPE` value → hard parse error (Class A).

**IN-TYPE,HTTP vs IN-TYPE,HTTPS:** `IN-TYPE,HTTP` is a superset that matches both plain HTTP and HTTPS connections detected by the listener. Use `IN-TYPE,HTTPS` to match only HTTPS. A rule `IN-TYPE,HTTP,Reject` will accidentally block HTTPS traffic — use `IN-TYPE,HTTPS` or `IN-TYPE,HTTPS` + `IN-TYPE,HTTP` split rules if the intent is to block plaintext only.

### GET /listeners

```json
[
  { "name": "mixed", "type": "mixed", "port": 7890, "listen": "127.0.0.1" },
  { "name": "corp-socks", "type": "socks5", "port": 7891, "listen": "0.0.0.0" }
]
```

No mutation endpoints in M1 — listener list is read-only at runtime.

## Acceptance criteria

1. `listeners: [{name: foo, type: socks5, port: 7891}]` spawns a SOCKS5
   listener; `IN-NAME,foo,...` rule matches connections through it.
2. `IN-NAME` with a name that doesn't match any listener — no match
   (passes to next rule), same as any non-matching rule.
3. `in_port` in Metadata matches the configured port; `IN-PORT,7891,...`
   matches.
4. `IN-TYPE,SOCKS5` matches connections from a SOCKS5 listener; does NOT
   match HTTP connections on the same port.
5. Shorthand `mixed-port: 7890` auto-names listener `"mixed"`;
   `IN-NAME,mixed,...` rule matches.
6. Duplicate port (shorthand + named) → hard parse error at startup.
7. Duplicate listener name → hard parse error at startup. Class A.
8. `GET /listeners` returns the running listener list with correct names/ports.
9. Two `listeners:` entries of different types on different ports both work simultaneously.
10. `listen` override per-listener overrides the global bind address for that listener only.

## Test plan (starting point — qa owns final shape)

**Unit (config parser):**

- `parse_named_listener_socks5` — single socks5 entry, all fields.
- `parse_shorthand_mixed_port_auto_names` — `mixed-port: 7890` → name `"mixed"`.
- `parse_duplicate_port_hard_errors` — two entries sharing port → parse error.
  Class A per ADR-0002.
- `parse_duplicate_name_hard_errors` — two entries same name → parse error.
  Class A per ADR-0002.
- `parse_unknown_type_hard_errors` — `type: redir` → parse error.
  Class A per ADR-0002.

**Unit (listener Metadata population):**

- `mixed_listener_populates_in_name` — construct MixedListener with name
  `"my-mixed"`; accept a connection; assert `Metadata.in_name == "my-mixed"`.
- `mixed_listener_populates_in_port` — same; assert `Metadata.in_port == 7890`.
- `socks5_listener_sets_conn_type` — SOCKS5 connection; assert
  `Metadata.conn_type == ConnType::Socks5`.

**Unit (IN-NAME rule matching):**

- `in_name_rule_matches_named_listener` — Metadata with `in_name = "corp"`;
  `IN-NAME,corp,Target` → match.
- `in_name_rule_no_match_different_name` — Metadata `in_name = "personal"`;
  `IN-NAME,corp,Target` → no match.
- `in_type_http_matches_http_and_https` — both ConnType::Http and
  ConnType::Https → IN-TYPE,HTTP match.
- `in_type_https_matches_only_https` — ConnType::Http → IN-TYPE,HTTPS no match.
- `in_type_unknown_value_hard_errors` — `IN-TYPE,QUIC` → parse error.
  Class A per ADR-0002.

## Implementation checklist (engineer handoff)

- [ ] Add `listeners: Option<Vec<RawListener>>` to `RawConfig` in `raw.rs`.
- [ ] Parse `listeners:` in `config_parser.rs`; merge with shorthand fields;
      detect and error on duplicate ports/names.
- [ ] Add `name: String` field to each listener constructor
      (`MixedListener::new`, etc.) and store it.
- [ ] Set `metadata.in_name` and `metadata.in_port` in each listener's
      connection handler.
- [ ] Implement `IN-TYPE` rule dispatch in `rules/parser.rs` mapping strings
      to ConnType patterns.
- [ ] Add `GET /listeners` handler and route in `meow-api/src/routes.rs`.
- [ ] Update `docs/roadmap.md` M1.F-1 row with merged PR link; unblock M1.D-4.
