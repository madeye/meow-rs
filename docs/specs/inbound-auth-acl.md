# Spec: Inbound authentication and LAN ACLs (M1.F-3)

Status: Approved (architect 2026-04-11)
Owner: pm
Tracks roadmap item: **M1.F-3**
Depends on: none — inbound auth is independent of named listeners (M1.F-1),
though both may land in the same PR.
See also: [`docs/specs/listeners-unified.md`](listeners-unified.md) — IN-USER
rule (M1.D-4) requires both F-1 (in_name) and F-3 (in_user populated in Metadata).
Upstream reference: `listener/http/proxy.go`, `listener/socks5/tcp.go`,
`config/config.go::parseAuthentication`.

## Motivation

The current HTTP and SOCKS5 listeners accept all connections without
credential checking — a security gap for any deployment where the
`allow-lan: true` or `bind-address: 0.0.0.0` exposes the proxy to
the local network or beyond. Corporate and shared-server deployments
need user-level auth.

`skip-auth-prefixes` provides a LAN bypass: traffic from trusted subnets
(e.g., `192.168.0.0/24`) is admitted without credentials, avoiding
disruption to internal tooling that doesn't support proxy authentication.

`IN-USER` rule (M1.D-4, gated on F-3) lets operators route traffic
differently based on which user's credentials authenticated the connection —
enabling per-user proxy group assignment.

## Scope

In scope:

1. `authentication: ["user:pass", ...]` global config field, list of
   `username:password` pairs. Applied to all HTTP and SOCKS5 listeners.
2. `skip-auth-prefixes: ["192.168.0.0/24", ...]` config field — source
   IP ranges that bypass auth entirely.
3. SOCKS5 listener: if `authentication` is non-empty, advertise method
   `0x02` (USERNAME/PASSWORD) during negotiation. Reject connections that
   don't authenticate or fail credential check.
4. HTTP listener: if `authentication` is non-empty, require
   `Proxy-Authorization: Basic <base64>` header on CONNECT requests.
   Return `407 Proxy Authentication Required` with
   `Proxy-Authenticate: Basic realm="meow"` if absent or wrong.
5. Populate `Metadata.in_user: Option<String>` with the authenticated
   username on success. `None` when auth is skipped (LAN bypass or no auth configured).
6. Mixed listener: delegates to HTTP or SOCKS5 sub-handler; auth is applied
   by the sub-handler based on detected protocol.
7. TProxy listener: auth is NOT applied. TProxy handles traffic transparently;
   `Metadata.in_user` is always `None` for TProxy connections.

Out of scope:

- **Per-listener auth config** — global auth list applies to all
  authenticated listeners. Per-listener auth is M2+.
- **Digest / NTLM auth for HTTP** — Basic only in M1.
- **RADIUS or external auth backends** — local config list only.
- **Rate limiting on failed auth** — M2+ (brute-force protection).
- **`IN-USER` rule implementation** — spec only covers Metadata.in_user
  population; rule matching dispatch is M1.D-4.

## User-facing config

```yaml
# Global config
authentication:
  - alice:hunter2
  - bob:s3cr3t!
  - carol:correct_horse_battery_staple

skip-auth-prefixes:
  - 127.0.0.1/32     # always skip localhost
  - 192.168.0.0/24   # LAN subnet
  - ::1/128          # IPv6 loopback
```

Field reference:

| Field | Type | Default | Meaning |
|-------|------|---------|---------|
| `authentication` | `[]string` | `[]` (no auth) | `user:pass` pairs. If empty, all connections are admitted without auth. |
| `skip-auth-prefixes` | `[]string` | `["127.0.0.1/32", "::1/128"]` | Source IP ranges that bypass auth. Loopback is always skipped. |

**Defaults**: `127.0.0.1/32` and `::1/128` are always in the skip list,
even when `skip-auth-prefixes` is not configured. Users cannot remove
loopback from the bypass (it would break local tooling).

**Divergences from upstream** (classified per
[ADR-0002](../adr/0002-upstream-divergence-policy.md)):

| # | Case | Class | Rationale |
|---|------|:-----:|-----------|
| 1 | Malformed `user:pass` entry (no colon) — upstream silently ignores | A | Hard parse error. An entry with no `:` is almost certainly a typo. |
| 2 | Empty password (`user:`) — upstream accepts | B | Warn-once at parse time. Empty passwords are valid but unusual; user may have made a config error. |
| 3 | SOCKS5 method 0xFF (no acceptable method) returned when auth required but not offered | — | We match upstream: if client does not offer method 0x02 when credentials are required, reply `[0x05, 0xFF]` and close. |
| 4 | HTTP `Proxy-Authorization` on all forward proxy requests — upstream checks | — | We check `Proxy-Authorization` on both CONNECT and non-CONNECT forward proxy requests. The listener already parses the first request line to distinguish CONNECT from forward proxy; auth check adds ~10 lines at that branch point. This matches upstream. |

## Internal design

### Credential store

```rust
// meow-config/src/lib.rs (or a dedicated auth.rs)

pub struct Credentials {
    /// username → password (plain text, not hashed — matches upstream)
    inner: HashMap<String, String>,
}

impl Credentials {
    pub fn verify(&self, username: &str, password: &str) -> bool {
        self.inner.get(username).map(|p| p == password).unwrap_or(false)
    }
    pub fn is_empty(&self) -> bool { self.inner.is_empty() }
}

pub struct AuthConfig {
    pub credentials: Arc<Credentials>,
    pub skip_prefixes: Vec<IpNet>,  // always includes 127.0.0.1/32 and ::1/128
}

impl AuthConfig {
    pub fn should_skip(&self, src_ip: &IpAddr) -> bool {
        self.skip_prefixes.iter().any(|net| net.contains(*src_ip))
    }
}
```

**Plain-text storage**: upstream Go mihomo stores credentials in plain text
in the config. We match. Hashing (bcrypt/argon2) is M2+.

**Constant-time comparison**: `verify()` must use constant-time string
comparison to prevent timing attacks. Use `subtle::ConstantTimeEq` or a
simple constant-time byte compare.

```rust
// Use subtle::ConstantTimeEq — do not use a manual loop.
// Note: HashMap lookup of username is not constant-time (leaks user-exists
// vs user-missing via timing); a constant-time user lookup would require
// linear scan over all credentials. We accept this limitation for M1:
// auth is over TCP with variable network jitter that dwarfs lookup timing.
fn verify(credentials: &HashMap<String, String>, username: &str, password: &str) -> bool {
    match credentials.get(username) {
        Some(stored) => {
            use subtle::ConstantTimeEq;
            stored.as_bytes().ct_eq(password.as_bytes()).into()
        }
        None => false,
    }
}
```

### Listener integration

All four listener implementations receive `Arc<AuthConfig>` at construction.
The check happens after TCP accept and before the proxy handshake:

**SOCKS5:**
```
1. Accept TCP connection, read src_addr
2. if auth_config.should_skip(src_addr): skip auth; proceed with no-auth (method 0x00)
3. else if !credentials.is_empty():
     advertise methods [0x02]; wait for method selection
     if chosen == 0xFF: close connection (client doesn't support 0x02)
     read username/password; verify; if fail: send [0x01, 0x01]; close
     metadata.in_user = Some(username)
4. else: no-auth (method 0x00)
```

**HTTP:**
```
1. Accept TCP connection, read src_addr
2. Parse CONNECT request line and headers
3. if auth_config.should_skip(src_addr): skip auth
4. else if !credentials.is_empty():
     read Proxy-Authorization header
     if absent: send 407 with Proxy-Authenticate; close
     decode Basic base64; split user:pass; verify
     if fail: send 407; close
     metadata.in_user = Some(username)
5. Continue CONNECT tunnel
```

**TProxy:** no auth. `metadata.in_user = None`.

**TProxy connections bypass auth unconditionally**, regardless of `skip-auth-prefixes`. Transparent proxy has no mechanism for the client to send `Proxy-Authorization` — it is assumed the operator gates TProxy at the kernel/netfilter level. `Metadata.in_user` is always `None` for TProxy connections.

### Metadata

Add `in_user: Option<String>` to `Metadata`. Default `None`. Set by auth-
aware listener code after successful credential verification.

## Acceptance criteria

1. No `authentication:` config → all connections admitted (existing behaviour unchanged).
2. `authentication: [alice:hunter2]` → SOCKS5 connection with correct
   credentials succeeds; `Metadata.in_user == Some("alice")`.
3. SOCKS5 with wrong password → method 0x02 response, auth failure `[0x01, 0x01]`,
   connection closed.
4. SOCKS5 client offers only method 0x00 when auth required → `[0x05, 0xFF]`,
   connection closed.
5. HTTP CONNECT with correct `Proxy-Authorization: Basic` → 200 established;
   `Metadata.in_user == Some("alice")`.
6. HTTP CONNECT with wrong credentials → `407 Proxy Authentication Required`.
7. HTTP CONNECT with no auth header → `407` with `Proxy-Authenticate: Basic realm="meow"`.
8. Source IP in `skip-auth-prefixes` → admitted without credentials;
   `Metadata.in_user == None`.
9. Loopback source IP (127.0.0.1) always bypasses auth, even when
   `skip-auth-prefixes` is not configured.
10. Malformed `authentication` entry (no colon) → hard parse error at startup.
    Class A per ADR-0002.
11. Empty password (`user:`) → warn-once at parse; accepted (not hard error).
    Class B per ADR-0002.
12. TProxy connections: auth never applied; `Metadata.in_user == None`.
13. Constant-time comparison: verify() uses constant-time byte comparison.
    (Assert via code review / grep for `subtle` or the manual loop — not a
    timing test.)

## Test plan (starting point — qa owns final shape)

**Unit (credential store):**

- `credentials_verify_correct` — `alice:hunter2` stored; verify passes.
- `credentials_verify_wrong_password` — wrong password → false.
  NOT true, NOT panic.
- `credentials_verify_unknown_user` — user not in store → false.
- `credentials_verify_constant_time` — verify same result regardless of
  which byte differs. Structural test (inspect implementation), not timing.
- `skip_prefixes_loopback_always_skipped` — `127.0.0.1` skipped with empty
  `skip-auth-prefixes` config. NOT requires explicit config. Always.

**Unit (SOCKS5 listener):**

- `socks5_auth_correct_credentials_admitted` — mock client sends method 0x02 +
  correct user/pass → admitted; `Metadata.in_user` set.
  Upstream: `listener/socks5/tcp.go::handleConn`. NOT method 0x00 when
  auth is configured.
- `socks5_auth_wrong_password_closed` — wrong password → server sends
  `[0x01, 0x01]`; connection closed.
- `socks5_no_method_02_offered_rejected` — client offers only `[0x00]`; server
  replies `[0x05, 0xFF]`; connection closed.
- `socks5_skip_prefix_bypasses_auth` — src_ip in skip list → method 0x00
  accepted even with credentials configured; `Metadata.in_user == None`.

**Unit (HTTP listener):**

- `http_connect_auth_correct_admitted` — correct `Proxy-Authorization: Basic`;
  tunnel established; `Metadata.in_user` set.
  Upstream: `listener/http/proxy.go::handleConn`.
- `http_connect_no_auth_header_returns_407` — no header → 407 with
  `Proxy-Authenticate: Basic realm="meow"`.
  NOT 200. NOT 401.
- `http_connect_wrong_credentials_returns_407` — bad credentials → 407.
- `http_connect_skip_prefix_bypasses_auth` — src_ip in skip list → no auth
  required; `Metadata.in_user == None`.

**Unit (config parser):**

- `parse_authentication_valid` — two `user:pass` entries.
- `parse_authentication_malformed_no_colon` → hard parse error. Class A.
- `parse_authentication_empty_password_warns` — `user:` → warn-once, accepted.
  Class B per ADR-0002.
- `parse_skip_auth_prefixes_valid_cidr` — valid CIDR entries parsed.
- `parse_skip_auth_prefixes_invalid_cidr` → hard parse error.

## Implementation checklist (engineer handoff)

- [ ] Add `authentication: Option<Vec<String>>` and `skip_auth_prefixes: Option<Vec<String>>`
      to `RawConfig` in `raw.rs`.
- [ ] Parse into `AuthConfig` in config parser; add loopback to skip list always.
- [ ] Add `subtle` crate to workspace for constant-time comparison.
- [ ] Add `in_user: Option<String>` to `Metadata` in `meow-common`.
- [ ] Pass `Arc<AuthConfig>` to all four listener constructors.
- [ ] Implement auth check in `socks5.rs` (before proxy handshake).
- [ ] Implement auth check in `http_proxy.rs` (after CONNECT line, before tunnel).
- [ ] Update `docs/roadmap.md` M1.F-3 row with merged PR link.
