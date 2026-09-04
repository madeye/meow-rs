# Changelog

All notable changes to meow-rs are documented in this file. The format is
based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Release notes are mirrored onto the GitHub Release for each tag; this file is
the canonical, in-repo source a release is cut from.

## [Unreleased]

### Changed

- **BoringSSL is now the only TLS backend; rustls is gone from the TLS path.**
  Previously a binary built with `boring-tls` (the default) still handshook
  with rustls unless a proxy set `client-fingerprint` or `ech-opts`, and four
  more places carried their own rustls client: URL-test health probes, the
  internal HTTP fetcher, DoT/DoH upstreams, and the vendored anytls client;
  `reqwest` (rustls-tls) did the direct subscription/provider/geodata fetches.
  All of that now goes through `meow_transport::tls::TlsLayer` on BoringSSL:
  every non-REALITY handshake (Trojan, VLESS, VMess, HTTP/SOCKS5-over-TLS,
  SS plugins, ECH tunnel, AnyTLS), health probes, DoT/DoH, and every internal
  HTTP(S) fetch (direct or via proxy — `reqwest` is removed; the in-tree
  client gained direct dialing through the host's resolver/`SocketProtector`
  hooks, custom headers, and a Content-Length precheck). The BoringSSL
  `SSL_CTX` is shared across proxies with the same
  `(client-fingerprint, alpn, skip-cert-verify)` key, and IP-literal server
  names no longer emit an SNI extension (RFC 6066 §3). rustls remains in the
  dependency graph for one reason: quinn, the QUIC stack under `hysteria2`,
  has no BoringSSL backend (a port to Cloudflare's BoringSSL-native `quiche`
  is the follow-up). The loopback TLS servers in the test suites are also
  rustls-based, as dev-dependencies only.
  **Build/feature changes:** the `boring-tls` features (meow-transport,
  meow-config, meow-app) are now no-op aliases — `tls` *is* BoringSSL — and
  the rustls-side `ech` feature is removed (ECH is native). `boring-sys` is
  therefore a hard build requirement (cmake 3.14+ and a C++ compiler); the
  `--no-default-features --features full` rustls fallback for targets that
  cannot link BoringSSL (MIPS, 32-bit musl time64, windows-gnu) no longer
  exists. `meow-anytls` gained a `server` feature (off by default) that gates
  its rustls-based server side; its client takes a `TlsConnect` hook instead
  of a rustls connector. Observable runtime differences: BoringSSL's default
  ClientHello replaces rustls' for proxies without `client-fingerprint`, and
  TLS session resumption is per `SSL_CTX` (64-entry cache) instead of per
  rustls `ClientConfig`.

- **`ipv6` is now effective end-to-end and keeps the `false` default.** The
  `ipv6` flag previously only gated a handful of code paths — the resolver
  queried A and AAAA regardless — so the documented `false` default and
  `GET /configs` disagreed with the actual runtime behaviour. The flag now
  drives the whole resolution pipeline: with `ipv6: false` (the default,
  matching mihomo/Clash) AAAA lookups are skipped and the resolver answers
  IPv4-only; with `ipv6: true` dual-stack domains are queried for both A and
  AAAA (concurrently, with IPv4 tried first as a connection fallback) and
  `DirectAdapter` can fall back to IPv6 when IPv4 connectivity fails. The
  default literal is now centralized in `meow_config::effective_ipv6`
  (previously scattered across six `unwrap_or(...)` sites), and the parser,
  `GET /configs`, and `website/guide/configuration.md` all agree on `false`.
  **Operators who relied on the old always-dual-stack behaviour of an
  omitted `ipv6` key must now set `ipv6: true` explicitly.**

- DNS dual-stack resolution (`resolve_ips` / `lookup_ip_with_ipv6_inner`) now
  queries A and AAAA **concurrently** when IPv6 is enabled, collecting both
  address families with IPv4 ordered first. `DirectAdapter::dial_tcp` iterates
  the full address list, so an IPv4 connect failure no longer discards the IPv6
  candidate — IPv6 remains a connection fallback.

### Fixed

- **`merge_family` no longer revives an expired sibling family.** When a new
  A answer merged into an entry whose AAAA had already expired, the old code
  unconditionally marked AAAA as `queried`, which `family_hit()` then read as a
  fresh `NoData`, suppressing re-resolution of AAAA. The sibling is now only
  carried forward when its own answer is still fresh; an expired sibling stays
  a `Miss` so the resolver re-queries it on demand.

- **`resolve_ips` no longer short-circuits when one family is cached.** A
  single-family cache entry (e.g. A already fresh, AAAA still `Miss`) no longer
  prevents the missing family from being queried. Only already-fresh families
  are dropped from the query set; the missing required family is always
  fetched, preserving `DirectAdapter`'s cross-family fallback.

- **`GET /configs` reports the same `ipv6` default the runtime uses.** The API
  previously reported `ipv6: false` for an unset config while the runtime
  actually queried AAAA anyway, causing UIs/controllers to display a state the
  resolver ignored. Both sides now share `meow_config::effective_ipv6` and
  default to `false` — and the reported value is the one actually enforced.

- **A fast NXDOMAIN no longer suppresses a slow positive answer.** Within a
  single nameserver tier, the first definitive negative (NODATA/NXDOMAIN) is
  now held for a short grace period while the remaining upstreams keep racing;
  a positive answer arriving later always wins. This restores correct
  behaviour for split-horizon / multi-upstream configurations. Network errors
  (`Err`) are not treated as definitive and never short-circuit the pool.

- **Single-flight broadcast misses no longer surface as SERVFAIL.** A
  subscriber that attached just after the publisher sent (and removed its
  inflight slot) previously received `Closed` and could be judged `Failed`.
  `lookup_real_with_ttl` now re-reads the cache on a missed broadcast, so the
  already-merged result is served instead of a transient SERVFAIL.

- **DoH response bodies are now size-capped.** `doh_exchange` previously
  `read_to_end`-ed an unbounded buffer, letting a misbehaving or hostile
  upstream drive unbounded heap growth. Responses are now rejected once they
  exceed the DNS message maximum (65535 B) plus HTTP header headroom.

- **`snapshot()` hides IPs of an expired family.** When one family is still
  fresh and the other has expired, only the fresh family's IPs appear in the
  cache snapshot panel.

- **Hosts-table AAAA answers follow the global `ipv6` switch.** An AAAA query
  for a domain present in the hosts trie is gated by `ipv6` exactly like every
  other AAAA path: with `ipv6: false` it returns NODATA even when the hosts
  file carries an IPv6 address for the domain (the entry remains reachable for
  A queries and for `ipv6: true` configs). This keeps the global toggle a
  single, predictable switch — dual-stack operators who pin addresses in
  `hosts:` must enable `ipv6: true` for the v6 entries to be served.