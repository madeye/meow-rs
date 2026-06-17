# ADR 0013: HTTPS/SVCB record handling in fake-IP mode (dual-stack)

- **Status:** Accepted
- **Date:** 2026-06-15
- **Author:** Claude (on behalf of @madeye)
- **Related:** PR #214 (direct UDP reply socket address family / QUIC), PR #215 (initial hint stripping), RFC 9460

## Context

Fake-IP mode hands clients a synthetic IP per hostname so the tunnel can route
and sniff by **domain** rather than by destination IP. The reverse map
(fake IP → host) only exists because the client was *forced* to connect to an
address we control.

DNS `HTTPS` (type 65) and `SVCB` (type 64) records (RFC 9460) break that
assumption. Their `ipv4hint` / `ipv6hint` SvcParams carry the origin's **real**
addresses, and an RFC 9460 client may connect straight to a hint address
without ever querying A/AAAA. On a dual-stack network the client runs Happy
Eyeballs across whatever families it can derive — so a leaked hint lets HTTP/3
(`alpn=h3`) traffic bypass fake-IP entirely: no domain-based rule match, no
sniffing, and on iOS the flow may not even traverse the tunnel correctly. This
is the same leak family as the QUIC direct-UDP bug fixed in PR #214.

Before this work, type-65/64 queries took the generic forward path and were
re-emitted **verbatim**, hints intact.

### What the reference implementation does

Upstream mihomo returns an **empty answer** for these records in fake-IP mode:

```go
case D.TypeSVCB, D.TypeHTTPS:
    return handleMsgWithEmptyAnswer(r), nil
```

This is correct for routing but blunt: it discards the **entire** record,
including two params that have nothing to do with addressing —

- `alpn` (e.g. `h3`): the client loses its DNS-level signal to try HTTP/3 on
  the first flight and must rediscover it via an `Alt-Svc` response header.
- `ech` (Encrypted ClientHello config): **only ever delivered via the
  HTTPS/SVCB record.** Returning empty disables ECH for every fake-IP user.

### RFC 9460 client behaviour (the dual-stack pivot)

> If A and AAAA records for TargetName are locally available, the client SHOULD
> ignore these hints. Otherwise, clients SHOULD perform A and/or AAAA queries
> for TargetName … When selecting between IPv4 and IPv6 … clients may use an
> approach such as Happy Eyeballs.

So: **a record with no IP hints forces the client onto the A/AAAA path**, where
our per-family fake synthesis already does the right thing. That is the lever
this ADR pulls.

## Decision

In fake-IP mode, **strip `ipv4hint` and `ipv6hint` from HTTPS/SVCB answers and
keep everything else** (`alpn`, `port`, `ech`, `mandatory`, …). Defer all
address-family selection to the existing A/AAAA fake synthesis.

Concretely:

1. `Resolver::fake_ip_active_for(host)` — true when fake-IP synthesis applies to
   `host` (fake-IP mode, ≥1 pool configured, host is not an explicit hosts-trie
   mapping, skipper does not bypass). Mirrors the gating in `lookup_ipv4` /
   `lookup_ipv6` so the HTTPS path and the A/AAAA path agree on *which* hosts are
   faked. Skipper-bypassed / hosts-mapped domains keep their real hints.

2. `strip_svc_ip_hints(record)` in the DNS server — for HTTPS/SVCB records,
   drop the two hint params; any other record type passes through unchanged.

3. **RFC 9460 §8 `mandatory` scrub.** A key listed in `mandatory` but absent
   from the RR makes the whole record malformed, so the client discards it —
   taking the `alpn`/`ech` we wanted to keep with it. So when a stripped hint
   appears in the `mandatory` list we remove it from that list too, and drop
   `mandatory` entirely if it would otherwise become empty (an empty mandatory
   list is itself malformed).

### Why this is correct on dual-stack — case analysis

The stripped record carries no addresses, so the client always resolves
A/AAAA. Correctness reduces to the per-family fake synthesis, which already
behaves correctly for every pool configuration:

| Fake pool | A query | AAAA query | Client outcome |
|-----------|---------|------------|----------------|
| v4-only (default) | v4 fake | `NOERROR`-empty (suppressed) | uses v4 fake; no stall |
| v4 + v6 | v4 fake | v6 fake | Happy Eyeballs over two fakes, both routed |
| v6-only | (no v4 pool → real v4 leak — pre-existing) | v6 fake | — |

IPv6-only **client** networks (no IPv4 at all, NAT64/DNS64/464XLAT) are a
confirmed non-goal for this app's deployments, so the v6-only-pool row and the
RFC 7050 NAT64 hint-synthesis edge cases are explicitly out of scope rather
than blocking. The supported matrix is v4-only (default) and dual-stack.

Both routed families land on fake IPs, so the reverse map resolves and the
tunnel re-resolves the real destination by domain at dial time (the real
address family is decoupled from the family the client used — see PR #214).

### Why strip rather than rewrite-to-fake

Rewriting the hints to the fake IPs (`ipv4hint=[fake4]`, `ipv6hint=[fake6]`)
would save the client a round trip, but is **less** correct on dual-stack:

- It duplicates the per-family synthesis logic (incl. AAAA suppression for
  v4-only pools) and risks divergence from the A/AAAA path.
- Leaving only an `ipv4hint` (v4-only pool) invites RFC 9460's NAT64 behaviour:
  the client may synthesize a v6 from the fake v4 (RFC 7050), producing an
  address **outside** our fake pool that the reverse map cannot resolve.

Stripping has a single source of truth (the A/AAAA path) and no NAT64 trap.

### Why keep `alpn`/`ech` rather than return empty (mihomo)

ECH config is delivered *only* via this record; returning empty disables ECH
for all fake-IP users. ECH is relayed end-to-end (the tunnel forwards the
ClientHello bytes), so keeping it is both safe and a privacy win. Keeping
`alpn=h3` lets the client attempt HTTP/3 on the first flight — which now works
end-to-end thanks to PR #214. This is a deliberate, documented divergence from
upstream (per ADR-0002 divergence policy).

## Consequences

- HTTP/3 and ECH keep working in fake-IP mode; no IP can be derived from an
  HTTPS/SVCB answer for a faked host.
- One extra A/AAAA round trip vs. rewriting hints — acceptable, and the records
  are short-TTL cached.
- Coverage: `strip_hints_*` (hint removal, ech/alpn preservation, mandatory
  scrub, empty-mandatory drop, non-SVCB passthrough),
  `fake_ip_active_for_gates_on_mode_pool_and_skipper`, and
  `fake_ip_dual_stack_synthesis_is_per_family` (the per-family A/AAAA contract
  this design rests on).

## Alternatives considered

- **Empty answer (mihomo).** Simplest; kills ECH + DNS-level h3. Rejected.
- **Rewrite hints to fake IPs.** NAT64 trap + logic duplication. Rejected.
- **Forward verbatim (status quo ante).** The leak this ADR closes.
