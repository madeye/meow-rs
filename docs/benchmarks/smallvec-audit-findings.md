# SmallVec Audit Findings — M2.smallvec-audit (task #37)

## Reference: commit after dea4b88

Methodology per ADR-0011 T5: for each candidate Vec field, compute
`SmallVec<[T; N]>` struct size at the p95 inline cap, compare to `Vec` (24 B).
If the SmallVec struct grows (common when `size_of::<T>()` is large), stay with Vec.
Rule: if p95 inline cap > 8 elements, stay with Vec.

`SmallVec<[T; N]>` size = max(N × size_of::<T>() + 8 B tag, 24 B).

---

## Candidates Evaluated

### 1. `CacheEntry.ips: Vec<IpAddr>` (meow-dns/src/cache.rs)

- Typical response size: 1–4 IpAddr entries (A + AAAA).
- `IpAddr` size: 17 B (alignment 1 B).
- `SmallVec<[IpAddr; 4]>`: 4 × 17 + 8 = **76 B** vs Vec = **24 B**.
- Verdict: **reject — struct grows +52 B**. Belongs to task #40 (M2.dns-cache-layout).

### 2. `ConnectionInfo.chains: Vec<Arc<str>>` (meow-tunnel/src/statistics.rs)

- Typical chain depth: 1–4 hops (Selector → URLTest → SS, or just Direct).
- `Arc<str>` size: 16 B (fat pointer).
- `SmallVec<[Arc<str>; 4]>`: 4 × 16 + 8 = **72 B** vs Vec = **24 B**.
- Verdict: **reject — struct grows +48 B**.

### 3. `Metadata.src_geo_ip / dst_geo_ip: Vec<SmolStr>` (meow-common/src/metadata.rs)

- Typical GeoIP label count: 0–2 per IP (country code, ASN occasionally).
- `SmolStr` size: 24 B.
- `SmallVec<[SmolStr; 2]>`: 2 × 24 + 8 = **56 B** vs Vec = **24 B**.
- Verdict: **reject — struct grows +32 B** (evaluated in task #34, same conclusion).

### 4. `RuleSet` / `ClassicalRuleSet` rule lists

- Rule sets range from tens to tens-of-thousands of entries (p99 >> 8).
- Inline cap at p99 would be enormous; SmallVec inline cost far exceeds heap cost.
- Verdict: **reject — p99 >> 8 elements, heap-backed Vec is correct**.

### 5. Listener per-conn byte buffers (sniffer.rs, socks5.rs)

- `Vec<u8>` buffers for TLS handshake sniffing (~50–200 B) and SOCKS5 parsing (~1–255 B).
- `SmallVec<[u8; N]>` for N ≥ 50 adds ≥58 B to each listener coroutine's stack frame.
- These are transient (sub-function lifetime); no struct embedding cost, but per-connection
  stack inflation is undesirable on async tasks where stack size is shared.
- Verdict: **reject — stack inflation on async tasks**.

---

## Outcome

**Zero conversions.** All candidates regress either struct size or stack size. The
fundamental constraint: `SmallVec<[T; N]>` is a size win only when
`N × size_of::<T>() < 16 B` (fitting inside Vec's 24 B minus the tag byte). In this
codebase the smallest hot-path element types are:
- `u8` (1 B) — used in byte buffers, but buffers are large (N > 16 always)
- `Arc<str>` (16 B) — N=1 gives 24 B = Vec, N≥2 grows
- `IpAddr` (17 B) — always grows
- `SmolStr` (24 B) — always grows

The ADR-0011 T5 spec correctly anticipated this outcome: "if p95 inline cap > 8 elements,
stay with Vec." For `IpAddr` the threshold is even lower (size_of 17 B means even N=1
nearly ties Vec).

No code changes. No regression-bar run needed (zero diff).

## Impact on M2.dns-cache-layout (task #40)

The `CacheEntry.ips: Vec<IpAddr>` finding is forwarded to task #40. The DNS cache
optimization opportunity is not SmallVec (struct regression) but rather:
- Storing `Box<[IpAddr]>` instead of `Vec<IpAddr>` (removes the capacity word, −8 B per entry).
- Or a fixed-size array with a length tag for the 1–4 address common case.
These are within #40's scope.
