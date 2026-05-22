# 24-Hour Soak Test Plan (M1 Exit Gate)

Status: **abandoned** — skipped by decision 2026-04-11. 24h soak replaced with manual real-subscription smoke test at M1 exit.

Per `vision.md` §M1 and `roadmap.md` §"M1 exit criteria", M1 is declared
complete when *"a representative real-world Clash Meta subscription loads,
routes traffic correctly, and survives a 24h soak test without leaks or
panics."* This document pins down what "representative", "routes correctly",
and "without leaks" actually mean so the harness can be built before we
need it.

## 1. Goals and non-goals

**Goals**

- Catch slow leaks: RSS growth, file-descriptor growth, connection-table
  growth, DNS cache unboundedness.
- Catch latent panics: any panic in any worker aborts the run.
- Catch behavioral drift under sustained load: selector/urltest stickiness,
  rule re-evaluation cost, DNS snooping table correctness.
- Produce a single pass/fail artifact plus time-series metrics the PM can
  attach to the M1 sign-off.

**Non-goals**

- Peak throughput benchmarking — that is M2's `docs/benchmarks/` work.
- Comparison against Go mihomo — also M2.
- Fuzzing / adversarial inputs — separate effort.

## 2. Representative subscription

A soak test is only as real as its config. The subscription used for the
gate must exercise every M1 feature surface at least once, so regressions
in any M1 item show up. Concretely, the config under
`tests/soak/config.yaml` must contain:

- **≥ 3 outbound protocols** from the M1 set: at least one of each of
  `ss`, `trojan`, `vmess` (M1.B-1), `vless` (M1.B-2), plus `direct` and
  `reject`.
- **At least one gRPC-transport node and one HTTP/2-transport node**
  (M1.A-1/A-2), wrapping one of the above protocols. These can point to
  the same backend; the point is that the transport code runs.
- **One `url-test`, one `fallback`, and one `select` group**, each with
  ≥ 2 members, so group machinery (health checks, switches) actually
  executes.
- **DoH and DoT upstreams** in the `dns` section (M1.E-1/E-2), plus at
  least one plain-UDP upstream as a control.
- **`hosts` entries** so the DNS hosts trie (M0-5) is hit.
- **A rule block of ≥ 200 rules** including `DOMAIN`, `DOMAIN-SUFFIX`,
  `DOMAIN-KEYWORD`, `IP-CIDR`, `IP-CIDR6`, `GEOIP` (M0-4), `PROCESS-NAME`
  (M0-3), `RULE-SET` (classical + ipcidr behaviors), and `MATCH`.
  200 rules is arbitrary but matches the order-of-magnitude of real
  community subscriptions.
- **At least one `rule-provider`** set to auto-refresh at a short
  interval so the refresh path gets exercised many times over 24h
  (M0-9).

We do not need a real paid subscription; we need a config that **looks
like one shape-wise**. The backing servers can be local mocks, with
real backends reserved for the "golden run" (§7).

## 3. Traffic generator

Pick something we can run inside a container without external network
dependencies.

**Primary generator — wrk2 driving a local HTTP echo behind meow-rs:**

- Local `caddy` or `nginx` as the origin on 127.0.0.1:18080, returning
  a 1 KiB response and a 1 MiB response on two different paths.
- `wrk2` running through meow-rs's mixed listener as an HTTP proxy,
  targeted at a rotating pool of hostnames that map (via /etc/hosts
  or the test's `hosts:` block) back to 127.0.0.1. Rotating hostnames
  force rule re-evaluation and DNS-snooping table updates; a single
  hostname would never exercise the cache eviction path.
- Fixed request rate (not "open the throttle"): start at 200 req/s
  constant. Soak tests care about duration, not peak.

**Secondary generator — UDP echo + DNS queries:**

- `socat` UDP echo on 127.0.0.1:18081. A small Python/Rust script sends
  paced UDP datagrams through the SOCKS5 listener to exercise UDP NAT.
- `dig` loop (every 5s, rotating qnames) against meow-rs's DNS server
  to cover the resolver / cache / snooping paths.

**Chaos injection (cheap, high-value):**

- Kill and restart one of the backend mock servers every 30 min to
  force group failover (`url-test`/`fallback`).
- Drop the rule-provider HTTP endpoint for 2 min every hour to exercise
  refresh-failure paths.

All generators run inside the same Docker Compose stack as the meow-rs
binary under test, so the whole soak is one `docker compose up`.

## 4. What we watch

Sampled every 30s into a CSV (owned by a tiny sidecar collector; no
Prometheus dependency required for M1):

| Metric | Source | Pass criterion |
|---|---|---|
| RSS (KiB) | `/proc/$pid/status` VmRSS | Slope over final 12h ≤ 0.5 MiB/h; peak ≤ 300 MiB |
| Open fds | `/proc/$pid/fd` count | Bounded; no monotonic growth after warm-up |
| TCP connections (kernel) | `ss -tan \| wc -l` for pid's netns | Returns to baseline ±10% between load bursts |
| Goroutines-equivalent | tokio task count via `/debug` endpoint (needs tiny addition; see §6) | Bounded |
| meow-rs conn table size | REST `/connections` count | Returns to near-zero within 2× idle-timeout after generators stop |
| DNS cache size | REST `/dns/...` or added debug endpoint | Bounded by configured cap |
| Panics | stderr grep `panicked at` | **Zero** |
| Generator error rate | wrk2 latency/error CSV | ≤ 0.1% over the 24h; no sustained error spike > 1% for > 5 min |
| Rule-match correctness | Periodic "canary" requests whose expected outbound is pinned; assert via REST `/connections` the right proxy was used | 100% |

Pass = all rows pass **and** the run completed 24h wall-clock without
the binary exiting.

## 5. Harness layout (proposed)

```
tests/soak/
  README.md
  docker-compose.yml        # meow-rs + origins + generators + collector
  config.yaml               # representative subscription
  generators/
    wrk2.sh
    udp_echo_loop.py
    dig_loop.sh
    chaos.sh                # random kill/restart
  collector/
    sample.sh               # cron-style sampler → soak.csv
  check.py                  # parses soak.csv + logs, emits pass/fail
```

CI wiring: **not** on every PR (24h is too long). Run it:

- Manually via `workflow_dispatch` before cutting an M1 release.
- Scheduled weekly on `main` once M1 is feature-complete.

The workflow uploads `soak.csv`, the meow-rs log, and `check.py`'s
verdict as artifacts. Red verdict fails the job.

## 6. What the binary needs that it doesn't have yet

Blockers I've found so far — these are not soak-harness work, they are
things the harness depends on and should probably become their own
tasks:

1. **Task-count / internal-state debug endpoint.** `/debug/state`
   returning goroutine-equivalent counts, active timers, and cache
   sizes. Without this we are guessing from `/proc`. Cheap to add; ask
   engineer.
2. **Deterministic shutdown of the connection table on idle.** Needs
   verification — if the table retains entries after their sockets
   close, the soak will look like a leak that is actually just
   bookkeeping. I'll file a verification task.
3. **Panic → non-zero exit.** Verify that a panic in any spawned tokio
   task actually aborts the process. If not, the soak will silently
   "pass" while a worker is dead. This is an engineer task worth filing
   regardless of the soak.

## 7. Two-tier gate

- **Tier 1 (required for M1 sign-off):** 24h run against the mock-only
  stack described above. Fully automatable, fully reproducible.
- **Tier 2 (recommended, not required):** 24h run against **one** real
  paid subscription on a dedicated VM, driven by the same generators.
  Catches things mock backends can't — real TLS cert rotations, real
  latency variance, real provider-side rate limits. This is the
  confidence check we'd actually want before telling users "M1 ships".

PM decides whether Tier 2 is mandatory; I lean "strongly recommended
but not gating" because a paid subscription introduces a flaky
dependency we don't want in the release path.

## 8. Open questions for PM / architect

- Is there a canonical "representative subscription" shape the PM
  wants me to match (protocol mix, rule count)? §2 is my guess.
- Do we want Prometheus `/metrics` (vision.md §M1 observability bullet)
  to land *before* the soak harness, so the collector can scrape rather
  than poll `/proc`? If yes, the soak harness is effectively blocked
  on that.
- Architect: any concerns about running the soak inside a single Docker
  Compose stack vs. multi-host? For M1 single-host is enough; flagging
  in case there's a reason it isn't.
