# Rule-IR Minimization Series — Raspberry Pi Production Benchmark (2026-07-04)

On-device comparison of the rule engine before and after the rule-IR
optimization series (#285, #291, #292, #295, #296, #297), measured on the
production tproxy gateway against its **live 7,528-rule subscription config**
— not a synthetic fixture.

## Versions compared

| Label | Commit | Notes |
|-------|--------|-------|
| 0.15 | `730e8f9` | Last `main` commit at workspace version 0.15.0 — closest buildable proxy for the binary deployed 2026-06-25 |
| 0.16 | `f2b85bc` | `main` after the full series merged (deployed 2026-07-04) |

## Hardware

| Field | Value |
|-------|-------|
| Machine | Raspberry Pi 4 Model B Rev 1.4 |
| CPU | BCM2711, 4× Cortex-A72 (aarch64) |
| RAM | 8 GB |
| OS / kernel | Debian 13 (trixie), Linux 6.12.47+rpt-rpi-v8 |
| CPU governor | ondemand |
| Load context | live `meow` + `meow-gateway` services running (mostly idle LAN) |

## Method

A single-source harness restricted to the API surface shared by both
versions (`CompiledRuleSet::build` / `CompiledRuleSet::match_rules` — the
same entry points `Tunnel` uses at each version) was compiled as a
`meow-tunnel` example at each commit with
`cargo zigbuild --release --target aarch64-unknown-linux-gnu.2.31`, so each
binary carries its own version's release codegen. Source is in the appendix.

- Config: the gateway's `/etc/meow/config.yaml` (7,528 rules, 166 proxies;
  GEOIP/GEOSITE providers resolved from the Pi's local geodata files).
- Timing: best of 7 repetitions × 20,000 iterations per case, single
  thread, strict (fully-enriched-metadata) match path.
- Both versions returned **identical match targets on every case**
  (semantic parity check built into the harness).

## Results

### Match latency

| Case | Metadata | 0.15 | 0.16 | Speedup |
|------|----------|------|------|---------|
| `cn_domain` | host `www.baidu.com` | 71.4 µs | 24.4 µs | **2.9×** |
| `foreign_domain` | host `www.google.com` | 15.0 µs | 5.7 µs | **2.6×** |
| `unruled_domain_fallthrough` | host `unmatched-domain.internal` | 18.3 µs | 9.1 µs | **2.0×** |
| `cn_ip` | dst `223.5.5.5` (GEOIP CN) | 96.5 µs | 52.6 µs | **1.8×** |
| `foreign_ip_fallthrough` | dst `142.250.72.14` → FINAL | 95.3 µs | 51.6 µs | **1.8×** |

### Rule-set minimization (compile-time passes, #296/#297)

| Metric | 0.15 | 0.16 | Delta |
|--------|------|------|-------|
| Source rules | 7,528 | 7,528 | — |
| Live slots after compilation | 7,528 | 6,662 | **−866 (−11.5%)** |

11.5% of the production subscription rule list is duplicate, shadowed, or
union-covered dead weight; the clean-up passes remove it at compile time
(duplicate canonical fingerprints, domain-family shadowing, covered-CIDR
elimination, logic-tree folding).

### IR build time (one-time, at startup / rule reload)

| Metric | 0.15 | 0.16 | Delta |
|--------|------|------|-------|
| `CompiledRuleSet::build` (best of 5) | 37.6 ms | 96.1 ms | +58.5 ms (2.6×) |

The added cost is the minimization oracles (suffix-set walks, canonical
fingerprints, per-CIDR `iprange::simplify()` union merging). It runs once
per config load, so ~96 ms is acceptable at this scale; if a much larger
CIDR-heavy config ever makes this hurt, the per-rule `simplify()` call
(effectively O(n²) over CIDR rules) is the first candidate to batch.

## Caveats

- The strict match path understates 0.16's production advantage: lazy
  metadata enrichment (#292) additionally skips DNS resolution / process
  lookup entirely when no reachable rule demands them, which this
  micro-benchmark does not exercise.
- The 0.15 reference is the nearest buildable commit, not the byte-exact
  deployed binary (its build commit was not recorded).
- Run on a live gateway with the ondemand governor; best-of-7 mitigates
  scheduling noise, and results were stable across repetitions.

## Appendix: harness source

Compiled as `crates/meow-tunnel/examples/rulebench.rs` at each commit
(not committed to the tree — reproduce by copy-paste):

```rust
use meow_common::Metadata;
use meow_config::load_config_from_str;
use meow_tunnel::rule_ir::CompiledRuleSet;
use std::net::IpAddr;
use std::time::Instant;

fn main() {
    let path = std::env::args()
        .nth(1)
        .expect("usage: rulebench <config.yaml>");
    let text = std::fs::read_to_string(&path).expect("config must be readable");
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let config = rt
        .block_on(load_config_from_str(&text))
        .expect("config must load");
    let rules = config.rules;
    println!("rules_loaded: {}", rules.len());

    let mut build_best_ms = f64::MAX;
    for _ in 0..5 {
        let t = Instant::now();
        let set = CompiledRuleSet::build(&rules);
        let ms = t.elapsed().as_secs_f64() * 1e3;
        std::hint::black_box(&set);
        if ms < build_best_ms {
            build_best_ms = ms;
        }
    }
    println!("ir_build_ms: {build_best_ms:.2}");

    let set = CompiledRuleSet::build(&rules);
    println!("live_slots: {}", set.len());

    let cases: Vec<(&str, Metadata)> = vec![
        (
            "cn_domain",
            Metadata {
                host: "www.baidu.com".into(),
                dst_port: 443,
                ..Default::default()
            },
        ),
        (
            "foreign_domain",
            Metadata {
                host: "www.google.com".into(),
                dst_port: 443,
                ..Default::default()
            },
        ),
        (
            "unruled_domain_fallthrough",
            Metadata {
                host: "unmatched-domain.internal".into(),
                dst_port: 443,
                ..Default::default()
            },
        ),
        (
            "cn_ip",
            Metadata {
                dst_ip: Some("223.5.5.5".parse::<IpAddr>().expect("ip")),
                dst_port: 443,
                ..Default::default()
            },
        ),
        (
            "foreign_ip_fallthrough",
            Metadata {
                dst_ip: Some("142.250.72.14".parse::<IpAddr>().expect("ip")),
                dst_port: 443,
                ..Default::default()
            },
        ),
    ];

    for (name, meta) in &cases {
        let target = set
            .match_rules(meta, &rules)
            .map(|r| r.adapter_name.to_string())
            .unwrap_or_else(|| "NO_MATCH".to_string());
        let mut best_ns = f64::MAX;
        for _rep in 0..7 {
            let n: u32 = 20_000;
            let t = Instant::now();
            for _ in 0..n {
                let r = set.match_rules(std::hint::black_box(meta), std::hint::black_box(&rules));
                std::hint::black_box(&r);
            }
            let ns = t.elapsed().as_secs_f64() * 1e9 / f64::from(n);
            if ns < best_ns {
                best_ns = ns;
            }
        }
        println!("{name}: {best_ns:.0} ns/op -> {target}");
    }
}
```
