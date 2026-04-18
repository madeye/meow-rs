# ADR 0005: Runtime event broadcaster for WebSocket streaming endpoints

- **Status:** Proposed (architect 2026-04-18, awaiting pm + engineer + qa review)
- **Date:** 2026-04-18
- **Author:** architect
- **Supersedes:** —
- **Related:** roadmap M1.G-3 (`GET /logs` websocket), M1.G-4
  (`GET /memory` websocket), M1.G-7 (`DELETE /connections` bulk),
  [`docs/specs/api-logs-websocket.md`](../specs/api-logs-websocket.md)
  (approved), `docs/specs/api-delay-endpoints.md`,
  [ADR-0002](0002-upstream-divergence-policy.md),
  memory `feedback_api_no_catch_panic.md` (QA panic-abort invariant)

## Context

`docs/specs/api-logs-websocket.md` is approved and covers the approach for
the log stream in detail: a `tokio::sync::broadcast` channel in `AppState`, a
custom `tracing::Layer` that publishes each event, per-subscriber
`?level=` filtering, a `{"type":"lagged","missed":N}` frame on
`RecvError::Lagged`, and a 128-message capacity knob. That spec settled the
single most important question — use `broadcast`, not `watch`, for logs —
and engineer already has enough detail to build `/logs` from it alone.

This ADR does **not** re-litigate the logs channel. Its job is the
cross-cutting story across the three endpoints the spec actually bundles:

1. **`/logs`** (fan-out: one publisher, N subscribers, every event to every
   live subscriber).
2. **`/memory`** (periodic poll: one subscriber's task samples RSS on a
   1 Hz timer — no publisher, no channel).
3. **`DELETE /connections`** (one-shot: the handler drains the
   connection table directly; no streaming, no channel at all).

Treating all three under one "runtime event bus" is a trap that would push
us toward either (a) a single `broadcast::Sender<RuntimeEvent>` enum that
fans out every kind of runtime notification — adding coupling and vtable-ish
matching on the hot path — or (b) a subscriber trait that memory and
DELETE /connections have to awkwardly fit. Neither earns the complexity.

What the three endpoints genuinely share is a **subscriber lifecycle and
panic-abort contract** for any `tokio::spawn` running inside the API
server: whether the spawned task is a WS push loop, a periodic sampler, or
a future drain operation, it must abort the process on panic (QA invariant
from memory `feedback_api_no_catch_panic.md`) and terminate cleanly on
client disconnect. That contract is what this ADR codifies.

## Decision

### 1. One channel type for fan-out: `tokio::sync::broadcast`

The approved logs spec already picks `broadcast`. This ADR ratifies that
for **all current and future fan-out streams** and documents the
reasoning so the next engineer adding a streaming endpoint does not
re-derive:

| Candidate | Why rejected for fan-out |
|---|---|
| `tokio::sync::watch` | Subscribers see "latest value" — events arriving between polls are lost. Dashboard log stream requires every event, not the latest. Memory stream *would* fit watch semantics, but see §2 — memory is not a broadcast use-case at all. |
| `tokio::sync::mpsc` per subscriber, publisher loops over a `Vec<Sender>` | Equivalent to hand-rolling `broadcast`. The publisher side needs locking around the vector, dead-subscriber cleanup, and per-slot lag handling — all of which `broadcast` already implements correctly. |
| `async-broadcast` (crate) | Same shape as `tokio::sync::broadcast`, adds a dependency with no material difference. Stay in-tree. |
| `tokio::sync::Notify` + shared state | Works only for "wake me up" semantics. Event *payload* has to live somewhere — shared `Mutex<VecDeque>` with slow-drainer handling — and that is what `broadcast` is. |

**Ratified:** `tokio::sync::broadcast::Sender<T>` is the fan-out primitive
for this repository. `T` is a per-endpoint message type (today `LogMessage`;
future: a `TrafficSnapshot` if the `GET /traffic` endpoint ever moves from
poll to stream, etc.). **No `RuntimeEvent` union enum.** One sender per
stream; each stream's `T` stays bounded and serializable.

### 2. `/memory` is not on the bus — it is a per-connection sampler

The readiness brief implied all three endpoints share a "broadcaster". The
approved spec already disagrees by shape:

```rust
// From docs/specs/api-logs-websocket.md §get_memory:
async fn get_memory(State(_state): State<Arc<AppState>>, ws: WebSocketUpgrade) -> Response {
    ws.on_upgrade(|mut socket| async move {
        let mut interval = tokio::time::interval(Duration::from_secs(1));
        loop {
            interval.tick().await;
            let frame = build_memory_frame();
            if socket.send(Message::Text(frame)).await.is_err() { break; }
        }
    })
}
```

No channel. No subscription. The per-connection task wakes on a 1 Hz timer,
samples `sysinfo`, sends, repeats. That is correct because:

- Memory frames are point-in-time samples, not events. There is no
  "missed a frame" concept — the next tick has fresh data.
- One subscriber vs N subscribers does not change the work. Each
  subscriber runs its own sampler (`sysinfo` refresh is per-process and
  cheap). There is nothing to fan out.
- A global 1 Hz sampler pushing into `broadcast` would wake up even when
  no client is connected, and subscribers with slow drain would see stale
  data that the sampler already moved past.

**Ratified:** periodic polling endpoints own their timer and their sample
call. No broadcast channel. Subscribers added later (e.g. traffic stream)
follow the same shape unless the sample is expensive enough to warrant
centralising — at which point that endpoint revisits this ADR.

### 3. `DELETE /connections` is not on the bus — it is a direct call

Upstream Go mihomo handles bulk-close by walking the connection table in
the handler and closing each entry. Same shape here:

```rust
pub async fn close_all_connections(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    state.tunnel.statistics().close_all_connections();
    StatusCode::NO_CONTENT
}
```

`close_all_connections()` on `ConnectionStats` acquires the map lock,
signals each connection's close handle, and clears the map. No event bus,
no notification, no subscriber. The only "broadcast" in the room is the
set of close signals fired into each active connection's close handle —
and those already exist for the per-id `DELETE /connections/{id}` route.

**Ratified:** one-shot mutating endpoints do their work synchronously (or
via a direct `tokio::spawn` if the work is long). Broadcaster is not the
idiom here.

Why spell this out in an ADR? Because a future engineer will read "runtime
event broadcaster" and reasonably ask whether the bulk-close should
publish a `ConnectionsCleared` event for other subscribers. It should not;
there are none, and speculative plumbing is the wrong investment.

### 4. Subscriber lifecycle contract

A WebSocket push loop (the `/logs` handler, and any future streaming
endpoint that uses `broadcast`) lives inside `ws.on_upgrade(|socket| …)`.
The contract:

1. **Per-client state lives in the async closure.** The `broadcast::
   Receiver`, any per-client filter config, and the `WebSocket` handle
   are all local to the closure. Dropping the `Receiver` on closure exit
   automatically unsubscribes — no explicit cleanup needed.
2. **Three terminal conditions, handled explicitly:**
   - `socket.send` error → break the loop (client disconnected, network
     error, or upgrade failure). No log emission for normal disconnect.
   - `Receiver::recv` returns `Err(Closed)` → break (publisher dropped,
     should not happen while server runs; if it does, the WS closes and
     the client reconnects).
   - `Receiver::recv` returns `Err(Lagged(n))` → emit a lag-notification
     frame, continue. **Do not close.** (This is the approved logs-spec
     behaviour.)
3. **No `.await` in a tracing `Layer::on_event`.** The publisher side
   runs inside a sync tracing hook; `broadcast::Sender::send` is
   non-blocking and always safe to call from sync context. Any future
   publisher MUST preserve this property.

### 5. Backpressure policy: drop-oldest per subscriber

`tokio::sync::broadcast` implements drop-oldest-per-subscriber natively:
when a subscriber is behind the sender by more than the channel capacity,
`recv()` returns `Lagged(n)` where `n` is the count of missed messages,
then resumes from the current tail. The approved logs spec picks capacity
128 and surfaces lag as a `{"type":"lagged","missed":n}` frame.

This ADR ratifies that policy for all broadcaster subscribers:

- **Drop-oldest-per-subscriber, not slow-client-disconnect.** Disconnect
  on lag would make one misbehaving client (or dev tools paused in a
  debugger) close the WebSocket and force a reconnect, losing the
  dashboard's scroll position. Drop-oldest gives a visible signal (the
  lag frame) without collateral damage to the session.
- **Do not back-pressure the publisher.** A full channel does not block
  `send()`; it evicts the oldest message. The publisher is a sync tracing
  hook on the critical path of every log statement — it must never block.
- **Do not globally drop events when any subscriber is slow.** Each
  subscriber's lag is independent; other subscribers see every event.

**Capacity revisit rule:** the logs spec's 128 is a starting point to be
revisited after soak-test subscriber measurements. New broadcaster
channels default to 128 unless the spec has a measured reason to deviate.
Document the choice in the feature spec, not here.

### 6. Panic-abort for spawned tasks

This is the part that most needs explicit capture. From memory
`feedback_api_no_catch_panic.md`: QA has established that the API router
must never wrap routes in `tower::catch_panic::CatchPanicLayer` or any
equivalent. A panic in an API handler must reach the tokio runtime's
default panic hook, which on our configuration aborts the process.

That invariant is about handler routes. This ADR extends it to the three
kinds of background / spawned task the streaming endpoints introduce:

| Task kind | Owner | Panic behaviour | Why |
|---|---|---|---|
| WS push loop inside `ws.on_upgrade` | Per-connection future driven by the axum handler | Panic propagates to tokio; process aborts | Panics here indicate logic bugs (e.g. serialisation invariant broken). Silently closing the WS would hide the bug from operator and CI. |
| Periodic sampler (`/memory`) inside `ws.on_upgrade` | Same | Same | Same reason — a panic sampling `sysinfo` is a real bug. |
| `LogBroadcastLayer::on_event` (sync tracing hook) | Tracing subscriber | Panic aborts *via the tracing layer's own hook* — tokio does not see it directly, but the default `std::panic::set_hook` we install in `main.rs` aborts | A panic in a tracing layer from a sync call path (anywhere in the binary) must not be swallowed. |
| Future global background tasks (health-check, provider refresh — ADR-0003) | `tokio::spawn` in `main.rs` | Panic aborts | ADR-0003 §5 already commits to this; repeated here for completeness. |

**Concretely in code:**

```rust
// In main.rs, exactly once, before the runtime starts spawning:
std::panic::set_hook(Box::new(|info| {
    tracing::error!(panic = %info, "fatal panic; aborting");
    std::process::abort();
}));
```

This hook runs for panics from **any** source (async task, sync tracing
layer, blocking helper). We do NOT depend on tokio's `unhandled_panic =
Shutdown` runtime builder knob as the sole mechanism, because:

- Tokio's builder knob only fires when a *task* panics. A panic inside a
  tracing `Layer::on_event` runs on the thread that emitted the log
  statement — which might be a blocking helper thread (see the startup-
  runtime-in-runtime dance in `rule_provider.rs`) that tokio does not
  own.
- `panic::set_hook` wins over the tokio knob and covers every thread.

**Forbidden patterns:** `CatchPanicLayer`, `panic::catch_unwind` anywhere
in the API server, `tokio::spawn(…).catch_unwind()`, any broadcast handler
that wraps `on_event` in `catch_unwind` to "protect" the publisher. A
panicking publisher is a bug — let it abort.

### 7. What lives in `AppState` vs per-endpoint module

| Item | Location | Why |
|---|---|---|
| `log_tx: broadcast::Sender<LogMessage>` | `AppState` | Shared by publisher (installed in `main.rs` before API server starts) and all WS subscribers (each handler calls `.subscribe()`). |
| `LogMessage`, `LogLevel`, `MessageVisitor` | `mihomo-api/src/log_stream.rs` | Per-feature. |
| `LogBroadcastLayer` | `mihomo-api/src/log_stream.rs` | Same. |
| Panic hook install | `mihomo-app/src/main.rs`, above `run()` | Process-wide. |
| Future `traffic_tx` (if `/traffic` moves to stream) | `AppState` | Same pattern. |
| `sysinfo::System` / memory sampler state | **Not** in `AppState` — per-connection local variable | Avoids shared-state locking; approved spec shape. |

This keeps `AppState` small (two channels max, today one) and avoids
turning it into a junk drawer.

### 8. Divergence classification (per ADR-0002)

Two dispositions in this ADR are divergences from upstream shape, cited
against ADR-0002 Class A/B:

| # | Case | Class | Rationale |
|---|------|:-----:|-----------|
| 1 | Lag → `{"type":"lagged","missed":N}` frame, not connection close | B | Upstream Go mihomo disconnects slow clients on overflow. We keep the session alive and surface a visible frame. User sees the dashboard stay connected; lag is observable. No routing change, no crypto change — Class B. |
| 2 | `std::panic::set_hook` → `std::process::abort()` on any panic | A | Upstream Go mihomo recovers panics in API handlers via `recover()` middleware. We refuse: a panicking handler or sampler is a silent correctness bug. Aborting is loud-failure, matching our operating principle. Class A (silent bug > loud crash). |

## Consequences

### Positive

- **One recipe for streaming endpoints.** Future endpoints that want to
  stream (traffic, health-check notifications, etc.) drop in a new
  `broadcast::Sender<YourT>` and follow the logs-spec shape — no new
  architectural decision needed.
- **No speculative event bus.** Memory and DELETE /connections stay as
  they are; no premature generalisation.
- **QA's panic-abort invariant gets code-level enforcement.** The
  `panic::set_hook` install is a one-line addition to `main.rs` and
  future reviewers have an ADR to point at when someone tries to add
  `CatchPanicLayer`.
- **Subscriber cleanup is free.** `Drop` on `Receiver` unsubscribes;
  there is no lifetime bookkeeping to get wrong.

### Negative / risks

- **Publisher-side panic aborts the process even if it came from a
  tracing layer.** This is a feature (loud failure) but means a bad
  third-party tracing integration could crash the server. Mitigated by
  the rule that we own all layers in the subscriber stack — no
  third-party layers installed by default.
- **128-message capacity is a guess.** The logs spec owns the actual
  knob; this ADR only ratifies the choice. Soak-test measurement may
  raise it. Engineer needs to make the capacity a named constant, not a
  magic number, so tuning is one line of change.
- **No history buffer.** A client connecting after a panic-free restart
  sees only events from that point forward. The logs spec explicitly
  defers historical buffering to M2.

### Neutral

- **`panic::set_hook` is process-global.** Any other code that wants to
  observe panics must chain through. For our binary this is fine; future
  multi-subscriber panic observers would need a small dispatcher, deferred
  to when someone asks.

## Alternatives considered

### A.1 — Single `broadcast::Sender<RuntimeEvent>` enum bus

```rust
enum RuntimeEvent {
    Log(LogMessage),
    Memory(MemorySnapshot),
    Connections(ConnectionsEvent),
    // ...
}
```

**Rejected.** Every subscriber pattern-matches on every event, or every
stream gets its own filtered view that discards 90% of messages. The
`broadcast` capacity is shared — a log-spam burst can lag the memory
stream. Enum growth touches every subscriber file. No shared consumer
needs this shape today.

### A.2 — `watch` for memory, `broadcast` for logs

**Rejected (for memory).** The approved spec is per-connection sampler,
which is simpler than `watch` (no shared sampler task, no publisher
lifetime question) and scales linearly with client count. `watch` would
reintroduce a central sampler task that wakes the publisher with no
subscribers attached. Revisit only if `sysinfo` sampling becomes
measurably expensive.

### A.3 — `CatchPanicLayer` to keep the API up if a handler panics

**Rejected.** Explicit QA invariant (memory `feedback_api_no_catch_panic.md`).
A swallowed panic leaves corrupted state visible to future requests and
defeats the panic-abort soak-test. Class A per ADR-0002 — silent failure
mode beats loud crash only in operating contexts that do not value
correctness, which is not ours.

### A.4 — Global sampler task for `/memory` shared across subscribers

**Rejected for M1.** The approved spec is per-connection sampler; a
shared sampler is a real future option (it buys deduplication of
`sysinfo` calls when many dashboards are connected) but needs a `watch`
channel, a cold-path shutdown when no subscribers remain, and a
publisher lifetime owned by `AppState`. All of that is work to avoid a
non-measured cost. M2 footprint audit can revisit.

### A.5 — Hand-rolled fan-out with `Vec<mpsc::Sender>` + publisher loop

**Rejected.** That is what `tokio::sync::broadcast` is. Reinventing it
means re-implementing the `Lagged` story, dead-subscriber GC, and
capacity handling. Plus losing tokio's tested concurrency around
subscriber registration vs send.

## Migration

None. No existing broadcaster code to migrate. The approved logs spec
(`docs/specs/api-logs-websocket.md`) is the first consumer; this ADR
cross-references it rather than rewriting it.

Engineer picking up task #17 (M1.G-3 et al.) should:

1. Follow `docs/specs/api-logs-websocket.md` as the implementation spec.
2. Install `panic::set_hook` in `main.rs` per §6 of this ADR (one-line
   change + helper).
3. Not add `CatchPanicLayer` anywhere.
4. Use `broadcast`'s native lag handling, not a custom drain/slow-client
   scheme.

Future streaming endpoints (task #18 `/metrics`, hypothetical streaming
`/traffic`) follow the same shape.

## References

- `docs/specs/api-logs-websocket.md` — approved feature spec; this ADR
  is the cross-cutting architectural sibling.
- `docs/adr/0002-upstream-divergence-policy.md` — divergence class cites
  in §8.
- `docs/adr/0003-provider-refresh-substrate.md` — §5 already codifies
  panic-abort for provider refresh tasks; §6 of this ADR extends the
  same rule to streaming endpoints.
- Memory `feedback_api_no_catch_panic.md` — the QA invariant this ADR
  encodes at the code level.
- Tokio docs: `tokio::sync::broadcast`, `tokio::sync::watch`,
  `tokio::runtime::Builder::unhandled_panic`.
