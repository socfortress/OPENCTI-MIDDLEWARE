# OpenCTI Lookup

A Graylog lookup-table backend that answers one question, fast:

> Does this IP, domain, URL, or file hash have a live Indicator in OpenCTI?

Built for the volume a Graylog pipeline generates. Misses — the overwhelming
majority of a log stream — are answered from process memory in about a
microsecond and never touch the network.

```bash
git clone https://github.com/socfortress/OPENCTI-MIDDLEWARE
cd OPENCTI-MIDDLEWARE
cp .env.example .env
python scripts/gen_token.py     # paste into API_KEY
$EDITOR .env                    # set OPENCTI_URL and OPENCTI_TOKEN
docker compose up -d            # pulls a prebuilt image, no build step
```

The image is published to GitHub Container Registry for `linux/amd64` and
`linux/arm64`, so there is nothing to compile locally:

```
ghcr.io/socfortress/opencti-middleware:latest   # tracks main
ghcr.io/socfortress/opencti-middleware:1.2.3    # release tags
ghcr.io/socfortress/opencti-middleware:sha-<commit>
```

Pin a version or a digest in production — `:latest` moves. To build from
source instead, comment out `image:` in `compose.yaml` and uncomment `build: .`.

```console
$ curl -s 'localhost:8000/lookup?value=212.193.31.122' -H "X-API-Key: $API_KEY"
{"found":"true","value":"212.193.31.122","type":"IPv4-Addr","match_type":"exact",
 "score":"20","confidence":"100","expired":"true","labels":"aisuru,iot botnet,ddos attacks",
 "marking":"TLP:CLEAR","created_by":"AlienVault","opencti_url":"https://…/indicators/da45…"}
```

---

## Why it's built this way

A lookup asks two questions with wildly different costs:

| Question | Cost per indicator |
|---|---|
| Is this value in OpenCTI at all? | **8 bytes** |
| What are its score, labels, marking, validity? | ~250 bytes |

Around **99% of a log stream is misses**, and a miss is answered entirely by
the first question. So only the cheap structure has to cover the whole corpus.
The expensive one is an ordinary bounded cache, filled on demand — you never
need payloads for 50M indicators, only for the few thousand your logs touch.

**Membership set** — one 64-bit hash per indicator in a sorted array backed by
shared memory. Eight bytes each, and genuinely *one copy regardless of worker
count* (see [Cross-worker sharing](#cross-worker-sharing)):

| Corpus | Membership set | Full payload mirror |
|---|---|---|
| 17,767 | 140 KB | 4 MB |
| 1,000,000 | 8 MB | 250 MB |
| 10,000,000 | **80 MB** | 2.5 GB |
| 50,000,000 | **400 MB** | 12.5 GB |

There is no corpus size at which misses stop being fast.

### What that buys

| | Miss (~99%) | Hit, warm | Hit, cold | OpenCTI down |
|---|---|---|---|---|
| Naive proxy | 330 ms | 50 µs | 361 ms | everything reads as a miss |
| Full mirror | 10 µs | 10 µs | 10 µs | fine until the corpus outgrows RAM |
| **This** | **~1 µs** | 50 µs | 361 ms once | **misses perfect, hits report `found` without enrichment** |

That last column is the one the other two can't reach: with OpenCTI
unreachable this still alerts correctly, it just can't enrich.

### Memory safety

**A miss allocates nothing.** It's answered from a fixed-size array and never
reaches a cache. A proxy design has to cache misses, and the miss keyspace is
unbounded — a scanner throwing random domains at you grows that cache without
limit. Here, unbounded miss traffic costs zero memory, permanently.

The payload cache is bounded three ways at once:

- **TTL** (24 h) — only a backstop; the live stream invalidates changed
  indicators precisely. If the stream goes unhealthy the TTL drops to a floor.
- **LRU maxsize** — derived from a byte budget, not set independently.
- **Max entry size** (1 KB, enforced by truncation) — this is what makes the
  ceiling real. `TTLCache(maxsize=N)` counts *entries, not bytes*; one
  indicator carrying 400 labels would otherwise blow the budget.

Redis gets `maxmemory` + `allkeys-lru` in `compose.yaml`. Default Redis has no
limit and will consume the box.

---

## Cross-worker sharing

`uvicorn --workers N` runs the lifespan in each worker independently. Left
alone that means N bootstraps against OpenCTI at startup and N copies of the
segment — at 50M indicators, 400 MB *per worker* instead of 400 MB total,
which defeats the point of using shared memory.

Workers elect a builder with a file lock:

1. Each worker tries `flock(LOCK_EX | LOCK_NB)` on `<state_dir>/membership.lock`.
2. The winner bootstraps, then atomically publishes `{shm_name, count,
   generation}` to `membership.json`.
3. The losers poll for that file and attach to the named segment.
4. A loser that times out serves via the live backend and keeps retrying,
   rather than building its own and reintroducing the N-copies problem.

Verified with four workers against a live instance: **1 bootstrap, 3 attaches,
one 142 KB segment.**

### Three things this has to get right

**A reader exiting must not destroy the segment.** CPython registers every
`SharedMemory` a process touches — including ones it only *attached* to — and
unlinks them when that process exits ([bpo-38119][]). Confirmed on 3.14: one
reader exiting destroyed the builder's segment. `attach()` unregisters from
the `resource_tracker`, so the builder alone owns the lifecycle.

**A rebuild must land in a new segment.** If the builder dies, its lock
releases and the respawned worker becomes the new builder. It publishes
`generation + 1` under a new name, because readers may still be mapping the
old one.

**The sweep must not unlink a live segment.** Stale-segment cleanup keeps both
the currently-published generation and the one being built. Unlinking a mapped
segment does not break existing readers — POSIX keeps the mapping alive — but
it does mean the next worker to start cannot attach and silently rebuilds.

Readers watch the state file and adopt a higher generation when one appears,
so a builder failover propagates without a restart:

```
membership.published        gen=2 shm=octi_membership_2 superseded=octi_membership_1
membership.generation_adopted  previous=1 adopted=2
membership.generation_adopted  previous=1 adopted=2
membership.generation_adopted  previous=1 adopted=2
```

Set `MEMBERSHIP_SHARED=false` to opt out and give every worker its own copy.

[bpo-38119]: https://github.com/python/cpython/issues/82300

## Live stream

Without it the membership set is a boot-time snapshot: correct at startup and
drifting afterwards, with new intel invisible until the next rebuild. The
consumer subscribes to OpenCTI's SSE stream and applies changes as they land.

An **indicator** event carries its observable values inline, under
`extensions[].observable_values`, so keeping the set current costs **no extra
GraphQL calls**:

```
event: update
id: 1789313330953-0
data: {"data": {"type": "indicator",
                "extensions": {"extension-definition--ea279b3e": {
                    "observable_values": [{"type": "Url", "value": "http://…/deploy_silent1.Ps1"}]}}}}
```

Observable events (`ipv4-addr`, `ipv6-addr`, `domain-name`, `url`, `hostname`)
carry a plain `value`. Everything else — vocabularies, relationships,
external references — is skipped; measured against a live replay, **143 of
1,137 events** were relevant.

The `id` is a Redis stream id and doubles as the resume cursor: reconnecting
with `?from=<id>` replays everything after it, so a dropped connection loses
no events within the stream's retention. Reconnects back off with jitter so N
workers don't thunder against OpenCTI in lockstep.

Every worker runs its own consumer. One shared consumer would not work: the
overlay it writes into is per-process Python state, not part of the shared
mapping. SSE connections are cheap and all workers converge.

### Quiet is not the same as dead

OpenCTI emits `heartbeat` events roughly every 6 seconds, plus
`consumer_metrics` carrying its own `timeLag`. That distinction matters more
than it looks: staleness is keyed on **activity** — heartbeats included —
never on when an indicator last changed.

Keying it on event recency would mark a perfectly healthy service stale on any
quiet night and drop it to slow live queries for no reason. Observed on the
idle test instance:

| | Value | Meaning |
|---|---|---|
| `stream_activity_lag_s` | 3.6 | heartbeats arriving — connection alive |
| `stream_event_lag_s` | 94.0 | nothing changed in OpenCTI for 94s |
| `stale` | `false` | correct |

Heartbeats also advance the resume cursor, so an idle connection doesn't
replay history when it reconnects.

When the stream *does* stall (`STREAM_STALE_AFTER_S`, default 120s — twenty
missed heartbeats), the backend marks itself stale and defers to live queries
until it recovers, because a stale set produces false negatives and those are
worse than a slow answer.

## Reconcile

The live stream keeps the set current, but two things still drift it:

- **Overlay growth.** Stream updates land in a per-process overlay of Python
  sets, not in the shared segment. Left alone it grows without bound, and the
  other workers never see it.
- **Silent divergence.** A missed event, a stream gap longer than retention,
  or a bulk change made directly in OpenCTI leaves the set subtly wrong with
  nothing to signal it. Only a full reload catches that.

So the builder rebuilds on whichever comes first: `MEMBERSHIP_RECONCILE_INTERVAL_S`
(default 24h), or the overlay crossing `MEMBERSHIP_OVERLAY_MAX`. Only the
builder reconciles — readers rebuilding independently would defeat sharing one
segment; a reader that hits its own cap waits for the next generation.

The old segment serves for the entire rebuild. Nothing swaps until the new one
is complete, and the swap carries the overlay forward, because events that
arrived mid-rebuild are not in the new snapshot.

Observed with a 45-second interval and three workers:

```
reconcile.completed  gen=2  4.35s  swept=[]
membership.generation_adopted  previous=1 adopted=2     (x2 readers)
reconcile.completed  gen=3  4.46s  swept=['octi_membership_1']
membership.generation_adopted  previous=2 adopted=3     (x2 readers)
```

Cleanup lags one generation on purpose: generation 1 is only unlinked once
everyone has moved to 2 or later, so a reader mid-swap never loses its
mapping. Requests were served continuously across both cycles.

A failed rebuild increments `reconcile_failures` and leaves the old segment
serving; the next interval retries.

### Transient memory during a rebuild

Fingerprints accumulate into fixed `numpy` blocks rather than a Python list. A
list of 50M Python ints is ~1.8 GB against a 400 MB result, and a reconcile
holds that peak *alongside* both the old and new segments. Chunked, the peak
is a small multiple of the result instead.

## Request path

```
  GET /lookup?value=…
       │
  0 ── normalize + reject     ~5 µs   RFC1918, .local, .internal — never cached, never queried
  1 ── membership set         ~1 µs   sorted uint64 in shared memory  ◄── ~99% exit here
  2 ── payload cache         ~50 µs   byte-bounded TTL + LRU
  3 ── single-flight                  N concurrent lookups of one value → 1 upstream call
  4 ── OpenCTI GraphQL     ~361 ms    pooled keep-alive, bounded concurrency, circuit breaker
```

Tier 4 is measured against a live OpenCTI 7.26 instance (median of six cold
queries, 326–394 ms). A *miss* upstream costs about the same as a hit, which
is why tiers 0 and 1 matter so much.

---

## Hit semantics

A hit requires a **curated Indicator**, not merely an observable — observables
get created as side effects of report ingest and aren't a verdict. The service
matches the observable on its exact indexed `value`, then traverses to the
Indicators linked to it, in one GraphQL round trip.

### `HIT_POLICY`

Measured on OpenCTI 7.26: **`revoked` is set automatically when `valid_until`
passes.** Cross-tabulating a real 17,767-indicator corpus gives zeros on both
off-diagonals — the revoked and expired sets are *identical*:

| | `valid_until` future | `valid_until` past |
|---|---|---|
| `revoked = false` | 16,212 | **0** |
| `revoked = true` | **0** | 1,555 |

So "exclude revoked" and "keep expired" cancel out unless you discriminate on
*why* something was revoked:

| Policy | Counts as a hit |
|---|---|
| `live_only` | Only `revoked = false`. Strictest. |
| `expiry_aware` *(default)* | Everything except human retractions — `revoked` while still inside the validity window. Expired still hits, flagged `expired: "true"`. |
| `all` | Every indicator; the pipeline rule filters. |

On a corpus with no manual revocations, `expiry_aware` and `all` behave
identically, and the real choice is `live_only` (drop the expired) versus
everything else (drop nothing).

### File hashes take a different filter key

MD5, SHA-1 and SHA-256 are detected by length and resolve against `StixFile`
observables. These are **not** reachable through the `value` filter that every
other indicator uses — filtering a StixFile by `value` returns nothing even
though `observable_value` displays the digest. They need `hashes.MD5`,
`hashes.SHA-1` or `hashes.SHA-256`. Digests are case-folded, since Sysmon
emits uppercase and OpenCTI stores lowercase.

### Domains are stored under two types

Measured: `Domain-Name` 8,124 and `Hostname` 2,867. A lookup filtering only on
`Domain-Name` silently misses ~26% of the domain corpus, so both are queried.
Controlled by `DOMAIN_MATCH_TYPES`.

### URLs

OpenCTI stores `Url` observables as exact strings, so a logged URL with a query
string rarely matches. The service tries the normalized URL, then falls back to
its hostname, and reports which fired via `match_type` (`exact` / `hostname`).

### Normalization

Runs ahead of every cache so `HXXP://Evil.COM/a/` and `http://evil.com/a` are
one cache key and one query, not two of each.

- Defang `hxxp→http`, `[.]→.`, `[:]→:`; strip wrapping brackets and quotes
- IPs reduced via `ipaddress` — `010.1.1.1`, `::1` and `0:0:…:1` collapse to
  one key. Zero-padded octets are canonicalized first, since `ipaddress`
  rejects them as ambiguously octal and they're a real evasion form
- Domains lowercased, trailing dot stripped, IDNA-encoded to punycode
- URLs: scheme and host lowercased, fragment dropped, default ports dropped,
  path and query left byte-exact
- File hashes are folded to lowercase and matched by length (32/40/64 hex)
- Private/loopback/link-local/reserved IPs and non-public TLDs return
  `found: "false"` in microseconds without touching a cache or the network

---

## API

| Endpoint | Method | Purpose | Auth |
|---|---|---|---|
| `/lookup?value=` | GET | The one Graylog calls | API key |
| `/lookup/bulk` | POST | Batch; for backfills and testing | API key |
| `/healthz` | GET | Liveness; never touches OpenCTI | none |
| `/readyz` | GET | Config valid, backend loaded, breaker closed | none |
| `/metrics` | GET | Prometheus | none |
| `/config/validate` | GET | Deployment aid; live-tests OpenCTI | API key |

Responses are **flat, all strings, no nulls, no arrays, no nesting** — Graylog
pipeline rules mishandle all four. Enforced by the serializer, not convention.

- Hit → `{"found": "true", …}`
- Miss → `{"found": "false"}` at **HTTP 200**, never 404. Graylog's
  HTTPJSONPath adapter treats non-2xx as an adapter error, and misses are the
  common case
- Upstream down → `{"found": "false", "degraded": "true"}`, still 200

---

## Two ways in

| Path | Use it for |
|---|---|
| **[Graylog lookup tables](docs/graylog-setup.md)** | High-volume streams. No process spawn; Graylog's own cache absorbs repeats. |
| **[Wazuh integration](docs/wazuh.md)** | Targeted enrichment inside Wazuh's correlation — FIM hashes, specific rule groups. |

Both can run at once. Note the Wazuh manager spawns a **process per matching
alert** — measured at ~73 ms each, ~44 ms of which is interpreter startup, so
roughly 14 alerts/sec per analysisd thread. That ceiling is the spawn, not the
lookup, so scope the `<integration>` filter tightly and send bulk traffic
through Graylog.

## Graylog setup

### Data adapter (HTTP JSONPath)

| Setting | Value |
|---|---|
| Lookup URL | `http://opencti-lookup:8000/lookup?value=${key}` |
| Single value JSONPath | `$.found` |
| Multi value JSONPath | `$` |
| HTTP headers | `X-API-Key: <token>` |

**Exactly one query parameter.** Graylog URL-encodes the whole substituted key,
so a second parameter arrives glued onto the value as `%26customer_code%3D…`.
Tenant tags travel as the `X-Customer-Code` header instead.

### Cache — configure this

Set the lookup table's cache to **Guava Cache**, ~20,000 entries, 60 s TTL.
It sits in front of this service and is free; a large share of lookups then
never leave Graylog at all.

### Pipeline rules

```java
// Stage 1 — enrich. set_fields() takes the whole map, so adding a response
// field never means editing this rule.
rule "OpenCTI :: enrich destination_ip"
when
    has_field("destination_ip")
then
    let ioc = lookup("opencti_indicators", to_string($message.destination_ip));
    set_fields(fields: ioc, prefix: "threat_intel_");
end
```

```java
// Stage 2 — decide. Non-expired hits alert; expired hits stay as context.
rule "OpenCTI :: flag live indicator"
when
    to_string($message.threat_intel_found)   == "true" &&
    to_string($message.threat_intel_expired) == "false"
then
    set_field("alert", true);
    set_field("alert_source", "OpenCTI");
    set_field("alert_severity", to_string($message.threat_intel_score));
end
```

---

## Configuration

Everything via `.env` — see [`.env.example`](.env.example) for the annotated
list. Required: `API_KEY`, `OPENCTI_URL`, `OPENCTI_TOKEN`. The service refuses
to boot on a bad config with one message naming every problem.

A few worth knowing about:

- **`WORKERS`** — start at `min(cpu_count, 4)`. The familiar `cpu*2+1` is the
  formula for *synchronous* workers and is wrong here; more workers means more
  fragmented payload caches and a lower hit rate.
- **`MEMBERSHIP_SOURCE`** — `observables` (default) reads values directly at
  ~4,500/sec; `indicators` walks the indicator→observable relationship at
  ~210/sec for exactness. The fast path's false positives self-correct (an
  observable with no indicator triggers a payload query that returns a miss),
  so switch only if observables greatly outnumber indicators. The ratio is
  logged at startup and warned on above 3:1.
- **Memory autodetection** reads the **cgroup** limit before host RAM. Under
  Docker those differ, and only the cgroup number avoids the OOM killer.
  It sets a *default*, logged loudly at startup; `MIRROR_MAX_MEMORY_MB` and
  `PAYLOAD_CACHE_MAX_MB` override it.

Bootstrap takes a few seconds on a small corpus and minutes on a large one.
`/readyz` stays false until it completes, so orchestration won't route early.

---

## Development

```bash
python -m venv .venv && .venv/bin/pip install -e '.[dev]'
.venv/bin/pytest                    # unit + respx-mocked integration
.venv/bin/ruff check . && .venv/bin/mypy src
```

Some tests spawn real subprocesses to exercise the cross-worker lock election
and shared-segment lifetime; those cannot be faked in-process. One test is
skipped on macOS, where POSIX shared memory is not visible as files under
`/dev/shm` — CI runs on Linux and covers it.

### Building the image yourself

```bash
docker build -t opencti-middleware .
# or multi-arch, as CI does:
docker buildx build --platform linux/amd64,linux/arm64 -t opencti-middleware .
```

CI lints, tests, builds both architectures, pushes to GHCR with build
provenance and an SBOM, then smoke-tests the published image — booting it
without a reachable OpenCTI and asserting it enforces auth and fails open
rather than returning 5xx.

## License

MIT
