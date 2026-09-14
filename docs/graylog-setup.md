# Graylog setup

Three pieces: a **data adapter** that calls this service, a **cache** in front
of it, and a **lookup table** binding them together for pipeline rules.

## 1. Data adapter

**System → Lookup Tables → Data Adapters → Create**, type **HTTP JSONPath**.

| Setting | Value |
|---|---|
| Title / Name | `opencti-lookup` |
| Lookup URL | `http://opencti-lookup:8000/lookup?value=${key}` |
| Single value JSONPath | `$.found` |
| Multi value JSONPath | `$` |
| HTTP User-Agent | `Graylog Lookup` |
| HTTP headers | `X-API-Key: <your API_KEY>` |

### Exactly one query parameter

Graylog URL-encodes the entire substituted key, so a second query parameter
arrives glued onto the value as `…%26customer_code%3DACME`. The service this
replaces unpicked that with ~20 lines of string surgery in the route handler.

Tenant tags travel as a header instead — add `X-Customer-Code: ACME` to the
HTTP headers box above and it comes back echoed in the response.

## 2. Cache — do not skip this

**Data Adapters → Caches → Create**, type **Guava Cache**.

| Setting | Value |
|---|---|
| Max size | `20000` |
| Expire after write | `60 seconds` |

This sits in front of the service and costs nothing. A large share of lookups
then never leave Graylog at all. The 60-second TTL keeps new OpenCTI intel
arriving promptly; the service's own membership set absorbs everything else.

## 3. Lookup table

**Lookup Tables → Create**, binding the adapter and cache above. Name it
`opencti_indicators` — that name is what the pipeline rules reference.

Set **Default single value** and **Default multi value** to empty.

## 4. Verify

```bash
curl -s 'http://opencti-lookup:8000/lookup?value=8.8.8.8' \
     -H "X-API-Key: $API_KEY"
# {"found":"false"}
```

In Graylog, use the lookup table's built-in **Test lookup** box. A miss returns
`found: false` at HTTP 200 — the adapter should never show errors for misses.
If you see adapter errors, something is returning non-2xx.

## Field reference

Every value is a string. Absent fields are omitted rather than null.

| Field | Example | Notes |
|---|---|---|
| `found` | `true` / `false` | Always present |
| `value` | `1.2.3.4` | Normalized form |
| `type` | `IPv4-Addr` | STIX observable type |
| `match_type` | `exact` / `hostname` | `hostname` means a URL matched on its host |
| `matched_value` | `bad.com` | Only on a hostname fallback match |
| `score` | `75` | Indicator score, not observable score |
| `confidence` | `90` | |
| `expired` | `true` / `false` | `valid_until` has passed |
| `revoked` | `true` / `false` | |
| `detection` | `true` / `false` | Often unset instance-wide; don't branch on it |
| `valid_from` / `valid_until` | ISO 8601 | |
| `labels` | `c2,apt29` | Comma-joined, deduped across all indicators, max 24 |
| `marking` | `TLP:AMBER` | |
| `created_by` | `AlienVault` | |
| `indicator_name` | `APT29 C2 node` | |
| `indicator_count` | `3` | Surviving indicators for this value |
| `kill_chain` | `command-and-control` | Comma-joined |
| `opencti_url` | `https://…/indicators/<id>` | Deep link for the analyst |
| `observable_score` | `60` | Differs from the indicator score |
| `degraded` | `true` | Only when OpenCTI was unreachable |
| `customer_code` | `ACME` | Only when the header was sent |
