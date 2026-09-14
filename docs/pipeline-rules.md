# Pipeline rules

Two stages: enrich, then decide. Keeping them separate means adding a response
field never requires editing the alerting logic.

## Stage 1 — enrich

`set_fields()` takes the whole map in one call, so new response fields appear
automatically with the `threat_intel_` prefix.

```java
rule "OpenCTI :: enrich destination_ip"
when
    has_field("destination_ip")
then
    let ioc = lookup("opencti_indicators", to_string($message.destination_ip));
    set_fields(fields: ioc, prefix: "threat_intel_");
end
```

The service already skips RFC1918, loopback, link-local and non-public TLDs
internally, so there is no need to pre-filter in the rule — but doing so saves
a lookup-table call if you want to:

```java
rule "OpenCTI :: enrich external destination_ip only"
when
    has_field("destination_ip") &&
    ! in_private_net(to_string($message.destination_ip))
then
    let ioc = lookup("opencti_indicators", to_string($message.destination_ip));
    set_fields(fields: ioc, prefix: "threat_intel_");
end
```

## Stage 2 — decide

Non-expired hits alert. Expired hits stay attached as context but don't fire.

```java
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

If you would rather expired intel never alert at all, set `HIT_POLICY=live_only`
in `.env` — the service then reports expired indicators as misses and this rule
simplifies to a `found == "true"` check.

## Domains and URLs

```java
rule "OpenCTI :: enrich dns_query"
when
    has_field("dns_query")
then
    let ioc = lookup("opencti_indicators", to_string($message.dns_query));
    set_fields(fields: ioc, prefix: "threat_intel_");
end
```

```java
rule "OpenCTI :: enrich http_url"
when
    has_field("http_url")
then
    let ioc = lookup("opencti_indicators", to_string($message.http_url));
    set_fields(fields: ioc, prefix: "threat_intel_");
end
```

For URLs, check `threat_intel_match_type` — `hostname` means the exact URL was
not in OpenCTI but its host was, which is usually a weaker signal:

```java
rule "OpenCTI :: downgrade hostname-only URL matches"
when
    to_string($message.threat_intel_found) == "true" &&
    to_string($message.threat_intel_match_type) == "hostname"
then
    set_field("alert_severity", "low");
    set_field("alert_note", "matched on host, not the full URL");
end
```

## Watching for degraded mode

When OpenCTI is unreachable the service fails open — it answers `found: false`
with `degraded: true` rather than erroring, so pipelines keep running. Surface
that so the gap is visible rather than silent:

```java
rule "OpenCTI :: note degraded enrichment"
when
    to_string($message.threat_intel_degraded) == "true"
then
    set_field("threat_intel_status", "degraded");
end
```

The service also exposes `opencti_lookup_degraded_total` and
`opencti_breaker_state` on `/metrics` — alert on those in Prometheus rather
than relying on log inspection.
