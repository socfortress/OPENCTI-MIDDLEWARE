# Pipeline rules

Production rules from a Wazuh + Sysmon + Packetbeat deployment. Each looks up
one field and merges the whole response under a `threat_intel_` prefix.

`set_fields()` takes the entire map in one call, so adding a response field
never means editing a rule.

## Pass the value, nothing else

The lookup key is the indicator **on its own**:

```java
let ldata = lookup(
  lookup_table: "threatintellookup",
  key: to_string($message.data_eventdata_DestinationIp)
);
```

Not concatenated with anything. Graylog URL-encodes the whole substituted key,
so a key built as `"1.2.3.4&customer_code=ACME"` arrives as
`value=1.2.3.4%26customer_code%3DACME`, decodes to the literal string
`1.2.3.4&customer_code=ACME`, and fails to classify — every lookup becomes a
miss. Tenant tags belong in the data adapter's HTTP headers
(`X-Customer-Code: ACME`), where they cost nothing and cannot corrupt the key.

---

## Linux

### Sysmon event 3 — network connection

```java
rule "LINUX SYSMON EVENT 3 - THREAT INTEL"
when
  $message.rule_group1 == "linux"
  AND $message.rule_group3 == "sysmon_event3"
  AND $message.data_eventdata_DestinationIp != "127.0.0.1"
  AND $message.data_eventdata_DestinationIp != "255.255.255.255"
  AND $message.data_eventdata_DestinationIp != "0.0.0.0"
  AND $message.data_eventdata_destinationIsIpv6 == "false"
  AND ! in_private_net(to_string($message.data_eventdata_DestinationIp))
then
  let ldata = lookup(
    lookup_table: "threatintellookup",
    key: to_string($message.data_eventdata_DestinationIp)
  );
  set_fields(fields: ldata, prefix: "threat_intel_");
end
```

The loopback/broadcast/private guards are redundant with the service, which
short-circuits those in microseconds without a cache entry or a network call —
but they do save a lookup-table call per message, so they are worth keeping.

### Packetbeat DNS query

```java
rule "PACKETBEAT DNS QUERY - THREAT INTEL"
when
  $message.rule_group1 == "linux" AND $message.rule_group3 == "dns"
then
  let ldata = lookup(
    lookup_table: "threatintellookup",
    key: to_string($message.data_dns_question_name)
  );
  set_fields(fields: ldata, prefix: "threat_intel_");
end
```

### Packetbeat HTTP/S connection

```java
rule "PACKETBEAT HTTP/S CONNECTION - THREAT INTEL"
when
  $message.rule_group1 == "linux"
  AND ($message.rule_group3 == "tls" OR $message.rule_group3 == "http")
then
  let ldata = lookup(
    lookup_table: "threatintellookup",
    key: to_string($message.data_destination_ip)
  );
  set_fields(fields: ldata, prefix: "threat_intel_");
end
```

Note the parentheses. `A AND B OR C` binds as `(A AND B) OR C`, so without them
any `http` event matches regardless of `rule_group1` — including Windows.

---

## Windows

### Sysmon event 1 — process creation

```java
rule "WINDOWS SYSMON EVENT 1 - THREAT INTEL"
when
  $message.rule_group1 == "windows"
  AND $message.rule_group3 == "sysmon_event1"
  AND ! has_field("data_win_eventdata_company")
then
  let ldata = lookup(
    lookup_table: "threatintellookup",
    key: to_string($message.sha256)
  );
  set_fields(fields: ldata, prefix: "threat_intel_");
end
```

Absence of a `company` field is a cheap proxy for unsigned/unattributed
binaries, which keeps hash lookups off the bulk of normal process activity.

### Sysmon event 6 — driver load

```java
rule "WINDOWS SYSMON EVENT 6 - THREAT INTEL"
when
  $message.rule_group1 == "windows"
  AND $message.rule_group3 == "sysmon_event6"
  AND $message.data_win_eventdata_signed == "false"
then
  let ldata = lookup(
    lookup_table: "threatintellookup",
    key: to_string($message.sha256)
  );
  set_fields(fields: ldata, prefix: "threat_intel_");
end
```

### Sysmon event 7 — image load

```java
rule "WINDOWS SYSMON EVENT 7 - THREAT INTEL"
when
  $message.rule_group1 == "windows"
  AND $message.rule_group3 == "sysmon_event7"
  AND $message.data_win_eventdata_signed == "false"
then
  let ldata = lookup(
    lookup_table: "threatintellookup",
    key: to_string($message.sha256)
  );
  set_fields(fields: ldata, prefix: "threat_intel_");
end
```

Event 7 is high volume — every module load, potentially thousands per host per
minute. The `signed == "false"` guard is doing real work; without it this rule
alone can dominate lookup traffic.

It is survivable because misses are answered from the membership set in about
a microsecond without allocating anything. But raise the lookup table's Guava
cache (20,000 entries / 60s is the documented starting point) before enabling
this one broadly — the same handful of signed-but-uncompanied DLLs recur
constantly, and Graylog-side caching means most never reach the service.

### Sysmon event 15 — file stream created

```java
rule "WINDOWS SYSMON EVENT 15 - THREAT INTEL"
when
  $message.rule_group1 == "windows" AND $message.rule_group3 == "sysmon_event_15"
then
  let ldata = lookup(
    lookup_table: "threatintellookup",
    key: to_string($message.sha256)
  );
  set_fields(fields: ldata, prefix: "threat_intel_");
end
```

### Sysmon event 22 — DNS query

```java
rule "WINDOWS SYSMON EVENT 22 - THREAT INTEL"
when
  $message.rule_group1 == "windows" AND $message.rule_group3 == "sysmon_event_22"
then
  let ldata = lookup(
    lookup_table: "threatintellookup",
    key: to_string($message.data_win_eventdata_queryName)
  );
  set_fields(fields: ldata, prefix: "threat_intel_");
end
```

---

---

## Hash lookups

Sysmon events 1, 6, 7 and 15 look up `$message.sha256`. These resolve against
OpenCTI's `StixFile` observables, which are matched by a `hashes.<ALGO>` filter
key rather than by `value` — a detail worth knowing if you query OpenCTI
directly, since filtering a StixFile by `value` returns nothing even though
`observable_value` displays the digest.

MD5, SHA-1 and SHA-256 are detected by length (32/40/64 hex characters) and
case-folded, so Sysmon's uppercase digests match OpenCTI's lowercase storage.
Hits carry a `threat_intel_virustotal_url` for the analyst.

## Acting on the result

The rules above only enrich. Put the decision in a later stage so adding a
source never means touching alerting logic.

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

Set `HIT_POLICY=live_only` if you would rather expired intel never reach this
stage at all; the rule then simplifies to a `found == "true"` check.

### Weaker signals worth downgrading

`threat_intel_match_type` is `hostname` when a URL itself was not in OpenCTI
but its host was:

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

### Degraded enrichment

When OpenCTI is unreachable the service fails open — `found: false` with
`degraded: true` — so pipelines keep running rather than stalling. Surface it
so the gap is visible instead of silent:

```java
rule "OpenCTI :: note degraded enrichment"
when
  to_string($message.threat_intel_degraded) == "true"
then
  set_field("threat_intel_status", "degraded");
end
```

Alert on `opencti_lookup_degraded_total` and `opencti_breaker_state` from
`/metrics` rather than relying on log inspection.
