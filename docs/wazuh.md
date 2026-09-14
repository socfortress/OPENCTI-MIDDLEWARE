# Wazuh integration

Enriches Wazuh alerts directly, without going through Graylog. The manager
calls the middleware for indicators found in an alert and writes hits back to
analysisd, where they become alerts your own rules can act on.

```
alert matches <integration> filter
   → analysisd spawns /var/ossec/integrations/custom-opencti
   → script extracts indicators from the alert JSON
   → POST /lookup/bulk  (or GET /lookup for one)
   → hits written to queue/sockets/queue
   → rules 100910-100915 fire
```

## Read this before enabling it

**Wazuh runs the integration as a new process per matching alert.** Measured
on a warm manager: **~73 ms per alert, of which ~44 ms is Python interpreter
startup alone** — roughly **14 alerts/sec per analysisd thread**, and that
ceiling is the process spawn, not the lookup.

The middleware answers misses in about a microsecond. None of that speed is
reachable through this path, because the cost is paid before your code runs.

So:

| Volume | Use |
|---|---|
| High-volume streams — every network connection, every DNS query, module loads | **Graylog lookup tables.** No process spawn, and Graylog's own cache absorbs repeats. See [pipeline-rules.md](pipeline-rules.md). |
| Targeted enrichment — FIM hashes, specific rule groups, higher-severity alerts | **This integration.** |

Running both is fine and often right: Graylog for breadth, Wazuh for alerts
you want enriched inside Wazuh's own correlation.

The single most important setting is the `<integration>` filter. A bare
`<level>3</level>` on a busy manager will saturate it.

## Install

```bash
sudo ./wazuh/install.sh              # or: sudo ./wazuh/install.sh /custom/path
```

Copies two files with the ownership Wazuh requires:

| Path | Owner | Mode |
|---|---|---|
| `integrations/custom-opencti` | `root:wazuh` | `750` |
| `integrations/custom-opencti.py` | `root:wazuh` | `750` |
| `etc/rules/0910-opencti_rules.xml` | `wazuh:wazuh` | `660` |

Then add to `<ossec_config>` in `ossec.conf`:

```xml
<integration>
  <name>custom-opencti</name>
  <hook_url>http://opencti-middleware:8000</hook_url>
  <api_key>YOUR_MIDDLEWARE_API_KEY</api_key>
  <alert_format>json</alert_format>
  <group>sysmon_event3,sysmon_event1,sysmon_event_22,syscheck</group>
</integration>
```

`hook_url` is the middleware base URL; a trailing `/lookup` is accepted too.
`api_key` is sent as `X-API-Key`. Restart with
`systemctl restart wazuh-manager`.

## What gets looked up

Indicators are pulled from these paths, covering the same sources as the
Graylog rules on both Linux and Windows Sysmon shapes:

| Kind | Alert paths |
|---|---|
| IPs | `data.eventdata.DestinationIp`, `data.win.eventdata.DestinationIp`, `data.destination.ip`, `data.dstip` |
| Domains | `data.dns.question.name`, `data.win.eventdata.queryName` |
| URLs | `data.url`, `data.http.url` |
| Hashes | `syscheck.sha256_after`, `syscheck.md5_after`, `syscheck.sha1_after`, `data.sha256` |
| Sysmon hash blob | `data.win.eventdata.hashes` — `SHA1=…,MD5=…,SHA256=…` is split into all three |

Two deliberate omissions:

- **`data.srcip` is not looked up.** It is usually the local side of the
  connection, so it generates noise rather than signal.
- **Private, loopback, link-local and reserved IPs are dropped in the script**,
  before any HTTP call. The middleware rejects them anyway, but skipping the
  round trip matters when the per-alert process spawn already dominates.

Several indicators in one alert (a Sysmon `hashes` blob yields three) go out
as a single `/lookup/bulk` request.

## What comes back

Only hits are written to analysisd — misses would mean an event per benign
connection. The event is flat and string-valued, the same shape Graylog gets,
plus provenance:

```json
{
  "integration": "opencti",
  "opencti": {
    "found": "true",
    "indicator": "212.193.31.122",
    "type": "IPv4-Addr",
    "score": "20",
    "expired": "true",
    "labels": "iot botnet,ddos attacks,tor infrastructure",
    "marking": "TLP:CLEAR",
    "virustotal_url": "https://www.virustotal.com/gui/ip-address/212.193.31.122",
    "opencti_url": "https://opencti.example.com/dashboard/observations/indicators/…",
    "source_rule_id": "92000",
    "source_rule_description": "Sysmon - Network connection detected",
    "source_alert_id": "1757.1"
  }
}
```

## Rules

`0910-opencti_rules.xml` ships:

| ID | Level | Fires on |
|---|---|---|
| 100910 | 0 | Parent; never alerts alone |
| 100911 | 8 | Any indicator match |
| 100912 | 4 | Match on an **expired** indicator — context, not a page |
| 100913 | 10 | Live indicator with score ≥ 50 |
| 100914 | 12 | High score **and** c2/ransomware/apt labels |
| 100915 | 5 | URL matched only on its hostname — weaker signal |

They start at 100910; change the range if it collides with your local rules.

Level 4 for expired matches lines up with the middleware's
`HIT_POLICY=expiry_aware` default, where an indicator past `valid_until` is
still returned but flagged. Set `HIT_POLICY=live_only` if you would rather
expired intel never arrive, and rule 100912 becomes dead.

## Troubleshooting

```bash
tail -f /var/ossec/logs/integrations.log
```

Run it by hand against a single alert file — exactly how Wazuh invokes it:

```bash
/var/ossec/integrations/custom-opencti /tmp/alert.json <api_key> <hook_url> debug
```

| Symptom | Cause |
|---|---|
| Nothing in the log at all | The `<integration>` filter matches no alerts, or ownership is wrong — must be `root:wazuh` `750` |
| `api_key and hook_url are both required` | One of them is missing or empty in `ossec.conf` |
| `http 401` / `http 403` | `api_key` does not match the middleware's `API_KEY` |
| `middleware unreachable` | The manager cannot resolve or reach `hook_url`; check container networking |
| Log shows `HIT` but no Wazuh alert | Rules file not installed, wrong ownership, or the ID range collides |

The script exits `0` on any unhandled error by design — an integration must
never take down alert processing. Failures land in the log instead.
