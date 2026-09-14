#!/usr/bin/env python3
"""Wazuh custom integration: enrich alerts from the OpenCTI middleware.

Wazuh invokes this once per matching alert:

    custom-opencti <alert_file> <api_key> <hook_url> [debug]

    argv[1]  path to a JSON file holding ONE alert
    argv[2]  <api_key>  from ossec.conf  -> sent as X-API-Key
    argv[3]  <hook_url> from ossec.conf  -> the middleware base URL
    argv[4]  "debug" to log verbosely

Indicators found in the alert are looked up, and a hit is written back to
analysisd so it becomes a new alert that local rules can act on. Misses are
dropped rather than written back -- analysisd should not see an event per
benign connection.

Standard library only, deliberately. Wazuh spawns a fresh process per alert,
so interpreter startup is the dominant cost; importing `requests` roughly
doubles it, and installing dependencies on a manager is a support burden.
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from socket import AF_UNIX, SOCK_DGRAM, socket

# --- exit codes ------------------------------------------------------------
ERR_BAD_ARGUMENTS = 2
ERR_FILE_NOT_FOUND = 6
ERR_INVALID_JSON = 7

# --- wiring ----------------------------------------------------------------
OSSEC_PATH = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
SOCKET_ADDR = f"{OSSEC_PATH}/queue/sockets/queue"
LOG_FILE = f"{OSSEC_PATH}/logs/integrations.log"

INTEGRATION_NAME = "opencti"
HTTP_TIMEOUT = 5.0
MAX_INDICATORS_PER_ALERT = 16

debug_enabled = False


def log(message: str, *, force: bool = False) -> None:
    if not (debug_enabled or force):
        return
    line = f"{time.strftime('%Y/%m/%d %H:%M:%S')} {INTEGRATION_NAME}: {message}\n"
    try:
        with open(LOG_FILE, "a") as handle:
            handle.write(line)
    except OSError:
        pass
    if debug_enabled:
        print(line, end="", file=sys.stderr)


# ---------------------------------------------------------------------------
# Extraction
# ---------------------------------------------------------------------------

#: Dotted paths that hold a single indicator value. Covers the same sources as
#: the Graylog pipeline rules, on both the Linux (data.eventdata) and Windows
#: (data.win.eventdata) Sysmon shapes, plus Packetbeat and FIM.
VALUE_PATHS: tuple[str, ...] = (
    # network
    "data.eventdata.DestinationIp",
    "data.win.eventdata.DestinationIp",
    "data.win.eventdata.destinationIp",
    "data.destination.ip",
    "data.dstip",
    # dns
    "data.dns.question.name",
    "data.win.eventdata.queryName",
    "data.dns_question_name",
    # urls
    "data.url",
    "data.http.url",
    "data.win.eventdata.DestinationHostname",
    # hashes
    "syscheck.sha256_after",
    "syscheck.md5_after",
    "syscheck.sha1_after",
    "data.sha256",
    "data.virustotal.source.sha1",
)

#: Sysmon packs several digests into one field:
#: "SHA1=...,MD5=...,SHA256=...,IMPHASH=..."
HASHES_PATHS: tuple[str, ...] = (
    "data.win.eventdata.hashes",
    "data.win.eventdata.Hashes",
    "data.eventdata.Hashes",
)
_HASH_PAIR_RE = re.compile(r"(MD5|SHA1|SHA256)=([a-fA-F0-9]{32,64})")

#: Source IPs are usually the local side of the connection; looking them up
#: produces noise rather than signal. Kept separate so it is a visible choice.
SKIP_PATHS: frozenset[str] = frozenset({"data.srcip", "data.src_ip"})


def dig(alert: dict, dotted: str):
    node = alert
    for part in dotted.split("."):
        if not isinstance(node, dict) or part not in node:
            return None
        node = node[part]
    return node


def looks_private(value: str) -> bool:
    """Cheap local filter.

    The middleware rejects these in microseconds anyway, but skipping them
    here avoids an HTTP round trip per alert -- which matters far more, since
    the per-alert process spawn is the real cost in this integration.
    """
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    return bool(
        ip.is_private or ip.is_loopback or ip.is_link_local
        or ip.is_multicast or ip.is_reserved or ip.is_unspecified
    )


def extract_indicators(alert: dict) -> list[str]:
    """Every distinct value in this alert worth looking up."""
    found: dict[str, None] = {}

    for path in VALUE_PATHS:
        if path in SKIP_PATHS:
            continue
        value = dig(alert, path)
        if isinstance(value, str) and value.strip():
            candidate = value.strip()
            if not looks_private(candidate):
                found.setdefault(candidate, None)

    for path in HASHES_PATHS:
        blob = dig(alert, path)
        if isinstance(blob, str):
            for _algorithm, digest in _HASH_PAIR_RE.findall(blob):
                found.setdefault(digest.lower(), None)

    return list(found)[:MAX_INDICATORS_PER_ALERT]


# ---------------------------------------------------------------------------
# Middleware
# ---------------------------------------------------------------------------


ALLOWED_SCHEMES = ("http", "https")


def _request(url: str, api_key: str, payload: bytes | None = None) -> dict | None:
    # hook_url comes from ossec.conf. That file is root-owned, but urlopen
    # honours file:// and other schemes, so a typo or a bad edit should fail
    # loudly rather than read a local file into the alert pipeline.
    if not url.startswith(("http://", "https://")):
        log(f"refusing non-HTTP hook_url scheme: {url[:40]!r}", force=True)
        return None

    request = urllib.request.Request(  # noqa: S310 - scheme checked above
        url, data=payload, method="POST" if payload else "GET"
    )
    request.add_header("X-API-Key", api_key)
    if payload:
        request.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(request, timeout=HTTP_TIMEOUT) as response:  # noqa: S310
            return json.loads(response.read().decode())
    except urllib.error.HTTPError as exc:
        log(f"http {exc.code} from {url}: {exc.read()[:200]!r}", force=exc.code in (401, 403))
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        log(f"middleware unreachable: {exc}", force=True)
    except ValueError as exc:
        log(f"bad JSON from middleware: {exc}", force=True)
    return None


def lookup(base_url: str, api_key: str, indicators: list[str]) -> dict[str, dict]:
    """Resolve indicators. One request regardless of how many."""
    base = base_url.rstrip("/")
    # Accept either the bare host or a full /lookup URL in <hook_url>.
    if base.endswith("/lookup"):
        base = base[: -len("/lookup")]

    if len(indicators) == 1:
        query = urllib.parse.urlencode({"value": indicators[0]})
        body = _request(f"{base}/lookup?{query}", api_key)
        return {indicators[0]: body} if body else {}

    payload = json.dumps({"values": indicators}).encode()
    body = _request(f"{base}/lookup/bulk", api_key, payload)
    if not body:
        return {}
    results = body.get("results")
    return results if isinstance(results, dict) else {}


# ---------------------------------------------------------------------------
# Back to analysisd
# ---------------------------------------------------------------------------


def send_event(message: dict, agent: dict | None = None) -> None:
    """Write an event to analysisd so it becomes an alert.

    Format matches Wazuh's own bundled integrations: the location field is
    escaped because analysisd treats ':' and '|' as delimiters.
    """
    if not agent or agent.get("id") == "000":
        payload = f"1:{INTEGRATION_NAME}:{json.dumps(message)}"
    else:
        location = f'[{agent.get("id")}] ({agent.get("name")}) {agent.get("ip", "any")}'
        location = location.replace("|", "||").replace(":", "|:")
        payload = f"1:{location}->{INTEGRATION_NAME}:{json.dumps(message)}"

    try:
        sock = socket(AF_UNIX, SOCK_DGRAM)
        sock.connect(SOCKET_ADDR)
        sock.send(payload.encode())
        sock.close()
    except OSError as exc:
        log(f"cannot write to {SOCKET_ADDR}: {exc}", force=True)


def build_event(alert: dict, indicator: str, result: dict) -> dict:
    """Flat, string-valued output, mirroring what Graylog receives."""
    rule = alert.get("rule") or {}
    enrichment = {k: v for k, v in result.items() if isinstance(v, (str, int, float))}
    enrichment["indicator"] = indicator
    enrichment["source_rule_id"] = str(rule.get("id", ""))
    enrichment["source_rule_description"] = str(rule.get("description", ""))[:256]
    enrichment["source_alert_id"] = str(alert.get("id", ""))
    return {"integration": INTEGRATION_NAME, INTEGRATION_NAME: enrichment}


# ---------------------------------------------------------------------------


def load_alert(path: str) -> dict:
    try:
        with open(path) as handle:
            return json.load(handle)
    except FileNotFoundError:
        log(f"alert file not found: {path}", force=True)
        sys.exit(ERR_FILE_NOT_FOUND)
    except (json.JSONDecodeError, ValueError) as exc:
        log(f"alert file is not valid JSON: {exc}", force=True)
        sys.exit(ERR_INVALID_JSON)


def main(argv: list[str]) -> int:
    global debug_enabled

    if len(argv) < 4:
        log("usage: custom-opencti <alert_file> <api_key> <hook_url> [debug]", force=True)
        return ERR_BAD_ARGUMENTS

    alert_file, api_key, hook_url = argv[1], argv[2], argv[3]
    debug_enabled = len(argv) > 4 and argv[4].lower() == "debug"

    if not api_key or not hook_url:
        log("api_key and hook_url are both required in ossec.conf", force=True)
        return ERR_BAD_ARGUMENTS

    alert = load_alert(alert_file)
    indicators = extract_indicators(alert)
    if not indicators:
        log("no indicators in alert")
        return 0

    log(f"looking up {len(indicators)}: {indicators}")
    results = lookup(hook_url, api_key, indicators)

    agent = alert.get("agent")
    hits = 0
    for indicator, result in results.items():
        if not isinstance(result, dict) or result.get("found") != "true":
            continue
        send_event(build_event(alert, indicator, result), agent)
        hits += 1
        log(f"HIT {indicator} score={result.get('score')} labels={result.get('labels')}")

    if not hits:
        log(f"no hits for {len(indicators)} indicator(s)")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv))
    except Exception as exc:
        # Never let an integration take down alert processing.
        log(f"unhandled error: {type(exc).__name__}: {exc}", force=True)
        sys.exit(0)
