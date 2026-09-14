"""Turn an OpenCTI observable node into a flat, Graylog-safe payload.

Graylog pipeline rules mishandle nulls, arrays, nested objects and numbers,
so every value leaving here is a plain string and absent fields are omitted
rather than set to null. That was a convention in the app this replaces; here
it is enforced by construction.

Every field is also length-bounded. `TTLCache(maxsize=N)` counts entries, not
bytes, so one indicator carrying 400 labels would otherwise blow the payload
cache budget. Bounding entry size is what turns maxsize into a real byte
guarantee.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from ..config import HitPolicy, Settings

MAX_LABELS = 24
MAX_LABEL_LEN = 64
MAX_TEXT_LEN = 256
MAX_NAME_LEN = 128


def _s(value: Any, limit: int = MAX_TEXT_LEN) -> str | None:
    """Coerce to a bounded, non-empty string, or None to omit the field."""
    if value is None:
        return None
    if isinstance(value, bool):
        return "true" if value else "false"
    text = str(value).strip()
    if not text:
        return None
    return text[:limit]


def _parse_dt(raw: Any) -> datetime | None:
    if not raw or not isinstance(raw, str):
        return None
    try:
        return datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return None


def is_expired(node: dict[str, Any], *, now: datetime | None = None) -> bool:
    valid_until = _parse_dt(node.get("valid_until"))
    if valid_until is None:
        return False
    return valid_until <= (now or datetime.now(UTC))


def passes_policy(
    node: dict[str, Any], policy: HitPolicy, *, now: datetime | None = None
) -> bool:
    """Whether one indicator counts as a hit under `policy`."""
    revoked = bool(node.get("revoked"))
    if policy is HitPolicy.ALL:
        return True
    if policy is HitPolicy.LIVE_ONLY:
        return not revoked
    # EXPIRY_AWARE: OpenCTI auto-revokes on expiry, so a revoked indicator
    # whose valid_until has already passed is just expired, not retracted.
    # Only a revoke while still inside the validity window is a human action.
    if not revoked:
        return True
    return is_expired(node, now=now)


def select_indicators(
    node: dict[str, Any], settings: Settings, *, now: datetime | None = None
) -> list[dict[str, Any]]:
    """Surviving indicators, best first."""
    raw = node.get("indicators") or {}
    candidates = [e["node"] for e in raw.get("edges", []) if e.get("node")]

    survivors = [
        ind
        for ind in candidates
        if passes_policy(ind, settings.hit_policy, now=now)
        and int(ind.get("x_opencti_score") or 0) >= settings.min_score
    ]

    def rank(ind: dict[str, Any]) -> tuple[int, int, str]:
        return (
            0 if not is_expired(ind, now=now) else 1,      # live before expired
            -int(ind.get("x_opencti_score") or 0),          # higher score first
            str(ind.get("valid_until") or ""),
        )

    survivors.sort(key=rank)
    return survivors


def _labels(indicators: list[dict[str, Any]]) -> list[str]:
    """Deduped union of labels across all surviving indicators."""
    seen: dict[str, None] = {}
    for ind in indicators:
        for label in ind.get("objectLabel") or []:
            value = (label or {}).get("value")
            if value:
                seen.setdefault(str(value).strip()[:MAX_LABEL_LEN], None)
            if len(seen) >= MAX_LABELS:
                return list(seen)
    return list(seen)


def _marking(node: dict[str, Any], primary: dict[str, Any]) -> str | None:
    for source in (primary, node):
        for marking in source.get("objectMarking") or []:
            definition = (marking or {}).get("definition")
            if definition:
                return str(definition)[:MAX_LABEL_LEN]
    return None


def build_payload(
    node: dict[str, Any],
    settings: Settings,
    *,
    value: str,
    indicator_type: str,
    match_type: str = "exact",
    now: datetime | None = None,
) -> dict[str, str] | None:
    """Flat Graylog payload, or None when nothing survives the hit policy."""
    survivors = select_indicators(node, settings, now=now)
    if not survivors:
        return None

    primary = survivors[0]
    expired = is_expired(primary, now=now)

    fields: dict[str, str | None] = {
        "found": "true",
        "value": value,
        "type": indicator_type,
        "match_type": match_type,
        "score": _s(primary.get("x_opencti_score")),
        "confidence": _s(primary.get("confidence")),
        "detection": _s(primary.get("x_opencti_detection")) or "false",
        "expired": "true" if expired else "false",
        "revoked": _s(primary.get("revoked")) or "false",
        "valid_from": _s(primary.get("valid_from")),
        "valid_until": _s(primary.get("valid_until")),
        "indicator_name": _s(primary.get("name"), MAX_NAME_LEN),
        "indicator_count": str(len(survivors)),
        "pattern_type": _s(primary.get("pattern_type"), 32),
        "description": _s(primary.get("description")),
        "marking": _marking(node, primary),
        "observable_score": _s(node.get("x_opencti_score")),
    }

    created_by = (primary.get("createdBy") or {}).get("name")
    fields["created_by"] = _s(created_by, MAX_NAME_LEN)

    phases = [
        str(p.get("phase_name"))[:MAX_LABEL_LEN]
        for p in (primary.get("killChainPhases") or [])
        if p.get("phase_name")
    ]
    fields["kill_chain"] = ",".join(phases[:MAX_LABELS]) or None

    labels = _labels(survivors)
    fields["labels"] = ",".join(labels) or None

    # Analyst convenience, carried over from the app this replaces.
    vt = _virustotal_url(indicator_type, value)
    if vt:
        fields["virustotal_url"] = vt

    indicator_id = primary.get("id")
    if indicator_id:
        fields["opencti_url"] = (
            f"{settings.opencti_url}/dashboard/observations/indicators/{indicator_id}"
        )

    # Omit rather than null -- Graylog pipeline rules choke on nulls.
    return {k: v for k, v in fields.items() if v is not None}


def _virustotal_url(indicator_type: str, value: str) -> str | None:
    if indicator_type.startswith("StixFile"):
        return f"https://www.virustotal.com/gui/file/{value}"
    if indicator_type in ("IPv4-Addr", "IPv6-Addr"):
        return f"https://www.virustotal.com/gui/ip-address/{value}"
    if indicator_type in ("Domain-Name", "Hostname"):
        return f"https://www.virustotal.com/gui/domain/{value}"
    return None


MISS: dict[str, str] = {"found": "false"}
DEGRADED: dict[str, str] = {"found": "false", "degraded": "true"}
