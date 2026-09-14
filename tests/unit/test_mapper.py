from __future__ import annotations

from datetime import UTC, datetime

import pytest

from opencti_lookup.config import HitPolicy, Settings
from opencti_lookup.opencti.mapper import build_payload, passes_policy

NOW = datetime(2026, 9, 14, tzinfo=UTC)
PAST = "2026-09-04T17:10:46.927Z"
FUTURE = "2027-01-01T00:00:00.000Z"


def indicator(**over: object) -> dict:
    base = {
        "id": "ind-1", "name": "1.2.3.4", "pattern_type": "stix",
        "confidence": 100, "x_opencti_score": 60, "x_opencti_detection": False,
        "valid_from": "2026-08-01T00:00:00.000Z", "valid_until": FUTURE,
        "revoked": False, "objectLabel": [{"value": "c2"}],
        "objectMarking": [{"definition": "TLP:AMBER"}],
        "createdBy": {"name": "AlienVault"}, "killChainPhases": [],
    }
    return {**base, **over}


def node(*inds: dict) -> dict:
    return {
        "id": "obs-1", "entity_type": "IPv4-Addr", "observable_value": "1.2.3.4",
        "x_opencti_score": 60, "objectMarking": [],
        "indicators": {"edges": [{"node": i} for i in inds]},
    }


# On OpenCTI 7.26 `revoked` is set automatically when valid_until passes, so
# revoked+expired is the ordinary case and revoked+valid is a human retraction.
@pytest.mark.parametrize(
    ("policy", "revoked", "valid_until", "expected"),
    [
        (HitPolicy.LIVE_ONLY, False, FUTURE, True),
        (HitPolicy.LIVE_ONLY, True, PAST, False),
        (HitPolicy.EXPIRY_AWARE, False, FUTURE, True),
        (HitPolicy.EXPIRY_AWARE, True, PAST, True),    # expiry-driven -> hit
        (HitPolicy.EXPIRY_AWARE, True, FUTURE, False), # human retraction -> miss
        (HitPolicy.ALL, True, FUTURE, True),
    ],
)
def test_hit_policy(policy: HitPolicy, revoked: bool, valid_until: str, expected: bool) -> None:
    ind = indicator(revoked=revoked, valid_until=valid_until)
    assert passes_policy(ind, policy, now=NOW) is expected


def test_miss_when_no_indicators(settings: Settings) -> None:
    assert build_payload(node(), settings, value="1.2.3.4", indicator_type="IPv4-Addr") is None


def test_payload_is_flat_strings_with_no_nulls(settings: Settings) -> None:
    payload = build_payload(
        node(indicator()), settings, value="1.2.3.4", indicator_type="IPv4-Addr", now=NOW
    )
    assert payload is not None
    assert all(isinstance(k, str) and isinstance(v, str) for k, v in payload.items())
    assert None not in payload.values()
    assert payload["found"] == "true"
    assert payload["labels"] == "c2"
    assert payload["marking"] == "TLP:AMBER"


def test_expired_flag_and_ranking(settings: Settings) -> None:
    """A live indicator outranks an expired one regardless of score order."""
    payload = build_payload(
        node(
            indicator(id="expired", valid_until=PAST, revoked=True, x_opencti_score=99),
            indicator(id="live", valid_until=FUTURE, x_opencti_score=10),
        ),
        settings, value="1.2.3.4", indicator_type="IPv4-Addr", now=NOW,
    )
    assert payload is not None
    assert payload["expired"] == "false"
    assert payload["indicator_count"] == "2"
    assert payload["opencti_url"].endswith("/live")


def test_labels_are_unioned_deduped_and_bounded(settings: Settings) -> None:
    payload = build_payload(
        node(
            indicator(id="a", objectLabel=[{"value": "x"}, {"value": "y"}]),
            indicator(id="b", objectLabel=[{"value": "y"}, {"value": "z"}]),
        ),
        settings, value="1.2.3.4", indicator_type="IPv4-Addr", now=NOW,
    )
    assert payload is not None
    assert payload["labels"] == "x,y,z"


def test_entry_size_is_bounded(settings: Settings) -> None:
    """Bounding entry size is what makes the cache's maxsize a byte guarantee."""
    import json

    payload = build_payload(
        node(indicator(
            objectLabel=[{"value": f"label-{i}-{'q' * 200}"} for i in range(500)],
            description="d" * 5000, name="n" * 5000,
        )),
        settings, value="1.2.3.4", indicator_type="IPv4-Addr", now=NOW,
    )
    assert payload is not None
    assert len(json.dumps(payload).encode()) <= settings.payload_max_entry_bytes * 4
    assert len(payload["labels"].split(",")) <= 24
