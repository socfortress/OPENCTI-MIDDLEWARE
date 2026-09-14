"""Stream event parsing, against payload shapes captured from a live 7.26."""

from __future__ import annotations

import json

import pytest

from opencti_lookup.opencti.stream import (
    OBSERVABLE_TYPES,
    StreamConsumer,
    extract_values,
)

# Trimmed from an actual `event: update` on the live test instance. The point
# of interest is extensions[].observable_values -- it means an indicator event
# needs no follow-up GraphQL call to learn which values it covers.
REAL_INDICATOR = {
    "version": 4,
    "scope": "external",
    "data": {
        "type": "indicator",
        "id": "indicator--0e1b",
        "name": "http://103.86.86.244:800/Gateway/deploy_silent1.Ps1",
        "pattern": "[url:value = 'http://103.86.86.244:800/Gateway/deploy_silent1.Ps1']",
        "revoked": False,
        "valid_until": "2026-10-03T13:35:31.649Z",
        "extensions": {
            "extension-definition--ea279b3e": {
                "extension_type": "property-extension",
                "id": "4a0e",
                "score": 50,
                "detection": False,
                "main_observable_type": "Url",
                "observable_values": [
                    {
                        "type": "Url",
                        "value": "http://103.86.86.244:800/Gateway/deploy_silent1.Ps1",
                    }
                ],
            },
            "extension-definition--other": {"extension_type": "property-extension"},
        },
    },
}

REAL_OBSERVABLE = {
    "version": 4,
    "data": {"type": "domain-name", "id": "domain-name--aa", "value": "stopransomware.gov"},
}

NOISE = {"version": 4, "data": {"type": "vocabulary", "id": "v--1", "name": "x"}}


def test_indicator_values_come_from_the_event_itself() -> None:
    assert list(extract_values(REAL_INDICATOR)) == [
        "http://103.86.86.244:800/Gateway/deploy_silent1.Ps1"
    ]


def test_indicator_with_several_observables() -> None:
    payload = {
        "data": {
            "type": "indicator",
            "extensions": {
                "e1": {
                    "observable_values": [
                        {"type": "Url", "value": "http://bad.com/a"},
                        {"type": "IPv4-Addr", "value": "1.2.3.4"},
                    ]
                }
            },
        }
    }
    assert list(extract_values(payload)) == ["http://bad.com/a", "1.2.3.4"]


@pytest.mark.parametrize("stix_type", sorted(OBSERVABLE_TYPES))
def test_every_observable_type_yields_its_value(stix_type: str) -> None:
    assert list(extract_values({"data": {"type": stix_type, "value": "x"}})) == ["x"]


@pytest.mark.parametrize(
    "payload",
    [NOISE, {"data": {"type": "file", "value": None}}, {"data": "not-a-dict"}, {}],
)
def test_irrelevant_events_yield_nothing(payload: dict) -> None:
    assert list(extract_values(payload)) == []


def _consumer(**over: object) -> tuple[StreamConsumer, list[str], list[str]]:
    added: list[str] = []
    removed: list[str] = []
    kwargs: dict[str, object] = {
        "url": "https://opencti.test/stream",
        "token": "t",
        "on_add": added.append,
        "on_remove": removed.append,
        "normalize": lambda v: v.lower(),
        **over,
    }
    return StreamConsumer(**kwargs), added, removed  # type: ignore[arg-type]


def test_create_adds_and_delete_removes() -> None:
    consumer, added, removed = _consumer()
    consumer._handle("create", "1-0", json.dumps(REAL_OBSERVABLE))
    consumer._handle("delete", "2-0", json.dumps(REAL_OBSERVABLE))
    assert added == ["stopransomware.gov"]
    assert removed == ["stopransomware.gov"]
    assert consumer.stats.events_applied == 2


def test_cursor_tracks_the_event_id() -> None:
    """The id is the resume cursor -- reconnecting with ?from=<id> replays
    everything after it, so a dropped connection costs no events."""
    consumer, _, _ = _consumer()
    consumer._handle("connected", "100-0", "{}")
    assert consumer.cursor == "100-0"
    consumer._handle("create", "101-0", json.dumps(REAL_OBSERVABLE))
    assert consumer.cursor == "101-0"


def test_values_are_normalized_before_writing() -> None:
    """The set is keyed on the normalized form; writing raw values would
    make every differing one a false miss."""
    consumer, added, _ = _consumer(normalize=lambda v: v.upper())
    consumer._handle("create", "1-0", json.dumps(REAL_OBSERVABLE))
    assert added == ["STOPRANSOMWARE.GOV"]


def test_unlookupable_values_are_dropped() -> None:
    consumer, added, _ = _consumer(normalize=lambda _v: None)
    consumer._handle("create", "1-0", json.dumps(REAL_OBSERVABLE))
    assert added == []
    assert consumer.stats.events_applied == 0
    assert consumer.stats.events_skipped == 1


def test_malformed_payloads_do_not_raise() -> None:
    consumer, added, _ = _consumer()
    for data in ("not json", "[]", "null", '{"data": 5}'):
        consumer._handle("create", "1-0", data)
    assert added == []
    assert consumer.stats.events_skipped == 4


def test_overlay_full_triggers_the_rebuild_signal() -> None:
    fired: list[bool] = []
    consumer, _, _ = _consumer(
        overlay_full=lambda: True, on_overlay_full=lambda: fired.append(True)
    )
    consumer._handle("create", "1-0", json.dumps(REAL_OBSERVABLE))
    assert fired == [True]


# --- heartbeats: the difference between "quiet" and "dead" -------------------


def test_heartbeat_keeps_the_connection_alive_without_touching_the_set() -> None:
    """A quiet instance must not look like a stalled stream."""
    consumer, added, removed = _consumer()
    consumer._handle("heartbeat", "500-0", '"2026-09-14T17:12:40.269Z"')
    assert consumer.stats.heartbeats == 1
    assert consumer.stats.activity_lag_s < 1.0   # liveness refreshed
    assert added == [] and removed == []          # set untouched
    assert consumer.stats.events_applied == 0
    assert consumer.stats.events_skipped == 0     # not "skipped", it's a ping


def test_heartbeat_advances_the_resume_cursor() -> None:
    """So reconnecting after an idle period doesn't replay old events."""
    consumer, _, _ = _consumer()
    consumer._handle("create", "100-0", json.dumps(REAL_OBSERVABLE))
    consumer._handle("heartbeat", "900-0", '"2026-09-14T17:12:40.269Z"')
    assert consumer.cursor == "900-0"


def test_consumer_metrics_records_upstream_lag() -> None:
    consumer, _, _ = _consumer()
    consumer._handle(
        "consumer_metrics", "500-0",
        '{"deliveryRate":0.2,"processingRate":0,"timeLag":42.5}',
    )
    assert consumer.stats.upstream_time_lag_s == 42.5


def test_event_lag_and_activity_lag_are_different_things() -> None:
    """event_lag grows on a quiet instance; activity_lag must not, or the
    backend would mark a healthy service stale every quiet night."""
    import time as _time

    consumer, _, _ = _consumer()
    consumer.stats.last_event_at = _time.monotonic() - 3600   # nothing changed in an hour
    consumer._handle("heartbeat", "1-0", '"t"')               # but we're being pinged
    assert consumer.stats.event_lag_s > 3500
    assert consumer.stats.activity_lag_s < 1.0
