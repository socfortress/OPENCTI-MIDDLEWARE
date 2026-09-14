"""A generation swap must not lose pending stream updates."""

from __future__ import annotations

from opencti_lookup.backends.membership import MembershipSet


def test_adopt_overlay_carries_adds_and_tombstones() -> None:
    old = MembershipSet.build(["a.example.com"])
    new = MembershipSet.build(["a.example.com", "b.example.com"])
    try:
        old.add("from-stream.example.net")
        old.remove("a.example.com")

        new.adopt_overlay(old)

        assert "from-stream.example.net" in new  # survived the swap
        assert "a.example.com" not in new        # tombstone survived too
        assert "b.example.com" in new            # new segment content intact
    finally:
        old.close()
        new.close()


def test_readd_after_tombstone_wins() -> None:
    old = MembershipSet.build(["x.example.com"])
    new = MembershipSet.build(["x.example.com"])
    try:
        old.remove("x.example.com")
        old.add("x.example.com")  # stream said delete, then create
        new.adopt_overlay(old)
        assert "x.example.com" in new
    finally:
        old.close()
        new.close()


def test_stream_health_ignores_event_recency() -> None:
    """A healthy but idle stream must never be marked stale."""
    from opencti_lookup.backends.live import LiveBackend
    from opencti_lookup.backends.split import SplitBackend
    from opencti_lookup.cache.payload import PayloadCache
    from opencti_lookup.config import Settings
    from opencti_lookup.opencti.client import OpenCTIClient

    settings = Settings(
        api_key="k" * 32,  # type: ignore[arg-type]
        opencti_url="https://opencti.test",
        opencti_token="t",  # type: ignore[arg-type]
    )
    membership = MembershipSet.build(["a"])
    split = SplitBackend(
        membership=membership,
        live=LiveBackend(
            client=OpenCTIClient(url="https://opencti.test/graphql", token="t"),
            settings=settings,
            cache=PayloadCache(budget_bytes=1024),
        ),
        settings=settings,
    )
    try:
        # connected, heartbeats flowing, nothing changed for hours
        split.stream_health(connected=True, activity_lag_s=3.0, stale_after_s=120)
        assert split.describe()["stale"] is False

        # heartbeats stopped -> genuinely stalled
        split.stream_health(connected=True, activity_lag_s=500.0, stale_after_s=120)
        assert split.describe()["stale"] is True

        # disconnected is stale regardless
        split.stream_health(connected=False, activity_lag_s=1.0, stale_after_s=120)
        assert split.describe()["stale"] is True
    finally:
        membership.close()
