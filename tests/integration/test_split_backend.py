"""The membership set must answer misses without any upstream call."""

from __future__ import annotations

import httpx
import pytest
import respx

from opencti_lookup.backends.live import LiveBackend
from opencti_lookup.backends.membership import MembershipSet
from opencti_lookup.backends.split import SplitBackend
from opencti_lookup.cache.payload import PayloadCache
from opencti_lookup.config import Settings
from opencti_lookup.indicators import normalize
from opencti_lookup.opencti.client import OpenCTIClient

GRAPHQL = "https://opencti.test/graphql"


@pytest.fixture
def backend(settings: Settings):
    membership = MembershipSet.build(["known.example.com", "1.2.3.4"])
    client = OpenCTIClient(url=GRAPHQL, token="t")
    live = LiveBackend(
        client=client, settings=settings, cache=PayloadCache(budget_bytes=1024 * 1024)
    )
    split = SplitBackend(membership=membership, live=live, settings=settings)
    split.mark_ready(True)
    yield split
    membership.close()


@respx.mock
async def test_miss_makes_no_upstream_call(backend: SplitBackend) -> None:
    route = respx.post(GRAPHQL).mock(
        return_value=httpx.Response(200, json={"data": {"stixCyberObservables": {"edges": []}}})
    )
    result = await backend.lookup(normalize("unknown.example.org"))
    assert result.payload == {"found": "false"}
    assert result.source == "membership"
    assert route.call_count == 0


@respx.mock
async def test_known_value_is_escalated_upstream(backend: SplitBackend) -> None:
    route = respx.post(GRAPHQL).mock(
        return_value=httpx.Response(200, json={"data": {"stixCyberObservables": {"edges": []}}})
    )
    result = await backend.lookup(normalize("known.example.com"))
    assert route.call_count == 1
    assert result.source == "opencti"


@respx.mock
async def test_stale_membership_defers_to_live(backend: SplitBackend) -> None:
    """A stale set can produce false negatives, which are worse than slow."""
    route = respx.post(GRAPHQL).mock(
        return_value=httpx.Response(200, json={"data": {"stixCyberObservables": {"edges": []}}})
    )
    backend.mark_stale(True)
    await backend.lookup(normalize("unknown.example.org"))
    assert route.call_count == 1


async def test_skipped_values_short_circuit(backend: SplitBackend) -> None:
    result = await backend.lookup(normalize("10.0.0.1"))
    assert result.source == "skip"
    assert result.payload == {"found": "false"}
