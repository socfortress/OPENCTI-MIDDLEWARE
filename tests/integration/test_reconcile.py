"""Scheduled and triggered rebuilds of the shared segment."""

from __future__ import annotations

import asyncio
import contextlib
import itertools
import tempfile
import time
from collections.abc import Iterator
from dataclasses import dataclass

import httpx
import pytest
import respx

from opencti_lookup.backends.live import LiveBackend
from opencti_lookup.backends.membership import MembershipSet
from opencti_lookup.backends.shared_state import (
    SharedMembershipState,
    SharedStateDir,
    segment_name,
)
from opencti_lookup.backends.split import SplitBackend
from opencti_lookup.cache.payload import PayloadCache
from opencti_lookup.config import Settings
from opencti_lookup.opencti.client import OpenCTIClient
from opencti_lookup.reconcile import Reconciler

GRAPHQL = "https://opencti.test/graphql"
_GENERATION = itertools.count()


def _corpus_response(values: list[str]) -> httpx.Response:
    return httpx.Response(
        200,
        json={
            "data": {
                "stixCyberObservables": {
                    "pageInfo": {"endCursor": None, "hasNextPage": False,
                                 "globalCount": len(values)},
                    "edges": [{"node": {"observable_value": v}} for v in values],
                }
            }
        },
    )


def _count(root: str, total: int) -> httpx.Response:
    return httpx.Response(
        200, json={"data": {root: {"pageInfo": {"globalCount": total}}}}
    )


def _counts(indicators: int, observables: int) -> list[httpx.Response]:
    """build_membership reads both counts before paginating."""
    return [
        _count("indicators", indicators),
        _count("stixCyberObservables", observables),
    ]


@dataclass
class Rig:
    reconciler: Reconciler
    backend: SplitBackend
    state_dir: SharedStateDir
    base_generation: int

    @property
    def original_segment(self) -> str:
        return segment_name(self.base_generation)


@pytest.fixture
def rig(settings: Settings) -> Iterator[Rig]:
    # A unique generation per test: swap_membership deliberately does NOT
    # unlink the segment it replaces (other workers may still map it), so a
    # shared name would leak from one test into the next.
    base = 9500 + next(_GENERATION)
    state_dir = SharedStateDir(tempfile.mkdtemp(prefix="octi-rec-"))
    membership = MembershipSet.build(["old.example.com"], name=segment_name(base))
    state_dir.publish(
        SharedMembershipState(segment_name(base), 1, base, time.time(), 1)
    )

    client = OpenCTIClient(url=GRAPHQL, token="t")
    backend = SplitBackend(
        membership=membership,
        live=LiveBackend(client=client, settings=settings,
                         cache=PayloadCache(budget_bytes=1024 * 1024)),
        settings=settings,
    )
    backend.mark_ready(True)
    reconciler = Reconciler(
        client=client, settings=settings, state_dir=state_dir,
        backend=backend, budget_bytes=1024 * 1024, generation=base,
    )
    try:
        yield Rig(reconciler, backend, state_dir, base)
    finally:
        backend.membership.close()
        # Unlink every segment this test created.
        for gen in (base, base + 1):
            with contextlib.suppress(FileNotFoundError, OSError):
                MembershipSet.attach(segment_name(gen), 0).close(unlink=True)


@respx.mock
async def test_rebuild_publishes_a_new_generation_and_swaps(rig: Rig) -> None:
    reconciler, backend, state_dir = rig.reconciler, rig.backend, rig.state_dir
    respx.post(GRAPHQL).mock(
        side_effect=[*_counts(2, 2), _corpus_response(["new-a.example.com", "new-b.example.com"])]
    )
    assert "new-a.example.com" not in backend.membership

    await reconciler._rebuild("test")

    published = state_dir.read()
    assert published is not None
    assert published.generation == rig.base_generation + 1
    assert published.shm_name == segment_name(rig.base_generation + 1)
    assert "new-a.example.com" in backend.membership
    assert reconciler.stats.rebuilds == 1


@respx.mock
async def test_rebuild_keeps_stream_updates_that_arrived_mid_build(rig: Rig) -> None:
    """The new snapshot predates them, so the overlay must carry over."""
    reconciler, backend = rig.reconciler, rig.backend
    respx.post(GRAPHQL).mock(
        side_effect=[*_counts(1, 1), _corpus_response(["from-opencti.example.com"])]
    )
    backend.membership.add("arrived-mid-rebuild.example.net")

    await reconciler._rebuild("test")

    assert "from-opencti.example.com" in backend.membership   # new snapshot
    assert "arrived-mid-rebuild.example.net" in backend.membership  # carried


@respx.mock
async def test_rebuild_keeps_the_superseded_segment_mapped(rig: Rig) -> None:
    """Readers may still be on it until their watcher adopts the new one."""
    reconciler = rig.reconciler
    respx.post(GRAPHQL).mock(side_effect=[*_counts(1, 1), _corpus_response(["x.example.com"])])
    reader = MembershipSet.attach(rig.original_segment, 1)
    try:
        await reconciler._rebuild("test")
        assert "old.example.com" in reader   # untouched by the sweep
    finally:
        reader.close()


async def test_overlay_full_requests_a_rebuild(rig: Rig) -> None:
    reconciler = rig.reconciler
    reconciler.request("overlay_full")
    assert reconciler.stats.pending_reason == "overlay_full"


async def test_request_is_ignored_while_a_rebuild_is_running(rig: Rig) -> None:
    reconciler = rig.reconciler
    reconciler.stats.running = True
    reconciler.request("overlay_full")
    assert reconciler.stats.pending_reason is None


@respx.mock
async def test_a_failed_rebuild_does_not_end_the_loop(rig: Rig) -> None:
    """The old segment keeps serving and the next interval retries."""
    reconciler, backend = rig.reconciler, rig.backend
    respx.post(GRAPHQL).mock(side_effect=httpx.ConnectError("down"))
    task = asyncio.create_task(reconciler.run())
    reconciler.request("test")
    await asyncio.sleep(0.3)
    assert reconciler.stats.failures >= 1
    assert not task.done()                      # loop survived
    assert "old.example.com" in backend.membership  # still serving
    reconciler.stop()
    task.cancel()
    with contextlib.suppress(asyncio.CancelledError):
        await task
