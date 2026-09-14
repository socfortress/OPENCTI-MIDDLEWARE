"""Load the membership set from OpenCTI.

Two paths, because they differ by 17x in speed on a live instance:

  observables (default)  ~3,500 values/sec -- reads observable values directly
  indicators (precise)     ~210 values/sec -- walks indicators, follows the
                                              nested observables relationship

The fast path is safe because the membership set is a *pre-filter*, not the
verdict. An observable with no indicator yields a false "present", which
triggers a payload query, which returns a miss, which gets cached. The
verdict still comes from the indicators themselves.

The cost of that is proportional to how far observables outnumber indicators,
so both counts are read at startup and the ratio is logged. Set
MEMBERSHIP_SOURCE=indicators to force precision on a lopsided instance.

The entry ceiling is enforced *while loading*, not from a projected size --
Python memory estimates are unreliable enough that the cap has to be applied
as we go.
"""

from __future__ import annotations

import time
from collections.abc import AsyncIterator

import structlog

from .backends.membership import MembershipSet, estimate_bytes
from .config import Settings
from .opencti.client import OpenCTIClient
from .opencti.queries import (
    BOOTSTRAP_INDICATORS,
    BOOTSTRAP_OBSERVABLES,
    COUNT_INDICATORS,
    COUNT_OBSERVABLES,
)

log = structlog.get_logger(__name__)

#: Above this observable:indicator ratio the fast path starts producing enough
#: false positives to be worth warning about.
RATIO_WARN_THRESHOLD = 3.0


async def _count(client: OpenCTIClient, query: str, root: str) -> int:
    data = await client.execute(query, retry_connect=False)
    return int((data.get(root) or {}).get("pageInfo", {}).get("globalCount") or 0)


async def count_indicators(client: OpenCTIClient) -> int:
    return await _count(client, COUNT_INDICATORS, "indicators")


async def count_observables(client: OpenCTIClient) -> int:
    return await _count(client, COUNT_OBSERVABLES, "stixCyberObservables")


async def _iter_page(
    client: OpenCTIClient, query: str, root: str, page_size: int
) -> AsyncIterator[dict]:
    cursor: str | None = None
    while True:
        data = await client.execute(query, {"first": page_size, "after": cursor})
        block = data.get(root) or {}
        yield block
        info = block.get("pageInfo") or {}
        if not info.get("hasNextPage"):
            return
        cursor = info.get("endCursor")
        if not cursor:
            return


async def iter_values(
    client: OpenCTIClient, settings: Settings, *, limit: int | None = None
) -> AsyncIterator[str]:
    """Yield the observable values that should populate the membership set."""
    precise = settings.membership_source == "indicators"
    query = BOOTSTRAP_INDICATORS if precise else BOOTSTRAP_OBSERVABLES
    root = "indicators" if precise else "stixCyberObservables"
    emitted = 0

    async for block in _iter_page(
        client, query, root, settings.membership_bootstrap_page_size
    ):
        for edge in block.get("edges") or []:
            node = edge.get("node") or {}
            if precise:
                values = [
                    (o.get("node") or {}).get("observable_value")
                    for o in (node.get("observables") or {}).get("edges") or []
                ]
            else:
                values = [node.get("observable_value")]
            for value in values:
                if not value:
                    continue
                yield value
                emitted += 1
                if limit is not None and emitted >= limit:
                    return


async def build_membership(
    client: OpenCTIClient,
    settings: Settings,
    *,
    max_entries: int | None = None,
    name: str | None = None,
) -> tuple[MembershipSet, dict[str, object]]:
    """Bootstrap the membership set. Returns the set plus a report for logs."""
    started = time.perf_counter()

    indicators = await count_indicators(client)
    observables = await count_observables(client)
    ratio = (observables / indicators) if indicators else 0.0
    if ratio > RATIO_WARN_THRESHOLD and settings.membership_source == "observables":
        log.warning(
            "membership.lopsided_corpus",
            observables=observables,
            indicators=indicators,
            ratio=round(ratio, 2),
            hint="observables greatly outnumber indicators; the fast bootstrap "
            "path will produce more false positives. Set "
            "MEMBERSHIP_SOURCE=indicators for precision at ~17x slower bootstrap.",
        )

    values: list[str] = []
    truncated = False
    async for value in iter_values(client, settings, limit=max_entries):
        values.append(value)
        if max_entries is not None and len(values) >= max_entries:
            truncated = True
            break

    membership = MembershipSet.build(
        values,
        name=name,
        overlay_max=settings.membership_overlay_max,
        max_entries=max_entries,
    )
    elapsed = time.perf_counter() - started

    report: dict[str, object] = {
        "source": settings.membership_source,
        "indicators": indicators,
        "observables": observables,
        "ratio": round(ratio, 2),
        "values_loaded": len(values),
        "unique_packed": membership.packed_count,
        "bytes_shared": estimate_bytes(membership.packed_count),
        "truncated": truncated,
        "seconds": round(elapsed, 2),
        "values_per_sec": round(len(values) / elapsed) if elapsed else 0,
    }
    log.info("membership.bootstrapped", **report)
    return membership, report
