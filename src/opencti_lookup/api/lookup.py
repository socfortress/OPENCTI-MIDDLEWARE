"""The endpoint Graylog calls."""

from __future__ import annotations

import time

from fastapi import APIRouter, Body, Depends, Query, Request

from ..indicators import normalize
from ..obs import metrics
from .deps import customer_code, verify_api_key

router = APIRouter()

MAX_BULK = 500


@router.get(
    "/lookup",
    dependencies=[Depends(verify_api_key)],
    summary="Look up one indicator",
)
async def lookup(
    request: Request,
    value: str = Query(..., min_length=1, max_length=2048),
    tenant: str | None = Depends(customer_code),
) -> dict[str, str]:
    """Always 200.

    A miss is `{"found": "false"}`, not a 404: Graylog's HTTPJSONPath adapter
    treats non-2xx as an adapter error, and misses are the common case, so
    404s would mean continuous error logging and a possibly-unhealthy adapter.
    """
    settings = request.app.state.settings
    backend = request.app.state.backend

    started = time.perf_counter()
    normalized = normalize(
        value, skip_private=settings.skip_private_ips, skip_tlds=settings.skip_tlds
    )
    result = await backend.lookup(normalized)
    elapsed = time.perf_counter() - started

    metrics.LOOKUP_LATENCY.labels(source=result.source).observe(elapsed)
    metrics.LOOKUPS.labels(
        result=result.payload.get("found", "false"),
        source=result.source,
        type=normalized.type.value,
    ).inc()
    if result.payload.get("degraded") == "true":
        metrics.DEGRADED.inc()

    if tenant:
        return {**result.payload, "customer_code": tenant}
    return result.payload


@router.post(
    "/lookup/bulk",
    dependencies=[Depends(verify_api_key)],
    summary="Look up many indicators",
)
async def lookup_bulk(
    request: Request, values: list[str] = Body(..., embed=True)
) -> dict[str, object]:
    """Batch lookup. Graylog's adapter can't use this; backfills and tests can."""
    settings = request.app.state.settings
    backend = request.app.state.backend

    trimmed = values[:MAX_BULK]
    results: dict[str, dict[str, str]] = {}
    for raw in trimmed:
        normalized = normalize(
            raw, skip_private=settings.skip_private_ips, skip_tlds=settings.skip_tlds
        )
        result = await backend.lookup(normalized)
        results[raw] = result.payload

    return {
        "count": str(len(results)),
        "truncated": "true" if len(values) > MAX_BULK else "false",
        "results": results,
    }
