"""Application factory and lifespan."""

from __future__ import annotations

import contextlib
from collections.abc import AsyncIterator

import structlog
from fastapi import FastAPI

from . import memory as memory_mod
from .api import lookup as lookup_routes
from .api import ops as ops_routes
from .backends.live import LiveBackend
from .backends.membership import MembershipSet, estimate_bytes
from .backends.split import SplitBackend
from .bootstrap import build_membership, count_observables
from .cache.payload import PayloadCache
from .config import Settings, get_settings
from .obs import logging as obs_logging
from .opencti.client import OpenCTIClient

log = structlog.get_logger(__name__)

MB = 1024 * 1024


def _resolve_budgets(settings: Settings) -> tuple[memory_mod.MemoryBudget, int, int, str]:
    """Split the detected budget between membership and payload cache."""
    override = (
        settings.mirror_max_memory_mb * MB
        if isinstance(settings.mirror_max_memory_mb, int)
        else None
    )
    budget = memory_mod.detect(
        workers=settings.workers,
        fraction=settings.memory_fraction,
        reserve_bytes=settings.memory_reserve_mb * MB,
        override_bytes=override,
    )

    if isinstance(settings.payload_cache_max_mb, int):
        payload_bytes = settings.payload_cache_max_mb * MB
    else:
        # Payload cache is per-worker; membership is shared, so it comes off
        # the shared total rather than the per-worker slice.
        payload_bytes = max(8 * MB, budget.per_worker // 4)

    membership_bytes = max(0, budget.usable - payload_bytes * settings.workers)
    note = (
        f"{budget.describe()} membership_budget={membership_bytes // MB}MB "
        f"payload_budget_per_worker={payload_bytes // MB}MB"
    )
    return budget, membership_bytes, payload_bytes, note


@contextlib.asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    settings: Settings = app.state.settings
    obs_logging.configure(settings.log_level, settings.log_format)

    _, membership_bytes, payload_bytes, note = _resolve_budgets(settings)
    app.state.memory_note = note
    log.info("memory.budget", detail=note)

    client = OpenCTIClient(
        url=settings.graphql_url,
        token=settings.opencti_token.get_secret_value(),
        verify_tls=settings.opencti_verify_tls,
        connect_timeout_ms=settings.opencti_timeout_connect_ms,
        read_timeout_ms=settings.opencti_timeout_read_ms,
        max_connections=settings.opencti_max_connections,
        max_concurrency=settings.opencti_max_concurrency,
        breaker_fail_threshold=settings.breaker_fail_threshold,
        breaker_reset_s=settings.breaker_reset_s,
    )
    app.state.opencti = client

    cache = PayloadCache(
        budget_bytes=payload_bytes,
        max_entry_bytes=settings.payload_max_entry_bytes,
        ttl_s=settings.payload_ttl_s,
        degraded_ttl_s=settings.payload_ttl_degraded_s,
    )
    live = LiveBackend(client=client, settings=settings, cache=cache)

    backend: object = live
    membership: MembershipSet | None = None

    if settings.membership_mode != "off":
        max_entries = membership_bytes // 8 if membership_bytes else 0
        try:
            corpus = await count_observables(client)
            projected = estimate_bytes(corpus)
            affordable = projected <= membership_bytes or settings.membership_mode == "always"
            log.info(
                "membership.sizing",
                corpus=corpus,
                projected_bytes=projected,
                budget_bytes=membership_bytes,
                affordable=affordable,
            )
            if affordable:
                membership, report = await build_membership(
                    client, settings, max_entries=max_entries or None
                )
                split = SplitBackend(membership=membership, live=live, settings=settings)
                split.mark_ready(True)
                backend = split
                app.state.bootstrap_report = report
            else:
                log.warning(
                    "membership.skipped_too_large",
                    corpus=corpus, projected_bytes=projected, budget_bytes=membership_bytes,
                )
        except Exception as exc:
            log.warning("membership.bootstrap_failed", error=str(exc))

    app.state.backend = backend
    app.state.membership = membership
    log.info("startup.complete", backend=backend.describe())  # type: ignore[attr-defined]

    try:
        yield
    finally:
        await client.aclose()
        if membership is not None:
            membership.close()
        log.info("shutdown.complete")


def create_app(settings: Settings | None = None) -> FastAPI:
    resolved = settings or get_settings()
    app = FastAPI(
        title="OpenCTI Lookup",
        description="Graylog lookup-table backend for OpenCTI indicator enrichment",
        version="0.1.0",
        lifespan=lifespan,
    )
    app.state.settings = resolved
    app.state.memory_note = "not resolved"
    app.include_router(lookup_routes.router, tags=["lookup"])
    app.include_router(ops_routes.router, tags=["ops"])
    return app


app = create_app  # uvicorn --factory opencti_lookup.main:app
