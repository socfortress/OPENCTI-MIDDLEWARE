"""Application factory and lifespan."""

from __future__ import annotations

import asyncio
import contextlib
from collections.abc import AsyncIterator

import structlog
from fastapi import FastAPI

from . import membership_loader
from . import memory as memory_mod
from .api import lookup as lookup_routes
from .api import ops as ops_routes
from .backends.live import LiveBackend
from .backends.membership import MembershipSet
from .backends.split import SplitBackend
from .cache.payload import PayloadCache
from .config import Settings, get_settings
from .indicators import normalize
from .obs import logging as obs_logging
from .opencti.client import OpenCTIClient
from .opencti.stream import StreamConsumer

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
    loaded: membership_loader.LoadedMembership | None = None
    retry_task: asyncio.Task[None] | None = None

    if settings.membership_mode != "off":
        try:
            loaded = await membership_loader.load(
                client, settings, budget_bytes=membership_bytes
            )
        except Exception as exc:
            log.warning("membership.load_failed", error=str(exc))
            loaded = None

        if loaded is not None and loaded.membership is not None:
            membership = loaded.membership
            split = SplitBackend(membership=membership, live=live, settings=settings)
            split.mark_ready(True)
            backend = split
            app.state.bootstrap_report = loaded.report
            app.state.membership_role = loaded.role
        elif loaded is not None and loaded.state_dir is not None:
            # Attach timed out. Serve via the live backend meanwhile -- building
            # our own here would reintroduce the N-copies problem this exists
            # to prevent -- and pick up the segment when it appears.
            split = SplitBackend(
                membership=MembershipSet.empty(), live=live, settings=settings
            )
            backend = split
            app.state.membership_role = "attaching"

        # Readers follow the published generation: if the builder dies and is
        # replaced, the replacement publishes a NEW segment, and without this
        # every existing reader stays pinned to the old data forever.
        if (
            loaded is not None
            and loaded.state_dir is not None
            and loaded.role != "builder"
            and isinstance(backend, SplitBackend)
        ):
            watched = backend

            def _adopt(new_membership: MembershipSet) -> None:
                watched.swap_membership(new_membership)
                app.state.membership = new_membership
                app.state.membership_role = "reader"

            retry_task = asyncio.create_task(
                membership_loader.watch_for_new_generation(
                    loaded.state_dir,
                    settings,
                    _adopt,
                    current_generation=int(
                        loaded.report.get("attached_generation") or 0
                    ),
                )
            )

    # --- live stream -------------------------------------------------------
    stream: StreamConsumer | None = None
    stream_task: asyncio.Task[None] | None = None
    health_task: asyncio.Task[None] | None = None

    if settings.stream_enabled and isinstance(backend, SplitBackend):
        watched_backend = backend

        def _norm(value: str) -> str | None:
            parsed = normalize(
                value,
                skip_private=settings.skip_private_ips,
                skip_tlds=settings.skip_tlds,
            )
            return parsed.value if parsed.lookupable else None

        stream = StreamConsumer(
            url=settings.stream_url,
            token=settings.opencti_token.get_secret_value(),
            on_add=lambda v: watched_backend.membership.add(v),
            on_remove=lambda v: watched_backend.membership.remove(v),
            normalize=_norm,
            verify_tls=settings.opencti_verify_tls,
            overlay_full=lambda: watched_backend.membership.overlay_full,
            on_overlay_full=lambda: log.warning(
                "membership.overlay_full",
                hint="rebuild needed to fold pending stream updates back in",
            ),
        )
        stream_task = asyncio.create_task(stream.run())

        async def _watch_stream_health() -> None:
            while True:
                await asyncio.sleep(30)
                watched_backend.stream_health(
                    connected=stream.stats.connected,  # type: ignore[union-attr]
                    activity_lag_s=stream.stats.activity_lag_s,  # type: ignore[union-attr]
                    stale_after_s=settings.stream_stale_after_s,
                )

        health_task = asyncio.create_task(_watch_stream_health())

    app.state.stream = stream
    app.state.backend = backend
    app.state.membership = membership
    log.info(
        "startup.complete",
        role=getattr(app.state, "membership_role", "none"),
        backend=backend.describe(),  # type: ignore[attr-defined]
    )

    try:
        yield
    finally:
        if stream is not None:
            stream.stop()
        for task in (stream_task, health_task, retry_task):
            if task is None:
                continue
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task
        await client.aclose()
        current: MembershipSet | None = getattr(app.state, "membership", membership)
        if current is not None:
            current.close()
        if loaded is not None and loaded.state_dir is not None:
            loaded.state_dir.release_builder()
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
