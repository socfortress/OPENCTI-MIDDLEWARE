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
from .reconcile import Reconciler

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
    reconciler: Reconciler | None = None
    stream: StreamConsumer | None = None
    tasks: list[asyncio.Task[None]] = []

    app.state.backend = backend
    app.state.membership = None
    app.state.reconciler = None
    app.state.stream = None

    # With membership on, this is the backend from the start. Until a set is
    # swapped in it is not ready: every lookup defers to live and /readyz
    # reports 503, so a failed first load is visible rather than silent.
    pending: SplitBackend | None = None
    if settings.membership_mode != "off":
        pending = SplitBackend(
            membership=MembershipSet.empty(), live=live, settings=settings
        )

    def _activate(
        target: SplitBackend, result: membership_loader.LoadedMembership
    ) -> None:
        """Wire up a completed load: inline at boot, or later from the retry."""
        nonlocal backend, membership, loaded, reconciler, stream
        loaded = result

        if result.membership is not None:
            membership = result.membership
            target.swap_membership(membership)
            backend = target
            app.state.bootstrap_report = result.report
            app.state.membership_role = result.role
        elif result.state_dir is not None:
            # Attach timed out. Serve via the live backend meanwhile -- building
            # our own here would reintroduce the N-copies problem this exists
            # to prevent -- and pick up the segment when it appears.
            backend = target
            app.state.membership_role = "attaching"
        else:
            # Corpus too large for the budget: the live backend is the service.
            backend = live
            app.state.membership_role = "none"

        app.state.backend = backend
        app.state.membership = membership
        if not isinstance(backend, SplitBackend):
            return
        split = backend

        # Readers follow the published generation: if the builder dies and is
        # replaced, the replacement publishes a NEW segment, and without this
        # every existing reader stays pinned to the old data forever.
        if result.state_dir is not None and result.role != "builder":

            def _adopt(new_membership: MembershipSet) -> None:
                split.swap_membership(new_membership)
                app.state.membership = new_membership
                app.state.membership_role = "reader"

            tasks.append(
                asyncio.create_task(
                    membership_loader.watch_for_new_generation(
                        result.state_dir,
                        settings,
                        _adopt,
                        current_generation=int(
                            result.report.get("attached_generation") or 0
                        ),
                    )
                )
            )

        # --- reconcile (builder only) -------------------------------------
        if result.role == "builder" and result.state_dir is not None:
            reconciler = Reconciler(
                client=client,
                settings=settings,
                state_dir=result.state_dir,
                backend=split,
                budget_bytes=membership_bytes,
                generation=int(result.report.get("generation") or 1),
            )
            tasks.append(asyncio.create_task(reconciler.run()))
            app.state.reconciler = reconciler

        # --- live stream ---------------------------------------------------
        if not settings.stream_enabled:
            return
        local_reconciler = reconciler

        def _overlay_full() -> None:
            # Only the builder can rebuild. A reader hitting its cap has to
            # wait for the builder's next generation, so say so rather than
            # warning every event from here on.
            if local_reconciler is not None:
                local_reconciler.request("overlay_full")
            else:
                log.warning(
                    "membership.overlay_full",
                    hint="reader at overlay cap; waiting for the builder's "
                    "next generation",
                )

        def _norm(value: str) -> str | None:
            parsed = normalize(
                value,
                skip_private=settings.skip_private_ips,
                skip_tlds=settings.skip_tlds,
            )
            return parsed.value if parsed.lookupable else None

        consumer = StreamConsumer(
            url=settings.stream_url,
            token=settings.opencti_token.get_secret_value(),
            on_add=lambda v: split.membership.add(v),
            on_remove=lambda v: split.membership.remove(v),
            normalize=_norm,
            verify_tls=settings.opencti_verify_tls,
            overlay_full=lambda: split.membership.overlay_full,
            on_overlay_full=lambda: _overlay_full(),
        )
        stream = consumer
        app.state.stream = consumer
        tasks.append(asyncio.create_task(consumer.run()))

        async def _watch_stream_health() -> None:
            while True:
                await asyncio.sleep(30)
                split.stream_health(
                    connected=consumer.stats.connected,
                    activity_lag_s=consumer.stats.activity_lag_s,
                    stale_after_s=settings.stream_stale_after_s,
                )

        tasks.append(asyncio.create_task(_watch_stream_health()))

    async def _retry_bootstrap(
        target: SplitBackend, attempt: int, delay: float
    ) -> None:
        # The reconciler only exists once a load has succeeded, so nothing
        # else would ever pick this up -- the process would stay live-only
        # until restarted.
        while True:
            await asyncio.sleep(delay)
            attempt += 1
            try:
                result = await membership_loader.load(
                    client, settings, budget_bytes=membership_bytes
                )
            except Exception as exc:
                delay = min(delay * 2, settings.membership_bootstrap_retry_max_s)
                log.warning(
                    "membership.load_failed",
                    attempt=attempt,
                    retry_in_s=delay,
                    error=str(exc),
                )
                continue
            log.info("membership.load_recovered", attempt=attempt)
            _activate(target, result)
            return

    if pending is not None:
        try:
            first = await membership_loader.load(
                client, settings, budget_bytes=membership_bytes
            )
        except Exception as exc:
            delay = min(
                settings.membership_bootstrap_retry_s,
                settings.membership_bootstrap_retry_max_s,
            )
            log.warning(
                "membership.load_failed", attempt=1, retry_in_s=delay, error=str(exc)
            )
            backend = pending
            app.state.backend = pending
            app.state.membership_role = "bootstrapping"
            tasks.append(asyncio.create_task(_retry_bootstrap(pending, 1, delay)))
        else:
            _activate(pending, first)

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
        if reconciler is not None:
            reconciler.stop()
        for task in list(tasks):
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
