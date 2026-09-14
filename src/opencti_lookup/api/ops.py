"""Health, readiness, metrics and config validation."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request, Response, status
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest

from ..obs import metrics
from .deps import verify_api_key

router = APIRouter()


@router.get("/healthz", summary="Liveness")
async def healthz() -> dict[str, str]:
    """Process is up. Deliberately never touches OpenCTI."""
    return {"status": "ok"}


def _stream_info(request: Request) -> dict[str, object]:
    stream = getattr(request.app.state, "stream", None)
    if stream is None:
        return {"stream": "disabled"}
    return {
        "stream": "connected" if stream.stats.connected else "disconnected",
        "stream_events_applied": stream.stats.events_applied,
        "stream_adds": stream.stats.adds,
        "stream_removes": stream.stats.removes,
        "stream_reconnects": stream.stats.reconnects,
        "stream_heartbeats": stream.stats.heartbeats,
        "stream_activity_lag_s": round(stream.stats.activity_lag_s, 1),
        "stream_event_lag_s": round(stream.stats.event_lag_s, 1),
        "stream_upstream_time_lag_s": stream.stats.upstream_time_lag_s,
        "stream_cursor": stream.stats.last_event_id,
        "stream_error": stream.stats.last_error,
    }


@router.get("/readyz", summary="Readiness")
async def readyz(request: Request, response: Response) -> dict[str, object]:
    backend = request.app.state.backend
    ready = await backend.ready()
    if not ready:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    reconciler = getattr(request.app.state, "reconciler", None)
    reconcile = reconciler.stats.describe() if reconciler else {"reconcile": "reader"}
    return {"ready": ready, **backend.describe(), **_stream_info(request), **reconcile}


@router.get("/metrics", summary="Prometheus metrics")
async def prometheus(request: Request) -> Response:
    backend = request.app.state.backend
    info = backend.describe()

    metrics.observe_breaker(str(info.get("breaker", "closed")))
    if "membership_effective" in info:
        metrics.MEMBERSHIP_SIZE.set(float(info["membership_effective"]))  # type: ignore[arg-type]
        metrics.MEMBERSHIP_BYTES.set(float(info["membership_bytes"]))  # type: ignore[arg-type]
    metrics.CACHE_ENTRIES.set(float(info.get("cache_entries", 0)))  # type: ignore[arg-type]
    metrics.CACHE_HIT_RATIO.set(float(info.get("cache_hit_ratio", 0.0)))  # type: ignore[arg-type]

    stream = getattr(request.app.state, "stream", None)
    if stream is not None:
        metrics.STREAM_CONNECTED.set(1.0 if stream.stats.connected else 0.0)
        metrics.MEMBERSHIP_LAG.set(stream.stats.activity_lag_s)
        metrics.STREAM_EVENTS.set(float(stream.stats.events_applied))
        metrics.STREAM_RECONNECTS.set(float(stream.stats.reconnects))

    return Response(generate_latest(metrics.REGISTRY), media_type=CONTENT_TYPE_LATEST)


@router.get(
    "/config/validate",
    dependencies=[Depends(verify_api_key)],
    summary="Validate configuration and upstream connectivity",
)
async def validate_config(request: Request) -> dict[str, object]:
    """Deployment aid, carried over from the app this replaces."""
    settings = request.app.state.settings
    client = request.app.state.opencti
    backend = request.app.state.backend

    checks: dict[str, str] = {}
    checks["api_key"] = (
        "ok" if len(settings.api_key.get_secret_value()) >= 32 else "weak (<32 chars)"
    )
    checks["opencti_url"] = "ok" if settings.opencti_url else "missing"
    checks["hit_policy"] = settings.hit_policy.value
    checks["domain_match_types"] = ",".join(settings.domain_match_types)

    try:
        version = await client.health()
        checks["opencti_connectivity"] = f"ok (v{version})"
    except Exception as exc:
        checks["opencti_connectivity"] = f"failed: {exc}"[:200]

    problems = [k for k, v in checks.items() if v.startswith(("failed", "missing", "weak"))]
    return {
        "status": "ready" if not problems else "issues",
        "problems": problems,
        "checks": checks,
        "backend": backend.describe(),
        "memory": request.app.state.memory_note,
    }
