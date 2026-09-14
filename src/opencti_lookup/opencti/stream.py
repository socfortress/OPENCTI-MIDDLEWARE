"""Consume OpenCTI's SSE live stream to keep the membership set current.

Without this the set is a snapshot: correct at boot and drifting afterwards,
with new intel invisible until the next rebuild.

Event shape, verified against a live 7.26 instance:

    event: create | update | delete | merge
    id: 1789313330953-0
    data: {"data": {<STIX object>}, "scope": ..., "type": ..., "version": 4}

The useful part is that an **indicator** event carries its observable values
inline, under ``extensions[<ext-id>].observable_values`` as ``{type, value}``
pairs. So an indicator create needs no follow-up GraphQL call to learn which
values it covers. Observable events (``ipv4-addr``, ``domain-name``, ``url``,
``hostname``) carry a plain ``value``.

The ``id`` is a Redis stream id and doubles as the resume cursor: reconnecting
with ``?from=<id>`` replays everything after it, so a dropped connection costs
no events as long as it is re-established inside the stream's retention.

Every worker runs its own consumer. The alternative -- one consumer applying
to the shared segment -- does not work, because the membership overlay is
per-process Python state, not part of the shared mapping. SSE connections are
cheap and all workers converge on the same result.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import random
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from typing import Any

import httpx
import structlog
from httpx_sse import aconnect_sse

log = structlog.get_logger(__name__)

#: STIX types whose `value` is something we might be asked to look up.
OBSERVABLE_TYPES: frozenset[str] = frozenset(
    {"ipv4-addr", "ipv6-addr", "domain-name", "url", "hostname"}
)

ADD_EVENTS: frozenset[str] = frozenset({"create", "update", "merge"})
REMOVE_EVENTS: frozenset[str] = frozenset({"delete"})

#: OpenCTI emits these roughly every 6 seconds on an idle stream. They are the
#: difference between "connected but nothing is happening" and "the connection
#: has stalled" -- without them, a quiet night looks identical to a dead
#: stream and the backend would needlessly fall back to live queries.
#: `heartbeat` also carries the current stream id, so an idle connection keeps
#: the resume cursor moving forward.
HEARTBEAT_EVENTS: frozenset[str] = frozenset({"heartbeat"})

#: `consumer_metrics` reports OpenCTI's own view of how far behind we are,
#: which beats inferring it from wall-clock time.
METRICS_EVENTS: frozenset[str] = frozenset({"consumer_metrics"})


@dataclass
class StreamStats:
    connected: bool = False
    events_applied: int = 0
    events_skipped: int = 0
    adds: int = 0
    removes: int = 0
    reconnects: int = 0
    heartbeats: int = 0
    last_event_id: str | None = None
    last_error: str | None = None
    upstream_time_lag_s: float = 0.0
    """OpenCTI's own timeLag from consumer_metrics."""

    last_activity_at: float = field(default_factory=time.monotonic)
    """Any SSE traffic at all, heartbeats included. Liveness."""

    last_event_at: float = field(default_factory=time.monotonic)
    """Last event that actually changed the set. Informational only."""

    @property
    def activity_lag_s(self) -> float:
        """Seconds since ANY traffic arrived -- the staleness signal.

        Heartbeats arrive about every 6 seconds, so this staying low means the
        connection is genuinely alive even when no intel is changing.
        """
        return time.monotonic() - self.last_activity_at

    @property
    def event_lag_s(self) -> float:
        """Seconds since the set last changed.

        Deliberately NOT the staleness signal: on a quiet instance this grows
        without bound while the stream is perfectly healthy.
        """
        return time.monotonic() - self.last_event_at


def extract_values(payload: dict[str, Any]) -> Iterator[str]:
    """Observable values an event touches, from the event alone."""
    stix = payload.get("data")
    if not isinstance(stix, dict):
        return
    stix_type = stix.get("type")

    if stix_type == "indicator":
        for extension in (stix.get("extensions") or {}).values():
            if not isinstance(extension, dict):
                continue
            for observable in extension.get("observable_values") or []:
                if isinstance(observable, dict) and observable.get("value"):
                    yield str(observable["value"])
        return

    if stix_type in OBSERVABLE_TYPES and stix.get("value"):
        yield str(stix["value"])


class StreamConsumer:
    """Reconnecting SSE consumer that applies events to a membership set."""

    def __init__(
        self,
        *,
        url: str,
        token: str,
        on_add: Callable[[str], None],
        on_remove: Callable[[str], None],
        normalize: Callable[[str], str | None],
        verify_tls: bool = True,
        start_from: str | None = None,
        on_overlay_full: Callable[[], None] | None = None,
        overlay_full: Callable[[], bool] | None = None,
    ) -> None:
        self._url = url
        self._token = token
        self._on_add = on_add
        self._on_remove = on_remove
        self._normalize = normalize
        self._verify_tls = verify_tls
        self._cursor = start_from
        self._on_overlay_full = on_overlay_full
        self._overlay_full = overlay_full
        self.stats = StreamStats()
        self._stop = asyncio.Event()

    @property
    def cursor(self) -> str | None:
        return self._cursor

    def stop(self) -> None:
        self._stop.set()

    async def run(self) -> None:
        """Consume forever, reconnecting with jittered backoff."""
        backoff = 1.0
        while not self._stop.is_set():
            try:
                await self._consume_once()
                backoff = 1.0
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                self.stats.connected = False
                self.stats.last_error = str(exc)[:200]
                self.stats.reconnects += 1
                # Jitter so N workers do not reconnect in lockstep and
                # thunder against OpenCTI after a restart.
                delay = min(backoff, 60.0) * (0.5 + random.random())  # noqa: S311
                log.warning(
                    "stream.reconnecting",
                    error=self.stats.last_error,
                    delay_s=round(delay, 1),
                    cursor=self._cursor,
                )
                with contextlib.suppress(TimeoutError):
                    await asyncio.wait_for(self._stop.wait(), timeout=delay)
                backoff = min(backoff * 2, 60.0)

    async def _consume_once(self) -> None:
        params = {"from": self._cursor} if self._cursor else {}
        headers = {
            "Authorization": f"Bearer {self._token}",
            "Accept": "text/event-stream",
            "Cache-Control": "no-cache",
        }
        timeout = httpx.Timeout(connect=10.0, read=None, write=10.0, pool=10.0)

        async with (
            httpx.AsyncClient(verify=self._verify_tls, timeout=timeout) as client,
            aconnect_sse(
                client, "GET", self._url, params=params, headers=headers
            ) as source,
        ):
            self.stats.connected = True
            self.stats.last_error = None
            log.info("stream.connected", url=self._url, cursor=self._cursor)

            async for event in source.aiter_sse():
                if self._stop.is_set():
                    return
                self._handle(event.event, event.id, event.data)

    def _handle(self, kind: str, event_id: str | None, data: str) -> None:
        if event_id:
            self._cursor = event_id
            self.stats.last_event_id = event_id

        # Any traffic, including heartbeats, proves the connection is alive.
        self.stats.last_activity_at = time.monotonic()

        if kind in HEARTBEAT_EVENTS:
            self.stats.heartbeats += 1
            return
        if kind in METRICS_EVENTS:
            with contextlib.suppress(ValueError, TypeError, AttributeError):
                self.stats.upstream_time_lag_s = float(
                    json.loads(data).get("timeLag", 0.0)
                )
            return
        if kind == "connected":
            return
        if kind not in ADD_EVENTS and kind not in REMOVE_EVENTS:
            self.stats.events_skipped += 1
            return

        try:
            payload = json.loads(data)
        except ValueError:
            self.stats.events_skipped += 1
            return
        if not isinstance(payload, dict):
            self.stats.events_skipped += 1
            return

        touched = 0
        for raw in extract_values(payload):
            # Normalize with the same function the lookup path uses, or the
            # set ends up keyed inconsistently and the write is a false miss.
            normalized = self._normalize(raw)
            if normalized is None:
                continue
            if kind in REMOVE_EVENTS:
                self._on_remove(normalized)
                self.stats.removes += 1
            else:
                self._on_add(normalized)
                self.stats.adds += 1
            touched += 1

        if touched:
            self.stats.events_applied += 1
            self.stats.last_event_at = time.monotonic()
            if (
                self._overlay_full is not None
                and self._on_overlay_full is not None
                and self._overlay_full()
            ):
                # The overlay is unbounded growth if left alone; past the cap
                # the segment is rebuilt to fold it back in.
                self._on_overlay_full()
        else:
            self.stats.events_skipped += 1
