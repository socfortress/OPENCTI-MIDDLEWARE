"""Async GraphQL client for OpenCTI.

Deliberately not `pycti`: that library is synchronous `requests`, so calling
it from an async handler blocks the event loop and caps concurrency at the
worker count. This talks to /graphql directly over a pooled httpx client.

Measured against a live 7.26 instance, a single lookup costs ~361 ms median
(326-394 ms over six cold queries) and a *miss* costs about the same as a hit.
That is OpenCTI's GraphQL and Elasticsearch overhead rather than data volume,
which is why the membership set in front of this matters so much.
"""

from __future__ import annotations

import asyncio
import enum
import time
from dataclasses import dataclass, field
from typing import Any

import httpx
import orjson
import structlog

log = structlog.get_logger(__name__)


class OpenCTIError(RuntimeError):
    """Upstream failed in a way the caller should treat as "no answer"."""


class BreakerOpenError(OpenCTIError):
    """Refused locally -- the breaker is open, no request was sent."""


class BreakerState(enum.StrEnum):
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


@dataclass
class CircuitBreaker:
    """Three-state breaker.

    The app this replaces set `available = False` on any exception and left it
    there until some later request happened to re-initialize the client. That
    is a latch, not a breaker: one malformed response disabled the source
    indefinitely. This recovers on its own via a half-open probe.
    """

    fail_threshold: int = 5
    reset_after_s: float = 30.0

    _state: BreakerState = BreakerState.CLOSED
    _failures: int = 0
    _opened_at: float = 0.0
    _lock: asyncio.Lock = field(default_factory=asyncio.Lock)

    @property
    def state(self) -> BreakerState:
        if self._state is BreakerState.OPEN and (
            time.monotonic() - self._opened_at >= self.reset_after_s
        ):
            return BreakerState.HALF_OPEN
        return self._state

    def allows(self) -> bool:
        return self.state is not BreakerState.OPEN

    async def record_success(self) -> None:
        async with self._lock:
            if self._state is not BreakerState.CLOSED:
                log.info("breaker.closed", previous=self._state)
            self._state = BreakerState.CLOSED
            self._failures = 0

    async def record_failure(self, reason: str) -> None:
        async with self._lock:
            self._failures += 1
            if self._failures >= self.fail_threshold and self._state is not BreakerState.OPEN:
                self._state = BreakerState.OPEN
                self._opened_at = time.monotonic()
                log.warning(
                    "breaker.opened", failures=self._failures, reason=reason,
                    reset_after_s=self.reset_after_s,
                )


class OpenCTIClient:
    """Pooled, bounded, breaker-guarded GraphQL client."""

    def __init__(
        self,
        *,
        url: str,
        token: str,
        verify_tls: bool = True,
        connect_timeout_ms: int = 1000,
        read_timeout_ms: int = 1500,
        max_connections: int = 50,
        max_concurrency: int = 20,
        breaker_fail_threshold: int = 5,
        breaker_reset_s: float = 30.0,
    ) -> None:
        self._url = url
        self._client = httpx.AsyncClient(
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
            timeout=httpx.Timeout(
                connect=connect_timeout_ms / 1000,
                read=read_timeout_ms / 1000,
                write=read_timeout_ms / 1000,
                pool=connect_timeout_ms / 1000,
            ),
            limits=httpx.Limits(
                max_connections=max_connections,
                max_keepalive_connections=max_connections,
                keepalive_expiry=90.0,
            ),
            verify=verify_tls,
        )
        self._semaphore = asyncio.Semaphore(max_concurrency)
        self.breaker = CircuitBreaker(
            fail_threshold=breaker_fail_threshold, reset_after_s=breaker_reset_s
        )
        self._last_error: str | None = None

    @property
    def last_error(self) -> str | None:
        return self._last_error

    async def execute(
        self, query: str, variables: dict[str, Any] | None = None, *, retry_connect: bool = True
    ) -> dict[str, Any]:
        """Run a GraphQL document. Raises OpenCTIError on any failure."""
        if not self.breaker.allows():
            raise BreakerOpenError("circuit breaker open")

        payload = orjson.dumps({"query": query, "variables": variables or {}})
        attempts = 2 if retry_connect else 1

        async with self._semaphore:
            for attempt in range(attempts):
                try:
                    response = await self._client.post(self._url, content=payload)
                except httpx.ConnectError as exc:
                    # Connection errors are worth one retry; a read timeout is
                    # not -- it has already spent the request budget, and
                    # retrying doubles load on an instance already struggling.
                    if attempt + 1 < attempts:
                        await asyncio.sleep(0.05)
                        continue
                    await self._fail(f"connect: {exc}")
                    raise OpenCTIError(f"connect failed: {exc}") from exc
                except httpx.TimeoutException as exc:
                    await self._fail(f"timeout: {exc}")
                    raise OpenCTIError(f"timeout: {exc}") from exc
                except httpx.HTTPError as exc:
                    await self._fail(f"http: {exc}")
                    raise OpenCTIError(f"http error: {exc}") from exc

                if response.status_code != 200:
                    await self._fail(f"status {response.status_code}")
                    raise OpenCTIError(f"unexpected status {response.status_code}")

                try:
                    body = orjson.loads(response.content)
                except orjson.JSONDecodeError as exc:
                    await self._fail("malformed json")
                    raise OpenCTIError("malformed json from OpenCTI") from exc

                if errors := body.get("errors"):
                    message = str(errors[0].get("message", errors[0]))[:200]
                    await self._fail(f"graphql: {message}")
                    raise OpenCTIError(f"graphql error: {message}")

                await self.breaker.record_success()
                self._last_error = None
                data: dict[str, Any] = body.get("data") or {}
                return data

        raise OpenCTIError("unreachable")

    async def _fail(self, reason: str) -> None:
        self._last_error = reason
        await self.breaker.record_failure(reason)

    async def health(self) -> str | None:
        from .queries import HEALTH

        data = await self.execute(HEALTH, retry_connect=False)
        version: str | None = (data.get("about") or {}).get("version")
        return version

    async def aclose(self) -> None:
        await self._client.aclose()
