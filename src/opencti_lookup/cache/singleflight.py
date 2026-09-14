"""Collapse concurrent identical lookups into one upstream call.

Without this, 500 simultaneous requests for a value that just fell out of
cache produce 500 OpenCTI queries. With it they produce one, and 499 awaits.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from typing import TypeVar

T = TypeVar("T")


class SingleFlight:
    __slots__ = ("_inflight",)

    def __init__(self) -> None:
        self._inflight: dict[str, asyncio.Future[object]] = {}

    async def do(self, key: str, fn: Callable[[], Awaitable[T]]) -> T:
        existing = self._inflight.get(key)
        if existing is not None:
            return await asyncio.shield(existing)  # type: ignore[return-value]

        loop = asyncio.get_running_loop()
        future: asyncio.Future[object] = loop.create_future()
        self._inflight[key] = future
        try:
            result = await fn()
        except BaseException as exc:
            if not future.done():
                future.set_exception(exc)
            raise
        else:
            if not future.done():
                future.set_result(result)
            return result
        finally:
            # Always drop the key, or a failure would wedge it permanently.
            self._inflight.pop(key, None)
            if future.done() and not future.cancelled():
                future.exception()  # mark retrieved, silence asyncio warning

    @property
    def inflight(self) -> int:
        return len(self._inflight)
