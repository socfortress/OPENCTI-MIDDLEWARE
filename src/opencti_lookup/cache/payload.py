"""Byte-bounded payload cache.

`cachetools.TTLCache(maxsize=N)` counts *entries*, not bytes -- so a cache
sized for 200k entries could be 50 MB or 500 MB depending on payload. The
mapper caps each payload's field lengths, which turns a maxsize into a real
byte guarantee; this class derives maxsize from a byte budget so the two
stay consistent.

TTL here is only a backstop. Real freshness comes from the live stream, which
invalidates changed indicators precisely by key. When the stream is unhealthy
the TTL drops to a configured floor automatically.
"""

from __future__ import annotations

import time
from collections import OrderedDict
from dataclasses import dataclass

Payload = dict[str, str]


@dataclass(frozen=True, slots=True)
class CacheStats:
    entries: int
    max_entries: int
    hits: int
    misses: int
    evictions: int
    expirations: int
    approx_bytes: int

    @property
    def hit_ratio(self) -> float:
        total = self.hits + self.misses
        return self.hits / total if total else 0.0


class PayloadCache:
    """TTL + LRU cache with an entry ceiling derived from a byte budget.

    Not thread-safe by design: one instance per event loop, and every access
    happens on that loop.
    """

    __slots__ = (
        "_data",
        "_degraded",
        "_degraded_ttl",
        "_entry_bytes",
        "_evictions",
        "_expirations",
        "_hits",
        "_max_entries",
        "_misses",
        "_ttl",
    )

    def __init__(
        self,
        *,
        budget_bytes: int,
        max_entry_bytes: int = 1024,
        ttl_s: int = 86_400,
        degraded_ttl_s: int = 900,
    ) -> None:
        self._entry_bytes = max(1, max_entry_bytes)
        self._max_entries = max(1, budget_bytes // self._entry_bytes)
        self._ttl = ttl_s
        self._degraded_ttl = degraded_ttl_s
        self._degraded = False
        self._data: OrderedDict[str, tuple[Payload, float]] = OrderedDict()
        self._hits = self._misses = self._evictions = self._expirations = 0

    @property
    def max_entries(self) -> int:
        return self._max_entries

    def set_degraded(self, degraded: bool) -> None:
        """Shorten TTLs while the live stream can't be trusted to invalidate."""
        self._degraded = degraded

    @property
    def _active_ttl(self) -> int:
        return self._degraded_ttl if self._degraded else self._ttl

    def get(self, key: str) -> Payload | None:
        entry = self._data.get(key)
        if entry is None:
            self._misses += 1
            return None
        payload, expires_at = entry
        if expires_at <= time.monotonic():
            del self._data[key]
            self._expirations += 1
            self._misses += 1
            return None
        self._data.move_to_end(key)
        self._hits += 1
        return payload

    def set(self, key: str, payload: Payload) -> None:
        if key in self._data:
            del self._data[key]
        self._data[key] = (payload, time.monotonic() + self._active_ttl)
        while len(self._data) > self._max_entries:
            self._data.popitem(last=False)
            self._evictions += 1

    def invalidate(self, key: str) -> bool:
        """Precise invalidation, driven by the live stream."""
        return self._data.pop(key, None) is not None

    def clear(self) -> None:
        self._data.clear()

    def stats(self) -> CacheStats:
        return CacheStats(
            entries=len(self._data),
            max_entries=self._max_entries,
            hits=self._hits,
            misses=self._misses,
            evictions=self._evictions,
            expirations=self._expirations,
            approx_bytes=len(self._data) * self._entry_bytes,
        )
