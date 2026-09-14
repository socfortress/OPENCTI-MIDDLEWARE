"""The default backend: membership set in front, payload cache behind.

A lookup asks two questions with very different costs:

  "is this value in OpenCTI at all?"   8 bytes per indicator
  "what are its score/labels/validity?"  ~250 bytes per indicator

Since ~99% of a log stream is misses, and a miss is answered entirely by the
first question, only the cheap structure has to cover the whole corpus. The
expensive one is an ordinary bounded cache filled on demand -- you never need
payloads for 50M indicators, only for the few thousand your logs touch.

The consequence worth calling out: a miss allocates nothing. It never reaches
a cache, so unbounded miss traffic (a scanner, a noisy day) costs zero memory
permanently. That is the strongest memory-safety property in the design and
it falls out of the split for free.
"""

from __future__ import annotations

import structlog

from ..config import Settings
from ..indicators import IndicatorType, Normalized, url_hostname
from ..opencti.mapper import MISS
from .base import LookupResult
from .live import LiveBackend
from .membership import MembershipSet

log = structlog.get_logger(__name__)


class SplitBackend:
    def __init__(
        self,
        *,
        membership: MembershipSet,
        live: LiveBackend,
        settings: Settings,
    ) -> None:
        self._membership = membership
        self._live = live
        self._settings = settings
        self._ready = False
        self._stale = False

    def mark_ready(self, ready: bool = True) -> None:
        self._ready = ready

    def stream_health(
        self, *, connected: bool, activity_lag_s: float, stale_after_s: int
    ) -> None:
        """Fold live-stream health into staleness.

        Keyed on *activity* (heartbeats included), never on when an indicator
        last changed. OpenCTI heartbeats every ~6s, so silence past the
        threshold means the connection has stalled. Using event recency here
        instead would mark a healthy service stale on any quiet night and
        drop it to slow live queries for no reason.
        """
        self.mark_stale(not connected or activity_lag_s > stale_after_s)

    def mark_stale(self, stale: bool) -> None:
        """Stream lag past the threshold -- stop trusting the membership set."""
        if stale != self._stale:
            log.warning("membership.stale_changed", stale=stale)
        self._stale = stale
        self._live.cache.set_degraded(stale)

    @property
    def membership(self) -> MembershipSet:
        return self._membership

    def swap_membership(self, membership: MembershipSet, *, ready: bool = True) -> None:
        """Replace the membership set in place.

        Used when a worker attaches after an initial timeout, and by the
        rebuild path when a new generation is published. The old set is
        closed only if this process owned it -- a reader must never unlink a
        segment other workers are still mapping.
        """
        previous = self._membership
        if previous is not membership:
            # The new segment was built from a snapshot that may predate
            # events already in the old overlay; carry them over.
            membership.adopt_overlay(previous)
        self._membership = membership
        self._ready = ready
        if previous is not membership:
            previous.close(unlink=False)

    async def lookup(self, value: Normalized) -> LookupResult:
        if not value.lookupable:
            return LookupResult(MISS, "skip")

        # While bootstrapping or stale, the membership set can produce false
        # negatives, which are far worse than a slow answer. Defer to live.
        if not self._ready or self._stale:
            return await self._live.lookup(value)

        if value.value in self._membership:
            return await self._live.lookup(value)

        # URL fallback has to be checked against membership too, or a URL
        # whose hostname is known would be dismissed here.
        if (
            value.type is IndicatorType.URL
            and self._settings.url_hostname_fallback
            and (host := url_hostname(value.value))
            and host in self._membership
        ):
            return await self._live.lookup(value)

        # Definitive miss, answered from a fixed-size array. No allocation,
        # no network, no cache entry.
        return LookupResult(MISS, "membership")

    async def ready(self) -> bool:
        return self._ready and await self._live.ready()

    def describe(self) -> dict[str, object]:
        stats = self._membership.stats()
        return {
            "backend": "split",
            "ready": self._ready,
            "stale": self._stale,
            "membership_packed": stats.packed,
            "membership_added": stats.added,
            "membership_tombstoned": stats.tombstoned,
            "membership_effective": stats.effective,
            "membership_bytes": stats.bytes_shared,
            **self._live.describe(),
        }
