"""Query-on-demand backend.

Used three ways: as the payload fetcher behind the membership set, as the
fallback while the membership set is still bootstrapping, and as the whole
backend when MEMBERSHIP_MODE=off or the corpus doesn't fit the budget.
"""

from __future__ import annotations

import structlog

from ..cache.payload import PayloadCache
from ..cache.singleflight import SingleFlight
from ..config import Settings
from ..indicators import IndicatorType, Normalized, url_hostname
from ..opencti.client import BreakerOpenError, OpenCTIClient, OpenCTIError
from ..opencti.mapper import DEGRADED, MISS, build_payload
from ..opencti.queries import LOOKUP, hash_filter, value_filter
from .base import LookupResult, Payload

log = structlog.get_logger(__name__)


class LiveBackend:
    def __init__(
        self, *, client: OpenCTIClient, settings: Settings, cache: PayloadCache
    ) -> None:
        self._client = client
        self._settings = settings
        self._cache = cache
        self._flight = SingleFlight()

    @property
    def cache(self) -> PayloadCache:
        return self._cache

    async def lookup(self, value: Normalized) -> LookupResult:
        if not value.lookupable:
            return LookupResult(MISS, "skip")

        key = f"{self._settings.cache_key_version}:{value.cache_key}"
        if (cached := self._cache.get(key)) is not None:
            return LookupResult(cached, "payload_cache")

        try:
            payload = await self._flight.do(key, lambda: self._fetch(value))
        except BreakerOpenError:
            return LookupResult(DEGRADED, "degraded")
        except OpenCTIError as exc:
            log.warning("lookup.upstream_failed", value=value.value, error=str(exc))
            return LookupResult(DEGRADED, "degraded")

        self._cache.set(key, payload)
        return LookupResult(payload, "opencti")

    async def fetch_payload(self, value: Normalized) -> Payload | None:
        """Resolve one value upstream. Returns None on a genuine miss."""
        payload = await self._fetch(value)
        return None if payload.get("found") != "true" else payload

    async def _fetch(self, value: Normalized) -> Payload:
        payload = await self._query(value.value, value.type, match_type="exact")
        if payload is not None:
            return payload

        # URL fallback: OpenCTI stores Url observables as exact strings, so a
        # logged URL with a query string rarely matches. Fall back to its
        # hostname, and say which matched via match_type.
        if (
            value.type is IndicatorType.URL
            and self._settings.url_hostname_fallback
            and (host := url_hostname(value.value))
        ):
            payload = await self._query(host, IndicatorType.DOMAIN, match_type="hostname")
            if payload is not None:
                payload["value"] = value.value
                payload["matched_value"] = host
                return payload

        return dict(MISS)

    async def _query(
        self, value: str, kind: IndicatorType, *, match_type: str
    ) -> Payload | None:
        algorithm = kind.hash_algorithm
        filters = (
            hash_filter(algorithm, value) if algorithm else value_filter(value)
        )
        data = await self._client.execute(
            LOOKUP,
            {
                "filters": filters,
                "types": list(self._settings.query_types_for(kind.value)),
            },
        )
        edges = (data.get("stixCyberObservables") or {}).get("edges") or []
        if not edges:
            return None
        node = edges[0].get("node") or {}
        return build_payload(
            node,
            self._settings,
            value=value,
            indicator_type=node.get("entity_type") or kind.value,
            match_type=match_type,
        )

    async def ready(self) -> bool:
        return self._client.breaker.allows()

    def describe(self) -> dict[str, object]:
        stats = self._cache.stats()
        return {
            "backend": "live",
            "breaker": self._client.breaker.state.value,
            "cache_entries": stats.entries,
            "cache_max_entries": stats.max_entries,
            "cache_hit_ratio": round(stats.hit_ratio, 4),
            "inflight": self._flight.inflight,
        }
