"""Prometheus metrics. Replaces the hand-rolled dict of lists in the old app."""

from __future__ import annotations

from prometheus_client import CollectorRegistry, Counter, Gauge, Histogram

REGISTRY = CollectorRegistry(auto_describe=True)

LOOKUPS = Counter(
    "opencti_lookup_requests_total",
    "Lookup requests by outcome and which tier answered.",
    ["result", "source", "type"],
    registry=REGISTRY,
)

LOOKUP_LATENCY = Histogram(
    "opencti_lookup_duration_seconds",
    "End-to-end lookup latency by answering tier.",
    ["source"],
    # Spans microseconds (membership) to hundreds of ms (OpenCTI).
    buckets=(0.000_005, 0.000_05, 0.000_5, 0.005, 0.05, 0.1, 0.25, 0.5, 1.0, 2.0),
    registry=REGISTRY,
)

UPSTREAM_LATENCY = Histogram(
    "opencti_upstream_duration_seconds",
    "OpenCTI GraphQL round-trip latency.",
    buckets=(0.05, 0.1, 0.2, 0.35, 0.5, 0.75, 1.0, 1.5, 2.0, 5.0),
    registry=REGISTRY,
)

BREAKER_STATE = Gauge(
    "opencti_breaker_state",
    "Circuit breaker: 0 closed, 1 half-open, 2 open.",
    registry=REGISTRY,
)

DEGRADED = Counter(
    "opencti_lookup_degraded_total",
    "Lookups answered as degraded misses because upstream was unavailable.",
    registry=REGISTRY,
)

MEMBERSHIP_SIZE = Gauge(
    "opencti_membership_entries", "Indicators in the membership set.", registry=REGISTRY
)
MEMBERSHIP_BYTES = Gauge(
    "opencti_membership_bytes", "Shared bytes held by the membership set.", registry=REGISTRY
)
MEMBERSHIP_LAG = Gauge(
    "opencti_membership_lag_seconds",
    "Seconds since the last live-stream event was applied.",
    registry=REGISTRY,
)

CACHE_ENTRIES = Gauge(
    "opencti_payload_cache_entries", "Entries in the payload cache.", registry=REGISTRY
)
CACHE_BYTES = Gauge(
    "opencti_payload_cache_bytes", "Approximate payload cache size.", registry=REGISTRY
)
CACHE_EVICTIONS = Gauge(
    "opencti_payload_cache_evictions_total", "LRU evictions.", registry=REGISTRY
)
CACHE_HIT_RATIO = Gauge(
    "opencti_payload_cache_hit_ratio", "Payload cache hit ratio.", registry=REGISTRY
)

_BREAKER_VALUES = {"closed": 0, "half_open": 1, "open": 2}


def observe_breaker(state: str) -> None:
    BREAKER_STATE.set(_BREAKER_VALUES.get(state, 0))
