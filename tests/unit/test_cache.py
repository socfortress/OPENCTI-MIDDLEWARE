from __future__ import annotations

from opencti_lookup.cache.payload import PayloadCache


def test_maxsize_derives_from_byte_budget() -> None:
    cache = PayloadCache(budget_bytes=100 * 1024, max_entry_bytes=1024)
    assert cache.max_entries == 100


def test_lru_evicts_at_the_ceiling() -> None:
    cache = PayloadCache(budget_bytes=3 * 1024, max_entry_bytes=1024)
    for i in range(10):
        cache.set(f"k{i}", {"found": "true"})
    stats = cache.stats()
    assert stats.entries == 3
    assert stats.evictions == 7
    assert cache.get("k0") is None
    assert cache.get("k9") is not None


def test_precise_invalidation() -> None:
    """The live stream invalidates changed indicators by key; TTL is a backstop."""
    cache = PayloadCache(budget_bytes=1024 * 1024)
    cache.set("a", {"found": "true"})
    assert cache.invalidate("a") is True
    assert cache.get("a") is None
    assert cache.invalidate("a") is False


def test_degraded_mode_shortens_ttl() -> None:
    cache = PayloadCache(budget_bytes=1024 * 1024, ttl_s=86400, degraded_ttl_s=1)
    cache.set_degraded(True)
    cache.set("a", {"found": "true"})
    # entry exists now, but was written with the short TTL
    assert cache.get("a") is not None


def test_hit_ratio() -> None:
    cache = PayloadCache(budget_bytes=1024 * 1024)
    cache.set("a", {"found": "true"})
    cache.get("a")
    cache.get("a")
    cache.get("missing")
    assert cache.stats().hit_ratio == 2 / 3
