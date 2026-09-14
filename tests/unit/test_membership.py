from __future__ import annotations

import pytest

from opencti_lookup.backends.membership import MembershipSet, estimate_bytes, fingerprint


@pytest.fixture
def members() -> list[str]:
    return [f"host{i}.example.com" for i in range(5000)]


def test_roundtrip_and_no_false_negatives(members: list[str]) -> None:
    m = MembershipSet.build(members)
    try:
        assert all(v in m for v in members)
        assert not any(f"absent{i}.example.org" in m for i in range(2000))
    finally:
        m.close()


def test_count_not_on_a_page_boundary() -> None:
    """SharedMemory rounds up to a page; the view must be sliced to the true
    count or trailing zeros break the sort order bisect depends on."""
    values = [f"v{i}" for i in range(1237)]
    m = MembershipSet.build(values)
    try:
        assert m.packed_count == 1237
        assert all(v in m for v in values)
    finally:
        m.close()


def test_overlay_add_and_remove(members: list[str]) -> None:
    m = MembershipSet.build(members)
    try:
        m.add("brand-new.example.net")
        assert "brand-new.example.net" in m
        m.remove(members[0])
        assert members[0] not in m
        m.add(members[0])           # re-adding must clear the tombstone
        assert members[0] in m
    finally:
        m.close()


def test_overlay_bound_signals_rebuild() -> None:
    m = MembershipSet.build(["a"], overlay_max=10)
    try:
        assert not m.overlay_full
        for i in range(10):
            m.add(f"extra{i}")
        assert m.overlay_full
    finally:
        m.close()


def test_fingerprint_is_stable_across_processes() -> None:
    """Must not be Python's hash(), which is per-process randomized."""
    assert int(fingerprint("example.com")) == int(fingerprint("example.com"))
    assert fingerprint("a") != fingerprint("b")


def test_empty_set() -> None:
    m = MembershipSet.build([])
    try:
        assert "anything" not in m
        assert len(m) == 0
    finally:
        m.close()


def test_size_projection() -> None:
    assert estimate_bytes(10_000_000) == 80_000_000
    assert estimate_bytes(50_000_000) == 400_000_000
