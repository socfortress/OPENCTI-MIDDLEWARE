"""Cross-worker sharing, exercised with real OS processes.

None of this can be verified in-process: the failure modes are a second
process winning a lock it shouldn't, and CPython's resource_tracker unlinking
a segment when a *reader* exits.
"""

from __future__ import annotations

import asyncio
import contextlib
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import pytest

from opencti_lookup.backends.membership import MembershipSet
from opencti_lookup.backends.shared_state import (
    SharedMembershipState,
    SharedStateDir,
    segment_name,
)
from opencti_lookup.config import Settings
from opencti_lookup.membership_loader import _attach, watch_for_new_generation

SRC = str(Path(__file__).resolve().parents[2] / "src")


def _run(code: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603
        [sys.executable, "-c", f"import sys; sys.path.insert(0, {SRC!r})\n{code}"],
        capture_output=True, text=True, timeout=60,
    )


@pytest.fixture
def state_dir() -> SharedStateDir:
    return SharedStateDir(tempfile.mkdtemp(prefix="octi-test-"))


def test_only_one_process_wins_the_builder_lock(state_dir: SharedStateDir) -> None:
    assert state_dir.try_become_builder() is True

    result = _run(f"""
from opencti_lookup.backends.shared_state import SharedStateDir
d = SharedStateDir({str(state_dir.dir)!r})
print("won" if d.try_become_builder() else "lost")
""")
    assert result.stdout.strip() == "lost", result.stderr

    state_dir.release_builder()
    result = _run(f"""
from opencti_lookup.backends.shared_state import SharedStateDir
d = SharedStateDir({str(state_dir.dir)!r})
print("won" if d.try_become_builder() else "lost")
""")
    assert result.stdout.strip() == "won", result.stderr


def test_reader_exit_does_not_destroy_the_segment() -> None:
    """CPython registers every SharedMemory a process touches and unlinks it
    on exit (bpo-38119) -- so a reader exiting would blank the set for every
    other worker. attach() must untrack."""
    name = segment_name(9101)
    owner = MembershipSet.build([f"v{i}" for i in range(500)], name=name)
    try:
        for _ in range(3):
            result = _run(f"""
from opencti_lookup.backends.membership import MembershipSet
m = MembershipSet.attach({name!r}, 500)
print("v250" in m)
m.close()
""")
            assert result.stdout.strip() == "True", result.stderr
        time.sleep(0.3)
        # The owner's segment must have survived all three readers exiting.
        assert "v250" in owner
        assert owner.packed_count == 500
    finally:
        owner.close()


def test_reader_sees_the_builders_data(state_dir: SharedStateDir) -> None:
    name = segment_name(9102)
    owner = MembershipSet.build(["known.example.com", "1.2.3.4"], name=name)
    try:
        state_dir.publish(
            SharedMembershipState(name, owner.packed_count, 1, time.time(), 2)
        )
        result = _run(f"""
from opencti_lookup.backends.shared_state import SharedStateDir
from opencti_lookup.backends.membership import MembershipSet
s = SharedStateDir({str(state_dir.dir)!r}).read()
m = MembershipSet.attach(s.shm_name, s.count)
print("known.example.com" in m, "absent.example.org" in m, m.packed_count)
m.close()
""")
        assert result.stdout.strip() == "True False 2", result.stderr
    finally:
        owner.close()


def test_publish_is_atomic(state_dir: SharedStateDir) -> None:
    """Readers poll this file; a half-written one must never be visible."""
    for generation in range(1, 40):
        state_dir.publish(
            SharedMembershipState(f"seg{generation}", generation * 10, generation, time.time(), 1)
        )
        loaded = state_dir.read()
        assert loaded is not None
        assert loaded.generation == generation
        assert loaded.count == generation * 10
    assert not list(state_dir.dir.glob(".membership-*.tmp"))


def test_wait_for_returns_once_published(state_dir: SharedStateDir) -> None:
    """A losing worker blocks on wait_for until the builder publishes."""
    script = (
        f"import sys, time; sys.path.insert(0, {SRC!r})\n"
        "from opencti_lookup.backends.shared_state import "
        "SharedStateDir, SharedMembershipState\n"
        "time.sleep(0.5)\n"
        f"SharedStateDir({str(state_dir.dir)!r}).publish("
        "SharedMembershipState('seg-late', 7, 1, time.time(), 7))"
    )
    with subprocess.Popen(  # noqa: S603
        [sys.executable, "-c", script],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    ) as publisher:
        started = time.monotonic()
        state = state_dir.wait_for(timeout_s=10, poll_s=0.1)
        elapsed = time.monotonic() - started
        publisher.communicate(timeout=10)

    assert state is not None
    assert state.shm_name == "seg-late"
    assert 0.4 < elapsed < 9  # actually waited, and did not time out


def test_wait_for_gives_up(state_dir: SharedStateDir) -> None:
    started = time.monotonic()
    assert state_dir.wait_for(timeout_s=0.5, poll_s=0.1) is None
    assert time.monotonic() - started >= 0.4


def test_swap_membership_does_not_unlink_a_shared_segment() -> None:
    """A reader swapping to a new generation must not destroy the old segment
    -- other workers may still be mapping it."""
    from opencti_lookup.backends.live import LiveBackend
    from opencti_lookup.backends.split import SplitBackend
    from opencti_lookup.cache.payload import PayloadCache
    from opencti_lookup.config import Settings
    from opencti_lookup.opencti.client import OpenCTIClient

    name = segment_name(9103)
    owner = MembershipSet.build(["a.example.com"], name=name)
    reader = MembershipSet.attach(name, owner.packed_count)
    settings = Settings(
        api_key="k" * 32,  # type: ignore[arg-type]
        opencti_url="https://opencti.test",
        opencti_token="t",  # type: ignore[arg-type]
    )
    split = SplitBackend(
        membership=reader,
        live=LiveBackend(
            client=OpenCTIClient(url="https://opencti.test/graphql", token="t"),
            settings=settings,
            cache=PayloadCache(budget_bytes=1024),
        ),
        settings=settings,
    )
    try:
        split.swap_membership(MembershipSet.build(["b.example.com"]))
        # Old segment must still be attachable by anyone else.
        again = MembershipSet.attach(name, owner.packed_count)
        assert "a.example.com" in again
        again.close()
        assert "b.example.com" in split.membership
    finally:
        split.membership.close()
        owner.close()


def test_generation_increments_and_names_a_new_segment(state_dir: SharedStateDir) -> None:
    """A rebuild must land in a new segment; readers may still map the old."""
    assert state_dir.next_generation() == 1
    state_dir.publish(SharedMembershipState(segment_name(1), 5, 1, time.time(), 5))
    assert state_dir.next_generation() == 2
    assert segment_name(1) != segment_name(2)


def test_sweep_never_removes_a_kept_segment() -> None:
    """Unlinking a segment other workers are mapping doesn't break them, but
    it does mean the next worker to start silently rebuilds instead."""
    if not Path("/dev/shm").is_dir():
        pytest.skip("POSIX shm not visible as files on this platform")

    live = MembershipSet.build(["a"], name=segment_name(7001))
    stale = MembershipSet.build(["b"], name=segment_name(7002))
    stale.close(unlink=False)  # simulate a crashed run: allocated, unmapped
    try:
        removed = SharedStateDir.sweep_stale_segments(
            keep=frozenset({segment_name(7001)})
        )
        assert segment_name(7002) in removed
        assert segment_name(7001) not in removed
        assert "a" in live  # untouched
    finally:
        live.close()
        with pytest.raises(FileNotFoundError):
            MembershipSet.attach(segment_name(7002), 1)


def _publish_empty_build(state_dir: SharedStateDir, generation: int) -> None:
    """Publish what the builder publishes for an empty corpus: the segment
    name it would have used, with no segment behind it."""
    built = MembershipSet.build([], name=segment_name(generation))
    assert built.shm_name is None  # SharedMemory cannot be zero bytes
    state_dir.publish(
        SharedMembershipState(
            built.shm_name or segment_name(generation), 0, generation, time.time(), 0
        )
    )


def test_reader_attaches_to_an_empty_corpus(
    state_dir: SharedStateDir, settings: Settings
) -> None:
    """A fresh OpenCTI has nothing to load when the middleware first starts.
    Readers used to retry mapping the recorded, never-created segment until
    the next non-empty rebuild (a day by default), staying unready."""
    _publish_empty_build(state_dir, generation=8101)
    state = state_dir.read()
    assert state is not None

    membership = _attach(state, settings)

    assert membership is not None
    assert len(membership) == 0
    assert "anything.example.com" not in membership
    # The stream keeps an attached reader current through its overlay
    membership.add("new.example.com")
    assert "new.example.com" in membership
    membership.close()


async def test_watcher_adopts_an_empty_generation(
    state_dir: SharedStateDir, settings: Settings
) -> None:
    """The stuck case seen in the field: a reader that found the empty build
    at startup must adopt it on its next background retry."""
    _publish_empty_build(state_dir, generation=1)
    adopted: list[MembershipSet] = []
    fast = settings.model_copy(update={"membership_attach_retry_s": 0})

    watcher = asyncio.create_task(
        watch_for_new_generation(state_dir, fast, adopted.append, current_generation=0)
    )
    try:
        for _ in range(200):
            if adopted:
                break
            await asyncio.sleep(0.01)
    finally:
        watcher.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await watcher

    assert len(adopted) == 1
    assert len(adopted[0]) == 0
