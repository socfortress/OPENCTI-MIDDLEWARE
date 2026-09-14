"""Packed membership set: "is this value in OpenCTI at all?" in ~1 microsecond.

Stores one 64-bit hash per indicator in a sorted ``numpy`` array backed by
``multiprocessing.shared_memory``, so the cost is 8 bytes per indicator
*total* rather than per worker. A plain Python ``set`` of 10M strings is
~1.1 GB in every worker; this is 80 MB once.

    corpus       packed set
    -----------  ----------
    17,767          140 KB
    1,000,000         8 MB
    10,000,000       80 MB
    50,000,000      400 MB

Lookups are ``bisect`` over a ``memoryview`` cast onto the shared buffer --
O(log n), about 26 comparisons at 50M, and measured ~2x faster than
``np.searchsorted``, whose Python->C call overhead dominates at this size.
NumPy is used to build and sort the array; the read path never touches it.

Hash collisions are possible but self-correcting: two distinct values sharing
a 64-bit hash (~0.007% likelihood across 50M entries) produce a false
"present", which triggers a payload fetch, which finds nothing, which is then
recorded as a miss. The cost is one wasted upstream query on a vanishingly
rare value -- a good trade for 8 bytes an entry.

Live-stream updates land in a small mutable overlay rather than rebuilding
the array: additions in a set, removals in a tombstone set. Both are bounded;
past ``overlay_max`` the caller is told to rebuild instead of letting them
grow without limit.
"""

from __future__ import annotations

import bisect
import contextlib
import hashlib
import threading
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from multiprocessing import shared_memory

import numpy as np

_DTYPE = np.uint64
_ITEMSIZE = 8


def fingerprint(value: str) -> np.uint64:
    """Stable 64-bit hash. Must not be Python's ``hash()``.

    ``hash()`` is randomized per process (PYTHONHASHSEED), so a value hashed
    in the builder would not match the same value hashed in a worker.
    """
    digest = hashlib.blake2b(value.encode("utf-8"), digest_size=8).digest()
    return np.uint64(int.from_bytes(digest, "big"))


def fingerprint_many(values: Iterable[str]) -> np.ndarray:
    return np.fromiter(
        (int(fingerprint(v)) for v in values), dtype=_DTYPE, count=-1
    )


@dataclass(frozen=True, slots=True)
class MembershipStats:
    packed: int
    added: int
    tombstoned: int
    bytes_shared: int

    @property
    def effective(self) -> int:
        return self.packed + self.added - self.tombstoned


class MembershipSet:
    """Read path for the packed set. Safe to share across threads.

    Instances are created either by :meth:`build` (which allocates the shared
    segment) or by :meth:`attach` (which maps one a builder already made).
    Only the builder should call :meth:`close` with ``unlink=True``.
    """

    __slots__ = (
        "_added",
        "_count",
        "_lock",
        "_owner",
        "_shm",
        "_tombstones",
        "_view",
        "overlay_max",
    )

    def __init__(
        self,
        shm: shared_memory.SharedMemory | None,
        count: int,
        *,
        owner: bool,
        overlay_max: int = 50_000,
    ) -> None:
        self._shm = shm
        self._count = count
        # SharedMemory rounds its allocation up to a page boundary, so the
        # raw buffer is longer than the data and the tail is zero-filled.
        # Slicing to `count` matters for correctness, not just tidiness: the
        # array is sorted ascending, so trailing zeros would break the
        # ordering bisect relies on and produce wrong answers.
        self._view: memoryview | None = (
            shm.buf.cast("Q")[:count] if shm is not None and count else None
        )
        self._added: set[int] = set()
        self._tombstones: set[int] = set()
        self._lock = threading.Lock()
        self._owner = owner
        self.overlay_max = overlay_max

    # ---------------------------------------------------------------- build

    @classmethod
    def build(
        cls,
        values: Iterable[str],
        *,
        name: str | None = None,
        overlay_max: int = 50_000,
        max_entries: int | None = None,
    ) -> MembershipSet:
        """Allocate a shared segment holding the sorted fingerprints.

        ``max_entries`` enforces the memory ceiling *while loading* rather
        than trusting a projected size -- Python memory estimates are
        unreliable enough that the cap has to be applied as we go.
        """
        seen: list[int] = []
        for value in values:
            if max_entries is not None and len(seen) >= max_entries:
                break
            seen.append(int(fingerprint(value)))

        arr = np.array(seen, dtype=_DTYPE)
        arr.sort()
        arr = np.unique(arr)

        if arr.size == 0:
            return cls(None, 0, owner=True, overlay_max=overlay_max)

        shm = shared_memory.SharedMemory(
            create=True, size=int(arr.size) * _ITEMSIZE, name=name
        )
        backing: np.ndarray = np.ndarray(arr.shape, dtype=_DTYPE, buffer=shm.buf)
        backing[:] = arr[:]
        return cls(shm, int(arr.size), owner=True, overlay_max=overlay_max)

    @classmethod
    def attach(cls, name: str, count: int, *, overlay_max: int = 50_000) -> MembershipSet:
        """Map a segment built by another process. Read-only usage.

        Detaches the segment from this process's ``resource_tracker`` first.
        CPython registers every SharedMemory a process touches -- including
        ones it merely attached to -- and unlinks them when that process
        exits (bpo-38119). Verified on 3.14: one reader exiting destroys the
        builder's segment for every other worker. Since the builder owns the
        lifecycle here, readers must not be tracked.
        """
        shm = shared_memory.SharedMemory(name=name, create=False)
        _untrack(shm)
        return cls(shm, count, owner=False, overlay_max=overlay_max)

    @classmethod
    def empty(cls) -> MembershipSet:
        return cls(None, 0, owner=True)

    # ----------------------------------------------------------------- read

    def __contains__(self, value: str) -> bool:
        fp = int(fingerprint(value))
        # Overlay first: a value added or removed since the last rebuild
        # must win over whatever the packed array says.
        if fp in self._tombstones:
            return False
        if fp in self._added:
            return True
        view = self._view
        if view is None:
            return False
        idx = bisect.bisect_left(view, fp)
        return idx < self._count and view[idx] == fp

    def __len__(self) -> int:
        return self._count + len(self._added) - len(self._tombstones)

    # ---------------------------------------------------------------- write

    def add(self, value: str) -> None:
        fp = int(fingerprint(value))
        with self._lock:
            self._tombstones.discard(fp)
            self._added.add(fp)

    def remove(self, value: str) -> None:
        fp = int(fingerprint(value))
        with self._lock:
            self._added.discard(fp)
            self._tombstones.add(fp)

    @property
    def overlay_full(self) -> bool:
        """True when the overlay has grown enough to warrant a rebuild."""
        return len(self._added) + len(self._tombstones) >= self.overlay_max

    # ----------------------------------------------------------------- meta

    @property
    def shm_name(self) -> str | None:
        return self._shm.name if self._shm is not None else None

    @property
    def packed_count(self) -> int:
        return self._count

    def stats(self) -> MembershipStats:
        return MembershipStats(
            packed=self._count,
            added=len(self._added),
            tombstoned=len(self._tombstones),
            bytes_shared=self._count * _ITEMSIZE,
        )

    def iter_packed(self) -> Iterator[int]:
        if self._view is not None:
            yield from self._view

    def close(self, *, unlink: bool | None = None) -> None:
        """Release the mapping. Only the builder should unlink."""
        if self._shm is None:
            return
        # Every exported buffer must be released before SharedMemory.close(),
        # or CPython raises BufferError.
        if self._view is not None:
            self._view.release()
            self._view = None
        should_unlink = self._owner if unlink is None else unlink
        try:
            self._shm.close()
            if should_unlink:
                self._shm.unlink()
        except FileNotFoundError:
            pass
        finally:
            self._shm = None


def _untrack(shm: shared_memory.SharedMemory) -> None:
    """Remove a segment from this process's resource_tracker registry.

    Without this a reader's exit unlinks the segment out from under every
    other worker. See MembershipSet.attach.
    """
    with contextlib.suppress(Exception):
        from multiprocessing import resource_tracker

        resource_tracker.unregister(f"/{shm.name}", "shared_memory")


def estimate_bytes(count: int) -> int:
    """Shared bytes a packed set of ``count`` indicators will occupy."""
    return count * _ITEMSIZE
