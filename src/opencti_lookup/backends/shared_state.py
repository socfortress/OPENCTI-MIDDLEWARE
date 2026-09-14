"""Coordinate one membership segment across uvicorn workers.

`uvicorn --workers N` spawns N independent processes, each running the full
lifespan. Without coordination every worker bootstraps its own copy: N times
the OpenCTI load at startup and N copies of the segment. At 50M indicators
that is 400 MB per worker instead of 400 MB total, which defeats the point of
using shared memory at all.

The protocol is a file lock plus a small state file:

  1. Every worker tries `flock(LOCK_EX | LOCK_NB)` on a lock file.
  2. The winner is the builder: it bootstraps from OpenCTI, publishes
     {shm_name, count, generation} to the state file, then releases the lock.
  3. Losers poll for the state file and attach to the named segment.
  4. If a loser times out waiting, it builds its own rather than serving
     nothing -- correctness beats memory efficiency.

This works under both fork and spawn, needs no changes to how uvicorn is
launched, and has no extra process to supervise.
"""

from __future__ import annotations

import contextlib
import fcntl
import json
import os
import tempfile
import time
from dataclasses import asdict, dataclass
from pathlib import Path

import structlog

log = structlog.get_logger(__name__)

STATE_FILENAME = "membership.json"
LOCK_FILENAME = "membership.lock"
SEGMENT_PREFIX = "octi_membership_"


@dataclass(frozen=True, slots=True)
class SharedMembershipState:
    shm_name: str
    count: int
    generation: int
    built_at: float
    corpus: int

    @property
    def age_s(self) -> float:
        return time.time() - self.built_at


class SharedStateDir:
    """The lock file and state file that let workers agree on one segment."""

    def __init__(self, directory: str | os.PathLike[str]) -> None:
        self.dir = Path(directory)
        self.dir.mkdir(parents=True, exist_ok=True)
        self.state_path = self.dir / STATE_FILENAME
        self.lock_path = self.dir / LOCK_FILENAME
        self._lock_fd: int | None = None

    # ------------------------------------------------------------- election

    def try_become_builder(self) -> bool:
        """Non-blocking exclusive lock. True means this process builds."""
        fd = os.open(self.lock_path, os.O_CREAT | os.O_RDWR, 0o644)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            os.close(fd)
            return False
        self._lock_fd = fd
        os.ftruncate(fd, 0)
        os.write(fd, str(os.getpid()).encode())
        return True

    def release_builder(self) -> None:
        if self._lock_fd is None:
            return
        try:
            fcntl.flock(self._lock_fd, fcntl.LOCK_UN)
        finally:
            os.close(self._lock_fd)
            self._lock_fd = None

    @property
    def is_builder(self) -> bool:
        return self._lock_fd is not None

    # ---------------------------------------------------------------- state

    def publish(self, state: SharedMembershipState) -> None:
        """Atomic publish -- readers never observe a half-written file."""
        fd, tmp = tempfile.mkstemp(dir=self.dir, prefix=".membership-", suffix=".tmp")
        try:
            with os.fdopen(fd, "w") as handle:
                json.dump(asdict(state), handle)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp, self.state_path)
        except BaseException:
            with contextlib.suppress(OSError):
                os.unlink(tmp)
            raise

    def read(self) -> SharedMembershipState | None:
        try:
            raw = json.loads(self.state_path.read_text())
        except (OSError, ValueError):
            return None
        try:
            return SharedMembershipState(**raw)
        except TypeError:
            return None

    def wait_for(
        self, *, timeout_s: float, poll_s: float = 0.25, min_generation: int = 0
    ) -> SharedMembershipState | None:
        """Poll until the builder publishes, or give up."""
        deadline = time.monotonic() + timeout_s
        while time.monotonic() < deadline:
            state = self.read()
            if state is not None and state.generation >= min_generation:
                return state
            time.sleep(poll_s)
        return self.read()

    def clear(self) -> None:
        with contextlib.suppress(OSError):
            self.state_path.unlink()

    # --------------------------------------------------------- housekeeping

    def next_generation(self) -> int:
        """Generation for the next build.

        Must increment: a rebuild has to land in a *new* segment so that
        readers still mapping the previous one are unaffected, and so they can
        detect that newer data exists.
        """
        current = self.read()
        return (current.generation + 1) if current else 1

    @staticmethod
    def sweep_stale_segments(keep: frozenset[str] = frozenset()) -> list[str]:
        """Remove segments left behind by a crashed previous run.

        Only meaningful on Linux, where POSIX shared memory is visible under
        /dev/shm. A hard kill leaves a segment allocated with nothing mapping
        it; without this they accumulate across restarts.

        `keep` is not optional in practice. Unlinking a segment that other
        workers are currently mapping does not break them -- POSIX keeps the
        mapping alive until the last process detaches -- but it does mean a
        worker starting a moment later cannot attach, and silently rebuilds.
        Always keep the currently-published generation and the one being
        built.
        """
        shm_dir = Path("/dev/shm")  # noqa: S108 - the POSIX shm mount, not a temp dir
        if not shm_dir.is_dir():
            return []
        removed: list[str] = []
        for entry in shm_dir.glob(f"{SEGMENT_PREFIX}*"):
            if entry.name in keep:
                continue
            with contextlib.suppress(OSError):
                entry.unlink()
                removed.append(entry.name)
        return removed


def segment_name(generation: int) -> str:
    """Deterministic per-generation name, so a rebuild is a new segment."""
    return f"{SEGMENT_PREFIX}{generation}"
