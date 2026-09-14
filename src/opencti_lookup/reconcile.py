"""Periodic and on-demand rebuilds of the membership set.

Two things drift the set away from OpenCTI between bootstraps:

*Overlay growth.* Live-stream updates land in a per-process overlay of Python
sets, not in the shared segment. Left alone that grows without bound, and it
is never shared with the other workers.

*Silent divergence.* A missed event, a stream gap longer than retention, or a
bulk change applied directly in OpenCTI all leave the set subtly wrong with
nothing to signal it. Only a full reload can catch that.

So the builder rebuilds on whichever comes first: a scheduled interval, or the
overlay crossing its cap. Each rebuild publishes a new generation, which the
readers adopt through the watcher they already run.

Only the builder reconciles. Readers rebuilding independently would defeat the
point of sharing one segment.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field

import structlog

from .backends.shared_state import SharedMembershipState, SharedStateDir, segment_name
from .backends.split import SplitBackend
from .bootstrap import build_membership
from .config import Settings
from .opencti.client import OpenCTIClient

log = structlog.get_logger(__name__)


@dataclass
class ReconcileStats:
    rebuilds: int = 0
    failures: int = 0
    last_reason: str | None = None
    last_duration_s: float = 0.0
    last_at: float | None = None
    generation: int = 0
    running: bool = False
    pending_reason: str | None = field(default=None, repr=False)

    def describe(self) -> dict[str, object]:
        return {
            "reconcile_rebuilds": self.rebuilds,
            "reconcile_failures": self.failures,
            "reconcile_last_reason": self.last_reason,
            "reconcile_last_duration_s": round(self.last_duration_s, 2),
            "reconcile_age_s": (
                round(time.monotonic() - self.last_at, 1) if self.last_at else None
            ),
            "reconcile_generation": self.generation,
            "reconcile_running": self.running,
        }


class Reconciler:
    """Rebuilds the shared segment, in the builder process only."""

    def __init__(
        self,
        *,
        client: OpenCTIClient,
        settings: Settings,
        state_dir: SharedStateDir,
        backend: SplitBackend,
        budget_bytes: int,
        generation: int = 1,
    ) -> None:
        self._client = client
        self._settings = settings
        self._state_dir = state_dir
        self._backend = backend
        self._budget_bytes = budget_bytes
        self._trigger = asyncio.Event()
        self._stop = asyncio.Event()
        self.stats = ReconcileStats(generation=generation, last_at=time.monotonic())

    def request(self, reason: str) -> None:
        """Ask for a rebuild at the next opportunity. Safe to call repeatedly."""
        if self.stats.running:
            return
        self.stats.pending_reason = reason
        self._trigger.set()

    def stop(self) -> None:
        self._stop.set()
        self._trigger.set()

    async def run(self) -> None:
        interval = self._settings.membership_reconcile_interval_s
        while not self._stop.is_set():
            reason = "scheduled"
            try:
                await asyncio.wait_for(self._trigger.wait(), timeout=interval)
                if self._stop.is_set():
                    return
                reason = self.stats.pending_reason or "requested"
            except TimeoutError:
                pass
            finally:
                self._trigger.clear()
                self.stats.pending_reason = None

            try:
                await self._rebuild(reason)
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                # end the loop; the old segment stays serving and we retry.
                self.stats.failures += 1
                log.warning("reconcile.failed", reason=reason, error=str(exc)[:200])

    async def _rebuild(self, reason: str) -> None:
        self.stats.running = True
        started = time.perf_counter()
        previous = self._state_dir.read()
        generation = self._state_dir.next_generation()
        name = segment_name(generation)

        log.info(
            "reconcile.started",
            reason=reason,
            generation=generation,
            overlay=self._backend.membership.stats().added
            + self._backend.membership.stats().tombstoned,
        )

        try:
            # The old segment keeps serving for the whole of this. Nothing
            # swaps until the new one is complete.
            membership, report = await build_membership(
                self._client,
                self._settings,
                max_entries=(self._budget_bytes // 8) or None,
                name=name,
            )
        finally:
            self.stats.running = False

        self._state_dir.publish(
            SharedMembershipState(
                shm_name=membership.shm_name or name,
                count=membership.packed_count,
                generation=generation,
                built_at=time.time(),
                corpus=int(report.get("observables") or 0),
            )
        )

        # swap_membership carries the overlay forward: events that arrived
        # while the rebuild was running are not in the new snapshot.
        old_name = self._backend.membership.shm_name
        self._backend.swap_membership(membership)

        # Keep the generation just superseded -- other workers may still be
        # mapping it until their watcher picks up the new one.
        keep = {name}
        if previous:
            keep.add(previous.shm_name)
        if old_name:
            keep.add(old_name)
        removed = self._state_dir.sweep_stale_segments(keep=frozenset(keep))

        self.stats.rebuilds += 1
        self.stats.generation = generation
        self.stats.last_reason = reason
        self.stats.last_duration_s = time.perf_counter() - started
        self.stats.last_at = time.monotonic()

        log.info(
            "reconcile.completed",
            reason=reason,
            generation=generation,
            packed=membership.packed_count,
            seconds=round(self.stats.last_duration_s, 2),
            swept=removed,
        )
