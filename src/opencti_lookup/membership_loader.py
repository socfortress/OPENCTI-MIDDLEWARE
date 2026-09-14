"""Decide, per worker, whether to build the membership set or attach to one.

`uvicorn --workers N` runs the lifespan in each worker independently. Left
alone, all N bootstrap from OpenCTI simultaneously and hold N copies of the
segment. One worker wins a file lock and builds; the rest attach.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Callable
from dataclasses import dataclass

import structlog

from .backends.membership import MembershipSet, estimate_bytes
from .backends.shared_state import (
    SharedMembershipState,
    SharedStateDir,
    segment_name,
)
from .bootstrap import build_membership, count_observables
from .config import Settings
from .opencti.client import OpenCTIClient

log = structlog.get_logger(__name__)


@dataclass
class LoadedMembership:
    membership: MembershipSet | None
    role: str
    """builder | reader | solo | none"""
    report: dict[str, object]
    state_dir: SharedStateDir | None = None


async def _build_and_publish(
    client: OpenCTIClient,
    settings: Settings,
    state_dir: SharedStateDir,
    *,
    max_entries: int | None,
) -> LoadedMembership:
    # A rebuild (for example after the previous builder was killed) must land
    # in a NEW segment. Readers may still be mapping the published one.
    previous = state_dir.read()
    generation = state_dir.next_generation()
    name = segment_name(generation)

    keep = {name} | ({previous.shm_name} if previous else set())
    removed = state_dir.sweep_stale_segments(keep=frozenset(keep))
    if removed:
        log.info("membership.swept_stale_segments", removed=removed, kept=sorted(keep))

    membership, report = await build_membership(
        client, settings, max_entries=max_entries, name=name
    )
    state_dir.publish(
        SharedMembershipState(
            shm_name=membership.shm_name or name,
            count=membership.packed_count,
            generation=generation,
            built_at=time.time(),
            corpus=int(report.get("observables") or 0),
        )
    )
    log.info(
        "membership.published",
        shm_name=membership.shm_name,
        count=membership.packed_count,
        generation=generation,
        superseded=previous.shm_name if previous else None,
    )
    report["generation"] = generation
    return LoadedMembership(membership, "builder", report, state_dir)


def _attach(state: SharedMembershipState, settings: Settings) -> MembershipSet | None:
    try:
        membership = MembershipSet.attach(
            state.shm_name, state.count, overlay_max=settings.membership_overlay_max
        )
    except (FileNotFoundError, OSError) as exc:
        log.warning("membership.attach_failed", shm_name=state.shm_name, error=str(exc))
        return None
    log.info(
        "membership.attached",
        shm_name=state.shm_name,
        count=state.count,
        generation=state.generation,
        bytes_shared=estimate_bytes(state.count),
    )
    return membership


async def load(
    client: OpenCTIClient, settings: Settings, *, budget_bytes: int
) -> LoadedMembership:
    """Build or attach, depending on who wins the lock."""
    max_entries = (budget_bytes // 8) or None

    corpus = await count_observables(client)
    projected = estimate_bytes(corpus)
    affordable = projected <= budget_bytes or settings.membership_mode == "always"
    log.info(
        "membership.sizing",
        corpus=corpus,
        projected_bytes=projected,
        budget_bytes=budget_bytes,
        affordable=affordable,
    )
    if not affordable:
        log.warning(
            "membership.skipped_too_large",
            corpus=corpus, projected_bytes=projected, budget_bytes=budget_bytes,
            hint="raise MIRROR_MAX_MEMORY_MB or the container memory limit",
        )
        return LoadedMembership(None, "none", {"reason": "too_large"})

    if not settings.membership_shared:
        membership, report = await build_membership(
            client, settings, max_entries=max_entries
        )
        return LoadedMembership(membership, "solo", report)

    state_dir = SharedStateDir(settings.state_dir)

    if state_dir.try_become_builder():
        # Hold the lock for the process lifetime so the role stays stable and
        # a later-starting worker attaches rather than rebuilding.
        try:
            return await _build_and_publish(
                client, settings, state_dir, max_entries=max_entries
            )
        except Exception:
            state_dir.release_builder()
            raise

    log.info("membership.waiting_for_builder", timeout_s=settings.membership_attach_timeout_s)
    state = await asyncio.to_thread(
        state_dir.wait_for, timeout_s=settings.membership_attach_timeout_s
    )
    if state is not None and (membership := _attach(state, settings)) is not None:
        return LoadedMembership(
            membership,
            "reader",
            {"attached_generation": state.generation, "unique_packed": state.count},
            state_dir,
        )

    # Falling back to building our own here would reintroduce exactly the
    # N-copies problem this exists to prevent, so serve via the live backend
    # instead and retry attaching in the background.
    log.warning(
        "membership.attach_timeout",
        timeout_s=settings.membership_attach_timeout_s,
        note="serving via live backend; will retry attaching in the background",
    )
    return LoadedMembership(None, "none", {"reason": "attach_timeout"}, state_dir)


async def watch_for_new_generation(
    state_dir: SharedStateDir,
    settings: Settings,
    on_attached: Callable[[MembershipSet], None],
    *,
    current_generation: int = 0,
) -> None:
    """Adopt a newly published segment.

    Covers two cases with one loop: a worker that timed out waiting for the
    first build (generation 0 -> 1), and a reader whose builder died and was
    replaced, publishing a higher generation. Without this, a rebuild leaves
    every existing reader pinned to the old data forever.
    """
    generation = current_generation
    while True:
        await asyncio.sleep(settings.membership_attach_retry_s)
        state = state_dir.read()
        if state is None or state.generation <= generation:
            continue
        membership = _attach(state, settings)
        if membership is None:
            continue
        log.info(
            "membership.generation_adopted",
            previous=generation,
            adopted=state.generation,
        )
        generation = state.generation
        on_attached(membership)
