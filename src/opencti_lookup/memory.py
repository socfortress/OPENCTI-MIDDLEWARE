"""Memory budget detection.

Under Docker the host reports far more memory than the container may use.
``psutil.virtual_memory()`` sees the host's total; the cgroup limit is what
actually triggers the OOM killer. We read the cgroup first and take the
minimum, so a 2 GB container on a 64 GB host budgets against 2 GB.

Everything here produces a *default*. It is logged at startup and any
explicit setting overrides it -- silent autodetection that guesses wrong on
someone else's VM is close to impossible to debug remotely.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import psutil

# cgroup v2 reports the literal string "max" when no limit is set. cgroup v1
# reports a sentinel close to 2**63, which we treat the same way.
_CGROUP_V2 = Path("/sys/fs/cgroup/memory.max")
_CGROUP_V1 = Path("/sys/fs/cgroup/memory/memory.limit_in_bytes")
_V1_UNLIMITED = 1 << 62

MB = 1024 * 1024


def _read_cgroup_limit() -> int | None:
    """Bytes the cgroup permits, or None when unconstrained/unreadable."""
    for path in (_CGROUP_V2, _CGROUP_V1):
        try:
            raw = path.read_text().strip()
        except (OSError, ValueError):
            continue
        if raw == "max":
            continue
        try:
            value = int(raw)
        except ValueError:
            continue
        if 0 < value < _V1_UNLIMITED:
            return value
    return None


@dataclass(frozen=True, slots=True)
class MemoryBudget:
    """Resolved memory limits. All values in bytes."""

    detected_limit: int
    """The binding limit -- min(cgroup, host)."""

    source: str
    """Where ``detected_limit`` came from, for the startup log line."""

    usable: int
    """What we allow ourselves in total, after fraction and reserve."""

    per_worker: int
    """``usable`` divided across workers, for non-shared structures."""

    workers: int

    def describe(self) -> str:
        return (
            f"limit={self.detected_limit // MB}MB ({self.source}) "
            f"usable={self.usable // MB}MB "
            f"workers={self.workers} "
            f"per_worker={self.per_worker // MB}MB"
        )


def detect(
    *,
    workers: int,
    fraction: float = 0.5,
    reserve_bytes: int = 512 * MB,
    override_bytes: int | None = None,
) -> MemoryBudget:
    """Resolve how much memory this service may use.

    ``fraction`` applies after ``reserve_bytes`` is taken off the top, so the
    reserve is a true floor for the OS rather than something the fraction can
    eat into.
    """
    cgroup = _read_cgroup_limit()
    host = psutil.virtual_memory().total

    if cgroup is not None and cgroup < host:
        detected, source = cgroup, "cgroup"
    else:
        detected, source = host, "host"

    if override_bytes is not None:
        usable = override_bytes
    else:
        usable = max(0, int((detected - reserve_bytes) * fraction))

    # Never hand out more than actually exists, even via an override.
    usable = min(usable, max(0, detected - reserve_bytes))

    return MemoryBudget(
        detected_limit=detected,
        source=source,
        usable=usable,
        per_worker=usable // max(1, workers),
        workers=workers,
    )
