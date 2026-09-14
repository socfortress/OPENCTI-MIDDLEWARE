"""The seam between the API layer and however lookups actually resolve."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from ..indicators import Normalized

Payload = dict[str, str]


@dataclass(frozen=True, slots=True)
class LookupResult:
    payload: Payload
    source: str
    """Which tier answered: skip | membership | payload_cache | redis | opencti | degraded."""


class LookupBackend(Protocol):
    async def lookup(self, value: Normalized) -> LookupResult: ...
    async def ready(self) -> bool: ...
    def describe(self) -> dict[str, object]: ...
