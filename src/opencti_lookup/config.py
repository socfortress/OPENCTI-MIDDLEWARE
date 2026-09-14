"""Settings, validated once at startup.

The service refuses to boot on a bad config with one readable message naming
every missing field, rather than raising a TypeError from inside a class body
the way the app this replaces did.
"""

from __future__ import annotations

from enum import StrEnum
from functools import lru_cache
from typing import Literal

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

MB = 1024 * 1024


class HitPolicy(StrEnum):
    """Which indicators count as a hit.

    Measured on OpenCTI 7.26: ``revoked`` is set automatically when
    ``valid_until`` passes, so the revoked and expired sets are identical
    unless a human has retracted something. ``live_only`` is therefore the
    only policy that excludes anything on a corpus without manual revocations.
    """

    LIVE_ONLY = "live_only"
    """Only ``revoked == false``."""

    EXPIRY_AWARE = "expiry_aware"
    """Everything except genuine human retractions (revoked while still valid)."""

    ALL = "all"
    """Every indicator; the pipeline rule does all filtering."""


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env", env_file_encoding="utf-8", extra="ignore", frozen=True
    )

    # ---------------------------------------------------------------- server
    app_host: str = "0.0.0.0"
    app_port: int = 8000
    workers: int = 4
    log_level: str = "INFO"
    log_format: Literal["json", "console"] = "json"

    # ------------------------------------------------------------------ auth
    api_key: SecretStr = Field(..., min_length=16)
    api_key_header: str = "X-API-Key"

    # --------------------------------------------------------------- opencti
    opencti_url: str = Field(...)
    opencti_token: SecretStr = Field(...)
    opencti_verify_tls: bool = True
    opencti_timeout_connect_ms: int = 1000
    opencti_timeout_read_ms: int = 1500
    opencti_max_connections: int = 50
    opencti_max_concurrency: int = 20

    # -------------------------------------------------------------- backend
    membership_mode: Literal["auto", "always", "off"] = "auto"
    # "observables" reads values directly (~3,500/sec). "indicators" walks the
    # indicator->observable relationship (~210/sec) for exactness. The fast
    # path's false positives self-correct via the payload query, so it is the
    # default unless observables greatly outnumber indicators.
    membership_source: Literal["observables", "indicators"] = "observables"
    membership_bootstrap_page_size: int = 2000
    membership_snapshot_interval_s: int = 300
    membership_stale_after_s: int = 900
    membership_reconcile_interval_s: int = 86_400
    membership_overlay_max: int = 50_000
    # Cross-worker sharing: one worker bootstraps and publishes the segment
    # name; the rest attach to it. Without this every uvicorn worker builds
    # its own copy -- N times the OpenCTI load and N copies of the segment.
    membership_shared: bool = True
    membership_state_dir: str = ""          # "" -> /dev/shm or the temp dir
    membership_attach_timeout_s: int = 300  # must exceed bootstrap time
    membership_attach_retry_s: int = 30     # background re-attach after a timeout

    # --------------------------------------------------------- memory budget
    mirror_max_memory_mb: int | Literal["auto"] = "auto"
    payload_cache_max_mb: int | Literal["auto"] = "auto"
    memory_fraction: float = Field(0.5, gt=0.0, le=1.0)
    memory_reserve_mb: int = 512
    payload_max_entry_bytes: int = 1024
    payload_ttl_s: int = 86_400
    payload_ttl_degraded_s: int = 900

    # -------------------------------------------------------- hit semantics
    hit_policy: HitPolicy = HitPolicy.EXPIRY_AWARE
    min_score: int = 0
    url_hostname_fallback: bool = True
    domain_match_types: tuple[str, ...] = ("Domain-Name", "Hostname")

    # ------------------------------------------------------------ resilience
    request_budget_ms: int = 2000
    breaker_fail_threshold: int = 5
    breaker_reset_s: int = 30

    # ----------------------------------------------------------------- redis
    redis_enabled: bool = True
    redis_url: str = "redis://redis:6379/0"
    redis_timeout_ms: int = 50
    cache_key_version: str = "v1"

    # ------------------------------------------------------------ skip lists
    skip_private_ips: bool = True
    skip_tlds: frozenset[str] = frozenset(
        {"local", "internal", "lan", "corp", "home", "arpa"}
    )

    # ------------------------------------------------------------ validators

    @field_validator("opencti_url")
    @classmethod
    def _clean_url(cls, v: str) -> str:
        v = v.rstrip("/")
        if not v.startswith(("http://", "https://")):
            raise ValueError("must start with http:// or https://")
        return v

    @field_validator("skip_tlds", "domain_match_types", mode="before")
    @classmethod
    def _split_csv(cls, v: object) -> object:
        if isinstance(v, str):
            return [part.strip().lower() for part in v.split(",") if part.strip()]
        return v

    @field_validator("mirror_max_memory_mb", "payload_cache_max_mb", mode="before")
    @classmethod
    def _auto_or_int(cls, v: object) -> object:
        if isinstance(v, str) and v.strip().lower() == "auto":
            return "auto"
        return v

    @model_validator(mode="after")
    def _budget_sanity(self) -> Settings:
        if self.opencti_timeout_read_ms >= self.request_budget_ms:
            raise ValueError(
                "opencti_timeout_read_ms must be below request_budget_ms, "
                f"got {self.opencti_timeout_read_ms} >= {self.request_budget_ms}"
            )
        return self

    # -------------------------------------------------------------- derived

    @property
    def state_dir(self) -> str:
        """Where the lock and state file live.

        /dev/shm is tmpfs on Linux and sits next to the segments themselves;
        it does not exist on macOS, so fall back to the temp dir there.
        """
        if self.membership_state_dir:
            return self.membership_state_dir
        import tempfile
        from pathlib import Path

        shm = Path("/dev/shm")  # noqa: S108 - the POSIX shm mount, not a temp dir
        base = shm if shm.is_dir() else Path(tempfile.gettempdir())
        return str(base / "opencti-lookup")

    @property
    def graphql_url(self) -> str:
        return f"{self.opencti_url}/graphql"

    @property
    def stream_url(self) -> str:
        return f"{self.opencti_url}/stream"

    def query_types_for(self, indicator_type: str) -> tuple[str, ...]:
        if indicator_type == "Domain-Name":
            return self.domain_match_types
        return (indicator_type,)


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()  # type: ignore[call-arg]
