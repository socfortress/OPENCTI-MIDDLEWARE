"""OpenCTI not answering at startup must not leave the process live-only.

Regression for issue #1: after a host reboot the middleware came up before
OpenCTI, the first membership load failed, and nothing ever retried it -- ~10h
of live-only answers until the container was restarted.
"""

from __future__ import annotations

import itertools
import json
import tempfile
import time
from collections.abc import Callable

import httpx
import respx
from fastapi.testclient import TestClient

from opencti_lookup.backends.shared_state import (
    SharedMembershipState,
    SharedStateDir,
    segment_name,
)
from opencti_lookup.config import Settings
from opencti_lookup.main import create_app

from ..conftest import API_KEY

GRAPHQL = "https://opencti.test/graphql"
AUTH = {"X-API-Key": API_KEY}
CORPUS = [f"bad{i}.example.com" for i in range(50)]
_GENERATION = itertools.count()


class Upstream:
    """OpenCTI that refuses connections until `up` is set."""

    def __init__(self, values: list[str]) -> None:
        self.values = values
        self.up = False
        self.refused = 0
        self.lookups = 0

    def __call__(self, request: httpx.Request) -> httpx.Response:
        if not self.up:
            self.refused += 1
            raise httpx.ConnectError("connection refused")
        query = json.loads(request.content)["query"]
        if "CountIndicators" in query:
            return self._data({"indicators": {"pageInfo": {"globalCount": len(self.values)}}})
        if "CountObservables" in query:
            return self._data(
                {"stixCyberObservables": {"pageInfo": {"globalCount": len(self.values)}}}
            )
        if "BootstrapObservables" in query:
            return self._data(
                {
                    "stixCyberObservables": {
                        "pageInfo": {"endCursor": None, "hasNextPage": False,
                                     "globalCount": len(self.values)},
                        "edges": [{"node": {"observable_value": v}} for v in self.values],
                    }
                }
            )
        self.lookups += 1
        return self._data({"stixCyberObservables": {"edges": []}})

    @staticmethod
    def _data(payload: dict) -> httpx.Response:
        return httpx.Response(200, json={"data": payload})


def _settings(settings: Settings, **overrides: object) -> Settings:
    return settings.model_copy(
        update={
            "membership_mode": "auto",
            "membership_shared": False,
            "mirror_max_memory_mb": 64,
            "payload_cache_max_mb": 8,
            "workers": 1,
            "stream_enabled": False,
            "redis_enabled": False,
            "membership_bootstrap_retry_s": 0.05,
            "membership_bootstrap_retry_max_s": 0.2,
            # Keep the breaker out of it: these tests are about the retry.
            "breaker_fail_threshold": 10_000,
            **overrides,
        }
    )


def _wait_for(predicate: Callable[[], bool], timeout_s: float = 5.0) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.02)
    raise AssertionError("condition not met in time")


@respx.mock
def test_failed_first_load_is_not_ready_and_answers_live(settings: Settings) -> None:
    upstream = Upstream(CORPUS)
    respx.post(GRAPHQL).mock(side_effect=upstream)

    with TestClient(create_app(_settings(settings))) as c:
        r = c.get("/readyz")
        assert r.status_code == 503
        assert r.json()["membership_role"] == "bootstrapping"

        # Lookups still work -- they go live and fail open while it's down.
        body = c.get("/lookup?value=8.8.8.8", headers=AUTH).json()
        assert body == {"found": "false", "degraded": "true"}

        # And it keeps trying rather than giving up after the first failure.
        seen = upstream.refused
        _wait_for(lambda: upstream.refused >= seen + 3)


@respx.mock
def test_membership_loads_once_opencti_comes_back(settings: Settings) -> None:
    upstream = Upstream(CORPUS)
    respx.post(GRAPHQL).mock(side_effect=upstream)

    with TestClient(create_app(_settings(settings))) as c:
        assert c.get("/readyz").status_code == 503

        upstream.up = True
        _wait_for(lambda: c.get("/readyz").status_code == 200)

        body = c.get("/readyz").json()
        assert body["membership_role"] == "solo"
        assert body["membership_packed"] == len(CORPUS)

        # A miss is now answered from the membership set, not from OpenCTI.
        before = upstream.lookups
        assert c.get("/lookup?value=8.8.8.8", headers=AUTH).json() == {"found": "false"}
        assert upstream.lookups == before

        # A member still goes live for its payload.
        c.get(f"/lookup?value={CORPUS[0]}", headers=AUTH)
        assert upstream.lookups == before + 1


@respx.mock
def test_recovered_builder_starts_the_reconciler(settings: Settings) -> None:
    """The reconciler was only ever created after a successful first load,
    which is why the hourly reconcile never rescued the process."""
    upstream = Upstream(CORPUS)
    respx.post(GRAPHQL).mock(side_effect=upstream)

    # A unique generation so the segment this builds can't collide with one
    # left behind by another test or a local run.
    base = 9700 + next(_GENERATION)
    state_dir = tempfile.mkdtemp(prefix="octi-boot-")
    SharedStateDir(state_dir).publish(
        SharedMembershipState(segment_name(base), 0, base, time.time(), 0)
    )

    app = create_app(
        _settings(settings, membership_shared=True, membership_state_dir=state_dir)
    )
    with TestClient(app) as c:
        assert app.state.reconciler is None

        upstream.up = True
        _wait_for(lambda: c.get("/readyz").status_code == 200)

        body = c.get("/readyz").json()
        assert body["membership_role"] == "builder"
        assert body["reconcile_generation"] == base + 1
        assert app.state.reconciler is not None


def test_membership_off_is_unaffected(settings: Settings) -> None:
    with TestClient(create_app(_settings(settings, membership_mode="off"))) as c:
        r = c.get("/readyz")
        assert r.status_code == 200
        assert r.json()["membership_role"] == "none"
        assert "membership_packed" not in r.json()
