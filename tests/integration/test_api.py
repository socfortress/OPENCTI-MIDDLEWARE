"""API behaviour with OpenCTI mocked at the transport layer via respx."""

from __future__ import annotations

import httpx
import pytest
import respx
from fastapi.testclient import TestClient

from opencti_lookup.config import Settings
from opencti_lookup.main import create_app

from ..conftest import API_KEY

GRAPHQL = "https://opencti.test/graphql"
AUTH = {"X-API-Key": API_KEY}


def gql(payload: dict) -> httpx.Response:
    return httpx.Response(200, json={"data": payload})


def observable(indicators: list[dict]) -> dict:
    return {
        "stixCyberObservables": {
            "edges": [
                {
                    "node": {
                        "id": "obs-1", "entity_type": "IPv4-Addr",
                        "observable_value": "1.2.3.4", "x_opencti_score": 60,
                        "objectMarking": [],
                        "indicators": {"edges": [{"node": i} for i in indicators]},
                    }
                }
            ]
        }
    }


LIVE_INDICATOR = {
    "id": "ind-1", "name": "1.2.3.4", "pattern_type": "stix", "confidence": 90,
    "x_opencti_score": 75, "x_opencti_detection": False,
    "valid_from": "2026-01-01T00:00:00.000Z", "valid_until": "2099-01-01T00:00:00.000Z",
    "revoked": False, "objectLabel": [{"value": "c2"}], "objectMarking": [],
    "createdBy": {"name": "Feed"}, "killChainPhases": [],
}

EMPTY = {"stixCyberObservables": {"edges": []}}


@pytest.fixture
def client(settings: Settings):
    app = create_app(settings.model_copy(update={"membership_mode": "off"}))
    with TestClient(app) as c:
        yield c


@respx.mock
def test_hit(client: TestClient) -> None:
    respx.post(GRAPHQL).mock(return_value=gql(observable([LIVE_INDICATOR])))
    body = client.get("/lookup?value=1.2.3.4", headers=AUTH).json()
    assert body["found"] == "true"
    assert body["score"] == "75"
    assert body["expired"] == "false"
    assert body["match_type"] == "exact"


@respx.mock
def test_miss_is_200_not_404(client: TestClient) -> None:
    """Graylog's HTTPJSONPath adapter treats non-2xx as an adapter error, and
    misses are the common case."""
    respx.post(GRAPHQL).mock(return_value=gql(EMPTY))
    r = client.get("/lookup?value=1.2.3.4", headers=AUTH)
    assert r.status_code == 200
    assert r.json() == {"found": "false"}


@respx.mock
def test_private_ip_never_reaches_opencti(client: TestClient) -> None:
    route = respx.post(GRAPHQL).mock(return_value=gql(EMPTY))
    assert client.get("/lookup?value=10.0.0.1", headers=AUTH).json() == {"found": "false"}
    assert route.call_count == 0


@respx.mock
def test_payload_cache_prevents_a_second_upstream_call(client: TestClient) -> None:
    route = respx.post(GRAPHQL).mock(return_value=gql(observable([LIVE_INDICATOR])))
    for _ in range(5):
        client.get("/lookup?value=1.2.3.4", headers=AUTH)
    assert route.call_count == 1


@respx.mock
def test_upstream_failure_fails_open(client: TestClient) -> None:
    respx.post(GRAPHQL).mock(side_effect=httpx.ConnectError("refused"))
    r = client.get("/lookup?value=1.2.3.4", headers=AUTH)
    assert r.status_code == 200
    assert r.json() == {"found": "false", "degraded": "true"}


@respx.mock
def test_breaker_opens_and_stops_calling_upstream(settings: Settings) -> None:
    app = create_app(
        settings.model_copy(
            update={"membership_mode": "off", "breaker_fail_threshold": 3}
        )
    )
    route = respx.post(GRAPHQL).mock(side_effect=httpx.ConnectError("refused"))
    with TestClient(app) as c:
        for i in range(8):
            c.get(f"/lookup?value=9.9.9.{i}", headers=AUTH)
    # Threshold 3, each lookup retries the connect error once -> opens quickly
    # and then makes no further calls.
    assert route.call_count < 8 * 2


@respx.mock
def test_url_falls_back_to_hostname(client: TestClient) -> None:
    """OpenCTI stores Url observables exactly, so a logged URL with a query
    string rarely matches; the hostname usually does."""
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        import json
        body = json.loads(request.content)
        value = body["variables"]["filters"]["filters"][0]["values"][0]
        calls.append(value)
        if value == "bad.com":
            return gql(observable([LIVE_INDICATOR]))
        return gql(EMPTY)

    respx.post(GRAPHQL).mock(side_effect=handler)
    body = client.get("/lookup?value=http://bad.com/x?id=99", headers=AUTH).json()
    assert body["found"] == "true"
    assert body["match_type"] == "hostname"
    assert body["matched_value"] == "bad.com"
    assert calls == ["http://bad.com/x?id=99", "bad.com"]


@respx.mock
def test_domain_query_covers_both_storage_types(client: TestClient) -> None:
    """Measured: Domain-Name 8,124 / Hostname 2,867 -- querying only
    Domain-Name silently drops ~26% of the domain corpus."""
    seen: list[list[str]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        import json
        seen.append(json.loads(request.content)["variables"]["types"])
        return gql(EMPTY)

    respx.post(GRAPHQL).mock(side_effect=handler)
    client.get("/lookup?value=evil.com", headers=AUTH)
    assert seen[0] == ["Domain-Name", "Hostname"]


def test_auth(client: TestClient) -> None:
    assert client.get("/lookup?value=1.2.3.4").status_code == 401
    assert client.get("/lookup?value=1.2.3.4", headers={"X-API-Key": "no"}).status_code == 403


def test_customer_code_travels_as_a_header(client: TestClient) -> None:
    """Not a second query param: Graylog encodes the whole substituted key,
    so a second param arrives glued onto the value."""
    with respx.mock:
        respx.post(GRAPHQL).mock(return_value=gql(EMPTY))
        body = client.get(
            "/lookup?value=1.2.3.4", headers={**AUTH, "X-Customer-Code": "ACME"}
        ).json()
    assert body["customer_code"] == "ACME"


def test_healthz_needs_no_auth(client: TestClient) -> None:
    assert client.get("/healthz").json() == {"status": "ok"}
