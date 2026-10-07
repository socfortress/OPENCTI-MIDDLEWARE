"""Upstream failures must say what went wrong, even when httpx doesn't."""

from __future__ import annotations

import httpx
import pytest
import respx

from opencti_lookup.opencti.client import OpenCTIClient, OpenCTIError

GRAPHQL = "https://opencti.test/graphql"


@pytest.mark.parametrize(
    ("raised", "expected"),
    [
        # httpx raises timeouts with an empty message; this used to log as
        # error='timeout: ' and gave no clue which phase failed.
        (httpx.ConnectTimeout(""), "timeout: ConnectTimeout"),
        (httpx.ReadTimeout(""), "timeout: ReadTimeout"),
        (httpx.ConnectError(""), "connect failed: ConnectError"),
        # A real message is kept as-is.
        (httpx.ConnectError("refused"), "connect failed: refused"),
    ],
)
@respx.mock
async def test_error_message_is_never_empty(
    raised: httpx.HTTPError, expected: str
) -> None:
    respx.post(GRAPHQL).mock(side_effect=raised)
    client = OpenCTIClient(url=GRAPHQL, token="t")
    try:
        with pytest.raises(OpenCTIError) as info:
            await client.execute("{ about { version } }", retry_connect=False)
        assert str(info.value) == expected
        assert client.last_error is not None
        assert client.last_error.split(": ", 1)[1] == expected.split(": ", 1)[1]
    finally:
        await client.aclose()
