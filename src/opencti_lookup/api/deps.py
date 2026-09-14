"""Auth and request-scoped dependencies."""

from __future__ import annotations

import hmac

from fastapi import Header, HTTPException, Request, status

from ..config import Settings


async def verify_api_key(request: Request, x_api_key: str | None = Header(None)) -> None:
    """Constant-time API key check.

    Two deliberate differences from the app this replaces: the comparison uses
    `hmac.compare_digest` rather than `!=`, and neither the supplied nor the
    expected token is ever logged -- the old version wrote the expected value
    to the log at DEBUG.
    """
    settings: Settings = request.app.state.settings
    expected = settings.api_key.get_secret_value()

    supplied = x_api_key
    if settings.api_key_header.lower() != "x-api-key":
        supplied = request.headers.get(settings.api_key_header)

    if not supplied:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"missing {settings.api_key_header} header",
        )
    if not hmac.compare_digest(supplied, expected):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="invalid API key"
        )


def customer_code(x_customer_code: str | None = Header(None)) -> str | None:
    """Optional tenant tag.

    Travels as a header rather than a second query parameter on purpose:
    Graylog URL-encodes the whole substituted key, so a second parameter
    arrives glued onto the value as `%26customer_code%3D...`. The app this
    replaces unpicked that with ~20 lines of string surgery in the route; a
    header removes the bug class instead of working around it.
    """
    return x_customer_code[:64] if x_customer_code else None
