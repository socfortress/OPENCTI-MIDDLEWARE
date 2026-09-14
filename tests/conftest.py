from __future__ import annotations

import os

import pytest

os.environ.setdefault("API_KEY", "k" * 32)
os.environ.setdefault("OPENCTI_URL", "https://opencti.test")
os.environ.setdefault("OPENCTI_TOKEN", "token")
os.environ.setdefault("MEMBERSHIP_MODE", "off")
os.environ.setdefault("LOG_LEVEL", "ERROR")

from opencti_lookup.config import Settings

API_KEY = "k" * 32


@pytest.fixture
def settings() -> Settings:
    return Settings(
        api_key=API_KEY,  # type: ignore[arg-type]
        opencti_url="https://opencti.test",
        opencti_token="token",  # type: ignore[arg-type]
    )
