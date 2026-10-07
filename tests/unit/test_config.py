"""Settings parsing, especially from a real .env file.

The CSV fields are the interesting ones: pydantic-settings JSON-decodes
complex types (list/tuple/set) inside the env source, *before* any field
validator runs, so a plain "a,b,c" value raises SettingsError unless the
field opts out with NoDecode. Passing env vars individually in a test never
exercises this -- only loading the shipped .env.example does, which is how it
reached a published image.
"""

from __future__ import annotations

import pathlib

import pytest

from opencti_lookup.config import HitPolicy, Settings

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]


def _write_env(tmp_path: pathlib.Path, body: str) -> pathlib.Path:
    env = tmp_path / ".env"
    env.write_text(body)
    return env


def test_csv_fields_parse_from_env_file(tmp_path: pathlib.Path) -> None:
    env = _write_env(
        tmp_path,
        "API_KEY=" + "k" * 32 + "\n"
        "OPENCTI_URL=https://opencti.example.com\n"
        "OPENCTI_TOKEN=token\n"
        "DOMAIN_MATCH_TYPES=Domain-Name,Hostname\n"
        "SKIP_TLDS=local,internal,lan\n",
    )
    settings = Settings(_env_file=env)  # type: ignore[call-arg]
    assert settings.domain_match_types == ("Domain-Name", "Hostname")
    assert settings.skip_tlds == frozenset({"local", "internal", "lan"})


def test_entity_types_keep_their_case(tmp_path: pathlib.Path) -> None:
    env = _write_env(
        tmp_path,
        "API_KEY=" + "k" * 32 + "\nOPENCTI_URL=https://x.test\nOPENCTI_TOKEN=t\n"
        "DOMAIN_MATCH_TYPES=Domain-Name, Hostname , IPv4-Addr\n",
    )
    settings = Settings(_env_file=env)  # type: ignore[call-arg]
    assert settings.domain_match_types == ("Domain-Name", "Hostname", "IPv4-Addr")


def test_tlds_are_folded(tmp_path: pathlib.Path) -> None:
    env = _write_env(
        tmp_path,
        "API_KEY=" + "k" * 32 + "\nOPENCTI_URL=https://x.test\nOPENCTI_TOKEN=t\n"
        "SKIP_TLDS=LOCAL,Internal\n",
    )
    settings = Settings(_env_file=env)  # type: ignore[call-arg]
    assert settings.skip_tlds == frozenset({"local", "internal"})


def test_the_shipped_env_example_actually_loads(tmp_path: pathlib.Path) -> None:
    """The file every deployment starts from must produce valid settings.

    This is the regression test for a published image that crash-looped on
    boot: .env.example sets DOMAIN_MATCH_TYPES and SKIP_TLDS as CSV, and
    nothing else in the suite loaded it.
    """
    example = (REPO_ROOT / ".env.example").read_text()
    # Fill in only what the file deliberately leaves blank.
    body = example.replace("API_KEY=\n", "API_KEY=" + "k" * 32 + "\n").replace(
        "OPENCTI_TOKEN=\n", "OPENCTI_TOKEN=token\n"
    )
    settings = Settings(_env_file=_write_env(tmp_path, body))  # type: ignore[call-arg]

    assert settings.domain_match_types == ("Domain-Name", "Hostname")
    assert "local" in settings.skip_tlds
    assert settings.hit_policy is HitPolicy.EXPIRY_AWARE
    assert settings.workers >= 1


def test_read_timeout_must_fit_inside_the_request_budget(tmp_path: pathlib.Path) -> None:
    env = _write_env(
        tmp_path,
        "API_KEY=" + "k" * 32 + "\nOPENCTI_URL=https://x.test\nOPENCTI_TOKEN=t\n"
        "OPENCTI_TIMEOUT_READ_MS=5000\nREQUEST_BUDGET_MS=2000\n",
    )
    with pytest.raises(ValueError, match="request_budget_ms"):
        Settings(_env_file=env)  # type: ignore[call-arg]


def test_stream_url_defaults_to_the_generic_stream(tmp_path: pathlib.Path) -> None:
    env = _write_env(
        tmp_path,
        "API_KEY=" + "k" * 32 + "\n"
        "OPENCTI_URL=https://opencti.example.com\n"
        "OPENCTI_TOKEN=token\n"
        # Present but empty, as in a copied .env.example: still generic.
        "OPENCTI_STREAM_ID=\n",
    )
    settings = Settings(_env_file=env)  # type: ignore[call-arg]
    assert settings.opencti_stream_id is None
    assert settings.stream_url == f"{settings.opencti_url}/stream"


def test_stream_id_selects_a_named_live_stream(tmp_path: pathlib.Path) -> None:
    """The generic stream is BYPASS-only; a named one lets a least-privilege
    token keep real-time membership (issue #2)."""
    stream_id = "4b6e5a3c-1d2f-4e8a-9b7c-0d1e2f3a4b5c"
    env = _write_env(
        tmp_path,
        "API_KEY=" + "k" * 32 + "\n"
        "OPENCTI_URL=https://opencti.example.com\n"
        "OPENCTI_TOKEN=token\n"
        f"OPENCTI_STREAM_ID= {stream_id} \n",
    )
    settings = Settings(_env_file=env)  # type: ignore[call-arg]
    assert settings.stream_url == f"{settings.opencti_url}/stream/{stream_id}"


@pytest.mark.parametrize(
    "bad",
    [
        "https://opencti.example.com/stream/4b6e5a3c",
        "../graphql",
        "4b6e5a3c?from=0",
    ],
)
def test_stream_id_must_be_an_id_not_a_url(settings: Settings, bad: str) -> None:
    with pytest.raises(ValueError, match="live stream's ID"):
        Settings(**{**settings.model_dump(), "opencti_stream_id": bad})
