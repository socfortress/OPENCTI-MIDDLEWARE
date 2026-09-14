"""File-hash classification and querying.

Hashes are a separate path from every other indicator: they live on StixFile
observables and are matched by a `hashes.<ALGO>` filter key. Filtering StixFile
by `value` returns nothing for a hash, even though `observable_value` displays
the digest -- verified against a live OpenCTI 7.26 instance.
"""

from __future__ import annotations

import pytest

from opencti_lookup.config import Settings
from opencti_lookup.indicators import IndicatorType as T
from opencti_lookup.indicators import normalize
from opencti_lookup.opencti.mapper import _virustotal_url
from opencti_lookup.opencti.queries import hash_filter, value_filter

MD5 = "d41d8cd98f00b204e9800998ecf8427e"
SHA1 = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


@pytest.mark.parametrize(
    ("digest", "kind", "algorithm"),
    [
        (MD5, T.HASH_MD5, "MD5"),
        (SHA1, T.HASH_SHA1, "SHA-1"),
        (SHA256, T.HASH_SHA256, "SHA-256"),
    ],
)
def test_classification_by_length(digest: str, kind: T, algorithm: str) -> None:
    n = normalize(digest)
    assert n.type is kind
    assert n.lookupable
    assert n.type.hash_algorithm == algorithm


def test_hashes_are_case_folded() -> None:
    """Sysmon emits uppercase; OpenCTI stores lowercase."""
    assert normalize(SHA256.upper()).value == SHA256
    assert normalize(MD5.upper()).cache_key == normalize(MD5).cache_key


@pytest.mark.parametrize("value", ["deadbeef", "z" * 64, "a" * 63, "a" * 65])
def test_near_misses_are_not_hashes(value: str) -> None:
    assert normalize(value).type is T.UNKNOWN


def test_hash_filter_uses_the_algorithm_key_not_value() -> None:
    """The whole reason hashes need their own path."""
    assert hash_filter("SHA-256", SHA256)["filters"][0]["key"] == "hashes.SHA-256"
    assert value_filter(SHA256)["filters"][0]["key"] == "value"


def test_all_hash_flavours_query_the_one_entity_type(settings: Settings) -> None:
    for kind in (T.HASH_MD5, T.HASH_SHA1, T.HASH_SHA256):
        assert settings.query_types_for(kind.value) == ("StixFile",)


def test_domain_still_queries_both_storage_types(settings: Settings) -> None:
    assert settings.query_types_for("Domain-Name") == ("Domain-Name", "Hostname")


@pytest.mark.parametrize(
    ("indicator_type", "fragment"),
    [
        ("StixFile:SHA-256", "/gui/file/"),
        ("IPv4-Addr", "/gui/ip-address/"),
        ("Domain-Name", "/gui/domain/"),
        ("Hostname", "/gui/domain/"),
    ],
)
def test_virustotal_deep_links(indicator_type: str, fragment: str) -> None:
    url = _virustotal_url(indicator_type, "x")
    assert url is not None
    assert fragment in url


def test_urls_get_no_virustotal_link() -> None:
    """VT's URL endpoint keys on a hash of the URL, not the URL itself."""
    assert _virustotal_url("Url", "http://x.com/a") is None


def test_hashes_survive_bootstrap_filtering() -> None:
    """They were previously dropped as unlookupable -- 4,907 StixFile
    observables on the test instance, most of the corpus we discarded."""
    assert normalize(SHA256).lookupable is True
