from __future__ import annotations

import pytest

from opencti_lookup.indicators import IndicatorType as T
from opencti_lookup.indicators import normalize, url_hostname


@pytest.mark.parametrize(
    ("raw", "kind", "value"),
    [
        ("8.8.8.8", T.IPV4, "8.8.8.8"),
        ("2001:4860:4860::8888", T.IPV6, "2001:4860:4860::8888"),
        # ipaddress rejects zero-padded octets as ambiguously octal; we
        # canonicalize first so obfuscated forms still resolve.
        ("08.8.8.8", T.IPV4, "8.8.8.8"),
        ("evil.com", T.DOMAIN, "evil.com"),
        ("EVIL.COM.", T.DOMAIN, "evil.com"),
        ("hxxp://bad[.]com/a", T.URL, "http://bad.com/a"),
        ("http://Evil.COM:80/a/?q=1#frag", T.URL, "http://evil.com/a/?q=1"),
        ("https://x.com:8443/p", T.URL, "https://x.com:8443/p"),
    ],
)
def test_classification(raw: str, kind: T, value: str) -> None:
    n = normalize(raw)
    assert n.type is kind
    assert n.value == value
    assert n.lookupable


@pytest.mark.parametrize(
    ("raw", "reason"),
    [
        ("10.0.0.1", "private_ip"),
        ("192.168.001.001", "private_ip"),   # zero-padded private form
        ("127.0.0.1", "loopback_ip"),
        ("169.254.1.1", "link_local_ip"),
        ("printer.local", "skipped_tld"),
        ("db.internal", "skipped_tld"),
        ("", "empty"),
    ],
)
def test_skipped(raw: str, reason: str) -> None:
    n = normalize(raw)
    assert n.skip_reason == reason
    assert not n.lookupable


@pytest.mark.parametrize("raw", ["not a value", "1.2.3.4.5", "999.1.1.1", "x.1"])
def test_unclassified(raw: str) -> None:
    """An all-numeric final label is a malformed IP, never a domain."""
    assert normalize(raw).type is T.UNKNOWN


def test_equivalent_forms_share_a_cache_key() -> None:
    keys = {
        normalize(v).cache_key
        for v in ("http://Evil.COM/a", "hxxp://evil[.]com/a", "  http://evil.com/a  ")
    }
    assert len(keys) == 1


def test_url_hostname_roundtrip() -> None:
    assert url_hostname(normalize("https://a.b.com/x?y=1").value) == "a.b.com"
