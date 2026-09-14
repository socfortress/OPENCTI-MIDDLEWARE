"""Defang, classify and normalize a value arriving from Graylog.

Runs ahead of every cache and every backend, so that ``HXXP://Evil.COM/a/``
and ``http://evil.com/a`` resolve to one cache key and one OpenCTI query
rather than two of each.

The skip list is a performance feature as much as a correctness one: internal
traffic dominates most log streams, and rejecting RFC1918 here means it never
allocates a cache entry or touches the network.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from enum import StrEnum
from urllib.parse import urlsplit, urlunsplit


class IndicatorType(StrEnum):
    """STIX observable types, spelled as OpenCTI spells them."""

    IPV4 = "IPv4-Addr"
    IPV6 = "IPv6-Addr"
    DOMAIN = "Domain-Name"
    URL = "Url"
    # File hashes all live on StixFile observables and are matched by a
    # `hashes.<ALGO>` filter key rather than by `value`, so they are separate
    # members here even though they share one OpenCTI entity type.
    HASH_MD5 = "StixFile:MD5"
    HASH_SHA1 = "StixFile:SHA-1"
    HASH_SHA256 = "StixFile:SHA-256"
    UNKNOWN = "Unknown"

    @property
    def is_hash(self) -> bool:
        return self in _HASH_TYPES

    @property
    def hash_algorithm(self) -> str | None:
        """OpenCTI's spelling of the algorithm, for the filter key."""
        return _HASH_ALGORITHMS.get(self)


_HASH_TYPES = frozenset(
    {IndicatorType.HASH_MD5, IndicatorType.HASH_SHA1, IndicatorType.HASH_SHA256}
)

#: Exactly as OpenCTI spells them in `hashes.<ALGO>` filter keys -- verified
#: against a live 7.26 instance, where `hashes.SHA-256` matches and a plain
#: `value` filter on the same hash returns nothing.
_HASH_ALGORITHMS: dict[IndicatorType, str] = {
    IndicatorType.HASH_MD5: "MD5",
    IndicatorType.HASH_SHA1: "SHA-1",
    IndicatorType.HASH_SHA256: "SHA-256",
}

_HASH_BY_LENGTH: dict[int, IndicatorType] = {
    32: IndicatorType.HASH_MD5,
    40: IndicatorType.HASH_SHA1,
    64: IndicatorType.HASH_SHA256,
}

_HEX_RE = re.compile(r"^[a-fA-F0-9]+$")


#: A domain arriving from Graylog may be stored under either type in OpenCTI.
#: Measured on a live 7.26 instance: Domain-Name 8,124 / Hostname 2,867 --
#: filtering on Domain-Name alone silently drops a quarter of the corpus.
DOMAIN_QUERY_TYPES: tuple[str, ...] = ("Domain-Name", "Hostname")

QUERY_TYPES: dict[IndicatorType, tuple[str, ...]] = {
    IndicatorType.IPV4: ("IPv4-Addr",),
    IndicatorType.IPV6: ("IPv6-Addr",),
    IndicatorType.DOMAIN: DOMAIN_QUERY_TYPES,
    IndicatorType.URL: ("Url",),
    IndicatorType.HASH_MD5: ("StixFile",),
    IndicatorType.HASH_SHA1: ("StixFile",),
    IndicatorType.HASH_SHA256: ("StixFile",),
}

DEFAULT_SKIP_TLDS: frozenset[str] = frozenset(
    {"local", "internal", "lan", "corp", "home", "arpa", "localdomain", "test", "invalid"}
)

#: A filename has exactly the shape of a domain -- "WMIC.exe" and "R34DM3.txt"
#: both satisfy the domain regex. OpenCTI carries these as StixFile
#: observables, and Graylog sends them in process-execution events. Without
#: this they classify as domains and generate lookups that can never hit.
#: Not a substitute for a public-suffix list, just the cheap 90%.
#:
#: Deliberately EXCLUDES extensions that are also real TLDs, because a false
#: negative on a domain is far worse than a wasted lookup on a file:
#:   com  legacy DOS executable, and the most common TLD there is
#:   zip  archive, and a real gTLD -- and a known phishing vector, so the
#:        domain reading is the one that matters for threat intel
#:   py   Python source, and Paraguay
#:   mov  video, and a real gTLD
#:   sh   shell script, and Saint Helena
FILE_EXTENSIONS: frozenset[str] = frozenset(
    {
        "exe", "dll", "sys", "bat", "cmd", "ps1", "vbs", "js", "jar", "msi",
        "scr", "bin", "dat", "tmp", "log", "txt", "doc", "docx", "xls",
        "xlsx", "ppt", "pptx", "pdf", "rtf", "rar", "7z", "gz", "tar",
        "iso", "img", "png", "jpg", "jpeg", "gif", "bmp", "svg", "mp3", "mp4",
        "avi", "lnk", "url", "hta", "chm", "reg", "conf", "ini", "xml", "json",
        "csv", "sql", "bak", "php", "asp", "aspx", "jsp",
    }
)

_DEFANG = (
    ("[.]", "."), ("(.)", "."), ("{.}", "."), (" dot ", "."),
    ("[:]", ":"), ("[/]", "/"), ("[@]", "@"), ("[at]", "@"),
    ("hxxps", "https"), ("hxxp", "http"), ("fxp", "ftp"),
)
_STRIP_CHARS = " \t\r\n\"'<>[]()"

# The final label must contain a letter: an all-numeric TLD is not a domain,
# it is a malformed IP. Without this, "1.2.3.4.5" and leading-zero IPv4
# forms fall through to the domain branch.
_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)"
    r"(?:\.(?!-)[a-z0-9-]{1,63}(?<!-))*"
    r"\.(?!-)[a-z0-9-]*[a-z][a-z0-9-]*(?<!-)$"
)

#: Dotted-quad with any number of leading zeros per octet.
_ZERO_PADDED_IPV4_RE = re.compile(
    r"^0\d{1,2}(?:\.\d{1,3}){3}$|^\d{1,3}(?:\.0\d{1,2}|\.\d{1,3}){3}$"
)
_DOTTED_QUAD_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
_DEFAULT_PORTS = {"http": "80", "https": "443", "ftp": "21"}


@dataclass(frozen=True, slots=True)
class Normalized:
    """A value ready to look up, or a reason it will never be looked up."""

    original: str
    value: str
    type: IndicatorType
    skip_reason: str | None = None

    @property
    def lookupable(self) -> bool:
        return self.skip_reason is None and self.type is not IndicatorType.UNKNOWN

    @property
    def cache_key(self) -> str:
        return f"{self.type.value}:{self.value}"


def _defang(raw: str) -> str:
    out = raw.strip().strip(_STRIP_CHARS)
    lowered = out.lower()
    # Only pay for replacement when a marker is actually present -- this runs
    # on every request and the common case has none.
    if any(marker in lowered for marker, _ in _DEFANG):
        for marker, repl in _DEFANG:
            idx = out.lower().find(marker)
            while idx != -1:
                out = out[:idx] + repl + out[idx + len(marker) :]
                idx = out.lower().find(marker)
    return out.strip(_STRIP_CHARS)


def _to_punycode(host: str) -> str:
    """IDNA-encode, falling back to the lowercased input.

    Python's idna codec raises on empty labels and over-long labels; a value
    we cannot encode is simply not a domain we will match, and the caller's
    regex will reject it.
    """
    if host.isascii():
        return host.lower()
    try:
        return host.encode("idna").decode("ascii").lower()
    except (UnicodeError, ValueError):
        return host.lower()


def _normalize_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> str:
    # compressed() collapses 010.1.1.1, ::1 and 0:0:0:0:0:0:0:1 onto one key.
    return ip.compressed


def _is_skippable_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> str | None:
    """Reason this IP is never worth looking up, or None.

    Ordered most-specific first: `ipaddress` reports loopback, link-local and
    unspecified addresses as `is_private` too, so testing `is_private` first
    would collapse every one of them to the same label. The reason string ends
    up as a metrics dimension, so the specific one is the useful one.
    """
    if ip.is_loopback:
        return "loopback_ip"
    if ip.is_link_local:
        return "link_local_ip"
    if ip.is_multicast:
        return "multicast_ip"
    if ip.is_unspecified:
        return "unspecified_ip"
    if ip.is_reserved:
        return "reserved_ip"
    if ip.is_private:
        return "private_ip"
    return None


def _normalize_url(raw: str) -> tuple[str, str] | None:
    """Return ``(normalized_url, hostname)`` or None if unparseable."""
    candidate = raw if "://" in raw else f"http://{raw}"
    try:
        parts = urlsplit(candidate)
    except ValueError:
        return None
    if not parts.hostname:
        return None

    host = _to_punycode(parts.hostname)
    netloc = host
    port = None
    try:
        port = parts.port
    except ValueError:
        return None
    if port is not None and str(port) != _DEFAULT_PORTS.get(parts.scheme.lower()):
        netloc = f"{host}:{port}"

    # Path and query stay byte-exact -- they are case- and order-significant
    # upstream, and OpenCTI stores the URL as an opaque string it matches on
    # equality. Notably an empty path stays empty: forcing a trailing slash
    # made "http://x.com" (as stored) unmatchable by "http://x.com/" (as
    # normalized). Measured against the live corpus, that alone accounted for
    # most of a 1.5% false-miss rate.
    normalized = urlunsplit(
        (parts.scheme.lower(), netloc, parts.path, parts.query, "")
    )
    return normalized, host


def normalize(
    raw: str,
    *,
    skip_private: bool = True,
    skip_tlds: frozenset[str] = DEFAULT_SKIP_TLDS,
) -> Normalized:
    """Classify and canonicalize one value from Graylog."""
    if not raw or not raw.strip():
        return Normalized(raw, "", IndicatorType.UNKNOWN, "empty")

    cleaned = _defang(raw)
    if not cleaned:
        return Normalized(raw, "", IndicatorType.UNKNOWN, "empty_after_defang")

    # --- IP address (cheapest test, and unambiguous) ---
    bare = cleaned.strip("[]")
    # ipaddress rejects zero-padded octets because they are ambiguously octal.
    # Threat feeds and evasion attempts both produce them, so canonicalize to
    # the decimal reading -- which is what Python, Go and Rust all use -- and
    # let the result flow through the normal private/reserved checks.
    if _DOTTED_QUAD_RE.match(bare) and _ZERO_PADDED_IPV4_RE.match(bare):
        bare = ".".join(str(int(octet)) for octet in bare.split("."))
    try:
        ip = ipaddress.ip_address(bare)
    except ValueError:
        pass
    else:
        kind = IndicatorType.IPV4 if ip.version == 4 else IndicatorType.IPV6
        reason = _is_skippable_ip(ip) if skip_private else None
        return Normalized(raw, _normalize_ip(ip), kind, reason)

    # --- File hash: fixed-length hex, no separators ---
    # Checked before URL/domain because a bare hex string matches neither and
    # would otherwise end up UNKNOWN.
    hash_type = _HASH_BY_LENGTH.get(len(cleaned))
    if hash_type is not None and _HEX_RE.match(cleaned):
        return Normalized(raw, cleaned.lower(), hash_type)

    # --- URL: anything carrying a scheme, a path, or a query ---
    if "://" in cleaned or "/" in cleaned or "?" in cleaned:
        parsed = _normalize_url(cleaned)
        if parsed is None:
            return Normalized(raw, cleaned, IndicatorType.UNKNOWN, "unparseable_url")
        url, host = parsed
        tld = host.rsplit(".", 1)[-1] if "." in host else host
        if tld in skip_tlds:
            return Normalized(raw, url, IndicatorType.URL, "skipped_tld")
        return Normalized(raw, url, IndicatorType.URL)

    # --- Domain ---
    host = _to_punycode(cleaned.rstrip("."))
    if _DOMAIN_RE.match(host):
        tld = host.rsplit(".", 1)[-1]
        if tld in skip_tlds:
            return Normalized(raw, host, IndicatorType.DOMAIN, "skipped_tld")
        if tld in FILE_EXTENSIONS:
            return Normalized(raw, host, IndicatorType.UNKNOWN, "looks_like_filename")
        return Normalized(raw, host, IndicatorType.DOMAIN)

    return Normalized(raw, cleaned, IndicatorType.UNKNOWN, "unclassified")


def url_hostname(normalized_url: str) -> str | None:
    """Hostname of an already-normalized URL, for the fallback lookup."""
    try:
        return urlsplit(normalized_url).hostname
    except ValueError:
        return None
