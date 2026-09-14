"""The Wazuh custom integration script.

Loaded by path because it ships as an executable for /var/ossec/integrations
rather than as part of the installable package -- it has to run under the
manager's own interpreter with no dependencies.
"""

from __future__ import annotations

import importlib.util
import json
import pathlib
import sys

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "wazuh" / "custom-opencti.py"


def _load():
    spec = importlib.util.spec_from_file_location("custom_opencti", SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


ci = _load()


def alert(**over) -> dict:
    base = {
        "id": "1757.1",
        "agent": {"id": "001", "name": "web-01", "ip": "10.0.0.5"},
        "rule": {"id": "92000", "description": "Sysmon - Network connection",
                 "groups": ["sysmon_event3"]},
    }
    base.update(over)
    return base


# --- extraction ------------------------------------------------------------


def test_linux_sysmon_destination_ip() -> None:
    a = alert(data={"eventdata": {"DestinationIp": "212.193.31.122"}})
    assert ci.extract_indicators(a) == ["212.193.31.122"]


def test_windows_sysmon_destination_ip_casing() -> None:
    """Wazuh emits both spellings depending on decoder version."""
    for key in ("DestinationIp", "destinationIp"):
        a = alert(data={"win": {"eventdata": {key: "1.2.3.4"}}})
        assert ci.extract_indicators(a) == ["1.2.3.4"]


def test_sysmon_hash_blob_yields_every_digest() -> None:
    """Sysmon packs several algorithms into one field."""
    blob = ("SHA1=DA39A3EE5E6B4B0D3255BFEF95601890AFD80709,"
            "MD5=D41D8CD98F00B204E9800998ECF8427E,"
            "SHA256=B12B743D4ECC0FE7320B6C1533E2A60BB89F94CA39A5BE37143E7AF27DAACF04,"
            "IMPHASH=00112233445566778899AABBCCDDEEFF")
    got = ci.extract_indicators(alert(data={"win": {"eventdata": {"hashes": blob}}}))
    assert "da39a3ee5e6b4b0d3255bfef95601890afd80709" in got
    assert "d41d8cd98f00b204e9800998ecf8427e" in got
    assert "b12b743d4ecc0fe7320b6c1533e2a60bb89f94ca39a5be37143e7af27daacf04" in got
    # IMPHASH is not a file hash OpenCTI indexes; it must not be looked up.
    assert "00112233445566778899aabbccddeeff" not in got


def test_digests_are_lowercased() -> None:
    """Sysmon emits uppercase; OpenCTI stores lowercase."""
    a = alert(data={"win": {"eventdata": {"hashes": "SHA256=" + "A" * 64}}})
    assert ci.extract_indicators(a) == ["a" * 64]


def test_fim_and_dns_paths() -> None:
    assert ci.extract_indicators(alert(syscheck={"sha256_after": "b" * 64})) == ["b" * 64]
    a = alert(data={"dns": {"question": {"name": "evil.com"}}})
    assert ci.extract_indicators(a) == ["evil.com"]
    a = alert(data={"win": {"eventdata": {"queryName": "evil.com"}}})
    assert ci.extract_indicators(a) == ["evil.com"]


@pytest.mark.parametrize(
    "ip", ["10.20.30.40", "192.168.1.1", "127.0.0.1", "169.254.1.1", "224.0.0.1"]
)
def test_unroutable_ips_never_leave_the_manager(ip: str) -> None:
    """Skipped in-script: the middleware would reject them anyway, but the
    HTTP round trip costs more than the check when a process spawn already
    dominates the per-alert budget."""
    assert ci.extract_indicators(alert(data={"eventdata": {"DestinationIp": ip}})) == []


def test_source_ip_is_deliberately_ignored() -> None:
    """Usually the local side of the connection -- noise, not signal."""
    assert ci.extract_indicators(alert(data={"srcip": "8.8.8.8"})) == []


def test_indicators_are_deduped_and_capped() -> None:
    a = alert(data={
        "eventdata": {"DestinationIp": "8.8.8.8"},
        "destination": {"ip": "8.8.8.8"},
    })
    assert ci.extract_indicators(a) == ["8.8.8.8"]
    many = {"win": {"eventdata": {"hashes": ",".join(
        f"SHA256={i:064x}" for i in range(50))}}}
    assert len(ci.extract_indicators(alert(data=many))) <= ci.MAX_INDICATORS_PER_ALERT


def test_alert_with_nothing_to_look_up() -> None:
    assert ci.extract_indicators(alert()) == []
    assert ci.extract_indicators({}) == []


def test_dig_survives_wrong_shapes() -> None:
    assert ci.dig({"a": "scalar"}, "a.b.c") is None
    assert ci.dig({}, "a") is None
    assert ci.dig({"a": {"b": 1}}, "a.b") == 1


# --- analysisd protocol ----------------------------------------------------


def test_socket_message_for_an_agent() -> None:
    sent: list[str] = []
    ci.socket = lambda *a, **k: type(
        "S", (), {"connect": lambda s, a: None,
                  "send": lambda s, b: sent.append(b.decode()),
                  "close": lambda s: None}
    )()
    ci.send_event({"integration": "opencti"}, {"id": "001", "name": "web-01", "ip": "10.0.0.5"})
    assert sent[0].startswith("1:[001] (web-01) 10.0.0.5->opencti:")


def test_socket_message_for_the_manager_itself() -> None:
    sent: list[str] = []
    ci.socket = lambda *a, **k: type(
        "S", (), {"connect": lambda s, a: None,
                  "send": lambda s, b: sent.append(b.decode()),
                  "close": lambda s: None}
    )()
    ci.send_event({"integration": "opencti"}, {"id": "000"})
    assert sent[0].startswith("1:opencti:")


def test_location_delimiters_are_escaped() -> None:
    """analysisd treats ':' and '|' as field separators."""
    sent: list[str] = []
    ci.socket = lambda *a, **k: type(
        "S", (), {"connect": lambda s, a: None,
                  "send": lambda s, b: sent.append(b.decode()),
                  "close": lambda s: None}
    )()
    ci.send_event({}, {"id": "001", "name": "a:b|c", "ip": "::1"})
    assert "a|:b||c" in sent[0]


def test_event_carries_provenance() -> None:
    event = ci.build_event(
        alert(), "1.2.3.4",
        {"found": "true", "score": "80", "labels": "c2"},
    )
    assert event["integration"] == "opencti"
    payload = event["opencti"]
    assert payload["indicator"] == "1.2.3.4"
    assert payload["source_rule_id"] == "92000"
    assert payload["source_alert_id"] == "1757.1"
    # Flat and string-valued, like the HTTP response.
    assert all(isinstance(v, (str, int, float)) for v in payload.values())


def test_event_is_json_serialisable() -> None:
    event = ci.build_event(alert(), "x", {"found": "true", "nested": {"no": 1}})
    json.dumps(event)
    assert "nested" not in event["opencti"]


# --- argument handling -----------------------------------------------------


def test_missing_arguments_are_rejected() -> None:
    assert ci.main(["custom-opencti"]) == ci.ERR_BAD_ARGUMENTS
    assert ci.main(["custom-opencti", "f", "key"]) == ci.ERR_BAD_ARGUMENTS


def test_empty_api_key_or_hook_url_is_rejected() -> None:
    assert ci.main(["custom-opencti", "f", "", "http://x"]) == ci.ERR_BAD_ARGUMENTS
    assert ci.main(["custom-opencti", "f", "key", ""]) == ci.ERR_BAD_ARGUMENTS


def test_missing_alert_file_exits_cleanly(tmp_path: pathlib.Path) -> None:
    with pytest.raises(SystemExit) as exc:
        ci.main(["custom-opencti", str(tmp_path / "nope.json"), "k", "http://x"])
    assert exc.value.code == ci.ERR_FILE_NOT_FOUND


def test_malformed_alert_file_exits_cleanly(tmp_path: pathlib.Path) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text("{not json")
    with pytest.raises(SystemExit) as exc:
        ci.main(["custom-opencti", str(bad), "k", "http://x"])
    assert exc.value.code == ci.ERR_INVALID_JSON


def test_hook_url_accepts_a_trailing_lookup_path(monkeypatch) -> None:
    seen: list[str] = []

    def fake(url, api_key, payload=None):
        seen.append(url)
        return {"found": "false"}

    monkeypatch.setattr(ci, "_request", fake)
    ci.lookup("http://m:8000/lookup", "k", ["1.2.3.4"])
    ci.lookup("http://m:8000", "k", ["1.2.3.4"])
    assert seen[0] == seen[1]


def test_several_indicators_use_one_bulk_request(monkeypatch) -> None:
    calls: list[tuple[str, bytes | None]] = []

    def fake(url, api_key, payload=None):
        calls.append((url, payload))
        return {"results": {}}

    monkeypatch.setattr(ci, "_request", fake)
    ci.lookup("http://m:8000", "k", ["a", "b", "c"])
    assert len(calls) == 1
    assert calls[0][0].endswith("/lookup/bulk")
    assert json.loads(calls[0][1])["values"] == ["a", "b", "c"]


def test_python_version_floor() -> None:
    """Runs under the manager's interpreter, which may be older than ours."""
    assert sys.version_info >= (3, 7)
