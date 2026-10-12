from __future__ import annotations

from datetime import datetime, timezone

import pytest

from dvl.hits import from_chainsaw, load_hits, parse_time, save_hits


def test_parse_time_powershell_seven_digits():
    t = parse_time("2026-10-11T12:00:01.1234567Z")
    assert t == datetime(2026, 10, 11, 12, 0, 1, 123456, tzinfo=timezone.utc)


def test_parse_time_offset_and_naive():
    assert parse_time("2026-10-11T14:00:00+02:00") == datetime(2026, 10, 11, 12, tzinfo=timezone.utc)
    assert parse_time("2026-10-11T12:00:00").tzinfo == timezone.utc


def test_parse_time_rejects_garbage():
    with pytest.raises(ValueError):
        parse_time("yesterday")


def _chainsaw_item(**over):
    item = {
        "group": "Sigma", "kind": "individual", "name": "Some rule", "level": "medium",
        "source": "sigma", "id": "8112e92f-c82f-4a42-b9ee-11982cceae00",
        "timestamp": "2025-10-22T20:35:26.043284+00:00",
        "document": {"kind": "evtx", "path": "C:\\logs\\sample.evtx", "data": {"Event": {
            "System": {"EventID": 1, "Computer": "ar-win-1", "Channel": "Microsoft-Windows-Sysmon/Operational"},
            "EventData": {"Image": "C:\\Windows\\System32\\reg.exe", "CommandLine": "reg add x",
                          "Nested": {"ignored": True}},
        }}},
    }
    item.update(over)
    return item


def test_from_chainsaw_normalises_a_sigma_hit():
    (hit,) = from_chainsaw([_chainsaw_item()])
    assert hit.rule_id == "8112e92f-c82f-4a42-b9ee-11982cceae00"
    assert hit.event_id == 1 and hit.computer == "ar-win-1"
    assert hit.source_file == "sample.evtx"
    assert hit.get("CommandLine") == "reg add x"
    assert hit.get("Computer") == "ar-win-1"
    assert "Nested" not in hit.fields
    assert hit.get("Missing") == ""


def test_from_chainsaw_eventid_with_qualifiers_and_non_sigma_items():
    item = _chainsaw_item()
    item["document"]["data"]["Event"]["System"]["EventID"] = {"#text": 4720, "Qualifiers": 0}
    chainsaw_builtin = _chainsaw_item(group="Suspicious", source="chainsaw")
    hits = from_chainsaw([item, chainsaw_builtin])
    assert len(hits) == 1 and hits[0].event_id == 4720


def test_from_chainsaw_eventdata_not_a_dict():
    item = _chainsaw_item()
    item["document"]["data"]["Event"]["EventData"] = None
    (hit,) = from_chainsaw([item])
    assert hit.fields == {}


def test_save_load_roundtrip(tmp_path):
    hits = from_chainsaw([_chainsaw_item()])
    save_hits(hits, tmp_path / "h.json")
    again = load_hits(tmp_path / "h.json")
    assert again[0].timestamp == hits[0].timestamp
    assert again[0].fields == hits[0].fields
