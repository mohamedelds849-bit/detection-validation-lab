from __future__ import annotations

import json

import pytest

from dvl.evaluate import evaluate_goodlog, evaluate_samples, evaluate_telemetry, load_manifest
from dvl.expectations import AtomicPlan, AtomicTest, Condition, KnownFP
from tests.conftest import iso


def _plan(*tests):
    return AtomicPlan(atomics_commit="x" * 40, invoke_version="2.3.0", tests=tests, benign_phase="benign")


def _manifest(tmp_path, phases):
    path = tmp_path / "manifest.json"
    # PowerShell writes UTF-8 with a BOM and 7 fractional digits
    path.write_text("\ufeff" + json.dumps({"host": "RUNNER", "phases": phases}), encoding="utf-8")
    return load_manifest(path)


A1 = AtomicTest("A1", "T1027", "a50d5a97-2531-499e-a1de-5544c74432c6", "enc", ("dvl_001",))
A5 = AtomicTest("A5", "T1087.001", "80887bec-5a9b-4efc-a81d-f83eb2eb32ab", "accounts", ("dvl_004", "dvl_005"))


@pytest.fixture
def manifest(tmp_path):
    return _manifest(tmp_path, [
        {"id": "benign", "start": iso(0), "end": iso(10)},
        {"id": "A1", "start": iso(30), "end": iso(40), "status": "ok"},
        {"id": "A5", "start": iso(60), "end": iso(70), "status": "ok"},
    ])


def test_all_expected_rules_fire(make_hit, rules, manifest):
    hits = [make_hit("dvl_001", 35), make_hit("dvl_004", 61), make_hit("dvl_005", 62),
            make_hit("dvl_004", 5)]  # building block in the benign phase is fine
    r = evaluate_telemetry(hits, manifest, _plan(A1, A5), rules)
    assert r["passed"]
    assert [t["status"] for t in r["tests"]] == ["PASS", "PASS"]
    assert len(r["benign"]["building_blocks"]) == 1 and not r["benign"]["false_positives"]


def test_missing_detection_fails(make_hit, rules, manifest):
    hits = [make_hit("dvl_001", 35), make_hit("dvl_004", 61)]
    r = evaluate_telemetry(hits, manifest, _plan(A1, A5), rules)
    assert not r["passed"]
    a5 = r["tests"][1]
    assert a5["status"] == "MISSED" and a5["missing"] == ["dvl_005"]


def test_hit_in_another_tests_window_does_not_count(make_hit, rules, manifest):
    r = evaluate_telemetry([make_hit("dvl_001", 65)], manifest, _plan(A1), rules)
    assert r["tests"][0]["status"] == "MISSED"


def test_grace_after_end_and_before_start(make_hit, rules, manifest):
    assert evaluate_telemetry([make_hit("dvl_001", 45)], manifest, _plan(A1), rules)["passed"]   # end + 5 s
    assert not evaluate_telemetry([make_hit("dvl_001", 46)], manifest, _plan(A1), rules)["passed"]
    assert evaluate_telemetry([make_hit("dvl_001", 29)], manifest, _plan(A1), rules)["passed"]   # start - 1 s


def test_alert_in_benign_phase_is_a_false_positive(make_hit, rules, manifest):
    hits = [make_hit("dvl_001", 35), make_hit("dvl_002", 3, CommandLine="schtasks /create /tn x")]
    r = evaluate_telemetry(hits, manifest, _plan(A1), rules)
    assert not r["passed"]
    assert r["benign"]["false_positives"][0]["rule"] == "dvl_002"


def test_benign_phase_must_have_run(make_hit, rules, tmp_path):
    m = _manifest(tmp_path, [{"id": "A1", "start": iso(30), "end": iso(40)}])
    r = evaluate_telemetry([make_hit("dvl_001", 35)], m, _plan(A1), rules)
    assert not r["passed"] and not r["benign"]["ran"]


def test_not_run_and_error_statuses(make_hit, rules, tmp_path):
    m = _manifest(tmp_path, [{"id": "benign", "start": iso(0), "end": iso(1)},
                             {"id": "A1", "start": iso(30), "end": iso(40), "status": "error"}])
    r = evaluate_telemetry([make_hit("dvl_001", 35)], m, _plan(A1, A5), rules)
    assert [t["status"] for t in r["tests"]] == ["ERROR", "NOT_RUN"]
    assert not r["passed"]


def test_extra_and_unattributed_are_reported_not_failed(make_hit, rules, manifest):
    hits = [make_hit("dvl_001", 35), make_hit("dvl_004", 36), make_hit("dvl_002", 500)]
    r = evaluate_telemetry(hits, manifest, _plan(A1), rules)
    assert r["passed"]
    assert r["tests"][0]["extra"] == ["dvl_004"]
    assert r["unattributed"] == {"dvl_002": 1}


def test_manifest_rejects_reversed_window(tmp_path):
    with pytest.raises(ValueError):
        _manifest(tmp_path, [{"id": "A1", "start": iso(10), "end": iso(0)}])


def test_manifest_accepts_powershell_timestamps(tmp_path):
    m = _manifest(tmp_path, [{"id": "benign", "start": "2026-10-11T12:00:00.1234567Z",
                              "end": "2026-10-11T12:00:05.7654321Z"}])
    assert m["phases"][0]["start_dt"].microsecond == 123456


# ---- goodlog -------------------------------------------------------------------------

def _fp(rule, *conds, max_count=1):
    return KnownFP(rule=rule, where=tuple(Condition(*c) for c in conds), reason="why", max_count=max_count)


def test_goodlog_accepts_listed_fps_and_fails_on_others(make_hit, rules):
    spotify = make_hit("dvl_003", 0, Details="C:\\Users\\u\\AppData\\Roaming\\Spotify\\Spotify.exe")
    other = make_hit("dvl_003", 1, Details="C:\\Users\\u\\AppData\\evil.exe")
    known = [_fp("dvl_003", ("Details", "contains", "\\spotify\\spotify.exe"))]
    r = evaluate_goodlog([spotify, other], known, rules, "ds")
    assert not r["passed"]
    assert len(r["accepted"]) == 1 and len(r["unexpected"]) == 1


def test_goodlog_all_conditions_must_match(make_hit, rules):
    hit = make_hit("dvl_007", 0, TargetUserName="user", SubjectUserName="admin")
    known = [_fp("dvl_007", ("TargetUserName", "equals", "user"), ("SubjectUserName", "endswith", "$"))]
    assert not evaluate_goodlog([hit], known, rules, "ds")["passed"]


def test_goodlog_max_count_and_stale_entries(make_hit, rules):
    hits = [make_hit("dvl_002", i, CommandLine='schtasks /create /TN "klcp_update"') for i in range(2)]
    known = [_fp("dvl_002", ("CommandLine", "contains", "klcp_update")),
             _fp("dvl_006", ("Image", "contains", "never"))]
    r = evaluate_goodlog(hits, known, rules, "ds")
    assert not r["passed"] and len(r["unexpected"]) == 1
    assert r["stale_allowlist_entries"] == [{"rule": "dvl_006", "value": "Image contains 'never'"}]


def test_goodlog_rule_key_must_match(make_hit, rules):
    hit = make_hit("dvl_002", 0, CommandLine="klcp_update")
    known = [_fp("dvl_008", ("CommandLine", "contains", "klcp_update"))]
    assert not evaluate_goodlog([hit], known, rules, "ds")["passed"]


def test_goodlog_building_blocks_never_fail(make_hit, rules):
    r = evaluate_goodlog([make_hit("dvl_004", 0, CommandLine="whoami")], [], rules, "ds")
    assert r["passed"] and r["building_block_hits"] == 1 and r["alert_hits"] == 0


# ---- samples -------------------------------------------------------------------------

def test_samples_gate(make_hit, rules):
    expected = {"a.evtx": ("dvl_001",), "b.evtx": ()}
    ok = [make_hit("dvl_001", 0, source_file="a.evtx")]
    assert evaluate_samples(ok, expected, rules)["passed"]
    missing = evaluate_samples([], expected, rules)
    assert not missing["passed"] and missing["samples"][0]["missing"] == ["dvl_001"]
    unexpected = evaluate_samples(ok + [make_hit("dvl_002", 0, source_file="b.evtx")], expected, rules)
    assert not unexpected["passed"]


def test_samples_unlisted_files(make_hit, rules):
    expected = {"a.evtx": ()}
    bb = [make_hit("dvl_004", 0, source_file="z.evtx")]
    alert = [make_hit("dvl_006", 0, source_file="z.evtx")]
    assert evaluate_samples(bb, expected, rules)["passed"]
    assert not evaluate_samples(alert, expected, rules)["passed"]
