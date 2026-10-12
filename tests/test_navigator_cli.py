from __future__ import annotations

import json

from dvl.cli import main
from dvl.hits import save_hits
from dvl.navigator import PROVEN, UNPROVEN, build_layer
from tests.conftest import ROOT, iso


def test_layer_lists_all_techniques_unproven_by_default(rules):
    layer = build_layer(rules)
    ids = {t["techniqueID"] for t in layer["techniques"]}
    assert ids == {"T1027.010", "T1059.001", "T1053.005", "T1547.001", "T1033", "T1082",
                   "T1087.001", "T1218.005", "T1136.001"}
    assert {t["color"] for t in layer["techniques"]} == {UNPROVEN}
    assert layer["versions"]["attack"] == "19"


def test_layer_marks_proven_rules(rules):
    report = {"tests": [{"status": "PASS", "expected": ["dvl_006"]},
                        {"status": "MISSED", "expected": ["dvl_001"]}]}
    colors = {t["techniqueID"]: t["color"] for t in build_layer(rules, report)["techniques"]}
    assert colors["T1218.005"] == PROVEN
    assert colors["T1027.010"] == UNPROVEN


def _write(tmp_path, make_hit, hits, phases):
    save_hits(hits, tmp_path / "hits.json")
    (tmp_path / "manifest.json").write_text(json.dumps({"phases": phases}), encoding="utf-8")


def test_cli_telemetry_exit_codes(tmp_path, make_hit, monkeypatch):
    monkeypatch.delenv("GITHUB_STEP_SUMMARY", raising=False)
    plan = tmp_path / "plan.yaml"
    plan.write_text("atomic_red_team: {atomics_commit: x, invoke_atomicredteam_version: '2.3.0'}\n"
                    "tests:\n  - {id: A7, technique: T1218.005, guid: g, name: mshta, expect: [dvl_006]}\n",
                    encoding="utf-8")
    phases = [{"id": "benign", "start": iso(0), "end": iso(5)}, {"id": "A7", "start": iso(20), "end": iso(25)}]
    args = ["telemetry", "--hits", str(tmp_path / "hits.json"), "--manifest", str(tmp_path / "manifest.json"),
            "--plan", str(plan), "--out", str(tmp_path / "r.json")]

    _write(tmp_path, make_hit, [make_hit("dvl_006", 21)], phases)
    assert main(args) == 0
    assert json.loads((tmp_path / "r.json").read_text(encoding="utf-8"))["passed"] is True

    _write(tmp_path, make_hit, [], phases)
    assert main(args) == 1


def test_cli_bad_input_is_exit_2(tmp_path, capsys):
    assert main(["goodlog", "--hits", str(tmp_path / "missing.json")]) == 2
    (tmp_path / "bad.json").write_text("{not json", encoding="utf-8")
    assert main(["samples", "--hits", str(tmp_path / "bad.json")]) == 2
    assert "error" in capsys.readouterr().err


def test_cli_writes_step_summary(tmp_path, make_hit, monkeypatch):
    summary = tmp_path / "summary.md"
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary))
    save_hits([make_hit("dvl_004", 0, CommandLine="whoami")], tmp_path / "hits.json")
    assert main(["goodlog", "--hits", str(tmp_path / "hits.json"), "--dataset", "ci-runner"]) == 0
    assert "Gate 2" in summary.read_text(encoding="utf-8")


def test_cli_navigator(tmp_path):
    out = tmp_path / "layer.json"
    assert main(["navigator", "--out", str(out)]) == 0
    assert json.loads(out.read_text(encoding="utf-8"))["domain"] == "enterprise-attack"


def test_committed_layer_is_up_to_date(rules):
    committed = json.loads((ROOT / "reports" / "coverage-layer.json").read_text(encoding="utf-8"))
    assert committed == json.loads(json.dumps(build_layer(rules)))
