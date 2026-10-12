from __future__ import annotations

import pytest

from dvl.expectations import load_atomic_plan, load_known_fps, load_sample_expectations
from tests.conftest import ROOT

LAB = ROOT / "lab"


def test_real_lab_files_load(rules):
    assert len(load_atomic_plan(LAB / "atomics.yaml", rules).tests) == 8
    assert len(load_known_fps(LAB / "known_fps.yaml", "nextron-win10-client", rules)) == 5
    assert load_known_fps(LAB / "known_fps.yaml", "ci-runner", rules) == []
    assert len(load_sample_expectations(LAB / "sample_expectations.yaml", rules)) == 8
    assert len(load_sample_expectations(LAB / "sigmahq_corpus_expectations.yaml", rules)) == 3


def test_every_vendored_sample_is_listed(rules):
    listed = set(load_sample_expectations(LAB / "sample_expectations.yaml", rules))
    on_disk = {p.name for p in (ROOT / "tests" / "data" / "real_evtx").glob("*.evtx")}
    assert listed == on_disk


def test_unknown_rule_key_is_rejected(tmp_path, rules):
    bad = tmp_path / "s.yaml"
    bad.write_text("samples:\n  x.evtx:\n    expect: [dvl_999]\n", encoding="utf-8")
    with pytest.raises(ValueError, match="dvl_999"):
        load_sample_expectations(bad, rules)


def test_known_fp_needs_reason_and_condition(tmp_path, rules):
    no_reason = tmp_path / "a.yaml"
    no_reason.write_text("datasets:\n  d:\n    - rule: dvl_003\n      where: [{field: Image, value: x}]\n",
                         encoding="utf-8")
    with pytest.raises(ValueError, match="reason"):
        load_known_fps(no_reason, "d", rules)
    no_cond = tmp_path / "b.yaml"
    no_cond.write_text("datasets:\n  d:\n    - rule: dvl_003\n      reason: r\n", encoding="utf-8")
    with pytest.raises(ValueError, match="where"):
        load_known_fps(no_cond, "d", rules)


def test_known_fp_rejects_unknown_operator(tmp_path, rules):
    f = tmp_path / "c.yaml"
    f.write_text("datasets:\n  d:\n    - rule: dvl_003\n      reason: r\n"
                 "      where: [{field: Image, op: regex, value: x}]\n", encoding="utf-8")
    with pytest.raises(ValueError, match="op"):
        load_known_fps(f, "d", rules)


def test_duplicate_atomic_ids_rejected(tmp_path, rules):
    f = tmp_path / "p.yaml"
    f.write_text(
        "atomic_red_team: {atomics_commit: x, invoke_atomicredteam_version: '1'}\n"
        "tests:\n"
        "  - {id: A1, technique: T1, guid: g, name: n, expect: [dvl_001]}\n"
        "  - {id: A1, technique: T1, guid: g, name: n, expect: [dvl_001]}\n", encoding="utf-8")
    with pytest.raises(ValueError, match="duplicate"):
        load_atomic_plan(f, rules)
