"""Static checks on the rule files (they do not need Chainsaw)."""
from __future__ import annotations

import re
import uuid

import pytest
import yaml
from sigma.collection import SigmaCollection

from dvl.expectations import load_atomic_plan
from dvl.rules import load_correlations, load_rule_file
from tests.conftest import ROOT

# Techniques verified on attack.mitre.org (ATT&CK v19) on 2026-10-11.
KNOWN_TECHNIQUES = {"T1027.010", "T1059.001", "T1053.005", "T1547.001", "T1033",
                    "T1082", "T1087.001", "T1218.005", "T1136.001"}
# v19 renamed "defense-evasion" to Stealth (TA0005) and added Defense Impairment (TA0112).
KNOWN_TACTICS = {"execution", "persistence", "privilege-escalation", "stealth", "discovery",
                 "defense-impairment"}
LEVELS = {"informational", "low", "medium", "high", "critical"}

RULE_FILES = sorted((ROOT / "rules").rglob("dvl_*.yml"))


def test_eight_rule_files():
    assert len(RULE_FILES) == 8


@pytest.mark.parametrize("path", RULE_FILES, ids=lambda p: p.name)
def test_metadata(path):
    doc = load_rule_file(path)
    assert uuid.UUID(doc["id"]).version == 4
    # Chainsaw silently ignores a Sigma rule without description/date (found the hard way)
    for field in ("title", "description", "author", "date", "level", "tags", "falsepositives"):
        assert doc.get(field), f"{path.name}: missing {field}"
    assert doc["level"] in LEVELS
    techniques = [t for t in doc["tags"] if re.match(r"attack\.t\d{4}", t)]
    tactics = [t.split(".", 1)[1] for t in doc["tags"] if not re.match(r"attack\.t\d{4}", t)]
    assert techniques, "at least one ATT&CK technique tag"
    assert {t.split(".", 1)[1].upper() for t in techniques} <= KNOWN_TECHNIQUES
    assert set(tactics) <= KNOWN_TACTICS


def test_unique_ids_and_keys(rules):
    assert len({m.id for m in rules.values()}) == len(rules)
    assert sorted(rules) == [f"dvl_00{i}" for i in range(1, 9)]


def test_pysigma_parses_everything_without_errors():
    texts = [p.read_text(encoding="utf-8") for p in RULE_FILES]
    collection = SigmaCollection.from_yaml("\n---\n".join(texts))
    assert len(collection.rules) == 8
    assert not collection.errors


def test_correlation_points_to_the_building_block(rules):
    (spec,) = load_correlations(ROOT / "rules")
    assert spec.base_rule_ids == (rules["dvl_004"].id,)
    assert (spec.gte, spec.timespan_seconds, spec.field) == (3, 300, "CommandLine")
    assert spec.group_by == ("Computer", "ParentProcessGuid")


def test_only_dvl_004_is_a_building_block(rules):
    assert [k for k, m in rules.items() if m.is_building_block] == ["dvl_004"]


def test_every_rule_is_expected_by_at_least_one_atomic_test(rules):
    plan = load_atomic_plan(ROOT / "lab" / "atomics.yaml", rules)
    expected = {k for t in plan.tests for k in t.expect}
    assert expected == set(rules)


def test_atomic_plan_is_pinned_and_uses_guids(rules):
    plan = load_atomic_plan(ROOT / "lab" / "atomics.yaml", rules)
    assert re.fullmatch(r"[0-9a-f]{40}", plan.atomics_commit)
    assert plan.invoke_version == "2.3.0"
    for test in plan.tests:
        uuid.UUID(test.guid)
    assert len(plan.tests) == 8


def test_ci_script_pins_match_the_plan(rules):
    plan = load_atomic_plan(ROOT / "lab" / "atomics.yaml", rules)
    script = (ROOT / "lab" / "ci" / "Install-Telemetry.ps1").read_text(encoding="utf-8")
    assert plan.atomics_commit in script
    assert f"'{plan.invoke_version}'" in script
    folders = re.search(r"\$Techniques\s*=\s*@\(([^)]*)\)", script).group(1)
    assert {t.technique for t in plan.tests} == set(re.findall(r"'([^']+)'", folders))


def test_no_forbidden_technique_families_in_the_plan():
    """Safety rail: the CI must never run credential access, impact or defense impairment tests."""
    doc = yaml.safe_load((ROOT / "lab" / "atomics.yaml").read_text(encoding="utf-8"))
    forbidden = ("T1003", "T1555", "T1558", "T1486", "T1490", "T1485", "T1562", "T1685",
                 "T1070", "T1105", "T1021")
    for test in doc["tests"]:
        assert not test["technique"].startswith(forbidden), test
