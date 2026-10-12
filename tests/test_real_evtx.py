"""Chainsaw on REAL EVTX recordings (vendored SigmaHQ regression samples).

Skipped when Chainsaw is not installed (python scripts/get_chainsaw.py). In CI the
unit job installs it, so these tests always run there.
"""
from __future__ import annotations

import shutil

import pytest

from dvl import chainsaw
from dvl.evaluate import evaluate_samples
from dvl.expectations import load_sample_expectations
from dvl.rules import load_rules
from tests.conftest import ROOT

SAMPLES = ROOT / "tests" / "data" / "real_evtx"

try:
    CHAINSAW = chainsaw.find_chainsaw()
except chainsaw.ChainsawNotFound:
    CHAINSAW = None

pytestmark = pytest.mark.skipif(CHAINSAW is None, reason="Chainsaw not installed")


def _gate(rules_root):
    rules = load_rules(rules_root)
    hits = chainsaw.hunt([SAMPLES], rules_root, CHAINSAW)
    expected = load_sample_expectations(ROOT / "lab" / "sample_expectations.yaml", rules)
    return evaluate_samples(hits, expected, rules), hits


def test_rules_behave_as_documented_on_real_samples():
    result, hits = _gate(ROOT / "rules")
    assert result["passed"], result
    assert len(hits) == 3


def test_chainsaw_loads_all_seven_single_event_rules(tmp_path):
    """A rule Chainsaw cannot load is silently skipped; hunting with each rule alone
    must not raise 'No valid detection rules'."""
    for path in sorted((ROOT / "rules" / "sigma").glob("*.yml")):
        one = tmp_path / path.stem
        one.mkdir()
        shutil.copy(path, one / path.name)
        chainsaw.run_chainsaw([SAMPLES / "sigmahq_certutil_encode.evtx"], one, CHAINSAW)


def _mutant(tmp_path, filename, old, new):
    root = tmp_path / "rules"
    shutil.copytree(ROOT / "rules", root)
    target = root / "sigma" / filename
    text = target.read_text(encoding="utf-8")
    assert old in text
    target.write_text(text.replace(old, new), encoding="utf-8")
    return root


def test_mutation_removing_wmic_branch_is_caught(tmp_path):
    root = _mutant(tmp_path, "dvl_004_recon_tool_execution.yml",
                   " or (selection_wmic_img and selection_wmic_cmd)", "")
    result, _ = _gate(root)
    assert not result["passed"]


def test_mutation_breaking_the_encoded_regex_is_caught(tmp_path):
    root = _mutant(tmp_path, "dvl_001_powershell_encoded_command.yml", "{20,}", "{2000,}")
    result, _ = _gate(root)
    assert not result["passed"]


def test_mutation_schtasks_matching_any_verb_is_caught(tmp_path):
    root = _mutant(tmp_path, "dvl_002_schtasks_create.yml",
                   "      - '/create'\n      - '-create'", "      - 'schtasks'")
    result, _ = _gate(root)
    assert not result["passed"]
