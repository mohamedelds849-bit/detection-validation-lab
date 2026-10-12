from __future__ import annotations

from dataclasses import replace

import pytest

from dvl.correlate import correlate
from dvl.rules import load_correlations, parse_timespan
from tests.conftest import ROOT


@pytest.fixture(scope="module")
def spec():
    (s,) = load_correlations(ROOT / "rules")
    return s


def _recon(make_hit, t, cmd, parent="P1", computer="RUNNER"):
    return make_hit("dvl_004", t, CommandLine=cmd, ParentProcessGuid=parent, computer=computer)


def test_three_distinct_commands_from_one_parent_fire(make_hit, spec):
    hits = [_recon(make_hit, 0, "net user"), _recon(make_hit, 1, "cmdkey /list"),
            _recon(make_hit, 2, "net localgroup")]
    (alert,) = correlate(hits, spec)
    assert alert.rule_id == spec.id and alert.level == "high"
    assert alert.fields["distinct_CommandLine"] == 3
    assert alert.fields["ParentProcessGuid"] == "P1"
    assert alert.timestamp == hits[-1].timestamp


def test_two_distinct_is_below_threshold(make_hit, spec):
    hits = [_recon(make_hit, 0, "whoami"), _recon(make_hit, 1, "net localgroup")]
    assert correlate(hits, spec) == []


def test_same_command_repeated_counts_once(make_hit, spec):
    hits = [_recon(make_hit, i, "whoami") for i in range(5)]
    assert correlate(hits, spec) == []


def test_window_boundary_300_vs_301_seconds(make_hit, spec):
    inside = [_recon(make_hit, 0, "a"), _recon(make_hit, 100, "b"), _recon(make_hit, 300, "c")]
    outside = [_recon(make_hit, 0, "a"), _recon(make_hit, 100, "b"), _recon(make_hit, 301, "c")]
    assert len(correlate(inside, spec)) == 1
    assert correlate(outside, spec) == []


def test_different_parents_or_hosts_are_not_mixed(make_hit, spec):
    by_parent = [_recon(make_hit, 0, "a", "P1"), _recon(make_hit, 1, "b", "P2"), _recon(make_hit, 2, "c", "P3")]
    by_host = [_recon(make_hit, 0, "a", computer="H1"), _recon(make_hit, 1, "b", computer="H2"),
               _recon(make_hit, 2, "c", computer="H3")]
    assert correlate(by_parent, spec) == []
    assert correlate(by_host, spec) == []


def test_events_without_parent_guid_are_ignored(make_hit, spec):
    hits = [make_hit("dvl_004", i, CommandLine=c) for i, c in enumerate("abc")]
    assert correlate(hits, spec) == []


def test_only_base_rule_hits_count(make_hit, spec):
    hits = [_recon(make_hit, 0, "a"), _recon(make_hit, 1, "b"),
            make_hit("dvl_001", 2, CommandLine="c", ParentProcessGuid="P1")]
    assert correlate(hits, spec) == []


def test_counting_restarts_after_an_alert(make_hit, spec):
    hits = [_recon(make_hit, i, c) for i, c in enumerate(["a", "b", "c", "d", "e"])]
    assert len(correlate(hits, spec)) == 1  # d, e alone are only 2 new values
    hits.append(_recon(make_hit, 6, "f"))
    assert len(correlate(hits, spec)) == 2


def test_unsorted_input_is_handled(make_hit, spec):
    hits = [_recon(make_hit, 2, "c"), _recon(make_hit, 0, "a"), _recon(make_hit, 1, "b")]
    assert len(correlate(hits, spec)) == 1


def test_threshold_comes_from_the_rule_file(make_hit, spec):
    hits = [_recon(make_hit, 0, "a"), _recon(make_hit, 1, "b")]
    assert len(correlate(hits, replace(spec, gte=2))) == 1


@pytest.mark.parametrize("text,seconds", [("30s", 30), ("5m", 300), ("2h", 7200), ("1d", 86400)])
def test_parse_timespan(text, seconds):
    assert parse_timespan(text) == seconds


@pytest.mark.parametrize("bad", ["5", "5min", "-1m", ""])
def test_parse_timespan_rejects(bad):
    with pytest.raises(ValueError):
        parse_timespan(bad)
