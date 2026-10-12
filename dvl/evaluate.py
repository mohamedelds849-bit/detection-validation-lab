"""The three quality gates.

1. telemetry : real EVTX from the CI Windows runner. Each Atomic test must fire its
               expected rules inside its own time window; the benign phase must not
               fire any alert rule (building blocks are allowed).
2. goodlog   : real EVTX from a clean machine (Nextron evtx-baseline). Every alert hit
               must be covered by an accepted false positive in lab/known_fps.yaml.
3. samples   : real EVTX samples (SigmaHQ regression data). Each file must fire exactly
               the expected rules - no missing hit, no unexpected alert.

Each function returns a plain dict (easy to dump as JSON and to render) with
"passed": bool. Hits are attributed to the phase whose window contains them.
"""
from __future__ import annotations

import json
from collections import Counter, defaultdict
from datetime import timedelta
from pathlib import Path

from .expectations import AtomicPlan, KnownFP
from .hits import Hit, parse_time
from .rules import RuleMeta, by_id

# Sysmon stamps the event when the process starts; Get-Date is taken by the harness
# just before / after the test on the same clock. A small margin absorbs log latency.
GRACE_BEFORE = timedelta(seconds=1)
GRACE_AFTER = timedelta(seconds=5)


def load_manifest(path: Path) -> dict:
    data = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    for phase in data["phases"]:
        phase["start_dt"] = parse_time(phase["start"])
        phase["end_dt"] = parse_time(phase["end"])
        if phase["end_dt"] < phase["start_dt"]:
            raise ValueError(f"phase {phase['id']} ends before it starts")
    return data


def phase_of(hit: Hit, phases: list[dict]) -> str | None:
    for phase in phases:
        if phase["start_dt"] - GRACE_BEFORE <= hit.timestamp <= phase["end_dt"] + GRACE_AFTER:
            return phase["id"]
    return None


def _key(hit: Hit, rules_by_id: dict[str, RuleMeta]) -> str:
    meta = rules_by_id.get(hit.rule_id)
    return meta.key if meta else f"unknown:{hit.rule_id}"


def _brief(hit: Hit, rules_by_id: dict[str, RuleMeta]) -> dict:
    detail = (hit.get("CommandLine") or hit.get("TargetObject") or hit.get("TargetUserName")
              or hit.get("correlated_values"))
    return {
        "rule": _key(hit, rules_by_id),
        "time": hit.timestamp.isoformat(),
        "detail": detail[:200],
    }


def evaluate_telemetry(hits: list[Hit], manifest: dict, plan: AtomicPlan,
                       rules: dict[str, RuleMeta]) -> dict:
    rules_by_id = by_id(rules)
    phases = manifest["phases"]
    phase_ids = {p["id"] for p in phases}
    by_phase: dict[str | None, list[Hit]] = defaultdict(list)
    for hit in hits:
        by_phase[phase_of(hit, phases)].append(hit)

    tests = []
    for test in plan.tests:
        phase = next((p for p in phases if p["id"] == test.id), None)
        if phase is None:
            tests.append({"id": test.id, "technique": test.technique, "name": test.name,
                          "status": "NOT_RUN", "missing": list(test.expect), "fired": []})
            continue
        fired = sorted({_key(h, rules_by_id) for h in by_phase.get(test.id, [])})
        missing = [k for k in test.expect if k not in fired]
        if phase.get("status", "ok") != "ok":
            status = "ERROR"
        else:
            status = "PASS" if not missing else "MISSED"
        tests.append({"id": test.id, "technique": test.technique, "name": test.name,
                      "guid": test.guid, "status": status, "expected": list(test.expect),
                      "fired": fired, "missing": missing,
                      "extra": [k for k in fired if k not in test.expect]})

    benign_hits = by_phase.get(plan.benign_phase, [])
    false_positives = [_brief(h, rules_by_id) for h in benign_hits
                       if not rules_by_id.get(h.rule_id, _UNKNOWN).is_building_block]
    building_blocks = [_brief(h, rules_by_id) for h in benign_hits
                       if rules_by_id.get(h.rule_id, _UNKNOWN).is_building_block]
    benign_ran = plan.benign_phase in phase_ids
    unattributed = Counter(_key(h, rules_by_id) for h in by_phase.get(None, []))

    passed = (benign_ran and not false_positives
              and all(t["status"] == "PASS" for t in tests))
    return {
        "gate": "telemetry",
        "passed": passed,
        "host": manifest.get("host", ""),
        "environment": {k: v for k, v in manifest.items() if k not in ("phases",)},
        "tests": tests,
        "benign": {"ran": benign_ran, "false_positives": false_positives,
                   "building_blocks": building_blocks},
        "unattributed": dict(sorted(unattributed.items())),
        "total_hits": len(hits),
    }


def evaluate_goodlog(hits: list[Hit], known: list[KnownFP], rules: dict[str, RuleMeta],
                     dataset: str) -> dict:
    rules_by_id = by_id(rules)
    alerts = [h for h in hits if not rules_by_id.get(h.rule_id, _UNKNOWN).is_building_block]
    used: Counter = Counter()
    accepted, unexpected = [], []
    for hit in alerts:
        entry = next((fp for fp in known if fp.matches(hit, rules_by_id)), None)
        if entry is not None and used[id(entry)] < entry.max_count:
            used[id(entry)] += 1
            accepted.append({**_brief(hit, rules_by_id), "reason": entry.reason})
        else:
            unexpected.append(_brief(hit, rules_by_id))
    stale = [{"rule": fp.rule, "value": fp.value} for fp in known if used[id(fp)] == 0]
    per_rule = Counter(_key(h, rules_by_id) for h in alerts)
    return {
        "gate": "goodlog",
        "dataset": dataset,
        "passed": not unexpected,
        "alert_hits": len(alerts),
        "building_block_hits": len(hits) - len(alerts),
        "per_rule": dict(sorted(per_rule.items())),
        "accepted": accepted,
        "unexpected": unexpected,
        "stale_allowlist_entries": stale,
    }


def evaluate_samples(hits: list[Hit], expected: dict[str, tuple[str, ...]],
                     rules: dict[str, RuleMeta], strict_unknown_files: bool = True) -> dict:
    """strict_unknown_files: an ALERT on a file that is not listed is a failure.
    Building-block hits on unlisted files are reported, not failed."""
    rules_by_id = by_id(rules)
    fired: dict[str, set[str]] = defaultdict(set)
    for hit in hits:
        fired[hit.source_file].add(_key(hit, rules_by_id))

    results, passed = [], True
    for name, keys in sorted(expected.items()):
        got = fired.get(name, set())
        missing = [k for k in keys if k not in got]
        unexpected = sorted(k for k in got if k not in keys
                            and not rules.get(k, _UNKNOWN).is_building_block)
        ok = not missing and not unexpected
        passed &= ok
        results.append({"sample": name, "expected": list(keys), "fired": sorted(got),
                        "missing": missing, "unexpected": unexpected,
                        "status": "PASS" if ok else "FAIL"})

    others = []
    for name, got in sorted(fired.items()):
        if name in expected:
            continue
        alerts = sorted(k for k in got if not rules.get(k, _UNKNOWN).is_building_block)
        others.append({"sample": name, "fired": sorted(got), "alerts": alerts})
        if strict_unknown_files and alerts:
            passed = False
    return {"gate": "samples", "passed": passed, "samples": results, "unlisted_files_with_hits": others}


class _Unknown:
    is_building_block = False
    key = "unknown"


_UNKNOWN = _Unknown()
