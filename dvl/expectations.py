"""Written expectations: what must fire, what must stay silent, which FPs are accepted.

- lab/atomics.yaml          : Atomic Red Team tests run in CI and the rules each must fire
- lab/known_fps.yaml        : accepted false positives per dataset (an allow-list, each
                              entry with a reason, like a SOC tuning ticket)
- lab/sample_expectations.yaml : real EVTX samples -> rules that must fire on them
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import yaml

from .hits import Hit
from .rules import RuleMeta

_OPS = ("equals", "contains", "startswith", "endswith")


@dataclass(frozen=True)
class AtomicTest:
    id: str
    technique: str
    guid: str
    name: str
    expect: tuple[str, ...]


@dataclass(frozen=True)
class AtomicPlan:
    atomics_commit: str
    invoke_version: str
    tests: tuple[AtomicTest, ...]
    benign_phase: str


@dataclass(frozen=True)
class Condition:
    field: str
    op: str
    value: str

    def matches(self, hit: Hit) -> bool:
        actual = hit.get(self.field).lower()
        expected = self.value.lower()
        if self.op == "equals":
            return actual == expected
        if self.op == "contains":
            return expected in actual
        if self.op == "startswith":
            return actual.startswith(expected)
        return actual.endswith(expected)


@dataclass(frozen=True)
class KnownFP:
    """An accepted false positive: rule + ALL conditions must match (AND)."""
    rule: str
    where: tuple[Condition, ...]
    reason: str
    max_count: int

    def matches(self, hit: Hit, rules_by_id: dict[str, RuleMeta]) -> bool:
        meta = rules_by_id.get(hit.rule_id)
        if meta is None or meta.key != self.rule:
            return False
        return all(cond.matches(hit) for cond in self.where)

    @property
    def value(self) -> str:
        return " AND ".join(f"{c.field} {c.op} {c.value!r}" for c in self.where)


def _check_rule_keys(keys, rules: dict[str, RuleMeta], where: str) -> None:
    unknown = [k for k in keys if k not in rules]
    if unknown:
        raise ValueError(f"{where}: unknown rule key(s) {unknown}")


def load_atomic_plan(path: Path, rules: dict[str, RuleMeta]) -> AtomicPlan:
    doc = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    tests = []
    seen = set()
    for item in doc["tests"]:
        test = AtomicTest(
            id=str(item["id"]),
            technique=str(item["technique"]),
            guid=str(item["guid"]),
            name=str(item["name"]),
            expect=tuple(item.get("expect") or ()),
        )
        if test.id in seen:
            raise ValueError(f"duplicate atomic test id {test.id}")
        seen.add(test.id)
        _check_rule_keys(test.expect, rules, f"atomic test {test.id}")
        tests.append(test)
    return AtomicPlan(
        atomics_commit=str(doc["atomic_red_team"]["atomics_commit"]),
        invoke_version=str(doc["atomic_red_team"]["invoke_atomicredteam_version"]),
        tests=tuple(tests),
        benign_phase=str(doc.get("benign_phase", "benign")),
    )


def load_known_fps(path: Path, dataset: str, rules: dict[str, RuleMeta]) -> list[KnownFP]:
    doc = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    entries = (doc.get("datasets") or {}).get(dataset) or []
    out = []
    for item in entries:
        if not str(item.get("reason", "")).strip():
            raise ValueError("known FP: every accepted false positive needs a reason")
        conditions = []
        for cond in item.get("where") or []:
            op = str(cond.get("op", "contains"))
            if op not in _OPS:
                raise ValueError(f"known FP: unsupported op {op}")
            conditions.append(Condition(field=str(cond["field"]), op=op, value=str(cond["value"])))
        if not conditions:
            raise ValueError("known FP: at least one 'where' condition is required")
        fp = KnownFP(
            rule=str(item["rule"]),
            where=tuple(conditions),
            reason=" ".join(str(item["reason"]).split()),
            max_count=int(item.get("max_count", 1)),
        )
        _check_rule_keys([fp.rule], rules, "known FP")
        out.append(fp)
    return out


def load_sample_expectations(path: Path, rules: dict[str, RuleMeta]) -> dict[str, tuple[str, ...]]:
    """{evtx file name: (rule keys that must fire)}; any other hit on these files fails."""
    doc = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    out = {}
    for name, item in (doc.get("samples") or {}).items():
        keys = tuple((item or {}).get("expect") or ())
        _check_rule_keys(keys, rules, f"sample {name}")
        out[str(name)] = keys
    return out
