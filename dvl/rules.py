"""Read the rule files: metadata of single-event rules and the correlation rule.

Short keys ("dvl_001") come from the file names, so expectations stay readable while
Chainsaw reports the rule UUID.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml

KEY_RE = re.compile(r"^(dvl_\d{3})_")
TECHNIQUE_RE = re.compile(r"^attack\.(t\d{4}(?:\.\d{3})?)$")
TIMESPAN_RE = re.compile(r"^(\d+)([smhd])$")
_UNIT_SECONDS = {"s": 1, "m": 60, "h": 3600, "d": 86400}


@dataclass(frozen=True)
class RuleMeta:
    key: str
    id: str
    title: str
    level: str
    techniques: tuple[str, ...]
    path: Path
    is_correlation: bool = False

    @property
    def is_building_block(self) -> bool:
        """Informational rules are building blocks: recorded, never an alert."""
        return self.level == "informational"


@dataclass(frozen=True)
class CorrelationSpec:
    key: str
    id: str
    title: str
    level: str
    base_rule_ids: tuple[str, ...]
    group_by: tuple[str, ...]
    timespan_seconds: int
    gte: int
    field: str
    techniques: tuple[str, ...] = field(default_factory=tuple)


def parse_timespan(value: str) -> int:
    """'5m' -> 300. Only the Sigma units s/m/h/d are accepted."""
    match = TIMESPAN_RE.match(str(value).strip())
    if not match:
        raise ValueError(f"invalid Sigma timespan: {value!r}")
    return int(match.group(1)) * _UNIT_SECONDS[match.group(2)]


def _techniques(tags) -> tuple[str, ...]:
    out = []
    for tag in tags or []:
        match = TECHNIQUE_RE.match(str(tag).lower())
        if match:
            out.append(match.group(1).upper())
    return tuple(out)


def _key_for(path: Path) -> str:
    match = KEY_RE.match(path.name)
    if not match:
        raise ValueError(f"rule file name must start with dvl_NNN_: {path.name}")
    return match.group(1)


def load_rule_file(path: Path) -> dict:
    with open(path, encoding="utf-8") as handle:
        return yaml.safe_load(handle)


def load_rules(rules_root: Path) -> dict[str, RuleMeta]:
    """All rules (single + correlation) under rules_root, keyed by short key."""
    rules: dict[str, RuleMeta] = {}
    for path in sorted(Path(rules_root).rglob("dvl_*.yml")):
        doc = load_rule_file(path)
        meta = RuleMeta(
            key=_key_for(path),
            id=str(doc["id"]),
            title=str(doc["title"]),
            level=str(doc.get("level", "")),
            techniques=_techniques(doc.get("tags")),
            path=path,
            is_correlation="correlation" in doc,
        )
        if meta.key in rules:
            raise ValueError(f"duplicate rule key {meta.key}")
        rules[meta.key] = meta
    return rules


def by_id(rules: dict[str, RuleMeta]) -> dict[str, RuleMeta]:
    return {meta.id: meta for meta in rules.values()}


def load_correlation(path: Path) -> CorrelationSpec:
    doc = load_rule_file(path)
    corr = doc["correlation"]
    if corr.get("type") != "value_count":
        raise ValueError("only value_count correlations are implemented")
    condition = corr["condition"]
    return CorrelationSpec(
        key=_key_for(Path(path)),
        id=str(doc["id"]),
        title=str(doc["title"]),
        level=str(doc.get("level", "")),
        base_rule_ids=tuple(str(r) for r in corr["rules"]),
        group_by=tuple(corr.get("group-by") or ()),
        timespan_seconds=parse_timespan(corr["timespan"]),
        gte=int(condition["gte"]),
        field=str(condition["field"]),
        techniques=_techniques(doc.get("tags")),
    )


def load_correlations(rules_root: Path) -> list[CorrelationSpec]:
    return [load_correlation(p) for p in sorted((Path(rules_root) / "correlation").glob("dvl_*.yml"))]
