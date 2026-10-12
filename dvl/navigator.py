"""ATT&CK Navigator layer: which techniques the rules cover, and how they were proven.

Colours: green = the rule fired on real telemetry in the CI gate (a telemetry report
with PASS for that rule is given), yellow = rule exists but no telemetry proof given.
Open the JSON in https://mitre-attack.github.io/attack-navigator/ (Open Existing Layer).
"""
from __future__ import annotations

from .rules import RuleMeta

PROVEN = "#8ec843"
UNPROVEN = "#ffe766"


def proven_rule_keys(telemetry_report: dict | None) -> set[str]:
    if not telemetry_report:
        return set()
    keys = set()
    for test in telemetry_report.get("tests", []):
        if test.get("status") == "PASS":
            keys.update(test.get("expected", []))
    return keys


def build_layer(rules: dict[str, RuleMeta], telemetry_report: dict | None = None,
                attack_version: str = "19") -> dict:
    proven = proven_rule_keys(telemetry_report)
    techniques: dict[str, list[RuleMeta]] = {}
    for meta in rules.values():
        for technique in meta.techniques:
            techniques.setdefault(technique, []).append(meta)

    entries = []
    for technique, metas in sorted(techniques.items()):
        is_proven = any(m.key in proven for m in metas)
        entries.append({
            "techniqueID": technique,
            "score": 2 if is_proven else 1,
            "color": PROVEN if is_proven else UNPROVEN,
            "comment": "; ".join(f"{m.key} {m.title}" for m in sorted(metas, key=lambda m: m.key)),
            "enabled": True,
        })
    return {
        "name": "detection-validation-lab coverage",
        "versions": {"attack": attack_version, "navigator": "5.1.0", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": "Green: fired on real Sysmon telemetry in CI. Yellow: rule only.",
        "techniques": entries,
        "legendItems": [
            {"label": "validated on real telemetry (CI)", "color": PROVEN},
            {"label": "rule written, not proven", "color": UNPROVEN},
        ],
    }
