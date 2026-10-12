"""Evaluate a Sigma 'value_count' correlation on building-block hits.

Chainsaw only runs single-event Sigma rules, so the correlation rule
(rules/correlation/dvl_005_discovery_burst.yml) is evaluated here. Its parameters
(base rule, group-by fields, timespan, threshold, counted field) are read from the
YAML file, so the rule file stays the single source of truth.

Semantics (as in the Sigma correlation spec): inside each group, alert when the
number of DISTINCT values of `field` within a sliding window of `timespan` reaches
`gte`. One alert per group per window: after an alert, counting restarts after the
event that triggered it.
"""
from __future__ import annotations

from collections import defaultdict
from datetime import timedelta

from .hits import Hit
from .rules import CorrelationSpec


def correlate(hits: list[Hit], spec: CorrelationSpec) -> list[Hit]:
    base = [h for h in hits if h.rule_id in spec.base_rule_ids]
    groups: dict[tuple, list[Hit]] = defaultdict(list)
    for hit in base:
        key = tuple(hit.get(name) for name in spec.group_by)
        if any(part == "" for part in key):
            continue  # an event without the grouping field cannot be correlated
        groups[key].append(hit)

    window = timedelta(seconds=spec.timespan_seconds)
    alerts: list[Hit] = []
    for key, members in groups.items():
        members.sort(key=lambda h: h.timestamp)
        start = 0
        for end, current in enumerate(members):
            while members[start].timestamp < current.timestamp - window:
                start += 1
            in_window = members[start : end + 1]
            distinct = {h.get(spec.field) for h in in_window if h.get(spec.field)}
            if len(distinct) >= spec.gte:
                alerts.append(_alert(spec, key, in_window, current, len(distinct)))
                start = end + 1  # restart counting after an alert
    return alerts


def _alert(spec: CorrelationSpec, key: tuple, members: list[Hit], last: Hit, count: int) -> Hit:
    fields = {name: value for name, value in zip(spec.group_by, key)}
    fields[f"distinct_{spec.field}"] = count
    fields["correlated_values"] = " || ".join(sorted({h.get(spec.field) for h in members}))
    return Hit(
        rule_id=spec.id,
        rule_title=spec.title,
        level=spec.level,
        timestamp=last.timestamp,
        computer=last.computer,
        event_id=None,
        channel="correlation",
        source_file=last.source_file,
        fields=fields,
    )
