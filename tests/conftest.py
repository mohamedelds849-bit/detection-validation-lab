from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from dvl.hits import Hit
from dvl.rules import load_rules

ROOT = Path(__file__).resolve().parent.parent
T0 = datetime(2026, 10, 11, 12, 0, 0, tzinfo=timezone.utc)


@pytest.fixture(scope="session")
def rules():
    return load_rules(ROOT / "rules")


@pytest.fixture
def make_hit(rules):
    def _make(key: str, seconds: float = 0, **fields) -> Hit:
        meta = rules[key]
        computer = fields.pop("computer", "RUNNER")
        source_file = fields.pop("source_file", "test.evtx")
        return Hit(
            rule_id=meta.id,
            rule_title=meta.title,
            level=meta.level,
            timestamp=T0 + timedelta(seconds=seconds),
            computer=computer,
            event_id=1,
            channel="Microsoft-Windows-Sysmon/Operational",
            source_file=source_file,
            fields=fields,
        )
    return _make


def iso(seconds: float) -> str:
    return (T0 + timedelta(seconds=seconds)).isoformat()
