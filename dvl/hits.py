"""A 'hit' = one rule matching one event. Normalised from Chainsaw's JSON output.

Chainsaw (`chainsaw hunt --json`) prints a list of detections. For Sigma rules each
item has the rule id/name/level, a timestamp and the full event under
document.data.Event (System + EventData). We keep only what the evaluation needs.
"""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path


def parse_time(value: str) -> datetime:
    """ISO-8601 to an aware UTC datetime.

    Accepts 'Z', '+00:00' and the 7 fractional digits that PowerShell's
    ToString('o') produces (Python only keeps microseconds, so extra digits are cut).
    """
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    if "." in text:
        head, rest = text.split(".", 1)
        digits = ""
        i = 0
        while i < len(rest) and rest[i].isdigit():
            digits += rest[i]
            i += 1
        text = f"{head}.{(digits + '000000')[:6]}{rest[i:]}"
    parsed = datetime.fromisoformat(text)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


@dataclass
class Hit:
    rule_id: str
    rule_title: str
    level: str
    timestamp: datetime
    computer: str = ""
    event_id: int | None = None
    channel: str = ""
    source_file: str = ""
    fields: dict = field(default_factory=dict)

    def get(self, name: str) -> str:
        """Event field lookup used by correlation (Computer comes from System)."""
        if name == "Computer":
            return self.computer
        value = self.fields.get(name)
        return "" if value is None else str(value)

    def to_dict(self) -> dict:
        data = asdict(self)
        data["timestamp"] = self.timestamp.isoformat()
        return data

    @classmethod
    def from_dict(cls, data: dict) -> "Hit":
        data = dict(data)
        data["timestamp"] = parse_time(data["timestamp"])
        return cls(**data)


def _event_data(event: dict) -> dict:
    data = event.get("EventData")
    if isinstance(data, dict):
        return {k: v for k, v in data.items() if not isinstance(v, (dict, list))}
    return {}


def from_chainsaw(items: list) -> list[Hit]:
    hits = []
    for item in items:
        if item.get("group") != "Sigma" and item.get("source") != "sigma":
            continue
        document = item.get("document") or {}
        event = (document.get("data") or {}).get("Event") or {}
        system = event.get("System") or {}
        event_id = system.get("EventID")
        if isinstance(event_id, dict):  # <EventID Qualifiers="..">4720</EventID>
            event_id = event_id.get("#text")
        hits.append(
            Hit(
                rule_id=str(item["id"]),
                rule_title=str(item.get("name", "")),
                level=str(item.get("level", "")),
                timestamp=parse_time(item["timestamp"]),
                computer=str(system.get("Computer", "")),
                event_id=int(event_id) if event_id is not None else None,
                channel=str(system.get("Channel", "")),
                source_file=Path(str(document.get("path", "")).replace("\\", "/")).name,
                fields=_event_data(event),
            )
        )
    return hits


def load_chainsaw_json(path: Path) -> list[Hit]:
    text = Path(path).read_text(encoding="utf-8").strip()
    return from_chainsaw(json.loads(text) if text else [])


def save_hits(hits: list[Hit], path: Path) -> None:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    payload = [h.to_dict() for h in sorted(hits, key=lambda h: (h.timestamp, h.rule_id))]
    Path(path).write_text(json.dumps(payload, indent=1, ensure_ascii=False), encoding="utf-8")


def load_hits(path: Path) -> list[Hit]:
    return [Hit.from_dict(d) for d in json.loads(Path(path).read_text(encoding="utf-8"))]
