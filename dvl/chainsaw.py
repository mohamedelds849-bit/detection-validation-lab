"""Run Chainsaw (WithSecure) on EVTX files and return normalised hits.

Chainsaw is the detection engine: it reads .evtx files and applies Sigma rules
through a mapping file (sigma-event-logs-all.yml) that tells it which Windows
event matches which Sigma logsource (process_creation = Sysmon 1, registry_set =
Sysmon 13, service security = Security log ...).
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

from .correlate import correlate
from .hits import Hit, from_chainsaw
from .rules import load_correlations

PROJECT_ROOT = Path(__file__).resolve().parent.parent
CHAINSAW_VERSION = "2.16.5"


class ChainsawNotFound(RuntimeError):
    pass


def find_chainsaw() -> Path:
    """DVL_CHAINSAW env var, then PATH, then tools/chainsaw/ (scripts/get_chainsaw.py)."""
    candidates = []
    if os.environ.get("DVL_CHAINSAW"):
        candidates.append(Path(os.environ["DVL_CHAINSAW"]))
    found = shutil.which("chainsaw")
    if found:
        candidates.append(Path(found))
    local = PROJECT_ROOT / "tools" / "chainsaw"
    candidates += [local / "chainsaw.exe", local / "chainsaw"]
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    raise ChainsawNotFound("Chainsaw not found: set DVL_CHAINSAW or run python scripts/get_chainsaw.py")


def find_mapping(chainsaw: Path) -> Path:
    if os.environ.get("DVL_CHAINSAW_MAPPING"):
        return Path(os.environ["DVL_CHAINSAW_MAPPING"])
    mapping = chainsaw.parent / "mappings" / "sigma-event-logs-all.yml"
    if not mapping.is_file():
        raise ChainsawNotFound(f"mapping file not found next to Chainsaw: {mapping}")
    return mapping


def run_chainsaw(evtx_paths: list[Path], sigma_dir: Path, chainsaw: Path | None = None) -> list:
    chainsaw = chainsaw or find_chainsaw()
    cmd = [
        str(chainsaw), "hunt", *[str(p) for p in evtx_paths],
        "--sigma", str(sigma_dir),
        "--mapping", str(find_mapping(chainsaw)),
        "--json", "-q", "--skip-errors",
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", check=False)
    if proc.returncode != 0:
        raise RuntimeError(f"chainsaw failed ({proc.returncode}): {proc.stderr.strip()[:500]}")
    text = proc.stdout.strip()
    return json.loads(text) if text else []


def hunt(evtx_paths: list[Path], rules_root: Path, chainsaw: Path | None = None) -> list[Hit]:
    """Single-event rules via Chainsaw, then the correlation rules in Python."""
    rules_root = Path(rules_root)
    hits = from_chainsaw(run_chainsaw(evtx_paths, rules_root / "sigma", chainsaw))
    for spec in load_correlations(rules_root):
        hits += correlate(hits, spec)
    return sorted(hits, key=lambda h: (h.timestamp, h.rule_id))
