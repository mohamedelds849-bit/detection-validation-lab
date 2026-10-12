"""Markdown rendering of a gate result (GitHub step summary or a file)."""
from __future__ import annotations


def _mark(ok: bool) -> str:
    return "PASS" if ok else "FAIL"


def _cell(text: str) -> str:
    return str(text).replace("|", "\\|").replace("\n", " ")


def render(result: dict) -> str:
    gate = result["gate"]
    if gate == "telemetry":
        return _telemetry(result)
    if gate == "goodlog":
        return _goodlog(result)
    return _samples(result)


def _telemetry(r: dict) -> str:
    lines = [f"## Gate 1 - real Windows telemetry: {_mark(r['passed'])}", ""]
    env = r.get("environment", {})
    if env:
        lines.append("Environment: " + ", ".join(f"{k}={_cell(v)}" for k, v in sorted(env.items())))
        lines.append("")
    lines += ["| Test | Technique | Atomic test | Expected | Fired | Status |",
              "|---|---|---|---|---|---|"]
    for t in r["tests"]:
        lines.append(f"| {t['id']} | {t['technique']} | {_cell(t['name'])} | "
                     f"{', '.join(t.get('expected', t.get('missing', [])))} | "
                     f"{', '.join(t.get('fired', []))} | {t['status']} |")
    benign = r["benign"]
    lines += ["", f"Benign phase ran: {benign['ran']} - false positives: {len(benign['false_positives'])}"
              f" - building blocks: {len(benign['building_blocks'])}"]
    for fp in benign["false_positives"]:
        lines.append(f"- FP {fp['rule']} at {fp['time']}: `{_cell(fp['detail'])}`")
    if r["unattributed"]:
        lines += ["", "Hits outside any phase (setup noise, not gated): "
                  + ", ".join(f"{k}={v}" for k, v in r["unattributed"].items())]
    return "\n".join(lines) + "\n"


def _goodlog(r: dict) -> str:
    lines = [f"## Gate 2 - clean-machine baseline ({r['dataset']}): {_mark(r['passed'])}", "",
             f"Alert hits: {r['alert_hits']} (accepted: {len(r['accepted'])}, unexpected: "
             f"{len(r['unexpected'])}) - building-block hits: {r['building_block_hits']}", ""]
    if r["per_rule"]:
        lines += ["| Rule | Alert hits |", "|---|---|"]
        lines += [f"| {k} | {v} |" for k, v in r["per_rule"].items()]
        lines.append("")
    for hit in r["unexpected"]:
        lines.append(f"- UNEXPECTED {hit['rule']}: `{_cell(hit['detail'])}`")
    for hit in r["accepted"]:
        lines.append(f"- accepted {hit['rule']}: {_cell(hit['reason'])}")
    for stale in r["stale_allowlist_entries"]:
        lines.append(f"- stale allow-list entry (never matched): {stale['rule']} {_cell(stale['value'])}")
    return "\n".join(lines) + "\n"


def _samples(r: dict) -> str:
    lines = [f"## Gate 3 - real EVTX samples: {_mark(r['passed'])}", "",
             "| Sample | Expected | Fired | Status |", "|---|---|---|---|"]
    for s in r["samples"]:
        lines.append(f"| {_cell(s['sample'])} | {', '.join(s['expected']) or '(none)'} | "
                     f"{', '.join(s['fired']) or '(none)'} | {s['status']} |")
    if r["unlisted_files_with_hits"]:
        lines += ["", "Other files with hits:"]
        for o in r["unlisted_files_with_hits"]:
            lines.append(f"- {_cell(o['sample'])}: {', '.join(o['fired'])}"
                         + (" (ALERT - fails the gate)" if o["alerts"] else " (building block only)"))
    return "\n".join(lines) + "\n"
