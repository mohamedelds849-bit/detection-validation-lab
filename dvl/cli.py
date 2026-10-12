"""Command line.

    python -m dvl hunt      --evtx DIR_OR_FILE... --out work/hits.json
    python -m dvl telemetry --hits work/hits.json --manifest work/manifest.json
    python -m dvl goodlog   --hits work/goodlog-hits.json [--dataset nextron-win10-client]
    python -m dvl samples   --hits work/sample-hits.json --expect lab/sample_expectations.yaml
    python -m dvl navigator --out reports/coverage-layer.json [--telemetry-report work/telemetry.json]

Exit codes: 0 = gate passed, 1 = gate failed, 2 = bad input or tool error.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from . import chainsaw, evaluate, expectations, navigator, report
from .hits import load_hits, save_hits
from .rules import load_rules

ROOT = Path(__file__).resolve().parent.parent


def _emit(result: dict, out: str | None) -> int:
    text = report.render(result)
    print(text)
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as handle:
            handle.write(text + "\n")
    if out:
        Path(out).parent.mkdir(parents=True, exist_ok=True)
        Path(out).write_text(json.dumps(result, indent=1, ensure_ascii=False), encoding="utf-8")
    return 0 if result["passed"] else 1


def cmd_hunt(args) -> int:
    hits = chainsaw.hunt([Path(p) for p in args.evtx], Path(args.rules))
    save_hits(hits, Path(args.out))
    print(f"{len(hits)} hits written to {args.out}")
    return 0


def cmd_telemetry(args) -> int:
    rules = load_rules(Path(args.rules))
    plan = expectations.load_atomic_plan(Path(args.plan), rules)
    manifest = evaluate.load_manifest(Path(args.manifest))
    result = evaluate.evaluate_telemetry(load_hits(Path(args.hits)), manifest, plan, rules)
    return _emit(result, args.out)


def cmd_goodlog(args) -> int:
    rules = load_rules(Path(args.rules))
    known = expectations.load_known_fps(Path(args.known_fps), args.dataset, rules)
    result = evaluate.evaluate_goodlog(load_hits(Path(args.hits)), known, rules, args.dataset)
    return _emit(result, args.out)


def cmd_samples(args) -> int:
    rules = load_rules(Path(args.rules))
    expected = expectations.load_sample_expectations(Path(args.expect), rules)
    result = evaluate.evaluate_samples(load_hits(Path(args.hits)), expected, rules)
    return _emit(result, args.out)


def cmd_navigator(args) -> int:
    rules = load_rules(Path(args.rules))
    telemetry = None
    if args.telemetry_report:
        telemetry = json.loads(Path(args.telemetry_report).read_text(encoding="utf-8"))
    layer = navigator.build_layer(rules, telemetry)
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text(json.dumps(layer, indent=1), encoding="utf-8")
    print(f"layer with {len(layer['techniques'])} techniques written to {args.out}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="dvl", description=__doc__.split("\n")[0])
    parser.add_argument("--rules", default=str(ROOT / "rules"), help="rules root (sigma/ + correlation/)")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("hunt", help="run Chainsaw + correlation on EVTX files")
    p.add_argument("--evtx", nargs="+", required=True)
    p.add_argument("--out", required=True)
    p.set_defaults(func=cmd_hunt)

    p = sub.add_parser("telemetry", help="gate 1: Atomic tests on the CI runner")
    p.add_argument("--hits", required=True)
    p.add_argument("--manifest", required=True)
    p.add_argument("--plan", default=str(ROOT / "lab" / "atomics.yaml"))
    p.add_argument("--out")
    p.set_defaults(func=cmd_telemetry)

    p = sub.add_parser("goodlog", help="gate 2: clean-machine baseline")
    p.add_argument("--hits", required=True)
    p.add_argument("--dataset", default="nextron-win10-client")
    p.add_argument("--known-fps", default=str(ROOT / "lab" / "known_fps.yaml"))
    p.add_argument("--out")
    p.set_defaults(func=cmd_goodlog)

    p = sub.add_parser("samples", help="gate 3: real EVTX samples with expected hits")
    p.add_argument("--hits", required=True)
    p.add_argument("--expect", default=str(ROOT / "lab" / "sample_expectations.yaml"))
    p.add_argument("--out")
    p.set_defaults(func=cmd_samples)

    p = sub.add_parser("navigator", help="ATT&CK Navigator coverage layer")
    p.add_argument("--out", required=True)
    p.add_argument("--telemetry-report")
    p.set_defaults(func=cmd_navigator)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except (FileNotFoundError, ValueError, KeyError, json.JSONDecodeError,
            chainsaw.ChainsawNotFound, RuntimeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
