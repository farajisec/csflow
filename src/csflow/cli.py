"""Command-line entry point: ``csflow <command>``.

    simulate   private side: inventory + samples (synthetic)
    aggregate  raw samples -> aggregates.json (delay, k-anonymity, schema allowlist)
    render     aggregates.json -> site/index.html
    gate       scan everything about to be published; exit 1 on any finding
    report     privacy and utility measurements -> report.{json,md}
    all        simulate -> aggregate -> render -> gate -> report
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from . import __version__
from .aggregate import aggregate, load_samples, write_aggregates
from .gate import run_gate
from .policy import Policy
from .render import render
from .report import markdown, privacy, utility
from .simulate import generate

NOW = datetime(2026, 3, 2, 12, 0, tzinfo=timezone.utc)
PUBLISHED = ["aggregates.json", "site/index.html"]


def _now(a) -> datetime:
    return datetime.fromisoformat(a.now) if a.now else NOW


def cmd_simulate(a):
    s = generate(a.seed, a.build, a.hours, _now(a))
    print(f"{s['hosts']} hosts, {s['samples']:,} samples -> {a.build} (private side)")
    return 0


def cmd_aggregate(a):
    policy = Policy.load(a.policy)
    samples = list(load_samples(a.build / "samples.jsonl"))
    summ = aggregate(samples, _now(a), policy, a.seed)
    write_aggregates(a.build / "aggregates.json", summ)
    print(f"{len(summ['groups'])} group rows, fleet row {'published' if summ.get('fleet') else 'withheld'}, "
          f"as of {summ['as_of']} ({policy.publish_delay_minutes} min delay) -> aggregates.json")
    return 0


def cmd_render(a):
    with open(a.build / "aggregates.json", encoding="utf-8") as f:
        summ = json.load(f)
    (a.build / "site").mkdir(exist_ok=True)
    (a.build / "site" / "index.html").write_text(render(summ), encoding="utf-8")
    print("rendered site/index.html from aggregates only")
    return 0


def cmd_gate(a):
    policy = Policy.load(a.policy)
    arts = [a.build / p for p in PUBLISHED]
    findings = run_gate(arts, a.build / "inventory.json", policy, _now(a))
    if findings:
        print(f"PUBLICATION REFUSED: {len(findings)} finding(s)")
        for f in findings[:50]:
            print(f"  {f}")
        return 1
    print(f"gate: PASS ({len(arts)} artifact(s), schema, k-anonymity, delay and suppression checks)")
    return 0


def cmd_report(a):
    policy = Policy.load(a.policy)
    samples = list(load_samples(a.build / "samples.jsonl"))
    with open(a.build / "inventory.json", encoding="utf-8") as f:
        inv = json.load(f)
    priv = privacy(a.build, policy, [a.build / p for p in PUBLISHED], _now(a))
    util = utility(samples, _now(a), policy)
    stats = {"hosts": len(inv), "samples": len(samples), "hours": a.hours}
    with open(a.build / "report.json", "w", encoding="utf-8") as f:
        json.dump({"privacy": priv, "utility": util, "stats": stats}, f, indent=1)
    (a.build / "report.md").write_text(markdown(priv, util, stats), encoding="utf-8")
    print(f"privacy: {len(priv['gate_findings_on_published_artifacts'])} findings, injections caught "
          f"{sum(priv['injected_leaks_caught'].values())}/{len(priv['injected_leaks_caught'])}; "
          f"utility: MAE {util.get('mean_abs_error_vs_live')} live / {util.get('mean_abs_error_after_delay')} lagged")
    if a.strict and (priv["gate_findings_on_published_artifacts"] or not priv["all_injections_caught"]):
        return 1
    return 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="csflow", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--version", action="version", version=__version__)
    p.add_argument("--build", type=Path, default=Path("build"))
    p.add_argument("--policy", type=Path, default=Path("policy.json"))
    p.add_argument("--now", default=None, help="ISO timestamp for 'now' (default: a fixed instant, for reproducibility)")
    p.add_argument("--seed", type=int, default=42)
    p.add_argument("--hours", type=int, default=30)
    sub = p.add_subparsers(dest="cmd", required=True)
    for name in ("simulate", "aggregate", "render", "gate"):
        sub.add_parser(name)
    sub.add_parser("report").add_argument("--strict", action="store_true")
    sub.add_parser("all").add_argument("--strict", action="store_true")
    a = p.parse_args(argv)
    if a.cmd == "all":
        return cmd_simulate(a) or cmd_aggregate(a) or cmd_render(a) or cmd_gate(a) or cmd_report(a)
    return {"simulate": cmd_simulate, "aggregate": cmd_aggregate, "render": cmd_render, "gate": cmd_gate,
            "report": cmd_report}[a.cmd](a)


if __name__ == "__main__":
    sys.exit(main())
