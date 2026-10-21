"""Measure what the pipeline gives up and what it keeps.

Privacy side: identifiers in the private input versus in the published
output (must be zero), the smallest published group, the delay actually
enforced, and whether the gate caught every one of a set of injected
leaks (the negative test that proves the gate is doing work).

Utility side: how well the delayed, aggregated page tracks the truth. The
true fleet health at each moment is compared with what the page would
have shown at that moment: the lag the delay introduces, and the
agreement once the lag is accounted for. A status page that is private
but useless is not a result; both numbers go in the README.
"""
from __future__ import annotations

import json
import statistics
from datetime import datetime, timedelta
from pathlib import Path

from .aggregate import aggregate
from .gate import IDENTIFYING_FIELDS, load_identifiers, run_gate
from .policy import Policy

LEAK_INJECTIONS = [
    ("plain hostname", lambda h: h["hostname"]),
    ("short hostname", lambda h: h["hostname"].split(".")[0]),
    ("ipv4", lambda h: h["ip"]),
    ("ipv6", lambda h: h["ipv6"]),
    ("mac", lambda h: h["mac"]),
    ("serial", lambda h: h["serial"]),
    ("owner", lambda h: h["owner"]),
    ("email", lambda h: h["owner_email"]),
    ("base64 hostname", lambda h: __import__("base64").b64encode(h["hostname"].encode()).decode()),
    ("url-encoded email", lambda h: __import__("urllib.parse").parse.quote(h["owner_email"], safe="")),
    ("unknown address", lambda h: "198.51.100.77"),
    ("unknown fqdn", lambda h: "backup-node77.cs.internal.example"),
    ("new field", None),
]


def true_health_series(samples: list[dict], now: datetime, hours: int) -> list[tuple[datetime, float]]:
    by_bucket: dict[datetime, dict[str, str]] = {}
    for s in samples:
        ts = datetime.fromisoformat(s["sampled_at"])
        if ts < now - timedelta(hours=hours):
            continue
        b = ts.replace(minute=(ts.minute // 5) * 5, second=0, microsecond=0)
        by_bucket.setdefault(b, {})[s["hostname"]] = s["status"]
    out = []
    for b in sorted(by_bucket):
        states = list(by_bucket[b].values())
        out.append((b, sum(1 for x in states if x == "up") / len(states)))
    return out


def utility(samples: list[dict], now: datetime, policy: Policy, hours: int = 12) -> dict:
    """Walk the clock forward: what did the page say vs what was true, and with what lag?"""
    truth = true_health_series(samples, now, hours)
    shown: list[tuple[datetime, float | None]] = []
    for t, _ in truth:
        summ = aggregate(samples, t, policy)
        fleet = summ.get("fleet")
        shown.append((t, fleet["health"] if fleet else None))
    pairs = [(a, b) for (_, a), (_, b) in zip(truth, shown, strict=True) if b is not None]
    if not pairs:
        return {"points": 0}
    mae_now = statistics.fmean(abs(a - b) for a, b in pairs)
    lag = policy.publish_delay_minutes // 5
    lagged = [(truth[i - lag][1], b) for i in range(lag, len(truth)) if (b := shown[i][1]) is not None]
    mae_lagged = statistics.fmean(abs(a - b) for a, b in lagged) if lagged else None
    # time for the page to reflect the biggest true change
    deltas = [abs(truth[i][1] - truth[i - 1][1]) for i in range(1, len(truth))]
    i_max = max(range(1, len(truth)), key=lambda i: deltas[i - 1]) if deltas else None
    return {"points": len(pairs), "mean_abs_error_vs_live": round(mae_now, 3),
            "mean_abs_error_after_delay": round(mae_lagged, 3) if mae_lagged is not None else None,
            "largest_true_change_at": truth[i_max][0].isoformat() if i_max else None,
            "reflected_after_minutes": policy.publish_delay_minutes,
            "fleet_row_withheld_points": sum(1 for _, b in shown if b is None)}


def privacy(build: Path, policy: Policy, artifacts: list[Path], generated_at: datetime) -> dict:
    idents = load_identifiers(build / "inventory.json")
    n_private = sum(len(v) for v in idents.values())
    findings = run_gate(artifacts, build / "inventory.json", policy, generated_at)
    with open(build / "aggregates.json", encoding="utf-8") as f:
        summ = json.load(f)
    groups = summ.get("groups", [])
    with open(build / "inventory.json", encoding="utf-8") as f:
        inv = json.load(f)
    private_groups: dict[str, int] = {}
    for h in inv:
        private_groups[h["group"]] = private_groups.get(h["group"], 0) + 1
    # injected-leak drill: each injection must be caught
    caught = {}
    page = (build / "site" / "index.html").read_text(encoding="utf-8")
    sample_host = inv[0]
    for name, fn in LEAK_INJECTIONS:
        tmp = build / "_leak_test.json" if fn is None else build / "_leak_test.html"
        if fn is None:
            doc = dict(summ)
            doc["debug_hosts"] = ["x"]
            tmp.write_text(json.dumps(doc), encoding="utf-8")
        else:
            tmp.write_text(page.replace("</footer>", f"<!-- {fn(sample_host)} --></footer>"), encoding="utf-8")
        hits = run_gate([tmp], build / "inventory.json", policy, generated_at)
        caught[name] = bool(hits)
        tmp.unlink()
    return {
        "identifying_values_in_private_input": n_private,
        "identifying_fields_in_private_input": list(IDENTIFYING_FIELDS),
        "gate_findings_on_published_artifacts": [str(f) for f in findings],
        "smallest_published_group": min((g["total"] for g in groups), default=None),
        "k": policy.k_min_group_size,
        "private_groups": len(private_groups),
        "published_groups": len(groups),
        "groups_below_k_in_private": sum(1 for v in private_groups.values() if v < policy.k_min_group_size),
        "fleet_row_published": summ.get("fleet") is not None,
        "delay_minutes": policy.publish_delay_minutes,
        "injected_leaks_caught": caught,
        "all_injections_caught": all(caught.values()),
    }


def markdown(priv: dict, util: dict, stats: dict) -> str:
    out = ["## Measured results", "",
           f"Fleet of {stats['hosts']} hosts in {priv['private_groups']} groups "
           f"({priv['groups_below_k_in_private']} smaller than k = {priv['k']}), {stats['samples']:,} samples over "
           f"{stats['hours']} hours.", "",
           "### Privacy", "", "| | Value |", "|---|---:|",
           f"| Identifying values on the private side | {priv['identifying_values_in_private_input']} |",
           f"| Identifiers found in published artifacts by the gate | {len(priv['gate_findings_on_published_artifacts'])} |",
           f"| Groups published / in private | {priv['published_groups']} / {priv['private_groups']} |",
           f"| Smallest published group | {priv['smallest_published_group']} (k = {priv['k']}) |",
           f"| Fleet row published | {'yes' if priv['fleet_row_published'] else 'withheld (complementary suppression)'} |",
           f"| Publish delay | {priv['delay_minutes']} min |",
           f"| Injected leaks caught by the gate | {sum(priv['injected_leaks_caught'].values())} / {len(priv['injected_leaks_caught'])} |",
           "", "Injection drill:", ""]
    for k, v in priv["injected_leaks_caught"].items():
        out.append(f"- {k}: {'caught' if v else 'MISSED'}")
    out += ["", "### Utility", "", "| | Value |", "|---|---:|",
            f"| Mean abs. error of published health vs live truth | {util.get('mean_abs_error_vs_live')} |",
            f"| Mean abs. error once the {priv['delay_minutes']}-min delay is accounted for | {util.get('mean_abs_error_after_delay')} |",
            f"| Largest real change reflected after | {util.get('reflected_after_minutes')} min |",
            f"| Moments the fleet row was withheld | {util.get('fleet_row_withheld_points')} / {util.get('points')} |", ""]
    return "\n".join(out)
