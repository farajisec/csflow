#!/usr/bin/env python3
"""Aggregate raw telemetry into a publish-safe summary.

Two privacy controls are applied here, by construction:

1. Delay. Only samples older than PUBLISH_DELAY are considered. A public
   board should never reflect the live state of the fleet in real time,
   because real-time status is itself operational intelligence.

2. Aggregation. The output carries counts per group and state only. Host
   names, addresses, and per-host load never enter the summary. There is
   no field in the output that could identify a single machine.

The output of this stage is the ONLY thing downstream stages may read.
"""
from __future__ import annotations

import argparse
import json
from collections import defaultdict
from datetime import datetime, timedelta, timezone

PUBLISH_DELAY = timedelta(hours=1)
STATES = ["up", "degraded", "down"]


def load_raw(path: str):
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line:
                yield json.loads(line)


def aggregate(rows, now: datetime):
    cutoff = now - PUBLISH_DELAY
    # take the most recent sample per host that is older than the cutoff
    latest: dict[str, dict] = {}
    for row in rows:
        ts = datetime.fromisoformat(row["ts"])
        if ts > cutoff:
            continue
        key = row["host"]
        if key not in latest or ts > datetime.fromisoformat(latest[key]["ts"]):
            latest[key] = row

    counts: dict[str, dict] = defaultdict(lambda: {s: 0 for s in STATES})
    for row in latest.values():
        counts[row["group"]][row["state"]] += 1

    groups = []
    for g in sorted(counts):
        c = counts[g]
        total = sum(c.values())
        groups.append({
            "group": g,
            "total": total,
            "up": c["up"], "degraded": c["degraded"], "down": c["down"],
            "health": round(c["up"] / total, 3) if total else 0.0,
        })
    fleet_total = sum(g["total"] for g in groups)
    fleet_up = sum(g["up"] for g in groups)
    return {
        "as_of": cutoff.isoformat(),
        "delay_hours": PUBLISH_DELAY.total_seconds() / 3600,
        "fleet": {"total": fleet_total, "up": fleet_up,
                  "health": round(fleet_up / fleet_total, 3) if fleet_total else 0.0},
        "groups": groups,
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--raw", default="data/raw_telemetry.jsonl")
    ap.add_argument("--out", default="data/aggregates.json")
    ap.add_argument("--now", default="2026-03-02T12:00:00+00:00")
    args = ap.parse_args()

    now = datetime.fromisoformat(args.now)
    summary = aggregate(load_raw(args.raw), now)
    with open(args.out, "w") as f:
        json.dump(summary, f, indent=2)
    print(f"aggregated {summary['fleet']['total']} hosts "
          f"across {len(summary['groups'])} groups -> {args.out}")
    print(f"as of {summary['as_of']} ({summary['delay_hours']}h delay)")


if __name__ == "__main__":
    main()
