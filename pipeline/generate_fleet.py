#!/usr/bin/env python3
"""Synthetic fleet telemetry generator for the csflow lab.

Produces raw per-host status samples for a fleet of generic hosts. This
raw stream deliberately contains the kind of detail you would NOT want on
a public status page: hostnames and internal addresses. The pipeline's job
is to make sure none of it reaches what gets published.

Everything is synthetic. The hostnames and addresses here are invented and
generic; they stand in for "internal detail", nothing more.
"""
from __future__ import annotations

import argparse
import json
import random
from datetime import datetime, timedelta, timezone

GROUPS = ["compute", "storage", "web", "gpu", "infra"]
STATES = ["up", "degraded", "down"]


def build_fleet(seed: int):
    r = random.Random(seed)
    fleet = []
    hid = 0
    for g in GROUPS:
        for i in range(r.randint(6, 14)):
            hid += 1
            fleet.append({
                "host": f"node-{g[:3]}{i:02d}",             # internal name
                "addr": f"10.{r.randint(10, 60)}.{r.randint(0, 255)}.{hid}",
                "group": g,
            })
    return fleet


def sample(r: random.Random) -> tuple[str, float]:
    x = r.random()
    if x > 0.90:
        return ("down" if x > 0.97 else "degraded", round(r.uniform(0.6, 1.4), 2))
    return "up", round(r.uniform(0.0, 0.7), 2)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--hours", type=int, default=3)
    ap.add_argument("--out", default="data/raw_telemetry.jsonl")
    args = ap.parse_args()

    r = random.Random(args.seed)
    fleet = build_fleet(args.seed)
    now = datetime(2026, 3, 2, 12, 0, tzinfo=timezone.utc)
    start = now - timedelta(hours=args.hours)

    rows = []
    t = start
    while t <= now:
        for h in fleet:
            state, load = sample(r)
            rows.append({
                "ts": t.isoformat(),
                "host": h["host"],
                "addr": h["addr"],
                "group": h["group"],
                "state": state,
                "load": load,
            })
        t += timedelta(minutes=10)

    with open(args.out, "w") as f:
        for row in rows:
            f.write(json.dumps(row) + "\n")

    # a manifest of the identifiers that must never reach the public output
    ids = sorted({h["host"] for h in fleet} | {h["addr"] for h in fleet})
    with open("data/identifiers.json", "w") as f:
        json.dump({"identifiers": ids}, f, indent=2)

    print(f"wrote {len(rows)} samples for {len(fleet)} hosts -> {args.out}")
    print(f"wrote {len(ids)} sensitive identifiers -> data/identifiers.json")


if __name__ == "__main__":
    main()
