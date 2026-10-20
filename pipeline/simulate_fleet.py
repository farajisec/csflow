#!/usr/bin/env python3
"""Synthetic fleet simulator: the PRIVATE side of the csflow pipeline.

Produces the kind of data a real collector would hold: an inventory of
hosts with names and addresses, and a time series of status samples per
host. This side is sensitive by construction, which is the point: the
pipeline's job is to prove none of it reaches the published output.

All identifiers are synthetic (documentation domains and RFC 5737 example
address ranges). No real environment is described.
"""
from __future__ import annotations

import argparse
import json
import random
from datetime import datetime, timedelta, timezone

# group -> host count; "tiny-group" is deliberately below the k-anonymity
# threshold to exercise the small-group merge in the aggregator
GROUPS = {
    "virtualization": 5,
    "storage": 2,
    "gpu-compute": 6,
    "web": 4,
    "research": 8,
    "lab": 10,
    "tiny-group": 2,
}


def build_inventory(rng: random.Random) -> list[dict]:
    inv, n = [], 0
    for group, count in GROUPS.items():
        for i in range(1, count + 1):
            n += 1
            inv.append({
                "hostname": f"{group}-node{i:02d}.internal.example",
                "ip": f"203.0.113.{n}",
                "group": group,
                "owner": f"user{n:02d}",
            })
    return inv


def simulate(inv: list[dict], rng: random.Random, hours: int,
             now: datetime) -> list[dict]:
    """Five-minute status samples per host over the window ending at now."""
    samples = []
    start = now - timedelta(hours=hours)
    down_hosts = set(rng.sample([h["hostname"] for h in inv], 2))
    degraded_hosts = set(rng.sample(
        [h["hostname"] for h in inv if h["hostname"] not in down_hosts], 3))
    t = start
    while t <= now:
        for h in inv:
            if h["hostname"] in down_hosts and t >= now - timedelta(hours=3):
                status = "down"
            elif (h["hostname"] in degraded_hosts
                  and t >= now - timedelta(hours=2)):
                status = "degraded"
            else:
                status = "up" if rng.random() > 0.002 else "degraded"
            samples.append({
                "hostname": h["hostname"],
                "ip": h["ip"],
                "group": h["group"],
                "owner": h["owner"],
                "status": status,
                "sampled_at": t.isoformat(),
            })
        t += timedelta(minutes=5)
    return samples


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--hours", type=int, default=6)
    ap.add_argument("--now", default=None,
                    help="ISO timestamp for 'now' (default: real now, UTC)")
    ap.add_argument("--inventory-out", default="data/inventory.json")
    ap.add_argument("--samples-out", default="data/samples.jsonl")
    args = ap.parse_args()

    rng = random.Random(args.seed)
    now = (datetime.fromisoformat(args.now) if args.now
           else datetime.now(timezone.utc))
    inv = build_inventory(rng)
    samples = simulate(inv, rng, args.hours, now)

    with open(args.inventory_out, "w") as f:
        json.dump(inv, f, indent=2)
    with open(args.samples_out, "w") as f:
        for s in samples:
            f.write(json.dumps(s) + "\n")
    print(f"{len(inv)} hosts, {len(samples)} samples "
          f"({args.hours}h window ending {now.isoformat()})")


if __name__ == "__main__":
    main()
