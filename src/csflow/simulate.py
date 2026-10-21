"""The PRIVATE side: a synthetic fleet with every identifier a real collector holds.

Hostnames, addresses, MACs, serials, owners and their emails are all
invented (RFC 5737 / RFC 2606 ranges, locally administered MACs), but
they are shaped like the real thing on purpose: the gate's job is to
prove that none of them, in any encoding, reach the published output.

The fleet has groups of very different sizes, including groups smaller
than the policy's k, so the aggregator's small-group handling is
exercised on every run. Status over time includes a partial outage, a
degraded group, flapping hosts and a maintenance window.
"""
from __future__ import annotations

import json
import random
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

GROUPS = {
    "virtualization": 6, "storage": 3, "gpu-compute": 8, "web": 5, "research": 11,
    "teaching-lab": 14, "sensors": 2, "legacy": 1,
}
OWNERS = ["ana.ortiz", "ben.kim", "carla.nguyen", "dev.patel", "eli.smith", "fatima.garcia", "gus.khan"]
STATES = ("up", "degraded", "down")


def build_inventory(rng: random.Random) -> list[dict]:
    inv, n = [], 0
    for group, count in GROUPS.items():
        for i in range(1, count + 1):
            n += 1
            owner = rng.choice(OWNERS)
            inv.append({
                "hostname": f"{group}-node{i:02d}.cs.internal.example",
                "ip": f"203.0.113.{n}",
                "ipv6": f"2001:db8:cafe::{n:x}",
                "mac": f"02:00:5e:{rng.randint(0, 255):02x}:{rng.randint(0, 255):02x}:{n:02x}",
                "serial": f"SN{rng.randint(10**7, 10**8 - 1)}X",
                "asset_id": str(uuid.UUID(int=rng.getrandbits(128))),
                "group": group,
                "owner": owner,
                "owner_email": f"{owner}@example.edu",
                "rack": f"R{rng.randint(1, 9)}-U{rng.randint(1, 42)}",
            })
    return inv


def simulate(inv: list[dict], rng: random.Random, hours: int, now: datetime) -> list[dict]:
    """Five-minute samples per host over the window ending at ``now``."""
    start = now - timedelta(hours=hours)
    names = [h["hostname"] for h in inv]
    down = set(rng.sample(names, 3))                                 # a few hosts down for the last 3 h
    degraded_group = rng.choice(["gpu-compute", "research"])          # one group degraded for 2 h
    flappers = set(rng.sample([n for n in names if n not in down], 2))
    maint_group, maint_start = "teaching-lab", now - timedelta(hours=hours - 2)
    samples = []
    t = start
    while t <= now:
        for h in inv:
            name = h["hostname"]
            if name in down and t >= now - timedelta(hours=3):
                state = "down"
            elif h["group"] == maint_group and maint_start <= t < maint_start + timedelta(hours=1):
                state = "down"                                       # planned maintenance
            elif h["group"] == degraded_group and t >= now - timedelta(hours=2):
                state = "degraded"
            elif name in flappers:
                state = "degraded" if (int(t.timestamp()) // 300) % 3 == 0 else "up"
            else:
                state = "up" if rng.random() > 0.004 else "degraded"
            samples.append({**{k: h[k] for k in ("hostname", "ip", "group", "owner")},
                            "status": state, "load": round(rng.uniform(0.02, 0.95), 2),
                            "sampled_at": t.isoformat()})
        t += timedelta(minutes=5)
    return samples


def generate(seed: int, out_dir: Path, hours: int = 30, now: datetime | None = None) -> dict:
    rng = random.Random(seed)
    now = now or datetime(2026, 3, 2, 12, 0, tzinfo=timezone.utc)
    inv = build_inventory(rng)
    samples = simulate(inv, rng, hours, now)
    out_dir.mkdir(parents=True, exist_ok=True)
    with open(out_dir / "inventory.json", "w", encoding="utf-8") as f:
        json.dump(inv, f, indent=1)
    with open(out_dir / "samples.jsonl", "w", encoding="utf-8") as f:
        for s in samples:
            f.write(json.dumps(s, separators=(",", ":")) + "\n")
    return {"hosts": len(inv), "samples": len(samples), "now": now.isoformat()}
