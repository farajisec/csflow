"""Aggregate raw samples into a publish-safe summary. The only stage that reads raw data.

Controls applied here, in order:

1. **Delay.** Only samples older than the policy delay are eligible. Live
   status of named infrastructure is operational intelligence; an hour
   behind it is a health indicator.
2. **Latest-per-host.** One state per host at the cut-off, so a host that
   reports every five minutes does not count twelve times.
3. **k-anonymity on groups.** A group smaller than *k* is never published
   on its own; small groups are merged into one labelled bucket, and if
   the bucket is still smaller than *k* it is folded into the fleet total
   and omitted. A count of "1 down of 1" is a named machine with extra
   steps.
4. **Complementary suppression.** If exactly one group was folded away,
   its counts could be recovered from the fleet total minus the published
   groups, so the fleet row is published only when at least two groups
   or none were folded.
5. **Optional noise.** Laplace noise on counts (epsilon from the policy),
   clamped and re-balanced so rows still sum. Off by default: at these
   scales it hurts utility more than it helps privacy, and the README
   says so rather than switching it on for show.
6. **Schema allowlist.** The output is built field by field from the
   policy's published-field lists; nothing else can be present.

The output carries no field that could identify a machine, a person or
an address, and ``gate.py`` checks that claim rather than trusting it.
"""
from __future__ import annotations

import json
import math
import random
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path

from .policy import Policy

STATES = ("up", "degraded", "down")


def load_samples(path: Path):
    with open(path, encoding="utf-8") as f:
        for line in f:
            if line.strip():
                yield json.loads(line)


def _latest_per_host(rows, cutoff: datetime) -> dict[str, dict]:
    latest: dict[str, dict] = {}
    for row in rows:
        ts = datetime.fromisoformat(row["sampled_at"])
        if ts > cutoff:
            continue
        key = row["hostname"]
        if key not in latest or ts > datetime.fromisoformat(latest[key]["sampled_at"]):
            latest[key] = row
    return latest


def _counts_by_group(latest: dict[str, dict]) -> dict[str, dict[str, int]]:
    counts: dict[str, dict[str, int]] = defaultdict(lambda: dict.fromkeys(STATES, 0))
    for row in latest.values():
        counts[row["group"]][row["status"]] += 1
    return counts


def _laplace(rng: random.Random, scale: float) -> float:
    u = rng.random() - 0.5
    return -scale * math.copysign(1, u) * math.log(1 - 2 * abs(u))


def _noisy(counts: dict[str, int], epsilon: float, rng: random.Random) -> dict[str, int]:
    total = sum(counts.values())
    noisy = {s: max(0, int(round(v + _laplace(rng, 1.0 / epsilon)))) for s, v in counts.items()}
    # re-balance so the row still sums to the (true) total; the total is a size, not a secret
    drift = total - sum(noisy.values())
    noisy["up"] = max(0, noisy["up"] + drift)
    return noisy


def k_anonymise(counts: dict[str, dict[str, int]], k: int, small_label: str
                ) -> tuple[list[tuple[str, dict[str, int]]], int, int]:
    """Return (published groups, number of groups folded away, hosts folded into the total only)."""
    published: list[tuple[str, dict[str, int]]] = []
    small = dict.fromkeys(STATES, 0)
    folded = 0
    for g in sorted(counts):
        c = counts[g]
        if sum(c.values()) >= k:
            published.append((g, dict(c)))
        else:
            folded += 1
            for s in STATES:
                small[s] += c[s]
    hidden_hosts = 0
    if folded and sum(small.values()) >= k:
        published.append((small_label, small))
    elif folded:
        hidden_hosts = sum(small.values())                   # too small even merged: total only
    return published, folded, hidden_hosts


def _history(rows, cutoff: datetime, policy: Policy) -> list[dict]:
    """Hourly fleet counts over the last ``history_hours`` before the cut-off, latest-per-host per bucket."""
    bucket = timedelta(minutes=policy.history_bucket_minutes)
    start = cutoff - timedelta(hours=policy.history_hours)
    per_bucket: dict[datetime, dict[str, dict]] = defaultdict(dict)
    for row in rows:
        ts = datetime.fromisoformat(row["sampled_at"])
        if not start <= ts <= cutoff:
            continue
        b = start + bucket * int((ts - start) / bucket)
        prev = per_bucket[b].get(row["hostname"])
        if prev is None or ts > datetime.fromisoformat(prev["sampled_at"]):
            per_bucket[b][row["hostname"]] = row
    out = []
    for b in sorted(per_bucket):
        c = dict.fromkeys(STATES, 0)
        for r in per_bucket[b].values():
            c[r["status"]] += 1
        out.append({"bucket_start": b.isoformat(), **c, "total": sum(c.values())})
    return out


def _pick(d: dict, fields: list[str]) -> dict:
    """Allowlist projection: only policy-listed fields survive, in policy order."""
    return {k: d[k] for k in fields if k in d}


def aggregate(samples: list[dict], now: datetime, policy: Policy, seed: int = 0) -> dict:
    cutoff = now - timedelta(minutes=policy.publish_delay_minutes)
    latest = _latest_per_host(samples, cutoff)
    counts = _counts_by_group(latest)
    rng = random.Random(seed)
    if policy.noise_enabled:
        counts = {g: _noisy(c, policy.noise_epsilon, rng) for g, c in counts.items()}
    groups, folded, hidden = k_anonymise(counts, policy.k_min_group_size, policy.small_group_label)

    rows = []
    for label, c in groups:
        total = sum(c.values())
        rows.append(_pick({"label": label, "total": total, **c,
                           "health": round(c["up"] / total, 3) if total else 0.0}, policy.published_fields["group"]))
    fleet_counts = dict.fromkeys(STATES, 0)
    for c in counts.values():
        for s in STATES:
            fleet_counts[s] += c[s]
    fleet_total = sum(fleet_counts.values())
    fleet = _pick({"total": fleet_total, **fleet_counts,
                   "health": round(fleet_counts["up"] / fleet_total, 3) if fleet_total else 0.0},
                  policy.published_fields["fleet"])
    # complementary suppression: with exactly one group hidden, fleet minus groups would reveal it
    publish_fleet = not (hidden and folded == 1)
    summary = {
        "as_of": cutoff.isoformat(),
        "delay_minutes": policy.publish_delay_minutes,
        "generated_from_samples_before": cutoff.isoformat(),
        "fleet": fleet if publish_fleet else None,
        "groups": rows,
        "history": [_pick(h, policy.published_fields["history_point"]) for h in _history(samples, cutoff, policy)],
        "policy": _pick(policy.to_public_dict(), policy.published_fields["policy"]),
    }
    return _pick(summary, policy.published_fields["summary"])


def write_aggregates(path: Path, summary: dict) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=1)
