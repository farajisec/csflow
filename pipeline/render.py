#!/usr/bin/env python3
"""Render the publish-safe aggregates into a static status page.

Input is the aggregates summary only. There is no path from this stage
back to the raw telemetry, so the page cannot leak anything the aggregate
stage did not already drop. The visual is a "tree of light": one lamp per
host, grouped, lit by state. It shows whether things are healthy without
naming a single machine.
"""
from __future__ import annotations

import argparse
import html
import json

LAMP = {"up": "#39d98a", "degraded": "#f5a623", "down": "#e5484d"}


def lamps(group: dict) -> str:
    cells = []
    for state in ("up", "degraded", "down"):
        for _ in range(group[state]):
            cells.append(f'<i class="lamp" style="background:{LAMP[state]}" '
                         f'title="{state}"></i>')
    return "".join(cells)


def render(summary: dict) -> str:
    fleet = summary["fleet"]
    blocks = []
    for g in summary["groups"]:
        pct = int(round(g["health"] * 100))
        blocks.append(
            f'<section class="grp"><header><span class="name">'
            f'{html.escape(g["group"])}</span>'
            f'<span class="meta">{g["up"]}/{g["total"]} up &middot; {pct}%'
            f'</span></header><div class="lamps">{lamps(g)}</div></section>')
    body = "\n".join(blocks)
    fpct = int(round(fleet["health"] * 100))
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Fleet Status</title>
<style>
:root{{--bg:#0b0e14;--fg:#e6e9ef;--muted:#8a93a6;--card:#141926}}
*{{box-sizing:border-box}}
body{{margin:0;background:var(--bg);color:var(--fg);
font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif}}
.wrap{{max-width:900px;margin:0 auto;padding:2rem 1rem}}
h1{{font-size:1.4rem;margin:0 0 .25rem}}
.sub{{color:var(--muted);font-size:.9rem;margin-bottom:1.5rem}}
.fleet{{font-size:2.2rem;font-weight:700;margin:.2rem 0}}
.grp{{background:var(--card);border-radius:12px;padding:1rem 1.1rem;
margin:.8rem 0}}
.grp header{{display:flex;justify-content:space-between;align-items:baseline;
margin-bottom:.6rem}}
.name{{font-weight:600;text-transform:capitalize}}
.meta{{color:var(--muted);font-size:.85rem}}
.lamps{{display:flex;flex-wrap:wrap;gap:6px}}
.lamp{{width:14px;height:14px;border-radius:50%;display:inline-block;
box-shadow:0 0 6px currentColor}}
footer{{color:var(--muted);font-size:.8rem;margin-top:2rem;
border-top:1px solid #222838;padding-top:1rem}}
</style></head><body><div class="wrap">
<h1>Fleet Status</h1>
<div class="fleet">{fpct}% healthy</div>
<div class="sub">{fleet['up']} of {fleet['total']} hosts up &middot;
aggregates only, delayed {int(summary['delay_hours'])}h &middot;
as of {html.escape(summary['as_of'])}</div>
{body}
<footer>Counts only. No hostnames, addresses, or per-host data are
published. Status is delayed and aggregated by design.</footer>
</div></body></html>
"""


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--aggregates", default="data/aggregates.json")
    ap.add_argument("--out", default="site/index.html")
    args = ap.parse_args()
    with open(args.aggregates) as f:
        summary = json.load(f)
    with open(args.out, "w") as f:
        f.write(render(summary))
    print(f"rendered status page -> {args.out}")


if __name__ == "__main__":
    main()
