"""Render the aggregates into a static status page. Reads the summary only.

There is no code path from this stage to the raw samples or the
inventory: it takes the summary dictionary and nothing else, so it cannot
leak what it was never given. The page is self-contained HTML with inline
SVG (lamps per group, a 24-hour history strip) and no scripts that fetch
anything.
"""
from __future__ import annotations

import html

LAMP = {"up": "#2ea85a", "degraded": "#e0a100", "down": "#d9433b"}


def _lamps(group: dict) -> str:
    cells = []
    for state in ("up", "degraded", "down"):
        for _ in range(int(group.get(state, 0))):
            cells.append(f'<i class="lamp" style="background:{LAMP[state]}" title="{state}"></i>')
    return "".join(cells)


def _history_svg(history: list[dict]) -> str:
    if not history:
        return ""
    w, h = 600, 64
    n = len(history)
    bw = w / n
    bars = []
    for i, p in enumerate(history):
        total = max(1, int(p.get("total", 0)))
        y = 0.0
        for state in ("down", "degraded", "up"):
            frac = int(p.get(state, 0)) / total
            hh = frac * h
            bars.append(f'<rect x="{i * bw:.1f}" y="{y:.1f}" width="{max(bw - 1, 1):.1f}" height="{hh:.1f}" '
                        f'fill="{LAMP[state]}"><title>{html.escape(p.get("bucket_start", ""))}: '
                        f'{p.get("up")} up, {p.get("degraded")} degraded, {p.get("down")} down</title></rect>')
            y += hh
    return (f'<svg viewBox="0 0 {w} {h}" width="100%" height="{h}" role="img" '
            f'aria-label="fleet state over the last {n} hours">' + "".join(bars) + "</svg>")


def render(summary: dict) -> str:
    fleet = summary.get("fleet")
    groups = summary.get("groups", [])
    pol = summary.get("policy", {})
    blocks = []
    for g in groups:
        pct = int(round(float(g.get("health", 0)) * 100))
        blocks.append(
            f'<section class="grp"><header><span class="name">{html.escape(str(g["label"]))}</span>'
            f'<span class="meta">{g["up"]}/{g["total"]} up &middot; {pct}%</span></header>'
            f'<div class="lamps">{_lamps(g)}</div></section>')
    if fleet:
        head = (f'<div class="fleet">{int(round(float(fleet["health"]) * 100))}% healthy</div>'
                f'<div class="sub">{fleet["up"]} of {fleet["total"]} hosts up</div>')
    else:
        head = '<div class="fleet">per-group status</div><div class="sub">fleet total withheld (small-group rule)</div>'
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Fleet Status</title>
<style>
:root{{--bg:#0b0e14;--fg:#e6e9ef;--muted:#8a93a6;--card:#141926;--line:#222838}}
*{{box-sizing:border-box}}
body{{margin:0;background:var(--bg);color:var(--fg);font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif}}
.wrap{{max-width:900px;margin:0 auto;padding:2rem 1rem}}
h1{{font-size:1.4rem;margin:0 0 .25rem}}
.sub{{color:var(--muted);font-size:.9rem;margin-bottom:1.2rem}}
.fleet{{font-size:2.2rem;font-weight:700;margin:.2rem 0}}
.hist{{background:var(--card);border-radius:12px;padding:.8rem 1.1rem;margin:.8rem 0}}
.grp{{background:var(--card);border-radius:12px;padding:1rem 1.1rem;margin:.8rem 0}}
.grp header{{display:flex;justify-content:space-between;align-items:baseline;margin-bottom:.6rem}}
.name{{font-weight:600;text-transform:capitalize}}
.meta{{color:var(--muted);font-size:.85rem}}
.lamps{{display:flex;flex-wrap:wrap;gap:6px}}
.lamp{{width:14px;height:14px;border-radius:50%;display:inline-block}}
footer{{color:var(--muted);font-size:.8rem;margin-top:2rem;border-top:1px solid var(--line);padding-top:1rem}}
</style></head><body><div class="wrap">
<h1>Fleet Status</h1>
{head}
<div class="sub">as of {html.escape(str(summary.get("as_of", "")))} &middot; delayed {summary.get("delay_minutes", "?")} min
&middot; groups smaller than {pol.get("k_min_group_size", "?")} hosts are merged or withheld</div>
<div class="hist"><div class="meta">last {pol.get("history_hours", "?")} hours, fleet-wide</div>{_history_svg(summary.get("history", []))}</div>
{"".join(blocks)}
<footer>Counts only. No hostnames, addresses, owners or per-host data are published. Status is delayed and
aggregated by policy, and a gate refuses publication if any identifier is found in this page.</footer>
</div></body></html>
"""
